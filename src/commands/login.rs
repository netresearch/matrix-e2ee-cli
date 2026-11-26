//! `login`: password login that creates a new device.

use anyhow::{Context, Result, bail};
use matrix_sdk::Client;
use matrix_sdk::ruma::UserId;

use crate::commands::sync_once;
use crate::config::{Config, load_config};
use crate::session::{
    KeySharing, Paths, SessionFile, UserIdMatch, build_client, compare_user_ids, discard_stash,
    existing_stash, generate_passphrase, parse_user_id, read_secret, read_session,
    restore_previous, rollback_failed_login, stash_local_state, stash_refusal, write_session,
};
use crate::text::term;

pub const DEVICE_NAME: &str = "Matrix Skill E2EE (Rust)";

pub async fn run(force: bool, restore_prev: bool) -> Result<()> {
    let paths = Paths::from_env()?;
    if restore_prev {
        restore_previous(&paths)?;
        let restored = read_session(&paths.session_file())?;
        match restored {
            Some(s) => println!(
                "Restored the previous session of {} with device {}.",
                term(&s.user_id),
                term(&s.device_id)
            ),
            None => println!("Restored the previous local state."),
        }
        return Ok(());
    }
    // A stash is the only copy of an earlier session: never touch it.
    if !existing_stash(&paths).is_empty() {
        bail!(stash_refusal(&paths));
    }
    let config = load_config()?;

    if let Some(existing) = read_session(&paths.session_file())? {
        if !force {
            bail!(
                "already logged in as {} with device {}; use --force to replace it, or `logout` first",
                existing.user_id,
                existing.device_id
            );
        }
        eprintln!(
            "Replacing the local session of device {}. That device stays on the server; remove it with Element or log it out first.",
            term(&existing.device_id)
        );
    }
    let password = read_secret(
        "MATRIX_PASSWORD",
        &format!("Matrix password for {}: ", config.user_id),
    )?;

    // A store belongs to one device and its passphrase, so the new device
    // needs an empty one. Keep the old state aside until the login succeeded.
    stash_local_state(&paths)?;
    let (client, session) = match create_device(&config, &paths, &password).await {
        Ok(done) => done,
        Err(err) => return rollback_failed_login(&paths, err),
    };
    drop(password);
    discard_stash(&paths)?;

    // Upload the new device's keys.
    client
        .encryption()
        .wait_for_e2ee_initialization_tasks()
        .await;
    sync_once(&client)
        .await
        .context("logged in, but the first sync failed")?;

    println!("Logged in as {}", term(&session.user_id));
    println!("Device: {} ({DEVICE_NAME})", term(&session.device_id));
    println!("Session: {}", paths.session_file().display());
    eprintln!(
        "Next: verify this device with `matrix-e2ee-cli verify --request <your other device id>`, or restore keys with `matrix-e2ee-cli backup-restore`."
    );
    Ok(())
}

/// What to do with the user id the server returned for the new device.
#[derive(Debug, PartialEq, Eq)]
enum ReturnedUser {
    /// Store it.
    Accept,
    /// Store the server's canonical id and tell the user to update config.json.
    AcceptCanonical(String),
    /// Log the new device out again and stop.
    Reject(String),
}

fn judge_returned_user(configured: &UserId, returned: &UserId) -> ReturnedUser {
    match compare_user_ids(configured, returned) {
        UserIdMatch::Same => ReturnedUser::Accept,
        UserIdMatch::CaseOnly => ReturnedUser::AcceptCanonical(format!(
            "note: the server spells your user id {returned}; put {returned} into config.json as user_id"
        )),
        UserIdMatch::Different => ReturnedUser::Reject(format!(
            "the server logged in {returned}, but config.json names {configured}"
        )),
    }
}

/// Write the new session file; on failure name the device that now exists on
/// the server, so the user can remove it.
fn store_new_session(paths: &Paths, session: &SessionFile) -> Result<()> {
    write_session(&paths.session_file(), session).with_context(|| {
        format!(
            "logged in as new device {}, but cannot save its session; remove device {} with Element or another client",
            session.device_id, session.device_id
        )
    })
}

/// Log in and write the session file. Once this returns Ok, the device
/// exists on the server and its session is stored.
async fn create_device(
    config: &Config,
    paths: &Paths,
    password: &str,
) -> Result<(Client, SessionFile)> {
    // Before the login, so an unusable id never leaves a device behind.
    let configured = parse_user_id(&config.user_id, "config.json")?;
    let passphrase = generate_passphrase();
    let client = build_client(
        &config.homeserver,
        paths,
        &passphrase,
        KeySharing::VerifiedOnly,
    )
    .await?;
    let response = client
        .matrix_auth()
        .login_username(&config.user_id, password)
        .initial_device_display_name(DEVICE_NAME)
        .send()
        .await
        .context("login failed")?;
    let device_id = response.device_id.to_string();
    match judge_returned_user(&configured, &response.user_id) {
        ReturnedUser::Accept => {}
        ReturnedUser::AcceptCanonical(note) => eprintln!("{}", term(&note)),
        ReturnedUser::Reject(reason) => {
            let err = anyhow::anyhow!("{reason}; the new device {device_id} was logged out again");
            if let Err(logout) = client.logout().await {
                return Err(logout).with_context(|| {
                    format!(
                        "{reason}; logging the new device {device_id} out failed, remove it with Element or another client"
                    )
                });
            }
            return Err(err);
        }
    }
    let session = SessionFile {
        homeserver: client.homeserver().to_string(),
        user_id: response.user_id.to_string(),
        device_id,
        access_token: response.access_token.clone(),
        store_passphrase: passphrase,
    };
    store_new_session(paths, &session)?;
    Ok((client, session))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_user_id_differing_in_case_is_accepted_with_a_note() {
        let id = |s: &str| parse_user_id(s, "test").unwrap();
        assert_eq!(
            judge_returned_user(&id("@alice:example.org"), &id("@alice:example.org")),
            ReturnedUser::Accept
        );
        match judge_returned_user(&id("@Alice:example.org"), &id("@alice:example.org")) {
            ReturnedUser::AcceptCanonical(note) => {
                assert!(
                    note.contains("@alice:example.org") && note.contains("config.json"),
                    "{note}"
                )
            }
            other => panic!("expected AcceptCanonical, got {other:?}"),
        }
        match judge_returned_user(&id("@alice:example.org"), &id("@bob:example.org")) {
            ReturnedUser::Reject(reason) => {
                assert!(
                    reason.contains("@alice:example.org") && reason.contains("@bob:example.org"),
                    "{reason}"
                )
            }
            other => panic!("expected Reject, got {other:?}"),
        }
        assert!(matches!(
            judge_returned_user(&id("@alice:example.org"), &id("@alice:other.org")),
            ReturnedUser::Reject(_)
        ));
    }

    #[test]
    fn failed_session_write_names_the_new_device() {
        let tmp = tempfile::tempdir().unwrap();
        // The data directory is a regular file, so the write fails.
        let blocker = tmp.path().join("app");
        std::fs::write(&blocker, "x").unwrap();
        let paths = Paths {
            data_dir: blocker.join("sub"),
        };
        let session = SessionFile {
            homeserver: "https://m.example".into(),
            user_id: "@a:example".into(),
            device_id: "NEWDEVICE".into(),
            access_token: "t".into(),
            store_passphrase: "p".into(),
        };
        let err = format!("{:#}", store_new_session(&paths, &session).unwrap_err());
        assert!(err.contains("NEWDEVICE"), "{err}");
    }
}
