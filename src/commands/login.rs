//! `login`: password login that creates a new device.

use std::time::Duration;

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
/// How long a failed login waits for the server to revoke the new device.
const REVOKE_WAIT: Duration = Duration::from_secs(10);

pub async fn run(force: bool, restore_prev: bool) -> Result<()> {
    let paths = Paths::from_env()?;
    // Before the stash and the store are touched, held until the login ends.
    let _lock = paths.lock().await?;
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

/// The error of a failed `send()`. The SDK installs the access token after
/// the server accepted the login and before it sets up the local store
/// (`MatrixAuth::set_session`), so a token means the server created a device
/// and only the local activation failed: try to log that device out again.
async fn failed_login(client: &Client, err: anyhow::Error, wait: Duration) -> anyhow::Error {
    if client.access_token().is_none() {
        return err.context("login failed");
    }
    // Known once the store loaded; unknown when the activation failed before.
    let device = client.device_id().map(ToString::to_string);
    let revoked = matches!(
        tokio::time::timeout(wait, client.matrix_auth().logout()).await,
        Ok(Ok(_))
    );
    err.context(activation_failure(device.as_deref(), revoked))
}

fn activation_failure(device: Option<&str>, revoked: bool) -> String {
    let device = match device {
        Some(id) => format!("device {id}"),
        None => format!("the new device \"{DEVICE_NAME}\""),
    };
    if revoked {
        format!(
            "the server accepted the login, but the local store could not be set up; {device} was logged out again"
        )
    } else {
        format!(
            "the server accepted the login and created {device}, but the local store could not be set up and logging it out again failed; remove {device} in Element under Settings > Sessions"
        )
    }
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
    let response = match client
        .matrix_auth()
        .login_username(&config.user_id, password)
        .initial_device_display_name(DEVICE_NAME)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => return Err(failed_login(&client, err.into(), REVOKE_WAIT).await),
    };
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
    fn activation_failure_says_whether_the_device_was_revoked() {
        let revoked = activation_failure(Some("NEWDEV"), true);
        assert!(
            revoked.contains("NEWDEV") && revoked.contains("logged out again"),
            "{revoked}"
        );
        assert!(!revoked.contains("Element"), "{revoked}");
        let left = activation_failure(Some("NEWDEV"), false);
        assert!(
            left.contains("remove device NEWDEV in Element under Settings > Sessions"),
            "{left}"
        );
        let unnamed = activation_failure(None, false);
        assert!(unnamed.contains(DEVICE_NAME), "{unnamed}");
    }

    async fn test_client(tmp: &tempfile::TempDir) -> Client {
        let paths = Paths {
            data_dir: tmp.path().join("app"),
        };
        // Port 9 on loopback: nothing answers, so a logout cannot succeed.
        build_client(
            "http://127.0.0.1:9",
            &paths,
            &generate_passphrase(),
            KeySharing::VerifiedOnly,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn rejected_login_is_reported_as_login_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(&tmp).await;
        let err = failed_login(
            &client,
            anyhow::anyhow!("M_FORBIDDEN"),
            Duration::from_secs(1),
        )
        .await;
        let chain = format!("{err:#}");
        assert!(chain.starts_with("login failed: M_FORBIDDEN"), "{chain}");
    }

    #[tokio::test]
    async fn failed_activation_after_a_token_names_the_device_to_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(&tmp).await;
        // The state send() leaves when the server accepted the login: a token
        // is installed on the client.
        client
            .matrix_auth()
            .restore_session(
                matrix_sdk::authentication::matrix::MatrixSession {
                    meta: matrix_sdk::SessionMeta {
                        user_id: parse_user_id("@a:example.org", "test").unwrap(),
                        device_id: "NEWDEV".into(),
                    },
                    tokens: matrix_sdk::SessionTokens {
                        access_token: "token".into(),
                        refresh_token: None,
                    },
                },
                matrix_sdk::store::RoomLoadSettings::default(),
            )
            .await
            .unwrap();
        let err = failed_login(
            &client,
            anyhow::anyhow!("sqlite I/O error"),
            Duration::from_secs(2),
        )
        .await;
        let chain = format!("{err:#}");
        assert!(chain.contains("remove device NEWDEV in Element"), "{chain}");
        assert!(!chain.starts_with("login failed"), "{chain}");
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
