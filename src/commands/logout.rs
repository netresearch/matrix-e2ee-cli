//! `logout`: log the device out on the server, then delete the local
//! session file and store. Works from the session file alone, without
//! config.json.

use anyhow::{Context, Result, bail};
use matrix_sdk::ruma::api::error::ErrorKind;

use crate::commands::ask_yes_no;
use crate::session::{
    KeySharing, Paths, Restored, delete_local_state, read_existing_session, restore_from,
    restore_without_store,
};
use crate::text::term;

pub async fn run(yes: bool, local_only: bool) -> Result<()> {
    let paths = Paths::from_env()?;
    // Held until the store is deleted: no other command may use it meanwhile.
    let _lock = paths.lock().await?;
    // The session file alone: logout is the way out of a session that does
    // not match config.json, so it must not depend on config.json.
    let restored = open_for_logout(&paths).await?;
    let device = term(&restored.session.device_id).into_owned();

    if !yes
        && !ask_yes_no(
            &format!(
                "Log out device {device} and delete its local store (its room keys are lost unless backed up)?"
            ),
            true,
        )?
    {
        bail!("aborted");
    }

    let mut device_may_remain = false;
    match restored.client.logout().await {
        Ok(()) => {}
        Err(err) => match judge_failed_logout(err.client_api_error_kind(), local_only) {
            FailedLogout::TokenGone => eprintln!(
                "The server no longer knows this session's token; deleting the local state only."
            ),
            FailedLogout::SoftLocalOnly => {
                device_may_remain = true;
                eprintln!(
                    "The server suspended this session (soft logout); device {device} may still exist on the server, remove it in Element under Settings > Sessions. Deleting the local state only (--local-only)."
                );
            }
            FailedLogout::SoftKeep => {
                return Err(err).with_context(|| {
                    format!(
                        "the server suspended this session (soft logout); device {device} may still exist on the server, so the local session was kept; remove device {device} in Element under Settings > Sessions, then run `matrix-e2ee-cli logout --local-only` to delete the local state"
                    )
                });
            }
            FailedLogout::Other => {
                return Err(err).context("server logout failed; the local session was kept");
            }
        },
    }
    drop(restored.client);
    delete_local_state(&paths)?;
    if device_may_remain {
        println!("Deleted the local session and store of device {device}.");
    } else {
        println!("Logged out device {device}; local session and store deleted.");
    }
    Ok(())
}

/// The client to send the logout with. The token is all the server needs,
/// so a store that cannot be opened does not block the revocation: the
/// session file's token is used with an in-memory store instead.
async fn open_for_logout(paths: &Paths) -> Result<Restored> {
    let session = read_existing_session(paths)?;
    match restore_from(session.clone(), paths, KeySharing::VerifiedOnly).await {
        Ok(restored) => Ok(restored),
        Err(err) => {
            eprintln!(
                "Cannot open the local store ({}); logging out with the session file alone.",
                term(&format!("{err:#}"))
            );
            restore_without_store(session)
                .await
                .with_context(|| format!("cannot open the local store ({err:#})"))
        }
    }
}

/// What a failed server logout means for the local state.
#[derive(Debug, PartialEq, Eq)]
enum FailedLogout {
    /// `M_UNKNOWN_TOKEN`: the token is dead and the device gone; delete the
    /// local state.
    TokenGone,
    /// Soft logout with `--local-only`: delete the local state although the
    /// device may remain on the server.
    SoftLocalOnly,
    /// Soft logout: the device may remain on the server; keep the local state.
    SoftKeep,
    /// Any other failure: keep the local state.
    Other,
}

fn judge_failed_logout(kind: Option<&ErrorKind>, local_only: bool) -> FailedLogout {
    match kind {
        Some(ErrorKind::UnknownToken(data)) if data.soft_logout => {
            if local_only {
                FailedLogout::SoftLocalOnly
            } else {
                FailedLogout::SoftKeep
            }
        }
        Some(ErrorKind::UnknownToken(_)) => FailedLogout::TokenGone,
        _ => FailedLogout::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionFile, build_client, generate_passphrase, write_session};
    use matrix_sdk::ruma::api::error::UnknownTokenErrorData;

    fn unknown_token(soft_logout: bool) -> ErrorKind {
        let mut data = UnknownTokenErrorData::new();
        data.soft_logout = soft_logout;
        ErrorKind::UnknownToken(data)
    }

    #[test]
    fn soft_logout_keeps_the_local_state_unless_local_only() {
        let soft = unknown_token(true);
        assert_eq!(
            judge_failed_logout(Some(&soft), false),
            FailedLogout::SoftKeep
        );
        assert_eq!(
            judge_failed_logout(Some(&soft), true),
            FailedLogout::SoftLocalOnly
        );
        let hard = unknown_token(false);
        for local_only in [false, true] {
            assert_eq!(
                judge_failed_logout(Some(&hard), local_only),
                FailedLogout::TokenGone
            );
            assert_eq!(judge_failed_logout(None, local_only), FailedLogout::Other);
            assert_eq!(
                judge_failed_logout(Some(&ErrorKind::Forbidden), local_only),
                FailedLogout::Other
            );
        }
    }

    #[tokio::test]
    async fn logout_uses_the_session_file_when_the_store_cannot_open() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths {
            data_dir: tmp.path().join("app"),
        };
        // A store bound to another passphrase than the session file's.
        drop(
            build_client(
                "https://matrix.invalid",
                &paths,
                &generate_passphrase(),
                KeySharing::VerifiedOnly,
            )
            .await
            .unwrap(),
        );
        let session = SessionFile {
            homeserver: "https://matrix.invalid".into(),
            user_id: "@a:example.org".into(),
            device_id: "DEV".into(),
            access_token: "token".into(),
            store_passphrase: generate_passphrase(),
        };
        write_session(&paths.session_file(), &session).unwrap();

        let restored = open_for_logout(&paths)
            .await
            .expect("no client to send the logout with");
        assert_eq!(restored.client.access_token().as_deref(), Some("token"));
        assert_eq!(restored.client.device_id().map(|d| d.as_str()), Some("DEV"));
    }
}
