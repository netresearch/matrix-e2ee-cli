//! `logout`: log the device out on the server, then delete the local
//! session file and store. Works from the session file alone, without
//! config.json.

use anyhow::{Context, Result, bail};
use matrix_sdk::ruma::api::error::ErrorKind;

use crate::commands::ask_yes_no;
use crate::session::{KeySharing, Paths, delete_local_state, restore_session};
use crate::text::term;

pub async fn run(yes: bool) -> Result<()> {
    let paths = Paths::from_env()?;
    // The session file alone: logout is the way out of a session that does
    // not match config.json, so it must not depend on config.json.
    let restored = restore_session(&paths, KeySharing::VerifiedOnly).await?;
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

    match restored.client.logout().await {
        Ok(()) => {}
        // The token is already dead: the device is gone on the server side.
        Err(err)
            if matches!(
                err.client_api_error_kind(),
                Some(ErrorKind::UnknownToken(_))
            ) =>
        {
            eprintln!(
                "The server no longer knows this session's token; deleting the local state only."
            );
        }
        Err(err) => return Err(err).context("server logout failed; the local session was kept"),
    }
    drop(restored.client);
    delete_local_state(&paths)?;
    println!("Logged out device {device}; local session and store deleted.");
    Ok(())
}
