//! `redact`: remove the content of one event, after checking the room's
//! power levels.

use anyhow::{Context, Result, bail};
use matrix_sdk::ruma::UserId;
use serde_json::json;

use crate::RedactArgs;
use crate::commands::{event_sender, fetch_event, parse_event_id, resolve_room, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term};

pub async fn run(args: RedactArgs) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    // A redaction is never encrypted: no room key is shared.
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let room = resolve_room(&client, &args.room).await?;
    let event_id = parse_event_id(&args.event_id)?;
    let own = client
        .user_id()
        .context("the client has no user id")?
        .to_owned();

    let (_, target) = fetch_event(&room, &event_id).await?;
    let sender = UserId::parse(event_sender(&target)?).context("the event's sender is invalid")?;
    // Without the room's power levels the permission cannot be checked;
    // assumed defaults could be wrong either way, so refuse.
    let levels = room
        .power_levels()
        .await
        .context("cannot read the room's power levels; not redacting")?;
    check_permission(
        &own,
        &sender,
        levels.user_can_redact_own_event(&own),
        levels.user_can_redact_event_of_other(&own),
    )?;

    let response = room
        .redact(&event_id, args.reason.as_deref(), None)
        .await
        .context("redaction failed")?;

    if args.json {
        println!(
            "{}",
            json_line(&json!({
                "event_id": response.event_id,
                "redacts": event_id,
                "room_id": room.room_id(),
            }))?
        );
    } else {
        println!("{}", term(response.event_id.as_str()));
    }
    Ok(())
}

/// Whether `own` may redact an event of `sender`, given what the power
/// levels allow `own`: its own events, and events of others.
pub fn check_permission(
    own: &UserId,
    sender: &UserId,
    can_redact_own: bool,
    can_redact_others: bool,
) -> Result<()> {
    if own == sender {
        if !can_redact_own {
            bail!("your power level in this room does not allow redacting your own events");
        }
    } else if !can_redact_others {
        bail!(
            "the event was sent by {sender}; your power level in this room does not allow redacting other users' events"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> matrix_sdk::ruma::OwnedUserId {
        UserId::parse(s).unwrap()
    }

    #[test]
    fn own_event_needs_the_own_permission_only() {
        let me = id("@me:example.org");
        assert!(check_permission(&me, &me, true, false).is_ok());
        let err = check_permission(&me, &me, false, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("your own events"), "{err}");
    }

    #[test]
    fn other_users_event_needs_the_others_permission() {
        let (me, other) = (id("@me:example.org"), id("@other:example.org"));
        assert!(check_permission(&me, &other, true, true).is_ok());
        let err = check_permission(&me, &other, true, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("@other:example.org") && err.contains("other users"),
            "{err}"
        );
    }
}
