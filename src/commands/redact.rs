//! `redact`: remove the content of one event, after checking the room's
//! power levels.

use anyhow::{Context, Result, bail};
use matrix_sdk::Client;
use matrix_sdk::ruma::UserId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::RedactArgs;
use crate::commands::send::{request_opt, request_str};
use crate::commands::{
    event_sender, fetch_event, parse_event_id, resolve_room, sync_once, via_daemon,
};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term};

pub async fn run(args: RedactArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    // The request the watch daemon takes (matrix-watchd.py's "redact").
    let request = json!({
        "op": "redact",
        "room": args.room,
        "event_id": args.event_id,
        "reason": args.reason(),
    });
    let outcome = match via_daemon::<RedactOutcome>(&paths, request.clone(), "redaction").await? {
        Some(outcome) => outcome,
        None => {
            let config = load_config()?;
            let _lock = paths.lock().await?;
            // A redaction is never encrypted: no room key is shared.
            let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
            sync_once(&restored.client).await?;
            execute(&restored.client, &request).await?
        }
    };
    for line in render(&args, &outcome)? {
        println!("{line}");
    }
    Ok(())
}

/// The stdout lines for a redaction, as matrix-redact.py prints them.
pub fn render(args: &RedactArgs, outcome: &RedactOutcome) -> Result<Vec<String>> {
    let id = term(&outcome.event_id);
    Ok(if args.json {
        vec![json_line(&json!({"event_id": outcome.event_id}))?]
    } else if args.quiet {
        vec![id.into_owned()]
    } else {
        vec![
            format!("Message redacted from {}", term(&args.room)),
            format!("Redaction event ID: {id}"),
        ]
    })
}

/// What a redaction is reported as, on the direct path and in the daemon's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactOutcome {
    pub event_id: String,
    pub redacts: String,
    pub room_id: String,
}

/// Carry out a "redact" request with `client`, after checking the room's
/// power levels.
pub async fn execute(client: &Client, request: &Value) -> Result<RedactOutcome> {
    let room = resolve_room(client, request_str(request, "room")?).await?;
    let event_id = parse_event_id(request_str(request, "event_id")?)?;
    let own = client
        .user_id()
        .context("the client has no user id")?
        .to_owned();

    let (_, target) = fetch_event(&room, &event_id).await?;
    if super::is_redacted(&target) {
        bail!("the event is already redacted");
    }
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
        .redact(&event_id, request_opt(request, "reason"), None)
        .await
        .context("redaction failed")?;
    Ok(RedactOutcome {
        event_id: response.event_id.to_string(),
        redacts: event_id.to_string(),
        room_id: room.room_id().to_string(),
    })
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

    fn args(quiet: bool, json: bool) -> RedactArgs {
        RedactArgs {
            room: "#it:netresearch.de".into(),
            event_id: "$r".into(),
            reason: None,
            reason_option: Some("abgeschlossen".into()),
            quiet,
            json,
        }
    }

    fn done() -> RedactOutcome {
        RedactOutcome {
            event_id: "$x".into(),
            redacts: "$r".into(),
            room_id: "!room:netresearch.de".into(),
        }
    }

    #[test]
    fn output_is_matrix_redact_py_s() {
        assert_eq!(
            render(&args(false, false), &done()).unwrap(),
            vec![
                "Message redacted from #it:netresearch.de".to_owned(),
                "Redaction event ID: $x".to_owned(),
            ]
        );
        assert_eq!(
            render(&args(true, false), &done()).unwrap(),
            vec!["$x".to_owned()]
        );
        // --json wins over -q, as in matrix-redact.py.
        for quiet in [false, true] {
            let line = render(&args(quiet, true), &done()).unwrap().remove(0);
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap(),
                json!({"event_id": "$x"})
            );
        }
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
