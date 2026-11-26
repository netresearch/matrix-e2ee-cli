//! `edit`: replace the text of one of the user's own messages (`m.replace`).
//!
//! The edit is sent like `send` sends a message (see [`send_guarded`]):
//! encrypted in an encrypted room, room keys to verified devices only unless
//! `--trust-unverified-devices` is given.

use anyhow::{Context, Result, bail};
use matrix_sdk::Client;
use matrix_sdk::ruma::UserId;
use matrix_sdk::ruma::events::room::message::{ReplacementMetadata, RoomMessageEventContent};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::EditArgs;
use crate::commands::send::{
    Sent, key_sharing, print_warnings, request_str, request_trusts_unverified, send_guarded,
};
use crate::commands::{
    event_sender, fetch_event, parse_event_id, resolve_room, sync_once, via_daemon,
};
use crate::config::load_config;
use crate::session::{Paths, restore};
use crate::text::{json_line, term};

/// The message type the edit keeps from the original.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditKind {
    Text,
    Notice,
    Emote,
}

pub async fn run(args: EditArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    // The request the watch daemon takes (matrix-watchd.py's "edit").
    let request = json!({
        "op": "edit",
        "room": args.room,
        "event_id": args.event_id,
        "body": args.new_message,
        "trust_unverified_devices": args.trust_unverified_devices,
    });
    let outcome = match via_daemon::<EditOutcome>(&paths, request.clone(), "edit").await? {
        Some(outcome) => outcome,
        None => {
            let config = load_config()?;
            let _lock = paths.lock().await?;
            let restored =
                restore(&config, &paths, key_sharing(args.trust_unverified_devices)).await?;
            sync_once(&restored.client).await?;
            execute(&restored.client, &request).await?
        }
    };
    print_warnings(&outcome.warnings);
    if args.json {
        println!(
            "{}",
            json_line(&json!({
                "event_id": outcome.event_id,
                "replaces": outcome.replaces,
                "room_id": outcome.room_id,
                "encrypted": outcome.encrypted,
            }))?
        );
    } else {
        println!("{}", term(&outcome.event_id));
    }
    Ok(())
}

/// What an edit is reported as, on the direct path and in the daemon's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditOutcome {
    pub event_id: String,
    pub replaces: String,
    pub room_id: String,
    pub encrypted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Carry out an "edit" request with `client`, which must have been built
/// with [`key_sharing`] of the request's `trust_unverified_devices`. The
/// message type is the original's; a `msgtype` in the request is ignored.
pub async fn execute(client: &Client, request: &Value) -> Result<EditOutcome> {
    let room = resolve_room(client, request_str(request, "room")?).await?;
    let event_id = parse_event_id(request_str(request, "event_id")?)?;
    let own = client
        .user_id()
        .context("the client has no user id")?
        .to_owned();

    let (fetched, original) = fetch_event(&room, &event_id).await?;
    let kind = check_editable(&original, &own)?;
    // The wire type: a decrypted original reads m.room.message in its JSON.
    let original_encrypted = fetched.encryption_info().is_some() || fetched.kind.is_utd();

    let body = request_str(request, "body")?;
    let content = match kind {
        EditKind::Text => RoomMessageEventContent::text_plain(body),
        EditKind::Notice => RoomMessageEventContent::notice_plain(body),
        EditKind::Emote => RoomMessageEventContent::emote_plain(body),
    }
    .make_replacement(ReplacementMetadata::new(event_id.clone(), None));
    let Sent {
        event_id: edit_id,
        encrypted,
        warnings,
    } = send_guarded(
        &room,
        content,
        request_trusts_unverified(request),
        "edit",
        |encrypt| check_same_encryption(original_encrypted, encrypt),
    )
    .await?;
    Ok(EditOutcome {
        event_id: edit_id.to_string(),
        replaces: event_id.to_string(),
        room_id: room.room_id().to_string(),
        encrypted,
        warnings,
    })
}

/// Refuse an edit whose wire type would differ from the original's: the
/// server aggregates a replacement only when both have the same event type
/// (`m.room.message` or `m.room.encrypted`). A plaintext message from before
/// the room was encrypted cannot be edited; the edit is never sent in
/// plaintext to match.
pub fn check_same_encryption(original_encrypted: bool, edit_encrypted: bool) -> Result<()> {
    match (original_encrypted, edit_encrypted) {
        (false, true) => bail!(
            "the message was sent unencrypted before the room was encrypted; an encrypted edit would not replace it, and the edit is never sent unencrypted, so it cannot be edited"
        ),
        (true, false) => bail!(
            "the message was sent encrypted, but the room is not encrypted now; an unencrypted edit would not replace it"
        ),
        _ => Ok(()),
    }
}

/// Whether the event (its JSON as fetched, decrypted where possible) is a
/// message of `own` that can be edited, and which message type the edit
/// keeps. Refuses someone else's event, an event this device cannot decrypt
/// (its type is unknown), a state event, an edit (edit the original
/// instead), and anything but a text, notice or emote message.
pub fn check_editable(event: &Value, own: &UserId) -> Result<EditKind> {
    let sender = event_sender(event)?;
    if sender != own.as_str() {
        bail!("the event was sent by {sender}, not by {own}; only your own messages can be edited");
    }
    if super::is_redacted(event) {
        bail!("the event was redacted; there is nothing left to edit");
    }
    let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
    match event_type {
        "m.room.message" => {}
        "m.room.encrypted" => bail!(
            "this device cannot decrypt the event, so it cannot tell what it would replace; run backup-restore to import the room key"
        ),
        other => bail!("the event is a {other:?} event, not a message"),
    }
    if event.get("state_key").is_some() {
        bail!("the event is a state event, not a message");
    }
    let content = event.get("content");
    let relation = content
        .and_then(|c| c.get("m.relates_to"))
        .and_then(|r| r.get("rel_type"))
        .and_then(Value::as_str);
    if relation == Some("m.replace") {
        bail!("the event is itself an edit; edit the original message instead");
    }
    match content
        .and_then(|c| c.get("msgtype"))
        .and_then(Value::as_str)
    {
        Some("m.text") => Ok(EditKind::Text),
        Some("m.notice") => Ok(EditKind::Notice),
        Some("m.emote") => Ok(EditKind::Emote),
        Some(other) => bail!("only text, notice and emote messages can be edited, not {other:?}"),
        None => bail!("the event has no message type (redacted?); nothing to edit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own() -> matrix_sdk::ruma::OwnedUserId {
        UserId::parse("@me:example.org").unwrap()
    }

    fn message(sender: &str, msgtype: &str) -> Value {
        json!({
            "type": "m.room.message",
            "event_id": "$e:example.org",
            "sender": sender,
            "origin_server_ts": 1u64,
            "content": {"msgtype": msgtype, "body": "hi"}
        })
    }

    #[test]
    fn own_text_notice_and_emote_are_editable() {
        assert_eq!(
            check_editable(&message("@me:example.org", "m.text"), &own()).unwrap(),
            EditKind::Text
        );
        assert_eq!(
            check_editable(&message("@me:example.org", "m.notice"), &own()).unwrap(),
            EditKind::Notice
        );
        assert_eq!(
            check_editable(&message("@me:example.org", "m.emote"), &own()).unwrap(),
            EditKind::Emote
        );
    }

    #[test]
    fn someone_elses_message_is_refused() {
        let err = check_editable(&message("@other:example.org", "m.text"), &own())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("@other:example.org") && err.contains("only your own"),
            "{err}"
        );
        // No case folding: the server sends canonical ids.
        assert!(check_editable(&message("@Me:example.org", "m.text"), &own()).is_err());
        let mut no_sender = message("@me:example.org", "m.text");
        no_sender.as_object_mut().unwrap().remove("sender");
        assert!(check_editable(&no_sender, &own()).is_err());
    }

    #[test]
    fn undecryptable_state_and_edit_events_are_refused() {
        let encrypted = json!({
            "type": "m.room.encrypted", "sender": "@me:example.org",
            "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x"}
        });
        assert!(
            check_editable(&encrypted, &own())
                .unwrap_err()
                .to_string()
                .contains("decrypt")
        );
        let topic = json!({"type": "m.room.topic", "sender": "@me:example.org", "state_key": "", "content": {"topic": "t"}});
        assert!(check_editable(&topic, &own()).is_err());
        let mut edit = message("@me:example.org", "m.text");
        edit["content"]["m.relates_to"] = json!({"rel_type": "m.replace", "event_id": "$o"});
        assert!(
            check_editable(&edit, &own())
                .unwrap_err()
                .to_string()
                .contains("original")
        );
    }

    #[test]
    fn state_events_of_message_type_are_refused() {
        for key in ["", "status"] {
            let mut state = message("@me:example.org", "m.text");
            state["state_key"] = json!(key);
            let err = check_editable(&state, &own()).unwrap_err().to_string();
            assert!(err.contains("state event"), "{key:?}: {err}");
        }
    }

    #[test]
    fn the_edit_keeps_the_original_wire_type() {
        assert!(check_same_encryption(false, false).is_ok());
        assert!(check_same_encryption(true, true).is_ok());
        let err = check_same_encryption(false, true).unwrap_err().to_string();
        assert!(
            err.contains("unencrypted before the room was encrypted"),
            "{err}"
        );
        assert!(check_same_encryption(true, false).is_err());
    }

    #[test]
    fn media_and_redacted_messages_are_refused() {
        assert!(check_editable(&message("@me:example.org", "m.image"), &own()).is_err());
        let redacted =
            json!({"type": "m.room.message", "sender": "@me:example.org", "content": {}});
        assert!(check_editable(&redacted, &own()).is_err());
    }
}
