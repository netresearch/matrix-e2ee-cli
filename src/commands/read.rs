//! `read`: the last messages of a room, decrypted where possible.

use anyhow::{Context, Result};
use chrono::{Local, TimeZone};
use matrix_sdk::deserialized_responses::{TimelineEvent, TimelineEventKind};
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::UInt;
use matrix_sdk::ruma::events::{AnySyncMessageLikeEvent, AnySyncTimelineEvent};
use matrix_sdk::ruma::serde::Raw;
use serde::Serialize;

use crate::ReadArgs;
use crate::commands::{resolve_room, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};

pub const UNDECRYPTABLE: &str = "[unable to decrypt]";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Line {
    pub event_id: String,
    pub sender: String,
    pub timestamp: u64,
    pub body: String,
    pub msgtype: String,
    /// The event was encrypted and this device decrypted it.
    pub decrypted: bool,
    /// The event was encrypted (decrypted or not).
    pub encrypted: bool,
}

pub async fn run(args: ReadArgs) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let room = resolve_room(&client, &args.room).await?;

    let mut options = MessagesOptions::backward();
    options.limit = UInt::from(args.limit);
    let messages = room
        .messages(options)
        .await
        .context("cannot fetch messages")?;

    // /messages backwards returns newest first; print oldest first.
    for event in messages.chunk.iter().rev() {
        let Some(line) = to_line(event) else { continue };
        if args.json {
            println!("{}", serde_json::to_string(&line)?);
        } else {
            println!("[{}] {}: {}", hh_mm(line.timestamp), line.sender, line.body);
        }
    }
    Ok(())
}

fn hh_mm(ms: u64) -> String {
    i64::try_from(ms)
        .ok()
        .and_then(|ms| Local.timestamp_millis_opt(ms).single())
        .map(|t| t.format("%H:%M").to_string())
        .unwrap_or_else(|| "--:--".to_owned())
}

/// A printable line for a message event or an undecryptable event; `None`
/// for everything else (state events, reactions, redactions, ...).
pub fn to_line(event: &TimelineEvent) -> Option<Line> {
    // Room::messages() hands an event it could not decrypt back as plain
    // text when decrypt_event() fails with an error, so check the type too.
    let still_encrypted = event
        .raw()
        .get_field::<String>("type")
        .ok()
        .flatten()
        .as_deref()
        == Some("m.room.encrypted");
    match &event.kind {
        TimelineEventKind::PlainText { event: raw } if still_encrypted => Some(undecryptable(raw)),
        TimelineEventKind::UnableToDecrypt { event: raw, .. } => Some(undecryptable(raw)),
        TimelineEventKind::Decrypted(_) | TimelineEventKind::PlainText { .. } => {
            let encrypted = event.encryption_info().is_some();
            let parsed = event.raw().deserialize().ok()?;
            message_line(&parsed, encrypted)
        }
    }
}

fn undecryptable(raw: &Raw<AnySyncTimelineEvent>) -> Line {
    Line {
        event_id: raw
            .get_field::<String>("event_id")
            .ok()
            .flatten()
            .unwrap_or_default(),
        sender: raw
            .get_field::<String>("sender")
            .ok()
            .flatten()
            .unwrap_or_default(),
        timestamp: raw
            .get_field::<u64>("origin_server_ts")
            .ok()
            .flatten()
            .unwrap_or_default(),
        body: UNDECRYPTABLE.to_owned(),
        msgtype: "m.room.encrypted".to_owned(),
        decrypted: false,
        encrypted: true,
    }
}

fn message_line(event: &AnySyncTimelineEvent, encrypted: bool) -> Option<Line> {
    let AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(msg)) = event else {
        return None;
    };
    let original = msg.as_original()?;
    let content = &original.content;
    Some(Line {
        event_id: original.event_id.to_string(),
        sender: original.sender.to_string(),
        timestamp: original.origin_server_ts.0.into(),
        body: content.msgtype.body().to_owned(),
        msgtype: content.msgtype().to_owned(),
        decrypted: encrypted,
        encrypted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::deserialized_responses::UnableToDecryptInfo;
    use serde_json::json;

    fn raw(value: serde_json::Value) -> Raw<AnySyncTimelineEvent> {
        serde_json::from_value(value).unwrap()
    }

    fn message(msgtype: &str, body: &str) -> serde_json::Value {
        json!({
            "type": "m.room.message",
            "event_id": "$e1",
            "sender": "@a:example",
            "origin_server_ts": 1_700_000_000_000u64,
            "content": {"msgtype": msgtype, "body": body}
        })
    }

    #[test]
    fn plaintext_message_becomes_a_line() {
        let ev = TimelineEvent::from_plaintext(raw(message("m.notice", "hello")));
        assert_eq!(
            to_line(&ev),
            Some(Line {
                event_id: "$e1".into(),
                sender: "@a:example".into(),
                timestamp: 1_700_000_000_000,
                body: "hello".into(),
                msgtype: "m.notice".into(),
                decrypted: false,
                encrypted: false,
            })
        );
    }

    #[test]
    fn undecryptable_event_is_a_marker_not_an_error() {
        let ev = TimelineEvent::from_utd(
            raw(json!({
                "type": "m.room.encrypted",
                "event_id": "$e2",
                "sender": "@b:example",
                "origin_server_ts": 5u64,
                "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x",
                            "session_id": "s", "sender_key": "k", "device_id": "D"}
            })),
            serde_json::from_value::<UnableToDecryptInfo>(json!({"session_id": "s"})).unwrap(),
        );
        let line = to_line(&ev).unwrap();
        assert_eq!(line.body, UNDECRYPTABLE);
        assert_eq!(
            (line.event_id.as_str(), line.sender.as_str(), line.timestamp),
            ("$e2", "@b:example", 5)
        );
        assert!(line.encrypted && !line.decrypted);
    }

    #[test]
    fn encrypted_event_returned_as_plain_text_is_a_marker() {
        let ev = TimelineEvent::from_plaintext(raw(json!({
            "type": "m.room.encrypted",
            "event_id": "$e4",
            "sender": "@b:example",
            "origin_server_ts": 7u64,
            "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x",
                        "session_id": "s", "sender_key": "k", "device_id": "D"}
        })));
        let line = to_line(&ev).expect("an encrypted event must not be dropped");
        assert_eq!(line.body, UNDECRYPTABLE);
        assert!(line.encrypted && !line.decrypted);
    }

    #[test]
    fn non_message_events_are_skipped() {
        let state = json!({
            "type": "m.room.topic", "state_key": "", "event_id": "$e3",
            "sender": "@a:example", "origin_server_ts": 1u64, "content": {"topic": "t"}
        });
        assert_eq!(to_line(&TimelineEvent::from_plaintext(raw(state))), None);
    }

    #[test]
    fn json_line_has_the_documented_keys() {
        let ev = TimelineEvent::from_plaintext(raw(message("m.text", "hi")));
        let value = serde_json::to_value(to_line(&ev).unwrap()).unwrap();
        for key in [
            "event_id",
            "sender",
            "timestamp",
            "body",
            "msgtype",
            "decrypted",
        ] {
            assert!(value.get(key).is_some(), "missing {key}");
        }
    }
}
