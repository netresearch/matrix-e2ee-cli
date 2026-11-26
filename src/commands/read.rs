//! `read`: the last messages of a room, decrypted where possible.

use anyhow::{Context, Result};
use chrono::{Local, TimeZone};
use matrix_sdk::EncryptionState;
use matrix_sdk::deserialized_responses::{
    DeviceLinkProblem, TimelineEvent, TimelineEventKind, VerificationLevel, VerificationState,
};
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::UInt;
use matrix_sdk::ruma::events::{AnySyncMessageLikeEvent, AnySyncTimelineEvent};
use matrix_sdk::ruma::serde::Raw;
use serde::Serialize;

use crate::ReadArgs;
use crate::commands::{resolve_room, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term, term_body};

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
    /// Decrypted, and matrix-sdk links the sending device to a verified
    /// identity (`VerificationState::Verified`).
    pub sender_verified: bool,
    /// The room is encrypted (an unknown state counts as encrypted).
    pub room_encrypted: bool,
}

/// Prefix in text mode: unencrypted events in an encrypted room, and
/// decrypted events whose sending device is not verified.
pub const UNENCRYPTED_MARK: &str = "[unencrypted] ";
pub const UNVERIFIED_MARK: &str = "[unverified device] ";

pub async fn run(args: ReadArgs) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let room = resolve_room(&client, &args.room).await?;
    let room_encrypted = match room
        .latest_encryption_state()
        .await
        .context("cannot read the room's encryption state")?
    {
        EncryptionState::Encrypted => true,
        EncryptionState::NotEncrypted => false,
        // Treat it as encrypted, so unencrypted events get marked.
        EncryptionState::Unknown => {
            eprintln!(
                "warning: the encryption state of {} is unknown; treating it as encrypted",
                term(room.room_id().as_str())
            );
            true
        }
    };

    let mut options = MessagesOptions::backward();
    options.limit = UInt::from(args.limit);
    let messages = room
        .messages(options)
        .await
        .context("cannot fetch messages")?;

    // /messages backwards returns newest first; print oldest first.
    for event in messages.chunk.iter().rev() {
        let Some(line) = to_line(event, room_encrypted) else {
            continue;
        };
        if args.json {
            println!("{}", json_line(&line)?);
        } else {
            println!("{}", text_line(&line));
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

/// One line of text output: control characters of sender and body replaced,
/// marks for unencrypted events and unverified sending devices.
pub fn text_line(line: &Line) -> String {
    let mark = if line.room_encrypted && !line.encrypted {
        UNENCRYPTED_MARK
    } else if line.decrypted && !line.sender_verified {
        UNVERIFIED_MARK
    } else {
        ""
    };
    format!(
        "[{}] {mark}{}: {}",
        hh_mm(line.timestamp),
        term(&line.sender),
        term_body(&line.body)
    )
}

/// Only `Verified` counts. Every variant is named, so a new one in a later
/// matrix-sdk is a compile error here instead of a silent default.
fn is_verified(state: &VerificationState) -> bool {
    match state {
        VerificationState::Verified => true,
        VerificationState::Unverified(
            VerificationLevel::UnverifiedIdentity
            | VerificationLevel::VerificationViolation
            | VerificationLevel::UnsignedDevice
            | VerificationLevel::None(
                DeviceLinkProblem::MissingDevice | DeviceLinkProblem::InsecureSource,
            )
            | VerificationLevel::MismatchedSender,
        ) => false,
    }
}

/// A printable line for a message event or an undecryptable event; `None`
/// for everything else (state events, reactions, redactions, ...).
pub fn to_line(event: &TimelineEvent, room_encrypted: bool) -> Option<Line> {
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
        TimelineEventKind::PlainText { event: raw } if still_encrypted => {
            Some(undecryptable(raw, room_encrypted))
        }
        TimelineEventKind::UnableToDecrypt { event: raw, .. } => {
            Some(undecryptable(raw, room_encrypted))
        }
        TimelineEventKind::Decrypted(_) | TimelineEventKind::PlainText { .. } => {
            let info = event.encryption_info();
            let encrypted = info.is_some();
            let sender_verified = info.is_some_and(|i| is_verified(&i.verification_state));
            let parsed = event.raw().deserialize().ok()?;
            message_line(&parsed, encrypted, sender_verified, room_encrypted)
        }
    }
}

fn undecryptable(raw: &Raw<AnySyncTimelineEvent>, room_encrypted: bool) -> Line {
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
        sender_verified: false,
        room_encrypted,
    }
}

fn message_line(
    event: &AnySyncTimelineEvent,
    encrypted: bool,
    sender_verified: bool,
    room_encrypted: bool,
) -> Option<Line> {
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
        sender_verified,
        room_encrypted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::deserialized_responses::{
        AlgorithmInfo, DecryptedRoomEvent, EncryptionInfo, UnableToDecryptInfo,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn decrypted(body: &str, state: VerificationState) -> TimelineEvent {
        let mut value = message("m.text", body);
        value["room_id"] = json!("!r:example");
        TimelineEvent::from_decrypted(
            DecryptedRoomEvent {
                event: serde_json::from_value(value).unwrap(),
                encryption_info: Arc::new(EncryptionInfo {
                    sender: "@a:example".try_into().unwrap(),
                    sender_device: Some("DEV".into()),
                    forwarder: None,
                    algorithm_info: AlgorithmInfo::MegolmV1AesSha2 {
                        curve25519_key: "k".into(),
                        sender_claimed_keys: BTreeMap::new(),
                        session_id: None,
                    },
                    verification_state: state,
                }),
                unsigned_encryption_info: None,
            },
            None,
        )
    }

    #[test]
    fn text_output_neutralises_control_characters() {
        let mut value = message(
            "m.text",
            "hi\x1b[2J\r\n[12:00] @boss:example: wire money\u{009b}",
        );
        value["sender"] = json!("@a\u{0007}:example");
        let ev = TimelineEvent::from_plaintext(raw(value));
        let shown = text_line(&to_line(&ev, false).unwrap());
        // Line breaks survive, but only as an indented continuation: no
        // other control character, and no second line that starts like a
        // message line.
        assert!(
            !shown.chars().any(|c| c.is_control() && c != '\n'),
            "{shown:?}"
        );
        assert!(shown.contains('\u{FFFD}'), "{shown:?}");
        assert!(shown.contains("\n    [12:00] @boss"), "{shown:?}");
        assert!(
            shown.lines().skip(1).all(|l| l.starts_with("    ")),
            "{shown:?}"
        );
        // JSON keeps the body as sent, with every control character escaped.
        let json = json_line(&to_line(&ev, false).unwrap()).unwrap();
        assert!(json.contains("\\u001b[2J\\r\\n"), "{json}");
    }

    #[test]
    fn json_escapes_del_and_c1_and_keeps_the_body() {
        let body = "a\u{7f}b\u{9b}2Jc\u{80}\u{9f}\u{a0}d";
        let ev = TimelineEvent::from_plaintext(raw(message("m.text", body)));
        let json = json_line(&to_line(&ev, false).unwrap()).unwrap();
        assert!(
            !json.chars().any(|c| matches!(c, '\u{7f}'..='\u{9f}')),
            "raw DEL or C1 in {json:?}"
        );
        assert!(
            json.contains("a\\u007fb\\u009b2Jc\\u0080\\u009f\u{a0}d"),
            "{json}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["body"], body);
    }

    #[test]
    fn unencrypted_event_in_encrypted_room_is_marked() {
        let ev = TimelineEvent::from_plaintext(raw(message("m.text", "hi")));
        let line = to_line(&ev, true).unwrap();
        assert!(line.room_encrypted && !line.encrypted && !line.sender_verified);
        assert!(text_line(&line).contains(&format!("{UNENCRYPTED_MARK}@a:example: hi")));
        // In an unencrypted room there is nothing to mark.
        let line = to_line(&ev, false).unwrap();
        assert!(!text_line(&line).contains(UNENCRYPTED_MARK));
    }

    #[test]
    fn decrypted_event_from_an_unverified_device_is_marked() {
        let unverified = [
            VerificationLevel::UnverifiedIdentity,
            VerificationLevel::VerificationViolation,
            VerificationLevel::UnsignedDevice,
            VerificationLevel::None(DeviceLinkProblem::MissingDevice),
            VerificationLevel::None(DeviceLinkProblem::InsecureSource),
            VerificationLevel::MismatchedSender,
        ];
        for level in unverified {
            let ev = decrypted("hi", VerificationState::Unverified(level.clone()));
            let line = to_line(&ev, true).unwrap();
            assert!(line.decrypted && !line.sender_verified, "{level:?}");
            assert!(
                text_line(&line).contains(&format!("{UNVERIFIED_MARK}@a:example: hi")),
                "{level:?}"
            );
        }
        let line = to_line(&decrypted("hi", VerificationState::Verified), true).unwrap();
        assert!(line.decrypted && line.sender_verified);
        let shown = text_line(&line);
        assert!(
            !shown.contains(UNVERIFIED_MARK) && !shown.contains(UNENCRYPTED_MARK),
            "{shown}"
        );
    }

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
            to_line(&ev, false),
            Some(Line {
                event_id: "$e1".into(),
                sender: "@a:example".into(),
                timestamp: 1_700_000_000_000,
                body: "hello".into(),
                msgtype: "m.notice".into(),
                decrypted: false,
                encrypted: false,
                sender_verified: false,
                room_encrypted: false,
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
        let line = to_line(&ev, true).unwrap();
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
        let line = to_line(&ev, true).expect("an encrypted event must not be dropped");
        assert_eq!(line.body, UNDECRYPTABLE);
        assert!(line.encrypted && !line.decrypted);
    }

    #[test]
    fn non_message_events_are_skipped() {
        let state = json!({
            "type": "m.room.topic", "state_key": "", "event_id": "$e3",
            "sender": "@a:example", "origin_server_ts": 1u64, "content": {"topic": "t"}
        });
        assert_eq!(
            to_line(&TimelineEvent::from_plaintext(raw(state)), true),
            None
        );
    }

    #[test]
    fn json_line_has_the_documented_keys() {
        let ev = TimelineEvent::from_plaintext(raw(message("m.text", "hi")));
        let value = serde_json::to_value(to_line(&ev, true).unwrap()).unwrap();
        for key in [
            "event_id",
            "sender",
            "timestamp",
            "body",
            "msgtype",
            "decrypted",
            "sender_verified",
            "room_encrypted",
        ] {
            assert!(value.get(key).is_some(), "missing {key}");
        }
    }
}
