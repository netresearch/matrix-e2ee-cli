//! `read`: the last messages of a room, decrypted where possible.
//!
//! Output at parity with the matrix-skill's `matrix-read-e2ee.py` (matrix-nio):
//! the same order (newest first), the same JSON fields and values, and the
//! same text line layout.

use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{Local, TimeZone};
use matrix_sdk::config::SyncSettings;
use matrix_sdk::deserialized_responses::{
    DeviceLinkProblem, TimelineEvent, TimelineEventKind, VerificationLevel, VerificationState,
};
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::UInt;
use matrix_sdk::{Client, EncryptionState, Room};
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::ReadArgs;
use crate::commands::{resolve_room, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{python_json, term, term_body};

/// The body of an event this device cannot decrypt (Python's spelling).
pub const UNDECRYPTABLE: &str = "[Unable to decrypt]";

/// One message, with the fields of matrix-read-e2ee.py's `process_event` in
/// Python's order, then the CLI's own fields.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Line {
    pub sender: String,
    pub body: String,
    pub msgtype: String,
    pub timestamp: u64,
    pub event_id: String,
    /// Python's value, which is not "was encrypted": matrix-nio turns m.text
    /// and m.emote into classes the script reports as `false` (decrypted or
    /// not), every other m.room.message (notices, media, redacted messages)
    /// as `true`, and an undecryptable event as `true`. `decrypted` and
    /// `room_encrypted` carry the real state.
    pub encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted_body: Option<String>,
    /// Media messages: the mxc URL (`file.url` for an encrypted file), never
    /// the file's decryption key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Value>,
    /// Media messages: `mimetype`, `size`, `w` and `h` of `content.info`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<OrderedMap>,
    /// Undecryptable events: the Megolm session (`null` if the event names none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Option<String>>,
    /// The event was encrypted and this device decrypted it.
    pub decrypted: bool,
    /// Decrypted, and matrix-sdk links the sending device to a verified
    /// identity (`VerificationState::Verified`).
    pub sender_verified: bool,
    /// The room is encrypted (an unknown state counts as encrypted).
    pub room_encrypted: bool,
    /// The event was encrypted (decrypted or not); drives the text marks.
    #[serde(skip)]
    pub was_encrypted: bool,
}

impl Line {
    pub fn is_undecryptable(&self) -> bool {
        self.session_id.is_some()
    }
}

/// A JSON object that keeps the order of its keys as received (serde_json's
/// own map sorts them; Python keeps the sender's order).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OrderedMap(pub Vec<(String, Value)>);

impl Serialize for OrderedMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for OrderedMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = OrderedMap;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<OrderedMap, A::Error> {
                let mut entries = Vec::new();
                while let Some((k, v)) = access.next_entry::<String, Value>()? {
                    entries.push((k, v));
                }
                Ok(OrderedMap(entries))
            }
        }
        deserializer.deserialize_map(V)
    }
}

/// Prefix in text mode: unencrypted events in an encrypted room, and
/// decrypted events whose sending device is not verified.
pub const UNENCRYPTED_MARK: &str = "[unencrypted] ";
pub const UNVERIFIED_MARK: &str = "[unverified device] ";

/// Python's text output for an empty result.
pub const NO_MESSAGES: &str = "No messages found";

/// --request-keys: rounds of (wait, sync) before the second read, as
/// matrix-read-e2ee.py does (6 x 5 s, each sync long-polling 5 s).
pub const KEY_WAIT_ROUNDS: u32 = 6;
pub const KEY_WAIT_INTERVAL: Duration = Duration::from_secs(5);
pub const KEY_WAIT_SYNC_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run(args: ReadArgs) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let room = resolve_room(&client, &args.room).await?;
    let room_encrypted = room_encrypted(&room).await?;

    // Room::messages() decrypts each event; for one without its key,
    // matrix-sdk queues a key request to our other devices
    // (automatic-room-key-forwarding), which the next sync sends.
    let mut lines = fetch_lines(&room, args.limit, room_encrypted).await?;
    if args.request_keys && lines.iter().any(Line::is_undecryptable) {
        warn_without_verified_device(&client).await;
        key_wait_rounds(KEY_WAIT_ROUNDS, KEY_WAIT_INTERVAL, || {
            sync_with_timeout(&client, KEY_WAIT_SYNC_TIMEOUT)
        })
        .await;
        lines = fetch_lines(&room, args.limit, room_encrypted).await?;
    }
    print!("{}", render(&lines, args.json)?);
    Ok(())
}

/// The whole output: one JSON array (Python's `json.dumps(messages, indent=2)`),
/// or one text line per message, each followed by a newline.
pub fn render(lines: &[Line], json: bool) -> Result<String> {
    if json {
        return Ok(python_json(&lines)? + "\n");
    }
    if lines.is_empty() {
        return Ok(format!("{NO_MESSAGES}\n"));
    }
    Ok(lines.iter().map(|l| text_line(l) + "\n").collect())
}

pub async fn room_encrypted(room: &Room) -> Result<bool> {
    Ok(
        match room
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
        },
    )
}

/// The last `limit` timeline events of `room` as the server returns them
/// (/messages backwards: newest first, Python's order).
pub async fn fetch_events(room: &Room, limit: u32) -> Result<Vec<TimelineEvent>> {
    let mut options = MessagesOptions::backward();
    options.limit = UInt::from(limit);
    Ok(room
        .messages(options)
        .await
        .context("cannot fetch messages")?
        .chunk)
}

async fn fetch_lines(room: &Room, limit: u32, room_encrypted: bool) -> Result<Vec<Line>> {
    Ok(lines_of(&fetch_events(room, limit).await?, room_encrypted))
}

/// The messages among `events`, in the order given (no re-sorting: Python
/// prints the server's newest-first order).
pub fn lines_of(events: &[TimelineEvent], room_encrypted: bool) -> Vec<Line> {
    events
        .iter()
        .filter_map(|e| to_line(e, room_encrypted))
        .collect()
}

/// One sync that long-polls up to `timeout`; it sends queued key requests first.
pub async fn sync_with_timeout(client: &Client, timeout: Duration) -> Result<()> {
    client
        .sync_once(SyncSettings::default().timeout(timeout))
        .await
        .context("sync failed")?;
    Ok(())
}

/// `rounds` times: wait `interval`, then sync. A failed sync is reported
/// and the next round runs, as in Python, where a sync error is a return
/// value nobody checks.
pub async fn key_wait_rounds<S, F>(rounds: u32, interval: Duration, mut sync: S)
where
    S: FnMut() -> F,
    F: Future<Output = Result<()>>,
{
    for _ in 0..rounds {
        tokio::time::sleep(interval).await;
        if let Err(err) = sync().await {
            eprintln!("warning: {}", term(&format!("{err:#}")));
        }
    }
}

/// matrix-sdk sends a key request only when one of our other devices is
/// verified (matrix-sdk-crypto gossiping/machine.rs, should_request_key).
/// Say so instead of waiting in silence for keys nobody was asked for.
pub async fn warn_without_verified_device(client: &Client) {
    let (Some(user), Some(own)) = (client.user_id(), client.device_id()) else {
        return;
    };
    let any = match client.encryption().get_user_devices(user).await {
        Ok(devices) => devices
            .devices()
            .any(|d| d.device_id() != own && d.is_verified()),
        Err(_) => return,
    };
    if !any {
        eprintln!(
            "warning: none of your other devices is verified; matrix-sdk sends no key request without one"
        );
    }
}

/// Python's `format_timestamp`: local time `YYYY-MM-DD HH:MM`, `unknown` for 0.
fn stamp(ms: u64) -> String {
    if ms == 0 {
        return "unknown".to_owned();
    }
    i64::try_from(ms)
        .ok()
        .and_then(|ms| Local.timestamp_millis_opt(ms).single())
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Python's cut: more than 100 characters become the first 100 plus "...".
pub fn shorten(body: &str) -> std::borrow::Cow<'_, str> {
    match body.char_indices().nth(100) {
        Some((cut, _)) => format!("{}...", &body[..cut]).into(),
        None => body.into(),
    }
}

/// One line of text output: `[YYYY-MM-DD HH:MM] sender: body` with the body cut
/// as Python cuts it, control characters of sender and body replaced, and
/// marks for unencrypted events and unverified sending devices.
pub fn text_line(line: &Line) -> String {
    let mark = if line.room_encrypted && !line.was_encrypted {
        UNENCRYPTED_MARK
    } else if line.decrypted && !line.sender_verified {
        UNVERIFIED_MARK
    } else {
        ""
    };
    format!(
        "[{}] {mark}{}: {}",
        stamp(line.timestamp),
        term(&line.sender),
        term_body(&shorten(&line.body))
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

/// The parts of an event's JSON the output needs. `info` stays raw, so its
/// key order survives and a non-object `info` does not drop the event.
#[derive(Deserialize, Default)]
struct RawEvent {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    event_id: String,
    #[serde(default)]
    sender: String,
    #[serde(default)]
    origin_server_ts: u64,
    #[serde(default)]
    content: RawContent,
    #[serde(default)]
    unsigned: Option<Value>,
}

#[derive(Deserialize, Default)]
struct RawContent {
    body: Option<Value>,
    msgtype: Option<Value>,
    format: Option<Value>,
    formatted_body: Option<Value>,
    url: Option<Value>,
    file: Option<Value>,
    info: Option<Box<RawValue>>,
    session_id: Option<Value>,
}

fn string(v: &Option<Value>) -> Option<String> {
    v.as_ref().and_then(Value::as_str).map(str::to_owned)
}

/// Python's `rich_text_fields`: a non-empty string, else nothing.
fn rich(v: &Option<Value>) -> Option<String> {
    string(v).filter(|s| !s.is_empty())
}

/// A printable line for a message event or an undecryptable event; `None`
/// for everything else (state events, reactions, redactions, redacted
/// encrypted events, ...), as matrix-read-e2ee.py's `process_event`.
pub fn to_line(event: &TimelineEvent, room_encrypted: bool) -> Option<Line> {
    let raw: RawEvent = serde_json::from_str(event.raw().json().get()).ok()?;
    let redacted = raw
        .unsigned
        .as_ref()
        .is_some_and(|u| u.get("redacted_because").is_some());
    let info = event.encryption_info();
    let decrypted = matches!(event.kind, TimelineEventKind::Decrypted(_));
    let sender_verified = info.is_some_and(|i| is_verified(&i.verification_state));
    let base = |body: String, msgtype: &str, encrypted: bool| Line {
        sender: raw.sender.clone(),
        body,
        msgtype: msgtype.to_owned(),
        timestamp: raw.origin_server_ts,
        event_id: raw.event_id.clone(),
        encrypted,
        format: None,
        formatted_body: None,
        url: None,
        info: None,
        session_id: None,
        decrypted,
        sender_verified,
        room_encrypted,
        was_encrypted: info.is_some(),
    };
    match raw.kind.as_str() {
        // Room::messages() can hand an event it could not decrypt back as
        // plain text, so the type decides, not the kind. A redacted
        // encrypted event has no ciphertext left: matrix-nio skips it.
        "m.room.encrypted" if !decrypted && !redacted => Some(Line {
            body: UNDECRYPTABLE.to_owned(),
            decrypted: false,
            sender_verified: false,
            was_encrypted: true,
            session_id: Some(string(&raw.content.session_id)),
            ..base(String::new(), "m.room.encrypted", true)
        }),
        "m.room.message" if redacted => Some(base(String::new(), "m.text", true)),
        "m.room.message" => {
            let c = &raw.content;
            let body = string(&c.body);
            let msgtype = string(&c.msgtype);
            let rich_line = |line: Line| Line {
                format: rich(&c.format),
                formatted_body: rich(&c.formatted_body),
                ..line
            };
            match (msgtype.as_deref(), body) {
                // matrix-nio's RoomMessageText / RoomMessageEmote.
                (Some(t @ ("m.text" | "m.emote")), Some(body)) => {
                    Some(rich_line(base(body, t, false)))
                }
                // Every other m.room.message: Python's generic branch.
                (msgtype, body) => {
                    let mut line = rich_line(base(
                        body.unwrap_or_default(),
                        msgtype.unwrap_or("m.text"),
                        true,
                    ));
                    line.url = match &c.file {
                        Some(file) => Some(
                            file.get("url")
                                .cloned()
                                .unwrap_or_else(|| Value::String(String::new())),
                        ),
                        None => c.url.clone(),
                    };
                    line.info = c
                        .info
                        .as_ref()
                        .and_then(|i| serde_json::from_str::<OrderedMap>(i.get()).ok())
                        .map(|OrderedMap(all)| {
                            OrderedMap(
                                all.into_iter()
                                    .filter(|(k, _)| {
                                        matches!(k.as_str(), "mimetype" | "size" | "w" | "h")
                                    })
                                    .collect(),
                            )
                        });
                    Some(line)
                }
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::deserialized_responses::{
        AlgorithmInfo, DecryptedRoomEvent, EncryptionInfo, UnableToDecryptInfo,
    };
    use matrix_sdk::ruma::events::AnySyncTimelineEvent;
    use matrix_sdk::ruma::serde::Raw;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn decrypted_value(value: serde_json::Value, state: VerificationState) -> TimelineEvent {
        let mut value = value;
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

    fn decrypted(body: &str, state: VerificationState) -> TimelineEvent {
        decrypted_value(message("m.text", body), state)
    }

    fn plain(value: serde_json::Value) -> TimelineEvent {
        TimelineEvent::from_plaintext(raw(value))
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

    fn encrypted(event_id: &str, session_id: &str) -> serde_json::Value {
        json!({
            "type": "m.room.encrypted",
            "event_id": event_id,
            "sender": "@b:example",
            "origin_server_ts": 5u64,
            "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x",
                        "session_id": session_id, "sender_key": "k", "device_id": "D"}
        })
    }

    fn utd(event_id: &str, session_id: &str) -> TimelineEvent {
        TimelineEvent::from_utd(
            raw(encrypted(event_id, session_id)),
            serde_json::from_value::<UnableToDecryptInfo>(json!({"session_id": session_id}))
                .unwrap(),
        )
    }

    fn json_of(event: &TimelineEvent) -> serde_json::Value {
        serde_json::to_value(to_line(event, true).expect("a line")).unwrap()
    }

    #[test]
    fn text_output_neutralises_control_characters() {
        let mut value = message(
            "m.text",
            "hi\x1b[2J\r\n[12:00] @boss:example: wire money\u{009b}",
        );
        value["sender"] = json!("@a\u{0007}:example");
        let ev = plain(value);
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
        let json = render(&[to_line(&ev, false).unwrap()], true).unwrap();
        assert!(json.contains("\\u001b[2J\\r\\n"), "{json}");
    }

    #[test]
    fn json_escapes_del_and_c1_and_keeps_the_body() {
        let body = "a\u{7f}b\u{9b}2Jc\u{80}\u{9f}\u{a0}d";
        let ev = plain(message("m.text", body));
        let json = render(&[to_line(&ev, false).unwrap()], true).unwrap();
        assert!(json.is_ascii(), "raw non-ASCII in {json:?}");
        assert!(
            json.contains("a\\u007fb\\u009b2Jc\\u0080\\u009f\\u00a0d"),
            "{json}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["body"], body);
    }

    #[test]
    fn unencrypted_event_in_encrypted_room_is_marked() {
        let ev = plain(message("m.text", "hi"));
        let line = to_line(&ev, true).unwrap();
        assert!(line.room_encrypted && !line.was_encrypted && !line.sender_verified);
        assert!(text_line(&line).contains(&format!("{UNENCRYPTED_MARK}@a:example: hi")));
        // In an unencrypted room there is nothing to mark.
        let line = to_line(&ev, false).unwrap();
        assert!(!text_line(&line).contains(UNENCRYPTED_MARK));
        // A notice is Python's "encrypted": true, but it was sent in clear:
        // the mark follows what happened, not Python's field.
        let notice = to_line(&plain(message("m.notice", "hi")), true).unwrap();
        assert!(notice.encrypted);
        assert!(text_line(&notice).contains(UNENCRYPTED_MARK));
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

    #[test]
    fn notice_is_python_generic_branch() {
        let ev = plain(message("m.notice", "hello"));
        assert_eq!(
            to_line(&ev, false),
            Some(Line {
                sender: "@a:example".into(),
                body: "hello".into(),
                msgtype: "m.notice".into(),
                timestamp: 1_700_000_000_000,
                event_id: "$e1".into(),
                // matrix-nio's RoomMessageNotice falls into Python's
                // generic branch, which says true.
                encrypted: true,
                format: None,
                formatted_body: None,
                url: None,
                info: None,
                session_id: None,
                decrypted: false,
                sender_verified: false,
                room_encrypted: false,
                was_encrypted: false,
            })
        );
    }

    #[test]
    fn python_encrypted_is_false_for_text_and_emote_even_when_decrypted() {
        let line = to_line(&decrypted("hi", VerificationState::Verified), true).unwrap();
        assert!(!line.encrypted && line.decrypted && line.was_encrypted);
        let emote = to_line(&plain(message("m.emote", "waves")), true).unwrap();
        assert_eq!(
            (emote.msgtype.as_str(), emote.encrypted),
            ("m.emote", false)
        );
        let image = decrypted_value(message("m.image", "p.png"), VerificationState::Verified);
        let image = to_line(&image, true).unwrap();
        assert!(image.encrypted && image.decrypted);
    }

    #[test]
    fn undecryptable_event_is_a_marker_not_an_error() {
        let line = to_line(&utd("$e2", "s"), true).unwrap();
        assert_eq!(line.body, "[Unable to decrypt]");
        assert_eq!(
            (line.event_id.as_str(), line.sender.as_str(), line.timestamp),
            ("$e2", "@b:example", 5)
        );
        assert!(line.encrypted && !line.decrypted && line.was_encrypted);
        assert_eq!(line.session_id, Some(Some("s".to_owned())));
        assert_eq!(line.msgtype, "m.room.encrypted");
    }

    #[test]
    fn encrypted_event_returned_as_plain_text_is_a_marker() {
        let line = to_line(&plain(encrypted("$e4", "s")), true)
            .expect("an encrypted event must not be dropped");
        assert_eq!(line.body, UNDECRYPTABLE);
        assert!(line.encrypted && !line.decrypted);
        assert!(line.is_undecryptable());
    }

    #[test]
    fn non_message_events_are_skipped() {
        let state = json!({
            "type": "m.room.topic", "state_key": "", "event_id": "$e3",
            "sender": "@a:example", "origin_server_ts": 1u64, "content": {"topic": "t"}
        });
        assert_eq!(to_line(&plain(state), true), None);
    }

    #[test]
    fn redacted_events_follow_matrix_nio() {
        // A redacted m.room.message: nio's RedactedEvent, Python's generic
        // branch with empty content.
        let mut gone = message("m.text", "x");
        gone["content"] = json!({});
        gone["unsigned"] = json!({"redacted_because": {"type": "m.room.redaction"}});
        let line = to_line(&plain(gone), false).unwrap();
        assert_eq!(
            (line.body.as_str(), line.msgtype.as_str(), line.encrypted),
            ("", "m.text", true)
        );
        // A redacted encrypted event: nio skips it.
        let mut enc = encrypted("$e5", "s");
        enc["content"] = json!({});
        enc["unsigned"] = json!({"redacted_because": {"type": "m.room.redaction"}});
        assert_eq!(to_line(&plain(enc), true), None);
    }

    #[test]
    fn rich_text_fields_as_python_takes_them() {
        let mut value = message("m.text", "hi");
        value["content"]["format"] = json!("org.matrix.custom.html");
        value["content"]["formatted_body"] = json!("<b>hi</b>");
        let json = json_of(&plain(value.clone()));
        assert_eq!(json["format"], "org.matrix.custom.html");
        assert_eq!(json["formatted_body"], "<b>hi</b>");
        // Empty or non-string values are dropped, as rich_text_fields does.
        value["content"]["format"] = json!(5);
        value["content"]["formatted_body"] = json!("");
        let json = json_of(&plain(value));
        assert!(json.get("format").is_none() && json.get("formatted_body").is_none());
        // The undecryptable branch carries none.
        assert!(json_of(&utd("$e2", "s")).get("format").is_none());
    }

    #[test]
    fn media_carries_url_and_filtered_info_in_sender_order() {
        // From a string: json!() would sort the keys before the test starts.
        let value = r#"{"type": "m.room.message", "event_id": "$m", "sender": "@a:example",
            "origin_server_ts": 6,
            "content": {"msgtype": "m.image", "body": "p.png",
                "file": {"url": "mxc://example/f", "key": {"k": "SECRET"}, "iv": "i"},
                "info": {"w": 2, "thumbnail_url": "mxc://t", "h": 1,
                         "mimetype": "image/png", "size": 7}}}"#;
        let event = TimelineEvent::from_plaintext(Raw::from_json_string(value.to_owned()).unwrap());
        let line = to_line(&event, true).unwrap();
        let shown = render(&[line], true).unwrap();
        assert!(
            shown.contains(
                "\"url\": \"mxc://example/f\",\n    \"info\": {\n      \"w\": 2,\n      \"h\": 1,\n      \"mimetype\": \"image/png\",\n      \"size\": 7\n    },"
            ),
            "{shown}"
        );
        assert!(
            !shown.contains("SECRET") && !shown.contains("thumbnail_url"),
            "{shown}"
        );
        // An unencrypted file: content.url.
        let value = json!({
            "type": "m.room.message", "event_id": "$m", "sender": "@a:example",
            "origin_server_ts": 6u64,
            "content": {"msgtype": "m.file", "body": "f", "url": "mxc://example/g"}
        });
        assert_eq!(json_of(&plain(value))["url"], "mxc://example/g");
        // m.text is not the media branch: no url even when one is there.
        let mut text = message("m.text", "hi");
        text["content"]["url"] = json!("mxc://example/h");
        assert!(json_of(&plain(text)).get("url").is_none());
    }

    #[test]
    fn json_output_is_python_json_dumps_of_the_list() {
        // python3: json.dumps(messages, indent=2), messages as
        // matrix-read-e2ee.py builds them, plus the CLI's three fields.
        let mut text = message("m.text", "Grüße 🙂");
        text["content"]["format"] = json!("org.matrix.custom.html");
        text["content"]["formatted_body"] = json!("<b>Grüße</b>");
        let lines = [
            to_line(&plain(text), true).unwrap(),
            to_line(&utd("$e2", "s"), true).unwrap(),
        ];
        let expected = "[\n  {\n    \"sender\": \"@a:example\",\n    \"body\": \"Gr\\u00fc\\u00dfe \\ud83d\\ude42\",\n    \"msgtype\": \"m.text\",\n    \"timestamp\": 1700000000000,\n    \"event_id\": \"$e1\",\n    \"encrypted\": false,\n    \"format\": \"org.matrix.custom.html\",\n    \"formatted_body\": \"<b>Gr\\u00fc\\u00dfe</b>\",\n    \"decrypted\": false,\n    \"sender_verified\": false,\n    \"room_encrypted\": true\n  },\n  {\n    \"sender\": \"@b:example\",\n    \"body\": \"[Unable to decrypt]\",\n    \"msgtype\": \"m.room.encrypted\",\n    \"timestamp\": 5,\n    \"event_id\": \"$e2\",\n    \"encrypted\": true,\n    \"session_id\": \"s\",\n    \"decrypted\": false,\n    \"sender_verified\": false,\n    \"room_encrypted\": true\n  }\n]\n";
        assert_eq!(render(&lines, true).unwrap(), expected);
    }

    #[test]
    fn callers_get_a_list_they_can_search_by_body() {
        // ticket-flow.py: json.loads(r.stdout) must be a list.
        // claiming-a-ticket.md: find an event by its body.
        assert_eq!(render(&[], true).unwrap(), "[]\n");
        let events = [plain(message("m.text", "claim NRS-1")), utd("$e2", "s")];
        let parsed: serde_json::Value =
            serde_json::from_str(&render(&lines_of(&events, true), true).unwrap()).unwrap();
        let list = parsed.as_array().expect("a JSON array");
        let hit = list.iter().find(|m| m["body"] == "claim NRS-1").unwrap();
        assert_eq!(hit["event_id"], "$e1");
    }

    #[test]
    fn events_keep_the_servers_newest_first_order() {
        let mut older = message("m.text", "older");
        older["event_id"] = json!("$old");
        let mut newer = message("m.text", "newer");
        newer["event_id"] = json!("$new");
        // /messages backwards: newest first, as Python prints it.
        let lines = lines_of(&[plain(newer), plain(older)], false);
        let ids: Vec<_> = lines.iter().map(|l| l.event_id.as_str()).collect();
        assert_eq!(ids, ["$new", "$old"]);
    }

    #[test]
    fn text_output_has_pythons_layout() {
        assert_eq!(render(&[], false).unwrap(), "No messages found\n");
        let line = to_line(&plain(message("m.text", "hi")), false).unwrap();
        let shown = render(&[line], false).unwrap();
        // [YYYY-MM-DD HH:MM] sender: body
        let stamp_text = &shown[1..17];
        assert!(
            stamp_text.chars().enumerate().all(|(i, c)| match i {
                4 | 7 => c == '-',
                10 => c == ' ',
                13 => c == ':',
                _ => c.is_ascii_digit(),
            }),
            "{shown:?}"
        );
        assert!(shown.ends_with("] @a:example: hi\n"), "{shown:?}");
        assert_eq!(stamp(0), "unknown");
    }

    #[test]
    fn long_bodies_are_cut_at_100_characters() {
        let long = "é".repeat(101);
        assert_eq!(shorten(&long), format!("{}...", "é".repeat(100)));
        let exact = "é".repeat(100);
        assert_eq!(shorten(&exact), exact);
        let line = to_line(&plain(message("m.text", &long)), false).unwrap();
        assert!(text_line(&line).ends_with(&format!("{}...", "é".repeat(100))));
        // JSON keeps the whole body.
        assert_eq!(json_of(&plain(message("m.text", &long)))["body"], long);
    }

    #[tokio::test]
    async fn key_wait_runs_six_rounds_and_survives_a_failed_sync() {
        let calls = std::cell::Cell::new(0u32);
        key_wait_rounds(KEY_WAIT_ROUNDS, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n == 2 {
                    anyhow::bail!("sync failed")
                }
                Ok(())
            }
        })
        .await;
        assert_eq!(calls.get(), 6);
        assert_eq!(
            (KEY_WAIT_INTERVAL, KEY_WAIT_SYNC_TIMEOUT),
            (Duration::from_secs(5), Duration::from_secs(5))
        );
    }
}
