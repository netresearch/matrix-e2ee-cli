//! `read`: the last messages of a room, decrypted where possible.
//!
//! Output at parity with the matrix-skill's `matrix-read-e2ee.py` (matrix-nio):
//! the same order (newest first), the same JSON fields and values, and the
//! same text line layout.
//!
//! Like the writing commands, `read` goes through the watch daemon when one
//! answers on its socket (the daemon holds the store and its lock), and
//! takes the direct path otherwise. Both paths render the same lines here.

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
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::ReadArgs;
use crate::commands::{resolve_room, sync_once, via_daemon};
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
    let paths = Paths::from_env()?;
    let request = read_request(&args);
    let lines = match via_daemon::<ReadOutcome>(&paths, request.clone(), "read").await? {
        Some(outcome) => {
            for line in &outcome.warnings {
                eprintln!("{}", term(line));
            }
            outcome.lines()
        }
        None => {
            let config = load_config()?;
            let _lock = paths.lock().await?;
            let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
            let client = restored.client;
            sync_once(&client).await?;
            execute(
                &client,
                &request,
                KEY_WAIT_INTERVAL,
                |line| eprintln!("{line}"),
                || sync_with_timeout(&client, KEY_WAIT_SYNC_TIMEOUT),
            )
            .await?
        }
    };
    // Rendered here on both paths, so the output (and the local time of
    // the text lines) is this process's.
    print!("{}", render(&lines, args.json)?);
    Ok(())
}

/// The "read" request the watch daemon takes. `--json` is not part of it:
/// the output is rendered by the calling process on both paths.
pub fn read_request(args: &ReadArgs) -> Value {
    json!({
        "op": "read",
        "room": args.room,
        "limit": args.limit,
        "request_keys": args.request_keys,
    })
}

/// Carry out a "read" request with `client`: the messages, newest first.
///
/// Warning lines (whole, with "warning: ") go to `warn`. With
/// `request_keys` and an undecryptable message, [`KEY_WAIT_ROUNDS`] rounds
/// of (wait `interval`, `sync`) run before the second read.
pub async fn execute<W, S, F>(
    client: &Client,
    request: &Value,
    interval: Duration,
    mut warn: W,
    sync: S,
) -> Result<Vec<Line>>
where
    W: FnMut(String),
    S: FnMut() -> F,
    F: Future<Output = Result<()>>,
{
    let room_arg = request
        .get("room")
        .and_then(Value::as_str)
        .context("the request has no \"room\"")?;
    let limit = request
        .get("limit")
        .and_then(Value::as_u64)
        .and_then(|l| u32::try_from(l).ok())
        .context("the request has no valid \"limit\"")?;
    let request_keys = request
        .get("request_keys")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let room = resolve_room(client, room_arg).await?;
    let (room_encrypted, unknown) = room_encryption(&room).await?;
    if let Some(line) = unknown {
        warn(line);
    }

    // Room::messages() decrypts each event; for one without its key,
    // matrix-sdk queues a key request to our other devices
    // (automatic-room-key-forwarding), which the next sync sends.
    let mut lines = fetch_lines(&room, limit, room_encrypted).await?;
    if request_keys && lines.iter().any(Line::is_undecryptable) {
        if let Some(line) = without_verified_device_warning(client).await {
            warn(line);
        }
        key_wait_rounds(KEY_WAIT_ROUNDS, interval, sync, &mut warn).await;
        lines = fetch_lines(&room, limit, room_encrypted).await?;
    }
    Ok(lines)
}

/// [`execute`] in the watch daemon: the warnings go into the answer, and
/// the key wait does not sync, since the daemon's own sync loop syncs
/// meanwhile (a second sync on the same client would race it).
#[cfg_attr(not(unix), allow(dead_code))]
pub async fn daemon_execute(
    client: &Client,
    request: &Value,
    interval: Duration,
) -> Result<ReadOutcome> {
    let mut warnings = Vec::new();
    let lines = execute(
        client,
        request,
        interval,
        |line| warnings.push(line),
        || async { Ok(()) },
    )
    .await?;
    Ok(ReadOutcome {
        messages: lines.iter().map(WireLine::from).collect(),
        warnings,
    })
}

/// The watch daemon's answer to "read".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadOutcome {
    pub messages: Vec<WireLine>,
    /// Whole warning lines, printed to stderr by the caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ReadOutcome {
    pub fn lines(&self) -> Vec<Line> {
        self.messages.iter().cloned().map(Line::from).collect()
    }
}

/// A [`Line`] on the daemon socket: every field, also the ones the JSON
/// output skips (`was_encrypted`) or leaves out when empty, and
/// `session_id`'s two levels as two fields (JSON `null` cannot tell
/// "undecryptable, no session named" from "not undecryptable").
///
/// The daemon's answer passes through `serde_json::Value` on both ends
/// (`to_answer`, the client's decode), which sorts object keys and reads a
/// `null` into `None`. So `url` has a `has_url` beside it (a `file.url`
/// of `null` prints `"url": null`), and `info` travels as a list of pairs,
/// which keeps the sender's key order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireLine {
    pub sender: String,
    pub body: String,
    pub msgtype: String,
    pub timestamp: u64,
    pub event_id: String,
    pub encrypted: bool,
    pub format: Option<String>,
    pub formatted_body: Option<String>,
    pub has_url: bool,
    pub url: Option<Value>,
    pub info: Option<Vec<(String, Value)>>,
    pub undecryptable: bool,
    pub session_id: Option<String>,
    pub decrypted: bool,
    pub sender_verified: bool,
    pub room_encrypted: bool,
    pub was_encrypted: bool,
}

impl From<&Line> for WireLine {
    fn from(line: &Line) -> Self {
        Self {
            sender: line.sender.clone(),
            body: line.body.clone(),
            msgtype: line.msgtype.clone(),
            timestamp: line.timestamp,
            event_id: line.event_id.clone(),
            encrypted: line.encrypted,
            format: line.format.clone(),
            formatted_body: line.formatted_body.clone(),
            has_url: line.url.is_some(),
            url: line.url.clone(),
            info: line.info.clone().map(|OrderedMap(pairs)| pairs),
            undecryptable: line.session_id.is_some(),
            session_id: line.session_id.clone().flatten(),
            decrypted: line.decrypted,
            sender_verified: line.sender_verified,
            room_encrypted: line.room_encrypted,
            was_encrypted: line.was_encrypted,
        }
    }
}

impl From<WireLine> for Line {
    fn from(wire: WireLine) -> Self {
        Self {
            sender: wire.sender,
            body: wire.body,
            msgtype: wire.msgtype,
            timestamp: wire.timestamp,
            event_id: wire.event_id,
            encrypted: wire.encrypted,
            format: wire.format,
            formatted_body: wire.formatted_body,
            url: wire.has_url.then(|| wire.url.unwrap_or(Value::Null)),
            info: wire.info.map(OrderedMap),
            session_id: wire.undecryptable.then_some(wire.session_id),
            decrypted: wire.decrypted,
            sender_verified: wire.sender_verified,
            room_encrypted: wire.room_encrypted,
            was_encrypted: wire.was_encrypted,
        }
    }
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

/// Whether the room is encrypted, and the warning line for an unknown
/// state, which counts as encrypted.
pub async fn room_encryption(room: &Room) -> Result<(bool, Option<String>)> {
    Ok(
        match room
            .latest_encryption_state()
            .await
            .context("cannot read the room's encryption state")?
        {
            EncryptionState::Encrypted => (true, None),
            EncryptionState::NotEncrypted => (false, None),
            // Treat it as encrypted, so unencrypted events get marked.
            EncryptionState::Unknown => (
                true,
                Some(format!(
                    "warning: the encryption state of {} is unknown; treating it as encrypted",
                    term(room.room_id().as_str())
                )),
            ),
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

/// Remembers the sync errors already reported, so a homeserver that stays
/// unreachable gives one warning per distinct message, not one per round.
#[derive(Debug, Default)]
pub struct SyncWarnings(std::collections::BTreeSet<String>);

impl SyncWarnings {
    /// The line to print for `err`; `None` if its message was printed before.
    pub fn line(&mut self, err: &anyhow::Error) -> Option<String> {
        let msg = format!("{err:#}");
        let line = format!("warning: {}", term(&msg));
        self.0.insert(msg).then_some(line)
    }
}

/// `rounds` times: wait `interval`, then sync. A failed sync is reported
/// (once per distinct message, through `warn`) and the next round runs, as
/// in Python, where a sync error is a return value nobody checks.
pub async fn key_wait_rounds<S, F, W>(rounds: u32, interval: Duration, mut sync: S, mut warn: W)
where
    S: FnMut() -> F,
    F: Future<Output = Result<()>>,
    W: FnMut(String),
{
    let mut warnings = SyncWarnings::default();
    for _ in 0..rounds {
        tokio::time::sleep(interval).await;
        if let Err(err) = sync().await
            && let Some(line) = warnings.line(&err)
        {
            warn(line);
        }
    }
}

/// matrix-sdk sends a key request only when one of our other devices is
/// verified (matrix-sdk-crypto gossiping/machine.rs, should_request_key).
/// Say so instead of waiting in silence for keys nobody was asked for.
pub async fn warn_without_verified_device(client: &Client) {
    if let Some(line) = without_verified_device_warning(client).await {
        eprintln!("{line}");
    }
}

/// The warning line of [`warn_without_verified_device`], if it applies.
pub async fn without_verified_device_warning(client: &Client) -> Option<String> {
    let (Some(user), Some(own)) = (client.user_id(), client.device_id()) else {
        return None;
    };
    let any = match client.encryption().get_user_devices(user).await {
        Ok(devices) => devices
            .devices()
            .any(|d| d.device_id() != own && d.is_verified()),
        Err(_) => return None,
    };
    (!any).then(|| {
        "warning: none of your other devices is verified; matrix-sdk sends no key request without one"
            .to_owned()
    })
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
pub(crate) mod tests {
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

    /// The timeline the read tests serve, newest first: a text message, a
    /// notice with HTML, an image with info, and (in an encrypted room) an
    /// event nobody can decrypt.
    /// The timeline the read tests serve, newest first, as the bytes the
    /// server sends: a text message, a notice with HTML, an image whose
    /// `info` keys are not sorted, a file whose `file.url` is null, and (in
    /// an encrypted room) an event nobody can decrypt.
    pub fn timeline(encrypted: bool) -> String {
        let mut chunk = vec![
            json!({"type": "m.room.message", "event_id": "$t:example.org", "sender": "@a:example.org",
                "origin_server_ts": 1_700_000_300_000u64, "room_id": "!r:example.org",
                "content": {"msgtype": "m.text", "body": "hello\nworld"}})
            .to_string(),
            json!({"type": "m.room.message", "event_id": "$n:example.org", "sender": "@bot:example.org",
                "origin_server_ts": 1_700_000_200_000u64, "room_id": "!r:example.org",
                "content": {"msgtype": "m.notice", "body": "**done**",
                    "format": "org.matrix.custom.html", "formatted_body": "<strong>done</strong>"}})
            .to_string(),
            // Written out: json! would sort the info keys.
            r#"{"type": "m.room.message", "event_id": "$i:example.org", "sender": "@a:example.org",
                "origin_server_ts": 1700000100000, "room_id": "!r:example.org",
                "content": {"msgtype": "m.image", "body": "p.png", "url": "mxc://example.org/p",
                    "info": {"w": 2, "mimetype": "image/png", "size": 3, "h": 1, "x": 9}}}"#
                .to_owned(),
            json!({"type": "m.room.message", "event_id": "$f:example.org", "sender": "@a:example.org",
                "origin_server_ts": 1_700_000_050_000u64, "room_id": "!r:example.org",
                "content": {"msgtype": "m.file", "body": "f.bin", "file": {"url": null}}})
            .to_string(),
        ];
        if encrypted {
            chunk.push(
                json!({"type": "m.room.encrypted", "event_id": "$u:example.org",
                "sender": "@b:example.org", "origin_server_ts": 1_700_000_000_000u64,
                "room_id": "!r:example.org",
                "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "AAAA",
                    "session_id": "SESSION", "sender_key": "KEY", "device_id": "DEV"}})
                .to_string(),
            );
        }
        format!(
            r#"{{"chunk": [{}], "start": "t0", "end": "t1"}}"#,
            chunk.join(", ")
        )
    }

    /// [`crate::commands::send::tests::room_server`] that also serves
    /// [`timeline`].
    pub fn read_server(encrypted: bool) -> crate::mock_homeserver::MockHomeserver {
        let server = crate::commands::send::tests::room_server(encrypted);
        server.route(
            "GET",
            "/_matrix/client/v3/rooms/!r:example.org/messages",
            200,
            &timeline(encrypted),
        );
        server
    }

    /// The queries of the /messages requests the server received.
    pub fn messages_queries(server: &crate::mock_homeserver::MockHomeserver) -> Vec<String> {
        server
            .received()
            .into_iter()
            .filter(|r| r.path == "/_matrix/client/v3/rooms/!r:example.org/messages")
            .map(|r| r.query)
            .collect()
    }

    pub fn read_args(argv: &[&str]) -> ReadArgs {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([&["m", "read"][..], argv].concat()).unwrap();
        let crate::Command::Read(args) = cli.command else {
            panic!("not read")
        };
        args
    }

    /// What the direct path prints for ARGV against [`read_server`]:
    /// (stdout, stderr lines, /messages queries).
    pub async fn direct_read(encrypted: bool, argv: &[&str]) -> (String, Vec<String>, Vec<String>) {
        let args = read_args(argv);
        let server = read_server(encrypted);
        let client = server.client("@me:example.org").await;
        sync_once(&client).await.unwrap();
        let mut warnings = Vec::new();
        let lines = execute(
            &client,
            &read_request(&args),
            Duration::ZERO,
            |line| warnings.push(line),
            || sync_with_timeout(&client, Duration::ZERO),
        )
        .await
        .unwrap();
        (
            render(&lines, args.json).unwrap(),
            warnings,
            messages_queries(&server),
        )
    }

    #[test]
    fn the_read_request_carries_room_limit_and_request_keys() {
        assert_eq!(
            read_request(&read_args(&["#ops:example.org"])),
            json!({"op": "read", "room": "#ops:example.org", "limit": 10, "request_keys": false})
        );
        // --json is rendered by the caller, so the request is the same.
        assert_eq!(
            read_request(&read_args(&["r", "-l", "3", "-k", "--json"])),
            json!({"op": "read", "room": "r", "limit": 3, "request_keys": true})
        );
    }

    #[test]
    fn a_line_survives_the_daemon_socket() {
        let mut lines = vec![
            to_line(&plain(message("m.text", "hi")), true).unwrap(),
            to_line(&decrypted("hi", VerificationState::Verified), true).unwrap(),
            to_line(&utd("$e2", "s"), true).unwrap(),
        ];
        // Undecryptable, without a session named: Some(None).
        let mut nameless = lines[2].clone();
        nameless.session_id = Some(None);
        lines.push(nameless);
        let mut image = message("m.image", "p.png");
        image["content"]["url"] = json!("mxc://e/p");
        image["content"]["info"] = json!({"w": 2, "mimetype": "image/png", "h": 1});
        let mut html = message("m.notice", "b");
        html["content"]["format"] = json!("org.matrix.custom.html");
        html["content"]["formatted_body"] = json!("<b>b</b>");
        lines.push(to_line(&plain(image), false).unwrap());
        let mut null_url = message("m.file", "f");
        null_url["content"]["file"] = json!({"url": null});
        let null_url = to_line(&plain(null_url), false).unwrap();
        // Info keys not sorted (json! would sort them).
        let unsorted = TimelineEvent::from_plaintext(
            Raw::from_json_string(
                r#"{"type": "m.room.message", "event_id": "$o", "sender": "@a:example",
                    "origin_server_ts": 1, "content": {"msgtype": "m.image", "body": "o",
                    "url": "mxc://e/o", "info": {"w": 2, "mimetype": "image/png", "h": 1}}}"#
                    .to_owned(),
            )
            .unwrap(),
        );
        let unsorted = to_line(&unsorted, false).unwrap();
        let keys: Vec<_> = unsorted
            .info
            .as_ref()
            .unwrap()
            .0
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(keys, ["w", "mimetype", "h"]);
        lines.push(unsorted);
        assert_eq!(null_url.url, Some(Value::Null));
        lines.push(null_url);
        lines.push(to_line(&plain(html), false).unwrap());
        let outcome = ReadOutcome {
            messages: lines.iter().map(WireLine::from).collect(),
            warnings: vec!["warning: w".into()],
        };
        // As the daemon answers (to_answer: through serde_json::Value) and
        // the client decodes (through Value again).
        let wire = serde_json::to_string(&serde_json::to_value(&outcome).unwrap()).unwrap();
        let back: ReadOutcome =
            serde_json::from_value(serde_json::from_str::<Value>(&wire).unwrap()).unwrap();
        // What the caller renders (a null url arrives as no url and
        // has_url, so the wire structs differ).
        assert_eq!(back.lines(), lines);
        assert_eq!(back.warnings, outcome.warnings);
        for json in [false, true] {
            assert_eq!(
                render(&back.lines(), json).unwrap(),
                render(&lines, json).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn the_direct_path_reads_what_the_server_holds() {
        let (out, warnings, queries) =
            direct_read(false, &["!r:example.org", "-l", "3", "--json"]).await;
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(queries.len(), 1);
        assert!(queries[0].contains("limit=3"), "{queries:?}");
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let ids: Vec<_> = parsed
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["event_id"].clone())
            .collect();
        assert_eq!(
            ids,
            [
                "$t:example.org",
                "$n:example.org",
                "$i:example.org",
                "$f:example.org"
            ]
        );
        // The image's info in the sender's order, without "x".
        assert!(
            out.contains("\"info\": {\n      \"w\": 2,\n      \"mimetype\": \"image/png\",\n      \"size\": 3,\n      \"h\": 1\n    }"),
            "{out}"
        );
        // The file's null file.url stays a null url.
        let file = parsed
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["event_id"] == "$f:example.org")
            .unwrap();
        assert_eq!(file.get("url"), Some(&Value::Null), "{file}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_large_answer_arrives_whole() {
        use crate::commands::via_daemon_at;
        use crate::daemon_test_support::FakeDaemon;
        // 200 messages of 10 000 characters: about 2 MB on one line.
        let line = to_line(&plain(message("m.text", &"x\n".repeat(5_000))), false).unwrap();
        let outcome = ReadOutcome {
            messages: vec![WireLine::from(&line); 200],
            warnings: Vec::new(),
        };
        let mut answer = serde_json::to_value(&outcome).unwrap();
        answer["ok"] = json!(true);
        let fake = FakeDaemon::start(Some(answer));
        let got =
            via_daemon_at::<ReadOutcome>(&fake.path, read_request(&read_args(&["r"])), "read")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(got, outcome);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_daemon_without_the_read_op_is_an_error() {
        use crate::commands::via_daemon_at;
        use crate::daemon_test_support::FakeDaemon;
        let fake = FakeDaemon::start(Some(json!({"ok": false, "error": "unknown op: \"read\""})));
        let err =
            via_daemon_at::<ReadOutcome>(&fake.path, read_request(&read_args(&["r"])), "read")
                .await
                .unwrap_err()
                .to_string();
        assert_eq!(fake.received()["op"], "read");
        assert!(err.contains("unknown op"), "{err}");
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
        let mut warnings = Vec::new();
        key_wait_rounds(
            KEY_WAIT_ROUNDS,
            Duration::ZERO,
            || {
                calls.set(calls.get() + 1);
                let n = calls.get();
                async move {
                    // The network is down from round 2 on: the same error
                    // five times gives one warning.
                    if n >= 2 {
                        anyhow::bail!("sync failed: connection refused")
                    }
                    Ok(())
                }
            },
            |line| warnings.push(line),
        )
        .await;
        assert_eq!(calls.get(), 6);
        assert_eq!(warnings, ["warning: sync failed: connection refused"]);
        assert_eq!(
            (KEY_WAIT_INTERVAL, KEY_WAIT_SYNC_TIMEOUT),
            (Duration::from_secs(5), Duration::from_secs(5))
        );
    }
}
