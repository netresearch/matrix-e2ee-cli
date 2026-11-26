//! Room event log: file names, records, append, the room pages and the
//! reader's cursor. Started as a port of the matrix-skill's
//! `_lib/roomlog.py` and no longer byte-compatible with it: the skill's
//! readers cannot follow a log this tool writes.
//!
//! - Every file of a room is named after its stem, the readable slug of the
//!   room id, `-` and the first 12 hex digits of the SHA-256 of the exact
//!   room id (`a_b_example.org-0123456789ab`): `<stem>.jsonl`, its rotated
//!   generation `<stem>.jsonl.1`, the reader cursors
//!   `<stem>.<name>.cursor` and the room page `<stem>.md`. The slug alone
//!   is not unique (`!a+b:…` and `!a_b:…` share it).
//! - Besides the event records, a log holds `gap` records: events the
//!   server left out of a sync that could not be fetched afterwards.
//! - `index.json` beside `index.md` lists the rooms the daemon watches now;
//!   only it resolves an alias. Pages of rooms no longer watched stay.
//!
//! The event records still have roomlog.py's shape:
//! `tests/fixtures/roomlog/expected.json` holds lines the Python module
//! wrote, and the tests compare against them.

// The writing half serves the watch daemon, which exists on Unix only.
#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

/// Longest body, in characters, a display line carries.
pub const TEXT_LIMIT: usize = 220;
/// A log is rotated once it has reached this size.
pub const DEFAULT_MAX_BYTES: u64 = 8_000_000;
/// How much of a referenced message names the target of a reaction or redaction.
pub const SUBJECT_LIMIT: usize = 40;
/// How many recent bodies per room stay resolvable as a subject.
pub const SUBJECT_INDEX_SIZE: usize = 500;

/// Whitespace as Python's `str.split()` sees it: Unicode White_Space
/// plus the separators U+001C to U+001F.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `" ".join(s.split())`: runs of whitespace become one space, none at the ends.
fn fold(s: &str) -> String {
    s.split(is_py_space)
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The first `limit - 1` characters and an ellipsis, when `s` is longer than `limit`.
fn shorten(s: String, limit: usize) -> String {
    if s.chars().count() > limit {
        let mut cut: String = s.chars().take(limit - 1).collect();
        cut.push('…');
        cut
    } else {
        s
    }
}

/// Filename-safe form of a room id: without the leading `!`, every character
/// outside `[A-Za-z0-9._-]` replaced by `_`. Readable, not unique.
pub fn room_slug(room_id: &str) -> String {
    safe_name(room_id.trim_start_matches('!'))
}

/// The name every file of a room starts with: the slug, `-` and the first
/// 12 hex digits of the SHA-256 of the exact room id, so two rooms whose
/// slugs agree still get files of their own.
pub fn room_file_stem(room_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(room_id.as_bytes());
    let hash: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{hash}", room_slug(room_id))
}

fn safe_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn localpart(user_id: &str) -> &str {
    user_id
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_start_matches('@')
}

/// Python's `\w` for str patterns: alphanumeric or underscore.
fn is_word(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

fn chars_equal_ignore_case(a: char, b: char) -> bool {
    a == b || a.to_lowercase().eq(b.to_lowercase())
}

/// `re.search(rf"\b{re.escape(needle)}\b", body, re.IGNORECASE)`.
fn contains_word(body: &str, needle: &str) -> bool {
    let hay: Vec<char> = body.chars().collect();
    let pat: Vec<char> = needle.chars().collect();
    if pat.is_empty() || pat.len() > hay.len() {
        return false;
    }
    // \b at position i: the characters on either side differ in "wordness".
    let boundary = |i: usize| {
        let before = i.checked_sub(1).map(|j| hay[j]);
        is_word(before) != is_word(hay.get(i).copied())
    };
    (0..=hay.len() - pat.len()).any(|start| {
        boundary(start)
            && boundary(start + pat.len())
            && hay[start..start + pat.len()]
                .iter()
                .zip(&pat)
                .all(|(a, b)| chars_equal_ignore_case(*a, *b))
    })
}

/// Whether `body` addresses us: the localpart or the display name as a word.
fn mentions(body: Option<&str>, own_user_id: &str, own_display_name: Option<&str>) -> bool {
    let Some(body) = body.filter(|b| !b.is_empty()) else {
        return false;
    };
    [Some(localpart(own_user_id)), own_display_name]
        .into_iter()
        .flatten()
        .filter(|n| !n.is_empty())
        .any(|needle| contains_word(body, needle))
}

/// A message shortened to just enough to recognise it by.
pub fn excerpt(body: Option<&str>) -> String {
    shorten(fold(body.unwrap_or_default()), SUBJECT_LIMIT)
}

/// One event as the daemon hands it over (the Python daemon's event dict).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Event {
    pub event_id: String,
    pub sender: String,
    pub sender_display: Option<String>,
    /// Milliseconds since the epoch.
    pub ts: i64,
    pub room_id: Option<String>,
    /// curve25519 key of the sending device, when the event was encrypted.
    pub sender_key: Option<String>,
    /// `m.text`, `m.notice`, `m.emote`, `reaction`, `redaction`, `membership`, `encrypted`.
    pub kind: String,
    pub body: Option<String>,
    pub reply_to: Option<String>,
    pub thread_root: Option<String>,
    pub session_id: Option<String>,
    pub relates_to: Option<String>,
    pub redacts: Option<String>,
    pub reason: Option<String>,
}

/// One log record. Field order, the always-present nulls and the keys that
/// appear only when set follow roomlog.py's `build_record`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Record {
    pub seq: i64,
    pub ts: i64,
    pub event_id: String,
    pub room_id: Option<String>,
    pub sender: String,
    pub sender_display: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    pub body: Option<String>,
    pub reply_to: Option<String>,
    pub thread_root: Option<String>,
    #[serde(rename = "self")]
    pub is_self: bool,
    pub self_basis: String,
    pub mentions_me: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relates_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub text: String,
}

/// Who the record's sender is to us.
pub struct Own<'a> {
    pub user_id: &'a str,
    pub display_name: Option<&'a str>,
    pub sender_key: Option<&'a str>,
}

/// Did this device send the event, and on what evidence (`device` or `account`).
fn is_own_device(event: &Event, own: &Own<'_>) -> (bool, &'static str) {
    let event_key = event.sender_key.as_deref().filter(|k| !k.is_empty());
    let own_key = own.sender_key.filter(|k| !k.is_empty());
    if event.sender != own.user_id {
        let basis = if event_key.is_some() && own_key.is_some() {
            "device"
        } else {
            "account"
        };
        return (false, basis);
    }
    match (event_key, own_key) {
        (Some(theirs), Some(mine)) => (theirs == mine, "device"),
        _ => (true, "account"),
    }
}

fn non_empty(value: &Option<String>) -> Option<String> {
    value.clone().filter(|v| !v.is_empty())
}

/// One record from one event; the line's time in local time.
pub fn build_record(seq: i64, event: &Event, own: &Own<'_>, subject: Option<&str>) -> Record {
    build_record_with(seq, event, own, subject, &local_hh_mm)
}

/// [`build_record`] with the clock rendering given (tests use UTC).
pub fn build_record_with(
    seq: i64,
    event: &Event,
    own: &Own<'_>,
    subject: Option<&str>,
    hh_mm: &dyn Fn(i64) -> String,
) -> Record {
    let (is_self, basis) = is_own_device(event, own);
    let mut record = Record {
        seq,
        ts: event.ts,
        event_id: event.event_id.clone(),
        room_id: event.room_id.clone(),
        sender: event.sender.clone(),
        sender_display: event.sender_display.clone(),
        kind: event.kind.clone(),
        body: event.body.clone(),
        reply_to: event.reply_to.clone(),
        thread_root: event.thread_root.clone(),
        is_self,
        self_basis: basis.to_owned(),
        mentions_me: mentions(event.body.as_deref(), own.user_id, own.display_name),
        session_id: non_empty(&event.session_id),
        relates_to: non_empty(&event.relates_to),
        redacts: non_empty(&event.redacts),
        reason: non_empty(&event.reason),
        text: String::new(),
    };
    record.text = render_text(&record, subject, hh_mm);
    record
}

fn local_hh_mm(ts: i64) -> String {
    use chrono::{Local, TimeZone};
    Local
        .timestamp_millis_opt(ts)
        .single()
        .map(|t| t.format("%H:%M").to_string())
        .unwrap_or_else(|| "--:--".to_owned())
}

/// The single line a reader prints.
fn render_text(record: &Record, subject: Option<&str>, hh_mm: &dyn Fn(i64) -> String) -> String {
    let stamp = hh_mm(record.ts);
    let mut who = match record.sender_display.as_deref() {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => localpart(&record.sender).to_owned(),
    };
    if record.is_self && record.self_basis == "device" {
        who = format!("{who} (agent)");
    }
    let body = fold(record.body.as_deref().unwrap_or_default());
    let subject = subject.filter(|s| !s.is_empty());
    let rstrip = |s: String| s.trim_end_matches(is_py_space).to_owned();

    match record.kind.as_str() {
        "encrypted" => format!("[{stamp}] {who}: [unable to decrypt]"),
        "reaction" => {
            let line = rstrip(format!("[{stamp}] {who} reacted {body}"));
            match subject {
                Some(subject) => format!("{line} to \"{subject}\""),
                None => line,
            }
        }
        "redaction" => {
            let target = subject.map_or_else(|| "a message".to_owned(), |s| format!("\"{s}\""));
            let line = format!("[{stamp}] {who} removed {target}");
            match record.reason.as_deref().filter(|r| !r.is_empty()) {
                Some(reason) => format!("{line} ({reason})"),
                None => line,
            }
        }
        "membership" => rstrip(format!("[{stamp}] {who}: {body}")),
        kind => {
            let body = shorten(body, TEXT_LIMIT);
            let prefix = if kind == "m.emote" { "* " } else { "" };
            format!("[{stamp}] {who}: {prefix}{body}")
        }
    }
}

/// Events missing from a log: the server left them out of a sync (a
/// limited timeline) and they could not be fetched afterwards. `after` is
/// the last event logged before them, `before` the first logged after
/// them, each as (event id, ms since the epoch) when known.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Gap {
    pub room_id: String,
    pub after: Option<(String, i64)>,
    pub before: Option<(String, i64)>,
    /// When the gap was noticed, ms since the epoch.
    pub noticed: i64,
}

/// The record of a [`Gap`]. It has no `event_id` (it is no event) and its
/// own `type`, `gap`; `ts` is the time of the first event after the gap,
/// or when it was noticed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GapRecord {
    pub seq: i64,
    pub ts: i64,
    pub room_id: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub after_event_id: Option<String>,
    pub after_ts: Option<i64>,
    pub before_event_id: Option<String>,
    pub before_ts: Option<i64>,
    pub text: String,
}

/// The `type` of a gap record.
pub const GAP: &str = "gap";

/// A gap's record; its line in local time.
pub fn build_gap_record(seq: i64, gap: &Gap) -> GapRecord {
    build_gap_record_with(seq, gap, &local_hh_mm)
}

/// [`build_gap_record`] with the clock rendering given (tests use UTC).
pub fn build_gap_record_with(seq: i64, gap: &Gap, hh_mm: &dyn Fn(i64) -> String) -> GapRecord {
    let ts = gap.before.as_ref().map_or(gap.noticed, |(_, ts)| *ts);
    let span = match (&gap.after, &gap.before) {
        (Some((_, a)), Some((_, b))) => {
            format!("events after {} and before {}", hh_mm(*a), hh_mm(*b))
        }
        (Some((_, a)), None) => format!("events after {}", hh_mm(*a)),
        (None, Some((_, b))) => format!("events before {}", hh_mm(*b)),
        (None, None) => "events".to_owned(),
    };
    GapRecord {
        seq,
        ts,
        room_id: gap.room_id.clone(),
        kind: GAP,
        after_event_id: gap.after.as_ref().map(|(id, _)| id.clone()),
        after_ts: gap.after.as_ref().map(|(_, ts)| *ts),
        before_event_id: gap.before.as_ref().map(|(id, _)| id.clone()),
        before_ts: gap.before.as_ref().map(|(_, ts)| *ts),
        text: format!(
            "[{}] --- gap: {span} are missing from this log; the server left them out and they could not be fetched ---",
            hh_mm(ts)
        ),
    }
}

/// The event a record applies to: a reaction's target or a redaction's.
#[cfg(test)]
pub fn target_of(record: &Value) -> Option<&str> {
    let field = |key| {
        record
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    field("relates_to").or_else(|| field("redacts"))
}

/// `event_id` -> excerpt of the most recent records with a body, oldest
/// dropped first. An id seen again keeps its place (a Python dict).
#[derive(Debug, Clone)]
pub struct SubjectIndex {
    limit: usize,
    order: VecDeque<String>,
    excerpts: HashMap<String, String>,
}

impl SubjectIndex {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            order: VecDeque::new(),
            excerpts: HashMap::new(),
        }
    }

    /// Seeded from a log, so a restarted daemon still names recent targets.
    pub fn from_log(path: &Path) -> Self {
        let mut index = Self::new(SUBJECT_INDEX_SIZE);
        for record in read_records(path) {
            index.remember(&record);
        }
        index
    }

    pub fn get(&self, event_id: &str) -> Option<&str> {
        self.excerpts.get(event_id).map(String::as_str)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Keep a record's body resolvable for a later reaction or redaction.
    pub fn remember(&mut self, record: &Value) {
        let body = record
            .get("body")
            .and_then(Value::as_str)
            .filter(|b| !b.is_empty());
        let event_id = record
            .get("event_id")
            .and_then(Value::as_str)
            .filter(|e| !e.is_empty());
        let (Some(body), Some(event_id)) = (body, event_id) else {
            return;
        };
        if self
            .excerpts
            .insert(event_id.to_owned(), excerpt(Some(body)))
            .is_none()
        {
            self.order.push_back(event_id.to_owned());
        }
        if self.order.len() > self.limit
            && let Some(oldest) = self.order.pop_front()
        {
            self.excerpts.remove(&oldest);
        }
    }
}

/// `<rooms_dir>/<stem>.jsonl`; creates `rooms_dir`.
pub fn log_path(rooms_dir: &Path, room_id: &str) -> Result<PathBuf> {
    fs::create_dir_all(rooms_dir)
        .with_context(|| format!("cannot create {}", rooms_dir.display()))?;
    Ok(rooms_dir.join(format!("{}.jsonl", room_file_stem(room_id))))
}

/// The one retained previous generation of a log.
pub fn rotated(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".1");
    path.with_file_name(name)
}

/// One parsed line, or `None` for a blank, damaged or truncated one.
pub fn parse_line(line: &[u8]) -> Option<Value> {
    let text = String::from_utf8_lossy(line);
    let text = text.trim_matches(is_py_space);
    if text.is_empty() {
        return None;
    }
    serde_json::from_str::<Value>(text)
        .ok()
        .filter(Value::is_object)
}

/// Records oldest first; damaged lines (a daemon killed mid-write) are skipped.
pub fn read_records(path: &Path) -> Vec<Value> {
    match fs::read(path) {
        Ok(bytes) => bytes
            .split(|b| *b == b'\n')
            .filter_map(parse_line)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The `seq` of a parsed record, 0 when it has none.
pub fn seq_of(record: &Value) -> i64 {
    record.get("seq").and_then(Value::as_i64).unwrap_or(0)
}

/// How many event ids per room [`LoggedEvents`] keeps.
pub const LOGGED_IDS_SIZE: usize = 1000;

/// The events most recently logged for a room: where a back-fill stops.
/// Daemon notices (`$daemon-...`) and gap records are left out, and a
/// correction (an id logged again) keeps the first place and `last`.
#[derive(Debug, Clone, Default)]
pub struct LoggedEvents {
    order: VecDeque<String>,
    ids: HashSet<String>,
    last: Option<(String, i64)>,
}

impl LoggedEvents {
    /// Seeded from both generations of a log, oldest first.
    pub fn from_log(path: &Path) -> Self {
        let mut logged = Self::default();
        for record in [rotated(path), path.to_path_buf()]
            .iter()
            .flat_map(|p| read_records(p))
        {
            logged.remember(&record);
        }
        logged
    }

    pub fn remember(&mut self, record: &Value) {
        if record.get("type").and_then(Value::as_str) == Some(GAP) {
            return;
        }
        let Some(event_id) = record
            .get("event_id")
            .and_then(Value::as_str)
            .filter(|e| !e.is_empty() && !e.starts_with("$daemon-"))
        else {
            return;
        };
        if !self.ids.insert(event_id.to_owned()) {
            return;
        }
        self.order.push_back(event_id.to_owned());
        let ts = record.get("ts").and_then(Value::as_i64).unwrap_or(0);
        self.last = Some((event_id.to_owned(), ts));
        if self.order.len() > LOGGED_IDS_SIZE
            && let Some(oldest) = self.order.pop_front()
        {
            self.ids.remove(&oldest);
        }
    }

    pub fn contains(&self, event_id: &str) -> bool {
        self.ids.contains(event_id)
    }

    /// The newest event logged (id and ts); `None` before the first.
    pub fn last(&self) -> Option<&(String, i64)> {
        self.last.as_ref()
    }
}

/// One past the highest seq, counting the rotated generation too.
pub fn next_seq(path: &Path) -> i64 {
    [rotated(path), path.to_path_buf()]
        .iter()
        .flat_map(|p| read_records(p))
        .map(|r| seq_of(&r))
        .fold(0, i64::max)
        + 1
}

/// Append one record, rotating first once the log has reached `max_bytes`.
///
/// A log that does not end in a newline holds a torn record (a writer killed
/// mid-line): the new record starts on a line of its own, so the torn one
/// does not swallow it. roomlog.py has no such guard; for a log that ends in
/// a newline the bytes written are the same.
pub fn append_record<T: Serialize>(path: &Path, record: &T, max_bytes: u64) -> Result<()> {
    if fs::metadata(path).is_ok_and(|m| m.len() >= max_bytes) {
        fs::rename(path, rotated(path))
            .with_context(|| format!("cannot rotate {}", path.display()))?;
    }
    let mut line = serde_json::to_string(record).context("cannot serialize the record")?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    if ends_torn(&mut file).with_context(|| format!("cannot read {}", path.display()))? {
        line.insert(0, '\n');
    }
    // One write, so the separator and the record land together.
    file.write_all(line.as_bytes())
        .with_context(|| format!("cannot append to {}", path.display()))
}

/// Is the file non-empty without a final newline?
fn ends_torn(file: &mut fs::File) -> std::io::Result<bool> {
    if file.metadata()?.len() == 0 {
        return Ok(false);
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] != b'\n')
}

/// Where one reader's position in a room log is kept.
pub fn cursor_path(rooms_dir: &Path, room_id: &str, name: &str) -> Result<PathBuf> {
    fs::create_dir_all(rooms_dir)
        .with_context(|| format!("cannot create {}", rooms_dir.display()))?;
    Ok(rooms_dir.join(format!(
        "{}.{}.cursor",
        room_file_stem(room_id),
        safe_name(name)
    )))
}

/// The last seq this reader saw; 0 when there is none or it is damaged.
pub fn read_cursor(path: &Path) -> i64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| t.trim_matches(is_py_space).parse().ok())
        .unwrap_or(0)
}

pub fn write_cursor(path: &Path, seq: i64) -> Result<()> {
    fs::write(path, format!("{seq}\n")).with_context(|| format!("cannot write {}", path.display()))
}

/// What arrived after a cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Distinct events: a correction record (the same `event_id` again,
    /// e.g. an undecryptable event decrypted later) does not count twice.
    pub total: u64,
    /// Distinct events that mention the user in any of their records.
    pub mentions: u64,
    pub last_seq: i64,
    /// The counts are a lower bound: the oldest record left is newer than
    /// the cursor (rotation carried the rest away), or a gap record after
    /// the cursor says events are missing.
    pub truncated: bool,
}

/// What arrived after `seq`, over both generations of the log (the
/// rotated one first). A gap record counts as no message.
pub fn summarize_since(log: &Path, seq: i64) -> Summary {
    let mut summary = Summary {
        total: 0,
        mentions: 0,
        last_seq: seq,
        truncated: false,
    };
    let mut oldest_seen = None;
    let mut counted: HashSet<String> = HashSet::new();
    let mut mentioned: HashSet<String> = HashSet::new();
    let mut gap = false;
    for record in [rotated(log), log.to_path_buf()]
        .iter()
        .flat_map(|p| read_records(p))
    {
        let record_seq = seq_of(&record);
        oldest_seen.get_or_insert(record_seq);
        summary.last_seq = summary.last_seq.max(record_seq);
        if record_seq > seq && record.get("type").and_then(Value::as_str) == Some(GAP) {
            gap = true;
        } else if record_seq > seq {
            let mentions_me = record.get("mentions_me").and_then(Value::as_bool) == Some(true);
            // A record without an event id counts on its own.
            let id = record.get("event_id").and_then(Value::as_str);
            if id.is_none_or(|id| counted.insert(id.to_owned())) {
                summary.total += 1;
            }
            if mentions_me && id.is_none_or(|id| mentioned.insert(id.to_owned())) {
                summary.mentions += 1;
            }
        }
    }
    summary.truncated = gap || (seq != 0 && oldest_seen.is_some_and(|o| o > seq + 1));
    summary
}

/// `datetime.now(tz=UTC).isoformat()`.
fn iso_now() -> String {
    let now = chrono::Utc::now();
    if now.timestamp_subsec_micros() == 0 {
        now.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        now.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
    }
}

/// Describe the watched rooms (room id, label) as an OKF bundle: one page per
/// room, `index.md`, and last `index.json`, the machine-readable list of
/// the rooms watched now (see [`read_room_index`]).
pub fn write_room_bundle(directory: &Path, rooms: &[(String, String)]) -> Result<()> {
    write_room_bundle_at(directory, rooms, &iso_now())
}

pub fn write_room_bundle_at(
    directory: &Path,
    rooms: &[(String, String)],
    stamp: &str,
) -> Result<()> {
    fs::create_dir_all(directory)
        .with_context(|| format!("cannot create {}", directory.display()))?;
    let mut sorted: Vec<&(String, String)> = rooms.iter().collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1));
    let mut entries = Vec::new();
    let mut listed = Vec::new();
    for (room_id, label) in sorted {
        let stem = room_file_stem(room_id);
        let description = format!("Matrix room {label}, watched by matrix-e2ee-cli watch-daemon.");
        let page = format!(
            "---\ntype: matrix-room\ntitle: {label}\ndescription: {description}\nresource: matrix:roomid/{}\ntags: [matrix, room, watched]\ntimestamp: {stamp}\n---\n\n# {label}\n\nRoom ID `{room_id}`. Events are appended to `{stem}.jsonl`;\nfollow them with `matrix-e2ee-cli watch`.\n",
            room_id.trim_start_matches('!')
        );
        let path = directory.join(format!("{stem}.md"));
        fs::write(&path, page).with_context(|| format!("cannot write {}", path.display()))?;
        entries.push(format!("- [{label}]({stem}.md) - {description}"));
        listed.push(IndexedRoom {
            room_id: room_id.clone(),
            title: label.clone(),
            file: format!("{stem}.jsonl"),
        });
    }
    let index = format!(
        "# Watched rooms\n\nWritten by `matrix-e2ee-cli watch-daemon`. Each room's events are in the `.jsonl` file next to its page.\n\n{}\n",
        entries.join("\n")
    );
    let path = directory.join("index.md");
    fs::write(&path, index).with_context(|| format!("cannot write {}", path.display()))?;
    let mut json = serde_json::to_string(&RoomIndex { rooms: listed })
        .context("cannot serialize the room index")?;
    json.push('\n');
    write_atomically(&directory.join(ROOM_INDEX), json.as_bytes())
}

/// The machine-readable list of the watched rooms, next to `index.md`.
pub const ROOM_INDEX: &str = "index.json";

#[derive(Debug, Serialize, serde::Deserialize)]
struct RoomIndex {
    rooms: Vec<IndexedRoom>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
struct IndexedRoom {
    room_id: String,
    title: String,
    /// The room's log, relative to the index.
    file: String,
}

/// Write `path` through a temporary file in the same directory and a
/// rename, so a reader sees the old content or the new, never a part.
fn write_atomically(path: &Path, content: &[u8]) -> Result<()> {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    fs::write(&temp, content).with_context(|| format!("cannot write {}", temp.display()))?;
    fs::rename(&temp, path).with_context(|| format!("cannot replace {}", path.display()))
}

/// Room id and title of each room the daemon watches now, from
/// `index.json`; empty when there is none or it is damaged. Pages of rooms
/// that are no longer watched do not count.
pub fn read_room_index(directory: &Path) -> Vec<(String, String)> {
    fs::read(directory.join(ROOM_INDEX))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<RoomIndex>(&bytes).ok())
        .map(|index| {
            index
                .rooms
                .into_iter()
                .map(|r| (r.room_id, r.title))
                .collect()
        })
        .unwrap_or_default()
}

/// Room id and title of each room page in `directory`, read from the
/// frontmatter (`title:` and `resource: matrix:roomid/...`). Every page
/// ever written, also of rooms no longer watched: not for alias lookup.
#[cfg(test)]
pub fn read_room_pages(directory: &Path) -> Vec<(String, String)> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut rooms = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "md")
            || path.file_name() == Some("index.md".as_ref())
        {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let Some(front) = text
            .strip_prefix("---\n")
            .and_then(|rest| rest.split("\n---\n").next())
        else {
            continue;
        };
        let field = |key: &str| {
            front
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .map(str::to_owned)
        };
        if let (Some(title), Some(resource)) = (field("title: "), field("resource: matrix:roomid/"))
        {
            rooms.push((format!("!{resource}"), title));
        }
    }
    rooms.sort();
    rooms
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "@tobias.hein:example.org";

    fn utc(ts: i64) -> String {
        chrono::DateTime::from_timestamp_millis(ts)
            .map(|t| t.format("%H:%M").to_string())
            .unwrap()
    }

    fn base_event() -> Event {
        Event {
            event_id: "$abc".into(),
            sender: EXAMPLE.into(),
            sender_display: Some("tobias.hein".into()),
            ts: 1_786_568_100_000,
            kind: "m.text".into(),
            body: Some("Ihr seid cool".into()),
            ..Default::default()
        }
    }

    fn own<'a>(user: &'a str, name: Option<&'a str>) -> Own<'a> {
        Own {
            user_id: user,
            display_name: name,
            sender_key: None,
        }
    }

    fn record(seq: i64, event: Event) -> Record {
        build_record_with(seq, &event, &own("@me:example.org", Some("me")), None, &utc)
    }

    fn rec_body(seq: i64, body: &str) -> Record {
        record(
            seq,
            Event {
                body: Some(body.into()),
                ..base_event()
            },
        )
    }

    fn value(r: &Record) -> Value {
        serde_json::to_value(r).unwrap()
    }

    // --- the record shape roomlog.py writes ----------------------------------
    // The records are still the lines the Python module wrote (the file names,
    // the room pages and the gap records are this tool's own).

    fn golden() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/roomlog/expected.json")).unwrap()
    }

    #[test]
    fn records_are_byte_identical_to_roomlog_py() {
        let e = || Event {
            room_id: Some("!r:example.org".into()),
            ..base_event()
        };
        let me = own("@me:example.org", Some("me"));
        let cases: Vec<(Event, Own<'_>, Option<&str>)> = vec![
            (e(), own("@me:example.org", Some("me")), None),
            (
                Event {
                    body: Some(
                        "Grüße 🎁 \"quoted\" back\\slash tab\there\nnew\u{1}ctl\u{7f}\u{2028}end"
                            .into(),
                    ),
                    reply_to: Some("$p".into()),
                    thread_root: Some("$t".into()),
                    ..e()
                },
                own("@me:example.org", Some("me")),
                None,
            ),
            (
                Event {
                    kind: "encrypted".into(),
                    body: None,
                    session_id: Some("sess1".into()),
                    sender_display: None,
                    ..e()
                },
                own("@me:example.org", Some("me")),
                None,
            ),
            (
                Event {
                    kind: "reaction".into(),
                    body: Some("✅".into()),
                    relates_to: Some("$abc".into()),
                    ..e()
                },
                own("@me:example.org", Some("me")),
                Some("so bin beim RA"),
            ),
            (
                Event {
                    kind: "redaction".into(),
                    body: None,
                    redacts: Some("$abc".into()),
                    reason: Some("Tippfehler".into()),
                    ..e()
                },
                own("@me:example.org", Some("me")),
                None,
            ),
            (
                Event {
                    kind: "membership".into(),
                    body: Some("join".into()),
                    sender_display: Some(String::new()),
                    ..e()
                },
                own("@me:example.org", Some("me")),
                None,
            ),
            (
                Event {
                    kind: "m.emote".into(),
                    body: Some("winkt ".repeat(60)),
                    ..e()
                },
                own("@me:example.org", Some("me")),
                None,
            ),
            (
                Event {
                    sender: "@me:example.org".into(),
                    sender_key: Some("K".into()),
                    body: Some("hallo me und Basti".into()),
                    ..e()
                },
                Own {
                    user_id: "@me:example.org",
                    display_name: Some("Basti"),
                    sender_key: Some("K"),
                },
                None,
            ),
            (
                Event {
                    kind: "m.notice".into(),
                    body: Some("  lots \u{1c} of\u{a0} space\u{3000} ".into()),
                    room_id: None,
                    ..e()
                },
                own("@me:example.org", None),
                None,
            ),
            (
                Event {
                    kind: "reaction".into(),
                    body: Some(String::new()),
                    relates_to: Some("$abc".into()),
                    ..e()
                },
                me,
                None,
            ),
        ];
        let expected = golden();
        let lines = expected["lines"].as_array().unwrap();
        assert_eq!(lines.len(), cases.len());
        for (i, ((event, who, subject), want)) in cases.iter().zip(lines).enumerate() {
            let rec = build_record_with(i as i64 + 1, event, who, *subject, &utc);
            assert_eq!(
                serde_json::to_string(&rec).unwrap(),
                want.as_str().unwrap(),
                "case {}",
                i + 1
            );
        }
    }

    #[test]
    fn room_pages_have_the_bundle_format() {
        let dir = tempfile::tempdir().unwrap();
        let rooms = vec![
            ("!a:example.org".to_owned(), "#ops:example.org".to_owned()),
            ("!b:example.org".to_owned(), "#it:example.org".to_owned()),
            ("!c:example.org".to_owned(), "!c:example.org".to_owned()),
        ];
        write_room_bundle_at(dir.path(), &rooms, "STAMP").unwrap();
        let mut written: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        written.sort();
        assert_eq!(
            written,
            [
                "a_example.org-c372f7da2d38.md",
                "b_example.org-0c9bd274a481.md",
                "c_example.org-5086bb002d42.md",
                "index.json",
                "index.md",
            ]
        );
        let read = |name: &str| fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(
            read("a_example.org-c372f7da2d38.md"),
            "---\ntype: matrix-room\ntitle: #ops:example.org\ndescription: Matrix room #ops:example.org, watched by matrix-e2ee-cli watch-daemon.\nresource: matrix:roomid/a:example.org\ntags: [matrix, room, watched]\ntimestamp: STAMP\n---\n\n# #ops:example.org\n\nRoom ID `!a:example.org`. Events are appended to `a_example.org-c372f7da2d38.jsonl`;\nfollow them with `matrix-e2ee-cli watch`.\n"
        );
        assert_eq!(
            read("index.md"),
            "# Watched rooms\n\nWritten by `matrix-e2ee-cli watch-daemon`. Each room's events are in the `.jsonl` file next to its page.\n\n\
             - [!c:example.org](c_example.org-5086bb002d42.md) - Matrix room !c:example.org, watched by matrix-e2ee-cli watch-daemon.\n\
             - [#it:example.org](b_example.org-0c9bd274a481.md) - Matrix room #it:example.org, watched by matrix-e2ee-cli watch-daemon.\n\
             - [#ops:example.org](a_example.org-c372f7da2d38.md) - Matrix room #ops:example.org, watched by matrix-e2ee-cli watch-daemon.\n"
        );
        assert_eq!(
            read("index.json"),
            concat!(
                r##"{"rooms":[{"room_id":"!c:example.org","title":"!c:example.org","file":"c_example.org-5086bb002d42.jsonl"},"##,
                r##"{"room_id":"!b:example.org","title":"#it:example.org","file":"b_example.org-0c9bd274a481.jsonl"},"##,
                r##"{"room_id":"!a:example.org","title":"#ops:example.org","file":"a_example.org-c372f7da2d38.jsonl"}]}"##,
                "\n"
            )
        );
        let mut sorted = rooms.clone();
        sorted.sort();
        assert_eq!(read_room_pages(dir.path()), sorted);
        let mut indexed = read_room_index(dir.path());
        indexed.sort();
        assert_eq!(indexed, sorted);
    }

    #[test]
    fn iso_stamp_has_the_python_shape() {
        let stamp = iso_now();
        assert!(stamp.ends_with("+00:00"), "{stamp}");
        assert_eq!(&stamp[10..11], "T");
    }

    // --- ported from test_roomlog.py: SlugTests ------------------------------

    #[test]
    fn room_id_becomes_shell_safe() {
        assert_eq!(room_slug("!IyRWAMq:example.org"), "IyRWAMq_example.org");
    }

    #[test]
    fn slug_has_no_shell_metacharacters() {
        let slug = room_slug("!a+b/c:example.org");
        assert!(!slug.contains('!') && !slug.contains('/') && !slug.contains('+'));
    }

    #[test]
    fn distinct_rooms_keep_distinct_slugs() {
        assert_ne!(room_slug("!a:example.org"), room_slug("!b:example.org"));
    }

    // --- RecordTests ----------------------------------------------------------

    #[test]
    fn record_carries_seq_and_identity() {
        let rec = record(7, base_event());
        assert_eq!(rec.seq, 7);
        assert_eq!(rec.event_id, "$abc");
        assert!(!rec.is_self && !rec.mentions_me);
    }

    #[test]
    fn own_message_is_flagged() {
        let rec = record(
            1,
            Event {
                sender: "@me:example.org".into(),
                ..base_event()
            },
        );
        assert!(rec.is_self);
    }

    fn mention_record(body: &str, user: &str, name: Option<&str>) -> Record {
        build_record_with(
            1,
            &Event {
                body: Some(body.into()),
                ..base_event()
            },
            &own(user, name),
            None,
            &utc,
        )
    }

    #[test]
    fn localpart_in_body_counts_as_mention() {
        assert!(
            mention_record("kann sebastian das sehen?", "@sebastian:example.org", None).mentions_me
        );
    }

    #[test]
    fn display_name_in_body_counts_as_mention() {
        assert!(
            mention_record("Frag mal Basti", "@sebastian:example.org", Some("Basti")).mentions_me
        );
    }

    #[test]
    fn substring_of_a_longer_word_is_not_a_mention() {
        assert!(
            !mention_record("der bastion host", "@sebastian:example.org", Some("Basti"))
                .mentions_me
        );
    }

    #[test]
    fn mention_boundaries_follow_python_word_rules() {
        // A name that starts with a non-word character needs a word character
        // before it (Python's \b), and umlauts are word characters.
        assert!(mention_record("hallo Jörg!", "@x:e", Some("jörg")).mentions_me);
        assert!(!mention_record("hallo Jörgen", "@x:e", Some("jörg")).mentions_me);
        assert!(!mention_record("an_basti_", "@x:e", Some("basti")).mentions_me);
        assert!(mention_record("BASTI.", "@x:e", Some("basti")).mentions_me);
    }

    #[test]
    fn text_is_the_display_line() {
        let text = record(1, base_event()).text;
        let (stamp, rest) = text.split_at(7);
        assert!(stamp.starts_with('[') && stamp.ends_with(']') && &stamp[3..4] == ":");
        assert_eq!(rest, " tobias.hein: Ihr seid cool");
        // The local-time rendering has the same shape.
        let local = build_record(1, &base_event(), &own("@me:e", None), None).text;
        assert_eq!(&local[7..], " tobias.hein: Ihr seid cool");
    }

    #[test]
    fn long_body_is_truncated_in_text_only() {
        let rec = rec_body(1, &"x".repeat(500));
        assert!(rec.text.chars().count() < 260);
        assert!(rec.text.ends_with('…'));
        assert_eq!(rec.body.unwrap().len(), 500);
    }

    #[test]
    fn newlines_are_folded_into_one_line() {
        assert!(!rec_body(1, "erste\nzweite\n\ndritte").text.contains('\n'));
    }

    #[test]
    fn undecryptable_event_still_renders() {
        let rec = record(
            1,
            Event {
                kind: "encrypted".into(),
                body: None,
                session_id: Some("sess1".into()),
                ..base_event()
            },
        );
        assert!(rec.text.contains("[unable to decrypt]"));
        assert_eq!(rec.session_id.as_deref(), Some("sess1"));
    }

    #[test]
    fn emote_is_marked() {
        let rec = record(
            1,
            Event {
                kind: "m.emote".into(),
                body: Some("winkt".into()),
                ..base_event()
            },
        );
        assert!(rec.text.contains("* winkt"));
    }

    // --- AppendTests ---------------------------------------------------------

    struct Log {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        path: PathBuf,
    }

    fn log() -> Log {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path(), "!r:example.org").unwrap();
        Log {
            dir: dir.path().to_owned(),
            _dir: dir,
            path,
        }
    }

    fn append_n(log: &Log, count: i64) {
        for i in 1..=count {
            let rec = record(
                i,
                Event {
                    event_id: format!("$e{i}"),
                    ..base_event()
                },
            );
            append_record(&log.path, &rec, DEFAULT_MAX_BYTES).unwrap();
        }
    }

    #[test]
    fn next_seq_on_empty_log_is_one() {
        assert_eq!(next_seq(&log().path), 1);
    }

    #[test]
    fn next_seq_continues_after_existing_records() {
        let l = log();
        append_n(&l, 3);
        assert_eq!(next_seq(&l.path), 4);
    }

    #[test]
    fn records_round_trip() {
        let l = log();
        append_n(&l, 2);
        let got = read_records(&l.path);
        assert_eq!(got.iter().map(seq_of).collect::<Vec<_>>(), vec![1, 2]);
        assert!(
            got[0]["text"]
                .as_str()
                .unwrap()
                .ends_with("tobias.hein: Ihr seid cool")
        );
    }

    #[test]
    fn each_record_is_exactly_one_line() {
        let l = log();
        append_n(&l, 1);
        assert_eq!(
            fs::read_to_string(&l.path).unwrap().matches('\n').count(),
            1
        );
    }

    #[test]
    fn a_truncated_final_line_is_skipped_not_fatal() {
        let l = log();
        append_n(&l, 2);
        let mut f = OpenOptions::new().append(true).open(&l.path).unwrap();
        f.write_all(br#"{"seq": 3, "text": "hal"#).unwrap();
        assert_eq!(
            read_records(&l.path).iter().map(seq_of).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn rotation_keeps_seq_monotonic() {
        let l = log();
        append_n(&l, 5);
        let rec = record(
            6,
            Event {
                event_id: "$e6".into(),
                ..base_event()
            },
        );
        append_record(&l.path, &rec, 10).unwrap();
        assert!(rotated(&l.path).exists());
        assert_eq!(
            rotated(&l.path).file_name().unwrap(),
            "r_example.org-7802310a0a60.jsonl.1"
        );
        assert_eq!(next_seq(&l.path), 7);
    }

    #[test]
    fn a_torn_record_does_not_swallow_the_next() {
        let l = log();
        append_record(&l.path, &rec_body(1, "eins"), DEFAULT_MAX_BYTES).unwrap();
        // A writer killed mid-line left a fragment without a newline.
        let mut f = OpenOptions::new().append(true).open(&l.path).unwrap();
        f.write_all(br#"{"seq":2,"type":"m.te"#).unwrap();
        drop(f);
        append_record(&l.path, &rec_body(3, "drei"), DEFAULT_MAX_BYTES).unwrap();
        let seqs: Vec<i64> = read_records(&l.path).iter().map(seq_of).collect();
        assert_eq!(seqs, vec![1, 3]);
        let text = fs::read_to_string(&l.path).unwrap();
        assert!(text.ends_with("\n"), "{text}");
        assert_eq!(text.lines().count(), 3, "{text}");
    }

    #[test]
    fn a_clean_log_gets_no_extra_newline() {
        let l = log();
        append_record(&l.path, &rec_body(1, "eins"), DEFAULT_MAX_BYTES).unwrap();
        append_record(&l.path, &rec_body(2, "zwei"), DEFAULT_MAX_BYTES).unwrap();
        let text = fs::read_to_string(&l.path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(!text.contains("\n\n"), "{text}");
    }

    #[test]
    fn unicode_survives_the_round_trip() {
        let l = log();
        append_record(&l.path, &rec_body(1, "Grüße 🎁"), DEFAULT_MAX_BYTES).unwrap();
        assert!(
            read_records(&l.path)[0]["body"]
                .as_str()
                .unwrap()
                .contains("Grüße 🎁")
        );
    }

    // --- CursorTests ---------------------------------------------------------

    fn cursor_log() -> Log {
        let l = log();
        for i in 1..=5 {
            let body = if i == 2 || i == 4 {
                "hallo sebastian"
            } else {
                "nichts"
            };
            let rec = build_record_with(
                i,
                &Event {
                    event_id: format!("$e{i}"),
                    body: Some(body.into()),
                    ..base_event()
                },
                &own("@sebastian:example.org", None),
                None,
                &utc,
            );
            append_record(&l.path, &rec, DEFAULT_MAX_BYTES).unwrap();
        }
        l
    }

    #[test]
    fn missing_cursor_reads_as_zero() {
        let l = log();
        assert_eq!(
            read_cursor(&cursor_path(&l.dir, "!r:example.org", "default").unwrap()),
            0
        );
    }

    #[test]
    fn cursor_round_trips() {
        let l = log();
        let path = cursor_path(&l.dir, "!r:example.org", "default").unwrap();
        write_cursor(&path, 3).unwrap();
        assert_eq!(read_cursor(&path), 3);
        assert_eq!(fs::read_to_string(&path).unwrap(), "3\n");
        assert_eq!(
            path.file_name().unwrap(),
            "r_example.org-7802310a0a60.default.cursor"
        );
    }

    #[test]
    fn named_cursors_are_independent() {
        let l = log();
        let a = cursor_path(&l.dir, "!r:example.org", "sessionA").unwrap();
        let b = cursor_path(&l.dir, "!r:example.org", "session/B").unwrap();
        write_cursor(&a, 4).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            b.file_name().unwrap(),
            "r_example.org-7802310a0a60.session_B.cursor"
        );
        assert_eq!(read_cursor(&b), 0);
    }

    #[test]
    fn summary_counts_total_and_mentions() {
        let l = cursor_log();
        assert_eq!(
            summarize_since(&l.path, 0),
            Summary {
                total: 5,
                mentions: 2,
                last_seq: 5,
                truncated: false
            }
        );
    }

    #[test]
    fn a_correction_record_does_not_count_twice() {
        let l = cursor_log();
        // $e2 again (decrypted later), then a daemon line without an id.
        for (seq, id) in [(6, "$e2"), (7, "$e4"), (8, "")] {
            let rec = build_record_with(
                seq,
                &Event {
                    event_id: id.into(),
                    body: Some("hallo sebastian".into()),
                    ..base_event()
                },
                &own("@sebastian:example.org", None),
                None,
                &utc,
            );
            let mut value = serde_json::to_value(&rec).unwrap();
            if id.is_empty() {
                value.as_object_mut().unwrap().remove("event_id");
            }
            let mut line = serde_json::to_string(&value).unwrap();
            line.push('\n');
            OpenOptions::new()
                .append(true)
                .open(&l.path)
                .unwrap()
                .write_all(line.as_bytes())
                .unwrap();
        }
        let s = summarize_since(&l.path, 0);
        assert_eq!((s.total, s.mentions, s.last_seq), (6, 3, 8));
        // After the cursor, a correction is new once.
        let s = summarize_since(&l.path, 5);
        assert_eq!((s.total, s.mentions), (3, 3));
    }

    #[test]
    fn summary_counts_only_what_is_new() {
        let s = summarize_since(&cursor_log().path, 3);
        assert_eq!((s.total, s.mentions), (2, 1));
    }

    #[test]
    fn cursor_ahead_of_log_counts_nothing() {
        assert_eq!(summarize_since(&cursor_log().path, 99).total, 0);
    }

    #[test]
    fn gap_older_than_the_log_is_marked_truncated() {
        let l = cursor_log();
        for i in 6..9 {
            let rec = build_record_with(
                i,
                &Event {
                    event_id: format!("$e{i}"),
                    ..base_event()
                },
                &own("@sebastian:example.org", None),
                None,
                &utc,
            );
            append_record(&l.path, &rec, 1).unwrap();
        }
        assert!(summarize_since(&l.path, 2).truncated);
    }

    #[test]
    fn a_corrupt_cursor_file_reads_as_zero() {
        let l = log();
        let path = cursor_path(&l.dir, "!r:example.org", "default").unwrap();
        fs::write(&path, "not a number").unwrap();
        assert_eq!(read_cursor(&path), 0);
    }

    // --- RoomBundleTests -----------------------------------------------------

    fn bundle() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_room_bundle(
            dir.path(),
            &[
                ("!a:example.org".into(), "#ops:example.org".into()),
                ("!b:example.org".into(), "#it:example.org".into()),
            ],
        )
        .unwrap();
        dir
    }

    #[test]
    fn one_file_per_room_with_the_okf_fields() {
        let dir = bundle();
        assert!(
            dir.path()
                .join(format!("{}.md", room_file_stem("!b:example.org")))
                .exists()
        );
        let text = fs::read_to_string(
            dir.path()
                .join(format!("{}.md", room_file_stem("!a:example.org"))),
        )
        .unwrap();
        assert!(text.starts_with("---\n") && text.contains("type: matrix-room"));
        for field in ["title:", "description:", "resource:", "tags:", "timestamp:"] {
            assert!(text.contains(field), "{field}");
        }
    }

    #[test]
    fn index_has_no_frontmatter_and_lists_every_room() {
        let text = fs::read_to_string(bundle().path().join("index.md")).unwrap();
        assert!(!text.starts_with("---"));
        assert!(
            text.contains("(a_example.org-c372f7da2d38.md)")
                && text.contains("(b_example.org-0c9bd274a481.md)")
        );
        assert!(text.contains("watched by matrix-e2ee-cli watch-daemon"));
    }

    #[test]
    fn rewriting_the_bundle_does_not_duplicate_entries() {
        let dir = bundle();
        write_room_bundle(
            dir.path(),
            &[("!a:example.org".into(), "#ops:example.org".into())],
        )
        .unwrap();
        let text = fs::read_to_string(dir.path().join("index.md")).unwrap();
        assert_eq!(text.matches("(a_example.org-c372f7da2d38.md)").count(), 1);
        assert!(!text.contains("(b_example.org-0c9bd274a481.md)"));
    }

    // --- SelfIsTheDeviceTests ------------------------------------------------

    const MINE: &str = "curve25519-of-my-device";
    const THEIRS: &str = "curve25519-of-their-element";
    const USER: &str = "@shared:example.org";

    fn device_record(sender: &str, sender_key: Option<&str>, own_key: Option<&str>) -> Record {
        build_record_with(
            1,
            &Event {
                sender: sender.into(),
                sender_key: sender_key.map(Into::into),
                ..base_event()
            },
            &Own {
                user_id: USER,
                display_name: None,
                sender_key: own_key,
            },
            None,
            &utc,
        )
    }

    #[test]
    fn our_own_device_is_self() {
        let rec = device_record(USER, Some(MINE), Some(MINE));
        assert!(rec.is_self);
        assert_eq!(rec.self_basis, "device");
    }

    #[test]
    fn the_humans_device_on_the_same_account_is_not_self() {
        let rec = device_record(USER, Some(THEIRS), Some(MINE));
        assert!(!rec.is_self);
        assert_eq!(rec.self_basis, "device");
    }

    #[test]
    fn another_account_is_never_self() {
        assert!(!device_record("@someone:example.org", Some(MINE), Some(MINE)).is_self);
    }

    #[test]
    fn without_a_sender_key_it_falls_back_to_the_account_and_says_so() {
        let rec = device_record(USER, None, Some(MINE));
        assert!(rec.is_self);
        assert_eq!(rec.self_basis, "account");
    }

    #[test]
    fn without_our_own_key_it_falls_back_too() {
        let rec = device_record(USER, Some(THEIRS), None);
        assert!(rec.is_self);
        assert_eq!(rec.self_basis, "account");
    }

    #[test]
    fn own_device_lines_are_marked_in_the_text() {
        assert!(
            device_record(USER, Some(MINE), Some(MINE))
                .text
                .contains("(agent)")
        );
        assert!(
            !device_record(USER, Some(THEIRS), Some(MINE))
                .text
                .contains("(agent)")
        );
    }

    // --- DisplayNameFallbackTests ---------------------------------------------

    #[test]
    fn display_name_is_used_when_known() {
        let rec = record(
            1,
            Event {
                sender_display: Some("Björn Marten".into()),
                ..base_event()
            },
        );
        assert!(rec.text.contains("Björn Marten:"));
    }

    #[test]
    fn unknown_display_name_falls_back_to_the_localpart_and_the_record_keeps_the_mxid() {
        let rec = record(
            1,
            Event {
                sender: "@bjoern.marten:netresearch.de".into(),
                sender_display: None,
                ..base_event()
            },
        );
        assert!(rec.text.contains("bjoern.marten:"));
        assert!(!rec.text.contains("@bjoern.marten:netresearch.de"));
        assert_eq!(rec.sender, "@bjoern.marten:netresearch.de");
    }

    // --- ExcerptTests ---------------------------------------------------------

    #[test]
    fn excerpts() {
        assert_eq!(excerpt(Some("zwei\nzeilen")), "zwei zeilen");
        assert_eq!(
            excerpt(Some(&"x".repeat(200))).chars().count(),
            SUBJECT_LIMIT
        );
        assert_eq!(excerpt(Some("so bin beim RA")), "so bin beim RA");
        assert_eq!(excerpt(None), "");
    }

    // --- RelationTargetTests --------------------------------------------------

    fn reaction() -> Event {
        Event {
            event_id: "$reaction".into(),
            sender: "@sebastian.mendel:example.org".into(),
            sender_display: Some("Sebastian Mendel".into()),
            kind: "reaction".into(),
            body: Some("✅".into()),
            ts: 1_786_568_100_000,
            relates_to: Some("$target".into()),
            ..Default::default()
        }
    }

    fn redaction() -> Event {
        Event {
            event_id: "$redaction".into(),
            kind: "redaction".into(),
            body: None,
            relates_to: None,
            redacts: Some("$target".into()),
            ..reaction()
        }
    }

    fn rel(event: Event, subject: Option<&str>) -> Record {
        build_record_with(
            1,
            &event,
            &own("@me:example.org", Some("me")),
            subject,
            &utc,
        )
    }

    #[test]
    fn relations_are_kept() {
        assert_eq!(rel(reaction(), None).relates_to.as_deref(), Some("$target"));
        assert_eq!(rel(redaction(), None).redacts.as_deref(), Some("$target"));
        let reason = Event {
            reason: Some("Tippfehler".into()),
            ..redaction()
        };
        assert_eq!(rel(reason, None).reason.as_deref(), Some("Tippfehler"));
    }

    #[test]
    fn a_plain_message_gains_no_relation_keys() {
        let v = value(&record(1, base_event()));
        for key in ["relates_to", "redacts", "reason", "session_id"] {
            assert!(v.get(key).is_none(), "{key}");
        }
    }

    #[test]
    fn target_of_reads_either_relation() {
        assert_eq!(target_of(&value(&rel(reaction(), None))), Some("$target"));
        assert_eq!(target_of(&value(&rel(redaction(), None))), Some("$target"));
        assert_eq!(target_of(&value(&record(1, base_event()))), None);
    }

    #[test]
    fn relation_lines_name_the_message() {
        assert!(
            rel(reaction(), Some("so bin beim RA"))
                .text
                .contains("reacted ✅ to \"so bin beim RA\"")
        );
        assert!(
            rel(redaction(), Some("so bin beim RA"))
                .text
                .contains("removed \"so bin beim RA\"")
        );
        let reason = Event {
            reason: Some("Tippfehler".into()),
            ..redaction()
        };
        assert!(
            rel(reason, Some("ups"))
                .text
                .contains("removed \"ups\" (Tippfehler)")
        );
    }

    #[test]
    fn unresolvable_target_falls_back_instead_of_printing_an_id() {
        for (event, expected) in [
            (reaction(), "reacted ✅"),
            (redaction(), "removed a message"),
        ] {
            let text = rel(event, None).text;
            assert!(text.ends_with(expected), "{text}");
            assert!(!text.contains("$target"));
        }
    }

    #[test]
    fn two_redactions_of_different_messages_read_differently() {
        let first = rel(
            Event {
                redacts: Some("$one".into()),
                ..redaction()
            },
            Some("erste Nachricht"),
        );
        let second = rel(
            Event {
                redacts: Some("$two".into()),
                ..redaction()
            },
            Some("zweite Nachricht"),
        );
        assert_ne!(first.text, second.text);
        assert_ne!(first.redacts, second.redacts);
    }

    // --- SubjectIndexTests -----------------------------------------------------

    #[test]
    fn index_resolves_a_body_written_earlier_and_survives_a_restart() {
        let l = log();
        let rec = record(
            1,
            Event {
                event_id: "$one".into(),
                body: Some("so bin beim RA".into()),
                ..base_event()
            },
        );
        append_record(&l.path, &rec, DEFAULT_MAX_BYTES).unwrap();
        let index = SubjectIndex::from_log(&l.path);
        assert_eq!(index.get("$one"), Some("so bin beim RA"));
        let reacted = rel(
            Event {
                relates_to: Some("$one".into()),
                ..reaction()
            },
            index.get("$one"),
        );
        assert!(reacted.text.contains("to \"so bin beim RA\""));
    }

    #[test]
    fn bodiless_events_are_not_indexed() {
        let l = log();
        let rec = record(
            1,
            Event {
                event_id: "$r".into(),
                kind: "redaction".into(),
                body: None,
                ..base_event()
            },
        );
        append_record(&l.path, &rec, DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(SubjectIndex::from_log(&l.path).len(), 0);
    }

    #[test]
    fn the_index_is_bounded_and_drops_the_oldest() {
        let mut index = SubjectIndex::new(3);
        for n in 0..5 {
            index.remember(&value(&record(
                n,
                Event {
                    event_id: format!("$e{n}"),
                    body: Some(format!("m{n}")),
                    ..base_event()
                },
            )));
        }
        assert_eq!(index.len(), 3);
        assert_eq!(index.get("$e0"), None);
        assert_eq!(index.get("$e4"), Some("m4"));
    }

    #[test]
    fn a_repeated_id_keeps_its_place_like_a_python_dict() {
        let mut index = SubjectIndex::new(2);
        let remember = |index: &mut SubjectIndex, id: &str, body: &str| {
            index.remember(&serde_json::json!({"event_id": id, "body": body}));
        };
        remember(&mut index, "$a", "1");
        remember(&mut index, "$b", "2");
        remember(&mut index, "$a", "3");
        remember(&mut index, "$c", "4");
        assert_eq!(index.get("$a"), None, "$a was still the oldest entry");
        assert_eq!(index.get("$b"), Some("2"));
    }

    // --- file names (4712777835) -----------------------------------------------

    #[test]
    fn rooms_whose_slugs_agree_get_files_of_their_own() {
        let (plus, underscore) = ("!a+b:example.org", "!a_b:example.org");
        assert_eq!(room_slug(plus), room_slug(underscore));
        let dir = tempfile::tempdir().unwrap();
        assert_ne!(
            log_path(dir.path(), plus).unwrap(),
            log_path(dir.path(), underscore).unwrap()
        );
        assert_ne!(
            cursor_path(dir.path(), plus, "default").unwrap(),
            cursor_path(dir.path(), underscore, "default").unwrap()
        );
        // Readable: the slug, then 12 hex digits of SHA-256 over the exact id.
        assert_eq!(room_file_stem(plus), "a_b_example.org-5bf71c05a203");
        assert_eq!(room_file_stem(underscore), "a_b_example.org-43b6871733a2");
        let rooms = vec![
            (plus.to_owned(), "#plus:example.org".to_owned()),
            (underscore.to_owned(), "#underscore:example.org".to_owned()),
        ];
        write_room_bundle_at(dir.path(), &rooms, "STAMP").unwrap();
        assert_eq!(
            read_room_pages(dir.path()).len(),
            2,
            "one page overwrote the other"
        );
    }

    // --- gap records (4712777805) ----------------------------------------------

    fn gap(after: Option<(&str, i64)>, before: Option<(&str, i64)>) -> GapRecord {
        build_gap_record_with(
            7,
            &Gap {
                room_id: "!r:example.org".into(),
                after: after.map(|(id, ts)| (id.to_owned(), ts)),
                before: before.map(|(id, ts)| (id.to_owned(), ts)),
                noticed: 1_786_568_100_000,
            },
            &utc,
        )
    }

    #[test]
    fn a_gap_record_has_its_own_type_and_one_line() {
        let rec = gap(
            Some(("$last", 1_786_560_000_000)),
            Some(("$next", 1_786_568_040_000)),
        );
        assert_eq!(
            serde_json::to_string(&rec).unwrap(),
            concat!(
                r#"{"seq":7,"ts":1786568040000,"room_id":"!r:example.org","type":"gap","#,
                r#""after_event_id":"$last","after_ts":1786560000000,"#,
                r#""before_event_id":"$next","before_ts":1786568040000,"#,
                r#""text":"[20:54] --- gap: events after 18:40 and before 20:54 are missing from this log; the server left them out and they could not be fetched ---"}"#
            )
        );
        let unknown = gap(None, None);
        assert_eq!(unknown.ts, 1_786_568_100_000);
        assert_eq!(
            (unknown.after_event_id, unknown.before_event_id),
            (None, None)
        );
        assert_eq!(
            unknown.text,
            "[20:55] --- gap: events are missing from this log; the server left them out and they could not be fetched ---"
        );
        assert!(
            gap(Some(("$l", 1_786_560_000_000)), None)
                .text
                .contains("events after 18:40 are")
        );
    }

    #[test]
    fn a_gap_is_no_message_and_makes_the_summary_a_lower_bound() {
        let l = cursor_log();
        append_record(&l.path, &gap(Some(("$e5", 0)), None), DEFAULT_MAX_BYTES).unwrap();
        let s = summarize_since(&l.path, 3);
        assert_eq!((s.total, s.mentions, s.last_seq), (2, 1, 7));
        assert!(
            s.truncated,
            "a gap after the cursor leaves the count a lower bound"
        );
        assert!(!summarize_since(&l.path, 7).truncated);
    }

    #[test]
    fn logged_events_skip_notices_gaps_and_corrections() {
        let l = log();
        let mut logged = LoggedEvents::default();
        for (seq, id) in [(1, "$a"), (2, "$daemon-5"), (3, "$b"), (4, "$a")] {
            let rec = record(
                seq,
                Event {
                    event_id: id.into(),
                    ts: seq * 10,
                    ..base_event()
                },
            );
            append_record(&l.path, &rec, DEFAULT_MAX_BYTES).unwrap();
            logged.remember(&value(&rec));
        }
        let gap = gap(None, None);
        append_record(&l.path, &gap, DEFAULT_MAX_BYTES).unwrap();
        logged.remember(&serde_json::to_value(&gap).unwrap());
        for logged in [logged, LoggedEvents::from_log(&l.path)] {
            assert!(logged.contains("$a") && logged.contains("$b"));
            assert!(!logged.contains("$daemon-5"));
            // The correction of $a does not move "last" back to it.
            assert_eq!(logged.last(), Some(&("$b".to_owned(), 30)));
        }
    }
}
