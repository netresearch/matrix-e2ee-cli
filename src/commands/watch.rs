//! `watch`: follow a room's event log, the way the matrix-skill's
//! `matrix-watch.py` does. Reads the files the watch daemon writes and never
//! opens the store or takes the data-dir lock, so any number of these can run
//! beside the daemon.
//!
//! Two deliberate differences from matrix-watch.py:
//! - After a rotation, and when it starts following, the reader reads the log
//!   from its start and prints the records whose `seq` is newer than the
//!   cursor. matrix-watch.py seeks to the end there, which loses the records
//!   written between its last read and the (re)open.
//! - A line without its newline is kept until it is complete. matrix-watch.py
//!   reads it, fails to parse it and drops it, losing that record.
//!
//! The printed line is the record's `text` with control characters replaced
//! (as every other command prints text other people chose).

// The reader is Unix only (see `run`); elsewhere only `run` is used.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::WatchArgs;
use crate::daemon_client::{REQUEST_TIMEOUT, Reply, request};
use crate::room_arg::{RoomArg, classify};
use crate::roomlog::{
    cursor_path, log_path, parse_line, read_cursor, read_room_pages, seq_of, summarize_since,
    write_cursor,
};
use crate::session::Paths;
use crate::text::term;

const POLL: Duration = Duration::from_millis(500);

pub async fn run(args: WatchArgs) -> Result<()> {
    // The daemon that writes the logs runs on Unix only, and rotation is
    // detected by inode.
    #[cfg(not(unix))]
    {
        let _ = args;
        bail!("watch is not supported on this platform (Linux and macOS only)");
    }
    #[cfg(unix)]
    {
        let paths = Paths::from_env()?;
        tokio::task::spawn_blocking(move || follow_room(&paths, &args))
            .await
            .context("the reader task failed")?
    }
}

fn follow_room(paths: &Paths, args: &WatchArgs) -> Result<()> {
    let rooms_dir = paths.rooms_dir();
    let room_id = resolve_watched_room(&rooms_dir, &args.room);
    let status = || match request(
        &paths.daemon_socket(),
        &json!({"op": "status"}),
        REQUEST_TIMEOUT,
    ) {
        Ok(Reply::Answer(answer)) if answer.get("ok").and_then(Value::as_bool) == Some(true) => {
            Some(answer)
        }
        _ => None,
    };
    let Some(room_id) = room_id else {
        if status().is_some() {
            bail!(
                "the watch daemon is running but not watching {}; add it to \"watch_rooms\" in config.json and restart the daemon",
                args.room
            );
        }
        bail!(
            "no log for {}, and no watch daemon is running: matrix-e2ee-cli watch-daemon --start",
            args.room
        );
    };
    let log = log_path(&rooms_dir, &room_id)?;
    let cursor = cursor_path(&rooms_dir, &room_id, &args.cursor)?;

    if !log.exists() {
        // Two very different causes; naming the wrong one sends people to
        // restart a daemon that is already running.
        match status() {
            Some(answer) if watches(&answer, &room_id) => {
                eprintln!(
                    "Watching {}, nothing logged yet. The log starts at the first event after the daemon began watching; a sync does not replay history.",
                    term(&room_id)
                );
                return Ok(());
            }
            Some(_) => bail!(
                "the watch daemon is running but not watching {room_id}; add it to \"watch_rooms\" in config.json and restart the daemon"
            ),
            None => bail!(
                "no log for {room_id}, and no watch daemon is running: matrix-e2ee-cli watch-daemon --start"
            ),
        }
    }

    let seen = read_cursor(&cursor);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if !args.no_summary
        && let Some(line) = summary_line(&log, seen)
    {
        writeln!(out, "{line}")?;
    }
    let mut follower = Follower::new(log, cursor, seen);
    follower.poll(&mut out)?;
    out.flush()?;
    if args.once {
        return Ok(());
    }
    loop {
        std::thread::sleep(POLL);
        follower.poll(&mut out)?;
        out.flush()?;
    }
}

fn watches(status: &Value, room_id: &str) -> bool {
    status
        .get("rooms")
        .and_then(Value::as_array)
        .is_some_and(|rooms| rooms.iter().any(|r| r.as_str() == Some(room_id)))
}

/// The room id for ROOM without a client: a room id stands for itself; an
/// alias or a name is looked up in the room pages the daemon writes, by
/// their title (the `watch_rooms` entry) ignoring case. `None` when no
/// watched room has that title.
pub fn resolve_watched_room(rooms_dir: &Path, arg: &str) -> Option<String> {
    if let RoomArg::Id(id) = classify(arg) {
        return Some(id.to_string());
    }
    let wanted = arg.trim().to_lowercase();
    read_room_pages(rooms_dir)
        .into_iter()
        .find(|(_, title)| title.to_lowercase() == wanted)
        .map(|(id, _)| id)
}

/// "since last: ..." or nothing when nothing is new.
pub fn summary_line(log: &Path, seen: i64) -> Option<String> {
    let summary = summarize_since(log, seen);
    if summary.total == 0 {
        return None;
    }
    let about = if summary.truncated { "at least " } else { "" };
    Some(format!(
        "since last: {about}{} messages, {} mentioning you",
        summary.total, summary.mentions
    ))
}

/// Identity of the file behind a path (device and inode), to notice a
/// rotation.
#[cfg(unix)]
fn identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn identity(_meta: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Follows one log by its path across rotation (like `tail -F`), printing
/// each record newer than the cursor once and advancing the cursor.
pub struct Follower {
    log: PathBuf,
    cursor: PathBuf,
    seen: i64,
    file: Option<(File, Option<(u64, u64)>)>,
    offset: u64,
    partial: Vec<u8>,
    cursor_written: bool,
}

impl Follower {
    pub fn new(log: PathBuf, cursor: PathBuf, seen: i64) -> Self {
        Self {
            log,
            cursor,
            seen,
            file: None,
            offset: 0,
            partial: Vec::new(),
            cursor_written: false,
        }
    }

    /// Print what is new, once. Reopens the path when it now names another
    /// file (rotation) or a shorter one (truncation), after reading what was
    /// left in the old one.
    pub fn poll(&mut self, out: &mut dyn Write) -> Result<()> {
        if self.file.is_none() && !self.open()? {
            return self.mark_read();
        }
        let replaced = match (fs::metadata(&self.log), &self.file) {
            (Ok(meta), Some((_, id))) => {
                (id.is_some() && identity(&meta) != *id) || meta.len() < self.offset
            }
            // Between the rename and the first append: keep reading the
            // old file and look again next time.
            _ => false,
        };
        self.read_available(out)?;
        if replaced {
            self.file = None;
            self.partial.clear();
            if self.open()? {
                self.read_available(out)?;
            }
        }
        self.mark_read()
    }

    fn open(&mut self) -> Result<bool> {
        match File::open(&self.log) {
            Ok(file) => {
                let id = file.metadata().ok().and_then(|m| identity(&m));
                self.file = Some((file, id));
                self.offset = 0;
                self.partial.clear();
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("cannot open {}", self.log.display())),
        }
    }

    /// The cursor is written at least once, also when nothing was new.
    fn mark_read(&mut self) -> Result<()> {
        if !self.cursor_written {
            write_cursor(&self.cursor, self.seen)?;
            self.cursor_written = true;
        }
        Ok(())
    }

    fn read_available(&mut self, out: &mut dyn Write) -> Result<()> {
        let Some((file, _)) = self.file.as_mut() else {
            return Ok(());
        };
        file.seek(SeekFrom::Start(self.offset))?;
        let mut fresh = Vec::new();
        file.read_to_end(&mut fresh)
            .with_context(|| format!("cannot read {}", self.log.display()))?;
        self.offset += fresh.len() as u64;
        self.partial.extend_from_slice(&fresh);
        let Some(end) = self.partial.iter().rposition(|b| *b == b'\n') else {
            return Ok(());
        };
        let complete: Vec<u8> = self.partial.drain(..=end).collect();
        for line in complete.split(|b| *b == b'\n') {
            let Some(record) = parse_line(line) else {
                continue;
            };
            let seq = seq_of(&record);
            if seq <= self.seen {
                continue;
            }
            if let Some(text) = record.get("text").and_then(Value::as_str) {
                writeln!(out, "{}", term(text))?;
            }
            self.seen = seq;
            write_cursor(&self.cursor, seq)?;
            self.cursor_written = true;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::roomlog::{
        DEFAULT_MAX_BYTES, Event, Own, append_record, build_record, read_cursor,
        write_room_bundle_at,
    };
    use std::fs::OpenOptions;

    fn append(log: &Path, seq: i64, body: &str, max_bytes: u64) {
        let event = Event {
            event_id: format!("$e{seq}"),
            sender: "@a:example.org".into(),
            ts: 1_786_568_100_000,
            kind: "m.text".into(),
            body: Some(body.into()),
            ..Default::default()
        };
        let own = Own {
            user_id: "@me:example.org",
            display_name: None,
            sender_key: None,
        };
        append_record(log, &build_record(seq, &event, &own, None), max_bytes).unwrap();
    }

    fn printed(follower: &mut Follower) -> Vec<String> {
        let mut out = Vec::new();
        follower.poll(&mut out).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| l.split_once(": ").unwrap().1.to_owned())
            .collect()
    }

    struct Setup {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        log: PathBuf,
        cursor: PathBuf,
    }

    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let log = log_path(dir.path(), "!r:example.org").unwrap();
        let cursor = cursor_path(dir.path(), "!r:example.org", "default").unwrap();
        Setup {
            dir: dir.path().to_owned(),
            _dir: dir,
            log,
            cursor,
        }
    }

    #[test]
    fn prints_what_is_new_and_advances_the_cursor() {
        let s = setup();
        append(&s.log, 1, "eins", DEFAULT_MAX_BYTES);
        append(&s.log, 2, "zwei", DEFAULT_MAX_BYTES);
        let mut f = Follower::new(s.log.clone(), s.cursor.clone(), 1);
        assert_eq!(printed(&mut f), vec!["zwei"]);
        assert_eq!(read_cursor(&s.cursor), 2);
        assert!(printed(&mut f).is_empty());
        append(&s.log, 3, "drei", DEFAULT_MAX_BYTES);
        assert_eq!(printed(&mut f), vec!["drei"]);
        assert_eq!(read_cursor(&s.cursor), 3);
        // A second reader with the same cursor starts after it.
        let mut again = Follower::new(s.log.clone(), s.cursor.clone(), read_cursor(&s.cursor));
        assert!(printed(&mut again).is_empty());
    }

    #[test]
    fn the_cursor_is_written_also_when_nothing_is_new() {
        let s = setup();
        append(&s.log, 1, "eins", DEFAULT_MAX_BYTES);
        let mut f = Follower::new(s.log.clone(), s.cursor.clone(), 5);
        assert!(printed(&mut f).is_empty());
        assert_eq!(fs::read_to_string(&s.cursor).unwrap(), "5\n");
    }

    #[test]
    fn rotation_is_followed_without_losing_a_record() {
        let s = setup();
        append(&s.log, 1, "eins", DEFAULT_MAX_BYTES);
        let mut f = Follower::new(s.log.clone(), s.cursor.clone(), 0);
        assert_eq!(printed(&mut f), vec!["eins"]);
        append(&s.log, 2, "zwei", DEFAULT_MAX_BYTES);
        // Rotates: record 2 stays in .1, record 3 starts the new file.
        append(&s.log, 3, "drei", 1);
        assert!(crate::roomlog::rotated(&s.log).exists());
        append(&s.log, 4, "vier", DEFAULT_MAX_BYTES);
        assert_eq!(printed(&mut f), vec!["zwei", "drei", "vier"]);
        assert_eq!(read_cursor(&s.cursor), 4);
        append(&s.log, 5, "fünf", DEFAULT_MAX_BYTES);
        assert_eq!(printed(&mut f), vec!["fünf"]);
    }

    #[test]
    fn a_log_that_appears_later_is_picked_up() {
        let s = setup();
        let mut f = Follower::new(s.log.clone(), s.cursor.clone(), 0);
        assert!(printed(&mut f).is_empty());
        append(&s.log, 1, "eins", DEFAULT_MAX_BYTES);
        assert_eq!(printed(&mut f), vec!["eins"]);
    }

    #[test]
    fn a_partial_line_waits_until_it_is_complete() {
        let s = setup();
        append(&s.log, 1, "eins", DEFAULT_MAX_BYTES);
        let mut f = Follower::new(s.log.clone(), s.cursor.clone(), 0);
        assert_eq!(printed(&mut f), vec!["eins"]);
        let line = serde_json::to_string(&json!({"seq": 2, "text": "[00:00] a: zwei"})).unwrap();
        let (head, tail) = line.split_at(10);
        let mut file = OpenOptions::new().append(true).open(&s.log).unwrap();
        file.write_all(head.as_bytes()).unwrap();
        assert!(printed(&mut f).is_empty());
        file.write_all(format!("{tail}\n").as_bytes()).unwrap();
        assert_eq!(printed(&mut f), vec!["zwei"]);
    }

    #[test]
    fn control_characters_in_a_line_are_replaced() {
        let s = setup();
        fs::write(&s.log, "{\"seq\":1,\"text\":\"[00:00] a: x\\u001b[2Jy\"}\n").unwrap();
        let mut f = Follower::new(s.log.clone(), s.cursor.clone(), 0);
        assert_eq!(printed(&mut f), vec!["x\u{FFFD}[2Jy"]);
    }

    #[test]
    fn summary_line_reports_only_a_gap() {
        let s = setup();
        assert_eq!(summary_line(&s.log, 0), None);
        append(&s.log, 1, "hallo me", DEFAULT_MAX_BYTES);
        append(&s.log, 2, "nichts", DEFAULT_MAX_BYTES);
        assert_eq!(
            summary_line(&s.log, 0).as_deref(),
            Some("since last: 2 messages, 1 mentioning you")
        );
        assert_eq!(summary_line(&s.log, 2), None);
    }

    #[test]
    fn rooms_resolve_without_a_client() {
        let s = setup();
        write_room_bundle_at(
            &s.dir,
            &[("!abc:example.org".into(), "#ops:example.org".into())],
            "STAMP",
        )
        .unwrap();
        assert_eq!(
            resolve_watched_room(&s.dir, "!xyz:example.org").as_deref(),
            Some("!xyz:example.org")
        );
        assert_eq!(
            resolve_watched_room(&s.dir, "#OPS:example.org").as_deref(),
            Some("!abc:example.org")
        );
        assert_eq!(resolve_watched_room(&s.dir, "#it:example.org"), None);
        assert_eq!(resolve_watched_room(&s.dir, "ops"), None);
    }
}
