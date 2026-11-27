//! `fetch-keys`: ask your other devices for the room keys of the messages this
//! device cannot decrypt, sync to receive them, and count what arrived. The
//! counterpart of the matrix-skill's `matrix-fetch-keys.py`.
//!
//! matrix-sdk 0.20.0 has no public call to send a key request: its
//! `OlmMachine::request_room_key` sits behind `Client::olm_machine`, which is
//! crate-private. A failed decryption queues the request instead
//! (automatic-room-key-forwarding, only when one of our other devices is
//! verified), and the next sync sends it. So the scan below is what asks; the
//! output counts sessions without a key, not requests it cannot observe.

use std::collections::BTreeSet;
use std::future::Future;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::{FutureExt, Stream, StreamExt};
use matrix_sdk::deserialized_responses::{TimelineEvent, TimelineEventKind};

use crate::FetchKeysArgs;
use crate::commands::read::{
    SyncWarnings, fetch_events, sync_with_timeout, to_line, warn_without_verified_device,
};
use crate::commands::resolve_room;
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::term;

/// Python's initial sync long-polls 10 s, each sync while waiting 5 s.
const INITIAL_SYNC_TIMEOUT: Duration = Duration::from_secs(10);
const WAIT_SYNC_TIMEOUT: Duration = Duration::from_secs(5);

/// What one scan of the room history found.
#[derive(Debug, Default, PartialEq)]
pub struct Scan {
    /// Timeline events returned (all types, as Python's `len(result.chunk)`).
    pub messages: usize,
    /// Events this device cannot decrypt.
    pub undecryptable: BTreeSet<String>,
    /// Events this device decrypted.
    pub decrypted: usize,
    /// Every event id of the scan.
    pub seen: BTreeSet<String>,
    /// The distinct Megolm sessions of the undecryptable events.
    pub sessions: BTreeSet<String>,
}

impl Scan {
    pub fn of(events: &[TimelineEvent]) -> Self {
        let mut scan = Scan {
            messages: events.len(),
            ..Scan::default()
        };
        for event in events {
            let id = event
                .raw()
                .get_field::<String>("event_id")
                .ok()
                .flatten()
                .unwrap_or_default();
            scan.seen.insert(id.clone());
            if matches!(event.kind, TimelineEventKind::Decrypted(_)) {
                scan.decrypted += 1;
            } else if let Some(line) = to_line(event, true).filter(|l| l.is_undecryptable()) {
                scan.undecryptable.insert(id);
                if let Some(Some(session)) = line.session_id {
                    scan.sessions.insert(session);
                }
            }
        }
        scan
    }

    /// The lines Python prints after "Fetching N messages from room...".
    pub fn report(&self) -> String {
        format!(
            "  Messages: {}\n  Encrypted (need keys): {}\n  Decrypted (have keys): {}\n  Sessions without a key: {}\n",
            self.messages,
            self.undecryptable.len(),
            self.decrypted,
            self.sessions.len()
        )
    }

    /// Events undecryptable in `self` that `later` holds and could decrypt.
    pub fn now_decryptable(&self, later: &Scan) -> usize {
        self.undecryptable
            .iter()
            .filter(|id| later.seen.contains(*id) && !later.undecryptable.contains(*id))
            .count()
    }
}

/// Python's line for a key that arrived: room and session cut to 20 characters.
pub fn key_line(room_id: &str, session_id: &str) -> String {
    let cut = |s: &str| s.chars().take(20).collect::<String>();
    format!(
        "  📨 Received key: {}... / {}...",
        term(&cut(room_id)),
        term(&cut(session_id))
    )
}

/// Python's progress line: after a sync that brought no new key, at every
/// whole 15 seconds.
pub fn progress_line(received: usize, last: &mut usize, elapsed_secs: u64) -> Option<String> {
    if received > *last {
        *last = received;
        None
    } else if elapsed_secs.is_multiple_of(15) && elapsed_secs > 0 {
        Some(format!("  [{elapsed_secs}s] Received {received} keys..."))
    } else {
        None
    }
}

/// The closing block, Python's wording where the facts are the same.
pub fn results(before: &Scan, received: usize, after: &Scan) -> String {
    let mut out = format!(
        "\n=== Results ===\nSessions without a key: {}\nKeys received: {received}\nNow decryptable: {} of {}\n",
        before.sessions.len(),
        before.now_decryptable(after),
        before.undecryptable.len()
    );
    if received > 0 {
        out.push_str(&format!(
            "\n✅ Received {received} keys!\nRun matrix-read-e2ee.py to read messages now.\n"
        ));
    } else {
        out.push_str(
            "\n⚠️  No keys received.\nPossible reasons:\n  - Device not verified in Element\n  - Other devices offline or don't share keys\n  - Try: Element → Settings → Security → enable key sharing\n",
        );
    }
    out
}

/// The two fields of matrix-sdk-crypto's RoomKeyInfo the output names.
pub trait KeyInfo {
    fn room(&self) -> &str;
    fn session(&self) -> &str;
}

impl KeyInfo for matrix_sdk_base::crypto::store::types::RoomKeyInfo {
    fn room(&self) -> &str {
        self.room_id.as_str()
    }
    fn session(&self) -> &str {
        &self.session_id
    }
}

/// Print a line per key the store has received since the last call; return
/// how many.
pub fn drain<S, I, E>(keys: &mut S) -> usize
where
    S: Stream<Item = Result<Vec<I>, E>> + Unpin,
    I: KeyInfo,
    E: std::fmt::Display,
{
    let mut count = 0;
    while let Some(Some(update)) = keys.next().now_or_never() {
        match update {
            Ok(infos) => {
                for info in infos {
                    count += 1;
                    println!("{}", key_line(info.room(), info.session()));
                }
            }
            Err(err) => eprintln!("warning: missed room key updates: {err}"),
        }
    }
    count
}

/// Sync until `total` has passed; `after` runs after each sync with the
/// seconds elapsed. A failed sync returns at once when the network is down
/// (matrix-sdk 0.20.0 does not retry a network failure), so the rest of its
/// `round` is waited out, never past `total`, instead of spinning. Each
/// distinct error is reported once through `warn`.
pub async fn sync_for<S, F, W, A>(
    total: Duration,
    round: Duration,
    mut sync: S,
    mut warn: W,
    mut after: A,
) where
    S: FnMut() -> F,
    F: Future<Output = Result<()>>,
    W: FnMut(String),
    A: FnMut(u64),
{
    let start = Instant::now();
    let mut warnings = SyncWarnings::default();
    while start.elapsed() < total {
        let begun = Instant::now();
        if let Err(err) = sync().await {
            if let Some(line) = warnings.line(&err) {
                warn(line);
            }
            let rest = round
                .saturating_sub(begun.elapsed())
                .min(total.saturating_sub(start.elapsed()));
            tokio::time::sleep(rest).await;
        }
        after(start.elapsed().as_secs());
    }
}

pub async fn run(args: FetchKeysArgs) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    // Subscribed before the first sync, as Python registers its key
    // callbacks before its initial sync.
    let mut keys = Box::pin(
        client
            .encryption()
            .room_keys_received_stream()
            .await
            .context("the crypto store is not open")?,
    );

    println!("Initial sync...");
    sync_with_timeout(&client, INITIAL_SYNC_TIMEOUT).await?;
    let mut received = drain(&mut keys);
    let room = resolve_room(&client, &args.room).await?;
    let name = room
        .display_name()
        .await
        .map(|n| n.to_string())
        .unwrap_or_else(|_| room.room_id().to_string());
    println!("Room: {}", term(&name));

    println!("\nFetching {} messages from room...", args.limit);
    let before = Scan::of(&fetch_events(&room, args.limit).await?);
    print!("{}", before.report());
    if before.undecryptable.is_empty() {
        println!("\n✅ No missing keys - all messages decryptable!");
        return Ok(());
    }

    warn_without_verified_device(&client).await;
    println!(
        "\nWaiting {}s for keys from other devices...",
        args.sync_time
    );
    println!("(Ensure you have other verified devices online)");
    let mut last = received;
    sync_for(
        Duration::from_secs(args.sync_time),
        WAIT_SYNC_TIMEOUT,
        || sync_with_timeout(&client, WAIT_SYNC_TIMEOUT),
        |line| eprintln!("{line}"),
        |elapsed| {
            received += drain(&mut keys);
            if let Some(line) = progress_line(received, &mut last, elapsed) {
                println!("{line}");
            }
        },
    )
    .await;

    let after = Scan::of(&fetch_events(&room, args.limit).await?);
    print!("{}", results(&before, received, &after));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::deserialized_responses::UnableToDecryptInfo;
    use serde_json::json;

    fn utd(event_id: &str, session_id: &str) -> TimelineEvent {
        TimelineEvent::from_utd(
            serde_json::from_value(json!({
                "type": "m.room.encrypted", "event_id": event_id, "sender": "@b:e",
                "origin_server_ts": 5u64,
                "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x",
                            "session_id": session_id, "sender_key": "k", "device_id": "D"}
            }))
            .unwrap(),
            serde_json::from_value::<UnableToDecryptInfo>(json!({"session_id": session_id}))
                .unwrap(),
        )
    }

    fn text(event_id: &str) -> TimelineEvent {
        TimelineEvent::from_plaintext(
            serde_json::from_value(json!({
                "type": "m.room.message", "event_id": event_id, "sender": "@a:e",
                "origin_server_ts": 6u64, "content": {"msgtype": "m.text", "body": "hi"}
            }))
            .unwrap(),
        )
    }

    fn topic() -> TimelineEvent {
        TimelineEvent::from_plaintext(
            serde_json::from_value(json!({
                "type": "m.room.topic", "state_key": "", "event_id": "$t", "sender": "@a:e",
                "origin_server_ts": 1u64, "content": {"topic": "t"}
            }))
            .unwrap(),
        )
    }

    #[test]
    fn scan_counts_as_pythons_history_pass() {
        // matrix-fetch-keys.py ROOM --limit N: two events of one session,
        // one of another, a message and a state event.
        let events = [
            utd("$1", "A"),
            utd("$2", "A"),
            utd("$3", "B"),
            text("$4"),
            topic(),
        ];
        let scan = Scan::of(&events);
        assert_eq!(
            scan.report(),
            "  Messages: 5\n  Encrypted (need keys): 3\n  Decrypted (have keys): 0\n  Sessions without a key: 2\n"
        );
    }

    #[test]
    fn results_count_what_decrypts_on_the_second_read() {
        let before = Scan::of(&[utd("$1", "A"), utd("$2", "B"), utd("$3", "C")]);
        // $1 now decrypts (plain text stands in for it), $2 still does not,
        // $3 is no longer in the window and does not count.
        let after = Scan::of(&[text("$1"), utd("$2", "B"), text("$9")]);
        assert_eq!(before.now_decryptable(&after), 1);
        let shown = results(&before, 2, &after);
        assert!(
            shown.starts_with(
                "\n=== Results ===\nSessions without a key: 3\nKeys received: 2\nNow decryptable: 1 of 3\n\n✅ Received 2 keys!\n"
            ),
            "{shown}"
        );
        let none = results(&before, 0, &before);
        assert!(
            none.contains("\n⚠️  No keys received.\nPossible reasons:\n"),
            "{none}"
        );
        assert!(none.contains("Now decryptable: 0 of 3"), "{none}");
    }

    #[test]
    fn key_and_progress_lines_as_python_prints_them() {
        assert_eq!(
            key_line("!abcdefghijklmnopqrstuvwxyz:e", "0123456789012345678901234"),
            "  📨 Received key: !abcdefghijklmnopqrs... / 01234567890123456789..."
        );
        // A server-chosen id cannot move the cursor.
        assert!(!key_line("!a\u{1b}[2J:e", "s").contains('\u{1b}'));
        let mut last = 0;
        assert_eq!(progress_line(0, &mut last, 0), None);
        assert_eq!(progress_line(0, &mut last, 7), None);
        assert_eq!(
            progress_line(0, &mut last, 15).as_deref(),
            Some("  [15s] Received 0 keys...")
        );
        // A sync that brought a key prints nothing and moves the mark.
        assert_eq!(progress_line(3, &mut last, 30), None);
        assert_eq!(last, 3);
        assert_eq!(
            progress_line(3, &mut last, 30).as_deref(),
            Some("  [30s] Received 3 keys...")
        );
    }

    struct Info(&'static str, &'static str);
    impl KeyInfo for Info {
        fn room(&self) -> &str {
            self.0
        }
        fn session(&self) -> &str {
            self.1
        }
    }

    #[tokio::test]
    async fn a_failing_sync_waits_out_its_round_and_warns_once() {
        // The network is down: every sync fails at once.
        let total = Duration::from_millis(350);
        let round = Duration::from_millis(100);
        let calls = std::cell::Cell::new(0u32);
        let mut warnings = Vec::new();
        let mut afters = 0u32;
        let started = Instant::now();
        sync_for(
            total,
            round,
            || {
                calls.set(calls.get() + 1);
                async { anyhow::bail!("sync failed: connection refused") }
            },
            |line| warnings.push(line),
            |_| afters += 1,
        )
        .await;
        let elapsed = started.elapsed();
        // About total / round syncs, not one per spin of the loop.
        assert!((3..=5).contains(&calls.get()), "{} syncs", calls.get());
        assert_eq!(afters, calls.get());
        assert_eq!(warnings, ["warning: sync failed: connection refused"]);
        // The last wait is cut at the deadline.
        assert!(elapsed >= total, "{elapsed:?}");
        assert!(elapsed < total + round, "{elapsed:?}");
    }

    #[test]
    fn drain_counts_every_key_and_does_not_wait() {
        let mut keys = futures_util::stream::iter([
            Ok::<_, String>(vec![Info("!r:e", "A"), Info("!r:e", "B")]),
            Err("lagged".to_owned()),
            Ok(vec![Info("!r:e", "C")]),
        ])
        .chain(futures_util::stream::pending());
        assert_eq!(drain(&mut keys), 3);
        assert_eq!(drain(&mut keys), 0);
    }
}
