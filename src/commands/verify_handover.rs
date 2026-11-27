//! The hand-over between a `verify` that waits without a terminal and the
//! `verify --confirm TOKEN` / `verify --cancel TOKEN` an agent runs after the
//! person compared the emoji.
//!
//! The waiting process holds the data-directory lock, so the second process
//! never takes it: it talks to the waiting one through owner-only files in
//! `<data_dir>/verify`, all named after the comparison's token
//! `<pid>-<nonce>`. The nonce is fresh random for every published comparison.
//!
//! - `<token>.emoji.json`: written by the waiting process, the JSON line it
//!   printed (with the token).
//! - `<token>.decision.json`: written by `--confirm` / `--cancel`, only when
//!   the emoji file of exactly that token exists.
//! - `<token>.taken.json`: the waiting process's acknowledgement, naming
//!   what it did with the decision; `--confirm` / `--cancel` read and remove it.
//!
//! A decision is bound to the comparison the person saw by its token, not
//! by the transaction id (the other side chooses that in `--listen`); the
//! waiting process checks the transaction id as well. A decision file left
//! from an earlier run carries another token and is never read.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::session::ensure_private_dir;
use crate::text::{json_line, term};

const EMOJI_SUFFIX: &str = ".emoji.json";
const DECISION_SUFFIX: &str = ".decision.json";
const TAKEN_SUFFIX: &str = ".taken.json";
const TMP_SUFFIX: &str = ".tmp";
const NONCE_BYTES: usize = 16;

/// The hand-over directory inside the data directory.
pub fn handover_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("verify")
}

/// One emoji to compare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmojiItem {
    pub symbol: String,
    pub description: String,
}

/// What the waiting process prints on stdout and writes to its emoji file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comparison {
    pub transaction_id: String,
    pub other_device: String,
    pub emojis: Vec<EmojiItem>,
    /// What `--confirm` / `--cancel` name: this comparison and no other.
    pub token: String,
}

/// The person's answer, handed over by `--confirm` or `--cancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Confirm,
    Cancel,
}

/// What the waiting process did with a decision file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Taken {
    /// It confirms the emoji.
    Confirm,
    /// It cancels the verification.
    Cancel,
    /// The file was not a decision for its transaction; it keeps waiting.
    Ignored,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecisionFile {
    transaction_id: String,
    decision: Decision,
}

#[derive(Debug, Serialize, Deserialize)]
struct TakenFile {
    taken: Taken,
}

fn random_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The process id in a well-formed token `<pid>-<32 lowercase hex>`; anything
/// else (a path, a guess) is refused before it reaches a file name.
fn token_pid(token: &str) -> Option<u32> {
    let (pid, nonce) = token.split_once('-')?;
    let digits = !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit());
    let hex = nonce.len() == 2 * NONCE_BYTES
        && nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if digits && hex {
        pid.parse().ok()
    } else {
        None
    }
}

/// Write `bytes` to `path` with mode 0600: a temporary file created
/// 0600 at open time, renamed over the target.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    write_through_tmp(path, bytes, |tmp, path| fs::rename(tmp, path))
}

/// Like [`write_private`], but never replaces an existing `path`: the
/// temporary file is hard-linked to it, which fails when it exists. The
/// error then has kind `AlreadyExists`.
fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_through_tmp(path, bytes, |tmp, path| {
        let linked = fs::hard_link(tmp, path);
        let _ = fs::remove_file(tmp);
        linked
    })
    .map_err(|err| match err.downcast::<std::io::Error>() {
        Ok(io) => io,
        Err(other) => std::io::Error::other(format!("{other:#}")),
    })
}

fn write_through_tmp(
    path: &Path,
    bytes: &[u8],
    finish: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    let name = path
        .file_name()
        .context("hand-over file has no name")?
        .to_string_lossy()
        .into_owned();
    let tmp = path.with_file_name(format!(".{name}.{}{TMP_SUFFIX}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let written = (|| -> Result<()> {
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("cannot create {}", tmp.display()))?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        finish(&tmp, path).map_err(anyhow::Error::new)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// Read a hand-over file; `None` when there is none. Refuses anything but a
/// regular file, and on Unix a file that other users can read or write.
fn read_private(path: &Path) -> Result<Option<String>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file", path.display());
    }
    #[cfg(unix)]
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} has mode {:o}; hand-over files must be owner-only",
            path.display(),
            meta.permissions().mode() & 0o777
        );
    }
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Remove every hand-over file in `dir`. Only a process that holds the
/// data-directory lock calls this: no other waiting process can exist then,
/// so whatever is there is left over from a process that ended.
pub fn sweep(dir: &Path) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot list {}", dir.display())),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if [EMOJI_SUFFIX, DECISION_SUFFIX, TAKEN_SUFFIX, TMP_SUFFIX]
            .iter()
            .any(|s| name.ends_with(s))
        {
            fs::remove_file(entry.path())
                .with_context(|| format!("cannot remove {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// A comparison published by the waiting process. Dropping it removes its
/// emoji and decision files, on every exit path (a timeout drops the future
/// that owns it). The acknowledgement stays for `--confirm` / `--cancel`
/// to read; the next `verify` sweeps it if nobody did.
#[derive(Debug)]
pub struct Pending {
    /// The first decision read; every later poll returns it, so a cancel
    /// once seen stays a cancel.
    taken: std::sync::Mutex<Option<Decision>>,
    comparison: Comparison,
    line: String,
    emoji_file: PathBuf,
    decision_file: PathBuf,
    taken_file: PathBuf,
}

impl Pending {
    /// Give the comparison a fresh token and write its emoji file into `dir`.
    pub fn publish(
        dir: &Path,
        transaction_id: &str,
        other_device: &str,
        emojis: Vec<EmojiItem>,
    ) -> Result<Self> {
        ensure_private_dir(dir)?;
        let token = format!("{}-{}", std::process::id(), random_nonce());
        let comparison = Comparison {
            transaction_id: transaction_id.to_owned(),
            other_device: other_device.to_owned(),
            emojis,
            token: token.clone(),
        };
        let pending = Self {
            taken: std::sync::Mutex::new(None),
            line: json_line(&comparison)?,
            emoji_file: dir.join(format!("{token}{EMOJI_SUFFIX}")),
            decision_file: dir.join(format!("{token}{DECISION_SUFFIX}")),
            taken_file: dir.join(format!("{token}{TAKEN_SUFFIX}")),
            comparison,
        };
        // Removed before the emoji file exists, so neither can predate it.
        let _ = fs::remove_file(&pending.decision_file);
        let _ = fs::remove_file(&pending.taken_file);
        write_private(
            &pending.emoji_file,
            format!("{}\n", pending.line).as_bytes(),
        )?;
        Ok(pending)
    }

    /// The JSON line to print on stdout (the emoji file holds the same).
    pub fn line(&self) -> &str {
        &self.line
    }

    pub fn token(&self) -> &str {
        &self.comparison.token
    }

    fn acknowledge(&self, taken: Taken) -> Result<()> {
        write_private(
            &self.taken_file,
            serde_json::to_string(&TakenFile { taken })?.as_bytes(),
        )
    }

    /// The decision for this comparison, once one was handed over, and
    /// acknowledged. The first decision counts: it is kept and returned by
    /// every later poll, and its file stays, so no second hand-over can be
    /// placed. A file under this token that names another transaction is
    /// removed and acknowledged as ignored. Once a decision is taken the
    /// emoji file goes too: the verification no longer waits, so a later
    /// --confirm or --cancel finds nothing.
    pub fn poll(&self) -> Result<Option<Decision>> {
        let mut taken = self
            .taken
            .lock()
            .map_err(|_| anyhow::anyhow!("the decision state is poisoned"))?;
        if let Some(decision) = *taken {
            return Ok(Some(decision));
        }
        let Some(text) = read_private(&self.decision_file)? else {
            return Ok(None);
        };
        let decision = serde_json::from_str::<DecisionFile>(&text)
            .ok()
            .filter(|file| file.transaction_id == self.comparison.transaction_id)
            .map(|file| file.decision);
        let Some(decision) = decision else {
            let _ = fs::remove_file(&self.decision_file);
            self.acknowledge(Taken::Ignored)?;
            return Ok(None);
        };
        *taken = Some(decision);
        let _ = fs::remove_file(&self.emoji_file);
        self.acknowledge(match decision {
            Decision::Confirm => Taken::Confirm,
            Decision::Cancel => Taken::Cancel,
        })?;
        Ok(Some(decision))
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.emoji_file);
        let _ = fs::remove_file(&self.decision_file);
    }
}

/// A verification a decision was handed to.
#[derive(Debug)]
pub struct Waiting {
    pub pid: u32,
    pub comparison: Comparison,
    taken_file: PathBuf,
}

/// Whether process `pid` still runs. Without a way to ask (Windows), every
/// process counts as running; the next `verify` removes what a killed one left.
fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        // SAFETY: signal 0 only checks that the process exists.
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Hand `decision` to the comparison with `token`: only when its emoji file
/// exists, its process still runs and no decision was handed over before
/// (the first one counts).
pub fn hand_over(dir: &Path, token: &str, decision: Decision) -> Result<Waiting> {
    let Some(pid) = token_pid(token) else {
        bail!(
            "{} is not a verification token (the \"token\" of the emoji line)",
            term(token)
        );
    };
    let missing = || {
        anyhow::anyhow!("no verification waits with token {token}; it ended or was already decided")
    };
    if !process_alive(pid) {
        return Err(missing());
    }
    let text = read_private(&dir.join(format!("{token}{EMOJI_SUFFIX}")))?.ok_or_else(missing)?;
    let comparison: Comparison = serde_json::from_str(&text)
        .with_context(|| format!("the emoji file of token {token} is not valid"))?;
    if comparison.token != token {
        bail!("the emoji file of token {token} names another token");
    }
    // The acknowledgement of an earlier decider stays for that decider.
    let taken_file = dir.join(format!("{token}{TAKEN_SUFFIX}"));
    let file = DecisionFile {
        transaction_id: comparison.transaction_id.clone(),
        decision,
    };
    let decision_file = dir.join(format!("{token}{DECISION_SUFFIX}"));
    match write_new_private(&decision_file, serde_json::to_string(&file)?.as_bytes()) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("a decision was already handed over for token {token}; the first one counts")
        }
        Err(err) => {
            return Err(err).with_context(|| format!("cannot write {}", decision_file.display()));
        }
    }
    Ok(Waiting {
        pid,
        comparison,
        taken_file,
    })
}

/// Wait up to `within` for the waiting process to acknowledge the decision;
/// `None` when it did not answer.
pub fn await_taken(waiting: &Waiting, within: Duration, every: Duration) -> Result<Option<Taken>> {
    let deadline = Instant::now() + within;
    loop {
        // Read, never removed: another decider may read it too; the next
        // `verify` sweeps it.
        if let Some(text) = read_private(&waiting.taken_file)? {
            let file: TakenFile =
                serde_json::from_str(&text).context("the acknowledgement is not valid")?;
            return Ok(Some(file.taken));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(every);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUICK: Duration = Duration::from_millis(10);

    fn emojis() -> Vec<EmojiItem> {
        vec![
            EmojiItem {
                symbol: "🐶".to_owned(),
                description: "Dog".to_owned(),
            },
            EmojiItem {
                symbol: "🔑".to_owned(),
                description: "Key".to_owned(),
            },
        ]
    }

    fn publish(dir: &Path, id: &str) -> Pending {
        Pending::publish(dir, id, "PHONE", emojis()).unwrap()
    }

    #[test]
    fn confirm_reaches_the_waiting_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        assert_eq!(
            pending.poll().unwrap(),
            None,
            "decided before any hand-over"
        );
        let target = hand_over(tmp.path(), pending.token(), Decision::Confirm).unwrap();
        assert_eq!(target.comparison.transaction_id, "tx1");
        assert_eq!(target.pid, std::process::id());
        assert_eq!(pending.poll().unwrap(), Some(Decision::Confirm));
        assert_eq!(
            await_taken(&target, QUICK, QUICK).unwrap(),
            Some(Taken::Confirm)
        );
        // Decided: a later --cancel must not report a hand-over nobody reads.
        let err = hand_over(tmp.path(), pending.token(), Decision::Cancel).unwrap_err();
        assert!(err.to_string().contains("already decided"), "{err}");
    }

    #[test]
    fn the_first_decision_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        // --cancel, then --confirm before the waiting process polled.
        let first = hand_over(tmp.path(), pending.token(), Decision::Cancel).unwrap();
        let err = hand_over(tmp.path(), pending.token(), Decision::Confirm).unwrap_err();
        assert!(err.to_string().contains("already handed over"), "{err}");
        assert_eq!(pending.poll().unwrap(), Some(Decision::Cancel));
        assert_eq!(
            await_taken(&first, QUICK, QUICK).unwrap(),
            Some(Taken::Cancel)
        );
    }

    #[test]
    fn a_cancel_once_seen_stays_a_cancel() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        hand_over(tmp.path(), pending.token(), Decision::Cancel).unwrap();
        assert_eq!(pending.poll().unwrap(), Some(Decision::Cancel));
        // Whatever replaces the decision file afterwards.
        let confirm = DecisionFile {
            transaction_id: "tx1".to_owned(),
            decision: Decision::Confirm,
        };
        write_private(
            &pending.decision_file,
            serde_json::to_string(&confirm).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(pending.poll().unwrap(), Some(Decision::Cancel));
    }

    #[test]
    fn a_later_reader_keeps_the_acknowledgement() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        let first = hand_over(tmp.path(), pending.token(), Decision::Confirm).unwrap();
        assert_eq!(pending.poll().unwrap(), Some(Decision::Confirm));
        // A second decider fails, and does not take the first one's answer.
        assert!(hand_over(tmp.path(), pending.token(), Decision::Cancel).is_err());
        assert_eq!(
            await_taken(&first, QUICK, QUICK).unwrap(),
            Some(Taken::Confirm)
        );
        assert_eq!(
            await_taken(&first, QUICK, QUICK).unwrap(),
            Some(Taken::Confirm)
        );
    }

    #[test]
    fn a_second_decider_leaves_the_first_ones_acknowledgement() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        let first = hand_over(tmp.path(), pending.token(), Decision::Confirm).unwrap();
        // The first decision turns out not to name the transaction.
        let wrong = DecisionFile {
            transaction_id: "tx0".to_owned(),
            decision: Decision::Confirm,
        };
        write_private(
            &pending.decision_file,
            serde_json::to_string(&wrong).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(pending.poll().unwrap(), None);
        // A second decider may hand over now, and leaves the answer alone.
        hand_over(tmp.path(), pending.token(), Decision::Cancel).unwrap();
        assert_eq!(
            await_taken(&first, QUICK, QUICK).unwrap(),
            Some(Taken::Ignored)
        );
    }

    #[test]
    fn cancel_reaches_the_waiting_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        let target = hand_over(tmp.path(), pending.token(), Decision::Cancel).unwrap();
        assert_eq!(pending.poll().unwrap(), Some(Decision::Cancel));
        assert_eq!(
            await_taken(&target, QUICK, QUICK).unwrap(),
            Some(Taken::Cancel)
        );
    }

    #[test]
    fn a_token_reaches_only_its_own_comparison() {
        let tmp = tempfile::tempdir().unwrap();
        // The same transaction id twice: a peer or server may reuse one.
        let seen = publish(tmp.path(), "X");
        let unseen = publish(tmp.path(), "X");
        assert_ne!(seen.token(), unseen.token());
        hand_over(tmp.path(), seen.token(), Decision::Confirm).unwrap();
        assert_eq!(
            unseen.poll().unwrap(),
            None,
            "the other comparison was confirmed"
        );
        assert_eq!(seen.poll().unwrap(), Some(Decision::Confirm));
    }

    #[test]
    fn a_malformed_or_unknown_token_hands_nothing_over() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        let unknown = format!("{}-{}", std::process::id(), "0".repeat(32));
        for token in [
            "tx1",
            "",
            "../x",
            "1-../../etc",
            "1-ABCDEF0123456789ABCDEF0123456789",
            unknown.as_str(),
        ] {
            assert!(
                hand_over(tmp.path(), token, Decision::Confirm).is_err(),
                "{token:?} was accepted"
            );
        }
        assert_eq!(pending.poll().unwrap(), None);
    }

    #[test]
    fn only_a_well_formed_token_names_a_file() {
        let nonce = "0123456789abcdef0123456789abcdef";
        assert_eq!(token_pid(&format!("42-{nonce}")), Some(42));
        for token in [
            String::new(),
            "tx1".to_owned(),
            format!("-{nonce}"),
            format!("x-{nonce}"),
            format!("1/../2-{nonce}"),
            "1-../../etc".to_owned(),
            format!("1-{}", nonce.to_uppercase()),
            format!("1-{nonce}0"),
            format!("1-{}", &nonce[1..]),
        ] {
            assert_eq!(token_pid(&token), None, "{token:?} was accepted");
        }
    }

    #[test]
    fn a_stale_decision_file_never_confirms() {
        let tmp = tempfile::tempdir().unwrap();
        // An earlier run of this process id handed over a confirm for the
        // same transaction id and ended before reading it.
        let earlier = publish(tmp.path(), "tx1");
        hand_over(tmp.path(), earlier.token(), Decision::Confirm).unwrap();
        let stale = earlier.decision_file.clone();
        let kept = fs::read(&stale).unwrap();
        drop(earlier);
        write_private(&stale, &kept).unwrap();

        let pending = publish(tmp.path(), "tx1");
        assert_ne!(pending.decision_file, stale);
        assert_eq!(pending.poll().unwrap(), None, "a stale decision confirmed");

        // A decision under this token that names another transaction.
        let other = DecisionFile {
            transaction_id: "tx0".to_owned(),
            decision: Decision::Confirm,
        };
        write_private(
            &pending.decision_file,
            serde_json::to_string(&other).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(
            pending.poll().unwrap(),
            None,
            "another transaction confirmed"
        );
        assert!(!pending.decision_file.exists());
        assert!(pending.emoji_file.exists(), "it stopped waiting");
        let text = fs::read_to_string(&pending.taken_file).unwrap();
        assert_eq!(text, r#"{"taken":"ignored"}"#);
    }

    #[test]
    fn no_acknowledgement_is_reported_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        let target = hand_over(tmp.path(), pending.token(), Decision::Confirm).unwrap();
        let started = Instant::now();
        let taken = await_taken(&target, Duration::from_millis(100), QUICK).unwrap();
        assert_eq!(taken, None);
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn sweep_removes_what_an_ended_process_left() {
        let tmp = tempfile::tempdir().unwrap();
        let earlier = publish(tmp.path(), "tx1");
        hand_over(tmp.path(), earlier.token(), Decision::Confirm).unwrap();
        write_private(&earlier.taken_file, b"{}").unwrap();
        std::mem::forget(earlier);
        fs::write(tmp.path().join("unrelated"), "x").unwrap();
        sweep(tmp.path()).unwrap();
        let left: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("unrelated")]);
    }

    #[test]
    fn an_ended_comparison_leaves_no_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("verify");
        let pending = publish(&dir, "tx1");
        let token = pending.token().to_owned();
        drop(pending);
        assert!(hand_over(&dir, &token, Decision::Cancel).is_err());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "files left behind");
    }

    #[cfg(unix)]
    #[test]
    fn a_dead_process_is_not_waiting() {
        let tmp = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        let token = format!("{dead}-{}", "a".repeat(32));
        let comparison = Comparison {
            transaction_id: "tx1".to_owned(),
            other_device: "PHONE".to_owned(),
            emojis: emojis(),
            token: token.clone(),
        };
        write_private(
            &tmp.path().join(format!("{token}{EMOJI_SUFFIX}")),
            json_line(&comparison).unwrap().as_bytes(),
        )
        .unwrap();
        assert!(hand_over(tmp.path(), &token, Decision::Confirm).is_err());
    }

    #[test]
    fn emoji_file_holds_the_printed_line_with_its_token() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = publish(tmp.path(), "tx1");
        let token = pending.token().to_owned();
        assert!(token_pid(&token).is_some(), "{token}");
        assert_eq!(
            pending.line(),
            format!(
                "{{\"transaction_id\":\"tx1\",\"other_device\":\"PHONE\",\"emojis\":[{{\"symbol\":\"🐶\",\"description\":\"Dog\"}},{{\"symbol\":\"🔑\",\"description\":\"Key\"}}],\"token\":\"{token}\"}}"
            )
        );
        let text = fs::read_to_string(&pending.emoji_file).unwrap();
        assert_eq!(text, format!("{}\n", pending.line()));
    }

    #[cfg(unix)]
    #[test]
    fn hand_over_files_are_owner_only() {
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("verify");
        let pending = publish(&dir, "tx1");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&pending.emoji_file), 0o600);
        hand_over(&dir, pending.token(), Decision::Confirm).unwrap();
        assert_eq!(mode(&pending.decision_file), 0o600);
        // A decision file others could have written is refused.
        fs::set_permissions(&pending.decision_file, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(pending.poll().is_err());
        fs::set_permissions(&pending.decision_file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(pending.poll().unwrap(), Some(Decision::Confirm));
        assert_eq!(mode(&pending.taken_file), 0o600);
    }
}
