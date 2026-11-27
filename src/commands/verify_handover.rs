//! The hand-over between a `verify` that waits without a terminal and the
//! `verify --confirm` / `verify --cancel` an agent runs after the person
//! compared the emoji.
//!
//! The waiting process holds the data-directory lock, so the second process
//! never takes it: it talks to the waiting one through owner-only files in
//! `<data_dir>/verify`. The waiting process writes
//! `<pid>-<nonce>.emoji.json` (the JSON line it printed); the second process
//! writes `<pid>-<nonce>.decision.json` next to it. The nonce is fresh random
//! for every published comparison and the waiting process reads only the
//! decision file named with its own nonce that also carries its own
//! transaction id, so a decision file left from an earlier run or written
//! for another transaction can never confirm a new verification.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::session::ensure_private_dir;
use crate::text::{json_line, term};

const EMOJI_SUFFIX: &str = ".emoji.json";
const DECISION_SUFFIX: &str = ".decision.json";
const TMP_SUFFIX: &str = ".tmp";

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
}

/// The person's answer, handed over by `--confirm` or `--cancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Confirm,
    Cancel,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecisionFile {
    transaction_id: String,
    decision: Decision,
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write `bytes` to `path` with mode 0600: a temporary file created
/// 0600 at open time, renamed over the target.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
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
        fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))
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
        if [EMOJI_SUFFIX, DECISION_SUFFIX, TMP_SUFFIX]
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
/// that owns it).
#[derive(Debug)]
pub struct Pending {
    transaction_id: String,
    emoji_file: PathBuf,
    decision_file: PathBuf,
}

impl Pending {
    /// Write the emoji file for `comparison` into `dir`.
    pub fn publish(dir: &Path, comparison: &Comparison) -> Result<Self> {
        ensure_private_dir(dir)?;
        let stem = format!("{}-{}", std::process::id(), random_nonce());
        let pending = Self {
            transaction_id: comparison.transaction_id.clone(),
            emoji_file: dir.join(format!("{stem}{EMOJI_SUFFIX}")),
            decision_file: dir.join(format!("{stem}{DECISION_SUFFIX}")),
        };
        // Created before the emoji file exists, so it cannot be a decision.
        let _ = fs::remove_file(&pending.decision_file);
        let line = json_line(comparison)?;
        write_private(&pending.emoji_file, format!("{line}\n").as_bytes())?;
        Ok(pending)
    }

    /// The decision for this comparison, once one was handed over. A file
    /// under this name that names another transaction is removed, not used.
    /// Once a decision is read, the emoji file goes too: the verification
    /// no longer waits, so a later --confirm or --cancel finds nothing.
    pub fn poll(&self) -> Result<Option<Decision>> {
        let Some(text) = read_private(&self.decision_file)? else {
            return Ok(None);
        };
        let _ = fs::remove_file(&self.decision_file);
        let file: DecisionFile = match serde_json::from_str(&text) {
            Ok(file) => file,
            Err(_) => return Ok(None),
        };
        if file.transaction_id != self.transaction_id {
            return Ok(None);
        }
        let _ = fs::remove_file(&self.emoji_file);
        Ok(Some(file.decision))
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.emoji_file);
        let _ = fs::remove_file(&self.decision_file);
    }
}

/// A verification that waits for a decision.
#[derive(Debug)]
pub struct Waiting {
    pub pid: u32,
    pub comparison: Comparison,
    decision_file: PathBuf,
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

/// The verifications waiting in `dir`: emoji files of running processes.
pub fn waiting(dir: &Path) -> Result<Vec<Waiting>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot list {}", dir.display())),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(EMOJI_SUFFIX) else {
            continue;
        };
        let Some(pid) = stem
            .split_once('-')
            .and_then(|(pid, _)| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if !process_alive(pid) {
            continue;
        }
        let Some(text) = read_private(&entry.path())? else {
            continue;
        };
        let Ok(comparison) = serde_json::from_str::<Comparison>(&text) else {
            continue;
        };
        found.push(Waiting {
            pid,
            comparison,
            decision_file: dir.join(format!("{stem}{DECISION_SUFFIX}")),
        });
    }
    found.sort_by(|a, b| {
        a.comparison
            .transaction_id
            .cmp(&b.comparison.transaction_id)
    });
    Ok(found)
}

/// Hand `decision` to the verification with `transaction_id`, or to the
/// only waiting one when none is given.
pub fn hand_over(dir: &Path, transaction_id: Option<&str>, decision: Decision) -> Result<Waiting> {
    let mut candidates: Vec<Waiting> = waiting(dir)?
        .into_iter()
        .filter(|w| transaction_id.is_none_or(|id| w.comparison.transaction_id == id))
        .collect();
    let target = match (candidates.len(), transaction_id) {
        (1, _) => candidates.remove(0),
        (0, Some(id)) => bail!("no waiting verification has transaction id {}", term(id)),
        (0, None) => bail!("no verification is waiting for a decision"),
        (_, _) => bail!(
            "{} verifications are waiting; name one: {}",
            candidates.len(),
            candidates
                .iter()
                .map(|w| term(&w.comparison.transaction_id).into_owned())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let file = DecisionFile {
        transaction_id: target.comparison.transaction_id.clone(),
        decision,
    };
    write_private(
        &target.decision_file,
        serde_json::to_string(&file)?.as_bytes(),
    )?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comparison(id: &str) -> Comparison {
        Comparison {
            transaction_id: id.to_owned(),
            other_device: "PHONE".to_owned(),
            emojis: vec![
                EmojiItem {
                    symbol: "🐶".to_owned(),
                    description: "Dog".to_owned(),
                },
                EmojiItem {
                    symbol: "🔑".to_owned(),
                    description: "Key".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn confirm_reaches_the_waiting_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = Pending::publish(tmp.path(), &comparison("tx1")).unwrap();
        assert_eq!(
            pending.poll().unwrap(),
            None,
            "decided before any hand-over"
        );
        let target = hand_over(tmp.path(), None, Decision::Confirm).unwrap();
        assert_eq!(target.comparison.transaction_id, "tx1");
        assert_eq!(target.pid, std::process::id());
        assert_eq!(pending.poll().unwrap(), Some(Decision::Confirm));
        // Decided: a later --cancel must not report a hand-over nobody reads.
        assert!(hand_over(tmp.path(), None, Decision::Cancel).is_err());
    }

    #[test]
    fn cancel_reaches_the_waiting_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = Pending::publish(tmp.path(), &comparison("tx1")).unwrap();
        hand_over(tmp.path(), Some("tx1"), Decision::Cancel).unwrap();
        assert_eq!(pending.poll().unwrap(), Some(Decision::Cancel));
    }

    #[test]
    fn a_wrong_transaction_id_hands_nothing_over() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = Pending::publish(tmp.path(), &comparison("tx1")).unwrap();
        let err = hand_over(tmp.path(), Some("tx2"), Decision::Confirm).unwrap_err();
        assert!(err.to_string().contains("tx2"), "{err}");
        assert_eq!(pending.poll().unwrap(), None);
    }

    #[test]
    fn a_stale_decision_file_never_confirms() {
        let tmp = tempfile::tempdir().unwrap();
        // An earlier run of this process id handed over a confirm for the
        // same transaction id and ended before reading it.
        let earlier = Pending::publish(tmp.path(), &comparison("tx1")).unwrap();
        hand_over(tmp.path(), None, Decision::Confirm).unwrap();
        let stale = earlier.decision_file.clone();
        let kept = fs::read(&stale).unwrap();
        drop(earlier);
        write_private(&stale, &kept).unwrap();

        let pending = Pending::publish(tmp.path(), &comparison("tx1")).unwrap();
        assert_ne!(pending.decision_file, stale);
        assert_eq!(pending.poll().unwrap(), None, "a stale decision confirmed");

        // A decision under the right name that names another transaction.
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
    }

    #[test]
    fn sweep_removes_what_an_ended_process_left() {
        let tmp = tempfile::tempdir().unwrap();
        let earlier = Pending::publish(tmp.path(), &comparison("tx1")).unwrap();
        hand_over(tmp.path(), None, Decision::Confirm).unwrap();
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
    fn two_waiting_need_a_transaction_id() {
        let tmp = tempfile::tempdir().unwrap();
        let first = Pending::publish(tmp.path(), &comparison("tx1")).unwrap();
        let second = Pending::publish(tmp.path(), &comparison("tx2")).unwrap();
        let err = hand_over(tmp.path(), None, Decision::Confirm).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tx1") && msg.contains("tx2"), "{msg}");
        assert_eq!(first.poll().unwrap(), None);
        assert_eq!(second.poll().unwrap(), None);
        hand_over(tmp.path(), Some("tx2"), Decision::Confirm).unwrap();
        assert_eq!(first.poll().unwrap(), None);
        assert_eq!(second.poll().unwrap(), Some(Decision::Confirm));
    }

    #[test]
    fn none_waiting_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("verify");
        let err = hand_over(&missing, None, Decision::Confirm).unwrap_err();
        assert!(
            err.to_string().contains("no verification is waiting"),
            "{err}"
        );
        let pending = Pending::publish(&missing, &comparison("tx1")).unwrap();
        drop(pending);
        assert!(hand_over(&missing, None, Decision::Cancel).is_err());
        assert_eq!(
            fs::read_dir(&missing).unwrap().count(),
            0,
            "files left behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_dead_process_is_not_waiting() {
        let tmp = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        let line = json_line(&comparison("tx1")).unwrap();
        write_private(
            &tmp.path().join(format!("{dead}-00{EMOJI_SUFFIX}")),
            line.as_bytes(),
        )
        .unwrap();
        assert!(hand_over(tmp.path(), None, Decision::Confirm).is_err());
    }

    #[test]
    fn emoji_file_holds_the_printed_line() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = Pending::publish(tmp.path(), &comparison("tx1")).unwrap();
        let text = fs::read_to_string(&pending.emoji_file).unwrap();
        assert_eq!(
            text,
            "{\"transaction_id\":\"tx1\",\"other_device\":\"PHONE\",\"emojis\":[{\"symbol\":\"🐶\",\"description\":\"Dog\"},{\"symbol\":\"🔑\",\"description\":\"Key\"}]}\n"
        );
        assert_eq!(text.trim_end(), json_line(&comparison("tx1")).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn hand_over_files_are_owner_only() {
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("verify");
        let pending = Pending::publish(&dir, &comparison("tx1")).unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&pending.emoji_file), 0o600);
        hand_over(&dir, None, Decision::Confirm).unwrap();
        assert_eq!(mode(&pending.decision_file), 0o600);
        // A decision file others could have written is refused.
        fs::set_permissions(&pending.decision_file, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(pending.poll().is_err());
    }
}
