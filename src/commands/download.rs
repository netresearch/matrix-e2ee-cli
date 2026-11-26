//! `download`: save the attachment of an `m.file`, `m.image`, `m.video` or
//! `m.audio` message; matrix-sdk decrypts an encrypted attachment.
//!
//! The file name comes from the message, so only a sanitized last component
//! is used, and an existing file is never replaced.

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use matrix_sdk::deserialized_responses::TimelineEvent;
use matrix_sdk::media::{MediaFormat, MediaRequestParameters};
use matrix_sdk::ruma::events::room::MediaSource;
use matrix_sdk::ruma::events::room::message::MessageType;
use matrix_sdk::ruma::events::{AnySyncMessageLikeEvent, AnySyncTimelineEvent};

use crate::DownloadArgs;
use crate::commands::{fetch_event, parse_event_id, resolve_room, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::term;

/// The name used when neither the message nor the event id yields one.
const DEFAULT_NAME: &str = "media_download";
/// Bytes; file systems allow 255, this leaves room for nothing else to fail.
const MAX_NAME: usize = 200;

pub async fn run(args: DownloadArgs) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let room = resolve_room(&client, &args.room).await?;
    let event_id = parse_event_id(&args.event_id)?;

    let (event, json) = fetch_event(&room, &event_id).await?;
    if super::is_redacted(&json) {
        bail!("the event was redacted; its media is no longer referenced");
    }
    if json.get("type").and_then(serde_json::Value::as_str) == Some("m.room.encrypted") {
        bail!("this device cannot decrypt the event; run backup-restore to import the room key");
    }
    let (source, name) = media_of(&event)?;
    let name = sanitize_file_name(args.filename.as_deref().unwrap_or(&name), event_id.as_str());
    let dir = args.output.unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let path = dir.join(&name);
    // Checked before the download to fail early; create_new below decides.
    if fs::symlink_metadata(&path).is_ok() {
        bail!(
            "{} exists; choose another name with --filename or another directory with --output",
            path.display()
        );
    }

    let data = client
        .media()
        .get_media_content(
            &MediaRequestParameters {
                source,
                format: MediaFormat::File,
            },
            // No cache: it would keep a decrypted copy in the store.
            false,
        )
        .await
        .context("downloading the attachment failed")?;
    write_new(&path, &data)?;
    println!("{}", term(&path.display().to_string()));
    Ok(())
}

/// The attachment source and the file name the message gives
/// (`filename`, else `body`).
fn media_of(event: &TimelineEvent) -> Result<(MediaSource, String)> {
    let parsed = event
        .raw()
        .deserialize()
        .context("the event cannot be parsed")?;
    let AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(message)) = parsed
    else {
        bail!("the event is not a message");
    };
    let original = message.as_original().context("the message was redacted")?;
    Ok(match &original.content.msgtype {
        MessageType::File(c) => (c.source.clone(), c.filename().to_owned()),
        MessageType::Image(c) => (c.source.clone(), c.filename().to_owned()),
        MessageType::Video(c) => (c.source.clone(), c.filename().to_owned()),
        MessageType::Audio(c) => (c.source.clone(), c.filename().to_owned()),
        other => bail!(
            "the event is not a media message (msgtype {})",
            other.msgtype()
        ),
    })
}

/// A file name for `name` that cannot leave the output directory or upset a
/// terminal: its last component after `/` and `\\`, control characters and
/// characters Windows reserves (`<>:"|?*`) replaced by `_`, trimmed, at most
/// 200 bytes. A name that is empty or only dots falls back to the event id,
/// sanitized the same way, then to "media_download".
pub fn sanitize_file_name(name: &str, event_id: &str) -> String {
    clean_name(name)
        .or_else(|| clean_name(event_id))
        .unwrap_or_else(|| DEFAULT_NAME.to_owned())
}

fn clean_name(name: &str) -> Option<String> {
    let last = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let replaced: String = last
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut cleaned = replaced.trim();
    if cleaned.len() > MAX_NAME {
        let mut end = MAX_NAME;
        while !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        cleaned = cleaned[..end].trim_end();
    }
    // Windows drops trailing dots and spaces from a name.
    let cleaned = cleaned.trim_end_matches(['.', ' ']);
    if cleaned.is_empty() {
        return None;
    }
    // No hidden file from someone else's message: a leading dot becomes "_".
    let mut out = match cleaned.strip_prefix('.') {
        Some(rest) => format!("_{rest}"),
        None => cleaned.to_owned(),
    };
    // Windows device names (CON, NUL, COM1, ...) with any extension would
    // open the device instead of a file; prefix them on every platform.
    if is_reserved_device_name(&out) {
        out.insert(0, '_');
    }
    Some(out)
}

fn is_reserved_device_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or_default().trim_end();
    let upper = base.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((upper.starts_with("COM") || upper.starts_with("LPT"))
        && upper.len() == 4
        && upper[3..].chars().all(|c| c.is_ascii_digit()))
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(&base[3..], "¹" | "²" | "³"))
}

/// Write `data` to a new file (never replacing one, never following a
/// symlink at `path`), mode 0600 on Unix. A partly written file is removed.
pub fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).with_context(|| {
        format!(
            "cannot create {} (an existing file is never replaced)",
            path.display()
        )
    })?;
    let written = file.write_all(data).and_then(|()| file.sync_all());
    if let Err(err) = written {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(err).with_context(|| format!("cannot write {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EV: &str = "$abc123:example.org";

    #[test]
    fn hidden_and_windows_device_names_are_defused() {
        assert_eq!(sanitize_file_name(".bashrc", EV), "_bashrc");
        assert_eq!(sanitize_file_name("..profile", EV), "_.profile");
        assert_eq!(sanitize_file_name("report.pdf. . ", EV), "report.pdf");
        assert_eq!(sanitize_file_name("CON", EV), "_CON");
        assert_eq!(sanitize_file_name("nul.txt", EV), "_nul.txt");
        assert_eq!(sanitize_file_name("Com7.tar.gz", EV), "_Com7.tar.gz");
        assert_eq!(sanitize_file_name("lpt¹", EV), "_lpt¹");
        assert_eq!(sanitize_file_name("console.log", EV), "console.log");
        assert_eq!(sanitize_file_name("COM10", EV), "COM10");
    }

    #[test]
    fn plain_names_are_kept() {
        assert_eq!(sanitize_file_name("report.pdf", EV), "report.pdf");
        assert_eq!(sanitize_file_name("Grüße 🙂.png", EV), "Grüße 🙂.png");
        assert_eq!(sanitize_file_name(".hidden", EV), "_hidden");
        assert_eq!(sanitize_file_name("a..b.txt", EV), "a..b.txt");
    }

    #[test]
    fn directory_parts_are_dropped() {
        assert_eq!(sanitize_file_name("../../etc/passwd", EV), "passwd");
        assert_eq!(sanitize_file_name("/abs/path/x.txt", EV), "x.txt");
        assert_eq!(sanitize_file_name("..\\..\\win.ini", EV), "win.ini");
        assert_eq!(sanitize_file_name("dir/", EV), "$abc123_example.org");
    }

    #[test]
    fn dot_names_fall_back_to_the_event_id() {
        for name in ["", "  ", ".", "..", "...", "a/..", "x\\.."] {
            assert_eq!(
                sanitize_file_name(name, EV),
                "$abc123_example.org",
                "{name:?}"
            );
        }
        // An old-style event id with a slash, and one that yields nothing.
        assert_eq!(sanitize_file_name("", "$a/b:example.org"), "b_example.org");
        assert_eq!(sanitize_file_name("..", "$x/.."), DEFAULT_NAME);
    }

    #[test]
    fn control_and_reserved_characters_are_replaced() {
        let name = sanitize_file_name("a\u{1b}[2J\r\nb\u{9b}c:d?.txt", EV);
        assert_eq!(name, "a_[2J__b_c_d_.txt");
        assert!(!name.chars().any(char::is_control));
    }

    #[test]
    fn long_names_are_cut_on_a_char_boundary() {
        let name = sanitize_file_name(&"ü".repeat(300), EV);
        assert!(name.len() <= MAX_NAME, "{}", name.len());
        assert_eq!(name, "ü".repeat(MAX_NAME / 2));
    }

    #[test]
    fn existing_files_and_symlinks_are_never_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f");
        write_new(&path, b"one").unwrap();
        assert!(write_new(&path, b"two").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let target = tmp.path().join("target");
            let link = tmp.path().join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(
                write_new(&link, b"x").is_err(),
                "a dangling symlink was followed"
            );
            assert!(!target.exists());
        }
    }
}
