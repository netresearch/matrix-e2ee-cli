//! The subcommands and the helpers they share.

pub mod backup;
pub mod login;
pub mod logout;
pub mod read;
pub mod send;
pub mod status;
pub mod verify;

use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::OwnedRoomAliasId;
use matrix_sdk::{Client, Room};

use crate::room_arg::{RoomArg, classify, match_name};
use crate::text::term;

/// One sync without long polling: room state, device lists and to-device
/// events up to now. Outgoing crypto requests (key upload, key queries) are
/// sent as part of it.
pub async fn sync_once(client: &Client) -> Result<()> {
    client
        .sync_once(SyncSettings::default().timeout(Duration::ZERO))
        .await
        .context("sync failed")?;
    Ok(())
}

/// Find a joined room by id, alias or name. An argument that parses as a
/// room id resolves only to the joined room with that id, never to a room of
/// that name, so a room named like an id cannot receive what was meant for
/// the room with that id.
pub async fn resolve_room(client: &Client, arg: &str) -> Result<Room> {
    let joined = |room: &Room| room.state() == matrix_sdk::RoomState::Joined;
    let room_id = match classify(arg) {
        RoomArg::Id(id) => {
            // No fallback to room names: a room someone named "!<id>" must
            // not receive a message meant for the room with that id.
            match client.get_room(&id).filter(joined) {
                Some(room) => return Ok(room),
                None => bail!(
                    "not joined to room {id}; a room whose name starts with \"!\" can only be addressed by its alias"
                ),
            }
        }
        RoomArg::Alias(alias) => {
            let alias: OwnedRoomAliasId = alias
                .as_str()
                .try_into()
                .with_context(|| format!("invalid room alias {alias}"))?;
            client
                .resolve_room_alias(&alias)
                .await
                .with_context(|| format!("cannot resolve {alias}"))?
                .room_id
        }
        RoomArg::Name(name) => match find_by_name(client, &name).await? {
            Some(room_id) => room_id,
            None => bail!("no joined room is named {name:?}"),
        },
    };
    client
        .get_room(&room_id)
        .filter(joined)
        .with_context(|| format!("not joined to room {room_id}"))
}

/// The joined room whose display name is `name` (ignoring case), `None` if
/// there is none; an error if several rooms carry that name.
async fn find_by_name(
    client: &Client,
    name: &str,
) -> Result<Option<matrix_sdk::ruma::OwnedRoomId>> {
    let rooms = client.joined_rooms();
    let mut names = Vec::with_capacity(rooms.len());
    for room in &rooms {
        let display = room
            .display_name()
            .await
            .map(|n| n.to_string())
            .unwrap_or_default();
        names.push(display);
    }
    let hits = match_name(&names, name);
    match hits.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(rooms[*one].room_id().to_owned())),
        many => {
            let list = many
                .iter()
                .map(|&i| format!("{} ({})", term(&names[i]), rooms[i].room_id()))
                .collect::<Vec<_>>()
                .join(", ");
            bail!("room name {name:?} is ambiguous; use one of these room ids: {list}");
        }
    }
}

/// Ask a yes/no question on stderr, read the answer from stdin. With
/// `require_terminal`, refuse when stdin is not a terminal. End of input is "no".
pub fn ask_yes_no(question: &str, require_terminal: bool) -> Result<bool> {
    let stdin = std::io::stdin();
    let is_terminal = stdin.is_terminal();
    ask_yes_no_on(
        question,
        require_terminal,
        is_terminal,
        &mut stdin.lock(),
        &mut std::io::stderr(),
    )
}

/// Write the question to `output`, read the answer from `input`.
pub fn ask_yes_no_on(
    question: &str,
    require_terminal: bool,
    is_terminal: bool,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<bool> {
    if require_terminal && !is_terminal {
        bail!("no terminal to ask on: {question}");
    }
    write!(output, "{question} [y/N] ").context("cannot show the question")?;
    output.flush().ok();
    let mut line = String::new();
    input
        .read_line(&mut line)
        .context("cannot read the answer")?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Confirm something shown just before the question: only a person at a
/// terminal may answer, and input typed before the question appeared is
/// discarded first, so a "y" typed ahead cannot answer it.
pub fn confirm_fresh_on(
    question: &str,
    is_terminal: bool,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    discard_typeahead: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    if !is_terminal {
        bail!(
            "stdin is not a terminal; this confirmation must be answered by a person: {question}"
        );
    }
    discard_typeahead()?;
    ask_yes_no_on(question, true, is_terminal, input, output)
}

#[cfg(unix)]
pub fn discard_typeahead_stdin() -> Result<()> {
    discard_typeahead(libc::STDIN_FILENO)
}

#[cfg(windows)]
pub fn discard_typeahead_stdin() -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    discard_console_input(std::io::stdin().as_raw_handle())
}

/// No way to discard typed-ahead input here: refuse, so an answer typed
/// before the question cannot answer it.
#[cfg(not(any(unix, windows)))]
pub fn discard_typeahead_stdin() -> Result<()> {
    bail!("cannot discard typed-ahead input on this platform")
}

/// Drop input the console received but nobody has read yet
/// (`FlushConsoleInputBuffer`). Fails when `handle` is no console input
/// handle (a pipe, a file, an msys/mintty terminal), so the confirmation is
/// refused instead of reading an answer typed earlier.
#[cfg(windows)]
fn discard_console_input(handle: std::os::windows::io::RawHandle) -> Result<()> {
    if handle.is_null() {
        bail!("stdin has no console; cannot discard typed-ahead input");
    }
    // SAFETY: FlushConsoleInputBuffer only takes the handle value; a handle
    // that is not a console input handle is reported through the return value.
    if unsafe { windows_sys::Win32::System::Console::FlushConsoleInputBuffer(handle) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot discard typed-ahead input (stdin is not a console)");
    }
    Ok(())
}

/// Drop input the terminal received but nobody has read yet (`tcflush`
/// with `TCIFLUSH`).
#[cfg(unix)]
pub fn discard_typeahead(fd: std::os::fd::RawFd) -> Result<()> {
    // SAFETY: tcflush only takes a file descriptor and a constant; an invalid
    // descriptor is reported through the return value.
    if unsafe { libc::tcflush(fd, libc::TCIFLUSH) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot discard typed-ahead input");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn fresh_confirmation_refuses_without_a_terminal() {
        let mut input = Cursor::new("y\n");
        let mut discarded = false;
        let err = confirm_fresh_on("Match?", false, &mut input, &mut Vec::new(), || {
            discarded = true;
            Ok(())
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("not a terminal"), "{err}");
        assert_eq!(input.position(), 0, "the piped answer must not be read");
        assert!(!discarded);
    }

    #[test]
    fn fresh_confirmation_discards_before_reading() {
        let mut input = Cursor::new("y\n");
        let mut discarded = false;
        assert!(
            confirm_fresh_on("Match?", true, &mut input, &mut Vec::new(), || {
                discarded = true;
                Ok(())
            })
            .unwrap()
        );
        assert!(discarded);
    }

    #[cfg(windows)]
    #[test]
    fn discard_refuses_a_handle_that_is_no_console() {
        use std::os::windows::io::AsRawHandle;
        let file = tempfile::tempfile().unwrap();
        assert!(discard_console_input(file.as_raw_handle()).is_err());
        assert!(discard_console_input(std::ptr::null_mut()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn discard_typeahead_drops_pending_terminal_input() {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty writes two descriptors; null name, termios and
        // winsize are allowed.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                // `as _`: libc declares these *const on Linux, *mut on macOS.
                std::ptr::null_mut::<libc::termios>() as _,
                std::ptr::null_mut::<libc::winsize>() as _,
            )
        };
        assert_eq!(rc, 0, "openpty failed");
        let pending = |fd: i32| {
            let mut n: libc::c_int = 0;
            // SAFETY: FIONREAD writes one c_int.
            assert_eq!(unsafe { libc::ioctl(fd, libc::FIONREAD, &mut n) }, 0);
            n
        };
        // SAFETY: writes 2 bytes from a valid buffer.
        assert_eq!(unsafe { libc::write(master, b"y\n".as_ptr().cast(), 2) }, 2);
        // Let the line discipline move the bytes to the slave side.
        for _ in 0..100 {
            if pending(slave) > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(pending(slave) > 0, "typed-ahead input did not arrive");
        discard_typeahead(slave).unwrap();
        assert_eq!(pending(slave), 0, "typed-ahead input survived");
        // SAFETY: closing the descriptors openpty returned.
        unsafe {
            libc::close(slave);
            libc::close(master);
        }
    }
}
