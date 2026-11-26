//! Test helpers for the daemon socket: a short temporary directory (a
//! socket path must fit into `sun_path`, about 104 to 108 bytes) and a
//! one-shot fake daemon.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use serde_json::Value;

/// A temporary directory with a short name, so `<dir>/d.sock` stays within
/// `sun_path` also under a long TMPDIR.
pub fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("s")
        .rand_bytes(4)
        .tempdir()
        .unwrap()
}

/// One-shot listener answering with a canned response, or closing the
/// connection without one.
pub struct FakeDaemon {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    received: mpsc::Receiver<Value>,
}

impl FakeDaemon {
    pub fn start(response: Option<Value>) -> Self {
        let raw = response.map(|r| {
            let mut out = serde_json::to_vec(&r).unwrap();
            out.push(b'\n');
            out
        });
        Self::start_raw(raw, false)
    }

    /// Answer with these bytes (none: close without answering); with
    /// `reset`, close with unread input pending, which resets the connection.
    pub fn start_raw(response: Option<Vec<u8>>, reset: bool) -> Self {
        let dir = short_tempdir();
        let path = dir.path().join("d.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            if reset {
                // Wait until the whole request line has arrived, but leave it
                // unread: closing with unread input makes the kernel reset
                // the connection instead of a clean end of stream.
                let line = peek_line(&conn);
                tx.send(serde_json::from_slice(&line).unwrap()).ok();
                drop(conn);
                return;
            }
            let mut line = Vec::new();
            BufReader::new(&conn).read_until(b'\n', &mut line).unwrap();
            tx.send(serde_json::from_slice(&line).unwrap()).ok();
            if let Some(response) = response {
                conn.write_all(&response).unwrap();
            }
        });
        Self {
            _dir: dir,
            path,
            received: rx,
        }
    }

    pub fn received(&self) -> Value {
        self.received
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
    }
}

/// The first line on `conn` (with its newline), read with `MSG_PEEK`: it
/// stays in the receive queue. Waits until the newline has arrived.
fn peek_line(conn: &std::os::unix::net::UnixStream) -> Vec<u8> {
    use std::os::fd::AsRawFd;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: buf is valid for buf.len() bytes; MSG_PEEK leaves the data.
        let n = unsafe {
            libc::recv(
                conn.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        let n = usize::try_from(n).expect("recv failed");
        assert!(n > 0, "the client closed before sending its request");
        if let Some(end) = buf[..n].iter().position(|&b| b == b'\n') {
            buf.truncate(end + 1);
            return buf;
        }
        thread::sleep(std::time::Duration::from_millis(5));
    }
}
