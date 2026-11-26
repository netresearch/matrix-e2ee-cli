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
                // Close before reading: the unread request makes the kernel
                // reset the connection instead of a clean end of stream.
                std::thread::sleep(std::time::Duration::from_millis(100));
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
