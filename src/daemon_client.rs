//! Client side of the watch daemon's socket, as the matrix-skill's
//! `_lib/daemon_client.py`: one request line, one response line, both JSON.
//!
//! Routing rule: a command delegates to the daemon only when something
//! answers on the socket. The data-dir lock is never the signal: a direct
//! command holds it too for its few seconds.

use std::path::Path;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use anyhow::Result;
use serde_json::Value;

/// How long a command waits for the daemon's answer. A send with
/// `trust_unverified_devices` waits for the daemon's current sync (up to
/// 30 s) and rebuilds its client twice.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// What came back from the socket.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// Nothing serves the socket (no socket file, the connection refused or
    /// not made within the timeout, or the request line could not be written
    /// whole): use the direct path. Nothing was
    /// handed to a daemon, so nothing can happen twice.
    NoDaemon,
    /// The daemon answered; an `"ok": false` answer is an answer too and
    /// must never lead to the direct path (the operation could happen twice).
    Answer(Value),
}

/// Send one request and read one response line.
///
/// Differs from daemon_client.py: once the whole request line is written,
/// every outcome other than an answer is an error, not "no daemon": a
/// timeout, the connection closed or reset, an empty or unreadable answer.
/// The daemon may have carried out the request (or may still), so falling
/// back to the direct path could send the message twice.
#[cfg(unix)]
pub fn request(socket: &Path, payload: &Value, timeout: Duration) -> Result<Reply> {
    use std::io::{ErrorKind, Read, Write};

    // One deadline for connecting, writing and reading.
    let deadline = Instant::now() + timeout;
    if !socket.exists() {
        return Ok(Reply::NoDaemon);
    }
    let Some(mut stream) = connect_until(socket, deadline) else {
        // A stale socket from a crashed daemon (refused), none at all, or a
        // listener whose backlog stayed full until the deadline. Nothing was
        // sent.
        return Ok(Reply::NoDaemon);
    };
    let mut line = serde_json::to_vec(payload)?;
    line.push(b'\n');
    let mut written = 0;
    while written < line.len() {
        // A part of the line is no request: the daemon carries out only a
        // line that ends in its newline.
        let Some(left) = remaining(deadline) else {
            return Ok(Reply::NoDaemon);
        };
        stream.set_write_timeout(Some(left)).ok();
        match stream.write(&line[written..]) {
            Ok(0) => return Ok(Reply::NoDaemon),
            Ok(n) => written += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Ok(Reply::NoDaemon),
        }
    }
    // From here on the daemon holds the request: no outcome but an answer
    // may lead to the direct path.
    let did_not_answer = || {
        anyhow::anyhow!(
            "the watch daemon did not answer within {} s; the request may still be carried out, so it is not retried directly",
            timeout.as_secs()
        )
    };
    let mut answer = Vec::new();
    let mut chunk = [0u8; 4096];
    while !answer.contains(&b'\n') {
        let Some(left) = remaining(deadline) else {
            return Err(did_not_answer());
        };
        stream.set_read_timeout(Some(left)).ok();
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => answer.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(did_not_answer());
            }
            Err(e) => anyhow::bail!("{CLOSED_WITHOUT_ANSWER} ({e})"),
        }
    }
    if let Some(end) = answer.iter().position(|b| *b == b'\n') {
        answer.truncate(end + 1);
    }
    if answer.iter().all(u8::is_ascii_whitespace) {
        anyhow::bail!("{CLOSED_WITHOUT_ANSWER}");
    }
    match serde_json::from_slice::<Value>(&answer) {
        Ok(value) if value.is_object() => Ok(Reply::Answer(value)),
        _ => anyhow::bail!(
            "the watch daemon's answer is not a JSON object; the request may have been carried out, so it is not retried directly"
        ),
    }
}

/// The time left until `deadline`; `None` once it has passed (a zero
/// socket timeout is refused, not "no time").
#[cfg(unix)]
fn remaining(deadline: Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    (!left.is_zero()).then_some(left)
}

/// Connect, waiting at most until `deadline`. A blocking connect to a
/// listener whose backlog is full waits without any socket timeout, so it
/// runs in a thread of its own; when the deadline passes first, that thread
/// drops the stream it may still get without writing to it.
#[cfg(unix)]
fn connect_until(socket: &Path, deadline: Instant) -> Option<std::os::unix::net::UnixStream> {
    let left = remaining(deadline)?;
    let (tx, rx) = std::sync::mpsc::channel();
    let path = socket.to_owned();
    std::thread::Builder::new()
        .name("daemon-connect".into())
        .spawn(move || {
            tx.send(std::os::unix::net::UnixStream::connect(path)).ok();
        })
        .ok()?;
    rx.recv_timeout(left).ok()?.ok()
}

/// Why a request that reached the daemon has no answer.
#[cfg(unix)]
const CLOSED_WITHOUT_ANSWER: &str = "the daemon closed the connection without answering; the request may have been carried out, so it is not retried directly";

/// No Unix sockets here, so never a daemon.
#[cfg(not(unix))]
pub fn request(_socket: &Path, _payload: &Value, _timeout: Duration) -> Result<Reply> {
    Ok(Reply::NoDaemon)
}

/// [`request`] off the async worker threads.
pub async fn request_async(socket: &Path, payload: Value, timeout: Duration) -> Result<Reply> {
    let socket = socket.to_owned();
    tokio::task::spawn_blocking(move || request(&socket, &payload, timeout))
        .await
        .map_err(|e| anyhow::anyhow!("the socket task failed: {e}"))?
}

/// The pid a status answer reports, or `None` when there is no usable one.
/// `--stop` signals only this pid, never the one in the pid file, which may
/// by now belong to an unrelated process.
pub fn running_daemon_pid(status: Option<&Value>) -> Option<i32> {
    let status = status?;
    if status.get("ok").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    // as_i64 is None for booleans, strings and non-integers.
    status
        .get("pid")
        .and_then(Value::as_i64)
        .filter(|pid| *pid > 0)
        .and_then(|pid| i32::try_from(pid).ok())
}

/// An answer's `error`, or `fallback` when it carries none.
pub fn error_of(answer: &Value, fallback: &str) -> String {
    answer
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pid_from_a_status_answer() {
        assert_eq!(
            running_daemon_pid(Some(&json!({"ok": true, "pid": 4242}))),
            Some(4242)
        );
    }

    #[test]
    fn no_answer_means_nothing_to_stop() {
        assert_eq!(running_daemon_pid(None), None);
        assert_eq!(
            running_daemon_pid(Some(&json!({"ok": false, "error": "x"}))),
            None
        );
    }

    #[test]
    fn implausible_pid_is_not_signalled() {
        for pid in [
            json!(0),
            json!(-1),
            json!("123"),
            json!(true),
            json!(null),
            json!(1.5),
        ] {
            assert_eq!(
                running_daemon_pid(Some(&json!({"ok": true, "pid": pid}))),
                None,
                "{pid}"
            );
        }
    }

    #[cfg(unix)]
    mod socket {
        use super::*;
        use crate::daemon_test_support::{FakeDaemon, short_tempdir};

        #[test]
        fn no_socket_file_means_no_daemon() {
            let dir = short_tempdir();
            let reply = request(
                &dir.path().join("d.sock"),
                &json!({"op": "status"}),
                REQUEST_TIMEOUT,
            );
            assert_eq!(reply.unwrap(), Reply::NoDaemon);
        }

        #[test]
        fn stale_socket_means_no_daemon() {
            let dir = short_tempdir();
            let path = dir.path().join("d.sock");
            std::fs::write(&path, "").unwrap();
            assert_eq!(
                request(&path, &json!({"op": "status"}), REQUEST_TIMEOUT).unwrap(),
                Reply::NoDaemon
            );
            // A real socket file nobody listens on any more.
            drop(std::os::unix::net::UnixListener::bind(dir.path().join("e.sock")).unwrap());
            let stale = dir.path().join("e.sock");
            assert!(stale.exists());
            assert_eq!(
                request(&stale, &json!({"op": "status"}), REQUEST_TIMEOUT).unwrap(),
                Reply::NoDaemon
            );
        }

        #[test]
        fn request_round_trips() {
            let fake = FakeDaemon::start(Some(json!({"ok": true, "event_id": "$x"})));
            let got = request(
                &fake.path,
                &json!({"op": "send", "room": "!r:e", "body": "hi"}),
                REQUEST_TIMEOUT,
            )
            .unwrap();
            assert_eq!(got, Reply::Answer(json!({"ok": true, "event_id": "$x"})));
            let received = fake.received();
            assert_eq!(received["op"], "send");
            assert_eq!(received["body"], "hi");
        }

        #[test]
        fn error_response_is_returned_not_swallowed() {
            let fake = FakeDaemon::start(Some(json!({"ok": false, "error": "no such room"})));
            let Reply::Answer(got) =
                request(&fake.path, &json!({"op": "send"}), REQUEST_TIMEOUT).unwrap()
            else {
                panic!("an error answer must not read as no daemon");
            };
            assert_eq!(got["ok"], false);
            assert!(error_of(&got, "x").contains("no such room"));
        }

        #[test]
        fn daemon_closing_without_answering_is_an_error_not_a_fallback() {
            let fake = FakeDaemon::start(None);
            let err = request(&fake.path, &json!({"op": "send"}), REQUEST_TIMEOUT).unwrap_err();
            assert!(
                err.to_string()
                    .contains("closed the connection without answering"),
                "{err}"
            );
            assert_eq!(fake.received()["op"], "send");
        }

        #[test]
        fn a_reset_connection_is_an_error_not_a_fallback() {
            let fake = FakeDaemon::start_raw(Some(Vec::new()), true);
            let err = request(&fake.path, &json!({"op": "send"}), REQUEST_TIMEOUT).unwrap_err();
            // The fake had the whole request before it reset the connection.
            assert_eq!(fake.received(), json!({"op": "send"}));
            assert!(
                err.to_string().contains("may have been carried out"),
                "{err}"
            );
            #[cfg(target_os = "linux")]
            assert!(err.to_string().contains("reset"), "not a reset: {err}");
        }

        #[test]
        fn an_unreadable_answer_is_an_error_not_a_fallback() {
            for raw in [b"\n".to_vec(), b"not json\n".to_vec(), b"[1]\n".to_vec()] {
                let fake = FakeDaemon::start_raw(Some(raw.clone()), false);
                let err = request(&fake.path, &json!({"op": "send"}), REQUEST_TIMEOUT).unwrap_err();
                assert!(
                    err.to_string().contains("may have been carried out"),
                    "{raw:?}: {err}"
                );
            }
        }

        #[test]
        fn a_daemon_that_accepts_but_never_answers_is_an_error_not_a_fallback() {
            let dir = short_tempdir();
            let path = dir.path().join("d.sock");
            let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            // The backlog accepts the connection; nobody reads or answers.
            let err =
                request(&path, &json!({"op": "send"}), Duration::from_millis(300)).unwrap_err();
            assert!(err.to_string().contains("did not answer"), "{err}");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn a_full_backlog_does_not_hold_the_request_past_its_deadline() {
            use std::os::fd::AsRawFd;
            let dir = short_tempdir();
            let path = dir.path().join("d.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            // A backlog of one connection, taken by `first`: the next
            // connect waits until it is accepted, which never happens.
            // SAFETY: listen on a listening socket only changes its backlog.
            assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
            let _first = std::os::unix::net::UnixStream::connect(&path).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let socket = path.clone();
            std::thread::spawn(move || {
                tx.send(request(
                    &socket,
                    &json!({"op": "send"}),
                    Duration::from_millis(300),
                ))
                .ok();
            });
            let reply = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the connect waited past the request's deadline");
            assert_eq!(reply.unwrap(), Reply::NoDaemon, "nothing was sent");
        }

        #[test]
        fn an_answer_trickled_past_the_deadline_is_an_error() {
            let dir = short_tempdir();
            let path = dir.path().join("d.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                let Ok((mut conn, _)) = listener.accept() else {
                    return;
                };
                let mut line = Vec::new();
                BufReader::new(&conn).read_until(b'\n', &mut line).ok();
                // One byte every 50 ms, never a newline: each read is quick.
                for _ in 0..60 {
                    if conn.write_all(b" ").is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
            let started = std::time::Instant::now();
            let err =
                request(&path, &json!({"op": "send"}), Duration::from_millis(300)).unwrap_err();
            assert!(
                started.elapsed() < Duration::from_millis(1500),
                "the read took {:?}, past the 300 ms deadline",
                started.elapsed()
            );
            assert!(err.to_string().contains("did not answer"), "{err}");
        }

        #[test]
        fn unicode_survives_the_round_trip() {
            let fake = FakeDaemon::start(Some(json!({"ok": true, "event_id": "$x"})));
            request(
                &fake.path,
                &json!({"op": "send", "body": "Grüße 🎁"}),
                REQUEST_TIMEOUT,
            )
            .unwrap();
            assert_eq!(fake.received()["body"], "Grüße 🎁");
        }
    }
}
