//! Client side of the watch daemon's socket, as the matrix-skill's
//! `_lib/daemon_client.py`: one request line, one response line, both JSON.
//!
//! Routing rule: a command delegates to the daemon only when something
//! answers on the socket. The data-dir lock is never the signal: a direct
//! command holds it too for its few seconds.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;

/// How long a command waits for the daemon's answer. A send with
/// `trust_unverified_devices` waits for the daemon's current sync (up to
/// 30 s) and rebuilds its client twice.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// What came back from the socket.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// Nothing serves the socket (no file, refused, a stale file, or the
    /// connection closed without an answer): use the direct path.
    NoDaemon,
    /// The daemon answered; an `"ok": false` answer is an answer too and
    /// must never lead to the direct path (the operation could happen twice).
    Answer(Value),
}

/// Send one request and read one response line.
///
/// Differs from daemon_client.py in one case: a daemon that accepted the
/// request but does not answer within `timeout` is an error, not "no
/// daemon". It may still carry out the request, so falling back to the
/// direct path could send the message twice.
#[cfg(unix)]
pub fn request(socket: &Path, payload: &Value, timeout: Duration) -> Result<Reply> {
    use std::io::{BufRead, BufReader, ErrorKind, Write};
    use std::os::unix::net::UnixStream;

    if !socket.exists() {
        return Ok(Reply::NoDaemon);
    }
    let Ok(mut stream) = UnixStream::connect(socket) else {
        // A stale socket from a crashed daemon, or none at all.
        return Ok(Reply::NoDaemon);
    };
    stream.set_write_timeout(Some(timeout)).ok();
    stream.set_read_timeout(Some(timeout)).ok();
    let mut line = serde_json::to_vec(payload)?;
    line.push(b'\n');
    if stream.write_all(&line).is_err() {
        return Ok(Reply::NoDaemon);
    }
    let mut answer = Vec::new();
    match BufReader::new(&stream).read_until(b'\n', &mut answer) {
        Ok(_) => {}
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => anyhow::bail!(
            "the watch daemon did not answer within {} s; the request may still be carried out, so it is not retried directly",
            timeout.as_secs()
        ),
        Err(_) => return Ok(Reply::NoDaemon),
    }
    if answer.iter().all(u8::is_ascii_whitespace) {
        return Ok(Reply::NoDaemon);
    }
    match serde_json::from_slice::<Value>(&answer) {
        Ok(value) if value.is_object() => Ok(Reply::Answer(value)),
        _ => Ok(Reply::NoDaemon),
    }
}

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
        fn daemon_closing_without_answering_reads_as_no_daemon() {
            let fake = FakeDaemon::start(None);
            assert_eq!(
                request(&fake.path, &json!({"op": "status"}), REQUEST_TIMEOUT).unwrap(),
                Reply::NoDaemon
            );
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
