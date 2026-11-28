//! A local homeserver for tests: each request is answered from a route
//! table (method and path prefix, the path percent-decoded) and recorded.
//! One request per connection (`Connection: close`), like the
//! one-shot servers in migrate_nio's and watch_daemon's tests.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::store::RoomLoadSettings;
use matrix_sdk::{Client, SessionMeta, SessionTokens};

/// What the server received.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    /// Percent-decoded, without the query.
    pub path: String,
    /// The query, as sent (without "?").
    pub query: String,
    pub body: String,
}

#[derive(Clone)]
struct Route {
    method: String,
    path: String,
    status: u16,
    body: String,
    /// How long the answer waits; a request of a delayed route counts as
    /// in flight meanwhile.
    delay: Duration,
}

/// Delayed requests in flight now, and the most there were at once.
#[derive(Default)]
struct InFlight {
    now: AtomicUsize,
    most: AtomicUsize,
}

pub struct MockHomeserver {
    pub url: String,
    routes: Arc<Mutex<Vec<Route>>>,
    received: Arc<Mutex<Vec<Recorded>>>,
    in_flight: Arc<InFlight>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// Answers every client needs: the spec versions, and the key upload and
/// query a fresh in-memory olm account sends during a sync.
fn base_routes() -> Vec<Route> {
    [
        (
            "GET",
            "/_matrix/client/versions",
            r#"{"versions": ["v1.11"]}"#,
        ),
        (
            "POST",
            "/_matrix/client/v3/keys/upload",
            r#"{"one_time_key_counts": {}}"#,
        ),
        (
            "POST",
            "/_matrix/client/v3/keys/query",
            r#"{"device_keys": {}, "failures": {}}"#,
        ),
    ]
    .into_iter()
    .map(|(method, path, body)| Route {
        method: method.into(),
        path: path.into(),
        status: 200,
        body: body.into(),
        delay: Duration::ZERO,
    })
    .collect()
}

impl MockHomeserver {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let routes = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::new(Mutex::new(Vec::new()));
        let in_flight = Arc::new(InFlight::default());
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (routes, received, in_flight, stop) = (
                routes.clone(),
                received.clone(),
                in_flight.clone(),
                stop.clone(),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        // One thread per connection, so delayed answers overlap.
                        Ok((stream, _)) => {
                            let (routes, received, in_flight) =
                                (routes.clone(), received.clone(), in_flight.clone());
                            std::thread::spawn(move || {
                                serve(stream, &routes, &received, &in_flight)
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
            })
        };
        Self {
            url,
            routes,
            received,
            in_flight,
            stop,
            thread: Some(thread),
        }
    }

    /// Answer METHOD requests whose decoded path starts with PATH. Routes
    /// added first win; the base routes come after all added ones.
    pub fn route(&self, method: &str, path: &str, status: u16, body: &str) -> &Self {
        self.route_delayed(method, path, status, body, Duration::ZERO)
    }

    /// [`Self::route`], answered after DELAY.
    pub fn route_delayed(
        &self,
        method: &str,
        path: &str,
        status: u16,
        body: &str,
        delay: Duration,
    ) -> &Self {
        self.routes.lock().unwrap().push(Route {
            method: method.into(),
            path: path.into(),
            status,
            body: body.into(),
            delay,
        });
        self
    }

    /// The most requests of delayed routes that were in flight at once.
    pub fn most_in_flight(&self) -> usize {
        self.in_flight.most.load(Ordering::SeqCst)
    }

    /// Every request received so far, in order.
    pub fn received(&self) -> Vec<Recorded> {
        self.received.lock().unwrap().clone()
    }

    /// The requests other than the versions query and the key upload and
    /// query.
    pub fn received_api(&self) -> Vec<Recorded> {
        self.received()
            .into_iter()
            .filter(|r| {
                !r.path.ends_with("/versions")
                    && !r.path.ends_with("/keys/upload")
                    && !r.path.ends_with("/keys/query")
            })
            .collect()
    }

    /// A client of user USER logged in to this server, with an in-memory
    /// store (no session file, no crypto store on disk).
    pub async fn client(&self, user: &str) -> Client {
        let client = Client::builder()
            .homeserver_url(&self.url)
            .build()
            .await
            .unwrap();
        client
            .matrix_auth()
            .restore_session(
                MatrixSession {
                    meta: SessionMeta {
                        user_id: user.try_into().unwrap(),
                        device_id: "TESTDEVICE".into(),
                    },
                    tokens: SessionTokens {
                        access_token: "test-token".into(),
                        refresh_token: None,
                    },
                },
                RoomLoadSettings::default(),
            )
            .await
            .unwrap();
        client
    }
}

impl Drop for MockHomeserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }
}

fn serve(
    mut stream: TcpStream,
    routes: &Mutex<Vec<Route>>,
    received: &Mutex<Vec<Recorded>>,
    in_flight: &InFlight,
) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut data = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => data.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let length = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while data.len() < head_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&chunk[..n]),
        }
    }
    let mut parts = head.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default();
    let path = percent_decode(target.split('?').next().unwrap_or_default());
    let query = target
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default()
        .to_owned();
    let body = String::from_utf8_lossy(&data[head_end..]).into_owned();
    received.lock().unwrap().push(Recorded {
        method: method.clone(),
        path: path.clone(),
        query,
        body,
    });
    let mut table = routes.lock().unwrap().clone();
    table.extend(base_routes());
    let (status, body, delay) = table
        .iter()
        .find(|r| r.method == method && path.starts_with(&r.path))
        .map(|r| (r.status, r.body.clone(), r.delay))
        .unwrap_or((
            404,
            r#"{"errcode": "M_UNRECOGNIZED", "error": "Unrecognized request"}"#.into(),
            Duration::ZERO,
        ));
    if !delay.is_zero() {
        let now = in_flight.now.fetch_add(1, Ordering::SeqCst) + 1;
        in_flight.most.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(delay);
        in_flight.now.fetch_sub(1, Ordering::SeqCst);
    }
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
