//! `watch-daemon`: one long-running process that holds this tool's data
//! directory (and with it the store), syncs, appends every event of the
//! rooms in config.json's `watch_rooms` to `<data_dir>/rooms/<slug>.jsonl`
//! and serves send, react, redact and edit on `<data_dir>/daemon.sock`.
//! A port of the matrix-skill's `matrix-watchd.py`; see
//! docs/specs/2026-08-13-live-room-awareness.md in that repository.
//!
//! Unix only: the commands report that the platform is not supported
//! elsewhere.

use anyhow::Result;

use crate::WatchDaemonArgs;

pub async fn run(args: WatchDaemonArgs) -> Result<()> {
    #[cfg(unix)]
    {
        unix::run(args).await
    }
    #[cfg(not(unix))]
    {
        let _ = args;
        anyhow::bail!(
            "watch-daemon is not supported on this platform: it serves a Unix socket (Linux and macOS)"
        )
    }
}

#[cfg(unix)]
pub mod unix {
    use std::collections::HashMap;
    use std::fs::{self, OpenOptions};
    use std::future::Future;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result, bail};
    use matrix_sdk::config::SyncSettings;
    use matrix_sdk::deserialized_responses::{AlgorithmInfo, TimelineEvent, TimelineEventKind};
    use matrix_sdk::ruma::api::error::ErrorKind;
    use matrix_sdk::ruma::{OwnedRoomAliasId, UserId};
    use matrix_sdk::sync::SyncResponse;
    use matrix_sdk::{Client, Room};
    use serde_json::{Value, json};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::{Mutex, RwLock, watch};

    use crate::WatchDaemonArgs;
    use crate::commands::{edit, react, redact, send};
    use crate::config::{Config, config_path, load_config, load_watch_rooms};
    use crate::daemon_client::{REQUEST_TIMEOUT, Reply, request_async, running_daemon_pid};
    use crate::roomlog::{
        DEFAULT_MAX_BYTES, Event, Own, SubjectIndex, append_record, build_record, log_path,
        next_seq, write_room_bundle,
    };
    use crate::session::{
        KeySharing, Paths, close_client, ensure_private_dir, read_existing_session, restore,
    };

    const SYNC_TIMEOUT: Duration = Duration::from_secs(30);
    /// How long a replaced client may take to close the store.
    const CLOSE_WAIT: Duration = Duration::from_secs(30);
    const NO_DAEMON: &str = "No daemon running.";
    /// The longest request line read from the socket.
    const MAX_REQUEST: u64 = 1 << 20;

    pub async fn run(args: WatchDaemonArgs) -> Result<()> {
        let paths = Paths::from_env()?;
        if args.status {
            show_status(&paths).await
        } else if args.stop {
            stop_daemon(&paths).await
        } else if args.start {
            start_detached(&paths).await
        } else {
            foreground(paths).await
        }
    }

    async fn status_answer(paths: &Paths) -> Result<Option<Value>> {
        Ok(
            match request_async(
                &paths.daemon_socket(),
                json!({"op": "status"}),
                REQUEST_TIMEOUT,
            )
            .await?
            {
                Reply::Answer(answer)
                    if answer.get("ok").and_then(Value::as_bool) == Some(true) =>
                {
                    Some(answer)
                }
                _ => None,
            },
        )
    }

    async fn show_status(paths: &Paths) -> Result<()> {
        let Some(status) = status_answer(paths).await? else {
            println!("{NO_DAEMON}");
            return Ok(());
        };
        print!("{}", status_text(&status));
        Ok(())
    }

    /// The four lines matrix-watchd.py --status prints.
    pub fn status_text(status: &Value) -> String {
        let field = |key: &str| match status.get(key) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        let rooms: Vec<String> = status
            .get("rooms")
            .and_then(Value::as_array)
            .map(|r| {
                r.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let rooms = if rooms.is_empty() {
            "none".to_owned()
        } else {
            rooms.join(", ")
        };
        let last_sync = match status.get("last_sync") {
            Some(Value::Number(n)) if n.as_i64() != Some(0) => n.to_string(),
            _ => "never".to_owned(),
        };
        format!(
            "pid:      {}\nuptime:   {}s\nrooms:    {}\nlast sync: {last_sync}\n",
            field("pid"),
            field("uptime_seconds"),
            crate::text::term(&rooms)
        )
    }

    /// Stop the daemon that answers on the socket: SIGTERM to the pid its
    /// status answer names, never the pid file's (it may be stale).
    async fn stop_daemon(paths: &Paths) -> Result<()> {
        let status = status_answer(paths).await?;
        let Some(pid) = running_daemon_pid(status.as_ref()) else {
            let pid_file = paths.daemon_pid_file();
            if pid_file.exists() {
                fs::remove_file(&pid_file).ok();
                println!("No daemon running (stale pid file removed).");
            } else {
                println!("{NO_DAEMON}");
            }
            return Ok(());
        };
        // SAFETY: kill takes two integers; failures come back through errno.
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                println!("{NO_DAEMON}");
                return Ok(());
            }
            return Err(err).with_context(|| format!("cannot stop the watch daemon (pid {pid})"));
        }
        println!("Stopped the watch daemon (pid {pid}).");
        Ok(())
    }

    /// Start `watch-daemon --foreground` in a new session, output appended to
    /// daemon.log, and wait until it answers (or exits).
    async fn start_detached(paths: &Paths) -> Result<()> {
        if let Some(status) = status_answer(paths).await? {
            println!(
                "Already running (pid {}).",
                status.get("pid").cloned().unwrap_or(Value::Null)
            );
            return Ok(());
        }
        ensure_private_dir(&paths.data_dir)?;
        let log_file = paths.daemon_log();
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_file)
            .with_context(|| format!("cannot open {}", log_file.display()))?;
        let exe = std::env::current_exe().context("cannot find this program's path")?;
        let mut command = Command::new(exe);
        command
            .args(["watch-daemon", "--foreground"])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        // SAFETY: setsid is async-signal-safe and touches no memory; it
        // detaches the child from this terminal's session.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().context("cannot start the watch daemon")?;
        let pid = child.id();
        // The first sync comes before the socket is served; it can take a while.
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Some(exit) = child.try_wait()? {
                bail!(
                    "the watch daemon exited at once ({exit}); see {}",
                    log_file.display()
                );
            }
            if status_answer(paths).await?.is_some() {
                println!("Started the watch daemon (pid {pid}).");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        println!(
            "Started the watch daemon (pid {pid}); it does not answer yet, see {}",
            log_file.display()
        );
        Ok(())
    }

    static STOP_SIGNAL: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_stop_signal(_: libc::c_int) {
        STOP_SIGNAL.store(true, Ordering::SeqCst);
    }

    /// SIGTERM and SIGINT set a flag; a task turns it into `stop`.
    fn stop_on_signals() -> watch::Receiver<bool> {
        let handler = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: the handler only stores into an atomic, which is
        // async-signal-safe.
        unsafe {
            libc::signal(libc::SIGTERM, handler);
            libc::signal(libc::SIGINT, handler);
        }
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            while !STOP_SIGNAL.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            tx.send(true).ok();
            // Keep the sender alive, so receivers see "stopped", not "closed".
            std::future::pending::<()>().await;
        });
        rx
    }

    /// Removes the socket and the pid file when the daemon ends.
    struct Cleanup(Vec<PathBuf>);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for path in &self.0 {
                fs::remove_file(path).ok();
            }
        }
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    async fn foreground(paths: Paths) -> Result<()> {
        let config = load_config()?;
        let watch_rooms = load_watch_rooms()?;
        read_existing_session(&paths)?;
        if watch_rooms.is_empty() {
            bail!(
                "no rooms to watch: add \"watch_rooms\": [\"#room:server\"] to {}",
                config_path()?.display()
            );
        }
        // Refuse at once instead of waiting: a second daemon, or a direct
        // command still running, holds the store.
        let _lock = paths
            .try_lock()
            .await
            .context("the watch daemon needs the store to itself")?;
        let mut cleanup = Cleanup(vec![paths.daemon_pid_file()]);
        fs::write(paths.daemon_pid_file(), std::process::id().to_string())
            .context("cannot write the pid file")?;
        let stop = stop_on_signals();

        let client = restore(&config, &paths, KeySharing::VerifiedOnly)
            .await?
            .client;
        let own_user = client
            .user_id()
            .context("the client has no user id")?
            .to_string();
        let own_display = client.account().get_display_name().await.ok().flatten();
        // This device's curve25519 key: the only way to tell our own events
        // from those of the person on the same account.
        let own_key = client
            .encryption()
            .curve25519_key()
            .await
            .map(|k| k.to_base64());

        let rooms = resolve_rooms(&client, &watch_rooms).await;
        write_room_bundle(&paths.rooms_dir(), &rooms)?;

        let daemon = Arc::new(Daemon {
            paths: paths.clone(),
            config,
            slot: RwLock::new(Some(client)),
            ops: Mutex::new(()),
            log: std::sync::Mutex::new(LogState::default()),
            rooms,
            started: Instant::now(),
            last_sync: AtomicI64::new(0),
            own_user,
            own_display,
            own_key,
        });

        // One state-carrying sync before anything is served, so the room
        // list is complete when the first request names a room.
        {
            let guard = daemon.slot.read().await;
            let client = guard.as_ref().context("no client")?;
            let response = client
                .sync_once(
                    SyncSettings::default()
                        .full_state(true)
                        .timeout(Duration::from_secs(10)),
                )
                .await
                .context("the first sync failed")?;
            daemon.process(client, &response).await;
            daemon.last_sync.store(now_ms() / 1000, Ordering::SeqCst);
        }

        let socket = paths.daemon_socket();
        // Holding the lock, so a socket file left here is stale.
        fs::remove_file(&socket).ok();
        let listener = UnixListener::bind(&socket).with_context(|| {
            format!(
                "cannot listen on {} (a socket path is limited to about 100 bytes)",
                socket.display()
            )
        })?;
        cleanup.0.push(socket.clone());
        // The data directory is 0700, so nobody else reaches the socket
        // between bind and chmod.
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot restrict {}", socket.display()))?;
        println!(
            "watching {} room(s), socket at {}",
            daemon.rooms.len(),
            socket.display()
        );

        let handler: Handler = {
            let daemon = daemon.clone();
            Arc::new(move |request| {
                let daemon = daemon.clone();
                Box::pin(async move { daemon.dispatch(request).await })
            })
        };
        let server = tokio::spawn(serve(listener, handler, stop.clone()));
        let result = daemon.sync_loop(stop).await;
        server.abort();
        drop(cleanup);
        result
    }

    /// (room id, label) per `watch_rooms` entry: an alias is resolved and
    /// labelled with itself, a room id with itself; an alias that does not
    /// resolve is kept as it is (matrix-watchd.py does the same).
    async fn resolve_rooms(client: &Client, entries: &[String]) -> Vec<(String, String)> {
        let mut rooms: Vec<(String, String)> = Vec::new();
        for entry in entries {
            let mut room_id = entry.clone();
            if entry.starts_with('#')
                && let Ok(alias) = OwnedRoomAliasId::try_from(entry.as_str())
            {
                match client.resolve_room_alias(&alias).await {
                    Ok(found) => room_id = found.room_id.to_string(),
                    Err(err) => eprintln!("cannot resolve {entry}: {err}"),
                }
            }
            let label = if entry.starts_with('#') {
                entry.clone()
            } else {
                room_id.clone()
            };
            match rooms.iter_mut().find(|(id, _)| *id == room_id) {
                Some(existing) => existing.1 = label,
                None => rooms.push((room_id, label)),
            }
        }
        rooms
    }

    /// The handler a connection's request goes to.
    pub type Handler =
        Arc<dyn Fn(Value) -> Pin<Box<dyn Future<Output = Value> + Send>> + Send + Sync>;

    /// Serve the socket until `stop`: one request line, one response line per
    /// connection, connections handled concurrently.
    pub async fn serve(listener: UnixListener, handler: Handler, mut stop: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        tokio::spawn(handle_connection(stream, handler.clone()));
                    }
                    Err(err) => eprintln!("socket accept failed: {err}"),
                },
                _ = stop.changed() => return,
            }
        }
    }

    async fn handle_connection(stream: UnixStream, handler: Handler) {
        let (read, mut write) = stream.into_split();
        let mut line = Vec::new();
        let mut reader = BufReader::new(read.take(MAX_REQUEST));
        if reader.read_until(b'\n', &mut line).await.is_err() || line.is_empty() {
            return;
        }
        let response = match serde_json::from_slice::<Value>(&line) {
            Ok(request) if request.is_object() => handler(request).await,
            _ => json!({"ok": false, "error": "malformed request"}),
        };
        let mut out = serde_json::to_vec(&response).unwrap_or_default();
        out.push(b'\n');
        write.write_all(&out).await.ok();
        write.shutdown().await.ok();
    }

    #[derive(Default)]
    struct LogState {
        next_seq: HashMap<String, i64>,
        subjects: HashMap<String, SubjectIndex>,
        /// Display names seen so far: member state arrives lazily in large rooms.
        known_names: HashMap<String, String>,
    }

    struct Daemon {
        paths: Paths,
        config: Config,
        /// The one client. A request with `trust_unverified_devices` replaces
        /// it for its duration (see [`Daemon::run_op`]).
        slot: RwLock<Option<Client>>,
        /// One operation at a time, like matrix-watchd.py's send lock.
        ops: Mutex<()>,
        log: std::sync::Mutex<LogState>,
        rooms: Vec<(String, String)>,
        started: Instant,
        /// Unix seconds of the last successful sync, 0 for never.
        last_sync: AtomicI64,
        own_user: String,
        own_display: Option<String>,
        own_key: Option<String>,
    }

    impl Daemon {
        fn watched(&self, room_id: &str) -> bool {
            self.rooms.iter().any(|(id, _)| id == room_id)
        }

        /// Append one event to its room's log. Sequence numbers and subjects
        /// are read from the log once per room and then kept in memory: the
        /// daemon is the only writer.
        fn record_event(&self, room_id: &str, event: &Event) {
            if let Err(err) = self.try_record_event(room_id, event) {
                eprintln!("cannot log an event of {room_id}: {err:#}");
            }
        }

        fn try_record_event(&self, room_id: &str, event: &Event) -> Result<()> {
            let path = log_path(&self.paths.rooms_dir(), room_id)?;
            let mut state = self
                .log
                .lock()
                .map_err(|_| anyhow::anyhow!("the log state is poisoned"))?;
            let seq = *state
                .next_seq
                .entry(room_id.to_owned())
                .or_insert_with(|| next_seq(&path));
            let subjects = state
                .subjects
                .entry(room_id.to_owned())
                .or_insert_with(|| SubjectIndex::from_log(&path));
            let target = event.relates_to.as_deref().or(event.redacts.as_deref());
            let own = Own {
                user_id: &self.own_user,
                display_name: self.own_display.as_deref(),
                sender_key: self.own_key.as_deref(),
            };
            let record = build_record(seq, event, &own, target.and_then(|t| subjects.get(t)));
            append_record(&path, &record, DEFAULT_MAX_BYTES)?;
            subjects.remember(&serde_json::to_value(&record)?);
            state.next_seq.insert(room_id.to_owned(), seq + 1);
            Ok(())
        }

        /// A daemon-level message into every watched log: a daemon that dies
        /// quietly looks like a quiet room.
        fn announce(&self, text: &str) {
            for (room_id, _) in &self.rooms {
                let ts = now_ms();
                self.record_event(
                    room_id,
                    &Event {
                        event_id: format!("$daemon-{ts}"),
                        sender: self.own_user.clone(),
                        sender_display: Some("watch-daemon".into()),
                        ts,
                        room_id: Some(room_id.clone()),
                        kind: "m.notice".into(),
                        body: Some(text.to_owned()),
                        ..Default::default()
                    },
                );
            }
        }

        /// Log the timeline events a sync delivered for the watched rooms.
        async fn process(&self, client: &Client, response: &SyncResponse) {
            for (room_id, update) in &response.rooms.joined {
                if !self.watched(room_id.as_str()) {
                    continue;
                }
                let room = client.get_room(room_id);
                for event in &update.timeline.events {
                    if let Some(event) = self.event_of(room.as_ref(), room_id.as_str(), event).await
                    {
                        self.record_event(room_id.as_str(), &event);
                    }
                }
            }
        }

        async fn display_name(&self, room: Option<&Room>, sender: &str) -> Option<String> {
            let member = match (room, UserId::parse(sender)) {
                (Some(room), Ok(user)) => room.get_member_no_sync(&user).await.ok().flatten(),
                _ => None,
            };
            let name = member.and_then(|m| m.display_name().map(str::to_owned));
            let mut state = self.log.lock().ok()?;
            match name {
                Some(name) => {
                    state.known_names.insert(sender.to_owned(), name.clone());
                    Some(name)
                }
                None => state.known_names.get(sender).cloned(),
            }
        }

        async fn event_of(
            &self,
            room: Option<&Room>,
            room_id: &str,
            event: &TimelineEvent,
        ) -> Option<Event> {
            let raw: Value = serde_json::from_str(event.raw().json().get()).ok()?;
            let sender_key = event
                .encryption_info()
                .map(|info| match &info.algorithm_info {
                    AlgorithmInfo::MegolmV1AesSha2 { curve25519_key, .. } => curve25519_key.clone(),
                    AlgorithmInfo::OlmV1Curve25519AesSha2 {
                        curve25519_public_key_base64,
                    } => curve25519_public_key_base64.clone(),
                });
            let undecryptable = matches!(event.kind, TimelineEventKind::UnableToDecrypt { .. })
                || raw.get("type").and_then(Value::as_str) == Some("m.room.encrypted");
            let mut mapped = event_from_json(&raw, undecryptable)?;
            mapped.room_id = Some(room_id.to_owned());
            mapped.sender_key = sender_key.or(mapped.sender_key);
            if mapped.ts == 0 {
                mapped.ts = now_ms();
            }
            mapped.sender_display = self.display_name(room, &mapped.sender).await;
            Some(mapped)
        }

        async fn dispatch(self: Arc<Self>, request: Value) -> Value {
            let op = request
                .get("op")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let result = match op.as_str() {
                "status" => Ok(self.status()),
                "send" => {
                    let trust = send::request_trusts_unverified(&request);
                    self.run_op(trust, |c| async move {
                        to_answer(send::execute(&c, &request).await?)
                    })
                    .await
                }
                "edit" => {
                    let trust = send::request_trusts_unverified(&request);
                    self.run_op(trust, |c| async move {
                        to_answer(edit::execute(&c, &request).await?)
                    })
                    .await
                }
                // Reactions and redactions are never encrypted: no room key.
                "react" => {
                    self.run_op(false, |c| async move {
                        to_answer(react::execute(&c, &request).await?)
                    })
                    .await
                }
                "redact" => {
                    self.run_op(false, |c| async move {
                        to_answer(redact::execute(&c, &request).await?)
                    })
                    .await
                }
                _ => Err(anyhow::anyhow!("unknown op: {op:?}")),
            };
            match result {
                Ok(answer) => answer,
                Err(err) => {
                    let msg = err
                        .chain()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(": ");
                    json!({"ok": false, "error": msg})
                }
            }
        }

        fn status(&self) -> Value {
            let last_sync = self.last_sync.load(Ordering::SeqCst);
            json!({
                "ok": true,
                "pid": std::process::id(),
                "uptime_seconds": self.started.elapsed().as_secs(),
                "rooms": self.rooms.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>(),
                "last_sync": if last_sync == 0 { Value::Null } else { json!(last_sync) },
            })
        }

        /// Run one operation with the client, one at a time.
        ///
        /// The room-key rule is fixed when a matrix-sdk client is built
        /// (`CollectStrategy`), and matrix-sdk 0.20.0 has no per-send
        /// override. A request with `trust_unverified_devices` therefore gets
        /// what the direct path gets: the daemon waits for the current sync,
        /// closes its client, opens the store with a client that shares the
        /// key with unverified devices too, carries out the request (which
        /// discards that room key afterwards, see `send_guarded`), closes that
        /// client and opens the store again with the verified-only client.
        /// "Closed" is waited for ([`close_client`]), so two clients are never
        /// open on the store at once.
        async fn run_op<F, Fut>(&self, trust_unverified: bool, op: F) -> Result<Value>
        where
            F: FnOnce(Client) -> Fut,
            Fut: Future<Output = Result<Value>>,
        {
            let _one_at_a_time = self.ops.lock().await;
            if !trust_unverified {
                let client = self
                    .slot
                    .read()
                    .await
                    .clone()
                    .context("the watch daemon has no client")?;
                return op(client).await;
            }
            let mut slot = self.slot.write().await;
            let current = slot.take().context("the watch daemon has no client")?;
            if let Err(still_open) = close_client(current, CLOSE_WAIT).await {
                *slot = Some(still_open);
                bail!(
                    "the store did not close in time; not sending to unverified devices (stop the watch daemon and send directly)"
                );
            }
            let result =
                match restore(&self.config, &self.paths, KeySharing::IncludeUnverified).await {
                    Ok(restored) => {
                        let flagged = restored.client;
                        let result = op(flagged.clone()).await;
                        if close_client(flagged, CLOSE_WAIT).await.is_err() {
                            // Opening the verified-only client now would put
                            // two clients on the store: leave the slot empty,
                            // and the sync loop stops the daemon.
                            eprintln!("the store did not close after a send to unverified devices");
                            return result;
                        }
                        result
                    }
                    Err(err) => {
                        Err(err.context("cannot open the store for a send to unverified devices"))
                    }
                };
            match restore(&self.config, &self.paths, KeySharing::VerifiedOnly).await {
                Ok(restored) => *slot = Some(restored.client),
                Err(err) => {
                    // The sync loop finds no client and stops the daemon.
                    eprintln!("cannot reopen the store: {err:#}");
                }
            }
            result
        }

        /// Sync until `stop`, or until the access token is rejected.
        async fn sync_loop(&self, mut stop: watch::Receiver<bool>) -> Result<()> {
            let mut backoff = Duration::from_secs(1);
            loop {
                if *stop.borrow() {
                    return Ok(());
                }
                let outcome = {
                    let guard = self.slot.read().await;
                    let Some(client) = guard.as_ref() else {
                        self.announce("the watch daemon stopped: it could not reopen its store; see daemon.log");
                        bail!("the store could not be reopened");
                    };
                    let settings = SyncSettings::default().timeout(SYNC_TIMEOUT);
                    tokio::select! {
                        result = client.sync_once(settings) => match result {
                            Ok(response) => {
                                self.process(client, &response).await;
                                Ok(())
                            }
                            Err(err) => Err(err),
                        },
                        _ = stop.changed() => return Ok(()),
                    }
                };
                match outcome {
                    Ok(()) => {
                        self.last_sync.store(now_ms() / 1000, Ordering::SeqCst);
                        backoff = Duration::from_secs(1);
                    }
                    Err(err)
                        if matches!(
                            err.client_api_error_kind(),
                            Some(ErrorKind::UnknownToken(_))
                        ) =>
                    {
                        self.announce(
                            "the watch daemon stopped: the access token was rejected (M_UNKNOWN_TOKEN). Run matrix-e2ee-cli login to create a new device.",
                        );
                        bail!("access token rejected, stopping");
                    }
                    Err(err) => {
                        eprintln!("sync error: {err}");
                        tokio::select! {
                            _ = tokio::time::sleep(backoff) => {}
                            _ = stop.changed() => return Ok(()),
                        }
                        backoff = (backoff * 2).min(Duration::from_secs(60));
                    }
                }
            }
        }
    }

    /// `{"ok": true}` plus the outcome's fields.
    fn to_answer<T: serde::Serialize>(outcome: T) -> Result<Value> {
        let mut answer = serde_json::to_value(outcome)?;
        let object = answer
            .as_object_mut()
            .context("an outcome is not an object")?;
        object.insert("ok".into(), json!(true));
        Ok(answer)
    }

    /// The log's view of one timeline event (matrix-watchd.py's
    /// `event_to_dict`): text, notice and emote messages, reactions,
    /// redactions, membership changes and undecryptable events. `None` for
    /// every other type, a redacted message and an event without id or sender.
    pub fn event_from_json(raw: &Value, undecryptable: bool) -> Option<Event> {
        let str_at = |v: &Value, path: &[&str]| -> Option<String> {
            let mut cur = v;
            for key in path {
                cur = cur.get(*key)?;
            }
            cur.as_str().map(str::to_owned)
        };
        let event_id = str_at(raw, &["event_id"]).filter(|s| !s.is_empty())?;
        let sender = str_at(raw, &["sender"]).filter(|s| !s.is_empty())?;
        let base = Event {
            event_id,
            sender,
            ts: raw
                .get("origin_server_ts")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            ..Default::default()
        };
        let content = raw.get("content").cloned().unwrap_or(Value::Null);
        if undecryptable {
            return Some(Event {
                kind: "encrypted".into(),
                session_id: str_at(&content, &["session_id"]),
                sender_key: str_at(&content, &["sender_key"]),
                ..base
            });
        }
        match raw.get("type").and_then(Value::as_str)? {
            "m.room.message" => {
                let body = str_at(&content, &["body"])?;
                match content.get("msgtype").and_then(Value::as_str)? {
                    "m.text" => {
                        let relates = content.get("m.relates_to").cloned().unwrap_or(Value::Null);
                        let thread_root =
                            if str_at(&relates, &["rel_type"]).as_deref() == Some("m.thread") {
                                str_at(&relates, &["event_id"])
                            } else {
                                None
                            };
                        Some(Event {
                            kind: "m.text".into(),
                            body: Some(body),
                            reply_to: str_at(&relates, &["m.in_reply_to", "event_id"]),
                            thread_root,
                            ..base
                        })
                    }
                    kind @ ("m.notice" | "m.emote") => Some(Event {
                        kind: kind.into(),
                        body: Some(body),
                        ..base
                    }),
                    _ => None,
                }
            }
            "m.reaction" => {
                let relates = content.get("m.relates_to")?;
                if str_at(relates, &["rel_type"]).as_deref() != Some("m.annotation") {
                    return None;
                }
                Some(Event {
                    kind: "reaction".into(),
                    body: Some(str_at(relates, &["key"])?),
                    relates_to: Some(str_at(relates, &["event_id"])?),
                    ..base
                })
            }
            "m.room.redaction" => Some(Event {
                kind: "redaction".into(),
                redacts: str_at(raw, &["redacts"]).or_else(|| str_at(&content, &["redacts"])),
                reason: str_at(&content, &["reason"]),
                ..base
            }),
            "m.room.member" => Some(Event {
                kind: "membership".into(),
                body: Some(str_at(&content, &["membership"])?),
                ..base
            }),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::daemon_client::{Reply, request};
        use crate::daemon_test_support::short_tempdir;

        fn echo_handler() -> Handler {
            Arc::new(|request: Value| {
                Box::pin(async move { json!({"ok": true, "event_id": "$x", "echo": request}) })
            })
        }

        async fn ask(path: PathBuf, payload: Value) -> Reply {
            tokio::task::spawn_blocking(move || request(&path, &payload, REQUEST_TIMEOUT).unwrap())
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn socket_round_trip_with_the_server() {
            let dir = short_tempdir();
            let path = dir.path().join("d.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (stop_tx, stop_rx) = watch::channel(false);
            let server = tokio::spawn(serve(listener, echo_handler(), stop_rx));

            let request = json!({"op": "send", "room": "!r:e", "body": "Grüße 🎁"});
            let Reply::Answer(answer) = ask(path.clone(), request.clone()).await else {
                panic!("no answer");
            };
            assert_eq!(answer["ok"], true);
            assert_eq!(answer["echo"], request);

            // Connections are independent: a second one is served too.
            assert!(matches!(
                ask(path.clone(), json!({"op": "status"})).await,
                Reply::Answer(_)
            ));

            stop_tx.send(true).unwrap();
            server.await.unwrap();
        }

        #[tokio::test]
        async fn a_malformed_request_gets_an_error_answer() {
            let dir = short_tempdir();
            let path = dir.path().join("d.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (_stop_tx, stop_rx) = watch::channel(false);
            tokio::spawn(serve(listener, echo_handler(), stop_rx));
            let answer = tokio::task::spawn_blocking(move || {
                use std::io::{BufRead, BufReader, Write};
                let mut stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
                stream.write_all(b"not json\n").unwrap();
                let mut line = String::new();
                BufReader::new(&stream).read_line(&mut line).unwrap();
                line
            })
            .await
            .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&answer).unwrap(),
                json!({"ok": false, "error": "malformed request"})
            );
        }

        #[test]
        fn status_text_matches_matrix_watchd() {
            let status = json!({"ok": true, "pid": 42, "uptime_seconds": 7, "rooms": ["!a:e", "!b:e"], "last_sync": 1_786_568_100});
            assert_eq!(
                status_text(&status),
                "pid:      42\nuptime:   7s\nrooms:    !a:e, !b:e\nlast sync: 1786568100\n"
            );
            let fresh =
                json!({"ok": true, "pid": 42, "uptime_seconds": 0, "rooms": [], "last_sync": null});
            assert!(status_text(&fresh).ends_with("rooms:    none\nlast sync: never\n"));
        }

        #[test]
        fn answers_carry_ok_and_the_outcome() {
            let answer = to_answer(send::SendOutcome {
                event_id: "$e".into(),
                room_id: "!r:e".into(),
                encrypted: true,
                warnings: vec![],
            })
            .unwrap();
            assert_eq!(
                answer,
                json!({"ok": true, "event_id": "$e", "room_id": "!r:e", "encrypted": true})
            );
        }

        fn ev(value: Value) -> Option<Event> {
            event_from_json(&value, false)
        }

        #[test]
        fn events_map_like_matrix_watchd() {
            let base = json!({"event_id": "$e", "sender": "@a:e", "origin_server_ts": 5});
            let with = |extra: Value| {
                let mut v = base.clone();
                v.as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().unwrap().clone());
                v
            };
            let text = ev(with(json!({"type": "m.room.message", "content": {
                "msgtype": "m.text", "body": "hi",
                "m.relates_to": {"rel_type": "m.thread", "event_id": "$root", "m.in_reply_to": {"event_id": "$p"}}}})))
            .unwrap();
            assert_eq!(
                (text.kind.as_str(), text.body.as_deref()),
                ("m.text", Some("hi"))
            );
            assert_eq!(text.thread_root.as_deref(), Some("$root"));
            assert_eq!(text.reply_to.as_deref(), Some("$p"));
            assert_eq!(text.ts, 5);

            let notice = ev(with(
                json!({"type": "m.room.message", "content": {"msgtype": "m.notice", "body": "n",
                "m.relates_to": {"m.in_reply_to": {"event_id": "$p"}}}}),
            ))
            .unwrap();
            assert_eq!(notice.kind, "m.notice");
            assert_eq!(
                notice.reply_to, None,
                "only m.text carries reply_to, as in nio"
            );

            assert!(ev(with(json!({"type": "m.room.message", "content": {"msgtype": "m.image", "body": "x"}}))).is_none());
            assert!(
                ev(with(json!({"type": "m.room.message", "content": {}}))).is_none(),
                "redacted"
            );

            let reaction = ev(with(
                json!({"type": "m.reaction", "content": {"m.relates_to": {
                "rel_type": "m.annotation", "event_id": "$t", "key": "✅"}}}),
            ))
            .unwrap();
            assert_eq!(
                (
                    reaction.kind.as_str(),
                    reaction.body.as_deref(),
                    reaction.relates_to.as_deref()
                ),
                ("reaction", Some("✅"), Some("$t"))
            );

            let redaction = ev(with(
                json!({"type": "m.room.redaction", "redacts": "$t", "content": {"reason": "spam"}}),
            ))
            .unwrap();
            assert_eq!(
                (redaction.redacts.as_deref(), redaction.reason.as_deref()),
                (Some("$t"), Some("spam"))
            );
            let v11 = ev(with(
                json!({"type": "m.room.redaction", "content": {"redacts": "$u"}}),
            ))
            .unwrap();
            assert_eq!(v11.redacts.as_deref(), Some("$u"));

            let member = ev(with(json!({"type": "m.room.member", "state_key": "@a:e", "content": {"membership": "join"}}))).unwrap();
            assert_eq!(
                (member.kind.as_str(), member.body.as_deref()),
                ("membership", Some("join"))
            );

            assert!(
                ev(with(
                    json!({"type": "m.room.topic", "content": {"topic": "t"}})
                ))
                .is_none()
            );
            assert!(ev(json!({"type": "m.room.message", "sender": "@a:e", "content": {"msgtype": "m.text", "body": "x"}})).is_none());

            let utd = event_from_json(&with(json!({"type": "m.room.encrypted", "content": {
                "algorithm": "m.megolm.v1.aes-sha2", "session_id": "S", "sender_key": "K", "ciphertext": "x"}})), true).unwrap();
            assert_eq!(
                (
                    utd.kind.as_str(),
                    utd.session_id.as_deref(),
                    utd.sender_key.as_deref(),
                    utd.body
                ),
                ("encrypted", Some("S"), Some("K"), None)
            );
        }
    }
}
