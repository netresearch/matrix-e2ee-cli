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
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::fs::{self, OpenOptions};
    use std::future::Future;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result, bail};
    use matrix_sdk::config::SyncSettings;
    use matrix_sdk::deserialized_responses::{
        AlgorithmInfo, TimelineEvent, TimelineEventKind, UnableToDecryptReason,
    };
    use matrix_sdk::ruma::api::error::ErrorKind;
    use matrix_sdk::ruma::events::room::encrypted::OriginalSyncRoomEncryptedEvent;
    use matrix_sdk::ruma::serde::Raw;
    use matrix_sdk::ruma::{OwnedRoomAliasId, RoomId, UserId};
    use matrix_sdk::sync::SyncResponse;
    use matrix_sdk::{Client, Room};
    use serde_json::{Value, json};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::{Mutex, RwLock, watch};
    use tokio::task::{JoinHandle, JoinSet};

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
            return match unanswered_pid_file(&paths.daemon_pid_file(), pid_alive) {
                PidFile::Missing => {
                    println!("{NO_DAEMON}");
                    Ok(())
                }
                PidFile::Removed => {
                    println!("No daemon running (stale pid file removed).");
                    Ok(())
                }
                // A daemon that is stopping no longer answers; its pid file
                // stays until it is gone (it removes the file itself).
                PidFile::Running(pid) => {
                    if wait_for_exit(|| pid_alive(pid), STOP_WAIT, Duration::from_millis(100)).await
                    {
                        println!("The watch daemon (pid {pid}) was stopping and has exited.");
                        return Ok(());
                    }
                    bail!(
                        "pid {pid} from {} is running but does not answer on the socket; the pid file is kept (see {})",
                        paths.daemon_pid_file().display(),
                        paths.daemon_log().display()
                    )
                }
            };
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
        // The daemon finishes the operation in flight and its answers first.
        if !wait_for_exit(|| pid_alive(pid), STOP_WAIT, Duration::from_millis(100)).await {
            bail!(
                "sent SIGTERM to the watch daemon (pid {pid}), but it has not exited after {} s; it may still be finishing an operation (see {})",
                STOP_WAIT.as_secs(),
                paths.daemon_log().display()
            );
        }
        println!("Stopped the watch daemon (pid {pid}).");
        Ok(())
    }

    /// How long `--stop` waits for the daemon to exit: its shutdown waits
    /// [`OP_WAIT`] for the operation in flight and [`ANSWER_WAIT`] for the
    /// answers.
    const STOP_WAIT: Duration = Duration::from_secs(OP_WAIT.as_secs() + ANSWER_WAIT.as_secs() + 5);

    /// The pid file when no daemon answers on the socket.
    #[derive(Debug, PartialEq, Eq)]
    enum PidFile {
        Missing,
        /// Unreadable, or its process is gone: removed.
        Removed,
        /// Its process exists (`alive`): kept.
        Running(i32),
    }

    /// Remove the pid file only when `alive` says its process is gone.
    fn unanswered_pid_file(pid_file: &Path, alive: impl Fn(i32) -> bool) -> PidFile {
        let Ok(text) = fs::read_to_string(pid_file) else {
            if !pid_file.exists() {
                return PidFile::Missing;
            }
            fs::remove_file(pid_file).ok();
            return PidFile::Removed;
        };
        if let Ok(pid) = text.trim().parse::<i32>()
            && pid > 0
            && alive(pid)
        {
            return PidFile::Running(pid);
        }
        fs::remove_file(pid_file).ok();
        PidFile::Removed
    }

    /// Does `pid` still exist? EPERM means it does, owned by someone else.
    /// A zombie (exited, not yet reaped) counts as gone.
    fn pid_alive(pid: i32) -> bool {
        // SAFETY: signal 0 checks only whether the process exists.
        let exists = unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
        exists && !is_zombie(pid)
    }

    /// The state in /proc/<pid>/stat is Z.
    #[cfg(target_os = "linux")]
    fn is_zombie(pid: i32) -> bool {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat_state(&stat))
            == Some('Z')
    }

    /// Without /proc a zombie is not told apart.
    #[cfg(not(target_os = "linux"))]
    fn is_zombie(_pid: i32) -> bool {
        false
    }

    /// The state field of /proc/<pid>/stat: after the command name, which is
    /// in parentheses and may itself contain spaces and parentheses.
    #[cfg(target_os = "linux")]
    fn stat_state(stat: &str) -> Option<char> {
        let (_, rest) = stat.rsplit_once(')')?;
        rest.trim_start().chars().next()
    }

    /// Poll `alive` until it reports false (true) or `limit` passes (false).
    pub async fn wait_for_exit(
        mut alive: impl FnMut() -> bool,
        limit: Duration,
        interval: Duration,
    ) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            if !alive() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(interval).await;
        }
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
        let (data_dir, log_file) = (paths.data_dir.clone(), paths.daemon_log());
        let log_path = log_file.clone();
        // Blocking file I/O: off the async worker threads.
        let log = tokio::task::spawn_blocking(move || -> Result<fs::File> {
            ensure_private_dir(&data_dir)?;
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&log_file)
                .with_context(|| format!("cannot open {}", log_file.display()))
        })
        .await
        .context("the log-file task failed")??;
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
                    log_path.display()
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
            log_path.display()
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
        let pid_file = paths.daemon_pid_file();
        tokio::task::spawn_blocking(move || fs::write(pid_file, std::process::id().to_string()))
            .await
            .context("the pid-file task failed")?
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
            stopping: AtomicBool::new(false),
            recorder: Recorder::new(paths.rooms_dir(), own_user, own_display, own_key),
            pending: std::sync::Mutex::new(PendingUtds::default()),
            rooms,
            started: Instant::now(),
            last_sync: AtomicI64::new(0),
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
        let stale = socket.clone();
        tokio::task::spawn_blocking(move || fs::remove_file(stale).ok())
            .await
            .context("the socket-cleanup task failed")?;
        let listener = UnixListener::bind(&socket).with_context(|| {
            format!(
                "cannot listen on {} (a socket path is limited to about 100 bytes)",
                socket.display()
            )
        })?;
        cleanup.0.push(socket.clone());
        // The data directory is 0700, so nobody else reaches the socket
        // between bind and chmod.
        let restrict = socket.clone();
        tokio::task::spawn_blocking(move || {
            fs::set_permissions(&restrict, fs::Permissions::from_mode(0o600))
        })
        .await
        .context("the socket-permission task failed")?
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
        // Its own stop: the sync loop also ends on errors, not only on signals.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve(listener, handler, shutdown_rx));
        let result = daemon.sync_loop(stop).await;
        shutdown(&daemon.ops, &daemon.stopping, &shutdown_tx, server, OP_WAIT).await;
        drop(cleanup);
        result
    }

    /// How long the connections may take to write their answers once the
    /// operation in flight has finished.
    const ANSWER_WAIT: Duration = Duration::from_secs(5);

    /// How long the shutdown waits for the operation in flight. The SDK
    /// retries a send on 5xx and 429 for up to 15 minutes.
    const OP_WAIT: Duration = Duration::from_secs(30);

    /// End serving without dropping an answer: stop accepting, let the
    /// operation in flight finish (later ones see `stopping` and refuse) for
    /// at most `op_wait`, then give the connections [`ANSWER_WAIT`] to
    /// answer. Only then may the process exit (main ends with
    /// `process::exit`, which kills every task). True when the operation in
    /// flight was abandoned.
    pub async fn shutdown(
        ops: &Mutex<()>,
        stopping: &AtomicBool,
        shutdown_tx: &watch::Sender<bool>,
        server: JoinHandle<JoinSet<()>>,
        op_wait: Duration,
    ) -> bool {
        stopping.store(true, Ordering::SeqCst);
        shutdown_tx.send(true).ok();
        let connections = server.await.unwrap_or_default();
        let abandoned = tokio::time::timeout(op_wait, ops.lock()).await.is_err();
        if abandoned {
            eprintln!(
                "an operation did not finish within {} s and was abandoned; its caller gets no answer, and it may or may not have been carried out",
                op_wait.as_secs()
            );
        }
        if !drain(connections, ANSWER_WAIT).await {
            eprintln!(
                "some connections did not finish within {} s",
                ANSWER_WAIT.as_secs()
            );
        }
        abandoned
    }

    /// Wait for every connection task, at most `limit`; true when all ended.
    async fn drain(mut connections: JoinSet<()>, limit: Duration) -> bool {
        tokio::time::timeout(limit, async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_ok()
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
    /// connection, connections handled concurrently. Returns the connections
    /// still running, for [`shutdown`] to wait for; dropping the set aborts
    /// them. The listener is closed on return, so a new client is refused at
    /// once instead of waiting for an answer that never comes.
    pub async fn serve(
        listener: UnixListener,
        handler: Handler,
        mut stop: watch::Receiver<bool>,
    ) -> JoinSet<()> {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        connections.spawn(handle_connection(stream, handler.clone()));
                    }
                    Err(err) => eprintln!("socket accept failed: {err}"),
                },
                // Reap finished connections, or the set grows per request.
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                _ = stop.changed() => break,
            }
        }
        drop(listener);
        connections
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

    /// Writes the room logs: the daemon is their only writer.
    pub struct Recorder {
        rooms_dir: PathBuf,
        log: std::sync::Mutex<LogState>,
        own_user: String,
        own_display: Option<String>,
        own_key: Option<String>,
    }

    impl Recorder {
        pub fn new(
            rooms_dir: PathBuf,
            own_user: String,
            own_display: Option<String>,
            own_key: Option<String>,
        ) -> Self {
            Self {
                rooms_dir,
                log: std::sync::Mutex::new(LogState::default()),
                own_user,
                own_display,
                own_key,
            }
        }

        /// Append one event to its room's log. Sequence numbers and subjects
        /// are read from the log once per room and then kept in memory: the
        /// daemon is the only writer.
        pub fn record_event(&self, room_id: &str, event: &Event) {
            if let Err(err) = self.try_record_event(room_id, event) {
                eprintln!("cannot log an event of {room_id}: {err:#}");
            }
        }

        fn try_record_event(&self, room_id: &str, event: &Event) -> Result<()> {
            let path = log_path(&self.rooms_dir, room_id)?;
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
    }

    struct Daemon {
        paths: Paths,
        config: Config,
        /// The one client. A request with `trust_unverified_devices` replaces
        /// it for its duration (see [`Daemon::run_op`]).
        slot: RwLock<Option<Client>>,
        /// One operation at a time, like matrix-watchd.py's send lock.
        ops: Mutex<()>,
        /// Set by [`shutdown`]: an operation still queued on `ops` refuses.
        stopping: AtomicBool,
        recorder: Recorder,
        /// Events logged as undecryptable, retried for a correction record.
        pending: std::sync::Mutex<PendingUtds>,
        rooms: Vec<(String, String)>,
        started: Instant,
        /// Unix seconds of the last successful sync, 0 for never.
        last_sync: AtomicI64,
    }

    impl Daemon {
        fn watched(&self, room_id: &str) -> bool {
            self.rooms.iter().any(|(id, _)| id == room_id)
        }

        fn record_event(&self, room_id: &str, event: &Event) {
            self.recorder.record_event(room_id, event);
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
                        sender: self.recorder.own_user.clone(),
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
                for timeline_event in &update.timeline.events {
                    if let Some(event) = self
                        .event_of(room.as_ref(), room_id.as_str(), timeline_event)
                        .await
                    {
                        self.record_event(room_id.as_str(), &event);
                        if let Ok(mut pending) = self.pending.lock() {
                            pending.track(
                                room_id.as_str(),
                                &event,
                                timeline_event.raw().json().get(),
                                Instant::now(),
                            );
                        }
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
            let mut state = self.recorder.log.lock().ok()?;
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
            let mut mapped = map_timeline_event(event)?;
            mapped.room_id = Some(room_id.to_owned());
            if mapped.ts == 0 {
                mapped.ts = now_ms();
            }
            mapped.sender_display = self.display_name(room, &mapped.sender).await;
            Some(mapped)
        }

        /// Retry the undecryptable events of the sessions that are due by
        /// decrypting the event kept from the sync again, with the keys now in
        /// the store. Local only: no fetch, and no key backup download
        /// (`BackupDownloadStrategy::Manual`, see `session.rs`). At most
        /// [`DECRYPTS_PER_ROUND`] attempts; the rest wait for the next round.
        async fn retry_undecryptable(&self, client: &Client) {
            retry_round(
                &self.pending,
                Instant::now(),
                DECRYPTS_PER_ROUND,
                move |entry| self.attempt(client, entry),
                |room_id, event| self.record_event(room_id, &event),
            )
            .await;
        }

        /// Decrypt one pending event again.
        async fn attempt(&self, client: &Client, entry: PendingUtd) -> Attempt {
            let room = RoomId::parse(&entry.room_id)
                .ok()
                .and_then(|id| client.get_room(&id));
            let Some(room) = room else {
                return Attempt::NoKey;
            };
            let Ok(raw) = Raw::<OriginalSyncRoomEncryptedEvent>::from_json_string(entry.raw) else {
                return Attempt::Decrypted(None);
            };
            let Ok(event) = room.decrypt_event(&raw, None).await else {
                return Attempt::Failed;
            };
            match retry_outcome(&event) {
                RetryOutcome::NoKey => Attempt::NoKey,
                RetryOutcome::StillUndecryptable => Attempt::Failed,
                RetryOutcome::NotLogged => Attempt::Decrypted(None),
                RetryOutcome::Decrypted(_) => Attempt::Decrypted(
                    self.event_of(Some(&room), &entry.room_id, &event)
                        .await
                        .map(Box::new),
                ),
            }
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
            if self.stopping.load(Ordering::SeqCst) {
                bail!("the watch daemon is stopping; the request was not carried out");
            }
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
                    // An operation may hold the slot (a send to unverified
                    // devices); stop must not wait for it here, shutdown does.
                    let guard = tokio::select! {
                        guard = self.slot.read() => guard,
                        _ = stop.changed() => return Ok(()),
                    };
                    let Some(client) = guard.as_ref() else {
                        self.announce("the watch daemon stopped: it could not reopen its store; see daemon.log");
                        bail!("the store could not be reopened");
                    };
                    // Before each sync, so the first round (for what the
                    // first sync logged) comes after the socket is bound.
                    tokio::select! {
                        () = self.retry_undecryptable(client) => {}
                        _ = stop.changed() => return Ok(()),
                    }
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

    /// Undecryptable events kept for a retry at most.
    const PENDING_MAX: usize = 1000;
    /// An undecryptable event is given up on after this long.
    const PENDING_GIVE_UP: Duration = Duration::from_secs(24 * 60 * 60);
    /// The first wait before a session without a key, or an event that
    /// failed to decrypt, is tried again; doubled per failure up to
    /// [`RETRY_MAX`].
    const RETRY_FIRST: Duration = Duration::from_secs(30);
    const RETRY_MAX: Duration = Duration::from_secs(60 * 60);
    /// Decryption attempts per round at most, over all sessions.
    const DECRYPTS_PER_ROUND: usize = 50;

    /// One event logged as undecryptable, with the event as the sync
    /// delivered it, for decrypting it again.
    #[derive(Debug, Clone, PartialEq)]
    pub struct PendingUtd {
        room_id: String,
        session_id: String,
        event_id: String,
        /// The `m.room.encrypted` event's JSON.
        raw: String,
        since: Instant,
        /// When this event may be tried again, and the wait after that.
        next: Instant,
        wait: Duration,
    }

    /// The undecryptable events waiting for their room key, oldest first,
    /// and when each session without a key is tried next. In memory only: a
    /// restarted daemon does not correct what an earlier one logged.
    #[derive(Debug, Default)]
    pub struct PendingUtds {
        entries: VecDeque<PendingUtd>,
        /// (room id, session id) -> (next try, current wait).
        schedule: HashMap<(String, String), (Instant, Duration)>,
    }

    impl PendingUtds {
        pub fn add(
            &mut self,
            room_id: &str,
            session_id: &str,
            event_id: &str,
            raw: &str,
            now: Instant,
        ) {
            if self.entries.iter().any(|e| e.event_id == event_id) {
                return;
            }
            self.entries.push_back(PendingUtd {
                room_id: room_id.to_owned(),
                session_id: session_id.to_owned(),
                event_id: event_id.to_owned(),
                raw: raw.to_owned(),
                since: now,
                next: now,
                wait: RETRY_FIRST,
            });
            // A new session is tried at the next round: its key often
            // arrives right after the event.
            self.schedule
                .entry((room_id.to_owned(), session_id.to_owned()))
                .or_insert((now, RETRY_FIRST));
            while self.entries.len() > PENDING_MAX {
                self.entries.pop_front();
            }
            self.forget_empty_sessions();
        }

        /// What a logged event means for the pending ones: an undecryptable
        /// event (`raw`: as the sync delivered it) waits for its key, and a
        /// redaction settles the event it names.
        pub fn track(&mut self, room_id: &str, event: &Event, raw: &str, now: Instant) {
            if event.kind == "encrypted"
                && let Some(session_id) = &event.session_id
            {
                self.add(room_id, session_id, &event.event_id, raw, now);
            }
            if let Some(redacted) = &event.redacts {
                // Only in its own room: an event id names no event elsewhere.
                self.entries
                    .retain(|e| !(e.room_id == room_id && &e.event_id == redacted));
                self.forget_empty_sessions();
            }
        }

        /// Drop what is past [`PENDING_GIVE_UP`], then the events that are
        /// due, grouped by session (oldest session first, its events oldest
        /// first), at most `budget`.
        pub fn due(&mut self, now: Instant, budget: usize) -> Vec<PendingUtd> {
            self.entries
                .retain(|e| now.saturating_duration_since(e.since) < PENDING_GIVE_UP);
            self.forget_empty_sessions();
            let mut sessions: Vec<(&str, &str)> = Vec::new();
            for e in &self.entries {
                let key = (e.room_id.as_str(), e.session_id.as_str());
                if !sessions.contains(&key) {
                    sessions.push(key);
                }
            }
            let mut due = Vec::new();
            for (room_id, session_id) in sessions {
                let session_due = self
                    .schedule
                    .get(&(room_id.to_owned(), session_id.to_owned()))
                    .is_none_or(|(next, _)| *next <= now);
                if !session_due {
                    continue;
                }
                for e in self
                    .entries
                    .iter()
                    .filter(|e| e.room_id == room_id && e.session_id == session_id && e.next <= now)
                {
                    if due.len() == budget {
                        return due;
                    }
                    due.push(e.clone());
                }
            }
            due
        }

        /// The store has no key for this session: wait longer before
        /// trying any of its events.
        pub fn no_key(&mut self, room_id: &str, session_id: &str, now: Instant) {
            let slot = self
                .schedule
                .entry((room_id.to_owned(), session_id.to_owned()))
                .or_insert((now, RETRY_FIRST));
            *slot = (now + slot.1, (slot.1 * 2).min(RETRY_MAX));
        }

        /// This event did not decrypt although its session may have a key
        /// (an earlier message index, a broken event): wait longer for it
        /// alone, so the next round tries the others first.
        pub fn failed(&mut self, event_id: &str, now: Instant) {
            if let Some(e) = self.entries.iter_mut().find(|e| e.event_id == event_id) {
                e.next = now + e.wait;
                e.wait = (e.wait * 2).min(RETRY_MAX);
            }
        }

        pub fn remove(&mut self, event_id: &str) {
            self.entries.retain(|e| e.event_id != event_id);
            self.forget_empty_sessions();
        }

        #[cfg(test)]
        pub fn len(&self) -> usize {
            self.entries.len()
        }

        fn forget_empty_sessions(&mut self) {
            let entries = &self.entries;
            self.schedule.retain(|(room, session), _| {
                entries
                    .iter()
                    .any(|e| &e.room_id == room && &e.session_id == session)
            });
        }
    }

    /// What one decryption attempt of a pending event gave.
    #[derive(Debug)]
    pub enum Attempt {
        /// Settled: the correction record to write, if the log carries the type.
        Decrypted(Option<Box<Event>>),
        /// The store has no key for the event's session.
        NoKey,
        /// Not decrypted for another reason.
        Failed,
    }

    /// One retry round: try the due events, at most `budget` attempts, and
    /// settle each that decrypts (`record` writes its correction first, with
    /// no await before it is removed). A session without a key is not tried
    /// further in this round. Returns the number of attempts.
    pub async fn retry_round<F, Fut>(
        pending: &std::sync::Mutex<PendingUtds>,
        now: Instant,
        budget: usize,
        mut attempt: F,
        mut record: impl FnMut(&str, Event),
    ) -> usize
    where
        F: FnMut(PendingUtd) -> Fut,
        Fut: Future<Output = Attempt>,
    {
        let mut without_key: HashSet<(String, String)> = HashSet::new();
        let mut attempts = 0;
        // Every attempt settles its event or moves it (or its session) past
        // `now`, so asking again for the rest of the budget ends.
        while attempts < budget {
            let due = match pending.lock() {
                Ok(mut pending) => pending.due(now, budget - attempts),
                Err(_) => break,
            };
            if due.is_empty() {
                break;
            }
            for entry in due {
                let session = (entry.room_id.clone(), entry.session_id.clone());
                if without_key.contains(&session) {
                    continue;
                }
                attempts += 1;
                let (room_id, event_id) = (entry.room_id.clone(), entry.event_id.clone());
                let outcome = attempt(entry).await;
                if let Attempt::Decrypted(Some(correction)) = outcome {
                    record(&room_id, *correction);
                    if let Ok(mut pending) = pending.lock() {
                        pending.remove(&event_id);
                    }
                    continue;
                }
                let Ok(mut pending) = pending.lock() else {
                    return attempts;
                };
                match outcome {
                    Attempt::Decrypted(_) => pending.remove(&event_id),
                    Attempt::NoKey => {
                        pending.no_key(&session.0, &session.1, now);
                        without_key.insert(session);
                    }
                    Attempt::Failed => pending.failed(&event_id, now),
                }
            }
        }
        attempts
    }

    /// What decrypting an undecryptable event again gave.
    #[derive(Debug, PartialEq)]
    pub enum RetryOutcome {
        /// The store has no room key for its session.
        NoKey,
        StillUndecryptable,
        /// Decrypted, but of a type the log does not carry.
        NotLogged,
        Decrypted(Box<Event>),
    }

    pub fn retry_outcome(event: &TimelineEvent) -> RetryOutcome {
        if let TimelineEventKind::UnableToDecrypt { utd_info, .. } = &event.kind
            && matches!(
                utd_info.reason,
                UnableToDecryptReason::MissingMegolmSession { .. }
            )
        {
            return RetryOutcome::NoKey;
        }
        match map_timeline_event(event) {
            None => RetryOutcome::NotLogged,
            Some(mapped) if mapped.kind == "encrypted" => RetryOutcome::StillUndecryptable,
            Some(mapped) => RetryOutcome::Decrypted(Box::new(mapped)),
        }
    }

    /// [`event_from_json`] for a timeline event: undecryptable when the SDK
    /// says so or when the event is still `m.room.encrypted` (a decryption
    /// that failed with an error), and the sender key of the device that
    /// encrypted it when it was decrypted.
    pub fn map_timeline_event(event: &TimelineEvent) -> Option<Event> {
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
        mapped.sender_key = sender_key.or(mapped.sender_key);
        Some(mapped)
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

        /// A handler that holds `ops` like run_op, says when it started and
        /// answers only after a while.
        fn slow_handler(ops: Arc<Mutex<()>>, started: Arc<tokio::sync::Notify>) -> Handler {
            Arc::new(move |request: Value| {
                let ops = ops.clone();
                let started = started.clone();
                Box::pin(async move {
                    let _op = ops.lock().await;
                    started.notify_one();
                    tokio::time::sleep(Duration::from_millis(700)).await;
                    json!({"ok": true, "event_id": "$sent", "echo": request})
                })
            })
        }

        #[test]
        fn an_operation_in_flight_is_answered_when_the_daemon_stops() {
            let dir = short_tempdir();
            let path = dir.path().join("d.sock");
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let client = runtime.block_on(async {
                let listener = UnixListener::bind(&path).unwrap();
                let ops = Arc::new(Mutex::new(()));
                let started = Arc::new(tokio::sync::Notify::new());
                let stopping = AtomicBool::new(false);
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let server = tokio::spawn(serve(
                    listener,
                    slow_handler(ops.clone(), started.clone()),
                    shutdown_rx,
                ));
                let socket = path.clone();
                let client = std::thread::spawn(move || {
                    request(
                        &socket,
                        &json!({"op": "send", "body": "hi"}),
                        REQUEST_TIMEOUT,
                    )
                });
                started.notified().await;
                // The stop arrives while the send is being carried out.
                shutdown(&ops, &stopping, &shutdown_tx, server, OP_WAIT).await;
                assert!(stopping.load(Ordering::SeqCst));
                client
            });
            // What process::exit does to every task still running.
            runtime.shutdown_background();
            let reply = client.join().unwrap();
            let Ok(Reply::Answer(answer)) = reply else {
                panic!("the send was carried out but not answered: {reply:?}");
            };
            assert_eq!(answer["event_id"], "$sent");
            assert!(!path.exists() || std::os::unix::net::UnixStream::connect(&path).is_err());
        }

        fn t0() -> Instant {
            Instant::now()
        }

        const RAW: &str = r#"{"type":"m.room.encrypted"}"#;

        fn ids(entries: &[PendingUtd]) -> Vec<&str> {
            entries.iter().map(|e| e.event_id.as_str()).collect()
        }

        #[test]
        fn pending_events_are_due_by_session_and_kept_once() {
            let now = t0();
            let mut p = PendingUtds::default();
            p.add("!r", "S1", "$a", RAW, now);
            p.add("!r", "S2", "$c", RAW, now);
            p.add("!r", "S1", "$b", RAW, now);
            p.add("!r", "S1", "$a", RAW, now);
            assert_eq!(p.len(), 3, "an event is kept once");
            assert_eq!(ids(&p.due(now, 10)), vec!["$a", "$b", "$c"]);
            assert_eq!(ids(&p.due(now, 2)), vec!["$a", "$b"]);
            p.remove("$a");
            // S2's event is now the oldest.
            assert_eq!(ids(&p.due(now, 10)), vec!["$c", "$b"]);
        }

        #[test]
        fn a_session_without_a_key_is_tried_less_often() {
            let now = t0();
            let mut p = PendingUtds::default();
            p.add("!r", "S", "$a", RAW, now);
            p.no_key("!r", "S", now);
            assert!(p.due(now + Duration::from_secs(29), 10).is_empty());
            assert_eq!(p.due(now + RETRY_FIRST, 10).len(), 1);
            p.no_key("!r", "S", now + RETRY_FIRST);
            assert!(
                p.due(now + RETRY_FIRST * 2, 10).is_empty(),
                "the wait doubles"
            );
            assert_eq!(p.due(now + RETRY_FIRST * 3, 10).len(), 1);
        }

        #[test]
        fn pending_is_bounded_and_drops_the_oldest() {
            let now = t0();
            let mut p = PendingUtds::default();
            for i in 0..PENDING_MAX + 5 {
                p.add("!r", &format!("S{i}"), &format!("$e{i}"), RAW, now);
            }
            assert_eq!(p.len(), PENDING_MAX);
            let due = p.due(now, PENDING_MAX);
            assert_eq!(due[0].event_id, "$e5");
            assert_eq!(
                p.schedule.len(),
                PENDING_MAX,
                "no schedule for dropped sessions"
            );
        }

        #[test]
        fn pending_gives_up_after_a_day() {
            let now = t0();
            let mut p = PendingUtds::default();
            p.add("!r", "S", "$old", RAW, now);
            p.add("!r", "T", "$new", RAW, now + Duration::from_secs(3600));
            assert_eq!(ids(&p.due(now + PENDING_GIVE_UP, 10)), vec!["$new"]);
            assert_eq!(p.len(), 1);
        }

        fn utd_event(id: &str, session: &str) -> Event {
            event_from_json(
                &json!({"event_id": id, "sender": "@a:e", "origin_server_ts": 5,
                    "type": "m.room.encrypted", "content": {"session_id": session}}),
                true,
            )
            .unwrap()
        }

        #[test]
        fn a_logged_utd_is_kept_with_its_raw_event_and_a_redaction_settles_it() {
            let now = t0();
            let mut p = PendingUtds::default();
            let raw = r#"{"type":"m.room.encrypted","event_id":"$e","content":{"session_id":"S"}}"#;
            p.track("!r", &utd_event("$e", "S"), raw, now);
            p.track("!r", &utd_event("$f", "S"), raw, now);
            let due = p.due(now, 10);
            assert_eq!(ids(&due), vec!["$e", "$f"]);
            assert_eq!(due[0].raw, raw, "the sync's event is kept for decryption");
            let redaction = event_from_json(
                &json!({"event_id": "$x", "sender": "@a:e", "origin_server_ts": 6,
                    "type": "m.room.redaction", "redacts": "$e", "content": {}}),
                false,
            )
            .unwrap();
            p.track("!r", &redaction, "{}", now);
            assert_eq!(ids(&p.due(now, 10)), vec!["$f"]);
        }

        #[test]
        fn a_redaction_in_another_room_leaves_the_event_pending() {
            let now = t0();
            let mut p = PendingUtds::default();
            p.track("!r", &utd_event("$e", "S"), RAW, now);
            let redaction = event_from_json(
                &json!({"event_id": "$x", "sender": "@a:e", "origin_server_ts": 6,
                    "type": "m.room.redaction", "redacts": "$e", "content": {}}),
                false,
            )
            .unwrap();
            p.track("!other", &redaction, "{}", now);
            assert_eq!(ids(&p.due(now, 10)), vec!["$e"]);
            p.track("!r", &redaction, "{}", now);
            assert!(p.due(now, 10).is_empty());
        }

        #[test]
        fn a_session_without_a_key_does_not_use_up_the_budget() {
            let now = t0();
            let pending = std::sync::Mutex::new(PendingUtds::default());
            for i in 0..60 {
                pending
                    .lock()
                    .unwrap()
                    .add("!r", "A", &format!("$a{i}"), RAW, now);
            }
            pending.lock().unwrap().add("!r", "B", "$b", RAW, now);
            let outcome = |id: &str| {
                if id == "$b" {
                    Attempt::Decrypted(Some(Box::new(decrypted(id))))
                } else {
                    Attempt::NoKey
                }
            };
            let (tried, written) = round(&pending, now, 50, outcome);
            assert_eq!(tried, vec!["$a0", "$b"]);
            assert_eq!(written, vec!["$b"]);
        }

        fn decrypted(id: &str) -> Event {
            Event {
                event_id: id.into(),
                kind: "m.text".into(),
                body: Some("hallo".into()),
                ..Default::default()
            }
        }

        /// Run one round; `outcome` decides per event id. The ids tried, and
        /// the corrections written.
        fn round(
            pending: &std::sync::Mutex<PendingUtds>,
            now: Instant,
            budget: usize,
            outcome: impl Fn(&str) -> Attempt,
        ) -> (Vec<String>, Vec<String>) {
            let tried = std::sync::Mutex::new(Vec::new());
            let mut written = Vec::new();
            let attempts = futures_util::FutureExt::now_or_never(retry_round(
                pending,
                now,
                budget,
                |entry| {
                    tried.lock().unwrap().push(entry.event_id.clone());
                    std::future::ready(outcome(&entry.event_id))
                },
                |_, event| written.push(event.event_id),
            ))
            .unwrap();
            let tried = tried.into_inner().unwrap();
            assert_eq!(attempts, tried.len());
            (tried, written)
        }

        #[test]
        fn a_round_counts_every_attempt_against_one_budget() {
            let now = t0();
            let pending = std::sync::Mutex::new(PendingUtds::default());
            for s in 0..3 {
                for i in 0..30 {
                    pending.lock().unwrap().add(
                        "!r",
                        &format!("S{s}"),
                        &format!("$e{s}-{i}"),
                        RAW,
                        now,
                    );
                }
            }
            let ok = |id: &str| Attempt::Decrypted(Some(Box::new(decrypted(id))));
            let (tried, written) = round(&pending, now, 50, ok);
            assert_eq!(tried.len(), 50, "one budget for all sessions");
            assert_eq!(written, tried);
            assert_eq!(pending.lock().unwrap().len(), 40);
            let (tried, _) = round(&pending, now, 50, ok);
            assert_eq!(tried.len(), 40, "the rest in the next round");
            assert_eq!(pending.lock().unwrap().len(), 0);
        }

        #[test]
        fn events_that_fail_do_not_block_the_later_ones_of_their_session() {
            let now = t0();
            let pending = std::sync::Mutex::new(PendingUtds::default());
            for i in 0..5 {
                pending
                    .lock()
                    .unwrap()
                    .add("!r", "S", &format!("$old{i}"), RAW, now);
            }
            pending.lock().unwrap().add("!r", "S", "$new", RAW, now);
            // The key arrived at a later message index: only $new decrypts.
            let outcome = |id: &str| {
                if id == "$new" {
                    Attempt::Decrypted(Some(Box::new(decrypted(id))))
                } else {
                    Attempt::Failed
                }
            };
            let (tried, written) = round(&pending, now, 4, outcome);
            assert_eq!(tried, vec!["$old0", "$old1", "$old2", "$old3"]);
            assert!(written.is_empty());
            let (tried, written) = round(&pending, now, 4, outcome);
            assert_eq!(tried, vec!["$old4", "$new"]);
            assert_eq!(written, vec!["$new"]);
            assert_eq!(pending.lock().unwrap().len(), 5);
        }

        #[test]
        fn a_session_without_a_key_ends_its_part_of_the_round() {
            let now = t0();
            let pending = std::sync::Mutex::new(PendingUtds::default());
            for id in ["$a1", "$a2", "$a3"] {
                pending.lock().unwrap().add("!r", "A", id, RAW, now);
            }
            pending.lock().unwrap().add("!r", "B", "$b1", RAW, now);
            let outcome = |id: &str| {
                if id.starts_with("$a") {
                    Attempt::NoKey
                } else {
                    Attempt::Decrypted(None)
                }
            };
            let (tried, written) = round(&pending, now, 50, outcome);
            assert_eq!(tried, vec!["$a1", "$b1"]);
            assert!(written.is_empty(), "nothing to write for an unlogged type");
            assert_eq!(pending.lock().unwrap().len(), 3);
            assert!(round(&pending, now, 50, outcome).0.is_empty());
        }

        #[test]
        fn a_missing_session_key_is_told_from_other_failures() {
            use matrix_sdk::deserialized_responses::UnableToDecryptInfo;
            let raw = Raw::from_json_string(
                json!({"event_id": "$e", "sender": "@a:e", "origin_server_ts": 5,
                    "type": "m.room.encrypted", "content": {"session_id": "S"}})
                .to_string(),
            )
            .unwrap();
            let utd = |reason| {
                TimelineEvent::from_utd(
                    raw.clone(),
                    UnableToDecryptInfo {
                        session_id: Some("S".into()),
                        reason,
                    },
                )
            };
            assert_eq!(
                retry_outcome(&utd(UnableToDecryptReason::MissingMegolmSession {
                    withheld_code: None
                })),
                RetryOutcome::NoKey
            );
            assert_eq!(
                retry_outcome(&utd(UnableToDecryptReason::UnknownMegolmMessageIndex)),
                RetryOutcome::StillUndecryptable
            );
        }

        #[tokio::test]
        async fn shutdown_abandons_an_operation_that_does_not_finish() {
            let ops = Mutex::new(());
            let stopping = AtomicBool::new(false);
            let (shutdown_tx, _rx) = watch::channel(false);
            let server = tokio::spawn(async { JoinSet::new() });
            // An operation that never ends (the SDK retrying a send).
            let _in_flight = ops.lock().await;
            let abandoned = tokio::time::timeout(
                Duration::from_secs(10),
                shutdown(
                    &ops,
                    &stopping,
                    &shutdown_tx,
                    server,
                    Duration::from_millis(200),
                ),
            )
            .await
            .expect("shutdown waited for the operation without a limit");
            assert!(abandoned);
            assert!(stopping.load(Ordering::SeqCst));
        }

        #[test]
        fn the_pid_file_of_a_live_process_is_kept() {
            let dir = tempfile::tempdir().unwrap();
            let pid_file = dir.path().join("daemon.pid");
            assert_eq!(unanswered_pid_file(&pid_file, |_| true), PidFile::Missing);
            fs::write(&pid_file, "4242").unwrap();
            assert_eq!(
                unanswered_pid_file(&pid_file, |pid| pid == 4242),
                PidFile::Running(4242)
            );
            assert!(
                pid_file.exists(),
                "a stopping daemon's pid file was deleted"
            );
            assert_eq!(unanswered_pid_file(&pid_file, |_| false), PidFile::Removed);
            assert!(!pid_file.exists());
            fs::write(&pid_file, "garbage").unwrap();
            assert_eq!(unanswered_pid_file(&pid_file, |_| true), PidFile::Removed);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn the_state_is_read_after_the_command_name() {
            assert_eq!(stat_state("42 (a) b) Z 1 2 3"), Some('Z'));
            assert_eq!(stat_state("42 (sleep) S 1 2 3"), Some('S'));
            assert_eq!(stat_state("garbage"), None);
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn a_zombie_counts_as_gone() {
            let mut child = std::process::Command::new("true").spawn().unwrap();
            let pid = i32::try_from(child.id()).unwrap();
            // Not reaped yet: a zombie once it has exited.
            let deadline = Instant::now() + Duration::from_secs(5);
            while !is_zombie(pid) {
                assert!(Instant::now() < deadline, "the child did not exit");
                std::thread::sleep(Duration::from_millis(10));
            }
            // SAFETY: signal 0 checks only whether the process exists.
            assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "a zombie still exists");
            assert!(!pid_alive(pid));
            child.wait().unwrap();
        }

        #[tokio::test]
        async fn the_sync_loop_retries_before_it_syncs_and_stops_on_the_signal() {
            let dir = short_tempdir();
            let paths = Paths {
                data_dir: dir.path().to_owned(),
            };
            // No session and nothing listening: every sync fails at once.
            let client = Client::builder()
                .homeserver_url("http://127.0.0.1:9")
                .build()
                .await
                .unwrap();
            let daemon = Arc::new(Daemon {
                paths: paths.clone(),
                config: Config {
                    homeserver: "http://127.0.0.1:9".into(),
                    user_id: "@me:e".into(),
                },
                slot: RwLock::new(Some(client)),
                ops: Mutex::new(()),
                stopping: AtomicBool::new(false),
                recorder: Recorder::new(paths.rooms_dir(), "@me:e".into(), None, None),
                pending: std::sync::Mutex::new(PendingUtds::default()),
                rooms: vec![("!r:e".into(), "!r:e".into())],
                started: Instant::now(),
                last_sync: AtomicI64::new(0),
            });
            let now = Instant::now();
            daemon
                .pending
                .lock()
                .unwrap()
                .add("!r:e", "S", "$e", RAW, now);
            let (stop_tx, stop_rx) = watch::channel(false);
            let looping = tokio::spawn({
                let daemon = daemon.clone();
                async move { daemon.sync_loop(stop_rx).await }
            });
            // Until the round has run (the session is no longer due), at most 5 s.
            let deadline = Instant::now() + Duration::from_secs(5);
            while !daemon.pending.lock().unwrap().due(now, 10).is_empty()
                && Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            stop_tx.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(5), looping)
                .await
                .expect("the sync loop did not stop")
                .unwrap()
                .unwrap();
            // The room is unknown to the client: tried once, without a key.
            assert!(
                daemon.pending.lock().unwrap().due(now, 10).is_empty(),
                "no retry round ran in the sync loop"
            );
        }

        fn timeline(value: Value) -> TimelineEvent {
            TimelineEvent::from_plaintext(
                matrix_sdk::ruma::serde::Raw::from_json_string(value.to_string()).unwrap(),
            )
        }

        #[test]
        fn a_retry_tells_decrypted_from_still_undecryptable() {
            let base = json!({"event_id": "$e", "sender": "@a:e", "origin_server_ts": 5});
            let with = |extra: Value| {
                let mut v = base.clone();
                v.as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().unwrap().clone());
                v
            };
            let still = timeline(with(json!({"type": "m.room.encrypted", "content": {
                "algorithm": "m.megolm.v1.aes-sha2", "session_id": "S", "ciphertext": "x"}})));
            assert_eq!(retry_outcome(&still), RetryOutcome::StillUndecryptable);
            let image = timeline(with(
                json!({"type": "m.room.message", "content": {"msgtype": "m.image", "body": "x"}}),
            ));
            assert_eq!(retry_outcome(&image), RetryOutcome::NotLogged);
            let text = timeline(with(
                json!({"type": "m.room.message", "content": {"msgtype": "m.text", "body": "hallo"}}),
            ));
            let RetryOutcome::Decrypted(event) = retry_outcome(&text) else {
                panic!("a decrypted message must give a correction");
            };
            assert_eq!(
                (event.event_id.as_str(), event.body.as_deref()),
                ("$e", Some("hallo"))
            );
        }

        #[test]
        fn a_correction_record_has_the_same_event_id_and_a_new_seq() {
            let dir = tempfile::tempdir().unwrap();
            let recorder = Recorder::new(dir.path().to_path_buf(), "@me:e".into(), None, None);
            let utd = event_from_json(
                &json!({"event_id": "$e", "sender": "@a:e", "origin_server_ts": 5,
                    "type": "m.room.encrypted", "content": {"session_id": "S"}}),
                true,
            )
            .unwrap();
            recorder.record_event("!r:e", &utd);
            let decrypted = timeline(
                json!({"event_id": "$e", "sender": "@a:e", "origin_server_ts": 5,
                "type": "m.room.message", "content": {"msgtype": "m.text", "body": "hallo"}}),
            );
            let RetryOutcome::Decrypted(corrected) = retry_outcome(&decrypted) else {
                panic!("no correction");
            };
            recorder.record_event("!r:e", &corrected);
            let records = crate::roomlog::read_records(&log_path(dir.path(), "!r:e").unwrap());
            assert_eq!(records.len(), 2);
            assert_eq!(
                records
                    .iter()
                    .map(|r| (r["event_id"].clone(), r["seq"].clone(), r["type"].clone()))
                    .collect::<Vec<_>>(),
                vec![
                    (json!("$e"), json!(1), json!("encrypted")),
                    (json!("$e"), json!(2), json!("m.text")),
                ]
            );
            assert_eq!(records[1]["body"], "hallo");
            assert_eq!(records[0]["session_id"], "S");
        }

        #[tokio::test]
        async fn stop_waits_until_the_process_is_gone() {
            let mut probes = 0;
            let gone = wait_for_exit(
                || {
                    probes += 1;
                    probes < 4
                },
                Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .await;
            assert!(gone);
            assert_eq!(probes, 4, "returned before the process was gone");
        }

        #[tokio::test]
        async fn stop_reports_a_process_that_does_not_exit() {
            let started = Instant::now();
            let gone =
                wait_for_exit(|| true, Duration::from_millis(50), Duration::from_millis(5)).await;
            assert!(!gone);
            assert!(started.elapsed() >= Duration::from_millis(50));
        }

        #[test]
        fn a_live_and_a_gone_pid() {
            assert!(pid_alive(i32::try_from(std::process::id()).unwrap()));
            let mut child = std::process::Command::new("true").spawn().unwrap();
            let pid = i32::try_from(child.id()).unwrap();
            child.wait().unwrap();
            assert!(!pid_alive(pid));
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
