//! `verify`: SAS (emoji) verification with one of the account's own devices.
//!
//! A sync loop runs in the background for the whole flow, because every
//! verification step arrives as a to-device event.
//!
//! With a terminal on stdin and stderr, a person confirms the emoji at the
//! prompt. With `--hand-over` (an agent runs the command, with or without a
//! terminal), the emoji go to stdout as one JSON line and to an owner-only
//! file, and the verification is confirmed only after a second process,
//! `verify --confirm`, handed over the person's decision; the CLI never
//! confirms on its own. Without a terminal and without `--hand-over` it
//! refuses.

use std::future::Future;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{Stream, StreamExt};
use matrix_sdk::Client;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::encryption::verification::{
    CancelInfo, Emoji, SasState, SasVerification, Verification, VerificationRequest,
    VerificationRequestState,
};
use matrix_sdk::ruma::events::key::verification::request::ToDeviceKeyVerificationRequestEvent;
use matrix_sdk::ruma::{OwnedDeviceId, OwnedUserId};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::VerifyArgs;
use crate::commands::verify_handover::{
    Ack, Decision, EmojiItem, Pending, TAKEN_STALE, TAKEN_WAIT, Taken, await_taken, hand_over,
    handover_dir, sweep,
};
use crate::commands::{confirm_fresh_on, discard_typeahead_stdin, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term_id};

const MATCH_QUESTION: &str = "Do they match exactly?";

/// A line on stderr. A failed write (a closed stderr) is ignored instead of
/// panicking: the flow must still reach its cancel and its cleanup.
macro_rules! note {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

/// The emoji (or numbers) to compare, as shown before the question.
fn comparison_text(emojis: Option<&[Emoji]>, decimals: (u16, u16, u16)) -> String {
    let mut text = String::from("\n");
    match emojis {
        Some(emojis) => {
            text.push_str("Compare these emoji with the other device:\n");
            for emoji in emojis {
                text.push_str(&format!(
                    "  {}  {}\n",
                    term_id(emoji.symbol),
                    term_id(emoji.description)
                ));
            }
        }
        None => text.push_str(&format!(
            "Compare these numbers: {} {} {}\n",
            decimals.0, decimals.1, decimals.2
        )),
    }
    text.push('\n');
    text
}

/// The emoji confirmation: a person at a terminal, answering after the emoji
/// appeared (input typed earlier is discarded). The emoji and the question go
/// to stderr, the same stream, so a redirected stdout cannot hide the emoji
/// while the question still asks about them.
fn confirm_emoji(comparison: &str) -> Result<bool> {
    let stdin = std::io::stdin();
    let is_terminal = stdin.is_terminal();
    confirm_emoji_on(
        comparison,
        is_terminal,
        &mut stdin.lock(),
        &mut std::io::stderr(),
        discard_typeahead_stdin,
    )
}

fn confirm_emoji_on(
    comparison: &str,
    is_terminal: bool,
    input: &mut dyn std::io::BufRead,
    output: &mut dyn std::io::Write,
    discard_typeahead: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    output
        .write_all(comparison.as_bytes())
        .context("cannot show the emoji")?;
    confirm_fresh_on(
        MATCH_QUESTION,
        is_terminal,
        input,
        output,
        discard_typeahead,
    )
}

/// How long a listener waits for the requesting device to start SAS before
/// starting it itself.
const OTHER_SIDE_START_GRACE: Duration = Duration::from_secs(5);
/// Sync time after success, so cross-signing updates and secrets arrive.
const SETTLE_TIME: Duration = Duration::from_secs(5);
/// How long the cancellation after a timeout may take.
const CANCEL_LIMIT: Duration = Duration::from_secs(10);

/// How often a waiting verification looks for a handed-over decision.
const DECISION_POLL: Duration = Duration::from_millis(250);
/// How often --confirm / --cancel look for the waiting process's answer
/// (they wait for it up to `TAKEN_WAIT`).
const TAKEN_POLL: Duration = Duration::from_millis(100);

/// Run a best-effort step for at most `limit`: a responsive server still
/// gets it, a stalled one cannot keep the command from ending. `None` when
/// the time ran out.
async fn best_effort<F: Future>(step: F, limit: Duration) -> Option<F::Output> {
    tokio::time::timeout(limit, step).await.ok()
}

/// Who confirms the emoji.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirmer {
    /// A person at the terminal (stdin and stderr are terminals).
    Person,
    /// An agent: the decision comes from `verify --confirm` / `--cancel`.
    Agent,
}

const NEEDS_TERMINAL: &str = "verify needs a terminal on stdin and stderr: the emoji comparison must be seen and confirmed by a person; no verification was started";

/// The hand-over only when asked for (`--hand-over`), with or without a
/// terminal. Otherwise the prompt, whose answer comes from stdin and whose
/// emoji and question go to stderr: both must be a terminal, or verify
/// refuses as before; it never falls back to the hand-over on its own.
fn confirmer(
    hand_over: bool,
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
) -> Result<Confirmer> {
    if hand_over {
        Ok(Confirmer::Agent)
    } else if stdin_is_terminal && stderr_is_terminal {
        Ok(Confirmer::Person)
    } else {
        bail!(
            "{NEEDS_TERMINAL}. An agent that has the person compare the emoji passes --hand-over."
        )
    }
}

/// How the waiting process gets the answer.
enum Answer {
    Prompt,
    HandOver { dir: PathBuf, timeout: u64 },
}

impl Answer {
    /// The result lines: stdout at a terminal, as before; stderr for an
    /// agent, whose stdout carries only the emoji line.
    fn report(&self, line: &str) {
        match self {
            Answer::Prompt => println!("{line}"),
            Answer::HandOver { .. } => note!("{line}"),
        }
    }
}

/// `verify --confirm` / `--cancel`: hand the decision to the comparison with
/// `token` and report what the waiting process did with it. Takes neither the
/// data-directory lock (the waiting process holds it) nor the store.
fn decide(token: &str, decision: Decision) -> Result<()> {
    let paths = Paths::from_env()?;
    let target = hand_over(&handover_dir(&paths.data_dir), token, decision)?;
    let taken = await_taken(&target, TAKEN_WAIT, TAKEN_POLL)?;
    let line = taken_report(
        decision,
        taken,
        &target.comparison.transaction_id,
        &target.comparison.other_device,
        target.pid,
    )?;
    note!("{line}");
    Ok(())
}

/// What the waiting process did with the decision this process handed over.
fn taken_report(
    sent: Decision,
    taken: Option<Ack>,
    transaction_id: &str,
    other_device: &str,
    pid: u32,
) -> Result<String> {
    let name = |decision: Decision| match decision {
        Decision::Confirm => "the confirmation",
        Decision::Cancel => "the cancellation",
    };
    let which = format!(
        "verification {} with device {} (process {pid})",
        term_id(transaction_id),
        term_id(other_device)
    );
    let kind = |taken: Taken| match taken {
        Taken::Confirm => "a confirmation",
        Taken::Cancel => "a cancellation",
        Taken::Ignored => "an ignored decision",
    };
    match (sent, taken) {
        (Decision::Confirm, Some(Ack::Mine(Taken::Confirm))) => Ok(format!(
            "The {which} took the confirmation; it confirms the emoji and reports the result."
        )),
        (Decision::Cancel, Some(Ack::Mine(Taken::Cancel))) => Ok(format!(
            "The {which} took the cancellation; it cancels and reports the result."
        )),
        (Decision::Cancel, Some(Ack::Mine(Taken::Confirm))) => {
            bail!("the {which} acted on a confirmation, not on this cancellation")
        }
        (Decision::Confirm, Some(Ack::Mine(Taken::Cancel))) => {
            bail!("the {which} acted on a cancellation, not on this confirmation")
        }
        (_, Some(Ack::Other(taken))) => bail!(
            "the {which} handled another decision for this token ({}); {} was not acknowledged within {} s",
            kind(taken),
            name(sent),
            TAKEN_WAIT.as_secs()
        ),
        (_, Some(Ack::Mine(Taken::Ignored))) => bail!(
            "the {which} ignored {}: it did not name its transaction",
            name(sent)
        ),
        (_, None) => bail!(
            "the {which} did not acknowledge {} within {} s; it may still act on it",
            name(sent),
            TAKEN_WAIT.as_secs()
        ),
    }
}

/// The emoji in the hand-over's form.
fn emoji_items(emojis: &[Emoji]) -> Vec<EmojiItem> {
    emojis
        .iter()
        .map(|e| EmojiItem {
            symbol: e.symbol.to_owned(),
            description: e.description.to_owned(),
        })
        .collect()
}

/// Write the emoji line; an error (a closed stdout) is returned, never a
/// panic, so the caller can cancel.
fn emit_line(out: &mut impl std::io::Write, line: &str) -> Result<()> {
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .context("cannot write the emoji line to stdout")
}

/// How to answer, on stderr, after the emoji line. `token` is this
/// process's own (digits, a dash, hex), safe on a command line as it is.
fn hand_over_instructions(token: &str, other_device: &str, timeout: u64) -> String {
    format!(
        "Compare the emoji on stdout with the ones device {} shows.\n\
         If the person confirms they match exactly, run:\n  matrix-e2ee-cli verify --confirm {token}\n\
         If they do not match, run:\n  matrix-e2ee-cli verify --cancel {token}\n\
         --confirm or --cancel exits 0 once this process took the decision; whether the \
         device ended up verified is reported here, on this process's stderr.\n\
         Waiting for the decision (the verification gives up {timeout} s after it started).\n",
        term_id(other_device)
    )
}

/// Whether the store holds the other device of `sas` as verified; an error
/// when the store could not be read. A device the store does not know is
/// not verified.
async fn stored_as_verified(client: &Client, sas: &SasVerification) -> Result<bool> {
    let device = sas.other_device();
    let stored = client
        .encryption()
        .get_device(device.user_id(), device.device_id())
        .await
        .context("cannot read the device from the store")?;
    Ok(stored.is_some_and(|stored| stored.is_verified()))
}

/// What the flow shares with the cleanup in `run()`, which runs after a
/// timeout or a signal dropped the flow.
#[derive(Default)]
struct FlowState {
    /// The verification request, once there is a handle for it.
    request: Mutex<Option<VerificationRequest>>,
    /// A request is being sent and its handle is not there yet: the SDK
    /// returns it only after the send succeeded.
    requesting: AtomicBool,
    /// The SAS, and whether the store held its device as verified when it
    /// began (`None`: that could not be read).
    sas: Mutex<Option<(SasVerification, Option<bool>)>>,
    /// This comparison called `sas.confirm()` (set before the call, so a
    /// confirmation interrupted while it is sent counts).
    confirmed: AtomicBool,
}

/// Why a device the store holds as verified is not counted as verified by
/// this comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotByThisFlow {
    /// Nobody confirmed this comparison.
    NobodyConfirmed,
    /// The device was verified already when the comparison began.
    VerifiedBefore,
    /// The state before the comparison could not be read.
    BeforeUnknown,
    /// The comparison was cancelled.
    SasCancelled,
}

/// What a failed, timed-out or interrupted flow may say about the trust of
/// the other device.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustAfterFailure {
    /// No comparison began.
    NoComparison,
    /// Not verified in the store.
    NotVerified,
    /// This comparison confirmed, and the store went from not verified to
    /// verified: the only case nothing is cancelled.
    VerifiedByThisFlow,
    /// Verified in the store, but not attributable to this comparison.
    VerifiedNotByThisFlow(NotByThisFlow),
    /// The store could not be read after the flow.
    Unknown { confirmed: bool, error: String },
}

impl TrustAfterFailure {
    /// Whether the unfinished request is to be cancelled.
    fn needs_cancel(&self) -> bool {
        !matches!(self, TrustAfterFailure::VerifiedByThisFlow)
    }
}

/// Classify the trust of the other device after a failed flow. `before` is
/// the store's answer when the comparison began (`None`: unreadable), `now`
/// its answer after the flow, `confirmed` whether this comparison called
/// `sas.confirm()`.
fn trust_after_failure(
    before: Option<bool>,
    now: std::result::Result<bool, String>,
    confirmed: bool,
    sas_cancelled: bool,
) -> TrustAfterFailure {
    match now {
        Err(error) => TrustAfterFailure::Unknown { confirmed, error },
        Ok(false) => TrustAfterFailure::NotVerified,
        Ok(true) if !confirmed => {
            TrustAfterFailure::VerifiedNotByThisFlow(NotByThisFlow::NobodyConfirmed)
        }
        Ok(true) => match before {
            None => TrustAfterFailure::VerifiedNotByThisFlow(NotByThisFlow::BeforeUnknown),
            Some(true) => TrustAfterFailure::VerifiedNotByThisFlow(NotByThisFlow::VerifiedBefore),
            Some(false) if sas_cancelled => {
                TrustAfterFailure::VerifiedNotByThisFlow(NotByThisFlow::SasCancelled)
            }
            Some(false) => TrustAfterFailure::VerifiedByThisFlow,
        },
    }
}

/// What the cancellation of the request after a failed flow achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CancelOutcome {
    /// The cancellation was sent.
    Sent,
    /// There was no unfinished request to cancel.
    NothingToCancel,
    /// Cancelled here; sending the cancellation failed.
    Failed(String),
    /// Cancelled here; sending the cancellation did not end in time.
    TimedOut,
    /// The request was still being sent when the flow stopped: there is no
    /// handle to cancel it with.
    RequestInFlight,
}

/// The outcome when there is no request handle to cancel.
fn without_request(requesting: bool) -> CancelOutcome {
    if requesting {
        CancelOutcome::RequestInFlight
    } else {
        CancelOutcome::NothingToCancel
    }
}

/// The context for the error of a failed flow: what was cancelled, and what
/// this comparison did to the trust of `device`.
fn failure_context(trust: &TrustAfterFailure, cancel: &CancelOutcome, device: &str) -> String {
    let device = term_id(device);
    let trust = match trust {
        TrustAfterFailure::VerifiedByThisFlow => {
            return format!(
                "device {device} is verified locally; the confirmation may not have reached it"
            );
        }
        TrustAfterFailure::NoComparison | TrustAfterFailure::NotVerified => {
            "nothing was trusted".to_owned()
        }
        TrustAfterFailure::VerifiedNotByThisFlow(why) => {
            let why = match why {
                NotByThisFlow::NobodyConfirmed => "nobody confirmed this comparison",
                NotByThisFlow::VerifiedBefore => "it was verified before this comparison began",
                NotByThisFlow::BeforeUnknown => {
                    "its state before this comparison could not be read"
                }
                NotByThisFlow::SasCancelled => "this comparison was cancelled",
            };
            format!(
                "device {device} is verified locally, but that is not counted as this comparison's doing: {why}"
            )
        }
        TrustAfterFailure::Unknown {
            confirmed: false,
            error,
        } => format!(
            "this comparison trusted nothing; whether device {device} is verified locally could not be determined: {}",
            term_id(error)
        ),
        TrustAfterFailure::Unknown {
            confirmed: true,
            error,
        } => format!(
            "whether device {device} is verified locally could not be determined: {}",
            term_id(error)
        ),
    };
    match cancel {
        CancelOutcome::Sent => format!("verification cancelled; {trust}"),
        CancelOutcome::NothingToCancel => trust,
        CancelOutcome::Failed(error) => format!(
            "{trust}; cancelled here; the other device may not have been notified: {}",
            term_id(error)
        ),
        CancelOutcome::TimedOut => format!(
            "{trust}; cancelled here; the other device may not have been notified: the cancellation was not sent within {} s",
            CANCEL_LIMIT.as_secs()
        ),
        CancelOutcome::RequestInFlight => format!(
            "{trust}; the verification request was still being sent: its cancellation could not be confirmed, and the other device may still show the request"
        ),
    }
}

/// How a `sas.cancel()` in the flow ended, as the start of its error.
fn cancel_context(sent: &std::result::Result<(), String>) -> String {
    match sent {
        Ok(()) => "verification cancelled".to_owned(),
        Err(error) => format!(
            "cancelled here; the other device may not have been notified: {}",
            term_id(error)
        ),
    }
}

/// Cancel `sas` and describe the outcome (see [`cancel_context`]).
async fn cancel_sas(sas: &SasVerification) -> String {
    cancel_context(&sas.cancel().await.map_err(|err| err.to_string()))
}

/// What ended the verification flow.
#[derive(Debug)]
enum Stop<T> {
    Finished(T),
    TimedOut,
    Interrupted(&'static str),
}

/// Run `flow` until it finishes, `limit` passes or `stop` resolves; the
/// flow is dropped in the last two cases (its hand-over files go with it).
async fn run_until_stopped<F: Future>(
    flow: F,
    limit: Duration,
    stop: impl Future<Output = &'static str>,
) -> Stop<F::Output> {
    tokio::select! {
        biased;
        signal = stop => Stop::Interrupted(signal),
        result = tokio::time::timeout(limit, flow) => match result {
            Ok(output) => Stop::Finished(output),
            Err(_) => Stop::TimedOut,
        },
    }
}

/// SIGINT or SIGTERM (Ctrl-C on Windows); never resolves when the handlers
/// cannot be installed.
async fn termination_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut interrupt), Ok(mut terminate), Ok(mut hangup), Ok(mut quit)) = (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
            signal(SignalKind::quit()),
        ) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = interrupt.recv() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
            _ = hangup.recv() => "SIGHUP",
            _ = quit.recv() => "SIGQUIT",
        }
    }
    #[cfg(not(unix))]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "Ctrl-C",
            Err(_) => std::future::pending().await,
        }
    }
}

/// Wait until a decision for `pending` was handed over; true for confirm.
async fn wait_for_decision(pending: &Pending) -> Result<bool> {
    loop {
        if let Some(decision) = pending.poll()? {
            return Ok(decision == Decision::Confirm);
        }
        tokio::time::sleep(DECISION_POLL).await;
    }
}

#[derive(Debug, Serialize)]
struct DeviceRow {
    device_id: String,
    display_name: Option<String>,
    verified: bool,
    is_current: bool,
}

/// `verify --list`: the lines to print, as matrix-e2ee-verify.py `--list`
/// with a verified column, or one JSON object per device.
fn device_lines(rows: &[DeviceRow], json: bool) -> Result<Vec<String>> {
    if json {
        return rows
            .iter()
            .map(|row| json_line(row).map_err(Into::into))
            .collect();
    }
    let mut lines = vec!["Your devices:".to_owned()];
    for row in rows {
        lines.push(format!(
            "  {}: {} [{}]{}",
            term_id(&row.device_id),
            term_id(row.display_name.as_deref().unwrap_or("No name")),
            if row.verified {
                "verified"
            } else {
                "not verified"
            },
            if row.is_current {
                " ← this device"
            } else {
                ""
            }
        ));
    }
    Ok(lines)
}

async fn list_devices(json: bool) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    let client = restore(&config, &paths, KeySharing::VerifiedOnly)
        .await?
        .client;
    let own_user = client
        .user_id()
        .context("no user id after restore")?
        .to_owned();
    // Device keys, and with them the verification state, arrive with a sync.
    sync_once(&client).await?;
    client
        .encryption()
        .wait_for_e2ee_initialization_tasks()
        .await;
    let devices = client
        .devices()
        .await
        .context("cannot list the devices")?
        .devices;
    let mut rows = Vec::new();
    for device in devices {
        let verified = client
            .encryption()
            .get_device(&own_user, &device.device_id)
            .await?
            .is_some_and(|d| d.is_verified());
        rows.push(DeviceRow {
            is_current: client.device_id() == Some(&*device.device_id),
            device_id: device.device_id.to_string(),
            display_name: device.display_name,
            verified,
        });
    }
    if rows.is_empty() {
        bail!("the server lists no devices for {own_user}");
    }
    for line in device_lines(&rows, json)? {
        println!("{line}");
    }
    Ok(())
}

pub async fn run(args: VerifyArgs) -> Result<()> {
    if let Some(token) = &args.confirm {
        return decide(token, Decision::Confirm);
    }
    if let Some(token) = &args.cancel {
        return decide(token, Decision::Cancel);
    }
    if args.list {
        return list_devices(args.json).await;
    }
    let who = confirmer(
        args.hand_over,
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    )?;
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    let answer = match who {
        Confirmer::Person => Answer::Prompt,
        Confirmer::Agent => {
            let dir = handover_dir(&paths.data_dir);
            // This process holds the lock: no other one waits, so whatever
            // is in the directory was left by a process that ended.
            sweep(&dir, TAKEN_STALE)?;
            Answer::HandOver {
                dir,
                timeout: args.timeout,
            }
        }
    };
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    let own_user: OwnedUserId = client
        .user_id()
        .context("no user id after restore")?
        .to_owned();

    // Register before the first sync, so no request is missed.
    let (tx, mut rx) = mpsc::unbounded_channel::<(OwnedUserId, String)>();
    if args.listen {
        let own = own_user.clone();
        client.add_event_handler(move |ev: ToDeviceKeyVerificationRequestEvent| {
            let tx = tx.clone();
            let own = own.clone();
            async move {
                if ev.sender != own {
                    note!(
                        "Ignoring a verification request from {}: only devices of {} are verified here.",
                        term_id(ev.sender.as_str()),
                        term_id(own.as_str())
                    );
                    return;
                }
                let _ = tx.send((ev.sender, ev.content.transaction_id.to_string()));
            }
        });
    }

    sync_once(&client).await?;
    client
        .encryption()
        .wait_for_e2ee_initialization_tasks()
        .await;

    let sync_client = client.clone();
    let sync_task = tokio::spawn(async move {
        let settings = SyncSettings::default().timeout(Duration::from_secs(5));
        if let Err(err) = sync_client.sync(settings).await {
            note!("sync stopped: {}", term_id(&err.to_string()));
        }
    });

    let state = FlowState::default();
    let flow = flow(&client, &own_user, &args, &mut rx, &state, &answer);
    // Without a person at the terminal, SIGINT and SIGTERM take the
    // timeout's path: cancel, remove the hand-over files, trust nothing.
    let stop = async {
        match &answer {
            Answer::HandOver { .. } => termination_signal().await,
            Answer::Prompt => std::future::pending().await,
        }
    };
    let agent = matches!(answer, Answer::HandOver { .. });
    let (outcome, stopped) =
        match run_until_stopped(flow, Duration::from_secs(args.timeout), stop).await {
            Stop::Finished(result) => (result, false),
            Stop::Interrupted(signal) => (
                Err(anyhow::anyhow!("verification interrupted by {signal}")),
                true,
            ),
            Stop::TimedOut => (
                Err(anyhow::anyhow!(
                    "verification timed out after {} s",
                    args.timeout
                )),
                true,
            ),
        };
    // A timeout, a signal or (without a person) any error can come after
    // confirm() stored the trust: ask the store before cancelling, so a
    // verified device is never reported as "nothing was trusted".
    let outcome = match outcome {
        Ok(()) => Ok(()),
        Err(err) if stopped || agent => {
            let sas = state.sas.lock().ok().and_then(|slot| slot.clone());
            let (trust, device) = match &sas {
                Some((sas, before)) => {
                    let now = stored_as_verified(&client, sas)
                        .await
                        .map_err(|err| format!("{err:#}"));
                    (
                        trust_after_failure(
                            *before,
                            now,
                            state.confirmed.load(Ordering::SeqCst),
                            sas.is_cancelled(),
                        ),
                        sas.other_device().device_id().to_string(),
                    )
                }
                None => (TrustAfterFailure::NoComparison, String::new()),
            };
            let cancel = if trust.needs_cancel() {
                let request = state.request.lock().ok().and_then(|slot| slot.clone());
                match request {
                    Some(request) if !request.is_done() && !request.is_cancelled() => {
                        match best_effort(request.cancel(), CANCEL_LIMIT).await {
                            Some(Ok(())) => CancelOutcome::Sent,
                            Some(Err(err)) => CancelOutcome::Failed(err.to_string()),
                            None => CancelOutcome::TimedOut,
                        }
                    }
                    Some(_) => CancelOutcome::NothingToCancel,
                    None => without_request(state.requesting.load(Ordering::SeqCst)),
                }
            } else {
                CancelOutcome::NothingToCancel
            };
            Err(err.context(failure_context(&trust, &cancel, &device)))
        }
        Err(err) => Err(err),
    };

    if outcome.is_ok() {
        tokio::time::sleep(SETTLE_TIME).await;
    }
    sync_task.abort();
    outcome?;
    print_final_state(&client, &answer).await
}

async fn flow(
    client: &Client,
    own_user: &OwnedUserId,
    args: &VerifyArgs,
    rx: &mut mpsc::UnboundedReceiver<(OwnedUserId, String)>,
    state: &FlowState,
    answer: &Answer,
) -> Result<()> {
    let encryption = client.encryption();
    let request = if let Some(device_id) = &args.request {
        let device_id: OwnedDeviceId = device_id.as_str().into();
        if client.device_id() == Some(&*device_id) {
            bail!("{device_id} is this device; name one of your other devices");
        }
        let Some(device) = encryption.get_device(own_user, &device_id).await? else {
            let known = encryption
                .get_user_devices(own_user)
                .await?
                .devices()
                .filter(|d| Some(d.device_id()) != client.device_id())
                .map(|d| {
                    format!(
                        "{}{}",
                        term_id(d.device_id().as_str()),
                        d.display_name()
                            .map(|n| format!(" ({})", term_id(n)))
                            .unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>();
            bail!(
                "device {device_id} of {own_user} is not known here; known devices: {}",
                if known.is_empty() {
                    "none".to_owned()
                } else {
                    known.join(", ")
                }
            );
        };
        note!(
            "Requesting verification with {}; accept it on that device.",
            term_id(device_id.as_str())
        );
        // Until the send succeeded there is no handle; a timeout or a
        // signal meanwhile cannot cancel, and must not claim it did.
        state.requesting.store(true, Ordering::SeqCst);
        let sent = device.request_verification().await;
        if let (Ok(request), Ok(mut slot)) = (&sent, state.request.lock()) {
            *slot = Some(request.clone());
        }
        state.requesting.store(false, Ordering::SeqCst);
        sent.context("cannot send the verification request")?
    } else {
        note!("Waiting for a verification request from one of your devices...");
        let request = loop {
            let (sender, flow_id) = rx.recv().await.context("the request listener stopped")?;
            match encryption.get_verification_request(&sender, &flow_id).await {
                Some(request) if !request.is_cancelled() && !request.is_done() => break request,
                // A stale request (e.g. replayed by the first sync): keep waiting.
                _ => continue,
            }
        };
        note!("Verification request received; accepting.");
        // Register before accepting: accept() marks the request ready before
        // its send completes, so a timeout during the send must cancel it too.
        if let Ok(mut slot) = state.request.lock() {
            *slot = Some(request.clone());
        }
        request
            .accept()
            .await
            .context("cannot accept the verification request")?;
        request
    };
    if let Ok(mut slot) = state.request.lock() {
        *slot = Some(request.clone());
    }

    let sas = wait_for_sas(&request).await?;
    // Before any confirm: only a change from here counts as this flow's.
    // Unreadable, it stays unknown, and no change is attributed to the flow.
    let verified_before = stored_as_verified(client, &sas).await.ok();
    if let Ok(mut slot) = state.sas.lock() {
        *slot = Some((sas.clone(), verified_before));
    }
    run_sas(&sas, request.flow_id(), answer, &state.confirmed).await
}

/// Drive the request until it turns into a SAS verification.
async fn wait_for_sas(request: &VerificationRequest) -> Result<SasVerification> {
    let mut changes = request.changes();
    // Read the state first: a transition before `changes()` is not replayed.
    let mut state = request.state();
    loop {
        match state {
            VerificationRequestState::Ready { .. } => {
                if !request.we_started() {
                    // Usually the requesting device starts SAS; give it a moment.
                    if let Ok(Some(next)) =
                        tokio::time::timeout(OTHER_SIDE_START_GRACE, changes.next()).await
                    {
                        state = next;
                        continue;
                    }
                }
                if let VerificationRequestState::Transitioned { verification, .. } = request.state()
                {
                    return into_sas(verification);
                }
                return request
                    .start_sas()
                    .await
                    .context("cannot start emoji verification")?
                    .context("the other device does not support emoji verification");
            }
            VerificationRequestState::Transitioned { verification, .. } => {
                return into_sas(verification);
            }
            VerificationRequestState::Done => {
                bail!("the request finished without an emoji verification")
            }
            VerificationRequestState::Cancelled(info) => {
                bail!(
                    "verification cancelled: {} ({})",
                    info.reason(),
                    info.cancel_code()
                )
            }
            VerificationRequestState::Created { .. }
            | VerificationRequestState::Requested { .. } => {}
        }
        state = changes
            .next()
            .await
            .context("the verification request stream ended")?;
    }
}

fn cancelled(info: &CancelInfo) -> anyhow::Error {
    anyhow::anyhow!(
        "verification cancelled: {} ({})",
        info.reason(),
        info.cancel_code()
    )
}

/// What ended the wait for the person's answer.
#[derive(Debug)]
enum PromptOutcome {
    /// The prompt returned: the answer, or why there is none.
    Answered(Result<bool>),
    /// The verification ended first (e.g. the other device cancelled); a
    /// later answer must not be acted on.
    Ended(anyhow::Error),
}

/// Wait for `prompt` while watching `changes`: when `ends` turns a state
/// into an error, or the stream ends, stop at once with that error.
async fn answer_unless_ended<T>(
    prompt: impl Future<Output = Result<bool>>,
    changes: &mut (impl Stream<Item = T> + Unpin),
    ends: impl Fn(&T) -> Option<anyhow::Error>,
) -> PromptOutcome {
    tokio::pin!(prompt);
    loop {
        tokio::select! {
            biased;
            state = changes.next() => match state {
                Some(state) => {
                    if let Some(err) = ends(&state) {
                        return PromptOutcome::Ended(err);
                    }
                }
                None => {
                    return PromptOutcome::Ended(anyhow::anyhow!("the verification stream ended"));
                }
            },
            answer = &mut prompt => return PromptOutcome::Answered(answer),
        }
    }
}

fn into_sas(verification: Verification) -> Result<SasVerification> {
    match verification {
        Verification::SasV1(sas) => Ok(sas),
        #[allow(unreachable_patterns)]
        _ => bail!("the other device chose a method other than emoji verification"),
    }
}

async fn run_sas(
    sas: &SasVerification,
    flow_id: &str,
    how: &Answer,
    confirmed: &AtomicBool,
) -> Result<()> {
    let mut changes = sas.changes();
    let mut state = sas.state();
    if matches!(state, SasState::Started { .. }) && !sas.we_started() {
        sas.accept()
            .await
            .context("cannot accept the emoji verification")?;
    }
    let mut asked = false;
    // The agent's emoji and decision files; removed when this ends, also
    // when a timeout drops this future.
    let mut _published: Option<Pending> = None;
    loop {
        match &state {
            SasState::KeysExchanged { emojis, decimals } if !asked => {
                asked = true;
                let ends = |state: &SasState| match state {
                    SasState::Cancelled(info) => Some(cancelled(info)),
                    _ => None,
                };
                let outcome = match how {
                    Answer::Prompt => {
                        let comparison = comparison_text(
                            emojis.as_ref().map(|short| &short.emojis[..]),
                            *decimals,
                        );
                        // The prompt blocks on stdin, so it runs on its own thread; a
                        // prompt abandoned here ends with the process.
                        let prompt = async {
                            tokio::task::spawn_blocking(move || confirm_emoji(&comparison))
                                .await
                                .unwrap_or_else(|err| {
                                    Err(anyhow::Error::new(err).context("the prompt failed"))
                                })
                        };
                        answer_unless_ended(prompt, &mut changes, ends).await
                    }
                    Answer::HandOver { dir, timeout } => {
                        let Some(emojis) = emojis else {
                            bail!(
                                "the other device offers numbers only, no emoji; {}",
                                cancel_sas(sas).await
                            );
                        };
                        let other = sas.other_device().device_id().as_str();
                        let pending = match Pending::publish(
                            dir,
                            flow_id,
                            other,
                            emoji_items(&emojis.emojis),
                        ) {
                            Ok(pending) => _published.insert(pending),
                            Err(err) => {
                                return Err(err.context(cancel_sas(sas).await));
                            }
                        };
                        if let Err(err) = emit_line(&mut std::io::stdout(), pending.line()) {
                            return Err(err.context(cancel_sas(sas).await));
                        }
                        {
                            use std::io::Write as _;
                            let _ = write!(
                                std::io::stderr(),
                                "{}",
                                hand_over_instructions(pending.token(), other, *timeout)
                            );
                        }
                        answer_unless_ended(wait_for_decision(pending), &mut changes, ends).await
                    }
                };
                let answer = match outcome {
                    PromptOutcome::Ended(err) => return Err(err),
                    PromptOutcome::Answered(Ok(answer)) => answer,
                    PromptOutcome::Answered(Err(err)) => {
                        return Err(err.context(cancel_sas(sas).await));
                    }
                };
                // A cancellation that arrived together with the answer.
                if let Some(info) = sas.cancel_info() {
                    return Err(cancelled(&info));
                }
                match (answer, how) {
                    (true, Answer::Prompt) => {
                        confirmed.store(true, Ordering::SeqCst);
                        sas.confirm()
                            .await
                            .context("cannot send the confirmation")?;
                        note!("Confirmed; waiting for the other device.");
                    }
                    (true, Answer::HandOver { .. }) => {
                        // On an error, run() looks up whether the device is
                        // stored as verified before it cancels anything.
                        confirmed.store(true, Ordering::SeqCst);
                        sas.confirm()
                            .await
                            .context("cannot send the confirmation")?;
                        note!("Confirmed; waiting for the other device.");
                    }
                    (false, Answer::Prompt) => {
                        sas.mismatch().await.ok();
                        bail!("the emoji do not match; verification cancelled");
                    }
                    (false, Answer::HandOver { .. }) => match sas.cancel().await {
                        Ok(()) => bail!("the person cancelled with verify --cancel"),
                        Err(err) => bail!(
                            "the person cancelled with verify --cancel; {}",
                            cancel_context(&Err(err.to_string()))
                        ),
                    },
                }
            }
            SasState::Done { .. } => {
                how.report(&format!(
                    "Verification done: device {} is verified.",
                    term_id(sas.other_device().device_id().as_str())
                ));
                return Ok(());
            }
            SasState::Cancelled(info) => return Err(cancelled(info)),
            _ => {}
        }
        state = changes
            .next()
            .await
            .context("the verification stream ended")?;
    }
}

async fn print_final_state(client: &Client, how: &Answer) -> Result<()> {
    let own = client.encryption().get_own_device().await?;
    let yn = |b: bool| if b { "yes" } else { "no" };
    how.report(&format!(
        "This device: cross-signed {}, verified {}",
        yn(own.as_ref().is_some_and(|d| d.is_cross_signed_by_owner())),
        yn(own.as_ref().is_some_and(|d| d.is_verified()))
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Fails the test instead of hanging when a wait is not bounded.
    async fn within_5s<F: Future>(what: &str, fut: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .unwrap_or_else(|_| panic!("{what}"))
    }

    #[tokio::test]
    async fn cancellation_after_the_timeout_is_bounded() {
        within_5s(
            "the cancellation was awaited without a limit",
            best_effort(std::future::pending::<()>(), Duration::from_millis(50)),
        )
        .await;
    }

    fn ends_on_2(state: &i32) -> Option<anyhow::Error> {
        (*state == 2).then(|| anyhow::anyhow!("cancelled by the other device"))
    }

    #[tokio::test]
    async fn peer_cancellation_ends_the_wait_for_the_answer() {
        let mut changes = futures_util::stream::iter([1, 2]).chain(futures_util::stream::pending());
        let outcome = within_5s(
            "the wait for the answer ignored the cancellation",
            answer_unless_ended(
                std::future::pending::<Result<bool>>(),
                &mut changes,
                ends_on_2,
            ),
        )
        .await;
        match outcome {
            PromptOutcome::Ended(err) => {
                assert!(err.to_string().contains("other device"), "{err}")
            }
            other => panic!("expected Ended, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn answer_counts_when_no_cancellation_comes() {
        let mut changes = futures_util::stream::iter([1]).chain(futures_util::stream::pending());
        let outcome = within_5s(
            "the answer was not taken",
            answer_unless_ended(async { Ok(true) }, &mut changes, ends_on_2),
        )
        .await;
        assert!(
            matches!(outcome, PromptOutcome::Answered(Ok(true))),
            "{outcome:?}"
        );
        let mut ended = futures_util::stream::empty::<i32>();
        let outcome = within_5s(
            "the end of the stream was ignored",
            answer_unless_ended(
                std::future::pending::<Result<bool>>(),
                &mut ended,
                ends_on_2,
            ),
        )
        .await;
        assert!(matches!(outcome, PromptOutcome::Ended(_)), "{outcome:?}");
    }

    #[test]
    fn the_hand_over_is_opt_in() {
        // Without --hand-over: the prompt at a terminal, else refused.
        assert_eq!(confirmer(false, true, true).unwrap(), Confirmer::Person);
        for (stdin, stderr) in [(false, true), (true, false), (false, false)] {
            let err = confirmer(false, stdin, stderr).unwrap_err().to_string();
            assert!(err.starts_with(NEEDS_TERMINAL), "{err}");
            assert!(err.contains("--hand-over"), "{err}");
        }
        // --hand-over: the hand-over, with and without a terminal.
        for (stdin, stderr) in [(true, true), (false, true), (true, false), (false, false)] {
            assert_eq!(
                confirmer(true, stdin, stderr).unwrap(),
                Confirmer::Agent,
                "{stdin} {stderr}"
            );
        }
    }

    #[test]
    fn emoji_line_has_the_documented_keys() {
        let emojis = [
            Emoji {
                symbol: "🐶",
                description: "Dog",
            },
            Emoji {
                symbol: "\u{1b}[2J",
                description: "Cat",
            },
        ];
        let tmp = tempfile::tempdir().unwrap();
        let pending = Pending::publish(tmp.path(), "tx1", "PHONE", emoji_items(&emojis)).unwrap();
        let token = pending.token();
        assert_eq!(
            pending.line(),
            format!(
                r#"{{"transaction_id":"tx1","other_device":"PHONE","emojis":[{{"symbol":"🐶","description":"Dog"}},{{"symbol":"\u001b[2J","description":"Cat"}}],"token":"{token}"}}"#
            )
        );
        let text = hand_over_instructions(token, "PH\u{1b}\u{202E}ONE", 180);
        assert!(
            text.contains(&format!("verify --confirm {token}\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!("verify --cancel {token}\n")),
            "{text}"
        );
        assert!(
            text.contains("device PH\u{FFFD}\u{FFFD}ONE shows"),
            "{text}"
        );
        assert!(
            text.contains(
                "exits 0 once this process took the decision; whether the device ended up verified is reported here, on this process's stderr."
            ),
            "{text}"
        );
    }

    #[test]
    fn a_closed_stdout_is_an_error_not_a_panic() {
        struct Closed;
        impl std::io::Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        assert!(emit_line(&mut Closed, "{}").is_err());
        let mut out = Vec::new();
        emit_line(&mut out, "{\"a\":1}").unwrap();
        assert_eq!(out, b"{\"a\":1}\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sighup_and_sigquit_end_the_wait() {
        use tokio::signal::unix::{SignalKind, signal};
        // Handlers of the test's own first, so a signal that arrives before
        // termination_signal() listens cannot end the test process.
        let _hangup = signal(SignalKind::hangup()).unwrap();
        let _quit = signal(SignalKind::quit()).unwrap();
        for (number, name) in [(libc::SIGHUP, "SIGHUP"), (libc::SIGQUIT, "SIGQUIT")] {
            let waiting = tokio::spawn(termination_signal());
            tokio::time::sleep(Duration::from_millis(100)).await;
            // SAFETY: raise only sends a signal to this process, whose
            // handler for it is installed above.
            assert_eq!(unsafe { libc::raise(number) }, 0);
            let got = within_5s("the signal did not end the wait", waiting).await;
            assert_eq!(got.unwrap(), name);
        }
    }

    #[tokio::test]
    async fn a_signal_stops_the_flow_like_a_timeout() {
        let stopped = within_5s(
            "the signal did not stop the flow",
            run_until_stopped(
                std::future::pending::<()>(),
                Duration::from_secs(60),
                async { "SIGTERM" },
            ),
        )
        .await;
        assert!(
            matches!(stopped, Stop::Interrupted("SIGTERM")),
            "{stopped:?}"
        );
        let timed_out = within_5s(
            "the timeout did not stop the flow",
            run_until_stopped(
                std::future::pending::<()>(),
                Duration::from_millis(20),
                std::future::pending(),
            ),
        )
        .await;
        assert!(matches!(timed_out, Stop::TimedOut), "{timed_out:?}");
        let finished =
            run_until_stopped(async { 7 }, Duration::from_secs(60), std::future::pending()).await;
        assert!(matches!(finished, Stop::Finished(7)), "{finished:?}");
    }

    #[test]
    fn a_device_verified_before_the_flow_is_cancelled_after_a_timeout() {
        // Re-verifying a known device: verified before and after, then a
        // timeout. Not this flow's trust: cancel and say so.
        let trust = trust_after_failure(Some(true), Ok(true), true, false);
        assert_eq!(
            trust,
            TrustAfterFailure::VerifiedNotByThisFlow(NotByThisFlow::VerifiedBefore)
        );
        assert!(trust.needs_cancel(), "the request would not be cancelled");
        let msg = failure_context(&trust, &CancelOutcome::Sent, "PHONE");
        assert!(msg.starts_with("verification cancelled; "), "{msg}");
        assert!(
            msg.contains("verified before this comparison began"),
            "{msg}"
        );
        assert!(!msg.contains("confirmation may not have reached"), "{msg}");
        // Only a confirmed change to verified by a SAS that was not
        // cancelled counts.
        assert_eq!(
            trust_after_failure(Some(false), Ok(true), true, false),
            TrustAfterFailure::VerifiedByThisFlow
        );
        assert_eq!(
            trust_after_failure(Some(false), Ok(false), true, false),
            TrustAfterFailure::NotVerified
        );
        assert_eq!(
            trust_after_failure(Some(false), Ok(true), true, true),
            TrustAfterFailure::VerifiedNotByThisFlow(NotByThisFlow::SasCancelled)
        );
    }

    #[test]
    fn a_device_verified_in_the_store_is_reported_and_not_cancelled() {
        let trust = TrustAfterFailure::VerifiedByThisFlow;
        assert!(
            !trust.needs_cancel(),
            "a verified device would be cancelled"
        );
        let msg = failure_context(&trust, &CancelOutcome::NothingToCancel, "PH\u{202E}ONE");
        assert_eq!(
            msg,
            "device PH\u{FFFD}ONE is verified locally; the confirmation may not have reached it"
        );
        let trust = TrustAfterFailure::NoComparison;
        assert!(trust.needs_cancel());
        let msg = failure_context(&trust, &CancelOutcome::Sent, "");
        assert_eq!(msg, "verification cancelled; nothing was trusted");
    }

    #[test]
    fn a_failed_trust_lookup_is_never_reported_as_nothing_trusted() {
        // The lookup after the flow failed: unknown, not "nothing".
        for confirmed in [true, false] {
            let trust = trust_after_failure(
                Some(false),
                Err("store locked".to_owned()),
                confirmed,
                false,
            );
            assert_eq!(
                trust,
                TrustAfterFailure::Unknown {
                    confirmed,
                    error: "store locked".to_owned()
                }
            );
            assert!(trust.needs_cancel());
            let msg = failure_context(&trust, &CancelOutcome::Sent, "PHONE");
            assert!(!msg.contains("nothing was trusted"), "{msg}");
            assert!(
                msg.contains(
                    "whether device PHONE is verified locally could not be determined: store locked"
                ),
                "{msg}"
            );
        }
        // The baseline lookup failed: a change is never this flow's.
        let trust = trust_after_failure(None, Ok(true), true, false);
        assert_eq!(
            trust,
            TrustAfterFailure::VerifiedNotByThisFlow(NotByThisFlow::BeforeUnknown)
        );
        assert!(trust.needs_cancel());
        let msg = failure_context(&trust, &CancelOutcome::Sent, "PHONE");
        assert!(
            msg.contains("not counted as this comparison's doing"),
            "{msg}"
        );
        assert!(!msg.contains("confirmation may not have reached"), "{msg}");
        assert_eq!(
            trust_after_failure(None, Ok(false), true, false),
            TrustAfterFailure::NotVerified
        );
    }

    #[test]
    fn trust_that_arrived_without_a_confirmation_is_not_this_flows() {
        // Not verified when the comparison began, verified now (a cross-
        // signature arrived by sync), but nobody confirmed.
        let trust = trust_after_failure(Some(false), Ok(true), false, false);
        assert_eq!(
            trust,
            TrustAfterFailure::VerifiedNotByThisFlow(NotByThisFlow::NobodyConfirmed)
        );
        assert!(trust.needs_cancel(), "the unfinished request stays open");
        let msg = failure_context(&trust, &CancelOutcome::Sent, "PHONE");
        assert_eq!(
            msg,
            "verification cancelled; device PHONE is verified locally, but that is not counted as this comparison's doing: nobody confirmed this comparison"
        );
    }

    #[test]
    fn a_request_still_being_sent_is_not_reported_as_cancelled() {
        assert_eq!(without_request(true), CancelOutcome::RequestInFlight);
        assert_eq!(without_request(false), CancelOutcome::NothingToCancel);
        let msg = failure_context(
            &TrustAfterFailure::NoComparison,
            &CancelOutcome::RequestInFlight,
            "",
        );
        assert!(!msg.contains("verification cancelled"), "{msg}");
        assert!(msg.contains("could not be confirmed"), "{msg}");
        assert!(msg.contains("may still show the request"), "{msg}");
        assert_eq!(
            failure_context(
                &TrustAfterFailure::NoComparison,
                &CancelOutcome::NothingToCancel,
                ""
            ),
            "nothing was trusted"
        );
    }

    #[test]
    fn a_cancellation_that_was_not_sent_is_reported() {
        assert_eq!(cancel_context(&Ok(())), "verification cancelled");
        let failed = cancel_context(&Err("M_LIMIT_EXCEEDED".to_owned()));
        assert_eq!(
            failed,
            "cancelled here; the other device may not have been notified: M_LIMIT_EXCEEDED"
        );
        for cancel in [
            CancelOutcome::Failed("connection reset".to_owned()),
            CancelOutcome::TimedOut,
        ] {
            let msg = failure_context(&TrustAfterFailure::NotVerified, &cancel, "PHONE");
            assert!(!msg.contains("verification cancelled"), "{msg}");
            assert!(
                msg.starts_with(
                    "nothing was trusted; cancelled here; the other device may not have been notified: "
                ),
                "{msg}"
            );
        }
    }

    #[test]
    fn decide_reports_what_the_waiting_process_did() {
        use Decision::{Cancel, Confirm};
        let report = |sent, taken| taken_report(sent, taken, "tx1", "PHONE", 42);
        assert!(
            report(Confirm, Some(Ack::Mine(Taken::Confirm)))
                .unwrap()
                .contains("took the confirmation")
        );
        assert!(
            report(Cancel, Some(Ack::Mine(Taken::Cancel)))
                .unwrap()
                .contains("took the cancellation")
        );
        for (sent, taken) in [
            (Cancel, Some(Ack::Mine(Taken::Confirm))),
            (Confirm, Some(Ack::Mine(Taken::Cancel))),
            (Confirm, Some(Ack::Mine(Taken::Ignored))),
            (Cancel, Some(Ack::Other(Taken::Cancel))),
            (Confirm, Some(Ack::Other(Taken::Confirm))),
            (Cancel, None),
        ] {
            assert!(report(sent, taken).is_err(), "{sent:?} {taken:?}");
        }
        let late = report(Cancel, None).unwrap_err().to_string();
        assert!(late.contains("did not acknowledge"), "{late}");
        // Another decision's acknowledgement is never this one's.
        let other = report(Cancel, Some(Ack::Other(Taken::Confirm)))
            .unwrap_err()
            .to_string();
        assert!(
            other.contains("handled another decision for this token (a confirmation)"),
            "{other}"
        );
        assert!(
            other.contains("the cancellation was not acknowledged"),
            "{other}"
        );
    }

    #[tokio::test]
    async fn the_wait_ends_only_with_a_handed_over_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = Pending::publish(tmp.path(), "tx1", "PHONE", Vec::new()).unwrap();
        let undecided =
            tokio::time::timeout(Duration::from_millis(600), wait_for_decision(&pending)).await;
        assert!(
            undecided.is_err(),
            "decided without a hand-over: {undecided:?}"
        );
        hand_over(tmp.path(), pending.token(), Decision::Cancel).unwrap();
        let answer = within_5s("the cancel was not read", wait_for_decision(&pending)).await;
        assert!(!answer.unwrap());
        drop(pending);
        let pending = Pending::publish(tmp.path(), "tx1", "PHONE", Vec::new()).unwrap();
        hand_over(tmp.path(), pending.token(), Decision::Confirm).unwrap();
        let answer = within_5s("the confirm was not read", wait_for_decision(&pending)).await;
        assert!(answer.unwrap());
    }

    #[test]
    fn device_list_matches_matrix_e2ee_verify_py() {
        let rows = [
            DeviceRow {
                device_id: "ABC".to_owned(),
                display_name: Some("Element Desktop".to_owned()),
                verified: true,
                is_current: false,
            },
            DeviceRow {
                device_id: "RUST".to_owned(),
                display_name: None,
                verified: false,
                is_current: true,
            },
        ];
        assert_eq!(
            device_lines(&rows, false).unwrap(),
            vec![
                "Your devices:",
                "  ABC: Element Desktop [verified]",
                "  RUST: No name [not verified] ← this device",
            ]
        );
        assert_eq!(
            device_lines(&rows, true).unwrap(),
            vec![
                r#"{"device_id":"ABC","display_name":"Element Desktop","verified":true,"is_current":false}"#,
                r#"{"device_id":"RUST","display_name":null,"verified":false,"is_current":true}"#,
            ]
        );
    }

    #[test]
    fn emoji_confirmation_is_not_taken_from_a_pipe() {
        let mut input = Cursor::new("y\n");
        let result = confirm_emoji_on("", false, &mut input, &mut Vec::new(), || Ok(()));
        assert!(
            result.is_err(),
            "a piped \"y\" confirmed the emoji: {result:?}"
        );
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn emoji_confirmation_discards_typed_ahead_input_first() {
        let mut input = Cursor::new("y\n");
        let mut discarded = false;
        let answer = confirm_emoji_on("", true, &mut input, &mut Vec::new(), || {
            discarded = true;
            Ok(())
        })
        .unwrap();
        assert!(answer);
        assert!(discarded, "typed-ahead input was not discarded");
    }

    #[test]
    fn emoji_and_question_go_to_the_same_writer() {
        let emojis = [
            Emoji {
                symbol: "🐶",
                description: "Dog",
            },
            Emoji {
                symbol: "\u{1b}[2J",
                description: "Cat",
            },
        ];
        for comparison in [
            comparison_text(Some(&emojis), (1, 2, 3)),
            comparison_text(None, (1111, 2222, 3333)),
        ] {
            let mut input = Cursor::new("n\n");
            let mut output = Vec::new();
            let answer =
                confirm_emoji_on(&comparison, true, &mut input, &mut output, || Ok(())).unwrap();
            assert!(!answer);
            let shown = String::from_utf8(output).unwrap();
            let question = shown
                .find(MATCH_QUESTION)
                .unwrap_or_else(|| panic!("no question in {shown:?}"));
            let compared = shown
                .find("Compare these")
                .unwrap_or_else(|| panic!("no emoji or numbers in {shown:?}"));
            assert!(compared < question, "{shown:?}");
        }
        let text = comparison_text(Some(&emojis), (1, 2, 3));
        assert!(text.contains("  🐶  Dog\n"), "{text:?}");
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(comparison_text(None, (1111, 2222, 3333)).contains("1111 2222 3333"));
    }
}
