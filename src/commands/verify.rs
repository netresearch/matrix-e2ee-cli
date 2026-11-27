//! `verify`: SAS (emoji) verification with one of the account's own devices.
//!
//! A sync loop runs in the background for the whole flow, because every
//! verification step arrives as a to-device event.
//!
//! With a terminal on stdin and stderr, a person confirms the emoji at the
//! prompt. Without one (an agent runs the command), the emoji go to stdout as
//! one JSON line and to an owner-only file, and the verification is confirmed
//! only after a second process, `verify --confirm`, handed over the person's
//! decision; the CLI never confirms on its own.

use std::future::Future;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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
    Comparison, Decision, EmojiItem, Pending, hand_over, handover_dir, sweep,
};
use crate::commands::{confirm_fresh_on, discard_typeahead_stdin, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term};

const MATCH_QUESTION: &str = "Do they match exactly?";

/// The emoji (or numbers) to compare, as shown before the question.
fn comparison_text(emojis: Option<&[Emoji]>, decimals: (u16, u16, u16)) -> String {
    let mut text = String::from("\n");
    match emojis {
        Some(emojis) => {
            text.push_str("Compare these emoji with the other device:\n");
            for emoji in emojis {
                text.push_str(&format!(
                    "  {}  {}\n",
                    term(emoji.symbol),
                    term(emoji.description)
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

/// Run a best-effort step for at most `limit`: a responsive server still
/// gets it, a stalled one cannot keep the command from ending.
async fn best_effort(step: impl Future, limit: Duration) {
    let _ = tokio::time::timeout(limit, step).await;
}

/// Who confirms the emoji.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirmer {
    /// A person at the terminal (stdin and stderr are terminals).
    Person,
    /// An agent: the decision comes from `verify --confirm` / `--cancel`.
    Agent,
}

/// stdin: the person's answer. stderr: the emoji and the question. Both
/// must be a terminal for the prompt; otherwise the agent hand-over is used.
fn confirmer(stdin_is_terminal: bool, stderr_is_terminal: bool) -> Confirmer {
    if stdin_is_terminal && stderr_is_terminal {
        Confirmer::Person
    } else {
        Confirmer::Agent
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
            Answer::HandOver { .. } => eprintln!("{line}"),
        }
    }
}

/// `verify --confirm` / `--cancel`: hand the decision to the waiting
/// process. Takes neither the data-directory lock (the waiting process holds
/// it) nor the store.
fn decide(transaction_id: Option<&str>, decision: Decision) -> Result<()> {
    let paths = Paths::from_env()?;
    let target = hand_over(&handover_dir(&paths.data_dir), transaction_id, decision)?;
    eprintln!(
        "Handed {} to verification {} with device {} (process {}); that process reports the result.",
        match decision {
            Decision::Confirm => "the confirmation",
            Decision::Cancel => "the cancellation",
        },
        term(&target.comparison.transaction_id),
        term(&target.comparison.other_device),
        target.pid
    );
    Ok(())
}

/// The JSON line for the emoji of transaction `transaction_id`.
fn comparison_record(transaction_id: &str, other_device: &str, emojis: &[Emoji]) -> Comparison {
    Comparison {
        transaction_id: transaction_id.to_owned(),
        other_device: other_device.to_owned(),
        emojis: emojis
            .iter()
            .map(|e| EmojiItem {
                symbol: e.symbol.to_owned(),
                description: e.description.to_owned(),
            })
            .collect(),
    }
}

/// How to answer, on stderr, after the emoji line.
fn hand_over_instructions(transaction_id: &str, other_device: &str, timeout: u64) -> String {
    // In --listen the requesting device chose the id: quote it for the shell
    // (as one argument; --confirm=... keeps a leading dash a value).
    let id = format!("'{}'", term(transaction_id).replace('\'', r"'\''"));
    format!(
        "Compare the emoji on stdout with the ones device {} shows.\n\
         If the person confirms they match exactly, run:\n  matrix-e2ee-cli verify --confirm={id}\n\
         If they do not match, run:\n  matrix-e2ee-cli verify --cancel={id}\n\
         Waiting for the decision (the verification gives up {timeout} s after it started).\n",
        term(other_device)
    )
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
            term(&row.device_id),
            term(row.display_name.as_deref().unwrap_or("No name")),
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
    if let Some(id) = &args.confirm {
        return decide(id.as_deref(), Decision::Confirm);
    }
    if let Some(id) = &args.cancel {
        return decide(id.as_deref(), Decision::Cancel);
    }
    if args.list {
        return list_devices(args.json).await;
    }
    let who = confirmer(
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    );
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    let answer = match who {
        Confirmer::Person => Answer::Prompt,
        Confirmer::Agent => {
            let dir = handover_dir(&paths.data_dir);
            // This process holds the lock: no other one waits, so whatever
            // is in the directory was left by a process that ended.
            sweep(&dir)?;
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
                    eprintln!(
                        "Ignoring a verification request from {}: only devices of {} are verified here.",
                        term(ev.sender.as_str()),
                        term(own.as_str())
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
            eprintln!("sync stopped: {}", term(&err.to_string()));
        }
    });

    let current: Arc<Mutex<Option<VerificationRequest>>> = Arc::default();
    let flow = flow(&client, &own_user, &args, &mut rx, current.clone(), &answer);
    let outcome = match tokio::time::timeout(Duration::from_secs(args.timeout), flow).await {
        Ok(result) => result,
        Err(_) => {
            let pending = current.lock().ok().and_then(|slot| slot.clone());
            if let Some(request) = pending {
                best_effort(request.cancel(), CANCEL_LIMIT).await;
            }
            Err(anyhow::anyhow!(
                "verification timed out after {} s",
                args.timeout
            ))
        }
    };
    // Without a person at the terminal, any failure cancels what is still
    // open: nothing is trusted unless a handed-over confirm completed.
    if outcome.is_err() && matches!(answer, Answer::HandOver { .. }) {
        let pending = current.lock().ok().and_then(|slot| slot.clone());
        if let Some(request) = pending.filter(|r| !r.is_done() && !r.is_cancelled()) {
            best_effort(request.cancel(), CANCEL_LIMIT).await;
        }
    }

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
    current: Arc<Mutex<Option<VerificationRequest>>>,
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
                        term(d.device_id().as_str()),
                        d.display_name()
                            .map(|n| format!(" ({})", term(n)))
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
        eprintln!(
            "Requesting verification with {}; accept it on that device.",
            term(device_id.as_str())
        );
        device
            .request_verification()
            .await
            .context("cannot send the verification request")?
    } else {
        eprintln!("Waiting for a verification request from one of your devices...");
        let request = loop {
            let (sender, flow_id) = rx.recv().await.context("the request listener stopped")?;
            match encryption.get_verification_request(&sender, &flow_id).await {
                Some(request) if !request.is_cancelled() && !request.is_done() => break request,
                // A stale request (e.g. replayed by the first sync): keep waiting.
                _ => continue,
            }
        };
        eprintln!("Verification request received; accepting.");
        // Register before accepting: accept() marks the request ready before
        // its send completes, so a timeout during the send must cancel it too.
        if let Ok(mut slot) = current.lock() {
            *slot = Some(request.clone());
        }
        request
            .accept()
            .await
            .context("cannot accept the verification request")?;
        request
    };
    if let Ok(mut slot) = current.lock() {
        *slot = Some(request.clone());
    }

    let sas = wait_for_sas(&request).await?;
    run_sas(&sas, request.flow_id(), answer).await
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

async fn run_sas(sas: &SasVerification, flow_id: &str, how: &Answer) -> Result<()> {
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
                            sas.cancel().await.ok();
                            bail!(
                                "the other device offers numbers only, no emoji; verification cancelled"
                            );
                        };
                        let other = sas.other_device().device_id().as_str();
                        let comparison = comparison_record(flow_id, other, &emojis.emojis);
                        let published = Pending::publish(dir, &comparison)
                            .and_then(|p| Ok((p, json_line(&comparison)?)));
                        let (pending, line) = match published {
                            Ok(published) => published,
                            Err(err) => {
                                sas.cancel().await.ok();
                                return Err(err.context("verification cancelled"));
                            }
                        };
                        let pending = _published.insert(pending);
                        println!("{line}");
                        eprint!("{}", hand_over_instructions(flow_id, other, *timeout));
                        answer_unless_ended(wait_for_decision(pending), &mut changes, ends).await
                    }
                };
                let answer = match outcome {
                    PromptOutcome::Ended(err) => return Err(err),
                    PromptOutcome::Answered(Ok(answer)) => answer,
                    PromptOutcome::Answered(Err(err)) => {
                        sas.cancel().await.ok();
                        return Err(err.context("verification cancelled"));
                    }
                };
                // A cancellation that arrived together with the answer.
                if let Some(info) = sas.cancel_info() {
                    return Err(cancelled(&info));
                }
                match (answer, how) {
                    (true, Answer::Prompt) => {
                        sas.confirm()
                            .await
                            .context("cannot send the confirmation")?;
                        eprintln!("Confirmed; waiting for the other device.");
                    }
                    (true, Answer::HandOver { .. }) => {
                        if let Err(err) = sas.confirm().await {
                            sas.cancel().await.ok();
                            return Err(anyhow::Error::new(err)
                                .context("cannot send the confirmation; verification cancelled"));
                        }
                        eprintln!("Confirmed; waiting for the other device.");
                    }
                    (false, Answer::Prompt) => {
                        sas.mismatch().await.ok();
                        bail!("the emoji do not match; verification cancelled");
                    }
                    (false, Answer::HandOver { .. }) => {
                        sas.cancel().await.ok();
                        bail!("verification cancelled with verify --cancel; nothing was trusted");
                    }
                }
            }
            SasState::Done { .. } => {
                how.report(&format!(
                    "Verification done: device {} is verified.",
                    term(sas.other_device().device_id().as_str())
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
    fn without_a_terminal_the_agent_hand_over_is_chosen() {
        assert_eq!(confirmer(true, true), Confirmer::Person);
        assert_eq!(confirmer(false, true), Confirmer::Agent);
        assert_eq!(confirmer(true, false), Confirmer::Agent);
        assert_eq!(confirmer(false, false), Confirmer::Agent);
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
        let line = json_line(&comparison_record("tx1", "PHONE", &emojis)).unwrap();
        assert_eq!(
            line,
            r#"{"transaction_id":"tx1","other_device":"PHONE","emojis":[{"symbol":"🐶","description":"Dog"},{"symbol":"\u001b[2J","description":"Cat"}]}"#
        );
        let text = hand_over_instructions("tx\u{1b}1", "PHONE", 180);
        assert!(text.contains("verify --confirm='tx\u{FFFD}1'\n"), "{text}");
        assert!(text.contains("verify --cancel='tx\u{FFFD}1'\n"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
        // An id the requesting device chose stays one quoted argument.
        let text = hand_over_instructions("x'; rm -rf ~; '", "PHONE", 180);
        assert!(
            text.contains(r"verify --confirm='x'\''; rm -rf ~; '\'''"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_wait_ends_only_with_a_handed_over_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let comparison = comparison_record("tx1", "PHONE", &[]);
        let pending = Pending::publish(tmp.path(), &comparison).unwrap();
        let undecided =
            tokio::time::timeout(Duration::from_millis(600), wait_for_decision(&pending)).await;
        assert!(
            undecided.is_err(),
            "decided without a hand-over: {undecided:?}"
        );
        hand_over(tmp.path(), None, Decision::Cancel).unwrap();
        let answer = within_5s("the cancel was not read", wait_for_decision(&pending)).await;
        assert!(!answer.unwrap());
        drop(pending);
        let pending = Pending::publish(tmp.path(), &comparison).unwrap();
        hand_over(tmp.path(), None, Decision::Confirm).unwrap();
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
