//! `verify`: SAS (emoji) verification with one of the account's own devices.
//!
//! A sync loop runs in the background for the whole flow, because every
//! verification step arrives as a to-device event.

use std::io::IsTerminal;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use matrix_sdk::Client;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::encryption::verification::{
    Emoji, SasState, SasVerification, Verification, VerificationRequest, VerificationRequestState,
};
use matrix_sdk::ruma::events::key::verification::request::ToDeviceKeyVerificationRequestEvent;
use matrix_sdk::ruma::{OwnedDeviceId, OwnedUserId};
use tokio::sync::mpsc;

use crate::VerifyArgs;
use crate::commands::{confirm_fresh_on, discard_typeahead_stdin, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::term;

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

pub async fn run(args: VerifyArgs) -> Result<()> {
    // stdin: the answer comes from a person. stderr: the emoji and the
    // question are shown to that person, not written to a file.
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!(
            "verify needs a terminal on stdin and stderr: the emoji comparison must be seen and confirmed by a person; no verification was started"
        );
    }
    let config = load_config()?;
    let paths = Paths::from_env()?;
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
    let flow = flow(&client, &own_user, &args, &mut rx, current.clone());
    let outcome = match tokio::time::timeout(Duration::from_secs(args.timeout), flow).await {
        Ok(result) => result,
        Err(_) => {
            let pending = current.lock().ok().and_then(|slot| slot.clone());
            if let Some(request) = pending {
                let _ = request.cancel().await;
            }
            Err(anyhow::anyhow!(
                "verification timed out after {} s",
                args.timeout
            ))
        }
    };

    if outcome.is_ok() {
        tokio::time::sleep(SETTLE_TIME).await;
    }
    sync_task.abort();
    outcome?;
    print_final_state(&client).await
}

async fn flow(
    client: &Client,
    own_user: &OwnedUserId,
    args: &VerifyArgs,
    rx: &mut mpsc::UnboundedReceiver<(OwnedUserId, String)>,
    current: Arc<Mutex<Option<VerificationRequest>>>,
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
    run_sas(&sas).await
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

fn into_sas(verification: Verification) -> Result<SasVerification> {
    match verification {
        Verification::SasV1(sas) => Ok(sas),
        #[allow(unreachable_patterns)]
        _ => bail!("the other device chose a method other than emoji verification"),
    }
}

async fn run_sas(sas: &SasVerification) -> Result<()> {
    let mut changes = sas.changes();
    let mut state = sas.state();
    if matches!(state, SasState::Started { .. }) && !sas.we_started() {
        sas.accept()
            .await
            .context("cannot accept the emoji verification")?;
    }
    let mut asked = false;
    loop {
        match &state {
            SasState::KeysExchanged { emojis, decimals } if !asked => {
                asked = true;
                let comparison =
                    comparison_text(emojis.as_ref().map(|short| &short.emojis[..]), *decimals);
                let answer =
                    match tokio::task::spawn_blocking(move || confirm_emoji(&comparison)).await {
                        Ok(Ok(answer)) => answer,
                        Ok(Err(err)) => {
                            sas.cancel().await.ok();
                            return Err(err.context("verification cancelled"));
                        }
                        Err(err) => {
                            sas.cancel().await.ok();
                            return Err(anyhow::Error::new(err)
                                .context("the prompt failed; verification cancelled"));
                        }
                    };
                if answer {
                    sas.confirm()
                        .await
                        .context("cannot send the confirmation")?;
                    eprintln!("Confirmed; waiting for the other device.");
                } else {
                    sas.mismatch().await.ok();
                    bail!("the emoji do not match; verification cancelled");
                }
            }
            SasState::Done { .. } => {
                println!(
                    "Verification done: device {} is verified.",
                    term(sas.other_device().device_id().as_str())
                );
                return Ok(());
            }
            SasState::Cancelled(info) => {
                bail!(
                    "verification cancelled: {} ({})",
                    info.reason(),
                    info.cancel_code()
                )
            }
            _ => {}
        }
        state = changes
            .next()
            .await
            .context("the verification stream ended")?;
    }
}

async fn print_final_state(client: &Client) -> Result<()> {
    let own = client.encryption().get_own_device().await?;
    let yn = |b: bool| if b { "yes" } else { "no" };
    println!(
        "This device: cross-signed {}, verified {}",
        yn(own.as_ref().is_some_and(|d| d.is_cross_signed_by_owner())),
        yn(own.as_ref().is_some_and(|d| d.is_verified()))
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
