//! `send`: one message, encrypted when the room is encrypted.
//!
//! Room keys go to verified devices only (`CollectStrategy::OnlyTrustedDevices`).
//! `--trust-unverified-devices` builds this process's client with
//! `CollectStrategy::AllDevices` instead, and discards the room key after the
//! send, so the next message starts a new megolm session. `edit` sends
//! through the same [`send_guarded`].

use anyhow::{Context, Result, bail};
use matrix_sdk::encryption::identities::Device;
use matrix_sdk::ruma::OwnedEventId;
use matrix_sdk::ruma::events::MessageLikeEventContent;
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use matrix_sdk::{Client, EncryptionState, Room, RoomMemberships};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::SendArgs;
use crate::commands::{resolve_room, sync_once, via_daemon};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term};

pub async fn run(args: SendArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    let msgtype = if args.notice {
        "m.notice"
    } else if args.emote {
        "m.emote"
    } else {
        "m.text"
    };
    // The request the watch daemon takes (matrix-watchd.py's "send"); the
    // direct path executes the same request.
    let request = json!({
        "op": "send",
        "room": args.room,
        "body": args.message,
        "msgtype": msgtype,
        "trust_unverified_devices": args.trust_unverified_devices,
    });
    let outcome = match via_daemon::<SendOutcome>(&paths, request.clone(), "message").await? {
        Some(outcome) => outcome,
        None => {
            let config = load_config()?;
            let _lock = paths.lock().await?;
            let restored =
                restore(&config, &paths, key_sharing(args.trust_unverified_devices)).await?;
            sync_once(&restored.client).await?;
            execute(&restored.client, &request).await?
        }
    };
    print_outcome(&outcome, args.json)
}

/// What a sent message is reported as, on the direct path and in the
/// daemon's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendOutcome {
    pub event_id: String,
    pub room_id: String,
    pub encrypted: bool,
    /// Printed to stderr as "warning: ...".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

fn print_outcome(outcome: &SendOutcome, json: bool) -> Result<()> {
    print_warnings(&outcome.warnings);
    if json {
        // json_line escapes DEL and C1, which a hostile server can put into a
        // room id and serde_json leaves raw.
        println!(
            "{}",
            json_line(&json!({
                "event_id": outcome.event_id,
                "room_id": outcome.room_id,
                "encrypted": outcome.encrypted,
            }))?
        );
    } else {
        println!("{}", term(&outcome.event_id));
    }
    Ok(())
}

pub fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("warning: {}", term(warning));
    }
}

/// Carry out a "send" request with `client`, which must have been built with
/// [`key_sharing`] of the request's `trust_unverified_devices`.
pub async fn execute(client: &Client, request: &Value) -> Result<SendOutcome> {
    let room = resolve_room(client, request_str(request, "room")?).await?;
    let content = message_content(request)?;
    let Sent {
        event_id,
        encrypted,
        warnings,
    } = send_guarded(
        &room,
        content,
        request_trusts_unverified(request),
        "message",
        |_| Ok(()),
    )
    .await?;
    Ok(SendOutcome {
        event_id: event_id.to_string(),
        room_id: room.room_id().to_string(),
        encrypted,
        warnings,
    })
}

/// A required string field of a request.
pub fn request_str<'a>(request: &'a Value, key: &str) -> Result<&'a str> {
    request
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("the request has no {key:?}"))
}

/// An optional, non-empty string field of a request.
pub fn request_opt<'a>(request: &'a Value, key: &str) -> Option<&'a str> {
    request
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

/// The request's `trust_unverified_devices` (absent: false).
pub fn request_trusts_unverified(request: &Value) -> bool {
    request
        .get("trust_unverified_devices")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The message a "send" request describes, built the way matrix-watchd.py's
/// `op_send` builds it: `msgtype` (default `m.text`), `mentions` and
/// `mention_room` as `m.mentions`, `formatted_body` as HTML, and
/// `reply_to` or else `thread_root` as the relation. Unlike the Python
/// daemon the body is not rendered as Markdown: this tool sends plain text.
pub fn message_content(request: &Value) -> Result<RoomMessageEventContent> {
    let body = request_str(request, "body")?;
    let msgtype = request_opt(request, "msgtype").unwrap_or("m.text");
    if !matches!(msgtype, "m.text" | "m.notice" | "m.emote") {
        bail!("msgtype {msgtype:?} is not supported; use m.text, m.notice or m.emote");
    }
    let mut content = json!({"msgtype": msgtype, "body": body});
    let mut mentions = serde_json::Map::new();
    if let Some(users) = request.get("mentions").filter(|v| !v.is_null()) {
        let users = users
            .as_array()
            .context("mentions must be a list of user ids")?;
        let mut ids: Vec<&str> = Vec::new();
        for user in users {
            let user = user
                .as_str()
                .context("mentions must be a list of user ids")?;
            if !ids.contains(&user) {
                ids.push(user);
            }
        }
        if !ids.is_empty() {
            mentions.insert("user_ids".into(), json!(ids));
        }
    }
    if request.get("mention_room").and_then(Value::as_bool) == Some(true) {
        mentions.insert("room".into(), json!(true));
    }
    if !mentions.is_empty() {
        content["m.mentions"] = Value::Object(mentions);
    }
    if let Some(html) = request_opt(request, "formatted_body") {
        content["format"] = json!("org.matrix.custom.html");
        content["formatted_body"] = json!(html);
    }
    if let Some(reply_to) = request_opt(request, "reply_to") {
        content["m.relates_to"] = json!({"m.in_reply_to": {"event_id": reply_to}});
    } else if let Some(root) = request_opt(request, "thread_root") {
        content["m.relates_to"] = json!({"rel_type": "m.thread", "event_id": root});
    }
    serde_json::from_value(content).context("the request does not describe a valid message")
}

/// The room-key sharing rule for a command that sends an encrypted event:
/// verified devices only, unless `--trust-unverified-devices` was given.
pub fn key_sharing(trust_unverified_devices: bool) -> KeySharing {
    if trust_unverified_devices {
        KeySharing::IncludeUnverified
    } else {
        KeySharing::VerifiedOnly
    }
}

/// A sent event.
pub struct Sent {
    pub event_id: OwnedEventId,
    /// The room is encrypted, so the event was sent encrypted.
    pub encrypted: bool,
    /// For stderr ("warning: ..."); the daemon hands them to the client.
    pub warnings: Vec<String>,
}

/// Send one message-like event the way `send` does. The client must have
/// been built with [`key_sharing`]`(trust_unverified_devices)`.
///
/// - The room's encryption state must be known; never plaintext on doubt.
/// - In an encrypted room without `trust_unverified_devices`, refuse while
///   devices are known that are neither verified nor blacklisted, and warn
///   afterwards about devices the key was withheld from.
/// - With `trust_unverified_devices`, discard the room key after the send
///   (also after a failed one), so the opt-in covers this event only.
///
/// `what` names the event in the refusal ("message", "edit").
/// `check_encryption` gets whether the event will be sent encrypted and may
/// refuse before anything is sent.
pub async fn send_guarded(
    room: &Room,
    content: impl MessageLikeEventContent,
    trust_unverified_devices: bool,
    what: &str,
    check_encryption: impl FnOnce(bool) -> Result<()>,
) -> Result<Sent> {
    let encrypted = match room
        .latest_encryption_state()
        .await
        .context("cannot read the room's encryption state")?
    {
        EncryptionState::Encrypted => true,
        EncryptionState::NotEncrypted => false,
        // Never fall back to plaintext on a room whose state is unknown.
        other => bail!(
            "the encryption state of {} is unknown ({other:?}); not sending",
            room.room_id()
        ),
    };
    check_encryption(encrypted)?;

    if encrypted && !trust_unverified_devices {
        let untrusted = untrusted_devices(room).await?;
        if !untrusted.is_empty() {
            bail!(
                "the room has devices that are not verified, so the {what} was not sent:{} verify them, or pass --trust-unverified-devices to share this {what}'s key with them anyway",
                describe(&untrusted)
            );
        }
    }

    let result = room.send(content).await;
    let discarded = if encrypted && trust_unverified_devices {
        // The opt-in covers this event only: drop the session the
        // unverified devices may now hold, before anything else can reuse
        // it. Also after a failed send: the key may have been shared already.
        room.discard_room_key().await
    } else {
        Ok(())
    };
    let (sent, warning) = settle_send(result, discarded)?;
    let mut warnings: Vec<String> = warning.into_iter().collect();
    let event_id = sent.response.event_id;

    if encrypted && !trust_unverified_devices {
        // The SDK queries device lists inside send(), after the check above:
        // devices learnt there got the key withheld. Say so.
        let withheld = untrusted_devices(room).await.unwrap_or_default();
        if !withheld.is_empty() {
            warnings.push(format!(
                "sent, but the room key was withheld from unverified devices:{}",
                describe(&withheld)
            ));
        }
    }

    Ok(Sent {
        event_id,
        encrypted,
        warnings,
    })
}

/// Combine the send result with the result of discarding the room key: a
/// failed send is the error (a discard failure attached as context); after a
/// successful send a discard failure is only a warning.
fn settle_send<T, E, D>(sent: Result<T, E>, discarded: Result<(), D>) -> Result<(T, Option<String>)>
where
    E: std::error::Error + Send + Sync + 'static,
    D: std::fmt::Display,
{
    match (sent, discarded) {
        (Ok(sent), Ok(())) => Ok((sent, None)),
        (Ok(sent), Err(discard)) => Ok((
            sent,
            Some(format!(
                "sent, but discarding the room key shared with unverified devices failed ({discard}); the next message may reuse it"
            )),
        )),
        (Err(err), Ok(())) => Err(anyhow::Error::new(err).context("sending failed")),
        (Err(err), Err(discard)) => Err(err).with_context(|| {
            format!(
                "sending failed, and discarding the room key shared with unverified devices failed too ({discard})"
            )
        }),
    }
}

fn describe(devices: &[Device]) -> String {
    devices
        .iter()
        .map(|d| {
            let name = d
                .display_name()
                .map(|n| format!(" ({})", term(n)))
                .unwrap_or_default();
            format!(
                " {} {}{name};",
                term(d.user_id().as_str()),
                term(d.device_id().as_str())
            )
        })
        .collect()
}

/// Devices of the room's members this tool will not share a room key with by
/// default: neither verified nor blacklisted, other than this device. Only
/// devices this store already knows are listed; matrix-sdk's
/// `OnlyTrustedDevices` strategy withholds the key from the rest at send time.
async fn untrusted_devices(room: &Room) -> Result<Vec<Device>> {
    let client = room.client();
    let own_user = client.user_id().map(ToOwned::to_owned);
    let own_device = client.device_id().map(ToOwned::to_owned);
    let mut found = Vec::new();
    for member in room
        .members(RoomMemberships::ACTIVE)
        .await
        .context("cannot list room members")?
    {
        let devices = client
            .encryption()
            .get_user_devices(member.user_id())
            .await?;
        for device in devices.devices() {
            if own_user.as_deref() == Some(member.user_id())
                && own_device.as_deref() == Some(device.device_id())
            {
                continue;
            }
            if device.is_verified() || device.is_blacklisted() || device.is_deleted() {
                continue;
            }
            found.push(device);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_error() -> std::io::Error {
        std::io::Error::other("server said no")
    }

    #[test]
    fn failed_send_is_an_error_even_when_the_discard_fails() {
        let err = settle_send::<u8, _, _>(Err(send_error()), Err("disk full")).unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("server said no"), "{chain}");
        assert!(
            chain.contains("sending failed") && chain.contains("disk full"),
            "{chain}"
        );
        assert!(!chain.starts_with("sent"), "{chain}");
    }

    #[test]
    fn message_content_follows_the_python_daemon() {
        let plain = message_content(&json!({"body": "hi"})).unwrap();
        assert_eq!(
            serde_json::to_value(&plain).unwrap(),
            json!({"msgtype": "m.text", "body": "hi"})
        );
        let notice = message_content(&json!({"body": "n", "msgtype": "m.notice"})).unwrap();
        assert_eq!(
            serde_json::to_value(&notice).unwrap()["msgtype"],
            "m.notice"
        );
        let full = serde_json::to_value(
            message_content(&json!({
                "body": "hi @a", "msgtype": "m.emote",
                "mentions": ["@a:example.org", "@a:example.org", "@b:example.org"],
                "mention_room": true,
                "formatted_body": "hi <b>a</b>",
                "reply_to": "$parent:example.org",
                "thread_root": "$ignored:example.org",
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(full["msgtype"], "m.emote");
        assert_eq!(
            full["m.mentions"],
            json!({"user_ids": ["@a:example.org", "@b:example.org"], "room": true})
        );
        assert_eq!(full["format"], "org.matrix.custom.html");
        assert_eq!(full["formatted_body"], "hi <b>a</b>");
        assert_eq!(
            full["m.relates_to"]["m.in_reply_to"]["event_id"],
            "$parent:example.org"
        );
        let thread = serde_json::to_value(
            message_content(&json!({"body": "t", "thread_root": "$root:example.org"})).unwrap(),
        )
        .unwrap();
        assert_eq!(thread["m.relates_to"]["rel_type"], "m.thread");
        assert_eq!(thread["m.relates_to"]["event_id"], "$root:example.org");
    }

    #[test]
    fn message_content_refuses_what_it_cannot_send() {
        assert!(message_content(&json!({})).is_err());
        assert!(message_content(&json!({"body": "x", "msgtype": "m.image"})).is_err());
        assert!(message_content(&json!({"body": "x", "mentions": "@a:e"})).is_err());
    }

    #[test]
    fn successful_send_with_failed_discard_is_a_warning() {
        let (sent, warning) =
            settle_send::<u8, std::io::Error, _>(Ok(7), Err("disk full")).unwrap();
        assert_eq!(sent, 7);
        assert!(warning.is_some_and(|w| w.contains("disk full")));
        let (_, warning) = settle_send::<u8, std::io::Error, &str>(Ok(7), Ok(())).unwrap();
        assert!(warning.is_none());
    }
}
