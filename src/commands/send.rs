//! `send`: one message, encrypted when the room is encrypted, at parity
//! with the matrix-skill's matrix-send-e2ee.py: Markdown rendered as HTML
//! (`formatted_body`), mentions, threads and replies, `--to` for a direct
//! chat, and the bot prefix of config.json.
//!
//! Room keys go to verified devices only (`CollectStrategy::OnlyTrustedDevices`).
//! `--trust-unverified-devices` builds this process's client with
//! `CollectStrategy::AllDevices` instead, and discards the room key after the
//! send, so the next message starts a new megolm session. `edit` sends
//! through the same [`send_guarded`].

use anyhow::{Context, Result, bail};
use matrix_sdk::encryption::identities::Device;
use matrix_sdk::ruma::events::MessageLikeEventContent;
use matrix_sdk::ruma::events::direct::DirectEventContent;
use matrix_sdk::ruma::events::room::member::MembershipState;
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use matrix_sdk::ruma::{OwnedEventId, RoomId, UserId};
use matrix_sdk::{Client, EncryptionState, Room, RoomMemberships, RoomState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::SendArgs;
use crate::commands::{resolve_room, sync_once, via_daemon};
use crate::config::{load_bot_prefix, load_config};
use crate::formatting::{add_bot_prefix, inject_pills, markdown_to_html};
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term};

pub async fn run(args: SendArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    // Like matrix-send-e2ee.py: no prefix on an emote.
    let prefix = if args.no_prefix || args.emote {
        None
    } else {
        load_bot_prefix()?
    };
    // The request the watch daemon takes (matrix-watchd.py's "send"); the
    // direct path executes the same request.
    let request = send_request(&args, prefix.as_deref())?;
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
    print_warnings(&outcome.warnings);
    // The confirmation names what was given: the room as typed, or the
    // person of --to.
    let target = args
        .to
        .as_deref()
        .or(args.room.as_deref())
        .unwrap_or_default();
    for line in outcome_lines(&outcome, target, args.json, args.quiet)? {
        println!("{line}");
    }
    Ok(())
}

/// The "send" request for these arguments, as matrix-send-e2ee.py builds
/// it: the bot prefix (none given: none added) before anything else, then
/// the HTML of the prefixed text with pills for the --mention users, sent as
/// `formatted_body` when it differs from the text.
pub fn send_request(args: &SendArgs, bot_prefix: Option<&str>) -> Result<Value> {
    let msgtype = if args.notice {
        "m.notice"
    } else if args.emote {
        "m.emote"
    } else {
        "m.text"
    };
    let body = match bot_prefix.filter(|p| !p.is_empty()) {
        Some(prefix) if !args.no_prefix && !args.emote => add_bot_prefix(&args.message, prefix)?,
        _ => args.message.clone(),
    };
    let html = markdown_to_html(&inject_pills(&body, &args.mention)?)?;
    let mut request = json!({
        "op": "send",
        "body": body,
        "msgtype": msgtype,
        "trust_unverified_devices": args.trust_unverified_devices,
    });
    let fields = [
        ("room", args.room.as_deref()),
        ("to", args.to.as_deref()),
        ("reply_to", args.reply.as_deref()),
        ("thread_root", args.thread.as_deref()),
    ];
    for (key, value) in fields {
        if let Some(value) = value {
            request[key] = json!(value);
        }
    }
    if !args.mention.is_empty() {
        request["mentions"] = json!(args.mention);
    }
    if args.mention_room {
        request["mention_room"] = json!(true);
    }
    if html != body {
        request["formatted_body"] = json!(html);
    }
    Ok(request)
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

/// What `send` prints on stdout: by default matrix-send-e2ee.py's two lines
/// (callers match `Event ID: (\$\S+)`), with `--quiet` the event id alone,
/// with `--json` (which wins) one JSON object.
pub fn outcome_lines(
    outcome: &SendOutcome,
    target: &str,
    json: bool,
    quiet: bool,
) -> Result<Vec<String>> {
    Ok(if json {
        // json_line escapes DEL and C1, which a hostile server can put into a
        // room id and serde_json leaves raw.
        vec![json_line(&json!({
            "event_id": outcome.event_id,
            "room_id": outcome.room_id,
            "encrypted": outcome.encrypted,
        }))?]
    } else if quiet {
        vec![term(&outcome.event_id).into_owned()]
    } else {
        vec![
            format!("Message sent to {}", term(target)),
            format!("Event ID: {}", term(&outcome.event_id)),
        ]
    })
}

pub fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("warning: {}", term(warning));
    }
}

/// Carry out a "send" request with `client`, which must have been built with
/// [`key_sharing`] of the request's `trust_unverified_devices`.
pub async fn execute(client: &Client, request: &Value) -> Result<SendOutcome> {
    let room = match request_opt(request, "to") {
        Some(user) => find_direct_room(client, user).await?,
        None => resolve_room(client, request_str(request, "room")?).await?,
    };
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

/// The message a "send" request describes, built the way
/// matrix-send-e2ee.py builds it: `msgtype` (default `m.text`), `mentions` and
/// `mention_room` as `m.mentions`, the body rendered as HTML with pills for
/// the mentioned users (matrix-watchd.py's `op_send` renders it the same way;
/// a request's own `formatted_body` is used only when the body renders to
/// itself), and `thread_root` (with the reply fallback to `reply_to` or the
/// root) or else `reply_to` as the relation.
///
/// Unlike matrix-watchd.py, which lets `reply_to` win and writes no fallback,
/// both paths of this tool build the event of the script's direct path.
pub fn message_content(request: &Value) -> Result<RoomMessageEventContent> {
    let body = request_str(request, "body")?;
    let msgtype = request_opt(request, "msgtype").unwrap_or("m.text");
    if !matches!(msgtype, "m.text" | "m.notice" | "m.emote") {
        bail!("msgtype {msgtype:?} is not supported; use m.text, m.notice or m.emote");
    }
    let mut content = json!({"msgtype": msgtype, "body": body});
    let mut mentions = serde_json::Map::new();
    let mut ids: Vec<String> = Vec::new();
    if let Some(users) = request.get("mentions").filter(|v| !v.is_null()) {
        let users = users
            .as_array()
            .context("mentions must be a list of user ids")?;
        for user in users {
            let user = user
                .as_str()
                .context("mentions must be a list of user ids")?;
            if !ids.iter().any(|id| id == user) {
                ids.push(user.to_owned());
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
    let html = markdown_to_html(&inject_pills(body, &ids)?)?;
    let html = if html != body {
        Some(html.as_str())
    } else {
        request_opt(request, "formatted_body")
    };
    if let Some(html) = html {
        content["format"] = json!("org.matrix.custom.html");
        content["formatted_body"] = json!(html);
    }
    let reply_to = request_opt(request, "reply_to");
    if let Some(root) = request_opt(request, "thread_root") {
        content["m.relates_to"] = json!({
            "rel_type": "m.thread",
            "event_id": root,
            "is_falling_back": true,
            "m.in_reply_to": {"event_id": reply_to.unwrap_or(root)},
        });
    } else if let Some(reply_to) = reply_to {
        content["m.relates_to"] = json!({"m.in_reply_to": {"event_id": reply_to}});
    }
    serde_json::from_value(content).context("the request does not describe a valid message")
}

/// The room ids `m.direct` (its content as JSON, absent: none) lists for
/// `user`, as `find_direct_room` of the matrix-skill reads them: the key must
/// be the user id exactly; anything but a string in the list is skipped.
pub fn listed_direct_rooms(direct: Option<&Value>, user: &str) -> Vec<String> {
    direct
        .and_then(|d| d.get(user))
        .and_then(Value::as_array)
        .map(|rooms| {
            rooms
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The one usable direct room, with the errors of the matrix-skill's
/// `find_direct_room`: none listed, none usable, or several.
pub fn choose_direct_room(user: &str, listed: &[String], usable: &[String]) -> Result<String> {
    if listed.is_empty() {
        bail!("No direct chat with {user} in m.direct");
    }
    match usable {
        [one] => Ok(one.clone()),
        [] => bail!(
            "No usable direct chat with {user}: m.direct lists {}, but you or they have left each of them",
            listed.join(", ")
        ),
        many => bail!(
            "Several direct chats with {user}: {}. Pass the room ID instead of --to",
            many.join(", ")
        ),
    }
}

/// The direct chat with `user` for `--to`: a room `m.direct` lists for them,
/// which this account has joined and `user` has joined or been invited to.
/// Never creates a room. Read from the synced store; matrix-send-e2ee.py
/// asks the server for the same three things.
pub async fn find_direct_room(client: &Client, user: &str) -> Result<Room> {
    let direct = client
        .account()
        .account_data::<DirectEventContent>()
        .await
        .context("cannot read m.direct")?
        .map(|raw| serde_json::from_str::<Value>(raw.json().get()))
        .transpose()
        .context("m.direct is not valid JSON")?;
    let listed = listed_direct_rooms(direct.as_ref(), user);
    let user_id = UserId::parse(user).with_context(|| format!("invalid user id {user:?}"))?;
    let mut usable = Vec::new();
    for listed_id in &listed {
        let Ok(room_id) = RoomId::parse(listed_id) else {
            continue;
        };
        let Some(room) = client
            .get_room(&room_id)
            .filter(|r| r.state() == RoomState::Joined)
        else {
            continue;
        };
        // As the Python helper: a member lookup that fails makes the room
        // unusable, not the command.
        if let Ok(Some(member)) = room.get_member(&user_id).await
            && matches!(
                member.membership(),
                MembershipState::Join | MembershipState::Invite
            )
        {
            usable.push(listed_id.clone());
        }
    }
    let chosen = choose_direct_room(user, &listed, &usable)?;
    let room_id = RoomId::parse(&chosen)?;
    client
        .get_room(&room_id)
        .with_context(|| format!("not joined to room {room_id}"))
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
    fn message_content_follows_matrix_send_e2ee() {
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
                "thread_root": "$root:example.org",
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(full["msgtype"], "m.emote");
        assert_eq!(
            full["m.mentions"],
            json!({"user_ids": ["@a:example.org", "@b:example.org"], "room": true})
        );
        // "hi @a" pills @a:example.org, so the rendered HTML wins.
        assert_eq!(full["format"], "org.matrix.custom.html");
        assert_eq!(
            full["formatted_body"],
            "hi <a href=\"https://matrix.to/#/@a:example.org\">a</a>"
        );
        // A thread reply names the replied-to event as its fallback.
        assert_eq!(
            full["m.relates_to"],
            json!({"rel_type": "m.thread", "event_id": "$root:example.org",
                "is_falling_back": true, "m.in_reply_to": {"event_id": "$parent:example.org"}})
        );
        let thread = serde_json::to_value(
            message_content(&json!({"body": "t", "thread_root": "$root:example.org"})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            thread["m.relates_to"],
            json!({"rel_type": "m.thread", "event_id": "$root:example.org",
                "is_falling_back": true, "m.in_reply_to": {"event_id": "$root:example.org"}})
        );
        let reply = serde_json::to_value(
            message_content(&json!({"body": "r", "reply_to": "$p:example.org"})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reply["m.relates_to"],
            json!({"m.in_reply_to": {"event_id": "$p:example.org"}})
        );
        // A body that renders to itself keeps a formatted_body of the request.
        let given = serde_json::to_value(
            message_content(&json!({"body": "x", "formatted_body": "<b>x</b>"})).unwrap(),
        )
        .unwrap();
        assert_eq!(given["formatted_body"], "<b>x</b>");
    }

    fn send_args(argv: &[&str]) -> SendArgs {
        use clap::Parser;
        let cli =
            crate::Cli::try_parse_from([&["matrix-e2ee-cli", "send"][..], argv].concat()).unwrap();
        let crate::Command::Send(args) = cli.command else {
            panic!("not send")
        };
        args
    }

    fn outcome() -> SendOutcome {
        SendOutcome {
            event_id: "$ev1:example.org".into(),
            room_id: "!r:example.org".into(),
            encrypted: true,
            warnings: vec![],
        }
    }

    #[test]
    fn the_ticket_flow_invocation_keeps_its_event_id_line() {
        // it-maintenance ticket-flow.py:
        //   r = _matrix("matrix-send-e2ee.py", room, text, *_trust_args())
        //   m = re.search(r"Event ID: (\$\S+)", r.stdout + r.stderr)
        let event_id_line = fancy_regex::Regex::new(r"Event ID: (\$\S+)").unwrap();
        for trust in [&[][..], &["--trust-unverified-devices"]] {
            let args = send_args(&[&["!r:example.org", "OPS-1 is done"][..], trust].concat());
            let request = send_request(&args, None).unwrap();
            assert_eq!(
                request,
                json!({"op": "send", "room": "!r:example.org", "body": "OPS-1 is done",
                    "msgtype": "m.text", "trust_unverified_devices": !trust.is_empty()})
            );
            let lines = outcome_lines(&outcome(), "!r:example.org", args.json, args.quiet).unwrap();
            assert_eq!(
                lines,
                [
                    "Message sent to !r:example.org",
                    "Event ID: $ev1:example.org"
                ]
            );
            let stdout = lines.join("\n") + "\n";
            let found = event_id_line.captures(stdout.as_str()).unwrap().unwrap();
            assert_eq!(found.get(1).unwrap().as_str(), "$ev1:example.org");
        }
    }

    #[test]
    fn quiet_prints_the_event_id_and_json_wins() {
        let quiet = send_args(&["r", "hi", "-q"]);
        assert_eq!(
            outcome_lines(&outcome(), "r", quiet.json, quiet.quiet).unwrap(),
            ["$ev1:example.org"]
        );
        let both = send_args(&["r", "hi", "-q", "--json"]);
        let lines = outcome_lines(&outcome(), "r", both.json, both.quiet).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&lines[0]).unwrap(),
            json!({"event_id": "$ev1:example.org", "room_id": "!r:example.org", "encrypted": true})
        );
        // --to: the confirmation names the person.
        let to = send_args(&["--to", "@jane:example.org", "hi"]);
        assert_eq!(
            outcome_lines(&outcome(), to.to.as_deref().unwrap(), false, false).unwrap()[0],
            "Message sent to @jane:example.org"
        );
    }

    /// The content matrix-send-e2ee.py sends for rich_args() with bot_prefix
    /// "🤖" (computed with the matrix-skill at 9f5663b).
    fn rich_python_content() -> Value {
        json!({
            "msgtype": "m.text",
            "body": "## Deploy\n\n🤖\nalice: **done**, see https://github.com/o/r/pull/7",
            "m.mentions": {"user_ids": ["@alice:example.org"], "room": true},
            "format": "org.matrix.custom.html",
            "formatted_body": "<h2>Deploy</h2>🤖<br><a href=\"https://matrix.to/#/@alice:example.org\">alice</a>: <strong>done</strong>, see <a href=\"https://github.com/o/r/pull/7\">o/r#7</a>",
            "m.relates_to": {
                "rel_type": "m.thread",
                "event_id": "$root:example.org",
                "is_falling_back": true,
                "m.in_reply_to": {"event_id": "$parent:example.org"},
            },
        })
    }

    fn rich_args() -> SendArgs {
        send_args(&[
            "!r:example.org",
            "## Deploy\nalice: **done**, see https://github.com/o/r/pull/7",
            "--mention",
            "@alice:example.org",
            "--mention-room",
            "--thread",
            "$root:example.org",
            "--reply",
            "$parent:example.org",
        ])
    }

    #[test]
    fn send_request_builds_the_content_of_matrix_send_e2ee() {
        let request = send_request(&rich_args(), Some("🤖")).unwrap();
        assert_eq!(
            request["formatted_body"],
            rich_python_content()["formatted_body"]
        );
        let content = serde_json::to_value(message_content(&request).unwrap()).unwrap();
        assert_eq!(content, rich_python_content());
    }

    #[test]
    fn the_prefix_is_left_out_for_emotes_and_with_no_prefix() {
        for argv in [
            &["r", "waves", "--emote"][..],
            &["r", "waves", "--no-prefix"],
        ] {
            let request = send_request(&send_args(argv), Some("🤖")).unwrap();
            assert_eq!(request["body"], "waves", "{argv:?}");
        }
        let request = send_request(&send_args(&["r", "waves"]), Some("🤖")).unwrap();
        assert_eq!(request["body"], "🤖 waves");
        assert!(request.get("formatted_body").is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_daemon_path_sends_the_event_of_the_direct_path() {
        use crate::commands::via_daemon_at;
        use crate::daemon_test_support::FakeDaemon;
        let request = send_request(&rich_args(), Some("🤖")).unwrap();
        let fake = FakeDaemon::start(Some(
            json!({"ok": true, "event_id": "$x", "room_id": "!r:example.org", "encrypted": true}),
        ));
        via_daemon_at::<SendOutcome>(&fake.path, request.clone(), "message")
            .await
            .unwrap()
            .unwrap();
        // What the daemon builds from the request it received, and what the
        // direct path builds from the request it holds.
        let via_daemon = serde_json::to_value(message_content(&fake.received()).unwrap()).unwrap();
        let direct = serde_json::to_value(message_content(&request).unwrap()).unwrap();
        assert_eq!(via_daemon, direct);
        assert_eq!(direct, rich_python_content());
    }

    #[test]
    fn direct_room_choice_follows_find_direct_room() {
        let direct = json!({"@jane:e": ["!a:e", 5, "!b:e"], "@other:e": ["!c:e"]});
        let listed = listed_direct_rooms(Some(&direct), "@jane:e");
        assert_eq!(listed, ["!a:e", "!b:e"]);
        assert!(listed_direct_rooms(None, "@jane:e").is_empty());
        assert!(listed_direct_rooms(Some(&direct), "@Jane:e").is_empty());
        assert_eq!(
            choose_direct_room("@jane:e", &listed, &["!b:e".to_owned()]).unwrap(),
            "!b:e"
        );
        let err = |listed: &[String], usable: &[String]| {
            choose_direct_room("@jane:e", listed, usable)
                .unwrap_err()
                .to_string()
        };
        assert_eq!(err(&[], &[]), "No direct chat with @jane:e in m.direct");
        assert_eq!(
            err(&listed, &[]),
            "No usable direct chat with @jane:e: m.direct lists !a:e, !b:e, but you or they have left each of them"
        );
        assert_eq!(
            err(&listed, &listed),
            "Several direct chats with @jane:e: !a:e, !b:e. Pass the room ID instead of --to"
        );
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
