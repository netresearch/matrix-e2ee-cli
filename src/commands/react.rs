//! `react`: add, remove, swap or list the user's own reactions
//! (`m.reaction` annotations) on one event.
//!
//! matrix-sdk 0.20.0 sends `m.reaction` unencrypted also in an encrypted
//! room (`room/futures.rs`: "Reactions are currently famously not
//! encrypted"), so no room key is shared and the key-sharing rule of `send`
//! does not apply here.
//!
//! The user's own reactions are looked up on the server
//! (`/relations/{event}/m.annotation`), so the caller never needs a
//! reaction's event id. Only events known to be `m.reaction` are listed or
//! removed; an annotation this device cannot decrypt is skipped and counted.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use matrix_sdk::room::{IncludeRelations, RelationsOptions};
use matrix_sdk::ruma::events::reaction::ReactionEventContent;
use matrix_sdk::ruma::events::relation::{Annotation, RelationType};
use matrix_sdk::ruma::{EventId, OwnedEventId, UInt};
use matrix_sdk::{Client, Room};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ReactArgs;
use crate::commands::send::request_str;
use crate::commands::{fetch_event, parse_event_id, resolve_room, sync_once, via_daemon};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term};

/// Guard against a server that never stops paging (100 reactions a page).
const MAX_PAGES: usize = 50;

/// One live reaction of the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnReaction {
    pub key: String,
    pub event_id: String,
}

/// What to do with KEY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Set KEY (not twice when it is already set).
    Add,
    /// Remove the user's own KEY reactions.
    Remove,
    /// Set KEY, then remove the user's own reactions with any of these keys.
    Replace(Vec<String>),
}

/// The steps for KEY in `mode`: whether to set it, and which of the user's
/// own reaction keys to remove afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub add: bool,
    pub drop: BTreeSet<String>,
}

impl Plan {
    pub fn new(key: &str, mode: &Mode) -> Self {
        match mode {
            Mode::Add => Plan {
                add: true,
                drop: BTreeSet::new(),
            },
            Mode::Remove => Plan {
                add: false,
                drop: BTreeSet::from([key.to_owned()]),
            },
            // A key that is both set and replaced is kept.
            Mode::Replace(old) => Plan {
                add: true,
                drop: old.iter().filter(|k| *k != key).cloned().collect(),
            },
        }
    }

    /// The keys whose reactions must be looked up first.
    pub fn lookup(&self, key: &str) -> BTreeSet<String> {
        let mut keys = self.drop.clone();
        if self.add {
            keys.insert(key.to_owned());
        }
        keys
    }
}

/// A reaction key must contain something visible and no control characters:
/// it is shown to every member as it is.
pub fn check_key(key: &str) -> Result<()> {
    if key.trim().is_empty() {
        bail!("the reaction key is empty");
    }
    if key.chars().any(char::is_control) {
        bail!("the reaction key contains control characters");
    }
    Ok(())
}

pub async fn run(args: ReactArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    let request = request_for(&args)?;
    let outcome = match via_daemon::<ReactOutcome>(&paths, request.clone(), "reaction").await? {
        Some(outcome) => outcome,
        None => {
            let config = load_config()?;
            let _lock = paths.lock().await?;
            // Reactions are sent unencrypted (see the module comment): no room key.
            let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
            sync_once(&restored.client).await?;
            execute(&restored.client, &request).await?
        }
    };
    let skipped = outcome.skipped_unconfirmed;
    if skipped > 0 {
        eprintln!("{}", skipped_note(skipped));
    }

    if args.list {
        let found = outcome.reactions.unwrap_or_default();
        if args.json {
            println!(
                "{}",
                json_line(&json!({
                    "reactions": found,
                    "skipped_unconfirmed": skipped,
                }))?
            );
        } else {
            for reaction in &found {
                println!("{}\t{}", term(&reaction.key), term(&reaction.event_id));
            }
        }
        return Ok(());
    }
    let key = outcome.key.unwrap_or_default();
    if args.json {
        println!(
            "{}",
            json_line(&json!({
                "event_id": outcome.event_id,
                "key": key,
                "removed": outcome.removed,
                "skipped_unconfirmed": skipped,
            }))?
        );
    } else {
        if let Some(id) = &outcome.event_id {
            println!("{}", term(id));
        }
        for done in &outcome.removed {
            println!("removed\t{}\t{}", term(&done.key), term(&done.event_id));
        }
        if args.remove && outcome.removed.is_empty() {
            let event_id = parse_event_id(&args.event_id)?;
            eprintln!("no {} reaction of yours on {event_id}", term(&key));
        }
    }
    Ok(())
}

/// The request for the watch daemon. Without `--list`, `--remove` and
/// `--replace` it is matrix-watchd.py's "react" (`room`, `event_id`,
/// `key`); those three options travel as the extra fields `list`,
/// `remove` and `replace`, which only this tool's daemon reads. The
/// keys are checked as [`parse_mode`] checks them before anything is sent.
pub fn request_for(args: &ReactArgs) -> Result<Value> {
    let mut request = json!({"op": "react", "room": args.room, "event_id": args.event_id});
    if args.list {
        request["list"] = json!(true);
        return Ok(request);
    }
    let (key, _) = parse_mode(args.key.clone(), args.remove, args.replace.clone())?;
    request["key"] = json!(key);
    if args.remove {
        request["remove"] = json!(true);
    } else if let Some(old) = &args.replace {
        request["replace"] = json!(old);
    }
    Ok(request)
}

/// KEY and the mode a "react" request asks for, checked by [`parse_mode`].
fn mode_of(request: &Value) -> Result<(String, Mode)> {
    let key = request_str(request, "key")?.to_owned();
    let remove = request.get("remove").and_then(Value::as_bool) == Some(true);
    let replace = match request.get("replace").filter(|v| !v.is_null()) {
        None => None,
        Some(old) => Some(
            old.as_array()
                .context("replace must be a list of reaction keys")?
                .iter()
                .map(|k| {
                    k.as_str()
                        .map(str::to_owned)
                        .context("replace must be a list of reaction keys")
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    };
    parse_mode(Some(key), remove, replace)
}

/// What a reaction request is reported as, on the direct path and in the
/// daemon's answer: `reactions` for a list, the rest otherwise.
/// `skipped_unconfirmed` counts the annotations of the user this device
/// cannot decrypt (listed: all of them; otherwise those with a key to drop).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reactions: Option<Vec<OwnReaction>>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub removed: Vec<OwnReaction>,
    #[serde(default)]
    pub skipped_unconfirmed: usize,
}

/// Carry out a "react" request with `client`.
pub async fn execute(client: &Client, request: &Value) -> Result<ReactOutcome> {
    let room = resolve_room(client, request_str(request, "room")?).await?;
    let event_id = parse_event_id(request_str(request, "event_id")?)?;
    let own = client
        .user_id()
        .context("the client has no user id")?
        .to_owned();

    if request.get("list").and_then(Value::as_bool) == Some(true) {
        return list(&room, &event_id, own.as_str()).await;
    }

    let (key, mode) = mode_of(request)?;
    let plan = Plan::new(&key, &mode);
    if plan.add {
        let (_, target) = fetch_event(&room, &event_id).await?;
        check_reactable(&target)?;
    }
    let wanted = plan.lookup(&key);
    let lookup = own_reactions(
        &annotations(&room, &event_id).await?,
        own.as_str(),
        Some(&wanted),
    );

    let reaction_id = if plan.add {
        Some(set_key(&room, &event_id, &key, &lookup.found).await?)
    } else {
        None
    };
    let removed = remove_reactions(
        &room,
        &key,
        reaction_id.as_deref(),
        &lookup.found,
        &plan.drop,
    )
    .await?;
    Ok(ReactOutcome {
        reactions: None,
        event_id: reaction_id,
        key: Some(key),
        removed,
        skipped_unconfirmed: lookup.unconfirmed_among(&plan.drop),
    })
}

/// `--list`: the user's own confirmed reactions on the event.
async fn list(room: &Room, event_id: &EventId, own: &str) -> Result<ReactOutcome> {
    let lookup = own_reactions(&annotations(room, event_id).await?, own, None);
    Ok(ReactOutcome {
        reactions: Some(lookup.found),
        event_id: None,
        key: None,
        removed: Vec::new(),
        skipped_unconfirmed: lookup.unconfirmed.len(),
    })
}

/// KEY and the mode from the arguments. Only a key this command sends (a
/// new KEY, also the one `--replace` sets) must pass [`check_key`]; the key
/// of `--remove` and the OLD keys of `--replace` name existing reactions,
/// which another client may have set with any string, and are matched
/// exactly.
pub fn parse_mode(
    key: Option<String>,
    remove: bool,
    replace: Option<Vec<String>>,
) -> Result<(String, Mode)> {
    // clap requires KEY unless --list is given.
    let key = key.context("KEY is required unless --list is given")?;
    if remove {
        return Ok((key, Mode::Remove));
    }
    check_key(&key)?;
    Ok((key, replace.map_or(Mode::Add, Mode::Replace)))
}

/// Refuse a reaction target that is an edit (`m.replace`) or itself a
/// reaction (`m.reaction`, or any `m.annotation`): clients ignore
/// annotations on them. The relation is clear text also on an encrypted
/// event, so an undecryptable target is checked too.
pub fn check_reactable(event: &Value) -> Result<()> {
    let relation = event
        .get("content")
        .and_then(|c| c.get("m.relates_to"))
        .and_then(|r| r.get("rel_type"))
        .and_then(Value::as_str);
    if relation == Some("m.replace") {
        bail!("the event is an edit; pass the event id of the original message instead");
    }
    if relation == Some("m.annotation")
        || event.get("type").and_then(Value::as_str) == Some("m.reaction")
    {
        bail!("the event is itself a reaction; pass the event id of the original message instead");
    }
    Ok(())
}

/// Set KEY unless the user already reacted with it; the reaction's event id.
async fn set_key(
    room: &Room,
    event_id: &EventId,
    key: &str,
    found: &[OwnReaction],
) -> Result<String> {
    if let Some(existing) = found.iter().find(|r| r.key == key) {
        // A second identical annotation is rejected or duplicated; keep the first.
        return Ok(existing.event_id.clone());
    }
    let content = ReactionEventContent::new(Annotation::new(event_id.to_owned(), key.to_owned()));
    let sent = room
        .send(content)
        .await
        .context("sending the reaction failed")?;
    Ok(sent.response.event_id.to_string())
}

/// Redact the found reactions whose key is in `drop`. A failure says in
/// the error what already happened (`reaction_id`: KEY was set), since the
/// daemon's stderr is not the caller's.
async fn remove_reactions(
    room: &Room,
    key: &str,
    reaction_id: Option<&str>,
    found: &[OwnReaction],
    drop: &BTreeSet<String>,
) -> Result<Vec<OwnReaction>> {
    let mut removed: Vec<OwnReaction> = Vec::new();
    for reaction in found.iter().filter(|r| drop.contains(&r.key)) {
        let target = EventId::parse(&reaction.event_id)
            .with_context(|| format!("invalid reaction event id {:?}", reaction.event_id))?;
        if let Err(err) = room.redact(&target, None, None).await {
            // Say what already happened before the error.
            let mut done: Vec<String> = Vec::new();
            if let Some(id) = reaction_id {
                done.push(format!("set {key} ({id})"));
            }
            done.extend(
                removed
                    .iter()
                    .map(|r| format!("removed {} ({})", r.key, r.event_id)),
            );
            let done = if done.is_empty() {
                String::new()
            } else {
                format!(" (already done: {})", done.join(", "))
            };
            return Err(anyhow::Error::new(err)).with_context(|| {
                format!(
                    "could not remove {} ({}){done}",
                    reaction.key, reaction.event_id
                )
            });
        }
        removed.push(reaction.clone());
    }
    Ok(removed)
}

/// The stderr note for annotations left alone because their type is unknown.
fn skipped_note(count: usize) -> String {
    format!(
        "skipped {count} encrypted annotation(s) of yours that this device cannot decrypt: they may not be reactions, so they are neither listed nor removed (run backup-restore to import the room key)"
    )
}

/// Every annotation on `event_id` as JSON, following pagination. A failed
/// page is an error, never "no reactions".
async fn annotations(room: &Room, event_id: &EventId) -> Result<Vec<Value>> {
    let mut events = Vec::new();
    let mut from: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let options = RelationsOptions {
            from: from.take(),
            limit: Some(UInt::from(100u32)),
            include_relations: IncludeRelations::RelationsOfType(RelationType::Annotation),
            ..Default::default()
        };
        let page = room
            .relations(OwnedEventId::from(event_id), options)
            .await
            .with_context(|| format!("cannot read the reactions on {event_id}"))?;
        for event in &page.chunk {
            events.push(
                serde_json::from_str(event.raw().json().get())
                    .context("a reaction event is not valid JSON")?,
            );
        }
        match page.next_batch_token {
            Some(token) => from = Some(token),
            None => return Ok(events),
        }
    }
    bail!("more than {MAX_PAGES} pages of reactions on {event_id}")
}

/// The user's annotations on the event, split by what this device knows of
/// their type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lookup {
    /// Live `m.reaction` events (sent in clear text, or decrypted).
    pub found: Vec<OwnReaction>,
    /// The keys of live annotations this device cannot decrypt
    /// (`m.room.encrypted`): their type is unknown, so they may be other
    /// events and are never redacted.
    pub unconfirmed: Vec<String>,
}

impl Lookup {
    /// How many unconfirmed annotations carry one of `keys`.
    pub fn unconfirmed_among(&self, keys: &BTreeSet<String>) -> usize {
        self.unconfirmed
            .iter()
            .filter(|k| keys.contains(*k))
            .count()
    }
}

/// The live annotations `user_id` set on the event, from the events the
/// server lists (decrypted where this device can); only the given keys when
/// `keys` is `Some`. Only an `m.reaction` is a reaction; an annotation this
/// device cannot decrypt is listed as unconfirmed. A redacted annotation
/// counts nowhere: redacting it again would only produce a useless event.
pub fn own_reactions(events: &[Value], user_id: &str, keys: Option<&BTreeSet<String>>) -> Lookup {
    let mut lookup = Lookup::default();
    for event in events {
        if event.get("sender").and_then(Value::as_str) != Some(user_id) {
            continue;
        }
        let confirmed = match event.get("type").and_then(Value::as_str) {
            Some("m.reaction") => true,
            Some("m.room.encrypted") => false,
            _ => continue,
        };
        if super::is_redacted(event) {
            continue;
        }
        let Some(relation) = event.get("content").and_then(|c| c.get("m.relates_to")) else {
            continue;
        };
        if relation.get("rel_type").and_then(Value::as_str) != Some("m.annotation") {
            continue;
        }
        let Some(key) = relation.get("key").and_then(Value::as_str) else {
            continue;
        };
        if keys.is_some_and(|keys| !keys.contains(key)) {
            continue;
        }
        let Some(event_id) = event.get("event_id").and_then(Value::as_str) else {
            continue;
        };
        if confirmed {
            lookup.found.push(OwnReaction {
                key: key.to_owned(),
                event_id: event_id.to_owned(),
            });
        } else {
            lookup.unconfirmed.push(key.to_owned());
        }
    }
    lookup
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "@me:example.org";

    fn reaction(id: &str, sender: &str, key: &str) -> Value {
        json!({
            "type": "m.reaction", "event_id": id, "sender": sender,
            "content": {"m.relates_to": {"rel_type": "m.annotation", "event_id": "$t", "key": key}}
        })
    }

    fn keys(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|k| (*k).to_owned()).collect()
    }

    #[test]
    fn only_own_live_annotations_count() {
        let mut redacted = reaction("$r3", ME, "✅");
        redacted["unsigned"] = json!({"redacted_because": {}});
        let mut reference = reaction("$r4", ME, "✅");
        reference["content"]["m.relates_to"]["rel_type"] = json!("m.reference");
        let encrypted = json!({
            "type": "m.room.encrypted", "event_id": "$r5", "sender": ME,
            "content": {"algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x",
                        "m.relates_to": {"rel_type": "m.annotation", "event_id": "$t", "key": "▶️"}}
        });
        let message = json!({"type": "m.room.message", "event_id": "$r6", "sender": ME,
            "content": {"m.relates_to": {"rel_type": "m.annotation", "key": "✅"}}});
        let events = vec![
            reaction("$r1", ME, "✅"),
            reaction("$r2", "@other:example.org", "✅"),
            redacted,
            reference,
            encrypted,
            message,
        ];
        // The undecryptable annotation $r5 may be no reaction: never found,
        // only counted as unconfirmed.
        assert_eq!(
            own_reactions(&events, ME, None),
            Lookup {
                found: vec![OwnReaction {
                    key: "✅".into(),
                    event_id: "$r1".into()
                }],
                unconfirmed: vec!["▶️".into()],
            }
        );
        let only_play = own_reactions(&events, ME, Some(&keys(&["▶️"])));
        assert!(only_play.found.is_empty(), "{only_play:?}");
        assert_eq!(only_play.unconfirmed_among(&keys(&["▶️"])), 1);
        assert_eq!(only_play.unconfirmed_among(&keys(&["✅"])), 0);
        assert_eq!(
            own_reactions(&events, ME, Some(&keys(&["🩹"]))),
            Lookup::default()
        );
    }

    #[test]
    fn a_decrypted_reaction_counts() {
        // relations() decrypts what it can; a decrypted reaction reads m.reaction.
        let events = vec![reaction("$r1", ME, "▶️")];
        assert_eq!(own_reactions(&events, ME, None).found.len(), 1);
    }

    #[test]
    fn keys_are_compared_exactly() {
        // "✅" with and without a variation selector are different keys.
        let events = vec![reaction("$r1", ME, "✔\u{fe0f}")];
        assert_eq!(
            own_reactions(&events, ME, Some(&keys(&["✔"]))),
            Lookup::default()
        );
    }

    #[test]
    fn plans_for_each_mode() {
        assert_eq!(
            Plan::new("✅", &Mode::Add),
            Plan {
                add: true,
                drop: keys(&[])
            }
        );
        assert_eq!(
            Plan::new("✅", &Mode::Remove),
            Plan {
                add: false,
                drop: keys(&["✅"])
            }
        );
        let swap = Plan::new(
            "✅",
            &Mode::Replace(vec!["▶️".into(), "✅".into(), "🩹".into()]),
        );
        // The key being set is never removed by its own swap.
        assert_eq!(
            swap,
            Plan {
                add: true,
                drop: keys(&["▶️", "🩹"])
            }
        );
        assert_eq!(swap.lookup("✅"), keys(&["▶️", "✅", "🩹"]));
        assert_eq!(Plan::new("✅", &Mode::Remove).lookup("✅"), keys(&["✅"]));
    }

    #[test]
    fn the_daemon_request_checks_keys_as_parse_mode_does() {
        let args = |key: &str, remove: bool, replace: Option<Vec<String>>| ReactArgs {
            room: "!r:e".into(),
            event_id: "$e".into(),
            key: Some(key.into()),
            remove,
            replace,
            list: false,
            json: false,
        };
        // --remove and the OLD keys of --replace name existing reactions.
        let request = request_for(&args("a\nb", true, None)).unwrap();
        assert_eq!(
            mode_of(&request).unwrap(),
            ("a\nb".to_owned(), Mode::Remove)
        );
        let request = request_for(&args("✅", false, Some(vec!["a\nb".into()]))).unwrap();
        assert_eq!(
            mode_of(&request).unwrap(),
            ("✅".to_owned(), Mode::Replace(vec!["a\nb".into()]))
        );
        // A KEY that is sent is checked on both sides of the socket.
        assert!(request_for(&args("a\nb", false, None)).is_err());
        assert!(mode_of(&json!({"key": "a\nb"})).is_err());
        assert!(mode_of(&json!({"key": "a\nb", "replace": ["✅"]})).is_err());
        assert_eq!(
            mode_of(&json!({"key": "✅"})).unwrap(),
            ("✅".to_owned(), Mode::Add)
        );
    }

    #[test]
    fn only_keys_that_are_sent_are_checked() {
        let odd = || Some("a\nb".to_owned());
        // --remove names an existing reaction: matched exactly, never checked.
        assert_eq!(
            parse_mode(odd(), true, None).unwrap(),
            ("a\nb".to_owned(), Mode::Remove)
        );
        // OLD keys of --replace are existing reactions too.
        assert_eq!(
            parse_mode(Some("✅".into()), false, Some(vec!["a\nb".into()])).unwrap(),
            ("✅".to_owned(), Mode::Replace(vec!["a\nb".into()]))
        );
        // A new KEY is sent, in both add and replace mode.
        assert!(parse_mode(odd(), false, None).is_err());
        assert!(parse_mode(odd(), false, Some(vec!["✅".into()])).is_err());
        assert!(parse_mode(None, false, None).is_err());
        assert_eq!(
            parse_mode(Some("✅".into()), false, None).unwrap(),
            ("✅".to_owned(), Mode::Add)
        );
    }

    #[test]
    fn edits_and_reactions_are_no_reaction_targets() {
        let message =
            json!({"type": "m.room.message", "content": {"msgtype": "m.text", "body": "hi"}});
        assert!(check_reactable(&message).is_ok());
        let thread_reply = json!({"type": "m.room.message", "content": {"msgtype": "m.text", "body": "hi",
            "m.relates_to": {"rel_type": "m.thread", "event_id": "$root"}}});
        assert!(check_reactable(&thread_reply).is_ok());
        let undecryptable = json!({"type": "m.room.encrypted", "content": {"ciphertext": "x"}});
        assert!(check_reactable(&undecryptable).is_ok());

        let edit = json!({"type": "m.room.message", "content": {"msgtype": "m.text", "body": "* hi",
            "m.relates_to": {"rel_type": "m.replace", "event_id": "$o"}}});
        let err = check_reactable(&edit).unwrap_err().to_string();
        assert!(err.contains("edit") && err.contains("original"), "{err}");
        let encrypted_edit = json!({"type": "m.room.encrypted", "content": {"ciphertext": "x",
            "m.relates_to": {"rel_type": "m.replace", "event_id": "$o"}}});
        assert!(check_reactable(&encrypted_edit).is_err());
        let err = check_reactable(&reaction("$r", ME, "✅"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("reaction") && err.contains("original"),
            "{err}"
        );
        let encrypted_annotation = json!({"type": "m.room.encrypted", "content": {"ciphertext": "x",
            "m.relates_to": {"rel_type": "m.annotation", "event_id": "$o", "key": "✅"}}});
        assert!(check_reactable(&encrypted_annotation).is_err());
    }

    #[test]
    fn empty_and_control_keys_are_refused() {
        assert!(check_key("✅").is_ok());
        assert!(check_key("👍🏽").is_ok());
        assert!(check_key("").is_err());
        assert!(check_key("  ").is_err());
        assert!(check_key("a\u{1b}[2J").is_err());
        assert!(check_key("a\nb").is_err());
    }
}
