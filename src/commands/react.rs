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
//! reaction's event id.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use matrix_sdk::Room;
use matrix_sdk::room::{IncludeRelations, RelationsOptions};
use matrix_sdk::ruma::events::reaction::ReactionEventContent;
use matrix_sdk::ruma::events::relation::{Annotation, RelationType};
use matrix_sdk::ruma::{EventId, OwnedEventId, UInt};
use serde::Serialize;
use serde_json::{Value, json};

use crate::ReactArgs;
use crate::commands::{parse_event_id, resolve_room, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{json_line, term};

/// Guard against a server that never stops paging (100 reactions a page).
const MAX_PAGES: usize = 50;

/// One live reaction of the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    // Reactions are sent unencrypted (see the module comment): no room key.
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let room = resolve_room(&client, &args.room).await?;
    let event_id = parse_event_id(&args.event_id)?;
    let own = client
        .user_id()
        .context("the client has no user id")?
        .to_owned();

    if args.list {
        let found = own_reactions(&annotations(&room, &event_id).await?, own.as_str(), None);
        if args.json {
            println!("{}", json_line(&json!({ "reactions": found }))?);
        } else {
            for reaction in &found {
                println!("{}\t{}", term(&reaction.key), term(&reaction.event_id));
            }
        }
        return Ok(());
    }

    // clap requires KEY unless --list is given.
    let key = args.key.context("KEY is required unless --list is given")?;
    check_key(&key)?;
    let mode = if args.remove {
        Mode::Remove
    } else if let Some(old) = args.replace {
        for k in &old {
            check_key(k)?;
        }
        Mode::Replace(old)
    } else {
        Mode::Add
    };
    let plan = Plan::new(&key, &mode);
    let wanted = plan.lookup(&key);
    let found = own_reactions(
        &annotations(&room, &event_id).await?,
        own.as_str(),
        Some(&wanted),
    );

    let mut reaction_id: Option<String> = None;
    if plan.add {
        if let Some(existing) = found.iter().find(|r| r.key == key) {
            // A second identical annotation is rejected or duplicated; keep the first.
            reaction_id = Some(existing.event_id.clone());
        } else {
            let content = ReactionEventContent::new(Annotation::new(event_id.clone(), key.clone()));
            let sent = room
                .send(content)
                .await
                .context("sending the reaction failed")?;
            reaction_id = Some(sent.response.event_id.to_string());
        }
    }

    let mut removed: Vec<OwnReaction> = Vec::new();
    for reaction in found.iter().filter(|r| plan.drop.contains(&r.key)) {
        let target = EventId::parse(&reaction.event_id)
            .with_context(|| format!("invalid reaction event id {:?}", reaction.event_id))?;
        if let Err(err) = room.redact(&target, None, None).await {
            // Say what already happened before the error.
            if let Some(id) = &reaction_id {
                eprintln!("set: {} ({})", term(&key), term(id));
            }
            for done in &removed {
                eprintln!("removed: {} ({})", term(&done.key), term(&done.event_id));
            }
            return Err(anyhow::Error::new(err)).with_context(|| {
                format!("could not remove {} ({})", reaction.key, reaction.event_id)
            });
        }
        removed.push(reaction.clone());
    }

    if args.json {
        println!(
            "{}",
            json_line(&json!({"event_id": reaction_id, "key": key, "removed": removed}))?
        );
    } else {
        if let Some(id) = &reaction_id {
            println!("{}", term(id));
        }
        for done in &removed {
            println!("removed\t{}\t{}", term(&done.key), term(&done.event_id));
        }
        if mode == Mode::Remove && removed.is_empty() {
            eprintln!("no {} reaction of yours on {event_id}", term(&key));
        }
    }
    Ok(())
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

/// The live reactions `user_id` set on the event, from the annotation events
/// the server lists; only the given keys when `keys` is `Some`. An
/// encrypted reaction (`m.room.encrypted`, sent by other clients) carries
/// `m.relates_to` in clear text and counts too. A redacted reaction does not:
/// redacting it again would only produce a useless event.
pub fn own_reactions(
    events: &[Value],
    user_id: &str,
    keys: Option<&BTreeSet<String>>,
) -> Vec<OwnReaction> {
    events
        .iter()
        .filter_map(|event| {
            if event.get("sender").and_then(Value::as_str) != Some(user_id) {
                return None;
            }
            let event_type = event.get("type").and_then(Value::as_str)?;
            if event_type != "m.reaction" && event_type != "m.room.encrypted" {
                return None;
            }
            if event
                .get("unsigned")
                .and_then(|u| u.get("redacted_because"))
                .is_some()
            {
                return None;
            }
            let relation = event.get("content")?.get("m.relates_to")?;
            if relation.get("rel_type").and_then(Value::as_str) != Some("m.annotation") {
                return None;
            }
            let key = relation.get("key").and_then(Value::as_str)?;
            if keys.is_some_and(|keys| !keys.contains(key)) {
                return None;
            }
            let event_id = event.get("event_id").and_then(Value::as_str)?;
            Some(OwnReaction {
                key: key.to_owned(),
                event_id: event_id.to_owned(),
            })
        })
        .collect()
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
        assert_eq!(
            own_reactions(&events, ME, None),
            vec![
                OwnReaction {
                    key: "✅".into(),
                    event_id: "$r1".into()
                },
                OwnReaction {
                    key: "▶️".into(),
                    event_id: "$r5".into()
                },
            ]
        );
        assert_eq!(
            own_reactions(&events, ME, Some(&keys(&["▶️"]))),
            vec![OwnReaction {
                key: "▶️".into(),
                event_id: "$r5".into()
            }]
        );
        assert!(own_reactions(&events, ME, Some(&keys(&["🩹"]))).is_empty());
    }

    #[test]
    fn keys_are_compared_exactly() {
        // "✅" with and without a variation selector are different keys.
        let events = vec![reaction("$r1", ME, "✔\u{fe0f}")];
        assert!(own_reactions(&events, ME, Some(&keys(&["✔"]))).is_empty());
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
    fn empty_and_control_keys_are_refused() {
        assert!(check_key("✅").is_ok());
        assert!(check_key("👍🏽").is_ok());
        assert!(check_key("").is_err());
        assert!(check_key("  ").is_err());
        assert!(check_key("a\u{1b}[2J").is_err());
        assert!(check_key("a\nb").is_err());
    }
}
