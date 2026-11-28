//! `rooms`: the joined rooms with name, alias and room id, at parity
//! with the matrix-skill's matrix-rooms.py and the helpers of its
//! _lib/rooms.py: a room without a name or alias is named after its members
//! as Element and matrix-nio name a direct chat, `--search` filters by name,
//! alias or member, `--lookup` finds one room (find_room_by_name).
//!
//! The list comes from the store after one sync (from the watch daemon's
//! store while it runs), not from one request per room as in the script.
//! The members of a room named after them are fetched from the server once
//! per room (`Room::members`) and kept in the store.

use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use matrix_sdk::{Client, RoomMemberships};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::RoomsArgs;
use crate::commands::{sync_once, via_daemon};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{python_json, term};

/// matrix-nio's MatrixRoom.group_name() lists at most this many members by name.
const GROUP_NAME_HEROES: usize = 5;

/// How many member lists [`execute`] fetches at once.
const MEMBER_FETCHES: usize = 8;

pub async fn run(args: RoomsArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    // The request the watch daemon takes; the direct path executes the same.
    let request = json!({"op": "rooms"});
    let outcome = match via_daemon::<RoomsOutcome>(&paths, request.clone(), "room list").await? {
        Some(outcome) => outcome,
        None => {
            let config = load_config()?;
            let _lock = paths.lock().await?;
            let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
            sync_once(&restored.client).await?;
            execute(&restored.client, &request).await?
        }
    };
    for warning in &outcome.warnings {
        eprintln!("warning: {}", term(warning));
    }
    print!("{}", render(&args, &outcome.rooms)?);
    Ok(())
}

/// One joined room as list_joined_rooms() describes it, with its keys in
/// the script's order. `members` only for a room named after its members:
/// the user ids it was named from, sorted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinedRoom {
    pub room_id: String,
    pub name: String,
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
}

/// The joined rooms, sorted by room id; on the direct path and in the
/// daemon's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomsOutcome {
    pub rooms: Vec<JoinedRoom>,
    /// Printed to stderr as "warning: ...".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// A joined or invited member of a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub user_id: String,
    pub display_name: Option<String>,
}

/// List the joined rooms of `client`'s store. The member lists of rooms
/// named after their members are fetched [`MEMBER_FETCHES`] at a time: in
/// the watch daemon this runs under the operation lock, and one request
/// after another could keep a queued send waiting past its caller's
/// deadline.
pub async fn execute(client: &Client, _request: &Value) -> Result<RoomsOutcome> {
    let own = client
        .user_id()
        .context("the client has no user id")?
        .to_string();
    let mut joined = client.joined_rooms();
    joined.sort_by(|a, b| a.room_id().cmp(b.room_id()));
    // buffered, not buffer_unordered: the results come in room id order.
    let looked_up: Vec<_> = futures_util::stream::iter(joined.iter().cloned())
        .map(|room: matrix_sdk::Room| async move {
            let name = room.name();
            let alias = room.canonical_alias().map(|a| a.to_string());
            let named = name.as_deref().is_some_and(|n| !n.is_empty()) || alias.is_some();
            let members = if named {
                None
            } else {
                Some(
                    room.members(RoomMemberships::JOIN | RoomMemberships::INVITE)
                        .await
                        .map(|members| {
                            members
                                .iter()
                                .map(|m| Member {
                                    user_id: m.user_id().to_string(),
                                    display_name: m.display_name().map(str::to_owned),
                                })
                                .collect::<Vec<_>>()
                        }),
                )
            };
            (room, name, alias, members)
        })
        .buffered(MEMBER_FETCHES)
        .collect()
        .await;
    let mut rooms = Vec::with_capacity(looked_up.len());
    let mut warnings = Vec::new();
    for (room, name, alias, members) in looked_up {
        let members = match members {
            None => None,
            Some(Ok(members)) => Some(members),
            Some(Err(err)) => {
                warnings.push(format!(
                    "cannot read the members of {}, listed under its room id: {err}",
                    room.room_id()
                ));
                None
            }
        };
        rooms.push(joined_room(
            room.room_id().as_str(),
            name.as_deref(),
            alias.as_deref(),
            members.as_deref(),
            &own,
        ));
    }
    Ok(RoomsOutcome { rooms, warnings })
}

/// The entry list_joined_rooms() makes of one room: its name, else its
/// alias, else a name after its members (`None`: they could not be read,
/// and the room goes by its id rather than "Empty Room").
pub fn joined_room(
    room_id: &str,
    name: Option<&str>,
    alias: Option<&str>,
    members: Option<&[Member]>,
    own: &str,
) -> JoinedRoom {
    let shown = name
        .filter(|n| !n.is_empty())
        .or(alias.filter(|a| !a.is_empty()));
    let alias = alias.map(str::to_owned);
    match (shown, members) {
        (Some(shown), _) => JoinedRoom {
            room_id: room_id.to_owned(),
            name: shown.to_owned(),
            alias,
            members: None,
        },
        (None, None) => JoinedRoom {
            room_id: room_id.to_owned(),
            name: room_id.to_owned(),
            alias,
            members: None,
        },
        (None, Some(members)) => {
            let named = member_names(members, own);
            let mut ids: Vec<String> = named.iter().map(|(id, _)| id.clone()).collect();
            ids.sort();
            JoinedRoom {
                room_id: room_id.to_owned(),
                name: group_name(named.into_iter().map(|(_, name)| name).collect()),
                alias,
                members: Some(ids),
            }
        }
    }
}

/// get_room_members(): each member except `own` with the name it is shown
/// by, its display name or else its user id. A display name that two
/// members share, `own` included, becomes "Name (@user:server)".
pub fn member_names(members: &[Member], own: &str) -> Vec<(String, String)> {
    // How many members, `own` included, are shown by each name.
    let mut taken: HashMap<&str, usize> = HashMap::new();
    for m in members {
        let shown = m
            .display_name
            .as_deref()
            .filter(|n| !n.is_empty())
            .unwrap_or(&m.user_id);
        *taken.entry(shown).or_default() += 1;
    }
    members
        .iter()
        .filter(|m| m.user_id != own)
        .map(|m| {
            let name = match m.display_name.as_deref().filter(|n| !n.is_empty()) {
                Some(name) if taken[name] > 1 => format!("{name} ({})", m.user_id),
                Some(name) => name.to_owned(),
                None => m.user_id.clone(),
            };
            (m.user_id.clone(), name)
        })
        .collect()
}

/// group_name(): the other members' names, sorted ignoring case: "A",
/// "A and B", "A, B and C", "A, B, C, D, E and 2 others", or "Empty Room".
pub fn group_name(mut names: Vec<String>) -> String {
    names.sort_by_cached_key(|n| n.to_lowercase());
    let others = names.len().saturating_sub(GROUP_NAME_HEROES);
    names.truncate(GROUP_NAME_HEROES);
    match names.as_slice() {
        [] => "Empty Room".to_owned(),
        _ if others > 0 => format!(
            "{} and {others} other{}",
            names.join(", "),
            if others == 1 { "" } else { "s" }
        ),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// room_matches(): with `exact` the name, or a member's user id; without it
/// a part of the name, the alias or a member's user id. `search_lower` is in
/// lower case already.
pub fn room_matches(room: &JoinedRoom, search_lower: &str, exact: bool) -> bool {
    let members: Vec<String> = room
        .members
        .iter()
        .flatten()
        .map(|m| m.to_lowercase())
        .collect();
    if exact {
        return room.name.to_lowercase() == search_lower
            || members.iter().any(|m| m == search_lower);
    }
    room.name.to_lowercase().contains(search_lower)
        || room
            .alias
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains(search_lower)
        || members.iter().any(|m| m.contains(search_lower))
}

/// find_room_by_name(): the room `term` names, and the candidates. In order:
/// the exact alias, the alias without its server, one exact name (a room
/// without an alias only when no other room someone named contains the
/// term), one partial match. No room: the candidates explain why.
pub fn find_room_by_name<'a>(
    rooms: &'a [JoinedRoom],
    term: &str,
) -> (Option<&'a JoinedRoom>, Vec<&'a JoinedRoom>) {
    let lower = term.to_lowercase();
    if let Some(room) = rooms
        .iter()
        .find(|r| alias_shown(r).is_some_and(|a| a.to_lowercase() == lower))
    {
        return (Some(room), vec![room]);
    }
    if let Some(room) = rooms.iter().find(|r| {
        alias_shown(r).is_some_and(|a| {
            a.split(':')
                .next()
                .unwrap_or_default()
                .trim_start_matches('#')
                .to_lowercase()
                == lower
        })
    }) {
        return (Some(room), vec![room]);
    }
    let exact: Vec<&JoinedRoom> = rooms
        .iter()
        .filter(|r| room_matches(r, &lower, true))
        .collect();
    match exact.as_slice() {
        [room] if alias_shown(room).is_some() => return (Some(*room), exact.clone()),
        [room] => {
            // Only names someone gave a room compete; a name made up from
            // members does not.
            let alternatives: Vec<&JoinedRoom> = rooms
                .iter()
                .filter(|r| {
                    r.room_id != room.room_id
                        && r.members.is_none()
                        && r.name.to_lowercase().contains(&lower)
                })
                .collect();
            if alternatives.is_empty() {
                return (Some(*room), exact.clone());
            }
            return (None, [exact.clone(), alternatives].concat());
        }
        [] => {}
        _ => return (None, exact),
    }
    let partial: Vec<&JoinedRoom> = rooms
        .iter()
        .filter(|r| room_matches(r, &lower, false))
        .collect();
    match partial.as_slice() {
        [room] => (Some(*room), partial.clone()),
        _ => (None, partial),
    }
}

/// What matrix-rooms.py prints on stdout for `rooms` (sorted by room id), or
/// its error for a lookup that finds no single room. The script's error
/// lists the candidates on lines of their own; here they follow on the
/// error's one line, separated by "; ".
pub fn render(args: &RoomsArgs, rooms: &[JoinedRoom]) -> Result<String> {
    if let Some(wanted) = args.lookup.as_deref().filter(|l| !l.is_empty()) {
        let (found, matches) = find_room_by_name(rooms, wanted);
        if let Some(room) = found {
            return Ok(if args.json {
                python_json(room)? + "\n"
            } else {
                format!("{}\n", term(&room.room_id))
            });
        }
        if matches.is_empty() {
            bail!("No room found matching '{wanted}'");
        }
        let listed = matches
            .iter()
            .map(|m| match alias_shown(m) {
                Some(alias) => format!("{} ({alias}): {}", m.name, m.room_id),
                None => format!("{}: {}", m.name, m.room_id),
            })
            .collect::<Vec<_>>()
            .join("; ");
        bail!(
            "Ambiguous match for '{wanted}'. Found {} rooms: {listed}",
            matches.len()
        );
    }
    let mut shown: Vec<&JoinedRoom> = rooms.iter().collect();
    shown.sort_by_cached_key(|r| r.name.to_lowercase());
    if let Some(search) = args.search.as_deref().filter(|s| !s.is_empty()) {
        let search = search.to_lowercase();
        shown.retain(|r| room_matches(r, &search, false));
    }
    if args.json {
        return Ok(python_json(&shown)? + "\n");
    }
    if shown.is_empty() {
        return Ok("No rooms found\n".to_owned());
    }
    let mut out = format!("{:<40} {:<35} {}\n", "Room Name", "Alias", "Room ID");
    out.push_str(&"-".repeat(120));
    out.push('\n');
    for room in shown {
        let name: String = term(&room.name).chars().take(38).collect();
        let alias: String = term(alias_shown(room).unwrap_or_default())
            .chars()
            .take(33)
            .collect();
        writeln!(out, "{name:<40} {alias:<35} {}", term(&room.room_id))?;
    }
    Ok(out)
}

/// The alias as the script shows it: an empty one is none.
fn alias_shown(room: &JoinedRoom) -> Option<&str> {
    room.alias.as_deref().filter(|a| !a.is_empty())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;

    /// tests/fixtures/room_cmds/expected.json, written by generate.py from
    /// the matrix-skill's scripts at 3db40d3.
    pub fn fixture() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/room_cmds/expected.json")).unwrap()
    }

    fn args(argv: &[&str]) -> RoomsArgs {
        let cli = Cli::try_parse_from([&["m", "rooms"][..], argv].concat()).unwrap();
        let Command::Rooms(args) = cli.command else {
            panic!("not rooms")
        };
        args
    }

    /// The corpus rooms as matrix-rooms.py --json lists them (in the order
    /// of /joined_rooms, which is room id order in the corpus).
    fn python_rooms(fixture: &Value) -> Vec<JoinedRoom> {
        let case = fixture["rooms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["argv"] == json!(["--json"]) && c["rooms"] == "corpus")
            .unwrap();
        let mut rooms: Vec<JoinedRoom> =
            serde_json::from_str(case["stdout"].as_str().unwrap()).unwrap();
        rooms.sort_by(|a, b| a.room_id.cmp(&b.room_id));
        rooms
    }

    /// The members of a corpus room as Room::members(JOIN | INVITE) returns them.
    fn corpus_members(room: &Value) -> Option<Vec<Member>> {
        let chunk = room.get("members")?.as_array()?;
        Some(
            chunk
                .iter()
                .filter(|m| matches!(m["content"]["membership"].as_str(), Some("join" | "invite")))
                .map(|m| Member {
                    user_id: m["state_key"].as_str().unwrap().to_owned(),
                    display_name: m["content"]["displayname"].as_str().map(str::to_owned),
                })
                .collect(),
        )
    }

    #[test]
    fn entries_are_list_joined_rooms_s() {
        let fixture = fixture();
        let me = fixture["me"].as_str().unwrap();
        let mut built: Vec<JoinedRoom> = fixture["rooms_corpus"]
            .as_array()
            .unwrap()
            .iter()
            .map(|room| {
                joined_room(
                    room["room_id"].as_str().unwrap(),
                    room["name"].as_str(),
                    room["alias"].as_str(),
                    corpus_members(room).as_deref(),
                    me,
                )
            })
            .collect();
        built.sort_by(|a, b| a.room_id.cmp(&b.room_id));
        assert_eq!(built, python_rooms(&fixture));
    }

    #[test]
    fn member_names_count_the_own_account() {
        // python3, _lib/rooms.py get_room_members() at 3db40d3 for these
        // members with user_id @me:e:
        // {'@jane:e': 'Jane (@jane:e)', '@x:e': 'X', '@y:e': '@y:e'}
        let member = |id: &str, name: Option<&str>| Member {
            user_id: id.into(),
            display_name: name.map(str::to_owned),
        };
        let members = [
            member("@me:e", Some("Jane")),
            member("@jane:e", Some("Jane")),
            member("@x:e", Some("X")),
            member("@y:e", None),
        ];
        let pair = |id: &str, name: &str| (id.to_owned(), name.to_owned());
        assert_eq!(
            member_names(&members, "@me:e"),
            [
                pair("@jane:e", "Jane (@jane:e)"),
                pair("@x:e", "X"),
                pair("@y:e", "@y:e")
            ]
        );
    }

    /// Eight unnamed rooms whose /members answers take 400 to 190 ms, one
    /// of them refused.
    #[tokio::test]
    async fn member_lists_are_fetched_side_by_side_in_room_order() {
        use std::time::Duration;
        let server = crate::mock_homeserver::MockHomeserver::start();
        let ids: Vec<String> = (0..8).map(|i| format!("!r{i}:example.org")).collect();
        let join: serde_json::Map<String, Value> =
            ids.iter().map(|id| (id.clone(), json!({}))).collect();
        server.route(
            "GET",
            "/_matrix/client/v3/sync",
            200,
            &json!({"next_batch": "s1", "rooms": {"join": join}}).to_string(),
        );
        for (i, id) in ids.iter().enumerate() {
            let path = format!("/_matrix/client/v3/rooms/{id}/members");
            // Later rooms answer sooner: completion order is the reverse of
            // room order.
            let delay = Duration::from_millis(400 - 30 * i as u64);
            if i == 5 {
                server.route_delayed(
                    "GET",
                    &path,
                    403,
                    r#"{"errcode": "M_FORBIDDEN", "error": "no"}"#,
                    delay,
                );
                continue;
            }
            let other = format!("@u{i}:example.org");
            let chunk = json!({"chunk": [{"type": "m.room.member", "state_key": other, "room_id": id,
                "sender": other, "event_id": format!("$m{i}"), "origin_server_ts": 1,
                "content": {"membership": "join", "displayname": format!("User {i}")}}]});
            server.route_delayed("GET", &path, 200, &chunk.to_string(), delay);
        }
        let client = server.client("@me:example.org").await;
        sync_once(&client).await.unwrap();
        let outcome = execute(&client, &json!({"op": "rooms"})).await.unwrap();
        assert!(
            server.most_in_flight() > 1,
            "the member lists were fetched one after another"
        );
        let names: Vec<(&str, &str)> = outcome
            .rooms
            .iter()
            .map(|r| (r.room_id.as_str(), r.name.as_str()))
            .collect();
        let expected: Vec<(String, String)> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                (
                    id.clone(),
                    if i == 5 {
                        id.clone()
                    } else {
                        format!("User {i}")
                    },
                )
            })
            .collect();
        let expected: Vec<(&str, &str)> = expected
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        assert_eq!(names, expected);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert!(
            outcome.warnings[0].contains("!r5:example.org"),
            "{:?}",
            outcome.warnings
        );
    }

    #[test]
    fn group_names_follow_matrix_nio() {
        let names = |n: &[&str]| group_name(n.iter().map(|s| (*s).to_owned()).collect());
        assert_eq!(names(&[]), "Empty Room");
        assert_eq!(names(&["Jane"]), "Jane");
        assert_eq!(names(&["b", "A"]), "A and b");
        assert_eq!(names(&["c", "B", "a"]), "a, B and c");
        assert_eq!(
            names(&["f", "e", "d", "c", "b", "a"]),
            "a, b, c, d, e and 1 other"
        );
        assert_eq!(
            names(&["g", "f", "e", "d", "c", "b", "a"]),
            "a, b, c, d, e and 2 others"
        );
    }

    /// Python's stderr for a failed lookup as this command's one error line.
    fn one_line(stderr: &str) -> String {
        let mut lines = stderr.lines();
        let first = lines.next().unwrap().strip_prefix("Error: ").unwrap();
        let listed: Vec<&str> = lines.map(|l| l.strip_prefix("  - ").unwrap()).collect();
        if listed.is_empty() {
            first.to_owned()
        } else {
            format!("{first} {}", listed.join("; "))
        }
    }

    #[test]
    fn output_is_matrix_rooms_py_s() {
        let fixture = fixture();
        let corpus = python_rooms(&fixture);
        let mut checked = 0;
        for case in fixture["rooms"].as_array().unwrap() {
            let argv: Vec<&str> = case["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            let rooms = if case["rooms"] == "corpus" {
                &corpus[..]
            } else {
                &[]
            };
            let rendered = render(&args(&argv), rooms);
            if case["exit"] == 0 {
                assert_eq!(
                    rendered.unwrap(),
                    case["stdout"].as_str().unwrap(),
                    "{argv:?}"
                );
            } else {
                assert_eq!(case["stdout"], "", "{argv:?}");
                let err = rendered.unwrap_err().to_string();
                assert_eq!(err, one_line(case["stderr"].as_str().unwrap()), "{argv:?}");
            }
            checked += 1;
        }
        assert_eq!(checked, 28);
    }

    /// The rooms of the corpus as a homeserver serves them: name and alias
    /// in the sync, the members from /members (403 for a room whose
    /// members cannot be read).
    pub fn serve_corpus(server: &crate::mock_homeserver::MockHomeserver, fixture: &Value) {
        let mut join = serde_json::Map::new();
        for (i, room) in fixture["rooms_corpus"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let id = room["room_id"].as_str().unwrap();
            let state = |kind: &str, content: Value, n: usize| {
                json!({"type": kind, "state_key": "", "sender": "@me:example.org",
                       "event_id": format!("$s{i}-{n}"), "origin_server_ts": 1, "content": content})
            };
            let mut events = Vec::new();
            if let Some(name) = room.get("name") {
                events.push(state("m.room.name", json!({"name": name}), 0));
            }
            if let Some(alias) = room.get("alias") {
                events.push(state("m.room.canonical_alias", json!({"alias": alias}), 1));
            }
            join.insert(id.to_owned(), json!({"state": {"events": events}}));
            let path = format!("/_matrix/client/v3/rooms/{id}/members");
            match room.get("members").and_then(Value::as_array) {
                None => {
                    server.route(
                        "GET",
                        &path,
                        403,
                        r#"{"errcode": "M_FORBIDDEN", "error": "forbidden"}"#,
                    );
                }
                Some(chunk) => {
                    let chunk: Vec<Value> = chunk
                        .iter()
                        .enumerate()
                        .map(|(n, m)| {
                            json!({"type": "m.room.member", "state_key": m["state_key"],
                                   "room_id": id, "sender": m["state_key"], "event_id": format!("$m{i}-{n}"),
                                   "origin_server_ts": 1, "content": m["content"]})
                        })
                        .collect();
                    server.route("GET", &path, 200, &json!({"chunk": chunk}).to_string());
                }
            }
        }
        server.route(
            "GET",
            "/_matrix/client/v3/sync",
            200,
            &json!({"next_batch": "s1", "rooms": {"join": join}}).to_string(),
        );
    }

    #[tokio::test]
    async fn execute_lists_the_rooms_of_the_store_as_the_script_does() {
        let fixture = fixture();
        let server = crate::mock_homeserver::MockHomeserver::start();
        serve_corpus(&server, &fixture);
        let client = server.client(fixture["me"].as_str().unwrap()).await;
        sync_once(&client).await.unwrap();
        let outcome = execute(&client, &json!({"op": "rooms"})).await.unwrap();
        assert_eq!(outcome.rooms, python_rooms(&fixture));
        // The one room whose members cannot be read is named, not hidden.
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert!(
            outcome.warnings[0].contains("!g:example.org"),
            "{:?}",
            outcome.warnings
        );
    }

    #[test]
    fn the_json_carries_what_room_lookup_reads() {
        // _lib/room_lookup.py's choose() and room_matches() read room_id,
        // name, alias and members.
        let room = JoinedRoom {
            room_id: "!d:e".into(),
            name: "Jane".into(),
            alias: None,
            members: Some(vec!["@jane:e".into()]),
        };
        let shown: Value = serde_json::from_str(&python_json(&room).unwrap()).unwrap();
        assert_eq!(
            shown,
            json!({"room_id": "!d:e", "name": "Jane", "alias": null, "members": ["@jane:e"]})
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_daemon_path_returns_the_rooms_of_the_direct_path() {
        use crate::commands::via_daemon_at;
        use crate::daemon_test_support::FakeDaemon;
        let rooms = python_rooms(&fixture());
        let fake = FakeDaemon::start(Some(json!({"ok": true, "rooms": rooms})));
        let outcome =
            via_daemon_at::<RoomsOutcome>(&fake.path, json!({"op": "rooms"}), "room list")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(fake.received(), json!({"op": "rooms"}));
        assert_eq!(outcome.rooms, rooms);
        assert!(outcome.warnings.is_empty());
    }
}
