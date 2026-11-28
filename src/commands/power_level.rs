//! `power-level`: show, read or set a user's power level, at parity with the
//! matrix-skill's matrix-power-level.py.
//!
//! The power levels are one state event. `--show` and `--get` read it live from
//! the server; `--set` reads it live, changes the one user's entry and writes
//! the whole content back (a PUT replaces it all), keeping every other key
//! and the order of the keys as the server sent them. A missing user falls
//! back to `users_default`, and that to 0. Nothing is checked locally: the
//! homeserver refuses a level above the acting user's, and, in room
//! version 12, any entry for a room creator in `users` ("Creator user must
//! not appear in content.users"), and that refusal is the error shown.

use anyhow::{Context, Result, anyhow, bail};
use matrix_sdk::Client;
use matrix_sdk::ruma::api::client::state::get_state_event_for_key;
use matrix_sdk::ruma::events::StateEventType;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::PowerLevelArgs;
use crate::commands::send::request_str;
use crate::commands::{resolve_room, server_message, sync_once, via_daemon};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{python_json, python_json_line, term};

/// What the command does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Show,
    Get(String),
    Set(String, i64),
}

pub async fn run(args: PowerLevelArgs) -> Result<()> {
    let action = action(&args)?;
    let paths = Paths::from_env()?;
    let request = level_request(&args.room, &action);
    let outcome =
        match via_daemon::<PowerLevelOutcome>(&paths, request.clone(), "power level request")
            .await?
        {
            Some(outcome) => outcome,
            None => {
                let config = load_config()?;
                let _lock = paths.lock().await?;
                let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
                sync_once(&restored.client).await?;
                execute(&restored.client, &request).await?
            }
        };
    print!("{}", render(&args, &action, &outcome)?);
    Ok(())
}

/// The action of the arguments; LEVEL is an integer as Python's int()
/// reads one (surrounding whitespace and a sign allowed).
pub fn action(args: &PowerLevelArgs) -> Result<Action> {
    if let Some(user) = &args.get {
        return Ok(Action::Get(user.clone()));
    }
    match args.set.as_deref() {
        Some([user, level]) => {
            let parsed = level
                .trim()
                .parse::<i64>()
                .map_err(|_| anyhow!("LEVEL must be an integer, got '{level}'"))?;
            Ok(Action::Set(user.clone(), parsed))
        }
        Some(_) => bail!("--set takes USER_ID and LEVEL"),
        None => Ok(Action::Show),
    }
}

/// The "power_levels" request the watch daemon takes.
pub fn level_request(room: &str, action: &Action) -> Value {
    match action {
        Action::Show => json!({"op": "power_levels", "room": room, "action": "show"}),
        Action::Get(user) => {
            json!({"op": "power_levels", "room": room, "action": "get", "user_id": user})
        }
        Action::Set(user, level) => json!({"op": "power_levels", "room": room, "action": "set",
            "user_id": user, "level": level}),
    }
}

/// The room and either the content read (show, get; the JSON text as the
/// server sent it, so its key order survives the daemon's socket) or the
/// change made (set).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PowerLevelOutcome {
    pub room_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default)]
    pub previous: Value,
    #[serde(default)]
    pub level: Value,
}

/// Carry out a "power_levels" request.
pub async fn execute(client: &Client, request: &Value) -> Result<PowerLevelOutcome> {
    let room = resolve_room(client, request_str(request, "room")?).await?;
    let response = client
        .send(get_state_event_for_key::v3::Request::new(
            room.room_id().to_owned(),
            StateEventType::RoomPowerLevels,
            String::new(),
        ))
        .await
        .map_err(|e| anyhow!("{}", server_message(e.as_client_api_error(), &e)))?;
    let content = response.event_or_content.get().to_owned();
    let room_id = room.room_id().to_string();
    if request_str(request, "action")? != "set" {
        return Ok(PowerLevelOutcome {
            room_id,
            content: Some(content),
            previous: Value::Null,
            level: Value::Null,
        });
    }
    let user = request_str(request, "user_id")?;
    let level = request
        .get("level")
        .and_then(Value::as_i64)
        .context("the request has no integer \"level\"")?;
    let mut doc: Json =
        serde_json::from_str(&content).context("the power levels are not valid JSON")?;
    let previous = set_level(&mut doc, user, level)?;
    let body = serde_json::value::to_raw_value(&doc)?;
    room.send_state_event_raw("m.room.power_levels", "", body)
        .await
        .map_err(|e| anyhow!("{}", server_message(e.as_client_api_error(), &e)))?;
    Ok(PowerLevelOutcome {
        room_id,
        content: None,
        previous,
        level: json!(level),
    })
}

/// set_power_level()'s change to the content: `users` added (at the end) when
/// missing, the user's entry replaced in place or added at the end. Returns
/// the level before: the user's entry, else `users_default`, else 0.
pub fn set_level(doc: &mut Json, user: &str, level: i64) -> Result<Value> {
    let Json::Object(fields) = doc else {
        bail!("the power levels are not a JSON object");
    };
    let default = field(fields, "users_default").map_or(json!(0), Json::to_value);
    if field(fields, "users").is_none() {
        fields.push(("users".to_owned(), Json::Object(Vec::new())));
    }
    let Some(Json::Object(users)) = field_mut(fields, "users") else {
        bail!("\"users\" in the power levels is not an object");
    };
    let previous = field(users, user).map_or(default, Json::to_value);
    let level = Json::Number(level.into());
    match field_mut(users, user) {
        Some(entry) => *entry = level,
        None => users.push((user.to_owned(), level)),
    }
    Ok(previous)
}

/// --get's level: the user's entry, else `users_default`, else 0.
pub fn level_of(doc: &Json, user: &str) -> Result<Value> {
    let Json::Object(fields) = doc else {
        bail!("the power levels are not a JSON object");
    };
    let default = field(fields, "users_default").map_or(json!(0), Json::to_value);
    match field(fields, "users") {
        None => Ok(default),
        Some(Json::Object(users)) => Ok(field(users, user).map_or(default, Json::to_value)),
        Some(_) => bail!("\"users\" in the power levels is not an object"),
    }
}

/// What matrix-power-level.py prints on stdout.
pub fn render(
    args: &PowerLevelArgs,
    action: &Action,
    outcome: &PowerLevelOutcome,
) -> Result<String> {
    let room = &outcome.room_id;
    let content = || -> Result<Json> {
        let text = outcome
            .content
            .as_deref()
            .context("the answer carries no power levels")?;
        serde_json::from_str(text).context("the power levels are not valid JSON")
    };
    Ok(match action {
        Action::Show => {
            if args.quiet {
                python_json_line(&content()?)? + "\n"
            } else {
                python_json(&content()?)? + "\n"
            }
        }
        Action::Get(user) => {
            let level = level_of(&content()?, user)?;
            if args.json {
                python_json_line(&GetJson {
                    room_id: room,
                    user_id: user,
                    level: &level,
                })? + "\n"
            } else if args.quiet {
                format!("{}\n", python_str(&level))
            } else {
                format!("{} in {}: {}\n", term(user), term(room), python_str(&level))
            }
        }
        Action::Set(user, _) => {
            if args.json {
                python_json_line(&SetJson {
                    room_id: room,
                    user_id: user,
                    previous: &outcome.previous,
                    level: &outcome.level,
                })? + "\n"
            } else if args.quiet {
                format!("{}\n", python_str(&outcome.level))
            } else {
                format!(
                    "{} in {}: {} -> {}\n",
                    term(user),
                    term(room),
                    python_str(&outcome.previous),
                    python_str(&outcome.level)
                )
            }
        }
    })
}

/// --get --json, in the script's key order.
#[derive(Serialize)]
struct GetJson<'a> {
    room_id: &'a str,
    user_id: &'a str,
    level: &'a Value,
}

/// --set --json, in the script's key order.
#[derive(Serialize)]
struct SetJson<'a> {
    room_id: &'a str,
    user_id: &'a str,
    previous: &'a Value,
    level: &'a Value,
}

/// A level as Python's print() shows it: a number as JSON writes it, a
/// string without quotes, true/false/null as True/False/None.
fn python_str(value: &Value) -> String {
    match value {
        Value::String(s) => term(s).into_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Null => "None".to_owned(),
        other => other.to_string(),
    }
}

fn field<'a>(fields: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn field_mut<'a>(fields: &'a mut [(String, Json)], key: &str) -> Option<&'a mut Json> {
    fields.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// A JSON value that keeps the order of an object's keys (serde_json's
/// Value sorts them here), as a Python dict does: a key that occurs twice
/// keeps its first place and its last value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

impl Serialize for Json {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self {
            Json::Null => serializer.serialize_unit(),
            Json::Bool(b) => serializer.serialize_bool(*b),
            Json::Number(n) => n.serialize(serializer),
            Json::String(s) => serializer.serialize_str(s),
            Json::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Json::Object(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (key, value) in fields {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Json;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_unit<E>(self) -> Result<Json, E> {
                Ok(Json::Null)
            }
            fn visit_none<E>(self) -> Result<Json, E> {
                Ok(Json::Null)
            }
            fn visit_bool<E>(self, b: bool) -> Result<Json, E> {
                Ok(Json::Bool(b))
            }
            fn visit_i64<E>(self, n: i64) -> Result<Json, E> {
                Ok(Json::Number(n.into()))
            }
            fn visit_u64<E>(self, n: u64) -> Result<Json, E> {
                Ok(Json::Number(n.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, n: f64) -> Result<Json, E> {
                serde_json::Number::from_f64(n)
                    .map(Json::Number)
                    .ok_or_else(|| E::custom("not a finite number"))
            }
            fn visit_str<E>(self, s: &str) -> Result<Json, E> {
                Ok(Json::String(s.to_owned()))
            }
            fn visit_string<E>(self, s: String) -> Result<Json, E> {
                Ok(Json::String(s))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Json::Array(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
                let mut fields: Vec<(String, Json)> = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Json>()? {
                    match fields.iter_mut().find(|(k, _)| *k == key) {
                        Some((_, old)) => *old = value,
                        None => fields.push((key, value)),
                    }
                }
                Ok(Json::Object(fields))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::rooms::tests::fixture;
    use crate::mock_homeserver::MockHomeserver;
    use crate::{Cli, Command};
    use clap::Parser;

    fn args(argv: &[&str]) -> PowerLevelArgs {
        let cli = Cli::try_parse_from([&["m", "power-level"][..], argv].concat()).unwrap();
        let Command::PowerLevel(args) = cli.command else {
            panic!("not power-level")
        };
        args
    }

    fn argv(case: &Value) -> Vec<&str> {
        case["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect()
    }

    /// The content as the fixture's server sent it, with its key order: the
    /// expected --show -q line is json.dumps of it.
    fn content_text(fixture: &Value, name: &str) -> String {
        let case = fixture["power_level"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| {
                c["content"] == name
                    && c["argv"][1] == "--show"
                    && c["argv"].get(2) == Some(&json!("-q"))
            })
            .unwrap();
        case["stdout"].as_str().unwrap().trim_end().to_owned()
    }

    /// Each case against a homeserver that serves the fixture's content (or
    /// refuses), with the PUT body compared to the script's.
    #[tokio::test]
    async fn requests_and_output_are_matrix_power_level_py_s() {
        let fixture = fixture();
        let mut checked = 0;
        for case in fixture["power_level"].as_array().unwrap() {
            let argv = argv(case);
            let args = args(&argv);
            let python_err = case["stderr"].as_str().unwrap();
            let action = match action(&args) {
                Ok(action) => action,
                Err(err) => {
                    // Refused before any request, as the script refuses.
                    assert_eq!(format!("Error: {err}\n"), python_err, "{argv:?}");
                    checked += 1;
                    continue;
                }
            };
            let server = MockHomeserver::start();
            crate::commands::invite::tests::serve_room(&server);
            let path = "/_matrix/client/v3/rooms/!r:example.org/state/m.room.power_levels";
            if case["content"] == "error" {
                server.route(
                    "GET",
                    path,
                    403,
                    r#"{"errcode": "M_FORBIDDEN", "error": "You don't have permission"}"#,
                );
            } else {
                server.route(
                    "GET",
                    path,
                    200,
                    &content_text(&fixture, case["content"].as_str().unwrap()),
                );
                server.route("PUT", path, 200, r#"{"event_id": "$pl"}"#);
            }
            let client = server.client("@me:example.org").await;
            sync_once(&client).await.unwrap();
            let result = execute(&client, &level_request(&args.room, &action)).await;
            let puts: Vec<String> = server
                .received_api()
                .into_iter()
                .filter(|r| r.method == "PUT")
                .map(|r| {
                    assert_eq!(r.path, format!("{path}/"));
                    // The body's key order, written as json.dumps writes it.
                    python_json_line(&serde_json::from_str::<Json>(&r.body).unwrap()).unwrap()
                })
                .collect();
            assert_eq!(json!(puts), case["put"], "{argv:?}");
            match result {
                Ok(outcome) => assert_eq!(
                    render(&args, &action, &outcome).unwrap(),
                    case["stdout"].as_str().unwrap(),
                    "{argv:?}"
                ),
                Err(err) => assert_eq!(format!("Error: {err}\n"), python_err, "{argv:?}"),
            }
            checked += 1;
        }
        assert_eq!(checked, 26);
    }

    #[test]
    fn set_level_keeps_the_rest_and_its_order() {
        let mut doc: Json = serde_json::from_str(
            r#"{"z": 1, "users": {"@b:e": 50, "@a:e": 10}, "a": [1, {"y": 2, "x": 3}]}"#,
        )
        .unwrap();
        assert_eq!(set_level(&mut doc, "@a:e", 100).unwrap(), json!(10));
        assert_eq!(set_level(&mut doc, "@c:e", 5).unwrap(), json!(0));
        assert_eq!(
            python_json_line(&doc).unwrap(),
            r#"{"z": 1, "users": {"@b:e": 50, "@a:e": 100, "@c:e": 5}, "a": [1, {"y": 2, "x": 3}]}"#
        );
        let mut bare: Json = serde_json::from_str(r#"{"users_default": 20}"#).unwrap();
        assert_eq!(set_level(&mut bare, "@a:e", 1).unwrap(), json!(20));
        assert_eq!(
            python_json_line(&bare).unwrap(),
            r#"{"users_default": 20, "users": {"@a:e": 1}}"#
        );
    }

    #[test]
    fn a_repeated_key_keeps_its_place_and_its_last_value() {
        let doc: Json = serde_json::from_str(r#"{"a": 1, "b": 2, "a": 3}"#).unwrap();
        assert_eq!(python_json_line(&doc).unwrap(), r#"{"a": 3, "b": 2}"#);
    }

    #[test]
    fn exactly_one_action_is_required() {
        for argv in [
            &["!r:e"][..],
            &["!r:e", "--show", "--get", "@a:e"],
            &["!r:e", "--set", "@a:e"],
        ] {
            let cli = Cli::try_parse_from([&["m", "power-level"][..], argv].concat());
            assert!(cli.is_err(), "{argv:?}");
        }
        assert_eq!(
            action(&args(&["!r:e", "--set", "@a:e", "-5"])).unwrap(),
            Action::Set("@a:e".into(), -5)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_daemon_path_sets_the_level_of_the_direct_path() {
        use crate::commands::via_daemon_at;
        use crate::daemon_test_support::FakeDaemon;
        let args = args(&["LSB Project", "--set", "@bob:example.org", "100"]);
        let action = action(&args).unwrap();
        let request = level_request(&args.room, &action);
        let fake = FakeDaemon::start(Some(json!({"ok": true, "room_id": "!r:example.org",
            "previous": 50, "level": 100})));
        let outcome =
            via_daemon_at::<PowerLevelOutcome>(&fake.path, request.clone(), "power level request")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            fake.received(),
            json!({"op": "power_levels", "room": "LSB Project", "action": "set",
                   "user_id": "@bob:example.org", "level": 100})
        );
        assert_eq!(
            render(&args, &action, &outcome).unwrap(),
            "@bob:example.org in !r:example.org: 50 -> 100\n"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_content_keeps_its_key_order_through_the_daemon() {
        use crate::commands::via_daemon_at;
        use crate::daemon_test_support::FakeDaemon;
        let content = content_text(&fixture(), "power");
        // The daemon's answer passes through serde_json::Value (to_answer),
        // which sorts object keys: the content travels as a string.
        let mut answer = serde_json::to_value(PowerLevelOutcome {
            room_id: "!r:example.org".into(),
            content: Some(content.clone()),
            previous: Value::Null,
            level: Value::Null,
        })
        .unwrap();
        answer["ok"] = json!(true);
        let fake = FakeDaemon::start(Some(answer));
        let args = args(&["!r:example.org", "--show", "-q"]);
        let outcome = via_daemon_at::<PowerLevelOutcome>(
            &fake.path,
            level_request(&args.room, &Action::Show),
            "power level request",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            render(&args, &Action::Show, &outcome).unwrap(),
            content + "\n"
        );
    }
}
