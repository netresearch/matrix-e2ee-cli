//! `create-room`: create a room, at parity with the matrix-skill's
//! matrix-create-room.py. The request carries what the script sends and
//! nothing more: name, preset, and alias localpart, topic and invites when
//! given. No initial state, so no `m.room.encryption` either: as with the
//! script, the room is encrypted only if the homeserver's defaults say so.

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use matrix_sdk::Client;
use matrix_sdk::ruma::OwnedUserId;
use matrix_sdk::ruma::api::client::room::Visibility;
use matrix_sdk::ruma::api::client::room::create_room::v3::{
    Request as CreateRoomRequest, RoomPreset,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::CreateRoomArgs;
use crate::commands::send::{request_opt, request_str};
use crate::commands::{server_message, via_daemon};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{python_json_line, term};

/// The presets matrix-create-room.py offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Preset {
    #[value(name = "private_chat")]
    Private,
    #[value(name = "public_chat")]
    Public,
    #[value(name = "trusted_private_chat")]
    TrustedPrivate,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Private => "private_chat",
            Preset::Public => "public_chat",
            Preset::TrustedPrivate => "trusted_private_chat",
        }
    }
}

pub async fn run(args: CreateRoomArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    let request = create_request(&args);
    let outcome =
        match via_daemon::<CreateRoomOutcome>(&paths, request.clone(), "room creation").await? {
            Some(outcome) => outcome,
            None => {
                let config = load_config()?;
                let _lock = paths.lock().await?;
                let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
                execute(&restored.client, &request).await?
            }
        };
    print!("{}", render(&args, &outcome)?);
    Ok(())
}

/// The "create_room" request: an empty alias, topic or invite list is left
/// out, as the script leaves it out.
pub fn create_request(args: &CreateRoomArgs) -> Value {
    let mut request = json!({
        "op": "create_room",
        "name": args.name,
        "preset": args.preset.as_str(),
    });
    if let Some(alias) = args.alias.as_deref().filter(|a| !a.is_empty()) {
        request["alias"] = json!(alias);
    }
    if let Some(topic) = args.topic.as_deref().filter(|t| !t.is_empty()) {
        request["topic"] = json!(topic);
    }
    if !args.invite.is_empty() {
        request["invite"] = json!(args.invite);
    }
    request
}

/// The /createRoom body for a "create_room" request.
pub fn room_request(request: &Value) -> Result<CreateRoomRequest> {
    let mut body = CreateRoomRequest::new();
    body.name = Some(request_str(request, "name")?.to_owned());
    body.preset = Some(match request_str(request, "preset")? {
        "private_chat" => RoomPreset::PrivateChat,
        "public_chat" => RoomPreset::PublicChat,
        "trusted_private_chat" => RoomPreset::TrustedPrivateChat,
        other => anyhow::bail!("unknown preset {other:?}"),
    });
    body.room_alias_name = request_opt(request, "alias").map(str::to_owned);
    body.topic = request_opt(request, "topic").map(str::to_owned);
    body.invite = match request.get("invite") {
        None => Vec::new(),
        Some(list) => list
            .as_array()
            .context("\"invite\" is not a list")?
            .iter()
            .map(|user| {
                let user = user.as_str().context("an invite is not a string")?;
                OwnedUserId::try_from(user).with_context(|| format!("invalid user id {user:?}"))
            })
            .collect::<Result<_>>()?,
    };
    // The default; serialized only when it differs.
    debug_assert_eq!(body.visibility, Visibility::Private);
    Ok(body)
}

/// The new room, and its full alias when one was asked for: on the user's
/// server name, where the homeserver creates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRoomOutcome {
    pub room_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

/// Create the room of a "create_room" request.
pub async fn execute(client: &Client, request: &Value) -> Result<CreateRoomOutcome> {
    let body = room_request(request)?;
    let server_name = client
        .user_id()
        .context("the client has no user id")?
        .server_name()
        .to_owned();
    let alias = body
        .room_alias_name
        .as_ref()
        .map(|local| format!("#{local}:{server_name}"));
    let room = client
        .create_room(body)
        .await
        .map_err(|e| anyhow!("{}", server_message(e.as_client_api_error(), &e)))?;
    Ok(CreateRoomOutcome {
        room_id: room.room_id().to_string(),
        alias,
    })
}

/// What matrix-create-room.py prints on stdout. Its --json prints the
/// server's answer, which from Synapse is {"room_id": ...} alone.
pub fn render(args: &CreateRoomArgs, outcome: &CreateRoomOutcome) -> Result<String> {
    Ok(if args.json {
        python_json_line(&json!({"room_id": outcome.room_id}))? + "\n"
    } else if args.quiet {
        format!("{}\n", term(&outcome.room_id))
    } else {
        let mut out = format!("Room created: {}\n", term(&outcome.room_id));
        if let Some(alias) = &outcome.alias {
            out.push_str(&format!("Alias: {}\n", term(alias)));
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::rooms::tests::fixture;
    use crate::mock_homeserver::MockHomeserver;
    use crate::{Cli, Command};
    use clap::Parser;

    fn args(argv: &[&str]) -> CreateRoomArgs {
        let cli = Cli::try_parse_from([&["m", "create-room"][..], argv].concat()).unwrap();
        let Command::CreateRoom(args) = cli.command else {
            panic!("not create-room")
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

    #[tokio::test]
    async fn the_body_sent_and_the_output_are_matrix_create_room_py_s() {
        let fixture = fixture();
        let mut checked = 0;
        for case in fixture["create_room"].as_array().unwrap() {
            let argv = argv(case);
            let args = args(&argv);
            let server = MockHomeserver::start();
            if case["exit"] == 0 {
                server.route(
                    "POST",
                    "/_matrix/client/v3/createRoom",
                    200,
                    r#"{"room_id": "!new:example.org"}"#,
                );
            } else {
                server.route(
                    "POST",
                    "/_matrix/client/v3/createRoom",
                    400,
                    r#"{"errcode": "M_ROOM_IN_USE", "error": "Room alias already taken"}"#,
                );
            }
            let client = server.client("@me:example.org").await;
            let result = execute(&client, &create_request(&args)).await;
            // The in-memory test client also asks for secret-storage account data.
            let sent: Vec<_> = server
                .received_api()
                .into_iter()
                .filter(|r| r.method == "POST")
                .collect();
            assert_eq!(sent.len(), 1, "{argv:?}: {sent:?}");
            assert_eq!(sent[0].method, "POST");
            assert_eq!(sent[0].path, "/_matrix/client/v3/createRoom");
            let body: Value = serde_json::from_str(&sent[0].body).unwrap();
            assert_eq!(body, case["requests"][0]["body"], "{argv:?}");
            match result {
                Ok(outcome) => {
                    assert_eq!(
                        render(&args, &outcome).unwrap(),
                        case["stdout"].as_str().unwrap(),
                        "{argv:?}"
                    );
                }
                Err(err) => {
                    assert_eq!(
                        format!("Error: {err}\n"),
                        case["stderr"].as_str().unwrap(),
                        "{argv:?}"
                    );
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 8);
    }

    #[test]
    fn invites_must_be_user_ids() {
        let request = create_request(&args(&["r", "--invite", "jane"]));
        let err = room_request(&request).unwrap_err().to_string();
        assert!(err.contains("invalid user id \"jane\""), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_daemon_path_creates_the_room_of_the_direct_path() {
        use crate::commands::via_daemon_at;
        use crate::daemon_test_support::FakeDaemon;
        let args = args(&[
            "LSB Project",
            "--alias",
            "lsb",
            "--invite",
            "@a:example.org",
            "--topic",
            "T",
        ]);
        let request = create_request(&args);
        let fake = FakeDaemon::start(Some(
            json!({"ok": true, "room_id": "!new:example.org", "alias": "#lsb:example.org"}),
        ));
        let outcome =
            via_daemon_at::<CreateRoomOutcome>(&fake.path, request.clone(), "room creation")
                .await
                .unwrap()
                .unwrap();
        let received = fake.received();
        assert_eq!(received, request);
        assert_eq!(received["op"], "create_room");
        // The daemon builds the body the direct path builds.
        let from_daemon = format!("{:?}", room_request(&received).unwrap());
        let direct = format!("{:?}", room_request(&request).unwrap());
        assert_eq!(from_daemon, direct);
        assert_eq!(
            render(&args, &outcome).unwrap(),
            "Room created: !new:example.org\nAlias: #lsb:example.org\n"
        );
    }
}
