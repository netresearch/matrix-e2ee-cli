//! `invite`: invite a user to a room, at parity with the matrix-skill's
//! matrix-invite.py.

use anyhow::{Context, Result, anyhow};
use matrix_sdk::Client;
use matrix_sdk::ruma::OwnedUserId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::InviteArgs;
use crate::commands::send::request_str;
use crate::commands::{resolve_room, server_message, sync_once, via_daemon};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{python_json_line, term};

pub async fn run(args: InviteArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    let request = invite_request(&args);
    let outcome = match via_daemon::<InviteOutcome>(&paths, request.clone(), "invitation").await? {
        Some(outcome) => outcome,
        None => {
            let config = load_config()?;
            let _lock = paths.lock().await?;
            let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
            sync_once(&restored.client).await?;
            execute(&restored.client, &request).await?
        }
    };
    print!("{}", render(&args, &outcome)?);
    Ok(())
}

/// The "invite" request the watch daemon takes.
pub fn invite_request(args: &InviteArgs) -> Value {
    json!({"op": "invite", "room": args.room, "user_id": args.user_id})
}

/// The room invited to and the user as given, in the order of the
/// script's JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteOutcome {
    pub room_id: String,
    pub user_id: String,
}

/// Carry out an "invite" request.
pub async fn execute(client: &Client, request: &Value) -> Result<InviteOutcome> {
    let given = request_str(request, "user_id")?;
    let user =
        OwnedUserId::try_from(given).with_context(|| format!("invalid user id {given:?}"))?;
    let room = resolve_room(client, request_str(request, "room")?).await?;
    room.invite_user_by_id(&user)
        .await
        .map_err(|e| anyhow!("{}", server_message(e.as_client_api_error(), &e)))?;
    Ok(InviteOutcome {
        room_id: room.room_id().to_string(),
        user_id: given.to_owned(),
    })
}

/// What matrix-invite.py prints on stdout.
pub fn render(args: &InviteArgs, outcome: &InviteOutcome) -> Result<String> {
    Ok(if args.json {
        python_json_line(outcome)? + "\n"
    } else if args.quiet {
        format!("{}\n", term(&outcome.room_id))
    } else {
        format!(
            "Invited {} to {}\n",
            term(&outcome.user_id),
            term(&outcome.room_id)
        )
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::commands::rooms::tests::fixture;
    use crate::mock_homeserver::MockHomeserver;
    use crate::{Cli, Command};
    use clap::Parser;

    fn args(argv: &[&str]) -> InviteArgs {
        let cli = Cli::try_parse_from([&["m", "invite"][..], argv].concat()).unwrap();
        let Command::Invite(args) = cli.command else {
            panic!("not invite")
        };
        args
    }

    /// A homeserver with the joined room !r:example.org.
    pub fn serve_room(server: &MockHomeserver) {
        server.route(
            "GET",
            "/_matrix/client/v3/sync",
            200,
            r#"{"next_batch": "s1", "rooms": {"join": {"!r:example.org": {}}}}"#,
        );
    }

    #[tokio::test]
    async fn the_request_sent_and_the_output_are_matrix_invite_py_s() {
        let fixture = fixture();
        let mut checked = 0;
        for case in fixture["invite"].as_array().unwrap() {
            let mut argv: Vec<&str> = case["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            // The script got the room resolved; here the room id is given.
            argv[0] = "!r:example.org";
            let args = args(&argv);
            let server = MockHomeserver::start();
            serve_room(&server);
            let path = "/_matrix/client/v3/rooms/!r:example.org/invite";
            if case["exit"] == 0 {
                server.route("POST", path, 200, "{}");
            } else {
                server.route("POST", path, 403,
                    r#"{"errcode": "M_FORBIDDEN", "error": "@jane:example.org is already in the room."}"#);
            }
            let client = server.client("@me:example.org").await;
            sync_once(&client).await.unwrap();
            let result = execute(&client, &invite_request(&args)).await;
            let sent: Vec<_> = server
                .received_api()
                .into_iter()
                .filter(|r| r.method == "POST")
                .collect();
            assert_eq!(sent.len(), 1, "{argv:?}: {sent:?}");
            let python = &case["requests"][0];
            assert_eq!(
                sent[0].path,
                format!("/_matrix/client/v3{}", "/rooms/!r:example.org/invite")
            );
            assert_eq!(python["endpoint"], "/rooms/%21r%3Aexample.org/invite");
            assert_eq!(
                serde_json::from_str::<Value>(&sent[0].body).unwrap(),
                python["body"],
                "{argv:?}"
            );
            match result {
                Ok(outcome) => assert_eq!(
                    render(&args, &outcome).unwrap(),
                    case["stdout"].as_str().unwrap(),
                    "{argv:?}"
                ),
                Err(err) => assert_eq!(
                    format!("Error: {err}\n"),
                    case["stderr"].as_str().unwrap(),
                    "{argv:?}"
                ),
            }
            checked += 1;
        }
        assert_eq!(checked, 5);
    }

    #[tokio::test]
    async fn an_invalid_user_id_is_refused_before_any_request() {
        let server = MockHomeserver::start();
        let client = server.client("@me:example.org").await;
        let err = execute(
            &client,
            &json!({"op": "invite", "room": "!r:example.org", "user_id": "jane"}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("invalid user id \"jane\""), "{err}");
        // The in-memory test client may still ask for account data on its own.
        assert!(
            !server.received().iter().any(|r| r.method == "POST"),
            "{:?}",
            server.received()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_daemon_path_sends_the_request_of_the_direct_path() {
        use crate::commands::via_daemon_at;
        use crate::daemon_test_support::FakeDaemon;
        let args = args(&["LSB Project", "@jane:example.org", "-q"]);
        let request = invite_request(&args);
        let fake = FakeDaemon::start(Some(
            json!({"ok": true, "room_id": "!r:example.org", "user_id": "@jane:example.org"}),
        ));
        let outcome = via_daemon_at::<InviteOutcome>(&fake.path, request.clone(), "invitation")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            fake.received(),
            json!({"op": "invite", "room": "LSB Project", "user_id": "@jane:example.org"})
        );
        assert_eq!(render(&args, &outcome).unwrap(), "!r:example.org\n");
    }
}
