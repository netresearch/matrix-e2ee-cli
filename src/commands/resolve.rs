//! `resolve`: a room alias to its room id, at parity with the matrix-skill's
//! matrix-resolve.py. A live directory request; needs no sync.

use anyhow::{Result, anyhow, bail};
use matrix_sdk::Client;
use matrix_sdk::ruma::OwnedRoomAliasId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ResolveArgs;
use crate::commands::send::request_str;
use crate::commands::{server_message, via_daemon};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::{python_json, term};

pub async fn run(args: ResolveArgs) -> Result<()> {
    // Checked before anything is opened, as matrix-resolve.py does.
    check_alias(&args.alias)?;
    let paths = Paths::from_env()?;
    let request = json!({"op": "resolve", "alias": args.alias});
    let outcome =
        match via_daemon::<ResolveOutcome>(&paths, request.clone(), "alias lookup").await? {
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

/// matrix-resolve.py's first check: an alias starts with "#".
pub fn check_alias(alias: &str) -> Result<()> {
    if !alias.starts_with('#') {
        bail!("Alias must start with #");
    }
    Ok(())
}

/// The alias as given and the room id it points at, in the order of the
/// script's JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveOutcome {
    pub room_id: String,
    pub alias: String,
}

/// Look the request's alias up in the room directory.
pub async fn execute(client: &Client, request: &Value) -> Result<ResolveOutcome> {
    let given = request_str(request, "alias")?;
    let alias: OwnedRoomAliasId = given
        .try_into()
        .map_err(|e| anyhow!("Could not resolve room alias: invalid alias {given:?}: {e}"))?;
    let response = client.resolve_room_alias(&alias).await.map_err(|e| {
        anyhow!(
            "Could not resolve room alias: {}",
            server_message(e.as_client_api_error(), &e)
        )
    })?;
    Ok(ResolveOutcome {
        room_id: response.room_id.to_string(),
        alias: given.to_owned(),
    })
}

/// What matrix-resolve.py prints on stdout.
pub fn render(args: &ResolveArgs, outcome: &ResolveOutcome) -> Result<String> {
    Ok(if args.json {
        python_json(outcome)? + "\n"
    } else {
        format!(
            "Alias: {}\nRoom ID: {}\n",
            term(&outcome.alias),
            term(&outcome.room_id)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::rooms::tests::fixture;
    use crate::mock_homeserver::MockHomeserver;
    use crate::{Cli, Command};
    use clap::Parser;

    fn args(argv: &[&str]) -> ResolveArgs {
        let cli = Cli::try_parse_from([&["m", "resolve"][..], argv].concat()).unwrap();
        let Command::Resolve(args) = cli.command else {
            panic!("not resolve")
        };
        args
    }

    fn cases() -> Vec<Value> {
        fixture()["resolve"].as_array().unwrap().clone()
    }

    #[test]
    fn output_is_matrix_resolve_py_s() {
        let outcome = ResolveOutcome {
            room_id: "!c:example.org".into(),
            alias: "#ops:example.org".into(),
        };
        let mut checked = 0;
        for case in cases().iter().filter(|c| c["exit"] == 0) {
            let argv: Vec<&str> = case["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            assert_eq!(
                render(&args(&argv), &outcome).unwrap(),
                case["stdout"].as_str().unwrap(),
                "{argv:?}"
            );
            checked += 1;
        }
        assert_eq!(checked, 2);
    }

    #[tokio::test]
    async fn the_server_s_error_text_is_the_message() {
        let server = MockHomeserver::start();
        server.route(
            "GET",
            "/_matrix/client/v3/directory/room/#ops:example.org",
            200,
            r#"{"room_id": "!c:example.org", "servers": ["example.org"]}"#,
        );
        server.route(
            "GET",
            "/_matrix/client/v3/directory/room/#missing:example.org",
            404,
            r##"{"errcode": "M_NOT_FOUND", "error": "Room alias #missing:example.org not found"}"##,
        );
        let client = server.client("@me:example.org").await;
        let found = execute(
            &client,
            &json!({"op": "resolve", "alias": "#ops:example.org"}),
        )
        .await
        .unwrap();
        assert_eq!(
            found,
            ResolveOutcome {
                room_id: "!c:example.org".into(),
                alias: "#ops:example.org".into()
            }
        );
        let err = execute(
            &client,
            &json!({"op": "resolve", "alias": "#missing:example.org"}),
        )
        .await
        .unwrap_err()
        .to_string();
        let python = cases()
            .into_iter()
            .find(|c| c["argv"] == json!(["#missing:example.org"]))
            .unwrap();
        assert_eq!(
            format!("Error: {err}\n"),
            python["stderr"].as_str().unwrap()
        );
    }

    #[test]
    fn an_alias_without_sigil_is_refused() {
        assert!(check_alias("#ops:example.org").is_ok());
        let err = check_alias("ops").unwrap_err().to_string();
        let python = cases()
            .into_iter()
            .find(|c| c["argv"] == json!(["ops"]))
            .unwrap();
        assert_eq!(
            format!("Error: {err}\n"),
            python["stderr"].as_str().unwrap()
        );
    }
}
