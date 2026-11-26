//! The subcommands and the helpers they share.

pub mod backup;
pub mod login;
pub mod logout;
pub mod read;
pub mod send;
pub mod status;
pub mod verify;

use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::{OwnedRoomAliasId, OwnedRoomId};
use matrix_sdk::{Client, Room};

use crate::room_arg::{RoomArg, classify, match_name};

/// One sync without long polling: room state, device lists and to-device
/// events up to now. Outgoing crypto requests (key upload, key queries) are
/// sent as part of it.
pub async fn sync_once(client: &Client) -> Result<()> {
    client
        .sync_once(SyncSettings::default().timeout(Duration::ZERO))
        .await
        .context("sync failed")?;
    Ok(())
}

/// Find a joined room by id, alias or name.
pub async fn resolve_room(client: &Client, arg: &str) -> Result<Room> {
    let room_id: OwnedRoomId = match classify(arg) {
        RoomArg::Id(id) => id
            .as_str()
            .try_into()
            .with_context(|| format!("invalid room id {id}"))?,
        RoomArg::Alias(alias) => {
            let alias: OwnedRoomAliasId = alias
                .as_str()
                .try_into()
                .with_context(|| format!("invalid room alias {alias}"))?;
            client
                .resolve_room_alias(&alias)
                .await
                .with_context(|| format!("cannot resolve {alias}"))?
                .room_id
        }
        RoomArg::Name(name) => {
            let rooms = client.joined_rooms();
            let mut names = Vec::with_capacity(rooms.len());
            for room in &rooms {
                let display = room
                    .display_name()
                    .await
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                names.push(display);
            }
            let hits = match_name(&names, &name);
            match hits.as_slice() {
                [] => bail!("no joined room is named {name:?}"),
                [one] => rooms[*one].room_id().to_owned(),
                many => {
                    let list = many
                        .iter()
                        .map(|&i| format!("{} ({})", names[i], rooms[i].room_id()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    bail!("room name {name:?} is ambiguous; use a room id: {list}");
                }
            }
        }
    };
    client
        .get_room(&room_id)
        .filter(|room| room.state() == matrix_sdk::RoomState::Joined)
        .with_context(|| format!("not joined to room {room_id}"))
}

/// Ask a yes/no question on stderr, read the answer from stdin. With
/// `require_terminal`, refuse when stdin is not a terminal. End of input is "no".
pub fn ask_yes_no(question: &str, require_terminal: bool) -> Result<bool> {
    if require_terminal && !std::io::stdin().is_terminal() {
        bail!("no terminal to ask on: {question}");
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("cannot read the answer")?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes"))
}
