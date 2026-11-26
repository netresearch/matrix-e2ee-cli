//! `send`: one message, encrypted when the room is encrypted.
//!
//! Room keys go to verified devices only (`CollectStrategy::OnlyTrustedDevices`).
//! `--trust-unverified-devices` builds this process's client with
//! `CollectStrategy::AllDevices` instead, and discards the room key after the
//! send, so the next message starts a new megolm session.

use anyhow::{Context, Result, bail};
use matrix_sdk::encryption::identities::Device;
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use matrix_sdk::{EncryptionState, Room, RoomMemberships};
use serde_json::json;

use crate::SendArgs;
use crate::commands::{resolve_room, sync_once};
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};
use crate::text::term;

pub async fn run(args: SendArgs) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let sharing = if args.trust_unverified_devices {
        KeySharing::IncludeUnverified
    } else {
        KeySharing::VerifiedOnly
    };
    let restored = restore(&config, &paths, sharing).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let room = resolve_room(&client, &args.room).await?;

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

    if encrypted && !args.trust_unverified_devices {
        let untrusted = untrusted_devices(&room).await?;
        if !untrusted.is_empty() {
            bail!(
                "the room has devices that are not verified, so the message was not sent:{} verify them, or pass --trust-unverified-devices to share this message's key with them anyway",
                describe(&untrusted)
            );
        }
    }

    let body = args.message.as_str();
    let content = if args.notice {
        RoomMessageEventContent::notice_plain(body)
    } else if args.emote {
        RoomMessageEventContent::emote_plain(body)
    } else {
        RoomMessageEventContent::text_plain(body)
    };

    let result = room.send(content).await;
    let discarded = if encrypted && args.trust_unverified_devices {
        // The opt-in covers this message only: drop the session the
        // unverified devices may now hold, before anything else can reuse
        // it. Also after a failed send: the key may have been shared already.
        room.discard_room_key().await
    } else {
        Ok(())
    };
    let (sent, warning) = settle_send(result, discarded)?;
    if let Some(warning) = warning {
        eprintln!("warning: {}", term(&warning));
    }
    let event_id = sent.response.event_id;

    if encrypted && !args.trust_unverified_devices {
        // The SDK queries device lists inside send(), after the check above:
        // devices learnt there got the key withheld. Say so.
        let withheld = untrusted_devices(&room).await.unwrap_or_default();
        if !withheld.is_empty() {
            eprintln!(
                "warning: sent, but the room key was withheld from unverified devices:{}",
                describe(&withheld)
            );
        }
    }

    if args.json {
        println!(
            "{}",
            json!({"event_id": event_id, "room_id": room.room_id(), "encrypted": encrypted})
        );
    } else {
        println!("{}", term(event_id.as_str()));
    }
    Ok(())
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
        (Err(err), Err(discard)) => Err(anyhow::Error::new(err).context(format!(
            "sending failed, and discarding the room key shared with unverified devices failed too ({discard})"
        ))),
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
    fn successful_send_with_failed_discard_is_a_warning() {
        let (sent, warning) =
            settle_send::<u8, std::io::Error, _>(Ok(7), Err("disk full")).unwrap();
        assert_eq!(sent, 7);
        assert!(warning.is_some_and(|w| w.contains("disk full")));
        let (_, warning) = settle_send::<u8, std::io::Error, &str>(Ok(7), Ok(())).unwrap();
        assert!(warning.is_none());
    }
}
