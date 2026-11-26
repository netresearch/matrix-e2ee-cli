//! `status`: who am I, is this device trusted, is key backup on.

use anyhow::Result;
use serde::Serialize;

use crate::commands::sync_once;
use crate::config::load_config;
use crate::session::{KeySharing, Paths, restore};

#[derive(Debug, Serialize)]
struct Status {
    user_id: String,
    device_id: String,
    /// Our own device carries a signature of our self-signing key.
    cross_signed: bool,
    /// matrix-sdk considers the device verified (cross-signed by a trusted
    /// identity, or trusted locally).
    verified: bool,
    /// The private cross-signing keys present in this device's store.
    cross_signing_keys: CrossSigningKeys,
    backup_enabled: bool,
    backup_state: String,
    recovery_state: String,
}

#[derive(Debug, Serialize)]
struct CrossSigningKeys {
    master: bool,
    self_signing: bool,
    user_signing: bool,
}

pub async fn run(json: bool) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let encryption = client.encryption();
    encryption.wait_for_e2ee_initialization_tasks().await;

    let own = encryption.get_own_device().await?;
    let keys = encryption.cross_signing_status().await;
    let status = Status {
        user_id: restored.session.user_id.clone(),
        device_id: restored.session.device_id.clone(),
        cross_signed: own.as_ref().is_some_and(|d| d.is_cross_signed_by_owner()),
        verified: own.as_ref().is_some_and(|d| d.is_verified()),
        cross_signing_keys: CrossSigningKeys {
            master: keys.as_ref().is_some_and(|k| k.has_master),
            self_signing: keys.as_ref().is_some_and(|k| k.has_self_signing),
            user_signing: keys.as_ref().is_some_and(|k| k.has_user_signing),
        },
        backup_enabled: encryption.backups().are_enabled().await,
        backup_state: format!("{:?}", encryption.backups().state()),
        recovery_state: format!("{:?}", encryption.recovery().state()),
    };

    if json {
        println!("{}", serde_json::to_string(&status)?);
    } else {
        let yn = |b: bool| if b { "yes" } else { "no" };
        println!("User:           {}", status.user_id);
        println!("Device:         {}", status.device_id);
        println!("Cross-signed:   {}", yn(status.cross_signed));
        println!("Verified:       {}", yn(status.verified));
        println!(
            "Signing keys:   master {}, self-signing {}, user-signing {}",
            yn(status.cross_signing_keys.master),
            yn(status.cross_signing_keys.self_signing),
            yn(status.cross_signing_keys.user_signing)
        );
        println!(
            "Key backup:     {} ({})",
            yn(status.backup_enabled),
            status.backup_state
        );
        println!("Recovery:       {}", status.recovery_state);
    }
    Ok(())
}
