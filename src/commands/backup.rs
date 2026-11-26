//! `backup-restore`: import secrets with the recovery key, then download the
//! room keys of every joined encrypted room from server-side key backup.

use anyhow::{Context, Result, bail};
use matrix_sdk::EncryptionState;

use crate::commands::sync_once;
use crate::config::load_config;
use crate::session::{KeySharing, Paths, read_secret, restore};

pub async fn run() -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;
    let _lock = paths.lock().await?;
    let restored = restore(&config, &paths, KeySharing::VerifiedOnly).await?;
    let client = restored.client;
    sync_once(&client).await?;
    let encryption = client.encryption();
    encryption.wait_for_e2ee_initialization_tasks().await;

    // Like the Python skill: a passphrase may come from its own variable.
    let from_env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let key = match (
        from_env("MATRIX_RECOVERY_KEY"),
        from_env("MATRIX_RECOVERY_PASSPHRASE"),
    ) {
        (Some(key), _) => key,
        (None, Some(passphrase)) => passphrase,
        (None, None) => read_secret("MATRIX_RECOVERY_KEY", "Recovery key (or passphrase): ")?,
    };
    encryption
        .recovery()
        .recover(&key)
        .await
        .context("recovery from secret storage failed")?;
    drop(key);
    eprintln!(
        "Secrets imported; recovery state: {:?}",
        encryption.recovery().state()
    );

    // download_room_keys_for_room() returns Ok without downloading anything
    // when the store holds no backup key or version: require an active backup.
    let backups = encryption.backups();
    if !backups.are_enabled().await {
        bail!(
            "secrets imported, but key backup is not active on this device (no backup on the server, or the secret storage holds no backup key); no room keys downloaded"
        );
    }

    // With BackupDownloadStrategy::Manual nothing is downloaded on its own, and
    // a background download would die with this process: fetch per room.
    let mut done = 0usize;
    let mut failed = Vec::new();
    for room in client.joined_rooms() {
        // As read and send do: ask the server when the state is not cached
        // yet. A state that stays unknown counts as encrypted, as in read.
        match room.latest_encryption_state().await {
            Ok(EncryptionState::NotEncrypted) => continue,
            Ok(EncryptionState::Encrypted | EncryptionState::Unknown) => {}
            Err(err) => {
                failed.push(format!(
                    "{}: cannot read the encryption state: {err}",
                    room.room_id()
                ));
                continue;
            }
        }
        match backups.download_room_keys_for_room(room.room_id()).await {
            Ok(()) => done += 1,
            Err(err) => failed.push(format!("{}: {err}", room.room_id())),
        }
    }
    // Ok also when the backup holds no keys for a room: count rooms checked.
    println!(
        "Key backup checked for {done} encrypted room(s); the keys found there were imported."
    );
    println!(
        "Key backup enabled: {}",
        if backups.are_enabled().await {
            "yes"
        } else {
            "no"
        }
    );
    if !failed.is_empty() {
        bail!(
            "key download failed for {} room(s): {}",
            failed.len(),
            failed.join("; ")
        );
    }
    Ok(())
}
