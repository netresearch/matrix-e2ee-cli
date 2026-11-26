//! `login`: password login that creates a new device.

use anyhow::{Context, Result, bail};
use matrix_sdk::Client;

use crate::commands::sync_once;
use crate::config::{Config, load_config};
use crate::session::{
    KeySharing, Paths, SessionFile, build_client, delete_local_state, discard_stash,
    generate_passphrase, read_secret, read_session, restore_stash, stash_local_state,
    write_session,
};

pub const DEVICE_NAME: &str = "Matrix Skill E2EE (Rust)";

pub async fn run(force: bool) -> Result<()> {
    let config = load_config()?;
    let paths = Paths::from_env()?;

    if let Some(existing) = read_session(&paths.session_file())? {
        if !force {
            bail!(
                "already logged in as {} with device {}; use --force to replace it, or `logout` first",
                existing.user_id,
                existing.device_id
            );
        }
        eprintln!(
            "Replacing the local session of device {}. That device stays on the server; remove it with Element or log it out first.",
            existing.device_id
        );
    }
    let password = read_secret(
        "MATRIX_PASSWORD",
        &format!("Matrix password for {}: ", config.user_id),
    )?;

    // A store belongs to one device and its passphrase, so the new device
    // needs an empty one. Keep the old state aside until the login succeeded.
    stash_local_state(&paths)?;
    let (client, session) = match create_device(&config, &paths, &password).await {
        Ok(done) => done,
        Err(err) => {
            delete_local_state(&paths)?;
            restore_stash(&paths)?;
            return Err(err);
        }
    };
    drop(password);
    discard_stash(&paths)?;

    // Upload the new device's keys.
    client
        .encryption()
        .wait_for_e2ee_initialization_tasks()
        .await;
    sync_once(&client)
        .await
        .context("logged in, but the first sync failed")?;

    println!("Logged in as {}", session.user_id);
    println!("Device: {} ({DEVICE_NAME})", session.device_id);
    println!("Session: {}", paths.session_file().display());
    eprintln!(
        "Next: verify this device with `matrix-e2ee-cli verify --request <your other device id>`, or restore keys with `matrix-e2ee-cli backup-restore`."
    );
    Ok(())
}

/// Log in and write the session file. Once this returns Ok, the device
/// exists on the server and its session is stored.
async fn create_device(
    config: &Config,
    paths: &Paths,
    password: &str,
) -> Result<(Client, SessionFile)> {
    let passphrase = generate_passphrase();
    let client = build_client(
        &config.homeserver,
        paths,
        &passphrase,
        KeySharing::VerifiedOnly,
    )
    .await?;
    let response = client
        .matrix_auth()
        .login_username(&config.user_id, password)
        .initial_device_display_name(DEVICE_NAME)
        .send()
        .await
        .context("login failed")?;
    let session = SessionFile {
        homeserver: client.homeserver().to_string(),
        user_id: response.user_id.to_string(),
        device_id: response.device_id.to_string(),
        access_token: response.access_token.clone(),
        store_passphrase: passphrase,
    };
    write_session(&paths.session_file(), &session)?;
    Ok((client, session))
}
