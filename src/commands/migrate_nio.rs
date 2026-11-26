//! `migrate-nio`: take over the device of the Python matrix-skill.

//! The matrix-skill keeps a matrix-nio 0.25 (libolm) E2EE store. This command
//! reads that store, read-only, and creates this tool's session file and
//! SQLite store for the same user and device, with the Olm account, the Olm
//! sessions and the Megolm inbound group sessions converted from libolm
//! pickles to vodozemac. The device keeps its identity keys, so the
//! server-side signatures that verified it stay valid, and its room keys.
//!
//! The conversion follows `migrate()` in matrix-rust-sdk's
//! `bindings/matrix-sdk-crypto-ffi/src/lib.rs` (tag matrix-sdk-0.20.0), with the
//! public APIs of matrix-sdk-crypto, matrix-sdk-sqlite and vodozemac.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use chrono::{Local, NaiveDateTime, TimeZone};
use futures_util::FutureExt;
use matrix_sdk::SqliteCryptoStore;
use matrix_sdk::ruma::{
    DeviceKeyAlgorithm, DeviceKeyId, MilliSecondsSinceUnixEpoch, OwnedDeviceId, OwnedUserId,
    RoomId, SecondsSinceUnixEpoch, UInt,
};
use matrix_sdk_base::crypto::olm::{
    Account, IdentityKeys, InboundGroupSession, PickledAccount, PickledInboundGroupSession,
    PickledSession, SenderData, Session,
};
use matrix_sdk_base::crypto::store::CryptoStore;
use matrix_sdk_base::crypto::store::types::{Changes, DeviceChanges, PendingChanges};
use matrix_sdk_base::crypto::types::{DeviceKey, DeviceKeys, EventEncryptionAlgorithm, SigningKey};
use matrix_sdk_base::crypto::vodozemac;
use matrix_sdk_base::crypto::{DeviceData, LocalTrust};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;

use crate::commands::{ask_yes_no, sync_once};
use crate::config::load_config;
use crate::session::{
    KeySharing, Paths, SessionFile, UserIdMatch, compare_user_ids, delete_local_state,
    ensure_private_dir, existing_stash, generate_passphrase, parse_user_id, restore_from,
    stash_refusal, write_session,
};
use crate::text::term;

/// The key nio 0.25 encrypts its libolm pickles with: `ClientConfig.pickle_key`
/// defaults to "DEFAULT_KEY", and the matrix-skill never sets another one.
const NIO_PICKLE_KEY: &[u8] = b"DEFAULT_KEY";
/// The only nio store schema version this reads (nio 0.25: `MatrixStore.store_version`).
const NIO_STORE_VERSION: i64 = 2;
/// The flock the matrix-skill takes for the right to open the store.
const DAEMON_LOCK: &str = ".daemon.lock";
const CREDENTIALS: &str = "credentials.json";

/// The matrix-skill's store directory, as `_lib/e2ee.py` `get_store_path()`
/// computes it: `$XDG_DATA_HOME/matrix-skill/store`, default
/// `~/.local/share/matrix-skill/store`. Only computed: unlike the Python
/// function this creates and chmods nothing. An empty XDG_DATA_HOME counts as
/// unset (Python would use the relative path `matrix-skill/store`).
pub fn nio_store_path_from(xdg_data_home: Option<&str>, home: Option<&str>) -> Result<PathBuf> {
    let base = match xdg_data_home.filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => match home.filter(|v| !v.is_empty()) {
            Some(home) => Path::new(home).join(".local").join("share"),
            None => bail!("neither XDG_DATA_HOME nor HOME is set"),
        },
    };
    Ok(base.join("matrix-skill").join("store"))
}

pub fn nio_store_path() -> Result<PathBuf> {
    nio_store_path_from(
        std::env::var("XDG_DATA_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// credentials.json of the matrix-skill (`_lib/e2ee.py` `save_credentials`).
#[derive(Deserialize)]
struct Credentials {
    user_id: String,
    device_id: String,
    access_token: String,
}

/// An Olm session row of the nio store.
struct NioOlmSession {
    session_id: String,
    sender_key: String,
    creation_time: String,
    last_usage_date: String,
    pickle: String,
}

/// A Megolm inbound group session row of the nio store.
struct NioMegolmSession {
    session_id: String,
    sender_key: String,
    fp_key: String,
    room_id: String,
    pickle: String,
    forwarded: bool,
}

/// Everything read from the nio store. Holds the access token and the
/// pickles, hence no Debug.
pub struct NioStore {
    user_id: String,
    device_id: String,
    access_token: String,
    account_rows: i64,
    account_pickle: String,
    account_shared: bool,
    olm_sessions: Vec<NioOlmSession>,
    megolm_sessions: Vec<NioMegolmSession>,
}

/// A shared flock on `<store>/.daemon.lock`, held while the store is read. Taken
/// on a read-only descriptor; a missing lock file is not created.
struct DaemonLockCheck {
    _file: Option<File>,
}

fn check_daemon_lock(store: &Path) -> Result<DaemonLockCheck> {
    let path = store.join(DAEMON_LOCK);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        // Nobody ever took the lock, so nobody holds it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DaemonLockCheck { _file: None });
        }
        Err(e) => return Err(e).with_context(|| format!("cannot open {}", path.display())),
    };
    // SAFETY: flock takes a valid descriptor and constant flags; failure is
    // reported through the return value.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            let mut holder = String::new();
            let _ = (&file).take(32).read_to_string(&mut holder);
            let holder = holder.trim();
            bail!(
                "the matrix-skill E2EE store {} is in use by pid {} (normally matrix-watchd); stop it with `matrix-watchd.py --stop` and run migrate-nio again",
                store.display(),
                if holder.is_empty() {
                    "unknown".into()
                } else {
                    term(holder).into_owned()
                }
            );
        }
        return Err(err).with_context(|| format!("cannot check the lock {}", path.display()));
    }
    Ok(DaemonLockCheck { _file: Some(file) })
}

fn blob_text(bytes: Vec<u8>, what: &str) -> Result<String> {
    String::from_utf8(bytes).with_context(|| format!("{what} is not text"))
}

/// Read credentials.json and the device's nio database. Writes nothing: the
/// database is opened read-only, the lock only checked.
pub fn read_nio_store(store: &Path) -> Result<NioStore> {
    let _lock = check_daemon_lock(store)?;

    let creds_path = store.join(CREDENTIALS);
    let text = std::fs::read_to_string(&creds_path)
        .with_context(|| format!("cannot read {}", creds_path.display()))?;
    let creds: Credentials = serde_json::from_str(&text).with_context(|| {
        format!(
            "{} is not a matrix-skill credentials file",
            creds_path.display()
        )
    })?;
    drop(text);
    ensure!(
        !creds.user_id.is_empty() && !creds.device_id.is_empty() && !creds.access_token.is_empty(),
        "{} lacks user_id, device_id or access_token",
        creds_path.display()
    );
    // nio names the database after the device (MatrixStore.__post_init__).
    let db_path = store.join(format!("{}_{}.db", creds.user_id, creds.device_id));
    ensure!(
        db_path.is_file(),
        "no nio database {} for the device in credentials.json",
        db_path.display()
    );
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("cannot open {} read-only", db_path.display()))?;
    // One read transaction: a consistent snapshot of all tables.
    let tx = conn.unchecked_transaction()?;
    let read = read_tables(&tx, creds).with_context(|| format!("in {}", db_path.display()));
    tx.finish()?;
    read
}

fn read_tables(conn: &Connection, creds: Credentials) -> Result<NioStore> {
    let version: Option<i64> = conn
        .query_row("SELECT version FROM storeversion", [], |r| r.get(0))
        .optional()
        .context("not a matrix-nio store (no storeversion table)")?;
    ensure!(
        version == Some(NIO_STORE_VERSION),
        "nio store version {version:?} is not supported (expected {NIO_STORE_VERSION}, matrix-nio 0.25)"
    );
    let account_rows: i64 = conn.query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))?;
    let (account_id, account_pickle, account_shared): (i64, Vec<u8>, bool) = conn
        .query_row(
            "SELECT id, account, shared FROM accounts WHERE user_id = ?1 AND device_id = ?2",
            [&creds.user_id, &creds.device_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .with_context(|| {
            format!(
                "the store has no Olm account for {} / {}",
                creds.user_id, creds.device_id
            )
        })?;
    let account_pickle = blob_text(account_pickle, "the account")?;

    let mut stmt = conn.prepare(
        "SELECT session_id, sender_key, creation_time, last_usage_date, session
         FROM olmsessions WHERE account_id = ?1 ORDER BY session_id",
    )?;
    let olm_sessions = stmt
        .query_map([account_id], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?
        .map(|row| {
            let (session_id, sender_key, creation_time, last_usage_date, pickle) = row?;
            Ok(NioOlmSession {
                session_id,
                sender_key,
                creation_time,
                last_usage_date,
                pickle: blob_text(pickle, "an Olm session")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut stmt = conn.prepare(
        "SELECT m.session_id, m.sender_key, m.fp_key, m.room_id, m.session,
                (SELECT count(*) FROM forwardedchains f WHERE f.session_id = m.session_id)
         FROM megolminboundsessions m WHERE m.account_id = ?1 ORDER BY m.session_id",
    )?;
    let megolm_sessions = stmt
        .query_map([account_id], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?
        .map(|row| {
            let (session_id, sender_key, fp_key, room_id, pickle, chains) = row?;
            Ok(NioMegolmSession {
                session_id,
                sender_key,
                fp_key,
                room_id,
                pickle: blob_text(pickle, "a Megolm session")?,
                forwarded: chains > 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(NioStore {
        user_id: creds.user_id,
        device_id: creds.device_id,
        access_token: creds.access_token,
        account_rows,
        account_pickle,
        account_shared,
        olm_sessions,
        megolm_sessions,
    })
}

/// nio's DateField: naive local time, "%Y-%m-%d %H:%M:%S.%f".
fn nio_timestamp(value: &str) -> SecondsSinceUnixEpoch {
    let secs = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
        .ok()
        .and_then(|naive| Local.from_local_datetime(&naive).earliest())
        .map(|t| t.timestamp())
        .unwrap_or_else(|| Local::now().timestamp());
    SecondsSinceUnixEpoch(
        u64::try_from(secs)
            .ok()
            .and_then(UInt::new)
            .unwrap_or_default(),
    )
}

/// The converted device, ready to be written.
struct Converted {
    account: Account,
    identity: IdentityKeys,
    sessions: Vec<Session>,
    inbound_group_sessions: Vec<InboundGroupSession>,
}

fn convert(nio: &NioStore) -> Result<Converted> {
    let user_id: OwnedUserId = parse_user_id(&nio.user_id, "credentials.json")?;
    let device_id: OwnedDeviceId = nio.device_id.as_str().into();

    let libolm = vodozemac::olm::Account::from_libolm_pickle(&nio.account_pickle, NIO_PICKLE_KEY)
        .context("cannot read the Olm account (libolm pickle)")?;
    let identity = libolm.identity_keys();
    let now = MilliSecondsSinceUnixEpoch::now();
    let account = Account::from_pickle(PickledAccount {
        user_id: user_id.clone(),
        device_id: device_id.clone(),
        pickle: libolm.pickle(),
        shared: nio.account_shared,
        // Never a dehydrated device. nio does not store the one-time key
        // count; the first sync reports the server's.
        dehydrated: false,
        uploaded_signed_key_count: 0,
        creation_local_time: now,
        fallback_key_creation_timestamp: Some(now),
    })
    .context("cannot convert the Olm account")?;
    drop(libolm);

    // Our own device keys, as the FFI migration builds them: enough for a
    // Session, which only keeps them for reference.
    let own_device = DeviceKeys::new(
        user_id,
        device_id.clone(),
        Vec::new(),
        BTreeMap::from([
            (
                DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, &device_id),
                DeviceKey::Ed25519(identity.ed25519),
            ),
            (
                DeviceKeyId::from_parts(DeviceKeyAlgorithm::Curve25519, &device_id),
                DeviceKey::Curve25519(identity.curve25519),
            ),
        ]),
        Default::default(),
    );

    let mut sessions = Vec::with_capacity(nio.olm_sessions.len());
    for row in &nio.olm_sessions {
        let inner = vodozemac::olm::Session::from_libolm_pickle(&row.pickle, NIO_PICKLE_KEY)
            .with_context(|| format!("cannot read Olm session {}", row.session_id))?;
        ensure!(
            inner.session_id() == row.session_id,
            "Olm session {} converts to session id {}",
            row.session_id,
            inner.session_id()
        );
        let session = Session::from_pickle(
            own_device.clone(),
            PickledSession {
                pickle: inner.pickle(),
                sender_key: vodozemac::Curve25519PublicKey::from_base64(&row.sender_key)
                    .with_context(|| format!("bad sender key of Olm session {}", row.session_id))?,
                // libolm does not record it.
                created_using_fallback_key: false,
                creation_time: nio_timestamp(&row.creation_time),
                last_use_time: nio_timestamp(&row.last_usage_date),
            },
        )
        .with_context(|| format!("cannot convert Olm session {}", row.session_id))?;
        sessions.push(session);
    }

    let mut inbound_group_sessions = Vec::with_capacity(nio.megolm_sessions.len());
    for row in &nio.megolm_sessions {
        let inner =
            vodozemac::megolm::InboundGroupSession::from_libolm_pickle(&row.pickle, NIO_PICKLE_KEY)
                .with_context(|| format!("cannot read Megolm session {}", row.session_id))?;
        ensure!(
            inner.session_id() == row.session_id,
            "Megolm session {} converts to session id {}",
            row.session_id,
            inner.session_id()
        );
        let pickle = inner.pickle();
        // libolm marks a session whose signing key it did not see signed (an
        // imported or forwarded key) with signing_key_verified = false;
        // vodozemac keeps the flag in its pickle but has no getter for it.
        let verified = serde_json::to_value(&pickle)
            .ok()
            .and_then(|v| v.get("signing_key_verified").and_then(|f| f.as_bool()))
            .unwrap_or(false);
        let algorithm = DeviceKeyAlgorithm::Ed25519;
        let signing_key = SigningKey::from_parts(&algorithm, row.fp_key.clone())
            .with_context(|| format!("bad signing key of Megolm session {}", row.session_id))?;
        let session = InboundGroupSession::from_pickle(PickledInboundGroupSession {
            pickle,
            sender_key: vodozemac::Curve25519PublicKey::from_base64(&row.sender_key)
                .with_context(|| format!("bad sender key of Megolm session {}", row.session_id))?,
            signing_key: [(algorithm, signing_key)].into_iter().collect(),
            sender_data: SenderData::legacy(),
            forwarder_data: None,
            room_id: RoomId::parse(&row.room_id)
                .with_context(|| format!("bad room id of Megolm session {}", row.session_id))?,
            imported: row.forwarded || !verified,
            backed_up: false,
            history_visibility: None,
            algorithm: EventEncryptionAlgorithm::MegolmV1AesSha2,
            shared_history: false,
        })
        .with_context(|| format!("cannot convert Megolm session {}", row.session_id))?;
        inbound_group_sessions.push(session);
    }

    Ok(Converted {
        account,
        identity,
        sessions,
        inbound_group_sessions,
    })
}

/// What the migrated store must show: the identity keys of the libolm
/// account and the session ids of the nio store. (nio never stores its own
/// device's keys in its devicekeys table: _handle_key_query skips them.)
struct Expected {
    curve25519: String,
    ed25519: String,
    olm: BTreeMap<String, BTreeSet<String>>,
    megolm: BTreeSet<String>,
}

fn expected(nio: &NioStore, converted: &Converted) -> Expected {
    let mut olm: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in &nio.olm_sessions {
        olm.entry(row.sender_key.clone())
            .or_default()
            .insert(row.session_id.clone());
    }
    Expected {
        curve25519: converted.identity.curve25519.to_base64(),
        ed25519: converted.identity.ed25519.to_base64(),
        olm,
        megolm: nio
            .megolm_sessions
            .iter()
            .map(|row| row.session_id.clone())
            .collect(),
    }
}

/// Compare identity keys from the migrated side with the expected ones.
fn compare_identity(
    what: &str,
    curve25519: Option<String>,
    ed25519: Option<String>,
    expected: &Expected,
) -> Result<()> {
    for (name, got, want) in [
        ("curve25519", curve25519, &expected.curve25519),
        ("ed25519", ed25519, &expected.ed25519),
    ] {
        ensure!(
            got.as_deref() == Some(want.as_str()),
            "{what}: the {name} identity key {} differs from the nio account's {want}",
            got.as_deref().unwrap_or("(none)")
        );
    }
    Ok(())
}

async fn write_store(paths: &Paths, passphrase: &str, converted: Converted) -> Result<()> {
    let store = SqliteCryptoStore::open(paths.store_dir(), Some(passphrase))
        .await
        .context("cannot create the crypto store")?;
    // The own device record, as OlmMachine::with_store writes it for a new
    // account: the device's own signed keys, locally trusted. The FFI
    // migration leaves it out; without it SqliteCryptoStore::get_sessions
    // panics in get_own_device ("We should be able to find our own device"),
    // so every Olm session lookup would.
    let own_device = DeviceData::new(converted.account.device_keys(), LocalTrust::Verified);
    store
        .save_changes(Changes {
            devices: DeviceChanges {
                new: vec![own_device],
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .context("cannot save the own device")?;
    store
        .save_pending_changes(PendingChanges {
            account: Some(converted.account),
        })
        .await
        .context("cannot save the account")?;
    store
        .save_changes(Changes {
            sessions: converted.sessions,
            inbound_group_sessions: converted.inbound_group_sessions,
            ..Default::default()
        })
        .await
        .context("cannot save the sessions")?;
    Ok(())
}

/// Reopen the written crypto store on its own and check account and sessions.
async fn check_store(paths: &Paths, passphrase: &str, expected: &Expected) -> Result<()> {
    let store = SqliteCryptoStore::open(paths.store_dir(), Some(passphrase))
        .await
        .context("cannot reopen the new crypto store")?;
    let account = store
        .load_account()
        .await?
        .context("the new store holds no account")?;
    let keys = account.identity_keys();
    compare_identity(
        "new store",
        Some(keys.curve25519.to_base64()),
        Some(keys.ed25519.to_base64()),
        expected,
    )?;
    for (sender_key, ids) in &expected.olm {
        let got: BTreeSet<String> = store
            .get_sessions(sender_key)
            .await?
            .unwrap_or_default()
            .iter()
            .map(|s| s.session_id().to_owned())
            .collect();
        ensure!(
            &got == ids,
            "the new store holds Olm sessions {got:?} for {sender_key}, expected {ids:?}"
        );
    }
    let got: BTreeSet<String> = store
        .get_inbound_group_sessions()
        .await?
        .iter()
        .map(|s| s.session_id().to_owned())
        .collect();
    ensure!(
        got == expected.megolm,
        "the new store holds {} Megolm sessions, the nio store {}",
        got.len(),
        expected.megolm.len()
    );
    Ok(())
}

/// Where migrate-nio reads from and how it talks.
pub struct Options {
    pub nio_store: PathBuf,
    pub homeserver: String,
    /// user_id from config.json.
    pub configured_user: String,
    pub check_online: bool,
}

/// Refuse to run over existing local state of this tool.
fn refuse_existing_state(paths: &Paths) -> Result<()> {
    if paths.session_file().exists() {
        bail!(
            "this tool already has a session ({}); `matrix-e2ee-cli logout` must remove the current device first",
            paths.session_file().display()
        );
    }
    if !existing_stash(paths).is_empty() {
        bail!(stash_refusal(paths));
    }
    if std::fs::symlink_metadata(paths.store_dir()).is_ok() {
        bail!(
            "{} exists without a session file; it cannot be opened (its passphrase was in the session file). Remove it and run migrate-nio again",
            paths.store_dir().display()
        );
    }
    Ok(())
}

/// The whole command without the process environment: `confirm` answers the
/// question (or not, with --yes), `out` receives what the user reads.
pub async fn migrate(
    paths: &Paths,
    opts: &Options,
    confirm: &mut dyn FnMut(&str) -> Result<bool>,
    out: &mut dyn Write,
) -> Result<()> {
    refuse_existing_state(paths)?;
    let nio = read_nio_store(&opts.nio_store)?;

    let configured = parse_user_id(&opts.configured_user, "config.json")?;
    let stored = parse_user_id(&nio.user_id, "credentials.json")?;
    if compare_user_ids(&configured, &stored) == UserIdMatch::Different {
        bail!(
            "the matrix-skill store belongs to {} but config.json names {}",
            nio.user_id,
            opts.configured_user
        );
    }

    writeln!(out, "matrix-skill store: {}", opts.nio_store.display())?;
    writeln!(out, "  User:            {}", term(&nio.user_id))?;
    writeln!(out, "  Device:          {}", term(&nio.device_id))?;
    writeln!(out, "  Accounts:        {}", nio.account_rows)?;
    writeln!(out, "  Olm sessions:    {}", nio.olm_sessions.len())?;
    writeln!(out, "  Megolm sessions: {}", nio.megolm_sessions.len())?;
    out.flush()?;

    let converted = convert(&nio)?;
    let expected = expected(&nio, &converted);

    if !confirm(&format!(
        "Take over device {} in this tool? The matrix-skill E2EE scripts must not use it afterwards.",
        term(&nio.device_id)
    ))? {
        bail!("aborted");
    }
    // Checked again: the question may have waited a while.
    refuse_existing_state(paths)?;

    let session = SessionFile {
        homeserver: opts.homeserver.clone(),
        user_id: nio.user_id.clone(),
        device_id: nio.device_id.clone(),
        access_token: nio.access_token.clone(),
        store_passphrase: generate_passphrase(),
    };
    let client = write_or_roll_back(paths, &session, converted, &expected).await?;

    writeln!(
        out,
        "Migrated device {} of {}: {} Olm and {} Megolm sessions; identity keys unchanged.",
        term(&session.device_id),
        term(&session.user_id),
        nio.olm_sessions.len(),
        nio.megolm_sessions.len()
    )?;
    writeln!(out, "Session: {}", paths.session_file().display())?;
    writeln!(
        out,
        "Do not use the matrix-skill E2EE scripts or matrix-watchd with this device any more: both copies would advance the same Olm sessions and one-time keys and break each other's decryption. The nio store was not changed."
    )?;
    if opts.check_online {
        sync_once(&client).await.context(
            "migrated, but the online check (one sync) failed; the new session was kept",
        )?;
        writeln!(out, "Online check: one sync succeeded.")?;
    } else {
        writeln!(
            out,
            "The access token was not checked against the server (use --check-online)."
        )?;
    }
    Ok(())
}

/// Write store and session file and verify them; on any failure, a panic
/// inside matrix-sdk included, delete what was written.
async fn write_or_roll_back(
    paths: &Paths,
    session: &SessionFile,
    converted: Converted,
    expected: &Expected,
) -> Result<matrix_sdk::Client> {
    ensure_private_dir(&paths.data_dir)?;
    ensure_private_dir(&paths.store_dir())?;
    let attempt = AssertUnwindSafe(write_and_verify(paths, session, converted, expected))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("the migration panicked")));
    attempt.map_err(|err| rollback(paths, err))
}

async fn write_and_verify(
    paths: &Paths,
    session: &SessionFile,
    converted: Converted,
    expected: &Expected,
) -> Result<matrix_sdk::Client> {
    write_store(paths, &session.store_passphrase, converted).await?;
    check_store(paths, &session.store_passphrase, expected).await?;
    // What a later command sees: the client restored from the session.
    let restored = restore_from(session.clone(), paths, KeySharing::VerifiedOnly).await?;
    let encryption = restored.client.encryption();
    compare_identity(
        "restored client",
        encryption.curve25519_key().await.map(|k| k.to_base64()),
        encryption.ed25519_key().await,
        expected,
    )?;
    // Last: only a verified store gets a session file.
    write_session(&paths.session_file(), session)?;
    Ok(restored.client)
}

/// Delete what this run created (it refused to start over existing state).
fn rollback(paths: &Paths, err: anyhow::Error) -> anyhow::Error {
    match delete_local_state(paths) {
        Ok(()) => err.context("migration failed; the new session and store were deleted, the nio store is unchanged"),
        Err(cleanup) => err.context(format!(
            "migration failed and deleting the new state failed too ({cleanup:#}); remove {} and {}",
            paths.session_file().display(),
            paths.store_dir().display()
        )),
    }
}

pub async fn run(store: Option<PathBuf>, yes: bool, check_online: bool) -> Result<()> {
    let paths = Paths::from_env()?;
    // Before config.json: the way out of an existing session is logout,
    // whatever state config.json is in.
    refuse_existing_state(&paths)?;
    let config = load_config()?;
    let opts = Options {
        nio_store: match store {
            Some(path) => path,
            None => nio_store_path()?,
        },
        homeserver: config.homeserver,
        configured_user: config.user_id,
        check_online,
    };
    let mut confirm = |question: &str| -> Result<bool> {
        if yes {
            Ok(true)
        } else {
            ask_yes_no(question, true)
        }
    };
    migrate(&paths, &opts, &mut confirm, &mut std::io::stdout()).await
}

// Unix only: nio's database name contains ":", which Windows does not allow
// in a file name, and the matrix-skill's nio store exists on Linux and macOS.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::session::read_session;
    use sha2::{Digest, Sha256};

    const USER: &str = "@test:example.org";
    const TOKEN: &str = "fixture-access-token-not-a-secret";

    /// tests/fixtures/nio_store/expected.json, written by generate.py next to
    /// the store it describes.
    #[derive(Deserialize)]
    struct Fixture {
        user_id: String,
        device_id: String,
        curve25519: String,
        ed25519: String,
        olm_sessions: Vec<FixtureOlm>,
        megolm_sessions: Vec<FixtureMegolm>,
        olm_message: FixtureOlmMessage,
    }
    #[derive(Deserialize)]
    struct FixtureOlm {
        session_id: String,
        sender_key: String,
    }
    /// A Megolm session and a message encrypted with its outbound side.
    #[derive(Deserialize)]
    struct FixtureMegolm {
        session_id: String,
        room_id: String,
        imported: bool,
        ciphertext: String,
        plaintext: String,
    }
    #[derive(Deserialize)]
    struct FixtureOlmMessage {
        message_type: u8,
        ciphertext: String,
        plaintext: String,
    }

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nio_store")
    }

    fn fixture() -> Fixture {
        let text = std::fs::read_to_string(fixture_dir().join("expected.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    /// A copy of the fixture store and an empty data directory of this tool.
    struct Setup {
        _tmp: tempfile::TempDir,
        paths: Paths,
        opts: Options,
    }

    fn setup() -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let nio = tmp.path().join("nio-store");
        std::fs::create_dir(&nio).unwrap();
        // The fixture database is stored as nio-store.db (no ":" in a file name
        // in the repository); nio names it "<user_id>_<device_id>.db".
        let fx = fixture();
        for entry in std::fs::read_dir(fixture_dir().join("store")).unwrap() {
            let entry = entry.unwrap();
            let name = if entry.file_name() == "nio-store.db" {
                format!("{}_{}.db", fx.user_id, fx.device_id).into()
            } else {
                entry.file_name()
            };
            std::fs::copy(entry.path(), nio.join(name)).unwrap();
        }
        Setup {
            paths: Paths {
                data_dir: tmp.path().join("app"),
            },
            opts: Options {
                nio_store: nio,
                homeserver: "https://matrix.invalid".into(),
                configured_user: USER.into(),
                check_online: false,
            },
            _tmp: tmp,
        }
    }

    /// Every entry of the nio store directory with the sha256 of its content.
    fn snapshot(dir: &Path) -> BTreeMap<String, String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let digest = Sha256::digest(std::fs::read(entry.path()).unwrap());
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    format!("{digest:x}"),
                )
            })
            .collect()
    }

    async fn run(setup: &Setup) -> (Result<()>, String) {
        let mut out = Vec::new();
        let result = migrate(&setup.paths, &setup.opts, &mut |_| Ok(true), &mut out).await;
        (result, String::from_utf8(out).unwrap())
    }

    fn assert_nothing_created(setup: &Setup) {
        assert!(!setup.paths.session_file().exists(), "session file left");
        assert!(
            std::fs::symlink_metadata(setup.paths.store_dir()).is_err(),
            "store left"
        );
    }

    #[tokio::test]
    async fn migrates_fixture_keeping_identity_sessions_and_room_keys() {
        let fx = fixture();
        let setup = setup();
        let before = snapshot(&setup.opts.nio_store);
        let nio = read_nio_store(&setup.opts.nio_store).unwrap();

        let (result, out) = run(&setup).await;
        result.unwrap();

        // The nio store is input only: same files, same bytes.
        assert_eq!(snapshot(&setup.opts.nio_store), before);

        let session = read_session(&setup.paths.session_file()).unwrap().unwrap();
        assert_eq!(
            (session.user_id.as_str(), session.device_id.as_str()),
            (fx.user_id.as_str(), fx.device_id.as_str())
        );
        assert_eq!(session.access_token, TOKEN);

        let store =
            SqliteCryptoStore::open(setup.paths.store_dir(), Some(&session.store_passphrase))
                .await
                .unwrap();
        let keys = store.load_account().await.unwrap().unwrap().identity_keys();
        assert_eq!(keys.curve25519.to_base64(), fx.curve25519);
        assert_eq!(keys.ed25519.to_base64(), fx.ed25519);

        // Olm: same sessions, and the migrated one decrypts the peer's reply.
        let mut olm_total = 0;
        for want in &fx.olm_sessions {
            let mut sessions = store.get_sessions(&want.sender_key).await.unwrap().unwrap();
            olm_total += sessions.len();
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].session_id(), want.session_id);
            let message: vodozemac::olm::OlmMessage = serde_json::from_value(serde_json::json!({
                "type": fx.olm_message.message_type,
                "body": fx.olm_message.ciphertext,
            }))
            .unwrap();
            assert_eq!(
                sessions[0].decrypt(&message).await.unwrap(),
                fx.olm_message.plaintext
            );
        }
        assert_eq!(olm_total, fx.olm_sessions.len());

        // Megolm: the same session ids and rooms, the imported key (from
        // matrix-key-backup.py's path) marked imported, the directly created
        // one not, and each key decrypts its message.
        let inbound = store.get_inbound_group_sessions().await.unwrap();
        assert_eq!(inbound.len(), fx.megolm_sessions.len());
        assert_eq!(fx.megolm_sessions.iter().filter(|m| m.imported).count(), 1);
        for want in &fx.megolm_sessions {
            let got = inbound
                .iter()
                .find(|s| s.session_id() == want.session_id)
                .unwrap_or_else(|| panic!("Megolm session {} missing", want.session_id));
            assert_eq!(got.room_id().as_str(), want.room_id);
            assert_eq!(got.has_been_imported(), want.imported, "{}", want.room_id);
            let key = got.export().await.session_key;
            let mut megolm = vodozemac::megolm::InboundGroupSession::import(
                &key,
                vodozemac::megolm::SessionConfig::version_1(),
            );
            let message = vodozemac::megolm::MegolmMessage::from_base64(&want.ciphertext).unwrap();
            assert_eq!(
                megolm.decrypt(&message).unwrap().plaintext,
                want.plaintext.as_bytes()
            );
        }

        // Counts and ids were shown; no secret was.
        assert!(
            out.contains(USER) && out.contains("Megolm sessions: 2"),
            "{out}"
        );
        assert!(!out.contains(TOKEN), "{out}");
        assert!(!out.contains(&session.store_passphrase), "{out}");
        assert!(!out.contains(&nio.account_pickle), "{out}");
        for row in &nio.olm_sessions {
            assert!(!out.contains(&row.pickle), "{out}");
        }
        for row in &nio.megolm_sessions {
            assert!(!out.contains(&row.pickle), "{out}");
        }
    }

    #[tokio::test]
    async fn refuses_when_this_tool_has_a_session() {
        let setup = setup();
        let existing = SessionFile {
            homeserver: "https://m.example".into(),
            user_id: USER.into(),
            device_id: "OTHER".into(),
            access_token: "t".into(),
            store_passphrase: generate_passphrase(),
        };
        write_session(&setup.paths.session_file(), &existing).unwrap();
        let before = snapshot(&setup.opts.nio_store);

        let err = run(&setup).await.0.unwrap_err().to_string();
        assert!(err.contains("matrix-e2ee-cli logout"), "{err}");
        assert_eq!(
            read_session(&setup.paths.session_file()).unwrap(),
            Some(existing)
        );
        assert!(std::fs::symlink_metadata(setup.paths.store_dir()).is_err());
        assert_eq!(snapshot(&setup.opts.nio_store), before);
    }

    #[tokio::test]
    async fn refuses_while_the_daemon_holds_the_store_lock() {
        let setup = setup();
        let lock_path = setup.opts.nio_store.join(DAEMON_LOCK);
        std::fs::write(&lock_path, "4242").unwrap();
        // What _lib/e2ee.py store_lock() does: LOCK_EX on its own descriptor.
        let holder = File::open(&lock_path).unwrap();
        // SAFETY: flock on a valid descriptor.
        assert_eq!(
            unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let before = snapshot(&setup.opts.nio_store);

        let err = run(&setup).await.0.unwrap_err().to_string();
        assert!(
            err.contains("matrix-watchd.py --stop") && err.contains("4242"),
            "{err}"
        );
        assert_nothing_created(&setup);
        assert_eq!(snapshot(&setup.opts.nio_store), before);

        // Released, the same lock file no longer stands in the way.
        drop(holder);
        run(&setup).await.0.unwrap();
        assert_eq!(snapshot(&setup.opts.nio_store), before);
    }

    #[tokio::test]
    async fn identity_mismatch_deletes_the_new_session_and_store() {
        let fx = fixture();
        let setup = setup();
        let nio = read_nio_store(&setup.opts.nio_store).unwrap();
        let converted = convert(&nio).unwrap();
        let mut want = expected(&nio, &converted);
        assert_eq!(want.curve25519, fx.curve25519);
        // The migrated account is right; what it is compared with is not.
        want.curve25519 = fx.olm_sessions[0].sender_key.clone();
        let session = SessionFile {
            homeserver: setup.opts.homeserver.clone(),
            user_id: nio.user_id.clone(),
            device_id: nio.device_id.clone(),
            access_token: nio.access_token.clone(),
            store_passphrase: generate_passphrase(),
        };

        let err = format!(
            "{:#}",
            write_or_roll_back(&setup.paths, &session, converted, &want)
                .await
                .expect_err("a mismatch must fail")
        );
        assert!(
            err.contains("curve25519 identity key") && err.contains("were deleted"),
            "{err}"
        );
        assert_nothing_created(&setup);
    }

    #[test]
    fn nio_timestamps_are_read_as_local_time() {
        let naive =
            NaiveDateTime::parse_from_str("2026-11-26 12:27:48", "%Y-%m-%d %H:%M:%S").unwrap();
        let want = Local
            .from_local_datetime(&naive)
            .earliest()
            .unwrap()
            .timestamp();
        let got = nio_timestamp("2026-11-26 12:27:48.611810");
        assert_eq!(i64::from(got.0), want);
        // Unparseable: now, not the epoch.
        assert!(i64::from(nio_timestamp("yesterday").0) >= want);
    }

    #[tokio::test]
    async fn failed_online_check_keeps_the_migrated_session() {
        let mut setup = setup();
        // .invalid never resolves: the sync fails without reaching a server.
        setup.opts.check_online = true;
        let err = format!("{:#}", run(&setup).await.0.unwrap_err());
        assert!(err.contains("online check"), "{err}");
        assert!(read_session(&setup.paths.session_file()).unwrap().is_some());
    }

    #[tokio::test]
    async fn declining_the_question_writes_nothing() {
        let setup = setup();
        let mut asked = false;
        let mut out = Vec::new();
        let err = migrate(
            &setup.paths,
            &setup.opts,
            &mut |_| {
                asked = true;
                Ok(false)
            },
            &mut out,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(asked && err.contains("aborted"), "{err}");
        assert_nothing_created(&setup);
    }

    #[tokio::test]
    async fn refuses_a_store_of_another_user() {
        let mut setup = setup();
        setup.opts.configured_user = "@someone:example.org".into();
        let err = run(&setup).await.0.unwrap_err().to_string();
        assert!(err.contains("config.json"), "{err}");
        assert_nothing_created(&setup);
    }

    #[test]
    fn default_store_path_follows_xdg_data_home() {
        assert_eq!(
            nio_store_path_from(Some("/x/data"), Some("/home/u")).unwrap(),
            PathBuf::from("/x/data/matrix-skill/store")
        );
        assert_eq!(
            nio_store_path_from(Some(""), Some("/home/u")).unwrap(),
            PathBuf::from("/home/u/.local/share/matrix-skill/store")
        );
        assert!(nio_store_path_from(None, None).is_err());
    }
}
