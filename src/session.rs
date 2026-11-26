//! The local session: data directory, session file (0600), SQLite store and
//! the matrix-sdk client built on them.

use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::encryption::{BackupDownloadStrategy, EncryptionSettings};
use matrix_sdk::ruma::{OwnedDeviceId, OwnedUserId, UserId};
use matrix_sdk::store::RoomLoadSettings;
use matrix_sdk::{Client, SessionMeta, SessionTokens};
use matrix_sdk_base::crypto::CollectStrategy;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::config::Config;

const APP_DIR: &str = "matrix-e2ee-cli";
const SESSION_FILE: &str = "session.json";
const STORE_DIR: &str = "store";

/// Where this tool keeps its state. Never the Python skill's store paths.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
}

impl Paths {
    /// `$XDG_DATA_HOME/matrix-e2ee-cli`, default `~/.local/share/matrix-e2ee-cli`.
    pub fn from_env_values(xdg_data_home: Option<&str>, home: Option<&str>) -> Result<Self> {
        let base = match xdg_data_home.filter(|v| !v.is_empty()) {
            Some(dir) => PathBuf::from(dir),
            None => match home.filter(|v| !v.is_empty()) {
                Some(home) => Path::new(home).join(".local").join("share"),
                None => bail!("neither XDG_DATA_HOME nor HOME is set"),
            },
        };
        Ok(Self {
            data_dir: base.join(APP_DIR),
        })
    }

    pub fn from_env() -> Result<Self> {
        Self::from_env_values(
            std::env::var("XDG_DATA_HOME").ok().as_deref(),
            std::env::var("HOME").ok().as_deref(),
        )
    }

    pub fn session_file(&self) -> PathBuf {
        self.data_dir.join(SESSION_FILE)
    }

    pub fn store_dir(&self) -> PathBuf {
        self.data_dir.join(STORE_DIR)
    }
}

/// What a later command needs to restore the device. Holds secrets: the
/// access token and the store passphrase, hence the 0600 file and no Debug.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionFile {
    pub homeserver: String,
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
    pub store_passphrase: String,
}

impl std::fmt::Debug for SessionFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionFile")
            .field("homeserver", &self.homeserver)
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// 32 random bytes from the thread-local CSPRNG, hex encoded.
pub fn generate_passphrase() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Create `dir` (and parents) and restrict it to the owner.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot restrict {}", dir.display()))?;
    Ok(())
}

/// Write the session file with mode 0600. The content goes to a temporary
/// file created with 0600 at open time and is renamed over the target, so the
/// secrets are never readable by others, also when an existing file with
/// wider permissions is replaced.
pub fn write_session(path: &Path, session: &SessionFile) -> Result<()> {
    let dir = path
        .parent()
        .context("session file has no parent directory")?;
    ensure_private_dir(dir)?;
    let tmp = dir.join(format!(".{SESSION_FILE}.tmp"));
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot remove {}", tmp.display())),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    // create_new + mode is subject to the umask; 0600 minus a umask is never
    // wider than 0600, but set it explicitly so it is exactly 0600.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(serde_json::to_string_pretty(session)?.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Read the session file; `None` when there is none. Refuses a file that
/// other users can read or write.
pub fn read_session(path: &Path) -> Result<Option<SessionFile>> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} has mode {:o}; it holds an access token, run: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        );
    }
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let session = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid session file", path.display()))?;
    Ok(Some(session))
}

/// Delete the session file and the store directory. Missing parts are fine.
pub fn delete_local_state(paths: &Paths) -> Result<()> {
    match fs::remove_file(paths.session_file()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("cannot delete the session file"),
    }
    remove_store(paths)
}

const STASH_SUFFIX: &str = ".prev";

fn stash_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(STASH_SUFFIX);
    path.with_file_name(name)
}

/// The stash paths (`*.prev`) that exist.
pub fn existing_stash(paths: &Paths) -> Vec<PathBuf> {
    [paths.session_file(), paths.store_dir()]
        .iter()
        .map(|path| stash_path(path))
        .filter(|stash| fs::symlink_metadata(stash).is_ok())
        .collect()
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

/// Why a stash blocks the next login, and the commands that resolve it in
/// the current state.
pub fn stash_refusal(paths: &Paths) -> String {
    let stash = existing_stash(paths);
    let listed = stash
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" and ");
    let drop_cmd = format!(
        "rm -r {}",
        stash
            .iter()
            .map(|p| shell_quote(p))
            .collect::<Vec<_>>()
            .join(" ")
    );
    if paths.session_file().exists() {
        format!(
            "a previous session is still kept aside in {listed} by an interrupted login; to put it back, run `matrix-e2ee-cli logout` (logs out the current device) and then `matrix-e2ee-cli login --restore-previous`; to keep the current session and drop the previous one, run: {drop_cmd}"
        )
    } else {
        format!(
            "a previous session is still kept aside in {listed} by an interrupted login; to put it back, run `matrix-e2ee-cli login --restore-previous`; to drop it, run: {drop_cmd}"
        )
    }
}

/// Move an existing session file and store aside (`*.prev`), so a failed
/// login can put them back. Refuses when a stash already exists:
/// it is the only copy of an earlier session.
pub fn stash_local_state(paths: &Paths) -> Result<()> {
    if !existing_stash(paths).is_empty() {
        bail!(stash_refusal(paths));
    }
    for path in [paths.session_file(), paths.store_dir()] {
        let stash = stash_path(&path);
        match fs::rename(&path, &stash) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("cannot move {} aside", path.display()));
            }
        }
    }
    Ok(())
}

/// Put a stash back in place of the current session file and store. The
/// store goes first and the session file last, so a session file is never
/// live while its store is still aside.
pub fn restore_stash(paths: &Paths) -> Result<()> {
    for path in [paths.store_dir(), paths.session_file()] {
        let stash = stash_path(&path);
        if fs::symlink_metadata(&stash).is_ok() {
            remove_path(&path)?;
            fs::rename(&stash, &path)
                .with_context(|| format!("cannot restore {}", path.display()))?;
        }
    }
    Ok(())
}

/// `login --restore-previous`: put a stash left by an interrupted login
/// back. Refuses while a session file exists, because that
/// session's device would be lost. A store without a session file is unusable
/// (its passphrase was in the session file) and is replaced only when its own
/// stash exists.
pub fn restore_previous(paths: &Paths) -> Result<()> {
    if existing_stash(paths).is_empty() {
        bail!("no previous session is kept aside; nothing to restore");
    }
    if paths.session_file().exists() {
        bail!(stash_refusal(paths));
    }
    restore_stash(paths)
}

/// Undo the local side of a failed login: delete what the attempt left and
/// put the stash back. Always tries both steps and returns the login error
/// (always `Err`), with any cleanup failure attached as context.
pub fn rollback_failed_login<T>(paths: &Paths, err: anyhow::Error) -> Result<T> {
    let cleanup = delete_local_state(paths);
    let restore = restore_stash(paths);
    let problems: Vec<String> = [cleanup.err(), restore.err()]
        .into_iter()
        .flatten()
        .map(|e| format!("{e:#}"))
        .collect();
    if problems.is_empty() {
        Err(err)
    } else if existing_stash(paths).is_empty() {
        // Nothing is kept aside any more: report what failed, no guidance
        // about a stash that does not exist.
        Err(err).with_context(|| {
            format!(
                "cleaning up after the failed login failed: {}",
                problems.join("; ")
            )
        })
    } else {
        Err(err).with_context(|| {
            format!(
                "the previous session could not be fully put back ({}); {}",
                problems.join("; "),
                stash_refusal(paths)
            )
        })
    }
}

pub fn discard_stash(paths: &Paths) -> Result<()> {
    remove_path(&stash_path(&paths.session_file()))?;
    remove_path(&stash_path(&paths.store_dir()))
}

fn remove_path(path: &Path) -> Result<()> {
    let result = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => Err(e),
    };
    result.with_context(|| format!("cannot delete {}", path.display()))
}

pub fn remove_store(paths: &Paths) -> Result<()> {
    match fs::remove_dir_all(paths.store_dir()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("cannot delete the store directory"),
    }
}

/// Settings for every client: no automatic cross-signing bootstrap, no
/// automatic backup creation, no automatic key download.
fn encryption_settings() -> EncryptionSettings {
    EncryptionSettings {
        auto_enable_cross_signing: false,
        backup_download_strategy: BackupDownloadStrategy::Manual,
        auto_enable_backups: false,
    }
}

/// How room keys of messages this process sends are shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySharing {
    /// Default: verified devices only (`CollectStrategy::OnlyTrustedDevices`).
    VerifiedOnly,
    /// `--trust-unverified-devices`: every device that is not blacklisted.
    IncludeUnverified,
}

impl KeySharing {
    pub fn strategy(self) -> CollectStrategy {
        match self {
            KeySharing::VerifiedOnly => CollectStrategy::OnlyTrustedDevices,
            KeySharing::IncludeUnverified => CollectStrategy::AllDevices,
        }
    }
}

pub async fn build_client(
    homeserver: &str,
    paths: &Paths,
    passphrase: &str,
    sharing: KeySharing,
) -> Result<Client> {
    ensure_private_dir(&paths.data_dir)?;
    ensure_private_dir(&paths.store_dir())?;
    Client::builder()
        .homeserver_url(homeserver)
        .sqlite_store(paths.store_dir(), Some(passphrase))
        .with_encryption_settings(encryption_settings())
        .with_room_key_recipient_strategy(sharing.strategy())
        .build()
        .await
        .context("cannot set up the Matrix client")
}

/// A logged-in client restored from the session file.
pub struct Restored {
    pub client: Client,
    pub session: SessionFile,
}

/// How a user id the server or the session file names relates to the one in
/// config.json.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserIdMatch {
    Same,
    /// Same account, spelled with different letter case in the localpart or
    /// the server name (both are compared case-insensitively; the port must
    /// be equal).
    CaseOnly,
    Different,
}

pub fn parse_user_id(value: &str, what: &str) -> Result<OwnedUserId> {
    UserId::parse(value).with_context(|| format!("invalid user id {value:?} in {what}"))
}

pub fn compare_user_ids(configured: &UserId, other: &UserId) -> UserIdMatch {
    if configured == other {
        UserIdMatch::Same
    } else if configured.server_name().host().to_lowercase()
        == other.server_name().host().to_lowercase()
        && configured.server_name().port() == other.server_name().port()
        && configured.localpart().to_lowercase() == other.localpart().to_lowercase()
    {
        UserIdMatch::CaseOnly
    } else {
        UserIdMatch::Different
    }
}

/// The session file must belong to the user config.json names; a difference
/// in letter case (localpart or server name) is the same account.
pub fn check_session_user(config: &Config, session: &SessionFile) -> Result<()> {
    let configured = parse_user_id(&config.user_id, "config.json")?;
    let stored = parse_user_id(&session.user_id, "the session file")?;
    if compare_user_ids(&configured, &stored) == UserIdMatch::Different {
        bail!(
            "the session belongs to {} but config.json names {}; run `matrix-e2ee-cli logout` or fix config.json",
            session.user_id,
            config.user_id
        );
    }
    Ok(())
}

pub async fn restore(config: &Config, paths: &Paths, sharing: KeySharing) -> Result<Restored> {
    let session = read_existing_session(paths)?;
    check_session_user(config, &session)?;
    restore_from(session, paths, sharing).await
}

/// Restore from the session file alone, without config.json (for `logout`).
pub async fn restore_session(paths: &Paths, sharing: KeySharing) -> Result<Restored> {
    let session = read_existing_session(paths)?;
    restore_from(session, paths, sharing).await
}

fn read_existing_session(paths: &Paths) -> Result<SessionFile> {
    match read_session(&paths.session_file())? {
        Some(session) => Ok(session),
        None if !existing_stash(paths).is_empty() => {
            bail!("not logged in; {}", stash_refusal(paths))
        }
        None => bail!("not logged in: run `matrix-e2ee-cli login` first"),
    }
}

async fn restore_from(
    session: SessionFile,
    paths: &Paths,
    sharing: KeySharing,
) -> Result<Restored> {
    let client = build_client(
        &session.homeserver,
        paths,
        &session.store_passphrase,
        sharing,
    )
    .await?;
    let user_id: OwnedUserId = session
        .user_id
        .as_str()
        .try_into()
        .context("invalid user id in session file")?;
    let device_id: OwnedDeviceId = session.device_id.as_str().into();
    client
        .matrix_auth()
        .restore_session(
            MatrixSession {
                meta: SessionMeta { user_id, device_id },
                tokens: SessionTokens {
                    access_token: session.access_token.clone(),
                    refresh_token: None,
                },
            },
            RoomLoadSettings::default(),
        )
        .await
        .context("cannot restore the session")?;
    Ok(Restored { client, session })
}

/// Read a secret from `env_name` or, on a terminal, a prompt without echo.
/// Never from the command line.
pub fn read_secret(env_name: &str, prompt: &str) -> Result<String> {
    if let Ok(value) = std::env::var(env_name)
        && !value.is_empty()
    {
        return Ok(value);
    }
    if !std::io::stdin().is_terminal() {
        bail!("no terminal to prompt on; set {env_name} for non-interactive use");
    }
    let value = rpassword::prompt_password(prompt).context("cannot read the secret")?;
    if value.is_empty() {
        bail!("the secret cannot be empty");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SessionFile {
        SessionFile {
            homeserver: "https://m.example".into(),
            user_id: "@a:example".into(),
            device_id: "DEV".into(),
            access_token: "secret-token".into(),
            store_passphrase: generate_passphrase(),
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn data_dir_follows_xdg_data_home() {
        let p = Paths::from_env_values(Some("/x/data"), Some("/home/u")).unwrap();
        assert_eq!(
            p.session_file(),
            PathBuf::from("/x/data/matrix-e2ee-cli/session.json")
        );
        let p = Paths::from_env_values(Some(""), Some("/home/u")).unwrap();
        assert_eq!(
            p.store_dir(),
            PathBuf::from("/home/u/.local/share/matrix-e2ee-cli/store")
        );
    }

    #[test]
    fn new_session_file_is_0600_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app").join("session.json");
        let s = sample();
        write_session(&path, &s).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(read_session(&path).unwrap(), Some(s));
    }

    #[test]
    fn overwriting_a_world_readable_file_leaves_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("session.json");
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_session(&path, &sample()).unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn refuses_a_session_file_others_can_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("session.json");
        write_session(&path, &sample()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let err = read_session(&path).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
    }

    #[test]
    fn missing_session_file_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_session(&tmp.path().join("nope.json")).unwrap(), None);
    }

    #[test]
    fn debug_output_hides_secrets() {
        let s = sample();
        let shown = format!("{s:?}");
        assert!(!shown.contains("secret-token") && !shown.contains(&s.store_passphrase));
    }

    #[test]
    fn passphrases_are_long_and_distinct() {
        let a = generate_passphrase();
        assert_eq!(a.len(), 64);
        assert_ne!(a, generate_passphrase());
    }

    #[tokio::test]
    async fn store_is_private_and_bound_to_its_passphrase() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths {
            data_dir: tmp.path().join("app"),
        };
        let pass = generate_passphrase();
        let client = build_client(
            "https://matrix.invalid",
            &paths,
            &pass,
            KeySharing::VerifiedOnly,
        )
        .await
        .unwrap();
        drop(client);
        assert_eq!(mode(&paths.store_dir()), 0o700);
        assert!(
            fs::read_dir(paths.store_dir()).unwrap().next().is_some(),
            "store files written"
        );
        // The same store opens with its passphrase and not with another one.
        assert!(
            build_client(
                "https://matrix.invalid",
                &paths,
                &pass,
                KeySharing::VerifiedOnly
            )
            .await
            .is_ok()
        );
        let wrong = generate_passphrase();
        assert!(
            build_client(
                "https://matrix.invalid",
                &paths,
                &wrong,
                KeySharing::VerifiedOnly
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn stash_restores_the_previous_session_and_store() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths {
            data_dir: tmp.path().join("app"),
        };
        let old = sample();
        write_session(&paths.session_file(), &old).unwrap();
        fs::create_dir_all(paths.store_dir()).unwrap();
        fs::write(paths.store_dir().join("db"), "old").unwrap();

        stash_local_state(&paths).unwrap();
        assert_eq!(read_session(&paths.session_file()).unwrap(), None);
        assert!(!paths.store_dir().exists());
        // A failed login leaves a half-made store behind.
        fs::create_dir_all(paths.store_dir()).unwrap();
        fs::write(paths.store_dir().join("db"), "new").unwrap();

        restore_stash(&paths).unwrap();
        assert_eq!(read_session(&paths.session_file()).unwrap(), Some(old));
        assert_eq!(
            fs::read_to_string(paths.store_dir().join("db")).unwrap(),
            "old"
        );
        discard_stash(&paths).unwrap();
        assert!(
            paths
                .data_dir
                .join("store.prev")
                .symlink_metadata()
                .is_err()
        );
    }

    fn paths_in(tmp: &tempfile::TempDir) -> Paths {
        Paths {
            data_dir: tmp.path().join("app"),
        }
    }

    fn write_state(paths: &Paths, session: &SessionFile, db: &str) {
        write_session(&paths.session_file(), session).unwrap();
        fs::create_dir_all(paths.store_dir()).unwrap();
        fs::write(paths.store_dir().join("db"), db).unwrap();
    }

    fn stash_files(paths: &Paths) -> (Option<SessionFile>, String) {
        (
            read_session(&paths.data_dir.join("session.json.prev")).unwrap(),
            fs::read_to_string(paths.data_dir.join("store.prev").join("db")).unwrap(),
        )
    }

    #[test]
    fn existing_stash_is_never_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(&tmp);
        let old = sample();
        write_state(&paths, &old, "old");
        stash_local_state(&paths).unwrap();
        // Simulated crash: no restore, no discard. The next login --force
        // created a new session in the meantime.
        let mut newer = sample();
        newer.device_id = "NEWER".into();
        write_state(&paths, &newer, "newer");

        let err = stash_local_state(&paths).unwrap_err().to_string();
        assert!(
            err.contains("--restore-previous") && err.contains("logout"),
            "{err}"
        );
        assert_eq!(stash_files(&paths), (Some(old), "old".to_owned()));
        assert_eq!(read_session(&paths.session_file()).unwrap(), Some(newer));
    }

    #[test]
    fn restore_previous_puts_the_stash_back_after_a_crash() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(&tmp);
        let old = sample();
        write_state(&paths, &old, "old");
        stash_local_state(&paths).unwrap();
        // Crash during the login: a half-made store, no session file.
        fs::create_dir_all(paths.store_dir()).unwrap();
        fs::write(paths.store_dir().join("db"), "half").unwrap();
        let err = stash_refusal(&paths);
        assert!(
            err.contains("login --restore-previous") && !err.contains("logout"),
            "{err}"
        );

        restore_previous(&paths).unwrap();
        assert_eq!(read_session(&paths.session_file()).unwrap(), Some(old));
        assert_eq!(
            fs::read_to_string(paths.store_dir().join("db")).unwrap(),
            "old"
        );
        assert!(existing_stash(&paths).is_empty());
        assert!(restore_previous(&paths).is_err(), "nothing left to restore");
    }

    #[test]
    fn restore_previous_refuses_while_a_session_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(&tmp);
        let old = sample();
        write_state(&paths, &old, "old");
        stash_local_state(&paths).unwrap();
        let newer = sample();
        write_state(&paths, &newer, "newer");
        assert!(restore_previous(&paths).is_err());
        assert_eq!(stash_files(&paths), (Some(old), "old".to_owned()));
        assert_eq!(read_session(&paths.session_file()).unwrap(), Some(newer));
    }

    #[test]
    fn stash_refusal_does_not_blame_login_force() {
        // A plain login stashes too (a store without a session file), so
        // the advice must not claim the stash came from `login --force`.
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(&tmp);
        write_state(&paths, &sample(), "old");
        stash_local_state(&paths).unwrap();
        let without_session = stash_refusal(&paths);
        write_state(&paths, &sample(), "newer");
        let with_session = stash_refusal(&paths);
        assert_ne!(without_session, with_session);
        for text in [without_session, with_session] {
            assert!(text.contains("by an interrupted login;"), "{text}");
            assert!(!text.contains("--force"), "{text}");
        }
    }

    #[test]
    fn crash_between_the_two_renames_keeps_the_unstashed_store() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(&tmp);
        let old = sample();
        write_state(&paths, &old, "old");
        // Only the session file was moved aside.
        fs::rename(
            paths.session_file(),
            paths.data_dir.join("session.json.prev"),
        )
        .unwrap();
        restore_previous(&paths).unwrap();
        assert_eq!(read_session(&paths.session_file()).unwrap(), Some(old));
        assert_eq!(
            fs::read_to_string(paths.store_dir().join("db")).unwrap(),
            "old"
        );
    }

    #[test]
    fn rollback_restores_the_stash_even_when_cleanup_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = paths_in(&tmp);
        let old = sample();
        write_state(&paths, &old, "old");
        stash_local_state(&paths).unwrap();
        // A directory where the session file belongs: delete_local_state
        // cannot remove it with remove_file and fails.
        fs::create_dir_all(paths.session_file().join("x")).unwrap();
        assert!(delete_local_state(&paths).is_err());

        let err = rollback_failed_login::<()>(&paths, anyhow::anyhow!("login failed: M_FORBIDDEN"))
            .unwrap_err();
        assert_eq!(err.root_cause().to_string(), "login failed: M_FORBIDDEN");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("cleaning up after the failed login failed"),
            "{chain}"
        );
        // The stash is back in place: no advice about a stash or a logout.
        assert!(
            !chain.contains("logout") && !chain.contains("--restore-previous"),
            "{chain}"
        );
        assert_eq!(read_session(&paths.session_file()).unwrap(), Some(old));
        assert_eq!(
            fs::read_to_string(paths.store_dir().join("db")).unwrap(),
            "old"
        );
    }

    #[test]
    fn user_ids_differing_only_in_localpart_case_match() {
        let id = |s: &str| parse_user_id(s, "test").unwrap();
        assert_eq!(
            compare_user_ids(&id("@Alice:example.org"), &id("@alice:example.org")),
            UserIdMatch::CaseOnly
        );
        assert_eq!(
            compare_user_ids(&id("@alice:example.org"), &id("@alice:example.org")),
            UserIdMatch::Same
        );
        assert_eq!(
            compare_user_ids(&id("@alice:example.org"), &id("@bob:example.org")),
            UserIdMatch::Different
        );
        assert_eq!(
            compare_user_ids(&id("@alice:example.org"), &id("@alice:other.org")),
            UserIdMatch::Different
        );
    }

    #[test]
    fn user_ids_differing_in_server_name_case_match() {
        let id = |s: &str| parse_user_id(s, "test").unwrap();
        assert_eq!(
            compare_user_ids(&id("@alice:example.org"), &id("@Alice:Example.ORG")),
            UserIdMatch::CaseOnly
        );
        assert_eq!(
            compare_user_ids(
                &id("@alice:example.org:8448"),
                &id("@alice:EXAMPLE.org:8448")
            ),
            UserIdMatch::CaseOnly
        );
        assert_eq!(
            compare_user_ids(
                &id("@alice:example.org:8448"),
                &id("@alice:Example.org:443")
            ),
            UserIdMatch::Different
        );
        assert_eq!(
            compare_user_ids(&id("@alice:example.org"), &id("@alice:example.org:8448")),
            UserIdMatch::Different
        );

        let config = Config {
            homeserver: "https://m.example".into(),
            user_id: "@Alice:example.org".into(),
        };
        let mut session = sample();
        session.user_id = "@alice:example.org".into();
        check_session_user(&config, &session).unwrap();
        session.user_id = "@bob:example.org".into();
        let err = check_session_user(&config, &session)
            .unwrap_err()
            .to_string();
        assert!(err.contains("logout"), "{err}");
    }

    #[test]
    fn key_sharing_maps_to_strategy() {
        assert_eq!(
            KeySharing::VerifiedOnly.strategy(),
            CollectStrategy::OnlyTrustedDevices
        );
        assert_eq!(
            KeySharing::IncludeUnverified.strategy(),
            CollectStrategy::AllDevices
        );
    }
}
