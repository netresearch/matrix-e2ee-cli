//! matrix-e2ee-cli: end-to-end encrypted Matrix messaging from the command line.

// matrix-sdk's sync future is deep enough to exceed the default limit when
// it is spawned (the Send check recurses through it).
#![recursion_limit = "256"]

mod commands;
mod config;
mod room_arg;
mod session;
mod text;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "matrix-e2ee-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Log in with a password and create a new device "Matrix Skill E2EE (Rust)".
    ///
    /// The password comes from MATRIX_PASSWORD or a prompt, never from the
    /// command line.
    Login {
        /// Replace an existing local session (the old device stays on the server).
        #[arg(long)]
        force: bool,
        /// Put back the session an interrupted login kept aside
        /// (session.json.prev, store.prev) instead of logging in.
        #[arg(long, conflicts_with = "force")]
        restore_previous: bool,
    },
    /// Show user, device, cross-signing/verification and key-backup state.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Verify this device with one of your own devices (SAS emoji).
    Verify(VerifyArgs),
    /// Send a message (encrypted if the room is encrypted).
    Send(SendArgs),
    /// Read the last messages of a room, decrypted.
    Read(ReadArgs),
    /// Edit one of your own messages (encrypted if the room is encrypted).
    Edit(EditArgs),
    /// Add, remove, swap or list your own reactions on a message.
    React(ReactArgs),
    /// Redact (delete) an event, if your power level allows it.
    Redact(RedactArgs),
    /// Download the attachment of a file, image, video or audio message.
    Download(DownloadArgs),
    /// Import secrets and room keys from server-side key backup with a recovery key.
    ///
    /// The key comes from MATRIX_RECOVERY_KEY or a prompt, never from the
    /// command line.
    BackupRestore,
    /// Log this device out on the server and delete the local session and store.
    Logout {
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
        /// When the server reports a soft logout (the token is suspended and
        /// the device may remain on the server), delete the local session and
        /// store anyway. Other failures still keep the local state.
        #[arg(long)]
        local_only: bool,
    },
    /// Take over the matrix-skill (matrix-nio) E2EE device: convert its store
    /// into this tool's session and store, keeping identity and room keys.
    ///
    /// The nio store is only read. Refuses while this tool has a session.
    MigrateNio {
        /// The matrix-skill store directory (default:
        /// $XDG_DATA_HOME/matrix-skill/store, ~/.local/share/matrix-skill/store).
        #[arg(long, value_name = "PATH")]
        store: Option<std::path::PathBuf>,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
        /// After the migration, sync once to check the access token.
        #[arg(long)]
        check_online: bool,
    },
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("mode").required(true).args(["request", "listen"])))]
pub struct VerifyArgs {
    /// Start verification towards this device of your own account.
    #[arg(long, value_name = "DEVICE_ID")]
    pub request: Option<String>,
    /// Wait for a verification request from one of your own devices.
    #[arg(long)]
    pub listen: bool,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 180, value_name = "SECONDS")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    pub message: String,
    /// Send as m.notice (for automation).
    #[arg(long, conflicts_with = "emote")]
    pub notice: bool,
    /// Send as m.emote.
    #[arg(long)]
    pub emote: bool,
    /// Share this message's room key with unverified devices too (this message only).
    #[arg(long)]
    pub trust_unverified_devices: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// Number of timeline events to fetch (non-message events are skipped).
    #[arg(long, default_value_t = 10)]
    pub limit: u32,
    /// Print one JSON object per line.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// The message to edit ($...); it must be one of your own.
    pub event_id: String,
    /// The new text; it replaces the whole message.
    pub new_message: String,
    /// Share this edit's room key with unverified devices too (this edit only).
    #[arg(long)]
    pub trust_unverified_devices: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ReactArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// The event to react to ($...).
    pub event_id: String,
    /// The reaction key, usually an emoji.
    #[arg(required_unless_present = "list", conflicts_with = "list")]
    pub key: Option<String>,
    /// Remove your own KEY reaction instead of adding one.
    #[arg(long, conflicts_with_all = ["replace", "list"])]
    pub remove: bool,
    /// Status swap: set KEY, then remove your own reactions with any of OLD.
    #[arg(long, num_args = 1.., value_name = "OLD", conflicts_with = "list")]
    pub replace: Option<Vec<String>>,
    /// List your own reactions on the event (key and reaction event id).
    #[arg(long)]
    pub list: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RedactArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// The event to redact ($...).
    pub event_id: String,
    /// Why; shown to the room's members.
    pub reason: Option<String>,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DownloadArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// The file, image, video or audio message ($...).
    pub event_id: String,
    /// Directory to save into (created if missing; default: the current one).
    #[arg(long, value_name = "DIR")]
    pub output: Option<std::path::PathBuf>,
    /// File name instead of the one the message gives (sanitized the same way).
    #[arg(long, value_name = "NAME")]
    pub filename: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Login {
            force,
            restore_previous,
        } => commands::login::run(force, restore_previous).await,
        Command::Status { json } => commands::status::run(json).await,
        Command::Verify(args) => commands::verify::run(args).await,
        Command::Send(args) => commands::send::run(args).await,
        Command::Read(args) => commands::read::run(args).await,
        Command::Edit(args) => commands::edit::run(args).await,
        Command::React(args) => commands::react::run(args).await,
        Command::Redact(args) => commands::redact::run(args).await,
        Command::Download(args) => commands::download::run(args).await,
        Command::BackupRestore => commands::backup::run().await,
        Command::Logout { yes, local_only } => commands::logout::run(yes, local_only).await,
        Command::MigrateNio {
            store,
            yes,
            check_online,
        } => {
            #[cfg(unix)]
            {
                commands::migrate_nio::run(store, yes, check_online).await
            }
            #[cfg(not(unix))]
            {
                let _ = (store, yes, check_online);
                Err(anyhow::anyhow!(
                    "migrate-nio is only available on Linux and macOS, where the matrix-skill keeps its nio store"
                ))
            }
        }
    };
    let code = match result {
        Ok(()) => 0,
        Err(err) => {
            // One line: the context chain joined, never a backtrace.
            let msg = err
                .chain()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(": ");
            // Server error texts and names in the chain are not ours.
            eprintln!("error: {}", text::term(&msg));
            1
        }
    };
    // Exit here instead of dropping the runtime: dropping it waits for
    // blocking tasks, and a stdin prompt abandoned by a timeout never ends.
    use std::io::Write;
    std::io::stdout().flush().ok();
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn notice_and_emote_are_exclusive() {
        assert!(Cli::try_parse_from(["m", "send", "r", "hi", "--notice", "--emote"]).is_err());
        assert!(Cli::try_parse_from(["m", "send", "r", "hi", "--notice"]).is_ok());
    }

    #[test]
    fn verify_needs_exactly_one_mode() {
        assert!(Cli::try_parse_from(["m", "verify"]).is_err());
        assert!(Cli::try_parse_from(["m", "verify", "--listen", "--request", "D"]).is_err());
        assert!(Cli::try_parse_from(["m", "verify", "--listen"]).is_ok());
    }

    #[test]
    fn edit_takes_three_arguments() {
        assert!(Cli::try_parse_from(["m", "edit", "r", "$e", "new"]).is_ok());
        assert!(Cli::try_parse_from(["m", "edit", "r", "$e"]).is_err());
        let cli = Cli::try_parse_from([
            "m",
            "edit",
            "r",
            "$e",
            "new",
            "--trust-unverified-devices",
            "--json",
        ])
        .unwrap();
        let Command::Edit(args) = cli.command else {
            panic!("not edit")
        };
        assert!(args.trust_unverified_devices && args.json);
        assert_eq!(args.new_message, "new");
    }

    #[test]
    fn react_modes() {
        let parse = |a: &[&str]| Cli::try_parse_from([&["m", "react", "r", "$e"][..], a].concat());
        assert!(parse(&["✅"]).is_ok());
        assert!(parse(&[]).is_err(), "KEY is required without --list");
        assert!(parse(&["--list"]).is_ok());
        assert!(parse(&["✅", "--list"]).is_err(), "--list takes no KEY");
        assert!(parse(&["✅", "--remove"]).is_ok());
        assert!(parse(&["--remove"]).is_err());
        assert!(parse(&["✅", "--remove", "--replace", "▶️"]).is_err());
        assert!(parse(&["--list", "--remove"]).is_err());
        assert!(parse(&["✅", "--replace"]).is_err(), "--replace needs OLD");
        let Command::React(args) = parse(&["✅", "--replace", "▶️", "🩹"]).unwrap().command
        else {
            panic!("not react")
        };
        assert_eq!(args.key.as_deref(), Some("✅"));
        assert_eq!(args.replace, Some(vec!["▶️".to_owned(), "🩹".to_owned()]));
    }

    #[test]
    fn redact_reason_is_optional() {
        assert!(Cli::try_parse_from(["m", "redact", "r", "$e"]).is_ok());
        let Command::Redact(args) = Cli::try_parse_from(["m", "redact", "r", "$e", "spam"])
            .unwrap()
            .command
        else {
            panic!("not redact")
        };
        assert_eq!(args.reason.as_deref(), Some("spam"));
        assert!(Cli::try_parse_from(["m", "redact", "r", "$e", "a", "b"]).is_err());
    }

    #[test]
    fn download_options() {
        assert!(Cli::try_parse_from(["m", "download", "r", "$e"]).is_ok());
        let Command::Download(args) = Cli::try_parse_from([
            "m",
            "download",
            "r",
            "$e",
            "--output",
            "d",
            "--filename",
            "f.txt",
        ])
        .unwrap()
        .command
        else {
            panic!("not download")
        };
        assert_eq!(args.output, Some(std::path::PathBuf::from("d")));
        assert_eq!(args.filename.as_deref(), Some("f.txt"));
        assert!(Cli::try_parse_from(["m", "download", "r", "$e", "--overwrite"]).is_err());
    }

    #[test]
    fn logout_takes_local_only() {
        assert!(Cli::try_parse_from(["m", "logout", "--yes", "--local-only"]).is_ok());
    }

    #[test]
    fn login_and_backup_take_no_secret_argument() {
        assert!(Cli::try_parse_from(["m", "login", "hunter2"]).is_err());
        assert!(Cli::try_parse_from(["m", "backup-restore", "EsTx abcd"]).is_err());
    }
}
