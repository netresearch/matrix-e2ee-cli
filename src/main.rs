//! matrix-e2ee-cli: end-to-end encrypted Matrix messaging from the command line.

// matrix-sdk's sync future is deep enough to exceed the default limit when
// it is spawned (the Send check recurses through it).
#![recursion_limit = "256"]

mod commands;
mod config;
mod daemon_client;
#[cfg(all(test, unix))]
mod daemon_test_support;
mod formatting;
mod room_arg;
mod roomlog;
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
    /// Read the last messages of a room, decrypted, newest first.
    Read(ReadArgs),
    /// Ask your other devices for the room keys of the messages this device
    /// cannot decrypt, then sync to receive them. A session already asked
    /// for is not asked again.
    FetchKeys(FetchKeysArgs),
    /// Edit one of your own messages (encrypted if the room is encrypted).
    Edit(EditArgs),
    /// Add, remove, swap or list your own reactions on a message.
    React(ReactArgs),
    /// Redact (delete) an event, if your power level allows it.
    Redact(RedactArgs),
    /// Download the attachment of a file, image, video or audio message.
    Download(DownloadArgs),
    /// Run the watch daemon: it holds the store, logs the rooms in
    /// config.json's "watch_rooms" and carries out send, react, redact and
    /// edit for the other commands while it runs (Linux and macOS).
    WatchDaemon(WatchDaemonArgs),
    /// Follow a watched room's log: a summary of what is new since the
    /// cursor, then one line per event. Needs no store and no lock.
    Watch(WatchArgs),
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
#[command(group(clap::ArgGroup::new("mode").required(true).args(["request", "listen", "list", "confirm", "cancel"])))]
pub struct VerifyArgs {
    /// Start verification towards this device of your own account.
    ///
    /// Without a terminal on stdin and stderr, the emoji are printed as one
    /// JSON line and the command waits for `verify --confirm` or
    /// `verify --cancel` from a second process; it never confirms on its own.
    #[arg(long, value_name = "DEVICE_ID")]
    pub request: Option<String>,
    /// Wait for a verification request from one of your own devices
    /// (without a terminal: as for --request).
    #[arg(long)]
    pub listen: bool,
    /// List your account's devices: id, name, verified or not, this device.
    #[arg(long)]
    pub list: bool,
    /// With --list: one JSON object per device.
    #[arg(long, conflicts_with_all = ["request", "listen", "confirm", "cancel"])]
    pub json: bool,
    /// Confirm the emoji of a verification that waits without a terminal,
    /// after the person compared them and said they match. Without
    /// TRANSACTION_ID: the only waiting verification.
    #[arg(long, value_name = "TRANSACTION_ID", num_args = 0..=1)]
    pub confirm: Option<Option<String>>,
    /// Cancel a verification that waits without a terminal. Without
    /// TRANSACTION_ID: the only waiting verification.
    #[arg(long, value_name = "TRANSACTION_ID", num_args = 0..=1)]
    pub cancel: Option<Option<String>>,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 180, value_name = "SECONDS")]
    pub timeout: u64,
}

#[derive(Debug, Args)]
#[command(allow_missing_positional = true)]
pub struct SendArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name. Omit with --to.
    #[arg(required_unless_present = "to")]
    pub room: Option<String>,
    /// The message, in Markdown: sent with an HTML body when it renders to more than its text.
    pub message: String,
    /// Send to the existing direct chat with this user (from m.direct) instead of ROOM; never creates a room.
    #[arg(long, value_name = "@user:server", conflicts_with = "room")]
    pub to: Option<String>,
    /// Send as m.notice (for automation).
    #[arg(long, conflicts_with = "emote")]
    pub notice: bool,
    /// Send as m.emote (no bot prefix).
    #[arg(long)]
    pub emote: bool,
    /// Reply in the thread of this root event.
    #[arg(long, value_name = "EVENT_ID")]
    pub thread: Option<String>,
    /// Reply to this event.
    #[arg(long, value_name = "EVENT_ID")]
    pub reply: Option<String>,
    /// Notify this user (repeatable): sets m.mentions, and pills the name where it appears in the text.
    #[arg(long, value_name = "@user:server")]
    pub mention: Vec<String>,
    /// Notify everyone in the room (@room).
    #[arg(long)]
    pub mention_room: bool,
    /// Do not add the bot_prefix of config.json.
    #[arg(long)]
    pub no_prefix: bool,
    /// Share this message's room key with unverified devices too (this message only).
    #[arg(long)]
    pub trust_unverified_devices: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
    /// Print only the event id.
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// Number of timeline events to fetch (non-message events are skipped).
    #[arg(short = 'l', long, default_value_t = 10)]
    pub limit: u32,
    /// Print the messages as one JSON array (matrix-read-e2ee.py's format).
    #[arg(long)]
    pub json: bool,
    /// For undecryptable messages: wait and sync 6 times (5 s each, plus up
    /// to 5 s per sync) so the key requests reach your other devices and
    /// their keys arrive, then read again.
    /// matrix-sdk asks only when one of your other devices is verified.
    /// A session already asked for is not asked again.
    #[arg(short = 'k', long)]
    pub request_keys: bool,
}

#[derive(Debug, Args)]
pub struct FetchKeysArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// Number of timeline events to scan.
    #[arg(long, default_value_t = 100)]
    pub limit: u32,
    /// Seconds to sync and wait for keys from your other devices.
    #[arg(long, default_value_t = 60, value_name = "SECONDS")]
    pub sync_time: u64,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// The message to edit ($...); it must be one of your own.
    pub event_id: String,
    /// The new text, in Markdown; it replaces the whole message.
    pub new_message: String,
    /// Do not add the bot_prefix of config.json.
    #[arg(long)]
    pub no_prefix: bool,
    /// Share this edit's room key with unverified devices too (this edit only).
    #[arg(long)]
    pub trust_unverified_devices: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
    /// Print only the edit's event id.
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct ReactArgs {
    /// Room id (!x:server, or !x in room version 12), alias (#x:server) or room name.
    pub room: String,
    /// The event to react to ($...).
    pub event_id: String,
    /// The reaction key, usually an emoji; several are set in one call, in
    /// the order given. Sent unencrypted, also in an encrypted room
    /// (matrix-sdk 0.20.0): the homeserver can read it.
    #[arg(
        value_name = "KEY",
        required_unless_present = "list",
        conflicts_with = "list"
    )]
    pub keys: Vec<String>,
    /// Remove your own KEY reactions instead of adding them.
    #[arg(long, conflicts_with_all = ["replace", "list"])]
    pub remove: bool,
    /// Status swap: set KEY, then remove your own reactions with any of OLD;
    /// with several KEYs, after the last one is set.
    #[arg(long, num_args = 1.., value_name = "OLD", conflicts_with = "list")]
    pub replace: Option<Vec<String>>,
    /// List your own reactions on the event (key and reaction event id).
    #[arg(long)]
    pub list: bool,
    /// Accepted for callers of matrix-react.py; has no effect: reactions
    /// are sent unencrypted, so no room key is shared with any device.
    #[arg(long)]
    pub trust_unverified_devices: bool,
    /// Print only the reaction event id, one line per KEY (an empty line
    /// for --remove).
    #[arg(short, long)]
    pub quiet: bool,
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
    /// Why; shown to the room's members (the same as --reason).
    #[arg(value_name = "REASON", conflicts_with = "reason_option")]
    pub reason: Option<String>,
    /// Why; shown to the room's members.
    #[arg(long = "reason", id = "reason_option", value_name = "REASON")]
    pub reason_option: Option<String>,
    /// Print only the redaction's event id.
    #[arg(short, long)]
    pub quiet: bool,
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

impl RedactArgs {
    /// The reason, from --reason or the positional REASON.
    pub fn reason(&self) -> Option<&str> {
        self.reason_option.as_deref().or(self.reason.as_deref())
    }
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("action").required(true).args(["start", "stop", "status", "foreground"])))]
pub struct WatchDaemonArgs {
    /// Start in the background (output in daemon.log in the data directory).
    #[arg(long)]
    pub start: bool,
    /// Stop the daemon that answers on the socket.
    #[arg(long)]
    pub stop: bool,
    /// Ask the running daemon for its state.
    #[arg(long)]
    pub status: bool,
    /// Run in this terminal.
    #[arg(long)]
    pub foreground: bool,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Room id (!x:server), or the alias or room id as written in "watch_rooms".
    pub room: String,
    /// Name this reader's position, so several sessions can follow one room
    /// (at most 64 bytes).
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub cursor: String,
    /// Skip the "since last" line.
    #[arg(long)]
    pub no_summary: bool,
    /// Print what is new and exit instead of following.
    #[arg(long)]
    pub once: bool,
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
        Command::FetchKeys(args) => commands::fetch_keys::run(args).await,
        Command::Edit(args) => commands::edit::run(args).await,
        Command::React(args) => commands::react::run(args).await,
        Command::Redact(args) => commands::redact::run(args).await,
        Command::Download(args) => commands::download::run(args).await,
        Command::WatchDaemon(args) => commands::watch_daemon::run(args).await,
        Command::Watch(args) => commands::watch::run(args).await,
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

    fn send_args(argv: &[&str]) -> Result<SendArgs, clap::Error> {
        let cli = Cli::try_parse_from([&["m", "send"][..], argv].concat())?;
        let Command::Send(args) = cli.command else {
            panic!("not send")
        };
        Ok(args)
    }

    #[test]
    fn send_takes_room_or_to() {
        let args = send_args(&["r", "hi"]).unwrap();
        assert_eq!(
            (args.room.as_deref(), args.to.as_deref()),
            (Some("r"), None)
        );
        assert_eq!(args.message, "hi");
        for argv in [&["--to", "@u:e", "hi"][..], &["hi", "--to", "@u:e"]] {
            let args = send_args(argv).unwrap();
            assert_eq!(args.room, None, "{argv:?}");
            assert_eq!(args.to.as_deref(), Some("@u:e"), "{argv:?}");
            assert_eq!(args.message, "hi", "{argv:?}");
        }
        assert!(
            send_args(&["r", "hi", "--to", "@u:e"]).is_err(),
            "ROOM and --to"
        );
        assert!(send_args(&["hi"]).is_err(), "neither ROOM nor --to");
    }

    #[test]
    fn send_options_of_matrix_send_e2ee() {
        let args = send_args(&[
            "r",
            "hi",
            "--thread",
            "$root",
            "--reply",
            "$p",
            "--mention",
            "@a:e",
            "--mention",
            "@b:e",
            "--mention-room",
            "--no-prefix",
            "-q",
        ])
        .unwrap();
        assert_eq!(args.thread.as_deref(), Some("$root"));
        assert_eq!(args.reply.as_deref(), Some("$p"));
        assert_eq!(args.mention, ["@a:e", "@b:e"]);
        assert!(args.mention_room && args.no_prefix && args.quiet);
        assert!(send_args(&["r", "hi", "--quiet", "--json"]).is_ok());
    }

    #[test]
    fn read_takes_the_callers_arguments() {
        // netresearch-jira claiming-a-ticket.md, through the thin
        // matrix-read-e2ee.py: '#it:netresearch.de' --limit 400 --json
        let Command::Read(args) = Cli::try_parse_from([
            "m",
            "read",
            "#it:netresearch.de",
            "--limit",
            "400",
            "--json",
        ])
        .unwrap()
        .command
        else {
            panic!("not read")
        };
        assert_eq!(
            (args.room.as_str(), args.limit, args.json, args.request_keys),
            ("#it:netresearch.de", 400, true, false)
        );
        // it-maintenance ticket-flow.py: ROOM --limit N --json
        assert!(Cli::try_parse_from(["m", "read", "!r:e", "--limit", "20", "--json"]).is_ok());
        // Python's short forms and default.
        let Command::Read(args) = Cli::try_parse_from(["m", "read", "r", "-l", "5", "-k"])
            .unwrap()
            .command
        else {
            panic!("not read")
        };
        assert_eq!((args.limit, args.request_keys, args.json), (5, true, false));
        let Command::Read(args) = Cli::try_parse_from(["m", "read", "r"]).unwrap().command else {
            panic!("not read")
        };
        assert_eq!((args.limit, args.request_keys), (10, false));
        assert!(Cli::try_parse_from(["m", "read", "r", "--request-keys"]).is_ok());
    }

    #[test]
    fn fetch_keys_takes_pythons_options() {
        // matrix-fetch-keys.py ROOM --sync-time 60 (the skill's CLAUDE.md)
        let Command::FetchKeys(args) =
            Cli::try_parse_from(["m", "fetch-keys", "ROOM", "--sync-time", "60"])
                .unwrap()
                .command
        else {
            panic!("not fetch-keys")
        };
        assert_eq!(
            (args.room.as_str(), args.limit, args.sync_time),
            ("ROOM", 100, 60)
        );
        let Command::FetchKeys(args) =
            Cli::try_parse_from(["m", "fetch-keys", "r", "--limit", "50", "--sync-time", "5"])
                .unwrap()
                .command
        else {
            panic!("not fetch-keys")
        };
        assert_eq!((args.limit, args.sync_time), (50, 5));
        assert!(Cli::try_parse_from(["m", "fetch-keys"]).is_err());
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

    fn verify(a: &[&str]) -> VerifyArgs {
        match Cli::try_parse_from([&["m", "verify"][..], a].concat())
            .unwrap_or_else(|e| panic!("{a:?}: {e}"))
            .command
        {
            Command::Verify(args) => args,
            _ => panic!("not verify"),
        }
    }

    #[test]
    fn verify_accepts_the_callers_invocations() {
        // matrix-skill CLAUDE.md: matrix-e2ee-verify.py --request DEVICE --timeout 180
        let request = verify(&["--request", "DEVICE", "--timeout", "180"]);
        assert_eq!(request.request.as_deref(), Some("DEVICE"));
        assert_eq!(request.timeout, 180);
        // matrix-e2ee-verify.py --list
        let list = verify(&["--list"]);
        assert!(list.list && !list.json);
        assert!(verify(&["--list", "--json"]).json);
        assert_eq!(verify(&["--listen"]).timeout, 180);
    }

    #[test]
    fn verify_confirm_and_cancel_take_an_optional_transaction_id() {
        assert_eq!(verify(&["--confirm"]).confirm, Some(None));
        assert_eq!(
            verify(&["--confirm", "tx1"]).confirm,
            Some(Some("tx1".to_owned()))
        );
        assert_eq!(verify(&["--cancel"]).cancel, Some(None));
        assert_eq!(
            verify(&["--cancel", "tx1"]).cancel,
            Some(Some("tx1".to_owned()))
        );
        let parse = |a: &[&str]| Cli::try_parse_from([&["m", "verify"][..], a].concat());
        assert!(parse(&["--confirm", "--cancel"]).is_err());
        assert!(parse(&["--confirm", "--listen"]).is_err());
        assert!(parse(&["--list", "--request", "D"]).is_err());
        assert!(parse(&["--json"]).is_err(), "--json only with --list");
        assert!(parse(&["--listen", "--json"]).is_err());
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
        assert!(!args.no_prefix && !args.quiet);
        assert_eq!(args.new_message, "new");
        let Command::Edit(args) =
            Cli::try_parse_from(["m", "edit", "r", "$e", "new", "--no-prefix", "-q"])
                .unwrap()
                .command
        else {
            panic!("not edit")
        };
        assert!(args.no_prefix && args.quiet);
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
        assert_eq!(args.keys, vec!["✅".to_owned()]);
        assert_eq!(args.replace, Some(vec!["▶️".to_owned(), "🩹".to_owned()]));
    }

    #[test]
    fn react_key_help_warns_that_it_is_unencrypted() {
        let cli = Cli::command();
        let react = cli.find_subcommand("react").expect("react subcommand");
        let key = react
            .get_arguments()
            .find(|a| a.get_id() == "keys")
            .expect("KEY argument");
        let help = key.get_help().expect("KEY help").to_string();
        assert!(
            help.contains("unencrypted") && help.contains("encrypted room"),
            "{help}"
        );
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
        assert_eq!(args.reason(), Some("spam"));
        assert!(Cli::try_parse_from(["m", "redact", "r", "$e", "a", "b"]).is_err());
    }

    #[test]
    fn redact_takes_the_reason_as_matrix_redact_py_does() {
        // it-maintenance ticket-flow.py:
        // _matrix("matrix-redact.py", room, state["play_reaction"], "--reason", "abgeschlossen")
        let parse = |a: &[&str]| {
            Cli::try_parse_from([&["m", "redact", "#it:netresearch.de", "$r"][..], a].concat())
        };
        let Command::Redact(args) = parse(&["--reason", "abgeschlossen"]).unwrap().command else {
            panic!("not redact")
        };
        assert_eq!(args.reason(), Some("abgeschlossen"));
        assert!(!args.quiet && !args.json);
        assert!(
            parse(&["spam", "--reason", "x"]).is_err(),
            "one reason only"
        );
        let Command::Redact(args) = parse(&["-q"]).unwrap().command else {
            panic!("not redact")
        };
        assert!(args.quiet);
        assert_eq!(args.reason(), None);
    }

    #[test]
    fn react_accepts_the_callers_invocations() {
        let parse = |a: &[&str]| {
            Cli::try_parse_from([&["m", "react", "#it:netresearch.de", "$eventId"][..], a].concat())
        };
        let react = |a: &[&str]| match parse(a).unwrap_or_else(|e| panic!("{a:?}: {e}")).command {
            Command::React(args) => args,
            _ => panic!("not react"),
        };
        // netresearch-jira claiming-a-ticket.md
        let swap = react(&["🩹", "--replace", "▶️", "✅"]);
        assert_eq!(swap.keys, vec!["🩹".to_owned()]);
        assert_eq!(swap.replace, Some(vec!["▶️".to_owned(), "✅".to_owned()]));
        assert_eq!(react(&["🤖"]).keys, vec!["🤖".to_owned()]);
        let remove = react(&["✅", "--remove"]);
        assert!(remove.remove && remove.keys == vec!["✅".to_owned()]);
        let list = react(&["--list"]);
        assert!(list.list && list.keys.is_empty());
        // it-maintenance ticket-flow.py: room, event_id, emoji, *extra, *_trust_args()
        let flow = react(&["✅", "--replace", "▶️", "--trust-unverified-devices"]);
        assert!(flow.trust_unverified_devices);
        assert_eq!(flow.replace, Some(vec!["▶️".to_owned()]));
        assert!(react(&["▶️", "--trust-unverified-devices"]).trust_unverified_devices);
        // Several keys, as matrix-react.py's EMOJI with nargs "*".
        let many = react(&["▶️", "🤖"]);
        assert_eq!(many.keys, vec!["▶️".to_owned(), "🤖".to_owned()]);
        let many = react(&["✅", "🤖", "--replace", "▶️", "🩹"]);
        assert_eq!(many.keys.len(), 2);
        assert_eq!(many.replace.map(|r| r.len()), Some(2));
        assert_eq!(react(&["✅", "🤖", "--remove"]).keys.len(), 2);
        assert!(react(&["✅", "-q"]).quiet);
        assert!(
            parse(&["✅", "🤖", "--list"]).is_err(),
            "--list takes no KEY"
        );
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
    fn watch_daemon_needs_exactly_one_action() {
        assert!(Cli::try_parse_from(["m", "watch-daemon"]).is_err());
        assert!(Cli::try_parse_from(["m", "watch-daemon", "--start", "--stop"]).is_err());
        for action in ["--start", "--stop", "--status", "--foreground"] {
            assert!(
                Cli::try_parse_from(["m", "watch-daemon", action]).is_ok(),
                "{action}"
            );
        }
    }

    #[test]
    fn watch_takes_a_room_and_a_cursor() {
        let Command::Watch(args) =
            Cli::try_parse_from(["m", "watch", "!r:e", "--cursor", "s1", "--once"])
                .unwrap()
                .command
        else {
            panic!("not watch")
        };
        assert_eq!((args.room.as_str(), args.cursor.as_str()), ("!r:e", "s1"));
        assert!(args.once && !args.no_summary);
        let Command::Watch(args) = Cli::try_parse_from(["m", "watch", "r"]).unwrap().command else {
            panic!("not watch")
        };
        assert_eq!(args.cursor, "default");
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
