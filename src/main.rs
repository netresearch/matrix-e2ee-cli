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
        /// Put back the session an interrupted `login --force` kept aside
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
    /// Room id (!x:server), alias (#x:server) or room name.
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
    /// Room id (!x:server), alias (#x:server) or room name.
    pub room: String,
    /// Number of timeline events to fetch (non-message events are skipped).
    #[arg(long, default_value_t = 10)]
    pub limit: u32,
    /// Print one JSON object per line.
    #[arg(long)]
    pub json: bool,
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
        Command::BackupRestore => commands::backup::run().await,
        Command::Logout { yes } => commands::logout::run(yes).await,
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
    fn login_and_backup_take_no_secret_argument() {
        assert!(Cli::try_parse_from(["m", "login", "hunter2"]).is_err());
        assert!(Cli::try_parse_from(["m", "backup-restore", "EsTx abcd"]).is_err());
    }
}
