# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-28

Commands that let the matrix-skill run every script through this tool's one session, a plaintext send for bots that cannot decrypt, and reads while the watch daemon runs. The new room commands that write (`create-room`, `invite`, `power-level --set`) have not run against a homeserver yet.

### Added

- `rooms [--json] [--search TERM] [--lookup NAME]`, `resolve ALIAS`, `create-room NAME`, `invite ROOM USER_ID` and `power-level ROOM (--show | --get USER | --set USER LEVEL)`, with the output of the matrix-skill's scripts of the same names; while the watch daemon runs they go through it ([#16](https://github.com/netresearch/matrix-e2ee-cli/pull/16)).
- `send --plaintext` sends an unencrypted `m.room.message` even in an encrypted room, after a warning, for bots without encryption such as a matrix-hookshot bridge ([#17](https://github.com/netresearch/matrix-e2ee-cli/pull/17)).
- `read` goes through the watch daemon while it runs; `read --request-keys` there waits for two of the daemon's syncs instead of syncing itself ([#17](https://github.com/netresearch/matrix-e2ee-cli/pull/17)).

### Changed

- **Breaking:** a watch daemon started from 0.3.0 or earlier answers `rooms`, `resolve`, `create-room`, `invite`, `power-level`, `read` and `send --plaintext` with `unknown op`, and these commands then stop instead of taking the direct path. Restart the daemon after the upgrade ([#16](https://github.com/netresearch/matrix-e2ee-cli/pull/16), [#17](https://github.com/netresearch/matrix-e2ee-cli/pull/17)).

## [0.3.0] - 2026-11-27

The behaviour of the matrix-skill's E2EE scripts, so the skill can call this CLI in their place, and device verification that an agent can drive. Key requests and agent verification have not run against a second, live device yet.

### Added

- `send` renders Markdown to HTML as the matrix-skill's `formatting.py` does, and takes `--mention`, `--mention-room`, `--thread`, `--reply`, `--to @user` (direct chat) and `--no-prefix`; `send` and `edit` prepend the `bot_prefix` of the config file ([#10](https://github.com/netresearch/matrix-e2ee-cli/pull/10)).
- `react` sets several keys in one call; `redact` takes `--reason` ([#9](https://github.com/netresearch/matrix-e2ee-cli/pull/9)).
- `read -l`, `read -k`/`--request-keys` and a `fetch-keys ROOM` command that waits for room keys from the user's other devices ([#11](https://github.com/netresearch/matrix-e2ee-cli/pull/11)).
- `verify --list`, and verification without a terminal: `verify --request` or `--listen` with `--hand-over` print the emojis as JSON and confirm only after `verify --confirm TOKEN` from a second process; `verify --cancel TOKEN` cancels ([#13](https://github.com/netresearch/matrix-e2ee-cli/pull/13)).
- `-q`/`--quiet` for `send`, `edit`, `react` and `redact` prints the event id only ([#10](https://github.com/netresearch/matrix-e2ee-cli/pull/10)).

### Changed

- **Breaking:** the default output of `send`, `edit`, `react` and `redact` is the text of the matrix-skill's scripts (`Event ID: $id` and similar) instead of the bare event id, and their `--json` output changed ([#9](https://github.com/netresearch/matrix-e2ee-cli/pull/9), [#10](https://github.com/netresearch/matrix-e2ee-cli/pull/10)).
- **Breaking:** `read --json` prints one JSON array in the format of `matrix-read-e2ee.py` instead of one object per line, newest event first ([#11](https://github.com/netresearch/matrix-e2ee-cli/pull/11)).

### Fixed

- `watch-daemon` writes the gap record of a failed append also when it restarts before the room's next record ([#8](https://github.com/netresearch/matrix-e2ee-cli/pull/8)).

## [0.2.0] - 2026-11-26

The commands the matrix-skill's E2EE scripts still needed, and a watch daemon that follows rooms in the background. None of the new commands has run against a homeserver yet.

### Added

- `edit`, `react` (add, `list`, `remove`, `replace`), `redact` and `download` (decrypts media; no decrypted copy stays in the store). `edit` shares room keys like `send`; matrix-sdk 0.20.0 sends reactions and redactions unencrypted ([#5](https://github.com/netresearch/matrix-e2ee-cli/pull/5)).
- `watch-daemon` (Linux and macOS): follows the rooms in `watch_rooms`, writes one JSONL log and one page per room, and back-fills limited sync timelines. While it runs, `send`, `edit`, `react` and `redact` go through its socket ([#6](https://github.com/netresearch/matrix-e2ee-cli/pull/6)).
- `watch ROOM`: reads one room's log from a named cursor, once or following ([#6](https://github.com/netresearch/matrix-e2ee-cli/pull/6)).

### Changed

- **Breaking for the matrix-skill's `roomlog.py` readers:** log, cursor and page files are named `<slug>-<12 hex of SHA-256 of the room id>`, logs hold `gap` records, aliases resolve through `rooms/index.json`, and page frontmatter strings are quoted. Logs and cursors written by `roomlog.py` are not read ([#6](https://github.com/netresearch/matrix-e2ee-cli/pull/6)).

## [0.1.0] - 2026-11-26

First release: an end-to-end encrypted Matrix command-line client on matrix-sdk 0.20.0, meant to replace the matrix-nio scripts of the matrix-skill.

### Added

- `login`, `status`, `logout` (with `--local-only` for a soft-logged-out device): a device of its own, "Matrix Skill E2EE (Rust)", with a passphrase-encrypted SQLite store; secrets come from the environment or a prompt, never from the command line ([#2](https://github.com/netresearch/matrix-e2ee-cli/pull/2)).
- `verify`: SAS emoji verification with one of the user's own devices, in either direction; the answer must come from a terminal ([#2](https://github.com/netresearch/matrix-e2ee-cli/pull/2)).
- `send` and `read`: room keys go to verified devices only unless `--trust-unverified-devices` is given; `read` marks unencrypted events and messages from unverified devices ([#2](https://github.com/netresearch/matrix-e2ee-cli/pull/2)).
- `backup-restore`: imports secrets and room keys from server-side key backup with a recovery key or passphrase ([#2](https://github.com/netresearch/matrix-e2ee-cli/pull/2)).
- `migrate-nio` (Linux and macOS): takes over the matrix-skill's matrix-nio 0.25.2 device with its keys, sessions and local trust ([#3](https://github.com/netresearch/matrix-e2ee-cli/pull/3)).
- Release binaries for x86_64 and aarch64 Linux (static musl), aarch64 and x86_64 macOS and x86_64 Windows, with `SHA256SUMS` and build provenance ([#1](https://github.com/netresearch/matrix-e2ee-cli/pull/1)).

[0.3.0]: https://github.com/netresearch/matrix-e2ee-cli/releases/tag/v0.3.0
[0.2.0]: https://github.com/netresearch/matrix-e2ee-cli/releases/tag/v0.2.0
[0.1.0]: https://github.com/netresearch/matrix-e2ee-cli/releases/tag/v0.1.0
