# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/netresearch/matrix-e2ee-cli/releases/tag/v0.2.0
[0.1.0]: https://github.com/netresearch/matrix-e2ee-cli/releases/tag/v0.1.0
