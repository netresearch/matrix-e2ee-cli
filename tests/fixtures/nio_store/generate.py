#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the matrix-nio 0.25.2 store that the migrate-nio tests read.

Offline: no homeserver is contacted. The store is written by nio itself
(AsyncClient.restore_login -> DefaultStore, pickle key "DEFAULT_KEY"), the
same way the matrix-skill scripts create theirs, with:

- the Olm account of @test:example.org / TESTDEVICE,
- one outbound Megolm session for !room:example.org, which stores the
  matching inbound group session,
- one Olm session from our account to a second local account (PEER),
- one Megolm session of PEER imported the way matrix-key-backup.py
  --import-keys imports a backed-up key (InboundGroupSession.import_session,
  empty forwarding chain, save_inbound_group_session).

Next to the store it writes credentials.json in the layout of
matrix-skill's _lib/e2ee.py, and expected.json with what the migration has
to reproduce: identity keys, session ids, and one Olm and one Megolm
ciphertext that only the migrated sessions can decrypt.

store/ and expected.json belong together: regenerate both, never one.

Run:
  uv run --isolated --no-project --with 'matrix-nio[e2e]==0.25.2' \
      tests/fixtures/nio_store/generate.py tests/fixtures/nio_store
"""

import asyncio
import json
import os
import shutil
import sys

from importlib.metadata import version

import olm
from nio import AsyncClient, AsyncClientConfig
from nio.crypto import InboundGroupSession

USER_ID = "@test:example.org"
DEVICE_ID = "TESTDEVICE"
ROOM_ID = "!room:example.org"
IMPORTED_ROOM_ID = "!imported:example.org"
ACCESS_TOKEN = "fixture-access-token-not-a-secret"
OLM_PLAINTEXT = "olm fixture plaintext"
MEGOLM_PLAINTEXT = "megolm fixture plaintext"
IMPORTED_PLAINTEXT = "imported megolm fixture plaintext"


async def main(out_dir: str) -> None:
    installed = version("matrix-nio")
    if installed != "0.25.2":
        sys.exit(f"matrix-nio {installed} is installed; the fixture needs 0.25.2")
    store = os.path.join(out_dir, "store")
    shutil.rmtree(store, ignore_errors=True)
    os.makedirs(store, mode=0o700)

    client = AsyncClient(
        "https://example.org",
        USER_ID,
        device_id=DEVICE_ID,
        store_path=store,
        config=AsyncClientConfig(store_sync_tokens=True, encryption_enabled=True),
    )
    client.restore_login(USER_ID, DEVICE_ID, ACCESS_TOKEN)
    machine = client.olm
    ours = machine.account.identity_keys

    # Megolm: the outbound session stores its inbound twin in the store.
    machine.create_outbound_group_session(ROOM_ID)
    outbound = machine.outbound_group_sessions[ROOM_ID]
    outbound.mark_as_shared()  # nobody to share with offline
    megolm_ciphertext = outbound.encrypt(MEGOLM_PLAINTEXT)

    # Olm: our account opens a session to PEER; PEER answers on it.
    peer = olm.Account()
    peer.generate_one_time_keys(1)
    peer_otk = next(iter(peer.one_time_keys["curve25519"].values()))
    peer_curve = peer.identity_keys["curve25519"]
    session = machine.create_session(peer_otk, peer_curve)
    prekey = session.encrypt("hello peer")
    machine.save_session(peer_curve, session)  # the ratchet moved
    peer_session = olm.InboundSession(peer, prekey, ours["curve25519"])
    assert peer_session.decrypt(prekey) == "hello peer"
    reply = peer_session.encrypt(OLM_PLAINTEXT)

    # An imported key, as matrix-key-backup.py stores one from the backup.
    remote = olm.OutboundGroupSession()
    remote_inbound = olm.InboundGroupSession(remote.session_key)
    exported = remote_inbound.export_session(remote_inbound.first_known_index)
    imported = InboundGroupSession.import_session(
        exported,
        peer.identity_keys["ed25519"],
        peer_curve,
        IMPORTED_ROOM_ID,
        [],
    )
    assert machine.inbound_group_store.add(imported)
    machine.store.save_inbound_group_session(imported)
    imported_ciphertext = remote.encrypt(IMPORTED_PLAINTEXT)

    await client.close()

    # nio names the database "<user_id>_<device_id>.db". A ":" cannot be part of
    # a file name on Windows, where the repository is checked out for CI, so
    # the fixture keeps a neutral name and the tests copy it back under nio's.
    os.rename(
        os.path.join(store, f"{USER_ID}_{DEVICE_ID}.db"),
        os.path.join(store, "nio-store.db"),
    )

    creds = os.path.join(store, "credentials.json")
    fd = os.open(creds, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(
            {"user_id": USER_ID, "device_id": DEVICE_ID, "access_token": ACCESS_TOKEN},
            handle,
            indent=2,
        )

    expected = {
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "curve25519": ours["curve25519"],
        "ed25519": ours["ed25519"],
        "olm_sessions": [{"session_id": session.id, "sender_key": peer_curve}],
        "megolm_sessions": [
            {
                "session_id": outbound.id,
                "room_id": ROOM_ID,
                "imported": False,
                "ciphertext": megolm_ciphertext,
                "plaintext": MEGOLM_PLAINTEXT,
            },
            {
                "session_id": imported.id,
                "room_id": IMPORTED_ROOM_ID,
                "imported": True,
                "ciphertext": imported_ciphertext,
                "plaintext": IMPORTED_PLAINTEXT,
            },
        ],
        "olm_message": {
            "message_type": reply.message_type,
            "ciphertext": reply.ciphertext,
            "plaintext": OLM_PLAINTEXT,
        },
    }
    with open(os.path.join(out_dir, "expected.json"), "w", encoding="utf-8") as handle:
        json.dump(expected, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
