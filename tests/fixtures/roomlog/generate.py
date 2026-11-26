# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Write expected.json: records as the matrix-skill's roomlog.py builds them,
for the record-shape test in src/roomlog.rs. Only the records: the file
names, the room pages and the gap records are matrix-e2ee-cli's own format
and are tested in src/roomlog.rs itself.

    TZ=UTC python3 -B generate.py <matrix-skill>/skills/matrix-communication/scripts/_lib > expected.json
"""
import sys, json
sys.path.insert(0, sys.argv[1])
import roomlog
from roomlog import build_record
E = {"event_id": "$abc", "sender": "@tobias.hein:example.org", "sender_display": "tobias.hein", "type": "m.text", "body": "Ihr seid cool", "ts": 1786568100000, "room_id": "!r:example.org"}
cases = [
  dict(seq=1, event=E, own_user_id="@me:example.org", own_display_name="me"),
  dict(seq=2, event={**E, "body": "Gr\u00fc\u00dfe \U0001F381 \"quoted\" back\\slash tab\there\nnew\x01ctl\x7f\u2028end", "reply_to": "$p", "thread_root": "$t"}, own_user_id="@me:example.org", own_display_name="me"),
  dict(seq=3, event={**E, "type": "encrypted", "body": None, "session_id": "sess1", "sender_display": None}, own_user_id="@me:example.org", own_display_name="me"),
  dict(seq=4, event={**E, "type": "reaction", "body": "\u2705", "relates_to": "$abc"}, own_user_id="@me:example.org", own_display_name="me", subject="so bin beim RA"),
  dict(seq=5, event={**E, "type": "redaction", "body": None, "redacts": "$abc", "reason": "Tippfehler"}, own_user_id="@me:example.org", own_display_name="me"),
  dict(seq=6, event={**E, "type": "membership", "body": "join", "sender_display": ""}, own_user_id="@me:example.org", own_display_name="me"),
  dict(seq=7, event={**E, "type": "m.emote", "body": "winkt " * 60}, own_user_id="@me:example.org", own_display_name="me"),
  dict(seq=8, event={**E, "sender": "@me:example.org", "sender_key": "K", "body": "hallo me und Basti"}, own_user_id="@me:example.org", own_display_name="Basti", own_sender_key="K"),
  dict(seq=9, event={**E, "type": "m.notice", "body": "  lots \x1c of\u00a0 space\u3000 ", "room_id": None}, own_user_id="@me:example.org", own_display_name=None),
  dict(seq=10, event={**E, "type": "reaction", "body": "", "relates_to": "$abc"}, own_user_id="@me:example.org", own_display_name="me"),
]
out = []
for c in cases:
    r = build_record(**c)
    out.append(json.dumps(r, ensure_ascii=False, separators=(",", ":")))
print(json.dumps({"lines": out}, ensure_ascii=False))
