# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Write expected.json: what the matrix-skill's room scripts print, for the
differential tests of rooms, resolve, create-room, invite and power-level.

    python3 -I -B generate.py <matrix-skill>/skills/matrix-communication/scripts > expected.json

Each script's main() runs with its HTTP layer (matrix_request) answered
from the corpus below, and for invite and power-level with the room
already resolved (the ROOM argument is resolved by the skill's wrapper,
not by these scripts' resolve_room_cli). Each case records argv, stdout,
stderr, the exit code and the request bodies the script sent.
"""
import contextlib
import importlib.util
import io
import json
import sys
import urllib.parse

SCRIPTS = sys.argv[1]
sys.path.insert(0, SCRIPTS)
import _lib  # noqa: E402
import _lib.rooms  # noqa: E402

ME = "@me:example.org"
CONFIG = {"homeserver": "https://matrix.example.org", "access_token": "t", "user_id": ME}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), f"{SCRIPTS}/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.load_config = lambda: dict(CONFIG)
    return module


def run(module, argv):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    sys.argv = ["script", *argv]
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            module.main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return {"argv": argv, "stdout": out.getvalue(), "stderr": err.getvalue(), "exit": code}


def member(user_id, displayname=None, membership="join"):
    content = {"membership": membership}
    if displayname is not None:
        content["displayname"] = displayname
    return {"state_key": user_id, "content": content}


# The joined rooms, in the order /joined_rooms lists them. "members" is the
# /members answer (None: the request fails).
ROOMS = [
    {"room_id": "!a:example.org", "name": "Agent Work", "alias": "#agent-work:example.org"},
    {"room_id": "!b:example.org", "name": "agent work archive"},
    {"room_id": "!c:example.org", "alias": "#ops:example.org"},
    {"room_id": "!d:example.org", "members": [
        member(ME, "Me"), member("@jane:example.org", "Jane Doe"),
        member("@gone:example.org", "Gone", "leave"), member("@banned:example.org", "Banned", "ban")]},
    {"room_id": "!e:example.org", "members": [
        member(ME), member("@max:example.org", None, "invite"), member("@anna:example.org", "Anna")]},
    {"room_id": "!f:example.org", "members": [
        member(ME, "Bob"), member("@bob1:example.org", "Bob"), member("@bob2:example.org", "Bob"),
        member("@carl:example.org", "carl"), member("@dora:example.org", "Dora"),
        member("@emil:example.org", "Émil"), member("@finn:example.org", "Finn"),
        member("@gus:example.org", "gus")]},
    {"room_id": "!g:example.org", "members": None},
    {"room_id": "!h:example.org", "members": [member(ME, "Me")]},
    {"room_id": "!i:example.org", "name": "Ünïcode Räum with a name longer than thirty-eight characters",
     "alias": "#a-very-long-alias-name-over-33-characters:example.org"},
    {"room_id": "!j:example.org", "name": "", "alias": "#empty-name:example.org"},
    {"room_id": "!k:example.org", "name": "Deploy"},
    {"room_id": "!l:example.org", "name": "Deploy Bot"},
    {"room_id": "!m:example.org", "members": [member(ME), member("@solo:example.org", "Solo", "invite")]},
]


def rooms_server(rooms):
    by_id = {r["room_id"]: r for r in rooms}

    def request(config, method, endpoint, data=None, api_version="v3"):
        if endpoint == "/joined_rooms":
            return {"joined_rooms": [r["room_id"] for r in rooms]}
        path, _, _query = endpoint.partition("?")
        parts = path.split("/")
        room = by_id[urllib.parse.unquote(parts[2])]
        if parts[3] == "members":
            if room.get("members") is None:
                return {"error": "forbidden", "errcode": "M_FORBIDDEN"}
            return {"chunk": room["members"]}
        key = {"m.room.name": "name", "m.room.canonical_alias": "alias"}[parts[4]]
        if key in room:
            return {key: room[key]}
        return {"error": "not found", "errcode": "M_NOT_FOUND"}

    return request


def rooms_cases():
    module = load("matrix-rooms")
    cases = []
    argvs = [
        [], ["--json"], ["--search", "agent"], ["-s", "@jane:example.org"],
        ["--search", "AGENT", "--json"], ["--search", "zzz"], ["--search", "zzz", "--json"],
        ["--search", ""], ["--lookup", "agent-work"], ["--lookup", "#ops:example.org"],
        ["--lookup", "OPS"], ["--lookup", "Jane Doe"], ["--lookup", "@jane:example.org"],
        ["-l", "agent work", "--json"], ["--lookup", "agent"], ["--lookup", "archive"],
        ["--lookup", "archive", "--json"], ["--lookup", "nothing"], ["--lookup", "deploy"],
        ["--lookup", "Solo"], ["--lookup", "bob"], ["--lookup", "agent-work", "--search", "zzz"],
        ["--lookup", ""], ["--lookup", "Empty Room"], ["--lookup", "!g:example.org"],
    ]
    for rooms, argv_list in ((ROOMS, argvs), ([], [[], ["--json"], ["--lookup", "x"]])):
        _lib.rooms.matrix_request = rooms_server(rooms)
        for argv in argv_list:
            case = run(module, argv)
            case["rooms"] = "corpus" if rooms else "none"
            cases.append(case)
    return cases


POWER = {
    "users": {ME: 100, "@bob:example.org": 50, "@old:example.org": "50"},
    "users_default": 0,
    "events": {"m.room.name": 50, "m.room.power_levels": 100},
    "events_default": 0,
    "state_default": 50,
    "ban": 50,
    "kick": 50,
    "redact": 50,
    "invite": 0,
    "notifications": {"room": 50},
    "x.unknown": ["Grüße 🙂", None, True, 1.5],
}
# No "users" and no "users_default": --get falls back to 0, --set adds "users".
BARE = {"events_default": 0, "state_default": 50}
# A users_default other than 0: --get and --set fall back to it.
DEFAULT = {"users": {ME: 100}, "users_default": 10}


def power_cases():
    module = load("matrix-power-level")
    module.resolve_room_cli = lambda config, room, json_out=False, debug=False: "!r:example.org"
    cases = []
    for name, content, argvs in (
        ("power", POWER, [
            ["--show"], ["--show", "-q"], ["--show", "--json"], ["--show", "--json", "--quiet"],
            ["--get", "@bob:example.org"], ["--get", "@nobody:example.org"], ["--get", "@old:example.org"],
            ["--get", "@bob:example.org", "-q"], ["--get", "@old:example.org", "--json"],
            ["--get", "@bob:example.org", "--json", "-q"],
            ["--set", "@bob:example.org", "100"], ["--set", "@new:example.org", "50"],
            ["--set", "@bob:example.org", " -5 "], ["--set", "@bob:example.org", "+7", "-q"],
            ["--set", "@bob:example.org", "25", "--json"], ["--set", "@bob:example.org", "abc"],
            ["--set", "@bob:example.org", "1.5"],
        ]),
        ("bare", BARE, [["--get", "@bob:example.org"], ["--set", "@bob:example.org", "50"], ["--show", "-q"]]),
        ("default", DEFAULT, [["--get", "@nobody:example.org"], ["--set", "@nobody:example.org", "20"],
                              ["--show", "-q"]]),
        ("error", None, [["--show"], ["--get", "@bob:example.org"], ["--set", "@bob:example.org", "50"]]),
    ):
        for argv in argvs:
            sent = []

            def request(config, method, endpoint, data=None, api_version="v3", content=content, sent=sent):
                if content is None:
                    return {"error": "You don't have permission", "errcode": "M_FORBIDDEN"}
                if method == "PUT":
                    sent.append(json.dumps(data))
                    return {"event_id": "$pl"}
                return json.loads(json.dumps(content))

            module.matrix_request = request
            case = run(module, ["!r:example.org", *argv])
            case["content"] = name
            case["put"] = sent
            cases.append(case)
    return cases


def create_cases():
    module = load("matrix-create-room")
    cases = []
    argvs = [
        ["LSB Project"],
        ["LSB Project", "--alias", "lsb", "--invite", "@a:example.org", "--invite", "@b:example.org",
         "--topic", "Landessportbund onboarding", "--preset", "public_chat"],
        ["LSB Project", "--alias", "lsb", "-q"],
        ["LSB Project", "--alias", "lsb", "--json"],
        ["LSB Project", "--alias", "lsb", "--json", "--quiet"],
        ["LSB Project", "--alias", "", "--topic", ""],
        ["Grüße 🙂", "--preset", "trusted_private_chat"],
        ["taken", "--alias", "taken"],
    ]
    for argv in argvs:
        sent = []

        def request(config, method, endpoint, data=None, api_version="v3", sent=sent, argv=argv):
            sent.append({"method": method, "endpoint": endpoint, "body": data})
            if argv[0] == "taken":
                return {"error": "Room alias already taken", "errcode": "M_ROOM_IN_USE"}
            return {"room_id": "!new:example.org"}

        module.matrix_request = request
        case = run(module, argv)
        case["requests"] = sent
        cases.append(case)
    return cases


def invite_cases():
    module = load("matrix-invite")
    module.resolve_room_cli = lambda config, room, json_out=False, debug=False: "!r:example.org"
    cases = []
    for argv, error in (
        (["LSB Project", "@jane:example.org"], None),
        (["LSB Project", "@jane:example.org", "-q"], None),
        (["LSB Project", "@jane:example.org", "--json"], None),
        (["LSB Project", "@jane:example.org", "--json", "--quiet"], None),
        (["LSB Project", "@jane:example.org"], "@jane:example.org is already in the room."),
    ):
        sent = []

        def request(config, method, endpoint, data=None, api_version="v3", sent=sent, error=error):
            sent.append({"method": method, "endpoint": endpoint, "body": data})
            return {"error": error, "errcode": "M_FORBIDDEN"} if error else {}

        module.matrix_request = request
        case = run(module, argv)
        case["requests"] = sent
        cases.append(case)
    return cases


def resolve_cases():
    module = load("matrix-resolve")
    cases = []

    def request(config, method, endpoint, data=None, api_version="v3"):
        alias = urllib.parse.unquote(endpoint.rsplit("/", 1)[1])
        if alias == "#ops:example.org":
            return {"room_id": "!c:example.org", "servers": ["example.org"]}
        return {"error": f"Room alias {alias} not found", "errcode": "M_NOT_FOUND"}

    _lib.rooms.matrix_request = request
    for argv in (["#ops:example.org"], ["#ops:example.org", "--json"], ["ops"], ["ops", "--json"],
                 ["#missing:example.org"], ["#missing:example.org", "--json"]):
        cases.append(run(module, argv))
    return cases


json.dump(
    {
        "me": ME,
        "rooms_corpus": ROOMS,
        "power_contents": {"power": POWER, "bare": BARE, "default": DEFAULT},
        "rooms": rooms_cases(),
        "power_level": power_cases(),
        "create_room": create_cases(),
        "invite": invite_cases(),
        "resolve": resolve_cases(),
    },
    sys.stdout,
    ensure_ascii=False,
    indent=1,
)
sys.stdout.write("\n")
