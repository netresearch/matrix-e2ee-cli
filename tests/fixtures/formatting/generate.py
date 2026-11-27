# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Write expected.json: Matrix HTML as the matrix-skill's formatting.py
renders it, for the differential test in src/formatting.rs.

    python3 -I -B generate.py <matrix-skill>/skills/matrix-communication/scripts/_lib > expected.json

Each "render" case holds the input, the --mention user ids and
markdown_to_html(inject_pills(text, mentions)), the HTML body
matrix-send-e2ee.py sends. Each "prefix" case holds
add_bot_prefix(text, prefix). The corpus is written here: single
constructs, mention forms, and whole announcement-style documents that
combine them; each document is also rendered fence by fence.
"""
import json
import re
import sys

sys.path.insert(0, sys.argv[1])
from formatting import add_bot_prefix, inject_pills, markdown_to_html  # noqa: E402

F = "```"

HAND = [
    ("heading levels", "# One\n## Two\n### Three\n#### Four\n##### Five\n###### Six\n####### Seven"),
    ("heading then text", "## Release 1.2\nThe text after it.\n\nA second paragraph."),
    ("dash list", "- one\n- two\n- three"),
    ("star and plus list", "* one\n+ two\n* three\nafter"),
    ("list then heading", "- a\n- b\n## H\ntext"),
    ("code block with lang", "before\n" + F + "python\nprint(\"<x> & 'y'\")\n**not bold**\n" + F + "\nafter"),
    ("code block without lang", F + "\nplain *code*\n\n\nkept blank lines\n" + F),
    ("unclosed code block", F + "sh\nnever closed *x*"),
    ("inline code", "run `make test` and `a < b`"),
    ("links", "[docs](https://example.org/a?b=1&c=2) and [mail](mailto:a@example.org) and [room](matrix:r/x:example.org)"),
    ("link with parentheses", "[jql](https://jira.example.org/issues/?jql=assignee=currentUser())"),
    ("javascript link", "[click](javascript:alert(1)) [x](  JavaScript:void(0)) [d](data:text/html,x)"),
    ("emphasis", "**bold** *italic* ~~gone~~ ||spoiler|| ** not ** * not *"),
    ("nested emphasis", "***both*** and **bold with *italic* inside**"),
    ("spoiler next to pipes", "|||x||| and ||a|| ||b||"),
    ("blockquote", "> quoted line\n> second\nafter\n\n> again"),
    ("table", "| Name | Value |\n|------|:-----:|\n| a | 1 |\n| b | 2 |\nafter"),
    ("table edge rows", "||\n|\n| only |"),
    ("html escaping", "<b>not bold</b> & \"quotes\" 'single' <script>x</script>"),
    ("escaped entity stays escaped", "&amp; &lt; &#106;"),
    ("forged placeholders", "{{BR}} {{CODEBLOCK_0}} \x00MDLINK0\x00 \x00MDLINK99\x00"),
    ("service urls", "See https://jira.example.org/browse/OPS-123 and https://github.com/netresearch/matrix-skill/pull/231 and https://github.com/netresearch/matrix-skill/commit/9f5663b0 and https://git.example.org/group/project/-/merge_requests/7 and https://gitlab.example.org/a/b/-/issues/3"),
    ("service url inside markdown link", "[the PR](https://github.com/o/r/pull/1)"),
    ("double scheme", "(https://http://example.org)"),
    ("matrix ids", "ping @alice:example.org in #ops:example.org, not \"@bob:example.org\" or /@carol:example.org"),
    ("newlines", "a\nb\n\n\nc\r\nd"),
    ("python whitespace", "\x1c- item\x1d\n\x1f## H\x1e\n**\x1cx**"),
    ("unicode", "Grüße 🎁 **fett** *kursiv* `ç` @jörg:example.org #räum:example.org"),
    ("plain", "just text"),
    ("empty", ""),
]

MENTIONS = [
    ("pill bare localpart", "thanks alice for the review", ["@alice:example.org"]),
    ("pill with at sign", "thanks @alice for the review", ["@alice:example.org"]),
    ("pill full id", "thanks @alice:example.org", ["@alice:example.org"]),
    ("pill already linked", "thanks [Alice](https://matrix.to/#/@alice:example.org)", ["@alice:example.org"]),
    ("pill only first", "alice and alice again", ["@alice:example.org"]),
    ("pill absent", "nobody named here", ["@alice:example.org"]),
    ("pill dotted localpart", "ping bjoern.marten and bjoern", ["@bjoern.marten:example.org", "@bjoern:example.org"]),
    ("pill duplicate mention", "hi alice", ["@alice:example.org", "@alice:example.org"]),
    ("pill word boundary", "alicex alice_ alice", ["@alice:example.org"]),
    ("pill regex characters", "hi a+b and a.b", ["@a+b:example.org", "@a.b:example.org"]),
    ("pill inside a longer word", "malice and alice", ["@alice:example.org"]),
    ("pill inside markdown", "**alice** said `alice`", ["@alice:example.org"]),
]

PREFIX = [
    ("plain", "hello", "🤖"),
    ("heading only", "## Title", "🤖"),
    ("heading and body", "## Title\nbody", "🤖"),
    ("heading, blank, body", "## Title\n\nbody", "🤖"),
    ("already prefixed", "🤖 hello", "🤖"),
    ("prefix with spaces", "  🤖 hello", " 🤖 "),
    ("prefixed after heading", "## Title\n\n🤖 body", "🤖"),
    ("indented heading", "  ## Title\nbody", "[bot]"),
    ("not a heading", "##Title", "[bot]"),
    ("blank prefix", "hello", "   "),
    ("python whitespace", "\x1c🤖 hi", "🤖"),
]

FENCE = re.compile(r"^" + F + r"[^\n]*\n(.*?)^" + F, re.DOTALL | re.MULTILINE)

DOCS = [
    ("release announcement", "\n".join([
        "## 📦 Release: matrix-e2ee-cli 0.3.0",
        "",
        "**What changed** for @alice:example.org and everyone in #ops:example.org:",
        "",
        "- *Markdown* in messages, rendered as HTML",
        "- Mentions: ping bob directly",
        "  - nested item with `inline code`",
        "  * nested star item",
        "    + deeper plus item",
        "- ~~removed~~ the old flag",
        "",
        "| Area | Before | After |",
        "|:-----|:------:|------:|",
        "| send | plain | **HTML** |",
        "| edit | plain | *HTML* |",
        "",
        "Upgrade with:",
        F + "sh",
        "cargo install --locked matrix-e2ee-cli",
        "echo \"done\" && exit 0",
        F,
        "",
        "Details: https://github.com/example/tool/pull/42, fix https://github.com/example/tool/commit/0123abcd",
        "and [the changelog](https://example.org/changelog#0.3.0).",
    ]), ["@bob:example.org"]),
    ("weekly digest", "\n".join([
        "# Weekly digest, week 47",
        "### Done",
        "1. OPS-12 closed: https://jira.example.org/browse/OPS-12",
        "2. MR https://git.example.org/infra/proxy/-/merge_requests/88 merged",
        "### Open",
        "* https://gitlab.example.org/team/app/-/issues/5 waits for carol",
        "* review by @dave:example.org",
        "",
        "> Note: the maintenance window moves",
        "> to Thursday 18:00.",
        "",
        "||spoiler: cake on Friday||",
        "Line one",
        "line two directly below",
        "",
        "",
        "after two blank lines",
    ]), ["@carol:example.org"]),
    ("postmortem", "\n".join([
        "## Postmortem: proxy outage",
        "**Impact:** 14 minutes, *all* sites behind the proxy.",
        "**Cause:** a config line `listen 443 ssl;` was missing; see [runbook](https://wiki.example.org/proxy(v2)).",
        "",
        "### Timeline",
        "| Time | Event |",
        "|------|-------|",
        "| 10:02 | alert fired |",
        "| 10:16 | fix deployed by @erin:example.org |",
        "",
        "### Config before",
        F,
        "server {",
        "    # listen 443 ssl;   <- missing",
        "    server_name example.org;",
        "}",
        F,
        "### Follow-ups",
        "- [ ] add a check",
        "- [x] restore service",
        "> \"Never again\" - the team",
    ]), []),
    ("heads-up with risky input", "\n".join([
        "⚠️ **Heads-up** <script>alert('x')</script> & friends",
        "[bad link](javascript:alert(1)) and [ok](mailto:ops@example.org) and [room](matrix:r/ops:example.org)",
        "*not italic * and ** not bold ** and a * bullet-like star",
        "Text with a trailing backslash \\",
        "tab\tseparated\tvalues",
        "",
        "- list right before a heading",
        "## Heading after a list",
        "| table | right after heading |",
        "plain line ends the table",
    ]), ["@frank:example.org"]),
    ("comparison", "\n".join([
        "## Option A vs. option B",
        "| | A | B |",
        "|---|---|---|",
        "| cost | ~~high~~ low | **medium** |",
        "| owner | @gina:example.org | hank |",
        "| link | [spec](https://example.org/a) | https://github.com/example/b/issues/9 |",
        "",
        "Recommendation: **A**, because *speed* matters more.",
    ]), ["@hank:example.org"]),
    ("incident update", "\n".join([
        "### 🔴 Incident ongoing",
        "> Status: investigating",
        "- affected: #web:example.org",
        "- not affected: #mail:example.org",
        "> back to a quote after the list",
        "",
        "Next update at 12:00. Ping ivan or @ivan if you see errors.",
        F + "json",
        "{\"error\": \"<timeout>\", \"code\": 504}",
        F,
        "Thanks, ivan!",
    ]), ["@ivan:example.org"]),
    ("deployment notice", "\n".join([
        "# Deployment",
        "",
        "Deploying **api** 2.4.1 to *production*:",
        "+ step 1: drain",
        "+ step 2: switch",
        "+ step 3: verify `/health`",
        "",
        "Rollback: `kubectl rollout undo deploy/api`",
        "Tracking: https://jira.example.org/browse/DEP-7 and https://git.example.org/ops/deploy/-/issues/31",
        "#### Contacts",
        "julia (on call), @kurt:example.org (backup)",
    ]), ["@julia:example.org", "@kurt:example.org"]),
]


def doc_cases():
    out = []
    for name, text, mentions in DOCS:
        out.append((name, text, mentions))
        for i, block in enumerate(FENCE.findall(text)):
            out.append((f"{name} fence {i + 1}", block, []))
    return out


render = []
for name, text in HAND:
    render.append({"name": name, "text": text, "mentions": [], "html": markdown_to_html(inject_pills(text, []))})
for name, text, mentions in MENTIONS:
    render.append({"name": name, "text": text, "mentions": mentions, "html": markdown_to_html(inject_pills(text, mentions))})
for name, text, mentions in doc_cases():
    render.append({"name": "document/" + name, "text": text, "mentions": mentions, "html": markdown_to_html(inject_pills(text, mentions))})

prefix = [{"name": n, "text": t, "prefix": p, "out": add_bot_prefix(t, p)} for n, t, p in PREFIX]

json.dump({"render": render, "prefix": prefix}, sys.stdout, ensure_ascii=False, indent=1)
sys.stdout.write("\n")
