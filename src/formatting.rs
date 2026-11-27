//! Message formatting as the matrix-skill's `_lib/formatting.py`: Markdown to
//! Matrix HTML (`markdown_to_html`), mention pills (`inject_pills`) and the
//! bot prefix (`add_bot_prefix`).
//!
//! A port, not a Markdown library: formatting.py is a regex pipeline of its
//! own (no paragraphs, lines joined with `<br>`, service URLs shortened,
//! Matrix ids linked), which CommonMark renderers such as pulldown-cmark or
//! comrak do not reproduce. The steps, their order and their patterns follow
//! the Python module one by one, quirks included, so both send the same
//! `formatted_body`. `tests/fixtures/formatting/expected.json` holds the
//! Python output for a corpus; the test below compares against it.
//!
//! Python's `\s` and `str.strip()` count U+001C..U+001F as whitespace,
//! Rust's do not; [`PY_SPACE`] and [`is_py_space`] add them.

use std::sync::LazyLock;

use anyhow::{Context, Result};
use fancy_regex::{Captures, Regex, RegexBuilder};

/// The characters of Python's `\s` in a str pattern, for a character class.
const PY_SPACE: &str = r"\s\x{1c}-\x{1f}";

/// Python's `str.isspace()`: Unicode White_Space plus U+001C..U+001F.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

fn py_lstrip(s: &str) -> &str {
    s.trim_start_matches(is_py_space)
}

/// Python's `re` backtracks without a limit; fancy-regex stops at its
/// limit with an error. A high one keeps long messages renderable.
const BACKTRACK_LIMIT: usize = 100_000_000;

fn re(pattern: &str) -> Regex {
    RegexBuilder::new(&pattern.replace("PYS", PY_SPACE))
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .expect("a formatting pattern does not compile")
}

/// `re.sub(pattern, rep, text)` (`count` 0: all matches).
fn sub(
    pattern: &Regex,
    text: &str,
    count: usize,
    rep: impl FnMut(&Captures<'_, str>) -> String,
) -> Result<String> {
    Ok(pattern
        .try_replacen(text, count, rep)
        .context("cannot render the message as HTML")?
        .into_owned())
}

pub const MATRIX_TO: &str = "https://matrix.to/#/";

// `[text](url)` where the URL may hold balanced parentheses one level deep.
static MD_LINK: LazyLock<Regex> = LazyLock::new(|| re(r"\[([^\]]+)\]\(((?:[^()]|\([^()]*\))+)\)"));
static PROTECTED: LazyLock<Regex> = LazyLock::new(|| re(r"\x00MDLINK(\d+)\x00"));
static JIRA: LazyLock<Regex> = LazyLock::new(|| re(r"https?://[^/]+/browse/([A-Z][A-Z0-9]+-\d+)"));
static DOUBLE_HTTPS: LazyLock<Regex> = LazyLock::new(|| re(r"\(https://https?://"));
static GITHUB_ISSUE: LazyLock<Regex> =
    LazyLock::new(|| re(r"https?://github\.com/([^/]+)/([^/]+)/(issues|pull)/(\d+)"));
static GITHUB_COMMIT: LazyLock<Regex> =
    LazyLock::new(|| re(r"https?://github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]{7,40})"));
static GITLAB: LazyLock<Regex> =
    LazyLock::new(|| re(r"https?://[^/]+/([^/]+/[^/]+)/-/(issues|merge_requests)/(\d+)"));

static CODE_BLOCK: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)```(\w*)\n(.*?)```"));
static SPOILER: LazyLock<Regex> = LazyLock::new(|| re(r"(?<!\|)\|\|(.+?)\|\|(?!\|)"));
static USER_ID: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?<!["'/])(@[a-zA-Z0-9._=-]+:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"#));
static ROOM_ALIAS: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?<!["'/])(#[a-zA-Z0-9._=-]+:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"#));
static STRIKE: LazyLock<Regex> = LazyLock::new(|| re(r"~~(?=[^PYS])(.+?)(?<=[^PYS])~~"));
static BOLD: LazyLock<Regex> = LazyLock::new(|| re(r"\*\*(?=[^PYS])(.+?)(?<=[^PYS])\*\*"));
static ITALIC: LazyLock<Regex> = LazyLock::new(|| re(r"\*(?=[^PYS])([^*\n]+?)(?<=[^PYS])\*"));
static INLINE_CODE: LazyLock<Regex> = LazyLock::new(|| re(r"`(.+?)`"));
static BLANK_LINES: LazyLock<Regex> = LazyLock::new(|| re(r"\n{2,}"));
static HEADING: LazyLock<Regex> = LazyLock::new(|| re(r"^(#{1,6})[PYS]+(.+)$"));
static BR_BEFORE_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\{\{BR\}\}(?=<ul>|<li>|</ul>|</li>|<blockquote>|</blockquote>|<pre>|<table>|<tr>|</table>|<h[1-6]>)",
    )
});
static BR_AFTER_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| re(r"(</ul>|</li>|</blockquote>|</pre>|</table>|</tr>|</h[1-6]>)\{\{BR\}\}"));
static BR_AFTER_OPEN: LazyLock<Regex> = LazyLock::new(|| re(r"(<blockquote>|<table>)\{\{BR\}\}"));
static HEADING_START: LazyLock<Regex> = LazyLock::new(|| re(r"^#{1,6}[PYS]+"));

// The links markdown_to_html has made (the input itself is escaped, so
// every `<a ` in the text is one of them).
static ANCHOR: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)<a [^>]*>.*?</a>"));

/// [`sub`] on the text outside `<a ...>...</a>` elements, href included.
fn sub_outside_links(
    pattern: &Regex,
    text: &str,
    mut rep: impl FnMut(&Captures<'_, str>) -> String,
) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for link in ANCHOR.find_iter(text) {
        let link = link.context("cannot find the links of the message")?;
        out.push_str(&sub(pattern, &text[last..link.start()], 0, &mut rep)?);
        out.push_str(link.as_str());
        last = link.end();
    }
    out.push_str(&sub(pattern, &text[last..], 0, &mut rep)?);
    Ok(out)
}

fn group<'a>(caps: &'a Captures<'_, str>, i: usize) -> &'a str {
    caps.get(i).map_or("", |m| m.as_str())
}

/// `shorten_service_urls`: Jira, GitHub and GitLab URLs as short linked text;
/// URLs inside a `[text](url)` link are left as they are.
pub fn shorten_service_urls(text: &str) -> Result<String> {
    let mut protected: Vec<String> = Vec::new();
    let text = sub(&MD_LINK, text, 0, |c| {
        let idx = protected.len();
        protected.push(group(c, 0).to_owned());
        format!("\x00MDLINK{idx}\x00")
    })?;
    let text = sub(&JIRA, &text, 0, |c| {
        format!("[{}](https://{})", group(c, 1), group(c, 0))
    })?;
    let text = sub(&DOUBLE_HTTPS, &text, 0, |_| "(https://".to_owned())?;
    let text = sub(&GITHUB_ISSUE, &text, 0, |c| {
        format!(
            "[{}/{}#{}]({})",
            group(c, 1),
            group(c, 2),
            group(c, 4),
            group(c, 0)
        )
    })?;
    let text = sub(&GITHUB_COMMIT, &text, 0, |c| {
        format!(
            "[{}/{}@{}]({})",
            group(c, 1),
            group(c, 2),
            group(c, 3),
            group(c, 0)
        )
    })?;
    let text = sub(&GITLAB, &text, 0, |c| {
        format!("[{}#{}]({})", group(c, 1), group(c, 3), group(c, 0))
    })?;
    // A placeholder typed into the message stays as it is unless its index
    // is one of ours.
    sub(&PROTECTED, &text, 0, |c| {
        group(c, 1)
            .parse::<usize>()
            .ok()
            .and_then(|idx| protected.get(idx))
            .cloned()
            .unwrap_or_else(|| group(c, 0).to_owned())
    })
}

/// `html.escape(text, quote=True)`.
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// `html.unescape` of text [`escape_html`] produced: there every `&`
/// starts one of its five entities, so undoing those five in one pass gives
/// what Python's full unescape gives.
fn unescape_escaped(text: &str) -> String {
    const ENTITIES: [(&str, char); 5] = [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&#x27;", '\''),
    ];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        match ENTITIES.iter().find(|(e, _)| rest.starts_with(e)) {
            Some((entity, c)) => {
                out.push(*c);
                rest = &rest[entity.len()..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

const LINK_SCHEMES: [&str; 4] = ["http://", "https://", "mailto:", "matrix:"];

/// `_markdown_link`: a link for web, mail and matrix URLs only; any other
/// scheme keeps the link text without a link.
fn markdown_link(caps: &Captures<'_, str>) -> String {
    let (label, url) = (group(caps, 1), group(caps, 2));
    let target = py_strip(&unescape_escaped(url)).to_lowercase();
    if !LINK_SCHEMES.iter().any(|s| target.starts_with(s)) {
        return label.to_owned();
    }
    format!("<a href=\"{url}\">{label}</a>")
}

/// `markdown_to_html`: Matrix HTML for a message body.
pub fn markdown_to_html(text: &str) -> Result<String> {
    let html = shorten_service_urls(text)?;
    // The input is text, not markup: escaped before any tag is generated.
    let html = escape_html(&html);

    let mut code_blocks: Vec<String> = Vec::new();
    let html = sub(&CODE_BLOCK, &html, 0, |c| {
        let (lang, code) = (group(c, 1), group(c, 2));
        let idx = code_blocks.len();
        code_blocks.push(if lang.is_empty() {
            format!("<pre><code>{code}</code></pre>")
        } else {
            format!("<pre><code class=\"language-{lang}\">{code}</code></pre>")
        });
        format!("{{{{CODEBLOCK_{idx}}}}}")
    })?;

    let html = sub(&SPOILER, &html, 0, |c| {
        format!("<span data-mx-spoiler>{}</span>", group(c, 1))
    })?;
    let html = sub(&MD_LINK, &html, 0, markdown_link)?;
    let pill = |c: &Captures<'_, str>| format!("<a href=\"{MATRIX_TO}{0}\">{0}</a>", group(c, 1));
    // Deviates from formatting.py, which also links ids inside an href:
    // only text outside the links made so far is searched.
    let html = sub_outside_links(&USER_ID, &html, pill)?;
    let html = sub_outside_links(&ROOM_ALIAS, &html, pill)?;
    let html = sub(&STRIKE, &html, 0, |c| format!("<del>{}</del>", group(c, 1)))?;
    let html = sub(&BOLD, &html, 0, |c| {
        format!("<strong>{}</strong>", group(c, 1))
    })?;
    let html = sub(&ITALIC, &html, 0, |c| format!("<em>{}</em>", group(c, 1)))?;
    let html = sub(&INLINE_CODE, &html, 0, |c| {
        format!("<code>{}</code>", group(c, 1))
    })?;
    let html = sub(&BLANK_LINES, &html, 0, |_| "\n".to_owned())?;

    let mut in_list = false;
    let mut in_quote = false;
    let mut in_table = false;
    let mut result: Vec<String> = Vec::new();
    for line in html.split('\n') {
        let stripped = py_strip(line);

        if let Some(caps) = HEADING
            .captures(stripped)
            .context("cannot render the message as HTML")?
        {
            if in_quote {
                result.push("</blockquote>".into());
                in_quote = false;
            }
            if in_list {
                result.push("</ul>".into());
                in_list = false;
            }
            if in_table {
                result.push("</table>".into());
                in_table = false;
            }
            let level = group(&caps, 1).len();
            result.push(format!("<h{level}>{}</h{level}>", group(&caps, 2)));
            continue;
        }

        let table_row = stripped.starts_with('|') && stripped.ends_with('|');
        if table_row {
            let parts: Vec<&str> = stripped.split('|').collect();
            let cells: Vec<&str> = parts[1..parts.len() - 1]
                .iter()
                .map(|c| py_strip(c))
                .collect();
            let separator = cells
                .iter()
                .filter(|c| !c.is_empty())
                .all(|c| c.chars().all(|ch| ch == '-' || ch == ':'));
            if separator {
                continue;
            }
            if in_quote {
                result.push("</blockquote>".into());
                in_quote = false;
            }
            if in_list {
                result.push("</ul>".into());
                in_list = false;
            }
            let tag = if in_table { "td" } else { "th" };
            if !in_table {
                result.push("<table>".into());
                in_table = true;
            }
            let row: String = cells
                .iter()
                .map(|c| format!("<{tag}>{c}</{tag}>"))
                .collect();
            result.push(format!("<tr>{row}</tr>"));
            continue;
        }

        if in_table {
            result.push("</table>".into());
            in_table = false;
        }

        if let Some(quoted) = stripped.strip_prefix("&gt; ") {
            if !in_quote {
                if in_list {
                    result.push("</ul>".into());
                    in_list = false;
                }
                result.push("<blockquote>".into());
                in_quote = true;
            }
            result.push(quoted.to_owned());
        } else if ["- ", "* ", "+ "].iter().any(|b| stripped.starts_with(b)) {
            if in_quote {
                result.push("</blockquote>".into());
                in_quote = false;
            }
            if !in_list {
                result.push("<ul>".into());
                in_list = true;
            }
            result.push(format!("<li>{}</li>", &stripped[2..]));
        } else if stripped.is_empty() {
            if in_quote {
                result.push("</blockquote>".into());
                in_quote = false;
            }
        } else {
            if in_quote {
                result.push("</blockquote>".into());
                in_quote = false;
            }
            if in_list {
                result.push("</ul>".into());
                in_list = false;
            }
            result.push(line.to_owned());
        }
    }
    if in_quote {
        result.push("</blockquote>".into());
    }
    if in_list {
        result.push("</ul>".into());
    }
    if in_table {
        result.push("</table>".into());
    }

    let html = result.join("{{BR}}");
    let html = sub(&BR_BEFORE_BLOCK, &html, 0, |_| String::new())?;
    let html = sub(&BR_AFTER_BLOCK, &html, 0, |c| group(c, 1).to_owned())?;
    let html = sub(&BR_AFTER_OPEN, &html, 0, |c| group(c, 1).to_owned())?;
    let mut html = html.replace("{{BR}}", "<br>");
    for (idx, block) in code_blocks.iter().enumerate() {
        html = html.replace(&format!("{{{{CODEBLOCK_{idx}}}}}"), block);
    }
    Ok(html)
}

/// `add_bot_prefix`: the prefix before the message, or after a leading
/// heading; a message that already opens with it is returned unchanged.
pub fn add_bot_prefix(message: &str, prefix: &str) -> Result<String> {
    let marker = py_strip(prefix);
    if !marker.is_empty() && py_lstrip(message).starts_with(marker) {
        return Ok(message.to_owned());
    }
    let mut lines: Vec<String> = message.split('\n').map(str::to_owned).collect();
    let first_line = py_strip(&lines[0]).to_owned();
    if HEADING_START
        .is_match(&first_line)
        .context("cannot add the bot prefix")?
    {
        let body = lines[1..]
            .iter()
            .find(|l| !py_strip(l).is_empty())
            .map_or("", String::as_str);
        if !marker.is_empty() && py_lstrip(body).starts_with(marker) {
            return Ok(message.to_owned());
        }
        lines[0] = first_line;
        if lines.len() > 1 {
            lines.insert(1, format!("\n{prefix}"));
        } else {
            lines.push(format!("\n{prefix}"));
        }
        Ok(lines.join("\n"))
    } else {
        Ok(format!("{prefix} {message}"))
    }
}

/// `inject_pills`: the first plain `@localpart` or `localpart` of each user
/// becomes a pill link, for the HTML body only. A name that is not in the
/// text is not inserted; one already pilled by hand is left alone.
///
/// Deviates from formatting.py, which matches inside a word ("malice") and
/// inside earlier pills: here only at a token boundary, outside any link.
pub fn inject_pills(markdown: &str, user_ids: &[String]) -> Result<String> {
    let mut markdown = markdown.to_owned();
    for user_id in user_ids {
        if markdown.contains(&format!("{MATRIX_TO}{user_id}")) {
            continue;
        }
        let localpart = user_id
            .split(':')
            .next()
            .unwrap_or_default()
            .trim_start_matches('@');
        let pattern = RegexBuilder::new(&format!(
            r"(?<![\w@])@?{}\b",
            fancy_regex::escape(localpart)
        ))
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .context("cannot build the mention pattern")?;
        // Links and pills, those of earlier users included, are left alone.
        let mut links = Vec::new();
        for link in MD_LINK.find_iter(&markdown) {
            let link = link.context("cannot find the links of the message")?;
            links.push(link.start()..link.end());
        }
        let mut hit = None;
        for found in pattern.find_iter(&markdown) {
            let found = found.context("cannot find the mention")?;
            if !links
                .iter()
                .any(|l| found.start() < l.end && l.start < found.end())
            {
                hit = Some(found.start()..found.end());
                break;
            }
        }
        if let Some(range) = hit {
            markdown.replace_range(range, &format!("[{localpart}]({MATRIX_TO}{user_id})"));
        }
    }
    Ok(markdown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/formatting/expected.json")).unwrap()
    }

    fn strings(v: &Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect()
    }

    /// Fixture cases where this port deliberately differs from
    /// formatting.py: (name, reason, the HTML this port renders).
    const DEVIATIONS: &[(&str, &str, &str)] = &[
        (
            "pill dotted localpart",
            "a later mention must not replace text inside an earlier pill",
            "ping <a href=\"https://matrix.to/#/@bjoern.marten:example.org\">bjoern.marten</a> and <a href=\"https://matrix.to/#/@bjoern:example.org\">bjoern</a>",
        ),
        (
            "ids inside a link URL",
            "user and room ids are linked only outside existing links, never inside an href",
            "<a href=\"https://example.org/?user=@alice:example.org\">profile</a> by <a href=\"https://matrix.to/#/@bob:example.org\">@bob:example.org</a>, <a href=\"https://example.org/?r=#ops:example.org\">room</a> in <a href=\"https://matrix.to/#/#web:example.org\">#web:example.org</a>",
        ),
        (
            "pill inside a longer word",
            "a localpart matches only at a token boundary, not inside a word",
            "malice and <a href=\"https://matrix.to/#/@alice:example.org\">alice</a>",
        ),
    ];

    #[test]
    fn renders_like_formatting_py() {
        let fixture = fixture();
        let cases = fixture["render"].as_array().unwrap();
        assert!(cases.len() > 50, "the corpus is incomplete");
        let mut differ = Vec::new();
        let mut deviations_seen = 0;
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let text = case["text"].as_str().unwrap();
            let python = case["html"].as_str().unwrap();
            let mentions = strings(&case["mentions"]);
            let got = markdown_to_html(&inject_pills(text, &mentions).unwrap()).unwrap();
            let expected = match DEVIATIONS.iter().find(|(n, _, _)| *n == name) {
                Some((_, reason, rust)) => {
                    deviations_seen += 1;
                    assert_ne!(
                        python, *rust,
                        "{name}: listed as a deviation ({reason}), but Python renders the same"
                    );
                    *rust
                }
                None => python,
            };
            if got != expected {
                differ.push(format!(
                    "{name}:\n  expected: {expected:?}\n  rust:     {got:?}"
                ));
            }
        }
        assert_eq!(
            deviations_seen,
            DEVIATIONS.len(),
            "a listed deviation is not in the fixture"
        );
        assert!(differ.is_empty(), "{}", differ.join("\n"));
    }

    #[test]
    fn ids_inside_a_link_stay_out_of_its_href() {
        assert_eq!(
            markdown_to_html("[profile](https://example.org/?user=@alice:example.org)").unwrap(),
            "<a href=\"https://example.org/?user=@alice:example.org\">profile</a>"
        );
        // An id outside the link, on the same line, is still linked.
        assert_eq!(
            markdown_to_html(
                "[profile](https://example.org/?user=@alice:example.org) by @bob:example.org"
            )
            .unwrap(),
            "<a href=\"https://example.org/?user=@alice:example.org\">profile</a> by <a href=\"https://matrix.to/#/@bob:example.org\">@bob:example.org</a>"
        );
        assert_eq!(
            markdown_to_html("[r](https://example.org/?r=#ops:example.org) #web:example.org")
                .unwrap(),
            "<a href=\"https://example.org/?r=#ops:example.org\">r</a> <a href=\"https://matrix.to/#/#web:example.org\">#web:example.org</a>"
        );
    }

    #[test]
    fn a_pill_needs_a_token_boundary() {
        let alice = ["@alice:example.org".to_owned()];
        assert_eq!(
            inject_pills("malice and alice", &alice).unwrap(),
            "malice and [alice](https://matrix.to/#/@alice:example.org)"
        );
        assert_eq!(
            inject_pills("hi @alice!", &alice).unwrap(),
            "hi [alice](https://matrix.to/#/@alice:example.org)!"
        );
        assert_eq!(
            inject_pills("alice first", &alice).unwrap(),
            "[alice](https://matrix.to/#/@alice:example.org) first"
        );
        assert_eq!(
            inject_pills("bob@alice.org", &alice).unwrap(),
            "bob@alice.org"
        );
    }

    #[test]
    fn a_later_mention_leaves_earlier_pills_and_links_alone() {
        let users = [
            "@bjoern.marten:example.org".to_owned(),
            "@bjoern:example.org".to_owned(),
        ];
        assert_eq!(
            inject_pills("ping bjoern.marten and bjoern", &users).unwrap(),
            "ping [bjoern.marten](https://matrix.to/#/@bjoern.marten:example.org) and [bjoern](https://matrix.to/#/@bjoern:example.org)"
        );
        // A link written by hand is no place for a pill either.
        let bob = ["@bob:example.org".to_owned()];
        assert_eq!(
            inject_pills("[bob's notes](https://example.org/bob) by bob", &bob).unwrap(),
            "[bob's notes](https://example.org/bob) by [bob](https://matrix.to/#/@bob:example.org)"
        );
    }

    #[test]
    fn bot_prefix_like_formatting_py() {
        let fixture = fixture();
        for case in fixture["prefix"].as_array().unwrap() {
            let got = add_bot_prefix(
                case["text"].as_str().unwrap(),
                case["prefix"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(got, case["out"].as_str().unwrap(), "{}", case["name"]);
        }
    }
}
