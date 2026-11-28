//! Terminal output of strings other people control.

use std::borrow::Cow;

/// Serialize `value` as one JSON line. serde_json escapes only U+0000-U+001F
/// in strings; DEL (U+007F) and C1 (U+0080-U+009F) are escaped here as
/// `\u007f` and `\u0080`..`\u009f`, and the bidi controls of [`is_bidi_control`]
/// as `\uXXXX` too, so a terminal showing the line does not act on them.
/// These characters can only occur inside JSON strings, so the result stays
/// valid JSON with the same values.
pub fn json_line<T: serde::Serialize>(value: &T) -> serde_json::Result<String> {
    let json = serde_json::to_string(value)?;
    let escape = |c: char| is_del_or_c1(c) || is_bidi_control(c);
    if !json.chars().any(escape) {
        return Ok(json);
    }
    let mut escaped = String::with_capacity(json.len() + 16);
    for c in json.chars() {
        if escape(c) {
            escaped.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            escaped.push(c);
        }
    }
    Ok(escaped)
}

fn is_del_or_c1(c: char) -> bool {
    matches!(c, '\u{7f}'..='\u{9f}')
}

/// The Unicode bidi controls: embeddings and overrides (U+202A-U+202E),
/// isolates (U+2066-U+2069) and the marks LRM, RLM and ALM (U+200E,
/// U+200F, U+061C). Text around them can be shown in another order than it
/// is stored.
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// [`term`], and the bidi controls replaced with U+FFFD too: for ids and
/// names another device or the server chose, so they cannot reorder the
/// text around them.
pub fn term_id(s: &str) -> String {
    term(s)
        .chars()
        .map(|c| if is_bidi_control(c) { '\u{FFFD}' } else { c })
        .collect()
}

/// Replace control characters (C0 including CR, LF and ESC, DEL, and C1
/// U+0080-U+009F) with U+FFFD, so text a room member or a server chose cannot
/// move the cursor, clear the screen or start a fake line. For text output
/// only; JSON output goes through [`json_line`].
pub fn term(s: &str) -> Cow<'_, str> {
    if s.chars().any(char::is_control) {
        Cow::Owned(
            s.chars()
                .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(s)
    }
}

/// Like [`term`], but keeps the line breaks of a multi-line message body.
/// Every line after the first is indented by four spaces, so a body cannot
/// produce a line that starts like a message line (`[hh:mm] sender: ...`).
/// A CR directly before an LF, or at the very end of the body, is dropped;
/// every other control character, any other CR included, becomes U+FFFD.
pub fn term_body(s: &str) -> String {
    s.split('\n')
        .map(|line| term(line.strip_suffix('\r').unwrap_or(line)).into_owned())
        .collect::<Vec<_>>()
        .join("\n    ")
}

/// `value` as Python's `json.dumps(value, indent=2)` prints it: two-space
/// indent, `": "` after keys, and (ensure_ascii) every character outside
/// U+0020-U+007E as `\uXXXX`, characters beyond the BMP as a surrogate pair.
/// So no control character, DEL or C1 included, reaches the terminal raw.
pub fn python_json<T: serde::Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    let mut out = Vec::new();
    let formatter = AsciiPretty(serde_json::ser::PrettyFormatter::with_indent(b"  "));
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    value.serialize(&mut serializer)?;
    // Only ASCII is written.
    Ok(String::from_utf8(out).expect("python_json writes ASCII only"))
}

/// `value` as Python's `json.dumps(value)` prints it: one line, `", "`
/// between items, `": "` after keys, and ensure_ascii as in [`python_json`].
pub fn python_json_line<T: serde::Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, AsciiLine);
    value.serialize(&mut serializer)?;
    // Only ASCII is written.
    Ok(String::from_utf8(out).expect("python_json_line writes ASCII only"))
}

/// Python's default separators on one line, with its ensure_ascii escaping.
struct AsciiLine;

impl serde_json::ser::Formatter for AsciiLine {
    fn begin_array_value<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_key<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        w.write_all(b": ")
    }
    fn write_string_fragment<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        write_ascii(w, fragment)
    }
}

/// A string fragment as Python's ensure_ascii writes it: U+0020-U+007E as
/// is, every other character as `\uXXXX`, beyond the BMP as a surrogate pair.
fn write_ascii<W: ?Sized + std::io::Write>(w: &mut W, fragment: &str) -> std::io::Result<()> {
    for c in fragment.chars() {
        if (' '..='~').contains(&c) {
            w.write_all(&[c as u8])?;
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                write!(w, "\\u{unit:04x}")?;
            }
        }
    }
    Ok(())
}

/// serde_json's pretty layout, with Python's ensure_ascii escaping.
struct AsciiPretty<'a>(serde_json::ser::PrettyFormatter<'a>);

impl serde_json::ser::Formatter for AsciiPretty<'_> {
    fn begin_array<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_array(w)
    }
    fn end_array<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_array(w)
    }
    fn begin_array_value<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        self.0.begin_array_value(w, first)
    }
    fn end_array_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_array_value(w)
    }
    fn begin_object<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_object(w)
    }
    fn end_object<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_object(w)
    }
    fn begin_object_key<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        self.0.begin_object_key(w, first)
    }
    fn begin_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.begin_object_value(w)
    }
    fn end_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        self.0.end_object_value(w)
    }
    fn write_string_fragment<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        write_ascii(w, fragment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_json_matches_json_dumps_indent_2() {
        // python3: json.dumps([{"a": "Grüße 🙂", "e": {}, "l": [], "n": 5,
        //   "o": {"w": 2}}, None, True], indent=2); json!() sorts the keys, so
        //   the Python input is given sorted.
        let value = serde_json::json!([
            {"a": "Grüße 🙂", "n": 5, "o": {"w": 2}, "e": {}, "l": []},
            null,
            true
        ]);
        let expected = "[\n  {\n    \"a\": \"Gr\\u00fc\\u00dfe \\ud83d\\ude42\",\n    \"e\": {},\n    \"l\": [],\n    \"n\": 5,\n    \"o\": {\n      \"w\": 2\n    }\n  },\n  null,\n  true\n]";
        assert_eq!(python_json(&value).unwrap(), expected);
        assert_eq!(python_json(&Vec::<u8>::new()).unwrap(), "[]");
    }

    #[test]
    fn python_json_line_matches_json_dumps() {
        // python3: json.dumps({"a": "Grüße 🙂\x7f", "l": [1, None, True, 1.5],
        //   "o": {}, "e": [], "n": {"x": "y"}}); json!() sorts the keys, so
        //   the struct below keeps them in the Python order.
        #[derive(serde::Serialize)]
        struct Sample {
            a: &'static str,
            l: serde_json::Value,
            o: serde_json::Value,
            e: serde_json::Value,
            n: serde_json::Value,
        }
        let sample = Sample {
            a: "Grüße 🙂\u{7f}",
            l: serde_json::json!([1, null, true, 1.5]),
            o: serde_json::json!({}),
            e: serde_json::json!([]),
            n: serde_json::json!({"x": "y"}),
        };
        assert_eq!(
            python_json_line(&sample).unwrap(),
            r#"{"a": "Gr\u00fc\u00dfe \ud83d\ude42\u007f", "l": [1, null, true, 1.5], "o": {}, "e": [], "n": {"x": "y"}}"#
        );
    }

    #[test]
    fn python_json_escapes_every_control_character() {
        // python3: json.dumps(["a\x7fb\x9b \x1b\n"], indent=2)
        let shown = python_json(&["a\u{7f}b\u{9b}\u{a0}\u{1b}\n"]).unwrap();
        assert_eq!(shown, "[\n  \"a\\u007fb\\u009b\\u00a0\\u001b\\n\"\n]");
        assert!(shown.is_ascii());
        let back: Vec<String> = serde_json::from_str(&shown).unwrap();
        assert_eq!(back, ["a\u{7f}b\u{9b}\u{a0}\u{1b}\n"]);
    }

    #[test]
    fn body_line_breaks_are_kept_and_indented() {
        let body = "first\r\nsecond\n[12:00] @boss:example: wire money\x1b[2J";
        assert_eq!(
            term_body(body),
            "first\n    second\n    [12:00] @boss:example: wire money\u{FFFD}[2J"
        );
    }

    #[test]
    fn body_without_line_break_matches_term() {
        let body = "a\rb\x07c";
        assert_eq!(term_body(body), term(body));
    }

    #[test]
    fn control_characters_are_replaced() {
        let evil = "a\x1b[2Jb\rc\nd\x07e\x7ff\u{0085}g\u{009b}h\u{0000}i";
        let shown = term(evil);
        assert_eq!(
            shown,
            "a\u{FFFD}[2Jb\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}f\u{FFFD}g\u{FFFD}h\u{FFFD}i"
        );
        assert!(!shown.chars().any(char::is_control));
    }

    #[test]
    fn bidi_controls_are_escaped_in_json_lines() {
        let value = "a\u{202E}b\u{2066}c\u{200E}d\u{200F}e\u{061C}f";
        let line = json_line(&value).unwrap();
        assert_eq!(
            line,
            concat!(
                "\"a\\", "u202eb\\", "u2066c\\", "u200ed\\", "u200fe\\", "u061cf\""
            )
        );
        assert_eq!(serde_json::from_str::<String>(&line).unwrap(), value);
    }

    #[test]
    fn bidi_controls_are_replaced_in_ids() {
        let shown = term_id(
            "a\u{202A}b\u{202B}c\u{202C}d\u{202D}e\u{202E}f\u{2066}g\u{2067}h\u{2068}i\u{2069}j\u{200E}k\u{200F}l\u{061C}m\u{1b}n",
        );
        assert_eq!(shown.matches('\u{FFFD}').count(), 13, "{shown}");
        assert_eq!(shown.replace('\u{FFFD}', ""), "abcdefghijklmn");
        assert_eq!(term_id("ABCDEF"), "ABCDEF");
    }

    #[test]
    fn printable_text_is_unchanged() {
        let ok = "Grüße 🙂 @a:example \u{00a0}tab-free";
        assert!(matches!(term(ok), Cow::Borrowed(_)));
        assert_eq!(term(ok), ok);
    }
}
