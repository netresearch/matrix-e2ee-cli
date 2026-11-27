//! Terminal output of strings other people control.

use std::borrow::Cow;

/// Serialize `value` as one JSON line. serde_json escapes only U+0000-U+001F
/// in strings; DEL (U+007F) and C1 (U+0080-U+009F) are escaped here as
/// `\u007f` and `\u0080`..`\u009f`, so a terminal showing the line does not
/// act on them. These characters can only occur inside JSON strings, so the
/// result stays valid JSON with the same values.
pub fn json_line<T: serde::Serialize>(value: &T) -> serde_json::Result<String> {
    let json = serde_json::to_string(value)?;
    if !json.chars().any(is_del_or_c1) {
        return Ok(json);
    }
    let mut escaped = String::with_capacity(json.len() + 16);
    for c in json.chars() {
        if is_del_or_c1(c) {
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
    fn printable_text_is_unchanged() {
        let ok = "Grüße 🙂 @a:example \u{00a0}tab-free";
        assert!(matches!(term(ok), Cow::Borrowed(_)));
        assert_eq!(term(ok), ok);
    }
}
