//! Terminal output of strings other people control.

use std::borrow::Cow;

/// Replace control characters (C0 including CR, LF and ESC, DEL, and C1
/// U+0080-U+009F) with U+FFFD, so text a room member or a server chose cannot
/// move the cursor, clear the screen or start a fake line. For text output
/// only; JSON output is escaped by serde.
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
/// A CR directly before an LF is dropped; every other control character,
/// a lone CR included, becomes U+FFFD.
pub fn term_body(s: &str) -> String {
    s.split('\n')
        .map(|line| term(line.strip_suffix('\r').unwrap_or(line)).into_owned())
        .collect::<Vec<_>>()
        .join("\n    ")
}

#[cfg(test)]
mod tests {
    use super::*;

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
