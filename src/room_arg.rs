//! Classification of the ROOM argument and matching of room names. Pure, no I/O.

/// What the user passed as ROOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomArg {
    /// `!opaque:server`
    Id(String),
    /// `#alias:server`
    Alias(String),
    /// Anything else: a display name, matched case-insensitively.
    Name(String),
}

pub fn classify(arg: &str) -> RoomArg {
    let arg = arg.trim();
    if arg.starts_with('!') && arg.contains(':') {
        RoomArg::Id(arg.to_owned())
    } else if arg.starts_with('#') && arg.contains(':') {
        RoomArg::Alias(arg.to_owned())
    } else {
        RoomArg::Name(arg.to_owned())
    }
}

/// Indices of the candidates whose display name equals `query`, ignoring case.
pub fn match_name<S: AsRef<str>>(names: &[S], query: &str) -> Vec<usize> {
    let wanted = query.trim().to_lowercase();
    names
        .iter()
        .enumerate()
        .filter(|(_, name)| name.as_ref().trim().to_lowercase() == wanted)
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ids_aliases_and_names() {
        assert_eq!(
            classify("!abc:example.org"),
            RoomArg::Id("!abc:example.org".into())
        );
        assert_eq!(
            classify("#ops:example.org"),
            RoomArg::Alias("#ops:example.org".into())
        );
        assert_eq!(classify("agent-work"), RoomArg::Name("agent-work".into()));
        assert_eq!(classify("Team Chat"), RoomArg::Name("Team Chat".into()));
    }

    #[test]
    fn sigil_without_server_is_a_name() {
        // "#general" is how people write a room name, not a full alias.
        assert_eq!(classify("#general"), RoomArg::Name("#general".into()));
        assert_eq!(classify("!wow"), RoomArg::Name("!wow".into()));
    }

    #[test]
    fn name_match_is_case_insensitive_and_exact() {
        let names = ["Agent Work", "agent work", "Agent Work Archive", "Ops"];
        assert_eq!(match_name(&names, "AGENT WORK"), vec![0, 1]);
        assert_eq!(match_name(&names, "ops"), vec![3]);
        assert!(match_name(&names, "agent").is_empty());
    }
}
