//! Classification of the ROOM argument and matching of room names. Pure, no I/O.

use matrix_sdk::ruma::{OwnedRoomId, RoomId};

/// What the user passed as ROOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomArg {
    /// Anything ruma parses as a room id: `!opaque:server`, or `!hash`
    /// without a server part (room version 12). It may still be a room name
    /// that starts with `!`; the caller falls back to name matching when no
    /// joined room has this id.
    Id(OwnedRoomId),
    /// `#alias:server`
    Alias(String),
    /// Anything else: a display name, matched case-insensitively.
    Name(String),
}

pub fn classify(arg: &str) -> RoomArg {
    let arg = arg.trim();
    if let Some(id) = arg
        .starts_with('!')
        .then(|| RoomId::parse(arg).ok())
        .flatten()
    {
        RoomArg::Id(id)
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
            RoomArg::Id(RoomId::parse("!abc:example.org").unwrap())
        );
        assert_eq!(
            classify("#ops:example.org"),
            RoomArg::Alias("#ops:example.org".into())
        );
        assert_eq!(classify("agent-work"), RoomArg::Name("agent-work".into()));
        assert_eq!(classify("Team Chat"), RoomArg::Name("Team Chat".into()));
    }

    #[test]
    fn alias_sigil_without_server_is_a_name() {
        // "#general" is how people write a room name, not a full alias.
        assert_eq!(classify("#general"), RoomArg::Name("#general".into()));
    }

    #[test]
    fn room_id_without_server_is_an_id() {
        // Room version 12 ids have no server part: "!" plus a hash. A name
        // starting with "!" also lands here; resolve_room falls back to name
        // matching when no joined room has that id.
        let v12 = "!31hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM";
        assert_eq!(classify(v12), RoomArg::Id(RoomId::parse(v12).unwrap()));
        assert_eq!(
            classify("!wow"),
            RoomArg::Id(RoomId::parse("!wow").unwrap())
        );
        // The ambiguous-name error lists room ids as RoomId displays them;
        // each one must come back as an id.
        let listed = RoomId::parse(v12).unwrap().to_string();
        assert!(matches!(classify(&listed), RoomArg::Id(_)));
    }

    #[test]
    fn name_match_is_case_insensitive_and_exact() {
        let names = ["Agent Work", "agent work", "Agent Work Archive", "Ops"];
        assert_eq!(match_name(&names, "AGENT WORK"), vec![0, 1]);
        assert_eq!(match_name(&names, "ops"), vec![3]);
        assert!(match_name(&names, "agent").is_empty());
    }
}
