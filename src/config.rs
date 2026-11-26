//! The Matrix skill's configuration file: `$XDG_CONFIG_HOME/matrix/config.json`
//! (default `~/.config/matrix/config.json`), the same file and keys the
//! Python skill's `_lib/config.py` reads.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// The keys this tool needs. Other keys in the file are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Config {
    pub homeserver: String,
    pub user_id: String,
}

/// Path of config.json, from the given environment values.
///
/// Like the Python skill, `XDG_CONFIG_HOME` wins when set; an empty value
/// counts as unset (XDG Base Directory specification).
pub fn config_path_from(xdg_config_home: Option<&str>, home: Option<&str>) -> Result<PathBuf> {
    let base = match xdg_config_home.filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => match home.filter(|v| !v.is_empty()) {
            Some(home) => Path::new(home).join(".config"),
            None => bail!("neither XDG_CONFIG_HOME nor HOME is set"),
        },
    };
    Ok(base.join("matrix").join("config.json"))
}

pub fn config_path() -> Result<PathBuf> {
    config_path_from(
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Parse config.json content; `homeserver` and `user_id` are required.
pub fn parse_config(text: &str) -> Result<Config> {
    let value: serde_json::Value =
        serde_json::from_str(text).context("config.json is not valid JSON")?;
    let missing: Vec<&str> = ["homeserver", "user_id"]
        .into_iter()
        .filter(|key| {
            value
                .get(key)
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
        })
        .collect();
    if !missing.is_empty() {
        bail!(
            "config.json is missing required fields: {}",
            missing.join(", ")
        );
    }
    let config: Config = serde_json::from_value(value)?;
    if !config.user_id.starts_with('@') || !config.user_id.contains(':') {
        bail!(
            "config.json user_id {:?} is not a Matrix user id (@user:server)",
            config.user_id
        );
    }
    Ok(config)
}

pub fn load_config() -> Result<Config> {
    let path = config_path()?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read config file {}", path.display()))?;
    parse_config(&text).with_context(|| format!("in {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_prefers_xdg_config_home() {
        let p = config_path_from(Some("/x/cfg"), Some("/home/u")).unwrap();
        assert_eq!(p, PathBuf::from("/x/cfg/matrix/config.json"));
    }

    #[test]
    fn path_falls_back_to_home_and_treats_empty_xdg_as_unset() {
        let expected = PathBuf::from("/home/u/.config/matrix/config.json");
        assert_eq!(config_path_from(None, Some("/home/u")).unwrap(), expected);
        assert_eq!(
            config_path_from(Some(""), Some("/home/u")).unwrap(),
            expected
        );
        assert!(config_path_from(None, None).is_err());
    }

    #[test]
    fn parses_required_keys_and_ignores_others() {
        let c = parse_config(
            r#"{"homeserver":"https://m.example","user_id":"@a:example","access_token":"x","bot_prefix":"b"}"#,
        )
        .unwrap();
        assert_eq!(
            c,
            Config {
                homeserver: "https://m.example".into(),
                user_id: "@a:example".into()
            }
        );
    }

    #[test]
    fn names_every_missing_key() {
        let err = parse_config(r#"{"access_token":"x"}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("homeserver, user_id"), "{err}");
        let err = parse_config(r#"{"homeserver":"https://m","user_id":""}"#)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("user_id") && !err.contains("homeserver"),
            "{err}"
        );
    }

    #[test]
    fn rejects_malformed_user_id_and_json() {
        assert!(parse_config(r#"{"homeserver":"https://m","user_id":"alice"}"#).is_err());
        assert!(parse_config("not json").is_err());
    }
}
