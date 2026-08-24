//! `[package.metadata.depcheck]` (falling back to
//! `[workspace.metadata.depcheck]`), so a project can commit its own
//! threshold/fail-on/ignore policy instead of every developer and CI job
//! repeating the same flags. Precedence is CLI flag (or its `env`
//! equivalent, which clap resolves before we ever see it) > this file >
//! the tool's built-in default — callers apply that merge themselves via
//! `Option::or`.

use anyhow::{Context, Result};
use chrono::NaiveDate;
use serde::Deserialize;

use crate::cli::FailOn;

/// `deny_unknown_fields` because a silently-ignored key here is dangerous
/// in a way a silently-ignored key usually isn't: someone who writes
/// `fail-on` instead of `fail_on` gets a green CI run and believes their
/// build is gated on critical findings when nothing is gating it at all.
/// This table already treats a malformed value as a hard exit-2 error, so
/// accepting an unrecognised key would be the inconsistent choice.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    threshold: Option<f64>,
    fail_on: Option<String>,
    #[serde(default)]
    ignore: Vec<RawIgnoreEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIgnoreEntry {
    #[serde(rename = "crate")]
    crate_name: String,
    reason: Option<String>,
    /// `YYYY-MM-DD`. Parsed (and validated) separately from the rest of the
    /// struct so a bad date gives a specific, actionable error rather than
    /// a generic deserialization failure.
    expires: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IgnoreEntry {
    pub crate_name: String,
    pub reason: Option<String>,
    pub expires: Option<NaiveDate>,
    pub is_expired: bool,
}

#[derive(Debug, Default)]
pub struct Config {
    pub threshold: Option<f64>,
    pub fail_on: Option<FailOn>,
    pub ignores: Vec<IgnoreEntry>,
}

/// Reads the config from `package_metadata` (the resolved package's own
/// `[package.metadata]`, as JSON — this is what `cargo metadata` already
/// gives us, so no separate TOML parsing is needed), falling back to
/// `workspace_metadata` if the package-level table has no `depcheck` key at
/// all. A malformed table is a hard error — callers should map it to exit
/// code 2 (a usage/config error), not let it propagate as an unexpected
/// panic or a generic failure.
pub fn load(
    package_metadata: &serde_json::Value,
    workspace_metadata: &serde_json::Value,
    today: NaiveDate,
) -> Result<Config> {
    let raw_value = package_metadata
        .get("depcheck")
        .or_else(|| workspace_metadata.get("depcheck"));

    let Some(raw_value) = raw_value else {
        return Ok(Config::default());
    };

    let raw: RawConfig = serde_json::from_value(raw_value.clone()).context(
        "invalid [package.metadata.depcheck] (or [workspace.metadata.depcheck]) in Cargo.toml",
    )?;

    let fail_on = raw.fail_on.as_deref().map(parse_fail_on).transpose()?;

    let ignores = raw
        .ignore
        .into_iter()
        .map(|entry| parse_ignore_entry(entry, today))
        .collect::<Result<Vec<_>>>()?;

    Ok(Config {
        threshold: raw.threshold,
        fail_on,
        ignores,
    })
}

fn parse_fail_on(s: &str) -> Result<FailOn> {
    match s {
        "none" => Ok(FailOn::None),
        "warn" => Ok(FailOn::Warn),
        "critical" => Ok(FailOn::Critical),
        other => anyhow::bail!(
            "invalid fail_on value {other:?} in [package.metadata.depcheck] — \
             expected \"none\", \"warn\", or \"critical\""
        ),
    }
}

fn parse_ignore_entry(entry: RawIgnoreEntry, today: NaiveDate) -> Result<IgnoreEntry> {
    let expires = entry
        .expires
        .as_deref()
        .map(|s| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d").with_context(|| {
                format!(
                    "invalid `expires` date {s:?} for ignored crate {:?} in \
                     [package.metadata.depcheck] — expected YYYY-MM-DD",
                    entry.crate_name
                )
            })
        })
        .transpose()?;

    let is_expired = expires.is_some_and(|d| d < today);

    Ok(IgnoreEntry {
        crate_name: entry.crate_name,
        reason: entry.reason,
        expires,
        is_expired,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn date(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn no_depcheck_table_returns_default() {
        let config = load(&json!({}), &json!({}), date("2026-01-01")).unwrap();
        assert_eq!(config.threshold, None);
        assert_eq!(config.fail_on, None);
        assert!(config.ignores.is_empty());
    }

    #[test]
    fn package_level_table_is_read() {
        let pkg = json!({ "depcheck": { "threshold": 30.0, "fail_on": "warn" } });
        let config = load(&pkg, &json!({}), date("2026-01-01")).unwrap();
        assert_eq!(config.threshold, Some(30.0));
        assert_eq!(config.fail_on, Some(FailOn::Warn));
    }

    #[test]
    fn package_level_table_wins_over_workspace_level() {
        let pkg = json!({ "depcheck": { "threshold": 30.0 } });
        let ws = json!({ "depcheck": { "threshold": 99.0 } });
        let config = load(&pkg, &ws, date("2026-01-01")).unwrap();
        assert_eq!(config.threshold, Some(30.0));
    }

    #[test]
    fn falls_back_to_workspace_level_when_package_has_none() {
        let ws = json!({ "depcheck": { "threshold": 55.0 } });
        let config = load(&json!({}), &ws, date("2026-01-01")).unwrap();
        assert_eq!(config.threshold, Some(55.0));
    }

    #[test]
    fn invalid_fail_on_is_a_clear_error_not_a_panic() {
        let pkg = json!({ "depcheck": { "fail_on": "yolo" } });
        let err = load(&pkg, &json!({}), date("2026-01-01")).unwrap_err();
        assert!(err.to_string().contains("fail_on"));
    }

    #[test]
    fn invalid_expires_date_is_a_clear_error() {
        let pkg =
            json!({ "depcheck": { "ignore": [{ "crate": "openssl", "expires": "not-a-date" }] } });
        let err = load(&pkg, &json!({}), date("2026-01-01")).unwrap_err();
        assert!(err.to_string().contains("openssl"));
    }

    #[test]
    fn a_typoed_key_is_rejected_rather_than_silently_ignored() {
        // `fail-on` instead of `fail_on`. Silently dropping this is the
        // worst possible outcome: CI goes green and the author believes the
        // build is gated on critical findings when nothing is gating it.
        let pkg = json!({ "depcheck": { "fail-on": "critical" } });
        let err = load(&pkg, &json!({}), date("2026-01-01")).unwrap_err();
        assert!(
            format!("{err:#}").contains("fail-on"),
            "the error should name the offending key: {err:#}"
        );
    }

    #[test]
    fn a_typoed_ignore_entry_key_is_rejected_too() {
        let pkg = json!({
            "depcheck": { "ignore": [{ "crate": "openssl", "reasons": "typo" }] }
        });
        assert!(load(&pkg, &json!({}), date("2026-01-01")).is_err());
    }

    #[test]
    fn malformed_table_shape_is_a_clear_error() {
        // threshold as a string instead of a number.
        let pkg = json!({ "depcheck": { "threshold": "not-a-number" } });
        assert!(load(&pkg, &json!({}), date("2026-01-01")).is_err());
    }

    #[test]
    fn ignore_reason_and_expiry_are_carried_through() {
        let pkg = json!({
            "depcheck": {
                "ignore": [
                    { "crate": "openssl", "reason": "vendored, patched internally", "expires": "2027-01-01" }
                ]
            }
        });
        let config = load(&pkg, &json!({}), date("2026-01-01")).unwrap();
        assert_eq!(config.ignores.len(), 1);
        let entry = &config.ignores[0];
        assert_eq!(entry.crate_name, "openssl");
        assert_eq!(
            entry.reason.as_deref(),
            Some("vendored, patched internally")
        );
        assert_eq!(entry.expires, Some(date("2027-01-01")));
        assert!(!entry.is_expired);
    }

    #[test]
    fn expired_ignore_is_flagged() {
        let pkg = json!({
            "depcheck": { "ignore": [{ "crate": "openssl", "expires": "2020-01-01" }] }
        });
        let config = load(&pkg, &json!({}), date("2026-01-01")).unwrap();
        assert!(config.ignores[0].is_expired);
    }

    #[test]
    fn ignore_with_no_expiry_never_expires() {
        let pkg = json!({ "depcheck": { "ignore": [{ "crate": "openssl" }] } });
        let config = load(&pkg, &json!({}), date("2026-01-01")).unwrap();
        assert!(!config.ignores[0].is_expired);
    }
}
