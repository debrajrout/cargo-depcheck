//! SARIF 2.1.0 output, for GitHub code scanning and similar tools.
//!
//! Hand-rolled rather than built on `serde-sarif` — the same choice
//! cargo-audit made (`cargo-audit/src/sarif.rs`), and the consistent one
//! here given this project's own stated goal of a lean dependency tree.
//! Structure follows GitHub's documented requirements:
//! <https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning>
//!
//! The differentiator worth calling out: `properties.security-severity` is
//! how GitHub sorts findings, and cargo-audit can only populate it from
//! CVSS — which 65% of RustSec advisories don't have. depcheck's composite
//! score populates it for every finding, not just the ones with a CVSS
//! vector.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::registry::Metadata;
use crate::report::{self, Finding};
use crate::score::RiskLevel;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "cargo-depcheck";
const INFORMATION_URI: &str = "https://github.com/debrajrout/cargo-depcheck";

#[derive(Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct Tool {
    driver: ToolComponent,
}

#[derive(Serialize)]
struct ToolComponent {
    name: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    version: String,
    rules: Vec<ReportingDescriptor>,
}

#[derive(Serialize)]
struct ReportingDescriptor {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: Message,
    #[serde(rename = "fullDescription")]
    full_description: Message,
    help: Message,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: ReportingConfiguration,
    properties: RuleProperties,
}

#[derive(Serialize)]
struct ReportingConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct RuleProperties {
    tags: Vec<&'static str>,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: Message,
    /// GitHub's docs mark this mandatory — cargo-deny had to patch it in
    /// after shipping without it (PR#819).
    locations: Vec<Location>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: HashMap<&'static str, String>,
    properties: ResultProperties,
}

#[derive(Serialize)]
struct ResultProperties {
    #[serde(rename = "security-severity")]
    security_severity: String,
    tags: Vec<&'static str>,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: &'static str,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: usize,
}

/// Builds the full SARIF log for a set of findings. `lockfile_path`, when
/// readable, is scanned for each finding's `[[package]]` block so
/// `locations[]` can point at the real line rather than a fixed one — best
/// effort only: a missing or unparseable lockfile falls back to line 1
/// rather than failing the whole report (this is exactly what cargo-audit's
/// own SARIF output does unconditionally, so it's a reasonable floor, not a
/// degraded case).
pub fn build(
    findings: &[Finding],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    lockfile_path: &Path,
) -> SarifLog {
    let lines = lockfile_line_numbers(lockfile_path);

    let mut seen_rules = HashSet::new();
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for finding in findings {
        if seen_rules.insert(finding.node.name.clone()) {
            rules.push(build_rule(&finding.node.name));
        }
        results.push(build_result(finding, meta_map, now, &lines));
    }

    SarifLog {
        schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: vec![Run {
            tool: Tool {
                driver: ToolComponent {
                    name: TOOL_NAME,
                    information_uri: INFORMATION_URI,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

pub fn render(log: &SarifLog) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(log)?)
}

fn build_rule(name: &str) -> ReportingDescriptor {
    ReportingDescriptor {
        id: name.to_string(),
        name: name.to_string(),
        short_description: Message {
            text: format!("Dependency health: {name}"),
        },
        full_description: Message {
            text: format!(
                "cargo-depcheck ranked {name} by security advisories, version lag, \
                 and maintenance signals, weighted by how much of the dependency \
                 graph relies on it."
            ),
        },
        help: Message {
            text: format!(
                "See {INFORMATION_URI}#how-scoring-works for how this score is computed."
            ),
        },
        default_configuration: ReportingConfiguration { level: "warning" },
        properties: RuleProperties {
            tags: vec!["dependencies", "supply-chain"],
        },
    }
}

fn build_result(
    finding: &Finding,
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    lines: &HashMap<(String, String), usize>,
) -> SarifResult {
    let level = match finding.risk.level {
        RiskLevel::Critical => "error",
        RiskLevel::Warn => "warning",
        RiskLevel::Low => "note",
    };

    let reasons = report::reason_lines(
        &finding.node,
        &finding.risk,
        &finding.advisories,
        meta_map,
        now,
    );
    let message = format!(
        "{} {} scored {:.0}/100: {}",
        finding.node.name,
        finding.node.version,
        finding.risk.total,
        reasons.join("; ")
    );

    let key = (finding.node.name.clone(), finding.node.version.to_string());
    let start_line = lines.get(&key).copied().unwrap_or(1);

    let mut partial_fingerprints = HashMap::new();
    partial_fingerprints.insert(
        "cargo-depcheck/dependency-fingerprint",
        format!("{}-{}", finding.node.name, finding.node.version),
    );

    SarifResult {
        rule_id: finding.node.name.clone(),
        level,
        message: Message { text: message },
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation { uri: "Cargo.lock" },
                region: Region { start_line },
            },
        }],
        partial_fingerprints,
        properties: ResultProperties {
            security_severity: security_severity(finding.risk.total),
            tags: vec!["dependencies", "supply-chain"],
        },
    }
}

/// Maps our 0-100 composite score to GitHub's expected 0.1-10.0
/// `security-severity` range, which is what GitHub actually sorts findings
/// by. Every finding gets one — unlike a CVSS-only tool, which can't
/// populate this for the 65% of RustSec advisories with no CVSS score.
fn security_severity(total: f64) -> String {
    let severity = (total / 100.0 * 10.0).clamp(0.1, 10.0);
    format!("{severity:.1}")
}

/// Best-effort scan of `Cargo.lock` for each `[[package]]` block's starting
/// line, keyed by (name, version). `Cargo.lock` is machine-generated with a
/// fixed, simple structure, so a plain line scan is reliable in practice
/// without pulling in a TOML parser just for this.
fn lockfile_line_numbers(lockfile_path: &Path) -> HashMap<(String, String), usize> {
    let mut map = HashMap::new();
    let Ok(content) = std::fs::read_to_string(lockfile_path) else {
        return map;
    };

    let mut block_start: Option<usize> = None;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    let flush = |map: &mut HashMap<(String, String), usize>,
                 start: Option<usize>,
                 name: Option<String>,
                 version: Option<String>| {
        if let (Some(start), Some(name), Some(version)) = (start, name, version) {
            map.insert((name, version), start);
        }
    };

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            flush(&mut map, block_start, name.take(), version.take());
            block_start = Some(line_no);
        } else if let Some(rest) = trimmed.strip_prefix("name = \"") {
            name = rest.strip_suffix('"').map(String::from);
        } else if let Some(rest) = trimmed.strip_prefix("version = \"") {
            version = rest.strip_suffix('"').map(String::from);
        }
    }
    flush(&mut map, block_start, name, version);

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DependencyNode;
    use crate::score::RiskScore;
    use semver::Version;

    fn test_finding(name: &str, version: Version, level: RiskLevel, total: f64) -> Finding {
        Finding {
            node: DependencyNode {
                name: name.to_string(),
                version,
                is_direct: true,
                depth: 1,
                dependent_count: 1,
                transitive_dependent_count: 1,
                is_registry: true,
                kind: crate::graph::NodeKind::Normal,
            },
            risk: RiskScore {
                security: 0.0,
                version_lag: 0.0,
                maintenance: 0.0,
                graph_multiplier: 1.0,
                total,
                level,
            },
            advisories: Vec::new(),
            baseline_state: crate::baseline::BaselineState::NotCompared,
        }
    }

    #[test]
    fn security_severity_maps_the_full_range() {
        assert_eq!(security_severity(0.0), "0.1");
        assert_eq!(security_severity(50.0), "5.0");
        assert_eq!(security_severity(100.0), "10.0");
    }

    #[test]
    fn security_severity_never_leaves_the_documented_range() {
        for total in [-10.0, 0.0, 33.3, 100.0, 500.0] {
            let s: f64 = security_severity(total).parse().unwrap();
            assert!(
                (0.1..=10.0).contains(&s),
                "security-severity {s} out of range"
            );
        }
    }

    #[test]
    fn build_has_required_top_level_shape() {
        let findings = vec![test_finding(
            "openssl",
            Version::new(0, 10, 45),
            RiskLevel::Critical,
            94.0,
        )];
        let meta_map = HashMap::new();
        let now = Utc::now();
        let log = build(
            &findings,
            &meta_map,
            now,
            Path::new("/nonexistent/Cargo.lock"),
        );

        assert_eq!(log.schema, SARIF_SCHEMA);
        assert_eq!(log.version, "2.1.0");
        assert_eq!(log.runs.len(), 1);
        assert_eq!(log.runs[0].tool.driver.name, "cargo-depcheck");
        assert_eq!(log.runs[0].tool.driver.rules.len(), 1);
        assert_eq!(log.runs[0].tool.driver.rules[0].id, "openssl");
    }

    #[test]
    fn every_result_has_at_least_one_location() {
        let findings = vec![
            test_finding(
                "openssl",
                Version::new(0, 10, 45),
                RiskLevel::Critical,
                94.0,
            ),
            test_finding("tokio", Version::new(1, 30, 0), RiskLevel::Warn, 55.0),
        ];
        let meta_map = HashMap::new();
        let now = Utc::now();
        let log = build(
            &findings,
            &meta_map,
            now,
            Path::new("/nonexistent/Cargo.lock"),
        );

        for result in &log.runs[0].results {
            assert!(
                !result.locations.is_empty(),
                "result for {} has no locations",
                result.rule_id
            );
            assert!(!result.partial_fingerprints.is_empty());
        }
    }

    #[test]
    fn duplicate_crate_names_share_one_rule_but_get_separate_results() {
        let findings = vec![
            test_finding("syn", Version::new(2, 0, 0), RiskLevel::Warn, 50.0),
            test_finding("syn", Version::new(3, 0, 0), RiskLevel::Low, 20.0),
        ];
        let meta_map = HashMap::new();
        let now = Utc::now();
        let log = build(
            &findings,
            &meta_map,
            now,
            Path::new("/nonexistent/Cargo.lock"),
        );

        assert_eq!(log.runs[0].tool.driver.rules.len(), 1);
        assert_eq!(log.runs[0].results.len(), 2);
    }

    #[test]
    fn risk_level_maps_to_the_documented_sarif_levels() {
        let findings = vec![
            test_finding("a", Version::new(1, 0, 0), RiskLevel::Critical, 90.0),
            test_finding("b", Version::new(1, 0, 0), RiskLevel::Warn, 50.0),
            test_finding("c", Version::new(1, 0, 0), RiskLevel::Low, 10.0),
        ];
        let meta_map = HashMap::new();
        let now = Utc::now();
        let log = build(
            &findings,
            &meta_map,
            now,
            Path::new("/nonexistent/Cargo.lock"),
        );

        let levels: Vec<&str> = log.runs[0].results.iter().map(|r| r.level).collect();
        assert_eq!(levels, vec!["error", "warning", "note"]);
    }

    #[test]
    fn missing_lockfile_falls_back_to_line_one() {
        let findings = vec![test_finding(
            "openssl",
            Version::new(0, 10, 45),
            RiskLevel::Critical,
            94.0,
        )];
        let meta_map = HashMap::new();
        let now = Utc::now();
        let log = build(
            &findings,
            &meta_map,
            now,
            Path::new("/nonexistent/Cargo.lock"),
        );

        assert_eq!(
            log.runs[0].results[0].locations[0]
                .physical_location
                .region
                .start_line,
            1
        );
    }

    #[test]
    fn lockfile_line_numbers_finds_the_real_block() {
        let dir =
            std::env::temp_dir().join(format!("cargo-depcheck-sarif-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lock_path = dir.join("Cargo.lock");
        std::fs::write(
            &lock_path,
            "# comment\n\n[[package]]\nname = \"openssl\"\nversion = \"0.10.45\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.30.0\"\n",
        )
        .unwrap();

        let lines = lockfile_line_numbers(&lock_path);
        assert_eq!(
            lines.get(&("openssl".to_string(), "0.10.45".to_string())),
            Some(&3)
        );
        assert_eq!(
            lines.get(&("tokio".to_string(), "1.30.0".to_string())),
            Some(&7)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn output_validates_against_the_real_sarif_2_1_0_schema() {
        // The other tests here hand-assert individual invariants (shape,
        // locations present, levels correct); none of them actually run
        // our output through the schema our own `$schema` field points
        // at. This test closes that gap: the schema is the real,
        // official one — vendored at `tests/schemas/sarif-2.1.0.json`,
        // fetched from the exact URL in `SARIF_SCHEMA` — not a hand-rolled
        // stand-in that could drift from what GitHub's own SARIF consumer
        // actually enforces.
        let findings = vec![
            test_finding(
                "openssl",
                Version::new(0, 10, 45),
                RiskLevel::Critical,
                94.0,
            ),
            test_finding("tokio", Version::new(1, 30, 0), RiskLevel::Warn, 55.0),
            test_finding("syn", Version::new(2, 0, 0), RiskLevel::Low, 10.0),
        ];
        let meta_map = HashMap::new();
        let now = Utc::now();
        let log = build(
            &findings,
            &meta_map,
            now,
            Path::new("/nonexistent/Cargo.lock"),
        );
        let json = render(&log).unwrap();
        let instance: serde_json::Value = serde_json::from_str(&json).unwrap();

        let schema_str = include_str!("../tests/schemas/sarif-2.1.0.json");
        let schema: serde_json::Value = serde_json::from_str(schema_str).unwrap();
        let validator = jsonschema::validator_for(&schema).expect("schema itself must compile");

        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|e| format!("{e} (at {})", e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "output does not conform to SARIF 2.1.0:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn output_is_valid_json_and_serializable() {
        let findings = vec![test_finding(
            "openssl",
            Version::new(0, 10, 45),
            RiskLevel::Critical,
            94.0,
        )];
        let meta_map = HashMap::new();
        let now = Utc::now();
        let log = build(
            &findings,
            &meta_map,
            now,
            Path::new("/nonexistent/Cargo.lock"),
        );
        let json = render(&log).unwrap();

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert!(value["runs"][0]["tool"]["driver"]["rules"].is_array());
        assert!(value["runs"][0]["results"][0]["locations"].is_array());
        assert!(value["runs"][0]["results"][0]["partialFingerprints"].is_object());
        assert!(value["runs"][0]["results"][0]["message"]["text"].is_string());
    }
}
