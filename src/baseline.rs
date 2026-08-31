//! Comparison against a previously stored report.
//!
//! An established project adopting a dependency-health gate starts from a
//! report that is already long — that is the normal case, not a failure, and
//! `--fail-on` applied to it fails on day one for reasons nobody introduced.
//! A baseline separates "this is our inherited backlog" from "this PR made it
//! worse": the whole report is still shown, but only findings that are new
//! since the baseline can fail the build.
//!
//! The stored file *is* a normal `--format json` report, so a baseline is
//! readable with the same tooling as any other report, and any report you
//! already archived can be used as one.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::report::{self, Finding};
use crate::score::RiskLevel;

/// Whether a finding was already present in the baseline. `NotCompared` is
/// the state of every finding when no baseline is in play at all — distinct
/// from `New`, so a run without `--baseline` never labels findings as new.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BaselineState {
    #[default]
    NotCompared,
    /// Present in the baseline, at no worse a level and with no new advisory.
    Known,
    New(NewReason),
}

impl BaselineState {
    /// Short tag for the human and Markdown reports. `None` when there is no
    /// baseline to compare against, so those reports stay unchanged.
    pub fn label(self) -> Option<&'static str> {
        match self {
            Self::NotCompared => None,
            Self::Known => Some("known"),
            Self::New(_) => Some("new"),
        }
    }

    /// Machine-readable form for the JSON report.
    pub fn as_str(self) -> Option<&'static str> {
        self.label()
    }
}

/// Why a finding counts as new. Kept explicit because "this crate is not in
/// the baseline" and "this crate is in the baseline but just picked up a
/// fresh advisory" are very different things to read in a PR comment, and
/// collapsing both to a bare `new` hides the more urgent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewReason {
    /// No entry for this crate at this version.
    NotInBaseline,
    /// Same crate and version, but carrying an advisory the baseline didn't.
    NewAdvisory,
    /// Same crate and version, but it has crossed into a higher severity.
    LevelIncreased,
}

impl NewReason {
    pub fn describe(self) -> &'static str {
        match self {
            Self::NotInBaseline => "not in the baseline",
            Self::NewAdvisory => "new advisory since the baseline",
            Self::LevelIncreased => "higher severity than in the baseline",
        }
    }
}

#[derive(Debug)]
pub struct Baseline {
    pub path: PathBuf,
    /// When the baseline report was generated, if it recorded that.
    pub generated_at: Option<String>,
    /// The threshold the baseline was written at. A baseline can only contain
    /// findings its own run reported, so comparing against it from a run with
    /// a lower threshold surfaces crates it never had a chance to record —
    /// worth warning about rather than reporting as a pile of new findings.
    pub threshold: Option<f64>,
    entries: HashMap<(String, String), Entry>,
}

#[derive(Debug)]
struct Entry {
    level: Option<RiskLevel>,
    advisories: BTreeSet<String>,
}

/// Only the fields a comparison needs. Deliberately not the `JsonReport`
/// types themselves: those are output types that may gain fields freely,
/// while everything read here has to stay readable across versions — an old
/// baseline must keep working after a schema bump, which is exactly when a
/// strict mirror of the current output types would refuse to load.
#[derive(Deserialize)]
struct BaselineFile {
    #[serde(default)]
    schema_version: Option<u32>,
    #[serde(default)]
    generated_at: Option<String>,
    #[serde(default)]
    summary: Option<BaselineSummary>,
    #[serde(default)]
    findings: Vec<BaselineFinding>,
}

#[derive(Deserialize)]
struct BaselineSummary {
    #[serde(default)]
    threshold: Option<f64>,
}

#[derive(Deserialize)]
struct BaselineFinding {
    name: String,
    version: String,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    advisories: Vec<String>,
}

pub fn load(path: &Path) -> Result<Baseline> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read the baseline report at {}\n\
             Write one first with: cargo depcheck --write-baseline {}",
            path.display(),
            path.display()
        )
    })?;
    let parsed: BaselineFile = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a cargo-depcheck JSON report", path.display()))?;

    if let Some(version) = parsed.schema_version {
        if version > report::JSON_SCHEMA_VERSION {
            eprintln!(
                "warning: baseline {} uses JSON schema {version}, newer than this tool's {} — \
                 comparing on the fields both versions share",
                path.display(),
                report::JSON_SCHEMA_VERSION
            );
        }
    }

    let mut entries: HashMap<(String, String), Entry> = HashMap::new();
    for finding in parsed.findings {
        let entry = entries
            .entry((finding.name, finding.version))
            .or_insert_with(|| Entry {
                level: None,
                advisories: BTreeSet::new(),
            });
        entry.advisories.extend(finding.advisories);
        let level = finding.level.as_deref().and_then(parse_level);
        // A duplicated key can only come from a hand-edited or merged
        // baseline; keep the worst level recorded for it rather than whichever
        // entry happened to be last.
        if level > entry.level {
            entry.level = level;
        }
    }

    Ok(Baseline {
        path: path.to_path_buf(),
        generated_at: parsed.generated_at,
        threshold: parsed.summary.and_then(|summary| summary.threshold),
        entries,
    })
}

/// Warns when this run would compare against a baseline recorded at a
/// different threshold. Lowering the threshold makes crates visible that the
/// baseline never listed, and without this they would all be reported as new
/// with no indication why.
pub fn warn_on_threshold_mismatch(baseline: &Baseline, threshold: f64) {
    let Some(recorded) = baseline.threshold else {
        return;
    };
    if (recorded - threshold).abs() < f64::EPSILON {
        return;
    }
    eprintln!(
        "warning: {} was written at threshold {recorded}, but this run uses {threshold}. \
         Findings between the two are reported as new because the baseline could not have \
         recorded them — rewrite the baseline at this threshold to compare like for like.",
        baseline.path.display()
    );
}

fn parse_level(level: &str) -> Option<RiskLevel> {
    match level {
        "critical" => Some(RiskLevel::Critical),
        "warn" => Some(RiskLevel::Warn),
        "low" => Some(RiskLevel::Low),
        _ => None,
    }
}

impl Baseline {
    pub fn classify(&self, finding: &Finding) -> BaselineState {
        let key = (finding.node.name.clone(), finding.node.version.to_string());
        let Some(entry) = self.entries.get(&key) else {
            return BaselineState::New(NewReason::NotInBaseline);
        };

        // A crate can sit in the baseline at the same version and still
        // deserve to fail the build: an advisory published since then is new
        // information about an unchanged dependency, which is precisely the
        // case a "same name and version means known" rule would swallow.
        let has_new_advisory = finding
            .advisories
            .iter()
            .map(report::advisory_label)
            .any(|label| !entry.advisories.contains(&label));
        if has_new_advisory {
            return BaselineState::New(NewReason::NewAdvisory);
        }

        if entry
            .level
            .is_some_and(|recorded| finding.risk.level > recorded)
        {
            return BaselineState::New(NewReason::LevelIncreased);
        }

        BaselineState::Known
    }

    /// Number of entries the baseline holds — reported so a baseline that
    /// silently loaded zero findings is visible rather than looking like a
    /// clean comparison.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Stamps every finding with its baseline state, in place.
pub fn apply(baseline: &Baseline, findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        finding.baseline_state = baseline.classify(finding);
    }
}

/// Counts of findings that are new since the baseline, by level. These are
/// what `--fail-on` evaluates when a baseline is in play, so they must be
/// computed over the whole analyzed set rather than the displayed subset —
/// `--threshold` and `--top` control output only, and must not be able to
/// hide a new critical finding from the gate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Delta {
    pub new_critical: usize,
    pub new_warnings: usize,
    pub new_total: usize,
    pub known_total: usize,
}

pub fn diff<'a>(baseline: &Baseline, findings: impl IntoIterator<Item = &'a Finding>) -> Delta {
    let mut delta = Delta::default();
    for finding in findings {
        match baseline.classify(finding) {
            BaselineState::New(_) => {
                delta.new_total += 1;
                match finding.risk.level {
                    RiskLevel::Critical => delta.new_critical += 1,
                    RiskLevel::Warn => delta.new_warnings += 1,
                    RiskLevel::Low => {}
                }
            }
            BaselineState::Known => delta.known_total += 1,
            BaselineState::NotCompared => {}
        }
    }
    delta
}

/// One line summarizing the comparison, for the top of a report.
pub fn summary_line(baseline: &Baseline, delta: &Delta) -> String {
    let when = baseline
        .generated_at
        .as_deref()
        .map(|t| format!(" from {t}"))
        .unwrap_or_default();
    format!(
        "baseline {}{when}: {} new · {} known ({} entries)",
        baseline.path.display(),
        delta.new_total,
        delta.known_total,
        baseline.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DependencyNode, NodeKind};
    use crate::score::RiskScore;
    use semver::Version;

    /// Counter rather than a timestamp: the test harness runs these in
    /// parallel, and `SystemTime`'s resolution is coarse enough that two
    /// threads entering this function together were getting the same path —
    /// one test then read the other's baseline, failing whichever lost the
    /// race. An atomic counter cannot collide.
    static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "depcheck-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn baseline_from(json: &str) -> Baseline {
        let path = temp_dir("baseline-test").join("baseline.json");
        std::fs::write(&path, json).unwrap();
        load(&path).unwrap()
    }

    fn finding(name: &str, version: &str, level: RiskLevel, total: f64) -> Finding {
        Finding {
            node: DependencyNode {
                name: name.to_string(),
                version: Version::parse(version).unwrap(),
                is_direct: false,
                depth: 1,
                dependent_count: 0,
                transitive_dependent_count: 0,
                is_registry: true,
                kind: NodeKind::Normal,
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
            baseline_state: BaselineState::NotCompared,
        }
    }

    const ONE_WARN: &str = r#"{
        "schema_version": 3,
        "generated_at": "2026-08-01T00:00:00+00:00",
        "findings": [
            {"name": "wasi", "version": "0.11.1", "level": "warn", "advisories": []}
        ]
    }"#;

    #[test]
    fn a_crate_in_the_baseline_at_the_same_version_is_known() {
        let baseline = baseline_from(ONE_WARN);
        let state = baseline.classify(&finding("wasi", "0.11.1", RiskLevel::Warn, 46.4));
        assert_eq!(state, BaselineState::Known);
    }

    #[test]
    fn a_score_that_drifted_upward_within_its_level_stays_known() {
        // Maintenance age grows every day a crate isn't republished, so a
        // baseline that only matched exact scores would call the same
        // untouched dependency "new" on the next run — the failure mode this
        // whole feature exists to prevent.
        let baseline = baseline_from(ONE_WARN);
        let state = baseline.classify(&finding("wasi", "0.11.1", RiskLevel::Warn, 52.8));
        assert_eq!(state, BaselineState::Known);
    }

    #[test]
    fn an_unlisted_crate_is_new() {
        let baseline = baseline_from(ONE_WARN);
        let state = baseline.classify(&finding("libc", "0.2.1", RiskLevel::Warn, 44.0));
        assert_eq!(state, BaselineState::New(NewReason::NotInBaseline));
    }

    #[test]
    fn a_different_version_of_a_listed_crate_is_new() {
        let baseline = baseline_from(ONE_WARN);
        let state = baseline.classify(&finding("wasi", "0.12.0", RiskLevel::Warn, 46.4));
        assert_eq!(state, BaselineState::New(NewReason::NotInBaseline));
    }

    #[test]
    fn crossing_into_a_higher_severity_is_new() {
        let baseline = baseline_from(ONE_WARN);
        let state = baseline.classify(&finding("wasi", "0.11.1", RiskLevel::Critical, 78.0));
        assert_eq!(state, BaselineState::New(NewReason::LevelIncreased));
    }

    #[test]
    fn dropping_to_a_lower_severity_is_not_new() {
        let baseline = baseline_from(ONE_WARN);
        let state = baseline.classify(&finding("wasi", "0.11.1", RiskLevel::Low, 12.0));
        assert_eq!(state, BaselineState::Known);
    }

    #[test]
    fn delta_counts_only_new_findings_by_level() {
        let baseline = baseline_from(ONE_WARN);
        let findings = vec![
            finding("wasi", "0.11.1", RiskLevel::Warn, 46.4),
            finding("libc", "0.2.1", RiskLevel::Warn, 44.0),
            finding("openssl", "0.9.0", RiskLevel::Critical, 91.0),
            finding("quiet", "1.0.0", RiskLevel::Low, 3.0),
        ];
        let delta = diff(&baseline, &findings);
        assert_eq!(
            delta,
            Delta {
                new_critical: 1,
                new_warnings: 1,
                new_total: 3,
                known_total: 1,
            }
        );
    }

    #[test]
    fn a_baseline_missing_the_level_field_still_matches_by_version() {
        let baseline = baseline_from(r#"{"findings": [{"name": "wasi", "version": "0.11.1"}]}"#);
        let state = baseline.classify(&finding("wasi", "0.11.1", RiskLevel::Critical, 90.0));
        assert_eq!(
            state,
            BaselineState::Known,
            "with no recorded level there is nothing to have increased from"
        );
    }

    #[test]
    fn a_missing_baseline_file_is_an_error_with_recovery_guidance() {
        let err = load(Path::new("/nonexistent/depcheck-baseline.json")).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("--write-baseline"), "{text}");
    }

    #[test]
    fn a_non_report_json_file_is_rejected() {
        let path = temp_dir("bad-baseline").join("not-a-report.json");
        std::fs::write(&path, "[1, 2, 3]").unwrap();
        let err = load(&path).unwrap_err();
        assert!(format!("{err:#}").contains("not a cargo-depcheck JSON report"));
    }
}
