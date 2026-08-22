use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use rustsec::advisory::Advisory;
use semver::Version;
use serde::Serialize;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::graph::DependencyNode;
use crate::registry::Metadata;
use crate::score;
use crate::score::{RiskLevel, RiskScore, DEFAULT_THRESHOLD};

/// Fallback box width when no terminal is attached (e.g. output piped to a
/// file) and `COLUMNS` isn't set.
const DEFAULT_INNER_WIDTH: usize = 77;
const MIN_INNER_WIDTH: usize = 60;
const MAX_INNER_WIDTH: usize = 120;
/// Space taken by the box's own `│ │` border characters.
const BORDER_OVERHEAD: usize = 2;
const NAME_FIELD_WIDTH: usize = 41;

pub const JSON_SCHEMA_VERSION: u32 = 2;

pub struct Finding {
    pub node: DependencyNode,
    pub risk: RiskScore,
    pub advisories: Vec<Advisory>,
}

pub struct ReportSummary {
    pub critical: usize,
    pub warnings: usize,
    pub unknown: usize,
    pub healthy: usize,
}

#[derive(Serialize)]
pub struct JsonReport {
    pub schema_version: u32,
    pub summary: JsonSummary,
    pub findings: Vec<JsonFinding>,
    /// Crates resolved at more than one version in the same graph — build
    /// bloat at minimum, and a real security gap when the older copy is the
    /// vulnerable one and only the newer one gets patched.
    pub duplicates: Vec<JsonDuplicate>,
}

#[derive(Serialize)]
pub struct JsonDuplicate {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Serialize)]
pub struct JsonSummary {
    pub critical: usize,
    pub warnings: usize,
    pub unknown: usize,
    pub healthy: usize,
    pub threshold: f64,
    /// True when crates.io metadata could not be fetched for one or more
    /// registry dependencies. Findings are still reported, but version-lag
    /// and maintenance scoring for affected crates is incomplete.
    pub degraded: bool,
    /// Names of registry dependencies whose crates.io metadata fetch failed
    /// this run (capped to a small sample; see `unchecked_count` for the total).
    pub unchecked_sample: Vec<String>,
    pub unchecked_count: usize,
}

#[derive(Serialize)]
pub struct JsonComponents {
    pub security: f64,
    pub version_lag: f64,
    pub maintenance: f64,
    pub graph_multiplier: f64,
}

#[derive(Serialize)]
pub struct JsonFinding {
    pub name: String,
    pub version: String,
    pub score: f64,
    pub level: &'static str,
    pub is_direct: bool,
    pub dependent_count: usize,
    pub transitive_dependent_count: usize,
    pub components: JsonComponents,
    pub reasons: Vec<String>,
    pub advisories: Vec<String>,
}

/// A prominent, hard-to-miss warning for when crates.io metadata could not
/// be fetched for one or more registry dependencies. Version-lag and
/// maintenance scoring is unavailable for the affected crates, so results
/// are incomplete — this must never be confused with a clean report.
pub fn degraded_warning(
    unchecked_count: usize,
    attempted: usize,
    sample: &[String],
    last_error: Option<&str>,
) -> String {
    let noun = if unchecked_count == 1 {
        "crate"
    } else {
        "crates"
    };
    let mut msg = format!(
        "  {} {} of {attempted} {noun} could not be checked (network error) — results are incomplete",
        "⚠".yellow().bold(),
        unchecked_count.to_string().yellow().bold(),
    );
    if !sample.is_empty() {
        let more = unchecked_count.saturating_sub(sample.len());
        let suffix = if more > 0 {
            format!(" (+ {more} more)")
        } else {
            String::new()
        };
        msg.push_str(&format!(
            "
     e.g. {}{suffix}",
            sample.join(", ")
        ));
    }
    if let Some(err) = last_error {
        msg.push_str(&format!(
            "
     last error: {err}"
        ));
    }
    msg
}

/// Crates resolved at more than one version in the same graph. Computed
/// from the *full* node set, not just findings that cleared the score
/// threshold — a duplicate is worth knowing about regardless of whether
/// either copy individually scores high enough to appear as a finding.
pub fn duplicate_groups(all_findings: &[Finding]) -> Vec<JsonDuplicate> {
    let mut by_name: HashMap<&str, Vec<Version>> = HashMap::new();
    for f in all_findings {
        by_name
            .entry(f.node.name.as_str())
            .or_default()
            .push(f.node.version.clone());
    }

    let mut groups: Vec<JsonDuplicate> = by_name
        .into_iter()
        .filter(|(_, versions)| versions.len() > 1)
        .map(|(name, mut versions)| {
            versions.sort();
            JsonDuplicate {
                name: name.to_string(),
                versions: versions.iter().map(Version::to_string).collect(),
            }
        })
        .collect();
    groups.sort_by(|a, b| a.name.cmp(&b.name));
    groups
}

/// A single-line summary of duplicate-version groups, capped so a graph
/// with many duplicates doesn't produce an unreadable wall of text.
pub fn duplicates_line(duplicates: &[JsonDuplicate]) -> Option<String> {
    if duplicates.is_empty() {
        return None;
    }

    const SHOWN: usize = 3;
    let noun = if duplicates.len() == 1 {
        "crate"
    } else {
        "crates"
    };
    let shown: Vec<String> = duplicates
        .iter()
        .take(SHOWN)
        .map(|d| format!("{} ({})", d.name, d.versions.join(", ")))
        .collect();
    let more = duplicates.len().saturating_sub(SHOWN);
    let suffix = if more > 0 {
        format!(" (+ {more} more)")
    } else {
        String::new()
    };

    Some(format!(
        "  {} {} {} resolve at multiple versions: {}{suffix}",
        "⚠".yellow(),
        duplicates.len(),
        noun,
        shown.join(", ")
    ))
}

pub fn summarize(total: usize, critical: usize, warnings: usize, unknown: usize) -> ReportSummary {
    ReportSummary {
        critical,
        warnings,
        unknown,
        healthy: total.saturating_sub(critical + warnings + unknown),
    }
}

pub fn to_json(
    findings: &[Finding],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    summary: &ReportSummary,
    threshold: f64,
    unchecked: &[String],
    duplicates: Vec<JsonDuplicate>,
) -> JsonReport {
    JsonReport {
        schema_version: JSON_SCHEMA_VERSION,
        summary: JsonSummary {
            critical: summary.critical,
            warnings: summary.warnings,
            unknown: summary.unknown,
            healthy: summary.healthy,
            threshold,
            degraded: !unchecked.is_empty(),
            unchecked_sample: unchecked.iter().take(5).cloned().collect(),
            unchecked_count: unchecked.len(),
        },
        findings: findings
            .iter()
            .map(|finding| json_finding(finding, meta_map, now))
            .collect(),
        duplicates,
    }
}

pub fn render_json(report: &JsonReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub fn render(
    findings: &[Finding],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    summary: &ReportSummary,
    quiet: bool,
    threshold: f64,
    duplicates: &[JsonDuplicate],
) {
    print!(
        "{}",
        render_to_string(findings, meta_map, now, summary, quiet, threshold, duplicates)
    );
}

/// Builds the exact text `render()` prints, as a `String` instead of writing
/// directly to stdout — this is what makes the report snapshot-testable:
/// tests can assert on the returned text (with `colored::control::set_override`
/// forcing ANSI on or off) without any global-stdout capture trickery.
fn render_to_string(
    findings: &[Finding],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    summary: &ReportSummary,
    quiet: bool,
    threshold: f64,
    duplicates: &[JsonDuplicate],
) -> String {
    let mut out = String::new();
    write_summary(&mut out, summary);

    if quiet {
        return out;
    }

    if let Some(line) = duplicates_line(duplicates) {
        writeln!(out, "{line}").unwrap();
    }

    writeln!(out).unwrap();
    let inner_width = detect_inner_width();

    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.risk.level == RiskLevel::Critical)
        .collect();
    let warnings: Vec<_> = findings
        .iter()
        .filter(|f| f.risk.level == RiskLevel::Warn)
        .collect();
    let notice: Vec<_> = findings
        .iter()
        .filter(|f| f.risk.level == RiskLevel::Low)
        .collect();

    if !critical.is_empty() {
        write_section(
            &mut out,
            "CRITICAL",
            RiskLevel::Critical,
            &critical,
            meta_map,
            now,
            inner_width,
        );
        writeln!(out).unwrap();
    }

    if !warnings.is_empty() {
        write_section(
            &mut out,
            "WARN",
            RiskLevel::Warn,
            &warnings,
            meta_map,
            now,
            inner_width,
        );
        writeln!(out).unwrap();
    }

    if threshold < DEFAULT_THRESHOLD && !notice.is_empty() {
        write_section(
            &mut out,
            "NOTICE",
            RiskLevel::Low,
            &notice,
            meta_map,
            now,
            inner_width,
        );
        writeln!(out).unwrap();
    }

    if critical.is_empty() && warnings.is_empty() && notice.is_empty() {
        writeln!(
            out,
            "  {} No dependencies scored at or above the threshold.\n",
            "✓".green()
        )
        .unwrap();
    }

    out
}

/// Picks a box width from the real terminal, `COLUMNS`, or a sane default —
/// clamped so a tiny or absurdly wide terminal never breaks the layout.
fn detect_inner_width() -> usize {
    let cols = terminal_size::terminal_size()
        .map(|(terminal_size::Width(w), _)| w as usize)
        .or_else(|| std::env::var("COLUMNS").ok().and_then(|v| v.parse().ok()));

    match cols {
        Some(c) => c
            .saturating_sub(BORDER_OVERHEAD)
            .clamp(MIN_INNER_WIDTH, MAX_INNER_WIDTH),
        None => DEFAULT_INNER_WIDTH,
    }
}

/// Right-pads `s` to `width` display columns (not bytes/chars), so
/// multi-byte and full-width characters still align.
fn pad_to_width(s: &str, width: usize) -> String {
    let visible = s.width();
    if visible >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - visible))
    }
}

/// Truncates `s` to `width` display columns, appending `…` if it was cut.
fn ellipsize(s: &str, width: usize) -> String {
    if s.width() <= width || width == 0 {
        return s.chars().take(width).collect();
    }
    let mut out = String::new();
    let mut w = 0;
    for ch in s.chars() {
        let cw = ch.width().unwrap_or(0);
        if w + cw > width.saturating_sub(1) {
            break;
        }
        out.push(ch);
        w += cw;
    }
    out.push('…');
    out
}

/// Wraps already-styled `content` in the box's left/right border, computing
/// padding from `visible_width` — the ANSI-stripped display width of
/// `content` — rather than from `content` itself. `format!("{:<N$}")` counts
/// escape-sequence bytes as columns, which is what misaligns colored and
/// bold rows; every caller must measure the unstyled text first.
fn boxed_line(content: &str, visible_width: usize, inner_width: usize) -> String {
    let pad = inner_width.saturating_sub(visible_width);
    format!("│{content}{}│", " ".repeat(pad))
}

fn write_summary(out: &mut String, summary: &ReportSummary) {
    if summary.unknown > 0 {
        writeln!(
            out,
            "  {} critical  ·  {} warnings  ·  {} unknown  ·  {} healthy",
            summary.critical.to_string().red().bold(),
            summary.warnings.to_string().yellow().bold(),
            summary.unknown.to_string().dimmed(),
            summary.healthy.to_string().green(),
        )
        .unwrap();
    } else {
        writeln!(
            out,
            "  {} critical  ·  {} warnings  ·  {} healthy",
            summary.critical.to_string().red().bold(),
            summary.warnings.to_string().yellow().bold(),
            summary.healthy.to_string().green(),
        )
        .unwrap();
    }
}

fn json_finding(
    finding: &Finding,
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
) -> JsonFinding {
    JsonFinding {
        name: finding.node.name.clone(),
        version: finding.node.version.to_string(),
        score: round1(finding.risk.total),
        level: finding.risk.level.as_str(),
        is_direct: finding.node.is_direct,
        dependent_count: finding.node.dependent_count,
        transitive_dependent_count: finding.node.transitive_dependent_count,
        components: JsonComponents {
            security: round1(finding.risk.security),
            version_lag: round1(finding.risk.version_lag),
            maintenance: round1(finding.risk.maintenance),
            graph_multiplier: round1(finding.risk.graph_multiplier),
        },
        reasons: reason_lines(
            &finding.node,
            &finding.risk,
            &finding.advisories,
            meta_map,
            now,
        ),
        advisories: finding.advisories.iter().map(advisory_label).collect(),
    }
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn advisory_label(advisory: &Advisory) -> String {
    if let Some(info) = &advisory.metadata.informational {
        return info.to_string();
    }

    advisory.id().as_str().to_string()
}

fn write_section(
    out: &mut String,
    title: &str,
    level: RiskLevel,
    items: &[&Finding],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    inner_width: usize,
) {
    writeln!(out, "┌{}┐", "─".repeat(inner_width)).unwrap();

    let title_label = format!("  {title} ");
    writeln!(
        out,
        "{}",
        boxed_line(&title_label, title_label.width(), inner_width)
    )
    .unwrap();
    writeln!(out, "├{}┤", "─".repeat(inner_width)).unwrap();

    for (index, finding) in items.iter().enumerate() {
        if index > 0 {
            writeln!(out, "├{}┤", "─".repeat(inner_width)).unwrap();
        }
        write_finding(out, finding, level, meta_map, now, inner_width);
    }

    writeln!(out, "└{}┘", "─".repeat(inner_width)).unwrap();
}

fn write_finding(
    out: &mut String,
    finding: &Finding,
    level: RiskLevel,
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    inner_width: usize,
) {
    let (header, visible_width) = build_header(finding, level);
    writeln!(out, "{}", boxed_line(&header, visible_width, inner_width)).unwrap();

    for line in reason_lines(
        &finding.node,
        &finding.risk,
        &finding.advisories,
        meta_map,
        now,
    ) {
        let detail = format!("   {line}");
        writeln!(out, "{}", boxed_line(&detail, detail.width(), inner_width)).unwrap();
    }
}

/// Builds a finding's header row: the styled content, plus its true visible
/// width measured from the *unstyled* text. Split out from `render_finding`
/// so the same construction is exercised directly in tests — this is the
/// exact code path where colored/bold rows previously misaligned the box.
fn build_header(finding: &Finding, level: RiskLevel) -> (String, usize) {
    let name_ver = format!("{} {}", finding.node.name, finding.node.version);
    let name_field = ellipsize(&name_ver, NAME_FIELD_WIDTH);
    let padded_name = format!(" {}", pad_to_width(&name_field, NAME_FIELD_WIDTH));

    let score_text = format!("{:>3.0}", finding.risk.total);
    let bar = score_bar(finding.risk.total, 12);

    let visible_width = format!("{padded_name}{score_text} {bar}").width();

    let score_display = match level {
        RiskLevel::Critical => score_text.red().bold().to_string(),
        RiskLevel::Warn => score_text.yellow().to_string(),
        RiskLevel::Low => score_text,
    };
    let styled_name = if finding.node.is_direct {
        padded_name.bold().to_string()
    } else {
        padded_name
    };
    (format!("{styled_name}{score_display} {bar}"), visible_width)
}

fn score_bar(score: f64, width: usize) -> String {
    let filled = ((score / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

pub(crate) fn reason_lines(
    node: &DependencyNode,
    risk: &RiskScore,
    advisories: &[Advisory],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut lines = Vec::new();

    for advisory in advisories {
        lines.push(advisory_line(advisory));
    }

    if let Some(meta) = meta_map.get(&node.name) {
        if meta.is_yanked(&node.version) {
            lines.push(format!(
                "yanked: {} {} was pulled from crates.io",
                node.name, node.version
            ));
        }

        if let Some(line) = version_lag_line(&node.version, meta.latest_stable()) {
            lines.push(line);
        }

        let days = (now - meta.updated_at).num_days();
        if risk.maintenance > 0.0 {
            lines.push(maintenance_line(days));
        }
    }

    if node.transitive_dependent_count > 0 {
        let noun = if node.transitive_dependent_count == 1 {
            "crate"
        } else {
            "crates"
        };
        lines.push(format!(
            "relied on by {} {} in your graph, directly or transitively",
            node.transitive_dependent_count, noun
        ));
    }

    if lines.is_empty() {
        lines.push(risk.explain());
    }

    lines
}

fn advisory_line(advisory: &Advisory) -> String {
    if let Some(info) = &advisory.metadata.informational {
        return format!("flagged: {info}");
    }

    format!("advisory: {}", advisory.id().as_str())
}

/// Wording follows the same Cargo-compatibility split used for scoring
/// (`score::lag_components`): a 0.x minor bump is described as "breaking,"
/// matching what it actually is under Cargo's rules, not glossed as
/// "minor" the way a compatible >=1.0 minor bump is.
fn version_lag_line(have: &Version, latest: &Version) -> Option<String> {
    if have >= latest {
        return None;
    }

    let (breaking, compatible, patch) = score::lag_components(have, latest);

    if breaking > 0 {
        return Some(format!(
            "{breaking} breaking version(s) behind latest ({have} → {latest})"
        ));
    }
    if compatible > 0 {
        return Some(format!(
            "{compatible} minor version(s) behind latest ({have} → {latest})"
        ));
    }
    if patch > 0 {
        return Some(format!(
            "{patch} patch version(s) behind latest ({have} → {latest})"
        ));
    }

    // have < latest by prerelease tag alone (e.g. pinned "1.0.0-beta.1" vs a
    // released "1.0.0") — no numeric component differs, so there's nothing
    // meaningful to report as a lag count.
    None
}

fn maintenance_line(days: i64) -> String {
    if days >= 365 {
        let years = days as f64 / 365.0;
        format!("last published {years:.0} years ago")
    } else {
        format!("last published {days} days ago")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_bar_full_and_empty() {
        assert_eq!(score_bar(100.0, 10), "██████████");
        assert_eq!(score_bar(0.0, 10), "░░░░░░░░░░");
        assert_eq!(score_bar(50.0, 10), "█████░░░░░");
    }

    #[test]
    fn summarize_counts() {
        let summary = summarize(100, 2, 6, 0);
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.warnings, 6);
        assert_eq!(summary.unknown, 0);
        assert_eq!(summary.healthy, 92);
    }

    #[test]
    fn summarize_never_folds_unknown_into_healthy() {
        let summary = summarize(100, 2, 6, 5);
        assert_eq!(summary.unknown, 5);
        assert_eq!(summary.healthy, 87);
        assert_eq!(
            summary.critical + summary.warnings + summary.unknown + summary.healthy,
            100
        );
    }

    #[test]
    fn summarize_saturates_when_buckets_exceed_total() {
        // Defensive: a total that undercounts (e.g. stale caller) must never
        // underflow healthy into a huge usize via wraparound.
        let summary = summarize(5, 3, 3, 3);
        assert_eq!(summary.healthy, 0);
    }

    #[test]
    fn version_lag_line_major() {
        let have = Version::new(0, 10, 45);
        let latest = Version::new(3, 0, 0);
        let line = version_lag_line(&have, &latest).unwrap();
        assert!(line.contains("3 breaking"));
    }

    #[test]
    fn version_lag_line_none_when_only_prerelease_tag_differs() {
        // have < latest (prerelease sorts below the release), but major,
        // minor, and patch are all identical — nothing numeric to report.
        let have = Version::parse("1.0.0-beta.1").unwrap();
        let latest = Version::parse("1.0.0").unwrap();
        assert!(have < latest);
        assert!(version_lag_line(&have, &latest).is_none());
    }

    /// Ensures `colored::control::set_override` is always undone, even if
    /// an assertion below panics — otherwise one failing test would leave
    /// every later test in this binary rendering ANSI codes it doesn't expect.
    ///
    /// Also serializes every test that touches `colored::control` against
    /// every other one: it's global process state, and `cargo test` runs
    /// tests from the same binary concurrently on different threads by
    /// default, so two such tests racing on the override was an observed,
    /// reproducible failure (one test's forced-off color randomly came back
    /// forced-on mid-run) before this lock existed.
    static COLOR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct ColorOverrideGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl ColorOverrideGuard {
        fn new(force: bool) -> Self {
            let lock = COLOR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            colored::control::set_override(force);
            Self { _lock: lock }
        }
    }

    impl Drop for ColorOverrideGuard {
        fn drop(&mut self) {
            colored::control::unset_override();
        }
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for c2 in chars.by_ref() {
                    if c2 == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn test_finding(name: &str, is_direct: bool, level: RiskLevel, total: f64) -> Finding {
        Finding {
            node: DependencyNode {
                name: name.to_string(),
                version: Version::new(1, 0, 0),
                is_direct,
                depth: 1,
                dependent_count: 0,
                transitive_dependent_count: 0,
                is_registry: true,
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
        }
    }

    #[test]
    fn colored_and_bold_rows_stay_aligned_with_the_border() {
        let _guard = ColorOverrideGuard::new(true);

        const INNER: usize = 77;
        let cases = [
            test_finding("plain-crate", false, RiskLevel::Low, 10.0),
            test_finding("bold-direct-crate", true, RiskLevel::Low, 10.0),
            test_finding("warn-crate", false, RiskLevel::Warn, 55.0),
            test_finding("critical-crate", true, RiskLevel::Critical, 90.0),
            test_finding(
                "a-crate-with-a-genuinely-long-name-that-does-not-fit-the-field",
                true,
                RiskLevel::Critical,
                90.0,
            ),
        ];

        for finding in &cases {
            let (header, visible_width) = build_header(finding, finding.risk.level);
            let line = boxed_line(&header, visible_width, INNER);
            let stripped = strip_ansi(&line);
            assert_eq!(
                stripped.chars().count(),
                INNER + 2,
                "misaligned for {} (is_direct={})",
                finding.node.name,
                finding.node.is_direct
            );
        }
    }

    #[test]
    fn ellipsize_truncates_overlong_names() {
        let long = "a-crate-with-a-genuinely-long-name-that-does-not-fit-the-field";
        let out = ellipsize(long, NAME_FIELD_WIDTH);
        assert!(out.width() <= NAME_FIELD_WIDTH);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn ellipsize_leaves_short_names_untouched() {
        assert_eq!(ellipsize("serde", NAME_FIELD_WIDTH), "serde");
    }

    /// A small, fully synthetic report exercising CRITICAL, WARN, and NOTICE
    /// sections, a direct and a transitive dependency, and both version-lag
    /// and maintenance reason lines — fixed inputs only, no network or clock
    /// dependency, so the rendered text is exactly reproducible.
    fn sample_report() -> (
        Vec<Finding>,
        HashMap<String, Metadata>,
        DateTime<Utc>,
        ReportSummary,
    ) {
        let now: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();

        let mut meta_map = HashMap::new();
        meta_map.insert(
            "openssl".to_string(),
            Metadata {
                newest_version: Version::new(3, 0, 0),
                max_stable_version: Some(Version::new(3, 0, 0)),
                updated_at: now - chrono::Duration::days(730),
                yanked_versions: Vec::new(),
            },
        );
        meta_map.insert(
            "tokio".to_string(),
            Metadata {
                newest_version: Version::new(1, 40, 0),
                max_stable_version: Some(Version::new(1, 40, 0)),
                updated_at: now - chrono::Duration::days(10),
                yanked_versions: Vec::new(),
            },
        );
        meta_map.insert(
            "libc".to_string(),
            Metadata {
                newest_version: Version::new(0, 2, 189),
                max_stable_version: Some(Version::new(0, 2, 189)),
                updated_at: now - chrono::Duration::days(20),
                yanked_versions: Vec::new(),
            },
        );

        let findings = vec![
            Finding {
                node: DependencyNode {
                    name: "openssl".to_string(),
                    version: Version::new(0, 10, 45),
                    is_direct: true,
                    depth: 1,
                    dependent_count: 23,
                    transitive_dependent_count: 31,
                    is_registry: true,
                },
                risk: RiskScore {
                    security: 0.0,
                    version_lag: 25.0,
                    maintenance: 15.0,
                    graph_multiplier: 1.8,
                    total: 94.0,
                    level: RiskLevel::Critical,
                },
                advisories: Vec::new(),
            },
            Finding {
                node: DependencyNode {
                    name: "tokio".to_string(),
                    version: Version::new(1, 30, 0),
                    is_direct: false,
                    depth: 2,
                    dependent_count: 3,
                    transitive_dependent_count: 5,
                    is_registry: true,
                },
                risk: RiskScore {
                    security: 0.0,
                    version_lag: 10.0,
                    maintenance: 2.0,
                    graph_multiplier: 1.1,
                    total: 55.0,
                    level: RiskLevel::Warn,
                },
                advisories: Vec::new(),
            },
            Finding {
                node: DependencyNode {
                    name: "libc".to_string(),
                    version: Version::new(0, 2, 180),
                    is_direct: true,
                    depth: 1,
                    dependent_count: 1,
                    transitive_dependent_count: 1,
                    is_registry: true,
                },
                risk: RiskScore {
                    security: 0.0,
                    version_lag: 2.5,
                    maintenance: 0.4,
                    graph_multiplier: 1.0,
                    total: 15.0,
                    level: RiskLevel::Low,
                },
                advisories: Vec::new(),
            },
        ];

        let summary = summarize(346, 1, 1, 0);
        (findings, meta_map, now, summary)
    }

    #[test]
    fn report_snapshot_colored() {
        let _guard = ColorOverrideGuard::new(true);

        let (findings, meta_map, now, summary) = sample_report();
        let output = render_to_string(&findings, &meta_map, now, &summary, false, 5.0, &[]);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn report_snapshot_uncolored() {
        let _guard = ColorOverrideGuard::new(false);

        let (findings, meta_map, now, summary) = sample_report();
        let output = render_to_string(&findings, &meta_map, now, &summary, false, 5.0, &[]);
        assert!(
            !output.contains('\u{1b}'),
            "uncolored snapshot must contain no ANSI escapes"
        );
        insta::assert_snapshot!(output);
    }
}
