//! GitHub-flavored Markdown output, for PR comments and job summaries.
//!
//! The terminal report is built for a terminal: box-drawing characters, a
//! score bar, ANSI color. Pasted into a PR comment it becomes an unreadable
//! block of pipes and escape codes, so review-time output gets its own
//! renderer rather than a stripped-down version of the human one.
//!
//! Everything here is plain text by construction — no `colored` calls — so
//! the output is identical whether or not a terminal is attached.

use std::collections::HashMap;
use std::fmt::Write as _;

use chrono::{DateTime, Utc};

use crate::baseline::BaselineState;
use crate::registry::Metadata;
use crate::report::{self, Finding, JsonDuplicate, ReportSummary};
use crate::score::{self, RiskLevel};

/// Marker comment emitted as the first line, so automation can find a
/// previous cargo-depcheck comment and update it in place instead of adding
/// another one to a PR on every push. Part of the tool's output rather than
/// the Action's shell script, so any CI system can implement the same
/// sticky-comment behavior.
pub const COMMENT_MARKER: &str = "<!-- cargo-depcheck -->";

/// Rows past this are summarized as a count rather than listed. A PR comment
/// has a hard size limit on GitHub, and a several-hundred-row table is not
/// review material anyway — `--top` is the deliberate way to choose a
/// smaller number.
const MAX_TABLE_ROWS: usize = 50;

pub struct MarkdownReport<'a> {
    pub findings: &'a [Finding],
    pub meta_map: &'a HashMap<String, Metadata>,
    pub now: DateTime<Utc>,
    pub summary: &'a ReportSummary,
    pub threshold: f64,
    pub duplicates: &'a [JsonDuplicate],
    pub project: Option<&'a str>,
    /// Pre-rendered baseline comparison line, when `--baseline` was used.
    pub baseline: Option<String>,
}

pub fn render(report: &MarkdownReport) -> String {
    let mut out = String::new();
    writeln!(out, "{COMMENT_MARKER}").unwrap();

    let summary = report.summary;
    writeln!(out, "### cargo-depcheck — {}", headline(summary)).unwrap();
    writeln!(out).unwrap();

    let mut facts: Vec<String> = Vec::new();
    if let Some(project) = report.project {
        facts.push(format!("**{}**", escape(project)));
    }
    facts.push(format!(
        "{} {} checked",
        summary.total,
        crate::plural(summary.total, "dependency", "dependencies")
    ));
    facts.push(format!("threshold {}", trim_float(report.threshold)));
    if summary.degraded {
        facts.push("**INCOMPLETE — some crates could not be checked**".to_string());
    }
    writeln!(out, "{}", facts.join(" · ")).unwrap();
    writeln!(out).unwrap();

    if let Some(line) = &report.baseline {
        writeln!(out, "> {}", escape(line)).unwrap();
        writeln!(out).unwrap();
    }

    if report.findings.is_empty() {
        writeln!(out, "No dependencies scored at or above the threshold.",).unwrap();
        writeln!(out).unwrap();
    } else {
        write_table(&mut out, report);
    }

    write_counts(&mut out, summary);

    if let Some(line) = duplicates_note(report.duplicates) {
        writeln!(out).unwrap();
        writeln!(out, "{line}").unwrap();
    }

    writeln!(out).unwrap();
    writeln!(
        out,
        "<sub>cargo-depcheck v{} · ranked by graph impact, not severity alone · \
         reproduce locally with `cargo depcheck`</sub>",
        env!("CARGO_PKG_VERSION")
    )
    .unwrap();

    out
}

fn headline(summary: &ReportSummary) -> String {
    if summary.critical == 0 && summary.warnings == 0 {
        return "nothing above the warning level".to_string();
    }
    let mut parts = Vec::new();
    if summary.critical > 0 {
        parts.push(format!("{} critical", summary.critical));
    }
    if summary.warnings > 0 {
        parts.push(format!(
            "{} {}",
            summary.warnings,
            crate::plural(summary.warnings, "warning", "warnings")
        ));
    }
    parts.join(", ")
}

fn write_table(out: &mut String, report: &MarkdownReport) {
    let comparing = report.baseline.is_some();
    if comparing {
        writeln!(out, "| Level | Crate | Score | Baseline | Why |").unwrap();
        writeln!(out, "|---|---|---:|---|---|").unwrap();
    } else {
        writeln!(out, "| Level | Crate | Score | Why |").unwrap();
        writeln!(out, "|---|---|---:|---|").unwrap();
    }

    for finding in report.findings.iter().take(MAX_TABLE_ROWS) {
        let level = level_label(finding.risk.level);
        // Backticks keep a crate name from being read as Markdown, and bold
        // marks a direct dependency — the same distinction the terminal
        // report draws, since "you own this one" changes who acts on it.
        // Escaped even inside the backticks: a pipe ends a table cell before
        // any code-span rule applies, so a name carrying one would silently
        // shift every column after it.
        let label = escape(&format!("{} {}", finding.node.name, finding.node.version));
        let name = if finding.node.is_direct {
            format!("**`{label}`**")
        } else {
            format!("`{label}`")
        };
        let score = format!("{:.1}", score::rounded(finding.risk.total));
        let why = escape(&reasons(finding, report));

        if comparing {
            let state = match finding.baseline_state {
                BaselineState::New(reason) => format!("**new** ({})", reason.describe()),
                BaselineState::Known => "known".to_string(),
                BaselineState::NotCompared => String::new(),
            };
            writeln!(out, "| {level} | {name} | {score} | {state} | {why} |").unwrap();
        } else {
            writeln!(out, "| {level} | {name} | {score} | {why} |").unwrap();
        }
    }

    let hidden = report.findings.len().saturating_sub(MAX_TABLE_ROWS);
    if hidden > 0 {
        writeln!(out).unwrap();
        writeln!(
            out,
            "_{hidden} more {} not shown. Raise `--threshold` or use `--top` to choose what appears._",
            crate::plural(hidden, "finding", "findings")
        )
        .unwrap();
    }
    writeln!(out).unwrap();
}

/// Severity as a plain-text label, never color or an icon alone — the same
/// rule the terminal report follows, and the one that keeps this readable in
/// a screen reader or a plain-text email notification.
fn level_label(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "**CRITICAL**",
        RiskLevel::Warn => "WARN",
        RiskLevel::Low => "notice",
    }
}

fn reasons(finding: &Finding, report: &MarkdownReport) -> String {
    let lines = report::reason_lines(
        &finding.node,
        &finding.risk,
        &finding.advisories,
        report.meta_map,
        report.now,
    );
    lines.join("; ")
}

fn write_counts(out: &mut String, summary: &ReportSummary) {
    writeln!(out, "<details>").unwrap();
    writeln!(out, "<summary>Summary counts</summary>").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "| critical | warnings | notices | unknown | not applicable | ignored | healthy |"
    )
    .unwrap();
    writeln!(out, "|---|---|---|---|---|---|---|").unwrap();
    writeln!(
        out,
        "| {} | {} | {} | {} | {} | {} | {} |",
        summary.critical,
        summary.warnings,
        summary.notices,
        summary.unknown,
        summary.not_applicable,
        summary.ignored,
        summary.healthy
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "</details>").unwrap();
}

fn duplicates_note(duplicates: &[JsonDuplicate]) -> Option<String> {
    if duplicates.is_empty() {
        return None;
    }
    const SHOWN: usize = 5;
    let shown: Vec<String> = duplicates
        .iter()
        .take(SHOWN)
        .map(|d| format!("`{}` ({})", d.name, d.versions.join(", ")))
        .collect();
    let more = duplicates.len().saturating_sub(SHOWN);
    let suffix = if more > 0 {
        format!(" (+ {more} more)")
    } else {
        String::new()
    };
    Some(format!(
        "_{} {} resolve at multiple versions: {}{suffix}_",
        duplicates.len(),
        crate::plural(duplicates.len(), "crate", "crates"),
        shown.join(", ")
    ))
}

/// Neutralizes the two characters that can break out of a table cell: a pipe
/// ends the cell, and a newline ends the row. Advisory titles and ignore
/// reasons are arbitrary upstream text, so neither can be assumed safe.
fn escape(text: &str) -> String {
    text.replace('|', "\\|").replace(['\r', '\n'], " ")
}

/// `40` rather than `40.0` for a whole-number threshold, matching how a user
/// typed it on the command line.
fn trim_float(value: f64) -> String {
    if value.fract().abs() < f64::EPSILON {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DependencyNode, NodeKind};
    use crate::score::RiskScore;
    use semver::Version;

    fn summary(critical: usize, warnings: usize) -> ReportSummary {
        ReportSummary {
            total: 345,
            critical,
            warnings,
            notices: 342,
            unknown: 0,
            not_applicable: 0,
            ignored: 0,
            healthy: 0,
            degraded: false,
        }
    }

    fn finding(name: &str, level: RiskLevel, total: f64, is_direct: bool) -> Finding {
        Finding {
            node: DependencyNode {
                name: name.to_string(),
                version: Version::new(0, 11, 1),
                is_direct,
                depth: 2,
                dependent_count: 3,
                transitive_dependent_count: 25,
                is_registry: true,
                kind: NodeKind::Normal,
            },
            risk: RiskScore {
                security: 0.0,
                version_lag: 25.0,
                maintenance: 7.0,
                graph_multiplier: 1.45,
                total,
                level,
            },
            advisories: Vec::new(),
            baseline_state: BaselineState::NotCompared,
        }
    }

    fn report<'a>(
        findings: &'a [Finding],
        meta_map: &'a HashMap<String, Metadata>,
        summary: &'a ReportSummary,
    ) -> MarkdownReport<'a> {
        MarkdownReport {
            findings,
            meta_map,
            now: "2026-08-31T00:00:00Z".parse().unwrap(),
            summary,
            threshold: 40.0,
            duplicates: &[],
            project: Some("my-crate"),
            baseline: None,
        }
    }

    #[test]
    fn output_starts_with_the_sticky_comment_marker() {
        let findings = vec![finding("wasi", RiskLevel::Warn, 46.4, false)];
        let meta = HashMap::new();
        let counts = summary(0, 1);
        let text = render(&report(&findings, &meta, &counts));
        assert!(
            text.starts_with(COMMENT_MARKER),
            "automation locates its own comment by this marker: {text}"
        );
    }

    #[test]
    fn contains_no_ansi_escapes_even_when_color_is_forced() {
        // The Markdown body must never depend on terminal state: a job
        // summary or PR comment rendering `\u{1b}[31m` is corrupted output,
        // and CI sets CLICOLOR_FORCE often enough for this to be a real path.
        colored::control::set_override(true);
        let findings = vec![finding("wasi", RiskLevel::Critical, 91.2, true)];
        let meta = HashMap::new();
        let counts = summary(1, 0);
        let text = render(&report(&findings, &meta, &counts));
        colored::control::unset_override();
        assert!(!text.contains('\u{1b}'), "ANSI escape leaked: {text:?}");
    }

    #[test]
    fn a_pipe_in_reason_text_cannot_break_the_table_row() {
        let mut findings = vec![finding("weird|name", RiskLevel::Warn, 44.0, false)];
        findings[0].node.name = "pipe|crate".to_string();
        let meta = HashMap::new();
        let counts = summary(0, 1);
        let text = render(&report(&findings, &meta, &counts));
        let row = text
            .lines()
            .find(|l| l.contains("pipe"))
            .expect("the finding row must be present");

        // A four-column row has exactly five column separators. Any pipe
        // beyond those must be backslash-escaped, or the columns after it
        // shift — count the unescaped ones directly rather than inferring it.
        let unescaped = row
            .char_indices()
            .filter(|(index, ch)| *ch == '|' && (*index == 0 || row.as_bytes()[index - 1] != b'\\'))
            .count();
        assert_eq!(unescaped, 5, "unescaped pipe in row: {row}");
        assert!(
            row.contains("pipe\\|crate"),
            "the name must be escaped: {row}"
        );
    }

    #[test]
    fn a_clean_report_says_so_instead_of_rendering_an_empty_table() {
        let meta = HashMap::new();
        let counts = summary(0, 0);
        let text = render(&report(&[], &meta, &counts));
        assert!(text.contains("nothing above the warning level"));
        assert!(text.contains("No dependencies scored at or above the threshold."));
        assert!(!text.contains("| Level |"), "no table header: {text}");
    }

    #[test]
    fn the_baseline_column_appears_only_when_comparing() {
        let findings = vec![finding("wasi", RiskLevel::Warn, 46.4, false)];
        let meta = HashMap::new();
        let counts = summary(0, 1);

        let without = render(&report(&findings, &meta, &counts));
        assert!(!without.contains("Baseline"));

        let mut with_baseline = report(&findings, &meta, &counts);
        with_baseline.baseline = Some("baseline b.json: 1 new · 0 known (0 entries)".into());
        let text = render(&with_baseline);
        assert!(
            text.contains("| Level | Crate | Score | Baseline | Why |"),
            "{text}"
        );
    }

    #[test]
    fn a_new_finding_is_marked_with_its_reason() {
        let mut findings = vec![finding("wasi", RiskLevel::Warn, 46.4, false)];
        findings[0].baseline_state = BaselineState::New(crate::baseline::NewReason::NewAdvisory);
        let meta = HashMap::new();
        let counts = summary(0, 1);
        let mut ctx = report(&findings, &meta, &counts);
        ctx.baseline = Some("baseline b.json: 1 new · 0 known (1 entries)".into());
        let text = render(&ctx);
        assert!(
            text.contains("**new** (new advisory since the baseline)"),
            "{text}"
        );
    }

    #[test]
    fn a_long_report_is_capped_with_a_count_of_what_is_hidden() {
        let findings: Vec<Finding> = (0..MAX_TABLE_ROWS + 7)
            .map(|i| finding(&format!("crate-{i}"), RiskLevel::Warn, 44.0, false))
            .collect();
        let meta = HashMap::new();
        let counts = summary(0, findings.len());
        let text = render(&report(&findings, &meta, &counts));
        assert_eq!(
            text.matches("| WARN |").count(),
            MAX_TABLE_ROWS,
            "table must stop at the row cap"
        );
        assert!(text.contains("7 more findings not shown"), "{text}");
    }

    #[test]
    fn a_whole_number_threshold_renders_without_a_decimal() {
        assert_eq!(trim_float(40.0), "40");
        assert_eq!(trim_float(37.5), "37.5");
    }
}
