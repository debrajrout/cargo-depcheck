use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use rustsec::advisory::Advisory;
use semver::Version;
use serde::Serialize;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::baseline::BaselineState;
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
/// Columns a finding's header spends on everything except the name field:
/// a leading space, the 5-column score, a space, the 3-column severity
/// marker, a space, and the 12-column bar.
const HEADER_FIXED_WIDTH: usize = 1 + 5 + 1 + 3 + 1 + 12;
/// Columns a wrapped reason line's continuation is indented by, so a
/// continuation reads as part of the line above rather than as a new reason.
const CONTINUATION_INDENT: usize = 5;

/// Bumped to 4 for the optional per-finding `baseline` field. Everything
/// schema 3 guaranteed is unchanged: a report produced without `--baseline`
/// is byte-identical to what schema 3 emitted, and the new key appears only
/// when a comparison actually happened.
pub const JSON_SCHEMA_VERSION: u32 = 4;

#[derive(Clone)]
pub struct Finding {
    pub node: DependencyNode,
    pub risk: RiskScore,
    pub advisories: Vec<Advisory>,
    /// Set only when `--baseline` is in play; `NotCompared` otherwise, so
    /// every report renders exactly as before when there is nothing to
    /// compare against.
    pub baseline_state: BaselineState,
}

pub struct ReportSummary {
    pub total: usize,
    pub critical: usize,
    pub warnings: usize,
    pub notices: usize,
    pub unknown: usize,
    pub not_applicable: usize,
    pub ignored: usize,
    pub healthy: usize,
    pub degraded: bool,
}

#[derive(Serialize)]
pub struct JsonReport {
    pub schema_version: u32,
    /// This tool's own version — a CI artifact stored for later can't
    /// otherwise tell which release produced it.
    pub tool_version: &'static str,
    /// RFC 3339 timestamp of when this report was generated.
    pub generated_at: String,
    pub project: JsonProject,
    /// SHA-1 of the RustSec advisory database commit this report was
    /// checked against, if advisories were checked at all (`None` with
    /// `--no-advisories`, or if the cached-only open couldn't resolve one).
    pub advisory_db_commit: Option<String>,
    pub summary: JsonSummary,
    pub findings: Vec<JsonFinding>,
    /// Crates resolved at more than one version in the same graph — build
    /// bloat at minimum, and a real security gap when the older copy is the
    /// vulnerable one and only the newer one gets patched.
    pub duplicates: Vec<JsonDuplicate>,
    /// Crates suppressed via `--ignore` or `[package.metadata.depcheck]`'s
    /// `ignore` list — surfaced here since an ignored crate never appears
    /// as a finding, so this is the only place a config-file ignore's
    /// `reason` (if any) is visible at all.
    pub ignored: Vec<JsonIgnored>,
}

#[derive(Serialize)]
pub struct JsonProject {
    /// `None` for a virtual workspace manifest (no `[package]` table).
    pub name: Option<String>,
    pub manifest_path: String,
}

#[derive(Serialize, Clone)]
pub struct JsonDuplicate {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Serialize)]
pub struct JsonIgnored {
    pub name: String,
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct JsonSummary {
    pub total: usize,
    pub critical: usize,
    pub warnings: usize,
    pub notices: usize,
    pub unknown: usize,
    pub not_applicable: usize,
    pub ignored: usize,
    pub healthy: usize,
    pub threshold: f64,
    /// True when registry metadata or the advisory database was unavailable.
    /// Findings are still reported, but at least one scoring signal is
    /// incomplete.
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
    /// `"normal"`, `"build"`, or `"dev"` — see `graph::NodeKind`. Only
    /// `"build"`/`"dev"` findings appear when `--include-build`/
    /// `--include-dev` is passed; `"normal"` is always eligible.
    pub kind: &'static str,
    pub components: JsonComponents,
    pub reasons: Vec<String>,
    pub advisories: Vec<String>,
    /// `"new"` or `"known"` when this run compared against `--baseline`;
    /// omitted entirely otherwise, so a report produced without a baseline
    /// keeps exactly the shape it had before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<&'static str>,
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
    let noun = crate::plural(unchecked_count, "crate", "crates");
    let mut msg = format!(
        "  {} {} of {attempted} {noun} could not be checked (registry metadata unavailable) — results are incomplete",
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
        .filter_map(|(name, mut versions)| {
            versions.sort();
            versions.dedup();
            (versions.len() > 1).then(|| JsonDuplicate {
                name: name.to_string(),
                versions: versions.iter().map(Version::to_string).collect(),
            })
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
    let noun = crate::plural(duplicates.len(), "crate", "crates");
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

/// Builds mutually-exclusive summary buckets from the complete analyzed set.
///
/// Severity wins over data completeness: if a crate has a known advisory but
/// its registry metadata is unavailable, it remains a finding rather than
/// being hidden inside `unknown`; `degraded` still records that the run was
/// incomplete. Path/git dependencies with a known advisory are handled the
/// same way. This keeps every dependency in exactly one result bucket without
/// discarding actionable information.
pub fn summarize(
    findings: &[Finding],
    meta_map: &HashMap<String, Metadata>,
    ignored: usize,
    degraded: bool,
) -> ReportSummary {
    let mut summary = ReportSummary {
        total: findings.len() + ignored,
        critical: 0,
        warnings: 0,
        notices: 0,
        unknown: 0,
        not_applicable: 0,
        ignored,
        healthy: 0,
        degraded,
    };

    for finding in findings {
        match finding.risk.level {
            RiskLevel::Critical => summary.critical += 1,
            RiskLevel::Warn => summary.warnings += 1,
            RiskLevel::Low
                if finding.node.is_registry && !meta_map.contains_key(&finding.node.name) =>
            {
                summary.unknown += 1;
            }
            RiskLevel::Low if !finding.node.is_registry && finding.advisories.is_empty() => {
                summary.not_applicable += 1;
            }
            RiskLevel::Low if score::rounded(finding.risk.total) > 0.0 => summary.notices += 1,
            RiskLevel::Low => summary.healthy += 1,
        }
    }

    summary
}

/// Bundles the pieces of `to_json`'s payload that aren't per-finding, so
/// the function itself stays under clippy's argument-count lint instead of
/// growing a ninth positional `Vec` the next time something needs surfacing
/// outside the findings list.
pub struct JsonExtras<'a> {
    pub unchecked: &'a [String],
    pub duplicates: Vec<JsonDuplicate>,
    pub ignored: Vec<(String, Option<String>)>,
    pub project: JsonProject,
    pub advisory_db_commit: Option<String>,
}

pub fn to_json(
    findings: &[Finding],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    summary: &ReportSummary,
    threshold: f64,
    extras: JsonExtras,
) -> JsonReport {
    JsonReport {
        schema_version: JSON_SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION"),
        generated_at: now.to_rfc3339(),
        project: extras.project,
        advisory_db_commit: extras.advisory_db_commit,
        summary: JsonSummary {
            total: summary.total,
            critical: summary.critical,
            warnings: summary.warnings,
            notices: summary.notices,
            unknown: summary.unknown,
            not_applicable: summary.not_applicable,
            ignored: summary.ignored,
            healthy: summary.healthy,
            threshold,
            degraded: summary.degraded,
            unchecked_sample: extras.unchecked.iter().take(5).cloned().collect(),
            unchecked_count: extras.unchecked.len(),
        },
        findings: findings
            .iter()
            .map(|finding| json_finding(finding, meta_map, now))
            .collect(),
        duplicates: extras.duplicates,
        ignored: extras
            .ignored
            .into_iter()
            .map(|(name, reason)| JsonIgnored { name, reason })
            .collect(),
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

/// Splits `text` into lines that each fit `width` display columns, breaking
/// at spaces and indenting continuations by `CONTINUATION_INDENT`.
///
/// Reason lines used to go to `boxed_line` unwrapped, and its `saturating_sub`
/// silently clamped the padding to zero — so any line wider than the box (a
/// long version pair like `0.11.1+wasi-snapshot-preview1 →
/// 0.14.7+wasi-0.2.4` reaches ~90 columns against a 77-column default) pushed
/// the closing `│` past the border and visibly broke the frame. Wrapping
/// rather than truncating because the tail of these lines is the actionable
/// half: the version to upgrade *to*.
///
/// A single word longer than `width` (no space to break at) is hard-split
/// rather than allowed to overflow — correctness of the frame wins over
/// keeping such a token intact.
fn wrap_to_width(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    if text.width() <= width {
        return vec![text.to_string()];
    }

    let continuation = " ".repeat(CONTINUATION_INDENT.min(width.saturating_sub(1)));
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0;

    for word in text.split(' ') {
        // Budget for this line: the full box on the first line, minus the
        // hanging indent on every continuation.
        let indent = if lines.is_empty() {
            0
        } else {
            continuation.width()
        };
        let budget = width.saturating_sub(indent);
        let word_width = word.width();
        let sep = if current.is_empty() { 0 } else { 1 };

        if current_width + sep + word_width <= budget {
            if sep == 1 {
                current.push(' ');
            }
            current.push_str(word);
            current_width += sep + word_width;
            continue;
        }

        if !current.is_empty() {
            lines.push(if lines.is_empty() {
                current.clone()
            } else {
                format!("{continuation}{current}")
            });
        }

        // The word alone may still exceed a whole line; hard-split it. Both
        // `current` and `current_width` are unconditionally reassigned on the
        // loop's only exit, so no reset is needed before it.
        let mut rest = word;
        loop {
            let indent = if lines.is_empty() {
                0
            } else {
                continuation.width()
            };
            let budget = width.saturating_sub(indent).max(1);
            if rest.width() <= budget {
                current = rest.to_string();
                current_width = rest.width();
                break;
            }
            let head = take_columns(rest, budget);
            lines.push(if lines.is_empty() {
                head.clone()
            } else {
                format!("{continuation}{head}")
            });
            rest = &rest[head.len()..];
        }
    }

    if !current.is_empty() {
        lines.push(if lines.is_empty() {
            current
        } else {
            format!("{continuation}{current}")
        });
    }

    lines
}

/// Longest prefix of `s` that fits `width` display columns, split on a
/// character boundary so the returned slice length is always valid to index
/// with.
fn take_columns(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut w = 0;
    for ch in s.chars() {
        let cw = ch.width().unwrap_or(0);
        if w + cw > width {
            break;
        }
        out.push(ch);
        w += cw;
    }
    out
}

fn write_summary(out: &mut String, summary: &ReportSummary) {
    let mut parts = vec![
        format!(
            "{} {}",
            summary.critical.to_string().red().bold(),
            crate::plural(summary.critical, "critical", "critical")
        ),
        format!(
            "{} {}",
            summary.warnings.to_string().yellow().bold(),
            crate::plural(summary.warnings, "warning", "warnings")
        ),
        format!(
            "{} {}",
            summary.notices.to_string().cyan(),
            crate::plural(summary.notices, "notice", "notices")
        ),
    ];
    if summary.unknown > 0 {
        parts.push(format!("{} unknown", summary.unknown.to_string().dimmed()));
    }
    if summary.not_applicable > 0 {
        parts.push(format!(
            "{} not applicable",
            summary.not_applicable.to_string().dimmed()
        ));
    }
    if summary.ignored > 0 {
        parts.push(format!("{} ignored", summary.ignored.to_string().dimmed()));
    }
    parts.push(format!("{} healthy", summary.healthy.to_string().green()));
    if summary.degraded {
        parts.push("INCOMPLETE".yellow().bold().to_string());
    }
    writeln!(out, "  {}", parts.join("  ·  ")).unwrap();
}

fn json_finding(
    finding: &Finding,
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
) -> JsonFinding {
    JsonFinding {
        name: finding.node.name.clone(),
        version: finding.node.version.to_string(),
        score: score::rounded(finding.risk.total),
        level: finding.risk.level.as_str(),
        is_direct: finding.node.is_direct,
        kind: finding.node.kind.as_str(),
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
        baseline: finding.baseline_state.as_str(),
    }
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

pub(crate) fn advisory_label(advisory: &Advisory) -> String {
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
    let (header, visible_width) = build_header(finding, level, inner_width);
    writeln!(out, "{}", boxed_line(&header, visible_width, inner_width)).unwrap();

    // Only new findings are annotated. Tagging the known ones too would put a
    // line on every row of an inherited backlog — the exact wall of text a
    // baseline exists to quiet down.
    let baseline_line = match finding.baseline_state {
        BaselineState::New(reason) => Some(format!("new: {}", reason.describe())),
        BaselineState::Known | BaselineState::NotCompared => None,
    };

    for line in baseline_line.into_iter().chain(reason_lines(
        &finding.node,
        &finding.risk,
        &finding.advisories,
        meta_map,
        now,
    )) {
        for piece in wrap_to_width(&line, inner_width.saturating_sub(3)) {
            let detail = format!("   {piece}");
            writeln!(out, "{}", boxed_line(&detail, detail.width(), inner_width)).unwrap();
        }
    }
}

/// Builds a finding's header row: the styled content, plus its true visible
/// width measured from the *unstyled* text. Split out from `render_finding`
/// so the same construction is exercised directly in tests — this is the
/// exact code path where colored/bold rows previously misaligned the box.
fn build_header(finding: &Finding, level: RiskLevel, inner_width: usize) -> (String, usize) {
    // Everything to the right of the name is fixed-width, so the name field
    // is what has to give on a narrow terminal. Holding it at a constant 41
    // overflowed the box by 2 columns at `MIN_INNER_WIDTH` — the header was
    // the one row `wrap_to_width` doesn't cover, since it is a laid-out
    // row rather than flowing text.
    let name_width = NAME_FIELD_WIDTH.min(inner_width.saturating_sub(HEADER_FIXED_WIDTH));

    let name_ver = format!("{} {}", finding.node.name, finding.node.version);
    let name_field = ellipsize(&name_ver, name_width);
    let padded_name = format!(" {}", pad_to_width(&name_field, name_width));

    // One decimal keeps display and classification honest around boundaries:
    // a raw 39.6 must not render as "40 [N]".
    let score_text = format!("{:>5.1}", finding.risk.total);
    let bar = score_bar(finding.risk.total, 12);
    // Plain-text severity tag, always present alongside the section box's
    // own CRITICAL/WARN/NOTICE header (never a substitute for it — a row
    // copy-pasted or grepped out of its box loses that context) and never
    // color alone: color plus a bare number was exactly the case a
    // red/green-colorblind reader, a grayscale render, or a piped
    // color-stripped terminal couldn't disambiguate.
    let marker = severity_marker(level);

    let visible_width = format!("{padded_name}{score_text} {marker} {bar}").width();

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
    (
        format!("{styled_name}{score_display} {marker} {bar}"),
        visible_width,
    )
}

fn severity_marker(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "[C]",
        RiskLevel::Warn => "[W]",
        RiskLevel::Low => "[N]",
    }
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

    match node.kind {
        crate::graph::NodeKind::Build => {
            lines.push(
                "build-only: runs at build time (build.rs), never shipped in your binary"
                    .to_string(),
            );
        }
        crate::graph::NodeKind::Dev => {
            lines.push(
                "dev-only: used for tests/examples/benchmarks, never shipped in your binary"
                    .to_string(),
            );
        }
        crate::graph::NodeKind::Normal => {}
    }

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
    } else if node.is_registry {
        lines.push("registry metadata unavailable; version and publish health unchecked".into());
    } else if advisories.is_empty() {
        lines.push("non-registry source; version and publish health not applicable".into());
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
        let years = days / 365;
        format!(
            "latest crate release published {years} {} ago",
            crate::plural(years as usize, "year", "years")
        )
    } else {
        format!(
            "latest crate release published {days} {} ago",
            crate::plural(days.max(0) as usize, "day", "days")
        )
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
    fn summarize_uses_exclusive_schema_v3_buckets() {
        let mut notice = test_finding("notice", false, RiskLevel::Low, 12.0);
        let mut healthy = test_finding("healthy", false, RiskLevel::Low, 0.0);
        let unknown = test_finding("unknown", false, RiskLevel::Low, 0.0);
        let mut not_applicable = test_finding("path-dep", false, RiskLevel::Low, 0.0);
        not_applicable.node.is_registry = false;

        // Keep these mutable assignments explicit: registry metadata is what
        // distinguishes checked low-risk crates from `unknown`.
        notice.node.is_registry = true;
        healthy.node.is_registry = true;

        let findings = vec![
            test_finding("critical", false, RiskLevel::Critical, 80.0),
            test_finding("warning", false, RiskLevel::Warn, 40.0),
            notice,
            healthy,
            unknown,
            not_applicable,
        ];
        let now = Utc::now();
        let mut meta_map = HashMap::new();
        for name in ["notice", "healthy"] {
            meta_map.insert(
                name.to_string(),
                Metadata {
                    newest_version: Version::new(1, 0, 0),
                    max_stable_version: Some(Version::new(1, 0, 0)),
                    stable_versions: vec![Version::new(1, 0, 0)],
                    updated_at: now,
                    yanked_versions: Vec::new(),
                },
            );
        }

        let summary = summarize(&findings, &meta_map, 2, true);
        assert_eq!(summary.total, 8);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.notices, 1);
        assert_eq!(summary.healthy, 1);
        assert_eq!(summary.unknown, 1);
        assert_eq!(summary.not_applicable, 1);
        assert_eq!(summary.ignored, 2);
        assert!(summary.degraded);
        assert_eq!(
            summary.critical
                + summary.warnings
                + summary.notices
                + summary.healthy
                + summary.unknown
                + summary.not_applicable
                + summary.ignored,
            summary.total
        );
    }

    #[test]
    fn a_score_that_rounds_to_zero_is_healthy_not_a_notice() {
        // The CHANGELOG's own definition: "`healthy` now means a checked
        // dependency whose score is exactly zero." Every other consumer of a
        // risk score rounds first — RiskLevel::from_score, the displayed
        // score text, the --threshold filter, and the JSON `score` field all
        // go through `score::rounded`. This bucketing compared the raw value
        // instead, so a crate published one day ago
        // (maintenance_points(1) = 15/730 ≈ 0.0205, raw > 0.0 but rounds to
        // 0.0) landed in `notices` while displaying the identical "0.0" a
        // genuinely healthy crate shows — two rows reading the same score,
        // filed under different, mutually-exclusive buckets.
        let raw_total = 15.0 / 730.0;
        assert_eq!(
            score::rounded(raw_total),
            0.0,
            "test is only meaningful if this rounds to zero"
        );

        let mut almost_zero = test_finding("almost-zero", false, RiskLevel::Low, raw_total);
        almost_zero.node.is_registry = true;

        let now = Utc::now();
        let mut meta_map = HashMap::new();
        meta_map.insert(
            "almost-zero".to_string(),
            Metadata {
                newest_version: Version::new(1, 0, 0),
                max_stable_version: Some(Version::new(1, 0, 0)),
                stable_versions: vec![Version::new(1, 0, 0)],
                updated_at: now,
                yanked_versions: Vec::new(),
            },
        );

        let summary = summarize(&[almost_zero], &meta_map, 0, false);
        assert_eq!(
            summary.healthy, 1,
            "a score that displays as 0.0 must count as healthy"
        );
        assert_eq!(summary.notices, 0);
    }

    #[test]
    fn duplicate_groups_require_distinct_versions() {
        let same_version = vec![
            test_finding("same-name", false, RiskLevel::Low, 0.0),
            test_finding("same-name", false, RiskLevel::Low, 0.0),
        ];
        assert!(duplicate_groups(&same_version).is_empty());

        let mut other = test_finding("same-name", false, RiskLevel::Low, 0.0);
        other.node.version = Version::new(2, 0, 0);
        let distinct_versions = vec![test_finding("same-name", false, RiskLevel::Low, 0.0), other];
        assert_eq!(duplicate_groups(&distinct_versions).len(), 1);
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

    #[test]
    fn maintenance_line_pluralizes_days_and_years() {
        assert_eq!(
            maintenance_line(1),
            "latest crate release published 1 day ago"
        );
        assert_eq!(
            maintenance_line(365),
            "latest crate release published 1 year ago"
        );
        assert_eq!(
            maintenance_line(730),
            "latest crate release published 2 years ago"
        );
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
            let (header, visible_width) = build_header(finding, finding.risk.level, INNER);
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

    #[test]
    fn wrap_leaves_a_fitting_line_as_one_piece() {
        let line = "last published 342 days ago";
        assert_eq!(wrap_to_width(line, 74), vec![line.to_string()]);
    }

    #[test]
    fn wrap_breaks_the_real_wasi_line_that_used_to_break_the_box() {
        // The exact reason line that overflowed a default-width box before
        // wrapping existed: ~87 columns against a 74-column budget.
        let line = "3 breaking version(s) behind latest \
                    (0.11.1+wasi-snapshot-preview1 → 0.14.7+wasi-0.2.4)";
        let pieces = wrap_to_width(line, 74);
        assert!(pieces.len() > 1, "expected a wrap, got {pieces:?}");
        for piece in &pieces {
            assert!(
                piece.width() <= 74,
                "piece exceeds the budget: {piece:?} ({} cols)",
                piece.width()
            );
        }
        // Wrapping, not truncating: the upgrade target must survive.
        assert!(pieces.join("").contains("0.14.7+wasi-0.2.4"));
    }

    #[test]
    fn wrap_hard_splits_a_single_overlong_word() {
        // No space to break at — the frame's correctness still wins.
        let line = "a".repeat(200);
        let pieces = wrap_to_width(&line, 40);
        assert!(pieces.len() > 1);
        for piece in &pieces {
            assert!(piece.width() <= 40, "{} cols", piece.width());
        }
        assert_eq!(
            pieces.iter().map(|p| p.trim_start()).collect::<String>(),
            line
        );
    }

    #[test]
    fn no_rendered_row_ever_exceeds_the_box_width() {
        // Every emitted row must measure exactly `inner_width + 2` once ANSI
        // is stripped, including reason lines long enough to have overflowed
        // before wrapping existed.
        let _guard = ColorOverrideGuard::new(false);

        const INNER: usize = 77;
        let (findings, meta_map, now, summary) = sample_report();
        let output = render_to_string(&findings, &meta_map, now, &summary, false, 5.0, &[]);

        for row in output.lines() {
            if !row.starts_with('│') {
                continue;
            }
            assert_eq!(
                strip_ansi(row).chars().count(),
                INNER + 2,
                "row is not exactly the box width: {row:?}"
            );
        }
    }

    #[test]
    fn rows_stay_inside_the_box_at_every_supported_width() {
        // The test above pins only the default 77. That is exactly how the
        // header overflow at `MIN_INNER_WIDTH` survived: the header is a
        // laid-out row, not flowing text, so `wrap_to_width` never touched
        // it, and its name field was a fixed 41 columns no matter how narrow
        // the terminal got. Sweep the whole supported range instead, with
        // content long enough to stress both the header and the reasons.
        let _guard = ColorOverrideGuard::new(false);

        let (findings, meta_map, now, _) = sample_report();
        let long = Finding {
            node: DependencyNode {
                name: "a-crate-with-a-deliberately-very-long-name-for-this-test".to_string(),
                version: Version::parse("0.11.1+wasi-snapshot-preview1").unwrap(),
                is_direct: true,
                depth: 1,
                dependent_count: 3,
                transitive_dependent_count: 26,
                is_registry: true,
                kind: crate::graph::NodeKind::Normal,
            },
            risk: RiskScore {
                security: 0.0,
                version_lag: 25.0,
                maintenance: 15.0,
                graph_multiplier: 1.4,
                total: 56.0,
                level: RiskLevel::Warn,
            },
            advisories: Vec::new(),
            baseline_state: crate::baseline::BaselineState::NotCompared,
        };

        for inner in MIN_INNER_WIDTH..=MAX_INNER_WIDTH {
            let mut out = String::new();
            write_finding(&mut out, &long, RiskLevel::Warn, &meta_map, now, inner);
            for f in &findings {
                write_finding(&mut out, f, f.risk.level, &meta_map, now, inner);
            }

            for row in out.lines() {
                assert_eq!(
                    strip_ansi(row).width(),
                    inner + 2,
                    "row is {} cols in a {inner}-col box: {row:?}",
                    strip_ansi(row).width()
                );
            }
        }
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
                stable_versions: vec![Version::new(3, 0, 0)],
                updated_at: now - chrono::Duration::days(730),
                yanked_versions: Vec::new(),
            },
        );
        meta_map.insert(
            "tokio".to_string(),
            Metadata {
                newest_version: Version::new(1, 40, 0),
                max_stable_version: Some(Version::new(1, 40, 0)),
                stable_versions: vec![Version::new(1, 40, 0)],
                updated_at: now - chrono::Duration::days(10),
                yanked_versions: Vec::new(),
            },
        );
        meta_map.insert(
            "libc".to_string(),
            Metadata {
                newest_version: Version::new(0, 2, 189),
                max_stable_version: Some(Version::new(0, 2, 189)),
                stable_versions: vec![Version::new(0, 2, 189)],
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
                    kind: crate::graph::NodeKind::Normal,
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
                baseline_state: crate::baseline::BaselineState::NotCompared,
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
                    kind: crate::graph::NodeKind::Normal,
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
                baseline_state: crate::baseline::BaselineState::NotCompared,
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
                    kind: crate::graph::NodeKind::Normal,
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
                baseline_state: crate::baseline::BaselineState::NotCompared,
            },
        ];

        // The snapshot models a 346-dependency project while rendering only
        // three threshold-passing examples.
        let summary = ReportSummary {
            total: 346,
            critical: 1,
            warnings: 1,
            notices: 1,
            unknown: 0,
            not_applicable: 0,
            ignored: 0,
            healthy: 343,
            degraded: false,
        };
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

    #[test]
    fn severity_marker_is_distinct_and_plain_text_per_level() {
        // The section box header (CRITICAL/WARN/NOTICE) already names the
        // level, but a single row copy-pasted or grepped out of that
        // context must still be classifiable — in grayscale, through a
        // color-stripping pipe, or with `--color never`. Each level's
        // marker must therefore be distinct plain ASCII, not merely a
        // different color on the same text.
        let markers = [
            severity_marker(RiskLevel::Critical),
            severity_marker(RiskLevel::Warn),
            severity_marker(RiskLevel::Low),
        ];
        for marker in markers {
            assert!(
                marker.is_ascii(),
                "{marker:?} must be identifiable without relying on a specific font/locale"
            );
        }
        assert_eq!(
            markers
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            markers.len(),
            "every level must have a visually distinct marker: {markers:?}"
        );
    }

    #[test]
    fn uncolored_row_still_carries_its_severity_marker() {
        let _guard = ColorOverrideGuard::new(false);

        for (level, marker) in [
            (RiskLevel::Critical, "[C]"),
            (RiskLevel::Warn, "[W]"),
            (RiskLevel::Low, "[N]"),
        ] {
            let finding = test_finding("some-crate", false, level, 50.0);
            let (header, _) = build_header(&finding, level, 77);
            assert!(
                header.contains(marker),
                "{level:?} row must carry {marker:?} even with color off: {header:?}"
            );
        }
    }

    #[test]
    fn json_report_snapshot_covers_provenance_shape() {
        let (findings, meta_map, now, summary) = sample_report();
        let mut json_report = to_json(
            &findings,
            &meta_map,
            now,
            &summary,
            5.0,
            JsonExtras {
                unchecked: &[],
                duplicates: Vec::new(),
                ignored: Vec::new(),
                project: JsonProject {
                    name: Some("sample-project".to_string()),
                    manifest_path: "/workspace/sample-project/Cargo.toml".to_string(),
                },
                advisory_db_commit: Some("abc123def456".to_string()),
            },
        );
        // `generated_at` is real wall-clock time in production (`Utc::now()`
        // in main.rs); sample_report()'s fixed `now` only happens to make
        // this particular assertion stable too. Normalize explicitly so the
        // snapshot can't silently start depending on that coincidence.
        json_report.generated_at = "REDACTED".to_string();

        let output = render_json(&json_report).unwrap();
        insta::assert_snapshot!(output);
    }
}
