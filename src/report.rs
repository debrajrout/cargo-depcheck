use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use rustsec::advisory::Advisory;
use semver::Version;
use serde::Serialize;

use crate::cratesio::Metadata;
use crate::graph::DependencyNode;
use crate::score::{RiskLevel, RiskScore, DEFAULT_THRESHOLD};

const INNER_WIDTH: usize = 77;
pub const JSON_SCHEMA_VERSION: u32 = 1;

pub struct Finding {
    pub node: DependencyNode,
    pub risk: RiskScore,
    pub advisories: Vec<Advisory>,
}

pub struct ReportSummary {
    pub critical: usize,
    pub warnings: usize,
    pub healthy: usize,
}

#[derive(Serialize)]
pub struct JsonReport {
    pub schema_version: u32,
    pub summary: JsonSummary,
    pub findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
pub struct JsonSummary {
    pub critical: usize,
    pub warnings: usize,
    pub healthy: usize,
    pub threshold: f64,
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
    pub components: JsonComponents,
    pub reasons: Vec<String>,
    pub advisories: Vec<String>,
}

pub fn summarize(total: usize, critical: usize, warnings: usize) -> ReportSummary {
    ReportSummary {
        critical,
        warnings,
        healthy: total.saturating_sub(critical + warnings),
    }
}

pub fn to_json(
    findings: &[Finding],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
    summary: &ReportSummary,
    threshold: f64,
) -> JsonReport {
    JsonReport {
        schema_version: JSON_SCHEMA_VERSION,
        summary: JsonSummary {
            critical: summary.critical,
            warnings: summary.warnings,
            healthy: summary.healthy,
            threshold,
        },
        findings: findings
            .iter()
            .map(|finding| json_finding(finding, meta_map, now))
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
) {
    print_summary(summary);

    if quiet {
        println!();
        return;
    }

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
        render_section("CRITICAL", RiskLevel::Critical, &critical, meta_map, now);
        println!();
    }

    if !warnings.is_empty() {
        render_section("WARN", RiskLevel::Warn, &warnings, meta_map, now);
        println!();
    }

    if threshold < DEFAULT_THRESHOLD && !notice.is_empty() {
        render_section("NOTICE", RiskLevel::Low, &notice, meta_map, now);
        println!();
    }

    if critical.is_empty() && warnings.is_empty() && notice.is_empty() {
        println!(
            "  {} No dependencies scored at or above the threshold.\n",
            "✓".green()
        );
    }
}

fn print_summary(summary: &ReportSummary) {
    println!(
        "  {} critical  ·  {} warnings  ·  {} healthy\n",
        summary.critical.to_string().red().bold(),
        summary.warnings.to_string().yellow().bold(),
        summary.healthy.to_string().green(),
    );
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
        advisories: finding
            .advisories
            .iter()
            .map(advisory_label)
            .collect(),
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

fn render_section(
    title: &str,
    level: RiskLevel,
    items: &[&Finding],
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
) {
    println!("┌{}┐", "─".repeat(INNER_WIDTH));

    let title_label = format!("  {title} ");
    println!("│{title_label:<INNER_WIDTH$}│");
    println!("├{}┤", "─".repeat(INNER_WIDTH));

    for (index, finding) in items.iter().enumerate() {
        if index > 0 {
            println!("├{}┤", "─".repeat(INNER_WIDTH));
        }
        render_finding(finding, level, meta_map, now);
    }

    println!("└{}┘", "─".repeat(INNER_WIDTH));
}

fn render_finding(
    finding: &Finding,
    level: RiskLevel,
    meta_map: &HashMap<String, Metadata>,
    now: DateTime<Utc>,
) {
    let name_ver = format!("{} {}", finding.node.name, finding.node.version);
    let padded_name = format!(" {name_ver:<41}");
    let score_raw = format!("{:>3.0}", finding.risk.total);
    let score_display = match level {
        RiskLevel::Critical => score_raw.red().bold().to_string(),
        RiskLevel::Warn => score_raw.yellow().to_string(),
        RiskLevel::Low => score_raw,
    };

    let bar = score_bar(finding.risk.total, 12);
    let header = if finding.node.is_direct {
        format!("{}{score_display} {bar}", padded_name.bold())
    } else {
        format!("{padded_name}{score_display} {bar}")
    };
    println!("│{header:<INNER_WIDTH$}│");

    for line in reason_lines(&finding.node, &finding.risk, &finding.advisories, meta_map, now) {
        let detail = format!("   {line}");
        println!("│{detail:<INNER_WIDTH$}│");
    }
}

fn score_bar(score: f64, width: usize) -> String {
    let filled = ((score / 100.0) * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn reason_lines(
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
        if let Some(line) = version_lag_line(&node.version, meta.latest_stable()) {
            lines.push(line);
        }

        let days = (now - meta.updated_at).num_days();
        if risk.maintenance > 0.0 {
            lines.push(maintenance_line(days));
        }
    }

    if node.dependent_count > 0 {
        let noun = if node.dependent_count == 1 {
            "crate"
        } else {
            "crates"
        };
        lines.push(format!(
            "relied on by {} {} in your graph",
            node.dependent_count, noun
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

fn version_lag_line(have: &Version, latest: &Version) -> Option<String> {
    if have >= latest {
        return None;
    }

    let major_behind = latest.major.saturating_sub(have.major);
    if major_behind > 0 {
        return Some(format!(
            "{major_behind} major version(s) behind latest ({have} → {latest})"
        ));
    }

    let minor_behind = latest.minor.saturating_sub(have.minor);
    Some(format!(
        "{minor_behind} minor version(s) behind latest ({have} → {latest})"
    ))
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
        let summary = summarize(100, 2, 6);
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.warnings, 6);
        assert_eq!(summary.healthy, 92);
    }

    #[test]
    fn version_lag_line_major() {
        let have = Version::new(0, 10, 45);
        let latest = Version::new(3, 0, 0);
        let line = version_lag_line(&have, &latest).unwrap();
        assert!(line.contains("3 major"));
    }
}
