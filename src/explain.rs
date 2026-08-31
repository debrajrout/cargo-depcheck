//! `cargo depcheck explain <crate>` — the full derivation of one crate's
//! score, plus what pulls it in and what would lower it.
//!
//! The ranked report answers "what first?"; it deliberately shows one line
//! per signal to stay short. That leaves two questions it cannot answer, both
//! of which block acting on a finding: *why* is this number what it is, and
//! *which of my own dependencies* dragged this crate in. A score you can't
//! interrogate is a score you're asked to trust, so this command exists to
//! make the whole calculation, and the graph behind it, inspectable.

use std::fmt::Write as _;

use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use rustsec::Database;
use semver::Version;
use serde::Serialize;

use crate::cli::{Args, OutputFormat};
use crate::graph::{self, KindOptions, NodeKind, PathStep};
use crate::registry::Metadata;
use crate::report::Finding;
use crate::score::{self, RiskLevel};
use crate::{advisories, analyze};

/// Version of the `explain --format json` payload. Independent of the report
/// schema: this is a different document with a different shape, and tying it
/// to the report's version would imply changes to one affect the other.
const EXPLAIN_SCHEMA_VERSION: u32 = 1;

pub async fn run(args: &Args, crate_name: &str, max_paths: usize) -> Result<()> {
    let format = args.format.unwrap_or(if args.json {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    });
    if matches!(format, OutputFormat::Sarif) {
        eprintln!(
            "error: --format sarif describes findings across a project, not one crate's score; \
             use --format json or the default human output with `explain`"
        );
        std::process::exit(2);
    }
    let machine_readable = format.is_machine_readable();
    let now = Utc::now();
    let analysis = analyze::run(args, machine_readable, now).await?;

    // Every resolved version of the crate, worst first. A graph that holds
    // two copies of the same crate is exactly when this command is most
    // useful, so explaining only one of them would hide the interesting half.
    let matches: Vec<&Finding> = analysis
        .all_findings
        .iter()
        .filter(|finding| finding.node.name == crate_name)
        .collect();

    if matches.is_empty() {
        report_not_found(crate_name, &analysis.all_findings);
        std::process::exit(2);
    }

    let kinds = KindOptions {
        include_build: args.include_build,
        include_dev: args.include_dev,
    };
    let paths = graph::dependency_paths(&analysis.metadata, kinds, crate_name, max_paths)?;

    let explanations: Vec<Explanation> = matches
        .iter()
        .map(|finding| {
            Explanation::build(
                finding,
                analysis.meta_map.get(crate_name),
                analysis.db.as_ref(),
                now,
                analysis.threshold,
                analysis.ignored_names.contains(crate_name),
            )
        })
        .collect();

    match format {
        OutputFormat::Json => {
            let payload = JsonExplain {
                schema_version: EXPLAIN_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION"),
                generated_at: now.to_rfc3339(),
                crate_name: crate_name.to_string(),
                threshold: analysis.threshold,
                resolved: explanations.iter().map(Explanation::to_json).collect(),
                paths: paths
                    .iter()
                    .map(|path| json_path(path.as_slice()))
                    .collect(),
            };
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        // Markdown shares the human layout: the derivation is a short list of
        // labelled numbers, which reads correctly as an indented code block
        // in a comment and needs no table.
        OutputFormat::Human | OutputFormat::Markdown => {
            let mut out = String::new();
            for (index, explanation) in explanations.iter().enumerate() {
                if index > 0 {
                    writeln!(out).unwrap();
                }
                explanation.write_human(&mut out);
            }
            write_paths(&mut out, crate_name, &paths, max_paths);
            print!("{out}");
        }
        OutputFormat::Sarif => unreachable!("rejected above"),
    }

    Ok(())
}

/// A crate name that isn't in the graph is almost always a typo or a crate
/// that only appears as a dev/build dependency — both worth saying out loud,
/// since "not found" alone leaves the user guessing which it was.
fn report_not_found(crate_name: &str, all: &[Finding]) {
    eprintln!("error: {crate_name} is not in this project's analyzed dependency graph");

    let mut near: Vec<&str> = all
        .iter()
        .map(|f| f.node.name.as_str())
        .filter(|name| {
            name.contains(crate_name)
                || crate_name.contains(*name)
                || name.replace('-', "_") == crate_name.replace('-', "_")
        })
        .collect();
    near.sort_unstable();
    near.dedup();
    if !near.is_empty() {
        eprintln!("  did you mean: {}", near.join(", "));
    }
    eprintln!(
        "  build-script and dev-only dependencies are excluded unless you pass \
         --include-build / --include-dev"
    );
    std::process::exit(2);
}

struct Explanation {
    name: String,
    version: Version,
    is_direct: bool,
    kind: NodeKind,
    level: RiskLevel,
    total: f64,
    security: f64,
    version_lag: f64,
    maintenance: f64,
    graph_multiplier: f64,
    transitive_dependent_count: usize,
    dependent_count: usize,
    security_detail: String,
    version_lag_detail: String,
    maintenance_detail: String,
    threshold: f64,
    ignored: bool,
    /// What the score would become at a newer version — a real re-scoring at
    /// that version, not an estimate.
    projections: Vec<Projection>,
}

struct Projection {
    label: &'static str,
    version: Version,
    total: f64,
    level: RiskLevel,
}

impl Explanation {
    fn build(
        finding: &Finding,
        meta: Option<&Metadata>,
        db: Option<&Database>,
        now: DateTime<Utc>,
        threshold: f64,
        ignored: bool,
    ) -> Self {
        let risk = &finding.risk;
        let node = &finding.node;

        let security_detail = if !finding.advisories.is_empty() {
            let ids: Vec<String> = finding
                .advisories
                .iter()
                .map(crate::report::advisory_label)
                .collect();
            format!(
                "{} ({})",
                crate::plural(ids.len(), "advisory", "advisories"),
                ids.join(", ")
            )
        } else if meta.is_some_and(|m| m.is_yanked(&node.version)) {
            format!("{} {} is yanked on crates.io", node.name, node.version)
        } else if db.is_none() {
            "advisories not checked this run".to_string()
        } else {
            "no advisories, not yanked".to_string()
        };

        let version_lag_detail = match meta {
            Some(meta) => {
                let latest = meta.latest_stable();
                if &node.version >= latest {
                    format!("up to date ({latest} is the latest stable)")
                } else {
                    let (breaking, compatible, patch) =
                        score::lag_components(&node.version, latest);
                    let (count, adjective) = if breaking > 0 {
                        (breaking, "breaking")
                    } else if compatible > 0 {
                        (compatible, "compatible")
                    } else {
                        (patch, "patch")
                    };
                    format!(
                        "{count} {adjective} {} behind ({} → {latest})",
                        crate::plural(count as usize, "release", "releases"),
                        node.version
                    )
                }
            }
            None if node.is_registry => "registry metadata unavailable".to_string(),
            None => "not a registry crate; no published versions to compare".to_string(),
        };

        let maintenance_detail = match meta {
            Some(meta) => {
                let days = (now - meta.updated_at).num_days();
                format!("latest release across all versions published {days} days ago")
            }
            None => "no publish history available".to_string(),
        };

        // Re-score at each candidate upgrade target with the same advisory
        // database and registry metadata the real run used, so a projection
        // reflects advisories that do (or don't) apply to that version rather
        // than assuming an upgrade only cancels version lag.
        let mut projections = Vec::new();
        if let Some(meta) = meta {
            let mut targets: Vec<(&'static str, Version)> = Vec::new();
            if let Some(compatible) = meta.latest_compatible(&node.version) {
                targets.push(("within its compatibility line", compatible.clone()));
            }
            let latest = meta.latest_stable();
            if latest > &node.version && !targets.iter().any(|(_, version)| version == latest) {
                targets.push(("at the latest stable", latest.clone()));
            }

            for (label, version) in targets {
                let mut projected_node = node.clone();
                projected_node.version = version.clone();
                let projected_advisories = db
                    .map(|database| advisories::lookup(database, &node.name, &version))
                    .unwrap_or_default();
                let projected =
                    score::compute(&projected_node, Some(meta), &projected_advisories, now);
                projections.push(Projection {
                    label,
                    version,
                    total: projected.total,
                    level: projected.level,
                });
            }
        }

        Self {
            name: node.name.clone(),
            version: node.version.clone(),
            is_direct: node.is_direct,
            kind: node.kind,
            level: risk.level,
            total: risk.total,
            security: risk.security,
            version_lag: risk.version_lag,
            maintenance: risk.maintenance,
            graph_multiplier: risk.graph_multiplier,
            transitive_dependent_count: node.transitive_dependent_count,
            dependent_count: node.dependent_count,
            security_detail,
            version_lag_detail,
            maintenance_detail,
            threshold,
            ignored,
            projections,
        }
    }

    fn write_human(&self, out: &mut String) {
        let rounded = score::rounded(self.total);
        let heading = format!("{} {}", self.name, self.version);
        writeln!(
            out,
            "{}  score {} {}",
            heading.bold(),
            format!("{rounded:.1}").bold(),
            level_tag(self.level),
        )
        .unwrap();

        let mut facts = vec![if self.is_direct {
            "direct dependency".to_string()
        } else {
            format!(
                "transitive dependency ({} direct {} in your graph)",
                self.dependent_count,
                crate::plural(self.dependent_count, "dependent", "dependents")
            )
        }];
        match self.kind {
            NodeKind::Build => facts.push("build-time only (never shipped)".into()),
            NodeKind::Dev => facts.push("dev-only (never shipped)".into()),
            NodeKind::Normal => {}
        }
        if self.ignored {
            facts.push("suppressed by an ignore rule — shown here anyway".into());
        }
        if rounded < self.threshold {
            facts.push(format!(
                "below your display threshold of {}",
                trim_float(self.threshold)
            ));
        }
        writeln!(out, "  {}", facts.join(" · ").dimmed()).unwrap();
        writeln!(out).unwrap();

        // The formula first, then each term: the point of this command is
        // that the total is arithmetic on four visible numbers, not a verdict.
        writeln!(
            out,
            "  score = (security {} + version lag {} + maintenance {}) × {} graph weight",
            format!("{:.1}", self.security).cyan(),
            format!("{:.1}", self.version_lag).cyan(),
            format!("{:.1}", self.maintenance).cyan(),
            format!("{:.2}", self.graph_multiplier).cyan(),
        )
        .unwrap();
        writeln!(out).unwrap();

        write_row(out, "security", self.security, 50.0, &self.security_detail);
        write_row(
            out,
            "version lag",
            self.version_lag,
            25.0,
            &self.version_lag_detail,
        );
        write_row(
            out,
            "maintenance",
            self.maintenance,
            15.0,
            &self.maintenance_detail,
        );
        writeln!(
            out,
            "    {:<13} {:>10}   relied on by {} {} in your graph, directly or transitively",
            "graph weight",
            format!("×{:.2}", self.graph_multiplier),
            self.transitive_dependent_count,
            crate::plural(self.transitive_dependent_count, "crate", "crates"),
        )
        .unwrap();
        writeln!(out).unwrap();

        let base = self.security + self.version_lag + self.maintenance;
        writeln!(
            out,
            "    {:<13} {:>10}   ({:.1} × {:.2}, capped at 100)",
            "total",
            format!("{rounded:.1}"),
            base,
            self.graph_multiplier,
        )
        .unwrap();

        if !self.projections.is_empty() {
            writeln!(out).unwrap();
            writeln!(out, "  {}", "If you upgrade:".bold()).unwrap();
            for projection in &self.projections {
                let projected = score::rounded(projection.total);
                let direction = if projected < rounded {
                    format!("{rounded:.1} → {projected:.1}").green().to_string()
                } else {
                    format!("{rounded:.1} → {projected:.1}")
                };
                writeln!(
                    out,
                    "    {} {}  score {} {}",
                    projection.label,
                    projection.version,
                    direction,
                    level_tag(projection.level),
                )
                .unwrap();
            }
            writeln!(
                out,
                "    {}",
                "re-scored at that version against the same advisory database".dimmed()
            )
            .unwrap();
        }
    }

    fn to_json(&self) -> JsonResolved {
        JsonResolved {
            version: self.version.to_string(),
            score: score::rounded(self.total),
            level: self.level.as_str(),
            is_direct: self.is_direct,
            kind: self.kind.as_str(),
            ignored: self.ignored,
            components: JsonComponent {
                security: JsonSignal {
                    points: round1(self.security),
                    max: 50.0,
                    detail: self.security_detail.clone(),
                },
                version_lag: JsonSignal {
                    points: round1(self.version_lag),
                    max: 25.0,
                    detail: self.version_lag_detail.clone(),
                },
                maintenance: JsonSignal {
                    points: round1(self.maintenance),
                    max: 15.0,
                    detail: self.maintenance_detail.clone(),
                },
                // Two decimals, matching the human breakdown: this command
                // exists so the arithmetic can be checked by hand, and a
                // multiplier shown as 1.4 doesn't reproduce the total.
                graph_multiplier: round2(self.graph_multiplier),
                transitive_dependent_count: self.transitive_dependent_count,
                dependent_count: self.dependent_count,
            },
            projections: self
                .projections
                .iter()
                .map(|p| JsonProjection {
                    label: p.label,
                    version: p.version.to_string(),
                    score: score::rounded(p.total),
                    level: p.level.as_str(),
                })
                .collect(),
        }
    }
}

fn write_row(out: &mut String, label: &str, points: f64, max: f64, detail: &str) {
    writeln!(
        out,
        "    {label:<13} {:>10}   {detail}",
        format!("{points:.1} / {max:.0}"),
    )
    .unwrap();
}

fn write_paths(out: &mut String, crate_name: &str, paths: &[Vec<PathStep>], max_paths: usize) {
    writeln!(out).unwrap();
    if paths.is_empty() {
        writeln!(
            out,
            "  {}",
            "No dependency path found — this crate is not reachable from a workspace member \
             under the current --include-build / --include-dev settings."
                .dimmed()
        )
        .unwrap();
        return;
    }

    writeln!(
        out,
        "  {} ({} shown, shortest first):",
        "Pulled in by".bold(),
        paths.len()
    )
    .unwrap();
    for path in paths {
        let rendered: Vec<String> = path
            .iter()
            .enumerate()
            .map(|(index, step)| {
                let mut text = if index == 0 {
                    // The workspace member itself — the thing you own, and
                    // therefore the only hop you can act on directly.
                    step.name.clone().bold().to_string()
                } else {
                    format!("{} {}", step.name, step.version)
                };
                match step.kind {
                    NodeKind::Build => text.push_str(" [build]"),
                    NodeKind::Dev => text.push_str(" [dev]"),
                    NodeKind::Normal => {}
                }
                text
            })
            .collect();
        writeln!(out, "    {}", rendered.join(" → ")).unwrap();
    }
    if paths.len() == max_paths {
        writeln!(
            out,
            "    {}",
            "(more paths may exist; raise --max-paths to see them)".dimmed()
        )
        .unwrap();
    }
    writeln!(
        out,
        "    {}",
        format!("cargo tree -i {crate_name} shows the same relationships from Cargo's own view")
            .dimmed()
    )
    .unwrap();
}

fn level_tag(level: RiskLevel) -> String {
    match level {
        RiskLevel::Critical => "[CRITICAL]".red().bold().to_string(),
        RiskLevel::Warn => "[WARN]".yellow().to_string(),
        RiskLevel::Low => "[NOTICE]".to_string(),
    }
}

fn trim_float(value: f64) -> String {
    if value.fract().abs() < f64::EPSILON {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[derive(Serialize)]
struct JsonExplain {
    schema_version: u32,
    tool_version: &'static str,
    generated_at: String,
    #[serde(rename = "crate")]
    crate_name: String,
    threshold: f64,
    /// One entry per resolved version of the crate in this graph.
    resolved: Vec<JsonResolved>,
    paths: Vec<Vec<JsonPathStep>>,
}

#[derive(Serialize)]
struct JsonResolved {
    version: String,
    score: f64,
    level: &'static str,
    is_direct: bool,
    kind: &'static str,
    ignored: bool,
    components: JsonComponent,
    projections: Vec<JsonProjection>,
}

#[derive(Serialize)]
struct JsonComponent {
    security: JsonSignal,
    version_lag: JsonSignal,
    maintenance: JsonSignal,
    graph_multiplier: f64,
    transitive_dependent_count: usize,
    dependent_count: usize,
}

#[derive(Serialize)]
struct JsonSignal {
    points: f64,
    max: f64,
    detail: String,
}

#[derive(Serialize)]
struct JsonProjection {
    label: &'static str,
    version: String,
    score: f64,
    level: &'static str,
}

#[derive(Serialize)]
struct JsonPathStep {
    name: String,
    version: String,
    kind: &'static str,
}

fn json_path(path: &[PathStep]) -> Vec<JsonPathStep> {
    path.iter()
        .map(|step| JsonPathStep {
            name: step.name.clone(),
            version: step.version.to_string(),
            kind: step.kind.as_str(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::BaselineState;
    use crate::graph::DependencyNode;
    use crate::score::RiskScore;

    fn metadata(current: &str, latest: &str, days_old: i64, now: DateTime<Utc>) -> Metadata {
        let latest = Version::parse(latest).unwrap();
        let current = Version::parse(current).unwrap();
        let mut stable = vec![current.clone(), latest.clone()];
        stable.sort();
        stable.dedup();
        Metadata {
            newest_version: latest.clone(),
            max_stable_version: Some(latest),
            stable_versions: stable,
            updated_at: now - chrono::Duration::days(days_old),
            yanked_versions: Vec::new(),
        }
    }

    fn finding(name: &str, version: &str, total: f64, level: RiskLevel) -> Finding {
        Finding {
            node: DependencyNode {
                name: name.to_string(),
                version: Version::parse(version).unwrap(),
                is_direct: false,
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

    #[test]
    fn the_human_breakdown_shows_every_term_of_the_formula() {
        colored::control::set_override(false);
        let now: DateTime<Utc> = "2026-08-31T00:00:00Z".parse().unwrap();
        let finding = finding("wasi", "0.11.1", 46.4, RiskLevel::Warn);
        let meta = metadata("0.11.1", "0.14.7", 342, now);
        let explanation = Explanation::build(&finding, Some(&meta), None, now, 40.0, false);

        let mut out = String::new();
        explanation.write_human(&mut out);

        assert!(out.contains("wasi 0.11.1"), "{out}");
        assert!(
            out.contains(
                "score = (security 0.0 + version lag 25.0 + maintenance 7.0) × 1.45 graph weight"
            ),
            "{out}"
        );
        assert!(
            out.contains("0.0 / 50"),
            "the security row must show its cap: {out}"
        );
        assert!(out.contains("25.0 / 25"), "{out}");
        assert!(out.contains("7.0 / 15"), "{out}");
        assert!(
            out.contains("3 breaking releases behind (0.11.1 → 0.14.7)"),
            "the lag detail must agree in number with its count: {out}"
        );
        assert!(out.contains("relied on by 25 crates"), "{out}");
        assert!(
            out.contains("(32.0 × 1.45, capped at 100)"),
            "the total line must show the arithmetic: {out}"
        );
    }

    #[test]
    fn a_projection_rescores_at_the_upgrade_target() {
        colored::control::set_override(false);
        let now: DateTime<Utc> = "2026-08-31T00:00:00Z".parse().unwrap();
        // 0.11.1 → 0.11.9 is a compatible move under Cargo's 0.y rule, so it
        // is offered as a projection and must land at a lower score: the lag
        // points go away while maintenance (a crate-level publish date) does
        // not.
        let finding = finding("wasi", "0.11.1", 46.4, RiskLevel::Warn);
        let meta = metadata("0.11.1", "0.11.9", 342, now);
        let explanation = Explanation::build(&finding, Some(&meta), None, now, 40.0, false);

        assert!(
            !explanation.projections.is_empty(),
            "a compatible upgrade target must be offered"
        );
        let projected = explanation.projections[0].total;
        assert!(
            projected < explanation.total,
            "projected {projected} must be below current {}",
            explanation.total
        );

        let mut out = String::new();
        explanation.write_human(&mut out);
        assert!(out.contains("If you upgrade:"), "{out}");
    }

    #[test]
    fn an_up_to_date_crate_offers_no_upgrade_projection() {
        colored::control::set_override(false);
        let now: DateTime<Utc> = "2026-08-31T00:00:00Z".parse().unwrap();
        let mut finding = finding("serde", "1.0.229", 6.0, RiskLevel::Low);
        finding.risk.version_lag = 0.0;
        let meta = metadata("1.0.229", "1.0.229", 20, now);
        let explanation = Explanation::build(&finding, Some(&meta), None, now, 40.0, false);

        assert!(explanation.projections.is_empty());
        let mut out = String::new();
        explanation.write_human(&mut out);
        assert!(out.contains("up to date"), "{out}");
        assert!(!out.contains("If you upgrade:"), "{out}");
    }

    #[test]
    fn a_crate_below_the_threshold_says_so_rather_than_looking_like_a_finding() {
        colored::control::set_override(false);
        let now: DateTime<Utc> = "2026-08-31T00:00:00Z".parse().unwrap();
        let finding = finding("quiet-crate", "1.0.0", 12.0, RiskLevel::Low);
        let meta = metadata("1.0.0", "1.0.0", 10, now);
        let explanation = Explanation::build(&finding, Some(&meta), None, now, 40.0, false);

        let mut out = String::new();
        explanation.write_human(&mut out);
        assert!(out.contains("below your display threshold of 40"), "{out}");
    }

    #[test]
    fn an_ignored_crate_is_explained_with_its_suppression_noted() {
        colored::control::set_override(false);
        let now: DateTime<Utc> = "2026-08-31T00:00:00Z".parse().unwrap();
        let finding = finding("openssl", "0.9.0", 88.0, RiskLevel::Critical);
        let meta = metadata("0.9.0", "0.10.0", 400, now);
        let explanation = Explanation::build(&finding, Some(&meta), None, now, 40.0, true);

        let mut out = String::new();
        explanation.write_human(&mut out);
        assert!(out.contains("suppressed by an ignore rule"), "{out}");
    }

    #[test]
    fn paths_render_the_workspace_member_first_and_label_edge_kinds() {
        colored::control::set_override(false);
        let paths = vec![vec![
            PathStep {
                name: "my-app".into(),
                version: Version::new(0, 1, 0),
                kind: NodeKind::Normal,
            },
            PathStep {
                name: "build-helper".into(),
                version: Version::new(1, 2, 0),
                kind: NodeKind::Build,
            },
            PathStep {
                name: "wasi".into(),
                version: Version::new(0, 11, 1),
                kind: NodeKind::Normal,
            },
        ]];

        let mut out = String::new();
        write_paths(&mut out, "wasi", &paths, 5);
        assert!(
            out.contains("my-app → build-helper 1.2.0 [build] → wasi 0.11.1"),
            "{out}"
        );
    }

    #[test]
    fn an_unreachable_crate_explains_the_kind_filters_instead_of_printing_nothing() {
        colored::control::set_override(false);
        let mut out = String::new();
        write_paths(&mut out, "cc", &[], 5);
        assert!(out.contains("--include-build"), "{out}");
    }
}
