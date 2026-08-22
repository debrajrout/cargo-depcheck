use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::task::JoinSet;

mod advisories;
mod cli;
mod cratesio;
mod graph;
mod report;
mod score;

#[tokio::main]
async fn main() -> Result<()> {
    let cli::Cargo {
        cmd: cli::CargoCommand::Depcheck(args),
    } = cli::Cargo::parse();

    resolve_color(args.color);

    let json_mode = args.json;
    let quiet = args.quiet;
    let ignore: HashSet<String> = args.ignore.into_iter().collect();

    if args.no_advisories && args.no_fetch {
        status_print(
            json_mode,
            quiet,
            "note: --no-fetch has no effect with --no-advisories",
        );
    }

    status_print(
        json_mode,
        quiet,
        format!("cargo-depcheck v{}", env!("CARGO_PKG_VERSION")).bold(),
    );
    status_print(
        json_mode,
        quiet,
        format!(
            "Analyzing {}...\n",
            manifest_display(args.manifest_path.as_deref()).cyan()
        ),
    );

    // ── Phase 1: parse the dependency graph ─────────────────────────────────
    let nodes = graph::load(args.manifest_path.as_deref())?;

    let direct = nodes.iter().filter(|n| n.is_direct).count();
    let transitive = nodes.len() - direct;
    let total_dependencies = nodes.len();

    status_print(
        json_mode,
        quiet,
        format!(
            "Found {}  ({} direct · {} transitive)\n",
            format!("{} dependencies", total_dependencies).bold(),
            direct.to_string().green(),
            transitive.to_string().dimmed(),
        ),
    );

    // ── Phase 2: fetch crates.io metadata concurrently ───────────────────────
    // Only registry-published crates have crates.io metadata at all — a git
    // or path dependency will 404 forever and must not be treated as a
    // failed fetch (see graph::DependencyNode::is_registry).
    let unique_names: Vec<String> = {
        let mut seen = HashSet::new();
        nodes
            .iter()
            .filter(|n| n.is_registry)
            .filter(|n| seen.insert(n.name.clone()))
            .map(|n| n.name.clone())
            .collect()
    };
    let attempted = unique_names.len();

    let client = Arc::new(cratesio::build_client()?);
    let limiter = Arc::new(cratesio::RateLimiter::default());

    let pb = if quiet {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(unique_names.len() as u64)
    };
    pb.set_style(
        ProgressStyle::with_template(
            "  {spinner:.cyan} Fetching crates.io metadata  \
             [{bar:40.cyan/237}]  {pos}/{len}  {elapsed_precise}",
        )
        .unwrap()
        .progress_chars("█░ "),
    );

    let mut set: JoinSet<(String, Result<cratesio::Metadata>)> = JoinSet::new();

    for name in unique_names {
        let client = client.clone();
        let limiter = limiter.clone();

        set.spawn(async move {
            let result = cratesio::fetch(&client, &limiter, &name).await;
            (name, result)
        });
    }

    let mut meta_map: HashMap<String, cratesio::Metadata> = HashMap::new();
    let mut unchecked: Vec<String> = Vec::new();
    let mut last_error: Option<String> = None;
    while let Some(outcome) = set.join_next().await {
        pb.inc(1);
        match outcome {
            Ok((name, Ok(meta))) => {
                meta_map.insert(name, meta);
            }
            Ok((name, Err(err))) => {
                last_error = Some(err.to_string());
                unchecked.push(name);
            }
            Err(join_err) => {
                last_error = Some(join_err.to_string());
            }
        }
    }
    unchecked.sort_unstable();

    pb.finish_and_clear();

    if !unchecked.is_empty() {
        let sample: Vec<String> = unchecked.iter().take(3).cloned().collect();
        status_print(
            json_mode,
            quiet,
            report::degraded_warning(unchecked.len(), attempted, &sample, last_error.as_deref()),
        );
    }

    // ── Phase 3: fetch RustSec advisory database ─────────────────────────────
    let db = if args.no_advisories {
        None
    } else {
        status_print(
            json_mode,
            quiet,
            format!("  {} Fetching RustSec advisory database...", "⠋".cyan()),
        );
        let load_fn = if args.no_fetch {
            advisories::load_cached
        } else {
            advisories::load
        };
        let database = tokio::task::spawn_blocking(load_fn)
            .await
            .context("advisory fetch task panicked")??;
        Some(database)
    };

    if let Some(ref database) = db {
        let advisory_index = advisories::index(database, &nodes);
        status_print(
            json_mode,
            quiet,
            format!(
                "\r  {} RustSec advisory database ready  ({} affected)",
                "✓".green(),
                advisory_index.len()
            ),
        );
    }

    // ── Phase 4: compute risk scores ─────────────────────────────────────────
    let now = Utc::now();
    let max_dependents = nodes.iter().map(|n| n.dependent_count).max().unwrap_or(0);

    // Built before the threshold filter so a crate we have zero signal for
    // (no advisories, no crates.io metadata) is counted as unknown rather
    // than silently vanishing from the "healthy" tally.
    let all_findings: Vec<report::Finding> = nodes
        .into_iter()
        .filter(|node| !ignore.contains(&node.name))
        .map(|node| {
            let node_advisories = db
                .as_ref()
                .map(|database| advisories::lookup(database, &node.name, &node.version))
                .unwrap_or_default();
            let risk = score::compute(
                &node,
                meta_map.get(&node.name),
                &node_advisories,
                max_dependents,
                now,
            );
            report::Finding {
                node,
                risk,
                advisories: node_advisories,
            }
        })
        .collect();

    let unknown = all_findings
        .iter()
        .filter(|f| f.advisories.is_empty() && !meta_map.contains_key(&f.node.name))
        .count();

    let mut findings: Vec<report::Finding> = all_findings
        .into_iter()
        .filter(|finding| finding.risk.total >= args.threshold)
        .collect();

    findings.sort_by(|a, b| {
        b.risk
            .total
            .partial_cmp(&a.risk.total)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let critical = findings
        .iter()
        .filter(|f| f.risk.level == score::RiskLevel::Critical)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.risk.level == score::RiskLevel::Warn)
        .count();
    let summary = report::summarize(total_dependencies, critical, warnings, unknown);

    // ── Phase 5: render report ───────────────────────────────────────────────
    if json_mode {
        let json_report = report::to_json(
            &findings,
            &meta_map,
            now,
            &summary,
            args.threshold,
            &unchecked,
        );
        let output = report::render_json(&json_report)?;
        println!("{output}");
    } else {
        report::render(
            &findings,
            &meta_map,
            now,
            &summary,
            args.quiet,
            args.threshold,
        );
    }

    // Exit code contract: 0 clean · 1 a finding at/above --fail-on is
    // present · 2 usage error (handled by clap before we ever get here) ·
    // 3 the data layer was incomplete (a run that could not check some or
    // all registry crates is not the same thing as a clean report).
    let code = exit_code(
        !unchecked.is_empty(),
        args.allow_incomplete,
        args.fail_on,
        critical,
        warnings,
    );
    if code != 0 {
        std::process::exit(code);
    }

    Ok(())
}

fn exit_code(
    degraded: bool,
    allow_incomplete: bool,
    fail_on: cli::FailOn,
    critical: usize,
    warnings: usize,
) -> i32 {
    if degraded && !allow_incomplete {
        return 3;
    }
    let triggered = match fail_on {
        cli::FailOn::None => false,
        cli::FailOn::Warn => critical > 0 || warnings > 0,
        cli::FailOn::Critical => critical > 0,
    };
    i32::from(triggered)
}

fn status_print(json_mode: bool, quiet: bool, message: impl std::fmt::Display) {
    if quiet {
        return;
    }
    if json_mode {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }
}

/// Resolves `--color` against the standard env-var stack, then applies it as
/// a global override for the `colored` crate. Precedence: an explicit
/// `--color` always wins; otherwise `NO_COLOR` (present and non-empty)
/// disables color; otherwise `CLICOLOR_FORCE` (present and non-empty) forces
/// it on; otherwise an unset `TERM` (not just `TERM=dumb`) disables color —
/// a case that's easy to miss and that hits CI containers; otherwise
/// `CLICOLOR=0` disables it; anything left falls through to `colored`'s own
/// terminal detection. See https://no-color.org/ and
/// https://bixense.com/clicolors/.
fn resolve_color(choice: cli::ColorChoice) {
    match choice {
        cli::ColorChoice::Always => {
            colored::control::set_override(true);
            return;
        }
        cli::ColorChoice::Never => {
            colored::control::set_override(false);
            return;
        }
        cli::ColorChoice::Auto => {}
    }

    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        colored::control::set_override(false);
        return;
    }

    if std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty()) {
        colored::control::set_override(true);
        return;
    }

    if std::env::var_os("TERM").is_none() {
        colored::control::set_override(false);
        return;
    }

    if std::env::var_os("CLICOLOR").is_some_and(|v| v == "0") {
        colored::control::set_override(false);
    }
}

fn manifest_display(path: Option<&std::path::Path>) -> String {
    path.map(|p| p.display().to_string())
        .unwrap_or_else(|| "current project".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_run_exits_zero() {
        assert_eq!(exit_code(false, false, cli::FailOn::Critical, 0, 0), 0);
    }

    #[test]
    fn fail_on_none_never_fails_on_findings() {
        assert_eq!(exit_code(false, false, cli::FailOn::None, 5, 5), 0);
    }

    #[test]
    fn fail_on_critical_ignores_warnings() {
        assert_eq!(exit_code(false, false, cli::FailOn::Critical, 0, 3), 0);
        assert_eq!(exit_code(false, false, cli::FailOn::Critical, 1, 0), 1);
    }

    #[test]
    fn fail_on_warn_triggers_on_either() {
        assert_eq!(exit_code(false, false, cli::FailOn::Warn, 0, 0), 0);
        assert_eq!(exit_code(false, false, cli::FailOn::Warn, 0, 1), 1);
        assert_eq!(exit_code(false, false, cli::FailOn::Warn, 1, 0), 1);
    }

    #[test]
    fn degraded_run_exits_three_regardless_of_fail_on() {
        assert_eq!(exit_code(true, false, cli::FailOn::None, 0, 0), 3);
        assert_eq!(exit_code(true, false, cli::FailOn::Critical, 0, 0), 3);
    }

    #[test]
    fn allow_incomplete_overrides_the_degraded_exit() {
        assert_eq!(exit_code(true, true, cli::FailOn::None, 0, 0), 0);
    }

    #[test]
    fn allow_incomplete_does_not_suppress_a_real_finding_failure() {
        // Degraded data and a real finding can coexist; --allow-incomplete
        // only waives the "data layer was incomplete" failure, not findings.
        assert_eq!(exit_code(true, true, cli::FailOn::Critical, 1, 0), 1);
    }
}
