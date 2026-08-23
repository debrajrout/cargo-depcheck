use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{CommandFactory, Parser};
use colored::Colorize;
use registry::IndexSource;

mod advisories;
mod cli;
mod config;
mod graph;
mod registry;
mod report;
mod sarif;
mod score;

#[tokio::main]
async fn main() -> Result<()> {
    let cli::Cargo {
        cmd: cli::CargoCommand::Depcheck(args),
    } = cli::Cargo::parse();

    if let Some(utility) = args.utility {
        run_utility_command(utility)?;
        return Ok(());
    }

    resolve_color(args.color);

    let format = args.format.unwrap_or(if args.json {
        cli::OutputFormat::Json
    } else {
        cli::OutputFormat::Human
    });
    // JSON and SARIF are both machine-readable: progress goes to stderr so
    // stdout stays clean for the payload, same convention as plain --json.
    let machine_readable = !matches!(format, cli::OutputFormat::Human);
    let quiet = args.quiet;
    let now = Utc::now();

    if args.no_advisories && args.no_fetch {
        status_print(
            machine_readable,
            quiet,
            "note: --no-fetch has no effect with --no-advisories",
        );
    }

    status_print(
        machine_readable,
        quiet,
        format!("cargo-depcheck v{}", env!("CARGO_PKG_VERSION")).bold(),
    );
    status_print(
        machine_readable,
        quiet,
        format!(
            "Analyzing {}...\n",
            manifest_display(args.manifest_path.as_deref()).cyan()
        ),
    );

    // ── Phase 1: parse the dependency graph ─────────────────────────────────
    let load_options = graph::LoadOptions {
        offline: args.offline,
        locked: args.locked,
        frozen: args.frozen,
    };
    let kind_options = graph::KindOptions {
        include_build: args.include_build,
        include_dev: args.include_dev,
    };
    let (nodes, metadata) = graph::load(args.manifest_path.as_deref(), load_options, kind_options)?;
    let workspace_root = metadata.workspace_root.clone().into_std_path_buf();

    // [package.metadata.depcheck], falling back to
    // [workspace.metadata.depcheck] — see config.rs. A malformed table is a
    // usage error (exit 2), not a panic or a generic failure.
    let package_metadata = metadata
        .root_package()
        .map(|p| &p.metadata)
        .unwrap_or(&serde_json::Value::Null);
    let config = match config::load(
        package_metadata,
        &metadata.workspace_metadata,
        now.date_naive(),
    ) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(2);
        }
    };

    let threshold = args
        .threshold
        .or(config.threshold)
        .unwrap_or(score::DEFAULT_THRESHOLD);
    let fail_on = args.fail_on.or(config.fail_on).unwrap_or(cli::FailOn::None);

    // CLI --ignore and config-file ignores are additive (a union of crates
    // to skip), not one overriding the other — ignoring is naturally a set
    // operation, unlike threshold/fail_on which are single values.
    let mut ignore: HashSet<String> = args.ignore.into_iter().collect();
    let mut ignored_with_reason: Vec<(String, Option<String>)> =
        ignore.iter().map(|name| (name.clone(), None)).collect();
    for entry in &config.ignores {
        if entry.is_expired {
            status_print(
                machine_readable,
                quiet,
                format!(
                    "  {} ignore for {:?} expired on {} — no longer applied, showing it again",
                    "⚠".yellow(),
                    entry.crate_name,
                    entry.expires.expect("is_expired implies expires is Some"),
                ),
            );
            continue;
        }
        ignore.insert(entry.crate_name.clone());
        ignored_with_reason.push((entry.crate_name.clone(), entry.reason.clone()));
    }
    ignored_with_reason.sort_by(|a, b| a.0.cmp(&b.0));
    ignored_with_reason.dedup_by(|a, b| a.0 == b.0);

    let direct = nodes.iter().filter(|n| n.is_direct).count();
    let transitive = nodes.len() - direct;
    let total_dependencies = nodes.len();

    status_print(
        machine_readable,
        quiet,
        format!(
            "Found {}  ({} direct · {} transitive)\n",
            format!("{} dependencies", total_dependencies).bold(),
            direct.to_string().green(),
            transitive.to_string().dimmed(),
        ),
    );

    // ── Phase 2: fetch registry metadata ─────────────────────────────────────
    // Only registry-published crates have index metadata at all — a git or
    // path dependency has none by definition and must not be treated as a
    // failed fetch (see graph::DependencyNode::is_registry). The sparse
    // index has no documented rate limit (unlike the old JSON API), so
    // every crate is requested at once rather than throttled.
    let unique_names: std::collections::BTreeSet<String> = nodes
        .iter()
        .filter(|n| n.is_registry)
        .map(|n| n.name.clone())
        .collect();
    let attempted = unique_names.len();

    if !unique_names.is_empty() {
        status_print(
            machine_readable,
            quiet,
            format!(
                "  {} Fetching registry metadata for {} crates...",
                "⠋".cyan(),
                attempted
            ),
        );
    }

    let index = registry::SparseRegistry::new(args.offline)?;
    let raw = index.fetch(unique_names).await;

    let mut meta_map: HashMap<String, registry::Metadata> = HashMap::new();
    let mut unchecked: Vec<String> = Vec::new();
    let mut last_error: Option<String> = None;
    for (name, result) in raw {
        match result {
            Ok(Some(meta)) => {
                meta_map.insert(name, meta);
            }
            Ok(None) => {
                // Successfully queried the index; this crate genuinely has
                // no entry (e.g. a rename). Not a data-layer failure.
            }
            Err(err) => {
                last_error = Some(err.to_string());
                unchecked.push(name);
            }
        }
    }
    unchecked.sort_unstable();

    if !unchecked.is_empty() {
        let sample: Vec<String> = unchecked.iter().take(3).cloned().collect();
        status_print(
            machine_readable,
            quiet,
            report::degraded_warning(unchecked.len(), attempted, &sample, last_error.as_deref()),
        );
    }

    // ── Phase 3: fetch RustSec advisory database ─────────────────────────────
    let db = if args.no_advisories {
        None
    } else {
        status_print(
            machine_readable,
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

    // ── Phase 4: compute risk scores ─────────────────────────────────────────
    // Each node's advisories are looked up exactly once here — previously
    // `advisories::index()` did a full pass over every node just to report
    // a count, then this loop repeated the same per-node lookup immediately
    // after. Built before the threshold filter so a crate we have zero
    // signal for (no advisories, no crates.io metadata) is counted as
    // unknown rather than silently vanishing from the "healthy" tally.
    let all_findings: Vec<report::Finding> = nodes
        .into_iter()
        .filter(|node| !ignore.contains(&node.name))
        .map(|node| {
            let node_advisories = db
                .as_ref()
                .map(|database| advisories::lookup(database, &node.name, &node.version))
                .unwrap_or_default();
            let risk = score::compute(&node, meta_map.get(&node.name), &node_advisories, now);
            report::Finding {
                node,
                risk,
                advisories: node_advisories,
            }
        })
        .collect();

    if db.is_some() {
        let affected: HashSet<&str> = all_findings
            .iter()
            .filter(|f| !f.advisories.is_empty())
            .map(|f| f.node.name.as_str())
            .collect();
        status_print(
            machine_readable,
            quiet,
            format!(
                "\r  {} RustSec advisory database ready  ({} affected)",
                "✓".green(),
                affected.len()
            ),
        );
    }

    let unknown = all_findings
        .iter()
        .filter(|f| f.advisories.is_empty() && !meta_map.contains_key(&f.node.name))
        .count();

    let duplicates = report::duplicate_groups(&all_findings);

    let mut findings: Vec<report::Finding> = all_findings
        .into_iter()
        .filter(|finding| finding.risk.total >= threshold)
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
    match format {
        cli::OutputFormat::Json => {
            let project = report::JsonProject {
                name: metadata.root_package().map(|p| p.name.to_string()),
                manifest_path: metadata
                    .root_package()
                    .map(|p| p.manifest_path.to_string())
                    .unwrap_or_else(|| workspace_root.join("Cargo.toml").display().to_string()),
            };
            let json_report = report::to_json(
                &findings,
                &meta_map,
                now,
                &summary,
                threshold,
                report::JsonExtras {
                    unchecked: &unchecked,
                    duplicates,
                    ignored: ignored_with_reason,
                    project,
                    advisory_db_commit: db.as_ref().and_then(advisories::commit_hash),
                },
            );
            let output = report::render_json(&json_report)?;
            println!("{output}");
        }
        cli::OutputFormat::Sarif => {
            let lockfile_path = workspace_root.join("Cargo.lock");
            let sarif_log = sarif::build(&findings, &meta_map, now, &lockfile_path);
            let output = sarif::render(&sarif_log)?;
            println!("{output}");
        }
        cli::OutputFormat::Human => {
            report::render(
                &findings,
                &meta_map,
                now,
                &summary,
                args.quiet,
                threshold,
                &duplicates,
            );
        }
    }

    // Exit code contract: 0 clean · 1 a finding at/above --fail-on is
    // present · 2 usage error (handled by clap before we ever get here) ·
    // 3 the data layer was incomplete (a run that could not check some or
    // all registry crates is not the same thing as a clean report).
    let code = exit_code(
        !unchecked.is_empty(),
        args.allow_incomplete,
        fail_on,
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

fn status_print(machine_readable: bool, quiet: bool, message: impl std::fmt::Display) {
    if quiet {
        return;
    }
    if machine_readable {
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

/// The invocable name completions and the man page are generated for. Not
/// `cargo-depcheck depcheck` (the literal argv `cargo` sees when it shells
/// out to this binary via subprocess) — that's cargo's own plumbing, and
/// nobody types it. Plugin authors document and generate against the real
/// entry point instead: the standalone binary name.
const UTILITY_BIN_NAME: &str = "cargo-depcheck";

fn run_utility_command(utility: cli::UtilityCommand) -> Result<()> {
    match utility {
        cli::UtilityCommand::Completions { shell } => {
            let mut cmd = cli::Args::command().name(UTILITY_BIN_NAME);
            clap_complete::generate(shell, &mut cmd, UTILITY_BIN_NAME, &mut std::io::stdout());
        }
        cli::UtilityCommand::Mangen => {
            let cmd = cli::Args::command().name(UTILITY_BIN_NAME);
            clap_mangen::Man::new(cmd)
                .render(&mut std::io::stdout())
                .context("failed to render man page")?;
        }
    }
    Ok(())
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
