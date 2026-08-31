use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use rustsec::Database;

use crate::cli::{Args, FailOn};
use crate::registry::{IndexSource, Metadata};
use crate::{advisories, config, graph, plural, registry, report, score, status_print};

pub struct Analysis {
    pub metadata: cargo_metadata::Metadata,
    pub workspace_root: PathBuf,
    pub threshold: f64,
    pub fail_on: FailOn,
    pub meta_map: HashMap<String, Metadata>,
    pub unchecked: Vec<String>,
    pub db: Option<Database>,
    pub summary: report::ReportSummary,
    pub duplicates: Vec<report::JsonDuplicate>,
    pub ignored_with_reason: Vec<(String, Option<String>)>,
    pub visible_findings: Vec<report::Finding>,
    /// Every analyzed dependency, highest score first, *including* the ones
    /// suppressed by an ignore rule and the ones below the threshold. The
    /// report never shows these, but `explain` has to: asking why a crate
    /// scored what it did is exactly the case where "it's below your
    /// threshold" or "you ignored it" is the answer you need.
    pub all_findings: Vec<report::Finding>,
    pub ignored_names: HashSet<String>,
    pub degraded: bool,
}

pub async fn run(args: &Args, machine_readable: bool, now: DateTime<Utc>) -> Result<Analysis> {
    let quiet = args.quiet;
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
            crate::manifest_display(args.manifest_path.as_deref()).cyan()
        ),
    );

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
    let fail_on = args.fail_on.or(config.fail_on).unwrap_or(FailOn::None);

    let mut ignore: HashSet<String> = args.ignore.iter().cloned().collect();
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
    let total_dependencies = nodes.len();
    status_print(
        machine_readable,
        quiet,
        format!(
            "Found {}  ({} direct · {} transitive)\n",
            format!(
                "{total_dependencies} {}",
                plural(total_dependencies, "dependency", "dependencies")
            )
            .bold(),
            direct.to_string().green(),
            (total_dependencies - direct).to_string().dimmed(),
        ),
    );

    let advisory_task = if args.no_advisories {
        None
    } else {
        let load_fn = if args.no_fetch || args.offline {
            advisories::load_cached
        } else {
            advisories::load
        };
        Some(tokio::task::spawn_blocking(load_fn))
    };
    let unique_names: BTreeSet<String> = nodes
        .iter()
        .filter(|n| n.is_registry)
        .map(|n| n.name.clone())
        .collect();
    let attempted = unique_names.len();
    if attempted > 0 {
        status_print(
            machine_readable,
            quiet,
            format!(
                "  {} Fetching registry metadata for {attempted} {}...",
                "⠋".cyan(),
                plural(attempted, "crate", "crates"),
            ),
        );
    }
    if advisory_task.is_some() {
        status_print(
            machine_readable,
            quiet,
            format!("  {} Fetching RustSec advisory database...", "⠋".cyan()),
        );
    }

    let index = registry::SparseRegistry::new(args.offline)?;
    let raw = index.fetch(unique_names).await;
    let (meta_map, unchecked, last_error) = collect_registry_results(raw);
    if !unchecked.is_empty() {
        let sample: Vec<String> = unchecked.iter().take(3).cloned().collect();
        status_print(
            machine_readable,
            quiet,
            report::degraded_warning(unchecked.len(), attempted, &sample, last_error.as_deref()),
        );
    }

    let (db, advisory_degraded) = match advisory_task {
        None => (None, false),
        Some(task) => match task.await.context("advisory fetch task panicked")? {
            Ok(database) => (Some(database), false),
            Err(err) => {
                eprintln!("error: failed to load the RustSec advisory database: {err:#}");
                if !args.allow_incomplete {
                    std::process::exit(3);
                }
                status_print(
                    machine_readable,
                    quiet,
                    format!(
                        "  {} continuing without advisories (--allow-incomplete)",
                        "⚠".yellow()
                    ),
                );
                (None, true)
            }
        },
    };
    let degraded = !unchecked.is_empty() || advisory_degraded;

    let all_findings: Vec<report::Finding> = nodes
        .into_iter()
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
                baseline_state: crate::baseline::BaselineState::NotCompared,
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

    let duplicates = report::duplicate_groups(&all_findings);
    let ignored_count = all_findings
        .iter()
        .filter(|f| ignore.contains(&f.node.name))
        .count();
    let mut all_findings = all_findings;
    all_findings.sort_by(by_score_desc);
    let mut analyzed_findings: Vec<report::Finding> = all_findings
        .iter()
        .filter(|finding| !ignore.contains(&finding.node.name))
        .cloned()
        .collect();
    let summary = report::summarize(&analyzed_findings, &meta_map, ignored_count, degraded);
    analyzed_findings.sort_by(by_score_desc);
    let mut visible_findings: Vec<report::Finding> = analyzed_findings
        .iter()
        .filter(|finding| score::rounded(finding.risk.total) >= threshold)
        .cloned()
        .collect();

    // `--top` trims an already-ranked list, so it can only ever remove
    // lower-scoring entries. Applied here rather than in the renderers so
    // every format agrees on what "the top N" means, and applied *after*
    // `summarize` so the summary counts (and therefore `--fail-on`) still
    // describe the whole graph.
    if let Some(top) = args.top {
        visible_findings.truncate(top as usize);
    }

    Ok(Analysis {
        metadata,
        workspace_root,
        threshold,
        fail_on,
        meta_map,
        unchecked,
        db,
        summary,
        duplicates,
        ignored_with_reason,
        visible_findings,
        all_findings,
        ignored_names: ignore,
        degraded,
    })
}

fn by_score_desc(a: &report::Finding, b: &report::Finding) -> std::cmp::Ordering {
    b.risk
        .total
        .partial_cmp(&a.risk.total)
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn collect_registry_results(
    raw: registry::FetchResults,
) -> (HashMap<String, Metadata>, Vec<String>, Option<String>) {
    let mut meta_map = HashMap::new();
    let mut unchecked = Vec::new();
    let mut last_error = None;
    for (name, result) in raw {
        match result {
            Ok(Some(meta)) => {
                meta_map.insert(name, meta);
            }
            Ok(None) => {
                last_error = Some(format!("{name} has no crates.io sparse-index entry"));
                unchecked.push(name);
            }
            Err(err) => {
                last_error = Some(err.to_string());
                unchecked.push(name);
            }
        }
    }
    unchecked.sort_unstable();
    (meta_map, unchecked, last_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_online_index_entry_is_unchecked_not_clean() {
        let mut raw = registry::FetchResults::new();
        raw.insert("ghost-crate".to_string(), Ok(None));
        let (metadata, unchecked, last_error) = collect_registry_results(raw);
        assert!(metadata.is_empty());
        assert_eq!(unchecked, ["ghost-crate"]);
        assert!(last_error
            .as_deref()
            .is_some_and(|message| message.contains("no crates.io sparse-index entry")));
    }
}
