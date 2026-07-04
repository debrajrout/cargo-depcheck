use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;
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

    let json_mode = args.json;
    let ignore: HashSet<String> = args.ignore.into_iter().collect();

    if args.no_advisories && args.no_fetch {
        status_print(json_mode, "note: --no-fetch has no effect with --no-advisories");
    }

    status_print(
        json_mode,
        format!("cargo-depcheck v{}", env!("CARGO_PKG_VERSION")).bold(),
    );
    status_print(
        json_mode,
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
        format!(
            "Found {}  ({} direct · {} transitive)\n",
            format!("{} dependencies", total_dependencies).bold(),
            direct.to_string().green(),
            transitive.to_string().dimmed(),
        ),
    );

    // ── Phase 2: fetch crates.io metadata concurrently ───────────────────────
    let unique_names: Vec<String> = {
        let mut seen = HashSet::new();
        nodes
            .iter()
            .filter(|n| seen.insert(n.name.clone()))
            .map(|n| n.name.clone())
            .collect()
    };

    let client = Arc::new(cratesio::build_client()?);
    let semaphore = Arc::new(Semaphore::new(5));

    let pb = ProgressBar::new(unique_names.len() as u64);
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
        let sem = semaphore.clone();

        set.spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            let result = cratesio::fetch(&client, &name).await;
            (name, result)
        });
    }

    let mut meta_map: HashMap<String, cratesio::Metadata> = HashMap::new();
    while let Some(outcome) = set.join_next().await {
        pb.inc(1);
        if let Ok((name, Ok(meta))) = outcome {
            meta_map.insert(name, meta);
        }
    }

    pb.finish_and_clear();

    // ── Phase 3: fetch RustSec advisory database ─────────────────────────────
    let db = if args.no_advisories {
        None
    } else {
        status_print(json_mode, format!("  {} Fetching RustSec advisory database...", "⠋".cyan()));
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
            format!(
                "\r  {} RustSec advisory database ready  ({} affected)",
                "✓".green(),
                advisory_index.len()
            ),
        );
    } else if !args.no_advisories {
        status_print(json_mode, "\r  ✓ RustSec advisory database ready");
    }

    // ── Phase 4: compute risk scores ─────────────────────────────────────────
    let now = Utc::now();
    let max_dependents = nodes.iter().map(|n| n.dependent_count).max().unwrap_or(0);

    let mut findings: Vec<report::Finding> = nodes
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
    let summary = report::summarize(total_dependencies, critical, warnings);

    // ── Phase 5: render report ───────────────────────────────────────────────
    if json_mode {
        let json_report = report::to_json(&findings, &meta_map, now, &summary, args.threshold);
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

    Ok(())
}

fn status_print(json_mode: bool, message: impl std::fmt::Display) {
    if json_mode {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }
}

fn manifest_display(path: Option<&std::path::Path>) -> String {
    path.map(|p| p.display().to_string())
        .unwrap_or_else(|| "current project".to_string())
}
