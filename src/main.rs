use anyhow::{Context, Result};
use chrono::Utc;
use clap::{CommandFactory, Parser};

mod advisories;
mod analyze;
mod baseline;
mod cli;
mod config;
mod explain;
mod graph;
mod markdown;
mod registry;
mod report;
mod sarif;
mod score;
mod upgrade;

#[tokio::main]
async fn main() -> Result<()> {
    let cli::Cargo {
        cmd: cli::CargoCommand::Depcheck(mut args),
    } = cli::Cargo::parse();

    if let Some(command) = args.utility.take() {
        return match command {
            cli::UtilityCommand::Explain {
                crate_name,
                max_paths,
            } => {
                resolve_color(args.color);
                explain::run(&args, &crate_name, max_paths).await
            }
            cli::UtilityCommand::Upgrade {
                compatible,
                dry_run,
                no_verify,
            } => {
                resolve_color(args.color);
                let upgrade_args = cli::UpgradeArgs {
                    compatible,
                    dry_run,
                    no_verify,
                };
                upgrade::run(&args, &upgrade_args).await
            }
            utility => run_utility_command(utility),
        };
    }

    resolve_color(args.color);
    let format = args.format.unwrap_or(if args.json {
        cli::OutputFormat::Json
    } else {
        cli::OutputFormat::Human
    });
    let machine_readable = format.is_machine_readable();
    validate_baseline_flags(&args);
    let now = Utc::now();
    let mut analysis = analyze::run(&args, machine_readable, now).await?;

    // Baseline comparison, before any rendering: the gate counts have to be
    // computed over the whole analyzed set, while the marks the reports show
    // belong on the displayed subset.
    let baseline = args
        .baseline
        .as_deref()
        .map(|path| match baseline::load(path) {
            Ok(loaded) => loaded,
            Err(err) => {
                eprintln!("error: {err:#}");
                std::process::exit(2);
            }
        });
    let delta = baseline.as_ref().map(|loaded| {
        baseline::warn_on_threshold_mismatch(loaded, analysis.threshold);

        // Compared against the population a baseline can actually contain:
        // what this run reports, plus every WARN/CRITICAL regardless of the
        // threshold. The second half preserves the rule that `--threshold`
        // controls display only — raising it must never hide a new warning
        // from `--fail-on` — while the first keeps a notice-level crate the
        // baseline never listed from being announced as new.
        let comparable = analysis.all_findings.iter().filter(|finding| {
            !analysis.ignored_names.contains(&finding.node.name)
                && (score::rounded(finding.risk.total) >= analysis.threshold
                    || finding.risk.level >= score::RiskLevel::Warn)
        });
        let delta = baseline::diff(loaded, comparable);
        baseline::apply(loaded, &mut analysis.visible_findings);
        delta
    });
    let baseline_line = baseline
        .as_ref()
        .zip(delta.as_ref())
        .map(|(loaded, delta)| baseline::summary_line(loaded, delta));

    let json_report = |analysis: &analyze::Analysis| {
        let project = report::JsonProject {
            name: analysis.metadata.root_package().map(|p| p.name.to_string()),
            manifest_path: analysis
                .metadata
                .root_package()
                .map(|p| p.manifest_path.to_string())
                .unwrap_or_else(|| {
                    analysis
                        .workspace_root
                        .join("Cargo.toml")
                        .display()
                        .to_string()
                }),
        };
        report::to_json(
            &analysis.visible_findings,
            &analysis.meta_map,
            now,
            &analysis.summary,
            analysis.threshold,
            report::JsonExtras {
                unchecked: &analysis.unchecked,
                duplicates: analysis.duplicates.clone(),
                ignored: analysis.ignored_with_reason.clone(),
                project,
                advisory_db_commit: analysis.db.as_ref().and_then(advisories::commit_hash),
            },
        )
    };

    // Written before this run's own exit code is applied, so a gating run that
    // fails still leaves the baseline it was asked to record.
    if let Some(path) = args.write_baseline.as_deref() {
        let text = report::render_json(&json_report(&analysis))?;
        std::fs::write(path, format!("{text}\n"))
            .with_context(|| format!("failed to write the baseline to {}", path.display()))?;
        status_print(
            machine_readable,
            args.quiet,
            format!(
                "  wrote baseline with {} {} to {}",
                analysis.visible_findings.len(),
                plural(analysis.visible_findings.len(), "finding", "findings"),
                path.display()
            ),
        );
    }

    match format {
        cli::OutputFormat::Json => {
            println!("{}", report::render_json(&json_report(&analysis))?);
        }
        cli::OutputFormat::Markdown => {
            let project = analysis.metadata.root_package().map(|p| p.name.to_string());
            print!(
                "{}",
                markdown::render(&markdown::MarkdownReport {
                    findings: &analysis.visible_findings,
                    meta_map: &analysis.meta_map,
                    now,
                    summary: &analysis.summary,
                    threshold: analysis.threshold,
                    duplicates: &analysis.duplicates,
                    project: project.as_deref(),
                    baseline: baseline_line.clone(),
                })
            );
        }
        cli::OutputFormat::Sarif => {
            let lockfile_path = analysis.workspace_root.join("Cargo.lock");
            let sarif_log = sarif::build(
                &analysis.visible_findings,
                &analysis.meta_map,
                now,
                &lockfile_path,
            );
            println!("{}", sarif::render(&sarif_log)?);
        }
        cli::OutputFormat::Human => {
            if let Some(line) = &baseline_line {
                status_print(machine_readable, args.quiet, format!("  {line}\n"));
            }
            report::render(
                &analysis.visible_findings,
                &analysis.meta_map,
                now,
                &analysis.summary,
                args.quiet,
                analysis.threshold,
                &analysis.duplicates,
            )
        }
    }

    // With a baseline in play, the gate looks only at what is new since it —
    // the inherited backlog is still reported, but it can't fail a build
    // nobody made worse.
    let (critical, warnings) = match &delta {
        Some(delta) => (delta.new_critical, delta.new_warnings),
        None => (analysis.summary.critical, analysis.summary.warnings),
    };
    let code = exit_code(
        analysis.degraded,
        args.allow_incomplete,
        analysis.fail_on,
        critical,
        warnings,
    );
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// `--top` truncates the report, and a truncated report is a corrupt
/// baseline: every finding it dropped would come back as "new" on the next
/// run, silently inverting what the baseline is for. Rejected up front rather
/// than written and regretted later.
fn validate_baseline_flags(args: &cli::Args) {
    if args.write_baseline.is_some() && args.top.is_some() {
        eprintln!(
            "error: --top cannot be used with --write-baseline: a baseline must record every \
             finding, or the ones it omits are reported as new next run"
        );
        std::process::exit(2);
    }
    if let (Some(read), Some(write)) = (args.baseline.as_deref(), args.write_baseline.as_deref()) {
        if read == write {
            eprintln!(
                "error: --baseline and --write-baseline both point at {}; comparing against a \
                 file this run is about to overwrite can never report anything as new",
                read.display()
            );
            std::process::exit(2);
        }
    }
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

pub(crate) fn status_print(machine_readable: bool, quiet: bool, message: impl std::fmt::Display) {
    if quiet {
        return;
    }
    if machine_readable {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }
}

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

pub(crate) fn plural(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 {
        one
    } else {
        many
    }
}

pub(crate) fn manifest_display(path: Option<&std::path::Path>) -> String {
    path.map(|p| p.display().to_string())
        .unwrap_or_else(|| "current project".to_string())
}

const UTILITY_BIN_NAME: &str = "cargo-depcheck";

fn run_utility_command(utility: cli::UtilityCommand) -> Result<()> {
    match utility {
        cli::UtilityCommand::Upgrade { .. } | cli::UtilityCommand::Explain { .. } => {
            unreachable!("upgrade and explain are handled asynchronously before utility dispatch")
        }
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
        assert_eq!(exit_code(true, true, cli::FailOn::Critical, 1, 0), 1);
    }
}
