use anyhow::{Context, Result};
use chrono::Utc;
use clap::{CommandFactory, Parser};

mod advisories;
mod analyze;
mod cli;
mod config;
mod graph;
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
    let machine_readable = !matches!(format, cli::OutputFormat::Human);
    let now = Utc::now();
    let analysis = analyze::run(&args, machine_readable, now).await?;

    match format {
        cli::OutputFormat::Json => {
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
            let json_report = report::to_json(
                &analysis.visible_findings,
                &analysis.meta_map,
                now,
                &analysis.summary,
                analysis.threshold,
                report::JsonExtras {
                    unchecked: &analysis.unchecked,
                    duplicates: analysis.duplicates,
                    ignored: analysis.ignored_with_reason,
                    project,
                    advisory_db_commit: analysis.db.as_ref().and_then(advisories::commit_hash),
                },
            );
            println!("{}", report::render_json(&json_report)?);
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
        cli::OutputFormat::Human => report::render(
            &analysis.visible_findings,
            &analysis.meta_map,
            now,
            &analysis.summary,
            args.quiet,
            analysis.threshold,
            &analysis.duplicates,
        ),
    }

    let code = exit_code(
        analysis.degraded,
        args.allow_incomplete,
        analysis.fail_on,
        analysis.summary.critical,
        analysis.summary.warnings,
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
        cli::UtilityCommand::Upgrade { .. } => {
            unreachable!("upgrade is handled asynchronously before utility dispatch")
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
