use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

// Outer struct named "cargo" so `cargo depcheck` works as a subcommand. When
// cargo invokes a plugin, it passes the subcommand name as the first
// argument — e.g. `cargo-depcheck depcheck [args]`. This wrapper absorbs it.
// A plain `//` comment (not `///`) so it never leaks into `--help` output —
// `about` below pulls the real description from Cargo.toml instead.
#[derive(Parser)]
#[command(name = "cargo", version, about, long_about = None, propagate_version = true)]
pub struct Cargo {
    #[command(subcommand)]
    pub cmd: CargoCommand,
}

#[derive(Subcommand)]
pub enum CargoCommand {
    /// Ranked dependency health: security advisories, version lag, and maintenance signals
    Depcheck(Args),
}

/// Ranked dependency health: security advisories, version lag, and maintenance signals
#[derive(Parser)]
pub struct Args {
    /// Print a shell completion script or man page instead of running an
    /// analysis. Hidden from --help since it's a one-off setup step, not
    /// part of everyday use — same treatment ripgrep/bat give theirs.
    #[command(subcommand)]
    pub utility: Option<UtilityCommand>,

    /// Path to Cargo.toml (defaults to the nearest one from the current directory)
    #[arg(long, value_name = "PATH", global = true)]
    pub manifest_path: Option<PathBuf>,

    /// Only report dependencies at or above this score. Overrides
    /// `threshold` in `[package.metadata.depcheck]`; tool default is 40.
    /// This controls output only and never weakens `--fail-on`.
    #[arg(
        long,
        value_name = "SCORE",
        env = "CARGO_DEPCHECK_THRESHOLD",
        global = true
    )]
    pub threshold: Option<f64>,

    /// Suppress a specific crate from the report (can be repeated)
    #[arg(long = "ignore", value_name = "CRATE", global = true)]
    pub ignore: Vec<String>,

    /// Report only the N highest-scoring dependencies. Applied after
    /// `--threshold`, so it trims a long report rather than changing what
    /// counts as a finding. Like `--threshold`, this controls output only and
    /// never weakens `--fail-on`.
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u64).range(1..),
        global = true
    )]
    pub top: Option<u64>,

    /// Compare against a baseline report written by `--write-baseline`, and
    /// evaluate `--fail-on` against only the findings that are new since it.
    /// Everything already in the baseline is still reported, marked `known`.
    #[arg(long, value_name = "PATH", global = true)]
    pub baseline: Option<PathBuf>,

    /// Write this run's JSON report to PATH for a later `--baseline` run to
    /// compare against. Writes the file regardless of the output format, and
    /// never changes this run's own exit code.
    #[arg(long, value_name = "PATH", global = true)]
    pub write_baseline: Option<PathBuf>,

    /// Machine-readable JSON output on stdout (progress goes to stderr).
    /// Deprecated alias for --format json; kept for compatibility.
    #[arg(long, global = true)]
    pub json: bool,

    /// Output format. `sarif` is SARIF 2.1.0, for GitHub code scanning and
    /// similar tools (progress goes to stderr, same as `json`).
    #[arg(long, value_enum, global = true)]
    pub format: Option<OutputFormat>,

    /// Skip RustSec advisory lookup entirely
    #[arg(long, global = true)]
    pub no_advisories: bool,

    /// Use the cached advisory database only — no network fetch
    #[arg(long, global = true)]
    pub no_fetch: bool,

    /// Print only summary counts (including an INCOMPLETE marker when needed)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Exit 0 even if crates.io metadata could not be fetched for some
    /// dependencies (by default, an incomplete data layer is a failure)
    #[arg(long, global = true)]
    pub allow_incomplete: bool,

    /// Exit non-zero when a finding at or above this level is present.
    /// Overrides `fail_on` in `[package.metadata.depcheck]`; tool default is
    /// `none`. (An incomplete data layer exits non-zero regardless of this
    /// setting — see --allow-incomplete.)
    #[arg(long, value_enum, env = "CARGO_DEPCHECK_FAIL_ON", global = true)]
    pub fail_on: Option<FailOn>,

    /// Control colored output. `auto` follows NO_COLOR / CLICOLOR_FORCE /
    /// terminal detection; an explicit choice here always wins.
    #[arg(long, value_enum, default_value = "auto", global = true)]
    pub color: ColorChoice,

    /// Use only the local sparse-index cache for crate metadata — no
    /// network access. Registry crates not already cached are reported as
    /// unknown; path/git dependencies are reported as not applicable. Also
    /// passes --offline through to the underlying `cargo metadata`.
    #[arg(long, global = true)]
    pub offline: bool,

    /// Require Cargo.lock to already be up to date (passed through to
    /// `cargo metadata`) — the same flag cargo itself, cargo-deny, and
    /// cargo-audit all use for this.
    #[arg(long, global = true)]
    pub locked: bool,

    /// Equivalent to --locked --offline (passed through to `cargo metadata`)
    #[arg(long, global = true)]
    pub frozen: bool,

    /// Also report build-script (build.rs) dependencies. A build script
    /// runs arbitrary code on your machine and CI at build time, so a
    /// compromised one is a real supply-chain risk even though it never
    /// ships in your binary. Off by default to match the tool's existing
    /// runtime-focused scope.
    #[arg(long, global = true)]
    pub include_build: bool,

    /// Also report dev-dependencies (test/example/benchmark-only crates).
    /// These never ship in your binary but do run arbitrary code on your
    /// machine and CI while testing.
    #[arg(long, global = true)]
    pub include_dev: bool,
}

#[derive(Subcommand)]
pub enum UtilityCommand {
    /// Show exactly how one crate's score was derived, and what pulls it in
    Explain {
        /// Crate name, as it appears in the report
        #[arg(value_name = "CRATE")]
        crate_name: String,
        /// Maximum dependency paths to print (shortest first)
        #[arg(long, value_name = "N", default_value_t = 5)]
        max_paths: usize,
    },
    /// Update prioritized dependencies within their current compatibility line
    Upgrade {
        /// Restrict updates to the resolved crate's current Cargo compatibility line
        #[arg(long, required = true)]
        compatible: bool,
        /// Validate and print updates without writing Cargo.lock
        #[arg(long)]
        dry_run: bool,
        /// Keep successful lockfile changes without running cargo check
        #[arg(long)]
        no_verify: bool,
    },
    /// Print a shell completion script for the given shell to stdout
    #[command(hide = true)]
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print a man page (roff) to stdout
    #[command(hide = true)]
    Mangen,
}

pub struct UpgradeArgs {
    pub compatible: bool,
    pub dry_run: bool,
    pub no_verify: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Never fail on findings (default for 0.x; incomplete data still fails)
    None,
    /// Fail if any WARN or CRITICAL finding is present
    Warn,
    /// Fail only if a CRITICAL finding is present
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    /// Decide from NO_COLOR / CLICOLOR_FORCE / CLICOLOR / terminal detection
    Auto,
    /// Always colorize, even when output is piped
    Always,
    /// Never colorize
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Terminal report (boxes, colors)
    Human,
    /// Versioned JSON on stdout
    Json,
    /// SARIF 2.1.0 on stdout, for GitHub code scanning and similar tools
    Sarif,
    /// GitHub-flavored Markdown on stdout, for PR comments and job summaries
    Markdown,
}

impl OutputFormat {
    /// Whether the report body goes to stdout as data rather than as a
    /// terminal rendering — progress lines are redirected to stderr for
    /// every one of these, so stdout stays parseable (or pasteable).
    pub fn is_machine_readable(self) -> bool {
        !matches!(self, Self::Human)
    }
}
