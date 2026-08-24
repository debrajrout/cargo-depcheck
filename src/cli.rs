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
    #[arg(long, value_name = "PATH")]
    pub manifest_path: Option<PathBuf>,

    /// Only report dependencies at or above this score. Overrides
    /// `threshold` in `[package.metadata.depcheck]`; tool default is 40.
    /// This controls output only and never weakens `--fail-on`.
    #[arg(long, value_name = "SCORE", env = "CARGO_DEPCHECK_THRESHOLD")]
    pub threshold: Option<f64>,

    /// Suppress a specific crate from the report (can be repeated)
    #[arg(long = "ignore", value_name = "CRATE")]
    pub ignore: Vec<String>,

    /// Machine-readable JSON output on stdout (progress goes to stderr).
    /// Deprecated alias for --format json; kept for compatibility.
    #[arg(long)]
    pub json: bool,

    /// Output format. `sarif` is SARIF 2.1.0, for GitHub code scanning and
    /// similar tools (progress goes to stderr, same as `json`).
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,

    /// Skip RustSec advisory lookup entirely
    #[arg(long)]
    pub no_advisories: bool,

    /// Use the cached advisory database only — no network fetch
    #[arg(long)]
    pub no_fetch: bool,

    /// Print only summary counts (including an INCOMPLETE marker when needed)
    #[arg(short, long)]
    pub quiet: bool,

    /// Exit 0 even if crates.io metadata could not be fetched for some
    /// dependencies (by default, an incomplete data layer is a failure)
    #[arg(long)]
    pub allow_incomplete: bool,

    /// Exit non-zero when a finding at or above this level is present.
    /// Overrides `fail_on` in `[package.metadata.depcheck]`; tool default is
    /// `none`. (An incomplete data layer exits non-zero regardless of this
    /// setting — see --allow-incomplete.)
    #[arg(long, value_enum, env = "CARGO_DEPCHECK_FAIL_ON")]
    pub fail_on: Option<FailOn>,

    /// Control colored output. `auto` follows NO_COLOR / CLICOLOR_FORCE /
    /// terminal detection; an explicit choice here always wins.
    #[arg(long, value_enum, default_value = "auto")]
    pub color: ColorChoice,

    /// Use only the local sparse-index cache for crate metadata — no
    /// network access. Registry crates not already cached are reported as
    /// unknown; path/git dependencies are reported as not applicable. Also
    /// passes --offline through to the underlying `cargo metadata`.
    #[arg(long)]
    pub offline: bool,

    /// Require Cargo.lock to already be up to date (passed through to
    /// `cargo metadata`) — the same flag cargo itself, cargo-deny, and
    /// cargo-audit all use for this.
    #[arg(long)]
    pub locked: bool,

    /// Equivalent to --locked --offline (passed through to `cargo metadata`)
    #[arg(long)]
    pub frozen: bool,

    /// Also report build-script (build.rs) dependencies. A build script
    /// runs arbitrary code on your machine and CI at build time, so a
    /// compromised one is a real supply-chain risk even though it never
    /// ships in your binary. Off by default to match the tool's existing
    /// runtime-focused scope.
    #[arg(long)]
    pub include_build: bool,

    /// Also report dev-dependencies (test/example/benchmark-only crates).
    /// These never ship in your binary but do run arbitrary code on your
    /// machine and CI while testing.
    #[arg(long)]
    pub include_dev: bool,
}

#[derive(Subcommand)]
pub enum UtilityCommand {
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
}
