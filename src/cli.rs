use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Outer struct named "cargo" so `cargo depcheck` works as a subcommand.
/// When cargo invokes a plugin, it passes the subcommand name as the first
/// argument — e.g. `cargo-depcheck depcheck [args]`. This wrapper absorbs it.
#[derive(Parser)]
#[command(name = "cargo")]
pub struct Cargo {
    #[command(subcommand)]
    pub cmd: CargoCommand,
}

#[derive(Subcommand)]
pub enum CargoCommand {
    /// Ranked dependency health: security advisories, version lag, and maintenance signals
    Depcheck(Args),
}

#[derive(Parser)]
pub struct Args {
    /// Path to Cargo.toml (defaults to the nearest one from the current directory)
    #[arg(long, value_name = "PATH")]
    pub manifest_path: Option<PathBuf>,

    /// Only report dependencies at or above this score
    #[arg(long, value_name = "SCORE", default_value_t = 40.0)]
    pub threshold: f64,

    /// Suppress a specific crate from the report (can be repeated)
    #[arg(long = "ignore", value_name = "CRATE")]
    pub ignore: Vec<String>,

    /// Machine-readable JSON output on stdout (progress goes to stderr)
    #[arg(long)]
    pub json: bool,

    /// Skip RustSec advisory lookup entirely
    #[arg(long)]
    pub no_advisories: bool,

    /// Use the cached advisory database only — no network fetch
    #[arg(long)]
    pub no_fetch: bool,

    /// Print only the summary counts, no detailed report
    #[arg(short, long)]
    pub quiet: bool,
}
