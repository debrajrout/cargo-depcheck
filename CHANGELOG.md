# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `--version` now works (previously errored with "unexpected argument").
  `--help` on the bare binary no longer leaks an internal implementation
  comment as its description. `--quiet` now prints exactly one line instead
  of ten. Added `--color <auto|always|never>`, honouring `NO_COLOR` and
  `CLICOLOR_FORCE` per their specs (an empty `NO_COLOR` does not disable
  color; an explicit `--color` always wins).
- `cargo depcheck` now exits non-zero on failure instead of always exiting 0.
  Contract: `0` clean · `1` a finding at/above `--fail-on`'s level is present
  · `2` usage error · `3` the data layer was incomplete (crates.io metadata
  could not be fetched for some dependencies). New `--fail-on
  <none|warn|critical>` flag (default `none` for 0.x; will default to
  `critical` at 1.0). The README's `jq`-based CI recipe is replaced by
  `--fail-on critical`.

- A run that could not fetch crates.io metadata for some or all dependencies
  no longer reports those crates as healthy. It now prints a prominent
  warning, buckets them as `unknown` in the summary (never folded into
  `healthy`), and exits non-zero by default (`--allow-incomplete` opts out).
  `--json` gains `degraded`, `unchecked_count`, and `unchecked_sample`.
- Git and path dependencies are no longer queried against crates.io (they
  have no registry metadata by definition) and so no longer falsely count
  as fetch failures.
- crates.io requests are now paced to at most 1/second (previously ~42/s,
  42x the documented API policy) and retry with backoff on 429, instead of
  silently dropping the result. The User-Agent contact URL, which pointed
  at a repository that does not exist, is now derived from
  `CARGO_PKG_REPOSITORY` so it can't drift from the real one again.
- Colored and bold report rows (CRITICAL/WARN scores, direct-dependency
  names) no longer misalign the box border. Padding is now computed from
  the ANSI-stripped display width instead of `{:<width$}`, which counted
  escape-sequence bytes as columns. Box width also now adapts to the real
  terminal width (falls back to 77 columns when not a TTY), and overlong
  crate names are ellipsized instead of blowing out the layout.

### Added

- Dependency graph analysis with security advisories (RustSec), version lag,
  and maintenance-age scoring, weighted by graph position.
- Terminal report (CRITICAL / WARN / NOTICE) and versioned `--json` output.
- CLI flags: `--threshold`, `--ignore`, `--json`, `--no-advisories`,
  `--no-fetch`, `--quiet`, `--manifest-path`.
- CI: test matrix (Linux/macOS/Windows), fmt, clippy, MSRV (1.70) build,
  and `cargo-deny` (advisories/licenses/bans/sources) checks.
- Release workflow: tagged builds for Linux, macOS (x86_64 + aarch64), and
  Windows, published to GitHub Releases.
- Dependabot for `cargo` and `github-actions` dependency updates.
- Contribution guides, issue/PR templates, CODEOWNERS, and Code of Conduct.

[Unreleased]: https://github.com/debrajrout/cargo-depcheck/commits/main
