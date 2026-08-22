# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — BREAKING

- **Version-lag scoring now follows Cargo's own compatibility rule.**
  Below 1.0, minor is the breaking axis — `0.3.1` to `0.4.0` was
  previously scored as a routine "minor" bump (2.5 pts) despite being
  exactly as incompatible as `1.0.0` to `2.0.0`; it's now scored as
  breaking (12.5 pts), matching reality. Real example from this repo:
  `windows-sys 0.52.0 -> 0.61.2` (9 breaking releases under this rule)
  moved from NOTICE (29.8) to WARN (44.5).
- **Patch-only version lag is no longer invisible.** `0.10.45 -> 0.10.99`
  previously scored exactly 0 — a real gap for a tool whose job is "what
  should I upgrade next," since security fixes often ship as patches. Now
  scores up to 5 points, low enough to never rival a real breaking-version
  gap, but visible.
- **Multiple advisories on the same crate now compound instead of
  collapsing to the worst one.** A crate with 3 advisories of equal
  severity now scores strictly higher than one with a single advisory,
  via a diminishing-returns accumulation (worst advisory at full weight,
  each additional one at 30% of the scale before it), still capped at the
  existing 50-point security ceiling.
- **Unscored RustSec advisories (no CVSS — 65% of the database) are now
  severity-ranked by category** instead of one flat, undocumented `35.0`
  constant that outranked genuinely Medium-severity advisories. See the
  README's "How scoring works" section for the full category ladder and
  reasoning.
- The report's "N major/minor version(s) behind" wording now says
  "breaking" for a 0.x-incompatible bump, matching the corrected scoring
  above, and "patch" for the newly-visible patch-lag tier.

### Added

- **Yanked-version detection.** A pinned version that's been pulled from
  crates.io now scores at the High-severity tier (40 pts) and gets a
  "yanked: NAME VERSION was pulled from crates.io" reason line — previously
  silent. Uses the yanked-flag data already available from the sparse index
  (P1-1).
- **Duplicate-version reporting.** When the same crate resolves at more than
  one version in your graph (build bloat at minimum; a real gap if the
  older copy is the vulnerable one), it's now surfaced as a one-line
  terminal summary and a `duplicates` array in `--json`, computed from the
  full dependency graph regardless of individual scores.
- `Unsound` RustSec advisories (real undefined-behavior risk from safe
  code — 203 of 1,206 advisories in the database) now score at their own
  tier (30 pts, above `Unmaintained`'s 20) instead of being folded into the
  same 10-point bucket as a routine `Notice`. The match on
  `rustsec::advisory::Informational` now names every variant explicitly —
  `rustsec` marks the enum `#[non_exhaustive]`, so Rust still requires a
  trailing wildcard arm, but it's a documented fallback for variants that
  don't exist yet, not a lazy default covering ones that already do.

### Changed — BREAKING

- **The graph-weight multiplier is now absolute, not relative to your own
  project.** Previously `1.0 + dependent_count / max_dependents_in_this_project`,
  so the same crate in the same state could score up to 85% higher in a
  smaller project purely because that project's *unrelated* most-depended-on
  crate happened to have fewer dependents. It's now a saturating function of
  the crate's own transitive dependent count alone —
  `1.0 + ln(1+n) / (ln(1+n) + 4)` — identical for a given count everywhere,
  and monotonic (adding a dependency can no longer lower another crate's
  score). See the README's "How scoring works" section for the formula and
  worked examples.
- **Graph weight now uses the transitive reverse-dependency closure, not
  just direct parents.** A crate with few direct dependents that sits
  underneath something widely used (e.g. `scopeguard`: 1 direct dependent
  but 53 transitive, in this project) now gets credit for its real blast
  radius instead of being scored as if it were a leaf. `graph.rs` computes
  this once per run (O(V·(V+E)), fine at real dependency-graph scale). The
  "relied on by N crates" report line and JSON's new
  `transitive_dependent_count` field both use this number now;
  `dependent_count` (direct only) is still reported alongside it.
- `--json` `schema_version` bumped to **2** for both changes above.
- CRITICAL (>70) / WARN (40-70) bands are **unchanged** — deliberately, not
  by oversight. The practical ceiling of the new multiplier is lower for
  very large graphs (~1.6-1.8 in practice vs. a hard 2.0 before), but
  re-tuning severity bands without real usage data would be guessing; that
  belongs with the "scoring feedback" work in CONTRIBUTING.md once there's
  data to tune against.

### Added

- Official GitHub Action (`action.yml`): downloads a prebuilt binary for
  the runner's platform (never `cargo install`), so it runs in seconds
  instead of doing a source build. Inputs mirror the CLI flags
  (`manifest-path`, `threshold`, `fail-on`, `ignore`, `allow-incomplete`);
  outputs (`critical`, `warnings`, `unknown`, `healthy`, `report-path`) are
  consumable by later steps, and a Markdown summary table is written to
  the job summary by default. Verified against the real binary for both
  the clean and degraded-network paths; full live verification (a real
  `uses: debrajrout/cargo-depcheck@v1` from another workflow) needs a
  published release and a maintained `v1` floating tag — see
  CONTRIBUTING.md's Maintainer section.

### Changed

- Release workflow now publishes to crates.io automatically after binaries
  build successfully for a tagged release, using a `CRATES_IO_TOKEN`
  repository secret (not yet configured — see CONTRIBUTING.md).
- Fixed `categories` in `Cargo.toml`: was `["command-line-utilities",
  "development-tools"]`, now includes the canonical
  `development-tools::cargo-plugins` slug — where cargo-audit, cargo-deny,
  cargo-outdated, and other cargo plugins actually live on crates.io. Also
  gets free indexing on lib.rs.

- Release binaries now target what people actually download. Independent
  GitHub Release asset data from cargo-machete and cargo-deny both show
  ~86-90% of installs are `x86_64-unknown-linux-musl` — not
  `x86_64-unknown-linux-gnu`, which is what this project built before.
  `aarch64-unknown-linux-musl` is now also built (previously missing
  entirely); `x86_64-apple-darwin` — under 0.5% of real demand — is kept
  but deprioritized rather than dropped. Cross-compilation for the musl and
  aarch64-linux targets is automatic via `taiki-e/upload-rust-binary-action`
  (it installs and uses `cross`), no extra toolchain step needed.

### Added

- Integration test harness: `graph.rs` (previously untested) now has unit
  tests covering BFS depth assignment, direct-vs-transitive classification,
  dependent-count, dev/build-dependency exclusion, the unreachable-depth
  drop, duplicate resolved versions of one crate, and multi-member
  workspace BFS — run against real (but network-free, path-only)
  fixture workspaces under `tests/fixtures/`. `graph::load()` is now split
  into a thin `cargo metadata` wrapper and a pure `from_metadata()` so this
  is testable without a subprocess.
- `tests/cli.rs`: end-to-end CLI tests via the real binary, including the
  full `--fail-on`/`--allow-incomplete` exit-code contract (0/2/3 asserted
  end-to-end; 1 remains covered at the unit level only — see notes).
- Report rendering has colored and uncolored snapshot tests (`insta`),
  locking the P0-3 box-alignment fix permanently. `report::render()` is
  now a thin wrapper around a pure `render_to_string()` for this purpose.

### Fixed

- Five existing CLI tests (quiet output, color precedence) never passed
  `--no-advisories`, so each one triggered a real RustSec advisory-database
  git fetch. Running them concurrently (`cargo test`'s default) raced
  against the same shared `~/.cargo/advisory-db` checkout and corrupted it
  during this work — reproduced firsthand. All five now pass
  `--no-advisories`; the whole suite is confirmed network-free.

### Changed

- Replaced the crates.io JSON API with the sparse index (`index.crates.io`)
  for crate metadata. The JSON API is rate-limited to 1 request/second by
  crates.io's own policy — the sparse index has no such limit, is faster,
  and shares its on-disk cache with `~/.cargo` itself. New `--offline` flag
  reports a full offline result from that cache alone. Maintenance-age
  scoring now uses each version's own publish time instead of a crate-level
  timestamp that could be bumped by yanks or metadata edits unrelated to an
  actual release. `Metadata` also now carries yanked-version and MSRV data,
  not yet consumed by scoring (P2-2).
- `src/cratesio.rs` renamed to `src/registry.rs`; fetching is now exposed
  behind an `IndexSource` trait so tests can stand in a fixture-backed
  implementation without HTTP mocking.
- On-disk caching (originally planned as a separate `src/cache.rs`, see
  IMPLEMENTATION_PLAN.md P1-2) is superseded by the sparse-index migration
  above: `tame-index` already shares its ETag-validated cache with
  `~/.cargo`, giving every run a cheap conditional revalidation rather than
  a TTL-based cache that risks serving stale data. Measured: a
  never-before-fetched crate takes ~4.5s; the same crate immediately after
  takes ~0.5s. A bespoke cache layer on top would only duplicate this.

### Fixed

- A degraded-network run with exactly one dependency could hang
  indefinitely: `tame-index`'s bulk fetch applies its per-crate timeout to
  every crate except the first one it processes, which retries a connect
  or timeout error forever with no cap. The whole batch is now wrapped in
  an outer timeout so a genuinely unreachable registry is reported as
  degraded within a bounded time instead of hanging.

- `Cargo.lock` no longer re-dirties itself on a bare `cargo metadata` (the
  committed `serde_derive → syn` edge had drifted from what the current
  toolchain resolves). CI now has a dedicated job that fails if this
  regresses, since `--locked` alone doesn't catch a lockfile that's an
  unstable resolution rather than a wrong one.
- Removed an unreachable branch in the advisory-status message, and the
  redundant full-graph advisory scan that only existed to produce its
  count — each dependency's advisories are now looked up exactly once.
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
- CI: test matrix (Linux/macOS/Windows), fmt, clippy, MSRV (1.91) build,
  and `cargo-deny` (advisories/licenses/bans/sources) checks.
- Release workflow: tagged builds for Linux, macOS (x86_64 + aarch64), and
  Windows, published to GitHub Releases.
- Dependabot for `cargo` and `github-actions` dependency updates.
- Contribution guides, issue/PR templates, CODEOWNERS, and Code of Conduct.

[Unreleased]: https://github.com/debrajrout/cargo-depcheck/commits/main
