# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-08-24

### Fixed (pre-release review)

- **`upgrade`'s rollback only existed in process memory.** Every normal
  failure (a `cargo update` error, a failed `cargo check`) restored
  `Cargo.lock` correctly, since `?` always runs `Drop` on the way out — but
  a hard kill (SIGKILL, OOM-kill, power loss) between the first update and
  the restore left nothing to recover from once the process was gone. The
  pre-upgrade bytes are now written to a real backup file before any
  mutation starts; a leftover backup at the start of a run is treated as
  an interrupted upgrade and refused with exact recovery steps, rather
  than silently trusting whatever Cargo.lock happens to contain. Verified
  by actually `kill -9`-ing the process mid-upgrade and confirming both
  the backup's integrity and the next run's refusal.
- **A score that rounds to zero was counted as a notice, not healthy.**
  `report::summarize` compared the raw, unrounded score, while every other
  consumer — `RiskLevel::from_score`, the displayed score text, the
  `--threshold` filter, and the JSON `score` field — rounds first. A crate
  published one day ago (`maintenance_points(1) ≈ 0.0205`, raw > 0 but
  rounds to `0.0`) landed in `notices` while displaying the identical
  `"0.0"` a genuinely healthy crate shows, contradicting this release's own
  documented definition of `healthy`.
- The JSON snapshot pinning `tool_version` wasn't regenerated for this
  version bump, breaking `cargo test --locked` (and CI) on all three
  platforms.

### Added

- `cargo depcheck upgrade --compatible` applies exact Cargo-approved updates
  within each selected crate's current compatibility line. `--dry-run`
  validates the plan without changing the lockfile; real runs verify with
  `cargo check --workspace` and restore the original `Cargo.lock` on failure.
  The command never edits `Cargo.toml`, and explains updates that require a
  manifest or parent-dependency change.

### Changed

- **JSON report schema 3** makes summary buckets mutually exclusive. It adds
  `total`, `notices`, `not_applicable`, and `ignored`; `healthy` now means a
  checked dependency whose score is exactly zero. The GitHub Action exposes
  the same buckets as outputs.
- Human summaries now distinguish NOTICE, unknown, non-registry, ignored,
  and healthy dependencies. Scores show one decimal so a value below a
  severity boundary cannot round up to a contradictory label.
- Maintenance reasons now say “latest crate release published” because the
  signal measures the most recent publish across every version of a crate,
  not the age of the resolved version.

### Fixed

- **A high `--threshold` could bypass `--fail-on`.** Severity counts and exit
  codes were calculated after display filtering, so
  `--threshold 80 --fail-on warn` could exit 0 with a score-40 warning in the
  graph. Threshold now controls output only; summaries and CI gating always
  use the complete analysis.
- Ignored dependencies were subtracted from findings but left in the total,
  silently counting them as healthy. They now have an explicit `ignored`
  bucket, and duplicate detection still sees the full graph.
- An unexpected missing sparse-index entry for a package Cargo identified as
  crates.io-backed was treated as a successful lookup. It now degrades the
  report and follows the incomplete-data exit-code policy.
- Path and git dependencies no longer appear as unexplained `unknown`
  dependencies; they are `not_applicable` unless a known advisory produces a
  finding. Quiet degraded reports carry an `INCOMPLETE` marker.
- Fixed singular/plural report text such as “1 warnings” and “1 years”.
- Published installs no longer warn about dev-profile overrides for test-only
  crates that Cargo omits during `cargo install`.

### Documentation

- Reorganized the README around a one-minute path from installation to
  interpreting and acting on a report. The output example is shorter,
  NOTICE/healthy semantics are explained up front, and reference material is
  separated from common workflows and CI guidance.

## [0.3.0] - 2026-08-24

### Changed

- **~35% faster.** The registry fetch and the RustSec advisory fetch need
  nothing from each other and touch different subsystems, but ran
  back-to-back. They now run concurrently. Measured over 6 alternating
  A/B pairs on the same network: median 1770ms → 1144ms. Every pair
  favoured the concurrent version. (The advisory task is spawned after the
  graph loads, not at startup, so a fast failure like a bad manifest still
  fails fast instead of waiting on an in-flight git fetch.)

### Fixed

- **`--offline` still went to the network.** It suppressed the registry
  fetch but not the RustSec advisory git fetch, which keyed off `--no-fetch`
  alone — so on a genuinely disconnected machine the flag documented as
  "skips the network entirely" aborted the run instead of producing a
  report. Verified by backdating the advisory cache's `FETCH_HEAD` and
  watching it get rewritten. `--offline` now implies the cached advisory DB.
- **`--offline` reported uncached crates as healthy.** A cache miss returned
  the same "not in the registry" result as a genuine 404, so those crates
  never entered the unchecked set: no degraded warning, exit 0, and — since
  version-lag and maintenance both fall back to zero without metadata — a
  stale dependency scored clean. Against a cold cache that turned an entire
  tree into a false all-clear. A miss is now an error, which is what the
  degraded path and exit code 3 exist for.
- **A failed advisory fetch exited 1 instead of 3.** Exit 1 is reserved for
  "a finding at or above `--fail-on`", so a transient GitHub outage was
  indistinguishable from a real critical finding in CI, and
  `--allow-incomplete` had no effect on it. It is an incomplete data layer,
  the same as the registry half, and now exits 3 and honours
  `--allow-incomplete`.
- **The report box broke at narrow terminal widths.** Reason lines were
  fixed earlier, but the header row lays itself out rather than flowing, and
  held its name field at a constant 41 columns however narrow the box got —
  overflowing by 2 at the 60-column minimum. The width sweep that would have
  caught this now runs over the whole supported range instead of only the
  77-column default.
- **"Found 1 dependencies".** The report already pluralises its own counts,
  so the summary line disagreeing with them read as a bug in the tool.
- **`sarif: true` could fail the job even with `fail-on: none`.** The SARIF
  step published its output path unconditionally, so a run that failed
  before rendering left a 0-byte file that the upload step — which is not
  `continue-on-error` — rejected, failing the whole job. The path is now
  published only when a usable report exists.
- **The release was published before its assets existed.** `gh release
  create` ran without `--draft`, so for the several minutes the matrix took
  to build, `/releases/latest` already pointed at the new tag and the
  action's default `version: latest` resolved to a release with nothing to
  download. It is now created as a draft and published only after every
  archive is attached, which also stops a partially-failed matrix from ever
  becoming "latest".
- **The Action had no real test.** CI's dogfood job used the published `@v1`,
  so a pull request that broke `action.yml` merged green. It now runs `./`,
  the action in the checkout under test.
- **`version: latest` had no auth or diagnostics.** The unauthenticated
  GitHub API allows 60 requests/hr per runner IP; exceeding it surfaced as a
  bare `curl` exit with no explanation. It now uses the job token by default
  (new optional `token` input) and reports a clear error if the lookup fails.
- **Dependent counts were inflated by packages not in the report**, which
  also inflated the graph multiplier derived from them. Reverse edges were
  built from every package in the resolved graph, including ones the kind
  filter excluded and the report later drops — so a dev-only crate, absent
  from the output, still voted on other crates' "relied on by N crates"
  line. On this repo's own graph that affected roughly half the nodes.
  **Scores for affected crates drop slightly**, since the multiplier they
  feed is now computed from real dependents only.
- **`--include-build` / `--include-dev` mislabelled whole subtrees as
  `normal`.** A crate's kind came from the single edge pointing at it, so a
  build-dependency's own dependencies were reported as shipping in your
  binary when they only ever run at build time — precisely backwards for
  the supply-chain question those flags exist to answer. Kind now
  propagates along the path: a path is only as strong as its weakest edge,
  and `normal` still wins whenever any qualifying path exists.
- **Long reason lines broke the report's box border.** The header row was
  ellipsized but reason lines were not, and the padding calculation
  silently clamped to zero instead of overflowing visibly — so any line
  wider than the box pushed the closing border out of alignment. Reason
  lines now wrap with a hanging indent, which keeps the upgrade-target
  version (the actionable half) rather than truncating it away.
- **A typo in `[package.metadata.depcheck]` was silently ignored.** Writing
  `fail-on` instead of `fail_on` left CI ungated while looking green.
  Unknown keys are now a config error (exit 2), and the message names both
  the offending key and the valid ones.

### Documentation

- **README rewritten for readability.** It had grown into a reference
  manual: three dense paragraphs of scoring rationale before a reader
  reached a usage example, and several claims that went stale the moment
  the crate was published (`@v1` "isn't resolvable yet", release archives
  "will include" completions, a note excusing the box-border overflow that
  is now actually fixed). The deep scoring rationale moved to
  [docs/SCORING.md](docs/SCORING.md) rather than being deleted; the README
  keeps a short version and links out. Every command in it was executed to
  confirm it works, and the sample output is a real capture.

- **Three integration tests failed on any fresh machine or CI runner** —
  `degraded_registry_exits_three`, `degraded_registry_with_allow_incomplete_exits_zero`,
  and `yanked_version_is_detected_and_scored` all pass `--no-fetch`
  (requires an *existing* cached advisory DB) without ever warming that
  cache first, unlike the equivalent registry-side warm-up these same
  tests already had. Reproduced locally by clearing `~/.cargo/advisory-db`
  before running the suite, and confirmed fixed the same way. This is what
  actually broke CI on the big implementation-plan merge, not the
  RustSec-advisory bump below (that only explains the separate
  `cargo-deny` job failure).
- **Two transitive RustSec advisories**, caught by `cargo-deny` in CI:
  `crossbeam-epoch` 0.9.18 → 0.9.20 (RUSTSEC-2026-0204, invalid pointer
  dereference in a `Debug`/`Display` impl) and `h2` 0.4.15 → 0.4.16
  (RUSTSEC-2026-0258, unbounded empty DATA frames). Both are patch bumps
  pulled in transitively (via `rayon`/`tame-index` and
  `reqwest`/`hyper`/`tame-index` respectively) — no direct dependency or
  code change needed.

## [0.2.0] - 2026-08-23

### Added

- **CI now dogfoods the published GitHub Action** (`debrajrout/cargo-depcheck@v1`)
  against this repo on every push/PR — real proof the Action installs and
  runs, not just a review of `action.yml`. `fail-on: none` so a real
  finding here never blocks unrelated PRs.
- **SARIF output now validates against the real, official SARIF 2.1.0
  JSON schema in a test** (vendored at `tests/schemas/sarif-2.1.0.json`,
  fetched from the same URL our own `$schema` field points at), not just
  hand-asserted structural invariants. Verified to actually catch
  violations, not just pass trivially, by deliberately breaking a field
  and confirming the test failed before reverting it.
- **Configuration file support** via `[package.metadata.depcheck]`
  (falling back to `[workspace.metadata.depcheck]`) in `Cargo.toml`:
  `threshold`, `fail_on`, and a per-crate `ignore` list with optional
  `reason` and `expires` (`YYYY-MM-DD`). CLI flags and their `env`
  equivalents always win over the file; `--ignore` is additive with the
  file's `ignore` list. An expired ignore stops applying and warns instead
  of silently hiding a crate forever. A malformed table is a config error
  (exit code 2), never a panic.
- **`--locked` and `--frozen` flags**, passed through to `cargo metadata`
  for reproducible-lockfile workflows (`--frozen` implies `--offline` and
  `--locked`).
- **Accessibility: severity is no longer color-only.** Each finding row now
  carries a plain-text `[C]`/`[W]`/`[N]` tag matching its
  CRITICAL/WARN/NOTICE section, so a row stays classifiable in grayscale,
  through a color-stripping pipe, or copy-pasted out of its box — not just
  by red/yellow, which red-green colorblindness can't distinguish.
  `--color never` was already text-complete; this makes every row
  self-describing too.
- **Shell completions and a man page**: `cargo depcheck completions
  <bash|elvish|fish|powershell|zsh>` and `cargo depcheck mangen` print a
  completion script / roff man page to stdout (both hidden from `--help`
  — one-off setup, not everyday flags). Release archives now bundle
  pre-generated copies of both alongside the binary.
- **JSON provenance fields**: `tool_version`, `generated_at`, `project`
  (name + manifest path), and `advisory_db_commit` (the RustSec database
  commit checked against, when advisories were checked at all). A stored
  CI artifact can now answer "which version made this, when, against what,
  and against which advisory snapshot" without re-running the tool.
  `schema_version` is unchanged at 2 — additive fields only.
- **`--include-build` and `--include-dev` flags** surface build-script and
  dev-only dependencies, which are excluded by default. A build script
  runs arbitrary code on every build and CI run — a supply-chain risk this
  tool previously couldn't see at all. Each finding's `kind`
  (`normal`/`build`/`dev`) is in `--json` output and called out in the
  human report; default behavior (normal deps only) is unchanged.
- **SARIF 2.1.0 output** (`--format sarif`, alongside `--format human|json`;
  `--json` remains a working alias for `--format json`). Hand-rolled rather
  than built on `serde-sarif`, matching cargo-audit's own approach and this
  project's lean-dependency-tree goal. Every result gets a real
  `locations[]` entry — the exact `Cargo.lock` line for that package, not a
  fixed placeholder — plus `partialFingerprints` and a `security-severity`
  populated from depcheck's composite score. That last part is the concrete
  differentiator: cargo-audit can only populate `security-severity` from
  CVSS, which 65% of RustSec advisories don't have; depcheck populates it
  for every finding. The GitHub Action gained a `sarif` input that uploads
  via `github/codeql-action/upload-sarif` before the `fail-on` gate can
  fail the job, so findings still reach the Security tab either way.

### Documentation

- **Honesty pass on README.md and CONTRIBUTING.md.** All sample output is
  now copied verbatim from real runs against this repo (previously
  hand-typed, and drifted from actual wording — e.g. "major version(s)"
  vs. the real "breaking version(s)"). `cargo install cargo-depcheck` and
  `uses: debrajrout/cargo-depcheck@v1` are both flagged as not-yet-live
  (unpublished crate, no tagged release) with a working alternative
  (`cargo install --git ...`) given instead of a command that just fails.
  Fixed a false "all CLI flags are available as [Action] inputs" claim,
  and two stale CONTRIBUTING.md claims left over from the pre-sparse-index
  registry client (a since-removed 5-way concurrency cap; Normal-only
  graph edges, now configurable via `--include-build`/`--include-dev`).

### Removed

- **Unused `indicatif` dependency.** Never referenced anywhere in the
  source — the tool's progress lines are plain `print!`/`println!`, not an
  `indicatif` progress bar. Dropping it trims the dependency tree with no
  behavior change.

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

[Unreleased]: https://github.com/debrajrout/cargo-depcheck/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/debrajrout/cargo-depcheck/releases/tag/v0.3.0
[0.2.0]: https://github.com/debrajrout/cargo-depcheck/releases/tag/v0.2.0
