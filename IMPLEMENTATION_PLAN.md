# cargo-depcheck — Implementation Plan: Road to 1.0

> **Audience:** the implementing agent (Sonnet 5).
> **Codebase at time of writing:** commit `f9f356f` (branch `main`), version `0.1.0`, **not published to crates.io**.
> Verify with `git rev-parse --short HEAD` before starting. If HEAD has moved, re-check the `file:line` references below — they were accurate at `f9f356f`.
> **Baseline:** `cargo build`, `cargo test` (9/9), `cargo clippy -D warnings`, `cargo fmt --check` all pass. The tool runs end-to-end and is correct on the happy path. This plan is about the paths that are *not* the happy path, and the gap between "works on my machine" and "a tool the Rust community installs."

Every claim below was verified — either reproduced against this repository, or measured live from crates.io / GitHub / primary docs on **2026-08-22**. Anything unverified is explicitly labelled.

---

## How to use this document

Work **in phase order** (P0 → P3). Within a phase, tasks are ordered by dependency.

Each task has **Problem** (with evidence), **Files**, **Approach**, and **Acceptance** (a concrete check that must pass).

Rules for the whole effort:

1. **Never break the baseline.** After every task: `cargo test && cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`.
2. **Write the test first where a test is possible.** Most P0 bugs exist because no test could have caught them.
3. **One task per commit**, in the existing style (`fix:`, `feat:`, `ci:`, `docs:`, `refactor:`).
4. **Update `CHANGELOG.md`** under `## [Unreleased]` as you go — it is already stale (P0-7).
5. If a task's premise turns out to be wrong once you're in the code, **stop and say so** rather than forcing it.

---

## Why this tool deserves to exist

Worth internalizing before you touch scoring, because it tells you what the differentiator actually is.

- **65% of RustSec advisories carry no CVSS score** — only **417 of 1,206** have one. Severity-based triage therefore *cannot* be done from CVSS alone. This is the single strongest argument for a composite, graph-weighted score, and it is also the hardest design problem in the project.
- **RustSec's own composition validates the thesis:** of 1,206 advisories — **730 vulnerabilities, 267 unmaintained, 203 unsound, 6 notice.** Two-fifths of the database is already maintenance signal rather than vulnerability signal.
- **The niche is empty.** `cargo-depcheck` is unclaimed on crates.io. The only direct competitor, `cargo-health`, has **26 total downloads**. The nearest serious tool, `cargo-unmaintained` (Trail of Bits, 55.6k downloads), is a **binary classifier, not a ranker**, and silently degrades without a `GITHUB_TOKEN`.
- **No tool in the ecosystem does graph-position weighting.** cargo-audit tells you 12 advisories exist; nothing tells you 11 are at depth 6 behind an optional feature and one is in your direct HTTP client.

The gap is **triage**, not data. Protect that differentiator — it is what P2-1 is about.

---

## Audit summary

| # | Finding | Severity | Evidence |
|---|---------|----------|----------|
| 1 | Total crates.io failure renders as `✓ 346 healthy`, exit 0 | **Critical** | Ran with unreachable proxy |
| 2 | ~42 req/s against crates.io; documented policy is **1 req/s** | **Critical** | 336 requests in ~8s; 429s confirmed live |
| 3 | Box borders misalign on every colored/bold row | High | Std-only repro: 69 vs 77 cols |
| 4 | Always exits 0 — cannot gate CI without `jq` | High | Exit code with 345 findings |
| 5 | User-Agent contact URL 404s (`debarajrout` ≠ `debrajrout`) | High | `curl` both URLs |
| 6 | Not published to crates.io — README's install command fails for everyone | High | crates.io API 404 |
| 7 | **No GitHub Action** — the one lever with a measured 5–50× effect | **High** | Downloads-per-star analysis, P1-6 |
| 8 | Release matrix misses musl (~88% of real demand) and aarch64-linux | High | Competitor asset download counts |
| 9 | Score depends on your *own* project's max — `--threshold` is not portable | High | Same crate scores +85% in a small repo |
| 10 | `graph.rs` (110 LOC, most intricate logic) and `main.rs` have **0 tests** | High | Per-module test count |
| 11 | Wrong crates.io category — absent from `development-tools::cargo-plugins` | Medium | Where all 6 competitors live |
| 12 | Yanked versions never detected | Medium | No yanked handling in code |
| 13 | `Unsound` scores same as `Notice` — affects **203 advisories** | Medium | `score.rs:100-112` |
| 14 | `--quiet` prints 10 lines; no `--version`; help leaks an internal doc comment | Medium | CLI invocations |
| 15 | 10 crates resolve at duplicate versions; never surfaced | Medium | JSON output analysis |
| 16 | No caching — every run refetches all ~336 crates | Medium | 8s per run |
| 17 | Dead unreachable branch in `main.rs:139` | Low | Code reading |
| 18 | JSON output has no tool version, timestamp, or project identity | Low | JSON keys |

---

## What this audit did and did not cover

Read this before assuming a clean bill of health on anything not listed above.

**Covered.** Every finding was reproduced first-hand: full build/test/clippy/fmt baseline; end-to-end runs against this repo (345 deps, real network); forced-failure runs with crates.io unreachable; a std-only repro of the padding bug; live verification of the sparse index schema; exit codes, `--quiet`, `--version`, `--help`, `--ignore`, `--json`, `--threshold`; per-module test counts; lockfile determinism; and the crates.io rate-limit arithmetic. Ecosystem claims (competitor metrics, release-asset download shares, policy text, SARIF requirements, CLI conventions) were researched against primary sources and are cited inline.

**Not covered — treat as unknown, not as working:**

- **Windows and Linux behaviour.** Everything was run on **macOS only**. CI covers all three for build/test, but none of the runtime findings above (box rendering, terminal width, color detection, cache paths, exit codes) were exercised on Windows or Linux. Terminal rendering and path handling are the most likely to differ.
- **Scale.** Largest project tested was this repo (345 deps). No monorepo or 1000+ dependency workspace was tried. The 8s runtime and the rate-limit math will get worse roughly linearly; whether anything breaks (memory, `JoinSet` behaviour, progress bar) is untested.
- **Workspace edge cases.** Multi-member workspaces, path dependencies, git dependencies, vendored deps, `[patch]` sections, and target-specific/optional dependencies were **not** tested against `graph.rs`. Given that module has zero tests, its behaviour on all of these is unverified — this is why P1-3 comes before P2.
- **Advisory query scope.** `advisories.rs` hardcodes `Collection::Crates` and `withdrawn(false)`. Excluding Rust-core advisories is probably correct and excluding withdrawn ones certainly is, but neither choice is documented or tested, and I did not verify the query returns what you'd expect for a crate with multiple overlapping advisories.
- **`--manifest-path` against an external project.** Only the default (current directory) path was exercised.
- **Security review of the tool itself.** No audit of the code for panics on malformed input, path traversal in future cache handling, or TLS configuration.
- **Concurrency correctness.** The `JoinSet` + `Semaphore` orchestration was not reviewed for panic-safety or cancellation behaviour; `.expect("semaphore closed")` in `main.rs:94` will abort a task if it ever fires.

Where a task below depends on one of these, it says so. The safest sequencing remains P1-3 (tests) before any P2 work.

---

# Phase P0 — Trust & correctness

**Goal: the tool never lies.** Nothing here adds a feature. **Do not publish to crates.io before P0 is complete.**

---

### P0-1 — A failed run must never render as a healthy one

**Problem.** The most serious defect in the codebase. In `main.rs`:

```rust
if let Ok((name, Ok(meta))) = outcome {
    meta_map.insert(name, meta);
}
```

Every error — DNS failure, 429, 5xx, timeout, deserialization failure — is silently discarded. A crate with no metadata scores 0 for both version lag and maintenance, lands under the threshold, and is counted as healthy.

Reproduced with crates.io unreachable:

```
Found 346 dependencies  (12 direct · 334 transitive)
  ✓ RustSec advisory database ready  (0 affected)
  0 critical  ·  0 warnings  ·  346 healthy
  ✓ No dependencies scored at or above the threshold.
exit: 0
```

Zero metadata was fetched. The user is told, with a green checkmark, that their project is clean. A transient blip or a CI runner without egress produces a false all-clear. This is compounded by P0-2: at 42 req/s you *will* be rate-limited, so partial failures are the expected case, not the exceptional one.

**Files.** `src/main.rs`, `src/cratesio.rs`, `src/report.rs`

**Approach.**

1. Track fetch outcomes: succeeded, failed (with error), and for which crates.
2. On any failure, print a prominent warning: `⚠ 336 of 336 crates could not be checked (network error) — results are incomplete`, with a few crate names and the underlying error.
3. Add `degraded: bool` and an unchecked count/sample to the JSON summary.
4. **Default to failing** when the data layer is substantially unavailable. Add `--allow-incomplete` to opt out. A run that checked 0 crates must not exit 0.
5. Crates with no metadata are **unknown**, not healthy. Add an `unknown` bucket to the summary line; never fold them into `healthy`.

**Acceptance.**

- `HTTPS_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 cargo run -- depcheck --no-fetch` prints a prominent warning and exits **non-zero**.
- Same command with `--allow-incomplete` exits 0 but still warns.
- `--json` contains `"degraded": true` and a non-zero unchecked count.
- `healthy` never includes unchecked crates.
- Unit test covers summary bucketing (healthy / unknown / warn / critical).

---

### P0-2 — Stop violating the crates.io crawler policy

**Problem.** The [crates.io data-access policy](https://crates.io/data-access) lists access methods in normative order and puts the JSON API **last**: *"Should you be unable to use one of the previous options, you are welcome to use the crates.io API provided you abide by the following limits: **A maximum of 1 request per second**, and a **user-agent** header that identifies your application."*

The tool fires **336 requests in ~8 seconds — ~42 req/s, about 42× the limit** — from `Semaphore::new(5)` with no delay and no 429 handling. This is not theoretical: during research, exceeding 1 req/s returned **`HTTP/2 429` with no `Retry-After` and an empty body**, persisting across subsequent requests.

Compounding it, the User-Agent contact URL does not exist:

```
src/cratesio.rs:10   https://github.com/debarajrout/cargo-depcheck   -> HTTP 404
Cargo.toml:8         https://github.com/debrajrout/cargo-depcheck    -> HTTP 200
```

The policy's stated purpose for contact info is so crates.io can ask you to change behaviour *instead of blocking you*. Over the limit **and** uncontactable is the profile of a client that gets blocked — which would break the tool for every user simultaneously.

Complying with the JSON API is not viable: at 1 req/s this run takes **5.6 minutes**.

**Files.** `src/cratesio.rs`, `src/main.rs`

**Approach.** This is the *interim* fix; P1-1 removes the JSON API entirely.

1. **Fix the User-Agent URL typo today** — one character, high consequence, and it must be correct before publishing. Derive it from `env!("CARGO_PKG_REPOSITORY")` so it can never drift again.
2. Add a real ≤1 req/s limiter; honour `Retry-After` and back off exponentially on 429 (remembering 429s here arrive with no `Retry-After`, so you need a default).
3. Feed retries and failures into the P0-1 reporting path.

> Don't over-invest. P1-1 replaces the data source. P0-2 exists so you are not abusive *right now* and so the contact URL is valid before publishing.

**Acceptance.**

- `grep -rn debarajrout src/` returns nothing.
- User-Agent derived from `CARGO_PKG_REPOSITORY`, asserted in a unit test.
- Sustained rate ≤ 1/s (assert via the limiter or a mock server).
- A 429 triggers backoff, not a silent drop.

---

### P0-3 — Fix box misalignment on colored rows

**Problem.** `report.rs` pads with `format!("│{header:<INNER_WIDTH$}│")`. Rust's width specifier counts **chars, including ANSI escape bytes**, so any styled row is padded short and the right border shifts left.

This hits exactly the rows that matter most: CRITICAL and WARN (colored score) and direct dependencies (bold name). Today's clean output is an artifact of piping, where `colored` disables itself. Std-only repro of the exact logic:

```
plain (no ANSI)        inner_visible= 77  (want 77)  OK
direct dep (bold)      inner_visible= 69  (want 77)  <-- MISALIGNED
WARN (yellow score)    inner_visible= 68  (want 77)  <-- MISALIGNED
```

The README's sample output is hand-written and does not reflect a real terminal.

**Files.** `src/report.rs`

**Approach.**

1. Compute padding from the **display width of the visible text**, not the styled string: build from unstyled parts, measure with `unicode_width::UnicodeWidthStr` (**already a transitive dep — no new supply-chain cost**), then style and append padding from the measured width.
2. Use `unicode-width`, not `.chars().count()` — versions can carry build metadata and the bar glyphs are non-ASCII.
3. Ellipsize `name version` beyond the 41-column field instead of blowing out the layout.
4. Replace the hardcoded `INNER_WIDTH = 77` with detected terminal width (`terminal_size` 0.4.4 is the ecosystem default; respect `COLUMNS`), clamped to ~60–120, falling back to 77 when not a TTY.

**Acceptance.**

- A unit test renders plain / bold-direct / yellow-WARN / red-CRITICAL / 60-char-name rows and asserts **identical ANSI-stripped display width** for all.
- Real terminal (not piped) shows aligned borders with color on.
- Piping to a file still yields clean, uncolored, aligned output.

---

### P0-4 — Meaningful exit codes

**Problem.** Always exits 0, even with 345 findings. The README works around it:

```yaml
- run: test "$(jq '.summary.critical' depcheck.json)" -eq 0
```

That is the tool asking the user to build its CI integration. Every peer exits non-zero on failure.

Peer convention is **0 / 1 / 2**: cargo-machete (0 clean, 1 unused deps, 2 processing error), cargo-unmaintained (0/1/2), cargo-deny (`process::exit(1)`).

**Watch the clap collision:** `clap::Error::exit_code()` returns **2** for any usage error. So "2 = processing error" is ambiguous with "2 = you typed the flag wrong." Rust panics exit **101**.

> **Do not use the `exitcode` crate**, despite the Rust CLI book recommending it: it was last published **2017-06-18, nearly nine years ago**. By depcheck's own maintenance criterion the officially-recommended crate is abandoned — which is a *perfect* worked example for the README, and exactly the blind spot this tool exists to surface. `sysexits` 0.13.0 is the maintained alternative, but its `USAGE = 64` conflicts with clap's 2 and no peer uses it. **Follow the herd, not the book.**

**Files.** `src/main.rs`, `src/cli.rs`

**Approach.**

1. Contract: `0` clean · `1` findings at/above fail level · `2` usage error (ceded to clap) · `3` operational/degraded failure (ties to P0-1).
2. Add `--fail-on <none|warn|critical>`. Suggest default `none` for 0.x and flip to `critical` at 1.0; state your choice in `CHANGELOG.md`.
3. Document the contract in `README.md`; replace the `jq` recipe.

**Acceptance.**

- `--fail-on critical` exits 1 with a critical finding, 0 otherwise; `--fail-on none` always exits 0 absent an error.
- Integration test asserts each code, including that clap usage errors give 2.
- README CI snippet no longer needs `jq`.

---

### P0-5 — CLI hygiene

**Problem.** Four defects that each cost credibility on first contact:

1. **No `--version`** → `error: unexpected argument '--version' found`.
2. **`--quiet` prints 10 lines**, despite "Print only the summary counts."
3. **Help leaks an internal note.** The `///` on `pub struct Cargo` (`cli.rs:5-7`) becomes the about text, so users see: *"Outer struct named "cargo" so `cargo depcheck` works as a subcommand. When cargo invokes a plugin, it passes the subcommand name as the first argument…"*
4. **No `--color` control**, and `NO_COLOR` is not explicitly honoured.

On (4), the three-standard stack has real subtleties:
- [NO_COLOR](https://no-color.org/): applies when *"present and not an empty string"* — `NO_COLOR=` does **not** disable color.
- [CLICOLOR_FORCE](https://bixense.com/clicolors/): set and non-empty → force color.
- Precedence: `NO_COLOR` > `CLICOLOR_FORCE` > `CLICOLOR` + TTY > TTY detection — **except** an explicit `--color=always` should beat `NO_COLOR`.
- `TERM` **unset** (not just `TERM=dumb`) means no color support — commonly missed, and it hits CI containers.

**Also consider replacing `colored` with `anstream`.** `colored` 3.1.1 does honour the env vars, but it keys off a global `io::stdout().is_terminal()`. depcheck specifically puts JSON on stdout and progress on stderr — the exact split that global check gets wrong. `anstream` 1.0.0 (167M downloads/90d, used by clap) degrades **per-stream**. Pair with `colorchoice-clap` for a drop-in `--color` flag. Use `std::io::IsTerminal` (stable since 1.70; MSRV is 1.91) rather than the legacy `is-terminal` crate.

**Files.** `src/cli.rs`, `src/main.rs`

**Approach.** Add `#[command(version, about, long_about = None)]` and move the implementation note to a `//` comment. Make `--quiet` emit only the summary. Add `--color auto|always|never` with the precedence above. Keep `--json` implying quiet stdout.

**Acceptance.**

- `--version` prints the version, exits 0.
- `--quiet` prints ≤ 2 lines.
- `--help` contains no "Outer struct".
- `NO_COLOR=1` and `--color never` produce escape-free output; `--color always` colors even when piped; `NO_COLOR=` (empty) does **not** disable color.
- Integration tests cover all of the above.

---

### P0-6 — Remove the dead branch

**Problem.** `db` is `None` **iff** `args.no_advisories`, so `main.rs:139` is unreachable:

```rust
} else if !args.no_advisories {          // never executes
    status_print(json_mode, "\r  ✓ RustSec advisory database ready");
}
```

Clippy misses it because the relationship isn't syntactically local.

**Files.** `src/main.rs`

**Approach.** Delete it. While there: `advisories::index()` is called only to produce a count for the status line, re-running `lookup()` across every node — work then repeated per-node in Phase 4. Compute once, reuse.

**Acceptance.** Branch gone; advisory lookup runs once per node; clippy clean; `--no-advisories` output unchanged.

---

### P0-7 — Correct the stale changelog

**Problem.** `CHANGELOG.md:17` still says `MSRV (1.70) build`, but `b367bf9` moved MSRV to 1.91 everywhere else. The changelog contradicts every other file in the repo.

**Files.** `CHANGELOG.md`

**Approach.** Correct the MSRV reference to 1.91. Then log every P0 fix under `## [Unreleased]` using Keep a Changelog sections (`Added` / `Changed` / `Fixed`) as you complete them — this is rule 4 of this document, and P0 is where the habit starts.

**Acceptance.**

- `grep -n "1.70" CHANGELOG.md` returns nothing.
- Every completed P0 task has a corresponding `## [Unreleased]` entry.

---

### P0-8 — Committed `Cargo.lock` is stale and re-dirties on every command

**Problem.** The committed lockfile records `serde_derive 1.0.229` as depending on `syn 2.0.118`, but cargo resolves that edge to `syn 3.0.3` and **rewrites the file on every invocation** — including a bare `cargo metadata`:

```sh
$ git checkout -- Cargo.lock && cargo metadata --format-version 1 >/dev/null
$ git diff --stat Cargo.lock
 Cargo.lock | 2 +-
```

Both `syn` versions are already in the lockfile, so the resolved package *set* is unchanged — which is why `cargo test --locked` still passes and CI doesn't catch it. But every contributor gets a dirty `git status` the moment they run any cargo command, and the diff reappears however many times they revert it. That is a small, constant "did I break something?" tax on every PR, and it makes `--locked` a weaker guarantee than it looks.

Likely introduced when `b367bf9` regenerated the lockfile under a different toolchain resolution than the current one produces.

**Files.** `Cargo.lock`

**Approach.** Regenerate the lockfile with the current toolchain (`cargo generate-lockfile`, or simply commit the corrected edge) and verify it is a genuine fixpoint. Consider adding a CI step that fails if `cargo metadata` leaves the working tree dirty, so this cannot silently return.

**Acceptance.**

- `git checkout -- Cargo.lock && cargo metadata --format-version 1 >/dev/null && git diff --quiet Cargo.lock` succeeds.
- `cargo test --locked` still passes on all three CI platforms.

---

# Phase P1 — Data layer & distribution

**Goal:** fast, policy-compliant, offline-capable, and actually installable.

---

### P1-1 — Replace the crates.io JSON API with the sparse index

**Problem.** P0-2 patched the symptom; the data source is the real issue. **The sparse index solves it completely and provides strictly more data.**

The Cargo index gained a **`pubtime`** field ([registry index reference](https://doc.rust-lang.org/cargo/reference/registry-index.html): *"Publish time in ISO8601 subset format `yyyy-mm-ddThh:mm:ssZ`"*), landed in the **Cargo 1.93** cycle. Verified live against `index.crates.io`:

```json
{"name":"anyhow","vers":"1.0.104","cksum":"330a5e...","features":{...},
 "yanked":false,"rust_version":"1.68","pubtime":"2026-07-18T20:59:37Z"}
```

**And crates.io backfilled it completely** — `serde 0.0.0` → `2014-12-05`, `clap 0.3.5` → `2015-03-01`, `tokio 0.0.0` → `2016-07-01`; all 316 serde versions have it. *(Backfill is observed-true, not documented — re-verify before relying on it.)*

| Need | JSON API today | Sparse index |
|---|---|---|
| Version lag | `newest_version`, `max_stable_version` | full `vers` list — **better** |
| Maintenance age | `updated_at`, **crate-level and noisy** (bumped by yanks and metadata edits) | `pubtime` **per version** — much better |
| Yanked detection | ✗ | ✓ `yanked` |
| MSRV signal | ✗ | ✓ `rust_version` |
| Rate limit | **1 req/s** | **none** |

Per-version `pubtime` is a genuine upgrade: it distinguishes *"this crate is abandoned"* from *"this crate is stable and the version you pin is old"* — which crate-level `updated_at` cannot.

**Measured caveats:**
- **Responses are large** (every version): `reqwest` 956 KB, `clap` 909 KB, `tokio` 833 KB. A naive 300-crate run moves ~50–100 MB. Send `Accept-Encoding: gzip`.
- **Caching works and is essential**: `etag`, `last-modified`, `cache-control: public,max-age=600`. Use `If-None-Match` / `If-Modified-Since` for 304s; ETag wins when both present.
- Path layout: `1/{name}`, `2/{name}`, `3/{first-char}/{name}`, else `{first-2}/{chars-3-4}/{name}`, lowercased.

**Use `tame-index`** — **already a transitive dep at 0.26.3**, so zero new compile cost or supply-chain surface. It's what cargo-deny uses (13.8M downloads). **`pubtime` support landed in tame-index 0.26.1 (PR #106), so pin `>= 0.26.1`.** *(`crates-index` 3.14 is an alternative; whether it exposes `pubtime` is unverified.)*

**Files.** `src/cratesio.rs` → rename `src/registry.rs`, `src/main.rs`, `src/score.rs`, `Cargo.toml`

**Approach.**

1. Add `tame-index >= 0.26.1` as a direct dependency.
2. **Introduce a `trait IndexSource` seam** — see P1-3; do it here, not later. A real implementation plus a fixture-backed one removes the need for HTTP mocking entirely.
3. Prefer cargo's local index cache when fresh; fall back to `index.crates.io` with gzip + ETag caching.
4. Extend `Metadata` with `yanked_versions` and `rust_version`; keep `latest_stable()` semantics.
5. Drop `reqwest` and narrow `tokio`'s `features = ["full"]` if nothing else needs them. The lockfile currently has **362 packages** — a notable look for a dependency-health tool, and a good README talking point once trimmed. (The tool currently compiles **two** reqwest versions: 0.12 direct, 0.13 via rustsec.)
6. Scoring behaviour should not change in this task beyond newly-available signals.

**Acceptance.**

- `grep -rn "api/v1" src/` is empty.
- Warm full run on this repo completes in **< 3s**.
- New `--offline` flag produces a full report from the local cargo index with no network.
- Existing `score.rs` / `report.rs` tests pass unchanged.
- `cargo tree -d` shows one fewer duplicate if reqwest was dropped; `Cargo.lock` package count drops measurably.

---

### P1-2 — On-disk cache

**Problem.** Every invocation refetches everything (~8s). No cache at all.

**Files.** new `src/cache.rs`, `src/main.rs`

**Approach.** Cache under the platform cache dir (respect `XDG_CACHE_HOME`). Key by crate name; store the **ETag** from P1-1 plus a fetch timestamp so revalidation is a cheap 304. Default TTL ~24h (matching the index's `max-age=600` for hot data and a longer floor for cold). Add `--no-cache` and `--refresh`. Version the cache format so upgrades invalidate cleanly.

**Acceptance.**

- Second consecutive run is measurably faster; document the measurement.
- `--no-cache` bypasses; `--refresh` repopulates.
- Corrupt/unreadable cache degrades to a normal fetch — never a panic.
- Honours `XDG_CACHE_HOME`.

---

### P1-3 — Integration test harness

**Problem.** Coverage is inverted — pure functions tested, intricate I/O untested:

```
src/graph.rs        110 LOC   0 tests     <- BFS, dep-kind filtering, dedup
src/main.rs         218 LOC   0 tests     <- all orchestration
src/cratesio.rs      82 LOC   0 tests
src/advisories.rs    61 LOC   0 tests
src/cli.rs           50 LOC   0 tests
src/report.rs       368 LOC   3 tests
src/score.rs        190 LOC   6 tests
```

`Cargo.toml:14` excludes `tests/fixtures/` — a directory that doesn't exist. **Every P0 bug would have been caught by a test.** This must land before P2 touches scoring.

**Key insight from the peers:** neither cargo-deny nor cargo-audit uses an HTTP-mocking crate. Both check in fixtures and run offline. cargo-deny's dev-deps are `insta` (with `json`), `tempfile`, `fs_extra`, `ureq`, `toml-span`.

**Files.** new `tests/`, `Cargo.toml` `[dev-dependencies]`

**Approach.**

1. **Architect for testability first** — the `IndexSource` trait from P1-1 is the seam. A fixture-backed implementation eliminates the HTTP-mocking question entirely. Do this before reaching for a mock crate.
2. `insta` 1.48 for report snapshots. Copy cargo-deny's trick: `[profile.dev.package.insta] opt-level = 3` (and for `similar`) — snapshot diffing is slow in debug.
3. `assert_cmd` 2.2.2 + `predicates` 3.1.4 for exit codes and the stdout/stderr split (JSON on stdout, progress on stderr).
4. Fixture workspaces under `tests/fixtures/`: no-deps crate; crate pinning a known-vulnerable version; multi-member workspace; project with duplicate versions of one crate; project pinning a **yanked** version (for P2-2).
5. Unit-test `graph.rs` against captured `cargo metadata` JSON: depth assignment, direct-vs-transitive, `dependent_count`, dev/build-dep exclusion, and the `usize::MAX` drop.
6. Snapshot report output with color forced **on and off** — this locks P0-3 permanently.
7. **Offline advisory fixtures:** the OSV crates.io dump is only **3.4 MB** (`https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip`) — vendor a trimmed subset for deterministic, network-free advisory tests.
8. Wire into `ci.yml`; keep the suite network-free.

> If you genuinely need HTTP mocking later: **avoid `wiremock`** — largest install base but **no release in 12 months**. Shipping a dev-dependency your own tool would flag is a bad look. `httpmock` 0.8.3 (Feb 2026) is the best activity/adoption balance.

**Acceptance.**

- `cargo test` runs the integration suite with **no network**.
- `graph.rs` covers all five behaviours above.
- Snapshot tests exist for colored and uncolored output.
- P0-4 exit codes asserted end-to-end.
- CI green on all three platforms.

---

### P1-4 — Fix the release target matrix

**Problem.** Real GitHub Release asset downloads show where demand actually is. cargo-machete v0.9.2 (one release, ~4 months):

| Asset | Downloads | Share |
|---|---|---|
| **x86_64-unknown-linux-musl** | **871,829** | **89.5%** |
| aarch64-unknown-linux-gnu | 36,642 | 3.8% |
| x86_64-pc-windows-msvc | 31,789 | 3.3% |
| aarch64-apple-darwin | 25,289 | 2.6% |
| x86_64-apple-darwin | 4,151 | 0.4% |

cargo-deny 0.20.2 independently shows the same shape: **86.0% x86_64-musl**, 6.2% aarch64-musl, 0.3% x86_64-darwin.

**Your `release.yml` builds the wrong four.** It ships `x86_64-unknown-linux-gnu` (**not musl**), includes `x86_64-apple-darwin` (**0.3% of demand**), and **omits `aarch64-unknown-linux-*` entirely**.

Also worth knowing: cargo-machete's 973,724 asset downloads for one release **exceed** its 478,864 crates.io 90-day count. **GitHub Releases is the primary channel; crates.io counts systematically undercount CI usage.**

**Files.** `.github/workflows/release.yml`

**Approach.** Reprioritize: `x86_64-unknown-linux-musl` ≫ `aarch64-unknown-linux-musl` > `x86_64-pc-windows-msvc` ≈ `aarch64-apple-darwin` ≫ `x86_64-apple-darwin`. Add musl targets, add aarch64-linux, keep Windows and aarch64-darwin, and consider dropping x86_64-darwin.

**Acceptance.** A tagged build produces musl and aarch64-linux archives; the musl binary runs in a `scratch`/`alpine` container.

---

### P1-5 — Publish to crates.io

**Problem.** The README's first instruction is `cargo install cargo-depcheck`. The crate does not exist:

```
$ curl -s https://crates.io/api/v1/crates/cargo-depcheck
{"errors":[{"detail":"crate `cargo-depcheck` does not exist"}]}
```

Every reader hits an error on line one. The name is unclaimed.

**Also: your categories are wrong.** You use `["command-line-utilities", "development-tools"]`. The canonical slug is **`development-tools::cargo-plugins`** (817 crates) — where cargo-audit, cargo-deny, cargo-outdated, cargo-crev, cargo-geiger, and cargo-supply-chain all live. **You are absent from the one category your users browse.** Limits: max 5 keywords (≤20 chars each), max 5 categories, each matching a slug from `https://crates.io/category_slugs` exactly. You have free slots. Fixing this also gets lib.rs indexing for free.

**On binstall:** the best outcome is needing **zero** `[package.metadata.binstall]` config. Your current `archive: cargo-depcheck-$tag-$target` under tag `v0.1.0` yields `cargo-depcheck-v0.1.0-x86_64-...tar.gz`, which **already matches binstall's default `{name}-v{version}-{target}`** pattern (and `PkgFmt::Tgz` accepts both `.tgz` and `.tar.gz`). Verify rather than assume — `bin-dir` resolution (binary at archive root vs. in a versioned directory) is the part most likely to need an override. **Leverage:** `taiki-e/install-action` (534★) falls back to cargo-binstall for tools not in its manifest, so correct naming buys install-action support for free with no PR.

**Files.** `Cargo.toml`, `.github/workflows/release.yml`, `README.md`

**Approach.**

1. Complete P0 first — do not ship the trust bugs.
2. Fix `categories` to include `development-tools::cargo-plugins`.
3. `cargo publish --dry-run`; confirm `exclude` is right (it references `tests/fixtures/`, which P1-3 creates). Max `.crate` size is 10 MB.
4. Verify binstall end-to-end; add metadata only if defaults don't match.
5. Publish **0.2.0** (not 0.1.0 — the fixes are substantial). Publishing is *"generally permanent"*; yanking does not delete code.
6. Add a `cargo publish` step to the release workflow, gated on tag, using a `CRATES_IO_TOKEN` secret.

**Acceptance.**

- `cargo publish --dry-run` succeeds.
- `cargo install cargo-depcheck` works from a clean machine.
- `cargo binstall cargo-depcheck` resolves to a prebuilt archive.
- The crate appears under `development-tools::cargo-plugins`.
- Release workflow publishes on tag with no manual steps.

---

### P1-6 — Official GitHub Action

**Problem — this is the highest-leverage item in the entire plan.** Downloads-per-star across the nine comparable tools:

```
tool                      90d dl   stars   dl/star  official action
cargo-audit              3004882    1939    1549.7  yes
cargo-deny               1404870    2402     584.9  yes
cargo-machete             478864    1354     353.7  yes
cargo-udeps               134621    2129      63.2  no
cargo-vet                  96793     976      99.2  no
cargo-outdated             70306    1414      49.7  no
cargo-geiger               48457    1642      29.5  no
cargo-supply-chain          3841     357      10.8  no
cargo-crev                  1514    2329       0.7  no
```

**Every tool with an official Action sits at 350–1550 dl/star. Every tool without one sits at 0.7–99. A 5–50× separation with no overlap.** Stars measure admiration; the Action measures whether the tool runs unattended in CI.

**cargo-crev is the cautionary tale:** 2,329 stars, 1,514 downloads in 90 days — roughly 17 installs a day worldwide. Maximum applause, near-zero adoption, because it depends on humans *maintaining* judgments rather than consuming computed ones. Any depcheck feature requiring ongoing human curation will land in the same place.

**Files.** new `action.yml`, `README.md`

**Approach.** Composite action that **downloads the prebuilt binary** for the runner platform from P1-4/P1-5 artifacts — never `cargo install`. Inputs: `threshold`, `fail-on`, `ignore`, `manifest-path`. Outputs: `critical`, `warnings`, `unknown`. Optional SARIF upload (P2-4). Copy-paste snippet in the README. Also consider writing a markdown summary to `$GITHUB_STEP_SUMMARY` — a cheaper PR-visible win than SARIF, with cargo-geiger's `GitHubMarkdown` format as precedent.

**Acceptance.**

- `uses: debrajrout/cargo-depcheck@v1` runs green on this repo.
- Completes in **< 30s** (no source build).
- Failing thresholds fail the job.
- Outputs consumable by later steps.

---

# Phase P2 — Scoring, integrations, configuration

**Goal:** make the score mean something stable and the tool machine-integrable.

> **This phase changes scores.** Treat as breaking: bump JSON `schema_version` to `2` and document the migration.

---

### P2-1 — Make scores portable across projects

**Problem.** The graph multiplier is relative to your own project's maximum:

```rust
1.0 + dependent_count as f64 / max_dependents as f64
```

`max_dependents` is data-dependent, so **the same crate in the same state scores differently in different projects.** Measured here, where `max_dependents = 37`:

```
crate with 3 dependents, project max=37  -> multiplier 1.08
crate with 3 dependents, project max=20  -> multiplier 1.15
crate with 3 dependents, project max= 5  -> multiplier 1.60
crate with 3 dependents, project max= 3  -> multiplier 2.00
```

That crate scores **85% higher in a small project**. Two consequences:

1. **`--threshold 70` is not portable** — it means something different in every repository. No shared CI policy, no cross-team comparison, and the documented CRITICAL/WARN bands are arbitrary per project.
2. **Scores are non-monotonic** — adding one heavily-depended-on crate raises `max_dependents` and *lowers* every other crate's score. A dependency you never touched can silently drop below your CI threshold.

Secondary: `dependent_count` counts **direct parents only**, but the report says *"relied on by N crates in your graph,"* which reads as blast radius and overstates what's measured.

**Files.** `src/score.rs`, `src/graph.rs`, `src/report.rs`

**Approach.**

1. Replace with an **absolute, saturating** function of dependents — logarithmic with a fixed anchor, so 0 dependents → 1.0 and large counts asymptote to 2.0, independent of the project.
2. Compute the **transitive reverse-dependency closure** in `graph.rs` (crates actually affected) and score on that. Keep direct-parent count too, and make the report wording match whichever number it prints.
3. Re-tune CRITICAL/WARN bands against the new distribution; update the README table.
4. Document the formula with worked examples.

**Acceptance.**

- Unit test: multiplier is identical for a given dependent count regardless of any other project property.
- Unit test: monotonicity — adding a dependency never lowers another crate's score.
- Transitive closure unit-tested against a known-shape fixture.
- README scoring table matches the implementation.
- `CHANGELOG.md` documents the breaking score change; `schema_version` → 2.

---

### P2-2 — Signals the tool currently misses

**Problem.** Three real signals absent or mis-weighted.

1. **Yanked versions never detected.** If your lockfile pins a yanked version, the tool is silent. cargo-deny treats this as deny-worthy. P1-1 makes the data free.
2. **`Unsound` scores the same as `Notice`** — and this affects **203 of 1,206 RustSec advisories**, not an edge case. In `score.rs:100-112`:
   ```rust
   if let Some(info) = &advisory.metadata.informational {
       return if info.is_unmaintained() { 20.0 } else { 10.0 };
   }
   ```
   `rustsec::advisory::Informational` has four variants — `Notice`, `Unmaintained`, `Unsound`, `Other(String)`. An **unsound** crate can cause undefined behaviour from safe code; scoring it as a routine notice is wrong.
3. **Duplicate versions computed but never surfaced.** This project resolves 10 crates at two versions — including `syn` 2 *and* 3, `reqwest` 0.12 *and* 0.13, `bitflags` 1 *and* 2. Build bloat, and a security signal when the older copy is the vulnerable one.

**Files.** `src/score.rs`, `src/report.rs`, `src/graph.rs`

**Approach.** Add a high-weight yanked signal. Give `Unsound` its own tier between `Unmaintained` and a vulnerability. **Match exhaustively on `Informational`** — no catch-all — so a future variant is a compile error, not a silent 10.0. Add duplicate-versions reporting to both the report and a `duplicates` array in JSON.

For weighting guidance, the RustSec category distribution: memory-corruption 266, denial-of-service 126, memory-exposure 88, crypto-failure 80, malicious 73, thread-safety 64, code-execution 36, format-injection 20, privilege-escalation 18, file-disclosure 16.

**Acceptance.**

- A fixture pinning a yanked version produces a finding.
- Unit tests pin the point value of each `Informational` variant, including `Other`.
- The `match` is exhaustive with no catch-all.
- Report and JSON surface duplicates; tested against the duplicate fixture.

---

### P2-3 — Fix the scoring model itself

**Problem.** Four defects in `score.rs` that are independent of the graph-weight problem in P2-1. All four are untested and undocumented.

**1. `0.x` versions are mis-modelled.** Cargo treats `0.y` as the breaking axis — `0.52` and `0.61` are *incompatible*. But `version_lag_points` only checks `major`:

```rust
let major_behind = latest.major.saturating_sub(have.major);
if major_behind > 0 { return (major_behind as f64 * 12.5).min(MAX_VERSION_LAG); }
let minor_behind = latest.minor.saturating_sub(have.minor);
(minor_behind as f64 * 2.5).min(MAX_VERSION_LAG)
```

So for a `0.x` crate, nine **breaking** releases are scored at the compatible-minor rate. Observed in real output from this repo:

```text
windows-sys 0.52.0 -> 0.61.2   9 breaking changes   scored 22.5  (as "minor")
hash32      0.3.1  -> 1.0.0    1 breaking change    scored 12.5  (as "major")
```

The model conflates "nine compatible feature releases" with "nine incompatible ones." Given how much of the ecosystem is pre-1.0, this affects a large share of findings.

**2. Patch-level lag is invisible.** `0.10.45 → 0.10.99` scores **0**. Security fixes shipped as patches produce no signal at all — a real gap for a tool whose entire question is "what should I upgrade next."

**3. `security_points` takes the max, not an accumulation.**

```rust
advisories.iter().map(advisory_points).fold(0.0, f64::max).min(MAX_SECURITY)
```

A crate with five separate advisories scores identically to a crate with one of the same severity. Advisory *count* is invisible.

**4. The unscored-advisory default is a magic number doing most of the work.**

```rust
Some(Severity::None) | None => 35.0,
```

**65% of RustSec advisories have no CVSS score** (417 of 1,206 have one). So this single hardcoded `35.0` — higher than `Low` (20) and `Medium` (30) — determines the security component for the *majority* of real findings. It is untested, unexplained, and ranks unscored advisories above genuinely Medium-severity ones.

**Files.** `src/score.rs`

**Approach.**

1. Make version lag semver-aware: compute *incompatible releases behind* using Cargo's compatibility rules (`0.y` → minor is breaking; `>=1.0` → major is breaking), then compatible releases behind, then patches. Score the three tiers distinctly.
2. Give patch lag a small non-zero weight so it is visible but never dominates.
3. Replace `fold(max)` with a saturating accumulation — the worst advisory dominates, additional ones add diminishing increments, still capped at `MAX_SECURITY`.
4. Replace the `35.0` default with a documented policy. Prefer deriving severity from the advisory's RustSec *category* when CVSS is absent (distribution: memory-corruption 266, denial-of-service 126, memory-exposure 88, crypto-failure 80, malicious 73, thread-safety 64, code-execution 36, format-injection 20, privilege-escalation 18, file-disclosure 16). This turns the majority case from a guess into a signal, and is a defensible differentiator over CVSS-only tools.
5. Handle pre-releases explicitly: `latest_stable()` falls back to `newest_version`, which may be a pre-release, so `have >= latest` can behave oddly. Decide and test the policy.

**Acceptance.**

- Unit tests pin lag scores for: `0.52.0 → 0.61.2`, `0.3.1 → 1.0.0`, `1.0.0 → 3.0.0`, `1.0.0 → 1.4.0`, `0.10.45 → 0.10.99`, and a pre-release latest.
- A `0.x` minor bump scores as breaking, not as a compatible minor.
- Patch-only lag produces a non-zero score.
- A crate with 3 advisories scores strictly higher than the same crate with 1 of equal severity.
- No unexplained numeric literal remains in `advisory_points`; the CVSS-absent policy is documented in the README scoring section.

---

### P2-4 — SARIF output

**Problem.** No SARIF, so findings can't reach GitHub's Security tab. **This is now table stakes** — both direct competitors shipped it within the last year: cargo-deny 0.18.5 (2025-09-22) and cargo-audit 0.22.0 (2025-11-07), both via `--format sarif`.

**Learn from their bugs.** Both had to fix theirs: cargo-deny PR#819 *"added locations to all SARIF results since that's mandatory for valid SARIF"*, and PR#845 *"fixed structural issues."* **Every result needs a `locations[]` entry** — for dependency findings, anchor to the `Cargo.lock` line for that package.

[GitHub's requirements](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning): **SARIF 2.1.0 only**; any third-party tool may upload (no allowlist). Limits: 10 MB gzipped, 25,000 results/run (top 5,000 displayed), 1,000 locations/result.

Required: `$schema`, `version: "2.1.0"`, `runs[]`, `tool.driver.name`, `tool.driver.rules[]`; per rule `id`, `shortDescription.text`, `fullDescription.text`, `help.text`; per result `message.text`, `locations[]` (≥1), and **`partialFingerprints`** (GitHub uses `primaryLocationLineHash`; required to avoid duplicate alerts via the REST API — the `upload-sarif` action generates them for you).

**The differentiator:** `properties.security-severity` (numeric 0.1–10.0) is how GitHub sorts findings — and it's the natural home for depcheck's composite score. **cargo-audit can only emit CVSS, which 65% of RustSec advisories lack. depcheck can populate `security-severity` for 100% of findings.** That is a concrete, demonstrable advantage worth leading with.

**Files.** `src/report.rs` or new `src/sarif.rs`, `src/cli.rs`, `action.yml`

**Approach.** Add `--format human|json|sarif`, keeping `--json` as an alias. **Hand-roll the `Serialize` impl** rather than adding `serde-sarif` — that's what cargo-audit did (`cargo-audit/src/sarif.rs` is a readable single-file reference), and it's the consistent choice given the 362-package lockfile you're trying to shrink. Map risk level to `defaultConfiguration.level`, composite score to `security-severity`, and add `properties.tags[]`. Wire optional upload into the P1-6 Action with a `category`.

**Acceptance.**

- Output validates against the SARIF 2.1.0 schema in a test.
- Every result has ≥1 `locations[]` entry.
- Uploading via `github/codeql-action/upload-sarif` surfaces findings in a test repo's Security tab.
- `--format json` is byte-identical to today's `--json`.

---

### P2-5 — Configuration file

**Problem.** Threshold and ignores are CLI-only, so every developer and CI job repeats them, with no way to record *why* something is ignored. Listed as wanted work in `CONTRIBUTING.md:134`.

**Files.** new `src/config.rs`, `src/cli.rs`, `src/main.rs`

**Approach.** Read `[package.metadata.depcheck]` and `[workspace.metadata.depcheck]` from `Cargo.toml`. Support `threshold`, `fail_on`, `ignore` (with per-entry `reason` and optional `expires` so ignores are auditable), `include_build`, `include_dev`. Precedence: CLI > env > config > default. Warn on expired ignores. Also add the cargo-standard `--offline` / `--locked` / `--frozen` flags that cargo-deny and cargo-audit both have.

**Acceptance.**

- Config honoured; CLI overrides; precedence unit-tested.
- An ignore's `reason` appears in `--json`.
- Expired ignores warn.
- Malformed config gives a clear error and exit code 2 — never a panic.

---

### P2-6 — Dev and build dependency coverage

**Problem.** `graph.rs:40-53` follows only `DependencyKind::Normal`, and `graph.rs:104` drops unreachable nodes — explicitly discarding build-script-only deps like `cc` and `autocfg`, on the reasoning that they "aren't relevant to health scoring."

Defensible for *shipped* code, wrong for *supply-chain* risk: a build script runs arbitrary code on developer machines and CI runners at build time. A compromised `build.rs` dependency is a textbook supply-chain attack, and the tool cannot see it at all. cargo-audit and cargo-deny both scan them.

**Files.** `src/graph.rs`, `src/cli.rs`

**Approach.** Keep the current default, add `--include-build` and `--include-dev`. Track dependency kind on `DependencyNode`; surface it in report and JSON so build-time risk is distinguishable from runtime. Consider making build deps default-on at 1.0 given the security framing — decide explicitly and document it.

**Acceptance.** `--include-build` surfaces build-only crates; default unchanged; kind appears in JSON; fixtures cover normal/dev/build classification.

---

# Phase P3 — Polish & ecosystem presence

**Goal:** the details that make the tool read as maintained. None of these move adoption the way P1-4 through P1-6 do — sequence them last.

---

### P3-1 — JSON provenance

**Problem.** The JSON carries only `schema_version`, `summary`, `findings`. A CI artifact stored for later cannot answer the four questions that matter when you re-read it: which tool version produced this, when, against which project, and was the run complete?

**Files.** `src/report.rs`, `src/main.rs`

**Approach.** Add `tool_version`, `generated_at`, `project` (name + manifest path), `advisory_db_commit`, and the P0-1 `degraded` / unchecked-crate fields. Bump `schema_version` **alongside P2-1** rather than twice — consumers should absorb one breaking schema change, not two.

**Acceptance.**

- All fields present in `--format json` output.
- Snapshot test covers the shape with `generated_at` normalized so it stays deterministic.
- `schema_version` bumped exactly once across P2-1 and P3-1 combined.

---

### P3-2 — Shell completions and man page

**Problem.** Neither exists. Both are baseline polish for a CLI, and distro packagers expect a man page.

**Files.** `src/cli.rs`, `Cargo.toml`, optional new `build.rs`, `.github/workflows/release.yml`

**Approach.** Use `clap_complete` **4.6.9**, whose static `Shell` enum covers exactly Bash, Elvish, Fish, PowerShell, and Zsh (Nushell needs the separate `clap_complete_nushell`). **Do not ship dynamic completion — `CompleteEnv` is still behind the `unstable-dynamic` feature.** The standard pattern is a hidden `completions <SHELL>` subcommand calling `generate(...)` into stdout; emitting into `OUT_DIR` from `build.rs` is the packager-friendly alternative. Add `clap_mangen` **0.3.3** for the man page. Ship both in the release archives from P1-4.

**Acceptance.**

- `cargo depcheck completions <shell>` emits valid output for all five shells.
- Generated completions load without error in at least zsh and bash.
- Man page renders under `man`.
- Release archives contain both artifacts.

---

### P3-3 — Accessibility

**Problem.** Severity is encoded in red/yellow **only**. CRITICAL vs WARN is precisely the distinction that must survive red/green colorblindness, and today it does not. Already flagged as wanted work in `CONTRIBUTING.md:138`.

**Files.** `src/report.rs`

**Approach.** Never rely on color as the sole carrier of meaning. The section header already names the level; add a per-row glyph or text prefix so a row remains classifiable in grayscale or when copy-pasted. Check contrast against both light and dark terminal backgrounds. `--color never` (P0-5) must remain fully informative, not degraded.

**Acceptance.**

- Piping output through a color stripper leaves severity unambiguous for every row.
- A grayscale/simulated-colorblind rendering keeps CRITICAL and WARN distinguishable.
- No information is available only via color.

---

### P3-4 — Documentation honesty pass

**Problem.** The README currently oversells relative to real behaviour. Each item is fixed by an earlier task, but the docs must actually be regenerated afterwards or the claims stay false:

- `cargo install cargo-depcheck` does not work — the crate is unpublished (P1-5)
- Sample output shows perfectly aligned boxes that a real terminal does not produce (P0-3)
- The CI recipe needs `jq` only because exit codes are missing (P0-4)
- "Ranked by graph impact ✓" is the central claim, and P2-1 is what makes it defensible

**Files.** `README.md`, `CONTRIBUTING.md`

**Approach.** Regenerate **all** sample output by copying real runs after P0–P2 land — do not hand-write terminal output. Document the exit-code contract, the scoring formula with worked examples, the config file, and offline mode. Consider using the `exitcode` anecdote from P0-4 in the README as a worked example of exactly the blind spot this tool surfaces.

**Acceptance.**

- Every command in the README executes successfully as written, verified by running each one.
- All sample output is copied verbatim from a real run.
- The scoring section matches the implemented formula.

---

### P3-5 — Ecosystem visibility

**Problem.** Once the tool is installable (P1-5) and CI-native (P1-6), discovery is the last remaining gap — nobody installs a tool they cannot find.

**Files.** No source changes; depends on the `Cargo.toml` metadata fixed in P1-5.

**Approach.**

- **awesome-rust** — explicit published bar: *"Accepted: (stars > 50 | downloads > 2000)"*. Cheap PR once you clear either. Format: `[ACCOUNT/REPO](url) [[CRATE](url)] - DESCRIPTION`, alphabetical.
- **blessed.rs** — hand-curated; its *Tooling → Managing Dependencies* section already lists cargo-audit, cargo-deny, cargo-license, cargo-outdated. That is the right shelf. *(No documented contribution criteria found — treat as a judgment-call PR, not a checklist.)*
- **lib.rs** — free once P1-5 fixes the category to `development-tools::cargo-plugins`.
- **Launch post** for r/rust and This Week in Rust. Lead with the differentiator — *ranked by graph impact* — and the 65%-no-CVSS statistic, which is the crispest one-line case for why ranking beats listing.
- **Skip Homebrew.** Measured: cargo-audit gets **134 Homebrew installs/30d** against roughly 1,000,000 crates.io downloads — about 0.01%. cargo-machete is not in homebrew-core at all and has 2.7M downloads. The acceptance bar (75 stars, or 225 for self-submission) is not worth clearing.

**Acceptance.**

- Published to crates.io and correctly categorized; lib.rs listing live.
- awesome-rust PR opened once the stars/downloads bar is met.
- Launch post drafted and published.

---

## Suggested release plan

| Release | Contents | Theme |
|---|---|---|
| **0.2.0** | P0 complete + P1-1, P1-2, P1-3 | *Trustworthy and fast.* |
| **0.3.0** | P1-4, P1-5, P1-6, P2-4 | *Installable and CI-native.* Publish, correct binaries, Action, SARIF. |
| **0.4.0** | P2-1, P2-2, P2-3, P2-5, P2-6 | *Scores that mean something.* Breaking score change. |
| **1.0.0** | P3 + stabilized JSON schema | *Stable contract.* |

Note P1-6 (the Action) is pulled into 0.3.0 rather than deferred — it is the single highest-leverage item in the plan and depends only on P1-4/P1-5.

---

## Future considerations (not scheduled)

Researched and viable, but out of scope for 1.0. Recorded so the option isn't lost.

**OSV as an additional advisory source.** The bulk zip is 3.4 MB, refreshed daily, and `POST https://api.osv.dev/v1/querybatch` takes many `{package, version}` pairs per request with no auth. It contains **2,749 crates.io advisories: 1,524 GHSA + 1,206 RUSTSEC + 19 MAL**. Two things make it interesting:

- The **19 `MAL-*` malicious-package advisories** are a distinct and arguably higher-urgency class than CVEs, and **no competitor surfaces them as a separate tier.**
- `ecosystem_specific.affected_functions` would enable **reachability** refinement — a genuine differentiator none of the nine competitors offer.

**Dedup is mandatory:** **778 of 1,206 RUSTSEC ids also appear as a GHSA alias.** Naively unioning GHSA + RUSTSEC roughly doubles your finding count. Key on `aliases`.

**deps.dev for repo-health signal.** Google's API supports `CARGO` natively, free, no auth. `GET /v3/projects/github.com%2Fserde-rs%2Fserde` returns stars, forks, open issues, and an **OpenSSF Scorecard**. This gives repo health **without a GitHub token** — a real advantage over `cargo-unmaintained`, which silently degrades without one. Caveats: Scorecard attaches to the *project*, not the package version; the crate→repo link is self-declared and spoofable (`relationProvenance: UNVERIFIED_METADATA`); *rate limits undocumented and unverified.*

---

## Verification snippets

Reproductions behind the findings above; useful as regression checks.

```sh
# P0-1 — silent failure presented as healthy
HTTPS_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
  cargo run --quiet -- depcheck --no-fetch; echo "exit: $?"

# P0-2 — the 404 contact URL
grep -rn "github.com" src/cratesio.rs Cargo.toml
curl -s -o /dev/null -w "%{http_code}\n" https://github.com/debarajrout/cargo-depcheck

# P0-4 — exit code with findings present
cargo run --quiet -- depcheck --no-fetch --threshold 0 >/dev/null 2>&1; echo "exit: $?"

# P0-5 — CLI hygiene
cargo run --quiet -- depcheck --version
cargo run --quiet -- depcheck --quiet 2>/dev/null | wc -l
cargo run --quiet -- depcheck --help | grep -c "Outer struct"

# P1-1 — sparse index carries every signal needed
curl -s --compressed -H "User-Agent: cargo-depcheck-dev (you@example.com)" \
  https://index.crates.io/an/yh/anyhow | tail -1 | python3 -m json.tool

# P2-2 — duplicate versions present but unreported
cargo tree -d | head -30

# Baseline after every task
cargo test && cargo clippy --all-targets --all-features -- -D warnings \
  && cargo fmt --all -- --check
```
