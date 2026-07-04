# cargo-depcheck — LLM / Developer Handover

Read this top to bottom before touching code. It reflects the **current** state of
the project as of July 2026 — all seven core milestones are complete.

This file is **gitignored** (local context only). User-facing docs live in
`README.md`.

---

## What this project is

A Rust CLI invoked as `cargo depcheck`. It analyzes every resolved dependency in
a Cargo project and produces a **ranked health report** — not a flat list of
every outdated crate, but a triage view of what actually deserves attention.

Three signals are combined:

1. **Security** — RustSec advisories (CVEs, unmaintained flags)
2. **Version lag** — how far behind the latest stable release
3. **Maintenance age** — days since last publish on crates.io

Each signal is weighted by **graph position**: a stale crate that 40 other deps
transitively rely on ranks above a stale leaf node with the same version lag.

**The gap it fills:**

| Tool | What it tells you |
|------|-------------------|
| `cargo audit` | "This crate has a CVE" |
| `cargo outdated` | "This crate is behind" |
| **`cargo depcheck`** | **"Fix this one first — and here's why"** |

**The user:** Debaraj (debarajrout). He is learning Rust through this project.
Prefer teaching over dumping code. Explain what and why before large diffs.

**Repository:** https://github.com/debarajrout/cargo-depcheck

---

## Current working state (July 2026)

The tool compiles, passes clippy, and runs end-to-end. All planned source modules
exist. Example run against this project:

```sh
cargo run -- depcheck
# → 366 deps, 0 critical, 0 warnings (nothing scores ≥ 40 by default)

cargo run -- depcheck --threshold 30
# → NOTICE section with number_prefix + proc-macro-error2 (unmaintained, ~35 pts)
```

**Git commits (newest first):**

```
1bb7b2e  Milestones 6–7: CLI flags + JSON output
e1e1a1d  Milestone 5: grouped scored report (report.rs)
5f5f007  Milestone 4: risk scoring (score.rs)
aed45f1  Milestone 3: RustSec advisory lookup (advisories.rs)
00f32fe  chore: gitignore local LLM files
d9cf352  Initial commit: graph + crates.io + flat table (since replaced)
```

**Uncommitted local change:** `README.md` rewritten (simple user-facing docs).

---

## Repository layout

```
cargo-depcheck/
├── src/
│   ├── main.rs         Phase orchestration (5 phases, async)
│   ├── cli.rs          Clap args + cargo plugin wrapper
│   ├── graph.rs        cargo metadata → DependencyNode + BFS
│   ├── cratesio.rs     crates.io HTTP client + Metadata
│   ├── advisories.rs   RustSec DB fetch/cache/query
│   ├── score.rs        RiskScore computation + unit tests
│   └── report.rs       Terminal boxes + JSON serialization
├── Cargo.toml          rustsec 0.33, MSRV 1.70
├── Cargo.lock          committed (reproducible binary builds)
├── README.md           user docs (public)
├── HANDOVER.md         this file (gitignored, local only)
├── LICENSE-MIT / LICENSE-APACHE
├── .gitignore
└── .github/workflows/ci.yml   test + clippy + fmt + MSRV on push to main
```

---

## Architecture — five phases in main()

```
cargo depcheck [flags]
  │
  ├─ Phase 1: graph::load(manifest_path)
  │     cargo metadata → Vec<DependencyNode>
  │     BFS depth, is_direct, dependent_count
  │     build-only unreachable nodes dropped
  │
  ├─ Phase 2: concurrent crates.io fetch
  │     dedupe by crate name (API is per-name, not per-version)
  │     Arc<Client> + Semaphore(5) + JoinSet
  │     per-crate errors silently skipped
  │     → HashMap<String, Metadata>
  │
  ├─ Phase 3: RustSec advisory database (optional)
  │     skipped with --no-advisories
  │     load() = fetch + refresh cache (~/.cargo/advisory-db)
  │     load_cached() = --no-fetch, open local cache only
  │     runs in spawn_blocking (sync git ops off async runtime)
  │
  ├─ Phase 4: score + filter
  │     per node: advisories::lookup → score::compute → report::Finding
  │     filter: --ignore names, --threshold minimum score
  │     sort by total score descending
  │
  └─ Phase 5: report
        --json  → JSON on stdout, all progress on stderr
        --quiet → summary counts only
        default → boxed CRITICAL / WARN / NOTICE sections
```

---

## Module reference

### `cli.rs` — arguments

Cargo plugin pattern: outer `Cargo` struct, inner `Depcheck(Args)`.

| Flag | Default | Effect |
|------|---------|--------|
| `--manifest-path PATH` | nearest Cargo.toml | Target project |
| `--threshold SCORE` | 40.0 | Min score to include in output |
| `--ignore CRATE` | — | Repeatable; exclude crate names |
| `--json` | off | Pretty JSON on stdout |
| `--no-advisories` | off | Skip RustSec; security score = 0 |
| `--no-fetch` | off | Open cached advisory DB, no git pull |
| `--quiet` / `-q` | off | Summary line only |

### `graph.rs` — dependency graph

```rust
pub struct DependencyNode {
    pub name: String,
    pub version: semver::Version,
    pub is_direct: bool,        // depth == 1 from workspace member
    pub depth: usize,           // BFS from workspace roots
    pub dependent_count: usize,   // reverse-edge count (Normal deps only)
}
```

- Uses `cargo_metadata`, not raw `Cargo.lock` (needs edge info for weighting)
- Only `DependencyKind::Normal` edges counted
- Nodes with `depth == usize::MAX` dropped (build-script-only tools)
- Sorted by depth then name before return

### `cratesio.rs` — registry metadata

```rust
pub struct Metadata {
    pub newest_version: Version,
    pub max_stable_version: Option<Version>,
    pub updated_at: DateTime<Utc>,
}
```

`latest_stable()` → `max_stable_version` if set, else `newest_version`.

Fetch: `GET https://crates.io/api/v1/crates/{name}` with custom User-Agent.
Missing/private/git deps fail silently (no metadata → lag/maintenance score 0).

### `advisories.rs` — RustSec

| Function | Purpose |
|----------|---------|
| `load()` | `Database::fetch()` — clone/pull advisory-db from GitHub |
| `load_cached()` | `Database::open(~/.cargo/advisory-db)` — no network |
| `lookup(db, name, version)` | Advisories for exact resolved version |
| `index(db, nodes)` | `HashMap<String, Vec<Advisory>>` merged by crate name |

Query uses `Query::new()` with `Collection::Crates`, `withdrawn(false)`, and
**does not** filter out informational advisories — unmaintained flags are included.

**Important:** `rustsec` must be **0.33+** for CVSS 4.0 advisories in the current
advisory-db. Version 0.29 fails to parse them.

### `score.rs` — risk scoring

```rust
pub struct RiskScore {
    pub security: f64,          // 0–50
    pub version_lag: f64,       // 0–25
    pub maintenance: f64,       // 0–15
    pub graph_multiplier: f64,    // 1.0–2.0
    pub total: f64,             // (base × multiplier).min(100)
    pub level: RiskLevel,       // Critical / Warn / Low
}
```

**Security points** (max across advisories, capped at 50):

| Advisory type | Points |
|---------------|--------|
| CVSS Critical | 50 |
| CVSS High | 40 |
| CVSS Medium | 30 |
| CVSS Low | 20 |
| CVE without CVSS / None | 35 |
| Unmaintained (informational) | 20 |
| Other informational | 10 |

**Version lag** (0 if up to date):

- Major behind: `major_diff × 12.5`, cap 25
- Minor only (same major): `minor_diff × 2.5`, cap 25

**Maintenance** (0 if published today):

- Linear: `(days / 730) × 15`, cap 15

**Graph multiplier:**

- `1.0 + (dependent_count / max_dependents_in_tree)`
- Leaf with 0 dependents → ×1.0; highest fan-in → ×2.0

**Risk levels** (classification, independent of `--threshold` filter):

| Level | Score range |
|-------|-------------|
| Critical | > 70 |
| Warn | 40–70 |
| Low | < 40 |

`--threshold` controls **visibility**, not classification. With `--threshold 30`,
Low-level findings appear in a **NOTICE** section (only when threshold < 40).

**Unit tests:** 6 tests in `score.rs` covering lag, maintenance, multiplier, levels.

### `report.rs` — output

**Terminal:** boxed sections (77-char inner width) with score bar `████░░░░`.

| Section | When shown |
|---------|------------|
| CRITICAL | findings with level Critical |
| WARN | findings with level Warn |
| NOTICE | level Low AND `--threshold` < 40 |

Each finding shows reason lines:
- `advisory: RUSTSEC-…` or `flagged: unmaintained`
- version lag line (`N major/minor version(s) behind latest (have → latest)`)
- maintenance line (`last published N days/years ago`)
- graph line (`relied on by N crates in your graph`)

Direct deps are **bold** in the header row. Pad before colorizing (see decisions).

**JSON** (`--json`, schema version 1):

```json
{
  "schema_version": 1,
  "summary": { "critical": 0, "warnings": 0, "healthy": 366, "threshold": 40.0 },
  "findings": [{
    "name": "number_prefix",
    "version": "0.4.0",
    "score": 36.0,
    "level": "low",
    "is_direct": false,
    "dependent_count": 1,
    "components": { "security": 20.0, "version_lag": 0.0, "maintenance": 15.0, "graph_multiplier": 1.0 },
    "reasons": ["flagged: unmaintained", "last published 6 years ago", "..."],
    "advisories": ["unmaintained"]
  }]
}
```

Progress/header output goes to **stderr** in JSON mode via `status_print()` in
`main.rs`. JSON goes to **stdout** only.

**Unit tests:** 3 tests in `report.rs` (score bar, summarize, version lag line).

---

## Dependencies (Cargo.toml)

| Crate | Version | Purpose |
|-------|---------|---------|
| clap 4 | derive | CLI |
| tokio 1 | full | Async runtime |
| reqwest 0.12 | json, rustls-tls | crates.io HTTP (no OpenSSL) |
| serde / serde_json 1 | | JSON report |
| cargo_metadata 0.18 | | Dependency graph |
| rustsec 0.33 | git feature | Advisory DB |
| semver 1 | | Version compare |
| chrono 0.4 | serde | Publish dates |
| anyhow 1 | | Errors (binary, not library) |
| indicatif 0.17 | | Progress bar |
| colored 2 | | Terminal colors |

---

## Key implementation decisions — do not reverse

1. **`cargo_metadata` over `Cargo.lock` parsing** — need edges for dependent_count
2. **Normal dependency edges only** — dev/build deps excluded from graph weight
3. **Build-only nodes dropped** — `depth == usize::MAX` after BFS
4. **Pad strings before colorizing** — ANSI bytes break `{:<N}` width specs
5. **Semaphore cap of 5 for crates.io** — respectful rate limiting
6. **Per-crate fetch errors silently skipped** — git/path/private deps won't crash
7. **Cargo plugin naming** — binary `cargo-depcheck`, clap wrapper absorbs `depcheck`
8. **`spawn_blocking` for RustSec** — `Database::fetch()` is sync/git-based
9. **`rustsec 0.33`** — required for CVSS 4.0 entries in current advisory-db
10. **Risk level thresholds fixed at 40/70** — `--threshold` only filters display

---

## What is complete (Milestones 1–7)

- [x] `cargo run -- depcheck` end-to-end
- [x] Dependency graph (depth, direct/transitive, dependent_count, BFS)
- [x] Build-only dep filtering
- [x] Concurrent crates.io fetch with progress bar
- [x] RustSec advisory fetch, cache, version-specific lookup
- [x] Risk scoring with graph weight multiplier
- [x] Grouped terminal report (CRITICAL / WARN / NOTICE)
- [x] Per-finding reason lines + score bar
- [x] CLI flags: threshold, ignore, json, no-advisories, no-fetch, quiet
- [x] Versioned JSON output for CI
- [x] Unit tests in score.rs and report.rs (9 total)
- [x] CI: test + clippy + fmt + MSRV 1.70 on Linux/macOS/Windows

**Removed:** the original flat table (NAME / HAVE / LATEST / DAYS OLD / DEPENDENTS)
from Milestone 1–2. It was replaced by the scored report in Milestone 5.

---

## What is NOT built — future work

These were mentioned in old README drafts but do **not** exist in code:

| Feature | Notes |
|---------|-------|
| `[package.metadata.depcheck]` config | threshold/ignore in Cargo.toml |
| Integration test fixtures | `tests/fixtures/` with stubbed HTTP/DB |
| `--fix` flag | Open crates.io / RustSec pages in browser |
| Delta mode | Compare against previous run baseline |
| SARIF output | GitHub Advanced Security integration |
| GitHub repo activity signal | Last commit, issue count as maintenance hint |
| crates.io publish | Not on crates.io yet; Cargo.toml URLs still say `your-username` in places |

When adding any of these, update `README.md` (public) and this file (local).

---

## Known quirks / edge cases

- **Empty report at default threshold:** this project's own deps mostly score
  < 40. Use `--threshold 30` to see `number_prefix` and `proc-macro-error2`
  (unmaintained, ~35 pts) in the NOTICE section.
- **Summary "healthy" count:** `total_deps - critical - warnings`. Low/NOTICE
  items still count as healthy in the summary line.
- **`RiskLevel` vs `--threshold`:** a crate can score 35 (Low), pass `--threshold 30`,
  appear in NOTICE, but still count toward "healthy" in the summary.
- **Same crate, multiple versions:** graph has one node per resolved package ID.
  crates.io metadata is keyed by name only (latest stable shared across versions).
- **First `--no-fetch` run fails** if advisory-db cache doesn't exist yet.

---

## Commands

```sh
# Build & test
cargo build
cargo test          # 9 unit tests
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check

# Run
cargo run -- depcheck
cargo run -- depcheck --manifest-path /path/to/Cargo.toml
cargo run -- depcheck --threshold 30
cargo run -- depcheck --json --threshold 70 > report.json
cargo run -- depcheck --quiet
cargo run -- depcheck --no-advisories
cargo run -- depcheck --no-fetch          # offline advisory lookup
cargo run -- depcheck --ignore foo --ignore bar

# Install locally
cargo install --path .
```

---

## Style rules for this codebase

- Comments explain **why**, not what. No narration of obvious code.
- `anyhow` for errors — this is a binary, not a library.
- No careless `unwrap()` on fallible paths. Use `?` or `.expect("invariant")`.
- Pad strings before applying `colored` styles.
- One responsibility per source file — don't bloat `main.rs`; add modules.
- Only add tests that cover real scoring/rendering logic, not trivial asserts.
- Minimize diff scope — don't refactor unrelated code in the same PR.
- Do not commit this file — it's in `.gitignore` by design.

---

## Teaching notes (for LLM sessions with Debaraj)

When continuing work with Debaraj:

1. **Explain before generating** — walk through the approach, then code in small steps.
2. **Rust concepts to reinforce** — ownership, `Result`/`?`, async vs blocking,
   `HashMap`/`Vec` patterns, trait derives (`Serialize`, `Parser`).
3. **Good next tasks** — config file support, integration test fixtures, fix
   Cargo.toml repository URLs, publish to crates.io.
4. **Avoid** — large rewrites, new dependencies without discussion, reversing
   the ten implementation decisions above.
