# cargo-depcheck

[![CI](https://github.com/debrajrout/cargo-depcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/debrajrout/cargo-depcheck/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV: 1.91](https://img.shields.io/badge/rustc-1.91%2B-orange.svg)](https://releases.rs/docs/1.91.0/)

**Your dependency tree has 300 crates. You have time for three.**

`cargo audit` finds CVEs. `cargo outdated` finds stale versions. Both dump lists — neither tells you *what to fix first*.

`cargo depcheck` reads your full resolved graph, checks RustSec + crates.io, and ranks every problem by **how much it actually matters**: advisories, version lag, maintenance age, and how many other crates lean on it.

One command. One ranked report. Start at the top.

---

## Try it

```sh
cargo install cargo-depcheck   # or clone & build below
cd your-rust-project
cargo depcheck
```

First run needs network (crates.io's sparse index + RustSec advisory DB). Crate metadata is cached in the same `~/.cargo` index cache your regular `cargo` commands already use, and the advisory DB is cached at `~/.cargo/advisory-db`. Once both are warm, `--offline` skips the network entirely.

**From source:**

```sh
git clone https://github.com/debrajrout/cargo-depcheck
cd cargo-depcheck
cargo install --path .
# or: cargo run -- depcheck --manifest-path /path/to/project/Cargo.toml
```

**Needs:** Rust 1.91+, `cargo` on your PATH.

---

## What you get

```
$ cargo depcheck

Found 366 dependencies  (12 direct · 354 transitive)

  ✓ RustSec advisory database ready  (2 affected)
  0 critical  ·  0 warnings  ·  366 healthy

┌─────────────────────────────────────────────────────────────────────────────┐
│  WARN                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ openssl 0.10.45                            94 ████████████                  │
│   advisory: RUSTSEC-2023-0044                                               │
│   3 major version(s) behind latest (0.10.45 → 3.0.0)                        │
│   last published 2 years ago                                                │
│   relied on by 23 crates in your graph                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

Each finding shows **why** it ranked where it did — not just a version number in a table.

| Section | Score | Meaning |
|---------|-------|---------|
| **CRITICAL** | > 70 | Fix soon — security + graph weight |
| **WARN** | 40–70 | Worth a look this sprint |
| *(hidden)* | < 40 | Omitted by default — use `--threshold` to reveal |

Direct dependencies appear **bold** in the report.

---

## Flags worth knowing

| Flag | What it does |
|------|----------------|
| `--threshold 30` | Show anything scoring ≥ 30 (default: 40) |
| `--ignore foo` | Skip a crate — repeat for multiple |
| `--quiet` | Summary line only |
| `--json` | CI-friendly JSON on stdout (progress on stderr) — alias for `--format json` |
| `--format <human\|json\|sarif>` | Output format. `sarif` targets GitHub code scanning and similar tools |
| `--no-advisories` | Skip RustSec — version/maintenance only |
| `--no-fetch` | Use cached advisory DB, no git pull |
| `--manifest-path PATH` | Point at another project |
| `--fail-on <none\|warn\|critical>` | Exit non-zero when a finding at/above this level is present (default: `none`) |
| `--allow-incomplete` | Exit 0 even if crates.io metadata couldn't be fetched for some dependencies |
| `--color <auto\|always\|never>` | Control colored output (respects `NO_COLOR` / `CLICOLOR_FORCE` in `auto`) |
| `--offline` | Use only the local sparse-index cache for crate metadata — no network |

```sh
cargo depcheck --threshold 30              # see lower-scoring issues
cargo depcheck --ignore number_prefix      # mute a known false positive
cargo depcheck --json --threshold 70 > report.json
cargo depcheck --quiet                     # 2 critical · 6 warnings · 239 healthy
```

Run `cargo depcheck --help` for the full list.

---

## How scoring works

Every crate gets 0–100 points from three signals, then multiplied by graph weight:

| Signal | Max | Source |
|--------|-----|--------|
| Security | 50 | RustSec advisories (CVE severity, unmaintained, unsound) or a yanked version — whichever is worse |
| Version lag | 25 | Breaking / compatible / patch releases behind latest stable |
| Maintenance | 15 | Days since last crates.io publish (cap: 2 years) |
| **× Graph weight** | 1.0–2.0 | More things depend on it → higher urgency |

A stale leaf at the edge of your tree scores lower than the same stale crate holding up 30 others. That's the point.

**Version lag follows Cargo's own compatibility rule, not raw major/minor
arithmetic.** Below 1.0, the *minor* version is the breaking axis — `0.3.1`
to `0.4.0` is exactly as incompatible as `1.0.0` to `2.0.0`, and is scored
the same way. Three tiers, most severe first: breaking releases behind
(12.5 pts each, capped at 25), then compatible releases behind (2.5 pts
each, capped at 25), then patch releases behind (0.5 pts each, capped at
5 — visible, since a security fix often ships as a patch, but never able
to outweigh a real breaking-version gap).

**When a RustSec advisory has no CVSS score, severity comes from its
category instead of a flat guess.** 65% of advisories in the database
(789 of 1,206) have no CVSS score at all, so this is the common case, not
an edge case. Categories are ranked by this project's own judgment of
real-world impact (RustSec doesn't rank them itself): malicious code and
arbitrary code execution score highest; privilege escalation and memory
corruption next; crypto failures, injection, thread-safety bugs, and file
disclosure in the middle; memory exposure and denial-of-service lowest. An
advisory with several categories takes the worst one; one with none at all
gets a conservative Medium-equivalent default.

**Graph weight is absolute, not relative to your project.** It's a
saturating function of how many crates depend on this one — directly or
transitively, so a crate with few direct dependents that sit underneath
something widely used still gets credit for its real blast radius:

```text
weight(n) = 1.0 + ln(1 + n) / (ln(1 + n) + 4)
```

| Transitive dependents | Weight |
|---|---|
| 0 | 1.00 |
| 5 | 1.31 |
| 20 | 1.43 |
| 100 | 1.54 |
| 1000 | 1.63 |

The same crate in the same state scores identically no matter what else is
in your dependency tree — earlier versions computed this relative to your
project's single most-depended-on crate, which meant the same crate could
score up to 85% higher in a smaller project purely because of an unrelated
crate elsewhere in the tree. `--threshold` now means the same thing in
every project.

---

## GitHub Actions

The official action downloads a prebuilt binary — no `cargo install` source
build in your CI:

```yaml
- uses: debrajrout/cargo-depcheck@v1
  with:
    fail-on: critical   # none | warn | critical (default: critical)
```

It writes a summary table to the job summary and exposes `critical`,
`warnings`, `unknown`, and `healthy` as step outputs for use in later steps:

```yaml
- uses: debrajrout/cargo-depcheck@v1
  id: depcheck
  with:
    fail-on: none   # don't fail here — decide based on the output instead
- run: echo "found ${{ steps.depcheck.outputs.critical }} critical issues"
```

All CLI flags are available as inputs: `manifest-path`, `threshold`,
`ignore` (space-separated), `allow-incomplete`, and `summary` (set to
`false` to skip the job-summary table).

**SARIF upload to the Security tab:**

```yaml
permissions:
  security-events: write   # required for the SARIF upload step

steps:
  - uses: debrajrout/cargo-depcheck@v1
    with:
      sarif: true
      fail-on: none   # let the Security tab show findings even on a clean job
```

The upload happens before `fail-on` can fail the job, so findings still
reach the Security tab even when the job itself fails. Every finding gets
a `security-severity` GitHub can sort by — including ones with no CVSS
score, which is the majority of RustSec's database (see "How scoring
works" above).

## CI without the Action

```yaml
- run: cargo install cargo-depcheck
- run: cargo depcheck --fail-on critical
```

No `jq`, no exit-code plumbing — `--fail-on` does it:

| Exit code | Meaning |
|-----------|---------|
| `0` | Clean, or no finding reached `--fail-on`'s level |
| `1` | A finding at or above `--fail-on`'s level is present |
| `2` | Usage error (bad flag or argument) |
| `3` | crates.io metadata couldn't be fetched for some dependencies — the report is incomplete (see `--allow-incomplete`) |

`--fail-on` accepts `none` (default), `warn`, or `critical`. JSON includes `"schema_version": 1` so scripts can pin against it.

---

## vs the usual tools

| | depcheck | audit | outdated | deny |
|---|:---:|:---:|:---:|:---:|
| Security advisories | ✓ | ✓ | | ✓ |
| Version lag | ✓ | | ✓ | |
| Maintenance age | ✓ | | | |
| **Ranked by graph impact** | ✓ | | | |
| JSON output | ✓ | ✓ | | ✓ |
| Policy / license enforcement | | | | ✓ |

Use **audit** to block merges on known CVEs. Use **depcheck** weekly to decide what to upgrade next.

---

## Contributing

**Open source and open to you.** Whether you fix a typo, add a test, or redesign scoring — there is a place for your work.

| I want to… | Start here |
|------------|------------|
| Report a bug | [Open a bug report](https://github.com/debrajrout/cargo-depcheck/issues/new?template=bug_report.yml) |
| Suggest a feature | [Open a feature request](https://github.com/debrajrout/cargo-depcheck/issues/new?template=feature_request.yml) |
| Write code | Read [CONTRIBUTING.md](CONTRIBUTING.md) — setup, roles, PR process |
| Find easy tasks | Issues labeled [`good first issue`](https://github.com/debrajrout/cargo-depcheck/labels/good%20first%20issue) |
| Ask a question | [GitHub Discussions](https://github.com/debrajrout/cargo-depcheck/discussions) |

**Roles:** User → Reporter → Contributor → Triager → Maintainer. You pick where to start; no permission needed to open an issue or PR. Full details in [CONTRIBUTING.md](CONTRIBUTING.md).

**Community:** [Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md)

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
