# cargo-depcheck

[![CI](https://github.com/debrajrout/cargo-depcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/debrajrout/cargo-depcheck/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cargo-depcheck.svg)](https://crates.io/crates/cargo-depcheck)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV: 1.91](https://img.shields.io/badge/rustc-1.91%2B-orange.svg)](https://releases.rs/docs/1.91.0/)

**Your dependency tree has 300 crates. You have time for three.**

`cargo audit` finds CVEs. `cargo outdated` finds stale versions. Both give
you a list — neither tells you what to fix **first**.

`cargo depcheck` ranks every problem by how much it actually matters: how
severe it is, *and* how much of your tree depends on the crate it's in.

```sh
cargo install cargo-depcheck
cd your-rust-project
cargo depcheck
```

---

## What you get

Real output, from running it on this repo:

```
$ cargo depcheck

Found 345 dependencies  (16 direct · 329 transitive)

  ✓ RustSec advisory database ready  (0 affected)
  0 critical  ·  3 warnings  ·  342 healthy
  ⚠ 9 crates resolve at multiple versions: bitflags (1.3.2, 2.13.0), cpufeatures (0.2.17, 0.3.0), getrandom (0.2.17, 0.4.3) (+ 6 more)

┌─────────────────────────────────────────────────────────────────────────────┐
│  WARN                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ wasi 0.11.1+wasi-snapshot-preview1        46 [W] ██████░░░░░░               │
│   3 breaking version(s) behind latest (0.11.1+wasi-snapshot-preview1 →      │
│        0.14.7+wasi-0.2.4)                                                   │
│   last published 342 days ago                                               │
│   relied on by 25 crates in your graph, directly or transitively            │
├─────────────────────────────────────────────────────────────────────────────┤
│ allocator-api2 0.2.21                     45 [W] █████░░░░░░░               │
│   2 breaking version(s) behind latest (0.2.21 → 0.4.0)                      │
│   last published 255 days ago                                               │
│   relied on by 37 crates in your graph, directly or transitively            │
├─────────────────────────────────────────────────────────────────────────────┤
│ windows-sys 0.52.0                        45 [W] █████░░░░░░░               │
│   9 breaking version(s) behind latest (0.52.0 → 0.61.2)                     │
│   last published 321 days ago                                               │
│   relied on by 15 crates in your graph, directly or transitively            │
└─────────────────────────────────────────────────────────────────────────────┘
```

Every finding tells you **why** it ranked where it did.

| Section | Score | What to do |
|---------|-------|------------|
| **CRITICAL** | > 70 | Fix soon |
| **WARN** | 40–70 | Worth a look this sprint |
| *(hidden)* | < 40 | Use `--threshold` to see these |

Direct dependencies are **bold**. Severity is never color-only — each row
also carries a `[C]` / `[W]` / `[N]` tag, so it stays readable in
grayscale, piped through a color stripper, or with `--color never`.

---

## Everyday use

```sh
cargo depcheck                        # the default report
cargo depcheck --threshold 30         # show lower-scoring issues too
cargo depcheck --ignore libc          # hide a crate you've already triaged
cargo depcheck --quiet                # just: 0 critical · 3 warnings · 342 healthy
cargo depcheck --json > report.json   # machine-readable
```

**In CI**, let the exit code do the work — no `jq`, no output parsing:

```sh
cargo depcheck --fail-on critical
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Clean, or nothing reached your `--fail-on` level |
| `1` | Something at or above `--fail-on` was found |
| `2` | Usage error (bad flag, bad config) |
| `3` | Couldn't reach crates.io — report is incomplete (`--allow-incomplete` to allow) |

First run needs network (the crates.io sparse index and the RustSec
advisory DB). Both land in the caches `cargo` already uses, so later runs
are fast — and `--offline` skips the network entirely, using whatever
both caches already hold. Anything not yet cached is reported as
unchecked rather than quietly assumed healthy.

---

## GitHub Action

Downloads a prebuilt binary — no source build in your CI:

```yaml
- uses: debrajrout/cargo-depcheck@v1
  with:
    fail-on: critical    # none | warn | critical
```

It writes a summary table to the job summary, and exposes `critical`,
`warnings`, `unknown`, and `healthy` as step outputs:

```yaml
- uses: debrajrout/cargo-depcheck@v1
  id: depcheck
  with:
    fail-on: none    # don't fail here — decide from the outputs instead
- run: echo "found ${{ steps.depcheck.outputs.critical }} critical issues"
```

**Send findings to the Security tab** with SARIF:

```yaml
permissions:
  security-events: write

steps:
  - uses: debrajrout/cargo-depcheck@v1
    with:
      sarif: true
      fail-on: none
```

The upload runs before `fail-on` can fail the job, so findings reach the
Security tab either way. Every finding gets a sortable `security-severity`
— including the ~65% of RustSec advisories that have no CVSS score.

Other inputs: `version`, `manifest-path`, `threshold`, `ignore`,
`allow-incomplete`, `summary`, `sarif-category`. See [action.yml](action.yml).

---

## Configuration file

Commit your policy so every developer and CI job uses the same settings:

```toml
[package.metadata.depcheck]
threshold = 30
fail_on = "critical"

[[package.metadata.depcheck.ignore]]
crate = "openssl"
reason = "vendored, patched internally"
expires = "2027-01-01"   # optional — omit for a permanent ignore
```

- CLI flags beat the config file. `CARGO_DEPCHECK_THRESHOLD` and
  `CARGO_DEPCHECK_FAIL_ON` work too.
- `--ignore` **adds to** the config's ignore list rather than replacing it.
- Once `expires` passes, the ignore stops applying and the crate is
  reported again, with a warning pointing at the stale entry — so muting
  something can't silently become permanent.
- A workspace can use `[workspace.metadata.depcheck]` as a fallback for
  members that don't define their own.

---

## How scoring works

Every crate scores 0–100:

```text
score = (security + version_lag + maintenance) × graph_weight
```

| Signal | Max | Source |
|--------|-----|--------|
| Security | 50 | RustSec advisories, or a yanked version |
| Version lag | 25 | Releases behind the latest stable |
| Maintenance | 15 | Days since last publish (caps at 2 years) |
| **× Graph weight** | 1.0–2.0 | How many crates depend on this one |

**That multiplier is the point.** A stale leaf crate nobody imports scores
lower than the same staleness in a crate holding up 30 others.

Three things worth knowing:

- **Version lag follows Cargo's compatibility rule.** Below 1.0, `0.3.1` →
  `0.4.0` is a *breaking* gap, scored like `1.0.0` → `2.0.0` — not a
  routine minor bump.
- **Advisories without a CVSS score still get ranked**, by category rather
  than a flat guess. That's 65% of the RustSec database.
- **Graph weight is absolute**, not relative to your project — so a
  threshold you tune once means the same thing everywhere.

→ **[Full scoring reference](docs/SCORING.md)** for the exact point values
and the reasoning behind them.

---

## All flags

| Flag | What it does |
|------|--------------|
| `--threshold N` | Report crates scoring ≥ N (default: 40) |
| `--ignore CRATE` | Skip a crate — repeat for multiple |
| `--fail-on LEVEL` | Exit non-zero at `none` \| `warn` \| `critical` (default: `none`) |
| `--format FORMAT` | `human` \| `json` \| `sarif` |
| `--json` | Alias for `--format json` |
| `--quiet` | Summary line only |
| `--manifest-path PATH` | Point at another project |
| `--color WHEN` | `auto` \| `always` \| `never` (respects `NO_COLOR`) |
| `--offline` | Local caches only, no network at all (implies the cached advisory DB) |
| `--locked` / `--frozen` | Require an up-to-date `Cargo.lock` |
| `--no-advisories` | Skip RustSec — version and maintenance only |
| `--no-fetch` | Use the cached advisory DB, no git pull |
| `--allow-incomplete` | Exit 0 even if some crates couldn't be checked |
| `--include-build` | Also check build-script (`build.rs`) dependencies |
| `--include-dev` | Also check dev-dependencies |

`--json` output carries `schema_version` (currently `2`) plus
`tool_version`, `generated_at`, `project`, and `advisory_db_commit`, so a
stored report still makes sense when you read it back later.

<details>
<summary><b>Shell completions and man page</b></summary>

```sh
cargo depcheck completions bash > /usr/local/etc/bash_completion.d/cargo-depcheck
cargo depcheck completions zsh  > "${fpath[1]}/_cargo-depcheck"
cargo depcheck completions fish > ~/.config/fish/completions/cargo-depcheck.fish

cargo depcheck mangen > /usr/local/share/man/man1/cargo-depcheck.1
```

`elvish` and `powershell` work too. Every [release archive][releases] also
ships pre-generated copies of all five, alongside the man page.

[releases]: https://github.com/debrajrout/cargo-depcheck/releases

</details>

<details>
<summary><b>Building from source</b></summary>

```sh
git clone https://github.com/debrajrout/cargo-depcheck
cd cargo-depcheck
cargo install --path .
```

Needs Rust 1.91+.

</details>

---

## Compared to other tools

| | depcheck | audit | outdated | deny |
|---|:---:|:---:|:---:|:---:|
| Security advisories | ✓ | ✓ | | ✓ |
| Version lag | ✓ | | ✓ | |
| Maintenance age | ✓ | | | |
| **Ranked by graph impact** | ✓ | | | |
| JSON output | ✓ | ✓ | | ✓ |
| License / policy enforcement | | | | ✓ |

They're complementary, not competing. Use **audit** to block merges on
known CVEs, **deny** for license policy, and **depcheck** to decide what to
upgrade next.

---

## Contributing

Whether you fix a typo, add a test, or redesign scoring — there's a place
for your work.

| I want to… | Start here |
|------------|------------|
| Report a bug | [Bug report](https://github.com/debrajrout/cargo-depcheck/issues/new?template=bug_report.yml) |
| Suggest a feature | [Feature request](https://github.com/debrajrout/cargo-depcheck/issues/new?template=feature_request.yml) |
| Write code | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Find an easy task | [`good first issue`](https://github.com/debrajrout/cargo-depcheck/labels/good%20first%20issue) |
| Ask a question | [Discussions](https://github.com/debrajrout/cargo-depcheck/discussions) |

**Scoring feedback is especially welcome** — if a ranking feels wrong for
your project, that's a bug report worth filing.

[Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md)

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
