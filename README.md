# cargo-depcheck

[![CI](https://github.com/debrajrout/cargo-depcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/debrajrout/cargo-depcheck/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cargo-depcheck.svg)](https://crates.io/crates/cargo-depcheck)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV: 1.91](https://img.shields.io/badge/rustc-1.91%2B-orange.svg)](https://releases.rs/docs/1.91.0/)

**Your dependency tree has 300 crates. You have time for three.**

`cargo-depcheck` is a dependency-health report for Rust projects. It combines
RustSec advisories, version lag, maintenance activity, and dependency-graph
impact into one ranked list.

`cargo audit` answers “is this vulnerable?” and `cargo outdated` answers “is
this old?”. `cargo depcheck` answers the follow-up question:

> Which dependency deserves attention first?

<img src="https://raw.githubusercontent.com/debrajrout/cargo-depcheck/main/docs/assets/demo-report.svg" alt="cargo depcheck ranking the three highest-scoring dependencies in its own dependency graph" width="820">

**[Documentation](https://debrajrout.github.io/cargo-depcheck/)** ·
[How scoring works](https://debrajrout.github.io/cargo-depcheck/scoring.html) ·
[Compared to cargo-audit, cargo-outdated, and cargo-deny](https://debrajrout.github.io/cargo-depcheck/vs-cargo-audit.html)

## Quick start

```sh
cargo install cargo-depcheck
cd your-rust-project
cargo depcheck
```

The first run downloads registry metadata and the RustSec advisory database.
Later runs reuse Cargo's caches.

## Reading the report

The report is a ranked list. Direct dependencies are **bold**, and every row
carries the score, a severity tag, and the reasons behind it:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│  WARN                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ wasi 0.11.1+wasi-snapshot-preview1        46.4 [W] ██████░░░░░░             │
│   3 breaking version(s) behind latest (0.11.1+wasi-snapshot-preview1 →      │
│        0.14.7+wasi-0.2.4)                                                   │
│   latest crate release published 342 days ago                               │
│   relied on by 25 crates in your graph, directly or transitively            │
└─────────────────────────────────────────────────────────────────────────────┘
```

The score is not a vulnerability severity score. It is a prioritization
score: a stale crate deep in the graph can rank above a stale leaf because
more of the project depends on it.

| Level | Score | Suggested response |
|---|---:|---|
| **CRITICAL** | > 70 | Investigate promptly |
| **WARN** | 40–70 | Plan an upgrade or document why it can wait |
| **NOTICE** | < 40 | Low-priority signal; hidden by default |

Direct dependencies are **bold**. Severity is never color-only — each row
also carries a `[C]` / `[W]` / `[N]` tag, so it stays readable in
grayscale, piped through a color stripper, or with `--color never`. Bold
identifies ownership; it does not add points to the score.

`notice` means “below the warning boundary”, not “broken”. Because even a
small amount of publish age produces a non-zero score, a mature project may
have many notices and few score-zero `healthy` crates. The default report
hides those notices so the actionable items remain short.

## Common workflows

```sh
cargo depcheck                          # the default report
cargo depcheck --top 5                  # only the five worst
cargo depcheck --threshold 30           # show lower-scoring issues too
cargo depcheck --threshold 0            # enumerate the complete checked graph
cargo depcheck --ignore libc            # hide a crate you've already triaged
cargo depcheck --quiet                  # summary counts only
cargo depcheck --json > report.json     # machine-readable
cargo depcheck --format markdown        # for a PR comment or job summary
cargo depcheck explain wasi             # why does this crate score that?
```

`--threshold` and `--top` control what is printed, not what CI evaluates. A
warning hidden by `--threshold 80` still makes `--fail-on warn` exit non-zero.
Summary buckets are also threshold-independent: `notice` means a non-zero
score below WARN, `healthy` means a checked score of zero, `unknown` means
registry metadata was unavailable, and path/git dependencies are
`not_applicable`.

## Why did this crate score that?

`explain` shows the whole derivation — each signal against its cap with the
evidence behind it, the graph multiplier and the count it came from, and the
arithmetic that produces the total:

```sh
cargo depcheck explain wasi
```

<img src="https://raw.githubusercontent.com/debrajrout/cargo-depcheck/main/docs/assets/demo-explain.svg" alt="cargo depcheck explain showing wasi's score broken down by signal, the projected score after upgrading, and the dependency paths that pull it in" width="820">

Three things it answers that the ranked report can't:

- **Which of your own dependencies pulled this in.** A transitive finding is
  only actionable once you know the direct dependency behind it, so the paths
  are printed shortest-first, with `[build]` or `[dev]` marking the hop where
  a path crosses a build-script or dev-only edge. (`cargo tree -i wasi` shows
  the same relationships from Cargo's own view.)
- **Whether upgrading would actually help.** The crate is re-scored at each
  upgrade target — within its Cargo compatibility line, and at the latest
  stable — against the same advisory database, rather than assuming an upgrade
  only cancels version lag.
- **Why a crate you expected isn't listed.** Being below your threshold,
  suppressed by an ignore rule, or excluded as a dev/build dependency is
  stated outright.

Add `--format json` for the same breakdown as data, or `--max-paths N` to see
more paths. `explain` is a diagnostic: it never fails a build, whatever it
finds.

## Adopt CI on a project that already has findings

A project with an existing backlog fails `--fail-on warn` on day one, for
reasons nobody in this PR introduced. A baseline separates the two:

```sh
cargo depcheck --write-baseline depcheck-baseline.json   # once, then commit it
cargo depcheck --baseline depcheck-baseline.json --fail-on warn
```

The full report is still shown, with each finding marked `known` or `new`, and
only the new ones can fail the build. A finding is new if the baseline has no
entry for that crate **at that version**, if it carries an advisory the
baseline didn't, or if it has crossed into a higher severity.

Score drift alone never counts as new: maintenance points grow every day a
crate isn't republished, so matching on exact scores would report every
untouched dependency as new on the next run.

The baseline file is an ordinary JSON report, so any report you've already
archived works as one. Write it at the same `--threshold` you gate on — a
mismatch is warned about, since a baseline can only contain what its own run
reported. `--top` is refused with `--write-baseline`, because a truncated
baseline would report everything it omitted as new next time.

## Apply safe lockfile upgrades

After reviewing the report, ask Cargo to apply only upgrades that stay on
each resolved crate's current compatibility line:

```sh
cargo depcheck upgrade --compatible --dry-run
cargo depcheck upgrade --compatible
```

The dry run asks Cargo to validate every exact `name@current → target` update
and does not write `Cargo.lock`. A real run:

- considers non-ignored registry findings visible at the configured threshold;
- allows compatible security and yanked-version fixes, regardless of severity;
- changes `Cargo.lock` only — never `Cargo.toml`;
- runs `cargo check --workspace`; and
- restores the original lockfile if an update or verification fails.

Cargo's compatibility rules are followed exactly: `1.x` stays on the same
major, `0.y` stays on the same minor, and `0.0.z` does not move automatically.
Breaking-only and manifest-blocked updates are skipped with guidance. Use
`--no-verify` only when you intend to verify the workspace yourself.
`--locked`, `--frozen`, `--offline`, JSON, and SARIF are intentionally
rejected for this mutating workflow.

## CI and automation

Let the exit code enforce policy; there is no need to parse terminal output:

```sh
cargo depcheck --fail-on critical
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Clean, or nothing reached your `--fail-on` level |
| `1` | Something at or above `--fail-on` was found |
| `2` | Usage error (bad flag, bad config) |
| `3` | Registry or advisory data was incomplete (`--allow-incomplete` to allow) |

First run needs network (the crates.io sparse index and the RustSec
advisory DB). Both land in the caches `cargo` already uses, so later runs
are fast — and `--offline` skips the network entirely, using whatever
both caches already hold. Any registry dependency not yet cached is reported
as unknown and marks the run incomplete rather than being quietly assumed
healthy. Path and git dependencies are counted separately as not applicable.

### GitHub Action

Downloads a prebuilt binary — no source build in your CI:

```yaml
- uses: debrajrout/cargo-depcheck@v1
  with:
    fail-on: critical    # none | warn | critical
```

It writes the report to the job summary, and exposes `critical`,
`warnings`, `notices`, `unknown`, `not_applicable`, `ignored`, and `healthy`
as step outputs:

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

**Comment the report on pull requests**, updating one comment instead of
adding a new one on every push:

```yaml
permissions:
  pull-requests: write

steps:
  - uses: debrajrout/cargo-depcheck@v1
    with:
      comment: true
      top: 10
      baseline: depcheck-baseline.json   # optional: mark what's new in this PR
```

Like the SARIF upload, the comment is posted before `fail-on` can fail the
job — a failing check is exactly when the reviewer needs the report. If the
job lacks `pull-requests: write` (the default for a pull request from a fork),
the comment is skipped with a warning rather than failing the build. Set
`comment-key` when one workflow runs the action more than once, so each run
updates its own comment instead of overwriting a sibling's.

Other inputs: `version`, `manifest-path`, `threshold`, `top`, `baseline`,
`ignore`, `allow-incomplete`, `summary`, `sarif-category`, `comment-key`.
Outputs also include `report-path`, `markdown-path`, and `comment-url`.
See [action.yml](action.yml).

## Project configuration

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

See the **[full scoring reference](docs/SCORING.md)** for exact point values
and design rationale.

## Command reference

Run `cargo depcheck --help` for the version installed on your machine.

| Flag | What it does |
|------|--------------|
| `--threshold N` | Display crates scoring ≥ N (default: 40); does not weaken `--fail-on` |
| `--top N` | Display only the N highest-scoring crates; does not weaken `--fail-on` |
| `--ignore CRATE` | Skip a crate — repeat for multiple |
| `--fail-on LEVEL` | Exit non-zero at `none` \| `warn` \| `critical` (default: `none`) |
| `--baseline PATH` | Compare against a stored report; `--fail-on` sees only new findings |
| `--write-baseline PATH` | Write this run's report for a later `--baseline` to compare against |
| `--format FORMAT` | `human` \| `json` \| `sarif` \| `markdown` |
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

Run `cargo depcheck explain --help` and `cargo depcheck upgrade --help` for
the per-command options. The upgrade command is intentionally local and
human-focused; the GitHub Action continues to analyze without modifying a
checkout.

`--json` output carries `schema_version` (currently `4`) plus
`tool_version`, `generated_at`, `project`, and `advisory_db_commit`, so a
stored report still makes sense when you read it back later. Schema 3
introduced exclusive `notices`, `not_applicable`, and `ignored` summary
buckets and reserved `healthy` for checked dependencies whose score is zero;
schema 4 adds an optional per-finding `baseline` field (`"new"` or `"known"`)
that appears only when a run compared against `--baseline`, so a report
produced without one is byte-identical to schema 3.

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

## Compared to other tools

| | depcheck | audit | outdated | deny |
|---|:---:|:---:|:---:|:---:|
| Security advisories | ✓ | ✓ | | ✓ |
| Version lag | ✓ | | ✓ | |
| Maintenance age | ✓ | | | |
| **Ranked by graph impact** | ✓ | | | |
| Per-crate score breakdown | ✓ | | | |
| Baseline / fail only on new | ✓ | | | |
| JSON output | ✓ | ✓ | | ✓ |
| SARIF / Security tab | ✓ | | | |
| License / policy enforcement | | | | ✓ |

They are complementary: use **audit** to block known vulnerabilities,
**deny** for license and policy enforcement, and **depcheck** to prioritize
dependency maintenance.

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

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
