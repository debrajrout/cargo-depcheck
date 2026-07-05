# Contributing to cargo-depcheck

Thank you for considering a contribution. Every issue filed, doc fix, test
added, and PR reviewed makes this tool more useful for the Rust community.

**cargo-depcheck** is intentionally small and focused — you do not need to
understand the entire codebase to help. Many valuable contributions take less
than an hour.

---

## Table of contents

- [Community standards](#community-standards)
- [Roles in this project](#roles-in-this-project)
- [Ways to contribute (pick your path)](#ways-to-contribute-pick-your-path)
- [Development setup](#development-setup)
- [Project structure](#project-structure)
- [Coding guidelines](#coding-guidelines)
- [Submitting changes](#submitting-changes)
- [Issue guidelines](#issue-guidelines)
- [Review process](#review-process)
- [Recognition](#recognition)

---

## Community standards

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating,
you agree to uphold it. Be kind, be direct, assume good intent.

---

## Roles in this project

You do not need permission to take on a role — just start at the level that
matches your comfort and time.

### 👤 User

**Who:** Anyone running `cargo depcheck` on their projects.

**You can:**
- Open issues when something is confusing, wrong, or missing
- Share example output (redact private crate names if needed)
- Suggest scoring tweaks with real-world reasoning
- Star the repo and recommend it if you find it useful

**You do not need to:** write code, know Rust, or understand the graph algorithm.

---

### 🐛 Reporter

**Who:** Users who turn problems into actionable GitHub issues.

**You can:**
- File [bug reports](https://github.com/debrajrout/cargo-depcheck/issues/new?template=bug_report.yml) with reproduction steps
- File [feature requests](https://github.com/debrajrout/cargo-depcheck/issues/new?template=feature_request.yml) explaining the use case
- Comment on existing issues with "+1", counter-examples, or extra context
- Verify fixes on `main` after a PR merges

**Good issue =** clear title, what you expected, what happened, version/OS, minimal repro.

---

### 🛠 Contributor

**Who:** Developers submitting code, tests, or docs via pull request.

**You can:**
- Fix bugs labeled `good first issue` or `help wanted`
- Add unit or integration tests
- Improve README, CONTRIBUTING, error messages, or CLI help text
- Implement features that have an approved issue (see below)

**Before a large PR:** open an issue first so design direction is agreed. Small
fixes (typos, clippy warnings, doc clarifications) do not need prior approval.

**Your PR should:**
- Pass CI (build, test, clippy, fmt on Linux/macOS/Windows)
- Stay focused — one logical change per PR
- Include a clear description linking to the issue (if any)

---

### 🔍 Triager

**Who:** Contributors who help organize issues without writing code.

**You can:**
- Reproduce bug reports and ask clarifying questions
- Label issues (bug, enhancement, good first issue, duplicate)
- Point newcomers to [good first issues](https://github.com/debrajrout/cargo-depcheck/labels/good%20first%20issue)
- Close stale issues with a friendly summary

Triagers earn trust over time; maintainers may grant triage permissions on GitHub
after consistent helpful participation.

---

### 🧭 Maintainer

**Who:** Core stewards with merge access (currently [@debrajrout](https://github.com/debrajrout)).

**Responsibilities:**
- Review PRs for correctness, scope, and project direction
- Cut releases and update version/changelog when appropriate
- Enforce Code of Conduct
- Make final calls on scoring formula changes and breaking JSON schema bumps
- Welcome new contributors and unblock stuck PRs

**Becoming a maintainer:** there is no application form. Long-term contributors
who review others' work, improve docs, and show good judgment may be invited.
Ask if you are interested after several merged contributions.

---

## Ways to contribute (pick your path)

| If you have… | Try this |
|--------------|----------|
| 5 minutes | Fix a typo in README, improve an error message |
| 30 minutes | Add a unit test in `score.rs` or `report.rs` |
| 1 hour | Reproduce and fix a `good first issue` bug |
| An afternoon | Integration test fixtures (stubbed HTTP — see [future work](#areas-we-especially-welcome-help-with)) |
| Ongoing interest | Become a triager; review open PRs |

### Areas we especially welcome help with

These are **not blockers** — the tool works today — but they would help the
project mature:

1. **`[package.metadata.depcheck]` config** — per-project threshold and ignore list in `Cargo.toml`
2. **Integration test fixtures** — `tests/fixtures/` with stubbed crates.io / RustSec (no live network in CI)
3. **Scoring feedback** — real projects where ranking feels wrong; we tune weights together
4. **Docs & examples** — blog-style "how we use depcheck in CI" snippets
5. **Accessibility** — color-blind-friendly output, `--no-color` respect
6. **SARIF / delta mode** — see open feature requests

Comment on an issue or open a new one before starting large work.

---

## Development setup

### Prerequisites

- Rust **1.70+** (`rustc --version`)
- `cargo` on your PATH
- Network access (first run fetches crates.io + RustSec advisory DB)

### Clone and build

```sh
git clone https://github.com/debrajrout/cargo-depcheck.git
cd cargo-depcheck
cargo build
```

### Run locally

```sh
# Against this repo
cargo run -- depcheck

# Against another project
cargo run -- depcheck --manifest-path /path/to/Cargo.toml

# Lower threshold to see more findings during development
cargo run -- depcheck --threshold 30
```

### Quality checks (run before every PR)

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all
```

CI runs the same checks on **Linux, macOS, and Windows**.

---

## Project structure

```
src/
├── main.rs         Five-phase orchestration (graph → crates.io → advisories → score → report)
├── cli.rs          Clap arguments + cargo plugin wrapper
├── graph.rs        cargo metadata, BFS, DependencyNode
├── cratesio.rs     crates.io API client
├── advisories.rs   RustSec database fetch and lookup
├── score.rs        RiskScore formula (unit tests here)
└── report.rs       Terminal boxes + JSON output (unit tests here)
```

**Pipeline:**

```
graph → crates.io → advisories → score → report
```

Read [README.md](README.md) for user-facing behavior and scoring tables.

---

## Coding guidelines

These match how the existing code is written:

1. **One module, one job** — keep logic in the right file; don't grow `main.rs`.
2. **`anyhow` for errors** — this is a binary, not a library crate.
3. **No careless `unwrap()`** — use `?` or `.expect("why this cannot fail")`.
4. **Pad before colorizing** — `colored` ANSI codes break format width specs.
   Always `format!("{:<32}", text)` then `.yellow()` / `.bold()`.
5. **Comments explain why**, not what — skip narration of obvious code.
6. **Minimal diffs** — don't refactor unrelated code in the same PR.
7. **Tests for real behavior** — scoring math and report helpers deserve tests;
   don't add tests that only assert `true == true`.

### Design decisions — please don't reverse without discussion

- Use `cargo_metadata`, not raw `Cargo.lock` parsing (need dependency edges)
- Only **Normal** dependency edges for depth and `dependent_count`
- crates.io concurrency capped at **5** (rate limit friendly)
- Per-crate fetch errors are **silently skipped** (git/path deps won't crash the run)
- `rustsec` **0.33+** required (CVSS 4.0 advisories in current advisory-db)

---

## Submitting changes

### 1. Fork and branch

```sh
git checkout -main
git pull origin main
git checkout -b fix/my-change
```

Use branch names like `fix/…`, `feat/…`, or `docs/…`.

### 2. Make your change

Keep commits logical. Write a clear commit message:

```
Fix graph multiplier when max_dependents is zero

When the tree has no fan-in, avoid division edge cases and keep
multiplier at 1.0.
```

### 3. Open a pull request

- Fill in the [PR template](.github/pull_request_template.md)
- Link the issue: `Fixes #123` or `Relates to #456`
- Ensure CI is green
- Respond to review feedback — we're here to help you get it merged

### 4. After merge

Your contribution will appear in the release notes when applicable. Thank you.

---

## Issue guidelines

### Bug reports

Include:
- `cargo-depcheck --version` (or commit hash)
- OS and Rust version
- Exact command you ran
- Expected vs actual output (paste terminal or JSON)
- Minimal `Cargo.toml` / lockfile snippet if possible

### Feature requests

Include:
- **Problem:** what pain point does this solve?
- **Proposal:** how should it work?
- **Alternatives:** what did you consider?
- **Willingness:** are you planning to implement it?

We prioritize features that improve **triage clarity** without duplicating
`cargo audit`, `cargo outdated`, or `cargo deny`.

### Good first issue

Look for the [`good first issue`](https://github.com/debrajrout/cargo-depcheck/labels/good%20first%20issue) label.
Maintainers add it to issues that are scoped, documented, and don't need deep
Rust async expertise.

---

## Review process

1. **Automated CI** must pass (build, test, clippy, fmt, MSRV).
2. **A maintainer** reviews for correctness, scope, and UX.
3. **Changes requested** are normal — not a rejection.
4. **Merge** when approved; we use squash merge for a clean history.

First-time contributors: say hello in the PR! We will be extra clear in review.

---

## Recognition

Contributors are credited through:

- Git commit history (your name on merged PRs)
- Release notes when your change is user-visible
- Future `CONTRIBUTORS` or GitHub contributors graph

There is no CLA — by contributing, you agree your work is licensed under the
same terms as the project ([MIT](LICENSE-MIT) / [Apache-2.0](LICENSE-APACHE)).

---

## Questions?

- **Usage questions:** open a [GitHub Discussion](https://github.com/debrajrout/cargo-depcheck/discussions) or an issue with the `question` label
- **Security:** see [SECURITY.md](SECURITY.md) — do not file public issues for vulns
- **Conduct concerns:** debaraj@zoop.one

We are glad you are here. Rust's ecosystem stays healthy when people show up —
even with a one-line doc fix.
