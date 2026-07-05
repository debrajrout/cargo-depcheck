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

First run needs network (crates.io + RustSec advisory DB). After that, the advisory DB is cached at `~/.cargo/advisory-db`.

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
| `--json` | CI-friendly JSON on stdout (progress on stderr) |
| `--no-advisories` | Skip RustSec — version/maintenance only |
| `--no-fetch` | Use cached advisory DB, no git pull |
| `--manifest-path PATH` | Point at another project |

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
| Security | 50 | RustSec advisories (CVE severity, unmaintained) |
| Version lag | 25 | Major/minor versions behind latest stable |
| Maintenance | 15 | Days since last crates.io publish (cap: 2 years) |
| **× Graph weight** | 1.0–2.0 | More dependents → higher urgency |

A stale leaf at the edge of your tree scores lower than the same stale crate holding up 30 others. That's the point.

---

## CI in 30 seconds

```yaml
- run: cargo install cargo-depcheck
- run: cargo depcheck --json --threshold 70 > depcheck.json
- run: |
    test "$(jq '.summary.critical' depcheck.json)" -eq 0
```

JSON includes `"schema_version": 1` so scripts can pin against it.

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
