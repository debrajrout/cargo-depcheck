# How scoring works, in detail

The [README](../README.md#how-scoring-works) has the short version. This
page explains *why* each rule is the way it is — useful if a score looks
wrong to you and you want to know whether it's a bug or a deliberate
tradeoff.

Every crate scores 0–100:

```text
score = (security + version_lag + maintenance) × graph_weight
```

| Signal | Max | Source |
|--------|-----|--------|
| Security | 50 | RustSec advisories, or a yanked version |
| Version lag | 25 | Releases behind the latest stable |
| Maintenance | 15 | Days since the crate's latest crates.io publish, across all versions (caps at 2 years) |
| **× Graph weight** | 1.0–2.0 | How many crates depend on this one |

---

## Version lag follows Cargo's compatibility rule, not raw semver arithmetic

Below 1.0, the *minor* version is the breaking axis. `0.3.1` → `0.4.0` is
exactly as incompatible as `1.0.0` → `2.0.0`, and scores the same way.
Treating it as a routine "minor bump" would badly understate it, and a
large share of the ecosystem lives below 1.0.

Three tiers, most severe first:

| Tier | Points each | Cap |
|------|-------------|-----|
| Breaking releases behind | 12.5 | 25 |
| Compatible releases behind | 2.5 | 25 |
| Patch releases behind | 0.5 | 5 |

Patch lag is deliberately small but **non-zero**: security fixes often ship
as patch releases, so `0.10.45` → `0.10.99` shouldn't be invisible. The low
cap keeps it from ever rivalling a real breaking-version gap.

---

## Advisories without a CVSS score are ranked by category

**65% of RustSec advisories (789 of 1,206) carry no CVSS score at all.**
This is the common case, not an edge case — any tool that sorts purely by
CVSS is blind on most of the database.

When CVSS is absent, severity comes from the advisory's category. RustSec
doesn't rank its own categories, so this ordering is this project's
judgment of real-world impact:

| Tier | Categories |
|------|-----------|
| Highest | Malicious code, arbitrary code execution |
| High | Privilege escalation, memory corruption |
| Medium | Crypto failure, injection, thread safety, file disclosure |
| Lower | Memory exposure, denial of service |

An advisory with several categories takes the worst one. An advisory with
none gets a conservative Medium-equivalent default.

Informational advisories are tiered separately: `Unsound` (30) sits above
`Unmaintained` (20), because unsoundness means safe code can trigger
undefined behavior — a live safety defect, not just a maintenance signal.
A plain `Notice` scores 10.

**Multiple advisories compound.** A crate with three advisories scores
strictly higher than one with a single advisory of the same severity, via
diminishing returns: the worst counts fully, each additional one at 30% of
the scale before it. Still capped at the 50-point security ceiling.

A **yanked** version scores 40 — the High-severity tier. Someone pulled
that exact release from crates.io, and that's worth surfacing loudly.

---

## Graph weight is absolute, not relative to your project

```text
weight(n) = 1.0 + ln(1 + n) / (ln(1 + n) + 4)
```

where `n` is the number of crates depending on this one, directly *or
transitively*. The transitive part matters: a crate with only two direct
dependents that both sit underneath something widely used still gets credit
for its true blast radius.

| Transitive dependents | Weight |
|---|---|
| 0 | 1.00 |
| 5 | 1.31 |
| 20 | 1.43 |
| 100 | 1.54 |
| 1000 | 1.63 |

The function saturates deliberately. The gap between 0 and 20 dependents
matters a great deal; the gap between 100 and 1000 barely matters, because
both are "load-bearing, fix it."

**Why absolute rather than relative:** an earlier version scaled this
against your project's single most-depended-on crate. That meant the same
crate in the same state could score up to 85% higher in a small project
than a large one, purely because of an unrelated crate elsewhere in the
tree — which made `--threshold` mean something different in every project.
It's absolute now, so a threshold you tune once travels between projects.

Direct dependencies are bold in the human report, but directness is not an
extra scoring term. The ranking measures security, lag, maintenance, and
graph impact; it does not automatically put a direct leaf above a more
widely reused transitive crate.

`--threshold` is a presentation filter over these scores. Summary counts and
`--fail-on` evaluate the complete analyzed graph, so increasing the threshold
cannot accidentally weaken a CI policy.

The maintenance timestamp describes crate-wide publishing activity, not the
publication date of the resolved version. This distinguishes an abandoned
crate from an actively maintained crate even when the project is pinned to
an older release; version lag separately captures that pin.

---

## What this deliberately does *not* do

- **No reachability analysis.** depcheck doesn't know whether you actually
  call the vulnerable function. A finding means "this crate is in your
  tree," not "you are exploitable."
- **No license or policy enforcement.** That's [`cargo-deny`][deny]'s job,
  and it does it well.
- **Not a replacement for `cargo audit`.** Use audit to *block merges* on
  known CVEs. Use depcheck to decide *what to upgrade next*.

[deny]: https://github.com/EmbarkStudios/cargo-deny
