use chrono::{DateTime, Utc};
use rustsec::advisory::{Advisory, Category, Informational, Severity};
use semver::Version;

use crate::graph::DependencyNode;
use crate::registry::Metadata;

const MAX_SECURITY: f64 = 50.0;
const MAX_VERSION_LAG: f64 = 25.0;
const MAX_MAINTENANCE: f64 = 15.0;
const MAINTENANCE_CEILING_DAYS: f64 = 730.0;

/// Default score floor — dependencies below this are omitted from output.
pub const DEFAULT_THRESHOLD: f64 = 40.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Warn,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        if score > 70.0 {
            Self::Critical
        } else if score >= DEFAULT_THRESHOLD {
            Self::Warn
        } else {
            Self::Low
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Warn => "warn",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskScore {
    pub security: f64,
    pub version_lag: f64,
    pub maintenance: f64,
    pub graph_multiplier: f64,
    pub total: f64,
    pub level: RiskLevel,
}

pub fn compute(
    node: &DependencyNode,
    meta: Option<&Metadata>,
    advisories: &[Advisory],
    now: DateTime<Utc>,
) -> RiskScore {
    let yanked = meta.is_some_and(|m| m.is_yanked(&node.version));
    let security = security_points(advisories, yanked);
    let version_lag = meta
        .map(|m| version_lag_points(&node.version, m.latest_stable()))
        .unwrap_or(0.0);
    let maintenance = meta
        .map(|m| maintenance_points((now - m.updated_at).num_days()))
        .unwrap_or(0.0);
    let graph_multiplier = graph_multiplier(node.transitive_dependent_count);

    let base = security + version_lag + maintenance;
    let total = (base * graph_multiplier).min(100.0);

    RiskScore {
        security,
        version_lag,
        maintenance,
        graph_multiplier,
        total,
        level: RiskLevel::from_score(total),
    }
}

impl RiskScore {
    /// Human-readable breakdown of how the total was derived.
    pub fn explain(&self) -> String {
        format!(
            "sec {:.0} + lag {:.0} + maint {:.0} × {:.1}",
            self.security, self.version_lag, self.maintenance, self.graph_multiplier
        )
    }
}

/// A yanked version is crates.io's own "don't use this" signal — the
/// publisher pulled it, for a security reason or otherwise. Weighted
/// comparably to a High-severity advisory: it doesn't always mean a
/// vulnerability, but it always means "there was a reason not to."
const YANKED_POINTS: f64 = 40.0;

/// Each additional advisory beyond the worst one contributes at this
/// fraction of the scale before it — the worst advisory still dominates,
/// but a crate with several advisories now strictly outscores one with a
/// single advisory of the same severity, which a plain `max()` couldn't
/// distinguish at all.
const ADVISORY_DIMINISHING_FACTOR: f64 = 0.3;

fn security_points(advisories: &[Advisory], yanked: bool) -> f64 {
    let points: Vec<f64> = advisories.iter().map(advisory_points).collect();
    accumulate_security_points(&points, yanked)
}

/// Split from `security_points` so the accumulation policy (diminishing
/// returns per extra advisory, folded against the yanked signal, capped at
/// `MAX_SECURITY`) is testable directly against plain point values, without
/// needing to construct real `Advisory` records.
fn accumulate_security_points(advisory_points: &[f64], yanked: bool) -> f64 {
    let mut sorted = advisory_points.to_vec();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

    let mut advisory_total = 0.0;
    let mut scale = 1.0;
    for p in sorted {
        advisory_total += p * scale;
        scale *= ADVISORY_DIMINISHING_FACTOR;
    }

    let yanked_points = if yanked { YANKED_POINTS } else { 0.0 };
    advisory_total.max(yanked_points).min(MAX_SECURITY)
}

fn advisory_points(advisory: &Advisory) -> f64 {
    if let Some(info) = &advisory.metadata.informational {
        return informational_points(info);
    }

    match advisory.severity() {
        Some(Severity::Critical) => 50.0,
        Some(Severity::High) => 40.0,
        Some(Severity::Medium) => 30.0,
        Some(Severity::Low) => 20.0,
        Some(Severity::None) | None => category_points(&advisory.metadata.categories),
    }
}

/// 65% of RustSec advisories carry no CVSS score at all (417 of 1,206 do) —
/// this decides the security score for the *majority* of real vulnerability
/// findings, not a rare fallback path. Rather than one arbitrary constant
/// for every unscored advisory, derive a severity from the worst RustSec
/// category the advisory carries. RustSec doesn't rank its own categories,
/// so this ladder is this project's own judgment of real-world impact, not
/// an authoritative external mapping — documented here so it can be
/// challenged and tuned, unlike the magic number it replaces.
fn category_points(categories: &[Category]) -> f64 {
    if categories.is_empty() {
        return 30.0;
    }
    categories.iter().map(category_severity).fold(0.0, f64::max)
}

fn category_severity(category: &Category) -> f64 {
    match category {
        Category::Malicious => 50.0,
        Category::CodeExecution => 45.0,
        Category::PrivilegeEscalation | Category::MemoryCorruption => 40.0,
        Category::CryptoFailure | Category::FormatInjection => 35.0,
        Category::ThreadSafety | Category::FileDisclosure => 30.0,
        Category::MemoryExposure => 25.0,
        Category::DenialOfService => 20.0,
        // `Category` is #[non_exhaustive] in rustsec; every variant that
        // exists today is matched above. A genuinely new category lands
        // here, at the same conservative default as "no category at all."
        _ => 30.0,
    }
}

/// Every variant `Informational` has today is matched by name, not folded
/// into a wildcard — so this is the one place a new RustSec advisory
/// category would need a deliberate decision, not a silent default.
///
/// One caveat: `Informational` is `#[non_exhaustive]` in `rustsec`, which
/// means Rust still requires a trailing `_` arm even though every variant
/// that exists today is listed above it — the compiler can't tell "every
/// current variant, explicitly" from "I didn't bother." That arm exists
/// only to satisfy that constraint; it is not a lazy catch-all, and if
/// rustsec ships a real fifth variant it silently lands there rather than
/// failing to compile — the closest this API lets us get to "a future
/// variant is a compile error."
fn informational_points(info: &Informational) -> f64 {
    match info {
        Informational::Notice => 10.0,
        Informational::Unmaintained => 20.0,
        // Unsound: using the crate's safe public API can cause undefined
        // behavior. That's a real safety defect, not routine housekeeping —
        // placed above Unmaintained, at the Medium-severity-CVE tier.
        Informational::Unsound => 30.0,
        Informational::Other(_) => 15.0,
        _ => 15.0,
    }
}

/// Patch-only lag was previously invisible (scored 0) — a real gap for a
/// tool whose whole point is "what should I upgrade next," since a security
/// fix often ships as a patch release. Weighted low enough to never rival a
/// genuine breaking-release gap, but non-zero so it's visible.
const PATCH_LAG_POINTS: f64 = 0.5;
const MAX_PATCH_LAG: f64 = 5.0;

/// Cargo's caret-requirement compatibility rule decides which version
/// component is the breaking axis: major, if it's nonzero; otherwise minor;
/// otherwise patch. That means `0.3.1` and `0.4.0` are exactly as
/// incompatible as `1.0.0` and `2.0.0` — a distinction plain
/// major-then-minor arithmetic misses entirely below 1.0, where a large
/// share of the ecosystem lives. Pre-release tags on `latest` are ignored
/// here (numeric lag is computed the same way regardless); the separate
/// `have >= latest` check above already accounts for pre-release ordering
/// when deciding whether there's any lag to report at all.
fn version_lag_points(have: &Version, latest: &Version) -> f64 {
    if have >= latest {
        return 0.0;
    }

    let (breaking_behind, compatible_behind, patch_behind) = lag_components(have, latest);

    if breaking_behind > 0 {
        return (breaking_behind as f64 * 12.5).min(MAX_VERSION_LAG);
    }
    if compatible_behind > 0 {
        return (compatible_behind as f64 * 2.5).min(MAX_VERSION_LAG);
    }
    (patch_behind as f64 * PATCH_LAG_POINTS).min(MAX_PATCH_LAG)
}

/// Splits the gap between `have` and `latest` into (breaking, compatible,
/// patch) release counts, per Cargo's `0.y.z` / `0.0.z` compatibility rules.
pub(crate) fn lag_components(have: &Version, latest: &Version) -> (u64, u64, u64) {
    if have.major > 0 || latest.major > 0 {
        let breaking = latest.major.saturating_sub(have.major);
        if breaking > 0 {
            return (breaking, 0, 0);
        }
        let compatible = latest.minor.saturating_sub(have.minor);
        if compatible > 0 {
            return (0, compatible, 0);
        }
        return (0, 0, latest.patch.saturating_sub(have.patch));
    }

    if have.minor > 0 || latest.minor > 0 {
        let breaking = latest.minor.saturating_sub(have.minor);
        if breaking > 0 {
            return (breaking, 0, 0);
        }
        return (0, 0, latest.patch.saturating_sub(have.patch));
    }

    // Both 0.0.z: every patch bump is breaking under Cargo's rules, so
    // patch is both the breaking axis and the count.
    (latest.patch.saturating_sub(have.patch), 0, 0)
}

fn maintenance_points(days: i64) -> f64 {
    if days <= 0 {
        return 0.0;
    }

    ((days as f64 / MAINTENANCE_CEILING_DAYS) * MAX_MAINTENANCE).min(MAX_MAINTENANCE)
}

/// Controls how fast the multiplier saturates: at this many transitive
/// dependents, the multiplier is exactly at the 1.0-2.0 range's midpoint
/// (1.5). Chosen so a genuinely foundational crate (tens to low hundreds of
/// transitive dependents — think `syn` or `serde` in a mid-size project)
/// lands in the upper half of the range, while a leaf with a handful of
/// dependents stays close to 1.0.
const GRAPH_WEIGHT_MIDPOINT: f64 = 4.0;

/// An absolute, saturating function of transitive dependent count: 0 always
/// maps to 1.0, and the value rises monotonically, asymptotically
/// approaching (never reaching) 2.0. Depending on nothing but its own input,
/// this is identical for a given count regardless of any other property of
/// the project — unlike the old `dependent_count / max_dependents_in_this_project`
/// design, where the same crate in the same state could score up to 85%
/// higher in a smaller project purely because that project's *largest*
/// dependency count happened to be smaller (see IMPLEMENTATION_PLAN.md P2-1).
fn graph_multiplier(transitive_dependent_count: usize) -> f64 {
    let weight = (1.0 + transitive_dependent_count as f64).ln();
    1.0 + weight / (weight + GRAPH_WEIGHT_MIDPOINT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_lag_major_behind() {
        let have = Version::new(1, 0, 0);
        let latest = Version::new(3, 0, 0);
        assert_eq!(version_lag_points(&have, &latest), 25.0);
    }

    #[test]
    fn version_lag_minor_only() {
        let have = Version::new(1, 0, 0);
        let latest = Version::new(1, 4, 0);
        assert_eq!(version_lag_points(&have, &latest), 10.0);
    }

    #[test]
    fn version_lag_up_to_date() {
        let have = Version::new(2, 1, 0);
        let latest = Version::new(2, 1, 0);
        assert_eq!(version_lag_points(&have, &latest), 0.0);
    }

    #[test]
    fn version_lag_0x_minor_bump_scores_as_breaking() {
        // windows-sys 0.52.0 -> 0.61.2: 9 breaking releases under Cargo's
        // 0.y compatibility rule, capped at MAX_VERSION_LAG (9 * 12.5 = 112.5).
        let have = Version::new(0, 52, 0);
        let latest = Version::new(0, 61, 2);
        assert_eq!(version_lag_points(&have, &latest), 25.0);
    }

    #[test]
    fn version_lag_0x_minor_bump_uncapped_example() {
        // A smaller, uncapped 0.y breaking bump: 0.1.0 -> 0.2.0 is exactly
        // one breaking release, same as 1.0.0 -> 2.0.0.
        let have = Version::new(0, 1, 0);
        let latest = Version::new(0, 2, 0);
        assert_eq!(version_lag_points(&have, &latest), 12.5);
    }

    #[test]
    fn version_lag_crossing_0x_to_1x_is_one_breaking_release() {
        // hash32 0.3.1 -> 1.0.0: the 0.x -> 1.0 line itself is the breaking
        // change, regardless of how many 0.x minors were skipped to get here.
        let have = Version::new(0, 3, 1);
        let latest = Version::new(1, 0, 0);
        assert_eq!(version_lag_points(&have, &latest), 12.5);
    }

    #[test]
    fn version_lag_patch_only_is_visible_but_small() {
        // Previously scored 0 — invisible. 0.10.45 -> 0.10.99 is 54 patches
        // behind, capped at MAX_PATCH_LAG so it never rivals a real
        // major/minor gap, but is no longer silent.
        let have = Version::new(0, 10, 45);
        let latest = Version::new(0, 10, 99);
        let points = version_lag_points(&have, &latest);
        assert!(points > 0.0, "patch-only lag must be visible");
        assert_eq!(points, 5.0);
    }

    #[test]
    fn version_lag_ignores_prerelease_tag_on_latest() {
        // A pre-release `latest` (e.g. the crate has never cut a 2.0.0
        // stable) is still numerically 1 major ahead of a 1.0.0 pin — the
        // prerelease qualifier doesn't hide that gap.
        let have = Version::new(1, 0, 0);
        let latest = Version::parse("2.0.0-alpha.1").unwrap();
        assert_eq!(version_lag_points(&have, &latest), 12.5);
    }

    #[test]
    fn maintenance_scales_to_cap() {
        assert_eq!(maintenance_points(365), 7.5);
        assert_eq!(maintenance_points(730), 15.0);
        assert_eq!(maintenance_points(2000), 15.0);
    }

    #[test]
    fn graph_multiplier_zero_dependents_is_exactly_one() {
        assert_eq!(graph_multiplier(0), 1.0);
    }

    #[test]
    fn graph_multiplier_never_reaches_two() {
        for n in [1, 10, 100, 10_000, 10_000_000] {
            let m = graph_multiplier(n);
            assert!(
                m > 1.0 && m < 2.0,
                "multiplier({n}) = {m} out of (1.0, 2.0)"
            );
        }
    }

    #[test]
    fn graph_multiplier_is_monotonically_increasing() {
        let counts = [0, 1, 2, 3, 5, 10, 20, 50, 100, 1000, 100_000];
        for pair in counts.windows(2) {
            let (a, b) = (graph_multiplier(pair[0]), graph_multiplier(pair[1]));
            assert!(
                b > a,
                "multiplier must strictly increase: f({}) = {a} >= f({}) = {b}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn graph_multiplier_depends_only_on_its_own_count() {
        // The whole point of P2-1: this must be a pure function of the
        // count alone, with no notion of "the rest of the project" at all —
        // there is no second parameter it even could read.
        assert_eq!(graph_multiplier(7), graph_multiplier(7));
        assert_eq!(graph_multiplier(500), graph_multiplier(500));
    }

    /// Reproduces the exact non-portability bug from the audit: the same
    /// crate, at the same transitive-dependent count, scored up to 85%
    /// higher in a smaller project purely because of that OTHER project's
    /// unrelated max-dependents value. `compute()` no longer takes a
    /// project-wide parameter at all, so there is nothing left to vary.
    #[test]
    fn score_is_identical_regardless_of_project_size() {
        let mut node_a = test_node("leaf", 3, 3);
        let mut node_b = test_node("leaf", 3, 3);
        node_a.name = "same-crate-small-project".into();
        node_b.name = "same-crate-huge-project".into();

        let now: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        let a = compute(&node_a, None, &[], now);
        let b = compute(&node_b, None, &[], now);
        assert_eq!(a.total, b.total);
        assert_eq!(a.graph_multiplier, b.graph_multiplier);
    }

    fn test_node(
        name: &str,
        dependent_count: usize,
        transitive_dependent_count: usize,
    ) -> DependencyNode {
        DependencyNode {
            name: name.to_string(),
            version: Version::new(1, 0, 0),
            is_direct: false,
            depth: 1,
            dependent_count,
            transitive_dependent_count,
            is_registry: true,
        }
    }

    #[test]
    fn risk_levels() {
        assert_eq!(RiskLevel::from_score(71.0), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(70.0), RiskLevel::Warn);
        assert_eq!(RiskLevel::from_score(40.0), RiskLevel::Warn);
        assert_eq!(RiskLevel::from_score(39.9), RiskLevel::Low);
    }

    #[test]
    fn informational_points_notice() {
        assert_eq!(informational_points(&Informational::Notice), 10.0);
    }

    #[test]
    fn informational_points_unmaintained() {
        assert_eq!(informational_points(&Informational::Unmaintained), 20.0);
    }

    #[test]
    fn informational_points_unsound_sits_above_unmaintained() {
        let unsound = informational_points(&Informational::Unsound);
        let unmaintained = informational_points(&Informational::Unmaintained);
        assert_eq!(unsound, 30.0);
        assert!(
            unsound > unmaintained,
            "an unsound crate (real UB risk) must outrank a merely unmaintained one"
        );
    }

    #[test]
    fn informational_points_other_is_pinned() {
        assert_eq!(
            informational_points(&Informational::Other("some-future-category".into())),
            15.0
        );
    }

    #[test]
    fn yanked_version_scores_as_a_high_severity_signal() {
        let node = test_node("leaf", 0, 0);
        let meta = Metadata {
            newest_version: Version::new(2, 0, 0),
            max_stable_version: Some(Version::new(2, 0, 0)),
            updated_at: Utc::now(),
            yanked_versions: vec![Version::new(1, 0, 0)],
        };
        let now = Utc::now();

        let risk = compute(&node, Some(&meta), &[], now);
        assert_eq!(risk.security, YANKED_POINTS);
    }

    #[test]
    fn non_yanked_version_is_unaffected_by_an_unrelated_yank() {
        let mut node = test_node("leaf", 0, 0);
        node.version = Version::new(2, 0, 0);
        let meta = Metadata {
            newest_version: Version::new(2, 0, 0),
            max_stable_version: Some(Version::new(2, 0, 0)),
            updated_at: Utc::now(),
            yanked_versions: vec![Version::new(1, 0, 0)],
        };
        let now = Utc::now();

        let risk = compute(&node, Some(&meta), &[], now);
        assert_eq!(risk.security, 0.0);
    }

    #[test]
    fn single_advisory_scores_at_its_own_value() {
        assert_eq!(accumulate_security_points(&[40.0], false), 40.0);
    }

    #[test]
    fn three_advisories_score_strictly_higher_than_one_of_equal_severity() {
        let one = accumulate_security_points(&[40.0], false);
        let three = accumulate_security_points(&[40.0, 40.0, 40.0], false);
        assert!(
            three > one,
            "3 advisories ({three}) must outscore 1 of equal severity ({one})"
        );
    }

    #[test]
    fn worst_advisory_still_dominates_the_total() {
        // A pile of Low-severity advisories must not out-rank one Critical.
        let many_low = accumulate_security_points(&[20.0; 10], false);
        let one_critical = accumulate_security_points(&[50.0], false);
        assert!(one_critical > many_low, "{one_critical} vs {many_low}");
    }

    #[test]
    fn advisory_accumulation_is_capped_at_max_security() {
        let total = accumulate_security_points(&[50.0, 50.0, 50.0, 50.0, 50.0], false);
        assert_eq!(total, MAX_SECURITY);
    }

    #[test]
    fn category_points_prefers_the_worst_of_several_categories() {
        let points = category_points(&[Category::DenialOfService, Category::Malicious]);
        assert_eq!(points, 50.0);
    }

    #[test]
    fn category_points_no_category_falls_back_to_conservative_default() {
        assert_eq!(category_points(&[]), 30.0);
    }

    #[test]
    fn category_points_ranks_memory_corruption_above_denial_of_service() {
        let corruption = category_points(&[Category::MemoryCorruption]);
        let dos = category_points(&[Category::DenialOfService]);
        assert!(corruption > dos);
    }
}
