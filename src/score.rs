use chrono::{DateTime, Utc};
use rustsec::advisory::{Advisory, Informational, Severity};
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

fn security_points(advisories: &[Advisory], yanked: bool) -> f64 {
    let advisory_max = advisories.iter().map(advisory_points).fold(0.0, f64::max);
    let yanked_points = if yanked { YANKED_POINTS } else { 0.0 };
    advisory_max.max(yanked_points).min(MAX_SECURITY)
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
        Some(Severity::None) | None => 35.0,
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

fn version_lag_points(have: &Version, latest: &Version) -> f64 {
    if have >= latest {
        return 0.0;
    }

    let major_behind = latest.major.saturating_sub(have.major);
    if major_behind > 0 {
        return (major_behind as f64 * 12.5).min(MAX_VERSION_LAG);
    }

    let minor_behind = latest.minor.saturating_sub(have.minor);
    (minor_behind as f64 * 2.5).min(MAX_VERSION_LAG)
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
}
