use chrono::{DateTime, Utc};
use rustsec::advisory::{Advisory, Severity};
use semver::Version;

use crate::cratesio::Metadata;
use crate::graph::DependencyNode;

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
    max_dependents: usize,
    now: DateTime<Utc>,
) -> RiskScore {
    let security = security_points(advisories);
    let version_lag = meta
        .map(|m| version_lag_points(&node.version, m.latest_stable()))
        .unwrap_or(0.0);
    let maintenance = meta
        .map(|m| maintenance_points((now - m.updated_at).num_days()))
        .unwrap_or(0.0);
    let graph_multiplier = graph_multiplier(node.dependent_count, max_dependents);

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

fn security_points(advisories: &[Advisory]) -> f64 {
    advisories
        .iter()
        .map(advisory_points)
        .fold(0.0, f64::max)
        .min(MAX_SECURITY)
}

fn advisory_points(advisory: &Advisory) -> f64 {
    if let Some(info) = &advisory.metadata.informational {
        return if info.is_unmaintained() { 20.0 } else { 10.0 };
    }

    match advisory.severity() {
        Some(Severity::Critical) => 50.0,
        Some(Severity::High) => 40.0,
        Some(Severity::Medium) => 30.0,
        Some(Severity::Low) => 20.0,
        Some(Severity::None) | None => 35.0,
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

fn graph_multiplier(dependent_count: usize, max_dependents: usize) -> f64 {
    if max_dependents == 0 {
        return 1.0;
    }

    1.0 + dependent_count as f64 / max_dependents as f64
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
    fn graph_multiplier_range() {
        assert_eq!(graph_multiplier(0, 40), 1.0);
        assert_eq!(graph_multiplier(20, 40), 1.5);
        assert_eq!(graph_multiplier(40, 40), 2.0);
    }

    #[test]
    fn risk_levels() {
        assert_eq!(RiskLevel::from_score(71.0), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(70.0), RiskLevel::Warn);
        assert_eq!(RiskLevel::from_score(40.0), RiskLevel::Warn);
        assert_eq!(RiskLevel::from_score(39.9), RiskLevel::Low);
    }
}
