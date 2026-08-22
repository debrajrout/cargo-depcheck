use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use semver::Version;
use tame_index::index::{AsyncRemoteSparseIndex, FileLock};
use tame_index::utils::flock::LockOptions;
use tame_index::{IndexKrate, IndexLocation, IndexUrl, SparseIndex};

/// Derived from `Cargo.toml`'s `repository` field so the contact URL can
/// never drift from the real repo.
const USER_AGENT: &str = concat!(
    "cargo-depcheck/",
    env!("CARGO_PKG_VERSION"),
    " (+",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

/// A single request to the sparse index gets every version at once, so a
/// generous per-crate timeout still keeps a stuck request from hanging the
/// whole run.
const PER_CRATE_TIMEOUT: Duration = Duration::from_secs(20);

/// Hard ceiling on the *entire* batch. `AsyncRemoteSparseIndex::krates()`
/// only applies `PER_CRATE_TIMEOUT` to crates after the first — the first
/// one it processes goes through an untimed path that retries a connect or
/// timeout error forever with no cap or backoff (verified: a single
/// dependency against an unreachable proxy hangs indefinitely without this).
/// This is a gap in the upstream API, not something callers can configure
/// around, so the whole call is wrapped here instead.
const BATCH_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Metadata {
    /// Highest version in the index, including yanked and pre-release.
    pub newest_version: Version,
    /// Highest non-yanked, non-prerelease version — the upgrade target.
    pub max_stable_version: Option<Version>,
    /// The most recent publish time across every version of the crate — the
    /// maintenance signal. Sourced per-version from the sparse index's
    /// `pubtime` field, unlike the old crates.io JSON API's crate-level
    /// `updated_at`, which was bumped by yanks and metadata edits and
    /// couldn't distinguish "abandoned" from "stable and old."
    pub updated_at: DateTime<Utc>,
    /// Every version of this crate that has been yanked. Not yet consumed
    /// by scoring — that's P2-2 ("signals the tool currently misses").
    #[allow(dead_code)]
    pub yanked_versions: Vec<Version>,
}

impl Metadata {
    /// The version a user should be on: stable if available, otherwise newest.
    pub fn latest_stable(&self) -> &Version {
        self.max_stable_version
            .as_ref()
            .unwrap_or(&self.newest_version)
    }

    #[allow(dead_code)] // consumed once P2-2 adds yanked-version scoring
    pub fn is_yanked(&self, version: &Version) -> bool {
        self.yanked_versions.contains(version)
    }
}

/// Per-crate fetch results, keyed by crate name.
pub type FetchResults = BTreeMap<String, Result<Option<Metadata>>>;

/// Abstracts "fetch registry metadata for a set of crate names" so callers
/// don't depend on `tame_index` directly, and so a fixture-backed
/// implementation can stand in for tests without HTTP mocking.
pub trait IndexSource: Send + Sync {
    fn fetch<'a>(
        &'a self,
        names: BTreeSet<String>,
    ) -> Pin<Box<dyn Future<Output = FetchResults> + Send + 'a>>;
}

/// The real registry: cargo's sparse index, sharing the same on-disk cache
/// as the user's own `~/.cargo` installation. No crates.io rate limit
/// applies to the sparse index — see https://crates.io/data-access, which
/// lists it first and states plainly that no rate limits are required.
pub struct SparseRegistry {
    remote: AsyncRemoteSparseIndex,
    offline: bool,
}

impl SparseRegistry {
    pub fn new(offline: bool) -> Result<Self> {
        let url = IndexUrl::crates_io(None, None, None)
            .context("failed to resolve the crates.io index URL")?;
        let index = SparseIndex::new(IndexLocation::new(url))
            .context("failed to open the local sparse index cache")?;
        let client = build_client()?;
        Ok(Self {
            remote: AsyncRemoteSparseIndex::new(index, client),
            offline,
        })
    }

    /// A shared lock compatible with cargo's own reads of the same cache.
    /// Non-blocking: if another cargo process holds it exclusively (e.g. a
    /// concurrent `cargo build` updating the index), this fails fast rather
    /// than stalling the whole run — the caller folds that into the existing
    /// per-crate failure handling instead of treating it as fatal.
    fn lock(&self) -> Result<FileLock> {
        LockOptions::cargo_package_lock(None)
            .context("failed to configure cargo's package cache lock")?
            .shared()
            .try_lock()
            .context("failed to lock cargo's package cache")
    }
}

impl IndexSource for SparseRegistry {
    fn fetch<'a>(
        &'a self,
        names: BTreeSet<String>,
    ) -> Pin<Box<dyn Future<Output = FetchResults> + Send + 'a>> {
        Box::pin(async move {
            let lock = match self.lock() {
                Ok(lock) => lock,
                Err(err) => {
                    return names
                        .into_iter()
                        .map(|name| {
                            (
                                name,
                                Err(anyhow::anyhow!("{err:#}").context("cache lock unavailable")),
                            )
                        })
                        .collect();
                }
            };

            if self.offline {
                return names
                    .into_iter()
                    .map(|name| {
                        let result = fetch_cached(&self.remote, &name, &lock);
                        (name, result)
                    })
                    .collect();
            }

            let requested = names.clone();
            let raw = tokio::time::timeout(
                BATCH_TIMEOUT,
                self.remote
                    .krates(names, true, Some(PER_CRATE_TIMEOUT), &lock),
            )
            .await;

            let Ok(raw) = raw else {
                return requested
                    .into_iter()
                    .map(|name| {
                        (
                            name,
                            Err(anyhow::anyhow!(
                                "sparse index request did not complete within {BATCH_TIMEOUT:?}"
                            )),
                        )
                    })
                    .collect();
            };

            raw.into_iter()
                .map(|(name, result)| {
                    let result = result
                        .map_err(|err| anyhow::anyhow!("{err}"))
                        .context("sparse index request failed")
                        .and_then(|krate| krate.as_ref().map(to_metadata).transpose());
                    (name, result)
                })
                .collect()
        })
    }
}

fn fetch_cached(
    remote: &AsyncRemoteSparseIndex,
    name: &str,
    lock: &FileLock,
) -> Result<Option<Metadata>> {
    let krate_name = name
        .try_into()
        .map_err(|err| anyhow::anyhow!("{err}"))
        .context("invalid crate name")?;
    let krate = remote
        .cached_krate(krate_name, lock)
        .map_err(|err| anyhow::anyhow!("{err}"))
        .context("failed to read the local index cache")?;
    krate.as_ref().map(to_metadata).transpose()
}

fn to_metadata(krate: &IndexKrate) -> Result<Metadata> {
    let newest_version = Version::parse(krate.highest_version().version.as_str())
        .context("invalid version in index")?;

    let max_stable_version = krate
        .highest_normal_version()
        .map(|v| Version::parse(v.version.as_str()))
        .transpose()
        .context("invalid stable version in index")?;

    // Most recent publish across every version, not just the highest-semver
    // one — a patch release on an old branch can be the most recent activity.
    let updated_at = krate
        .versions
        .iter()
        .filter_map(|v| v.pubtime.as_deref())
        .filter_map(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc))
        .max()
        // No publish-time data at all (older index entries can lack it):
        // treat as just published rather than penalizing for missing data.
        .unwrap_or_else(Utc::now);

    let yanked_versions = krate
        .versions
        .iter()
        .filter(|v| v.is_yanked())
        .filter_map(|v| Version::parse(v.version.as_str()).ok())
        .collect();

    Ok(Metadata {
        newest_version,
        max_stable_version,
        updated_at,
        yanked_versions,
    })
}

fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .context("failed to build HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_matches_the_real_repository() {
        assert!(USER_AGENT.contains(env!("CARGO_PKG_REPOSITORY")));
        assert!(!USER_AGENT.contains("debarajrout"));
    }

    #[test]
    fn latest_stable_prefers_stable_over_newest() {
        let meta = Metadata {
            newest_version: Version::new(2, 0, 0),
            max_stable_version: Some(Version::new(1, 5, 0)),
            updated_at: Utc::now(),
            yanked_versions: Vec::new(),
        };
        assert_eq!(meta.latest_stable(), &Version::new(1, 5, 0));
    }

    #[test]
    fn latest_stable_falls_back_to_newest_when_no_stable_exists() {
        let meta = Metadata {
            newest_version: Version::new(2, 0, 0),
            max_stable_version: None,
            updated_at: Utc::now(),
            yanked_versions: Vec::new(),
        };
        assert_eq!(meta.latest_stable(), &Version::new(2, 0, 0));
    }

    #[test]
    fn is_yanked_checks_the_yanked_list() {
        let meta = Metadata {
            newest_version: Version::new(1, 0, 0),
            max_stable_version: None,
            updated_at: Utc::now(),
            yanked_versions: vec![Version::new(0, 9, 0)],
        };
        assert!(meta.is_yanked(&Version::new(0, 9, 0)));
        assert!(!meta.is_yanked(&Version::new(1, 0, 0)));
    }

    #[test]
    fn to_metadata_picks_max_pubtime_not_highest_semver_version() {
        let mut old_but_recent = IndexKrate {
            versions: vec![
                fake_version("1.0.0", "2020-01-01T00:00:00Z", false),
                fake_version("0.9.0", "2026-01-01T00:00:00Z", false),
            ],
        };
        old_but_recent
            .versions
            .sort_by(|a, b| a.version.cmp(&b.version));

        let meta = to_metadata(&old_but_recent).unwrap();
        assert_eq!(meta.updated_at.to_rfc3339(), "2026-01-01T00:00:00+00:00");
    }

    #[test]
    fn to_metadata_excludes_yanked_from_max_stable_version() {
        let krate = IndexKrate {
            versions: vec![
                fake_version("1.0.0", "2020-01-01T00:00:00Z", false),
                fake_version("2.0.0", "2021-01-01T00:00:00Z", true),
            ],
        };
        let meta = to_metadata(&krate).unwrap();
        assert_eq!(meta.max_stable_version, Some(Version::new(1, 0, 0)));
        assert_eq!(meta.newest_version, Version::new(2, 0, 0));
        assert!(meta.is_yanked(&Version::new(2, 0, 0)));
    }

    fn fake_version(version: &str, pubtime: &str, yanked: bool) -> tame_index::IndexVersion {
        let mut v = tame_index::IndexVersion::fake("test-crate", version);
        v.yanked = yanked;
        v.pubtime = Some(pubtime.into());
        v
    }
}
