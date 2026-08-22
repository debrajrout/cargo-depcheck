use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::{header::RETRY_AFTER, Client, StatusCode};
use semver::Version;
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

/// Derived from `Cargo.toml`'s `repository` field so the contact URL can
/// never drift from the real repo (crates.io's data-access policy requires
/// a User-Agent that identifies the application and how to reach its author).
const USER_AGENT: &str = concat!(
    "cargo-depcheck/",
    env!("CARGO_PKG_VERSION"),
    " (+",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

/// crates.io's documented policy caps the JSON API at 1 request/second.
/// See https://crates.io/data-access. The sparse index (P1-1) has no such
/// limit; this exists only because the JSON API is still in use until then.
const MIN_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

const MAX_RETRIES: u32 = 3;
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct Metadata {
    /// Latest version published, including pre-releases.
    pub newest_version: Version,
    /// Latest stable (non-pre-release) version. Usually the one to compare against.
    pub max_stable_version: Option<Version>,
    /// When any version of this crate was last published — the primary maintenance signal.
    pub updated_at: DateTime<Utc>,
}

impl Metadata {
    /// The version a user should be on: stable if available, otherwise newest.
    pub fn latest_stable(&self) -> &Version {
        self.max_stable_version
            .as_ref()
            .unwrap_or(&self.newest_version)
    }
}

// Private structs that mirror the crates.io API shape. Kept out of the public
// surface so callers only ever see `Metadata`.
#[derive(Deserialize)]
struct ApiResponse {
    #[serde(rename = "crate")]
    krate: ApiCrate,
}

#[derive(Deserialize)]
struct ApiCrate {
    newest_version: String,
    max_stable_version: Option<String>,
    updated_at: DateTime<Utc>,
}

/// Paces requests to at most one per second, as crates.io's API policy
/// requires. Shared across every concurrent fetch task so the limit holds
/// regardless of how many are in flight.
pub struct RateLimiter {
    min_interval: Duration,
    next_slot: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            next_slot: Mutex::new(Instant::now()),
        }
    }

    /// Blocks until it is this caller's turn, then reserves the next slot.
    async fn acquire(&self) {
        let wait = {
            let mut next_slot = self.next_slot.lock().await;
            let now = Instant::now();
            let start = (*next_slot).max(now);
            *next_slot = start + self.min_interval;
            start.saturating_duration_since(now)
        };
        if !wait.is_zero() {
            sleep(wait).await;
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(MIN_REQUEST_INTERVAL)
    }
}

pub fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .context("failed to build HTTP client")
}

pub async fn fetch(client: &Client, limiter: &RateLimiter, crate_name: &str) -> Result<Metadata> {
    let url = format!("https://crates.io/api/v1/crates/{crate_name}");

    let mut attempt: u32 = 0;
    let response = loop {
        limiter.acquire().await;
        let response = client.get(&url).send().await.context("request failed")?;

        if response.status() != StatusCode::TOO_MANY_REQUESTS {
            break response;
        }

        if attempt >= MAX_RETRIES {
            anyhow::bail!("crates.io rate-limited this request after {MAX_RETRIES} retries");
        }

        // Observed live: crates.io's 429s often carry no Retry-After header,
        // so a default exponential backoff is required, not just optional.
        let backoff = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_RETRY_AFTER * 2u32.pow(attempt));

        sleep(backoff).await;
        attempt += 1;
    };

    let resp: ApiResponse = response
        .error_for_status()
        .context("crates.io returned an error status")?
        .json()
        .await
        .context("failed to deserialize crates.io response")?;

    let newest_version =
        Version::parse(&resp.krate.newest_version).context("invalid newest_version in response")?;

    let max_stable_version = resp
        .krate
        .max_stable_version
        .as_deref()
        .and_then(|v| Version::parse(v).ok());

    Ok(Metadata {
        newest_version,
        max_stable_version,
        updated_at: resp.krate.updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_matches_the_real_repository() {
        assert!(USER_AGENT.contains(env!("CARGO_PKG_REPOSITORY")));
        assert!(!USER_AGENT.contains("debarajrout"));
    }

    #[tokio::test]
    async fn rate_limiter_paces_sequential_acquires() {
        let limiter = RateLimiter::new(Duration::from_millis(50));
        let start = Instant::now();
        limiter.acquire().await;
        limiter.acquire().await;
        limiter.acquire().await;
        // Three acquires must span at least two full intervals.
        assert!(start.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn rate_limiter_paces_concurrent_acquires_from_many_tasks() {
        // This is the property the crates.io policy actually cares about:
        // even when many fetches race to start at once, the achieved rate
        // must stay at or below 1/interval — never bursty.
        use std::sync::Arc;

        let limiter = Arc::new(RateLimiter::new(Duration::from_millis(20)));
        let start = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let limiter = limiter.clone();
            set.spawn(async move { limiter.acquire().await });
        }
        while set.join_next().await.is_some() {}

        // 5 acquires at a 20ms floor must span at least 4 intervals (80ms),
        // and should not blow up into something unbounded either.
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(80), "elapsed={elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "elapsed={elapsed:?}");
    }
}
