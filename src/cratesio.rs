use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use semver::Version;
use serde::Deserialize;

const USER_AGENT: &str = concat!(
    "cargo-depcheck/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/debarajrout/cargo-depcheck)"
);

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

pub fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .context("failed to build HTTP client")
}

pub async fn fetch(client: &Client, crate_name: &str) -> Result<Metadata> {
    let url = format!("https://crates.io/api/v1/crates/{crate_name}");

    let resp: ApiResponse = client
        .get(&url)
        .send()
        .await
        .context("request failed")?
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
