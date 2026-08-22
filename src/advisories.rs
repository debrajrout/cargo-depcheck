use anyhow::{Context, Result};
use rustsec::advisory::Advisory;
use rustsec::database::Query;
use rustsec::{Collection, Database, Repository};
use semver::Version;

/// Fetch the RustSec advisory database from GitHub, refreshing the local cache when stale.
pub fn load() -> Result<Database> {
    Database::fetch().context("failed to fetch RustSec advisory database")
}

/// Open the locally cached advisory database without contacting the network.
pub fn load_cached() -> Result<Database> {
    let path = Repository::default_path();
    Database::open(&path).with_context(|| {
        format!(
            "failed to open cached advisory database at {} — run without --no-fetch first",
            path.display()
        )
    })
}

/// Query advisories affecting a specific crate name and resolved version.
///
/// Includes vulnerability advisories and informational ones (e.g. unmaintained).
pub fn lookup(db: &Database, name: &str, version: &Version) -> Vec<Advisory> {
    let Ok(package_name) = name.parse::<rustsec::package::Name>() else {
        return Vec::new();
    };

    let query = Query::new()
        .collection(Collection::Crates)
        .withdrawn(false)
        .package_name(package_name)
        .package_version(version.clone());

    db.query(&query).into_iter().cloned().collect()
}
