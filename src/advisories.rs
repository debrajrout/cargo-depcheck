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
///
/// Goes through `Repository::open` + `Database::load_from_repo` rather than
/// the simpler `Database::open`, purely so `commit_hash()` below still has
/// something to report for `--no-fetch` runs — both read the same on-disk
/// checkout, neither touches the network.
pub fn load_cached() -> Result<Database> {
    let path = Repository::default_path();
    let repo = Repository::open(&path).with_context(|| {
        format!(
            "failed to open cached advisory database at {} — run without --no-fetch first",
            path.display()
        )
    })?;
    Database::load_from_repo(&repo).context("failed to load advisories from cached repository")
}

/// SHA-1 of the advisory database's HEAD commit, for provenance in JSON
/// output. `None` only if the underlying git metadata couldn't be read.
pub fn commit_hash(db: &Database) -> Option<String> {
    db.latest_commit()
        .map(|commit| commit.commit_id.to_string())
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
