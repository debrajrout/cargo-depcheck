use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use semver::Version;

use crate::analyze::{self, Analysis};
use crate::cli::{Args, OutputFormat, UpgradeArgs};
use crate::report::Finding;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    name: String,
    from: Version,
    to: Version,
    score: String,
}

impl Candidate {
    fn spec(&self) -> String {
        format!("{}@{}", self.name, self.from)
    }
}

pub async fn run(args: &Args, upgrade_args: &UpgradeArgs) -> Result<()> {
    validate_flags(args, upgrade_args);
    let analysis = analyze::run(args, false, Utc::now()).await?;
    if analysis.degraded {
        eprintln!("error: dependency data is incomplete; refusing to modify Cargo.lock");
        std::process::exit(3);
    }

    let (candidates, skipped) = select_candidates(&analysis);
    print_skipped(&skipped);
    if candidates.is_empty() {
        println!("No compatible lockfile upgrades are available for the selected findings.");
        return Ok(());
    }

    let manifest = analysis.workspace_root.join("Cargo.toml");
    let runner = SystemCargo::new(&analysis.workspace_root);
    let mut validated = Vec::new();
    println!(
        "{} compatible {} selected:",
        candidates.len(),
        crate::plural(candidates.len(), "upgrade", "upgrades")
    );
    for candidate in candidates {
        println!(
            "  {} {} → {}  (score {})",
            candidate.name, candidate.from, candidate.to, candidate.score
        );
        match preflight(&runner, &manifest, &candidate) {
            Ok(()) => validated.push(candidate),
            Err(err) => {
                println!(
                    "    skipped: Cargo.toml constraints prevent this lockfile-only update ({err})"
                );
            }
        }
    }

    if validated.is_empty() {
        println!("Cargo confirmed that none of the selected upgrades can change Cargo.lock.");
        return Ok(());
    }
    if upgrade_args.dry_run {
        println!(
            "\nDry run complete: {} {} can be applied; Cargo.lock was not changed.",
            validated.len(),
            crate::plural(validated.len(), "upgrade", "upgrades")
        );
        return Ok(());
    }

    let lockfile = analysis.workspace_root.join("Cargo.lock");
    let original =
        fs::read(&lockfile).with_context(|| format!("failed to back up {}", lockfile.display()))?;
    let mut transaction = LockfileTransaction::new(lockfile.clone(), original.clone());

    for candidate in &validated {
        apply_update(&runner, &manifest, candidate).with_context(|| {
            format!(
                "failed to update {} from {} to {}; Cargo.lock was restored",
                candidate.name, candidate.from, candidate.to
            )
        })?;
    }

    let updated = fs::read(&lockfile)
        .with_context(|| format!("failed to read updated {}", lockfile.display()))?;
    if updated == original {
        transaction.commit();
        println!("Cargo.lock is already up to date within the selected compatibility lines.");
        return Ok(());
    }

    if !upgrade_args.no_verify {
        println!("\nVerifying the updated workspace with cargo check...");
        if !runner.check(&manifest)? {
            transaction.restore()?;
            bail!("cargo check failed; the original Cargo.lock was restored");
        }
    }

    let changes = lockfile_changes(&original, &updated);
    transaction.commit();
    println!("\nUpdated Cargo.lock:");
    for change in &changes {
        println!("  {change}");
    }
    if upgrade_args.no_verify {
        println!("Verification skipped (--no-verify).");
    } else {
        println!("Workspace verification passed.");
    }
    Ok(())
}

fn validate_flags(args: &Args, upgrade_args: &UpgradeArgs) {
    let incompatible = if args.locked {
        Some("--locked")
    } else if args.frozen {
        Some("--frozen")
    } else if args.offline {
        Some("--offline")
    } else if args.json {
        Some("--json")
    } else if matches!(args.format, Some(OutputFormat::Json | OutputFormat::Sarif)) {
        Some("--format json/sarif")
    } else {
        None
    };
    if let Some(flag) = incompatible {
        eprintln!("error: {flag} cannot be used with `upgrade --compatible`");
        std::process::exit(2);
    }
    debug_assert!(upgrade_args.compatible);
}

fn select_candidates(analysis: &Analysis) -> (Vec<Candidate>, Vec<String>) {
    select_candidates_from(&analysis.visible_findings, &analysis.meta_map)
}

fn select_candidates_from(
    findings: &[Finding],
    meta_map: &HashMap<String, crate::registry::Metadata>,
) -> (Vec<Candidate>, Vec<String>) {
    let mut candidates = Vec::new();
    let mut skipped = Vec::new();
    for finding in findings {
        if !finding.node.is_registry {
            skipped.push(format!(
                "{} {}: non-registry dependency; update its source manually",
                finding.node.name, finding.node.version
            ));
            continue;
        }
        let Some(metadata) = meta_map.get(&finding.node.name) else {
            skipped.push(format!(
                "{} {}: registry metadata unavailable",
                finding.node.name, finding.node.version
            ));
            continue;
        };
        let Some(target) = metadata.latest_compatible(&finding.node.version) else {
            skipped.push(manual_guidance(finding, metadata.latest_stable()));
            continue;
        };
        candidates.push(Candidate {
            name: finding.node.name.clone(),
            from: finding.node.version.clone(),
            to: target.clone(),
            score: format!("{:.1}", crate::score::rounded(finding.risk.total)),
        });
    }
    candidates.dedup_by(|a, b| a.name == b.name && a.from == b.from && a.to == b.to);
    (candidates, skipped)
}

fn manual_guidance(finding: &Finding, latest: &Version) -> String {
    if &finding.node.version < latest {
        format!(
            "{} {}: latest {} requires a Cargo.toml or parent-dependency upgrade; inspect with `cargo tree -i {}@{}`",
            finding.node.name,
            finding.node.version,
            latest,
            finding.node.name,
            finding.node.version
        )
    } else {
        format!(
            "{} {}: no newer compatible stable release",
            finding.node.name, finding.node.version
        )
    }
}

fn print_skipped(skipped: &[String]) {
    if skipped.is_empty() {
        return;
    }
    println!("Manual action required:");
    for reason in skipped {
        println!("  {reason}");
    }
    println!();
}

trait CargoRunner {
    fn update(&self, manifest: &Path, candidate: &Candidate, dry_run: bool) -> Result<Output>;
    fn check(&self, manifest: &Path) -> Result<bool>;
}

struct SystemCargo {
    cargo: OsString,
    cwd: PathBuf,
}

impl SystemCargo {
    fn new(cwd: &Path) -> Self {
        Self {
            cargo: std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")),
            cwd: cwd.to_path_buf(),
        }
    }
}

impl CargoRunner for SystemCargo {
    fn update(&self, manifest: &Path, candidate: &Candidate, dry_run: bool) -> Result<Output> {
        let mut command = Command::new(&self.cargo);
        command
            .current_dir(&self.cwd)
            .arg("update")
            .arg("--manifest-path")
            .arg(manifest)
            .arg("-p")
            .arg(candidate.spec())
            .arg("--precise")
            .arg(candidate.to.to_string());
        if dry_run {
            command.arg("--dry-run");
        }
        command.output().context("failed to run cargo update")
    }

    fn check(&self, manifest: &Path) -> Result<bool> {
        let status = Command::new(&self.cargo)
            .current_dir(&self.cwd)
            .arg("check")
            .arg("--workspace")
            .arg("--manifest-path")
            .arg(manifest)
            .status()
            .context("failed to run cargo check")?;
        Ok(status.success())
    }
}

fn preflight(runner: &dyn CargoRunner, manifest: &Path, candidate: &Candidate) -> Result<()> {
    let output = runner.update(manifest, candidate, true)?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{}", concise_error(&stderr))
    }
}

fn apply_update(runner: &dyn CargoRunner, manifest: &Path, candidate: &Candidate) -> Result<()> {
    let output = runner.update(manifest, candidate, false)?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{}", concise_error(&stderr))
    }
}

fn concise_error(stderr: &str) -> String {
    stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("cargo update failed")
        .trim()
        .to_string()
}

struct LockfileTransaction {
    path: PathBuf,
    original: Vec<u8>,
    active: bool,
}

impl LockfileTransaction {
    fn new(path: PathBuf, original: Vec<u8>) -> Self {
        Self {
            path,
            original,
            active: true,
        }
    }

    fn restore(&mut self) -> Result<()> {
        restore_lockfile(&self.path, &self.original)?;
        self.active = false;
        Ok(())
    }

    fn commit(&mut self) {
        self.active = false;
    }
}

impl Drop for LockfileTransaction {
    fn drop(&mut self) {
        if self.active {
            let _ = restore_lockfile(&self.path, &self.original);
        }
    }
}

fn restore_lockfile(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("lock.cargo-depcheck.tmp");
    fs::write(&temp, bytes)
        .with_context(|| format!("failed to write lockfile backup {}", temp.display()))?;
    if fs::rename(&temp, path).is_err() {
        fs::write(path, bytes).with_context(|| format!("failed to restore {}", path.display()))?;
        let _ = fs::remove_file(temp);
    }
    Ok(())
}

fn lockfile_changes(before: &[u8], after: &[u8]) -> Vec<String> {
    let before = parse_lockfile_packages(before);
    let after = parse_lockfile_packages(after);
    let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut changes = Vec::new();
    for name in names {
        let old = before.get(name).cloned().unwrap_or_default();
        let new = after.get(name).cloned().unwrap_or_default();
        if old != new {
            changes.push(format!(
                "{}: {} → {}",
                name,
                display_versions(&old),
                display_versions(&new)
            ));
        }
    }
    changes
}

fn parse_lockfile_packages(bytes: &[u8]) -> BTreeMap<String, BTreeSet<String>> {
    let text = String::from_utf8_lossy(bytes);
    let mut packages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in text.lines().chain(std::iter::once("[[package]]")) {
        if line == "[[package]]" {
            if let (Some(name), Some(version)) = (name.take(), version.take()) {
                packages.entry(name).or_default().insert(version);
            }
            in_package = true;
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(value) = quoted_value(line, "name") {
            name = Some(value);
        } else if let Some(value) = quoted_value(line, "version") {
            version = Some(value);
        }
    }
    packages
}

fn quoted_value(line: &str, key: &str) -> Option<String> {
    let value = line.strip_prefix(&format!("{key} = \""))?;
    Some(value.strip_suffix('"')?.to_string())
}

fn display_versions(versions: &BTreeSet<String>) -> String {
    if versions.is_empty() {
        "removed".into()
    } else {
        versions.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct FailingRunner;

    impl CargoRunner for FailingRunner {
        fn update(
            &self,
            _manifest: &Path,
            _candidate: &Candidate,
            _dry_run: bool,
        ) -> Result<Output> {
            bail!("version is blocked by the manifest")
        }

        fn check(&self, _manifest: &Path) -> Result<bool> {
            Ok(false)
        }
    }

    fn candidate() -> Candidate {
        Candidate {
            name: "demo".into(),
            from: Version::new(1, 0, 0),
            to: Version::new(1, 2, 0),
            score: "42.0".into(),
        }
    }

    fn finding(name: &str, version: Version, is_registry: bool) -> Finding {
        Finding {
            node: crate::graph::DependencyNode {
                name: name.into(),
                version,
                is_direct: true,
                depth: 1,
                dependent_count: 1,
                transitive_dependent_count: 1,
                is_registry,
                kind: crate::graph::NodeKind::Normal,
            },
            risk: crate::score::RiskScore {
                security: 0.0,
                version_lag: 42.0,
                maintenance: 0.0,
                graph_multiplier: 1.0,
                total: 42.0,
                level: crate::score::RiskLevel::Warn,
            },
            advisories: Vec::new(),
        }
    }

    fn metadata(versions: Vec<Version>) -> crate::registry::Metadata {
        crate::registry::Metadata {
            newest_version: versions.last().cloned().unwrap(),
            max_stable_version: versions.last().cloned(),
            stable_versions: versions,
            updated_at: Utc::now(),
            yanked_versions: Vec::new(),
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cargo-depcheck-{name}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn lockfile_diff_reports_version_changes() {
        let before = br#"[[package]]
name = "demo"
version = "1.0.0"
"#;
        let after = br#"[[package]]
name = "demo"
version = "1.2.0"
"#;
        assert_eq!(lockfile_changes(before, after), ["demo: 1.0.0 → 1.2.0"]);
    }

    #[test]
    fn duplicate_versions_are_preserved_in_lockfile_diff() {
        let lock = br#"[[package]]
name = "demo"
version = "1.0.0"
[[package]]
name = "demo"
version = "2.0.0"
"#;
        assert_eq!(
            parse_lockfile_packages(lock)["demo"],
            BTreeSet::from(["1.0.0".into(), "2.0.0".into()])
        );
    }

    #[test]
    fn duplicate_package_specs_include_the_resolved_version() {
        assert_eq!(candidate().spec(), "demo@1.0.0");
    }

    #[test]
    fn cargo_preflight_failure_is_actionable() {
        let error = preflight(&FailingRunner, Path::new("Cargo.toml"), &candidate())
            .expect_err("preflight should fail");
        assert!(error.to_string().contains("blocked by the manifest"));
    }

    #[test]
    fn active_transaction_rolls_back_on_drop() {
        let path = temp_path("rollback");
        fs::write(&path, b"original").unwrap();
        {
            let _transaction = LockfileTransaction::new(path.clone(), b"original".to_vec());
            fs::write(&path, b"changed").unwrap();
        }
        assert_eq!(fs::read(&path).unwrap(), b"original");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn committed_transaction_keeps_the_change() {
        let path = temp_path("commit");
        fs::write(&path, b"original").unwrap();
        {
            let mut transaction = LockfileTransaction::new(path.clone(), b"original".to_vec());
            fs::write(&path, b"changed").unwrap();
            transaction.commit();
        }
        assert_eq!(fs::read(&path).unwrap(), b"changed");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn selection_keeps_duplicate_versions_unambiguous() {
        let findings = vec![
            finding("demo", Version::new(1, 0, 0), true),
            finding("demo", Version::new(2, 0, 0), true),
        ];
        let metadata = HashMap::from([(
            "demo".into(),
            metadata(vec![
                Version::new(1, 0, 0),
                Version::new(1, 5, 0),
                Version::new(2, 0, 0),
                Version::new(2, 3, 0),
            ]),
        )]);
        let (selected, skipped) = select_candidates_from(&findings, &metadata);
        assert!(skipped.is_empty());
        assert_eq!(
            selected.iter().map(Candidate::spec).collect::<Vec<_>>(),
            ["demo@1.0.0", "demo@2.0.0"]
        );
        assert_eq!(selected[0].to, Version::new(1, 5, 0));
        assert_eq!(selected[1].to, Version::new(2, 3, 0));
    }

    #[test]
    fn selection_excludes_path_and_zero_zero_dependencies() {
        let findings = vec![
            finding("local", Version::new(1, 0, 0), false),
            finding("tiny", Version::new(0, 0, 1), true),
        ];
        let metadata = HashMap::from([(
            "tiny".into(),
            metadata(vec![Version::new(0, 0, 1), Version::new(0, 0, 2)]),
        )]);
        let (selected, skipped) = select_candidates_from(&findings, &metadata);
        assert!(selected.is_empty());
        assert_eq!(skipped.len(), 2);
        assert!(skipped[0].contains("non-registry"));
        assert!(skipped[1].contains("Cargo.toml"));
    }
}
