//! CLI-level integration tests. Network-free by construction: every test
//! here targets `tests/fixtures/no-deps`, a crate with zero dependencies, so
//! the crates.io fetch phase has nothing to attempt and every run completes
//! instantly regardless of network availability.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

const NO_DEPS_MANIFEST: &str = "tests/fixtures/no-deps/Cargo.toml";
const PATH_CHAIN_MANIFEST: &str = "tests/fixtures/chain/Cargo.toml";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn depcheck() -> Command {
    Command::cargo_bin("cargo-depcheck").expect("binary should build")
}

fn copy_no_deps_fixture() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "cargo-depcheck-cli-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("src")).unwrap();
    for relative in ["Cargo.toml", "Cargo.lock", "src/main.rs"] {
        fs::copy(
            std::path::Path::new("tests/fixtures/no-deps").join(relative),
            root.join(relative),
        )
        .unwrap();
    }
    root
}

#[test]
fn version_flag_prints_version_and_exits_zero() {
    depcheck()
        .args(["depcheck", "--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn bare_invocation_help_does_not_leak_internal_comment() {
    depcheck()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Outer struct").not());
}

#[test]
fn subcommand_help_does_not_leak_internal_comment() {
    depcheck()
        .args(["depcheck", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Outer struct").not());
}

#[test]
fn quiet_prints_at_most_two_lines() {
    let assert = depcheck()
        .args([
            "depcheck",
            "--manifest-path",
            NO_DEPS_MANIFEST,
            "--quiet",
            "--no-advisories",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.lines().count() <= 2,
        "expected <= 2 lines, got: {stdout:?}"
    );
}

#[test]
fn no_color_env_disables_ansi_escapes() {
    let assert = depcheck()
        .env("NO_COLOR", "1")
        .args([
            "depcheck",
            "--manifest-path",
            NO_DEPS_MANIFEST,
            "--no-advisories",
        ])
        .assert()
        .success();
    assert!(!assert.get_output().stdout.contains(&0x1b));
}

#[test]
fn color_never_wins_over_clicolor_force() {
    let assert = depcheck()
        .env("CLICOLOR_FORCE", "1")
        .args([
            "depcheck",
            "--manifest-path",
            NO_DEPS_MANIFEST,
            "--color",
            "never",
            "--no-advisories",
        ])
        .assert()
        .success();
    assert!(!assert.get_output().stdout.contains(&0x1b));
}

#[test]
fn color_always_forces_ansi_even_with_no_color_set() {
    let assert = depcheck()
        .env("NO_COLOR", "1")
        .args([
            "depcheck",
            "--manifest-path",
            NO_DEPS_MANIFEST,
            "--color",
            "always",
            "--no-advisories",
        ])
        .assert()
        .success();
    assert!(assert.get_output().stdout.contains(&0x1b));
}

#[test]
fn empty_no_color_does_not_disable_color() {
    // NO_COLOR must be "present and not an empty string" to apply —
    // https://no-color.org/. An empty value must not suppress color.
    let assert = depcheck()
        .env("NO_COLOR", "")
        .env("CLICOLOR_FORCE", "1")
        .args([
            "depcheck",
            "--manifest-path",
            NO_DEPS_MANIFEST,
            "--no-advisories",
        ])
        .assert()
        .success();
    assert!(assert.get_output().stdout.contains(&0x1b));
}

#[test]
fn invalid_flag_value_exits_two() {
    depcheck()
        .args(["depcheck", "--fail-on", "bogus"])
        .assert()
        .code(2);
}

#[test]
fn upgrade_help_documents_the_safety_controls() {
    depcheck()
        .args(["depcheck", "upgrade", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--compatible"))
        .stdout(predicate::str::contains("--dry-run"))
        .stdout(predicate::str::contains("--no-verify"));
}

#[test]
fn upgrade_requires_explicit_compatible_mode() {
    depcheck()
        .args(["depcheck", "upgrade"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--compatible"));
}

#[test]
fn upgrade_rejects_lockfile_guards_before_analysis() {
    for flag in ["--locked", "--frozen", "--offline"] {
        depcheck()
            .args([
                "depcheck",
                "upgrade",
                "--compatible",
                flag,
                "--manifest-path",
                NO_DEPS_MANIFEST,
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("cannot be used"));
    }
}

#[test]
fn upgrade_rejects_machine_readable_formats() {
    for args in [
        vec!["--json"],
        vec!["--format", "sarif"],
        vec!["--format", "json"],
    ] {
        depcheck()
            .args(["depcheck", "upgrade", "--compatible"])
            .args(args)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("cannot be used"));
    }
}

#[test]
fn upgrade_dry_run_leaves_lockfile_unchanged() {
    let root = copy_no_deps_fixture();
    let lockfile = root.join("Cargo.lock");
    let before = fs::read(&lockfile).unwrap();
    depcheck()
        .args([
            "depcheck",
            "upgrade",
            "--compatible",
            "--dry-run",
            "--no-advisories",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .assert()
        .success()
        .stdout(predicate::str::contains("No compatible lockfile upgrades"));
    assert_eq!(fs::read(&lockfile).unwrap(), before);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn path_dependencies_are_not_applicable_not_unknown() {
    let assert = depcheck()
        .args([
            "depcheck",
            "--manifest-path",
            PATH_CHAIN_MANIFEST,
            "--no-advisories",
            "--json",
        ])
        .assert()
        .success();
    let report: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("valid JSON report");

    assert_eq!(report["schema_version"], 3);
    assert_eq!(report["summary"]["total"], 2);
    assert_eq!(report["summary"]["not_applicable"], 2);
    assert_eq!(report["summary"]["unknown"], 0);
    assert_eq!(report["summary"]["healthy"], 0);
}

/// A fixture pinning one real crates.io dependency (`libc`), with a
/// committed lockfile, so its resolved version never changes underfoot.
/// Unlike every other test here, the tests below need the crate's source
/// already present in the local cargo cache before the proxy is broken —
/// `cargo metadata` itself needs that to resolve the graph at all, which is
/// a Cargo behavior, not something this tool controls. `warm_up_cache()`
/// isolates that one real-network dependency into an explicit, documented
/// step; the actual behavior under test (a broken registry connection)
/// still needs no network once the cache is warm.
const ONE_REGISTRY_DEP_MANIFEST: &str = "tests/fixtures/one-registry-dep/Cargo.toml";

fn warm_up_cache() {
    std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--manifest-path",
            ONE_REGISTRY_DEP_MANIFEST,
            "--format-version",
            "1",
        ])
        .output()
        .expect("warm-up `cargo metadata` failed to even run");
}

/// `--no-fetch` means "use the cached advisory DB, no git pull" — it
/// requires that cache to already exist, and errors otherwise (see
/// `advisories::load_cached`). On a fresh machine or CI runner with no
/// `~/.cargo/advisory-db`, every test below that passes `--no-fetch`
/// without this warm-up first fails outright, not just runs slower — this
/// isolates that one real-network dependency the same way `warm_up_cache`
/// does for the registry side.
fn warm_up_advisory_db() {
    depcheck()
        .args(["depcheck", "--manifest-path", NO_DEPS_MANIFEST])
        .output()
        .expect("warm-up advisory fetch failed to even run");
}

#[test]
fn degraded_registry_exits_three() {
    warm_up_cache();
    warm_up_advisory_db();
    depcheck()
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("CARGO_DEPCHECK_TEST_BATCH_TIMEOUT_MS", "3000")
        .args([
            "depcheck",
            "--manifest-path",
            ONE_REGISTRY_DEP_MANIFEST,
            "--no-fetch",
        ])
        .timeout(std::time::Duration::from_secs(15))
        .assert()
        .code(3);
}

#[test]
fn degraded_registry_with_allow_incomplete_exits_zero() {
    warm_up_cache();
    warm_up_advisory_db();
    depcheck()
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("CARGO_DEPCHECK_TEST_BATCH_TIMEOUT_MS", "3000")
        .args([
            "depcheck",
            "--manifest-path",
            ONE_REGISTRY_DEP_MANIFEST,
            "--no-fetch",
            "--allow-incomplete",
            "--quiet",
        ])
        .timeout(std::time::Duration::from_secs(15))
        .assert()
        .success()
        .stdout(predicate::str::contains("INCOMPLETE"));
}

const YANKED_DEP_MANIFEST: &str = "tests/fixtures/yanked-dep/Cargo.toml";

#[test]
fn yanked_version_is_detected_and_scored() {
    warm_up_advisory_db();
    let assert = depcheck()
        .args([
            "depcheck",
            "--manifest-path",
            YANKED_DEP_MANIFEST,
            "--no-fetch",
            "--threshold",
            "0",
            "--json",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON report");
    let libc = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "libc")
        .unwrap_or_else(|| panic!("libc must appear as a finding: {report}"));

    assert_eq!(libc["version"], "0.2.63");
    assert!(
        libc["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap().starts_with("yanked:")),
        "expected a yanked reason line, got: {libc}"
    );
    assert!(
        libc["components"]["security"].as_f64().unwrap() >= 40.0,
        "a yanked version should score at least the High-severity tier: {libc}"
    );
}

#[test]
fn high_display_threshold_does_not_bypass_fail_on() {
    warm_up_advisory_db();
    depcheck()
        .args([
            "depcheck",
            "--manifest-path",
            YANKED_DEP_MANIFEST,
            "--no-fetch",
            "--threshold",
            "100",
            "--fail-on",
            "warn",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("1 warning"))
        .stdout(predicate::str::contains("No dependencies scored"));
}

#[test]
fn completions_emits_a_nonempty_script_for_every_supported_shell() {
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let assert = depcheck()
            .args(["depcheck", "completions", shell])
            .assert()
            .success();
        let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        assert!(
            stdout.contains("cargo-depcheck"),
            "{shell} completion script should reference the binary name: {stdout}"
        );
        assert!(
            stdout.contains("upgrade"),
            "{shell} completion script should include the upgrade command"
        );
    }
}

#[test]
fn completions_is_hidden_from_help() {
    depcheck()
        .args(["depcheck", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("completions").not());
}

#[test]
fn mangen_emits_roff_with_the_binary_name() {
    depcheck()
        .args(["depcheck", "mangen"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(".ie"))
        .stdout(predicate::str::contains("cargo\\-depcheck"))
        .stdout(predicate::str::contains("upgrade"));
}
