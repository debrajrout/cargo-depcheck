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
fn top_rejects_zero_rather_than_silently_reporting_nothing() {
    depcheck()
        .args([
            "depcheck",
            "--top",
            "0",
            "--manifest-path",
            NO_DEPS_MANIFEST,
        ])
        .assert()
        .code(2);
}

#[test]
fn markdown_output_is_plain_and_carries_the_sticky_comment_marker() {
    let assert = depcheck()
        .args([
            "depcheck",
            "--format",
            "markdown",
            "--no-advisories",
            "--manifest-path",
            NO_DEPS_MANIFEST,
        ])
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(
        stdout.starts_with("<!-- cargo-depcheck -->"),
        "the marker must be first so automation can update its own comment: {stdout}"
    );
    // CLICOLOR_FORCE is set above precisely because CI often sets it: the
    // Markdown body must never carry terminal escapes into a PR comment.
    assert!(
        !stdout.contains('\u{1b}'),
        "ANSI escape leaked into Markdown: {stdout:?}"
    );
    assert!(stdout.contains("cargo-depcheck —"), "{stdout}");
}

#[test]
fn a_baseline_round_trips_through_a_written_file() {
    let root = copy_no_deps_fixture();
    let baseline = root.join("depcheck-baseline.json");

    depcheck()
        .args([
            "depcheck",
            "--no-advisories",
            "--write-baseline",
            baseline.to_str().unwrap(),
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .assert()
        .success();

    let written = fs::read_to_string(&baseline).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert!(
        parsed.get("findings").is_some_and(|f| f.is_array()),
        "a baseline must be a readable report: {written}"
    );

    // Comparing a run against a baseline taken from that same state must find
    // nothing new — the property the whole feature rests on.
    depcheck()
        .args([
            "depcheck",
            "--no-advisories",
            "--fail-on",
            "warn",
            "--baseline",
            baseline.to_str().unwrap(),
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .assert()
        .success()
        .stdout(predicate::str::contains("0 new"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_missing_baseline_file_explains_how_to_create_one() {
    depcheck()
        .args([
            "depcheck",
            "--no-advisories",
            "--baseline",
            "/nonexistent/depcheck-baseline.json",
            "--manifest-path",
            NO_DEPS_MANIFEST,
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--write-baseline"));
}

#[test]
fn write_baseline_refuses_a_truncated_report() {
    depcheck()
        .args([
            "depcheck",
            "--top",
            "3",
            "--write-baseline",
            "/tmp/should-not-be-written.json",
            "--manifest-path",
            NO_DEPS_MANIFEST,
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--top cannot be used"));
    assert!(
        !std::path::Path::new("/tmp/should-not-be-written.json").exists(),
        "the rejected run must not have written a baseline"
    );
}

#[test]
fn explain_names_a_missing_crate_and_suggests_close_matches() {
    depcheck()
        .args([
            "depcheck",
            "explain",
            "serde",
            "--no-advisories",
            "--manifest-path",
            NO_DEPS_MANIFEST,
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not in this project's analyzed"))
        .stderr(predicate::str::contains("--include-build"));
}

#[test]
fn explain_rejects_sarif_which_describes_a_project_not_a_crate() {
    depcheck()
        .args([
            "depcheck",
            "explain",
            "serde",
            "--format",
            "sarif",
            "--manifest-path",
            NO_DEPS_MANIFEST,
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--format sarif"));
}

#[test]
fn explain_help_documents_the_path_limit() {
    depcheck()
        .args(["depcheck", "explain", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--max-paths"));
}

#[test]
fn explain_reports_a_path_dependency_with_its_dependency_path() {
    // The `chain` fixture is all path dependencies, so this stays
    // network-free while still exercising the real path search:
    // chain-root → chain-mid → chain-leaf.
    depcheck()
        .args([
            "depcheck",
            "explain",
            "chain-leaf",
            "--no-advisories",
            "--color",
            "never",
            "--manifest-path",
            PATH_CHAIN_MANIFEST,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("chain-leaf"))
        .stdout(predicate::str::contains("Pulled in by"))
        .stdout(predicate::str::contains(
            "chain-root → chain-mid 0.1.0 → chain-leaf 0.1.0",
        ));
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
fn upgrade_rejects_the_baseline_flags_instead_of_ignoring_them() {
    // `upgrade` reports no findings, so it has nothing to mark new or known.
    // Accepting these silently would drop a flag the user passed deliberately.
    for args in [
        vec!["--baseline", "baseline.json"],
        vec!["--write-baseline", "baseline.json"],
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
fn upgrade_rejects_machine_readable_formats() {
    for args in [
        vec!["--json"],
        vec!["--format", "sarif"],
        vec!["--format", "json"],
        vec!["--format", "markdown"],
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

    assert_eq!(report["schema_version"], 4);
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
