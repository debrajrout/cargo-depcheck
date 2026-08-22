//! CLI-level integration tests. Network-free by construction: every test
//! here targets `tests/fixtures/no-deps`, a crate with zero dependencies, so
//! the crates.io fetch phase has nothing to attempt and every run completes
//! instantly regardless of network availability.

use assert_cmd::Command;
use predicates::prelude::*;

const NO_DEPS_MANIFEST: &str = "tests/fixtures/no-deps/Cargo.toml";

fn depcheck() -> Command {
    Command::cargo_bin("cargo-depcheck").expect("binary should build")
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
        .args(["depcheck", "--manifest-path", NO_DEPS_MANIFEST, "--quiet"])
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
        .args(["depcheck", "--manifest-path", NO_DEPS_MANIFEST])
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
        .args(["depcheck", "--manifest-path", NO_DEPS_MANIFEST])
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
