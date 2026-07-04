# Security policy

## Reporting a vulnerability in cargo-depcheck

If you believe you have found a security vulnerability in **this tool** (not in
a third-party crate that depcheck reports on), please report it responsibly.

**Do not open a public GitHub issue for security bugs.**

Instead, email **debaraj@zoop.one** with:

- A description of the vulnerability
- Steps to reproduce
- Impact assessment (if known)
- Your suggested fix (optional)

You should receive a response within **7 days**. We will work with you on a fix
and coordinated disclosure before any public announcement.

## What this policy covers

| In scope | Out of scope |
|----------|--------------|
| Bugs in cargo-depcheck source code | CVEs in your project's dependencies |
| Credential leaks, unsafe network handling | RustSec advisories depcheck surfaces |
| JSON/CLI output injection issues | crates.io or RustSec upstream issues |

For vulnerabilities **in your dependencies**, use [RustSec](https://rustsec.org/)
and `cargo audit` — that is what depcheck helps you triage, not what this policy
covers.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest on `main` | yes |
| older releases | best-effort |
