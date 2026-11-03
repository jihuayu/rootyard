# Phase-one verification record

This record distinguishes completed local checks from unsupported guarantees. The automated JSON report is generated with `--report test-results/e2e.json`; test artifacts are not source-controlled.

## Local environment

- Linux, Debian 13.
- Rust/cargo 1.99.1.
- PostgreSQL 17.11.
- Git 2.52.0 and Git 2.56.0, each used as both client and server.

These are tested tool versions, not a promise that every version above the minimum behaves identically. The Docker image and GitHub Actions environment are separate verification targets.

## End-to-end results

Both versioned reports show **15 of 15 cases passed** on 2026-11-03:

- `test-results/e2e-git-2.52.json`
- `test-results/e2e-git-2.56.json`

Both exercised the same debug binary, SHA-256 `a35ebecf851f6d4b7124e006831fa83d8c4130ac8d64d26bc63d8812d13a5e66`.

Covered cases:

- Real standard-client clone/commit/push/clone/fetch and integrity checks.
- Token digests/expiry, authentication, owner isolation, paths and write permissions.
- Branches, tags, deletion, non-fast-forward rejection and atomic ref updates.
- Parallel ref updates, malformed/interrupted uploads and restart persistence.
- A 40-branch clone triggering native Git gzip requests, explicit gzip/x-gzip and malformed gzip rejection.
- Slow-reader/incomplete-upload cleanup using one Git slot, a two-second timeout and a 12 MiB incompressible payload; observed Git descendants were reaped and capacity released.
- Interrupted provisioning recovery, including missing, staged and published repository states.
- Provisioning fairness with 64 blocked jobs and a later valid job; symlink targets remained untouched.
- Content-length, chunked and expanded-gzip request limits, output limits and a healthy clone after restoring defaults.
- Offline paired PostgreSQL schema dump/restore and full Git-directory copy, followed by independent clone/fsck/ref checks and preserved read-only/revoked access behavior.

Child-cleanup checks enumerate the Linux process hierarchy using `/proc` parent IDs and start times, rather than relying on the main thread’s child list.

## Build and unit checks

Completed successfully: `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --all-targets` (six unit tests), debug build and release build. Two unit tests specifically exercise process lifecycle.

The final harness separates valid decoded/chunked input-cap fixtures from output-cap failures, checks a 64 KiB clone-output cap, and then repeats identical negotiation and a full clone successfully after resetting limits. Both versioned 15-case runs passed with these final fixtures.

Independent additional Git 2.56 checks covered protocol v0/v1/v2, chunked plain/gzip, multi-member gzip, expanded/wire/output caps, and failed truncated streams after HTTP headers were already sent.

## Boundaries

- Provisioning interruption tests inject deterministic states, not every possible hardware interruption.
- Process-kill recovery is not kernel, PostgreSQL, device or power-loss failure testing.
- The backup drill restores only the harness-owned schema and data tree, not a fresh external database/server deployment.
- Executable-file modes and symlink roundtrips are not covered by the current harness.
- Loopback concurrency and timings are functional checks, not a capacity benchmark or latency SLA.
- No HA, multi-node fencing, complete push audit/outbox or Git/PostgreSQL atomic transaction is claimed.
- Container build/runtime and hosted CI have not yet been verified by this local run.
