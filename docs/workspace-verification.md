# Workspace foundation verification record

Verified 2026-11-03 on Linux with Rust 1.99.1, Git 2.56.0 and Git 2.52.0. The hosting regression used a newly created disposable loopback PostgreSQL 17.11 cluster and synthetic repositories only. Its server was stopped afterward. No production repository, database, deployment or user's desktop was used.

## Exact exercised implementation

Base commit: `373138a` (phase-two durable GitFS events). The lab is a separate binary and is not connected to the HTTP router or production database. Existing production Rust modules are unchanged.

- Lab binary SHA-256: `f9ca450c565b7e5f85e75b4e0428e6fd63e3553c29e43220d30b7b49f7a9f812`.
- `src/workspace_lab.rs` SHA-256: `f4367736d265f21377b7b03ff23610444454d6241046bea279ecc197c03cc508`.
- `tests/workspaces.py` SHA-256: `67056047c501831beadf1e58d6d1019127bde0bad45a78cea113fe94d76b0c47`.
- Production server regression binary SHA-256: `faac5525c00d4a305bf15547888859939dc783941f24204e6eeb37f73a7ea6d2`.

These are debug-build measurements in this environment, not reproducible-release binary identities. The test harness records the tested binary hash and checks it did not change during a run.

## Results

- Formatting, Clippy with warnings denied, locked build of both binaries: passed.
- Existing Rust unit tests: 19 passed. The PostgreSQL-dependent outbox test is intentionally ignored in the default test command and was then run explicitly against the disposable cluster: 1 passed.
- Existing Smart HTTP end-to-end suite: 15 groups passed, including standard clone/push/fetch, fsck, permission isolation, ref conflicts, interruption, restart and paired offline restore.
- Existing durable reliability suite: 18 groups passed, including receipts/outbox/reconciliation and ambiguous outcomes.
- New workspace suite: **16 groups passed independently on Git 2.56.0 and 2.52.0**. Each fixture uses one Git version throughout; this is not cross-version checkpoint restoration support.

Workspace checks:

1. Source, workspace, checkpoint and two forks have disjoint regular-file inodes (135 files in the baseline fixture); edits, staging, commits and branch creation in one do not change another. Base OID remains fixed when HEAD advances.
2. HEAD, index and worktree contain three distinct versions after restoration; original index bytes, intent-to-add and untracked binary bytes survive.
3. Source hardlinks are split into independent destination files; detached HEAD remains detached.
4. A real native merge conflict retains stages 1/2/3, MERGE_HEAD and worktree bytes; resolution and merge commit after restoration succeed.
5. Nested Git ignore rules, tracked files under ignored parents, forced adds, HEAD-union `rm --cached`, and later committed deletion behave correctly. Ignored/native files stay local and are absent from forks.
6. Staged/unstaged deletes and renames preserve native status and bytes.
7. Non-UTF-8, whitespace, tab/newline and leading-dash names, internal symlinks and execution bits survive exactly.
8. Missing, modified, unexpected and wrong-mode checkpoint data fails closed; malformed paths and duplicate entries also reject after recalculating the manifest checksum.
9. Unsupported Git storage/config/index and unsafe direct/indirect symlinks are rejected without changing the source or publishing a workspace.
10. Explicit quiescence acknowledgment and native Git lock checks are enforced; this validates the interface, not the truth of the caller's quiescence assertion.
11. Source/store overlap rejects before creating any file or directory in the source.
12. Real sparse/fsmonitor/split-index cases are rejected rather than partially restored.
13. A mismatched recorded Git version rejects; the matching version restores.
14. Process exit before checkpoint publication leaves no published checkpoint; after-publication exit leaves a restorable completed checkpoint. Older checkpoints remain restorable.
15. Inherited Git configuration/environment cannot redirect observation to another repository or execute custom policy.
16. Allowed user configuration and raw line-ending bytes are preserved.

The harness creates and removes disposable fixtures. Reports are written to the ignored `test-results/` directory and CI uploads its reports. Local records: `workspaces-git-2.56.json`, `workspaces-git-2.52.json`, `workspace-baseline-e2e.json`, and `workspace-baseline-reliability.json`.

## Independent review

A separate test/review worker reproduced two issues before publication: lexical-only symlink checks admitted indirect escapes, and source/store overlap was rejected only after store initialization. Both were corrected and regression-tested. Final independent review found no remaining blocker within the explicitly trusted, caller-quiescent, local-only scope.

## Not established

This is a local full-copy semantics foundation, not completion of phase five. No performance benchmark or large-repository qualification was conducted. Functional suite timings are not throughput/RPO/RTO evidence. There was no power cut, kernel/VM crash, multi-host recovery, remote object persistence, enforced writer barrier, FUSE, live watcher, namespace mount implementation, authentication/authorization, hostile multi-tenant execution or security isolation test. The [full contract and future gates](workspace-foundation.md) remain authoritative for limitations.
