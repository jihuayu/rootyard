# Workspace Merkle Directory Manifest & Incremental Sync (Issue #181)

Versioned, immutable, domain-separated Merkle directory manifests, dirty-subtree incremental scanning, lossy watcher convergence with quiescence verification, and blob-first OpenDAL `BlobStore` sync/restore for `rootyard` workspaces (`Refs #181`).

## Architecture Overview

The implementation lives under [merkle_sync.rs](../src/workspace_lab/merkle_sync.rs) and is wired cleanly via [workspace_lab.rs](../src/workspace_lab.rs) without modifying FUSE, PostgreSQL schema, or legacy workspace state machines:

| Module | Responsibility |
| --- | --- |
| [manifest.rs](../src/workspace_lab/merkle_sync/manifest.rs) | Canonical immutable schemas (`MerkleStateManifest`, `MerkleDirNode`, `MerkleDirChild`), domain-separated SHA-256 node/entry codecs, chunk IDs, empty-dir retention policy |
| [manifest_verify.rs](../src/workspace_lab/merkle_sync/manifest_verify.rs) | Structural validation, digest recomputation verification, rename/chmod/delete/add diffing |
| [git_state.rs](../src/workspace_lab/merkle_sync/git_state.rs) | Strict `.git` compatibility validation (`sha1` & `sha256`), binary index v2/v3 parser, `(HEAD, index)` & ignore rule snapshots |
| [git_compare.rs](../src/workspace_lab/merkle_sync/git_compare.rs) | Explicit `(HEAD, index, worktree)` diff & `.git` snapshot bundling/materialization, plus `sha1`/`sha256`/conflict/ignore/non-UTF-8 unit suite |
| [scan_fs.rs](../src/workspace_lab/merkle_sync/scan_fs.rs) | Symlink-loop & `.git`-escape bounded realpath checks, POSIX mode/raw non-UTF-8 byte scanning, lossy watcher barrier unit suite |
| [scanner.rs](../src/workspace_lab/merkle_sync/scanner.rs) | Dirty-subtree incremental scanner reusing unchanged content/metadata subtrees under identical ignore rules & chunk size |
| [converge.rs](../src/workspace_lab/merkle_sync/converge.rs) | Lossy `WatcherCoalescer` (dedup, out-of-order batches, overflow/drop escalation) and pre/post single-barrier quiescence verifier |
| [authz.rs](../src/workspace_lab/merkle_sync/authz.rs) | Strict per-request tenant/repo/user authorization and active `HistoryFenceRegistry` epoch enforcement |
| [ledger.rs](../src/workspace_lab/merkle_sync/ledger.rs) | Scoped checkpoint commit ledger, mid-flight pin/hold tracking, and GC sweep protection |
| [blob_sync.rs](../src/workspace_lab/merkle_sync/blob_sync.rs) | Blob-first incremental upload of missing chunks/nodes/Git bundle, `BlobClosureSpec` readback verification, fail-closed commit |
| [restore.rs](../src/workspace_lab/merkle_sync/restore.rs) | Cross-node restore & fork into an empty target directory after full closure verification |
| [backup_restore.rs](../src/workspace_lab/merkle_sync/backup_restore.rs) | Authorized checkpoint backup export/restore across histories with hold protection |

## Domain-Separated Hashing & Semantics

- Every manifest node separates **Merkle directory state** (`merkle_root_digest` / `worktree_root_digest`) from **Git tree OIDs**, **`checkpoint_id`**, and **authorization**.
- Directory nodes, files, symlinks, empty directories (controlled via `EmptyDirPolicy::IgnoreEmptyDirs`, `RetainEmptyDirs`, `RetainNonIgnoredEmptyDirs`), raw non-UTF-8 POSIX path bytes (Base64-encoded canonically), and POSIX executable/permission bits feed bottom-up into SHA-256 node digests.
- Worktree ignore rule changes (`.gitignore`, `.rootyardignore`, `.git/info/exclude`) invalidate cached directory reuse in affected subtrees and record `ignore_rules_digest`.
- Unsupported Git states (linked worktrees, submodules/gitlinks, shallow clones, split/sparse indexes, custom hooks/filters in `.gitattributes`, replacement refs, active `.git/*.lock` files) fail closed with `NotQuiescent` or `UnsupportedGitState`.

## Lossy Watcher Convergence & Quiescence Barrier

1. `WatcherCoalescer` ingests out-of-order/duplicated events, folds duplicate path events, and escalates sequence gaps, `Overflow`, `Dropped(_)`, or root-ignore changes to `DirtyScope::FullRescan`.
2. `capture_with_quiescence_barrier` snapshots `(watcher_seq, revision, lease_epoch, .git/index)` before scanning dirty subtrees and re-checks them after scanning (`QuiescenceBarrierProbe`), refusing mixed-point states instead of publishing an inconsistent checkpoint.

## Blob-First Incremental Upload, Restore & Security Boundaries

- Content reuse lookup is scoped strictly by `(tenant_id, repo_id)` via [authz.rs](../src/workspace_lab/merkle_sync/authz.rs) and [ledger.rs](../src/workspace_lab/merkle_sync/ledger.rs); identical file contents in another tenant never trigger cross-tenant deduplication or cache hits.
- Every missing chunk, node manifest, and `.git` bundle is uploaded first via OpenDAL `BlobStore` with `BlobReceipt` + `BlobClosureSpec` readback verification before committing `checkpoint_id`; `UploadFailpoint::BeforeAtomicCommit` leaves zero committed state while allowing orphaned blobs to be swept safely by `plan_gc_sweep`.
- Deleting the local source workspace and restoring or forking into an empty directory verifies every closure object before staging, restoring files, symlinks, POSIX modes, empty directories, and `.git` state (verified with `git fsck --full --strict`).

## Verification & Reproducible Benchmark

- Rust integration & adversarial suite (`LoopbackS3` + OpenDAL + stock `git`): [workspace_merkle_sync.rs](../tests/workspace_merkle_sync.rs)
- Offline contract suite: [test_workspace_merkle_sync_contracts.py](../tests/test_workspace_merkle_sync_contracts.py)
- Workflow gate: [workspace-merkle-sync.yml](../.github/workflows/workspace-merkle-sync.yml)
- Benchmark evaluator: [eval_workspace_merkle_sync.py](../scripts/eval_workspace_merkle_sync.py)

Measured baseline (`eval_methodology_version=v2-atomic-git-dir-rename`, `mode=python-dataset-git-rename-plus-chunked-cas-v2`, `source_git_rev=62d978a7884c4c9ae60403ee4689b7a1be52ed7b`, `git version 2.45.1.windows.1`, `Windows-11-10.0.26100-SP0`, `Python 3.12.3`, `chunk_size_bytes=16384`, 5 iterations/case, single-subtree delta):

| Profile / Git Format | Dataset Digest (prefix) | Full Hashed (B) | Incr Hashed (B) | Full Wire (B) | Incr Wire (B) | Full p50 / p95 (ms) | Incr p50 / p95 (ms) | Restore p50 / p95 (ms) | Reused / Recomp Nodes | Restore `git fsck` |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `small` / `sha1` | `3ca488de55e6` | 1,179,648 | 147,456 | 2,360,674 | 34,146 | 676.61 / 807.42 | 31.60 / 35.44 | 533.69 / 917.72 | 8 / 2 | pass |
| `small` / `sha256` | `c4bf55b6fa47` | 1,179,648 | 147,456 | 2,360,674 | 34,146 | 653.55 / 805.64 | 30.03 / 40.37 | 510.29 / 732.25 | 8 / 2 | pass |
| `medium` / `sha1` | `89aae28f050c` | 3,145,728 | 196,608 | 6,294,050 | 35,362 | 2138.72 / 2438.34 | 36.45 / 39.84 | 1072.18 / 1692.85 | 16 / 2 | pass |
| `medium` / `sha256` | `48a95c4ad1df` | 3,145,728 | 196,608 | 6,294,050 | 35,362 | 1937.59 / 2145.52 | 30.94 / 33.08 | 944.49 / 1193.49 | 16 / 2 | pass |

**Scope & non-claims**: The table above is explicitly versioned as `v2-atomic-git-dir-rename` (`git_materialization_method=atomic_dir_rename_v2` avoids `shutil.copytree` stack races and is not directly comparable to pre-v2 full-directory `.git` copy measurements). It measures the standalone Python + stock Git + local CAS evaluator on Windows (`peak_rss_kib` 23,416–27,872 KiB; `temp_disk_bytes` 1,197,410 B / 3,164,706 B) and is distinct from the Rust OpenDAL `LoopbackS3` integration suite on Linux CI (`ubuntu-24.04`). This isolated module component does not wire live PostgreSQL / server HTTP workspace handlers, so end-to-end PG/service acceptance remains open on Issue #181 (`Refs #181`).
