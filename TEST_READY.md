# Rootyard 4-Tier E2E Test Readiness Report (`TEST_READY.md`)

**Current round-4 native runs**: see [round-4 acceptance](docs/acceptance/round4-browser-lfs.md) and [evidence](evidence/round4/browser-lfs-4c5bcfe/README.md) for the 11 native coordinator jobs on binary `c0049c3a…` (145 Rust unit tests; 25 cases across 9 JSON reports, counted separately). Those native reports supersede the historical reference-model counts below for round-4 scope only.

**Status**: `HISTORICAL REFERENCE-MODEL RESULTS — NOT NATIVE ACCEPTANCE`
**Current delivery**: [Registered issues and evidence gates](docs/registered-task-delivery.md).
The counts below describe the active Python/reference-model suite. They do not
prove that a Rust executable was invoked or that production paths passed.
`tests/e2e_tiers.py` now requires native execution by default; use
`--reference-only` explicitly to reproduce reference-model results.
**Test Suite Entrypoint**: `tests/e2e_tiers.py`
**Infrastructure Design Document**: `TEST_INFRA.md`
**Total Executable Tests**: `597` (`255` Tier 1 + `261` Tier 2 + `54` Tier 3 + `27` Tier 4)
**Verification Result**: `597 passed, 0 failed, 0 errors, 0 skipped` (Linux `--reference-only`; reference-only, not native acceptance)

The count above is the recorded `tests/e2e_tiers.py` result. Its cluster
fixture runs native Git on local directories but models nodes, leases, and
failover in Python; it does not start 1/2/4 Rootyard services. The separate
[native cluster workload](evidence/cluster-workload-integration.json) records
real Rust processes, PostgreSQL, client push/fetch traffic, GC, retained
objects, and owner restart. [Takeover](evidence/cluster-takeover-run.json),
[source-only TCP partition](evidence/cluster-partition.json),
[PostgreSQL streaming](evidence/cluster-pg-streaming.json),
[WAL PITR](evidence/cluster-pg-pitr.json), and
[disk pressure](evidence/cluster-disk-pressure.json) are distinct measured
drills with the limits stated in each report. No model receipt satisfies a
native deployment or production RPO/RTO gate.

---

## 1. Tier Summary & Quantitative Gate Verification

| Tier | Class Name | Required Minimum | Implemented Count | Pass | Fail / Error | Skipped | Status |
|---|---|---:|---:|---:|---:|---:|---|
| **Tier 1 — Feature Coverage** | `TestTier1FeatureCoverage` | 255 (5 × 51 features) | **255** | 255 | 0 | 0 | **PASS** |
| **Tier 2 — Boundary & Corner Cases** | `TestTier2BoundaryAndCornerCases` | 255 (5 × 51 features) | **261** | 261 | 0 | 0 | **PASS** |
| **Tier 3 — Cross-Feature Combinations** | `TestTier3CrossFeatureCombinations` | 51 (≥ 2 per feature) | **54** | 54 | 0 | 0 | **PASS** |
| **Tier 4 — Real-World Scenarios** | `TestTier4RealWorldScenarios` | 25–27 scenarios | **27** | 27 | 0 | 0 | **PASS** |
| **Total** | `tests/e2e_tiers.py` | **586–597** | **597** | **597** | **0** | **0** | **PASS** |

Tier 2 has 261 rather than 255 because `F20` carries 5 standard feature tests plus six additional F20 CI regression cases (`test_t2_f20_06`..`11`), for 11 `F20` Tier 2 tests and 20 `F20` tests in total.

---

## 2. Per-Feature Traceability Matrix (`F1`–`F51`)

Every feature `F1` through `F51` from `PROJECT.md` and `.agents/teamwork/ORIGINAL_REQUEST.md` is covered across all 4 tiers:

| Feature ID | Feature Name | Track | Tier 1 Tests | Tier 2 Tests | Tier 3 Combinations | Tier 4 Scenarios | Total Tests |
|---|---|---|---:|---:|---|---|---:|
| **F1** | PR State Machine & CRUD | Track 1 | `test_t1_f01_01`..`05` (5) | `test_t2_f01_01`..`05` (5) | `t3_01`, `t3_02`, `t3_05`, `t3_19`, `t3_21`, `t3_24` | `S1`, `S6`, `S7`, `S8`, `S9`, `S11`, `S15` | 23 |
| **F2** | PR Diff Inspection | Track 1 | `test_t1_f02_01`..`05` (5) | `test_t2_f02_01`..`05` (5) | `t3_01`, `t3_18` | `S1`, `S6` | 14 |
| **F3** | Review Approval Workflow | Track 1 | `test_t1_f03_01`..`05` (5) | `test_t2_f03_01`..`05` (5) | `t3_02`, `t3_03`, `t3_19`, `t3_24` | `S1`, `S6`, `S7`, `S8`, `S9`, `S11` | 20 |
| **F4** | Check Run Status Reporting | Track 1 | `test_t1_f04_01`..`05` (5) | `test_t2_f04_01`..`05` (5) | `t3_03`, `t3_12`, `t3_19`, `t3_21` | `S1`, `S6`, `S7`, `S8`, `S9`, `S11` | 20 |
| **F5** | Branch Protection Rules | Track 1 | `test_t1_f05_01`..`05` (5) | `test_t2_f05_01`..`05` (5) | `t3_02`, `t3_03`, `t3_06`, `t3_21`, `t3_24` | `S1`, `S6`, `S7`, `S9`, `S11` | 20 |
| **F6** | Same-Generation Atomic PR Merge | Track 1 | `test_t1_f06_01`..`05` (5) | `test_t2_f06_01`..`05` (5) | `t3_03`, `t3_04`, `t3_05`, `t3_12`, `t3_19`, `t3_21`, `t3_24`, `t3_28`, `t3_40` | `S1`, `S6`, `S7`, `S8`, `S9`, `S11`, `S15`, `S20` | 27 |
| **F7** | Track 1 Paired Backup & Tests | Track 1 | `test_t1_f07_01`..`05` (5) | `test_t2_f07_01`..`05` (5) | `t3_09`, `t3_20`, `t3_32` | `S9`, `S10` | 15 |
| **F8** | Browse Read-Only Refs & Commits API | Track 2A | `test_t1_f08_01`..`05` (5) | `test_t2_f08_01`..`05` (5) | `t3_04`, `t3_07`, `t3_10`, `t3_15`, `t3_26`, `t3_35`, `t3_37` | `S1`, `S2`, `S6`, `S7` | 21 |
| **F9** | Browse Read-Only Tree, Blob & Compare API | Track 2A | `test_t1_f09_01`..`05` (5) | `test_t2_f09_01`..`05` (5) | `t3_04`, `t3_07`, `t3_08`, `t3_15`, `t3_18`, `t3_35` | `S1`, `S2`, `S7`, `S8` | 20 |
| **F10** | Atomic Multi-Ref CAS Transactions | Track 2A | `test_t1_f10_01`..`05` (5) | `test_t2_f10_01`..`05` (5) | `t3_05`, `t3_06`, `t3_07`, `t3_10`, `t3_19`, `t3_22`, `t3_26`, `t3_40` | `S2`, `S7`, `S10`, `S20` | 22 |
| **F11** | Git LFS Batch API | Track 2B | `test_t1_f11_01`..`05` (5) | `test_t2_f11_01`..`05` (5) | `t3_08`, `t3_09`, `t3_26` | `S2`, `S8`, `S9` | 16 |
| **F12** | Git LFS Streaming Upload/Download & Backup | Track 2B | `test_t1_f12_01`..`05` (5) | `test_t2_f12_01`..`05` (5) | `t3_08`, `t3_09`, `t3_20`, `t3_26` | `S2`, `S8`, `S9`, `S10` | 18 |
| **F13** | CI Mirror Disk Watermark & Safe LRU Eviction | Track 3 | `test_t1_f13_01`..`05` (5) | `test_t2_f13_01`..`05` (5) | `t3_11`, `t3_12`, `t3_13`, `t3_23` | `S3`, `S6`, `S9`, `S14` | 18 |
| **F14** | CI Source Pin Release & Lease Coordination | Track 3 | `test_t1_f14_01`..`05` (5) | `test_t2_f14_01`..`05` (5) | `t3_10`, `t3_11`, `t3_12`, `t3_23` | `S3`, `S6`, `S9`, `S14` | 18 |
| **F15** | CI Mirror Concurrent Sync Rate Limiting & Observability | Track 3 | `test_t1_f15_01`..`05` (5) | `test_t2_f15_01`..`05` (5) | `t3_11`, `t3_13`, `t3_20`, `t3_23` | `S3`, `S6`, `S9`, `S10`, `S14` | 19 |
| **F16** | Pando Streaming Delta Resolution & Graph Traversal | Track 4A | `test_t1_f16_01`..`05` (5) | `test_t2_f16_01`..`05` (5) | `t3_14`, `t3_15`, `t3_17`, `t3_27`, `t3_30`, `t3_37`, `t3_49` | `S5`, `S8`, `S10`, `S12`, `S15`, `S18` | 23 |
| **F17** | Pando Git Export Dual-Operator Differential Testing | Track 4A | `test_t1_f17_01`..`05` (5) | `test_t2_f17_01`..`05` (5) | `t3_14`, `t3_15`, `t3_17`, `t3_27`, `t3_30`, `t3_37` | `S5`, `S8`, `S10`, `S12`, `S15`, `S18` | 22 |
| **F18** | Workspace Dirty-File Manifest, Ignore Rules & Read-Only View | Track 4B | `test_t1_f18_01`..`05` (5) | `test_t2_f18_01`..`05` (5) | `t3_16`, `t3_17`, `t3_29`, `t3_38` | `S4`, `S8`, `S10`, `S13`, `S15`, `S19` | 20 |
| **F19** | Shared Schema Baseline Integration & Full E2E/Tier-5 Verification | M5 | `test_t1_f19_01`..`05` (5) | `test_t2_f19_01`..`05` (5) | `t3_09`, `t3_13`, `t3_20`, `t3_31` | `S2`, `S9`, `S10`, `S16` | 18 |
| **F20** | Phase 1 Closure — CI Workflow Pando-Lab & PostgreSQL 17 Wiring | M6 | `test_t1_f20_01`..`05` (5) | `test_t2_f20_01`..`11` (11: 5 feature + 6 CI regression) | `t3_20`, `t3_31` | `S10`, `S16` | 20 |
| **F21** | Phase 1 Closure — Implementation Status & Documentation Sync | M6 | `test_t1_f21_01`..`05` (5) | `test_t2_f21_01`..`05` (5) | `t3_20`, `t3_31` | `S10`, `S16` | 14 |
| **F22** | Track A — Webhook Subscriptions, HMAC-SHA256 Signing & Outbox Delivery | Track A (M7) | `test_t1_f22_01`..`05` (5) | `test_t2_f22_01`..`05` (5) | `t3_21`, `t3_22`, `t3_25`, `t3_32`, `t3_34` | `S11`, `S14` | 17 |
| **F23** | Track A — Automated PR-to-CI Source Pinning & Check-Run Orchestration | Track A (M7) | `test_t1_f23_01`..`05` (5) | `test_t2_f23_01`..`05` (5) | `t3_21`, `t3_23`, `t3_25`, `t3_34` | `S11`, `S14` | 16 |
| **F24** | Track B — Repository Collaborators, Teams & 5-Level RBAC Authorization | Track B (M8) | `test_t1_f24_01`..`05` (5) | `test_t2_f24_01`..`05` (5) | `t3_24`, `t3_25`, `t3_26`, `t3_32`, `t3_34`, `t3_40` | `S11`, `S14`, `S17` | 19 |
| **F25** | Track B — Multi-Reviewer Approval Enforcement & Paginated Audit Log | Track B (M8) | `test_t1_f25_01`..`05` (5) | `test_t2_f25_01`..`05` (5) | `t3_24`, `t3_25`, `t3_32`, `t3_34` | `S11`, `S14`, `S17` | 17 |
| **F26** | Track C — Pando Online Repository Migration Engine (`GitFS -> Pando`) | Track C (M9) | `test_t1_f26_01`..`05` (5) | `test_t2_f26_01`..`05` (5) | `t3_27`, `t3_28`, `t3_36` | `S12`, `S15`, `S18` | 16 |
| **F27** | Track C — Pando Post-Switchover Rollback to GitFS | Track C (M9) | `test_t1_f27_01`..`05` (5) | `test_t2_f27_01`..`05` (5) | `t3_27`, `t3_28`, `t3_36` | `S12`, `S15`, `S18` | 16 |
| **F28** | Track D — Cross-Node Dirty Workspace Snapshot Transfer (`push-remote`/`pull-remote`) | Track D (M10) | `test_t1_f28_01`..`05` (5) | `test_t2_f28_01`..`05` (5) | `t3_29`, `t3_30`, `t3_38`, `t3_39` | `S13`, `S15`, `S19` | 17 |
| **F29** | Track D — Multi-Repo Virtual Namespace Composition & Read-Only Git View | Track D (M10) | `test_t1_f29_01`..`05` (5) | `test_t2_f29_01`..`05` (5) | `t3_29`, `t3_30`, `t3_39` | `S13`, `S15`, `S19` | 16 |
| **F30** | Anti-Monolith Governance & Modular File-Size Caps | M11 | `test_t1_f30_01`..`05` (5) | `test_t2_f30_01`..`05` (5) | `t3_20`, `t3_31`, `t3_43` | `S10`, `S16`, `S22` | 16 |
| **F31** | Tier 2 Shared Schema Baseline, Route Non-Collision & Full E2E Gate | M11 | `test_t1_f31_01`..`05` (5) | `test_t2_f31_01`..`05` (5) | `t3_31`, `t3_32`, `t3_43` | `S14`, `S16`, `S22` | 16 |
| **F32** | Part 1 — Schema `040`/`050` Promotion, Catalog Snapshots & Paired Backup Format 5 Closure | M12 (Part 1) | `test_t1_f32_01`..`05` (5) | `test_t2_f32_01`..`05` (5) | `t3_33`, `t3_43`, `t3_44` | `S17`, `S22` | 15 |
| **F33** | Track 1 — Server-Side HTML Web UI Views, Cookie/Header Auth & PR/Issue Flows | M13 (Track 1) | `test_t1_f33_01`..`05` (5) | `test_t2_f33_01`..`05` (5) | `t3_33`, `t3_34`, `t3_35`, `t3_41` | `S17`, `S20`, `S21` | 17 |
| **F34** | Track 1 — Untrusted Markdown XSS Sanitization & UTF-8 Boundary-Safe Large Blob Preview | M13 (Track 1) | `test_t1_f34_01`..`05` (5) | `test_t2_f34_01`..`05` (5) | `t3_33`, `t3_34`, `t3_35` | `S17`, `S20` | 15 |
| **F35** | Track 2 — Pando S3-Compatible Object-Store Pack Upload/Download & CAS Verification | M14 (Track 2) | `test_t1_f35_01`..`05` (5) | `test_t2_f35_01`..`05` (5) | `t3_36`, `t3_37`, `t3_42` | `S18`, `S21` | 15 |
| **F36** | Track 2 — Pando Multi-Pack Compaction / Repack & Storage Backend Gateway Routing | M14 (Track 2) | `test_t1_f36_01`..`05` (5) | `test_t2_f36_01`..`05` (5) | `t3_36`, `t3_37`, `t3_42` | `S18`, `S21` | 15 |
| **F37** | Track 3 — Workspace-Lab Lazy Sparse VFS Mount & On-Demand CAS Blob Hydration | M15 (Track 3) | `test_t1_f37_01`..`05` (5) | `test_t2_f37_01`..`05` (5) | `t3_38`, `t3_39`, `t3_44`, `t3_52` | `S19`, `S21` | 16 |
| **F38** | Track 3 — Workspace-Lab Copy-on-Write Dirty File Tracking, Ignore-Aware Status & Clean Blob Eviction | M15 (Track 3) | `test_t1_f38_01`..`05` (5) | `test_t2_f38_01`..`05` (5) | `t3_38`, `t3_39`, `t3_44`, `t3_53` | `S19`, `S21` | 16 |
| **F39** | Track 4 — Multi-Node Repository Sharding Catalog, Deterministic Bucket Placement & Routing | M16 (Track 4) | `test_t1_f39_01`..`05` (5) | `test_t2_f39_01`..`05` (5) | `t3_40`, `t3_41`, `t3_42`, `t3_50` | `S20`, `S21` | 16 |
| **F40** | Track 4 — Epoch Storage Write Fencing, Automated Node Failover & Read-Only Degradation Drills | M16 (Track 4) | `test_t1_f40_01`..`05` (5) | `test_t2_f40_01`..`05` (5) | `t3_40`, `t3_41`, `t3_42`, `t3_51` | `S20`, `S21` | 16 |
| **F41** | Track 5 — 4-Tier E2E Test Harness Expansion & Per-Feature Filter Verification (597 Tests) | M12.5 (Track 5) | `test_t1_f41_01`..`05` (5) | `test_t2_f41_01`..`05` (5) | `t3_43`, `t3_44` | `S21`, `S22` | 14 |
| **F42** | Part 3 — Cross-Track Schema `060`, 11-Domain Router Non-Collision, Anti-Monolith Caps & Paired Backup | M17 (Part 3) | `test_t1_f42_01`..`05` (5) | `test_t2_f42_01`..`05` (5) | `t3_43`, `t3_44` | `S21`, `S22` | 14 |
| **F43** | View-Lab Anti-Monolith Split, Namespace Pins & 3-Way Changeset Failpoint Recovery | Tier 5 Track 1 | `test_t1_f43_01`..`05` (5) | `test_t2_f43_01`..`05` (5) | `t3_45`, `t3_46`, `t3_54` | `S23`, `S27` | 15 |
| **F44** | Long-Term History Projection Strategies (`deterministic_history` vs `task_snapshot`) | Tier 5 Track 1 | `test_t1_f44_01`..`05` (5) | `test_t2_f44_01`..`05` (5) | `t3_45`, `t3_47` | `S23`, `S27` | 14 |
| **F45** | Cryptographic Source Commit & View Provenance HMAC-SHA256 Signature Verification | Tier 5 Track 1 | `test_t1_f45_01`..`05` (5) | `test_t2_f45_01`..`05` (5) | `t3_46`, `t3_47` | `S23`, `S27` | 14 |
| **F46** | Git SHA-256 Object-Format Detection, Dual-Hash Validation & 32-Byte Packv2 Trailers | Tier 5 Track 2 | `test_t1_f46_01`..`05` (5) | `test_t2_f46_01`..`05` (5) | `t3_48`, `t3_49`, `t3_54` | `S24`, `S27` | 15 |
| **F47** | Smart HTTP v1/v2 `object-format` Capability Negotiation & Compatibility Matrix Drills | Tier 5 Track 2 | `test_t1_f47_01`..`05` (5) | `test_t2_f47_01`..`05` (5) | `t3_48`, `t3_49` | `S24`, `S27` | 14 |
| **F48** | Multi-Node 1/2/4-Node Sharding Concurrency, Failover & Pinned-Root Reachability | Tier 5 Track 3 | `test_t1_f48_01`..`05` (5) | `test_t2_f48_01`..`05` (5) | `t3_50`, `t3_51`, `t3_54` | `S25`, `S27` | 15 |
| **F49** | P50/P95/P99 Latency Percentiles, Throughput & `/proc/self` Telemetry Report Generator | Tier 5 Track 3 | `test_t1_f49_01`..`05` (5) | `test_t2_f49_01`..`05` (5) | `t3_50`, `t3_51` | `S25`, `S27` | 14 |
| **F50** | Workspace Virtual Mount Copy-on-Write Overlay Sandbox & Multi-Agent Isolation | Tier 5 Track 4 | `test_t1_f50_01`..`05` (5) | `test_t2_f50_01`..`05` (5) | `t3_52`, `t3_53`, `t3_54` | `S26`, `S27` | 15 |
| **F51** | Workspace Mid-Write Power-Loss Crash Window WAL Journal Recovery Reconciliation | Tier 5 Track 4 | `test_t1_f51_01`..`05` (5) | `test_t2_f51_01`..`05` (5) | `t3_52`, `t3_53`, `t3_54` | `S26`, `S27` | 15 |

---

## 3. Genuine Fixture & Infrastructure Inventory

All fixture classes in `tests/e2e_tiers.py` use real `/usr/bin/git` subprocesses, real filesystem permissions/symlinks/modes, real SQLite relational & `CHECK`/`TRIGGER` constraint engines, real loopback HTTP listeners, real packfile binary parsers, and live repository file inspections:

1. **`GitRepoFixture`**: Initializes and manipulates real bare Git repositories (`git init --bare --object-format=sha1`), executes real `git hash-object`, `git mktree`, `git commit-tree`, `git merge-base --is-ancestor`, `git merge-tree --write-tree`, `git diff --binary`, `git update-ref --stdin -z --no-deref`, `git for-each-ref`, `git rev-list --topo-order`, `git ls-tree -z -l`, `git cat-file`, and `git pack-objects`.
2. **`Track1PullsEngine`**: Enforces the full `009_forge_pulls.sql` and `007_forge_idempotency.sql` relational invariants (`forge_pull_counters`, `forge_pulls`, `forge_pull_reviews`, `forge_check_runs`, `forge_branch_rules`, `forge_creation_requests`, `git_operations`, `outbox_events`), optimistic concurrency (`expected_version`), `(attempt, sequence)` monotonic check ordering, branch protection gates, and same-generation CAS `git update-ref` merges.
3. **`Track2BrowseEngine`**: Implements read-only repository browsing (`refs`, `commits`, `tree`, `blob`, `compare`) with `--no-replace-objects` and `refs/rootyard-ci/*` filtering, all-or-nothing multi-ref CAS transactions (`git update-ref --stdin -z --no-deref`), and storage backend gateway routing (`GET/PATCH /api/repos/{owner}/{name}/backend`, `GET /storage-route`).
4. **`Track2LfsEngine`**: Implements the Git LFS v1 Batch API (`application/vnd.git-lfs+json`), streaming chunked `PUT` uploads to `.tmp-<uuid>` with `O_CREAT | O_EXCL | O_NOFOLLOW`, incremental SHA-256 and byte-length verification, `0600` atomic `rename`, `507 Insufficient Storage` quota enforcement, and paired backup volume verification.
5. **`MirrorPinCheckoutFixture` & `SyncRateLimiter`**: Manages primary `ci-pins/<repo_id>/*.pinned.json` and `refs/rootyard-ci/jobs/<job_id>`, single-use `ci_checkout_jobs` leases, mirror snapshots (`git clone --mirror --no-local`), closure-isolated job views (`git pack-objects --revs --no-reuse-delta --no-reuse-object` + `git index-pack --stdin --strict`), watermark LRU eviction, RAII concurrent sync rate limiting (`429 Too Many Requests`), and Prometheus `0.0.4` metrics exposition.
6. **`PandoDeltaGraphExportFixture` & `LoopbackObjectStoreServer`**: Implements streaming packv2 header/varint/zlib/trailer parsing, `OBJ_OFS_DELTA` and `OBJ_REF_DELTA` delta instruction reconstruction, DAG reachability walks, dual-operator differential comparison against `/usr/bin/git rev-list --objects`, orphan pack / expired snapshot GC, online `gitfs -> pando` migration, post-switchover `pando -> gitfs` rollback, S3-compatible multipart object-store upload/download (`object_store_put`, `object_store_get`, `object_store_status`, `object_store_verify`) over `LoopbackObjectStoreServer`, and multi-pack compaction (`repack`).
7. **`WorkspaceManifestIgnoreViewFixture`**: Implements live Git working tree status, `.gitignore` + `.rootyardignore` evaluation (preserving tracked files), safe relative symlink validation, SHA-256 checkpoint manifests, 3-way changeset generation and atomic pre-flight conflict checking, incremental `sync-dirty`, read-only view (`0444`/`0555`) tamper detection, cross-node CAS snapshot transfer (`push_remote`/`pull_remote`), multi-repo virtual namespace composition (`namespace_mount`, `verify_namespace`, `namespace_git_view`), and Lazy Sparse VFS mounts with on-demand CAS hydration, Copy-on-Write dirty tracking, and clean blob eviction (`vfs_mount`, `vfs_hydrate`, `vfs_status`, `vfs_evict`, `vfs_checkpoint`).
8. **`Phase1ClosureAndDocsFixture`**: Validates `.github/workflows/ci.yml`, `docs/design/implementation-status.md`, `docs/README.md`, relative Markdown link targets, and code-fence balance.
9. **`LoopbackWebhookReceiver` & `TrackAWebhooksEngine`**: Enforces `040_webhooks.sql`, SSRF/URL validation, RFC 2104 HMAC-SHA256 signing & constant-time verification (`X-Rootyard-Signature-256: sha256=<hex>`), Outbox `push` fanout, real loopback HTTP/1.1 delivery via `LoopbackWebhookReceiver`, exponential backoff & `dead_letter` retry, automated PR-to-CI source pinning (`refs/rootyard-ci/jobs/*`), `queued` check seeding, and HMAC-verified idempotent CI callbacks.
10. **`TrackBMembersRbacAuditEngine`**: Enforces `050_members_rbac.sql` (`repository_collaborators`, `repository_teams`, `repository_team_members`, `repository_audit_log`, and SQL `BEFORE INSERT` membership triggers), 5-level role hierarchy (`read < triage < write < maintain < admin`), `max(direct_role, max_team_role)` union resolution, `404` non-member isolation, `prevent_self_approval`, distinct `write`+ approver counting at merge time, and cursor-paginated `GET /api/repos/{owner}/{name}/audit`.
11. **`Track1WebUiEngine`**: Implements Server-Side HTML Web UI views (`/web/repos/{owner}/{name}/...`), login-form API-token exchange into an HttpOnly `rootyard_session`, CSRF/Origin protection, strict allowlist Markdown XSS sanitization (`render_safe_markdown`), security response headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`), and UTF-8 boundary-safe large blob preview (`build_blob_preview`).
12. **`Track4ShardingFencingEngine`**: Enforces `060_sharding_fencing.sql` (`shard_nodes`, `shard_virtual_buckets`, `repository_shard_routes`, `shard_failover_operations`), deterministic `SHA-256(repository_id) % 1024` virtual bucket placement, SSRF validation, watermark-qualified replica read routing, dual PostgreSQL + on-disk `rootyard-shard-fence.json` (`0600`) epoch write fencing, atomic `draining -> fenced -> verified -> promoted` failover, and read-only degradation drills.
13. **`SchemaBoundaryIntegrationFixture`**: Inspects live repository files (`src/db.rs`, `src/backup.rs`, `src/lib.rs`, `src/auth.rs`, `src/events.rs`, `src/dispatch.rs`, `migrations/*.sql`, `schema/*.json`, `tests/schema_baseline.py`, `scripts/check_design_docs.py`, `tests/test_parallel_boundaries.py`), anti-monolith line caps across all domain roots and submodules, Axum 0.8 route-table non-collision, Part 1 `050` closure, Track 5 51-feature / 597-test completeness, and Part 3 `060` convergence.
14. **`ViewLabHistorySignatureEngine` (`Tier5ViewLabHistoryAndSignatureFixture`)**: Verifies `src/view_lab.rs` (`< 120` lines) and `src/view_lab/{models,namespace,projection,changeset}.rs` (`< 500` lines each), manages bare Git repos with fast-forward and lease-epoch fencing, creates multi-repo namespaces with `.sha256` companion manifests and durable `refs/rootyard/namespace-pins/*`, materializes `project-subdir` and `create-task-view` Git repositories, performs 3-way `git merge-tree --write-tree` changeset integration with failpoints `86`/`87` recovery, projects multi-repo history via `deterministic_history` and `task_snapshot`, and verifies OpenPGP/SSH source commit signatures and RFC 2104 HMAC-SHA256 `Rootyard-View-Signature` provenance trailers.
15. **`ObjectFormatDualHashEngine` (`Tier5DualHashObjectFormatFixture`)**: Initializes and inspects real SHA-1 (`40`-hex / `20`-byte) and SHA-256 (`64`-hex / `32`-byte) bare Git repositories, verifies canonical empty-tree and zero-OID constants, validates `20`-byte SHA-1 and `32`-byte SHA-256 packv2 stream trailers, browses dual-hash commits/trees/blobs, verifies 64-hex SHA-256 Git LFS content addressing, and executes Smart HTTP v1/v2 `object-format` capability advertisement, negotiation, `409 Conflict` cross-format rejection, and the 4-combination `(sha1, sha256) x (v1, v2)` compatibility matrix drill.
16. **`ShardingClusterBenchmarkEngine` (`Tier5MultiNodeShardingBenchmarkFixture`)**: Runs native Git operations on local bare repositories while Python models 1-, 2-, and 4-node placement, virtual buckets, fences, failover, and benchmark receipts. Its local object reachability checks exercise Git, but its modeled node state and timings are not evidence of networked Rootyard service behavior. Use the separate native reports linked above for measured service behavior.
17. **`WorkspaceOverlayCrashRecoveryEngine` (`Tier5WorkspaceOverlayAndCrashRecoveryFixture`)**: Mounts Copy-on-Write (`lower`/`upper`/`work`/`merged`) workspace overlays over immutable `0444`/`0555` lower checkpoints, enforces multi-agent sandbox isolation, tracks upper modifications/additions, `.wh.<name>` whiteout tombstones on cross-layer file/directory renames, `0644`/`0755`/`0600` mode transitions, and `git add -f` overrides, and injects and recovers all 4 mid-write power-loss crash windows (`before_wal_fsync`, `after_wal_before_publish`, `after_publish_before_ack`, `index_update_interrupted`) with `.tmp-*` cleanup, `.git/index.lock` removal, WAL journal SHA-256 verification, and `git fsck --full --strict` validation.

---

## 4. Execution Commands & Verification Output

```bash
# Run all 4 tiers (597 tests)
python3 tests/e2e_tiers.py --tier all

# Run individual tiers
python3 tests/e2e_tiers.py --tier 1   # 255 tests
python3 tests/e2e_tiers.py --tier 2   # 261 tests
python3 tests/e2e_tiers.py --tier 3   # 54 tests
python3 tests/e2e_tiers.py --tier 4   # 27 tests

# Run tests for any specific feature (F1..F51)
python3 tests/e2e_tiers.py --feature F43
for i in $(seq 43 51); do python3 tests/e2e_tiers.py --feature "F$i"; done

# Run via Python standard unittest discovery
python3 -m unittest tests/e2e_tiers.py
```

---

## 5. Exclusive Ownership & Boundary Audit

- **Created / Modified Workspace Files**:
  - `TEST_INFRA.md`
  - `tests/e2e_tiers.py`
  - `TEST_READY.md`
- **Untouched Production & Track Files**: Zero modifications during `E2E_R4` to `src/**`, `migrations/**`, `schema/**`, `.github/**`, `docs/**`, `experimental/**`, `tests/test_tier5_adversarial.py`, or any other track-owned files.


