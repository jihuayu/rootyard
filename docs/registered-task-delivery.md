# Rootyard registered-task delivery

Baseline: `85e5fa0` (2026-11-06). Scope: all 46 issues #2–#47, including transparent VFS and LFS locks. This ledger distinguishes implementation, executed acceptance, independent review, and merge evidence. An open row is not a completion claim.

Five isolated Sol/xhigh executors implement the work; Luna/max independently reviews each batch. Main integration coordinates schema, authorization, routing, backup and release gates.

| Issue | Workstream | Current evidence/status |
| --- | --- | --- |
| [#2](https://github.com/jihuayu/rootyard/issues/2) overlay-write follows parent symlinks and overwrites the read-only lower layer | workspace | In progress; acceptance and review pending. |
| [#3](https://github.com/jihuayu/rootyard/issues/3) Push webhook synchronization permanently skips events after the first 200 | ci | In progress; acceptance and review pending. |
| [#4](https://github.com/jihuayu/rootyard/issues/4) Owner-only gates reject authorized collaborators on Git transport and write endpoints | forge | In progress; acceptance and review pending. |
| [#5](https://github.com/jihuayu/rootyard/issues/5) LFS uses the caller as tenant and fails for authorized collaborators | forge | In progress; acceptance and review pending. |
| [#6](https://github.com/jihuayu/rootyard/issues/6) RBAC schema detection hard-codes public and breaks custom search_path deployments | forge | Existing fix: Luna ran native members suite (9 cases) on baseline; full issue acceptance/merge not yet closed. |
| [#7](https://github.com/jihuayu/rootyard/issues/7) Concurrent audited writes fail because audit IDs are allocated with MAX(id) + 1 | forge | In progress; acceptance and review pending. |
| [#8](https://github.com/jihuayu/rootyard/issues/8) Browse pagination enumerates every ref and fails on large repositories even with limit=1 | storage | In progress; acceptance and review pending. |
| [#9](https://github.com/jihuayu/rootyard/issues/9) Commit browsing launches one Git subprocess per commit instead of batching object reads | storage | In progress; acceptance and review pending. |
| [#10](https://github.com/jihuayu/rootyard/issues/10) E2E validation can pass without executing the requested Rust binary | integration | Missing-binary false-green reproduced; native entrypoint correction under validation. |
| [#11](https://github.com/jihuayu/rootyard/issues/11) The members integration-test entrypoint cannot run the command configured in CI | forge | Existing fix: Luna ran native members suite (9 cases) on baseline; full issue acceptance/merge not yet closed. |
| [#12](https://github.com/jihuayu/rootyard/issues/12) Any writable user token can modify global shard nodes and disrupt other tenants | cluster | In progress; acceptance and review pending. |
| [#13](https://github.com/jihuayu/rootyard/issues/13) A failed queued LFS upload can delete an object already committed by another upload | forge | In progress; acceptance and review pending. |
| [#14](https://github.com/jihuayu/rootyard/issues/14) Ref transactions update Git before recording durable intent, leaving untracked successful mutations | storage | In progress; acceptance and review pending. |
| [#15](https://github.com/jihuayu/rootyard/issues/15) Failed shard state transitions leave durable volume markers inconsistent with rolled-back PostgreSQL state | cluster | In progress; acceptance and review pending. |
| [#16](https://github.com/jihuayu/rootyard/issues/16) Concurrent webhook dispatches can overwrite a delivered result with dead_letter | ci | In progress; acceptance and review pending. |
| [#17](https://github.com/jihuayu/rootyard/issues/17) A stalled LFS request body holds the repository write lock without a transfer deadline | forge | In progress; acceptance and review pending. |
| [#18](https://github.com/jihuayu/rootyard/issues/18) Direct Git writes and ref transactions bypass configured branch protection | storage | In progress; acceptance and review pending. |
| [#19](https://github.com/jihuayu/rootyard/issues/19) Webhook HTTPS targets use plaintext on loopback and always fail for external hosts | ci | In progress; acceptance and review pending. |
| [#20](https://github.com/jihuayu/rootyard/issues/20) Add a real streaming S3-compatible object storage backend | storage | In progress; acceptance and review pending. |
| [#21](https://github.com/jihuayu/rootyard/issues/21) Implement authenticated pack encryption and KMS-backed key rotation | storage | In progress; acceptance and review pending. |
| [#22](https://github.com/jihuayu/rootyard/issues/22) Integrate Pando into the authenticated Git gateway and backend migration lifecycle | storage | In progress; acceptance and review pending. |
| [#23](https://github.com/jihuayu/rootyard/issues/23) Run storage maintenance as durable background jobs | storage | In progress; acceptance and review pending. |
| [#24](https://github.com/jihuayu/rootyard/issues/24) Route Git data requests to the owning shard node | cluster | In progress; acceptance and review pending. |
| [#25](https://github.com/jihuayu/rootyard/issues/25) Implement repository replication and resumable shard data migration | cluster | In progress; acceptance and review pending. |
| [#26](https://github.com/jihuayu/rootyard/issues/26) Add a cluster controller with storage-enforced fencing and automatic takeover | cluster | In progress; acceptance and review pending. |
| [#27](https://github.com/jihuayu/rootyard/issues/27) Add the persistent, authorized Workspace service API | workspace | In progress; acceptance and review pending. |
| [#28](https://github.com/jihuayu/rootyard/issues/28) Add live workspace capture, consistent checkpoints and replayable events | workspace | In progress; acceptance and review pending. |
| [#29](https://github.com/jihuayu/rootyard/issues/29) Persist workspace checkpoints over an authenticated remote CAS protocol | workspace | In progress; acceptance and review pending. |
| [#30](https://github.com/jihuayu/rootyard/issues/30) Add transparent on-demand filesystem hydration for Workspace VFS | workspace | In progress; acceptance and review pending. |
| [#31](https://github.com/jihuayu/rootyard/issues/31) Serve authorized Namespace and Git View workflows online | workspace | In progress; acceptance and review pending. |
| [#32](https://github.com/jihuayu/rootyard/issues/32) Implement the Agent and CI sandbox runner lifecycle | workspace | In progress; acceptance and review pending. |
| [#33](https://github.com/jihuayu/rootyard/issues/33) Automatically synchronize PRs and deliver webhooks from durable background workers | ci | In progress; acceptance and review pending. |
| [#34](https://github.com/jihuayu/rootyard/issues/34) Add durable CI run orchestration and multi-mirror checkout scheduling | ci | In progress; acceptance and review pending. |
| [#35](https://github.com/jihuayu/rootyard/issues/35) Bind required CI checks to trusted integration identities | ci | In progress; acceptance and review pending. |
| [#36](https://github.com/jihuayu/rootyard/issues/36) Include LFS and submodule dependencies in CI checkout readiness | ci | In progress; acceptance and review pending. |
| [#37](https://github.com/jihuayu/rootyard/issues/37) Enforce bounded authorization revocation on active checkout transfers | ci | In progress; acceptance and review pending. |
| [#38](https://github.com/jihuayu/rootyard/issues/38) Complete SHA-256 repository support across hosting, Forge and CI checkout | storage | In progress; acceptance and review pending. |
| [#39](https://github.com/jihuayu/rootyard/issues/39) Store and recover LFS objects through the remote object-storage backend | forge | In progress; acceptance and review pending. |
| [#40](https://github.com/jihuayu/rootyard/issues/40) Validate newly introduced Git LFS pointers before publishing refs | forge | In progress; acceptance and review pending. |
| [#41](https://github.com/jihuayu/rootyard/issues/41) Implement the Git LFS file-locking protocol | forge | In progress; acceptance and review pending. |
| [#42](https://github.com/jihuayu/rootyard/issues/42) Support concurrent independent-ref writes without a repository-wide transfer lock | storage | In progress; acceptance and review pending. |
| [#43](https://github.com/jihuayu/rootyard/issues/43) Provide a supported distributed deployment profile with secure dependencies and HA recovery | cluster | In progress; acceptance and review pending. |
| [#44](https://github.com/jihuayu/rootyard/issues/44) Replace simulated cluster and DR receipts with real multi-node measurements | cluster | In progress; acceptance and review pending. |
| [#45](https://github.com/jihuayu/rootyard/issues/45) Add a real Git client and repository-state compatibility matrix | integration | In progress; acceptance and review pending. |
| [#46](https://github.com/jihuayu/rootyard/issues/46) Add organization-owned repositories, teams and company namespace ownership | forge | In progress; acceptance and review pending. |
| [#47](https://github.com/jihuayu/rootyard/issues/47) Add browser sign-in, sign-out and revocable Web UI sessions | forge | In progress; acceptance and review pending. |

## Execution environment

- Rust 1.99.1; PostgreSQL 17.11; isolated test schemas and owned temporary repositories.
- No configured external cloud credentials or identities. Real local services may establish functional evidence, but do not establish cloud KMS, production HA, hardware fault or geo-replication guarantees.
- Raw acceptance results are retained in `test-results/`; durable reviewed receipts will identify exact source/binary hashes, tools, topology, dataset, commands and measured outcomes.
- No simulated benchmark, reference model, metadata flag or unexecuted test can close an issue.

## Delivery gates

Each batch needs native regressions, independent review and re-review of findings, then integration checks. Final gates include cross-module compatibility, schema upgrade, paired backup/restore, revocation, retained-object reachability and actual fault workload measurements. PRs use related-issue links until closure evidence is complete.
