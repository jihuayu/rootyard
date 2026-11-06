# Push handoff — 2026-11-06

The user requested wrap-up and push. This is a draft integration delivery, not completion of all 46 issues. No issue was closed or merged.

## Remote branches

| Remote branch | Commit at handoff | Boundary |
| --- | --- | --- |
| `codex/rootyard-integration` | source checkpoint `3529131`, plus final catalog/evidence commit | Draft PR #49; retains long Git transfer mutex and disables production physical GC |
| `codex/rootyard-storage` | `f003ee1` | Stock authenticated Pando HTTP and atomic CAS tested; no real cutover/rollback or durable data fence |
| `codex/rootyard-cluster` | `78cb17a` | Reviewed migration/publication fixes and native runtime-role profile; includes local compatibility commits that must not be blindly cherry-picked |
| `codex/rootyard-forge-lifecycle` | `d70cbaf` | Durable maintenance and test-only physical-GC evidence; production physical switch is false |
| `codex/rootyard-workspace-ci` | `e53e00a` | Signed CI, reader cancellation, PTY terminal, conflict-state and pinned-OID view fixes; terminal migration renumbered to116, final integration rebuild pending |
| `codex/rootyard-ci` | `8f17f0e` | Earlier stable CI branch; later staged publication prerequisites are also recorded on the separate concurrency branch |
| `codex/rootyard-ref-concurrency-wip` | `2290e16` | **Experimental: admitted-writer SIGSTOP takeover failed. Do not merge.** |
| `codex/rootyard-workspace-lazy-wip` | `e04d33d` | **Experimental: final source rebuild and independent review missing; earlier offline-read hang.** |

Earlier Forge/Workspace executor branches were also pushed to preserve their commit history. Branch existence is not an acceptance claim. Draft PR: https://github.com/jihuayu/rootyard/pull/49. Per-issue status: [registered-task delivery](registered-task-delivery.md).

## Final safety boundaries

- Physical GC stays disabled. The PostgreSQL collector session can lose its exclusive advisory lock before its child stops. A durable admission fence (planned077), quiescence proof, complete namespace/view/change-set roots and a rerun on the exact integrated reader fixes are required. Test-only physical-GC binaries deliberately differ from production; their passes cannot enable the production switch.
- Independent-ref upload overlap stays outside integration. Its native client/CI/pull/migration suites passed, but SIGSTOP with an admitted writer exposed a local journal operation absent from target SQL settlement. A durable SQL admission marker/controller check and token-revocation publication boundary remain necessary.
- Pando encrypted pack, ref staging and atomic refs/outbox primitives passed live Garage/Vault/PostgreSQL SHA-256 tests. Executor HTTP tests passed separately. Real cutover/rollback, production backup export/import wiring and the durable transition fence remain unfinished.
- Workspace PTY and CI cancellation/disconnect fixes have focused independent native evidence. Lazy remote hydration is separate WIP; no stable completion claim. Production cgroup quotas and cross-host/hardware/cloud qualification remain unverified.
- Cluster runtime role splitting has executor native2/4-node TLS/SCRAM and Kafka SASL_SSL receipts. The final independent role-split rerun did not start because that shell lacked initdb on PATH. External HA/DCS and cross-host storage fencing remain outside demonstrated topology.

## Evidence

Committed native receipts are in `evidence/`; independent reports are in `evidence/reviews/`. Each receipt applies to its named binary, source and topology. Original executor evidence remains under `/workspace/shared/` in this workspace. Important receipts include the offline backup/legacy restore/worker recovery series, the client compatibility matrix, and cluster workload/fault results. Source checkpoints and executor branch commits differ; use the exact receipt rather than inferring acceptance from branch HEAD.

The integration build and real PostgreSQL schema contract are rerun for this handoff. New feature expansion stopped at the user's request.
