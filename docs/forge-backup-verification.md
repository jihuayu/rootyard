# Populated Forge backup and restore integration

Verified locally on 2026-11-03. This independently branched integration combines worker/backup `8e3d15afebb8d6ff995f8479aae3b6c721fc8de5` with private-owner Forge `36a6e9f38242f4a082998884237507e8bf2f752b`. Kafka, experimental storage and workspace branches are not included. No main merge, deployment, production access or traffic switch was performed.

## Exact implementation and runtime

- Fixed executable SHA-256: `06db1bee575e40f6200273e9059dc6fa8a08d81eb49f03d0844dd6796772151c`.
- Linux x86-64, Rust/cargo 1.99.1, Git client/server 2.56.0, PostgreSQL server and clients 17.11, real Redis 7.2.7.
- Separate freshly initialized synthetic PostgreSQL clusters on random loopback ports and private run-owned volumes. Restore targets were a new database on the other cluster and a nonexistent directory.
- Exact migrations `[1,2,3,6]`, fourteen supported tables, five functions, six application triggers. Format 3 binds the schema006 catalog and volume identity. The three Forge tables are in the same frozen SHARE-lock list as the other eleven tables, not just included in the dump.
- Canonical contracts were regenerated only from pristine migrations and a real full-schema dump/restore round trip. Removing the three added Forge tables' descriptors leaves every schema003 descriptor exactly unchanged. Three complete catalog shapes are accepted: pristine006, fully restored006, and restored003 upgraded through006. They differ only in equivalent parentheses for the Forge comment-body/title CHECKs and the pre-existing ref-name CHECK. Internal FK trigger enabled state, all composite keys/checks/indexes, recovery functions and protection triggers remain checked exactly.

The merge keeps the PG-only worker CLI paths, restored-volume startup guard, full-schema transactional import and explicit isolated-target contract. Docker still copies the schema fixtures and includes matching PostgreSQL maintenance clients. Both sides' CI tests remain, with populated Forge restore acceptance added. Actual image building is performed by CI; no local Docker daemon was available. The final published head's CI must be checked separately from these local results.

## Full local regression

- Formatting and clippy with warnings denied.
- 32 Rust tests, plus both real PostgreSQL integration tests explicitly run with `--ignored`.
- Pristine, dump/restored and restored003-upgrade006 catalog comparisons, including a further full dump/restore of the upgraded shape.
- 15 e2e, 18 reliability, seven explicit recovery and five metrics groups.
- Seven backup fault groups, six recovery-history restore groups, four restored-worker groups.
- Six cross-process groups including actual Redis disconnect/restart and worker SIGKILL/lease recovery; Redis coverage was not skipped.
- Eleven Forge API groups, eight populated Forge restore groups and five genuine legacy-restore upgrade groups.

All runtime suites use the fixed executable above. The original Forge and worker verification records remain historical evidence for their own binaries, not substitutes for this integrated run.

## Populated restore: eight groups

1. Two personal owners across three repositories create Unicode Issue/comment content, open/closed/reopened states, edits, authors and timestamps. Synthetic recovery history contains two resolved unknown incidents and one unresolved incident. Native pushes supply pending deliveries and expired/unexpired lease fixtures. Forge API calls leave native refs, storage generations, git operations and outbox records byte-for-byte/data-for-data unchanged.
2. An uncommitted PostgreSQL transaction updates an Issue counter and inserts an Issue and comment across all three Forge tables. Backup genuinely waits at its table-lock barrier. After COMMIT, the snapshot contains ten Issues, 28 comments and three repository counters, including the committed Issue/comment counters. No stale pre-lock snapshot is accepted.
3. After backup, the source acknowledges another Issue, another comment, an Issue edit and a comment edit. All four changes are deliberately outside the recovery point.
4. Restore into the other fresh PostgreSQL cluster and new volume compares every row of all fourteen tables, not just counts. Text, personal tenant/repository/author binding, states, versions, timestamps, both counter types, resolutions, snapshots, leases, UUID and journal bytes exactly match the captured source. The four post-boundary creations/edits are absent.
5. The restored API returns identical content and pagination; cross-owner access stays 404, read-only mutations 403, revoked/expired tokens 401. All eight Issue/comment routes on the unresolved recovering repository remain frozen with 409. Read and denied calls do not mutate database rows.
6. New Issues/comments receive the captured counters' next numbers. Current-version edits succeed, stale versions fail, close/reopen works, and eight concurrent updates have one winner. Forge mutations still do not alter native refs, generations, operations or outbox data.
7. Two real PG-only workers drain eligible restored deliveries without reading or changing GitFS. Unexpired leases remain untouched until the synthetic deadline is explicitly advanced; reclaimed leases get newer fences. An old-generation candidate cannot overwrite the recovery snapshot, unknown histories stay frozen, and all three Forge tables remain unchanged.
8. Authenticated native clone/fsck and a real generation-2 push succeed after deliberate startup. Independent workers apply the genuine effects once; another worker-once changes no rows. Git and workers leave Forge contents unchanged, while revoked/read-only and unresolved-repository restrictions remain enforced.

The final populated drill's full restore command took **8.548 seconds** on a tiny synthetic fixture. Four acknowledged Forge writes approximately **15.328 seconds after** its captured boundary were intentionally not recovered. The separate fault-drill sample measured backup **10.718 seconds**, restore **8.139 seconds**, zero missing boundary commits and one missing acknowledged Git commit made **97.721 seconds after** the boundary. These are command timings and finite recovery-point demonstrations, not production RPO/RTO or lossless guarantees.

## Restored legacy upgrade regression

The five-group upgrade suite creates a real schema003 database from migrations 001/002/003 with a legacy owner/repository, logically dumps and restores it, then migrates to006 twice. Its actual catalog must equal the third exact fixture and differ from both the pristine006 and fully restored006 fixtures. Native Git operations and nonempty Forge content are added before the upgraded source is backed up. The final restore into another fresh database/volume compares all fourteen tables, preserves the legacy identities, and verifies authenticated clone/fsck, Forge content, permissions, numbering and CAS. Its final restore command took **8.957 seconds**. Later acknowledged Git/Forge changes are intentionally absent.

The pre-fix executable was separately tested in an explicit negative reproduction mode: the known valid third catalog was rejected and no backup destination published. Normal CI never enables that mode and requires the complete five-group successful upgrade path. Independent review also used an actual historical schema003 executable, a real old-schema dump/restore, the corrected new migrator, and a successful backup/verify/fresh restore; that separate reproduction confirms the same compatibility fix without relying only on the acceptance harness.

## Recovery limits and review

Issue/comment counters and CAS versions return to the snapshot. Numbers and versions observed only after the backup can recur in the restored timeline; this is not global monotonic identity/versioning across data loss. After cutover, clients must GET and confirm restored content and versions rather than rely on cached post-boundary identities/versions as a recovery fence. No disaster-recovery epoch protocol is implemented.

Independent review checked the merge, exact schema contract, all new Forge constraints and the populated test assertions. It found a real compatibility regression: a logically restored schema003 upgraded to006 has the normalized old ref CHECK alongside native new Forge CHECKs, and the initial two-shape comparator refused its backup. The fix adds only that third complete reviewed fixture, binds it in the manifest digest, and tests both the real migration/restore path and full upgraded backup/restore. Arbitrary expression normalization remains forbidden. Preliminary binary results are not counted as final verification. After the correction and final report/document checks, independent review reported no remaining confirmed blocker; the exact remote head's CI remains a separate check. The API is still personal-owner-only, not an organization/collaborator ACL model. Trigger immutability is not protection against privileged administrators. Keep all target database clients, including PG-only workers, stopped until restore succeeds and is reviewed; the filesystem guard cannot fence workers that intentionally never access GitFS.

Not established: hardware/power-loss safety, actual PostgreSQL crash or network partitions, distributed fencing, production scale/RPO/RTO, online/PITR recovery, backup signatures/remote retention, external exactly-once effects, Kafka, multi-user Forge collaboration or automatic traffic cutover. See [the backup contract](backup-restore.md) and [Forge contract](forge-issues.md).
