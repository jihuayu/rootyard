# Pando authority-scoped remote retention — combined acceptance evidence (source `1061a8e`)

Permanent evidence for issue
[#23](https://github.com/jihuayu/rootyard/issues/23) after the round-3
integration of Pando remote retention with the verified sandbox runtime.
Independent reviews: code `APPROVE_SCOPED_MODE` (0 P1, 0 P2, 4 P3) and
acceptance `ACCEPT_FOR_DOCUMENTED_MODE`, `closable_23 = true`, for a
**documented managed-authority mode**, not for universal production GC.

**Status: all 10 jobs of the combined-source acceptance pipeline passed.**
The issue closes only after the primary's final review and merge of the
documentation/evidence change; this bundle does not close it by itself.

## Read this scope first

This is an **opt-in, authority-scoped** deletion mode, not a universal safe
GC:

- Destructive remote deletion requires the explicit operator switch
  `ROOTYARD_PANDO_REMOTE_DELETE=true`. Without it, marking and a measured
  dry run still execute (`remote_deleted=false`, `dry_run=true`) and no bytes
  are removed.
- Only artifacts that this database installation **registered itself** in
  `pando_remote_artifacts`, under its **current authority**, in
  `.../authorities/...` paths, and that are **unreferenced by every serving
  pack set, every non-stable/non-Pando transition and every nonexpired
  publication fence**, can become deletion candidates.
- Legacy PackManifest v1 objects at tenant-only keys, uploaded-but-unlinked
  staged objects, and objects of any **foreign/other authority** (including a
  restored deployment) are permanently protected. S3 `LIST` is never used as
  a retention authority; deletion is by exact registered key.
- A **metadata-only PostgreSQL dump/PITR copy** keeps the source
  `authority_id` and registry rows. Starting such a copy against the shared
  bucket is **UNSUPPORTED, UNDETECTED and NOT fail-closed** — the deleter
  cannot distinguish it from the source installation. Never run it against
  the shared bucket. Only a **paired Rootyard archive restore** is a supported
  Pando backup authority; it rotates the storage authority exactly once for
  the whole restored database before importing repository closures (including
  when the restored database contains zero Pando repositories).
- No per-OID pruning inside a serving pack: deletion works on whole registered
  remote artifacts, not individual Git objects inside a serving pack.
- No hardware power-loss, cross-host failover/HA or multi-zone durability
  claim. Fixtures are single-host loopback except the hosted-VM kernel run
  cited below, which is a different feature's profile proof.
- Migration `132` is already pushed on the integration line and is immutable;
  this evidence/docs change contains no runtime, schema or test change.
  Backup format 8 / schema 132 are the current contracts; frozen legacy
  format 6/schema 130 and format 7/schema 131 archives still restore.

## Source, input and binaries

| Item | Value |
| --- | --- |
| Compiled production source | `1061a8ee9d1ecc783189d33949980eac6b3bd6ea` |
| Harness commit in `status.json` | `750ccce7571dc5eed7bc9ccaaf3aa04e31755760` (test-only diagnostic snapshot; no production/schema delta) |
| Production input digest | `9e33859aad991589c57863af6f6b46fe42290071b3e271f90eda44f6d707feac` |
| Local immutable binary | `6f76d70966473cd4bc956bc6a6cff792191664dba3516736b5d50cb92e156eba` (role `pando61`, certificate `valid=true`) |
| Source-input map raw file | `5142b8fdf31484967b7b647414e697bfac78c3a58c4dd3b7e3bbda7cbd71283b` (`source-inputs.json`; `build-inputs-before.json` was byte-identical) |
| Hosted-VM source | `1061a8ee9d1ecc783189d33949980eac6b3bd6ea` |
| Hosted-VM binary | `f0061754a2ccb4678db272cfc3662cc106945ee2819838b5a4868fde9d413046` |
| Hosted-VM artifact ZIP | `692d86087ccfeeb1815d35d891926241f4e3b0c2d6d1cddac7183b5ba7f3d168` (ZIP **not** stored in this repo) |

`status.json` records `production_inputs_unchanged_after_compile=true` and a
valid certificate with `built_commit == source_commit == 1061a8e...`. The
harness commit `750ccce` changed only test diagnostics and documentation, so
the already-certified `1061a8e` binary was reused under the source-input
equivalence rule; `python3 source_digest.py` on the current tree still
reproduces `9e33859...` over 329 files.

The VM binary and the local binary are **distinct artifacts of the same
production input**, built in different environments. This bundle does **not**
claim equal binary hashes across platforms.

## Passing results (`status.json`, state `passed`, stage `complete`)

| Job | Result on `6f76d70` | Evidence |
| --- | --- | --- |
| rust-lib | `142 passed; 0 failed` (18.71 s) | `logs/rust-lib-1794024574.log` (stdout only; no JSON by coordinator design) |
| rust-pando (real PostgreSQL + Garage/S3 + Vault) | `1 passed; 0 failed` (test body 12.31 s) | `logs/rust-pando-1794024629.log` (stdout only; no JSON by coordinator design) |
| schema | 8 contract checks all true, version `132`, 85 tables / 13 functions / 33 triggers | `logs/schema-1794024696.log` (stdout only; no JSON by coordinator design) |
| gitfs-lifecycle | 3/3 cases passed (17.23 s) | `reports/gitfs-lifecycle-1794024701.json` |
| gitfs-physical | 8/8 cases passed (149.71 s) | `reports/gitfs-physical-1794026210.json` |
| pando-service | 2/2 cases passed (26.48 s) | `reports/pando-service-1794026360.json` |
| legacy131 | 3/3 cases passed (90.21 s) | `reports/legacy131-1794026387.json` |
| legacy130 | 3/3 cases passed (88.04 s) | `reports/legacy130-1794026478.json` |
| sha256-matrix | 6/6 cases passed (10.88 s) | `reports/sha256-matrix-1794026568.json` |
| sha256-restore | 2/2 cases passed (70.33 s) | `reports/sha256-restore-1794026579.json` |

All seven report files carry `"passed": true` and the same binary SHA-256
`6f76d709...`; every case in them is `passed` (27 cases total). Each stored
report's SHA-256 equals the `report_sha256` recorded in `status.json`.
`rust-lib`, `rust-pando` and `schema` have **no report JSON**: the coordinator
passes `--report` only to Python jobs. Their evidence is the actual stdout log
plus `exit_code: 0` in `status.json`; no `.json` report is fabricated here.

### What the genuine Rust Pando test proves

`tests/pando_maintenance.rs` is a real PostgreSQL + Garage/S3 + Vault
acceptance test; it skips only when `ROOTYARD_OBJECT_STORE_ENDPOINT`,
`ROOTYARD_KMS_VAULT_URL`, `ROOTYARD_PANDO_TEST_ROOT` or
`ROOTYARD_TEST_DATABASE_URL` is absent. The log shows it ran (not skipped) in
the coordinator's environment, which loads `ready.env` into every job
(secret values are not read or published here). In the destructive stage it:

- first runs the delete job without opt-in and asserts
  `remote_deleted=false`, `dry_run=true` (no bytes removed);
- sets `ROOTYARD_PANDO_REMOTE_DELETE=true`, runs again and asserts
  `remote_deleted=true` and `deleted >= 1`;
- asserts every eligible retired key is now absent via remote `HEAD` (none);
- asserts the serving pack ciphertext is still present;
- asserts an unregistered legacy tenant-only object survives;
- asserts the paired pre-compaction backup bytes are byte-unchanged.

The compacted serving set, the four-artifact publication proof and the
pending-fence/reservation/lease paths are exercised in the same test. This is
the only suite here that actually deletes remote Pando bytes.

The Python `pando-service` fixture is **not** a remote-deletion test: its
report says `remote_deleted: false` and its limitation is
`"Loopback single-node fixture; no remote-delete qualification."` It proves
automatic threshold compaction, cache hydration/eviction/tamper recovery,
backup-barrier retry and non-ref-OID survival, not remote DELETE.

### Backup/restore and schema evidence

- `legacy131` and `legacy130` each create a **genuine** archive with the old
  trusted binary (format 7/schema 131 `35d01c5f...`; format 6/schema 130
  `6135f028...`), assert the candidate rejects it without explicit opt-in,
  then restore and upgrade to schema `132` with exact SHA-256 clone, preserved
  pin and generation, revoked checkout grant and preserved cancellation
  tombstone.
- `sha256-restore` proves exact HEAD/object format and retained pin after an
  asynchronous-provisioning-aware retry; `sha256-matrix` covers SHA-256 and
  SHA-1 flows plus mixed/abbreviated/uppercase/zero-OID negatives.
- `schema` passes canonical/roundtrip/restored-003/006/007-upgrade/
  upgraded-roundtrip/custom-search-path/custom-migrate-idempotent checks on
  schema `132`.

## Hosted-VM combined-source proof

`vm-42337108050/` contains the verified hosted-VM receipt for source
`1061a8e`: run
[42337108050](https://github.com/jihuayu/rootyard/actions/runs/42337108050),
job `128296401784`, artifact `13559528645`, conclusion `success`, all
**17/17** required kernel-cgroup assertions `true`, non-root uid 1001 and a
real 64 MiB tmpfs artifact pool. Files: `receipt.json`,
`native-cgroup-receipt.json`, `download-verification.json`, `binary.sha256`,
and a derived `run.json` reference. For the general supported-profile cgroup
proof, see the already-merged
[`evidence/round3/kernel32-vm-8197377/`](../kernel32-vm-8197377/README.md).
This VM run only pins combined source `1061a8e` for the sandbox profile; it is
not a Pando remote-deletion or HA proof.

## The first combined physical-GC attempt actually failed

This is recorded as a failure, not smoothed over:

- `attempts/pre-gc-physical-1794024719/status.json` is the first full combined
  run at harness `750ccce`; state `failed`, stage `gitfs-physical`,
  `exit_code: 1`.
- `gitfs-physical-1794024719.json` shows case
  `physical_loose_packed_and_pin` failed after **53.3013 s** with
  `maintenance state did not reach deleted: pending`; the tombstone stayed
  pending instead of deleted. **No SQL snapshot was retained** (the harness
  did not capture jobs/tombstone state before cleanup), so the cause is
  **UNCLASSIFIED**. There was **no runtime fix** for this observation.
- Harness `750ccce` added a bounded diagnostic failure snapshot to the
  physical fixture **without relaxing any assertion**; it did not change
  production inputs.
- A focused rerun of only the failing case with the **same certified binary**
  passed in **19.6391 s** (`focused-gc.json`, `focused-gc-state.json`), and
  the later full suite passed physical 8/8 in 149.71 s
  (`reports/gitfs-physical-1794026210.json`), followed by the remaining jobs.

The retry is qualified for the recorded binary/input, but the **transient
cause remains unknown**. Do not read this as "a GC bug was fixed"; no such
claim is made.

## Reviews and their exact scope

`reviews/` contains unchanged copies of the independent reviews:

- `review-final.json` / `.md` — code verdict `APPROVE_SCOPED_MODE` for source
  `89ba6a8` (0 P1, 0 P2, 4 P3). It was written while runtime was still
  pending, so it explicitly claims no native pass; its P3 observations remain
  open and non-blocking. The runtime gap it names was subsequently filled: the
  `pando23` run passed all 8 jobs on `89ba6a8`, and this bundle's combined
  `1061a8e` run passes all 10.
- `acceptance-review.json` / `.md` — `ACCEPT_FOR_DOCUMENTED_MODE`,
  `closable_23 = true`, scoped to managed authority-scoped remote GC with
  paired Rootyard archives as the only supported backup authority and
  destructive deletion opt-in via `ROOTYARD_PANDO_REMOTE_DELETE`. It was
  written against the `pando23` source `89ba6a8` evidence and explicitly says
  the combined source `1061a8e` had no report yet. That gap is resolved by
  `status.json` and the reports here; the acceptance scope itself is
  unchanged.

`pando23-source-89ba6a8/` preserves the actual evidence the acceptance review
cites: its `status.json`, the Rust Pando/schema stdout logs, the passing
reports, and the two pre-fix failures preserved unchanged in
`failed-pre-fix/` (`pando-service-1794023097.json`: automatic compaction did
not replace the serving set; `sha256-restore-1794023791.json`: expected 201,
got asynchronous 202 provisioning). Those earlier test-only convergence fixes
are history; they are not reintroduced or claimed as production fixes.
Earlier component failures (SQL parenthesis imbalance, fixture timing) are
summarized here only as historical context because they were fixed before
this final run.

## Verification performed for this bundle

- `sha256sum` of every stored file is in `manifest.json`; each copied report
  hash was cross-checked against `status.json` `report_sha256`.
- `source_digest.py` over the current tree returns
  `9e33859aad991589c57863af6f6b46fe42290071b3e271f90eda44f6d707feac`; the
  embedded digest in `source-inputs.json` and the certificate agree.
- Text scan of every stored file found no access keys, passwords, tokens,
  private keys, DSNs or raw environment dumps. Only the env-var names and the
  `ready.env` path appear in the acceptance review's environment note.
- No binary, artifact ZIP, backup set, PKI material, key, database dump or
  raw SQL snapshot is stored in this repository; large/ephemeral paths in the
  logs are scratch-run paths only.

## Remaining limitations

- P3-1..P3-4 from `review-final` remain open (serving proof counts joined rows
  rather than distinct artifacts; expired-publication error is generic;
  `renew_publication` does not check 4 rows; the fixture simulates the serving
  CAS with separate statements). They are not runtime blockers for the scoped
  mode but are real follow-ups.
- Pando worker SIGKILL/duplicate-wakeup recovery for the delete path is proven
  by SQL/lease fault injection in Rust, and real process-death/duplicate-wake
  recovery is exercised by the GitFS lifecycle/physical jobs; there is no
  Pando-specific process-SIGKILL test.
- No multi-instance two-process push+GC race test; single-node loopback
  fixtures.
- The transient first physical-GC failure cause is unclassified with no
  retained SQL snapshot.
- No production HA, hardware power-loss, cross-host or cloud-KMS
  qualification is claimed.
