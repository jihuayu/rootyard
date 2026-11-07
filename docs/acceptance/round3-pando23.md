# Round-3 issue #23 acceptance — Pando authority-scoped remote retention

Status: **ACCEPT_FOR_DOCUMENTED_MODE / closable**, pending the primary's final
review and merge. This is an opt-in managed-authority mode, not universal
production GC. Permanent evidence:
[`evidence/round3/pando23-authority-1061a8e/`](../../evidence/round3/pando23-authority-1061a8e/README.md).

## Source and result

- Compiled production source: `1061a8ee9d1ecc783189d33949980eac6b3bd6ea`;
  harness commit `750ccce` is test-only. Production input digest
  `9e33859aad991589c57863af6f6b46fe42290071b3e271f90eda44f6d707feac`
  (329 files) is unchanged by the compile and still reproduces from the
  current tree.
- Local certified binary: `6f76d70966473cd4bc956bc6a6cff792191664dba3516736b5d50cb92e156eba`.
  Hosted-VM binary: `f0061754a2ccb4678db272cfc3662cc106945ee2819838b5a4868fde9d413046`
  for the same source and production input; the two binaries are distinct
  build artifacts (no equal-hash-across-platforms claim).
- `coordinator-status.json` (stored as `status.json`): state `passed`, stage
  `complete`, **10/10 jobs passed** — Rust lib 142 tests, real Garage/S3 +
  Vault + PostgreSQL Rust Pando test 1/1, schema 132 contract 8 checks, GitFS
  lifecycle 3/3, GitFS physical 8/8, Pando service 2/2, legacy 131 3/3,
  legacy 130 3/3, SHA-256 matrix 6/6, SHA-256 restore 2/2.
- The Rust Pando test is the only suite that actually removes remote bytes:
  dry run first (`remote_deleted=false`), then with
  `ROOTYARD_PANDO_REMOTE_DELETE=true` it asserts `remote_deleted=true`,
  `deleted>=1`, every eligible retired key absent by remote `HEAD`, the
  serving pack and unregistered legacy object still present, and the paired
  backup bytes unchanged. The Python `pando-service` fixture does not test
  remote deletion (`remote_deleted=false`; its limitation says "no
  remote-delete qualification").
- Hosted VM run [42337108050](https://github.com/jihuayu/rootyard/actions/runs/42337108050)
  passed all 17/17 kernel-cgroup assertions on combined source `1061a8e`;
  general supported-profile cgroup evidence remains the already-merged
  [kernel32 bundle](../kernel32-vm-8197377/README.md).

## Scope explicitly accepted

- Destructive deletion is opt-in via `ROOTYARD_PANDO_REMOTE_DELETE=true`; the
  default path marks and dry-runs without deleting.
- Only artifacts registered by this installation under its current storage
  authority, unreferenced by every serving pack set, stable transition and
  nonexpired publication fence, are eligible. Deletion uses exact registered
  keys; S3 `LIST` is never a retention authority.
- Legacy PackManifest v1 tenant-only keys, uploaded-but-unlinked objects and
  foreign-authority objects are permanently protected.
- Migration 132 adds the authority/registry/fence tables; backup format 8 and
  schema 132 are current, and frozen genuine format 6/schema 130 and format
  7/schema 131 archives still restore and upgrade.
- A paired Rootyard archive restore rotates the storage authority exactly once
  for the whole database, including a database with zero Pando repositories,
  before importing repository closures.
- Reviews: code `APPROVE_SCOPED_MODE` (0 P1, 0 P2, 4 P3), acceptance
  `ACCEPT_FOR_DOCUMENTED_MODE` with `closable_23=true`.

## Explicit non-claims

- A raw metadata-only PostgreSQL dump/PITR copy against the shared bucket is
  **unsupported, undetected and not fail-closed**; it retains the source
  authority and registry rows.
- No per-OID pruning inside serving packs; no hardware power-loss, cross-host
  HA, multi-zone durability or production scaling claim.
- The first combined physical-GC attempt failed with a pending tombstone after
  53.3 s and no retained SQL snapshot; the cause is **unclassified**. A
  focused rerun passed in 19.6 s and the full suite later passed 8/8 on the
  same certified binary. No runtime fix or "GC bug fixed" claim is made; the
  transient cause remains unknown.
- P3-1..P3-4 code-review observations (distinct-artifact serving proof,
  generic expired-publication error, unchecked `renew_publication` row count,
  fixture CAS not transactional) remain open follow-ups, not runtime
  blockers for the documented mode.

## Closure condition

Issue #23 may close only after the primary's final review and merge of this
documentation/evidence change. Roadmap #48 remains open with #25, #26, #43 and
#44; #32 is closed via PR #60 and #38 via PR #57.
