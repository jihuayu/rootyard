# SHA-256 repository acceptance (issue #38)

This document records the delivered SHA-256 repository boundary and the native
evidence used for issue #38. It does not claim SHA-1-only code paths or
compatibility drills as end-to-end support.

## Delivered boundary

- Repository creation accepts an explicit `object_format` of `sha1` or
  `sha256`; the value is persisted on `repositories` and carried through source
  pins, CI checkout plans, job views, mirror snapshots, backup manifests and
  restore.
- Smart HTTP and native Git operations are performed by the stock Git binary.
  Cross-format operations fail closed instead of being inferred from OID length.
- Source pins and CI checkout plans validate OIDs against the repository's
  declared format: 40 lowercase hex for `sha1`, 64 lowercase hex for `sha256`.
  Zero OIDs, uppercase hex, abbreviations and the other format's width are
  rejected through the actual HTTP/native services.
- A complete SHA-256 CI plan contains `object_format: "sha256"`, the exact
  64-hex target OID, the SHA-256 receipt digest and the declared dependencies.
  The materialized job view and mirror credential fetch the exact OID and a
  stock `git clone` verifies it with `rev-parse` and `fsck`.
- Offline backup/restore preserves the SHA-256 repository, its refs, its
  retained CI pin receipt and its object format. A post-restore stock clone
  fetches the original 64-hex head and passes strict `fsck`.
- SHA-256 Git object identity remains separate from SHA-256 LFS content
  digests; the LFS hash algorithm is still a content digest, not a Git object
  format.

## Schema correction

The original schema had two constraints on `ci_checkout_jobs`:

1. the plan presence NULL/required shape (migration 008), and
2. an automatically named `ci_checkout_jobs_check1` (migration 008) that
   hard-coded `object_format = 'sha1'` and a 40-hex `target_oid`.

Migration 109 dropped only the first constraint and added a format-aware
constraint for the JSON plan. The old auto-named constraint remained and made
every real SHA-256 checkout plan fail PostgreSQL insertion with
`23514 ci_checkout_jobs_check1`, even though the Rust plan validation had
accepted it.

Migration `131_ci_checkout_plan_shape.sql`:

- drops `ci_checkout_jobs_check1` and replaces it with the explicitly named,
  format-aware `ci_checkout_jobs_plan_shape`;
- restores the plan-presence invariant as `ci_checkout_jobs_plan_presence`
  (migration 109 had dropped it without replacement);
- keeps zero OIDs, uppercase hex, wrong-width OIDs and malformed receipt
  digests rejected at the database boundary.

The canonical schema fixtures are `schema/131_catalog.json`,
`schema/131_restored_catalog.json` and `schema/131_upgraded_catalog.json`, with
`schema/131_catalog.sql` used by the backup catalog projection. New backups use
format 7 and embed the 131 catalogs; format 6 remains frozen at the schema130
catalogs so archives made before migration 131 stay verifiable.

## Reproducible native tests

Environment: disposable PostgreSQL 17 at `127.0.0.1:55433`, stock Git 2.52,
isolated loopback HTTP ports and temporary storage. Build the private binary
with the shared cargo lock, then run:

```sh
export ROOTYARD_TEST_DATABASE_URL=postgres://agent@127.0.0.1:55433/round2_sha38
BIN=/workspace/scratch/rootyard-round2/sha38/rootyard

python3 tests/sha256_service.py --binary "$BIN"
python3 tests/sha256_matrix.py --binary "$BIN" \
  --report /workspace/scratch/rootyard-round2/sha38/sha256_matrix-report.json
python3 tests/sha256_restore.py --binary "$BIN" \
  --report /workspace/scratch/rootyard-round2/sha38/sha256_restore-report.json
python3 tests/schema_contract.py --binary "$BIN"
python3 tests/ci_job_checkouts.py --binary "$BIN"
```

`tests/sha256_service.py` covers service creation, stock push/fetch/browse,
ref CAS and Forge pull/review/check/check-run/CI-pin/merge format admission.

`tests/sha256_matrix.py` is the missing end-to-end matrix. It runs:

| case | real assertion |
| --- | --- |
| `setup_matrix` | primary and real `serve-mirror` process, shared audience, isolated schema |
| `sha256_full_flow` | create SHA-256 repo, stock push/fetch/fsck, mirror sync/prepare, source pin, complete plan/receipt with 64-hex target, checkout clone with exact OID, uppercase/abbreviated/zero-OID negatives |
| `sha1_regression` | the same mirror/pin/checkout matrix on a SHA-1 repository with exact 40-hex target |
| `mixed_format_rejections` | valid OIDs from the other format rejected by pin/prepare/checkout and a native cross-format fetch |
| `policy_and_storage_bounds` | one durable intent per job, exact receipt digest, wrong storage generation rejected |
| `plan_constraint_shapes` | PostgreSQL accepts valid SHA-1/SHA-256 plan shapes and rejects mismatched width, uppercase, all-zero, malformed receipt and null-plan rows |

`tests/backup_sha256_legacy130.py` creates a real format6/schema130 archive with
a trusted baseline binary, proves the current binary rejects it without opt-in,
then restores it with `--allow-legacy-schema130`, verifies the frozen format6
catalog and applies migration 131 while preserving SHA-256 objects, refs, pin,
generation and checkout-revocation/tombstone semantics.

`tests/sha256_restore.py` creates a SHA-256 repository plus a retained CI pin,
takes an offline paired backup, restores into a fresh database and volume with
`--isolated --trust-backup`, then performs a stock clone, format check, strict
`fsck`, retained pin lookup and native retention-ref check.

## Actual results

Final production source: `f31910086acbaa87d9e98df440ca8c28c7bb7e08`
(format-7 version freeze `<=131`); certified input digest
`fdfbbfcfe3acc36e5315e7dcc679d39709856c8c8fddf9aa32f8822b90c2ef5b`; immutable
binary SHA-256
`35d01c5f454bd8ea505a639e6a85ad5b90193f996451daa1a4d598c8e5dd0153`.
The reports are committed at
[`evidence/round2/integration-f319100/`](../evidence/round2/integration-f319100/)
(`core/sha256_service-output.json`, `core/sha256_matrix-output.json`,
`core/sha256_restore-output.json`, `core/backup_sha256_legacy130-output.json`,
`core/schema_contract-output.json`, `core/ci_job_checkouts-output.json`). Earlier pre-final-format executions are
historical and are not cited as the final run.

| command | real outcome on binary `35d01` |
| --- | --- |
| `tests/sha256_service.py` | 2/2 passed. |
| `tests/sha256_matrix.py` | 6/6 passed: mirror/pin/checkout, 64-hex plan/receipt, SHA-1 regression, mixed/abbreviated/zero-OID negatives. (Forge pull/review/check/merge is covered by `sha256_service`.) |
| `tests/sha256_restore.py` | 2/2 passed. |
| `tests/backup_sha256_legacy130.py` | 3/3 passed from a genuine format-6 archive produced by the old `6135` binary. |
| `tests/schema_contract.py` | 8 checks passed, including public and custom bootstrap paths. |
| `tests/ci_job_checkouts.py` | 15/15 passed on an isolated own database; the failed first attempt (9 cases, shared-database migration/advisory-lock collision) is preserved unchanged. |
| Rust | 139 library tests + 1 Rust Pando test passed. |

All tests used real PostgreSQL 17, real processes and stock Git. No test was
skipped or replaced by a simulated receipt. Final raw logs are under the
coordinator scratch `verify_final_core/postprocess*`; the committed report set
is the committed evidence directory linked above. The exact source/input/binary
digests above are the certificate for this issue.

## Explicit boundaries

- The exercises are single-host loopback fixtures, not a scaling,
  power-loss, production RPO/RTO or multi-node availability claim.
- Native cross-format rejection is exercised through service APIs and one
  stock `git fetch`; it is not an exhaustive transport matrix.
- Git SHA-256 support requires a Git client with SHA-256 object-format support;
  the tested client is stock Git 2.52.
- The backup test restores a local paired database/volume; it does not test
  restoring into a different cluster topology.
