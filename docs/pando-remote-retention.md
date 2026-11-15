# Pando remote artifact retention

Migration 132 adds a *storage authority* to Pando remote artifact keys. Only
objects this database installation registered and published itself can ever
become deletion candidates:

- new pack keys live under
  `tenants/<tenant>/authorities/<authority>/g<generation>/<namespace>/<sha256>`;
- `pando_remote_artifacts` records the exact immutable path and state;
- `pando_manifest_artifacts` links each acknowledged manifest to its four
  encrypted objects;
- marking retires an active artifact only when **no** link belongs to any
  serving `pando_repository_states.pack_ids` and no owning repository is in a
  non-stable/non-Pando transition;
- `pando_publication_fences` is a durable pending-publication root: it is
  written atomically with each reservation, renewed in the activation
  transaction after all four remote objects pass read-back verification, and
  removed only by the serving `pack_ids` CAS. Marking and deletion treat any
  nonexpired fence as a retention root, so a publisher paused past its lease is
  fenced rather than deleted;
- the serving CAS verifies, with row locks in that same transaction, that all
  four linked artifact rows are `active` and their publication fences are
  nonexpired. Any expired/retired/deleting/missing artifact fails the CAS so the
  caller must republish a fresh generation;
- deletion claims use owner + claim generation + lease, re-prove the absence of
  serving/transition/fence references immediately before `DELETE`, and finalize
  with a claim-generation CAS. Expired `deleting` claims are retried with a new
  claim generation. Resurrecting a retired content address bumps the authority
  generation onto a fresh path, so a stale deleter can only remove abandoned
  bytes and never a newly acknowledged object.

## External bucket authority proofs & PITR fencing (#77)

Starting with `schema 148`, `pando_storage_authorities` and an external
write-once proof object under the shared bucket fence metadata-only
`pg_dump` / PostgreSQL PITR clones from deleting objects belonging to another
deployment sharing the same bucket:

- At runtime attestation (`serve` startup when remote delete or Pando state is
  active, `prepare`, `pando-transition cutover`, `pando_repack`,
  `pando_tombstone_delete`, and `rootyard pando-authority verify`), Rootyard
  binds the active `authority_id` and `authority_epoch` to the deployment's
  stable identity tuple:
  - local `.volume-id` and `.pando-deployment-id` markers in `ROOTYARD_DATA_DIR`,
  - PostgreSQL system coordinates (`system_identifier`, `database_oid`,
    `schema_oid` of `pando_storage_authorities`, and `pg_timeline_id`),
  - canonical sanitized `backend_identity`, and a fresh `proof_nonce`.
- External proof records live at
  `pando-authorities/<authority_id>/epochs/<epoch:020>.json` and are written with
  write-once CAS (`If-None-Match: *` on S3, `create_new` + `hard_link` locally).
  Neither Pando artifact GC nor tombstone pruning may delete keys under
  `pando-authorities/`.
- Every destructive `pando_tombstone_delete` run strictly validates
  `ROOTYARD_PANDO_REMOTE_DELETE` (`true`, `false`, or unset — invalid values fail
  closed), verifies local + PG + external epoch proof consistency and checks
  that `epoch + 1` is absent in the bucket, then atomically advances
  `authority_epoch` (`E -> E + 1`) via CAS before issuing any remote `DELETE`.
- Any deployment identity mismatch, missing proof, or pre-existing successor
  epoch `E + 1` (clone/PITR rollback) fails closed, latches
  `remote_delete_fenced = true` in `pando_storage_authorities`, blocks Pando
  pack publication, and performs zero remote object deletions.
- `pando_retention_roots` and `pando_retention_root_manifests` record durable
  backup/PITR retention pins (`backup_snapshot`, `pitr_recovery_point`,
  `manual_pin`); active non-expired roots block artifact retirement and deletion.
- Operators inspect and manage authorities via `rootyard pando-authority`:
  `status`, `verify`, `isolate --confirm-shared-bucket`, `pin-recovery-point`,
  and `release-recovery-point`.

## Live-service acceptance harness (#77)

CI runs the prebuilt candidate through the existing reporting boundary:

```sh
python3 tests/pando_pitr_service.py \
  --binary "$ROOTYARD_BIN" \
  --build-receipt "$ROOTYARD_BUILD_RECEIPT" \
  --expect-commit "$GITHUB_SHA" \
  --report test-results/pando-pitr-service.json
```

The harness refuses to run unless the shared v2 receipt reader revalidates the
exact checkout, bound source/config/toolchain inputs, receipt bytes, binary
digest and expected commit. It revalidates the same closure after the suite and
only reports `passed: true` when all seven mandatory cases passed and the
binary, receipt and owned harness hashes/identities are unchanged. The CI
native manifest binds that report and those seven case names.

Scope is deliberately narrow: actual Rootyard and stock Git run against actual
PostgreSQL, while object storage and Vault Transit are **in-process loopback
HTTP fixtures** (`TrackingLoopbackS3` / `TrackingLoopbackVaultTransit`).
Recovery is a logical `pg_dump`/`pg_restore` metadata clone plus a simulated
epoch rollback; the seeded Pando metadata and receipts are synthetic fixtures.
This is not a real external Garage/S3, Vault, physical PostgreSQL WAL/PITR,
cloud or hardware qualification, and the suite's best-effort cleanup is not
asserted.

## Real-provider qualification gates (#77)

The hosted live-service case above is only the logical/in-process baseline. The
separately reviewed real-provider harnesses must be run against one clean final
source SHA and the exact same source/config/toolchain-bound immutable CLI build
receipt. They use real owned PostgreSQL 17, real owned Garage and real Vault
Transit fixtures. The report binding revalidates the source, receipt, binary,
configuration/toolchain closure and the complete pre/post transitive harness
identity list before returning a passing report; a report whose source, binary,
receipt or harness bytes change is not a pass.

Use generic public placeholders below; substitute paths on the qualification
host. Run these commands from the final clean source tree that matches the
receipt and binary, and derive the task-specific source variable from that
tree's HEAD. Provider credentials, DSNs, tokens and locator paths are runtime
environment data and are never command-line arguments or report artifacts. Do
not place secrets in argv, shell history, the JSON report or captured
diagnostics.

```sh
ROOTYARD_QUALIFICATION_SHA="$(git rev-parse HEAD)"

python3 tests/pando_pitr_physical_service.py \
  --binary /srv/rootyard/bin/rootyard \
  --build-receipt /srv/rootyard/evidence/rootyard.build-receipt.json \
  --expect-commit "$ROOTYARD_QUALIFICATION_SHA" \
  --pg-bin /opt/postgresql/17/bin \
  --report /srv/rootyard/evidence/pando-pitr-physical.json \
  --timeout 1800

python3 tests/pando_backup_restore_service.py \
  --binary /srv/rootyard/bin/rootyard \
  --build-receipt /srv/rootyard/evidence/rootyard.build-receipt.json \
  --expect-commit "$ROOTYARD_QUALIFICATION_SHA" \
  --pg-bin /opt/postgresql/17/bin \
  --report /srv/rootyard/evidence/pando-backup-restore.json \
  --timeout 1800
```

`--pg-bin` must contain the explicit PostgreSQL 17 tools; `psql` and `git` must
also be available. `--timeout` is an optional bounded override. Keep provider
configuration only in the runtime environment. The required preflight names are:

```text
ROOTYARD_OBJECT_STORE_ENDPOINT
ROOTYARD_OBJECT_STORE_BUCKET
ROOTYARD_OBJECT_STORE_REGION
ROOTYARD_OBJECT_STORE_ACCESS_KEY
ROOTYARD_OBJECT_STORE_SECRET_KEY
ROOTYARD_KMS_VAULT_URL
ROOTYARD_KMS_VAULT_TOKEN
ROOTYARD_KMS_VAULT_KEY
ROOTYARD_GARAGE_IMAGE_DIGEST
ROOTYARD_VAULT_IMAGE_DIGEST
```

Optional preflight names are `ROOTYARD_OBJECT_STORE_SESSION_TOKEN` and
`ROOTYARD_KMS_VAULT_MOUNT`. The Garage image must match the immutable
`expected_digest` in [scripts/owned_garage_fixture.sh](../scripts/owned_garage_fixture.sh)
(currently `sha256:4c9b34c113e61358466e83fd6e7d66e6d18657ede14b776eb78a93ee8da7cf6a`);
the Vault pin is currently
`hashicorp/vault@sha256:44fa1e5a57d0bcf7fb163159872263b79a575e5dbfefd5b9bde1b7e4aada2f32`.
A different valid-looking digest is not accepted.

AC2 exercises the current metadata-only Pando archive contract from
`tests/schema_baseline.CURRENT_BACKUP_FORMAT` (currently 25) and the current
`schema_baseline.SCHEMA_VERSIONS` vector (currently 149). It is not the frozen
format 23 contract. The paired Blob/RefStore
`CURRENT_BLOB_BACKUP_FORMAT` (currently 26) and the whole #169 durability,
RPO/RTO or cross-provider platform remain separate and are not claimed here.

The AC2 archive checks require the CLI result and archive manifest to match the
current format, the exact current schema vector, `COMPLETE`, zero CLI
`blob_artifacts` and the Pando-only manifest shape. Do not accept an arbitrary
integer or infer the expected contract from the manifest under test.

### Fixed AC1 physical case inventory (11)

```text
physical_restore_to_named_target
source_external_authority_advanced_after_restore_point
source_verify_after_clone_gc
due_unpinned_candidate_observed_before_clone_gc
stale_clone_fenced_before_remote_delete
remote_delete_method_count_zero
known_live_and_pinned_recovery_objects_head_get_digest_unchanged
clone_isolate_succeeded
clone_cache_wiped
real_service_stock_git_clone_fetch_fsck
owned_resource_cleanup_passed
```

### Fixed AC2 current-archive case inventory (7)

```text
archive_current_pando_only_and_backup_verify_passed
restore_authority_rotated_once_and_restore_generation_incremented_once
old_authority_claim_not_reused_and_new_closure_readable
source_and_restored_permissions_preserved
active_pin_reissued_under_new_authority_and_closure_remains_readable
single_export_failure_not_published_then_fresh_path_retry_passed
all_owned_resources_cleaned
```

A pass requires every fixed case, not a subset, plus unchanged source/binary/
receipt/harness identities and successful owned cleanup. Raw Rust/service
stdout/stderr, SQL bodies, credentials, DSNs, object bytes and locator paths are
not report artifacts.

The other affected service regressions are run through their existing owning
harnesses and are not replaced by these two real-provider gates:

- `tests/pando_pitr_service.py` — logical/in-process mock service baseline,
  honestly distinct from the physical AC1 provider run above.
- `tests/pando_transition_service.py` — transition coverage.
- `tests/pando_maintenance_service.py` — normal repack/cache and the existing
  bounded backup-barrier retry.
- `tests/backup_recovery.py` — recovery-history backup/restore drill.
- `tests/backup.py` — offline backup/restore drill.
- `tests/pando_maintenance.rs` — existing stale-claim CAS case; use its normal
  Rust test runner.

Current hosted CI's full Python discovery (`scripts/run_python_ci_tests.py`)
includes the new pure boundary test modules, but the existing live CI Pando
step (`.github/workflows/ci.yml`) invokes only the logical/mock
`tests/pando_pitr_service.py` harness. The two real-provider commands above are
not part of hosted CI at this source identity and no new hosted workflow,
provider credentials or helper platform are required by the original AC.
Before Issue #77 closure,
the exact final SHA must be run through both real-provider harnesses and the
affected regressions, with all 11 + 7 case outcomes, source/binary/receipt/
harness stability and owned cleanup verified separately. Pure CI or source
review alone is not an actual-provider qualification claim, and this document
does not record or assert that the real-provider gates have run or passed.

## Supported backup contract

Paired Rootyard archives and isolated cloned authorities are the supported Pando
recovery paths. An offline `rootyard restore` calls `reset_authority`,
incrementing `restore_generation`, generating a fresh `authority_id`, clearing
prior attestation/fence fields, and clearing source retention roots before
re-importing the archive's Pando closure, so the restored deployment never
inherits the source's deletable authority namespace.

Out-of-band metadata-only PostgreSQL PITR / basebackup / `pg_dump` clones that
retain the source `authority_id` are detected fail-closed: remote deletion is
refused and `remote_delete_fenced` latches `true` before any shared bucket
object can be touched. To bring an intentional replacement clone online against a
shared bucket without deleting historical source objects, operators must first
pin recovery points as needed and explicitly rotate to a fresh isolated
authority via `rootyard pando-authority isolate --confirm-shared-bucket`.

## Explicit exclusions

- Pre-132 PackManifest v1 objects at tenant-only keys are never registered and
  are permanently protected.
- Uploaded-but-unlinked staged objects (crash/publish retry) are protected.
- Objects under another authority (foreign/restored/isolated deployment) are
  protected.
- External authority proofs under `pando-authorities/` and objects linked to
  active non-expired `pando_retention_roots` are protected.
- S3 `LIST` is never used as a retention authority.

Destructive deletion additionally requires `ROOTYARD_PANDO_REMOTE_DELETE=true`;
without it (or when set to `false`), marking and proofs remain active and no
bytes are removed. Any value other than `true` or `false` fails closed.
