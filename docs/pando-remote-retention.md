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
