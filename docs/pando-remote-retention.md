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

## Supported backup contract

Paired Rootyard archives are the supported Pando backup authority. A restore
rotates the storage authority exactly once for the whole database before
importing every serving repository closure, so a restored database sharing the
same bucket never inherits the source installation's deletable namespace.

Arbitrary metadata-only PostgreSQL PITR snapshots or external base backups are
**not** a supported backup authority for Pando remote GC. Such a copy retains
the source `authority_id` and registry rows, so it is **not detected** and the
deleter does **not** fail closed for it: starting that copy against the shared
bucket would let it treat the source installation's live, non-serving artifacts
as its own. Never run an out-of-band metadata copy against the shared bucket.
Operators must retain a paired Rootyard archive (the only path that rotates the
authority once for the whole restored database), or re-register/pin the
required closure, before enabling destructive Pando deletion.

## Explicit exclusions

- Pre-132 PackManifest v1 objects at tenant-only keys are never registered and
  are permanently protected.
- Uploaded-but-unlinked staged objects (crash/publish retry) are protected.
- Objects under another authority (foreign/restored deployment) are protected.
- S3 `LIST` is never used as a retention authority.

Destructive deletion additionally requires `ROOTYARD_PANDO_REMOTE_DELETE=true`;
without it, marking and dry-run evidence still run and no bytes are removed.
