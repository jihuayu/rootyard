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
- deletion claims use owner + claim generation + lease, re-prove the absence of
  serving/transition links immediately before `DELETE`, and finalize with a
  claim-generation CAS. Resurrecting a retired content address bumps the
  authority generation onto a fresh path, so a stale deleter can only remove
  abandoned bytes and never a newly acknowledged object.

## Supported backup contract

Paired Rootyard archives are the supported Pando backup authority. A restore
rotates the storage authority exactly once for the whole database before
importing every serving repository closure, so a restored database sharing the
same bucket never inherits the source installation's deletable namespace.

Arbitrary metadata-only PostgreSQL PITR snapshots or external base backups are
**not** a supported backup authority for Pando remote GC: restoring such a
snapshot after remote deletion can point at bytes this GC removed. Operators
must retain a paired Rootyard archive, or re-register/pin the required closure,
before enabling destructive Pando deletion. The feature therefore fails closed
on unknown backup authority instead of assuming every database snapshot is a
retention root.

## Explicit exclusions

- Pre-132 PackManifest v1 objects at tenant-only keys are never registered and
  are permanently protected.
- Uploaded-but-unlinked staged objects (crash/publish retry) are protected.
- Objects under another authority (foreign/restored deployment) are protected.
- S3 `LIST` is never used as a retention authority.

Destructive deletion additionally requires `ROOTYARD_PANDO_REMOTE_DELETE=true`;
without it, marking and dry-run evidence still run and no bytes are removed.
