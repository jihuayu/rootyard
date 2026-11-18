# W8-A single-node PG + Blob paired restore

Issue #120 adds a fail-closed, single-node recovery path for a `pg_refstore`
source whose Git bytes live in the remote Blob backend. A W8-A archive is a
frozen `format30` paired archive plus a non-secret sidecar and a completion
marker. Restore always creates a **new incarnation**: the source cluster
incarnation, storage authority epoch and every source execution credential are
never reused.

Raft cuts are deliberately out of scope. The producer refuses any source with
`ref_cas_projection_cursors` or `ref_cas_projected_operations` rows, and the
restorer refuses a `paired-manifest.json` sidecar. Multi-node coordinated cut
belongs to a different workstream.

## What is produced

```
<destination>/
  W8A_COMPLETE                 64 lowercase hex bytes: SHA-256 of w8a-paired.json
  w8a-paired.json              canonical non-secret sidecar (sealed)
  format30/                    unchanged paired PostgreSQL + Blob backup
    COMPLETE
    manifest.json
    metadata.dump
    blob/<repository>/<pack>/{pack.pack,idx.idx}
    volume/
```

The format30 inner archive is produced by the shared offline backup path. Any
`pg_refstore` serving repository makes that path choose format 30; W8-A does not
fork it. The sidecar is added only after the inner archive passes
`crate::backup::check`.

`W8A_COMPLETE` covers the sidecar bytes, and the sidecar seal covers the whole
sidecar with `manifest_seal_sha256` temporarily blank. This binds the source
cluster incarnation, storage authority identity/epoch, inner manifest and
completion hashes, metadata hash, Blob closure counts/digest, backend identity
and provider, and the key reference into one envelope.

## Key and configuration reference

The sidecar records public identity only:

* encryption mode (`provider-managed` or `local-envelope`);
* active key id, sorted known key ids and a domain-separated digest of
  `(key_id, public_sha256)` pairs;
* a deterministic canary wrap under
  `rootyard-w8a-key-canary-v1\0`;
* an optional printable, non-secret KMS reference.

The three domain tags are `rootyard-w8a-manifest-v1\0`,
`rootyard-w8a-key-canary-v1\0` and `rootyard-w8a-keyring-public-v1\0`.
Key bytes and passphrases are never serialized. `verify_key_reference` runs
before the target database or data directory is touched: a changed mode,
keyring, public key set, canary or KMS reference fails with
`KeyReferenceMismatch`. See
[`manifest_key_ref.rs`](../src/backup/w8a_paired/manifest_key_ref.rs) for the
exact domains and validation rules.

## Operator flow

1. Stop Rootyard, all Git descendants and every Blob reader/writer for the
   volume. The offline backup takes the volume lock and a repeatable-read
   database cut.
2. Keep destructive GC disabled:
   `ROOTYARD_STORAGE_MAINTENANCE=false`,
   `ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE=false` and
   `ROOTYARD_BLOB_DELETE=disabled`.
3. Run the backup binary against an **absent** destination directory:

   ```
   rootyard-w8a-backup create /srv/rootyard/backups/w8a-001
   ```

   The binary also rejects `ROOTYARD_PAIRED_RAFT_CLUSTER_JSON` and any
   pre-existing `paired-manifest.json`.
4. Verify the envelope without touching PostgreSQL:

   ```
   rootyard-w8a-backup check /srv/rootyard/backups/w8a-001
   ```

5. Restore into a **new, empty** PostgreSQL database and a **new, non-existent**
   data directory. `--compute-dir` must be empty or absent:

   ```
   rootyard-w8a-backup restore /srv/rootyard/backups/w8a-001 \
     --compute-dir /var/tmp/w8a-fsck --trust-backup
   ```

   `--trust-backup` is mandatory; there is no implicit trust mode. Use the same
   Blob backend identity and key material as the source. A different identity
   or keyring is refused.

## Fresh-incarnation fence

After the shared format30 restore succeeds, W8-A verifies that the restored
database has no raft projection rows and then runs one fencing transaction:

* rotate `cluster_authority.incarnation`;
* revoke every API and browser token and every web session;
* cancel queued/leased CI runs and revoke every plan-bearing checkout job
  (tombstone rows with `plan IS NULL` are preserved);
* expire ready workspaces;
* cancel every `OPEN` publication decision with
  `closed_code='restored_incarnation'` and advance all decision scope versions;
* release every active transient pin with `release_reason='operator_request'`;
* abort pending remote merge attempts when that ephemeral table exists;
* raise `pando_storage_authorities.authority_epoch` above the source epoch,
  rotate the authority, and set `remote_delete_fenced=true` with reason
  `'w8a-paired-restore-fenced'`;
* reset leased `event_deliveries` to pending so audit and ref-index workers can
  drain them.

RefStore realm columns, serving bindings, gates, protocol repo rows and
`ref_store_core_root_heads` are deliberately not rewritten: their internal
consistency is part of the restored archive, not of the capability fence.

Deleter admission checks the durable epoch first, then destructive policy, then
the remote-delete fence. A pre-restore epoch is `StaleDeleterFenced`; the new
epoch still is `StaleDeleterFenced` while `remote_delete_fenced` is true; and an
enabled maintenance worker or remote delete switch is
`DestructiveGcForbidden`. See
[`deleter_fence.rs`](../src/backup/w8a_paired/deleter_fence.rs).

## Blob and Git proof

The restorer opens the target Blob store, compares its backend identity with the
sidecar, and re-exports every archived `pack`/`idx` member into an isolated
`--compute-dir` through the sealed archive read. It then initializes a bare
repository with the recorded object format, writes the restored refs, sets
`HEAD`, and runs the stock Git command:

```
git --git-dir <compute>/<repo> fsck --full --strict
```

Every repository must pass. The receipt contains one entry per repository with
the object format, head ref/oid, ref count and artifact count. The compute
directory is removed after the sweep. A non-zero exit or any missing/corrupt
member is a hard failure.

## Refusal matrix

| Condition | Error |
| --- | --- |
| raft cursor/operation row at backup | `RaftCutForbiddenInSingleNodeW8a` |
| `ROOTYARD_PAIRED_RAFT_CLUSTER_JSON` set | `RaftCutForbiddenInSingleNodeW8a` |
| `paired-manifest.json` present | `RaftCutForbiddenInSingleNodeW8a` |
| non-`pg_refstore` or mixed backend | `UnsupportedRepositoryBackend` |
| changed keyring/canary/KMS reference | `KeyReferenceMismatch` |
| swapped metadata/manifest/complete or unexpected members | `MixedPointInTime` |
| missing, corrupt or mismatched Blob member | `MissingOrCorruptBlobArtifact` |
| stale or undeletable-while-fenced deleter | `StaleDeleterFenced` |
| destructive GC enabled | `DestructiveGcForbidden` |
| stock Git fsck failure | `GitFsckFailed` |

All errors carry bounded, non-secret diagnostic text. `check` never opens a
database and never creates a target directory.

## Verification and evidence

The integration drill in
[`w8a_pg_blob_paired_restore.rs`](../tests/w8a_pg_blob_paired_restore.rs)
uses PostgreSQL 17, a process-local S3 loopback, real `pg_dump`/`pg_restore`,
real Git, both SHA-1 and SHA-256 repositories, and the production provisioning,
pack-plan, snapshot, root, authentication and event paths. It asserts the
negative matrix above and the post-restore credential/CI/workspace/pin/outbox
state.

The offline contract test
[`test_w8a_pg_blob_paired_contracts.py`](../tests/test_w8a_pg_blob_paired_contracts.py)
checks the allowed file set, line limits, LF endings, absence of broad
`#[allow(...)]`, the documented domains and sidecar keys, and the workflow pins.
It does not run Cargo or install anything.

CI runs the same contract test plus formatting, Clippy, unit tests and the live
drill in
[`w8a-pg-blob-restore.yml`](../.github/workflows/w8a-pg-blob-restore.yml), and
uploads `test-results/w8a-pg-blob-restore/test.log` as evidence.
