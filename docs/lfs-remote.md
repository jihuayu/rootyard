# Remote Git LFS durability

When `ROOTYARD_OBJECT_STORE_ENDPOINT` is configured, a verified LFS upload is
streamed to the configured S3-compatible object store before its metadata is
marked `ready`. The acknowledgement contract is unchanged: the server hashes
the source, writes the immutable key, checks its size with HEAD, and reads the
object back through the same verification path before the `ready` transaction
commits. The key is scoped to the repository owner's namespace ID and the
SHA-256 digest. Clients receive service URLs, not object-store credentials or
pre-signed URLs. Removing a role or revoking a token blocks new downloads,
including on another node.

## Read-path verification and cache

A serving node verifies its local copy before download. Verification admits a
file only after opening it with `O_NOFOLLOW` and validating that it is a regular
single-link `0600` file whose size equals the promised size. The cache key is
the complete file identity, not just `(oid, size)`:

```
data_root / repository_id / oid / promised_size /
dev / ino / mtime seconds+nanoseconds / ctime seconds+nanoseconds / size / mode / nlink
```

An `O_NOFOLLOW` symlink swap is rejected at admission, and a same-length
in-place tamper, corruption, truncation, or inode replacement either fails
layout admission or changes the identity and forces a fresh SHA-256 pass that
fails closed. The cache is a bounded, time-limited metadata cache
(`MAX_CACHE_ENTRIES = 4,096`, `CACHE_TTL = 15 minutes`); it never makes a
missing, replaced, symlinked, or unreadable path acceptable. Verification and
the download body use one already-open descriptor, so a path cannot be swapped
between the digest check and the response stream. Concurrent cache-miss readers
of the same admitted identity share one digest pass; followers wait under their
own deadlines and never open the path again, so they cannot hash a different
inode or start a duplicate full-file pass. This coalescing is local-only and is
not cold hydration: an absent or inadmissible local file still takes the
explicit hydration path.

The process-wide eight-slot verification limiter
(`MAX_CONCURRENT_VERIFICATIONS = 8` in `src/lfs/verification_limiter.rs`) is
shared across both asynchronous HTTP Batch/verify/download entry points
(`verify_local` and `open_verified_file`) and synchronous `verify_path_blocking`
callers (CI checkout dependency scans, mirror preparation, paired backup LFS
inventory, and concurrent publication race fallback). Asynchronous callers wait
for a slot up to their request deadline before `tokio::task::spawn_blocking`, so
excess HTTP requests never occupy blocking-pool threads while queued, and then
move the owned permit into the blocking closure; synchronous callers wait on
the same eight-slot pool via deadline-bounded condition variable waits. Every
caller acquires its slot before registering in the singleflight table, so a
`FlightLeader` never waits for a second slot while singleflight followers hold
permits.

Warm verified reads are local-only: steady-state `Batch -> GET` waves achieve
`rchar / served_bytes == 1.0` with `0` remote object-store requests, while
cache-empty existing-local waves coalesce onto one digest pass across concurrent
readers (`tests/lfs_read_amplification.py`, `tests/lfs_process_metrics.py`).
Warm reads do not construct an object-store client, issue a remote HEAD/GET, or
perform a synchronous remote repair; an unreachable or misconfigured endpoint
cannot turn a verified local download into a 5xx (issue #71). A cold miss
(`local file absent, corrupt, truncated, replaced, or symlinked`) is explicit:
if the configured remote has no correct-size copy, batch download reports the
object as unavailable and a direct GET fails closed rather than streaming
partial or unverified bytes.

Cold hydration is coalesced: each remote-cold `Batch -> GET` wave issues
`1 HEAD + 1 GET` against the object store for a given
`(data_root, repository, tenant, oid, size)` key (maximum four hydrations in
flight, maximum eight concurrent verifications), followers wait with their own
request deadlines, and each reader then streams through its own
identity-validated descriptor. A cancelled HTTP request does not abort the
leader fetch into a partial publication: bytes are fetched into a unique
`.tmp-<uuid>` staging file, digest/size verified, permissioned and synced, then
renamed atomically. The staging guard only removes its own temporary path.

## Deferred repair

Because warm reads never probe the remote, a remote copy that is lost while
verified local bytes remain is **not** repaired silently on read. Local verified
bytes and the paired backup remain authoritative; reads continue to succeed.
The explicit supported repair workflow is a later LFS Batch **upload** request
for the same already-ready object (for example
`git lfs push --object-id origin <oid>`). That write-path request schedules a
bounded background republish (at most two concurrent repairs, deadline-bound,
failure logged as `rootyard: deferred LFS remote repair failed`), while the
batch response remains an idempotent dedup. No read path claims that a missing
remote object was repaired.

Without the endpoint, LFS remains on the local data volume and belongs in the
paired database/volume backup. With the endpoint, the remote store preserves
objects between backups. A current paired backup (manifest format 9, schema versions through 133)
inventories every ready LFS object and hydrates any missing local copy from the
remote store before it publishes the backup. Restore accepts manifest formats 4
through 9; frozen older archives are read against their own catalogs and need a
documented explicit opt-in (see [backup and restore](backup-restore.md) and
`src/backup/restore.rs`) rather than an unpublished legacy binary. The current
tested path is format 9 / schema 133. Restore verifies those bytes and can serve them without
an object-store endpoint. The remote store must remain available during backup
if any ready object's local copy is missing; retain completed paired backups
for recovery if the store is lost afterward.

The service currently exposes no LFS object-delete or garbage-collection API.
Aborted and duplicate uploads cannot delete bytes published by another
request. Ready remote objects must remain available while any Git ref may
reference them; operator cleanup requires reachability and backup-retention
checks before deleting a key.

`ROOTYARD_LFS_POINTER_VERIFY_BYTES` caps the aggregate ready-object bytes
verified for a ref update (512 MiB by default, 8 GiB maximum). Ref publication
fails closed when its verification budget or Git deadline is exhausted. The
same bounded inspection examines at most 20,000 newly reachable Git objects
and reads at most 4,096 small (≤ 1 KiB) blobs per ref update; a larger
new-object set is rejected fail-closed rather than partially inspected, so a
monorepo push above that bound must be split. This bound applies to
repositories without LFS content as well, because pointer candidates can only
be identified after reading blob bytes. Pointer blobs are normalized before validation: the official client's LF and
CRLF forms, leading Unicode whitespace including NBSP, the legacy
`https://hawser.github.com/spec/v1` header and the legacy
`http://git-media.io/v/2` header are recognized, and every distinct `(OID,
promised size)` pair is validated before the ref moves. Binary or non-UTF-8
blobs, and header/scheme shapes the official client itself rejects, are not valid
stock-client pointers and remain ordinary content. No LFS object-delete or
garbage-collection API exists, so accepted pointers cannot lose bytes to an LFS
GC.
