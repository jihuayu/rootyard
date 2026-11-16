# Experimental Ref-CAS Raft log storage

This isolated crate implements openraft **0.9.26** `RaftLogStorage` and
`RaftLogReader` using SQLite. It is not wired into Rootyard. The root Cargo
workspace and production service are unchanged. Native entries use `u64` node
identities, `Vec<u8>` application data and `BasicNode` membership.

## Storage and contract

`log.sqlite3` uses rollback journaling (`DELETE`), `synchronous=FULL` and
serialized `BEGIN IMMEDIATE` transactions. `.raftlog.lock` excludes a second
opener for the store lifetime. Blocking SQLite work runs on Tokio's blocking
pool, with the shared connection locked inside each blocking task.

The on-disk marker is `rootyard-refcas-log/3`. `meta` stores the format, node
identity, vote, optional committed log ID and optional exact native purged log
ID. `log_entry` stores the index and JSON for the native log ID and entry.
Both tables store SHA-256 checksums over length-prefixed fields with separate
metadata and entry domains. Reads verify checksums before decoding. Opening
validates metadata, identity, the final entry, retained-index density from the
correct lower bound through the tail, and, when not validly covered by the purge
boundary, the exact row named by the committed log ID; it does not decode every
historical entry. SQLite `quick_check` remains optional. Unknown formats,
corruption and identity mismatch cause errors without resetting the database.

Mutations commit before returning. `append` reports `LogFlushed` success only
after COMMIT. If storage returns an error, callers must treat persistence as
unknown; an error is not an acknowledgement. Vote changes only through
`save_vote`, never through append.

Append rejects holes and revival of purged entries. Committed entries accept
only identical replay. Conflicting uncommitted entries replace their suffix
atomically. Truncate refuses committed indexes. Purge preserves the caller's
complete native log ID and can advance beyond the local tail for snapshot
installation; an empty log retains that boundary. The Raft engine owns vote,
commit and membership protocol decisions.

Each batch or read is bounded to 4,096 entries and 8 MiB encoded data; each
encoded entry is limited to 1 MiB. Input collection and JSON encoding enforce
these bounds before unbounded allocation. Full reads fail when a range exceeds
the budget; limited reads return a bounded nonempty prefix when entries exist.
Index zero is valid, empty ranges stay empty, and SQLite index overflow fails.
Complete reads reject missing entries throughout the requested range's
intersection with the persisted live bounds. Limited reads validate only the
returned prefix (the first live requested index and contiguous entries) and may
stop at their count or byte budget; they do not inspect the remaining suffix, so
a gap after the budget is not diagnosed by that call.

Reads fail closed on a genuine hole. Append, truncate and purge each commit in
one transaction and never leave a hole, so the stored log is exactly
`(last_purged_log_id, last_log_id]`, and openraft allows a missing entry to be
returned as a short read. The reader derives `known = stored max + 1`; with the
pinned purge boundary `purged + 1`, every requested index in
`[max(asked, purged + 1), min(known, asked end))` must be stored. Whatever is
returned, a limited read stopped by its count or byte budget included, must start
at that first index and be gap-free; only a complete read must also reach the end.
Violations fail as "log entry N is missing although it is stored". A deleted row
can raise `known`, so it is still caught. Ranges past the end, wholly purged
ranges, empty ranges and missing rows at or below the boundary keep valid short
reads. SQLite `quick_check` cannot see a lost row; this check is what catches
one. Without a persisted end (after deletes from a prefix back to the tail) no
evidence of a hole remains, and the reduced log is reported, as openraft permits.

Without a purge boundary, a nonempty request wholly below the smallest stored
row asks for no live index and returns empty, matching openraft's allowed short
read. If it starts below that row and overlaps retained rows, it is refused as an
unavailable prefix instead of silently starting at the first stored row. That
refusal does not claim the prefix was ever stored, so it neither invents an
index-zero invariant nor turns a legal positive-first slice into a loss claim.

`open` also runs the density check before returning a handle. With a persisted
purge boundary, the required live lower bound is the boundary's successor; the
exact boundary row is allowed residue but is excluded from the live aggregate and
never substitutes for the successor. Without a boundary, the smallest stored row
is the only observable lower bound. The pinned 0.9.26 storage contract requires
consecutive entries and permits a missing entry in a read, but it does not make an
unpurged positive-first log an engine-supported shape: pinned
`engine/log_id_list.rs::load_log_ids` probes `get_log_id(0)` when
`last_purged_log_id` is `None`, and `storage/log_store_ext.rs`'s
`RaftLogReaderExt::get_log_entries` requires the requested first entry. This crate
therefore accepts and retains a dense positive-first slice at the storage layer
without inventing an index-zero invariant, while a read that starts below that
slice and overlaps it explicitly refuses the unavailable prefix. A positive-first
live slice with a persisted purge boundary is the normal supported shape, because
the boundary supplies the lower bound. On-disk compatibility is unchanged: the
format marker remains `rootyard-refcas-log/3`, a dense existing database opens
normally, and no migration is attempted.

The density proof is a primary-key aggregate (`count`, `min`, `max`) over the
required live range, with a first-gap index lookup only on mismatch. Memory is
O(1) and historical row payloads are not decoded, but a healthy open now pays an
O(N) covering-index scan instead of the previous O(log N) tail lookup. That
startup cost is the price of refusing a store with an internal missing row before
`get_log_state` or any range read can present it as healthy. `quick_check` remains
a separate optional O(N) check.

Opening also validates the optional committed log ID against the retained log.
A committed row may be absent when the purge boundary strictly covers it: a
boundary after `committed.index` is the legitimate snapshot-style ordering in
which persisted committed metadata lags an advancing purge boundary. At the
same index the boundary must name the exact committed `LogId`, because the index
alone does not identify a Raft entry. Otherwise the row at the committed index
must exist with the exact committed `LogId`, because only purge removes a
committed row, append never rewrites one, and truncate refuses through it. Thus
`committed Some + last None` with no purge boundary is known loss and is refused,
as are a committed index ahead of the retained tail, a committed row that is
missing or carries another `LogId`, and a same-index purge boundary that carries
another `LogId`. `save_committed(Some(c))` applies the same check before writing
and `append` validates the current state before extending, so a successful API
write cannot create the refused state; `save_committed(None)` stays allowed.
`purge` also validates the already persisted witness and refuses a
caller-supplied boundary that disagrees with the committed ID, a retained row,
or the persisted boundary at the same index, before deleting rows or writing
metadata. Deleting every `log_entry` row while retaining committed metadata is
the regression that must fail `open`. Refusal is not a reset, migration, or a
zero-loss claim: the database is left unchanged.

The startup check cannot prove absence of loss without an independent witness.
Deleting the entire log together with its committed metadata leaves a valid empty
store. Deleting a fresh prefix can move the only observable lower bound up; if
the persisted committed row itself is lost the guard refuses, but a prefix below a
surviving committed row is indistinguishable from a legal positive-first start
without an independent lower bound. Deleting an uncommitted suffix moves the
tail down; and deleting a span together with every later row can leave a shorter
dense log. The persisted purge boundary, surviving rows and optional committed
log ID are the inputs used here. The committed ID is not a live lower bound
because purge may legally advance beyond it, but it is a witness for its own row
when no boundary covers that row. Detecting the remaining cases needs an
independent expected bound, such as durable state-machine/snapshot progress or
out-of-band replica evidence. Read-time checks remain in place as defense in
depth and can still fail when a request's known lower bound intersects a lost
row, but they do not repair or infer a missing witness.

This checkpoint therefore establishes bounded startup refusal for internal holes,
purge-successor gaps, and committed rows that no retained row or valid covering
purge boundary can satisfy, not a whole-log physical-loss guarantee. A boundary
strictly after the commit remains valid lag; one at the same index is valid only
with the full committed `LogId`. A nontrivial independent witness would need its
own format/API checkpoint; none is added here.

`purge` is inclusive and writes its `meta` boundary in the same transaction that
deletes rows, so the only row a purge can leave at the boundary index is one
carrying the boundary's own `LogId` (an entry whose commit was lost). That row is
never live: it is not reported as the tail and not returned by reads, which start
at the boundary's successor. A row below the boundary, or a row at it with any
other `LogId`, cannot come from this store. This rule covers the whole database,
not only its highest row: open and every read path (state and ranges) run one
bounded indexed lookup per purged level, so residue hidden beneath a valid live
tail still makes them fail closed.

Rename, truncate or purge commit before the crates.io 0.9.26 reader checks, so
this crate allows those errors for a committed log at exactly
`last_log_id.index + 1` (a narrow, crash-consistent outer bound), accepts valid
entries there, and never persists such a row.

## Verification

From the repository root, using the pinned toolchain:

```sh
cargo fmt --manifest-path crates/refcas-log/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path crates/refcas-log/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path crates/refcas-log/Cargo.toml --all-targets
```

Thirty unit tests in `src/lib.rs` cover restart, exact purge identity,
replay, committed rewrite refusal, holes, truncation, snapshot-style purge,
bounds, identity/lock refusal, and malformed or valid-JSON corruption. Startup
contiguity regressions delete a middle live row in a still-valid SQLite database,
verify that later rows remain, and require a fresh `open` to refuse before
`get_log_state` or a range read; a purge-successor gap is refused even when the
allowed exact boundary row is present, while a dense suffix above that residue
still opens. A positive-first-index dense store is accepted at the storage layer
without an index-zero assumption; a wholly-below-first request is an empty short
read, an overlapping request from below is refused as an unavailable prefix, and
the pinned `get_log_id(0)` startup probe fails rather than pretending index 0
exists. The committed-loss regression saves committed metadata, deletes every
`log_entry` row through a database whose `quick_check` still passes, verifies
that the commit and absence of a purge boundary remain, and requires both checked
and unchecked `open` to refuse without changing the database; a retained handle
also refuses to append over that state. A second regression deletes only the
committed row and leaves a later suffix; open still refuses instead of treating
the survivor as a legal positive-first start. Write/order tests require
`save_committed` to reject a commit ahead of the tail or with no row/boundary,
accept a commit covered by a purge boundary, and leave a purge-covered empty log
reopenable. Equal-index identity regressions save a committed ID, reject a purge
whose same-index boundary carries another leader, and verify the raw rows and
metadata are unchanged; they also reject the symmetric retained-row and
persisted-boundary conflicts, and require `open` to refuse a checksum-valid
same-index committed/purge mismatch from either side. A greater-index snapshot
purge over an older committed witness remains accepted with the witness intact
across reopen. The older hole tests now delete rows behind a retained handle so the
read-time defense-in-depth checks still run, then require the corresponding fresh
open to refuse; the fresh-prefix-to-tail deletion remains a successful open when
no committed witness falls inside the lost prefix, and is explicitly documented
as the no-witness limit. Limited reads are covered when the lost head or middle
index is followed by enough rows to fill the count budget (fcb22c5 returned
them), and when a byte budget stops below the count budget (fcb22c5 called that
valid prefix a hole); a full read over either budget still refuses. Boundary
tests pin empty, totally purged, first-live, past-the-end and budget-cap reads.
Purge-residue tests pin a boundary row carrying the boundary's own LogId
(served from its successor) and rows at or below the boundary with another
`LogId`, which fail `open` (fcb22c5 reported them as the tail). One regression
hides invalid residue below the boundary and at it beneath a valid live tail:
8a8ceb9's max-only check, graded through its
own helper, accepts it, while open, state and reads here refuse it and the
matching boundary row stays supported. The four regressions for the fcb22c5
defects grade fcb22c5 through its own reader helpers and fail on it; the
own-`LogId` leftover test passes there through the purge pin that shortens
whole-range starts, and the grading probes inside it show that. Tests exercise
the same durable helpers as the trait implementations.

Two integration tests in `tests/` use owned child processes. The vote test calls
the public vote trait in a child, waits for a persisted-vote acknowledgement,
sends SIGKILL, and verifies that a fresh process reads the identical vote. The
log test calls openraft's public `RaftLogStorageExt::blocking_append`, the
public path that constructs `LogFlushed`, invokes `RaftLogStorage::append`, and
waits for that callback; `LogFlushed::new` itself is private in pinned openraft
0.9.26. The child writes exact native entries and log IDs, saves exact committed
metadata, reads both back, and only then prints `ACK`. Thus the parent's SIGKILL
cannot run on a merely queued append, and a storage `append` that returns without
completing its callback cannot yield the ACK: the extension either waits for
the callback or reports the dropped sender as an error, and the startup
deadline bounds either outcome. After the acknowledgement the parent sends
SIGKILL to its own writer and reaps it under a deadline. A fresh process opens
the store and reads the exact contiguous entries, log IDs, committed metadata
and checksum-verified rows; the parent then re-reads `log_entry` and `meta`
directly to pin the stored SHA-256 values. Startup, output, wait, kill and reap
are bounded. The success path consumes the owned handle through `finish`, which
kills when requested and returns only after `try_wait` confirms reaping. On a
panic path `Drop` makes one bounded kill-and-poll attempt; if the child has not
been reaped when that deadline expires, `Drop` reports that reaping remains
unconfirmed instead of counting cleanup as successful.

The log fixture is a fresh temporary directory. On Linux the test reads
`/proc/self/mountinfo`, records the longest matching mount point's device and
filesystem type, rejects an explicit denylist of known network filesystem types
(including `fuse.glusterfs` and other named remote FUSE types), and additionally
refuses every FUSE mount because its backing store is not qualified. It also
requires the database file and fixture directory to report the same `st_dev`.
This is a negative denylist, not positive proof that the backing device is local
or directly attached: an unlisted non-FUSE remote type can still pass. Non-Linux
hosts perform no filesystem qualification and only bind the fixture to the
canonical temp path. The test uses at most one writer and one reader child,
never concurrently, with no socket, loopback server, peer process or state
machine. It sends SIGKILL only to its own writer after the callback-backed
acknowledgement and waits for the reader to exit normally.

The dedicated workflow runs these checks independently of Rootyard's Cargo
workspace. The SIGKILL tests establish only vote and acknowledged-log
persistence across a process crash on the Linux fixture whose mount type passed
the network denylist; on other Unix hosts they establish vote and
acknowledged-log persistence across a process crash with no filesystem
qualification. They do not establish power-loss or hardware-failure durability,
quorum or peer acknowledgements, Git acknowledgements, three-host behavior,
state-machine/snapshot atomicity, or whole-#149 completion. Past-tail empty
reads starting at `last_log_id.index + 1` remain valid: range ends are
exclusive.

## State machine, snapshots, and multi-process fault injection

`state_machine` adds `PersistentStateMachine` and `PersistentSnapshotBuilder` implementing openraft **0.9.26** `RaftStateMachine<LogTypeConfig>` and `RaftSnapshotBuilder<LogTypeConfig>`. It uses a dedicated lock `.raftsm.lock`, SQLite database `sm.sqlite3` (`rootyard-refcas-sm/1`, `DELETE` journal, `synchronous=FULL`, `BEGIN IMMEDIATE`, SHA-256 checksums over `meta`, `sm_entries`, and `sm_kv`), and serialized `snapshots/snap-*.snap` payloads (`rootyard-refcas-snapshot/1`) cross-checked on every `open`.

- **Serialization and idempotency**: An async `op_gate` mutex serializes `applied_state`, `apply` (including membership changes), `build_snapshot`, `install_snapshot`, and `get_current_snapshot`. Replaying an already-applied entry, snapshot boundary, or identical snapshot metadata/checksum is an idempotent no-op; conflicting replays or regressive snapshots fail closed.
- **Atomic snapshot install, pre-commit rollback, and post-commit uncertainty**: `install_snapshot` validates JSON/unknown fields, embedded canonical `payload_sha256_hex`, and `SnapshotMeta`, writes a staged `pending-install-*.snap` file, `fsync`s it, renames it to a new generation filename while keeping the previous snapshot intact, and updates `sm_kv`/`sm_entries`/`meta` in one `BEGIN IMMEDIATE` transaction.
  - **Pre-commit failures** (`ENOSPC`, staging `fsync` errors, `SQLITE_FULL`, payload/meta mismatches, `SnapshotInstallCommitSync` failures, or crashes before SQLite `COMMIT`): SQLite rolls back the transaction and `StagingCleanupGuard` deletes the uncommitted candidate/staged snapshot without disturbing prior state, membership, or the previous active snapshot.
  - **Commit and post-commit uncertain errors** (errors returned by SQLite `tx.commit()` after reaching the commit point, or post-commit `SnapshotInstallPostCommitSync` / cleanup errors): SQLite metadata may already reference the new active snapshot. Therefore `commit_staged_snapshot` disarms unconditional candidate deletion before `tx.commit()`, only unlinks the candidate file if committed SQLite metadata proves another snapshot remains active, and otherwise **preserves the durable file and does not promise rollback**; callers must reopen or re-read durable metadata (`get_current_snapshot`) to observe whether the new snapshot became active.
- **Fixture qualification and fault hooks**: `fixture::qualify_store_dir` checks directory writability/`fsync`, available space (`DEFAULT_MIN_FREE_BYTES`), same backing `st_dev`, and on Linux rejects network filesystems and FUSE mounts from `/proc/self/mountinfo` before tests and `raft-node` start. `fault::FaultController` injects deterministic `ENOSPC`, `fsync` EIO, and mid-install pause barriers.
- **mTLS transport and identity binding (`src/mtls.rs`, `src/cluster.rs`, `src/bin/raft-node.rs`)**: `raft-node` requires `--tls-ca`, `--tls-cert`, and `--tls-key` at startup (verifying its own leaf certificate SAN matches `raft-node-{id}.refcas.internal`) and runs strict mutual TLS 1.3 via `rustls`/`tokio-rustls`/`ring`. Both server and peer/control clients validate peer chains against the cluster CA and bind RPC authorization to verified leaf SAN identities (`PeerIdentity::Node(id)` only accepts consensus RPCs whose `vote.leader_id.node_id == id`; `PeerIdentity::Client` is restricted to control/client RPCs and synthetic vote fault tests). Plaintext TCP, anonymous TLS clients, wrong-CA certs, mismatched SAN hostnames, and unrecognized SANs fail closed before frame dispatch.
- **Linearizable `ReadIndex` quorum barriers and minority refusal**: `RpcRequest::KvGet` and `RpcRequest::EnsureReadIndex` execute openraft's `ensure_linearizable()` quorum heartbeat barrier and wait for local state-machine application (`last_applied >= read_log_id`). Followers return `ForwardToLeader`; isolated/partitioned minority nodes fail closed on both writes (`ClientWrite` bounded write timeout, no PostgreSQL or Redis fallback) and `ReadIndex` reads (`QuorumNotEnough`). `ClientWrite` also enforces metadata bounds (`MAX_ENTRY_BYTES` / `MAX_KV_VAL_BYTES`) before appending to the Raft log so large blob bytes never enter the Raft WAL; regular Blob API (`opendal`) is not used as WAL, and root standalone binaries do not link this crate.
- **Tenant-scoped mTLS RPC, `LeaderRedirect`, and bounded streaming (`src/mtls/tenant_san.rs`, `src/tenant_rpc.rs`, `src/streaming.rs`)**:
  - **X.509 SAN & bearer token binding**: `MtlsServer::accept_tenant` verifies client certs combining `raft-client-tenant-<tenant_uuid>.raft.internal` DNS SAN with narrow `urn:rootyard:refcas:tenant:<uuid>:group:<group_id>:scope:<caps>` URI SAN, failing closed on cluster node certs (`raft-node-{id}.refcas.internal`), unscoped client certs (`raft-client.refcas.internal`), mixed-role SANs, cross-tenant reuse, and wide/unscoped bearer tokens (`ryt1;...` validation).
  - **Follower `ReadIndex`, structured `LeaderRedirect`, and realm epoch fences**: Tenant endpoints execute bounded `ensure_linearizable()` quorum barriers, emit `LeaderRedirect { leader_id, leader_addr, raft_term }` on followers (separating `raft_term` from business `storage_generation`), and fail closed on stale/mismatched `authority_id`, `history_id`, `group_epoch`, `storage_generation`, wrong `group_id`, closed tenants, or partitioned minorities.
  - **Bounded streaming & Raft large-byte fence**: `StreamCompute` uses a bounded Tokio `mpsc` channel (`<= 16` slots), per-frame/total byte caps (`<= 64 KiB` / `<= 4 MiB`), credit-window flow control, and deadlines so slow consumers trigger early producer cancellation and RAII `TrackedChunk` drops free buffered memory to `0`; Raft proposals reject payloads `> 256 KiB` or raw Git `PACK`/LFS payloads before WAL append.
- **Conventions and test coverage**:
  - `tests/raft_suite.rs` verifies all 31 compatible `openraft::testing::Suite` conformance cases (including `last_applied_state` and `transfer_snapshot`), explicitly asserts that the remaining 4 `Suite` cases (`last_membership_in_log`, `last_membership_in_log_multi_step`, `get_membership_from_log_and_empty_sm`, `get_initial_state_membership_from_log_and_sm`) trigger `PersistentLog`'s fail-closed `unavailable prefix` and `revive a purged prefix` refusal guards rather than silently weakening those boundaries, and tests `install_snapshot` vs concurrent `apply(Membership)` serialization, rollback on `ENOSPC`/`fsync`/`SQLITE_FULL`/corruption, and idempotent vs conflicting replay checks.
  - `tests/raft_fault_injection.rs` runs real 3-process mTLS clusters covering `kill -9` (`SIGKILL`) on follower and leader, injected `fsync` failure, injected `ENOSPC` with snapshot catch-up, corruption refusal on `log.sqlite3`/`sm.sqlite3`/`snap-*.snap`, persisted vote non-double-voting across `kill -9`, and live membership change across crash recovery.
  - `tests/raft_mtls_readindex.rs` tests mTLS refusal invariants (missing flags, mismatched node SAN, plaintext, wrong CA, wrong SAN, forged leader/peer RPC, client-vs-node role separation), `ReadIndex` quorum barriers across followers/leaders/partitions, minority write/read refusal with zero PG/Redis fallback, bounded WAL payload refusal, 3-voter -> 4-voter learner promote -> 3-voter reconfigure + `SIGKILL`/restart durability, and static Cargo isolation from `opendal`/`sqlx`/`redis`/root `Cargo.toml`.
  - `tests/tenant_mtls_rpc.rs` runs live 3-node mTLS Raft clusters verifying tenant X.509 SAN binding, wide/unscoped bearer token refusal, follower `ReadIndex` + `LeaderRedirect`, `raft_term` vs `storage_generation` isolation, stale `authority_id`/`history_id`/`group_epoch` & closed-tenant fail-closed refusal, bounded streaming backpressure/cancellation memory drop, and pre-WAL large Git/Blob payload rejection.

## Remaining scope

Online Rootyard gateway wiring (`src/ref_store` RPC adapter / `src/sharding` / `src/git_http/process.rs`), PostgreSQL event projection (`#117`), and multi-host physical power-loss qualification remain outside this standalone crate; Issues `#149`, `#115`, and `#150` stay open until service wiring and target acceptance complete. Database corruption still fails closed rather than repairing or migrating corrupt state.
