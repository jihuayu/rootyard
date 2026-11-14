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
validates metadata, identity, the final entry and optionally SQLite
`quick_check`; it does not scan every historical entry. Unknown formats,
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

Twenty-one unit tests cover restart, exact purge identity, replay, committed
rewrite refusal, holes, truncation, snapshot-style purge, bounds, identity/lock
refusal, and malformed or valid-JSON corruption. They delete rows directly in
SQLite (after a passing `quick_check`) and reopen: an internal row, index 0 with
several holes, the row after the purge boundary, and a prefix-to-tail deletion
with its documented limit. Limited reads are covered when the lost head or
middle index is followed by enough rows to fill the count budget (fcb22c5
returned them), and when a byte budget stops below the count budget (fcb22c5
called that valid prefix a hole); a full read over either budget still refuses.
Boundary tests pin empty, totally purged, first-live, past-the-end and budget-cap
reads. Purge-residue tests pin a boundary row carrying the boundary's own LogId
(served from its successor) and rows at or below the boundary with another
`LogId`, which fail `open` (fcb22c5 reported them as the tail). One regression
hides invalid residue below the boundary and at it beneath a valid live tail:
8a8ceb9's max-only check, graded through its own helper, accepts it, while open,
state and reads here refuse it and the matching boundary row stays supported.
The four regressions for the fcb22c5 defects grade fcb22c5 through its own reader
helpers and fail on it; the own-`LogId` leftover test passes there through the
purge pin that shortens whole-range starts, and the grading probes inside it show
that. Tests exercise the same durable helpers as the trait implementations.

Two integration tests use owned child processes. The vote test calls the public
vote trait in a child, waits for a persisted-vote acknowledgement, sends SIGKILL,
and verifies that a fresh process reads the identical vote. The log test calls
openraft's public `RaftLogStorageExt::blocking_append`, the public path that
constructs `LogFlushed`, invokes `RaftLogStorage::append`, and waits for that
callback; `LogFlushed::new` itself is private in pinned openraft 0.9.26. The
child writes exact native entries and log IDs, saves exact committed metadata,
reads both back, and only then prints `ACK`. Thus the parent's SIGKILL cannot
run on a merely queued append, and a storage `append` that returns without
completing its callback cannot yield the ACK: the extension either waits for
the callback or reports the dropped sender as an error, and the startup
deadline bounds either outcome. After the acknowledgement the parent sends
SIGKILL to its own writer and reaps it under a deadline. A fresh process opens
the store and reads
the exact contiguous entries, log IDs, committed metadata and checksum-verified
rows; the parent then re-reads `log_entry` and `meta` directly to pin the stored
SHA-256 values. Startup, output, wait, kill and reap are bounded, and `Drop`
kills and reaps an owned child on every failure path.

The log fixture is a fresh local temporary directory. On Linux the test reads
`/proc/self/mountinfo`, records the mount device and filesystem type, fails on
known network filesystem types, and requires the database file to stay on the
fixture's device; other Unix hosts report that the mount check is unavailable.
The test uses at most one writer and one reader child, never concurrently, with
no socket, loopback server, peer process or state machine. It sends SIGKILL only
to its own writer after the callback-backed acknowledgement and waits for the
reader to exit normally.

The dedicated workflow runs these checks independently of Rootyard's Cargo
workspace. The SIGKILL tests establish only vote and acknowledged-log
persistence across a process crash on the tested local filesystem. They do not
establish power-loss durability, quorum or peer acknowledgements, Git
acknowledgements, three-host behavior, state-machine/snapshot atomicity, or
whole-#149 completion. Past-tail empty reads starting at `last_log_id.index + 1`
remain valid: range ends are exclusive.

## Remaining scope

State machine storage, snapshots, RPC, TLS, ReadIndex, complete openraft suite,
Ref-CAS integration and multi-host qualification remain unimplemented. This
slice does not complete issues #149 or #115 and has no production routing.

A separate follow-up must decide whether to fail closed on a non-dense retained
log during `open` and whether a fresh unpurged store must start at index 0: a
middle-row delete can currently pass `open` and fail a later read, and the
pinned OpenRaft storage contract and existing tests must be checked before
changing first-index behavior. This checkpoint does not combine that contiguity
change.
