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

Reads fail closed on a genuine hole. Append, truncate and purge each commit in
one transaction and never leave a hole, so the stored log is exactly
`(last_purged_log_id, last_log_id]`, and openraft allows a missing entry to be
returned as a short read. The reader derives `known = stored max + 1`; with the
pinned purge boundary `purged + 1`, every requested index in
`[max(asked, purged + 1), min(known, asked end))` must be stored. A result that
is empty, starts past that first index, skips an index, or stops short of that
end fails as "log entry N is missing although it is stored"; a limited read may
instead stop at its own budget. A deleted row can raise `known`, so it is still
caught. Ranges past the end, ranges wholly purged (including the boundary index
itself), empty ranges and missing rows at or below the boundary keep valid short
reads. SQLite `quick_check` cannot see a lost row; this check is what catches
one. Without a persisted end (after deletes from a prefix back to the tail) no
evidence of a hole remains, and the reduced log is reported, as openraft permits.

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

Twelve unit tests cover restart, exact purge identity, replay, committed rewrite
refusal, holes, truncation, snapshot-style purge, bounds, identity/lock refusal,
and malformed or valid-JSON corruption. Three of them delete rows directly in
SQLite (after a passing `quick_check`) and reopen the store: an internal row, an
index-0 row with several holes, the row after the purge boundary, and a
prefix-to-tail deletion with its documented limit. They assert that the gap
fails closed through both readers while purged, past-the-end, empty, budget and
boundary reads keep valid short results. They exercise the same durable helpers
as the trait implementations, and all three fail against the previous reader. One integration test calls the public vote
trait in a child process, waits for a persisted-vote acknowledgement, sends
SIGKILL, and verifies that a fresh process reads the identical vote. Child
ownership and deadlines bound the probe.

The dedicated workflow runs these checks independently of Rootyard's Cargo
workspace. The SIGKILL test establishes only vote persistence across a process
crash on the tested filesystem. It does not establish power-loss durability,
quorum acknowledgements or Git acknowledgements.

## Remaining scope

State machine storage, snapshots, RPC, TLS, ReadIndex, complete openraft suite,
Ref-CAS integration and multi-host qualification remain unimplemented. This
slice does not complete issues #149 or #115 and has no production routing.
