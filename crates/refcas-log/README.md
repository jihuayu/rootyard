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
Both reader methods reject gaps between returned entries, while a purged prefix
or missing suffix remains a valid short read. This is not a full store scan and
does not identify a missing entry at a requested range boundary.

## Verification

From the repository root, using the pinned toolchain:

```sh
cargo fmt --manifest-path crates/refcas-log/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path crates/refcas-log/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path crates/refcas-log/Cargo.toml --all-targets
```

Nine unit tests cover restart, exact purge identity, replay, committed rewrite
refusal, holes, truncation, snapshot-style purge, bounds, identity/lock refusal,
and malformed or valid-JSON corruption. They exercise the same durable helpers
as the trait implementations. One integration test calls the public vote
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
