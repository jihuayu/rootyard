# Pando lab: PG refs and immutable local packs

**Experimental phase-three slice, not a production backend or completed migration.**
This opt-in Rust executable does not import the serving `Storage` implementation,
change GitFS routes, migrate an existing repository, or select a new authority.
The ordinary Rootyard binary and its migration runner do not load this schema.

## What is implemented

- Real native Git Smart HTTP receive-pack/upload-pack behind a loopback gateway.
- PostgreSQL authoritative refs, object locators, generation, operation result and
  change record, committed together in one transaction.
- Native `proc-receive` adapts writes. Every HTTP request creates a disposable
  bare repository. No persistent bare repository is authoritative.
- Self-contained immutable `.pack` and `.idx` files in a separate local store.
  Each successful push currently writes the **entire reachable closure of its
  new tips**, rather than a compact incremental storage representation.
- Old-OID CAS, atomic multi-ref publication, final ref directory/file validation,
  commit-time repository ACL validation, and storage-generation fencing.
- PG-persisted five-minute read snapshots spanning advertisement and subsequent
  HTTP requests, bound to repository and synthetic principal. Every request
  rechecks current repository access.
- Cold reconstruction, four hook-exit failure points, and deterministic writer
  barriers for tests. Missing/corrupt committed pack bytes fail closed.

## Run only with synthetic data

Prerequisites: Linux, Rust stable, native Git 2.43 or newer, and
PostgreSQL server/client binaries on PATH. The recorded run uses Git 2.56.0 and
PostgreSQL 17.11. No new Rust dependency is added.

```sh
cargo build --locked --features pando-lab --bin rootyard-pando-lab
# Creates its own temporary cluster, database, object store, clients, and server.
# Never uses an inherited production DATABASE_URL. Run as a non-root user.
./scripts/test-pando-lab.sh
```

If PostgreSQL is unpacked rather than installed, set `PG_SHARE` to its matching
share directory; set PATH and LD_LIBRARY_PATH for that installation. The runner
also accepts `ROOTYARD_TOOLS_ENV`, `ROOTYARD_GIT_ENV`, `PANDO_BINARY`, and
`PANDO_SKIP_BUILD=1` for an already-built binary. It always stops its owned PG
cluster in `finally`, and prints the retained evidence directory.

Manual synthetic API example, using an **already-created disposable** database
and an existing disposable directory:

```sh
export PANDO_SYNTHETIC_ONLY=1
export PANDO_DATABASE_URL=postgresql://lab@127.0.0.1:55459/pando_lab
export PANDO_ROOT=/tmp/my-disposable-pando-store
export PANDO_GIT=/absolute/path/to/git
export PANDO_LISTEN=127.0.0.1:0
mkdir -p "$PANDO_ROOT"
BIN=target/debug/rootyard-pando-lab
"$BIN" init
"$BIN" create-repo 11111111-1111-4111-8111-111111111111 alice
"$BIN" serve  # Prints LISTEN http://127.0.0.1:<allocated-port>
git -c 'http.extraHeader=X-Pando-Principal: alice' clone \
  http://127.0.0.1:<allocated-port>/repos/11111111-1111-4111-8111-111111111111.git
```

`X-Pando-Principal` is a **spoofable synthetic test identity, not authentication**.
The executable refuses non-loopback listen addresses, non-literal-loopback
database hosts, and non-loopback `hostaddr` overrides, and requires the explicit
synthetic-only gate. These checks do
not make it safe to point at a production database reachable on localhost.
Do not expose this server through a proxy or use real repositories/secrets.

## Correctness contract and linearization points

### Receive and publish

1. Capture current PG refs and committed pack identities in REPEATABLE READ.
   Reconstruct the authorized repository view, enabling native receive fsck and
   routing all supported refs through proc-receive.
2. Native receive-pack ingests the client's pack. A `pre-receive` hook persists
   the **complete** old/new/name command group for this operation. Native Git can
   omit failed commands from `proc-receive`, even for an atomic push. The proc
   hook must match the saved complete group exactly; it refuses a filtered subset
   before object publication. Without this check, PG could commit only the valid
   half of an atomic push while native Git rejects another command.
   The hook separately validates
   supported namespaces, branch target types, fast-forward policy, full strict
   fsck and reachable object closure. Only SHA-1 is supported here.
3. Generate a non-thin, self-contained pack and index. Create files with
   `create_new` at `objects/<repository>/<operation UUID>.{pack,idx}`. UUIDs are
   never reused. Write, fsync each file, read back, and sync the object directory
   before any committed locator or ref can reference those bytes.
4. Begin the final PG transaction. Lock the repository row; compare storage
   generation; lock/check the principal's write ACL; compare **all** old OIDs
   against current authoritative refs; validate the final set of names.
5. Insert immutable manifests and object locators; update all refs; increment
   generation; insert one change record; store the COMMITTED operation result.
   COMMIT is the publication linearization point. The connection explicitly uses
   synchronous_commit=on. Any earlier failure leaves no published ref mutation.
6. Only after successful COMMIT does proc-receive report success. Exiting after
   COMMIT can still cause the Git client to report failure. PG remains the outcome
   authority and the next clone sees committed state.

Same-repository final publications are conservatively serialized, including
independent refs. This is a correctness baseline, **not the later parallel-ref
performance design**. A non-atomic push is also handled as an atomic hook batch;
the prototype deliberately offers stricter all-or-nothing behavior.

`changes` is a durable transactional change log. This slice has no delivery
worker, replay consumer, cache invalidation fanout, or end-to-end outbox delivery
claim. It is independent of the existing GitFS outbox tables.

### Read isolation

The first upload-pack advertisement redirects the standard client to a random
snapshot URL. Snapshot refs, generation and immutable pack identities are stored
in PG, not process memory. Subsequent advertisement/ls-refs/fetch requests check
the same snapshot ID, repository, principal, expiry, and current ACL.

Cold reconstruction first checks all captured pack/index digests. It then builds
a **second** repository containing only the closure reachable from snapshot refs.
That second repository is the only one exposed to upload-pack. Historical
unreachable objects and other repositories' objects are not merely hidden behind
unadvertised refs; they are absent from the serving object database. A live old
snapshot intentionally retains its original reachable objects until expiry.

No committed object is deleted in this slice. Snapshot retention therefore does
not prove a GC pin/lease implementation. Every snapshot currently lists all of
the repository's historical committed packs, so a missing obsolete pack can
conservatively fail an otherwise possible read. This favors fail-closed behavior
over availability and is not an efficient read plan.

### Failure and recovery meaning

`PANDO_ROOT/control.json` is a local test-only control, never an HTTP parameter:

```json
{"fault":"before-objects"}
```

Other fault values are `after-objects`, `before-commit`, `after-commit`, and
`corrupt-read`. A `barrier` absolute directory writes `<operation>.ready` after
pack persistence and waits for a `release` file before final CAS.

- Before objects, after objects, and before COMMIT: hook process exits, client
  fails, authoritative refs/locators/generation/change log remain unchanged.
  Durable unreferenced files may remain and are **not** automatically reclaimed.
- After COMMIT: client may fail although refs and objects are committed. The
  ordinary retry in the test becomes a Git no-op because remote refs already
  match. **This is not idempotent operation replay.**
- A fresh gateway process reconstructs both new reads and persisted old snapshots
  after its entire sessions cache is deleted.

Each receive POST gets a new server-generated operation UUID in the
`X-Pando-Operation` response header. There is no client-supplied idempotency key,
operation-replay protocol, or operation-status HTTP API. An interrupted client may
not receive that header. Operators can inspect `pando_lab.operations` and
`pando_lab.changes`; nonterminal rows remain evidence of uncertain/interrupted
attempts, not automatically declared failures. Do not infer idempotent retry
guarantees from the earlier standalone research prototype.

## Acceptance evidence

`evidence/results.json` records the latest actual run. The harness retains exact
Git commands, stdout/stderr, packet traces, CGI replies, generated thin pack,
server logs and PostgreSQL logs in its printed run directory. Tests check:

- Native v0/v2 clone and fetch with packet-level v2 negotiation proof, exact OIDs,
  strict fsck, annotated tags and deletions.
- Atomic success, DB-constraint rejection rollback, D/F rejection, raw-protocol
  valid-plus-missing-OID/invalid-ref/outside-refs batches with no partial commit,
  and two
  overlapping atomic pushes: one commit, one CAS rejection, no losing extra ref.
- Four publication failure windows and stale storage-generation rejection.
- Repository permissions on advertisement and RPC, commit-time ACL revocation,
  same-repository principal binding and cross-repository snapshot binding/expiry,
  snapshot continuity across writes and a fresh process, and cold reconstruction.
- Foreign-repository and deleted-branch raw-OID requests rejected.
- An actual thin pack verified to require a missing delta base: accepted against
  its existing base, rejected in an empty authorized repo with no publication.
- Committed pack/index SHA-256 checks, corrupt bytes and missing-file rejection,
  followed by a restored clone/fsck.
- Configuration rejection before connection for non-loopback `hostaddr`, plus
  Rust tests for IPv4, IPv6, mixed address lists and valid loopback addresses.

## Not implemented or not verified

- GitFS-to-Pando migration, authority switch, drain/fence orchestration, reverse
  synchronization after target writes, or migration rollback. The storage epoch
  check is only a tested primitive, **not a completed migration workflow**.
- Real S3/R2/MinIO consistency/durability, multi-host deployment, PG replication,
  failover, network partitions, disk power loss, media failure, or PITR coordination.
- Object GC, orphan reclamation, snapshot cleanup/pins, pack compaction, incremental
  pack dependency planning, deduplicated cross-repo storage, or capacity benchmarks.
- Production authentication/TLS, branch-level authorization, LFS, SHA-256 repos,
  partial/shallow clone guarantees, push-options, arbitrary ref namespaces, force
  updates to branches, compressed HTTP request bodies, or full Git compatibility.
- Hardened cancellation of all descendant processes and decompressed object/disk
  quotas. HTTP and pack fixture limits are 32 MiB; stdout/stderr are incrementally
  bounded at 128 MiB/1 MiB, concurrency at eight, command deadline at 45 seconds.
  Those are lab limits, not a hostile-tenant resource-isolation certificate.
- Abrupt in-flight gateway/PG process termination. The current fault cases are
  explicit hook exits; restart testing is a clean idle gateway restart.

The existing GitFS backend remains the only default implementation. Do not merge
this prototype's tables or enable it automatically based on these tests.

## References

- [Native proc-receive contract](https://git-scm.com/docs/githooks#_proc_receive)
- [Git pack-objects](https://git-scm.com/docs/git-pack-objects)
- [PostgreSQL transaction isolation](https://www.postgresql.org/docs/17/transaction-iso.html)
- [PostgreSQL explicit locking](https://www.postgresql.org/docs/17/explicit-locking.html)
