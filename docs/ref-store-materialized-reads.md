# Materialized registered-pack reads

This is an unserved library foundation for #105/#107, layered on migration143 snapshots and pins. It introduces no schema or serving route and does not change repository authority. The metadata-only `PackReadSnapshot` continues to report `complete_git_read_snapshot() == false`; only a successful `PgPackSnapshotMaterializer::read` returns a `MaterializedPackRead` that reports true.

Callers first obtain an atomic registered-membership snapshot and durable pin through `PgPackSnapshot::create`. They pass its snapshot/pin identity and expected generation to the materializer, together with the PostgreSQL pool, explicit Blob store, absolute trusted Git binary and caller deadline. Returned data includes the complete captured refs/HEAD, pack identities and full materialization digest. The owned result has no public constructor, Clone or serde factory and exposes verified local pack/index bytes without exposing its filesystem path or granting write/publish authority.

## Read ordering

The entire operation uses one effective monotonic deadline: the earlier of the caller deadline and entry plus30seconds. Both pool waits, SQL stages and transaction cleanup, Blob reads, independent SHA/length checks and native verification use that same budget.

1. T1 validates the complete captured metadata and live pin in a bounded short transaction. It requires successful bounded cleanup and releases every PostgreSQL client before Blob/native work.
2. The private common engine verifies the live Blob backend and every exact registered locator, SHA256 and length, then runs native Git pair/index, exact refs/HEAD, branch-type and connectivity checks for SHA1 or SHA256. It writes validated sorted packed-refs rather than a loose user-shaped directory tree (#139). The private native result carries the full T1 scope, pin/generation/expiry, snapshot and artifact binding digest.
3. T2 reacquires PostgreSQL under the same deadline, revalidates immutable metadata/registration ledgers and full binding, then checks generation/scope and a fresh database clock after all slow ledger reads. It constructs the sealed result while the pin lock remains held and returns only after successful bounded cleanup. That locked final check is the read linearization point. A mutation ordered later can finish before the caller receives its already-linearized local copy.

An older pinned revision may remain readable after a newer commit in the same current realm. Release, expiry, generation change, deletion or a realm/epoch transition before the final check refuses the result. The returned copied data is disposable; it creates no new durable lease or authority.

## Resource ownership

A4 and materialization share one process-wide native verification admission bound of2. A separate process-wide materialized-view budget of2 is acquired first and remains owned through each returned view lifetime. Native admission returns after every child is confirmed quiescent, so retained idle read views do not occupy A4 native capacity. Each workspace is conservatively checked against a160MiB aggregate logical bound around mutating native operations.

The actual Blob transfer, independent read-back and local artifact-read tasks retain workspace ownership even if their waiter times out or is cancelled. Blob task-entry ownership shares its reader/staging lease and opaque workspace keepalive with staging cleanup; only confirmed unlink success or absence permits normal release. Runtime abort/panic or unknown cleanup outcomes conservatively quarantine resources until process exit. These bounds are process-local; there is no new restart-durable cleanup or hard return-time promise for kernel-blocked filesystem/process cleanup.

## Qualification boundary

The dedicated ignored integration suite is `tests/ref_store_materialized_reads.rs`; it requires an explicit dedicated PostgreSQL fixture, S3 provider configuration and trusted native Git. Ordinary cargo test does not qualify those real-provider cases. Blob lifecycle gate tests use the in-process memory backend and prove ownership wiring, not S3/Azure provider behavior. Exact source/test/binary-bound native results and failures are recorded separately once run.

Serving cutover, complete roots/decisions/accepted-subset contracts, GC, encryption and physical Blob-byte backup remain separate work. Existing metadata archives still do not contain external S3 originals. No issue closes before the corresponding change is merged and its acceptance is complete.
