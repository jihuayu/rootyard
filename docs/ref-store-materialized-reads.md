# Materialized registered-pack reads

This is the shared registered-pack materializer foundation for #105/#107, layered on migration143 snapshots and pins. It introduces no schema or HTTP route and does not change repository authority. The metadata-only `PackReadSnapshot` continues to report `complete_git_read_snapshot() == false`; only a successful materializer call returns a `MaterializedPackRead` that reports true. The legacy `PgPackSnapshotMaterializer::read` remains the unserved/history path; the authorized serving coordinator adds the retained-serving lane below.

Callers first obtain an atomic registered-membership snapshot and durable pin through `PgPackSnapshot::create`. They pass its snapshot/pin identity and expected generation to the materializer, together with the PostgreSQL pool, explicit Blob store, absolute trusted Git binary and caller deadline. Returned data includes the complete captured refs/HEAD, pack identities and full materialization digest. The owned result has no public constructor, Clone or serde factory and exposes verified local pack/index bytes without exposing its filesystem path or granting write/publish authority.

## Read ordering

The entire operation uses one effective monotonic deadline: the earlier of the caller deadline and entry plus 30 seconds. Both pool waits, SQL stages and transaction cleanup, Blob reads, independent SHA/length checks and native verification use that same budget.

1. T1 validates the complete captured metadata and live pin in a bounded short transaction. It requires successful bounded cleanup and releases every PostgreSQL client before Blob/native work.
2. The private common engine verifies the live Blob backend and every exact registered locator, SHA-256 and length, then runs native Git pair/index, exact refs/HEAD, branch-type and connectivity checks for SHA-1 or SHA-256. It writes validated sorted packed-refs rather than a loose user-shaped directory tree (#139). The private native result carries the full T1 scope, pin/generation/expiry, snapshot and artifact binding digest.
3. T2 reacquires PostgreSQL under the same deadline, revalidates immutable metadata/registration ledgers and full binding, then checks generation/scope and a fresh database clock after all slow ledger reads. It constructs the sealed result while the pin lock remains held and returns only after successful bounded cleanup. That locked final check is the read linearization point. A mutation ordered later can finish before the caller receives its already-linearized local copy.

An older pinned revision may remain readable after a newer commit in the same current realm. Release, expiry, generation change, deletion or a realm/epoch transition before the final check refuses the result. The returned copied data is disposable; it creates no new durable lease or authority.

## Authorized retained-serving entrypoint

`PgServingSnapshotMetadata::materialize` is the narrow serving coordinator for a retained A5a snapshot selected only by owner/name/snapshot. It derives the repository, tenant, owner, purpose, object format, history/authority/group realm, pin id/generation, pin liveness, ready binding and actual opened Blob backend from authorized stored rows; no caller proof, digest, generation or backend string is accepted.

1. T1 uses the current Owner/Admin plus ContentsRead and the existing serving lane (`read_serving_by_snapshot`) to capture the exact stored snapshot and cluster-authority incarnation; the whole authorization/capture/final-auth await is bounded by the caller's absolute deadline and its cleanup must succeed.
2. The same private native engine downloads and verifies every captured pack/index outside every PostgreSQL lease.
3. T2 is a fresh authorized transaction in the same absolute deadline: current Admin/ContentsRead, exact stored capture equality, current ready binding/backend/gate realm, the captured cluster incarnation, a fresh database-clock pin generation/expiry check, and the complete A5b binding comparison with the native closure. No value exists unless T2 cleanup succeeds.

The retained result is `MaterializedPackRead` with no serving proof anchor/session/HWM; it cannot be converted into a transient `MaterializedServingRead` or `VerifiedReadViewProof`.

## Retained snapshot HTTP content

The opt-in serve-blob gateway exposes only snapshot-scoped
`GET /api/repos/{owner}/{name}/snapshots/{snapshot}/tree` and
`GET /api/repos/{owner}/{name}/snapshots/{snapshot}/blob/{oid}`. They reuse the
current Browse query/path/limit/after/full-OID validation, captured-ref
reachability (`rev-list --objects --all`), tree/blob rendering and bounded JSON
encoder. The full OID path is admitted only inside the captured historical ref
closure; current refs, loose objects, GitFS/Pando and local paths are never
fallbacks.

The handlers retain the opaque T1 context (exact capture + cluster anchor +
absolute deadline) through the private Git view copy, content read and bounded
JSON encoding, then run a fresh same-transaction Admin/ContentsRead, exact
capture/pin/generation/liveness, current ready binding/backend/gate and cluster
fence before releasing the response. The metadata GET route remains
metadata-only with `complete_git_read_snapshot=false`. Retained content never
uses ordinary Browse session finalization; it emits no session token, current
revision, HWM or #174 proof. Roots remain later work.

## Resource ownership

A4 and materialization share one process-wide native verification admission bound of 2. A separate process-wide materialized-view budget of 2 is acquired first and remains owned through each returned view lifetime. Native admission returns after every child is confirmed quiescent, so retained idle read views do not occupy A4 native capacity. Each workspace is conservatively checked against a 160 MiB aggregate logical bound around mutating native operations.

The actual Blob transfer, independent read-back and local artifact-read tasks retain workspace ownership even if their waiter times out or is cancelled. Blob task-entry ownership shares its reader/staging lease and opaque workspace keepalive with staging cleanup; only confirmed unlink success or absence permits normal release. Runtime abort/panic or unknown cleanup outcomes conservatively quarantine resources until process exit. These bounds are process-local; there is no new restart-durable cleanup or hard return-time promise for kernel-blocked filesystem/process cleanup.

## Qualification boundary

The dedicated ignored integration suites are `tests/ref_store_materialized_reads.rs` (legacy/history) and the serving retained-materialization cases in `tests/ref_store_pack_snapshots.rs`; they require an explicit PostgreSQL fixture, S3 provider configuration and trusted native Git. Ordinary cargo test does not qualify those real-provider cases. Blob lifecycle gate tests use the in-process memory backend and prove ownership wiring, not S3/Azure provider behavior. Exact source/test/binary-bound native results and failures are recorded separately once run.

Serving cutover, complete roots/decisions/accepted-subset contracts, GC, encryption and physical Blob-byte backup remain separate work. Existing metadata archives still do not contain external S3 originals. No issue closes before the corresponding change is merged and its acceptance is complete.
