# OpenDAL Blob layer: #105 / #108

Status: the new unique-attempt S3 component passed its source-bound21MiB
provider contract at b8e6fc6 (it first passed at `eaab8cd`), including
independent read-back/range verification, corruption rejection and disabled
deletion. The legacy content-addressed paths were separately qualified at the
same commit: 283 library tests (8 explicitly ignored), the two-MiB-stack
regression, a two-process S3 publish/recover cycle, 41 native Pando cases with
18/18 committed and zero pending operation rows, and a stock Git LFS
remote-only push with replacement-volume recovery. Optional Azure is
compile-only. This still does not complete #108 or qualify all-content Blob
storage, standalone deployment, conditional creation, HA or physical
durability.

The custom S3 signer, XML multipart implementation and HTTP retry code are replaced by Apache OpenDAL 0.57.0. Minimal features select S3, Tokio execution, bounded concurrency/retry/timeout layers and `reqwest-rustls-no-provider-tls`; the application already supplies Rustls Ring. `blob-azblob` adds Azure. The project target is Rust 1.88, matching the pending security integration; OpenDAL 0.57 itself declares Rust 1.85. Cargo.lock is regenerated and reviewed, not left implicit.

## Boundaries

`RemoteObjectStore` retains legacy content-addressed paths and its explicit local mode for existing readers. Its S3 implementation now delegates to OpenDAL. Legacy identical-key uploads succeed only after full verification of existing content, including conditional conflicts at multipart completion. The old local durable ACK paths are not converted by this layer.

The separate `BlobStore` uses `v1/tenants/<tenant>/authorities/<authority>/g<generation>/attempts/<attempt>/<namespace>/<digest>` locators. Backup-volume locators retain the same identity fields. Locator fields are validated. Receipts are defined in the private `transfer::receipt` module: `BlobReceipt::new` is `pub(super)` to `blob_store::transfer`, so the bounded verifier that re-read the object from the provider is the only mint point in the crate. The public `blob_store::BlobReceipt` is a read-only re-export (getters, `clone`, metadata `matches`); there is no `serde`/`Deserialize` and no public or `pub(crate)` factory, so no adapter, service handler, checkpoint or other `blob_store` child can forge acknowledgement. Metadata equality is not a substitute for revalidating an untrusted receipt. A receipt also records the immutable physical backend identity of the store that performed the read-back; `matches` stays deliberately locator/metadata-only for compatibility, so a consumer that cares about the physical target must compare `receipt.backend_identity()` with the live store's identity and provider.

Both profiles require complete upload plus provider read-back and independent SHA-256/length verification before a receipt. ETag, stat, and LIST are not content proofs. The new profile publication contract is a fresh one-use `UploadIntent`: only `BlobStore::new_upload` mints it, it always generates a new random attempt id inside the byte layer, it cannot be cloned, deserialized, forged from `BlobLocator` or given a caller-chosen attempt id, and the raw writer `BlobStore::put_file` consumes it by value. Two publications of identical bytes therefore never share an address, and a locator restored from metadata is read-only. Retrying an unknown outcome means verifying the old read-only locator (without overwrite) or minting a fresh intent/path; a trusted resume must not recover write authority from metadata. A crash may leave an orphan object but can never cause address reuse. The configured prefix is applied once by the operator. The intent is also bound to an immutable, non-secret `BlobBackendIdentity`: a domain/version-tagged SHA-256 over the *actually opened* profile's effective provider, endpoint origin (or a provider-default marker plus the default scheme), bucket/container, root prefix, region and stable account identity (a domain-separated hash of the S3 access key id, or the Azure account name). It is never derived from the caller's artifact scope, authority id or generation, which remain logical path scope. The identity contains no secret key, session token or plain credential and is redacted in Debug. Rotating only the secret keeps the identity because the physical mapping did not change; a different access key id, account, endpoint, bucket or root yields a different identity, so an old grant is conservatively rejected as `ForeignBackend` and the ledger must treat that grant as dead rather than retry it against the new mapping. Only URL-parser-guaranteed equivalences (scheme and host case, default ports) are normalized; root and region spelling are preserved, and no network discovery, ETag or listing is used.

The raw write is sealed separately from the intent. `BlobStore::put_file` is `pub(super)`: only modules under `blob_store` can name it, the production caller is the protected uploader (`blob_store::protected`), which may call it only after it consumed an opaque grant, and nothing else may publish. `BlobStore::operator`, `BlobStore::object_path`, `BlobStore::profile` and `BlobProfile::credentials` are narrowed to the same `pub(super)` boundary, so no other crate subtree can reach the raw provider handle or the path mapping. There is no feature-gated or `#[doc(hidden)]` raw-write hook at all, so `pando-lab` and every other feature combination expose only the protected path and the default production build compiles no raw-write entry point. `put_file` first compares the intent's privately bound backend identity with the store's identity and returns `ForeignBackend` before opening the source, acquiring a slot or touching the provider, so a foreign grant performs no IO. The schema141 hold ledger persists the identity hex and compares it in addition to the provider and locator metadata; a stored hex string is a claim, never a minted proof or write capability.

Provider `write_with_if_not_exists` remains only optional defense-in-depth when the SDK declares it. It is not a startup requirement and not a provider guarantee: the v4 raw conditional multipart probe observed the duplicate completion returning Ok instead of AlreadyExists, despite the SDK declaring the capability, so native conditional-create is unenforced and not qualified. The unique-attempt contract holds irrespective of provider conditional behaviour; there is no stat-then-overwrite, in-memory used-key set or silent local fallback.

**New-profile deletion is unavailable.** `BlobStore::delete` always returns `DeleteDisabled`; `ROOTYARD_BLOB_DELETE=exact-locator` is rejected. A future deletion API requires the persistent hold/root and retirement protocols in #113/#114. The direct raw operator used by provider tests injects faults and removes only fresh test-owned identities; it does not enable product GC.

## Configuration

Set `ROOTYARD_BLOB_DRIVER=opendal` (the only driver), `ROOTYARD_BLOB_SERVICE=s3|azblob`, and an explicit origin-only `ROOTYARD_BLOB_ENDPOINT`. Missing configuration, fs/memory, credentials in URLs, path/query/fragment endpoints and unknown drivers are rejected. TLS is required except HTTP loopback fixtures.

S3 requires `ROOTYARD_BLOB_BUCKET`, `ROOTYARD_BLOB_ACCESS_KEY_ID`, `ROOTYARD_BLOB_SECRET_ACCESS_KEY`; optional settings include `ROOTYARD_BLOB_REGION` and `ROOTYARD_BLOB_SESSION_TOKEN`. Azure requires its feature plus `ROOTYARD_BLOB_CONTAINER`, `ROOTYARD_BLOB_ACCOUNT_NAME`, and `ROOTYARD_BLOB_ACCOUNT_KEY`. Credentials and private locators are redacted in Debug and provider errors.

Optional limits are `ROOTYARD_BLOB_ROOT`, `ROOTYARD_BLOB_TIMEOUT_MS` (30000), `ROOTYARD_BLOB_IO_TIMEOUT_MS` (60000), `ROOTYARD_BLOB_CONCURRENCY` (16, at most 256), `ROOTYARD_BLOB_RETRY_MAX_TIMES` (3, at most 10), `ROOTYARD_BLOB_MAX_OBJECT_BYTES` (defaults to the staging budget, at most 1 TiB), and `ROOTYARD_BLOB_RANGE_FULL_GET_MAX_BYTES` (64 MiB by default, at most 256 MiB). The root prefix is validated and not repeated in operation paths.

Resource capacity is explicit: `ROOTYARD_BLOB_ACTIVE_UPLOADS` (default 2, 1..=32), `ROOTYARD_BLOB_ACTIVE_READERS` (default 4, 1..=32) and `ROOTYARD_BLOB_STAGING_BYTES` (default 256 MiB, 64 KiB..=16 GiB). See the budget section below.

Uploads hash 64 KiB source blocks and use compliant 8 MiB multipart chunks with bounded concurrency. The source must be a regular file: it is opened with `O_NOFOLLOW|O_NONBLOCK` and `fstat`-confirmed before any provider write, so a symlink or FIFO source cannot turn a publish into a hanging read. Downloads verify before an atomic destination rename and use private mode-0600 staging files. A guard owns an unfinished writer throughout write, close and abort awaits. Errors attempt bounded cleanup with a separate budget; cancellation schedules a bounded best-effort abort. Process kill/runtime shutdown can leave an orphan, and no receipt is issued for unknown completion. There is no periodic orphan sweep yet (#122 owns persistent cleanup, which is not claimed here).

Ranges are at most 1 MiB. Since a ranged GET cannot prove the whole-object SHA-256, v1 downloads and verifies the complete object to a private temporary file before seeking the slice. It rejects objects above the configured full-download ceiling until a chunk-hash manifest/cache proof exists. This deliberately has whole-object cold-read cost. SDK readers are configured explicitly at 64 KiB chunks with one in-flight window per reader; concurrency across verified readers comes from the reader budget, not from one reader fanning out.

Each long-lived BlobStore owns a shared operator with bounded layers and shares the process-wide resource context described above. The legacy `RemoteObjectStore` adapter is **not** part of this budget: it keeps its own per-call operator, its own temp-file handling and its unchanged `UploadGuard::new` constructor (no upload slot), pending a separate migration. Consequently this is not a complete application quota: other storage paths, Git/LFS/backup work and non-Blob subsystems are unaccounted by these numbers. Provider-managed encryption is a future profile contract, not implemented or certified by these bytes-only methods. Existing encrypted Pando paths retain their Vault dependency.

## Process-wide resource budget and whole-method deadlines

These budgets apply to the new `BlobStore` only. Every `BlobStore::open` in a process registers or joins **one** process-wide context (`src/blob_store/budget.rs`); capacities are never a fresh semaphore per operator or per call. A later profile that requests *different* limits is rejected with `CapacityConflict` instead of silently inheriting the first profile's numbers, so two operators can never hold different beliefs about one budget.

* Upload slots: at most `ROOTYARD_BLOB_ACTIVE_UPLOADS` concurrently unfinished provider writers process-wide. A slot is owned by the writer guard and stays owned through close, explicit abort and cancellation cleanup: a cancelled operation hands the writer *and* the slot to one bounded background abort task, so a still-open writer is never counted as free capacity. The slot is returned after the write/abort finished and **before** the post-close read-back, which needs a reader slot instead.
* Verified-reader slots: at most `ROOTYARD_BLOB_ACTIVE_READERS` concurrent verified downloads (download, range and read-back verification).
* Weighted staging: `ROOTYARD_BLOB_STAGING_BYTES` of staging is leased in 64 KiB units. A full verified download or range read leases `length` bytes for the whole download *and* through the cleanup of its staging file; a stream-only read-back leases zero bytes. A request larger than the entire budget is refused with `StagingBudgetExceeded` **before** any queue wait instead of blocking forever, and queued waiters expire into `DeadlineExceeded` at their absolute deadline (Tokio's fair semaphore also removes a cancelled waiter from the queue).

Leases are owned values (`UploadLease`, `ReaderLease`, `StagingLease`, `ReadLease`), not guard counters, so cancellation cannot release capacity that cleanup is still using. A staging file created by this call is the only path its cleanup may unlink; the guard is constructed after `create_new` succeeded, so a failed create never unlinks someone else's path. Dropping staging does not unlink on a Tokio worker: the unlink moves to `spawn_blocking` with its own lease retained, which bounds pending cleanups to `ACTIVE_READERS` process-wide and charges the bytes until the OS call returns.

Object ceiling coherence: the default `ROOTYARD_BLOB_MAX_OBJECT_BYTES` equals the staging budget (capped at 1 TiB), and an explicit object ceiling above the staging budget is a configuration error. There is no alternative full-read API, so this contract refuses to acknowledge an object it could not later fetch and verify through its own staging path. `ROOTYARD_BLOB_RANGE_FULL_GET_MAX_BYTES` above the staging budget is rejected for the same reason. Raising staging up to 16 GiB is the only way to accept larger objects.

Deadlines: `put_file`, `get_to_file`, `get_range`, `verify`, `verify_receipt` and `head` take the caller's absolute `std::time::Instant`. Queueing and the caller-visible wait are bounded with an outer `timeout_at`; reads run the whole local pipeline in an owned task so a caller timeout detaches rather than cancels it. That task settles its current local open/write/fsync/rename and cleanup before releasing the shared read lease; provider futures may time out inside it. Upload abort after an error or cancellation runs on a separate bounded budget (`ROOTYARD_BLOB_ABORT_TIMEOUT_MS`). On error or timeout there is no receipt. Downloads do not guarantee a side-effect-free result: a timeout, cancellation, or any error after the rename (for example directory-fsync failure) can leave a destination and/or orphan staging file; the bytes were verified only if the owned task reached commit, so callers must verify the destination or use a fresh path. Uploads likewise may have committed at close or left an orphan multipart upload after a late abort. Runtime shutdown or a kernel-blocked syscall can orphan temp files or aborts; these budgets and cleanup are not restart-durable. Cleanup capacity is retained where possible, and a receipt is issued only on successful completion before the deadline.

Limits of this claim, stated plainly: these numbers bound leased slots and staging bytes, not resident memory. SDK/HTTP buffers, provider-side transfer sizes, page cache and allocator behaviour are outside the accounting, so no exact RSS figure follows from the slot counts. A local open/read/fsync or unlink blocked inside the kernel cannot be hard-cancelled by Tokio: the deadline stops *waiting*, the staging lease stays charged until the syscall returns, and a process kill can orphan the temp file. These bytes-only methods also promise no S3-side rollback of an object whose completion is unknown.

## Qualification

Provider contract tests are a `#[cfg(test)]` child module (`src/blob_store/provider_contract_tests.rs`), not an integration target, so they can call the sealed `put_file` directly and no public raw-write entry point is needed in any feature build. The normal library run (`cargo test --lib blob_store::provider_contract_tests`) executes the local invariants (strict profile parsing, locator/layout, deterministic identity binding, receipt/intent identity and foreign-intent refusal before source IO) and explicitly ignores both real provider cases. To exercise a configured disposable provider, run `cargo test --lib blob_store::provider_contract_tests -- --ignored --nocapture`; every selected real-provider case is mandatory-configured and panics on a missing `ROOTYARD_BLOB_*` profile instead of being reported as skipped or passed. The cancellation case additionally requires the S3 `ROOTYARD_BLOB_ENDPOINT` to be a plain HTTP loopback origin; it refuses a TLS endpoint rather than bypassing the owned gate. The bucket/container must permit fixture-only overwrite/delete for deliberate corruption probes; all keys use fresh random identities.

Local lifecycle unit tests (`cargo test --lib blob_store`) use a private per-test `memory`-backed store and a private `ResourceContext`, so they never mutate process environment for each other. Deterministic stalled-readback and stalled-upload-read gates prove that an outer timeout detaches the owned task without releasing its reader/staging or upload capacity until the inner local operation and bounded abort drain. They cover weighted staging that never overcommits, oversize refusal before waiting, queue-deadline expiry with no receipt and accounting released where possible, upload-slot release before read-back with a single slot, a cancelled writer retaining then returning its slot, shared process limits with conflict rejection, bounded limits, symlink/FIFO source refusal, deterministic canonical identity hex, receipt/intent identity binding, and foreign-backend intent refusal before a missing source can even be opened. The `cfg(test)` memory operator uses its own fresh realm identity rather than pretending to be the synthetic S3 profile mapping. A deadline does not promise side-effect freedom: an outstanding Tokio FS write, fsync or rename may complete late and leave a destination or orphan staging file. They are not provider qualification.

The existing real case covers multipart publication through owned one-use intents, distinct attempt paths for identical bytes, independent-client read-back, verified download/range, a short read-only locator against an existing key, refusal of wrong source length and wrong expected digest with no ACK, fixture truncation and same-length corruption, global digest validation for a range outside the corrupt byte, product deletion refusal, backend-identity equality between intent, receipt and the store that read back, and late old-attempt deletion isolation. The two `compile_fail` examples on `UploadIntent` prove that cloning the write capability and forging one from a locator do not compile. Cleanup runs on caught assertion failure and targets only exact owned paths.

The real cancellation case (`real_provider_timeout_and_caller_cancel_isolate_late_completion`) fronts that HTTP loopback endpoint with a bounded owned TCP pass-through gate. It forwards the signed PUT unchanged and withholds the real backend's final response until the caller has already timed out or been aborted. The observation keeps only the HTTP method, numeric status and arrival instant, so an observed PUT/2xx timestamped before the caller stopped proves the real backend answered before cancellation; the gate never synthesizes an S3 response and records no path, header, body, credential or locator. The deadline path must return `DeadlineExceeded` with no receipt and may leave an orphan at the timed-out attempt's own address. The caller-abort path must surface a cancelled task and no caller-visible receipt; a detached late read-back may finish only into a dropped handle and persists nothing. A fresh one-use attempt must remain absent until explicitly published; fixture-operator exact deletion of the old attempt runs after the new attempt exists, and the new object must still verify; product `delete` must remain `DeleteDisabled`. Returned error text is checked against locator fields, long configured bucket/root values, URL and credential markers. The gate assumes no interim 1xx response, treats any first response as final, and is not a TLS or cloud-S3 qualifier. This single checkpoint does not establish retry/network-partition behavior, Azure, a product late-DELETE/GC path, exhaustive cancellation behavior or completion of #108. The full source-bound reports are in `evidence/state-services/opendal/`.

Follow-ups: #109 connects content ACKs and KeyProvider; #113/#114 own persistent retention; #120 owns Blob backup/restore. A local-envelope KeyProvider component now exists in isolation (`src/blob_store/key_provider.rs`, [key-provider.md](key-provider.md)); it is not connected to the paths above and does not change the Vault envelope. All-content Blob publication, removal of local authority, standalone defaults, real Azure service qualification and destructive GC remain unqualified.

## SDK error compatibility and current evidence

This branch is stacked on the RefStore operation-registry increment
(schema138 / backup format14). The legacy content-addressed RemoteObjectStore
paths remain stable while their S3 transport delegates to OpenDAL.

The exact-request HttpFetch wrapper keeps signing, TLS, retry and multipart in
the SDK. For non-2xx responses it accumulates at most64KiB of body, reuses the
pinned Apache S3 parser, preserves its kind/retry classification, then drops
all provider text/URL context and retains a finite status/stage marker.
An oversized or unreadable body uses the same parser with an empty body,
preserving status-only defaults. Successful responses pass through, including
HTTP200 multipart provider-error documents. Concurrent parts carry their own
error value; there is no task-local or global last-status correlation.

OpenDAL0.57 has no public numeric-status/context getter. The280KiB vendored
`opendal-service-s3` crate adds one documented public shim around its unchanged
parser. LICENSE, NOTICE, upstream revision/archive SHA and per-file checksums
are retained; it adds no custom S3 signing, XML parser, retry or multipart logic.
Transport failures retain only finite SDK kind/temporary/stage values, not an
opaque SDK source that can retain private URLs. Unknown decode/stream failures
have no invented HTTP status. Deadline exhaustion retains typed timeout(op).

283 Rust library tests passed (eight service-dependent tests explicitly ignored),
and the operator's all-target Clippy run (v10 log) ended `Finished` with no
diagnostics. The provider executable
from b8e6fc6 passed the one explicitly selected realS3 contract, with zero
ignored cases; its receipt includes source/test/lock hashes and actual build
flags. Two `UploadIntent` compile-fail doc-tests also passed. The observed
multipart conditional-create weakness remains recorded above; fresh opaque
upload intents, rather than a conditional-write claim, supply the new
address-uniqueness contract.

The legacy real-service paths were also exercised at b8e6fc6: 41 native Pando
cases passed with 18 committed, zero pending and 18 terminal operation rows; the
legacy S3 adapter published and then recovered a 20MiB+4-byte object in two
separate processes; stock Git LFS pushed a remote-only pointer and recovered
after replacement-volume loss. These ran against loopback PostgreSQL, Garage and
Vault on one physical host. They are ordinary-workload and recovery evidence,
not synchronized old-OID CAS, fault-injection for actual429/503/disconnect
responses, two-host HA or physical-durability qualification. The v8 attempt at
source `3257358` failed on the first Pando push after the server process
exited; that failure is retained as a counterexample and is attributed to the
pre-`719c7cc` async layer stack, which the type-erasure fix and the two-MiB-stack
regression now bound.

Existing encrypted Pando still requires Vault and the production legacy profile
remains the active one; the new serving profile stays disabled and has no
serving route. In the default production build the writer is the legacy
`RemoteObjectStore` path; the v1 profile enables no remote delete and no
persistent hold, legal-hold, root-retirement or storage-membership model, so no
hold dependency is satisfied by this layer alone. The sealed v1 raw write has no
production caller until `blob_store::protected` is wired. Serving-mode
switch, KeyProvider replacement, durable roots/holds and GC remain
#109/#110/#112-#123 work. Azure stays compile-only and conditional create is
unqualified.
