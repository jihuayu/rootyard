# OpenDAL Blob layer (W1-B / #105 / #108)

Status: source implementation, not a provider qualification. The only evidence
that counts for a provider is the contract suite below run against a real
service on the stated version; this change does not claim any provider passed
it, because no provider endpoint was available in this work environment.

## What changed

- The hand-written S3 SigV4 signer, XML multipart upload/abort and ad-hoc retry
  in `src/storage/remote_objects.rs` are removed. Transport, signing, TLS,
  multipart, abort, retry, timeout and concurrency are owned by Apache OpenDAL.
- `RemoteObjectStore` keeps its public API, error surface and frozen
  content-addressed paths for LFS, Workspace, backups and the Pando PG
  retention path. `RemoteObjectStore::Local` remains available and is
  explicitly marked legacy/local fixture mode.
- A new standalone profile lives in `src/blob_store/`:
  - `mod.rs`: strong typed `BlobLocator`, `BlobReceipt`, capability and delete
    policy types.
  - `config.rs`: strict `ROOTYARD_BLOB_*` profile parsing.
  - `opendal.rs`: one shared OpenDAL `Operator` + layers and capability gate.
  - `transfer.rs`: bounded streaming publish and provider read-back receipts.
  - `readback.rs`: bounded download, range read, length-only head and
    policy-gated exact-locator delete.
- `src/storage/remote_provider.rs` is the legacy-layout OpenDAL adapter.

Pinned dependency: `opendal = "=0.57.0"`, `default-features = false`, features
`services-s3`, `rustls`, `layers-concurrent-limit`, `layers-retry`,
`layers-timeout`. Azure Blob is optional via the Cargo feature `blob-azblob`.
The crate MSRV stays `rust-version = "1.85"`; nothing silently bumps it.

## Two layouts, on purpose

| | Legacy adapter | New standalone profile |
| --- | --- | --- |
| Path | `tenants/<tenant>[/authorities/<id>/g<n>]/<ns>/<sha256>` | `v1/tenants/<tenant>/authorities/<id>/g<n>/attempts/<attempt>/<ns>/<sha256>` |
| Attempt identity | absent; content-addressed key may outlive a cancelled attempt | always bound; paths are never reused |
| Missing config | falls back to `RemoteObjectStore::Local` (legacy) | hard error |
| `fs`/`memory` service | only the explicit `Local` fixture variant | rejected by name |
| Receipt | returned `StoredObject` after full read-back | `BlobReceipt` with SHA-256 + length read-back |
| Delete | existing Pando PG claim path, exact key, unchanged | disabled by default; exact-locator only when explicitly configured |

Existing readers and manifests keep the legacy paths; the new profile's `v1/`
prefix cannot collide with them. This change does **not** migrate any legacy
object and does not change any durable ACK path.

## Configuration (new profile)

Required:

- `ROOTYARD_BLOB_SERVICE=s3|azblob` (no default; `fs`, `memory` and unknown
  services are rejected, as is `ROOTYARD_BLOB_DRIVER` other than `opendal`)
- S3: `ROOTYARD_BLOB_BUCKET`, credentials `ROOTYARD_BLOB_ACCESS_KEY_ID` +
  `ROOTYARD_BLOB_SECRET_ACCESS_KEY`, and either `ROOTYARD_BLOB_REGION` or
  `ROOTYARD_BLOB_ENDPOINT`
- azblob (feature `blob-azblob`): `ROOTYARD_BLOB_CONTAINER`,
  `ROOTYARD_BLOB_ENDPOINT`, `ROOTYARD_BLOB_ACCOUNT_NAME`,
  `ROOTYARD_BLOB_ACCOUNT_KEY`

Optional:

- `ROOTYARD_BLOB_ENDPOINT`: origin URL only. HTTPS is mandatory; plain HTTP is
  accepted only for `127.0.0.1`/`::1`/`localhost` fixtures. Userinfo, path,
  query and fragment are rejected so a bearer URL cannot become storage config.
- `ROOTYARD_BLOB_ROOT`: object prefix, path-segment validated.
- `ROOTYARD_BLOB_TIMEOUT_MS` (default 30000), `ROOTYARD_BLOB_IO_TIMEOUT_MS`
  (default 60000), `ROOTYARD_BLOB_CONCURRENCY` (default 16, max 256),
  `ROOTYARD_BLOB_RETRY_MAX_TIMES` (default 3, max 10),
  `ROOTYARD_BLOB_MAX_OBJECT_BYTES` (default 1 TiB, hard ceiling).
- `ROOTYARD_BLOB_DELETE=disabled|exact-locator` (default `disabled`).

Credentials are never `Debug`-printed, logged or embedded in errors. Legacy
`ROOTYARD_OBJECT_STORE_*` variables still drive `RemoteObjectStore`.

## Semantics and guarantees

- **Receipt = content proof.** A receipt is issued only after re-reading the
  object from the provider and recomputing SHA-256 and length. `stat`,
  `Content-Length`, provider ETag and provider checksums alone never prove
  content; ETag is never treated as SHA-256.
- **Bounded IO.** Upload streams 64 KiB source chunks into an OpenDAL writer
  (4 MiB write window; OpenDAL decides multipart). Download/read-back hashes
  and length-checks 64 KiB chunks into a private staging file, fsyncs, then
  renames atomically; only this call's staging file is removed on failure.
  Range reads are capped at 1 MiB and must return exactly the requested length.
- **Conditional create / no overwrite.** The new path already contains a fresh
  attempt id, so a repeat publication never shares a key. When the provider
  declares `write_with_if_none_match`, the write is additionally conditional.
  The legacy adapter requires `if-none-match` support at startup and refuses to
  publish otherwise; it never falls back to stat-then-overwrite.
- **Delete.** No listing, prefix delete, rename or GC sweep exists. The new
  profile returns `DeleteDisabled` unless `ROOTYARD_BLOB_DELETE=exact-locator`,
  and even then only deletes one fully resolved versioned locator. Legacy
  remote delete is still only the existing Pando PG claim path, unchanged.
- **Errors and deadlines.** Missing objects map to `NotFound`, precondition
  failures to `AlreadyExists`, deadline expiry to `DeadlineExceeded`; OpenDAL
  retry is bounded and every provider await is wrapped in the caller deadline.
- **Concurrency.** One shared operator per profile carries a single
  `ConcurrentLimitLayer`; there is no per-call semaphore that forgets live
  operations.
- **No LIST inventory.** There is no list API in the driver: a provider listing
  cannot be used as an authoritative inventory.

## Exact limitations (not implemented / not claimed)

- **No provider qualification was run here.** No S3 or Azure endpoint was
  reachable in this environment, so no real-service contract result is claimed.
  Missing env means `SKIPPED`, never "passed".
- **No destructive GC for the new authority.** Persistent hold/root protocols
  (#113/#114) are prerequisites. `exact-locator` deletion is implemented but
  must not be enabled in a deployment that has not adopted those protocols.
- **No hold ledger, reconciliation or orphan GC.** Aborted/abandoned attempts
  stay as unreferenced bytes under unique attempt paths; nothing reclaims them
  automatically. Abandoned multipart uploads are aborted by OpenDAL on the
  writer failure path, but no periodic orphan sweep exists.
- **No key provider / envelope encryption.** The new profile relies on
  provider-managed encryption. It does not implement application-layer keys,
  KMS, rotation or migration of legacy encrypted Pando objects.
- **No backup/restore integration.** `volume_path()` exists on the locator but
  backup jobs, restore, event archives and CI artifacts are not yet wired to
  the new profile.
- **No presign, rename or POSIX semantics.** Private packs never get bearer
  URLs from this layer.
- **No paging/parallel range assembly.** Range reads are single bounded reads;
  no random-access layout or chunk cache is claimed.
- **Legacy adapter construction is per call.** `RemoteObjectStore::from_env`
  builds an operator on each call (as the old code built a client per call);
  the shared/ bounded operator requirement is met by the long-lived
  `BlobStore`, not by the frozen legacy adapter.
- **Legacy local ACKs remain unchanged.** Local LFS/Workspace checkpoint
  durability is #109 and is not solved here. Legacy `RemoteObjectStore::Local`
  still exists for fixtures/development and must not be considered production
  storage.
- **OpenDAL API/feature compatibility is compiled by the root integrator.**
  `Cargo.lock` was intentionally not regenerated in this change, and no
  `cargo build/check/test` was run. Provider-layer behaviour (retry semantics,
  conditional-create support, timeouts) is declared at startup but only proven
  by the contract suite below.

## Provider contract suite

`tests/blob_provider_contract.rs` always checks strict config rejection and
locator/legacy-path invariants locally. The real-provider contract covers:

1. two publications of identical bytes under different attempts,
2. receipt emission and cross-client receipt re-verification by provider
   read-back,
3. download hash equality and bounded range equality,
4. length-short read failure with no destination left behind,
5. locator length mismatch rejected before upload, and
6. delete policy: disabled by default; with `exact-locator`, deleting one
   locator leaves the sibling attempt object intact.

Run it only against a real service:

```sh
ROOTYARD_BLOB_SERVICE=s3 \
ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... ROOTYARD_BLOB_ENDPOINT=https://... \
ROOTYARD_BLOB_ACCESS_KEY_ID=... ROOTYARD_BLOB_SECRET_ACCESS_KEY=... \
cargo test --test blob_provider_contract
```

Record the provider, endpoint type, OpenDAL version, date and exact command with
the raw output before calling a provider qualified. A successful run against one
S3-compatible endpoint does not qualify a different provider.

## Follow-ups

- #109: durable local-to-Blob ACK for LFS/Workspace.
- #113/#114: persistent artifact holds and roots before any new-profile delete.
- W1-C: move pack/LFS/Workspace/checkpoint/backup writers onto `BlobStore`.
