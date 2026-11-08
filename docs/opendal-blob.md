# OpenDAL Blob layer: #105 / #108

Status: implementation under acceptance. Full unique-mode qualification is PENDING a root-run 21 MiB real-S3 contract test; no native conditional-create qualification is claimed. S3 and optional Azure targets compile, but this is not yet a provider, all-Blob, standalone-deployment or full #108 qualification. Real provider results must identify the precise service/profile, source and executable. Azure currently has compilation evidence only.

The custom S3 signer, XML multipart implementation and HTTP retry code are replaced by Apache OpenDAL 0.57.0. Minimal features select S3, Tokio execution, bounded concurrency/retry/timeout layers and `reqwest-rustls-no-provider-tls`; the application already supplies Rustls Ring. `blob-azblob` adds Azure. The project target is Rust 1.88, matching the pending security integration; OpenDAL 0.57 itself declares Rust 1.85. Cargo.lock is regenerated and reviewed, not left implicit.

## Boundaries

`RemoteObjectStore` retains legacy content-addressed paths and its explicit local mode for existing readers. Its S3 implementation now delegates to OpenDAL. Legacy identical-key uploads succeed only after full verification of existing content, including conditional conflicts at multipart completion. The old local durable ACK paths are not converted by this layer.

The separate `BlobStore` uses `v1/tenants/<tenant>/authorities/<authority>/g<generation>/attempts/<attempt>/<namespace>/<digest>` locators. Backup-volume locators retain the same identity fields. Locator fields are validated; receipts can be constructed only inside the verified Blob implementation and expose read-only accessors. Metadata equality is not a substitute for revalidating an untrusted receipt.

Both profiles require complete upload plus provider read-back and independent SHA-256/length verification before a receipt. ETag, stat, and LIST are not content proofs. The new profile publication contract is a fresh one-use `UploadIntent`: only `BlobStore::new_upload` mints it, it always generates a new random attempt id inside the byte layer, it cannot be cloned, deserialized, forged from `BlobLocator` or given a caller-chosen attempt id, and `put_file` consumes it by value. Two publications of identical bytes therefore never share an address, and a locator restored from metadata is read-only. Retrying an unknown outcome means verifying the old read-only locator (without overwrite) or minting a fresh intent/path; a trusted resume must not recover write authority from metadata. A crash may leave an orphan object but can never cause address reuse. The configured prefix is applied once by the operator.

Provider `write_with_if_not_exists` remains only optional defense-in-depth when the SDK declares it. It is not a startup requirement and not a provider guarantee: the v4 raw conditional multipart probe observed the duplicate completion returning Ok instead of AlreadyExists, despite the SDK declaring the capability, so native conditional-create is unenforced and not qualified. The unique-attempt contract holds irrespective of provider conditional behaviour; there is no stat-then-overwrite, in-memory used-key set or silent local fallback.

**New-profile deletion is unavailable.** `BlobStore::delete` always returns `DeleteDisabled`; `ROOTYARD_BLOB_DELETE=exact-locator` is rejected. A future deletion API requires the persistent hold/root and retirement protocols in #113/#114. The direct raw operator used by provider tests injects faults and removes only fresh test-owned identities; it does not enable product GC.

## Configuration

Set `ROOTYARD_BLOB_DRIVER=opendal` (the only driver), `ROOTYARD_BLOB_SERVICE=s3|azblob`, and an explicit origin-only `ROOTYARD_BLOB_ENDPOINT`. Missing configuration, fs/memory, credentials in URLs, path/query/fragment endpoints and unknown drivers are rejected. TLS is required except HTTP loopback fixtures.

S3 requires `ROOTYARD_BLOB_BUCKET`, `ROOTYARD_BLOB_ACCESS_KEY_ID`, `ROOTYARD_BLOB_SECRET_ACCESS_KEY`; optional settings include `ROOTYARD_BLOB_REGION` and `ROOTYARD_BLOB_SESSION_TOKEN`. Azure requires its feature plus `ROOTYARD_BLOB_CONTAINER`, `ROOTYARD_BLOB_ACCOUNT_NAME`, and `ROOTYARD_BLOB_ACCOUNT_KEY`. Credentials and private locators are redacted in Debug and provider errors.

Optional limits are `ROOTYARD_BLOB_ROOT`, `ROOTYARD_BLOB_TIMEOUT_MS` (30000), `ROOTYARD_BLOB_IO_TIMEOUT_MS` (60000), `ROOTYARD_BLOB_CONCURRENCY` (16, at most 256), `ROOTYARD_BLOB_RETRY_MAX_TIMES` (3, at most 10), `ROOTYARD_BLOB_MAX_OBJECT_BYTES` (at most 1 TiB), and `ROOTYARD_BLOB_RANGE_FULL_GET_MAX_BYTES` (64 MiB by default, at most 256 MiB). The root prefix is validated and not repeated in operation paths.

Uploads hash 64 KiB source blocks and use compliant 8 MiB multipart chunks with bounded concurrency. Downloads verify before an atomic destination rename and use private mode-0600 staging files. A guard owns an unfinished writer throughout write, close and abort awaits. Errors attempt bounded cleanup with a separate budget; cancellation schedules a bounded best-effort abort. Process kill/runtime shutdown can leave an orphan, and no receipt is issued for unknown completion. There is no periodic orphan sweep yet.

Ranges are at most 1 MiB. Since a ranged GET cannot prove the whole-object SHA-256, v1 downloads and verifies the complete object to a private temporary file before seeking the slice. It rejects objects above the configured full-download ceiling until a chunk-hash manifest/cache proof exists. This deliberately has whole-object cold-read cost.

Each long-lived BlobStore owns a shared operator with bounded layers. Legacy `RemoteObjectStore::from_env` still constructs its operator per call; application-wide reuse and workflow wiring are separate work. Provider-managed encryption is a future profile contract, not implemented or certified by these bytes-only methods. Existing encrypted Pando paths retain their Vault dependency.

## Qualification

Normal `cargo test --test blob_provider_contract` runs local invariants and explicitly ignores the real provider case. To exercise a configured disposable provider, run `cargo test --test blob_provider_contract -- --ignored --nocapture`. Missing real configuration fails that case. The bucket/container must permit fixture-only overwrite/delete for deliberate corruption probes; all keys use fresh random identities.

The real case covers multipart publication through owned one-use intents, distinct attempt paths for identical bytes, independent-client read-back, verified download/range, a short read-only locator against an existing key, refusal of wrong source length and wrong expected digest with no ACK, fixture truncation and same-length corruption, global digest validation for a range outside the corrupt byte, product deletion refusal and late old-attempt deletion isolation. The two `compile_fail` examples on `UploadIntent` prove that cloning the write capability and forging one from a locator do not compile. Cleanup runs on caught assertion failure and targets only exact owned paths. These cases do not establish the cross-store hold/GC protocol, exhaustive cancellation/retry behavior, a different provider's contract or physical durability/HA.

Follow-ups: #109 connects content ACKs and KeyProvider; #113/#114 own persistent retention; #120 owns Blob backup/restore. All-content Blob publication, removal of local authority, standalone defaults, real Azure service qualification and destructive GC remain unqualified.
