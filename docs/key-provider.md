# Local-envelope KeyProvider & Envelope Integration (#109 `blob_store` slice)

Status: `KeyProvider` (`src/blob_store/key_provider.rs`) is now wired into the
standalone `blob_store` configuration and authenticated envelope pipeline
(`encryption_config`, `envelope`, `encrypted_transfer`, and `closure`). The
legacy `storage::encrypted_objects::Envelope` format, Vault Transit callsites,
`PackStore` byte format, and downstream `src/ref_store/**` wiring (#107 / #144)
remain separate and unchanged. Vault is not a required dependency for the
standalone Blob profile.

## Contract

`KeyProvider` exposes typed wrapping, unwrapping and rewrap of a 32-byte DEK:

* new wraps always use the explicitly configured `current` key id;
* unwrap selects exactly the key id recorded in the wrapped metadata and fails
  with `MissingKey` or `AuthenticationFailed`; it never tries another version,
  falls back to plaintext or generates/replaces a key;
* rewrap decrypts the DEK with its recorded key and wraps the same bytes under
  the current key, changing only non-secret wrapped metadata;
* there is no key deletion API.

Wrapped metadata is non-secret envelope metadata, not the KEK and not the
plaintext DEK. `WrappedKey::from_json` is bounded, denies unknown fields and
validates the format version, key-id syntax, fixed nonce/tag/digest lengths and
the wrapped-dek size. `DataKey`, `WrappedKey`, `WrapContext` and the provider
have custom `Debug` output that does not print secrets. Errors contain no key
bytes or paths. The plaintext DEK is returned as `DataKey`; it zeroizes on drop,
but `Zeroizing<T>`'s own `Debug` prints the array, so `DataKey` redacts
explicitly.

The AAD is a length-delimited transcript of domain, format version, key id,
tenant, authority, object generation, attempt id, namespace and content digest.
`WrapContext` validates each typed field before use, so moving bytes between
adjacent fields cannot create an ambiguous binding.

## Keyring layout

`LocalFileKeyProvider::load` is blocking configuration-time IO. It requires a clean
absolute directory owned by the effective uid with mode exactly `0700`, a
private `keyring.json` and one `<key_id>.key` file per listed version:

```json
{
  "schema": 1,
  "current": "v2",
  "keys": [
    { "key_id": "v1", "sha256": "<sha256 of the raw 32-byte v1.key>" },
    { "key_id": "v2", "sha256": "<sha256 of the raw 32-byte v2.key>" }
  ]
}
```

Each key file must be a regular file, owned by the effective uid, mode exactly
`0600`, exactly 32 bytes. The manifest is also a regular file, owner euid, mode
`0600`, at most 16 KiB. The directory and entries are opened relative to a
pinned directory descriptor with `O_NOFOLLOW|O_NONBLOCK`; each descriptor is
`fstat`-checked before a bounded read. Symlinks, FIFOs, devices, directories,
wrong owner/mode and wrong length are refused without a blocking read. Loading
never creates, repairs or replaces a key file.

The manifest SHA-256 binds a key id to its bytes. Replacing bytes behind an
existing id makes loading fail with `KeyIdentityMismatch`; rotation must add a
new id instead of overwriting one. Keys are loaded once into zeroizing memory
and a running provider is a pinned snapshot: later file replacement or directory
rename does not alter it, and there is no reload/generation/deletion API.

## Honest limits

* The keyring directory's final component is opened with `O_NOFOLLOW`, but
  intermediate path components are resolved by the kernel and are not
  independently re-walked. The configured path must live on an
  operator-controlled filesystem that other users cannot rename or replace.
  Entries inside the `0700` directory are opened with `openat` on the pinned
  descriptor, which avoids key-file path TOCTOU.
* Permission bits are checked, not POSIX ACLs, immutable mount options, fs-verity
  or equivalent. A same-uid attacker is out of scope: it can read the process or
  keyring anyway.
* The snapshot is not `mlock`ed. Rust zeroize wipes only the buffers this module
  owns. ring does not document erasure of its expanded AES key state, so this
  component makes no secure-erasure claim beyond the zeroize semantics of those
  buffers.
* Only AES-256-GCM from the existing ring dependency is used, with a fresh
  96-bit nonce from ring `SystemRandom` on every wrap. Wrapping and unwrapping
  are synchronous CPU-only calls; the only file IO is `load`.

## Backup, rotation and authenticated Blob envelopes

Backup manifests and closure records may persist `EnvelopeMetadata` (bounded
JSON, `#[serde(deny_unknown_fields)]`, recording `schema`, `cipher`, `envelope_id`,
4-byte `nonce_prefix`, 64 KiB `chunk_bytes`, owner scope, plaintext/ciphertext
SHA-256 and length, and `WrappedKey`), never the KEK or plaintext DEK.

Envelope sealing and opening (`src/blob_store/envelope.rs` + `envelope/io.rs`):

* Explicit encryption policy (`src/blob_store/encryption_config.rs`) selects
  `ROOTYARD_BLOB_ENCRYPTION_MODE=provider-managed` or `local-envelope` (with
  clean absolute `ROOTYARD_BLOB_KEYRING_DIR`), rejecting `vault`, `vault-transit`,
  `plaintext`, `none`, empty values, or partial keyring configuration fail-closed.
* Two-phase sealing (`prepare_file_envelope` -> `PreparedCiphertext::bind_and_wrap`)
  encrypts regular files into `0o600` staging files using fresh random 32-byte
  AES-256-GCM DEKs and 4-byte nonce prefixes concatenated with big-endian 8-byte
  chunk indices. Every chunk binds `envelope_id`, owner scope, `plaintext_sha256`,
  `plaintext_length`, `chunk_bytes`, `chunk_index`, and `is_final` in AAD; empty
  files still emit one authenticated 16-byte final tag chunk.
* Once `BlobStore::new_upload` allocates the immutable `attempt_id`, `bind_and_wrap`
  wraps the DEK with `WrapContext::new(tenant_id, authority_id, generation, attempt_id, namespace, plaintext_sha256)`
  and zeroizes the in-memory plaintext DEK immediately.
* `KeyProvider` capability gates fail closed if `local_envelope == false` or
  `plaintext_fallback == true`.
* Rotation adds a new key id (`current`), retains old versions temporarily, and
  calls `rewrap_envelope_metadata` (`KeyProvider::rewrap_data_key`) to rotate
  non-secret `EnvelopeMetadata` without rewriting immutable ciphertext blobs.
  Once old key ids are retired from the keyring, un-rewrapped `EnvelopeMetadata`
  fails closed with `MissingKey`.

## Verification

Contract and unit test targets (run in Linux CI; Vault and external object
providers are not required for the in-memory OpenDAL tests):

```text
cargo test --test key_provider_contract
cargo test --test blob_store_w1c_contract
cargo test --lib blob_store::envelope_tests
```

They cover roundtrip, empty and multi-chunk encryption, replaceable
`KeyProvider` adapters, plaintext-fallback rejection, nonce variance, tampered
ciphertext/chunk-order/truncation/trailing-bytes/metadata/nonce/AAD/version/key
id, wrong and retired/missing keys, old-read/new-write/rewrap with unchanged
ciphertext, malformed key-file length/mode/symlink/FIFO, keyring directory
policy, and Debug/JSON redaction. Downstream serving, `RefStore` commit wiring
(#107/#144), cloud KMS adapters, and destructive GC remain outside this layer.
