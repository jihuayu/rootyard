# Local-envelope KeyProvider component (#109 increment)

Status: this is an independent component in `src/blob_store/key_provider.rs`. It
is **not** wired into serving, Blob publication, LFS, Workspace, backup, schema,
runtime selection or any request path. The legacy
`storage::encrypted_objects::Envelope` format, Vault Transit callsites and
`PackStore` byte format are unchanged. No serving default has been selected.

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

## Backup and rotation

Backup manifests may record `key_id` and wrapped metadata, never the KEK or the
keyring files. A restore needs the same key ids provisioned out of band; if a
referenced id is missing, unwrap fails closed. The keyring must be backed up
separately from the data backup, with access controls at least as strong as the
original.

Rotation adds a new key id, updates `current`, and keeps old ids loaded. Existing
objects remain readable with their old key id. `rewrap_data_key` changes wrapped
metadata only; this increment does not persist rewrap receipts or switch object
references, so a caller must do that before retiring anything. Old ids should be
retained until every reference is rewrapped and every dependent backup has
expired. This component provides no automated deletion and makes no claim of a
complete backup integration.

## Verification

Local contract tests, no Vault and no provider service:

```text
cargo test --test key_provider_contract
```

They cover roundtrip, nonce variance, tampered ciphertext/nonce/AAD/version/key
id, wrong and missing keys, old-read/new-write/rewrap with an unchanged DEK,
malformed key-file length/mode/symlink/FIFO, keyring directory/manifest policy,
Debug/JSON redaction and a length-delimiting collision construction. They do not
qualify a cloud KMS, full backup/restore, serving integration, all-content Blob
storage or destructive GC.
