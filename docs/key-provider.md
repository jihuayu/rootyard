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
cargo test --lib blob_store::policy_matrix_tests
```

They cover roundtrip, empty and multi-chunk encryption, replaceable
`KeyProvider` adapters, plaintext-fallback rejection, three-mode encryption
policy enforcement (`unset`, explicit `provider-managed`, explicit
`local-envelope`) with zero provider IO on refused calls, `ProtectedUploader`
pre-consume hold-to-prepared validation, nonce variance, tampered
ciphertext/chunk-order/truncation/trailing-bytes/metadata/nonce/AAD/version/key
id, wrong and retired/missing keys, old-read/new-write/rewrap with unchanged
ciphertext, malformed key-file length/mode/symlink/FIFO, keyring directory
policy, and Debug/JSON redaction. Downstream serving, `RefStore` commit wiring
(#107/#144), cloud KMS adapters, and destructive GC remain outside this layer.

## Pando Lab Pack Encryption & Resumable KMS Rotation (#21)

Inside `src/pando_lab/lifecycle/`, stored Git pack artifacts use `KeyProvider`
(`PandoKmsProvider` backed by `LocalFileKeyProvider`) with real authenticated
encryption (`encryption_mode = "authenticated-envelope-v1"`):

* **Chunked AEAD sealing (`PANDOENC` v2)**: every sealed pack generates a fresh
  random 32-byte DEK in `Zeroizing<[u8; 32]>` and a random 4-byte nonce prefix
  combined with an 8-byte big-endian chunk counter (`AES-256-GCM-HMAC-SHA256` or
  `CHACHA20-POLY1305-SHA256` via `ring::aead`), plus a length-delimited AAD
  transcript binding cipher suite, `repo`, `pack_id`, `envelope_id`,
  `pack_sha256`, `idx_sha256`, plaintext length, chunk size, chunk index, and
  final-chunk flag.
* **KMS keyring & policy enforcement**: per-repo keyrings live under
  `$PANDO_ROOT/kms/<repo>` (or `$PANDO_KMS_KEYRING_DIR`) with `0700`/`0600` file
  modes. `PandoKmsProvider` enforces `provider_revoked`, key revocation
  (`kms-revoke-key` zeroes and unlinks the `.key` file),
  `retain_previous_generations`, and `min_readable_key_version`, failing closed on
  tamper, wrong keys, revoked keys, or revoked provider access.
* **Resumable key rotation (`kms-rotate`)**: checkpoints progress to both
  `rotation_state.json` (`0600`) and `pando_lab.kms_rotations` (`IN_PROGRESS` /
  `COMPLETED`), rewraps only `WrappedKey` metadata (leaving immutable object-store
  ciphertext unchanged), tolerates fault injection (`--fail-after-packs`) and
  concurrent writes to newly active keys, and resumes via `--resume`.
* **Explicit synthetic lab mode**: metadata-only envelope generation
  (`build_envelope_record` / `--encryption-mode synthetic-metadata-lab-only`) is
  explicitly labeled `synthetic-metadata-lab-only`, never performs authenticated
  pack encryption, and is rejected by `object-store-get`, `kms-verify`, and cold
  pack hydration.

The Local `kms-revoke-key`, `kms-revoke-provider`, `kms-grant-provider` and
`kms-policy` mutations refuse to run while Vault Transit is selected; they are
Local-file operations, not Vault administration. Local `kms-rotate` adds a new
key id. Vault mode instead rotates to an already existing Transit key version
and never asks Vault to create one.

## Issue #21 real-Vault and Local producer qualification boundary

The historical hosted `verify` job passed all five real Vault cases, all 17
Local PostgreSQL producer cases, and all seven PITR cases for PR #283's synthetic
merge `2b8da9d52602839d27075b249d5b36c487a97808`. The evidence is in artifact
`14422436208` from [run 44284634068](https://github.com/jihuayu/rootyard/actions/runs/44284634068).
Later compositions require fresh exact-head hosted verification.

### Required five real Vault cases

The actual fixture CLI on this source is `tests/pando_vault_rotation.py`. It
accepts an existing `rootyard-pando-lab` binary and native-build receipt, a clean
source root, the exact expected commit and a report path:

```sh
python3 tests/pando_vault_rotation.py \
  --binary "$ROOTYARD_PANDO_LAB_BIN" \
  --receipt "$ROOTYARD_PANDO_BUILD_RECEIPT" \
  --source-root "$PWD" \
  --expected-commit "$(git rev-parse HEAD)" \
  --report test-results/pando-vault-rotation.json
```

`--expected-binary-sha256` is an optional independently exported digest; its
actual flag is not `--build-receipt`, and the commit flag is not `--expect-commit`.
The harness loads the receipt with implicit builds forbidden and rechecks the
source commit/tree/clean state, binary, receipt and harness digest before and
after the cases. Its report schema is
`rootyard/issue21-derived-vault-rotation/v1`. Missing Docker, PostgreSQL 17,
Vault, binary or receipt fails; there is no skip path.

The harness has one absolute monotonic deadline established before input
validation. The CI step supplies `--timeout-seconds 1080` under its 1200-second
step cap and the default `--cleanup-reserve-seconds 90`; the work deadline is
therefore 990 seconds and cleanup may use the whole 1080 seconds. The deadline
is never reset per case, phase or operation. Existing per-operation caps are
only clamped to the remaining budget, and a late return from a non-preemptible
OS/filesystem/Popen/socket boundary fails closed rather than being recorded as
success. Source Git/receipt reads run in one bounded owned child; a timed-out
child, unresolved owned resource, failed final binding or failed report write
cannot produce a passing report.

The five exact authored IDs, in order, are:

1. `vault_fixture_and_app_capability_boundary`
2. `authentic_envelope_digest_and_cold_read`
3. `admin_rotated_target_interrupted_resume_and_new_write`
4. `wrong_key_ciphertext_envelope_and_provider_revocation_fail_closed`
5. `owned_resource_cleanup`

They use a digest-pinned real Vault image with a derived `aes256-gcm96` Transit
key, `min_decryption_version=1`, a random owned PostgreSQL 17 database and a
disposable owned root. The application token may read key metadata and
encrypt/decrypt/rewrap; it is denied master rotate, delete, config, token-admin
and policy-admin. The fixture administrator, never the app, creates the newer
master versions.

### Existing-target rotation, version pinning and readability

The rotation contract is the explicit existing-target contract
`existing-vault-version/v1`, not an automatic Vault master rotation:

* Initial real Git pushes produce packs sealed at Transit version 1.
* The admin pre-creates version 2. The app's rotate probe must receive `403` and
  leave `latest_version` at 2.
* A fresh CLI run of
  `kms-rotate "$REPO" --target-version 2 --fail-after-packs 1` fails after the
  first rewrap and leaves a DB-backed `IN_PROGRESS` checkpoint with target and
  expected version 2, positive `write_epoch`, one completed original pack and
  one remaining failed pack.
* At that midpoint, cold reads must still recover both an unrewrapped version-1
  pack and a rewrapped version-2 pack. This is the retained-version readability
  check for version 1 under the fixture's decrypt floor.
* The admin then creates latest version 3 while the checkpoint target remains 2.
  A real new push must commit a version-2 envelope, not latest version 3.
* `kms-rotate "$REPO" --resume` retains the same rotation identity and target 2,
  verifies every current pack and marks the checkpoint `COMPLETED`.
* A post-completion push while latest is still 3 must also write version 2. The
  DB loader selects the single completed checkpoint with the highest positive
  `write_epoch`; that durable completed checkpoint is the write pin. An
  ambiguous maximum completed epoch fails closed. Legacy Local completion rows
  at epoch 0 are ignored in favor of the Local policy file, but they are not a
  Vault positive-epoch pin.
* Vault `--revoke-previous` retention retirement is refused as unimplemented.
  The application never calls Transit rotate; only the fixture admin does.

### DB authority, mirror repair and cold-cache checks

The complete pair in `pando_lab.object_store_manifests` plus
`pando_lab.kms_envelopes` is checked as authority for DB-backed
publication/recovery and remote S3 reads. The local CAS `object-store-get` path
is narrower: a digest-matching warm pack/index cache returns `verified` before
any manifest or DB envelope lookup. On a cold cache it reads and validates the
local CAS manifest plus the exact stored ciphertext SHA-256/length, then loads
the DB `kms_envelopes` record through `load_authoritative_envelope` using the
repository pack/index digests; it does not query
`pando_lab.object_store_manifests`. `$PANDO_ROOT/object_store/envelopes/<repo>/<pack>.json`
is a post-commit mirror, not a fallback authority. The fail-closed
missing-DB-envelope/no-mirror-fallback guarantee applies to cold hydration
(cache miss); the verified file-only path is reserved for raw helpers without a
DB client. A cold local read repairs a missing or damaged mirror from the DB
envelope best-effort after verification.

Before a cold probe the fixture evicts only the exact owned pack/index cache and
then requires the cache to remain absent after a rejected read. Because it
evicts before every provider probe, the five authored cases' cache/provider
failure evidence is cold-hydration only; they do not establish warm-cache
provider revocation or whole-KMS access-control runtime behavior. A successful
cold read rechecks the immutable manifest digest, the exact stored ciphertext
SHA-256 and length, the DB envelope's ciphertext identity and MAC/wrapped-key
binding, decrypts the authenticated pack, and rechecks the plaintext SHA-256,
length and object count before caching. Changing only `envelope_mac`, changing
only the DB ciphertext digest, flipping stored ciphertext, or using a usable
wrong scoped key must fail without creating a plaintext cache or replacing CAS
bytes.

### Separate 17 Local PostgreSQL producer tests

The five Vault cases do not include, and `pando_vault_rotation.py` does not run,
the separate Local-provider PostgreSQL producer contract: exactly 17
`#[ignore]`d tests in the existing `rootyard-pando-lab` bin unit-test harness
(7 migration, 5 repack, 5 snapshot). The full IDs are listed in
[`experimental/pando/README.md`](../experimental/pando/README.md). They are
Local-provider PG tests, not additional Vault cases.

The mandatory gate runs each exact name serially in the existing PG17
job but in a separately owned random database initialized from
`experimental/pando/schema.sql`, with `PANDO_OBJECT_STORE_ROOT`,
`PANDO_KMS_KEYRING_DIR`, `PANDO_KMS_PROVIDER` and
`ROOTYARD_OBJECT_STORE_ENDPOINT` absent before any DB/root creation. It resolves
the existing Cargo bin-test executable for `rootyard-pando-lab`, not the normal
CLI executable or the library-test harness. The runner, its source-bound report
and the workflow wiring are integrated in this source: the existing verify job
runs the 17-case runner as a mandatory bounded step, and separately runs the
five-case Vault harness, strict adapter and Pando-specific native manifest as a
mandatory bounded step.

### Remote S3, claims and uncovered cases

The five Vault cases run local CAS only; their report limitations include
`local_cas_only` and `s3_rotation_unsupported`. This is not a generic ban on
S3. Normal standalone remote S3-compatible `object-store-put`,
`object-store-get` and `object-store-verify` remain implemented and keep their
DB/manifest/envelope behavior. What is unsupported is the composed remote path:
`kms-rotate` refuses while the remote object-store endpoint is enabled, the
encrypted prepared Git-hook publication rejects that backend, and the migration
prepared-publication and a compacted repack with object-store sync fail closed
rather than stage remote authority and commit it in one SQL transaction.

No CloudHSM/HSM service, FIPS 140 validation, production durability or
availability, or cross-process GC/destructive collection guarantee is claimed.
The five cases also do not cover two original plan-level negative scenarios:
a valid envelope mirror retained while the authoritative DB envelope row is
missing (the no-mirror-fallback missing-DB-row probe), and a valid scoped token
that can read key metadata but is denied decrypt. They do not qualify every
migration/repack/snapshot producer or the full derived-Vault Astra matrix.
