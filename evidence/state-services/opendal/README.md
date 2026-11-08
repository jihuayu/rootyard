# #108 Blob component and legacy-path qualification (b8e6fc6)

These are the source-bound reports behind `docs/opendal-blob.md` at commit
`b8e6fc67337acb4c0109ea082ae99bafb488d746` ("b8"). They qualify the newest
OpenDAL `BlobStore` component and the legacy content-addressed paths that the
component is replacing. They do not complete #108.

All reports are copied verbatim from the operator's staging directory. Nothing
in them was edited. The JSON contains absolute operator build paths
(`/workspace/...`, `/tmp/rootyard-*`); those are build/fixture locations, not
credentials. No keys, tokens, passwords or private wrapper paths are included.

## Results at b8e6fc6

| Evidence | What passed | Scope / limits |
| --- | --- | --- |
| `state-blob-provider-native-v9.json` | New unique-attempt S3 contract: 1 real case, **1 passed, 0 ignored** (separate executable `blob_provider_contract`) | 21 MiB multipart publish, distinct attempt paths for identical bytes, independent read-back, verified download/range, corruption/truncation refusal, product-delete refusal. One loopback S3-compatible host, one physical host. Azure not runtime-qualified. |
| `state-blob-full-library-v9.log` | `cargo test --lib`: **283 passed, 0 failed, 8 explicitly ignored** | Library/unit invariants only; not provider qualification. The log does not echo a commit. |
| `state-blob-two-mib-stack-v9.log` | `legacy_s3_operator_polls_on_two_mib_worker_stack`: **1 passed** | Proves the type-erased legacy S3 operator survives a 2 MiB worker stack; it is the regression gate for the v8 stack-overflow failure. |
| `state-blob-legacy-s3-v9.json` | Legacy `RemoteObjectStore` S3: `s3_streaming_cycle` **publish and recover each passed in a separate process** (two independent invocations of the same source-bound test binary; 20 MiB + 4-byte tail: 320 × 64 KiB + 4) | One loopback S3-compatible host, one physical host. Publish verifies wrong-digest refusal and ranged read; recover re-opens the persisted locator, rejects a short read and deletes only the fresh fixture key. No physical-durability or HA proof. |
| `state-blob-legacy-publication-v9.json` | Source-bound native Pando workload: **41/41 cases passed**; operation registry audit **18 total / 18 committed / 0 pending / 18 terminal** | Ordinary Git pushes against loopback PostgreSQL/Garage/Vault on one physical host. Not synchronized old-OID CAS, not client retry-idempotency, not distributed RefStore, not HA or RPO/RTO. |
| `state-blob-legacy-lfs-v9.json` | Stock Git LFS **remote-only pointer push** then recovery after source-volume loss: **1/1 passed** | Replacement-volume recovery on the same host. Not two physical hosts, not LFS lock/HA qualification. |
| `state-blob-final-clippy-v10.log` | All-target Clippy at b8: log ends `Finished`, no errors/warnings | The log does not echo its argv, so flag-level scope follows the operator invocation; no diagnostics were produced. |
| `state-blob-doc-contract-v10.log` | Doc contract: **2 compile-fail doc-tests passed, 0 failed** (`UploadIntent` clone and forge-from-locator examples) | Doc-tests only. |
| `*.build.json` (5 files) | Source-bound build receipts for the executable, library and three test binaries | See hash table below. |
| `native-publication-runner.py` | Exact runner used for the Pando report (`runner_sha256` in the report matches this file) | Static harness code only; no credentials. |
| `state-blob-legacy-publication-v8.json` | **Historical failure, retained unchanged** | Source `3257358` / binary `9f0e1d46...`; first 6 setup cases passed, then the first Pando push failed after the server process disappeared (client saw connection refused). The server-side cause was diagnosed as a Tokio stack overflow in the deeply nested OpenDAL layer stack; `719c7cc` type-erases the layers (`operator.finish()` before applying custom layers) and bounds the async stack. The same workload was re-qualified successfully at b8 above. This file is a counterexample, not a b8 result. |

## Hash and command table (from the receipts)

| Artifact | Binary SHA-256 | Inputs |
| --- | --- | --- |
| `rootyard` (application binary) | `5b1bca4e0b20cce7970c65147e7ab875f6007d89a6c1c32e3370b351cf3d9a1f` | source digest `7d8fda90...`; lock `92f76a2d...` |
| `rootyard` library test build | `b37da9125c1930f3456496a982ae4f5a9998a4ecff9b01d40698f44e9ffb66a6` | source digest `7d8fda90...` |
| `blob_provider_contract` | `936236eb013f55dfe683a0863a4d2a6cb5bef936d4c2b627d5dc7f4022829f6d` | test source `7897c829...` |
| `legacy_s3_stack` | `ecaaa83dd3f23bf2cdbd25752de011cb29b454acd9ecaa5cf9b06c03c9f77e0a` | test source `ffd77747...` |
| `remote_objects` | `89e6f147dc82358f270724b4dd724596f40ebdb463d9cdc96f66504a8b486d44` | test source `4535d96f...` |

All five receipts share `workspace_commit` b8e6fc6, source-inputs digest
`7d8fda90ba516390ff4a612b707fee9c3540fba26d9b8f8505d83448ff4833cb`, lock
`92f76a2deabe9da8a3186aedd7607d40b1f7dfb1ff83bdaf56a1f54e5d139c48` and rebuild
the package with:

```
cargo --config profile.dev.package.rootyard.debug=0 \
      --config profile.test.package.rootyard.debug=0 \
      --config 'profile.dev.package.rootyard.strip="debuginfo"' \
      --config 'profile.test.package.rootyard.strip="debuginfo"' \
      test --locked --lib --test legacy_s3_stack --test remote_objects \
      --test blob_provider_contract --features blob-azblob --no-run \
      --message-format=json-render-diagnostics
```

`source_inputs_sha256` is `scripts/build_native.py::source_digest()` over
`Cargo.toml`, `Cargo.lock`, and the files under `src/`, `migrations/`,
`schema/` and `vendor/`. The receipts assert the artifact was rebuilt
(`fresh: false`) and relocated without changing its hash.

The gzip archives of the relocated binaries are not committed (about 56 MiB).
`binary-archives.sha256` records their exact archive hashes; at evidence time
each decompressed stream matched the corresponding `binary_sha256` above.

## Reproduce

1. Check out b8e6fc6 clean and provide a trusted build receipt. The provider
   test is only evidence when its `.build.json` is present and its
   `binary_sha256` and `source_inputs_sha256` match the executable and the clean
   tree.
2. Configure a disposable S3-compatible fixture in the private environment:
   `ROOTYARD_OBJECT_STORE_ENDPOINT`, `ROOTYARD_BLOB_*` credentials,
   `ROOTYARD_S3_TEST_FIXTURE` (a writable per-run path) and
   `ROOTYARD_S3_TEST_PHASE`. Use fresh keys/tenant identities only; never
   commit the values.
3. Run the real provider case:
   `./blob_provider_contract --ignored --exact real_provider_publish_verify_range_delete_contract --nocapture`.
   Missing configuration must fail, not pass.
4. Run the legacy two-process cycle:
   `./remote_objects --ignored --exact s3_streaming_cycle --nocapture` once
   with phase `publish`, then again with phase `recover`, using the same
   `ROOTYARD_S3_TEST_FIXTURE`.
5. With configured loopback PostgreSQL, Garage/S3 and Vault, run
   `python3 native-publication-runner.py --binary <path>/rootyard
   --source-root <checkout> --report <out>.json`. The runner requires
   `rootyard.build.json` beside the binary and refuses hash/source mismatch.
6. `cargo test --lib` and `cargo clippy --all-targets --features blob-azblob`
   reproduce the library, stack and lint gates.

All test data is synthetic: random tenants/digests, fixture-only buckets and
generated 64 KiB block payloads. No production content is used.

## Boundaries (unchanged)

Azure is a compile-only optional feature; the real runtime case is S3 only.
Provider `write_with_if_not_exists` was observed to return success for a
duplicate multipart completion, so native conditional create is **unqualified**
and is not the uniqueness mechanism: opaque one-use `UploadIntent`s are.
New-profile deletion is always disabled (`DeleteDisabled`), and
`ROOTYARD_BLOB_DELETE` is rejected. This evidence does **not** qualify all
content classes, standalone deployment, HA, physical durability, a KeyProvider,
or GC/hold protocols. Production still uses the legacy Vault-backed profile;
the new serving profile remains disabled. #109, #110 and #112-#123 remain open.
