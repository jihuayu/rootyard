# Independent Vault 9287037 re-review

Used the live Vault fixture from `/tmp/rootyard-vault-test/env` without printing or recording credentials. Executed the compiled native integration test binary `/workspace/rootyard-storage/target/debug/deps/encrypted_objects-b250764b18c7b5c7` in isolated fixture root `/tmp/rootyard-vault-review-928`:

- `ROOTYARD_KMS_TEST_PHASE=publish ... --exact vault_pack_encryption_rotation` — PASS against live Vault. The test exercises >12 MiB AES-GCM chunking, missing envelope-parent failure with no final ciphertext, retry after parent creation, exact decrypt, key rotation, old/current envelope reads, and tamper rejection.
- `ROOTYARD_KMS_TEST_PHASE=recover ... --exact vault_pack_encryption_rotation` in a second process — PASS; old and current generations decrypted to identical bytes.

Commit 9287037 fixes the prior ordinary filesystem-error retry poison: it creates the envelope directory before final ciphertext publication and removes ciphertext/metadata on returned errors. It also clears DEKs on wrap failure and when the second unwrap during rotation fails. The adapter still lacks crash atomicity across ciphertext/envelope paths; a process crash after ciphertext rename and before envelope/CURRENT publication can strand an object. Pando publication/manifest integration remains required for closure.

## Remaining key hygiene finding

`data_key.fill(0)`, `old_key.fill(0)`, and `new_key.fill(0)` are manual cleanup. An async future dropped/cancelled while awaiting I/O or Vault may skip those statements, and ordinary `fill` is not a guaranteed non-optimizable zeroization primitive. `VaultTransit::unwrap` also materializes the DEK in response JSON/base64 `String` and decoded `Vec` buffers that are dropped without clearing. Use a directly declared `zeroize` dependency and RAII `Zeroizing` wrappers for key arrays and transient plaintext buffers to make cleanup survive cancellation and all early returns. This remains an adapter-only review; no end-to-end Pando pack encryption claim is made.
