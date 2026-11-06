# Independent Vault Transit review: 855c7a0

Reviewed exact source commit `855c7a0132e2f95a7a049d177afd7bb0aa9b2165` in `/workspace/rootyard-review-vault`.

## Native checks run

Using the live Vault fixture via sourced environment (credentials not recorded or printed), exact native `cargo test --test encrypted_objects` in publish phase passed: 12 MiB+15-byte pack streamed through AES-256-GCM chunks, cleartext marker absent from ciphertext, decrypt round trip matched, master-key rotation/rewrap preserved old and current envelope reads, and tampered ciphertext was rejected without publishing plaintext. Test binary SHA-256 `91115f329af7f88bd073dbe715b12b0d2f4271f67073021c7fada60e8ae50a1f`.

The `recover` phase passed in a new test process against the same persisted fixture. No key-version revocation was attempted because revoking the shared Vault key version would affect other work.

## Finding: failed envelope publication leaves an unretryable ciphertext

I added a temporary isolated native regression test (removed after execution) that passes an existing ciphertext parent but an envelope directory whose parent does not exist. `encrypt_file` first renames the completed ciphertext into its final path, then `create_dir(envelope_dir)` fails. The ciphertext remains, no envelope/current pointer exists, and retry is rejected immediately by the initial `ciphertext.exists()` check. The test reproduced this exact outcome against live Vault and passed as a regression (`review_atomicity` binary SHA-256 `5255d2c43c1026e388f4e2c6d10ab91162fe0051eeacdd3d6b7171f188957d7e`). This can strand an object on ordinary metadata/storage failure after ciphertext publication. Publish ciphertext and envelope under one staged directory/manifest transaction, or clean up the ciphertext if metadata publication has not committed.

## Key handling

`encrypt_file` returns directly if `provider.wrap()` fails before calling `data_key.fill(0)`. `rotate_envelope` also returns early on either unwrap error without clearing any key already recovered. Replace manual cleanup with an RAII zeroizing wrapper so all error paths clear data keys; Rust does not guarantee that a plain `fill(0)` survives optimization.

The adapter remains a standalone module and is not yet integrated into Pando pack publication, so the live test verifies the adapter only, not end-to-end pack storage/encryption behavior.
