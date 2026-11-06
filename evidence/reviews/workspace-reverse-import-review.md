# Independent reverse View importer review

Reviewed workspace commits `b0a5ff9`, `92f7ff5`, and `1f8a5fd` in `/workspace/rootyard-workspace`.

## Native checks

- Before the ref-guard fix, `python3 -m unittest tests.test_namespace_service -v` passed 1/1 against binary SHA-256 `6c9b708225c0292dabb2d972ace458adb2c662f988d17e2094082be69396a09a`; the separate compiled Rust test `namespace_service::reverse::reverse_git::tests::cat_file_drains_more_than_pipe_capacity` passed with 60,000 object IDs in 0.88s.
- After `1f8a5fd`, reran the same native service suite against rebuilt binary SHA-256 `9beb9e5d61570117bf2c0b8f583204fb9c38bdba11a5a923b1638ea32efc2b14` — PASS 1/1. It created the ChangeSet pin at the expected OID; authenticated Git delete and force-update, plus public ref-transaction delete and update, were rejected; the pin remained unchanged and integration completed.

The original `git_input` deadlock is fixed by concurrent stdin writing and stdout draining. Output is capped; Git runs in a process group with a 60s watchdog and CPU, address-space, and per-file limits. Request/bundle, object, view, source, and staged-store checks are explicit, and docs disclose that aggregate temporary disk use during unpack has no strict quota.

## Resolved pin-protection finding

Before `1f8a5fd`, an ordinary authenticated Git push deleted `refs/heads/rootyard-proposals/<uuid>`. The fix reserves that prefix in shared public-ref validation and journal receive-pack validation, and permits only a crate-private create-only operation for an exact generated UUID pin with zero old OID. The native test covers deletion and replacement through both Git and API paths. No further issue found in the pin guard.

The importer still does not provide crash-atomic publication across ciphertext/object, pin ref, and ChangeSet metadata. Its docs disclose that proposal-pin cleanup and aggregate temporary disk quotas remain deployment work; this is not a full namespace/View acceptance claim.
