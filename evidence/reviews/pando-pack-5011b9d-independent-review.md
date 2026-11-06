# Independent review: encrypted Pando pack CAS foundation

Reviewed storage commits `5011b9d` and `6c2042a` (`PackStore` and migration 073), plus the corresponding root integration commits `1c8b36d` and `971f364`. This is a storage foundation review only; it does not approve Pando gateway cutover.

## Findings

**Resolved in `e47512f`: SHA-256 format-aware verification.** The original `verify_git_pack` ran `git index-pack --verify <pack>` without a repository object-format context. A native Git 2.52 SHA-256 fixture showed the context-free call failed with `wrong index v2 file size`, while an in-repository call succeeded. The fix initializes an isolated bare repository with the declared `sha1`/`sha256` format and passes it to `index-pack`; the independent live SHA-256 publish/recovery below passes.

**Resolved in `e47512f`: private plaintext scratch.** `from_env` now creates and validates owner-only 0700 work roots, per-operation dirs are 0700, and `decrypt_file` creates plaintext files mode 0600. An independent live fixture measured the recovered pack and index at 0600. Crash residue remains in private scratch until cleanup; there is no startup scavenger in this slice, so disk cleanup after process crash is still an operational follow-up.

**Generation race still needs closure before publish is wired.** `publish` performs an autocommit `INSERT ... SELECT ... WHERE storage_generation=$expected`, but it does not lock the repository row. A concurrent non-key generation update can commit after the statement snapshot and before the manifest insert commits; the FK key-share lock is compatible with the non-key update lock. The executor’s wrong-input-generation test does not exercise this interleaving. Acquire `SELECT ... FOR SHARE` and insert in the same final transaction after remote verification, then add a two-connection PostgreSQL regression. The no-cutover test scope keeps this an integration gap today.

## Verified properties

- `RemoteObjectStore::put_file` hashes local source data, uploads, checks `HEAD`, then downloads to a temporary file and verifies exact size and SHA-256 before returning. The pack-store inserts its PostgreSQL manifest only after both ciphertext/envelope pairs return successfully, so a partial remote upload cannot create a ready manifest.
- The manifest insert filters on current repository ID, tenant owner, generation, object format, and ready state. A wrong-generation call is rejected after remote upload without adding a row; those orphan remote objects are a storage-GC concern, not a false ready publication.
- I tested a pack paired with an unrelated `.idx`: Git 2.52 `index-pack --verify` fails when the sibling index is mismatched, so that command does validate the pair in the supported SHA-1 context. This is not a separate defect.
- Live Garage/Vault/PostgreSQL publish and restart-recovery report from the executor: `/workspace/shared/storage-pando-encrypted-pack-report.json`, source commit `6c2042a`, test binary SHA `4c2e28e0439f3df2d3c5d14f1435d54a52b2c7ab243213fc4b4f506e71dde0db`. It proves SHA-1 pack publish/recovery and wrong-generation rejection, not SHA-256 behavior or crash confidentiality.

## Validation performed independently

- Native Git 2.52 SHA-256 bare repository and repacked pack/index fixture: in-repository `index-pack --verify` passed; context-free verification failed with the error above. A mismatched sibling index was rejected.
- Verified the storage-built test binary SHA `c23e4c91832924f7e16e00709a96ad38ad45a95cf6c4e6cae4e47489840f3fb3` matched the executor’s report, then independently ran its live Garage/Vault/PostgreSQL SHA-256 publish and separate-process recovery phases in a fresh fixture. Both passed; PostgreSQL refs materialized into a disposable snapshot and native Git `fsck` passed. Report: `/workspace/shared/reviews/pando-pack-e47512f-independent.json`.
- The executor’s combined SHA-1/SHA-256 report is `/workspace/shared/storage-pando-encrypted-snapshot-report.json`; I independently repeated SHA-256 only.

## Status

The SHA-256 and confidentiality findings are fixed and independently re-tested. Keep crash-time stale scratch cleanup and the publication-generation race open. The test seeds Pando serving state directly, so the authenticated main gateway integration and production cutover remain unproven; do not close #21 from this foundation alone.
