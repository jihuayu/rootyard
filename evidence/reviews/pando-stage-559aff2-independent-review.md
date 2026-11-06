# Pando stage refs-only pack review — 559aff2

Status: **pass for the staged-pack primitive**, with no production HTTP gateway cutover claim.

Reviewed `/workspace/rootyard-storage` commit `559aff2009f2f8de8bbd3726289f9b4e83a7a68b` (`Reuse committed Pando packs for refs-only pushes`). The change retains source pack IDs on `Snapshot`, verifies changed refs in a private bare repo containing only the immutable source pack set, avoids republishing on branch-copy and deletion-only updates, and verifies a new pack alone contains the changed refs before upload. Pack-set verification uses `fsck --full --strict`; verify directories are mode 0700 and removed on normal return.

Independent native validation used the live Garage, Vault and PostgreSQL fixtures with SHA-256 Git repositories, against the committed source and Cargo test executable SHA-256 `5e060dda9d8412e9c52a775cf024154a72ae98895281bc4235d022223d62e38e`:

- `ROOTYARD_PANDO_TEST_PHASE=publish ROOTYARD_PANDO_TEST_OBJECT_FORMAT=sha256 cargo test --test pando_gateway_pack -- --nocapture` — PASS (1/1).
- Restarted the Garage service, then `ROOTYARD_PANDO_TEST_PHASE=recover ROOTYARD_PANDO_TEST_OBJECT_FORMAT=sha256 cargo test --test pando_gateway_pack -- --nocapture` — PASS (1/1, 28.01s).

The recovery run exercised remote-only encrypted pack recovery, materialized an authoritative snapshot, exported and re-imported encrypted backup closure after remote deletion, then exercised stock Git clone/push, new-content staging, refs-only branch copy, and deletion-only staging. Source tree had unrelated uncommitted work in `db.rs`, `git_http/protocol.rs`, `pando_gateway.rs`, `migrations/075_pando_operation_sequence.sql`, and `pando_gateway/publish.rs`; the reviewed files themselves match commit `559aff2`.

Remaining scope limit: these tests validate staging and recovery primitives using the native Rust service and live PG/Garage/Vault, but do not prove the production authenticated HTTP write path has been cut over to this gateway or that crash cleanup removes private verify scratch directories.
