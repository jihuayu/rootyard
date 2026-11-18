# Streaming Git Push Ingestion & Causal Pack Proof (`Refs #183`)

## Architecture & Security Invariants

1. **Shared End-to-End Deadline Across pkt-line Commands & Pack Stream (`protocol.rs`, `gateway_stream.rs`, `src/blob_git_gateway/receive.rs`)**:
   - One total `deadline` governs both the Smart HTTP `receive-pack` pkt-line command framing (up to the `0000` flush) and the trailing `64 KiB`-chunked `PACK` v2 stream (both raw identity and single-member `gzip`).
   - Slowloris command-phase stalls fail closed on the shared deadline before any native Git subprocess, Blob I/O, or database transaction runs.

2. **Mandatory Verified Authority Snapshot Closure for Base Packs (`closure_prove.rs`, `git_verify.rs`, `gateway_bridge.rs`)**:
   - Every base pack and non-empty repository snapshot MUST carry a verified `#180` authority snapshot dependency closure (`verify_dependency_closure` / `ServingReadCapture::registered_snapshot()`).
   - Missing (`None`) or empty (`packs.is_empty()`) closures fail closed unconditionally (`UnauthorizedBaseDependency`), preventing unverified thin/delta base resolution.

3. **Full Commit Receipt Binding & Scoped-Decision + Durable-Hold PG/Raft Gate (`receipt.rs`, `pg_producer.rs`, `sm_executor.rs`)**:
   - `CausalPushProofReceipt` binds `(operation_id, snapshot, ticket, final_accepted_cas_subset)` (`rebind_final_cas_terminal` + `verify_commit_binding`), including partial `AcceptedSubset` outcomes (`Applied` + `NotApplied`).
   - PostgreSQL publication (`commit_push_on_pg` & `blob_git_gateway::receive`) gates every mutation on a live migration-144 scoped decision (`PgAuthorizedCommit` / `PgAuthorizedMetadata`) and migration-141 durable artifact holds (`PgArtifactHoldStore` + `ProtectedUploader`).

4. **Recoverable Reclaim Ledger & Stock-Git HTTP Acceptance (`reclaim.rs`, `tests/push_causal_stream/pg_http_gateway.rs`, `scripts/eval_push_causal_stream.py`)**:
   - Partial or `OutcomeUnknown` Blob uploads persist `0600` fsync-durable `BlobUploadReclaimRecord` entries (`QuarantineReclaimLedger`), refusing premature reclamation until operation abort is proven.
   - Verified end-to-end with stock `git` (`SHA-1` & `SHA-256`) over `crate::blob_git_gateway::router` + PG17 + `LoopbackS3` (`OverlappedPipeline` vs `#164` naive full-repo repack).
