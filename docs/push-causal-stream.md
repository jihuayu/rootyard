# Streaming Git Push Ingestion & Causal Pack Proof (`Refs #183`)

## Architecture & Security Invariants

1. **Shared End-to-End Deadline Across pkt-line Commands & Pack Stream (`protocol.rs`, `gateway_stream.rs`, `src/blob_git_gateway/receive.rs`)**:
   - One total `deadline` governs both the Smart HTTP `receive-pack` pkt-line command framing (up to the `0000` flush) and the trailing `64 KiB`-chunked `PACK` v2 stream (both raw identity and single-member `gzip`).
   - Slowloris command-phase stalls fail closed on the shared deadline before any native Git subprocess, Blob I/O, or database transaction runs.

2. **Mandatory Verified Authority Snapshot Closure for Base Packs (`closure_prove.rs`, `git_verify.rs`, `gateway_bridge.rs`)**:
   - Every base pack and non-empty repository snapshot MUST carry a verified `#180` authority snapshot dependency closure (`verify_dependency_closure` / `ServingReadCapture::registered_snapshot()`).
   - Missing (`None`) or empty (`packs.is_empty()`) closures fail closed unconditionally (`UnauthorizedBaseDependency`), preventing unverified thin/delta base resolution.

3. **Authoritative PG Sequence, Post-CAS Snapshot & Durable Restart Replay (`receipt.rs`, `gateway_prover.rs`, `gateway_durable_replay.rs`, `pg_producer.rs`)**:
   - Production HTTP `receive-pack` executes object-level causal closure proving (`prove_gateway_incoming_pack_closure`) before CAS admission, refusing unresolved thin-pack delta bases or missing ancestor objects before any database or hold mutation.
   - `CausalPushProofReceipt` (`materialize_durable_gateway_receipt`) binds the actual PostgreSQL `ref_store_operations.sequence`, post-CAS `ref_store_publication_decisions.base_revision` snapshot, all `0..=8` `pack_pairs`, and final CAS subset (`PgAuthorizedCommit` + `PgArtifactHoldStore`), replaying byte-for-byte identically across full process restarts.

4. **Multi-Pair Recoverable Reclaim Ledger & Remote Sweeper (`reclaim.rs`, `reclaim_sweeper.rs`, `tests/push_causal_stream/pg_restart_and_reclaim.rs`)**:
   - `QuarantineReclaimLedger` records all `0..=8` staged `.pack`/`.idx` pairs; `sweep_gateway_reclaim_ledger` and `settle_aborted_gateway_reclaim` sweep 100% of unpromoted/partial/rejected remote staging packs once PostgreSQL proves terminal abort with zero active memberships or pins (`OverlappedPipeline` vs `#164` naive full-repo repack, `SHA-1` & `SHA-256`).
