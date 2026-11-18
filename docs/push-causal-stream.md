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

5. **Positive Durable Terminal-Abort Proof (`reclaim_sweeper.rs`, `tests/push_causal_stream/pg_reclaim_terminal_and_replay.rs`)**:
   - `is_operation_proven_aborted_and_unreferenced` requires POSITIVE durable PostgreSQL terminal-abort proof: `ref_store_operations.state IN ('rejected','cancelled')`, or — only when NO `ref_store_operations` row exists — a durable `ref_store_cancellations` row or a terminal `'REJECTED'`/`'CANCELLED'` `ref_store_publication_decisions` row.
   - A missing or still-`pending` operation row is never deletable, even with `0` references, so the quarantined record stays in `QuarantineReclaimLedger` and `0` S3 `DELETE`s are issued.
   - Positive proof additionally requires `0` live references across `ref_store_core_pack_memberships`, `ref_store_core_snapshot_packs`, `ref_store_core_serving_read_packs`, active (`state = 'active'`) `ref_store_core_root_heads`/`ref_store_core_root_packs`, and `ref_store_publication_decisions` in `'OPEN'`/`'CONSUMED'`.

6. **Strict Replay Zero-Write Contract (`src/blob_git_gateway/receive.rs`, `reclaim_sweeper.rs`)**:
   - `sweep_gateway_reclaim_ledger` runs strictly AFTER `operation::probe` resolves `Claim::Fresh`, so `Claim::Pending`, `Claim::Cancelled` and `Claim::Replay` never sweep. The sweeper also resolves the reclaim operator and requires an existing private ledger directory before opening the ledger, so a no-op sweep never creates `reclaim-*.json`.
   - An HTTP `Claim::Replay` is therefore 100% zero-write: `0` reclaim-ledger files or `modified()` timestamps changed, `0` PostgreSQL rows changed across the operation/decision/event/hold/membership/cancellation ledgers, and `0` S3 `PUT`/`DELETE` mutations.
