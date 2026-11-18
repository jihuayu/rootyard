# Streaming Git Smart-HTTP Push & Pack Causal Dependency Prover (`Refs #183`)

This design and implementation slice delivers the verified write data path specified in **`#183`** (building atop `#107`, `#108`, `#112`, `#113`, `#114`, `#144`, `#151`, `#152`, and `#180`) inside `src/namespace_service/push_causal_stream/`.

## 1. Architecture & Fail-Closed Pipeline

1. **Bounded Smart HTTP Command Prefix (`protocol.rs`)**:
   - `decode_receive_pack_stream` reads `git-receive-pack` pkt-line headers over raw or single-member `gzip` streams in `64 KiB` chunks without buffering the pack payload on the Rust heap.
   - Enforces `max_command_bytes` (`128 KiB`), `max_commands` (`128`), `max_stream_bytes` (`128 MiB`), `GitObjectFormat` (`sha1` / `sha256`), and rejects `shallow` uploads (`ShallowRejected`) unless explicitly permitted.
   - Tracks `report-status`, `report-status-v2`, `side-band-64k`, `atomic`, `ofs-delta`, and `delete-refs`.
2. **Quarantined Pack Ingest (`quarantine.rs`)**:
   - `ingest_pack_to_quarantine` streams trailing pack bytes directly into a `0o700` per-push private `QuarantineSlot` (`incoming.pack` mode `0o600`), verifying `PACK` v2 magic, declared object count `<= max_pack_objects`, trailer checksum length, and rolling SHA-256.
   - `QuarantineSlot::sweep()` / `Drop` deterministically deletes temporary files and staging directories on both success and failure.
3. **Authorized Base Staging & Thin/Causal/LFS Verification (`git_verify.rs`, `closure_prove.rs`)**:
   - `verify_base_packs_and_dependencies` evaluates `#180` `verify_dependency_closure` against `RefVersionRealm` and `VersionGraph`, failing closed on foreign realms, retired versions, or un-authorized base packs.
   - `stage_and_index_quarantine_pack` downloads ONLY authorized base packs via `BlobStore::get_to_file` (with SHA-256 read-back verification) into an isolated bare repository view, runs `git index-pack --stdin --fix-thin --strict` and `git verify-pack -v` under POSIX `setrlimit` bounds (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, `RLIMIT_CORE=0`).
   - `verify_causal_closure_and_lfs` validates branch commit types, fast-forward/protected-branch rules, `git fsck --full --strict --connectivity-only`, `git rev-list` transitive closure, and Git LFS pointer byte proofs via `BlobStore::verify_receipt`.
4. **Overlapped Pipeline & Cryptographic Read-Back (`closure_prove.rs`, `quarantine.rs`)**:
   - Under `PackPipelineMode::OverlappedPipeline`, OpenDAL `BlobStore` pack+idx upload + full provider read-back closure verification (`BlobStore::verify_closure` -> `BlobClosureProof`) runs concurrently with deep Git closure and LFS verification (`tokio::try_join!`).
   - Never substitutes client claims, HTTP `200`, Blob `stat`, or ETag metadata for provider read-back proof.
5. **Dual-Authority Ref-CAS Gate & Hold Protection (`commit_gate.rs`)**:
   - Mints `CausalPushProofReceipt` binding `(tenant_id, repository_id, history_incarnation, authority_epoch, group_epoch, object_format, operation_id, base_snapshot_seq, resolved_thin_base_oids, required_ancestor_oids, base_closure_digest, blob_closure_digest, accepted_subset_digest, proof_digest)`.
   - `StateMachinePushExecutor` exercises the `#113` `AcquireHoldBatch`/`MarkHoldConsumed`, `#112/#152` `InstallScopedDecision`/`CloseAuthScope` auth barriers, and `CommitScopedRefs` (`CommitMode::Atomic` & `AcceptedSubset`).
   - `build_pg_commit_request` and `commit_push_on_pg` bind the same verified proof to `PgRefStoreCore::commit_refs` (`Atomic` & `AcceptedSubset`), keeping `OperationHoldGuard` in `ActiveHeld` across `CommitUnknown` until idempotent `recover_unknown_operation` settles.

## 2. Capability-Checked Ref Advertisement Safety

`build_push_ref_advertisement` never discloses unauthorized refs (`visible_to_principal = false`). Narrowing (`AdvertisementStrategy::NarrowedSharedBases`) requires verified client capability compatibility (`compatibility_proof_id`) and preserves shared bases, `HEAD`, `requested_targets`, stacked-branch parent refs, and `force-with-lease` refs; missing compatibility falls back deterministically to `AdvertisementStrategy::FullAuthorizedFallback`, while referencing an unauthorized base or lease ref fails closed (`UnauthorizedBaseDependency` / `AuthorizationDenied`).

## 3. Reproducible Benchmark & Verification (`#164` Parity)

[`scripts/eval_push_causal_stream.py`](../scripts/eval_push_causal_stream.py) compares `overlapped_stream`, `sequential_stream`, and `naive_full_repack` across `SHA-1` & `SHA-256` (`blob_put_bytes`, `blob_get_bytes`, `duplicate_materialized_bytes`, `peak_temp_disk_bytes`, `peak_rss_kib`, `hash_git_cpu_ms`, `P50/P95/P99`). Issue `#183` stays `OPEN` (`Refs #183`); distributed gateway wiring remains gated on `#164` calibration.
