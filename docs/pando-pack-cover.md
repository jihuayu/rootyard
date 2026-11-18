# Pando / Causal Ref-Version & Tiered Pack-Cover Fetch Planner (Issue #184)

> **Status**: Implementation & verification contract for Issue #184 (`Refs #184`).  
> **Depends on**: [`docs/ref-version-pack-contract.md`](./ref-version-pack-contract.md) (`#180` ref-version closures, `#183` verified dependency closure, `#162` non-destructive compaction covers, `#164` pack-size/latency workloads).

## 1. Scope & Module Layout

The `pack_cover` subsystem lives under [`src/ref_store/core/ref_version/pack_cover.rs`](../src/ref_store/core/ref_version/pack_cover.rs) and is re-exported cleanly from [`src/ref_store/core/ref_version/mod.rs`](../src/ref_store/core/ref_version/mod.rs):

| Module | Responsibility |
| --- | --- |
| [`model.rs`](../src/ref_store/core/ref_version/pack_cover/model.rs), [`model_codec.rs`](../src/ref_store/core/ref_version/pack_cover/model_codec.rs) | Immutable `CoverHierarchyRecord` (`ry-pack-cover-record-v1`), `CoverTier` (`Base` / `Delta` / `Compacted`), membership digest (`compute_cover_membership_digest`), epoch/membership CAS index (`CoverHierarchyIndex`) |
| [`retention_class.rs`](../src/ref_store/core/ref_version/pack_cover/retention_class.rs) | Explicit 3-state retention classification (`PhysicallyPresent`, `PlannableForFetch`, `GcEligible`), hold aggregation, and rejection of TTL/cache/async-projection deletion hints |
| [`auth.rs`](../src/ref_store/core/ref_version/pack_cover/auth.rs) | Live per-request `AuthorizationContext`, ref-visibility filtering (`advertise_authorized_refs`), default `StrongSnapshot` isolation, and typed `StrongSnapshotFallback` transitions |
| [`planner.rs`](../src/ref_store/core/ref_version/pack_cover/planner.rs), [`planner_select.rs`](../src/ref_store/core/ref_version/pack_cover/planner_select.rs) | Causal `have/want` + `ref_version` + cover planner (`plan_fetch_covers`), delta-base expansion, topological ordering, deep-lag fallback pass, and bounded closure limits |
| [`verifier.rs`](../src/ref_store/core/ref_version/pack_cover/verifier.rs) | Independent closure proof verifier (`verify_fetch_plan_closure`) issuing unforgeable `VerifiedFetchPlanProof` (no `Clone`, no `Deserialize`) |
| [`blob_verify.rs`](../src/ref_store/core/ref_version/pack_cover/blob_verify.rs) | OpenDAL `BlobStore` + `DisposableViewRoot` + stock `git` (`SHA-1` & `SHA-256`) materialization (`verify-pack -v`, `index-pack --stdin --fix-thin --strict`, `fsck --full --strict`, `rev-list --objects`) |

---

## 2. Compaction Cover Hierarchy & Concurrency Fencing

Compaction creates higher-tier immutable packs without mutating or prematurely deleting active base/delta packs. Every `CoverHierarchyRecord` is sealed over canonical bytes (`ry-pack-cover-record-v1` domain separator) binding:

- exact `(tenant_id, repository_id, history_incarnation, object_format, authority_kind, authority_epoch)`,
- `compaction_epoch` and `membership_generation`,
- exact `membership_digest` computed deterministically from `(realm, generation, sorted pack entries)`,
- sorted unique `covered_versions`, sorted `covered_commits` with parent links, and sorted unique `input_cover_ids`.

Concurrency races are fenced in `CoverHierarchyIndex::publish_compacted_cover`:

1. **Stale worker fencing**: `expected_epoch != self.compaction_epoch` or `expected_membership != self.membership_digest` is rejected with `CoverModelError::StaleCompactionWorker` or `CoverModelError::MembershipConflict` — stale workers can never overwrite or retire newer covers.
2. **Idempotent retry safety**: Re-publishing a compacted cover with the same `cover_id`, identical `record_digest`, and matching CAS fence returns `CompactionPublishOutcome::AlreadyPublished`. Conflicting digests for an existing `cover_id` fail closed.
3. **Zero hidden-version drops**: Every `VersionId` covered by any input cover must appear in the compacted cover's `covered_versions` (`CoverModelError::CoverageDrop`).
4. **Retire-after-durable-publish**: Leaf/delta covers can only be marked `retired_from_active` after their replacement compacted cover is already registered and membership-verified.

---

## 3. Explicit 3-State Retention Classification

Planner visibility and physical garbage collection are intentionally decoupled in [`retention_class.rs`](../src/ref_store/core/ref_version/pack_cover/retention_class.rs). Physical deletion stays solely owned by `PHYSICAL_GC_OWNER` (`#122/#151/#153`). Each immutable cover carries an explicit `PackRetentionClassification`:

| State | Meaning | Planner / GC Consequence |
| --- | --- | --- |
| `PhysicallyPresent` | Physical pack/idx exists, but active holds prevent retiring, quarantine/pending hold bars serving, or `AuthorityHoldSnapshot` is missing/incomplete | `plannable_for_fetch == false`, `gc_eligible == false`; fails closed against GC and triggers fallback instead of serving unsafe cover |
| `PlannableForFetch` | Physically present, verified, and free of quarantine or unknown pending exclusion holds | Eligible for `plan_fetch_covers` selection and proof verification |
| `GcEligible` | Zero active holds, explicit complete non-zero `AuthorityHoldSnapshot`, and `cover_id` explicitly listed as retired | Never plannable; safe handoff input for `#122/#151/#153` GC |

**Hard Non-Inference Invariant**: `RetentionClassificationIndex` explicitly rejects deletion or un-pin decisions sourced from `TtlExpired`, `CacheEvicted`, or `AsyncProjectionLag` hints (`NonAuthoritativeHint`) and refuses `GcEligible` whenever authoritative completeness (`AuthorityHoldSnapshot::complete`) or explicit retirement is absent, preventing silent data loss when async views lag or authority state is partial.

---

## 4. Authorization & Strong-Snapshot Isolation

1. **Live per-request auth validation**: Every planning and verification call validates `AuthorizationContext::validate` — nil tenant/repo/history/actor/token IDs, `revoked == true`, stale `auth_epoch < min_valid_auth_epoch`, tenant mismatches (`TenantMismatch`), and repo/history mismatches (`RealmMismatch`) fail closed.
2. **Hidden-ref filtering & anti-oracle checks**: `advertise_authorized_refs` strips invisible refs and tombstones. Requesting an unauthorized `WantTarget` returns `FetchPlanError::HiddenRefDenied`. Candidate covers that bundle commits reachable only from unauthorized refs cannot be reused across tenants or privilege boundaries; when `allow_strong_fallback == true`, the planner falls back via `FallbackReason::SharedCoverExposesHiddenObjects`, otherwise failing closed.
3. **Default `StrongSnapshot`**: `ReadIsolationMode::StrongSnapshot` is the default (`Default` impl) for clones, smart HTTP fetches, PR diffs, CI, and backups, requiring an exact `StrongSnapshotCut` matching `membership_digest`, `cut.authority_seq > 0`, and `key == head.ref_name()` plus matching realm/sequence across cut ref heads. `VersionClosure` (single ref / historical pin) and `VersionSet` (`CrossRefCompare` with explicit `allow_non_common_time_set`) require explicit opt-in.

---

## 5. Failure Handling & Fail-Closed Fallback

The planner never silently serves an unverified partial cover or falls back without labeling it:

- Missing base cover (`MissingBaseCover`), digest/seal tampering (`TamperedCoverDigest`), missing/quarantined retention (`RetentionLost`), membership drift (`MembershipDrifted`), closure/work-budget violations (`ClosureBoundsExceeded` exceeding `MAX_CLOSURE_PACKS`, `MAX_CLOSURE_ARTIFACTS`, `MAX_CLOSURE_VERIFIED_BYTES`, `MAX_PLANNER_INDEXED_COVERS`, `MAX_PLANNER_INDEXED_LINKS`, or `MAX_PLANNER_SCORING_STEPS`), or hidden-object exposure (`SharedCoverExposesHiddenObjects`) either emit `FetchPlanOutcome::FallbackToStrongSnapshot` (if `allow_strong_fallback == true`) or return a typed `FetchPlanError` (`allow_strong_fallback == false`).
- `verify_fetch_plan_closure` independently recomputes the plan digest, enforces `validate_strong_cut`, verifies every pack closure via `verify_dependency_closure`, enforces exact `delta_base_cover_ids` ordering, and checks live retention/auth before minting `VerifiedFetchPlanProof` bound to `(actor_id, token_id, auth_epoch)`.
- `materialize_and_verify_fetch_plan` re-validates live `AuthorizationContext` (`binds_live_auth`, revocation, epoch, ref visibility) before allocating a `0o700` `DisposableViewRoot` lease, attaches `Arc<TempViewLease>` across OpenDAL `BlobStore::get_to_file_with_owner` so detached timeouts preserve the reservation and view directory until cleanup settles, resolves `--thin` packs via `git index-pack --stdin --fix-thin --strict`, validates self-contained packs via `git verify-pack -v`, checks full object integrity via `git fsck --full --strict`, and verifies object reachability via `git rev-list --objects`.

---

## 6. Reproducible Verification & Benchmark Semantics

- Integration suite: [`tests/pando_pack_cover.rs`](../tests/pando_pack_cover.rs) exercises Loopback S3 OpenDAL + `DisposableViewRoot` + stock `git` (`SHA-1` & `SHA-256`), `--thin` delta base resolution, S3 corruption/deletion fault injection, `QuarantineHold` fallback, `Atomic` vs `AcceptedSubset` ref batches, hidden refs, revoked auth, cross-tenant, and `VersionSet` isolation.
- Unit & matrix suite: [`tests.rs`](../src/ref_store/core/ref_version/pack_cover/tests.rs), [`tests_matrix.rs`](../src/ref_store/core/ref_version/pack_cover/tests_matrix.rs), [`tests_git_blob.rs`](../src/ref_store/core/ref_version/pack_cover/tests_git_blob.rs), and [`tests_safety.rs`](../src/ref_store/core/ref_version/pack_cover/tests_safety.rs) verify model sealing (`covered_versions` vs commit-link consistency), compaction CAS fencing, 3-state retention holds + `AuthorityHoldSnapshot` completeness, forged `StrongSnapshotCut` key/realm/seq rejection, aggregate planner work budgets, live materializer auth revocation, `Arc<TempViewLease>` detachment ownership, criss-cross multi-merge topologies, deep lag compaction, historical pins, and non-fast-forward resets against OpenDAL S3 + stock `git`.
- Workload benchmark: [`scripts/eval_pando_pack_cover.py`](../scripts/eval_pando_pack_cover.py) runs stock `git` benchmarks across mixed workloads (`SHA-1` & `SHA-256`) and reports `selected_packs`, `transferred_bytes`, `metadata_reads`, measured `plan_cpu_p50_p95_p99` (`p50_ms`, `p95_ms`, `p99_ms`), `write_amplification`, and `old_new_pack_physical_bytes`.

### Explicit Non-Claims

1. **No theoretical $O(\log \Delta)$ bound**: Cover selection is bounded by the actual repository cover graph (`MAX_CLOSURE_PACKS`, `MAX_CLOSURE_ARTIFACTS`) and real measured CPU/transfer metrics rather than unverified asymptotic claims.
2. **No physical storage savings without `#122` GC**: Compaction reduces `transferred_bytes` and `selected_packs` for serving, while `old_new_pack_physical_bytes` honestly accounts for both active compacted covers (`newly_written_compacted_bytes`) and retained retired delta packs (`retained_old_pack_bytes`) until `#122/#151/#153` executes GC.
3. **No unverified external benchmarks**: All numbers in CI artifacts come directly from local stock `git` execution in [`scripts/eval_pando_pack_cover.py`](../scripts/eval_pando_pack_cover.py).
