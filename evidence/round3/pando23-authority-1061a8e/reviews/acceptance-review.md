# Issue 23 acceptance review - Pando authority-scoped remote retention

**Verdict: ACCEPT_FOR_DOCUMENTED_MODE - closable_23 = true** (documented managed-authority / paired-archive mode)
Source: compiled 89ba6a8bad9f, harness f35285d9b106 (test-only 724b94c, f35285d); binary sha256 eb1e4a09bf1a9c24...; coordinator-status.json state=passed, 8/8 jobs.

## Criteria
### thresholds cause actual maintenance without a manual lifecycle API
**pass** - pando-service case automatic_compaction_and_cache passed with detail automatic_compaction=true, serving_packs=1, old_pack_manifests_retained=8, cache_hydrated_evicted_rehydrated=true, cache_tamper_recovered=true, backup_barrier_retried=true, non_ref_oid_survived_compaction_and_rollback=3e951da0. Compaction and cache work were driven by the scheduler/threshold path; no lifecycle API call is in the passing detail. The first attempt failed (automatic compaction did not replace the serving pack set: 2) and the passing run needed test-only 724b94c to wait for convergence; the final assertions still require serving_packs==1 and old manifests retained.

### worker death / duplicate wakeups / expired claims recover without overlapping destructive work or retained-object deletion
**pass_with_bounded_gap** - Rust Pando (rust-pando job) exercised the SQL lease/fence fault-injection surface against real S3: expired publication fence fails the serving proof, renew restores it, expired re-reservation gets a fresh generation path, expired deleting claims are re-claimable with claim_generation+1, resurrection makes a stale finalize a no-op, and dry-run/opt-in gating holds. Genuine process death + duplicate wakeups are exercised by tests/storage_lifecycle.py and tests/physical.py against the shared worker engine, but those jobs (GitFS lifecycle3 / physical8) belong to the round3-integrated rebuild that has no reports yet.
Gap: No Pando-specific process SIGKILL of the mark/delete worker was executed inside the pando23 suite; Pando-side death handling is proven by SQL/lease fault injection, and real process-death recovery proof is pending in the integrated suite.

### concurrent push/fetch/GC with backup/active snapshots preserves retained objects
**pass_with_bounded_gap** - rust-pando exports a paired backup before GC and asserts the archived old ciphertext is byte-unchanged after destructive deletion, asserts serving pack ciphertext survives (resolve_artifact + HEAD present), asserts the unregistered legacy tenant-only object survives, and re-materialises serving snapshots (read leases) before and after compaction. pando-service reports backup_barrier_retried=true.
Gap: A live push racing mark/delete end-to-end is serialised by the worker per-repo write lock inside one process and is not exercised as a multi-connection race in these suites; the durable publication fence and the serving-CAS proof are the in-product guarantees for that window.

### legacy / unregistered / foreign authority bytes permanently protected
**pass** - GC predicates pin authority_id and require remote_path LIKE %/authorities/%; resolve_artifact falls back to the authority-free legacy path for unregistered artifacts; mark/claim/delete all include the retained-link and fence predicates; the rust-pando test legacy-object assertion passed.

### metadata-only raw PG/PITR copies are explicitly unsupported and undetected against a shared bucket; new mode is opt-in
**pass** - docs/pando-remote-retention.md states such a copy keeps the source authority_id and registry rows, is NOT detected and the deleter does NOT fail closed, and forbids running it against the shared bucket; destructive deletion requires ROOTYARD_PANDO_REMOTE_DELETE=true and the rust-pando dry-run case asserts remote_deleted=false/dry_run=true before the opt-in stage.

### backup format 8 / frozen legacy 4-7 / schema 132 contract
**pass** - legacy130: genuine format6/schema130 archive from legacy binary 6135f028, rejected without opt-in, restored and upgraded to max(version) 132 with sha256 clone exact, pin/generation preserved, grant revoked, tombstone preserved. legacy131: genuine format7/schema131 archive from legacy binary 35d01c5f, same pass set. schema job passed against the 132 golden catalog. sha256-matrix and sha256-restore (async-provisioning fix f35285d) passed with exact head/format and retained pin.

## Integration
- combined source: 1061a8e Integrate authority-scoped Pando retention with verified sandbox runtime (round3-integrated)
- ancestry: 89ba6a8 is an ancestor of 1061a8e; f35285d is an ancestor; 724b94c is an ancestor; 946955b (merged sandbox work) is an ancestor
- diff 89ba..1061: src changes limited to src/sandbox/cgroup.rs and src/sandbox/runner.rs (sandbox runtime), no Pando retention source delta
- runtime: primary is force-clean rebuilding and rerunning the same suite plus GitFS lifecycle3/physical8 (genuine worker SIGKILL and volume barrier); a separate VM kernel17 run will pin the combined source. No combined report exists yet, so nothing in this document claims combined tests pass.

## Meaningful gaps
- Pando worker SIGKILL / duplicate-wakeup recovery for the delete path is proven by SQL/lease fault injection only in the pando23 suite; the real process-death assertion lives in the integrated GitFS lifecycle/physical jobs and is pending.
- No multi-instance (two-process) concurrent push+GC race test; single-node loopback fixtures only, as stated in every report limitations field.
- rust-lib/rust-pando/schema jobs have cargo-log evidence only (coordinator design); a future Pando change should add a case-level report for the rust-pando test or assert its exit status explicitly in the coordinator status.
- Combined source 1061a8e and the VM kernel17 pin are unreported at review time; this acceptance is for the pando23 source 89ba6a8 evidence only.

## Excluded (not gaps for this issue)
- No physical-host power-loss, kernel, or multi-zone durability requirement is invented for this storage-maintenance issue; the reports are explicitly loopback/synthetic.
- Secret values were not read; only the fact that ready.env supplies endpoints is cited.

## Honesty notes
- Two jobs first failed and passed after test-only convergence fixes (724b94c, f35285d) with the SAME binary_sha256 eb1e4a09 in every report, which is consistent with harness timing defects rather than product fixes; the pre-fix failure lines are recorded in logs/pando-service-1794023097.json and logs/sha256-restore-1794023791.json.
- The passing rust-pando evidence is one integration test binary (1 test, 11.86s); it is not a Pando test-suite breadth claim.
