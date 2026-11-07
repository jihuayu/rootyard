# Native lease review: bb15389 (tests-only) versus f3cb5f0

**Head:** bb15389e1f42bebe63a9e3a92eff5b6ccfb8172b  
**Previous:** f3cb5f01c797a2dc6ca7fcb588060da966ddac53  
**Report:** lfs_retention-gc17.json (binary 157748a)  
**Delta:** tests/lfs_retention_acceptance.py; src paths changed 0; worktree clean True

## Conclusion
B2 CLOSED on the owned tests at baseline binary 157748a. The GitFS stage-cleanup job is proven to run concurrently with a real native push that itself holds the repository data lease (rootyard-data-v1 ShareLock, application_name=rootyard, xact-scoped), cannot delete the 4000 staged temps while that lease is held, and succeeds only after the push publishes. 39 and 40 stay PENDING combined integration only.

## B2 - closed
- Gap: The earlier barrier was a test-held shared advisory lock, so native publication was not itself the data-lease holder.
- Method: The fixture holds ONLY the product ref key rootyard-ref-v1:<repo>:<ref> via a session-level try lock. The real native HTTP push takes read_leases::shared on rootyard-data-v1 first (src/storage/ref_publication.rs:270, entry at src/git_http.rs:204) and then retries the exact-ref lock, so the data-lease holder is the application backend waiting on that ref key. No hook wrapping and no product change.

Evidence from the real run:
- native_backend_pid: 408921
- native_application_name: rootyard
- native_lock_mode: ShareLock
- consecutive_samples: 5
- fixture_backend_pid: 409139
- fixture_lock_scope: rootyard-ref-v1 only: refs/heads/gc-race-native
- exclusive_probe: pg_try_advisory_lock on the rootyard-data-v1 key returned false while the native lease was held
- cleanup_running_while_native_lease_held: True
- stale_files_untouched_before_release: 4000
- staging_files_deleted_after_native_release: 4000
- job_kind: gitfs_stage_cleanup
- job_state: succeeded
- job_completed_after_push: 1794040616.979397
- push_window: {"start": 1794040614.7452097, "end": 1794040616.8959467}

Why this is sound and not a flag:
- pg_locks filter requires locktype=advisory, granted, mode=ShareLock and objsubid=1, which selects the single-bigint advisory-key namespace (objsubid=2 is the two-int key namespace); objsubid does not distinguish transaction from session scope. The holder is established instead by the exact rootyard-data-v1 key, application_name=rootyard, the fixture pid being excluded, and five stable consecutive samples.
- application_name=rootyard is set on the application pool (src/db.rs:18), and the fixture is excluded by pid, by application_name and by native_pid != fixture_pid.
- Five consecutive samples at 50 ms spacing inside a 2.15 s push window, so this is sustained holding, not a transient blip.
- read_leases::exclusive retries every 50 ms until its deadline (src/storage/read_leases.rs:81-110), so the maintenance worker stays claimed and denied for as long as the native shared lease is held and cannot reach gitfs::execute (src/storage_lifecycle/worker.rs:51).
- Direct behavioural proof, not only a probe: the job was running while 4000 aged .tmp-* files still existed and were asserted present; after the fixture released the ref key the push completed rc 0, the job succeeded, deleted 4000, and completed after push end.
- Cleanup scope is unchanged: gitfs_stage_cleanup only removes aged .tmp-<uuid> files under lfs/<repo> (src/storage_lifecycle/gitfs.rs), so committed <oid> bytes are never candidates; the LFS row and bytes were re-verified ready and identical afterwards.

## Other delta checks
### Interrupted first upload now asserts no leftover staging temp
Status: verified

- tests/lfs_retention_acceptance.py adds assert list(fresh_path.parent.glob(.tmp-*)) == [] with message interrupted first upload left staging temp files
- gc17 committed_bytes_survive_failures passed with interrupted_first_upload_stayed_pending and retry_became_ready true

Note: Closes the residual note from the f3cb5f0 review, where the temp check only guarded the polling break condition.

### No product or hook code was added to force the barrier
Status: verified

- diff f3cb5f0..bb15389 touches only tests/lfs_retention_acceptance.py
- rootyard-ref-v1 and rootyard-data-v1 keys come from existing product constants (src/storage/ref_publication.rs:22, src/storage/read_leases.rs:18-19)

### Clock domains consistent
Status: verified

- push window uses time.time(); job completed_at converted with datetime.fromisoformat().timestamp(); gc17 wall-clock order 614.745 < 616.896 < 616.979

## Correction to the earlier review
- Prior finding F1 (remote hydration writing straight to the final oid path, possible partial-file exposure) is RETRACTED as a false concern.
- Basis: src/storage/remote_objects.rs get_to_file writes to a sibling .rootyard-object-<uuid> temp, enforces size and sha256 against the key digest, sync_all, then fs::rename onto the destination and fsyncs the parent; the temp is removed on failure. The caller fs::set_permissions(0600) after a completed rename cannot truncate it.
- Residual: In-process failures clean the temp, but a hard crash can leave a .rootyard-object-<uuid> file in lfs/<repo>/ while gitfs_stage_cleanup only reclaims names matching .tmp-<uuid> (src/storage_lifecycle/gitfs.rs). Harmless for retention and never confusable with a committed <oid> path, but a tiny housekeeping residual if the prefix is not widened.

## Accepted supported-mode residuals
- Loopback single host, local data volume and local Garage on a second data directory; no vendor credentials or hardware are required or claimed.
- The barrier fixture needs the psql client and a dedicated disposable database; environment-specific and passed in gc17.
- No LFS delete or GC API exists; retention is asserted through failed, duplicate and interrupted uploads, permission removal and the stage-cleanup job.
- Non-LFS compatibility push uses 300 small files against 4096 small-blob and 20000 object bounds.
- Documentation claiming older manifest formats need the legacy binary is untested.
- restored_schema_versions_verified remains a constant true; the real evidence is manifest schema_versions plus the restore-path assertion.
- gitfs_stage_cleanup deletes at most 4096 entries per run, so more than 4096 stale temps need repeated runs.

## Status
- 39: pending combined integration only
- 40: pending combined integration only
- Why not closable yet: Primary integrated bb15389 plus a fresh build final pipeline is still pending; the hydration tree (adapter atomicity correction already present in this binary, caller 0600 hardening) and the remaining H pointer variants are still finishing, so no closure is claimed from this checkpoint.

## Verification performed
- git log: HEAD bb15389e1f42bebe63a9e3a92eff5b6ccfb8172b on f3cb5f0 and 79987b4
- git diff --name-status f3cb5f0 bb15389: tests/lfs_retention_acceptance.py only; git status clean
- read gc17 json and progress.json b2_resolution/native_runs; binary 157748a
- checked src/storage/ref_publication.rs acquire ordering, src/storage/read_leases.rs retry loop, src/db.rs application_name, src/storage/remote_objects.rs get_to_file atomicity, src/storage_lifecycle/gitfs.rs cleanup scope
- no repo edits, no native reruns, no Cargo build, no network or credential access

