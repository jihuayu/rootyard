# HA43/PR62 final publication and evidence claims review

**Verdict:** APPROVE EVIDENCE / MERGE ALLOWED for the bounded single-host reference profile; 0 P1 and 0 P2. Two non-blocking P3 wording/evidence-clarity discrepancies remain. #43/#44/#26/#48 stay OPEN; no physical/hardware closure.

Reviewed head: `de96bced9b7e794269b0a361a4bcd674142d399d` (`de96bce`); deployment source `ac54f7163561ad98fb83e4c5f45cd2e1f7151f74`; HA harness `300c6c93cc054fbd723af2243a8f321307835cbc`; compiled `1061a8ee9d1ecc783189d33949980eac6b3bd6ea`; binary `6f76d70966473cd4bc956bc6a6cff792191664dba3516736b5d50cb92e156eba`; 329 production inputs `9e33859aad991589c57863af6f6b46fe42290071b3e271f90eda44f6d707feac`.

## Evidence integrity

- report SHA-256 `43655b1a59fc49aeac2049010a9ed022c5832daf9db5d09a8f568680f9ad9dea` matches status; status SHA-256 `3fb675166ab661604d0b6035e98ef62dbc10a96d82c43e755851c00f2123b432`; source-equivalence SHA-256 `b7c8c7c612af0940325aa82c648890ed8e4c3ae9370605f668d2e133088bad3c`.
- Published copies are byte-equal to the scratch coordinator files; all manifest-listed file hashes/sizes match. `manifest.json` is the only self-excluded file; no unlisted evidence.
- production-inputs map: 329 paths/digest `9e33859aad991589c57863af6f6b46fe42290071b3e271f90eda44f6d707feac`; source-equivalence says 329 identical.
- No rootyard binary, PKI/private keys, env/config credentials, backup sets, DB data directories or raw service logs are published. Manifest secret-scan hits: 0.
- Failed attempts are preserved as failures (pre-restored Git identity, 579 wrong Intent.state); checkpoint-85 is an archived pass only, not the current 300 pass.

## Claims verified

- **Native Execution:** True
- **Simulated Fields:** False
- **Source Worktree Dirty:** False
- **Topology:** 3 etcd mTLS, 3 Patroni PG17 TLS/SCRAM, strict remote_apply, HAProxy primary/replica, one Rootyard server
- **Rto:** {'read_ms': 18519.1, 'write_ms': 19896.9, 'rootyard_ready_ms': 18596.6}
- **Automatic Failover:** {'old_primary': 'pg3', 'successor': 'pg1', 'manual_promotion_invoked': False, 'crash_to_successor_elected_ms': 18480.3, 'old_node_processes_after_crash': 0, 'old_pg_port_closed': True, 'same_rootyard_pid': True, 'rootyard_pid': '357650'}
- **Rpo:** {'lost_acknowledged_commits_after_automatic_promotion': 0, 'acked_commits_verified': 6}
- **Dcs Quorum Loss:** {'healthy_write_probe': 'UPDATE 1', 'post_demotion_write_probes': 4, 'post_demotion_write_rejections': 4, 'post_demotion_verification_window_seconds_observed': 6.25, 'valid_lease_write_probes_accepted': 8, 'role_history_samples': 13, 'old_primary_readonly_or_stopped': True, 'endpoint_writes_rejected': True, 'promotion_without_quorum': False}
- **Restore:** {'format': 8, 'schema_versions_include_132': True, 'checksums_verified': True, 'authenticity_verified': False, 'local_unencrypted_trusted_closure': True, 'authority_rotated_automatically_by_restore': True, 'transport_nonces_cleared': True, 'old_ci_grant_active_before_backup': True, 'old_ci_grant_revoked_by_restore': True, 'old_grant_cancelled': False, 'old_grant_expiry_still_future': True, 'old_grant_audience_unchanged': True, 'old_token_http_status': 401, 'new_ci_grant_revoked': False, 'new_ci_checkout_exact_oid': True, 'new_ci_checkout_fsck': 'passed', 'intent_and_receipt_canonical_hash_equal': True, 'retention_ref_oid_catfile_checks': True, 'ordinary_user_credentials_preserved': True, 'prerevoked_token_denied': True, 'tenant_denial': 'passed', 'delivery_identity_set_drain': {'pre_backup': 6, 'pre_backup_delivered': 6}, 'source_restored_ref_maps_equal': True, 'post_boundary_oid_absent': True, 'restored_push': 'passed'}

## Material P3 findings (non-blocking)

### P3-1 (P3): source-equivalence scope string still says HA be247 deployment/test while manifest and harness are 300c6c9

**Files:**
- `evidence/round3/ha43-patroni-300c6c9/source-equivalence.json:5`
- `evidence/round3/ha43-patroni-300c6c9/manifest.json:19-20`
- `docs/acceptance/round3-ha43.md:11-13`

**Discrepancy:** source-equivalence.scope says "with HA be247 deployment/test"; manifest.source.native_harness_commit says 300c6c9 and support commit 0223b24, and acceptance says HA delta 300c6c9. The digest/hash fields are correct; only the descriptive scope is stale.

**Impact:** A reader checking only source-equivalence.json could misidentify the HA harness version. No numeric/source-equivalence claim is false.

**Correction:** Update the descriptive scope to HA 300c6c9/support 0223b24 or label it as the inherited composition descriptor; no rerun needed.

### P3-2 (P3): manifest worktree_clean_at_manifest=false is not distinguished from the clean run-state claim

**Files:**
- `evidence/round3/ha43-patroni-300c6c9/manifest.json:11`
- `evidence/round3/ha43-patroni-300c6c9/README.md:56-57`
- `docs/acceptance/round3-ha43.md:17-18`

**Discrepancy:** manifest records worktree_clean_at_manifest=false (publication bundle generation state), while README/acceptance say the tree was clean before/after the run and report.json has source_worktree_dirty=false. These concern different moments; no false run-clean claim, but the word "clean" is not qualified.

**Impact:** A reader may read manifest=false as contradicting the run-clean statement. No report or source-equivalence field is contradicted.

**Correction:** Label the manifest field as publication-worktree cleanliness and cite the run field source_worktree_dirty=false; no rerun needed.

## Merge / issue state

- **Merge allowed:** True — bounded single-host external HA reference profile evidence and documentation only; no production HA/DR certification.
- **Issue closure:** none; #43/#44/#26/#48 remain OPEN; PR62 has no Closes.
- **Physical gates:** cross-host fencing, hardware watchdog/power-loss/rack/zone, HAProxy HA, Kafka HA and Git-volume replication remain unqualified.

## Scope expressly not proved

Single physical host; no cross-host fencing, hardware watchdog/power-loss/rack/zone, HAProxy HA, Kafka HA or Git-volume replication. The backup is local unencrypted trusted closure (`checksums_verified=true`, `authenticity_verified=false`); no authenticated/encrypted archive claim. RPO 0 is only for automatic promotion; the restore intentionally loses one post-boundary acknowledged OID and is not a zero-RPO DR claim.

Read-only source/evidence/report/status/hash inspection; no project edits, no Cargo/native test, no network or GitHub mutation.

