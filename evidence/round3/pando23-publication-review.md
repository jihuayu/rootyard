# Evidence and claims review - candidate 601a925 on round3-integrated

**Verdict: ACCEPT_EVIDENCE_AND_CLAIMS - closable_23 = true** (documented managed-authority mode only: opt-in ROOTYARD_PANDO_REMOTE_DELETE=true, current-authority registered obsolete artifacts deleted by exact key with no S3 LIST, legacy/unregistered/foreign protected, paired Rootyard archive the only supported restore authority; closes after the primary merges 601a925)
Reviewed head 601a925a15c08ff7f05cde90de27d8e1c62629ed (clean); project READONLY.

## Verified
### evidence_bundle
{
 "path": "evidence/round3/pando23-authority-1061a8e",
 "files_on_disk": 40,
 "bytes_on_disk": 179216,
 "manifest_entries": 39,
 "manifest_covers_bytes": 167359,
 "missing": [],
 "unlisted": [],
 "hash_or_size_mismatches": 0,
 "manifest_excludes_itself": true
}

### status
{
 "states": "passed / complete",
 "jobs_passed": 10,
 "jobs_failed": 0,
 "harness_commit": "750ccce7571dc5eed7bc9ccaaf3aa04e31755760 (test-only)",
 "compiled_source_commit": "1061a8ee9d1ecc783189d33949980eac6b3bd6ea",
 "local_binary_sha256": "6f76d70966473cd4bc956bc6a6cff792191664dba3516736b5d50cb92e156eba",
 "production_inputs_sha256": "9e33859aad991589c57863af6f6b46fe42290071b3e271f90eda44f6d707feac",
 "production_inputs_unchanged_after_compile": true,
 "byte_identical_to_scratch": "status.json equals /workspace/scratch/rootyard-round3/pando61/coordinator-status.json"
}

### reports
{
 "json_reports": 7,
 "cases_total": 27,
 "cases_failed": 0,
 "report_sha256_equals_status": "7/7 verified",
 "breakdown": "gitfs-lifecycle 3/3, gitfs-physical 8/8, pando-service 2/2, legacy131 3/3, legacy130 3/3, sha256-matrix 6/6, sha256-restore 2/2, every report carries binary_sha256 6f76d70",
 "stdout_only_jobs": "rust-lib 142 tests, rust-pando 1 test on real Garage/S3 + Vault + PostgreSQL, schema 8 checks",
 "honest_failures": "pando23-source-89ba6a8/failed-pre-fix contains pando-service-1794023097.json and sha256-restore-1794023791.json; both fixed by test-only 724b94c/f35285d with the same certified binary"
}

### vm
{
 "run_id": 42337108050,
 "job_id": 128296401784,
 "source_commit": "1061a8e",
 "assertions_verified": 17,
 "assertions_all_true": true,
 "vm_binary_sha256": "f0061754a2ccb4678db272cfc3662cc106945ee2819838b5a4868fde9d413046",
 "local_binary_distinct": true,
 "same_binary_hash_claimed": false,
 "same_production_input": true,
 "binary_sha256_file_present": true,
 "artifact_download_witness": "download-verification.json artifact_id 13559528645, zip sha256 692d86087ccfeeb1815d35d891926241f4e3b0c2d6d1cddac7183b5ba7f3d168, conclusion success; zip not stored (declared)"
}

### source_and_tree
{
 "head": "601a925a15c08ff7f05cde90de27d8e1c62629ed",
 "clean": true,
 "ancestors_verified": [
  "89ba6a8 reviewed production source",
  "750ccce test-only"
 ],
 "src_diff_89ba_to_head": "only src/sandbox/cgroup.rs and src/sandbox/runner.rs (145 insertions, 11 deletions) - no new Pando production code",
 "750ccce_scope": "tests/storage_lifecycle_physical.py only",
 "current_source_digest_recomputed": "9e33859aad991589c57863af6f6b46fe42290071b3e271f90eda44f6d707feac over 329 files, equal to manifest verification and the acceptance doc",
 "docs_present": [
  "docs/acceptance/round3-pando23.md",
  "README.md top bloc"
 ],
 "readme_states": "10/10 combined jobs, ACCEPT_FOR_DOCUMENTED_MODE, closable_23 pending merge, #32 closed via PR #60, #38 via PR #57, #25/#26/#43/#44/#48 open, no HA qualification claim"
}

### claims_checked
{
 "mode_bounds_preserved": true,
 "details": [
  "opt-in delete only; mark and dry-run by default",
  "registered current-authority unreferenced artifacts, exact keys, no S3 LIST",
  "legacy PackManifest v1, uploaded-but-unlinked and foreign-authority objects permanently protected",
  "raw metadata-only PG/PITR against a shared bucket stated unsupported, undetected and not fail-closed",
  "paired Rootyard archive is the only restore authority and rotates the authority once for all repos including zero-Pando",
  "no per-OID in-pack pruning, no hardware power-loss, cross-host HA or multi-zone claims",
  "53.3 s physical tombstone timeout stays unclassified with no runtime-fix claim; focused 19.6 s and full 8/8 later on the same certified binary"
 ]
}

## P1/P2/P3
P1: 0, P2: 0. P3:
- **P3-1** Repo acceptance doc omits the preserved Pando SIGKILL / multi-process race bound
  bundle README lines 230-234 keep it (SQL/lease fault injection only, no Pando-specific process SIGKILL, no two-process push+GC race); docs/acceptance/round3-pando23.md Explicit non-claims covers PITR, per-OID/hardware, the 53.3 s transient and P3 follow-ups but not this bound
  Fix: add one bullet to the repo doc so the repo-level claim cannot be read as process-death or multi-instance coverage
- **P3-2** manifest.json is excluded from its own hash coverage
  manifest declares manifest_excludes_itself=true; all 39 listed files verify byte-exact (167359 bytes) and exactly 39 files exist besides manifest.json, so the index itself is covered only by the git commit
  Fix: publish manifest.json.sha256 next to it, or list it in the signed status file
- **P3-3** rust-lib / rust-pando / schema evidence is stdout logs only
  declared rust_and_schema_reports_are_stdout_logs_only=true; logs/rust-pando-1794024629.log carries the single real-S3 Pando test, logs/rust-lib-1794024574.log the 142 lib tests, logs/schema-1794024696.log 8 contract checks; no per-case JSON for these three jobs
  Fix: emit a case-level report for the rust-pando integration test so the strongest Pando evidence is machine-verifiable
- **P3-4** Failed first combined physical-GC attempt remains unclassified and is correctly not claimed fixed
  attempts/pre-gc-physical-1794024719 plus manifest.failed_attempt: physical_loose_packed_and_pin, 53.3013 s, error maintenance state did not reach deleted: pending, cause UNCLASSIFIED, sql_snapshot_retained=false, focused rerun 19.6391 s passed, later full 8/8 in 149.71 s, runtime_fix_claimed=false; 750ccce is test-only (tests/storage_lifecycle_physical.py, 118 insertions) and only captures bounded state
  Fix: keep it visible in the delivery ledger after #23 closes; it is a GitFS physical-fixture transient, not a Pando-mode claim

## Not performed
- No native, cargo, network, GitHub or project edits; only file reads, hash computation and one read-only source_digest.py run whose output went to /tmp.
