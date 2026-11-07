# PR63 final-combination addendum review

**Verdict: ACCEPT_PUBLICATION_ADDENDUM - merge_allowed = true, closable_25 = true**
Reviewed HEAD 1460b0889f5f3e6e033d26de17fa31bc68950d38 (clean). docs/evidence only (README.md, docs/acceptance/round3-ha43.md, docs/acceptance/round3-migration25.md, docs/registered-task-delivery.md, evidence/round3/final-combination-157748add/**, evidence/round3/migration25-publication-review.json/.md, 13 files, 766 insertions, 8 deletions); no src/tests/migrations/schema/Cargo change.
Identities: delivery 1460b088 (this publication: docs/evidence only), harness/tested 0d9f48211e8e, compiled cb8d1b915a3c, binary 157748addd3ad1cc..., inputs 0f865a04763c5be077e15151143554b191f8ad8a84462f6746d045eabea3bc90 (331 files)

## Bundle
- path: evidence/round3/final-combination-157748add
- files: ["README.md", "coordinator-native.log", "manifest.json", "production-inputs.json", "report.json", "source-equivalence.json", "status.json"]
- manifest_entries: 6
- missing: []
- unlisted: []
- hash_or_size_mismatches: 0
- status_report_sha256: efcfd7e455b3aa05750ffeaa637871ee00d6a62d232b80f5339871678b0bf118
- recomputed_report_sha256: efcfd7e455b3aa05750ffeaa637871ee00d6a62d232b80f5339871678b0bf118
- report_sha_matches_manifest_and_status: true
- bundle_status_equals_scratch_status: status.json is byte-identical to /workspace/scratch/rootyard-round3/final-combination/coordinator-status.json
- coordinator: state passed, exit_code 0, log coordinator-native.log result passed
- harness_hashes_match_status_map: {"tests/cluster_patroni_native.py": "07c5265aa0f3ec7c7ccb963fea7648e5c0bd8ba8fd17d4f6ade3b81c10feb9e1", "tests/ha_fixture.py": "ef14ad3ad05c827a2310c0b264b48de84be80adddf4b853e717fda48dff7bc7b", "deployment/ha/render.py": "95dd01fbc9266c3c7e11fad526b9c94b6b6c608717c907fd4030c3da5822db4b"}
- harness_file_sha_recomputed: 07c5265aa0f3ec7c7ccb963fea7648e5c0bd8ba8fd17d4f6ade3b81c10feb9e1 equals report harness_sha256 and the file in both worktrees
- production_input_eq_current_tree: production-inputs.json carries 331 files with digest 0f865a04... matching source-equivalence, the manifest and the certified compile

## Runtime facts
- rto: {"read_ms": 19522.7, "write_ms": 20762.3, "rootyard_ready_ms": 19597.6}
- rpo: {"acked_commits_verified": 6, "lost_acknowledged_commits_after_automatic_promotion": 0}
- automatic_failover: {"manual_promotion_invoked": false, "old_node_processes_after_crash": 0, "old_pg_port_closed": true, "successor": "pg3"}
- dcs_quorum_loss: "2 of 3 etcd members stopped on one host; healthy Patroni REST reported UPDATE 1 and >=3 post-demotion durable probes were rejected"
- restore: "actual offline backup format 8 / schema 132 restore: authority rotated by restore, backup_verify, git_fsck passed, restored_ref_map_equals_source, retained_acknowledged_oids, restored_push_oid present, worker drained before ingress, post-boundary ref change/oid intentionally absent"
- ci_grants: "a real pre-backup CI grant revoked and then denied with HTTP 401 at the same audience, while a fresh grant checked out the exact retained OID with fsck passed; no SQL manual authority or grant rewrite"
- intent_receipt: "full intent and pinned receipt JSON plus hash and ref-OID compatibility recorded"

## Bounds preserved
- physical_scope: report declares hosts=1, cross_host_failover=false, hardware_watchdog=false, production_certified=false; no cross-host, hardware power-loss, rack/zone, Kafka HA or HAProxy HA claim
- not_a_production_ha_qualification: README and both acceptance docs say so explicitly; issue 26 physical cross-host fencing stays OPEN
- older_ha_report_separate: the older 6f76d70 PR62 HA report (1061a8e / harness 300c6c9, RTO 18519.1 read / 19896.9 write) is retained and clearly labelled as a different identity; the new 157748add run does not reuse or overwrite it
- hooks_and_fixture_bounds: no all-13-kill claim introduced; 13 registered hooks are still documented as not 13 SIGKILLs, the 34-row reconcile fixture remains metadata-only, and the three inherited fail-closed P2 plus the fixed 1024-intent/2 MiB cap and the UNCLASSIFIED old 16 MiB takeover 409 are preserved verbatim in the docs and ledger

## Docs claims
- README: current-status paragraph and the dedicated Issue 25 status paragraph state #25 completed for the accepted one-host separate-volume mode via PR 63 (final merge step pending at publication time), #23 via PR 61, #32 via PR 60, #38 via PR 57, #26/#43/#44/#48 open, PR 62 closes nothing, and the addendum run facts; not a production HA qualification
- docs/acceptance/round3-migration25.md: adds the final combined compatibility paragraph with the same numbers and identities, keeps the ACCEPT_FOR_DOCUMENTED_MODE / closable_25 verdict, the 3 inherited P2, 1024/2 MiB cap, 13-hooks note, 34-row metadata-only fixture and the UNCLASSIFIED 409
- docs/acceptance/round3-ha43.md: records the final combined compatibility run as additional current-binary proof and states the older 6f76d70 HA metrics and bundle are not overwritten; HA profile issues 43/44 stay open
- docs/registered-task-delivery.md: row 25 is CLOSED via PR 63 for the accepted one-host separate-volume mode (final merge step pending), with the same evidence links and preserved bounds; row 26 remains OPEN with physical cross-host fencing unqualified and PR 62 closing no issue

## Findings
- P1: 0, P2: 0
- P3: report.json has no top-level result field (declared report_has_top_level_result_field=false); pass is established by coordinator exit 0 -- same presentation nit previously noted for the partition report
- P3: the bundle stores status.json without an explicit stage field; harmless because exit_code 0 and report hash are recorded

## Inherited unchanged
- 3 old B-mode non-blocking P2 (lost live evidence 409/permanent 503; release+re-pin same job id 409; orphan staging retained with no observability)
- fixed fail-closed 1024-intent / 2 MiB per-repository cap
- old 16 MiB takeover generic 409 remains UNCLASSIFIED and is not claimed fixed

## Approval
approved for merge of PR 63 as the final publication/receipt for issue 25 in the documented one-host separate-volume mode; no hardware or cross-host gate is attached to this bounded mode

## Not performed
- read-only: no project edits, no Cargo, no native runs, no network, no GitHub actions; only git plumbing, sha256 recomputation, JSON inspection and doc reads. The original 99fe publication review artifacts were not modified.
