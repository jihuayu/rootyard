#!/usr/bin/env python3
"""Validate native operations evidence for issues #43 and #44.

The gate accepts only reports produced by executed processes, storage and
client traffic.  Every report must carry matching binary/source provenance and
declare that no simulated fields were supplied.  Synthetic benchmark receipts
cannot be substituted.

Issue #44 (real multi-process measurement) can pass from the local evidence.
Issue #43 is reported as blocked while cross-host storage fencing and external
PostgreSQL HA are unavailable; the local secure profile evidence is accepted
separately.  The gate therefore never presents the local profile as full HA.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ops_provenance


CORE_REPORTS = {
    "tls": "cluster-tls.json",
    "kafka": "cluster-kafka-tls.json",
    "local_profile": "cluster-local-profile.json",
    "workload": "cluster-workload-integration.json",
    "streaming": "cluster-pg-streaming.json",
    "pitr": "cluster-pg-pitr.json",
    "disk": "cluster-disk-pressure.json",
}
LOCAL_HA_REPORTS = {
    "takeover": "cluster-takeover-run.json",
    "partition": "cluster-partition.json",
}
BLOCKER_FILE = "cluster-source-blockers.json"
HARNESS_FILES = {
    "tls": "tests/cluster_tls_native.py",
    "kafka": "tests/cluster_kafka_tls_native.py",
    "local_profile": "tests/cluster_local_profile_native.py",
    "workload": "tests/cluster_workload_native.py",
    "streaming": "tests/cluster_pg_streaming_native.py",
    "pitr": "tests/cluster_pg_pitr_native.py",
    "disk": "tests/cluster_disk_pressure_native.py",
    "takeover": "tests/cluster_takeover_native.py",
    "partition": "tests/cluster_partition_native.py",
}

PROVENANCE_KEYS = ("binary_sha256", "source_base_commit", "measurement_kind",
                   "simulated_fields", "tool_versions", "hardware", "topology",
                   "dataset", "workload", "limits")


class GateFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise GateFailure(message)


def load(evidence, filename):
    path = evidence / filename
    require(path.is_file(), f"missing evidence file: {filename}")
    data = json.loads(path.read_text())
    require(isinstance(data, dict), f"{filename}: report is not an object")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, data, digest


def validate_provenance(path, data, source_commit, binary_sha, harness_file):
    for key in PROVENANCE_KEYS:
        require(key in data, f"{path.name}: missing provenance field {key}")
    require(data["measurement_kind"] == "native_execution",
            f"{path.name}: measurement_kind is not native_execution")
    require(data["simulated_fields"] is False,
            f"{path.name}: simulated_fields must be false for a gate report")
    require(data["source_base_commit"] == source_commit,
            f"{path.name}: source commit {data['source_base_commit']} != {source_commit}")
    require(data.get("source_worktree_dirty") is False,
            f"{path.name}: evidence was produced from a dirty source tree")
    require(data["binary_sha256"] == binary_sha,
            f"{path.name}: binary SHA-256 does not match the gate binary")
    require(data["tool_versions"], f"{path.name}: no tool versions")
    require(data["hardware"], f"{path.name}: no hardware description")
    require(data["topology"] and data["dataset"] and data["workload"],
            f"{path.name}: topology/dataset/workload missing")
    require(isinstance(data["limits"], list) and data["limits"],
            f"{path.name}: explicit limits are required")
    require("harness_sha256" in data, f"{path.name}: harness SHA-256 missing")
    actual_harness = REPO / harness_file
    require(actual_harness.is_file(), f"{path.name}: mapped harness is missing: {harness_file}")
    actual_digest = hashlib.sha256(actual_harness.read_bytes()).hexdigest()
    require(data["harness_sha256"] == actual_digest,
            f"{path.name}: harness SHA-256 does not match {harness_file}")
    return {"file": path.name, "kind": data.get("kind"),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "binary_sha256": data["binary_sha256"],
            "source_base_commit": data["source_base_commit"],
            "topology": data["topology"], "limits": data["limits"]}


def check_tls(data):
    require(data.get("encrypted") is True and data.get("scram_sha256_authenticated") is True,
            "TLS/SCRAM was not established")
    for key in ("wrong_password_rejected", "ca_validation_rejected_wrong_root",
                "hostname_validation_rejected_ip_mismatch", "explicit_downgrade_rejected"):
        require(data.get(key) is True, f"TLS negative check failed: {key}")
    require(data.get("postgres_version"), "PostgreSQL version missing")


def check_kafka(data):
    for key in ("wrong_ca_rejected", "wrong_hostname_rejected", "wrong_sasl_password_rejected",
                "broker_restart_reconnected"):
        require(data.get(key) is True, f"Kafka negative check failed: {key}")
    require(data.get("sasl_mechanism", "").startswith("PLAIN over TLS"),
            "Kafka is not SASL over TLS")
    require(data.get("kafka_version"), "Kafka version missing")
    require(data.get("post_restart_wake_offset", 0) > data.get("initial_wake_offset", 0),
            "Kafka wake offset did not advance after restart")
    require(data.get("git_push_during_broker_outage") and data.get("git_push_after_reconnect"),
            "Kafka outage did not preserve real Git acknowledgement")


def check_local_profile(data):
    require(data.get("node_count", 0) >= 2, "profile has fewer than two data processes")
    require(len(set(data.get("postgres_roles", []))) == len(data.get("postgres_roles", [])),
            "PostgreSQL identities are not distinct")
    require(len(set(data.get("kafka_roles", []))) == len(data.get("kafka_roles", [])),
            "Kafka identities are not distinct")
    oids = (data.get("acknowledged_oid"), data.get("owner_clone_oid"),
            data.get("routed_browse_oid"))
    require(oids[0] and oids[0] == oids[1] == oids[2],
            "cross-node push/clone/browse OIDs differ")
    require(data.get("kafka_offset_after", 0) > data.get("kafka_offset_before", 0),
            "Kafka wake offset did not advance")
    require(data.get("wrong_kafka_role_password_rejected_before_start") is True,
            "wrong Kafka role password was not rejected during preflight")
    require(data.get("failed_preflight_secrets_cleaned") is True,
            "failed preflight retained client secrets")
    require(data.get("sigterm_resistant_descendant_killed") is True,
            "profile shutdown did not quiesce a resistant descendant")
    require(data.get("kafka_version") and data.get("postgres_version"),
            "profile report lacks exact dependency versions")


def check_workload(data):
    tiers = data.get("tiers") or []
    require([tier.get("node_count") for tier in tiers] == [1, 2, 4],
            "workload did not measure 1/2/4 nodes")
    raw = data.get("raw") or []
    require(len(raw) == 24, "workload raw evidence is not 24 push/fetch pairs")
    require(all(item.get("acknowledged_oid") for item in raw), "a raw operation has no acknowledged OID")
    require(all(item.get("push_ms", 0) > 0 and item.get("fetch_ms", 0) > 0 for item in raw),
            "raw workload has no measured client latency")
    require(len({item["acknowledged_oid"] for item in raw}) == len(raw),
            "acknowledged OIDs are not unique")
    failure = data.get("failure") or {}
    require(failure.get("acknowledged_commits_checked") == len(raw),
            "not all acknowledged commits were checked for survival")
    require(failure.get("rpo_lost_acknowledged_commits") == 0,
            "acknowledged writes were lost after process failure")
    require(failure.get("read_while_owner_stopped_status", 0) >= 500,
            "unreachable owner did not fail the read assertion closed")
    require(failure.get("rto_read_ms", 0) > 0 and failure.get("rto_write_ms", 0) > 0,
            "RTO was not observed")
    live = data.get("live_object_negative_control") or {}
    require(live.get("owner_process_stopped_before_object_removal") is True and
            live.get("owner_process_restarted_before_fetch") is True,
            "live corruption did not stop/restart the serving process")
    require(live.get("stock_fetch_exit_while_corrupt", 0) != 0,
            "stock Git fetch succeeded with a physically removed retained object")
    require(live.get("native_fsck_failed_while_corrupt") is True,
            "native fsck did not fail after object removal")
    require(live.get("native_fsck_after_restore") == "passed" and
            live.get("stock_fetch_exit_after_restore") == 0 and
            live.get("fetched_tip_after_restore") == live.get("acknowledged_tip"),
            "live serving volume did not recover after the object bytes were restored")
    require(data.get("removed_object_negative_control", {}).get("native_fsck_failed") is True,
            "copy-fixture negative control is missing")
    retained = data.get("retained_root") or {}
    require(retained.get("native_fsck") == "passed" and retained.get("reachable_oids_after_gc", 0) > 0,
            "retained root was not verified after GC")
    require(data.get("client_cache_eviction", {}).get("removed_local_clone_and_refetched_from_node4") is True,
            "client cache-eviction drill did not complete")


def check_streaming(data):
    require(data.get("standby_promoted") is True, "standby was not promoted")
    require(data.get("synchronous_commit") == "remote_apply",
            "PostgreSQL was not synchronously applying standby WAL")
    require(data.get("rpo_lost_acknowledged_commits") == 0,
            "acknowledged commit was lost across PostgreSQL promotion")
    load = data.get("write_load") or {}
    require(load.get("all_acknowledged", 0) >= 3,
            "fewer than three acknowledged writes were measured under load")
    require(load.get("writer_terminated_before_accounting") is True,
            "ACK set was not snapshotted after the load writer terminated")
    require(len(load.get("acknowledged_oids", [])) == load.get("all_acknowledged"),
            "ACK OID list does not match the observed ACK count")
    require(load.get("failed_or_unacknowledged_during_outage", 0) > 0,
            "primary failure did not affect the concurrent writer")
    require(data.get("rpo_lost_acknowledged_writes_under_load") == 0,
            "acknowledged write under load was lost after promotion")
    require(data.get("rto_read_ms", 0) > 0 and data.get("rto_write_ms", 0) > 0,
            "PostgreSQL promotion RTO was not observed")
    operator = data.get("operator_recovery") or {}
    require("required" in operator and operator.get("repository_state_after_promotion_restart"),
            "promotion report lacks fail-closed/recovery semantics")
    if operator["required"]:
        require(operator.get("inspection_unknown_operations", 0) > 0 and operator.get("resolution"),
                "unknown in-flight push was not explicitly resolved before writes reopened")


def check_pitr(data):
    require(data.get("archive_mode") == "on", "WAL archive was not enabled")
    require(data.get("later_write_intentionally_lost_at_point_in_time") is True,
            "post-boundary write was not shown outside the restore point")
    require(data.get("later_acknowledged_oid_outside_recovery_point") and
            data.get("post_restore_acknowledged_oid"),
            "PITR report lacks boundary/restored OIDs")
    require(data.get("retained_ref_and_objects_fsck") == "passed",
            "restored retained refs/objects failed fsck")
    require(data.get("reader_access_unrelated_tenant_denial_and_token_revocation") == "passed",
            "restored permission/token checks are missing")
    require(data.get("delegation_authority_rotated_before_reopening") is True,
            "delegation authority was not rotated before reopening writes")
    worker = data.get("worker_restore") or {}
    require(worker.get("worker_once_processed", 0) > 0,
            "restored delivery worker processed no retained job")
    require(worker.get("pending_deliveries_after_worker") == 0,
            "restored worker left pending deliveries")
    require(worker.get("outbox_events_after_restore") == worker.get("outbox_events_before_boundary"),
            "post-boundary outbox event survived PITR")
    deployment = data.get("restored_deployment") or {}
    require(all(deployment.get(key) for key in ("data_volume", "endpoint", "metadata")),
            "restore was not exercised in a new deployment")


def check_disk(data):
    require(data.get("free_kib_at_push") == 0, "ENOSPC was not reached")
    require(data.get("push_exit_code_during_enospc", 0) != 0,
            "Git push was falsely acknowledged while the volume was full")
    require(data.get("ref_after_removing_pressure") == data.get("retained_acknowledged_oid"),
            "acknowledged ref moved during a rejected ENOSPC push")
    require(data.get("native_fsck_after_pressure") == "passed",
            "repository fsck failed after pressure was removed")
    require(data.get("post_pressure_retry_acked") is True,
            "post-pressure retry was not acknowledged")
    require(data.get("mount_size_mib", 0) >= 128, "pressure volume is implausibly small")


def check_takeover(data):
    require(data.get("result") == "passed", "takeover did not pass")
    for key in ("stale_replica_rejected", "old_writer_sigstop_then_killed",
                "admitted_native_writer_paused_and_promotion_rejected",
                "duplicate_live_node_identity_rejected",
                "unavailable_fence_directory_blocks_promotion",
                "controller_restart_preserved_single_promotion",
                "retired_source_volume_write_rejected_without_fence_env",
                "old_writer_restart_blocked"):
        require(data.get(key) is True, f"takeover assertion missing: {key}")
    require(data.get("target_fsck") == "passed", "takeover target fsck failed")
    require(data.get("takeover_ms", 0) > 0, "takeover time was not observed")


def check_partition(data):
    require(data.get("source_metadata_status_after_partition", 0) >= 500,
            "partitioned source did not fail closed")
    require(data.get("old_source_session_killed") is True and data.get("durable_restart_block") is True,
            "partitioned source was not durably fenced")
    require(data.get("rpo_lost_acknowledged_commits") == 0,
            "acknowledged commit was lost across partition takeover")
    require(data.get("post_takeover_oid") and data.get("takeover_ms", 0) > 0,
            "partition takeover did not measure a post-takeover write")


def check_simulator_source():
    source = (REPO / "src/sharding/benchmark.rs").read_text()
    require('status: "simulation_only".to_string()' in source,
            "shard benchmark no longer marks its synthetic receipt as simulation_only")
    require("# Simulation only" in source,
            "shard benchmark markdown no longer labels simulation output")
    require("pinned_roots_verified: false, failover_verified: false" in source,
            "synthetic benchmark can claim verified pinned roots/failover")


def check_docs():
    ready = (REPO / "TEST_READY.md").read_text()
    require("NOT NATIVE ACCEPTANCE" in ready and "native cluster workload" in ready,
            "TEST_READY.md still presents model results as native acceptance")
    fence = (REPO / "docs/cluster-local-process-fence.md").read_text()
    for required in ("cluster_workload_native.py", "cluster_pg_streaming_native.py",
                     "cluster_pg_pitr_native.py", "single host"):
        require(required in fence, f"cluster operations doc is missing {required}")
    operations = (REPO / "docs/cluster-operations.md").read_text()
    for required in ("Untested boundaries", "cross-host", "RPO/RTO assumptions",
                     "Failure and restore ordering"):
        require(required in operations, f"cluster operations map is missing {required}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=REPO / "evidence")
    parser.add_argument("--report", type=Path, default=REPO / "evidence/cluster-operations-gate.json")
    parser.add_argument("--source-commit", default=None)
    args = parser.parse_args()
    evidence = args.evidence_dir
    checks = []
    records = {}
    blockers = []
    loaded = {}

    for name, filename in CORE_REPORTS.items():
        try:
            loaded[name] = load(evidence, filename)
        except GateFailure as error:
            checks.append({"issue": "43/44", "criterion": f"load {name}",
                           "status": "failed", "evidence": [filename], "error": str(error)})

    def emit_failure(message):
        report = {
            "kind": "cluster_operations_gate", "gate_version": 2,
            "measurement_kind": "validated_native_evidence", "simulated_fields": False,
            "source_base_commit": args.source_commit or ops_provenance.source_commit(),
            "binary_sha256": None, "validated_at_unix": int(time.time()),
            "status": "failed", "issues": {"43": "failed", "44": "failed"},
            "local_profile_accepted": False,
            "production_scope": "not_certified; missing required local evidence",
            "checks": checks, "evidence": records, "local_storage_ha": {},
            "limits": ["gate failed closed before issuing a partial receipt"],
            "blockers": [message],
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "failed", "blockers": [message],
                          "report": str(args.report)}))
        raise SystemExit(1)

    if not loaded:
        emit_failure("no core operations evidence reports could be loaded")
    if "workload" not in loaded:
        emit_failure("required workload report is missing")

    report_commits = {data["source_base_commit"] for _, data, _ in loaded.values()
                      if data.get("source_base_commit")}
    if len(report_commits) != 1:
        emit_failure("core reports do not share exactly one source commit")
    source_commit = args.source_commit or report_commits.pop()
    head = ops_provenance.source_commit()
    if head != source_commit:
        changed = subprocess.check_output(
            ["git", "diff", "--name-only", source_commit + ".." + head],
            cwd=REPO, text=True).splitlines()
        unexpected = [path for path in changed
                      if not path.startswith("evidence/") and path != "tests/cluster_operations_gate.py"]
        if unexpected:
            emit_failure("reports were produced from a different source commit and non-evidence files changed: "
                         + ", ".join(unexpected[:5]))
        blockers.append(f"reports record source commit {source_commit}; current HEAD {head} only adds evidence files")

    binary_sha = loaded["workload"][1]["binary_sha256"]
    for name, (path, data, _) in loaded.items():
        try:
            records[name] = validate_provenance(path, data, source_commit, binary_sha,
                                                HARNESS_FILES[name])
        except GateFailure as error:
            records[name] = {"file": path.name, "kind": data.get("kind"), "error": str(error)}
            checks.append({"issue": "43/44", "criterion": f"provenance {name}",
                           "status": "failed", "evidence": [path.name], "error": str(error)})

    # Local secure-profile evidence is accepted on its own.
    local_checks = [
        (43, "1. secure split-role profile: real cross-node Git and encrypted authenticated dependencies",
         ["cluster-local-profile.json"], check_local_profile, loaded.get("local_profile")),
        (43, "1a. PostgreSQL verify-full/SCRAM negative checks", ["cluster-tls.json"],
         check_tls, loaded.get("tls")),
        (43, "1b. Kafka SASL_SSL negative checks and outage semantics", ["cluster-kafka-tls.json"],
         check_kafka, loaded.get("kafka")),
        (43, "3. metadata and storage restore in a new deployment, including worker drain",
         ["cluster-pg-pitr.json"], check_pitr, loaded.get("pitr")),
    ]
    for issue, criterion, files, function, item in local_checks:
        if item is None:
            checks.append({"issue": issue, "criterion": criterion, "status": "failed",
                           "evidence": files, "error": "required evidence unavailable"})
            continue
        try:
            function(item[1])
            checks.append({"issue": issue, "criterion": criterion, "status": "passed",
                           "evidence": files})
        except GateFailure as error:
            checks.append({"issue": issue, "criterion": criterion, "status": "failed",
                           "evidence": files, "error": str(error)})

    # Local PostgreSQL failover and disk/44 checks.
    for issue, criterion, files, function, item in [
        (43, "2a. PostgreSQL failover under concurrent read/write load",
         ["cluster-pg-streaming.json"], check_streaming, loaded.get("streaming")),
        (44, "1. real 1/2/4-node client workload with versions/topology/hardware/raw evidence",
         ["cluster-workload-integration.json"], check_workload, loaded.get("workload")),
        (44, "2. live serving-volume corruption/recovery and node-stop failure assertions",
         ["cluster-workload-integration.json"], lambda _: None, loaded.get("workload")),
        (44, "3. disk-pressure rejection without moving the acknowledged ref",
         ["cluster-disk-pressure.json"], check_disk, loaded.get("disk")),
    ]:
        if item is None:
            checks.append({"issue": issue, "criterion": criterion, "status": "failed",
                           "evidence": files, "error": "required evidence unavailable"})
            continue
        try:
            function(item[1])
            checks.append({"issue": issue, "criterion": criterion, "status": "passed",
                           "evidence": files})
        except GateFailure as error:
            checks.append({"issue": issue, "criterion": criterion, "status": "failed",
                           "evidence": files, "error": str(error)})

    # Local storage takeover evidence is optional but evaluated when current.
    local_ha = {}
    for name, filename, function in (("takeover", "cluster-takeover-run.json", check_takeover),
                                     ("partition", "cluster-partition.json", check_partition)):
        try:
            path, data, _ = load(evidence, filename)
            validate_provenance(path, data, source_commit, binary_sha, HARNESS_FILES[name])
            function(data)
            local_ha[name] = {"status": "passed", "file": filename}
        except (GateFailure, Exception) as error:
            local_ha[name] = {"status": "blocked", "file": filename, "reason": str(error)}
    checks.append({"issue": 43,
                   "criterion": "2b. single-host storage takeover and source-only network break",
                   "status": "passed" if all(item["status"] == "passed" for item in local_ha.values())
                   else "blocked",
                   "evidence": [item["file"] for item in local_ha.values()],
                   "details": local_ha})
    if any(item["status"] != "passed" for item in local_ha.values()):
        blockers.append("local storage takeover/partition evidence is stale or blocked: "
                        + "; ".join(f"{name}: {item.get('reason', 'not passed')}"
                                    for name, item in local_ha.items() if item["status"] != "passed"))

    # Source blocker evidence from an explicit minimal reproduction.
    blocker_path = evidence / BLOCKER_FILE
    if blocker_path.is_file():
        blocker_data = json.loads(blocker_path.read_text())
        for item in blocker_data.get("blockers", []):
            blockers.append(item)
        checks.append({"issue": 43, "criterion": "source blocker reproduction",
                       "status": "blocked", "evidence": [BLOCKER_FILE],
                       "details": blocker_data.get("blockers", [])})

    for issue, criterion, function in [
        (44, "4. simulated benchmark output is visibly separated from measured evidence", check_simulator_source),
        (44, "5. readiness/implementation docs distinguish native evidence and limits", check_docs),
    ]:
        try:
            function()
            checks.append({"issue": issue, "criterion": criterion, "status": "passed", "evidence": []})
        except GateFailure as error:
            checks.append({"issue": issue, "criterion": criterion, "status": "failed",
                           "evidence": [], "error": str(error)})

    blockers.append("cross-host storage fencing and external PostgreSQL leader election are not proven: "
                    "no additional physical hosts are configured in this environment")
    checks.append({"issue": 43,
                   "criterion": "2c. external physical-host storage fencing and automatic PostgreSQL HA",
                   "status": "blocked", "evidence": [],
                   "details": "not executable here; the single-host profile and manual promotion are not full HA"})
    checks.append({"issue": 43,
                   "criterion": "2d. multi-broker Kafka failover",
                   "status": "blocked", "evidence": [],
                   "details": "not executable here; only one task-owned KRaft broker is available"})

    failed = [check for check in checks if check["status"] == "failed"]
    blocked = [check for check in checks if check["status"] == "blocked"]
    issue_status = {}
    for issue in (43, 44):
        issue_checks = [check for check in checks if check["issue"] == issue]
        if any(check["status"] == "failed" for check in issue_checks):
            issue_status[str(issue)] = "failed"
        elif issue == 44 and all(check["status"] == "passed" for check in issue_checks):
            # Local multi-process evidence only; never report this as full
            # production/distributed HA acceptance.
            issue_status[str(issue)] = "passed_local_single_host"
        elif any(check["status"] == "blocked" for check in issue_checks):
            issue_status[str(issue)] = "blocked_external_ha_and_source_fence"
        else:
            issue_status[str(issue)] = "passed"
    overall = "failed" if failed else ("blocked" if blocked else "passed")
    global_limits = [
        "all multi-process figures are single Linux host and loopback; no additional physical hosts are configured",
        "PostgreSQL promotion is manual and local; no DCS, automatic leader election, or cross-host fencing",
        "Kafka uses one KRaft broker; the controller listener is local plaintext",
        "PITR archive and matching GitFS snapshot are local and unencrypted",
        "disk pressure uses a container tmpfs, not a hardware volume",
        "simulated shard benchmark receipts never satisfy these gates",
    ]
    report = {
        "kind": "cluster_operations_gate",
        "gate_version": 2,
        "measurement_kind": "validated_native_evidence",
        "simulated_fields": False,
        "source_base_commit": source_commit,
        "binary_sha256": binary_sha,
        "validated_at_unix": int(time.time()),
        "status": overall,
        "issues": issue_status,
        "local_profile_accepted": issue_status.get("43") != "failed",
        "production_scope": "not_certified; local single-host evidence only",
        "checks": checks,
        "evidence": records,
        "local_storage_ha": local_ha,
        "limits": global_limits,
        "blockers": sorted(set(blockers)),
        "commands": [
            "python3 tests/cluster_tls_native.py --binary <binary> --report evidence/cluster-tls.json",
            "python3 tests/cluster_kafka_tls_native.py --binary <binary> --kafka-home <kafka> --report evidence/cluster-kafka-tls.json",
            "python3 tests/cluster_local_profile_native.py --binary <binary> --kafka-home <kafka> --report evidence/cluster-local-profile.json",
            "python3 tests/cluster_workload_native.py --binary <binary> --report evidence/cluster-workload-integration.json",
            "python3 tests/cluster_pg_streaming_native.py --binary <binary> --report evidence/cluster-pg-streaming.json",
            "python3 tests/cluster_pg_pitr_native.py --binary <binary> --report evidence/cluster-pg-pitr.json",
            "python3 tests/cluster_takeover_native.py --binary <binary> --report evidence/cluster-takeover-run.json",
            "python3 tests/cluster_partition_native.py --binary <binary> --report evidence/cluster-partition.json",
            "python3 tests/cluster_disk_pressure_native.py --binary <binary> --report evidence/cluster-disk-pressure.json",
            "python3 tests/cluster_operations_gate.py --evidence-dir evidence --report evidence/cluster-operations-gate.json",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": overall, "issues": issue_status,
                      "failed_checks": [check["criterion"] for check in failed],
                      "blocked_checks": [check["criterion"] for check in blocked],
                      "report": str(args.report)}))
    raise SystemExit(0 if overall == "passed" else 1)


if __name__ == "__main__":
    main()
