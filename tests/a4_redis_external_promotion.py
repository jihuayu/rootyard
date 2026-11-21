#!/usr/bin/env python3
"""Opt-in external A4 Redis replica promotion acceptance (Refs #111).

This standalone case reuses the owned external-A4 fixture and relay from
``tests/a4_redis_wake_partition.py``. It adds exactly one owned replica and
proves, with positive evidence, that:

* two freshly spawned loopback Redis processes are independently fixture-owned;
* the replica really streams a harmless key canary from the exact primary;
* after the relay is cut and the exact primary is stopped, an ordinary stock
  Git push still reaches the already-running external A4 worker through its
  PostgreSQL poll, without a Redis publish or relay forwarding;
* the already-proved replica, and only that replica, is promoted after the old
  primary is gone;
* the same worker process reconnects at the unchanged relay endpoint and a
  fresh ordinary operation is delivered by wake before its next periodic poll;
* duplicate/invalid hints still leave durable PostgreSQL authority unchanged.

No native result is claimed from source inspection. Run only against an owned
PostgreSQL/Garage/Redis fixture with an exact attested binary and matching source
commit.
"""
import argparse
import json
from pathlib import Path
import re
import signal
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import a4_redis_wake_partition as a4
from a4_redis_wake_partition import A4RedisWakeHarness, POLL_SECONDS, TARGET_REF
from backup_recovery_cache import OwnedRestoreRedis, build_binding
from blob_only_service import sha256_file, write_report
from cross_process_failover import replication_status

CASE = "real_a4_external_redis_replica_promotion"
CASE_STAGES = a4.CASE_STAGES + (
    "outage_pg_poll",
    "promotion",
    "reconnect",
    "post_promotion_wake",
    "post_promotion_duplicate_hints",
    "promotion_validation",
)
REPORT_KIND = "rootyard/a4-redis-external-promotion-acceptance"
CANARY = b"owned-a4-replica"
LIMITATIONS = list(a4.LIMITATIONS) + [
    "This case stops and promotes one already-owned loopback replica after the exact fixture primary is stopped; it is not Sentinel/Cluster, split-brain fencing, kernel, power-loss or multi-host failover evidence.",
    "The stable relay endpoint is one test-only loopback socket; production TLS/ACL/address discovery is not exercised here.",
]

# Only fixed booleans, positive integer counts and exact UUIDs belong in a
# passing report. Any other shape is rejected rather than copied into a report.
CASE_DETAIL_TYPES = dict(a4.CASE_DETAIL_TYPES)
CASE_DETAIL_TYPES.update({
    "owned_primary_and_replica_loopback_verified": bool,
    "replica_link_and_canary_verified": bool,
    "owned_primary_stopped": bool,
    "outage_push_delivered_by_postgres_poll": bool,
    "outage_push_no_redis_publish": bool,
    "owned_replica_promoted": bool,
    "same_worker_reconnected_at_stable_relay_endpoint": bool,
    "post_promotion_wake_before_periodic_poll": bool,
    "same_worker_process_preserved": bool,
    "post_promotion_duplicate_hints_preserved_snapshot": bool,
})
REQUIRED_PROMOTION_TRUE = (
    "owned_primary_and_replica_loopback_verified",
    "replica_link_and_canary_verified",
    "owned_primary_stopped",
    "outage_push_delivered_by_postgres_poll",
    "outage_push_no_redis_publish",
    "owned_replica_promoted",
    "same_worker_reconnected_at_stable_relay_endpoint",
    "post_promotion_wake_before_periodic_poll",
    "same_worker_process_preserved",
    "post_promotion_duplicate_hints_preserved_snapshot",
)
REQUIRED_BASE_TRUE = (
    "external_worker_mode_serving",
    "no_embedded_consumer_before_external_start",
    "external_worker_only_claim",
    "healthy_publish_forwarded",
    "healthy_delivery_before_periodic_poll",
    "durable_terminal_ref_object_hold_outbox",
    "redis_cut_push_acknowledged",
    "redis_cut_delivery_by_postgres_poll",
    "redis_cut_no_publish_forwarded",
    "duplicate_and_invalid_hints_preserved_snapshot",
    "no_legacy_ref_index_or_projection",
)
REQUIRED_OPERATION_FIELDS = (
    "initial_operation",
    "healthy_operation",
    "cut_operation",
    "healed_operation",
)


def validate_case_detail(detail):
    """Project a passing detail onto the fixed typed report schema."""
    if not isinstance(detail, dict):
        raise AssertionError("A4 promotion detail is not an object")
    projected = {}
    for key, value in detail.items():
        expected = CASE_DETAIL_TYPES.get(key)
        if expected is None:
            continue
        if expected is bool:
            if type(value) is not bool:
                raise AssertionError("A4 promotion detail field has the wrong type")
        elif expected == "uuid":
            if not isinstance(value, str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value
            ):
                raise AssertionError("A4 promotion detail field has the wrong type")
        elif expected == "positive_int":
            if type(value) is not int or value <= 0:
                raise AssertionError("A4 promotion detail field has the wrong type")
        projected[key] = value
    return projected


def require_promotion_witness(detail):
    """Fail closed unless every fixed promotion witness is present and true."""
    if not isinstance(detail, dict):
        raise AssertionError("A4 promotion witness is not an object")
    for key in REQUIRED_BASE_TRUE + REQUIRED_PROMOTION_TRUE:
        if detail.get(key) is not True:
            raise AssertionError("A4 promotion witness is incomplete: " + key)
    for key in REQUIRED_OPERATION_FIELDS:
        value = detail.get(key)
        if not isinstance(value, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value
        ):
            raise AssertionError("A4 promotion operation witness is incomplete: " + key)
    if type(detail.get("poll_seconds")) is not int or detail["poll_seconds"] <= 0:
        raise AssertionError("A4 promotion poll witness is incomplete")
    return detail


class A4RedisPromotionHarness(A4RedisWakeHarness):
    def __init__(self, args, profile, blob_profile, redis_binary, containment=None):
        super().__init__(args, profile, blob_profile, redis_binary, containment)
        self.primary = self.owned_redis
        self.replica = OwnedRestoreRedis(redis_binary)
        self.replica_root = None
        self.canary_key = ("rootyard:a4:test:" + self.schema + ":replication-canary").encode("ascii")

    # ---- owned fixture ---------------------------------------------------
    def setup_partition(self):
        super().setup_partition()
        self.replica_root = self.root / "replica"
        self.replica_root.mkdir()
        self.replica.start(self.replica_root)
        self.configure_replication()

    def configure_replication(self):
        primary, replica = self.primary, self.replica
        assert primary.redis_port != replica.redis_port
        assert primary.process.pid != replica.process.pid
        assert primary.run_id != replica.run_id
        self.prove_owned_redis(primary, self.root)
        self.prove_owned_redis(replica, self.replica_root)
        assert replication_status(primary)[b"role"] == b"master"

        def unattached(command):
            assert replication_status(replica, command)[b"role"] == b"master"

        assert replica.redis_command(
            "REPLICAOF", "127.0.0.1", primary.redis_port, before_send=unattached
        ) == b"OK"
        self.until(lambda: self.replica_link(b"up"), "owned replica linked", timeout=15)
        assert replication_status(primary)[b"connected_slaves"] == b"1"
        assert replica.redis_command("STRLEN", self.canary_key) == 0

        def primary_role(command):
            assert replication_status(primary, command)[b"role"] == b"master"

        assert primary.redis_command(
            "SET", self.canary_key, CANARY, before_send=primary_role
        ) == b"OK"
        self.until(
            lambda: replica.redis_command("STRLEN", self.canary_key) == len(CANARY),
            "replica received primary canary",
            timeout=5,
        )
        assert replica.redis_command("GET", self.canary_key) == CANARY
        return True

    def replica_link(self, state, command=None):
        status = replication_status(self.replica, command)
        assert status[b"role"] == b"slave"
        assert status[b"master_host"] == b"127.0.0.1"
        assert int(status[b"master_port"]) == self.primary.redis_port
        return status[b"master_link_status"] == state and status[b"master_sync_in_progress"] == b"0"

    def stop_redis(self):
        first = None
        for redis in (self.primary, self.replica):
            try:
                redis.stop()
            except (Exception, KeyboardInterrupt) as error:
                first = first or error
        self.redis_started = False
        for redis in (self.primary, self.replica):
            try:
                assert redis.process is None or redis.process.poll() is not None, \
                    "owned Redis process did not exit"
            except (Exception, KeyboardInterrupt) as error:
                first = first or error
        if first is not None:
            raise first

    # ---- named phases ----------------------------------------------------
    def outage_pg_poll_push(self, work, repo, first_poll):
        self.settle_worker()
        published = self.publishes()
        relay_before = self.relay.counts()
        assert self.relay.target == ("127.0.0.1", self.primary.redis_port)
        assert relay_before.active >= 1 and self.subscriber_count() == 1, \
            "no established external subscriber to cut"
        assert self.relay.cut() >= 1, "relay cut reaped no established connection"
        self.until(
            lambda: self.subscriber_count() == 0 and self.relay.counts().refused > relay_before.refused,
            "cut subscriber and refused reconnect",
            timeout=10,
        )
        assert self.publishes() == published, "cut relay still forwarded a publish"
        self.prove_owned_redis(self.primary, self.root)
        self.primary.stop()
        assert self.primary.process.poll() is not None, "owned primary did not stop"
        self.until(lambda: self.replica_link(b"down"), "replica observed stopped primary", timeout=5)
        self.owned_redis = self.replica
        replica_published = self.publishes()
        relay_cut = self.relay.counts()

        oid, operation, _ = self.commit_and_push(work, "outage-" + uuid.uuid4().hex)
        assert self.git(
            "ls-remote", "--refs", self.base + repo["clone_path"], TARGET_REF, token=self.alice
        ).returncode == 0
        remaining = first_poll - 1 - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        assert time.monotonic() < first_poll, "fixture missed the pre-poll observation window"
        assert self.audit_count(operation) == 0, "cut delivery occurred before the PostgreSQL poll"
        assert self.publishes() == replica_published, "outage push published to the owned Redis"
        assert self.relay.counts().forwarded == relay_cut.forwarded, "cut relay forwarded the outage push"
        self.until(
            lambda: self.audit_count(operation) == 1,
            "external worker PostgreSQL poll delivered after cut",
            timeout=max(1.0, first_poll - time.monotonic()) + 10,
        )
        assert time.monotonic() >= first_poll, "pre-poll delivery was mislabeled as fallback"
        assert self.publishes() == replica_published, "fallback delivery was accompanied by a Redis publish"
        assert self.relay.counts().forwarded == relay_cut.forwarded, "cut relay forwarded a hint"
        self.assert_claim(operation)
        self.assert_operation(repo["id"], operation, oid, delivered=True)
        return oid, operation

    def promote_replica(self):
        assert self.primary.process.poll() is not None, "old primary is still live"
        assert self.owned_redis is self.replica, "current fixture Redis is not the owned replica"
        replica_pid = self.replica.process.pid
        replica_run_id = self.replica.run_id
        self.prove_owned_redis(self.replica, self.replica_root)
        assert self.replica_link(b"down"), "owned replica did not observe the primary stop"

        def attached_to_stopped_primary(command):
            assert self.primary.process.poll() is not None, "old primary restarted before promotion"
            assert self.replica_link(b"down", command), "owned replica was not still attached to the stopped primary"

        assert self.replica.redis_command(
            "REPLICAOF", "NO", "ONE", before_send=attached_to_stopped_primary
        ) == b"OK"
        self.until(
            lambda: replication_status(self.replica)[b"role"] == b"master",
            "owned replica became master",
            timeout=5,
        )
        assert self.replica.process.pid == replica_pid, "promoted Redis process changed"
        assert self.replica.run_id == replica_run_id, "promoted Redis identity changed"
        assert self.replica.redis_command("GET", self.canary_key) == CANARY, \
            "replica lost the replicated canary during promotion"
        assert self.primary.process.poll() is not None, "old primary is live after promotion"
        return True

    def reconnect_same_worker(self, worker_pid):
        assert self.worker_count == 1 and len(self.workers) == 1, "a worker was restarted or added"
        worker = self.workers[0][0]
        assert worker.pid == worker_pid and worker.poll() is None, "worker process changed before reconnect"
        endpoint = self.relay.port
        self.relay.heal(redis_port=self.replica.redis_port)
        assert self.relay.port == endpoint, "relay endpoint changed during promotion"
        assert self.relay.target == ("127.0.0.1", self.replica.redis_port)
        self.until(
            lambda: self.subscriber_count() == 1 and self.relay.counts().active >= 1,
            "same external worker resubscribed at the stable relay endpoint",
            timeout=10,
        )
        self.settle_worker()
        assert self.worker_count == 1 and len(self.workers) == 1, "a worker was restarted or added"
        assert worker.pid == worker_pid and worker.poll() is None, "worker process changed after reconnect"
        return True

    def run_case(self):
        self.case_stage = "repo_create"
        self.repo_create_code = None
        repo, _ = self.create("a4promotion", self.alice, observer=self.observe_repo_create)
        remote = self.base + repo["clone_path"]
        work = self.root / "a4promotion-work"
        self.case_stage = "empty_clone"
        self.empty_clone(remote, work, self.alice)
        self.configure(work)
        self.case_stage = "initial_push"
        initial_oid, initial_op, _ = self.commit_and_push(work, "initial")
        self.assert_ref(remote, TARGET_REF, initial_oid)
        self.case_stage = "pre_worker_assertions"
        self.assert_no_embedded_delivery(repo, initial_op, initial_oid)
        self.case_stage = "worker_startup"
        start = self.start_external_worker(repo, initial_op, initial_oid)
        worker_pid = self.workers[0][0].pid
        first_poll = start + POLL_SECONDS

        self.case_stage = "healthy_push"
        healthy_oid, healthy_op = self.healthy_push(work, repo, first_poll)
        self.assert_ref(remote, TARGET_REF, healthy_oid)
        self.case_stage = "invalid_hints"
        self.duplicate_and_invalid_hints(repo)

        self.case_stage = "outage_pg_poll"
        cut_oid, cut_op = self.outage_pg_poll_push(work, repo, first_poll)
        self.assert_ref(remote, TARGET_REF, cut_oid)

        self.case_stage = "promotion"
        assert self.promote_replica()
        self.case_stage = "reconnect"
        assert self.reconnect_same_worker(worker_pid)

        second_poll = start + 2 * POLL_SECONDS
        self.case_stage = "post_promotion_wake"
        healed_oid, healed_op = self.healthy_push(work, repo, second_poll)
        self.assert_ref(remote, TARGET_REF, healed_oid)
        self.case_stage = "post_promotion_duplicate_hints"
        self.duplicate_and_invalid_hints(repo)

        self.case_stage = "final_assertions"
        assert self.primary.process.poll() is not None, "old primary is live at final assertions"
        assert self.replica.process.poll() is None, "owned replica is not live at final assertions"
        assert replication_status(self.replica)[b"role"] == b"master"
        assert self.replica.redis_command("GET", self.canary_key) == CANARY
        assert self.worker_count == 1 and len(self.workers) == 1
        assert self.workers[0][0].pid == worker_pid and self.workers[0][0].poll() is None
        final = self.snapshot(repo["id"])
        assert final["legacy_projection"] == "0", "legacy ref projection exists"
        assert final["projection_jobs"] == "0", "legacy Ref-CAS projection job exists"

        self.case_stage = "promotion_validation"
        detail = dict(
            external_worker_mode_serving=True,
            no_embedded_consumer_before_external_start=True,
            external_worker_only_claim=True,
            healthy_publish_forwarded=True,
            healthy_delivery_before_periodic_poll=True,
            durable_terminal_ref_object_hold_outbox=True,
            redis_cut_push_acknowledged=True,
            redis_cut_delivery_by_postgres_poll=True,
            redis_cut_no_publish_forwarded=True,
            duplicate_and_invalid_hints_preserved_snapshot=True,
            no_legacy_ref_index_or_projection=True,
            initial_operation=initial_op,
            healthy_operation=healthy_op,
            cut_operation=cut_op,
            healed_operation=healed_op,
            poll_seconds=POLL_SECONDS,
            owned_primary_and_replica_loopback_verified=True,
            replica_link_and_canary_verified=True,
            owned_primary_stopped=True,
            outage_push_delivered_by_postgres_poll=True,
            outage_push_no_redis_publish=True,
            owned_replica_promoted=True,
            same_worker_reconnected_at_stable_relay_endpoint=True,
            post_promotion_wake_before_periodic_poll=True,
            same_worker_process_preserved=True,
            post_promotion_duplicate_hints_preserved_snapshot=True,
        )
        detail = validate_case_detail(detail)
        require_promotion_witness(detail)
        self.promotion_detail = detail
        return detail


def preflight(args):
    prepared = a4.preflight(args)
    prepared.fixture_harness_sha256 = prepared.harness_sha256
    prepared.harness_sha256 = sha256_file(Path(__file__))
    return prepared


def result_report(
    binding,
    case,
    passed,
    harness_sha256=None,
    fixture_harness_sha256=None,
    postgres_major=None,
    postgres_server_version_num=None,
):
    report = dict(
        kind=REPORT_KIND,
        qualification_kind="clean-candidate" if binding.get("source_head") else "unbound",
        measurement_kind="native_execution",
        simulated_fields=False,
        passed=bool(passed),
        expected_cases=[CASE],
        case_count=1,
        expected_count=1,
        skips=0,
        pending_cases=[],
        cases=[case],
        limitations=LIMITATIONS,
        **binding,
    )
    if harness_sha256:
        report["harness_sha256"] = harness_sha256
    if fixture_harness_sha256:
        report["fixture_harness_sha256"] = fixture_harness_sha256
    if postgres_major is not None:
        report["postgres_major"] = postgres_major
    if postgres_server_version_num is not None:
        report["postgres_server_version_num"] = postgres_server_version_num
    return report


def acceptance_report(args, *, harness_type=None, preflight_fn=None, containment=None, containment_factory=None):
    prepare = preflight_fn or preflight
    binding = {}
    harness = None
    harness_sha256 = None
    fixture_harness_sha256 = None
    postgres_major_value = None
    postgres_server_version_num_value = None
    primary = "preflight"
    cleanup_error = None
    detail = None
    try:
        if containment is None and containment_factory is not None:
            containment = containment_factory()
        prepared = prepare(args)
        binding = prepared.binding
        harness_sha256 = prepared.harness_sha256
        fixture_harness_sha256 = getattr(prepared, "fixture_harness_sha256", None)
        postgres_server_version_num_value = getattr(prepared, "postgres_server_version_num", None)
        postgres_major_value = a4.require_postgres_17(postgres_server_version_num_value)
        primary = "fixture"
        harness = (harness_type or A4RedisPromotionHarness)(
            args, prepared.profile, prepared.blob_profile, prepared.redis_binary,
            containment=containment,
        )
        harness.setup_partition()
        primary = "case"
        detail = harness.run_case()
        detail = validate_case_detail(detail)
        require_promotion_witness(detail)
        primary = "receipt_changed"
        assert build_binding(args.binary, args.expect_commit) == binding, "source/receipt binding changed"
        assert sha256_file(Path(__file__)) == harness_sha256, "acceptance harness changed"
        assert fixture_harness_sha256 and sha256_file(Path(a4.__file__)) == fixture_harness_sha256, \
            "reused fixture harness changed"
        primary = None
    except (Exception, KeyboardInterrupt):
        pass
    finally:
        if harness is not None:
            try:
                harness.cleanup()
            except (Exception, KeyboardInterrupt):
                cleanup_error = "cleanup"
    passed = primary is None and cleanup_error is None
    if passed:
        case = dict(name=CASE, status="passed", detail=dict(detail, owned_cleanup_completed=True))
    else:
        case = dict(name=CASE, status="failed", error=primary or cleanup_error)
        if primary == "case" and harness is not None:
            stage = getattr(harness, "case_stage", None)
            if isinstance(stage, str) and stage in CASE_STAGES:
                case["stage"] = stage
                if stage == "repo_create":
                    code = getattr(harness, "repo_create_code", None)
                    case["repo_create"] = code if isinstance(code, str) and code in a4.REPO_CREATE_CODES else "unavailable"
                if stage == "worker_startup":
                    code = getattr(harness, "worker_startup_code", None)
                    case["worker_startup"] = code if isinstance(code, str) and code in a4.WORKER_STARTUP_CODES else "unavailable"
                if stage == "invalid_hints":
                    code = getattr(harness, "invalid_hints_code", None)
                    case["invalid_hints"] = code if isinstance(code, str) and code in a4.INVALID_HINT_CODES else "unavailable"
        if cleanup_error is not None:
            case["cleanup_failed"] = True
        if primary is not None and cleanup_error is not None:
            case["cleanup_error"] = cleanup_error
    return result_report(
        binding,
        case,
        passed,
        harness_sha256,
        fixture_harness_sha256,
        postgres_major_value,
        postgres_server_version_num_value,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="absolute attested rootyard binary")
    parser.add_argument("--git", help="absolute trusted Git (defaults to ROOTYARD_GIT)")
    parser.add_argument("--expect-commit", required=True, help="exact clean source commit bound to the binary")
    parser.add_argument("--report", type=Path, required=True, help="exact JSON report destination")
    parser.add_argument("--keep", action="store_true", help="keep temporary files on successful cleanup; failed cleanup retains diagnostics and schema")
    args = parser.parse_args(argv)
    args.binary = str(args.binary.resolve())

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        report = acceptance_report(args, containment_factory=a4.LinuxChildSubreaper.install)
        try:
            write_report(args.report, report)
        except OSError:
            report = result_report(
                {key: value for key, value in report.items() if key in (
                    "source_head", "source_tree", "source_inputs_sha256",
                    "binary_sha256", "build_receipt_sha256",
                )},
                dict(name=CASE, status="failed", error="report_write"),
                False,
                report.get("harness_sha256"),
                report.get("fixture_harness_sha256"),
                report.get("postgres_major"),
                report.get("postgres_server_version_num"),
            )
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
