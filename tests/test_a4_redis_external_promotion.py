"""Pure tests for the opt-in external A4 replica-promotion acceptance."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import ANY, Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import a4_redis_external_promotion as promotion
from a4_redis_external_promotion import A4RedisPromotionHarness
from redis_partition_relay import RelayCounts


ROOT = Path(__file__).resolve().parents[1]


def complete_detail():
    return {
        "external_worker_mode_serving": True,
        "no_embedded_consumer_before_external_start": True,
        "external_worker_only_claim": True,
        "healthy_publish_forwarded": True,
        "healthy_delivery_before_periodic_poll": True,
        "durable_terminal_ref_object_hold_outbox": True,
        "redis_cut_push_acknowledged": True,
        "redis_cut_delivery_by_postgres_poll": True,
        "redis_cut_no_publish_forwarded": True,
        "duplicate_and_invalid_hints_preserved_snapshot": True,
        "no_legacy_ref_index_or_projection": True,
        "initial_operation": "11111111-1111-1111-1111-111111111111",
        "healthy_operation": "22222222-2222-2222-2222-222222222222",
        "cut_operation": "33333333-3333-3333-3333-333333333333",
        "healed_operation": "44444444-4444-4444-4444-444444444444",
        "poll_seconds": promotion.POLL_SECONDS,
        "owned_primary_and_replica_loopback_verified": True,
        "replica_link_and_canary_verified": True,
        "owned_primary_stopped": True,
        "outage_push_delivered_by_postgres_poll": True,
        "outage_push_no_redis_publish": True,
        "owned_replica_promoted": True,
        "same_worker_reconnected_at_stable_relay_endpoint": True,
        "post_promotion_wake_before_periodic_poll": True,
        "same_worker_process_preserved": True,
        "post_promotion_duplicate_hints_preserved_snapshot": True,
    }


class ReplicationSetupTest(unittest.TestCase):
    def harness(self):
        harness = object.__new__(A4RedisPromotionHarness)
        harness.root = Path("/tmp/owned-primary")
        harness.replica_root = Path("/tmp/owned-replica")
        harness.primary = SimpleNamespace(redis_port=16379, run_id=b"p" * 40)
        harness.primary.process = SimpleNamespace(pid=4101, poll=Mock(return_value=None))
        harness.primary.redis_command = Mock(return_value=b"OK")
        harness.replica = Mock(redis_port=16380, run_id=b"r" * 40)
        harness.replica.process = SimpleNamespace(pid=4102, poll=Mock(return_value=None))
        harness.canary_key = b"rootyard-test:canary"
        harness.prove_owned_redis = Mock()
        harness.replica_link = Mock(return_value=True)
        harness.until = Mock(side_effect=lambda predicate, *_args, **_kwargs: self.assertTrue(predicate()))
        return harness

    def test_both_owned_servers_are_proved_and_only_the_canary_replicates(self):
        harness = self.harness()
        sent = []

        def command(*parts, before_send=None):
            if before_send is not None:
                before_send(Mock())
            sent.append(parts)
            if parts == ("REPLICAOF", "127.0.0.1", 16379):
                return b"OK"
            if parts[0] == "STRLEN":
                return 0 if sent.count(("STRLEN", harness.canary_key)) == 1 else len(promotion.CANARY)
            if parts[0] == "GET":
                return promotion.CANARY
            raise AssertionError("unexpected replica command")

        harness.replica.redis_command.side_effect = command
        with patch.object(promotion, "replication_status", side_effect=lambda redis, command=None: {
            b"role": b"master",
            b"connected_slaves": b"1",
        }):
            self.assertTrue(harness.configure_replication())

        self.assertEqual(harness.prove_owned_redis.call_args_list, [
            call(harness.primary, harness.root),
            call(harness.replica, harness.replica_root),
        ])
        self.assertEqual(sent, [
            ("REPLICAOF", "127.0.0.1", 16379),
            ("STRLEN", harness.canary_key),
            ("STRLEN", harness.canary_key),
            ("GET", harness.canary_key),
        ])
        harness.primary.redis_command.assert_called_once_with(
            "SET", harness.canary_key, promotion.CANARY, before_send=ANY,
        )

    def test_same_port_pid_or_run_id_is_refused_before_any_proof(self):
        for field, value in (
            ("redis_port", 16379),
            ("process", SimpleNamespace(pid=4101, poll=Mock(return_value=None))),
            ("run_id", b"p" * 40),
        ):
            with self.subTest(field=field):
                harness = self.harness()
                if field == "process":
                    harness.replica.process = value
                else:
                    setattr(harness.replica, field, value)
                with self.assertRaises(AssertionError):
                    harness.configure_replication()
                harness.prove_owned_redis.assert_not_called()
                harness.replica.redis_command.assert_not_called()


class PromotionTransitionTest(unittest.TestCase):
    def harness(self):
        harness = object.__new__(A4RedisPromotionHarness)
        harness.root = Path("/tmp/owned-primary")
        harness.replica_root = Path("/tmp/owned-replica")
        harness.primary = SimpleNamespace(redis_port=16379, run_id=b"p" * 40)
        harness.primary.process = SimpleNamespace(pid=4101, poll=Mock(return_value=0))
        harness.replica = Mock(redis_port=16380, run_id=b"r" * 40)
        harness.replica.process = SimpleNamespace(pid=4102, poll=Mock(return_value=None))
        harness.owned_redis = harness.replica
        harness.canary_key = b"rootyard-test:canary"
        harness.prove_owned_redis = Mock()
        harness.replica_link = Mock(return_value=True)
        harness.relay = Mock()
        harness.until = Mock(side_effect=lambda predicate, *_args, **_kwargs: self.assertTrue(predicate()))
        return harness

    def test_promotion_is_closed_without_a_stopped_primary_or_owned_replica(self):
        cases = (
            ("primary-live", lambda h: setattr(h.primary.process, "poll", Mock(return_value=None))),
            ("not-replica", lambda h: setattr(h, "owned_redis", Mock())),
            ("proof", lambda h: setattr(h.prove_owned_redis, "side_effect", AssertionError("private"))),
            ("link", lambda h: setattr(h.replica_link, "return_value", False)),
        )
        for name, configure in cases:
            with self.subTest(name=name):
                harness = self.harness()
                configure(harness)
                with self.assertRaises(AssertionError):
                    harness.promote_replica()
                harness.replica.redis_command.assert_not_called()
                harness.relay.heal.assert_not_called()

    def test_replica_only_becomes_primary_after_identity_and_down_link_proof(self):
        harness = self.harness()
        sent = []

        def command(*parts, before_send=None):
            if before_send is not None:
                before_send(Mock())
            sent.append(parts)
            if parts[0] == "REPLICAOF":
                return b"OK"
            if parts[0] == "GET":
                return promotion.CANARY
            raise AssertionError("unexpected replica command")

        harness.replica.redis_command.side_effect = command
        with patch.object(promotion, "replication_status", return_value={b"role": b"master"}):
            self.assertTrue(harness.promote_replica())

        self.assertEqual(sent, [
            ("REPLICAOF", "NO", "ONE"),
            ("GET", harness.canary_key),
        ])
        harness.prove_owned_redis.assert_called_once_with(harness.replica, harness.replica_root)
        self.assertEqual(harness.replica_link.call_args_list, [
            call(b"down"),
            call(b"down", ANY),
        ])
        harness.relay.heal.assert_not_called()

    def test_changed_replica_identity_after_promotion_fails_closed(self):
        harness = self.harness()
        harness.replica.redis_command.side_effect = [b"OK", promotion.CANARY]

        def until(predicate, *_args, **_kwargs):
            harness.replica.run_id = b"changed"
            return True

        harness.until = Mock(side_effect=until)
        with patch.object(promotion, "replication_status", return_value={b"role": b"master"}):
            with self.assertRaises(AssertionError):
                harness.promote_replica()
        harness.relay.heal.assert_not_called()


class SameWorkerReconnectTest(unittest.TestCase):
    def harness(self):
        harness = object.__new__(A4RedisPromotionHarness)
        harness.worker_count = 1
        harness.workers = [(SimpleNamespace(pid=777, poll=Mock(return_value=None)), Mock())]
        harness.replica = SimpleNamespace(redis_port=16380)
        harness.subscriber_count = Mock(return_value=1)
        harness.settle_worker = Mock()
        harness.until = Mock(side_effect=lambda predicate, *_args, **_kwargs: self.assertTrue(predicate()))
        harness.relay = SimpleNamespace(
            port=26379,
            target=("127.0.0.1", 16379),
            counts=Mock(return_value=RelayCounts(4, 2, 1)),
        )

        def heal(*, redis_port=None):
            harness.relay.target = ("127.0.0.1", redis_port)

        harness.relay.heal = Mock(side_effect=heal)
        return harness

    def test_same_worker_reconnects_on_the_unchanged_relay_endpoint(self):
        harness = self.harness()
        worker = harness.workers[0][0]
        self.assertTrue(harness.reconnect_same_worker(worker.pid))
        harness.relay.heal.assert_called_once_with(redis_port=16380)
        self.assertEqual(harness.relay.target, ("127.0.0.1", 16380))
        harness.settle_worker.assert_called_once_with()
        self.assertIsNone(worker.poll())
        self.assertEqual(harness.worker_count, 1)
        self.assertEqual(len(harness.workers), 1)

    def test_worker_restart_or_pid_change_never_heals_the_relay(self):
        cases = (
            ("extra-worker", lambda h: setattr(h, "worker_count", 2)),
            ("changed-pid", lambda h: setattr(h, "workers", [
                (SimpleNamespace(pid=778, poll=Mock(return_value=None)), Mock()),
            ])),
        )
        for name, configure in cases:
            with self.subTest(name=name):
                harness = self.harness()
                configure(harness)
                with self.assertRaises(AssertionError):
                    harness.reconnect_same_worker(777)
                harness.relay.heal.assert_not_called()
                harness.settle_worker.assert_not_called()


class CleanupTest(unittest.TestCase):
    def test_both_redis_servers_are_stopped_after_one_failure(self):
        harness = object.__new__(A4RedisPromotionHarness)
        harness.redis_started = True
        harness.primary = Mock()
        harness.primary.process = SimpleNamespace(poll=Mock(return_value=0))
        harness.replica = Mock()
        harness.replica.process = SimpleNamespace(poll=Mock(return_value=0))
        harness.replica.stop.side_effect = RuntimeError("synthetic")
        with self.assertRaises(RuntimeError):
            harness.stop_redis()
        harness.primary.stop.assert_called_once_with()
        harness.replica.stop.assert_called_once_with()
        self.assertFalse(harness.redis_started)

    def test_live_redis_after_stop_fails_cleanup(self):
        harness = object.__new__(A4RedisPromotionHarness)
        harness.redis_started = True
        harness.primary = Mock()
        harness.primary.process = SimpleNamespace(poll=Mock(return_value=None))
        harness.replica = Mock()
        harness.replica.process = SimpleNamespace(poll=Mock(return_value=0))
        with self.assertRaisesRegex(AssertionError, "did not exit"):
            harness.stop_redis()
        harness.primary.stop.assert_called_once_with()
        harness.replica.stop.assert_called_once_with()


class DetailValidationTest(unittest.TestCase):
    def test_complete_witness_is_projected_and_accepted(self):
        detail = dict(complete_detail(), private="ignored")
        projected = promotion.validate_case_detail(detail)
        self.assertNotIn("private", projected)
        self.assertIs(promotion.require_promotion_witness(projected), projected)

    def test_every_promotion_base_and_operation_witness_is_required(self):
        for key in (
            promotion.REQUIRED_PROMOTION_TRUE
            + promotion.REQUIRED_BASE_TRUE
            + promotion.REQUIRED_OPERATION_FIELDS
        ):
            with self.subTest(key=key):
                detail = complete_detail()
                if key in promotion.REQUIRED_OPERATION_FIELDS:
                    detail.pop(key)
                else:
                    detail[key] = False
                projected = promotion.validate_case_detail(detail)
                with self.assertRaisesRegex(AssertionError, key):
                    promotion.require_promotion_witness(projected)
        detail = complete_detail()
        detail["poll_seconds"] = 0
        with self.assertRaises(AssertionError):
            promotion.require_promotion_witness(promotion.validate_case_detail(detail))

    def test_wrong_types_fail_before_projection(self):
        bad = complete_detail()
        bad["owned_replica_promoted"] = "true"
        with self.assertRaisesRegex(AssertionError, "wrong type"):
            promotion.validate_case_detail(bad)
        bad = complete_detail()
        bad["cut_operation"] = "not-a-uuid"
        with self.assertRaisesRegex(AssertionError, "wrong type"):
            promotion.validate_case_detail(bad)
        bad = complete_detail()
        bad["poll_seconds"] = True
        with self.assertRaisesRegex(AssertionError, "wrong type"):
            promotion.validate_case_detail(bad)


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(binary="binary", expect_commit="b" * 40, git=None, keep=False, report=None)
        self.binding = dict(
            source_head=self.args.expect_commit,
            source_tree="c" * 40,
            source_inputs_sha256="d" * 64,
            binary_sha256="e" * 64,
            build_receipt_sha256="f" * 64,
        )
        self.prepared = SimpleNamespace(
            binding=self.binding,
            redis_binary="redis",
            profile=Mock(),
            blob_profile={},
            harness_sha256="a" * 64,
            fixture_harness_sha256="b" * 64,
            postgres_major=17,
            postgres_server_version_num=170004,
        )
        self.enterContext(patch.object(promotion, "preflight", return_value=self.prepared))
        self.build = self.enterContext(patch.object(promotion, "build_binding", return_value=self.binding))
        self.hash = self.enterContext(patch.object(
            promotion, "sha256_file", side_effect=[
                self.prepared.harness_sha256, self.prepared.fixture_harness_sha256,
            ],
        ))
        self.factory = self.enterContext(patch.object(promotion, "A4RedisPromotionHarness"))

    def test_success_requires_complete_witness_and_cleanup(self):
        harness = self.factory.return_value
        harness.run_case.return_value = complete_detail()
        report = promotion.acceptance_report(self.args)
        self.assertTrue(report["passed"])
        self.assertEqual(report["kind"], promotion.REPORT_KIND)
        self.assertEqual(report["expected_cases"], [promotion.CASE])
        self.assertEqual(report["fixture_harness_sha256"], self.prepared.fixture_harness_sha256)
        self.assertEqual(report["postgres_major"], 17)
        self.assertEqual(report["cases"], [dict(
            name=promotion.CASE,
            status="passed",
            detail=dict(complete_detail(), owned_cleanup_completed=True),
        )])
        self.assertEqual(harness.method_calls, [call.setup_partition(), call.run_case(), call.cleanup()])
        self.factory.assert_called_once_with(
            self.args,
            self.prepared.profile,
            self.prepared.blob_profile,
            self.prepared.redis_binary,
            containment=None,
        )
        self.assertEqual(self.build.call_args_list, [call(self.args.binary, self.args.expect_commit)])
        self.assertEqual(self.hash.call_args_list, [
            call(Path(promotion.__file__)), call(Path(promotion.a4.__file__)),
        ])

    def test_missing_or_false_promotion_witness_fails_the_case(self):
        for key in promotion.REQUIRED_PROMOTION_TRUE:
            with self.subTest(key=key):
                harness = self.factory.return_value
                harness.reset_mock()
                harness.run_case.return_value = complete_detail()
                harness.run_case.return_value[key] = False
                harness.case_stage = "promotion_validation"
                report = promotion.acceptance_report(self.args)
                self.assertFalse(report["passed"])
                self.assertEqual(report["cases"], [dict(
                    name=promotion.CASE,
                    status="failed",
                    error="case",
                    stage="promotion_validation",
                )])
                harness.cleanup.assert_called_once()

    def test_cleanup_failure_never_passes_a_complete_witness(self):
        harness = self.factory.return_value
        harness.run_case.return_value = complete_detail()
        harness.cleanup.side_effect = RuntimeError("cleanup-specific")
        report = promotion.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=promotion.CASE,
            status="failed",
            error="cleanup",
            cleanup_failed=True,
        )])
        harness.cleanup.assert_called_once()

    def test_failure_reports_only_closed_stages(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private repo id url oid")
        for stage, expected in (
            ("promotion", "promotion"),
            ("private/repo/url", None),
            (None, None),
            (7, None),
        ):
            with self.subTest(stage=stage):
                harness.reset_mock()
                harness.run_case.side_effect = RuntimeError("private repo id url oid")
                harness.case_stage = stage
                report = promotion.acceptance_report(self.args)
                self.assertFalse(report["passed"])
                case = report["cases"][0]
                self.assertEqual(case["error"], "case")
                self.assertNotIn("private", repr(report))
                if expected is None:
                    self.assertNotIn("stage", case)
                else:
                    self.assertEqual(case["stage"], expected)
                harness.cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
