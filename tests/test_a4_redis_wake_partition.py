"""Pure tests for the opt-in external A4 Redis wake acceptance harness."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import a4_redis_wake_partition as a4
from redis_partition_relay import RelayCounts

ROOT = Path(__file__).resolve().parents[1]


class SourceBindingTest(unittest.TestCase):
    def test_named_constants_match_the_product_source(self):
        events = (ROOT / "src" / "events.rs").read_text(encoding="utf-8")
        self.assertIn(f'pub const TARGET_AUDIT_CONSUMER: &str = "{a4.TARGET_CONSUMER}"', events)
        self.assertIn(f'pub const TARGET_AUDIT_KIND: &str = "{a4.TARGET_KIND}"', events)
        dispatch = (ROOT / "src" / "dispatch.rs").read_text(encoding="utf-8")
        self.assertIn('pub const A4_WORKER_MODE_ENV: &str = "ROOTYARD_A4_WORKER_MODE"', dispatch)
        self.assertIn('Some("external") => Ok(A4WorkerMode::External)', dispatch)
        self.assertIn("pub const fn runs_embedded_worker", dispatch)
        standalone = (ROOT / "src" / "standalone.rs").read_text(encoding="utf-8")
        self.assertIn("if mode.runs_embedded_worker()", standalone)
        self.assertIn("crate::dispatch::Settings::standalone_from_env()", standalone)
        self.assertIn("std::future::pending::<()>().await", standalone)
        doc = (ROOT / "docs" / "a4-redis-wake-acceptance.md").read_text(encoding="utf-8")
        self.assertIn("ROOTYARD_A4_WORKER_MODE=external", doc)
        script = (ROOT / "tests" / "a4_redis_wake_partition.py").read_text(encoding="utf-8")
        self.assertIn('ROOTYARD_A4_WORKER_MODE="external"', script)
        self.assertIn('ROOTYARD_A4_WAKE_TRANSPORT="redis"', script)
        self.assertIn('ROOTYARD_WORKER_SCOPE="a4-target-audit"', script)
        self.assertIn('"rootyard:a4:test:" + self.schema', script)


class HealthyTimingTest(unittest.TestCase):
    def make_harness(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.settle_worker = Mock()
        harness.commit_and_push = Mock(return_value=("a" * 40, "operation", Mock()))
        harness.audit_count = Mock(return_value=1)
        harness.subscriber_count = Mock(return_value=1)
        harness.assert_claim = Mock()
        harness.assert_operation = Mock()

        def until(predicate, description, timeout=20):
            self.assertTrue(predicate(), description)

        harness.until = Mock(side_effect=until)
        return harness

    def test_delivery_at_or_after_poll_deadline_is_not_a_wake(self):
        harness = self.make_harness()
        harness.publishes = Mock(side_effect=[10, 11])
        harness.relay = Mock()
        harness.relay.counts.side_effect = [RelayCounts(1, 0, 1), RelayCounts(2, 0, 1)]
        with patch.object(a4.time, "monotonic", return_value=20):
            with self.assertRaisesRegex(AssertionError, "periodic poll"):
                harness.healthy_push(None, {"id": "repo"}, 20)

    def test_delivery_before_deadline_still_requires_publish_forwarding_and_claim(self):
        harness = self.make_harness()
        harness.publishes = Mock(side_effect=[10, 11])
        harness.relay = Mock()
        harness.relay.counts.side_effect = [RelayCounts(1, 0, 1), RelayCounts(2, 0, 1)]
        with patch.object(a4.time, "monotonic", return_value=10):
            harness.healthy_push(None, {"id": "repo"}, 20)
        harness.assert_claim.assert_called_once_with("operation")
        harness.assert_operation.assert_called_once_with("repo", "operation", "a" * 40, delivered=True)

    def test_no_producer_publish_is_a_failure(self):
        harness = self.make_harness()
        harness.publishes = Mock(side_effect=[10, 10])
        harness.relay = Mock()
        harness.relay.counts.return_value = RelayCounts(1, 0, 1)
        with patch.object(a4.time, "monotonic", return_value=10):
            with self.assertRaisesRegex(AssertionError, "published through relay"):
                harness.healthy_push(None, {"id": "repo"}, 20)

    def test_no_relay_forwarding_is_a_failure(self):
        harness = self.make_harness()
        harness.publishes = Mock(side_effect=[10, 11])
        harness.relay = Mock()
        harness.relay.counts.side_effect = [RelayCounts(1, 0, 1), RelayCounts(1, 0, 1)]
        with patch.object(a4.time, "monotonic", return_value=10):
            with self.assertRaisesRegex(AssertionError, "did not use the relay"):
                harness.healthy_push(None, {"id": "repo"}, 20)


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
        )
        self.prepare = self.enterContext(patch.object(a4, "preflight", return_value=self.prepared))
        self.build = self.enterContext(patch.object(a4, "build_binding", return_value=self.binding))
        self.hash = self.enterContext(patch.object(a4, "sha256_file", return_value=self.prepared.harness_sha256))
        self.factory = self.enterContext(patch.object(a4, "A4RedisWakeHarness"))

    def test_success_requires_case_receipt_binding_and_cleanup(self):
        harness = self.factory.return_value
        harness.run_case.return_value = {"healthy_wake_before_poll": True}
        report = a4.acceptance_report(self.args)
        self.assertTrue(report["passed"])
        self.assertEqual(report["kind"], a4.REPORT_KIND)
        self.assertEqual(report["expected_cases"], [a4.CASE])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE,
            status="passed",
            detail={"healthy_wake_before_poll": True, "owned_cleanup_completed": True},
        )])
        self.assertEqual(harness.method_calls, [call.setup_partition(), call.run_case(), call.cleanup()])
        self.assertEqual(self.build.call_args_list, [call(self.args.binary, self.args.expect_commit)])
        self.assertEqual(self.hash.call_args_list, [call(Path(a4.__file__))])

    def test_failure_stages_are_fixed_and_cleanup_always_runs(self):
        harness = self.factory.return_value
        for stage in ("case", "receipt_changed", "cleanup"):
            with self.subTest(stage=stage):
                harness.reset_mock()
                harness.run_case.side_effect = RuntimeError("fixture-specific") if stage == "case" else None
                self.build.return_value = {} if stage == "receipt_changed" else self.binding
                harness.cleanup.side_effect = RuntimeError("cleanup-specific") if stage == "cleanup" else None
                report = a4.acceptance_report(self.args)
                self.assertFalse(report["passed"])
                self.assertEqual(report["cases"], [dict(name=a4.CASE, status="failed", error=stage)])
                harness.cleanup.assert_called_once()

    def test_preflight_failure_allocates_no_fixture(self):
        self.prepare.side_effect = a4.ProfileError("synthetic preflight")
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(name=a4.CASE, status="failed", error="preflight")])
        self.factory.assert_not_called()

    def test_result_report_never_carries_exception_text(self):
        case = dict(name=a4.CASE, status="failed", error="case")
        report = a4.result_report(self.binding, case, False)
        self.assertEqual(report["kind"], a4.REPORT_KIND)
        self.assertNotIn("trace", report)
        self.assertNotIn("fixture-specific", repr(report))


class PreflightTest(unittest.TestCase):
    def test_missing_database_fails_closed(self):
        args = SimpleNamespace(binary="binary", expect_commit="b" * 40, git=None)
        with patch.object(a4.sys, "platform", "linux"):
            with patch.dict(a4.os.environ, {}, clear=True):
                with self.assertRaises(a4.ProfileError):
                    a4.preflight(args)

    def test_missing_redis_fails_before_building_a_fixture(self):
        args = SimpleNamespace(binary="binary", expect_commit="b" * 40, git=None)
        env = {"ROOTYARD_TEST_DATABASE_URL": "postgresql://fixture@127.0.0.1/synthetic"}
        with patch.object(a4.sys, "platform", "linux"):
            with patch.dict(a4.os.environ, env, clear=True):
                with patch.object(a4.shutil, "which", return_value="/usr/bin/psql"):
                    with patch.object(a4.CrossProcessHarness, "resolve_redis", return_value=None):
                        with patch.object(a4, "build_binding") as build:
                            with self.assertRaises(a4.ProfileError):
                                a4.preflight(args)
        build.assert_not_called()


class CleanupTest(unittest.TestCase):
    def test_cleanup_attempts_every_owned_resource_after_a_worker_failure(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.stop_workers = Mock(side_effect=RuntimeError("synthetic worker stop"))
        harness.stop = Mock()
        harness.close_relay = Mock()
        harness.stop_redis = Mock()
        with patch.object(a4.BlobOnlyHarness, "cleanup") as parent_cleanup:
            with self.assertRaisesRegex(RuntimeError, "synthetic worker stop"):
                harness.cleanup()
        harness.stop.assert_called_once()
        harness.close_relay.assert_called_once()
        harness.stop_redis.assert_called_once()
        parent_cleanup.assert_called_once()

    def test_cleanup_orders_worker_service_relay_redis_then_schema(self):
        events = []
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.stop_workers = Mock(side_effect=lambda: events.append("workers"))
        harness.stop = Mock(side_effect=lambda: events.append("service"))
        harness.close_relay = Mock(side_effect=lambda: events.append("relay"))
        harness.stop_redis = Mock(side_effect=lambda: events.append("redis"))
        with patch.object(a4.BlobOnlyHarness, "cleanup", side_effect=lambda: events.append("schema")):
            harness.cleanup()
        self.assertEqual(events, ["workers", "service", "relay", "redis", "schema"])


if __name__ == "__main__":
    unittest.main()
