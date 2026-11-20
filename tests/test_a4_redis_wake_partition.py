"""Pure tests for the opt-in external A4 Redis wake acceptance harness."""
from pathlib import Path
import sys
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import MagicMock, Mock, call, patch

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
        self.assertIn("require_postgres_17", script)
        self.assertIn("SHOW server_version_num", script)
        self.assertIn("PR_SET_CHILD_SUBREAPER", script)
        self.assertIn("os.waitpid(-1, os.WNOHANG)", script)
        self.assertIn("containment_factory=LinuxChildSubreaper.install", script)


class SnapshotProjectionTest(unittest.TestCase):
    def test_delivery_snapshot_uses_named_order_and_keeps_full_projection(self):
        repo = "11111111-1111-1111-1111-111111111111"
        keys = [
            "repository", "refs", "gate_revision", "operations", "core_events",
            "holds", "consume_receipts", "memberships", "outbox", "deliveries",
            "audit", "legacy_projection", "projection_jobs",
        ]
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.sql = Mock(side_effect=[f"value-{index}" for index in range(len(keys))])

        snapshot = harness.snapshot(repo)

        self.assertEqual(list(snapshot), keys)
        self.assertEqual(snapshot, {key: f"value-{index}" for index, key in enumerate(keys)})
        delivery_sql = harness.sql.call_args_list[keys.index("deliveries")].args[0]
        self.assertEqual(delivery_sql, (
            "SELECT d.consumer || '|' || d.state || '|' || count(*)::text "
            "FROM event_deliveries d JOIN outbox_events e USING(event_id) "
            f"WHERE e.repository_id='{repo}' GROUP BY d.consumer,d.state "
            "ORDER BY d.consumer,d.state"
        ))
        self.assertNotRegex(delivery_sql, r"ORDER BY\s+\d")


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


class PostgresVersionTest(unittest.TestCase):
    def test_only_postgres_17_is_accepted(self):
        for value in (170000, 170004, 179999):
            self.assertEqual(a4.postgres_major(value), 17)
            self.assertEqual(a4.require_postgres_17(value), 17)
        for value in (0, 9999, 100000, 160000, 160004, 180000, 180001):
            with self.subTest(value=value):
                with self.assertRaises(a4.ProfileError):
                    a4.require_postgres_17(value)

    def test_lookup_is_bounded_parsed_and_redacted(self):
        ok = SimpleNamespace(returncode=0, stdout="170004\n", stderr="")
        with patch.object(a4.subprocess, "run", return_value=ok):
            self.assertEqual(a4.postgres_server_version_num("/usr/bin/psql", "postgresql://fixture@127.0.0.1/db"), 170004)
        failed = SimpleNamespace(returncode=1, stdout="", stderr="private-dsn-value")
        with patch.object(a4.subprocess, "run", return_value=failed):
            with self.assertRaises(a4.ProfileError) as caught:
                a4.postgres_server_version_num("/usr/bin/psql", "postgresql://fixture:private@127.0.0.1/db")
        self.assertNotIn("private", str(caught.exception))
        malformed = SimpleNamespace(returncode=0, stdout="not-a-number\n", stderr="")
        with patch.object(a4.subprocess, "run", return_value=malformed):
            with self.assertRaises(a4.ProfileError):
                a4.postgres_server_version_num("/usr/bin/psql", "postgresql://fixture@127.0.0.1/db")


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
            postgres_major=17,
            postgres_server_version_num=170004,
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
        self.assertEqual(report["postgres_major"], 17)
        self.assertEqual(report["postgres_server_version_num"], 170004)
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE,
            status="passed",
            detail={"healthy_wake_before_poll": True, "owned_cleanup_completed": True},
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
                if stage == "cleanup":
                    self.assertEqual(report["cases"], [dict(
                        name=a4.CASE, status="failed", error="cleanup", cleanup_failed=True,
                    )])
                else:
                    self.assertEqual(report["cases"], [dict(name=a4.CASE, status="failed", error=stage)])
                harness.cleanup.assert_called_once()

    def test_case_failure_reports_selected_fixed_stage_only(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private repo id url oid")
        harness.case_stage = "healthy_push"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case", stage="healthy_push",
        )])
        self.assertNotIn("private", repr(report))

    def test_case_failure_rejects_unknown_or_missing_stage(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private repo id url oid")
        for stage in (None, "private/repo/url", ["healthy_push"], 7):
            with self.subTest(stage=stage):
                harness.case_stage = stage
                report = a4.acceptance_report(self.args)
                self.assertFalse(report["passed"])
                self.assertEqual(report["cases"], [dict(
                    name=a4.CASE, status="failed", error="case",
                )])
                self.assertNotIn("private", repr(report))

    def test_passing_case_does_not_emit_stage(self):
        harness = self.factory.return_value
        harness.run_case.return_value = {"healthy_wake_before_poll": True}
        harness.case_stage = "healthy_push"
        report = a4.acceptance_report(self.args)
        self.assertTrue(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE,
            status="passed",
            detail={"healthy_wake_before_poll": True, "owned_cleanup_completed": True},
        )])
        self.assertNotIn("stage", repr(report["cases"]))
        self.assertNotIn("repo_create", repr(report["cases"]))
        self.assertNotIn("worker_startup", repr(report["cases"]))
        self.assertNotIn("invalid_hints", repr(report["cases"]))

    def test_worker_startup_failure_reports_fixed_code(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private worker log")
        harness.case_stage = "worker_startup"
        harness.worker_startup_code = "catch_up"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case",
            stage="worker_startup", worker_startup="catch_up",
        )])
        self.assertNotIn("private", repr(report))

    def test_worker_startup_failure_reports_closed_unavailable(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private worker log")
        harness.case_stage = "worker_startup"
        harness.worker_startup_code = "unavailable"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case",
            stage="worker_startup", worker_startup="unavailable",
        )])
        self.assertNotIn("private", repr(report))

    def test_worker_startup_failure_rejects_unknown_or_missing_code(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private worker log")
        harness.case_stage = "worker_startup"
        for code in (None, "private/worker/log", ["catch_up"], 7):
            with self.subTest(code=code):
                harness.worker_startup_code = code
                report = a4.acceptance_report(self.args)
                self.assertFalse(report["passed"])
                self.assertEqual(report["cases"], [dict(
                    name=a4.CASE, status="failed", error="case",
                    stage="worker_startup", worker_startup="unavailable",
                )])
                self.assertNotIn("private", repr(report))

    def test_worker_startup_code_not_emitted_for_other_stage(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private worker log")
        harness.case_stage = "healthy_push"
        harness.worker_startup_code = "catch_up"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case", stage="healthy_push",
        )])
        self.assertNotIn("worker_startup", repr(report["cases"]))

    def test_repo_create_failure_reports_fixed_code(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private repo id url oid")
        harness.case_stage = "repo_create"
        harness.repo_create_code = "post_status_5xx"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case",
            stage="repo_create", repo_create="post_status_5xx",
        )])
        self.assertNotIn("private", repr(report))

    def test_repo_create_failure_rejects_unknown_or_missing_code(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private repo id url oid")
        harness.case_stage = "repo_create"
        for code in (None, "private/repo/url", ["post_status_5xx"], 7):
            with self.subTest(code=code):
                harness.repo_create_code = code
                report = a4.acceptance_report(self.args)
                self.assertFalse(report["passed"])
                self.assertEqual(report["cases"], [dict(
                    name=a4.CASE, status="failed", error="case",
                    stage="repo_create", repo_create="unavailable",
                )])
                self.assertNotIn("private", repr(report))

    def test_repo_create_code_not_emitted_for_other_stage(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private repo id url oid")
        harness.case_stage = "healthy_push"
        harness.repo_create_code = "post_status_5xx"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case", stage="healthy_push",
        )])
        self.assertNotIn("repo_create", repr(report["cases"]))

    def test_invalid_hints_failure_reports_fixed_code(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private SQL row")
        harness.case_stage = "invalid_hints"
        harness.invalid_hints_code = "subscriber_recovery"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case",
            stage="invalid_hints", invalid_hints="subscriber_recovery",
        )])
        self.assertNotIn("private", repr(report))

    def test_invalid_hints_failure_reports_closed_unavailable(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private SQL row")
        harness.case_stage = "invalid_hints"
        harness.invalid_hints_code = "unavailable"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case",
            stage="invalid_hints", invalid_hints="unavailable",
        )])
        self.assertNotIn("private", repr(report))

    def test_invalid_hints_failure_rejects_unknown_or_missing_code(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private SQL row")
        harness.case_stage = "invalid_hints"
        for code in (None, "private/sql/row", ["snapshot_equality"], 7):
            with self.subTest(code=code):
                harness.invalid_hints_code = code
                report = a4.acceptance_report(self.args)
                self.assertFalse(report["passed"])
                self.assertEqual(report["cases"], [dict(
                    name=a4.CASE, status="failed", error="case",
                    stage="invalid_hints", invalid_hints="unavailable",
                )])
                self.assertNotIn("private", repr(report))

    def test_invalid_hints_code_not_emitted_for_other_stage(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("private SQL row")
        harness.case_stage = "healthy_push"
        harness.invalid_hints_code = "snapshot_equality"
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE, status="failed", error="case", stage="healthy_push",
        )])
        self.assertNotIn("invalid_hints", repr(report["cases"]))

    def test_primary_failure_precedes_cleanup_failure_but_records_it(self):
        harness = self.factory.return_value
        harness.run_case.side_effect = RuntimeError("primary case failure")
        harness.cleanup.side_effect = RuntimeError("cleanup failure")
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(
            name=a4.CASE,
            status="failed",
            error="case",
            cleanup_failed=True,
            cleanup_error="cleanup",
        )])
        harness.cleanup.assert_called_once()

    def test_preflight_failure_allocates_no_fixture(self):
        self.prepare.side_effect = a4.ProfileError("synthetic preflight")
        report = a4.acceptance_report(self.args)
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(name=a4.CASE, status="failed", error="preflight")])
        self.factory.assert_not_called()

    def test_containment_setup_failure_allocates_no_fixture(self):
        report = a4.acceptance_report(
            self.args,
            containment_factory=Mock(side_effect=a4.ContainmentError("containment unavailable")),
        )
        self.assertFalse(report["passed"])
        self.assertEqual(report["cases"], [dict(name=a4.CASE, status="failed", error="preflight")])
        self.factory.assert_not_called()

    def test_result_report_never_carries_exception_text(self):
        case = dict(name=a4.CASE, status="failed", error="case")
        report = a4.result_report(self.binding, case, False)
        self.assertEqual(report["kind"], a4.REPORT_KIND)
        self.assertNotIn("trace", report)
        self.assertNotIn("fixture-specific", repr(report))


class CaseStageTest(unittest.TestCase):
    def test_real_run_case_tracks_last_top_level_stage(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.case_stage = None
        harness.base = "http://fixture"
        harness.root = Path("/tmp/a4-stage")
        harness.alice = object()
        harness.create = Mock(return_value=({"id": "repo", "clone_path": "/repo"}, None))
        harness.empty_clone = Mock()
        harness.configure = Mock()
        harness.commit_and_push = Mock(return_value=("a" * 40, "op", None))
        harness.assert_ref = Mock()
        harness.assert_no_embedded_delivery = Mock()
        harness.start_external_worker = Mock(return_value=0.0)
        harness.healthy_push = Mock(side_effect=RuntimeError("private detail"))
        with self.assertRaisesRegex(RuntimeError, "private detail"):
            harness.run_case()
        self.assertEqual(harness.case_stage, "healthy_push")

    def test_real_run_case_tracks_repo_create_code(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.case_stage = None
        harness.repo_create_code = None
        harness.base = "http://fixture"
        harness.root = Path("/tmp/a4-stage")
        harness.alice = object()
        def fail_create(*_args, **_kwargs):
            harness.observe_repo_create("post_status_5xx")
            raise RuntimeError("private detail")
        harness.create = Mock(side_effect=fail_create)
        with self.assertRaisesRegex(RuntimeError, "private detail"):
            harness.run_case()
        self.assertEqual(harness.case_stage, "repo_create")
        self.assertEqual(harness.repo_create_code, "post_status_5xx")
        harness.repo_create_code = None
        harness.observe_repo_create("private/repo/url")
        self.assertIsNone(harness.repo_create_code)


class InvalidHintsTest(unittest.TestCase):
    def _harness(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.invalid_hints_code = None
        harness.channel = "rootyard:a4:test:schema"
        harness.settle_worker = Mock()
        harness.snapshot = Mock(return_value="snapshot")
        harness.claim_rows = Mock(return_value="claims")
        harness.redis_command = Mock()
        harness.until = Mock()
        harness.subscriber_count = Mock(return_value=1)
        return harness

    def test_failure_rails_are_closed_and_first_failure_wins(self):
        cases = {
            "baseline_idle": lambda harness: setattr(
                harness.settle_worker, "side_effect", RuntimeError("private")),
            "baseline_snapshot": lambda harness: setattr(
                harness.snapshot, "side_effect", RuntimeError("private")),
            "baseline_claim": lambda harness: setattr(
                harness.claim_rows, "side_effect", RuntimeError("private")),
            "duplicate_publish": lambda harness: setattr(
                harness.redis_command, "side_effect", RuntimeError("private")),
            "wrong_version_publish": lambda harness: setattr(
                harness.redis_command, "side_effect", [None] * 10 + [RuntimeError("private")]),
            "other_channel_publish": lambda harness: setattr(
                harness.redis_command, "side_effect", [None] * 11 + [RuntimeError("private")]),
            "subscriber_recovery": lambda harness: setattr(
                harness.until, "side_effect", RuntimeError("private")),
            "post_probe_idle": lambda harness: setattr(
                harness.settle_worker, "side_effect", [None, RuntimeError("private")]),
            "snapshot_equality": lambda harness: setattr(
                harness.snapshot, "side_effect", ["before", "after"]),
            "claim_equality": lambda harness: setattr(
                harness.claim_rows, "side_effect", ["before", "after"]),
        }
        self.assertEqual(set(cases), set(a4.INVALID_HINT_CODES) - {"unavailable"})
        for expected, configure in cases.items():
            with self.subTest(code=expected):
                harness = self._harness()
                configure(harness)
                with patch.object(a4.time, "sleep"):
                    with self.assertRaises((AssertionError, RuntimeError)):
                        harness.duplicate_and_invalid_hints({"id": "repo"})
                self.assertEqual(harness.invalid_hints_code, expected)

    def test_success_keeps_probe_order_and_emits_no_code(self):
        harness = self._harness()
        with patch.object(a4.time, "sleep") as sleep:
            harness.duplicate_and_invalid_hints({"id": "repo"})
        self.assertIsNone(harness.invalid_hints_code)
        self.assertEqual(harness.settle_worker.call_count, 2)
        self.assertEqual(harness.snapshot.call_args_list, [call("repo"), call("repo")])
        self.assertEqual(harness.claim_rows.call_args_list, [call("repo"), call("repo")])
        self.assertEqual(harness.until.call_count, 1)
        self.assertEqual(sleep.call_args_list, [call(0.5)])
        self.assertEqual(harness.redis_command.call_args_list, [
            call("PUBLISH", harness.channel, b"v1"),
        ] * 10 + [
            call("PUBLISH", harness.channel, b"wrong-version"),
            call("PUBLISH", "rootyard:a4:test:other", b"v1"),
        ])


class WorkerEnvironmentTest(unittest.TestCase):
    def test_worker_forces_external_schema_mode_only_in_its_child_copy(self):
        for inherited in (None, "auto"):
            with self.subTest(inherited=inherited):
                harness = object.__new__(a4.A4RedisWakeHarness)
                harness.channel = "rootyard:a4:test:schema"
                harness.relay = SimpleNamespace(port=6379)
                harness.env = {"DATABASE_URL": "postgresql://fixture@127.0.0.1/db"}
                if inherited is not None:
                    harness.env["ROOTYARD_SCHEMA_MODE"] = inherited
                parent = dict(harness.env)

                child = harness.worker_env()

                self.assertEqual(child["ROOTYARD_SCHEMA_MODE"], "external")
                self.assertEqual(harness.env, parent)
                self.assertIsNot(child, harness.env)


class WorkerStartupTest(unittest.TestCase):
    def _harness(self, exit_code=None, subscriber=0, relay_active=0):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.worker_startup_code = None
        harness.spawn_worker = Mock()
        harness.until = Mock()
        proc = Mock()
        proc.poll.return_value = exit_code
        proc.returncode = exit_code if exit_code is not None else 0
        harness.workers = [(proc, Mock())]
        harness.subscriber_count = Mock(return_value=subscriber)
        harness.relay = self._relay(failed=False)
        if relay_active:
            harness.relay.sessions[object()] = ()
        harness.assert_claim = Mock()
        harness.assert_operation = Mock()
        harness.settle_worker = Mock()
        return harness

    def test_worker_startup_classifies_spawn_exit_subscribe_relay_and_catch_up(self):
        cases = (
            ("spawn", {"exit_code": None, "subscriber": 0, "relay_active": 0}, "spawn"),
            ("worker_exit_zero", {"exit_code": 0}, "worker_exit_zero"),
            ("worker_exit_nonzero", {"exit_code": 1}, "worker_exit_nonzero"),
            ("subscribe", {"exit_code": None}, "subscribe"),
            ("relay", {"exit_code": None, "subscriber": 1, "relay_active": 0}, "relay"),
            ("catch_up", {"exit_code": None}, "catch_up"),
        )
        for name, options, expected in cases:
            with self.subTest(name=name):
                harness = self._harness(**options)
                if name == "spawn":
                    harness.workers = []
                    harness.spawn_worker.side_effect = RuntimeError("private worker log")
                elif name == "catch_up":
                    harness.until.side_effect = [None, AssertionError("private worker log")]
                else:
                    harness.until.side_effect = AssertionError("private worker log")
                with self.assertRaises(Exception):
                    harness.start_external_worker({"id": "repo"}, "operation", "oid")
                self.assertEqual(harness.worker_startup_code, expected)

    def _relay(self, failed=False):
        relay = object.__new__(a4.RedisPartitionRelay)
        relay.lock = threading.Lock()
        relay.failed = failed
        relay.forwarded = relay.refused = 0
        relay.sessions = {}
        return relay

    def test_subscribe_attribution_uses_real_relay_health_and_counts(self):
        harness = self._harness(exit_code=None, subscriber=0, relay_active=0)
        harness.relay = self._relay(failed=False)
        harness.until.side_effect = AssertionError("private worker log")
        with self.assertRaises(AssertionError):
            harness.start_external_worker({"id": "repo"}, "operation", "oid")
        self.assertEqual(harness.worker_startup_code, "subscribe")

        harness = self._harness(exit_code=None, subscriber=1, relay_active=0)
        harness.relay = self._relay(failed=True)
        harness.until.side_effect = AssertionError("private worker log")
        with self.assertRaises(AssertionError):
            harness.start_external_worker({"id": "repo"}, "operation", "oid")
        self.assertEqual(harness.worker_startup_code, "relay")
        with self.assertRaises(AssertionError):
            harness.relay.counts()

        harness = self._harness(exit_code=None, subscriber=1, relay_active=0)
        harness.relay = self._relay(failed=False)
        harness.relay.lock = MagicMock()
        harness.relay.lock.__enter__.side_effect = RuntimeError("private worker log")
        harness.until.side_effect = AssertionError("private worker log")
        with self.assertRaises(AssertionError):
            harness.start_external_worker({"id": "repo"}, "operation", "oid")
        self.assertEqual(harness.worker_startup_code, "unavailable")

    def test_worker_startup_classifies_claim_binding_idle_and_success(self):
        for name, expected in (
            ("claim", "claim"),
            ("durable_binding", "durable_binding"),
            ("settle_idle", "settle_idle"),
        ):
            with self.subTest(name=name):
                harness = self._harness(exit_code=None)
                harness.until.side_effect = [None, None]
                if name == "claim":
                    harness.assert_claim.side_effect = RuntimeError("private worker log")
                elif name == "durable_binding":
                    harness.assert_operation.side_effect = RuntimeError("private worker log")
                else:
                    harness.settle_worker.side_effect = RuntimeError("private worker log")
                with self.assertRaises(Exception):
                    harness.start_external_worker({"id": "repo"}, "operation", "oid")
                self.assertEqual(harness.worker_startup_code, expected)
        harness = self._harness(exit_code=None)
        harness.until.side_effect = [None, None]
        harness.start_external_worker({"id": "repo"}, "operation", "oid")
        self.assertIsNone(harness.worker_startup_code)


class RepoCreateObserverTest(unittest.TestCase):
    def test_post_status_class_and_shape_observers(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.repo_create_code = None
        harness.http = Mock(return_value=(503, b"{}", {}))
        with self.assertRaisesRegex(AssertionError, "POST /api/repos"):
            harness.post_repo("repo", None, observer=harness.observe_repo_create)
        self.assertEqual(harness.repo_create_code, "post_status_5xx")
        harness.repo_create_code = None
        harness.http = Mock(return_value=(201, b"not-json", {}))
        with self.assertRaises(ValueError):
            harness.post_repo("repo", None, observer=harness.observe_repo_create)
        self.assertEqual(harness.repo_create_code, "post_shape")

    def test_get_status_and_terminal_state_observers(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.repo_create_code = None
        harness.http = Mock(return_value=(404, b"{}", {}))
        with self.assertRaisesRegex(AssertionError, "GET "):
            harness.await_ready("alice", "repo", None, observer=harness.observe_repo_create)
        self.assertEqual(harness.repo_create_code, "get_status_4xx")
        harness.repo_create_code = None
        harness.http = Mock(return_value=(200, b'{"state":"failed"}', {}))
        with self.assertRaisesRegex(AssertionError, "failed"):
            harness.await_ready("alice", "repo", None, observer=harness.observe_repo_create)
        self.assertEqual(harness.repo_create_code, "get_terminal_state")

    def test_create_owner_name_present_missing_id_calls_get_and_old_failure(self):
        for use_observer in (False, True):
            with self.subTest(observer=use_observer):
                harness = object.__new__(a4.A4RedisWakeHarness)
                harness.repo_create_code = None
                harness.http = Mock(return_value=(201, b'{"owner":"alice","name":"repo"}', {}))
                harness.await_ready = Mock(return_value={
                    "id": "1", "owner": "alice", "name": "repo", "storage_backend": "pg_refstore",
                    "object_format": "sha1", "clone_path": "/git/alice/repo.git",
                })
                observer = harness.observe_repo_create if use_observer else None
                with self.assertRaises(KeyError):
                    harness.create("repo", None, observer=observer)
                harness.await_ready.assert_called_once()
                if use_observer:
                    self.assertEqual(harness.repo_create_code, "post_shape")

    def test_create_malformed_owner_name_does_not_coerce_clone_path(self):
        for use_observer in (False, True):
            with self.subTest(observer=use_observer):
                harness = object.__new__(a4.A4RedisWakeHarness)
                harness.repo_create_code = None
                harness.post_repo = Mock(return_value=(201, {"id": "1", "owner": "alice", "name": "repo"}))
                harness.await_ready = Mock(return_value={
                    "id": "1", "owner": 123, "name": 456, "storage_backend": "pg_refstore",
                    "object_format": "sha1", "clone_path": "/git/123/456.git",
                })
                observer = harness.observe_repo_create if use_observer else None
                with self.assertRaises(TypeError):
                    harness.create("repo", None, observer=observer)
                harness.await_ready.assert_called_once()
                if use_observer:
                    self.assertEqual(harness.repo_create_code, "get_shape")

    def test_create_without_observer_keeps_existing_contract(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.post_repo = Mock(return_value=(201, {"id": "1", "owner": "alice", "name": "repo"}))
        harness.await_ready = Mock(return_value={
            "id": "1", "owner": "alice", "name": "repo", "storage_backend": "pg_refstore",
            "object_format": "sha1", "clone_path": "/git/alice/repo.git",
        })
        repo, code = harness.create("repo", None)
        self.assertEqual(code, 201)
        self.assertEqual(repo["id"], "1")
        self.assertEqual(repo["clone_path"], "/git/alice/repo.git")

    def test_create_final_identity_observer(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.repo_create_code = None
        harness.post_repo = Mock(return_value=(201, {"id": "1", "owner": "alice", "name": "repo"}))
        harness.await_ready = Mock(return_value={
            "id": "2", "owner": "alice", "name": "repo", "storage_backend": "pg_refstore",
            "object_format": "sha1", "clone_path": "/git/alice/repo.git",
        })
        with self.assertRaises(AssertionError):
            harness.create("repo", None, observer=harness.observe_repo_create)
        self.assertEqual(harness.repo_create_code, "identity_mismatch")


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
                    with patch.object(a4, "postgres_server_version_num", return_value=170000):
                        with patch.object(a4.CrossProcessHarness, "resolve_redis", return_value=None):
                            with patch.object(a4, "build_binding") as build:
                                with self.assertRaises(a4.ProfileError):
                                    a4.preflight(args)
        build.assert_not_called()

    def test_unsupported_postgres_fails_before_binding_or_fixture(self):
        args = SimpleNamespace(binary="binary", expect_commit="b" * 40, git=None)
        env = {"ROOTYARD_TEST_DATABASE_URL": "postgresql://fixture@127.0.0.1/synthetic"}
        with patch.object(a4.sys, "platform", "linux"):
            with patch.dict(a4.os.environ, env, clear=True):
                with patch.object(a4.shutil, "which", return_value="/usr/bin/psql"):
                    with patch.object(a4, "postgres_server_version_num", return_value=160000):
                        with patch.object(a4.CrossProcessHarness, "resolve_redis", return_value="redis"):
                            with patch.object(a4, "build_binding") as build:
                                with self.assertRaisesRegex(a4.ProfileError, "PostgreSQL 17"):
                                    a4.preflight(args)
        build.assert_not_called()


class ContainmentTest(unittest.TestCase):
    def make(self, timeout=0.5):
        containment = object.__new__(a4.LinuxChildSubreaper)
        containment.timeout = timeout
        containment.verify = Mock()
        return containment

    def test_reaped_adopted_exit_then_echild_proves_quiescence(self):
        containment = self.make()
        with patch.object(a4.os, "waitpid", side_effect=[(123, 0), ChildProcessError()]) as wait:
            with patch.object(a4.time, "monotonic", return_value=0.0):
                containment.prove_no_descendants()
        containment.verify.assert_called_once()
        self.assertEqual(wait.call_args_list, [call(-1, a4.os.WNOHANG), call(-1, a4.os.WNOHANG)])

    def test_continuous_positive_reaps_cannot_bypass_deadline(self):
        containment = self.make(timeout=0.5)
        with patch.object(a4.os, "waitpid", return_value=(123, 0)) as wait:
            with patch.object(a4.time, "monotonic", side_effect=[0.0, 0.1, 0.2, 0.4, 0.6]):
                with patch.object(a4.time, "sleep") as sleep:
                    with self.assertRaisesRegex(a4.ContainmentError, "deadline"):
                        containment.prove_no_descendants()
        self.assertEqual(wait.call_count, 4)
        sleep.assert_not_called()

    def test_echild_after_deadline_fails_closed(self):
        containment = self.make(timeout=0.5)
        with patch.object(a4.os, "waitpid", side_effect=ChildProcessError()):
            with patch.object(a4.time, "monotonic", side_effect=[0.0, 0.6]):
                with self.assertRaisesRegex(a4.ContainmentError, "deadline"):
                    containment.prove_no_descendants()

    def test_reaped_leader_with_live_descendant_times_out(self):
        containment = self.make(timeout=0.5)
        with patch.object(a4.os, "waitpid", return_value=(0, 0)):
            with patch.object(a4.time, "monotonic", side_effect=[0.0, 0.0, 0.6]):
                with patch.object(a4.time, "sleep") as sleep:
                    with self.assertRaisesRegex(a4.ContainmentError, "deadline"):
                        containment.prove_no_descendants()
        sleep.assert_called_once()

    def test_wait_error_fails_closed(self):
        containment = self.make()
        with patch.object(a4.os, "waitpid", side_effect=OSError("synthetic wait failure")):
            with self.assertRaisesRegex(a4.ContainmentError, "quiescence proof failed"):
                containment.prove_no_descendants()

    def test_verify_failure_fails_closed(self):
        containment = object.__new__(a4.LinuxChildSubreaper)
        containment._get = Mock(return_value=0)
        with self.assertRaisesRegex(a4.ContainmentError, "verification failed"):
            containment.verify()

    def test_install_rejects_non_linux(self):
        with patch.object(a4.sys, "platform", "darwin"):
            with self.assertRaisesRegex(a4.ContainmentError, "unavailable"):
                a4.LinuxChildSubreaper.install()


class StopWorkersTest(unittest.TestCase):
    def test_unconfirmed_worker_keeps_exact_owner_and_open_log(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        proc, log = Mock(), Mock()
        proc.poll.return_value = None
        harness.workers = [(proc, log)]
        with patch.object(a4.CrossProcessHarness, "stop_process", side_effect=RuntimeError("still alive")):
            with self.assertRaisesRegex(RuntimeError, "still alive"):
                harness.stop_workers()
        self.assertEqual(harness.workers, [(proc, log)])
        log.close.assert_not_called()

    def test_stop_returning_while_alive_is_still_unconfirmed(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        proc, log = Mock(), Mock()
        proc.poll.return_value = None
        harness.workers = [(proc, log)]
        with patch.object(a4.CrossProcessHarness, "stop_process", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "did not exit"):
                harness.stop_workers()
        self.assertEqual(harness.workers, [(proc, log)])
        log.close.assert_not_called()

    def test_confirmed_exit_retains_owner_until_descendant_proof(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        proc, log = Mock(), Mock()
        proc.poll.return_value = 0
        harness.workers = [(proc, log)]
        harness.log = None
        with patch.object(a4.CrossProcessHarness, "stop_process", return_value=None):
            harness.stop_workers()
        self.assertEqual(harness.workers, [(proc, log)])
        log.close.assert_not_called()
        harness.close_owner_diagnostics()
        self.assertEqual(harness.workers, [])
        log.close.assert_called_once()

    def test_mixed_failure_retains_all_until_diagnostics_close(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        confirmed, confirmed_log = Mock(), Mock()
        unconfirmed, unconfirmed_log = Mock(), Mock()
        confirmed.poll.return_value = 0
        unconfirmed.poll.return_value = None
        harness.workers = [(confirmed, confirmed_log), (unconfirmed, unconfirmed_log)]
        harness.log = None
        with patch.object(
            a4.CrossProcessHarness,
            "stop_process",
            side_effect=[None, RuntimeError("still alive")],
        ):
            with self.assertRaisesRegex(RuntimeError, "still alive"):
                harness.stop_workers()
        self.assertEqual(harness.workers, [(confirmed, confirmed_log), (unconfirmed, unconfirmed_log)])
        confirmed_log.close.assert_not_called()
        unconfirmed_log.close.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "did not exit"):
            harness.close_owner_diagnostics()
        self.assertEqual(harness.workers, [(unconfirmed, unconfirmed_log)])
        confirmed_log.close.assert_called_once()
        unconfirmed_log.close.assert_not_called()

    def test_owner_close_failure_retains_worker_and_service_diagnostics(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        proc, worker_log = Mock(), Mock()
        proc.poll.return_value = 0
        worker_log.close.side_effect = RuntimeError("worker log close failed")
        service_log = Mock()
        service_log.close.side_effect = RuntimeError("service log close failed")
        harness.workers = [(proc, worker_log)]
        harness.log = service_log
        with self.assertRaisesRegex(RuntimeError, "worker log close failed"):
            harness.close_owner_diagnostics()
        self.assertEqual(harness.workers, [(proc, worker_log)])
        self.assertIs(harness.log, service_log)

    def test_service_stop_preserves_log_until_owner_close(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.proc = Mock()
        log = Mock()
        harness.log = log
        harness.workers = []
        with patch.object(
            a4.BlobOnlyHarness,
            "stop",
            side_effect=lambda: setattr(harness, "proc", None),
        ) as inherited_stop:
            harness.stop_service_retaining_log()
        inherited_stop.assert_called_once()
        self.assertIs(harness.log, log)
        log.close.assert_not_called()
        harness.close_owner_diagnostics()
        log.close.assert_called_once()
        self.assertIsNone(harness.log)

    def test_owner_close_refuses_live_service_and_retains_log(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.proc = Mock()
        log = Mock()
        harness.log = log
        harness.workers = []
        with self.assertRaisesRegex(RuntimeError, "did not exit"):
            harness.close_owner_diagnostics()
        log.close.assert_not_called()
        self.assertIs(harness.log, log)


class CleanupTest(unittest.TestCase):
    def make_harness(self):
        harness = object.__new__(a4.A4RedisWakeHarness)
        harness.stop_workers = Mock()
        harness.stop_service_retaining_log = Mock()
        harness.close_relay = Mock()
        harness.stop_redis = Mock()
        harness.containment = Mock()
        harness.close_owner_diagnostics = Mock()
        harness.workers = []
        harness.log = None
        return harness

    def test_cleanup_attempts_all_stops_but_skips_teardown_after_worker_failure(self):
        harness = self.make_harness()
        harness.stop_workers.side_effect = RuntimeError("synthetic worker stop")
        with patch.object(a4.BlobOnlyHarness, "cleanup") as parent_cleanup:
            with self.assertRaisesRegex(RuntimeError, "synthetic worker stop"):
                harness.cleanup()
        harness.stop_service_retaining_log.assert_called_once()
        harness.close_relay.assert_called_once()
        harness.stop_redis.assert_called_once()
        harness.containment.prove_no_descendants.assert_not_called()
        harness.close_owner_diagnostics.assert_not_called()
        parent_cleanup.assert_not_called()

    def test_cleanup_skips_teardown_after_server_failure_but_stops_other_members(self):
        harness = self.make_harness()
        harness.stop_service_retaining_log.side_effect = RuntimeError("service still alive")
        with patch.object(a4.BlobOnlyHarness, "cleanup") as parent_cleanup:
            with self.assertRaisesRegex(RuntimeError, "service still alive"):
                harness.cleanup()
        harness.stop_workers.assert_called_once()
        harness.close_relay.assert_called_once()
        harness.stop_redis.assert_called_once()
        harness.containment.prove_no_descendants.assert_not_called()
        harness.close_owner_diagnostics.assert_not_called()
        parent_cleanup.assert_not_called()

    def test_cleanup_skips_teardown_when_containment_proof_fails(self):
        harness = self.make_harness()
        harness.containment.prove_no_descendants.side_effect = a4.ContainmentError("synthetic proof failure")
        with patch.object(a4.BlobOnlyHarness, "cleanup") as parent_cleanup:
            with self.assertRaisesRegex(a4.ContainmentError, "synthetic proof failure"):
                harness.cleanup()
        harness.containment.prove_no_descendants.assert_called_once()
        harness.close_owner_diagnostics.assert_not_called()
        parent_cleanup.assert_not_called()

    def test_cleanup_requires_containment_before_schema_teardown(self):
        harness = self.make_harness()
        harness.containment = None
        with patch.object(a4.BlobOnlyHarness, "cleanup") as parent_cleanup:
            with self.assertRaisesRegex(a4.ContainmentError, "not installed"):
                harness.cleanup()
        harness.close_owner_diagnostics.assert_not_called()
        parent_cleanup.assert_not_called()

    def test_cleanup_skips_teardown_when_owner_diagnostics_close_fails(self):
        harness = self.make_harness()
        harness.close_owner_diagnostics.side_effect = RuntimeError("diagnostics close failed")
        with patch.object(a4.BlobOnlyHarness, "cleanup") as parent_cleanup:
            with self.assertRaisesRegex(RuntimeError, "diagnostics close failed"):
                harness.cleanup()
        harness.containment.prove_no_descendants.assert_called_once()
        parent_cleanup.assert_not_called()

    def test_cleanup_orders_worker_service_relay_redis_containment_owner_close_then_schema(self):
        events = []
        harness = self.make_harness()
        harness.stop_workers = Mock(side_effect=lambda: events.append("workers"))
        harness.stop_service_retaining_log = Mock(side_effect=lambda: events.append("service"))
        harness.close_relay = Mock(side_effect=lambda: events.append("relay"))
        harness.stop_redis = Mock(side_effect=lambda: events.append("redis"))
        harness.containment = Mock()
        harness.containment.prove_no_descendants = Mock(side_effect=lambda: events.append("containment"))
        harness.close_owner_diagnostics = Mock(side_effect=lambda: events.append("diagnostics"))
        with patch.object(a4.BlobOnlyHarness, "cleanup", side_effect=lambda: events.append("schema")):
            harness.cleanup()
        self.assertEqual(
            events,
            ["workers", "service", "relay", "redis", "containment", "diagnostics", "schema"],
        )


if __name__ == "__main__":
    unittest.main()
