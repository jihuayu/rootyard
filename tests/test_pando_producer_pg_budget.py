#!/usr/bin/env python3
"""Pure runner-budget regressions for the producer PG final verification.

No PostgreSQL, psql, Cargo, compiler, Git, Vault, Docker, network or real child
process is used.  Time is a fake monotonic clock and every stage is a fake.
"""
from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_producer_pg.cases as cases  # noqa: E402
import run_pando_producer_pg as runner  # noqa: E402
from pando_producer_pg.errors import RunnerError  # noqa: E402

BOOTSTRAP = "postgresql://user:password@127.0.0.1:55432/bootstrap"
BINARY = "/tmp/owned/target/debug/deps/rootyard_pando_lab-abc"


class FakeClock:
    def __init__(self, now=0.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)

    def set(self, value):
        self.now = float(value)


def passing_records():
    rows = cases.not_run_records()
    for row in rows:
        row.update(
            status="passed", executed=True, exit_code=0, passed=1, code="passed"
        )
    return rows


class CaseBudgetTest(unittest.TestCase):
    class Runner:
        def __init__(self, responses):
            self.responses = list(responses)
            self.calls = []

        def run(self, argv, **kwargs):
            self.calls.append((list(argv), dict(kwargs)))
            item = self.responses.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item

    def test_case_budget_reserves_the_cleanup_window(self):
        fake = self.Runner([])
        records = cases.execute_cases(
            BINARY, {}, fake, work_deadline=100, case_timeout=30,
            clock=lambda: 97.5,
        )
        self.assertEqual(fake.calls, [])
        self.assertEqual(records[0]["code"], "not_run_deadline")

        fake = self.Runner([RunnerError("execute", "case_timeout")])
        records = cases.execute_cases(
            BINARY, {}, fake, work_deadline=100, case_timeout=30,
            clock=lambda: 96.5,
        )
        self.assertEqual(fake.calls[0][1]["timeout"], 1.5)
        self.assertEqual(records[0]["code"], "case_timeout")


class OrchestrationFakes:
    def binding(self):
        return {
            "source_commit": "b" * 40,
            "source_tree": "c" * 40,
            "source_clean": True,
            "source_inputs_sha256": "d" * 64,
            "bound_inputs_sha256": "e" * 64,
            "cargo_lock_sha256": "f" * 64,
            "schema_sha256": "1" * 64,
            "input_hashes": [],
            "runner_source_hashes": [],
        }

    def selection(self):
        return {
            "target": "rootyard-pando-lab", "kind": ["bin"],
            "profile": {"test": True}, "features": ["pando-lab"],
            "command": ["cargo", "test"], "fresh": True,
            "source": "src/bin/rootyard-pando-lab.rs",
            "executable_path": BINARY, "executable_sha256": "a" * 64,
            "executable": {"executable_name": "fake", "sha256": "a" * 64,
                           "size": 1, "st_dev": 1, "st_ino": 1,
                           "mtime_ns": 1},
        }

    def config(self):
        return runner.Config(
            source_root=Path("/tmp/source"),
            expected_commit="b" * 40,
            expected_tree="c" * 40,
            report=Path("/tmp/report.json"),
            product_receipt=Path("/tmp/pando-product.json"),
            total_seconds=100.0,
            cleanup_reserve_seconds=20.0,
            selection_timeout_seconds=10.0,
            setup_timeout_seconds=10.0,
            case_timeout_seconds=5.0,
            prepare_only=False,
        )


class FakeFixture:
    def __init__(self, cleanup_result, clock=None, advance=None):
        self.root = SimpleNamespace(path=Path("/tmp/owned-root"))
        self.child_environment = {}
        self.cleanup_result = dict(cleanup_result)
        self.clock = clock
        self.advance = advance
        self.started = False

    def start(self, deadline):
        self.started = True

    def cleanup(self, deadline):
        if self.clock is not None and self.advance:
            self.clock.advance(self.advance)
        return dict(self.cleanup_result)


class RunnerBudgetTest(OrchestrationFakes, unittest.TestCase):
    def invoke(
        self, clock, capture, execute, cleanup, verify=None, records=None,
        select=None,
    ):
        cleanup = cleanup or {
            "cleanup_ok": True,
            "postgres_dropped": True,
            "database_absent": True,
            "root_removed": True,
            "root_absent": True,
            "cleanup_within_deadline": True,
        }
        fixture = FakeFixture(cleanup, clock=clock, advance=None)
        writes = []
        verify = verify or mock.Mock(return_value={})
        with mock.patch.object(
            runner.artifacts, "verify_selected_binary", verify
        ):
            payload = runner.run(
                self.config(),
                runner=object(),
                clock=clock,
                capture_source=capture,
                select_binary=select or (
                    lambda *args, **kwargs: self.selection()
                ),
                fixture_factory=lambda *args, **kwargs: fixture,
                execute_cases_fn=execute,
                write_report_fn=(
                    lambda path, payload, **kwargs: writes.append((path, payload))
                ),
                validate_product=lambda *args, **kwargs: {
                    "provided": True,
                    "same_source": True,
                    "used_as_test_binary_receipt": False,
                    "attached_to_native_gate": False,
                },
                environ={"ROOTYARD_TEST_DATABASE_URL": BOOTSTRAP},
            )
        return payload, writes, fixture, verify

    def test_selection_budget_reserves_cleanup_window(self):
        clock = FakeClock(0)
        captured = {}

        def capture(*args, **kwargs):
            clock.set(75)
            return self.binding()

        def select(source, runner_obj, remaining, **kwargs):
            captured["remaining"] = remaining
            return self.selection()

        self.invoke(
            clock,
            capture=capture,
            execute=lambda *args, **kwargs: passing_records(),
            cleanup=None,
            select=select,
        )
        self.assertEqual(captured["remaining"], 3)

    def test_cleanup_secondary_failure_cannot_overwrite_primary_failure(self):
        clock = FakeClock(0)
        rows = cases.not_run_records()
        rows[0].update(
            status="failed", executed=True, exit_code=1, code="nonzero_exit"
        )
        cleanup = {
            "cleanup_ok": False,
            "cleanup_within_deadline": True,
            "error_code": "postgres_drop_unverified",
        }
        payload, writes, _, _ = self.invoke(
            clock,
            capture=lambda *args, **kwargs: self.binding(),
            execute=lambda *args, **kwargs: rows,
            cleanup=cleanup,
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "nonzero_exit")
        self.assertEqual(payload["stage"], "execute")
        self.assertEqual(
            payload["cleanup"]["secondary_error_code"],
            "postgres_drop_unverified",
        )
        self.assertEqual(len(writes), 1)

    def test_post_case_deadline_loss_is_failed_and_unverified(self):
        clock = FakeClock(0)
        initial = self.binding()

        def execute(*args, **kwargs):
            clock.set(79)
            return passing_records()

        payload, writes, _, _ = self.invoke(
            clock,
            capture=lambda *args, **kwargs: dict(initial),
            execute=execute,
            cleanup=None,
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "post_case_deadline_exceeded")
        self.assertEqual(payload["stage"], "binding")
        binding = payload["source_bindings"]
        self.assertEqual(
            binding["source_inputs_sha256"], initial["source_inputs_sha256"]
        )
        self.assertFalse(binding["source_rechecked"])
        self.assertFalse(binding["source_unchanged"])
        self.assertFalse(binding["test_binary_unchanged"])
        self.assertFalse(binding["fresh_verification"])
        self.assertFalse(payload["fresh_verification"])
        self.assertEqual(len(writes), 1)
        self.assertEqual(payload["case_count"], 17)

    def test_source_recheck_deadline_is_failed_and_unverified(self):
        clock = FakeClock(0)
        initial = self.binding()
        state = {"calls": 0}

        def capture(*args, **kwargs):
            state["calls"] += 1
            if state["calls"] > 1:
                raise RunnerError("source", "source_capture_deadline_exceeded")
            return dict(initial)

        def execute(*args, **kwargs):
            clock.set(70)
            return passing_records()

        payload, _, _, _ = self.invoke(
            clock, capture=capture, execute=execute, cleanup=None
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(
            payload["error_code"], "source_recheck_deadline_exceeded"
        )
        self.assertFalse(payload["source_bindings"]["source_rechecked"])
        self.assertFalse(payload["fresh_verification"])

    def test_source_recheck_group_unverified_preserves_primary(self):
        clock = FakeClock(0)
        initial = self.binding()
        state = {"calls": 0}

        def capture(*args, **kwargs):
            state["calls"] += 1
            if state["calls"] > 1:
                raise RunnerError(
                    "source",
                    "process_group_unverified",
                    primary_code="source_capture_deadline_exceeded",
                )
            return dict(initial)

        payload, _, _, _ = self.invoke(
            clock, capture=capture, execute=lambda *a, **k: passing_records(),
            cleanup=None,
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "process_group_unverified")
        self.assertEqual(payload["stage"], "binding")
        binding = payload["source_bindings"]
        self.assertFalse(binding["source_rechecked"])
        self.assertEqual(binding["verification_code"], "process_group_unverified")
        self.assertEqual(
            binding["verification_primary_code"],
            "source_capture_deadline_exceeded",
        )
        self.assertFalse(payload["fresh_verification"])

    def test_binary_recheck_deadline_skips_hash_and_marks_unverified(self):
        clock = FakeClock(0)
        initial = self.binding()
        state = {"calls": 0}

        def capture(*args, **kwargs):
            state["calls"] += 1
            if state["calls"] > 1:
                clock.advance(5)
            return dict(initial)

        def execute(*args, **kwargs):
            clock.set(74)
            return passing_records()

        verify = mock.Mock(return_value={})
        payload, _, _, _ = self.invoke(
            clock,
            capture=capture,
            execute=execute,
            cleanup=None,
            verify=verify,
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(
            payload["error_code"], "binary_recheck_deadline_exceeded"
        )
        binding = payload["source_bindings"]
        self.assertTrue(binding["source_rechecked"])
        self.assertTrue(binding["source_unchanged"])
        self.assertFalse(binding["test_binary_unchanged"])
        self.assertFalse(binding["fresh_verification"])
        self.assertFalse(verify.called)

    def test_cleanup_after_overall_deadline_cannot_pass(self):
        clock = FakeClock(0)

        def cleanup_advance(deadline):
            clock.advance(101)
            return {
                "cleanup_ok": True,
                "postgres_dropped": True,
                "database_absent": True,
                "root_removed": True,
                "root_absent": True,
                "cleanup_within_deadline": True,
            }

        fixture = SimpleNamespace(
            root=SimpleNamespace(path=Path("/tmp/owned-root")),
            child_environment={},
            start=lambda deadline: None,
            cleanup=cleanup_advance,
        )
        with mock.patch.object(
            runner.artifacts, "verify_selected_binary", return_value={}
        ):
            payload = runner.run(
                self.config(),
                runner=object(),
                clock=clock,
                capture_source=lambda *args, **kwargs: self.binding(),
                select_binary=lambda *args, **kwargs: self.selection(),
                fixture_factory=lambda *args, **kwargs: fixture,
                execute_cases_fn=lambda *args, **kwargs: passing_records(),
                write_report_fn=lambda *args, **kwargs: None,
                validate_product=lambda *args, **kwargs: {
                    "provided": True,
                    "same_source": True,
                    "used_as_test_binary_receipt": False,
                    "attached_to_native_gate": False,
                },
                environ={"ROOTYARD_TEST_DATABASE_URL": BOOTSTRAP},
            )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["error_code"], "overall_deadline_exceeded")


if __name__ == "__main__":
    unittest.main()
