#!/usr/bin/env python3
"""Pure fault counterexamples for the Vault harness shared deadline.

Only a fake monotonic clock, fake runners, a fake HTTP opener and temporary
files are used.  No Docker, Vault, PostgreSQL, Git, network, compiler, Cargo,
child process or thread is started.
"""
from __future__ import annotations

import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

TESTS = Path(__file__).resolve().parent
SCRIPTS = TESTS.parent / "scripts"
for entry in (str(TESTS), str(SCRIPTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import pando_vault_rotation as main  # noqa: E402
import pando_vault_rotation_fixture_resources as resources  # noqa: E402
import pando_vault_rotation_fixture_vault as vault_fixture  # noqa: E402
import pando_vault_rotation_service as service  # noqa: E402
from pando_vault_rotation_budget import Budget  # noqa: E402
from pando_vault_rotation_support import (  # noqa: E402
    CASES,
    Completed,
    QualificationError,
)

A = "a" * 40
B = "b" * 40
C = "c" * 64
D = "d" * 64
E = "e" * 64


class Clock:
    def __init__(self, now=0.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)
        return self.now


def binding():
    return {
        "source_commit": A,
        "source_tree": B,
        "source_clean": True,
        "binary_sha256": C,
        "receipt_sha256": D,
        "harness_sha256": E,
    }


def passed_rows():
    return [
        {"id": case_id, "status": "passed", "facts": {}}
        for case_id in CASES[:4]
    ]


def passed_cleanup():
    return {
        "id": CASES[4],
        "status": "passed",
        "facts": {"cleanup_ok": True},
    }


def failed_cleanup(code="cleanup_secondary"):
    return {
        "id": CASES[4],
        "status": "failed",
        "code": code,
        "stage": "cleanup",
        "facts": {"cleanup_ok": False},
    }


def inputs(report):
    return {
        "report": report,
        "binary": Path("/never-read-binary"),
        "receipt": Path("/never-read-receipt"),
        "source_root": Path("/never-read-source"),
        "source_commit": A,
        "source_tree": B,
        "source_clean": True,
        "binary_sha256": C,
        "receipt_sha256": D,
        "harness_sha256": E,
    }


class HarnessDeadlineTest(unittest.TestCase):
    def _run(self, clock, context, before, after, cleanup, case_rows=None):
        rows = list(case_rows or passed_rows())
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        report_path = Path(temporary.name) / "report.json"
        args = main.parse_args([
            "--report", str(report_path),
            "--timeout-seconds", "100",
            "--cleanup-reserve-seconds", "20",
        ])
        calls = {"n": 0}

        def snapshot(value, budget=None, runner=None):
            calls["n"] += 1
            action = before if calls["n"] == 1 else after
            if callable(action):
                return action(value, budget=budget, runner=runner)
            return action

        with mock.patch.object(main, "validate_inputs",
                               return_value=inputs(report_path)), \
             mock.patch.object(main, "binding_snapshot",
                               side_effect=snapshot), \
             mock.patch.object(main, "Context", return_value=context), \
             mock.patch.object(
                 main.cases, "case_fixture_and_app_capability_boundary",
                 return_value=rows[0]), \
             mock.patch.object(
                 main.cases, "case_authentic_envelope_digest_and_cold_read",
                 return_value=rows[1]), \
             mock.patch.object(
                 main.cases,
                 "case_admin_rotated_target_interrupted_resume_and_new_write",
                 return_value=rows[2]), \
             mock.patch.object(
                 main.negative,
                 "case_wrong_key_ciphertext_envelope_and_provider_revocation",
                 return_value=rows[3]), \
             mock.patch.object(
                 main.negative, "case_owned_resource_cleanup",
                 side_effect=cleanup if callable(cleanup)
                 else (lambda _ctx: cleanup)):
            report = main.run_qualification(args, environ={}, clock=clock)
        return report, report_path

    def test_primary_case_failure_survives_secondary_cleanup_failure(self):
        clock = Clock()
        context = SimpleNamespace(
            start_base=lambda: (_ for _ in ()).throw(
                QualificationError("case_primary", "case")),
            prepare_initial_packs=lambda: None,
        )
        report, path = self._run(
            clock, context, binding(), binding(), failed_cleanup())
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_code"], "case_primary")
        self.assertEqual(report["stage"], "case")
        self.assertEqual(report["cases"][4]["status"], "failed")
        self.assertEqual(report["cases"][4]["code"], "cleanup_secondary")
        self.assertTrue(path.is_file())

    def test_work_expiry_still_runs_cleanup_with_the_reserve(self):
        clock = Clock()
        observed = {}

        def start_base():
            clock.advance(80)
            raise QualificationError("work_deadline_exceeded", "case")

        def cleanup(ctx):
            observed["phase"] = ctx.budget.phase
            observed["remaining"] = ctx.budget.remaining_overall()
            return passed_cleanup()

        context = SimpleNamespace(
            start_base=start_base,
            prepare_initial_packs=lambda: None,
            budget=None,
        )
        # The real Context would already hold the shared budget; attach the
        # same Budget instance the orchestrator creates for the cleanup probe.
        original_run = main.run_qualification

        def run_with_attached_budget(args, **kwargs):
            budget = Budget(100, 20, clock=clock,
                            error_factory=QualificationError)
            context.budget = budget
            with mock.patch.object(main, "Budget", return_value=budget):
                return original_run(args, **kwargs)

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        report_path = Path(temporary.name) / "report.json"
        args = main.parse_args([
            "--report", str(report_path),
            "--timeout-seconds", "100",
            "--cleanup-reserve-seconds", "20",
        ])
        with mock.patch.object(main, "validate_inputs",
                               return_value=inputs(report_path)), \
             mock.patch.object(main, "binding_snapshot",
                               side_effect=[binding(), binding()]), \
             mock.patch.object(main, "Context", return_value=context), \
             mock.patch.object(
                 main.negative, "case_owned_resource_cleanup",
                 side_effect=cleanup):
            report = run_with_attached_budget(args, environ={}, clock=clock)
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_code"], "work_deadline_exceeded")
        self.assertEqual(observed["phase"], "cleanup")
        self.assertEqual(observed["remaining"], 20.0)

    def test_same_deadlines_are_reused_for_before_and_after_binding(self):
        clock = Clock()
        seen = []

        def before(value, budget=None, runner=None):
            seen.append((budget.work_deadline, budget.overall_deadline))
            return binding()

        def after(value, budget=None, runner=None):
            seen.append((budget.work_deadline, budget.overall_deadline))
            return binding()

        def start_base():
            clock.advance(10)

        context = SimpleNamespace(
            start_base=start_base,
            prepare_initial_packs=lambda: clock.advance(10),
        )
        report, _path = self._run(
            clock, context, before, after, passed_cleanup())
        self.assertTrue(report["passed"])
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0], (80.0, 100.0))
        self.assertEqual(seen[1], seen[0])

    def test_final_binding_deadline_failure_cannot_green(self):
        clock = Clock()

        def final(value, budget=None, runner=None):
            clock.advance(90)
            raise QualificationError("work_deadline_exceeded", "binding")

        context = SimpleNamespace(
            start_base=lambda: None,
            prepare_initial_packs=lambda: None,
        )
        report, _path = self._run(
            clock, context, binding(), final, passed_cleanup())
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_code"], "work_deadline_exceeded")
        self.assertEqual(report["stage"], "binding")

    def test_late_report_write_is_rewritten_as_failure(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        payload = {
            "schema": main.REPORT_SCHEMA,
            "passed": True,
            "status": "passed",
            "case_count": len(CASES),
            "cases": [],
            "binding": binding(),
            "cleanup": {"cleanup_ok": True},
            "limitations": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            real_write = main.atomic_write_json
            calls = []

            def late_write(target, value):
                calls.append(value.get("passed"))
                if len(calls) == 1:
                    clock.advance(100)
                real_write(target, value)

            with mock.patch.object(main, "atomic_write_json",
                                   side_effect=late_write):
                ok = main._finish_report(path, payload, budget)
            written = json.loads(path.read_text())
        self.assertFalse(ok)
        self.assertFalse(written["passed"])
        self.assertEqual(written["error_code"], "overall_deadline_exceeded")
        self.assertEqual(calls[0], True)
        self.assertIn(False, calls[1:])


class FakeHttpResponse:
    def __init__(self, clock):
        self.clock = clock
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, _limit):
        self.clock.advance(80)
        return b"{}"


class LateHttpOpener:
    def __init__(self, clock):
        self.clock = clock
        self.timeouts = []

    def open(self, _request, timeout=None):
        self.timeouts.append(timeout)
        return FakeHttpResponse(self.clock)


class ExpiredDockerRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        raise AssertionError("expired budget must not start Docker")


class FixtureDeadlineTest(unittest.TestCase):
    def test_expired_budget_never_starts_a_docker_pull(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        clock.advance(80)
        runner = ExpiredDockerRunner()
        fixture = vault_fixture.VaultFixture(
            Path("/unused"), runner=runner, budget=budget)
        with self.assertRaises(QualificationError) as caught:
            fixture.ensure_image()
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(runner.calls, [])

    def test_late_http_success_is_not_counted(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        fixture = vault_fixture.VaultFixture(
            Path("/unused"), runner=ExpiredDockerRunner(), budget=budget)
        fixture.host_url = "http://127.0.0.1:1"
        fixture.opener = LateHttpOpener(clock)
        with self.assertRaises(QualificationError) as caught:
            fixture.api("GET", "/v1/sys/health")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(fixture.opener.timeouts, [5])


class UnknownPostgresOutcomeTest(unittest.TestCase):
    def test_unknown_create_timeout_never_issues_a_blind_drop(self):
        class Runner:
            def __init__(self, database):
                self.database = database
                self.sql = []

            def run(self, argv, **kwargs):
                sql = (kwargs.get("input") or b"").decode()
                self.sql.append(sql)
                if "SHOW server_version_num" in sql:
                    return Completed(argv, 0, b"170004\n", b"")
                if "FROM pg_database" in sql:
                    return Completed(argv, 0, b"", b"")
                if sql.startswith("CREATE DATABASE"):
                    raise QualificationError("subprocess_timeout", "database")
                raise AssertionError("unexpected SQL after unknown create")

        postgres = resources.OwnedPostgres(
            "postgresql://user:password@127.0.0.1:55432/admin",
            nonce="a" * 12)
        runner = Runner(postgres.database)
        postgres.runner = runner
        with self.assertRaises(QualificationError):
            postgres.create()
        self.assertEqual(postgres.creation_outcome, "unknown")
        self.assertFalse(postgres.owned)
        with self.assertRaises(resources.FixtureError) as caught:
            postgres.drop()
        self.assertEqual(caught.exception.code, "pg_create_outcome_unknown")
        self.assertFalse(any(sql.startswith("DROP DATABASE")
                             for sql in runner.sql))


class RetainedWriterCleanupTest(unittest.TestCase):
    def test_unreaped_owned_child_blocks_root_removal(self):
        import pando_vault_rotation_negative as negative

        class Root:
            created = True
            path = Path("/never-read-root")

            def remove(self):
                raise AssertionError("root must not be removed with a live child")

        class Runner:
            unresolved_children = True

        class Server:
            process = None

            def stop(self):
                return True

        class Fixture:
            container_id = "a" * 64
            state_written = True
            state_path = Path("/never-read-state")
            version = "2.2.2"

            def stop(self):
                return "stopped"

        class Postgres:
            prechecked_absent = True
            created = True
            dropped = False
            major = 17

            def drop(self):
                self.dropped = True
                return True

        ctx = SimpleNamespace(
            server=Server(), fixture=Fixture(), postgres=Postgres(),
            root=Root(), runner=Runner(),
            repo="11111111-1111-4111-8111-111111111111")
        result = negative.case_owned_resource_cleanup(ctx)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["facts"]["root_removed"])
        self.assertFalse(result["facts"]["root_absent"])
        self.assertFalse(result["facts"]["cleanup_ok"])


class FakeStream:
    def __init__(self, lines=()):
        self.lines = list(lines)
        self.closed = False

    def readline(self, _limit):
        return self.lines.pop(0) if self.lines else ""

    def close(self):
        self.closed = True


class FakeProcess:
    """A fake Popen handle; no OS process or thread is created."""

    def __init__(self, pid=4321, lines=(), returncode=None):
        self.pid = pid
        self.stdout = FakeStream(lines)
        self.returncode = returncode
        self.waits = []

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.returncode is None:
            raise subprocess.TimeoutExpired(["lab"], timeout)
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9


class FakePopen:
    def __init__(self, process):
        self.process = process
        self.kwargs = None
        self.argv = None

    def __call__(self, argv, **kwargs):
        self.argv = list(argv)
        self.kwargs = dict(kwargs)
        return self.process


class FakeKillpg:
    def __init__(self, process, exit_on=()):
        self.process = process
        self.exit_on = set(exit_on)
        self.calls = []

    def __call__(self, pgid, sig):
        self.calls.append((pgid, sig))
        if sig in self.exit_on:
            self.process.returncode = 0 if sig == signal.SIGTERM else -9


class ServerProcessBoundaryTest(unittest.TestCase):
    def test_start_owns_group_and_returns_bounded_loopback_announcement(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(
            lines=["LISTEN http://127.0.0.1:9000\n"])
        popen = FakePopen(process)
        with mock.patch.object(
                service.select, "select",
                return_value=([process.stdout], [], [])):
            server = service.Server(
                "/bin/lab", {}, budget=budget, clock=clock,
                popen=popen, killpg=FakeKillpg(process))
            self.assertEqual(server.start(), "http://127.0.0.1:9000")
        self.assertTrue(popen.kwargs["start_new_session"])
        self.assertEqual(popen.argv, ["/bin/lab", "serve"])

    def test_stop_signals_kills_reaps_and_closes_the_exact_group(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess()
        killpg = FakeKillpg(process, exit_on=(signal.SIGTERM,))
        server = service.Server(
            "/bin/lab", {}, budget=budget, clock=clock,
            popen=FakePopen(process), killpg=killpg)
        server.process = process
        server.owned_group = True
        self.assertTrue(server.stop())
        self.assertEqual(killpg.calls, [(process.pid, signal.SIGTERM)])
        self.assertTrue(process.stdout.closed)
        self.assertIsNone(server.process)
        self.assertFalse(server.owned_group)

    def test_stop_without_exit_escalates_to_sigkill_before_success(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess()
        killpg = FakeKillpg(process, exit_on=(signal.SIGKILL,))
        server = service.Server(
            "/bin/lab", {}, budget=budget, clock=clock,
            popen=FakePopen(process), killpg=killpg)
        server.process = process
        server.owned_group = True
        self.assertTrue(server.stop())
        self.assertEqual(
            [sig for _pid, sig in killpg.calls],
            [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(process.stdout.closed)

    def test_stop_after_overall_deadline_does_not_start_a_kill(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess()
        killpg = FakeKillpg(process)
        server = service.Server(
            "/bin/lab", {}, budget=budget, clock=clock,
            popen=FakePopen(process), killpg=killpg)
        server.process = process
        server.owned_group = True
        clock.advance(100)
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "overall_deadline_exceeded")
        self.assertEqual(killpg.calls, [])
        self.assertIs(server.process, process)

    def test_already_exited_server_is_reaped_and_closed_without_signal(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(returncode=0)
        killpg = FakeKillpg(process)
        server = service.Server(
            "/bin/lab", {}, budget=budget, clock=clock,
            popen=FakePopen(process), killpg=killpg)
        server.process = process
        server.owned_group = True
        self.assertTrue(server.stop())
        self.assertEqual(killpg.calls, [])
        self.assertTrue(process.stdout.closed)
        self.assertIsNone(server.process)

    def test_oversized_announcement_fails_without_losing_primary(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(lines=["x" * service.Server.MAX_LINE])
        killpg = FakeKillpg(process, exit_on=(signal.SIGTERM,))
        with mock.patch.object(
                service.select, "select",
                return_value=([process.stdout], [], [])):
            server = service.Server(
                "/bin/lab", {}, budget=budget, clock=clock,
                popen=FakePopen(process), killpg=killpg)
            with self.assertRaises(QualificationError) as caught:
                server.start()
        self.assertEqual(caught.exception.code, "server_announcement_invalid")
        self.assertEqual(killpg.calls, [(process.pid, signal.SIGTERM)])
        self.assertTrue(process.stdout.closed)


class ExpiredInputValidationTest(unittest.TestCase):
    def test_expired_budget_refuses_before_any_input_probe(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        args = SimpleNamespace(
            binary="/never-read-binary",
            receipt="/never-read-receipt",
            expected_commit=A,
            expected_binary_sha256=None,
            report="/never-write-report",
            source_root="/never-read-source",
        )
        clock.advance(80)
        with self.assertRaises(QualificationError) as caught:
            main.validate_inputs(args, {}, budget=budget, runner=None)
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(caught.exception.stage, "input")


if __name__ == "__main__":
    unittest.main()
