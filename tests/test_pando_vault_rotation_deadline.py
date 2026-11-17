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

    def test_case_that_returns_after_the_work_deadline_is_not_green(self):
        clock = Clock()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        report_path = Path(temporary.name) / "report.json"
        args = main.parse_args([
            "--report", str(report_path),
            "--timeout-seconds", "100",
            "--cleanup-reserve-seconds", "20",
        ])

        def late_case(_ctx):
            clock.advance(80)
            return {"id": CASES[0], "status": "passed", "facts": {}}

        context = SimpleNamespace(
            start_base=lambda: None,
            prepare_initial_packs=lambda: None,
        )
        with mock.patch.object(main, "validate_inputs",
                               return_value=inputs(report_path)), \
             mock.patch.object(main, "binding_snapshot",
                               side_effect=[binding(), binding()]), \
             mock.patch.object(main, "Context", return_value=context), \
             mock.patch.object(
                 main.cases, "case_fixture_and_app_capability_boundary",
                 side_effect=late_case), \
             mock.patch.object(
                 main.negative, "case_owned_resource_cleanup",
                 return_value=passed_cleanup()):
            report = main.run_qualification(args, environ={}, clock=clock)
        self.assertFalse(report["passed"])
        self.assertEqual(report["error_code"], "work_deadline_exceeded")
        self.assertTrue(all(
            case["status"] == "failed" for case in report["cases"][:4]))


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

    def test_live_server_process_blocks_root_removal(self):
        import pando_vault_rotation_negative as negative

        class Root:
            created = True
            path = Path("/never-read-root")

            def remove(self):
                raise AssertionError("root must not be removed with a live group")

        class Runner:
            unresolved_children = False

        class Server:
            process = object()

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
    def __init__(self, fd=99):
        self.fd = fd
        self.closed = False

    def fileno(self):
        return self.fd

    def close(self):
        self.closed = True


class FakeGroup:
    """Async fake process group; no OS process, signal or wait is created."""

    def __init__(self, clock, pgid=4321, leader_exit_at=None,
                 child_exit_at=None, term_leader_delay=0.0,
                 term_child_delay=0.0, kill_leader_delay=0.0,
                 kill_child_delay=0.0, ambiguous=False,
                 eperm_signals=(), zombie_present=True):
        self.clock = clock
        self.pgid = pgid
        self.leader_exit_at = (
            float("inf") if leader_exit_at is None else float(leader_exit_at))
        self.child_exit_at = (
            float("inf") if child_exit_at is None else float(child_exit_at))
        self.term_leader_delay = float(term_leader_delay)
        self.term_child_delay = float(term_child_delay)
        self.kill_leader_delay = float(kill_leader_delay)
        self.kill_child_delay = float(kill_child_delay)
        self.ambiguous = ambiguous
        self.eperm_signals = set(eperm_signals)
        self.zombie_present = zombie_present
        self.leader_reaped = False
        self.reaped_at_call = []
        self.calls = []

    def leader_exited(self):
        return self.clock.now >= self.leader_exit_at

    def child_alive(self):
        return self.clock.now < self.child_exit_at

    def present(self):
        if not self.leader_reaped:
            if self.zombie_present or not self.leader_exited():
                return True
        return self.child_alive()

    def killpg(self, pgid, sig):
        self.reaped_at_call.append(self.leader_reaped)
        self.calls.append((pgid, sig, self.clock.now))
        if self.ambiguous:
            raise PermissionError("ambiguous group")
        if sig in self.eperm_signals:
            raise PermissionError("eperm group")
        if sig == 0:
            if self.present():
                return None
            raise ProcessLookupError()
        if not self.present():
            raise ProcessLookupError()
        if sig == signal.SIGTERM:
            self.leader_exit_at = min(
                self.leader_exit_at,
                self.clock.now + self.term_leader_delay)
            self.child_exit_at = min(
                self.child_exit_at,
                self.clock.now + self.term_child_delay)
        elif sig == signal.SIGKILL:
            self.leader_exit_at = min(
                self.leader_exit_at,
                self.clock.now + self.kill_leader_delay)
            self.child_exit_at = min(
                self.child_exit_at,
                self.clock.now + self.kill_child_delay)
        return None


class FakeProcess:
    """A fake Popen handle; no OS process or thread is created."""

    def __init__(self, group, pid=None):
        self.group = group
        self.pid = group.pgid if pid is None else pid
        self.stdout = FakeStream()
        self.returncode = None
        self.waits = []

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.returncode is not None:
            return self.returncode
        now = self.group.clock.now
        if self.group.leader_exited():
            self.returncode = 0
            self.group.leader_reaped = True
            return 0
        if self.group.leader_exit_at <= now + float(timeout):
            self.group.clock.now = self.group.leader_exit_at
            self.returncode = 0
            self.group.leader_reaped = True
            return 0
        self.group.clock.advance(timeout)
        raise subprocess.TimeoutExpired(["lab"], timeout)

    def terminate(self):
        self.group.leader_exit_at = self.group.clock.now
        self.returncode = 0
        self.group.leader_reaped = True

    def kill(self):
        self.terminate()


class FakePopen:
    def __init__(self, process):
        self.process = process
        self.kwargs = None
        self.argv = None
        self.calls = 0

    def __call__(self, argv, **kwargs):
        self.calls += 1
        self.argv = list(argv)
        self.kwargs = dict(kwargs)
        return self.process


class FakeRead:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.calls = []

    def __call__(self, fd, size):
        self.calls.append((fd, size))
        if not self.chunks:
            raise AssertionError("unexpected read")
        item = self.chunks.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeSelect:
    def __init__(self, clock=None, advance=0.0, ready=True):
        self.clock = clock
        self.advance = advance
        self.ready = ready
        self.calls = []

    def __call__(self, read_list, _write_list, _error_list, timeout):
        self.calls.append((list(read_list), timeout))
        if self.clock is not None and self.advance:
            self.clock.advance(self.advance)
        if self.ready:
            return (list(read_list), [], [])
        return ([], [], [])


class FakeSleep:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []

    def __call__(self, seconds):
        self.calls.append(seconds)
        self.clock.advance(seconds)


def _leader_state_for(process, group):
    def observe():
        if process.returncode is not None or group.leader_reaped:
            return "reaped"
        if group.leader_exited():
            return "exited"
        return "alive"
    return observe


def _server_for_start(clock, budget, process, read_chunks,
                      advance=0.0, ready=True):
    group = process.group
    popen = FakePopen(process)
    reader = FakeRead(read_chunks)
    selector = FakeSelect(clock=clock, advance=advance, ready=ready)
    sleep = FakeSleep(clock)
    server = service.Server(
        "/bin/lab", {}, budget=budget, clock=clock,
        popen=popen, killpg=group.killpg,
        select_fn=selector, read_fn=reader,
        set_blocking_fn=lambda _fd, _flag: None,
        sleep_fn=sleep, leader_state_fn=_leader_state_for(process, group))
    return server, popen, reader, selector, sleep


def _server_for_stop(clock, budget, group=None):
    group = group or FakeGroup(clock)
    process = FakeProcess(group)
    sleep = FakeSleep(clock)
    server = service.Server(
        "/bin/lab", {}, budget=budget, clock=clock,
        popen=FakePopen(process), killpg=group.killpg,
        sleep_fn=sleep, leader_state_fn=_leader_state_for(process, group))
    server.process = process
    server.owned_group = True
    server.pgid = group.pgid
    return server, process, group, sleep


class ServerProcessBoundaryTest(unittest.TestCase):
    def test_start_owns_group_and_reads_a_bounded_announcement(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(FakeGroup(clock))
        server, popen, reader, selector, _sleep = _server_for_start(
            clock, budget, process,
            [b"LISTEN http://127.0.0.1:9000\n"])
        self.assertEqual(server.start(), "http://127.0.0.1:9000")
        self.assertTrue(popen.kwargs["start_new_session"])
        self.assertFalse(popen.kwargs.get("text", False))
        self.assertEqual(popen.kwargs.get("bufsize"), 0)
        self.assertEqual(popen.argv, ["/bin/lab", "serve"])
        self.assertEqual(reader.calls, [(process.stdout.fd, 4096)])
        self.assertLessEqual(selector.calls[0][1], 0.2)
        self.assertEqual(process.waits, [])

    def test_partial_no_newline_live_writer_regains_control_at_startup_d(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(FakeGroup(clock))
        reader = FakeRead([b"LISTEN http://127.0.0.1:9000"])
        select_calls = []

        def selector(read_list, _write_list, _error_list, timeout):
            select_calls.append((list(read_list), timeout))
            if len(select_calls) == 1:
                return (list(read_list), [], [])
            clock.advance(46.0)
            return ([], [], [])

        sleep = FakeSleep(clock)
        server = service.Server(
            "/bin/lab", {}, budget=budget, clock=clock,
            popen=FakePopen(process), killpg=process.group.killpg,
            select_fn=selector, read_fn=reader,
            set_blocking_fn=lambda _fd, _flag: None,
            sleep_fn=sleep,
            leader_state_fn=_leader_state_for(process, process.group))
        with self.assertRaises(QualificationError) as caught:
            server.start()
        self.assertEqual(caught.exception.code, "server_start_timeout")
        self.assertEqual(reader.calls, [(process.stdout.fd, 4096)])
        self.assertEqual(len(select_calls), 2)
        self.assertLessEqual(select_calls[1][1], 0.2)
        self.assertIsNone(server.process)

    def test_eof_and_malformed_announcements_fail_closed(self):
        for chunks, code in (
            ([b""], "server_exited"),
            ([b"HELLO\n"], "server_announcement_invalid"),
            ([b"LISTEN http://0.0.0.0:9000\n"],
             "server_announcement_invalid"),
            ([b"LISTEN http://127.0.0.1:9000/extra\n"],
             "server_announcement_invalid"),
            ([b"LISTEN http://127.0.0.1:9000?x=1\n"],
             "server_announcement_invalid"),
            ([b"LISTEN http://user@127.0.0.1:9000\n"],
             "server_announcement_invalid"),
            ([b"LISTEN http://127.0.0.1:9000\nX"],
             "server_announcement_invalid"),
        ):
            with self.subTest(chunks=chunks):
                clock = Clock()
                budget = Budget(100, 20, clock=clock,
                                error_factory=QualificationError)
                process = FakeProcess(FakeGroup(clock))
                server, _popen, _reader, _selector, _sleep = _server_for_start(
                    clock, budget, process, list(chunks))
                with self.assertRaises(QualificationError) as caught:
                    server.start()
                self.assertEqual(caught.exception.code, code)
                self.assertIsNone(server.process)

    def test_announcement_overflow_fails_without_a_second_read(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(FakeGroup(clock))
        server, _popen, reader, _selector, _sleep = _server_for_start(
            clock, budget, process, [b"x" * service.Server.MAX_ANNOUNCEMENT])
        with self.assertRaises(QualificationError) as caught:
            server.start()
        self.assertEqual(caught.exception.code, "server_announcement_invalid")
        self.assertEqual(len(reader.calls), 1)
        self.assertLessEqual(reader.calls[0][1], 4096)
        self.assertIsNone(server.process)

    def test_expired_budget_and_cleanup_phase_never_start_popen(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(FakeGroup(clock))
        server, popen, _reader, _selector, _sleep = _server_for_start(
            clock, budget, process, [])
        clock.advance(80)
        with self.assertRaises(QualificationError) as caught:
            server.start()
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(popen.calls, 0)

        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        budget.begin_cleanup()
        process = FakeProcess(FakeGroup(clock))
        server, popen, _reader, _selector, _sleep = _server_for_start(
            clock, budget, process, [])
        with self.assertRaises(QualificationError) as caught:
            server.start()
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(popen.calls, 0)

    def test_late_complete_announcement_is_not_success(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(FakeGroup(clock))

        class LateRead:
            def __call__(self, _fd, _size):
                clock.advance(81)
                return b"LISTEN http://127.0.0.1:9000\n"

        selector = FakeSelect(clock=clock, ready=True)
        sleep = FakeSleep(clock)
        server = service.Server(
            "/bin/lab", {}, budget=budget, clock=clock,
            popen=FakePopen(process), killpg=process.group.killpg,
            select_fn=selector, read_fn=LateRead(),
            set_blocking_fn=lambda _fd, _flag: None,
            sleep_fn=sleep,
            leader_state_fn=_leader_state_for(process, process.group))
        with self.assertRaises(QualificationError) as caught:
            server.start()
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertIs(server.process, process)

    def test_oversized_announcement_fails_without_losing_primary(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        process = FakeProcess(FakeGroup(clock))
        server, _popen, _reader, _selector, _sleep = _server_for_start(
            clock, budget, process,
            [b"x" * service.Server.MAX_ANNOUNCEMENT])
        with self.assertRaises(QualificationError) as caught:
            server.start()
        self.assertEqual(caught.exception.code, "server_announcement_invalid")
        self.assertIsNone(server.process)

    def test_stop_leader_exit_does_not_hide_a_live_child(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(
            clock, leader_exit_at=0.0, child_exit_at=float("inf"),
            term_child_delay=float("inf"),
            kill_leader_delay=0.0, kill_child_delay=0.0)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        self.assertTrue(server.stop())
        kill_index = next(
            index for index, (_pgid, sig, _at) in enumerate(group.calls)
            if sig == signal.SIGKILL)
        self.assertFalse(group.reaped_at_call[kill_index])
        self.assertTrue(process.stdout.closed)

    def test_stop_zombie_leader_keeps_group_present_until_reap(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(
            clock, leader_exit_at=0.0, child_exit_at=0.0,
            term_leader_delay=float("inf"),
            term_child_delay=float("inf"),
            kill_leader_delay=0.0, kill_child_delay=0.0)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        self.assertTrue(server.stop())
        kill_index = next(
            index for index, (_pgid, sig, _at) in enumerate(group.calls)
            if sig == signal.SIGKILL)
        self.assertFalse(group.reaped_at_call[kill_index])
        self.assertTrue(process.stdout.closed)

    def test_stop_no_signal_after_leader_reap_on_later_cleanup(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(
            clock, term_leader_delay=float("inf"),
            term_child_delay=float("inf"),
            kill_leader_delay=0.0, kill_child_delay=2.1)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        with self.assertRaises(QualificationError):
            server.stop()
        calls_after_first = len(group.calls)
        self.assertTrue(group.leader_reaped)
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "server_group_unverified")
        self.assertEqual(len(group.calls), calls_after_first)
        self.assertIs(server.process, process)
        self.assertTrue(server.owned_group)

    def test_stop_ambiguous_group_is_never_marked_stopped(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(clock, ambiguous=True)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "server_group_unverified")
        self.assertIs(server.process, process)
        self.assertTrue(server.owned_group)
        self.assertFalse(process.stdout.closed)

    def test_stop_eperm_after_term_is_never_marked_stopped(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(clock, eperm_signals=(signal.SIGTERM,))
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "server_group_unverified")
        self.assertIs(server.process, process)
        self.assertTrue(server.owned_group)

    def test_stop_group_alive_after_kill_is_never_marked_stopped(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(
            clock, term_leader_delay=float("inf"),
            term_child_delay=float("inf"),
            kill_leader_delay=0.0, kill_child_delay=float("inf"))
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "server_group_alive")
        self.assertIs(server.process, process)
        self.assertTrue(server.owned_group)
        self.assertFalse(process.stdout.closed)

    def test_stop_uses_the_verified_pgid_fence(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(clock, pgid=5555)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        server.pgid = 5555
        self.assertTrue(server.stop())
        self.assertTrue(group.calls)
        self.assertTrue(all(pgid == 5555 for pgid, _sig, _at in group.calls))

    def test_stop_refuses_an_unowned_group_without_signal(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(clock)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        server.owned_group = False
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "server_group_unverified")
        self.assertEqual(group.calls, [])
        self.assertIs(server.process, process)

    def test_stop_after_overall_deadline_does_not_start_a_kill(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(clock)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        clock.advance(100)
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "overall_deadline_exceeded")
        self.assertEqual(group.calls, [])
        self.assertIs(server.process, process)

    def test_stop_work_phase_does_not_borrow_cleanup_reserve(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(clock)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        clock.advance(80)
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(group.calls, [])
        self.assertIs(server.process, process)

    def test_stop_cleanup_phase_may_use_overall_deadline(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        budget.begin_cleanup()
        group = FakeGroup(clock)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        clock.advance(80)
        self.assertTrue(server.stop())
        self.assertIn(signal.SIGTERM,
                      [sig for _pgid, sig, _at in group.calls])
        self.assertIsNone(server.process)

    def test_stop_already_exited_group_absent_while_unreaped(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(
            clock, leader_exit_at=0.0, child_exit_at=0.0,
            zombie_present=False)
        server, process, group, _sleep = _server_for_stop(
            clock, budget, group)
        self.assertTrue(server.stop())
        self.assertEqual(
            [sig for _pgid, sig, _at in group.calls
             if sig in (signal.SIGTERM, signal.SIGKILL)], [])
        self.assertTrue(process.stdout.closed)
        self.assertIsNone(server.process)

    def test_stop_leader_already_reaped_fails_closed_without_signal(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(clock, leader_exit_at=0.0, child_exit_at=0.0)
        process = FakeProcess(group)
        process.returncode = 0
        group.leader_reaped = True
        sleep = FakeSleep(clock)
        server = service.Server(
            "/bin/lab", {}, budget=budget, clock=clock,
            popen=FakePopen(process), killpg=group.killpg,
            sleep_fn=sleep,
            leader_state_fn=_leader_state_for(process, group))
        server.process = process
        server.owned_group = True
        server.pgid = group.pgid
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "server_group_unverified")
        self.assertEqual(group.calls, [])
        self.assertIs(server.process, process)

    def test_stop_late_server_reap_is_not_marked_stopped(self):
        clock = Clock()
        budget = Budget(100, 20, clock=clock,
                        error_factory=QualificationError)
        group = FakeGroup(
            clock, term_leader_delay=float("inf"),
            term_child_delay=float("inf"),
            kill_leader_delay=0.0, kill_child_delay=0.0)

        class LateProcess(FakeProcess):
            def wait(self, timeout=None):
                self.waits.append(timeout)
                self.group.clock.advance(timeout + 0.2)
                self.group.leader_exit_at = min(
                    self.group.leader_exit_at, self.group.clock.now)
                self.returncode = 0
                self.group.leader_reaped = True
                return 0

        process = LateProcess(group)
        sleep = FakeSleep(clock)
        server = service.Server(
            "/bin/lab", {}, budget=budget, clock=clock,
            popen=FakePopen(process), killpg=group.killpg,
            sleep_fn=sleep,
            leader_state_fn=_leader_state_for(process, group))
        server.process = process
        server.owned_group = True
        server.pgid = group.pgid
        clock.advance(79.9)
        with self.assertRaises(QualificationError) as caught:
            server.stop()
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertIs(server.process, process)
        self.assertTrue(server.owned_group)
        self.assertFalse(process.stdout.closed)


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
