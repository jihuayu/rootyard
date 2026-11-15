"""Pure boundary tests for the owned physical PostgreSQL PITR fixture.

These tests never start PostgreSQL, open a database socket, read a server log or
claim physical qualification.  They exercise fixed failure mapping, recovery
configuration, containment checks, owned-descendant closure and the opt-in
self-check report boundary.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pando_pitr_physical_pg as physical  # noqa: E402

REAL_OWNED = physical._OwnedProcessSet
FAKE_TOOLS = physical.PgTools(
    initdb=Path("/opt/pg17/bin/initdb"),
    pg_ctl=Path("/opt/pg17/bin/pg_ctl"),
    psql=Path("/opt/pg17/bin/psql"),
    pg_basebackup=Path("/opt/pg17/bin/pg_basebackup"),
)


def completed(stdout: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")


class FakePidfd:
    def __init__(self, pid: int, starttime: int, generation: int) -> None:
        self.pid = pid
        self.starttime = starttime
        self.generation = generation
        self.closed = False


class FakePidfdApi:
    """Stable-generation pidfd mock; sends only while the pinned process lives."""

    def __init__(self, processes: "FakeProcesses") -> None:
        self.processes = processes
        self.opened = 0
        self.closed = 0
        self.closed_pids: list[int] = []
        self.live: list[FakePidfd] = []
        self.before_open = None
        self.before_send = None
        self.fail_open: set[int] = set()

    def open(self, pid: int, flags: int) -> FakePidfd:
        if pid in self.fail_open:
            self.fail_open.remove(pid)
            raise ProcessLookupError(pid)
        record = self.processes.records.get(pid)
        if record is None:
            raise ProcessLookupError(pid)
        self.opened += 1
        fd = FakePidfd(pid, record["starttime"], record["generation"])
        self.live.append(fd)
        if self.before_open is not None:
            callback = self.before_open
            self.before_open = None
            callback()
        return fd

    def send(self, fd: FakePidfd, signum: int) -> None:
        if signum != 0 and self.before_send is not None:
            callback = self.before_send
            self.before_send = None
            callback()
        record = self.processes.records.get(fd.pid)
        if (
            fd.closed
            or record is None
            or record["starttime"] != fd.starttime
            or record["generation"] != fd.generation
        ):
            raise ProcessLookupError(fd.pid)
        if signum != 0:
            self.processes.signal(fd.pid, signum)

    def close(self, fd: FakePidfd) -> None:
        if fd.closed:
            raise OSError("double close")
        fd.closed = True
        self.closed += 1
        self.closed_pids.append(fd.pid)
        self.live.remove(fd)


class FakeProcesses:
    """In-memory /proc boundary; no host process is ever signalled."""

    def __init__(self) -> None:
        self.records: dict[int, dict] = {}
        self.signals: list[tuple[int, int]] = []
        self.boot_id = "boot-test"
        self.ignore_term: set[int] = set()
        self.ignore_kill: set[int] = set()
        self.pidfds = FakePidfdApi(self)
        self._next_start = 1
        self._next_generation = 1

    def add(self, pid: int, *, ppid: int = 1, session: int | None = None,
            pgrp: int | None = None, starttime: int | None = None) -> dict:
        record = {
            "pid": pid,
            "state": "S",
            "ppid": ppid,
            "pgrp": pgrp if pgrp is not None else pid,
            "session": session if session is not None else pid,
            "starttime": starttime if starttime is not None else self._next_start,
            "uid": os.getuid(),
            "boot_id": self.boot_id,
            "generation": self._next_generation,
        }
        self._next_generation += 1
        self._next_start = max(self._next_start + 1, record["starttime"] + 1)
        self.records[pid] = record
        return record

    def table(self, phase: str) -> dict[int, dict]:
        return {pid: dict(record) for pid, record in self.records.items()}

    def boot(self, phase: str) -> str:
        return self.boot_id

    def record(self, pid: int, phase: str) -> dict:
        if pid not in self.records:
            raise physical.FixtureError(phase, "process_missing")
        return dict(self.records[pid])

    def replace(self, pid: int, *, starttime: int, session: int | None = None,
                pgrp: int | None = None, ppid: int | None = None) -> None:
        record = self.records[pid]
        record["generation"] = self._next_generation
        self._next_generation += 1
        record["starttime"] = starttime
        if session is not None:
            record["session"] = session
        if pgrp is not None:
            record["pgrp"] = pgrp
        if ppid is not None:
            record["ppid"] = ppid

    def signal(self, pid: int, signum: int) -> None:
        self.signals.append((pid, signum))
        if signum == signal.SIGTERM and pid in self.ignore_term:
            return
        if signum == signal.SIGKILL and pid in self.ignore_kill:
            return
        self.records.pop(pid, None)

    def relocate(self, pid: int, *, session: int | None = None,
                 pgrp: int | None = None, ppid: int | None = None) -> None:
        """Mutable location change for the same process generation (setsid/reparent)."""
        record = self.records[pid]
        if session is not None:
            record["session"] = session
        if pgrp is not None:
            record["pgrp"] = pgrp
        if ppid is not None:
            record["ppid"] = ppid

    def tracker(self) -> physical._OwnedProcessSet:
        tracker = REAL_OWNED(
            table_provider=self.table,
            boot_id_provider=self.boot,
            record_provider=self.record,
            pidfd_api_provider=lambda: (self.pidfds.open, self.pidfds.send),
            pidfd_close_fn=self.pidfds.close,
        )
        terminate = tracker.terminate_all

        def fast_terminate(phase: str, *, timeout: float = 0.2) -> None:
            terminate(phase, timeout=timeout)

        tracker.terminate_all = fast_terminate  # bounded test clock
        return tracker


class ProcTableTest(unittest.TestCase):
    def test_census_skips_init_keeps_foreign_rows_and_skips_missing(self) -> None:
        real_stat = physical._proc_stat
        real_record = physical._process_record
        calls: list[int] = []

        def fake_stat(pid: int, phase: str) -> dict:
            calls.append(pid)
            if pid == 100:
                return {"pid": 100, "state": "S", "ppid": 1, "pgrp": 100,
                        "session": 100, "starttime": 10, "uid": os.getuid()}
            if pid == 200:
                return {"pid": 200, "state": "S", "ppid": 1, "pgrp": 200,
                        "session": 200, "starttime": 20, "uid": 0}
            if pid == 300:
                raise physical.FixtureError(phase, "process_missing")
            raise AssertionError(f"unexpected census pid {pid}")

        with mock.patch.object(physical.os, "listdir",
                               return_value=["1", "100", "200", "300", "not-a-pid"]), \
                mock.patch.object(physical, "_proc_stat", side_effect=fake_stat), \
                mock.patch.object(physical, "_current_boot_id", return_value="boot-1"):
            table = physical._proc_table("test")

        self.assertEqual(set(table), {100, 200})
        self.assertEqual(calls, [100, 200, 300])
        self.assertEqual(table[100]["boot_id"], "boot-1")
        self.assertEqual(table[200]["uid"], 0)  # foreign readable row retained
        self.assertNotIn(1, table)

        with self.assertRaises(physical.FixtureError) as stat_error:
            real_stat(1, "test")
        self.assertEqual((stat_error.exception.phase, stat_error.exception.code),
                         ("test", "pid_invalid"))
        with self.assertRaises(physical.FixtureError) as record_error:
            real_record(1, "test")
        self.assertEqual((record_error.exception.phase, record_error.exception.code),
                         ("test", "pid_invalid"))

    def test_census_unreadable_row_still_fails_closed(self) -> None:
        calls: list[int] = []

        def fake_stat(pid: int, phase: str) -> dict:
            calls.append(pid)
            if pid == 100:
                return {"pid": 100, "state": "S", "ppid": 1, "pgrp": 100,
                        "session": 100, "starttime": 10, "uid": os.getuid()}
            raise physical.FixtureError(phase, "proc_unavailable")

        with mock.patch.object(physical.os, "listdir",
                               return_value=["1", "100", "200"]), \
                mock.patch.object(physical, "_proc_stat", side_effect=fake_stat), \
                mock.patch.object(physical, "_current_boot_id", return_value="boot-1"):
            with self.assertRaises(physical.FixtureError) as caught:
                physical._proc_table("test")

        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ("test", "proc_unavailable"))
        self.assertEqual(calls, [100, 200])
        self.assertNotIn(1, calls)


class PidfdPlatformTest(unittest.TestCase):
    def test_unsupported_pidfd_api_fails_before_popen_or_scratch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rootyard-pidfd-platform-") as temporary:
            with mock.patch.object(physical, "_proc_available", return_value=True), \
                    mock.patch.object(physical, "_pidfd_api", return_value=(None, None)), \
                    mock.patch.object(physical.subprocess, "Popen") as popen, \
                    mock.patch.object(physical.subprocess, "run") as run:
                with self.assertRaises(physical.FixtureError) as caught:
                    physical.PhysicalPitrFixture(
                        Path("/unused"), tools=FAKE_TOOLS,
                        scratch_parent=Path(temporary),
                    )
            self.assertEqual((caught.exception.phase, caught.exception.code),
                             ("platform", "pidfd_unavailable"))
            popen.assert_not_called()
            run.assert_not_called()
            self.assertEqual(list(Path(temporary).iterdir()), [])


class ToolValidationTest(unittest.TestCase):
    def test_wrong_pg_major_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rootyard-pg-tools-") as temporary:
            base = Path(temporary)
            for name in ("initdb", "pg_ctl", "psql", "pg_basebackup"):
                binary = base / name
                binary.write_text("#!/bin/sh\n", encoding="utf-8")
                binary.chmod(0o755)

            def fake_run(argv, *, phase, timeout):
                return completed(f"{Path(argv[0]).name} (PostgreSQL) 16.4\n".encode())

            with mock.patch.object(physical, "_run", side_effect=fake_run):
                with self.assertRaises(physical.FixtureError) as caught:
                    physical._validate_pg17_tools(base)
            self.assertEqual((caught.exception.phase, caught.exception.code),
                             ("tools", "pg_major_mismatch"))

    def test_relative_or_incomplete_tool_directory_is_rejected(self) -> None:
        with self.assertRaises(physical.FixtureError) as relative:
            physical._validate_pg17_tools(Path("relative/pg17/bin"))
        self.assertEqual((relative.exception.phase, relative.exception.code),
                         ("tools", "absolute_path_required"))

        with tempfile.TemporaryDirectory(prefix="rootyard-pg-tools-") as temporary:
            with self.assertRaises(physical.FixtureError) as missing:
                physical._validate_pg17_tools(Path(temporary))
        self.assertEqual((missing.exception.phase, missing.exception.code),
                         ("tools", "binary_missing"))

    def test_all_four_pg17_tool_versions_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rootyard-pg-tools-") as temporary:
            base = Path(temporary)
            for name in ("initdb", "pg_ctl", "psql", "pg_basebackup"):
                binary = base / name
                binary.write_text("#!/bin/sh\n", encoding="utf-8")
                binary.chmod(0o755)

            def fake_run(argv, *, phase, timeout):
                return completed(f"{Path(argv[0]).name} (PostgreSQL) 17.5\n".encode())

            with mock.patch.object(physical, "_run", side_effect=fake_run):
                tools = physical._validate_pg17_tools(base)
            self.assertEqual(tools.initdb, (base / "initdb").resolve())
            self.assertEqual(tools.pg_ctl, (base / "pg_ctl").resolve())
            self.assertEqual(tools.psql, (base / "psql").resolve())
            self.assertEqual(tools.pg_basebackup, (base / "pg_basebackup").resolve())


class FixtureBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        support = mock.patch.object(physical, "_require_pidfd_support", return_value=None)
        support.start()
        self.addCleanup(support.stop)

    def make_fixture(self, processes: FakeProcesses | None = None) -> physical.PhysicalPitrFixture:
        fixture = physical.PhysicalPitrFixture(Path("/unused"), tools=FAKE_TOOLS)
        fixture.owned = (processes or FakeProcesses()).tracker()
        self.addCleanup(fixture.cleanup)
        return fixture

    def test_recovery_configuration_is_named_physical_and_promoting(self) -> None:
        fixture = self.make_fixture()
        fixture.restored_data.mkdir(mode=0o700)
        (fixture.restored_data / "postgresql.conf").write_text(
            "# base backup config\n", encoding="utf-8"
        )

        fixture._prepare_recovery("rootyard_selfcheck")

        config = (fixture.restored_data / "postgresql.conf").read_text(encoding="utf-8")
        self.assertIn("archive_mode=off", config)
        self.assertIn(f"port={fixture.restored_port}", config)
        self.assertIn("restore_command='cp ", config)
        self.assertIn("recovery_target_name='rootyard_selfcheck'", config)
        self.assertIn("recovery_target_action='promote'", config)
        self.assertIn("unix_socket_directories='", config)
        self.assertTrue((fixture.restored_data / "recovery.signal").is_file())

    def test_failed_start_reports_no_pass_and_cleans_owned_scratch(self) -> None:
        processes = FakeProcesses()

        def fake_run(argv, *, phase, timeout=physical.COMMAND_TIMEOUT_SECONDS, owned=None):
            if Path(argv[0]).name == "initdb":
                data = Path(argv[argv.index("-D") + 1])
                data.mkdir(parents=True)
                (data / "pg_hba.conf").write_text("", encoding="utf-8")
                (data / "postgresql.conf").write_text("", encoding="utf-8")
                return completed()
            if Path(argv[0]).name == "pg_ctl":
                raise physical.FixtureError("start", "command_failed")
            raise AssertionError("unexpected command")

        with tempfile.TemporaryDirectory(prefix="rootyard-physical-test-") as temporary:
            with mock.patch.object(physical, "_validate_pg17_tools", return_value=FAKE_TOOLS), \
                    mock.patch.object(physical, "_OwnedProcessSet", new=lambda: processes.tracker()), \
                    mock.patch.object(physical, "_run", side_effect=fake_run):
                report = physical.run_self_check(Path("/unused"), Path(temporary))
            self.assertFalse(report["passed"])
            self.assertEqual(report["failure"],
                             {"phase": "start", "code": "command_failed",
                              "exception_class": "FixtureError"})
            self.assertTrue(report["cleanup"]["passed"])
            self.assertTrue(report["cleanup"]["owned_processes_stopped"])
            self.assertTrue(report["cleanup"]["scratch_removed"])
            self.assertEqual(list(Path(temporary).iterdir()), [])
            self.assertNotIn("postgresql://", json.dumps(report))

    def test_failed_basebackup_reports_no_pass_and_stops_primary(self) -> None:
        processes = FakeProcesses()
        processes.add(424242, session=424242)

        def fake_run(argv, *, phase, timeout=physical.COMMAND_TIMEOUT_SECONDS, owned=None):
            name = Path(argv[0]).name
            if name == "initdb":
                data = Path(argv[argv.index("-D") + 1])
                data.mkdir(parents=True)
                (data / "pg_hba.conf").write_text("", encoding="utf-8")
                (data / "postgresql.conf").write_text("", encoding="utf-8")
                return completed()
            if name == "pg_ctl":
                return completed()
            if name == "psql":
                if "SHOW server_version_num" in argv:
                    return completed(b"170005\n")
                return completed()
            if name == "pg_basebackup":
                raise physical.FixtureError("basebackup", "command_failed")
            raise AssertionError("unexpected command")

        with tempfile.TemporaryDirectory(prefix="rootyard-physical-test-") as temporary:
            with mock.patch.object(physical, "_validate_pg17_tools", return_value=FAKE_TOOLS), \
                    mock.patch.object(physical, "_OwnedProcessSet", new=lambda: processes.tracker()), \
                    mock.patch.object(physical.PhysicalPitrFixture, "_read_postmaster_pid",
                                      return_value=424242), \
                    mock.patch.object(physical, "_run", side_effect=fake_run):
                report = physical.run_self_check(Path("/unused"), Path(temporary))
            self.assertFalse(report["passed"])
            self.assertEqual(report["failure"]["phase"], "basebackup")
            self.assertEqual(report["failure"]["code"], "command_failed")
            self.assertTrue(report["cleanup"]["primary_stopped"])
            self.assertTrue(report["cleanup"]["owned_processes_stopped"])
            self.assertTrue(report["cleanup"]["scratch_removed"])
            self.assertIn((424242, signal.SIGTERM), processes.signals)
            self.assertEqual(list(Path(temporary).iterdir()), [])
            self.assertNotIn("postmaster.pid", json.dumps(report))

    def test_failed_restore_is_a_fixed_error_and_cleanup_keeps_primary_path_safe(self) -> None:
        fixture = self.make_fixture()
        fixture.base_backup_dir.mkdir(mode=0o700)
        (fixture.base_backup_dir / "postgresql.conf").write_text(
            "# copied base backup\n", encoding="utf-8"
        )
        fixture.base_backup_ready = True
        fixture.restore_point_name = "rootyard_selfcheck"
        fixture.restore_point_lsn = "0/16B6C50"
        fixture.archive_count = 1

        def fail_start(argv, *, phase, timeout=physical.COMMAND_TIMEOUT_SECONDS, owned=None):
            raise physical.FixtureError("restore", "command_failed")

        with mock.patch.object(physical, "_run", side_effect=fail_start):
            with self.assertRaises(physical.FixtureError) as caught:
                fixture.restore_to_point()
        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ("restore", "command_failed"))
        cleanup = fixture.cleanup()
        self.assertTrue(cleanup["passed"])
        self.assertTrue(cleanup["primary_stopped"])
        self.assertTrue(cleanup["restored_stopped"])
        self.assertTrue(cleanup["owned_processes_stopped"])

    def test_postmaster_exit_with_verified_session_child_is_killed(self) -> None:
        processes = FakeProcesses()
        processes.add(100, session=100, starttime=10)
        processes.add(101, ppid=100, session=100, pgrp=100, starttime=11)
        processes.ignore_term.add(101)
        tracker = processes.tracker()
        tracker.remember_postmaster(100, "cleanup")
        processes.records.pop(100)
        processes.records[101]["ppid"] = 1  # PG child reparented after the leader exit

        self.assertEqual(set(tracker.members("cleanup")), {101})
        tracker.terminate_all("cleanup", timeout=0.2)

        self.assertIn((101, signal.SIGTERM), processes.signals)
        self.assertIn((101, signal.SIGKILL), processes.signals)
        self.assertEqual(tracker.members("cleanup"), {})

    def test_stop_failure_with_postmaster_exit_kills_surviving_child(self) -> None:
        processes = FakeProcesses()
        postmaster = processes.add(500, session=500, starttime=50)
        processes.add(501, ppid=500, session=500, pgrp=500, starttime=51)
        processes.ignore_term.add(501)
        fixture = self.make_fixture(processes)
        fixture.primary_data.mkdir(mode=0o700)
        fixture.primary_identity = postmaster
        (fixture.primary_data / "postmaster.pid").write_text(
            f"500\n{fixture.primary_data}\n0\n{fixture.primary_port}\n"
            f"{fixture.socket_dir}\n127.0.0.1\n0\nready\n",
            encoding="ascii",
        )

        def failed_stop(argv, *, phase, timeout=physical.COMMAND_TIMEOUT_SECONDS, owned=None):
            processes.records.pop(500, None)  # postmaster exited, child survives
            raise physical.FixtureError(phase, "command_failed")

        with mock.patch.object(physical, "_run", side_effect=failed_stop):
            stopped = fixture._stop_cluster(
                fixture.primary_data, fixture.primary_identity,
                fixture.primary_port, "cleanup",
            )

        self.assertTrue(stopped)
        self.assertIn((501, signal.SIGTERM), processes.signals)
        self.assertIn((501, signal.SIGKILL), processes.signals)
        self.assertNotIn(501, processes.records)

    def test_pidfd_pins_old_process_when_numeric_pid_is_replaced_before_send(self) -> None:
        processes = FakeProcesses()
        processes.add(600, session=600, starttime=60)
        tracker = processes.tracker()
        tracker.remember_postmaster(600, "cleanup")

        def replace_pid() -> None:
            processes.replace(600, starttime=70, session=999, pgrp=999)

        processes.pidfds.before_send = replace_pid
        tracker.terminate_all("cleanup", timeout=0.2)

        self.assertEqual(processes.signals, [])
        self.assertEqual(tracker.members("cleanup"), {})
        self.assertEqual(processes.pidfds.closed, processes.pidfds.opened)
        self.assertEqual(processes.pidfds.live, [])

    def test_pidfd_identity_mismatch_on_acquisition_denies_signal(self) -> None:
        processes = FakeProcesses()
        processes.add(700, session=700, starttime=80)
        tracker = processes.tracker()
        expected = processes.record(700, "test")

        def replace_pid() -> None:
            processes.replace(700, starttime=81, session=999, pgrp=999)

        processes.pidfds.before_open = replace_pid
        with self.assertRaises(physical.FixtureError) as caught:
            tracker._pin(expected, "test")

        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ("test", "pidfd_identity_mismatch"))
        self.assertEqual(processes.signals, [])
        self.assertEqual(processes.pidfds.closed, processes.pidfds.opened)
        self.assertEqual(processes.pidfds.live, [])

    def test_first_pin_none_does_not_readopt_same_tick_replacement(self) -> None:
        processes = FakeProcesses()
        processes.add(800, ppid=1, session=800, starttime=80)
        processes.pidfds.fail_open.add(800)
        tracker = processes.tracker()

        tracker.remember_launch(800, "cleanup")
        self.assertEqual(tracker._pins, {})
        self.assertTrue(tracker._unknown)

        processes.replace(800, starttime=80, ppid=42, pgrp=999, session=999)
        self.assertEqual(tracker.members("cleanup"), {})
        with self.assertRaises(physical.FixtureError) as caught:
            tracker.terminate_all("cleanup", timeout=0.2)

        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ("cleanup", "owned_process_unknown"))
        self.assertEqual(processes.signals, [])
        self.assertEqual(processes.pidfds.live, [])

    def test_revoked_session_anchor_does_not_adopt_reused_numeric_sid(self) -> None:
        processes = FakeProcesses()
        processes.add(900, ppid=1, session=900, starttime=90)
        tracker = processes.tracker()
        tracker.remember_postmaster(900, "cleanup")

        processes.records.pop(900)
        processes.add(900, ppid=42, session=900, pgrp=999, starttime=90)
        with self.assertRaises(physical.FixtureError) as caught:
            tracker.terminate_all("cleanup", timeout=0.2)

        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ("cleanup", "owned_process_unknown"))
        self.assertEqual(tracker.members("cleanup"), {})
        self.assertEqual(processes.signals, [])
        self.assertEqual(processes.pidfds.live, [])

    def test_pinned_child_setsid_after_leader_exit_stays_owned_via_original_fd(self) -> None:
        processes = FakeProcesses()
        processes.add(1000, ppid=1, session=1000, starttime=100)
        processes.add(1001, ppid=1000, session=1000, pgrp=1000, starttime=101)
        tracker = processes.tracker()
        tracker.remember_postmaster(1000, "cleanup")
        opened = processes.pidfds.opened

        processes.records.pop(1000)
        processes.relocate(1001, ppid=1, pgrp=1001, session=1001)
        self.assertIn(1001, tracker.members("cleanup"))
        self.assertNotIn(1000, tracker._sessions)
        self.assertIn(1001, tracker._sessions)

        tracker.terminate_all("cleanup", timeout=0.2)

        self.assertIn((1001, signal.SIGTERM), processes.signals)
        self.assertNotIn(1000, processes.records)
        self.assertEqual(processes.pidfds.opened, opened)
        self.assertEqual(processes.pidfds.closed, processes.pidfds.opened)
        self.assertEqual(processes.pidfds.live, [])

    def test_moved_pinned_child_does_not_adopt_old_sid_foreign_replacement(self) -> None:
        processes = FakeProcesses()
        processes.add(1100, ppid=1, session=1100, starttime=110)
        processes.add(1101, ppid=1100, session=1100, pgrp=1100, starttime=111)
        tracker = processes.tracker()
        tracker.remember_postmaster(1100, "cleanup")

        processes.records.pop(1100)
        processes.relocate(1101, ppid=1, pgrp=1101, session=1101)
        processes.add(1102, ppid=1, session=1100, pgrp=1100, starttime=112)

        members = tracker.members("cleanup")
        self.assertIn(1101, members)
        self.assertNotIn(1102, members)
        with self.assertRaises(physical.FixtureError) as caught:
            tracker.terminate_all("cleanup", timeout=0.2)

        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ("cleanup", "owned_process_unknown"))
        self.assertIn((1101, signal.SIGTERM), processes.signals)
        self.assertNotIn((1102, signal.SIGTERM), processes.signals)
        self.assertNotIn((1102, signal.SIGKILL), processes.signals)
        self.assertEqual(processes.pidfds.closed, processes.pidfds.opened)

    def test_pinned_identity_uncertainty_retains_scratch(self) -> None:
        processes = FakeProcesses()
        processes.add(1200, ppid=1, session=1200, starttime=120)
        fixture = self.make_fixture(processes)
        fixture.owned.remember_postmaster(1200, "cleanup")

        processes.replace(1200, starttime=120, session=1200)
        cleanup = fixture.cleanup()

        self.assertFalse(cleanup["passed"])
        self.assertFalse(cleanup["owned_processes_stopped"])
        self.assertFalse(cleanup["scratch_removed"])
        self.assertTrue(fixture.root.is_dir())
        self.assertEqual(processes.signals, [])

        fixture.owned = FakeProcesses().tracker()
        self.assertTrue(fixture.cleanup()["passed"])

    def test_anchor_fd_liveness_blocks_same_field_generation_replacement(self) -> None:
        processes = FakeProcesses()
        processes.add(1400, ppid=1, session=1400, pgrp=1400, starttime=140)
        fixture = self.make_fixture(processes)
        fixture.owned.remember_postmaster(1400, "cleanup")
        processes.add(1401, ppid=42, session=1400, pgrp=1400, starttime=141)

        def replace_anchor_with_same_fields() -> None:
            # Old anchor fd remains pinned; the new numeric row is a different
            # generation with identical PID/starttime/PPID/PGRP/SID/boot/UID.
            processes.replace(1400, starttime=140, ppid=1, pgrp=1400, session=1400)

        processes.pidfds.before_open = replace_anchor_with_same_fields
        members = fixture.owned.members("cleanup")

        self.assertNotIn(1401, members)
        self.assertTrue(fixture.owned._unknown)
        self.assertNotIn(1401, [fd.pid for fd in processes.pidfds.live])
        self.assertEqual(processes.pidfds.closed_pids.count(1401), 1)
        self.assertEqual(processes.signals, [])

        cleanup = fixture.cleanup()
        self.assertFalse(cleanup["passed"])
        self.assertFalse(cleanup["scratch_removed"])
        self.assertTrue(fixture.root.is_dir())

        fixture.owned = FakeProcesses().tracker()
        self.assertTrue(fixture.cleanup()["passed"])

    def test_session_member_adoption_revalidates_live_anchor_around_pin(self) -> None:
        processes = FakeProcesses()
        processes.add(1300, ppid=1, session=1300, starttime=130)
        fixture = self.make_fixture(processes)
        fixture.owned.remember_postmaster(1300, "cleanup")
        processes.add(1301, ppid=42, session=1300, pgrp=1300, starttime=131)

        def move_anchor() -> None:
            processes.relocate(1300, ppid=1, pgrp=2000, session=2000)

        processes.pidfds.before_open = move_anchor
        members = fixture.owned.members("cleanup")

        self.assertIn(1300, members)
        self.assertNotIn(1301, members)
        self.assertTrue(fixture.owned._unknown)
        self.assertEqual(processes.signals, [])
        self.assertNotIn(1301, processes.pidfds.live)

    def test_partial_start_without_pidfile_requires_owned_child_absence(self) -> None:
        processes = FakeProcesses()
        processes.add(200, session=200, starttime=20)
        processes.add(201, ppid=200, session=200, pgrp=200, starttime=21)
        processes.ignore_term.add(201)
        fixture = self.make_fixture(processes)
        fixture.owned.remember_launch(200, "start")
        processes.records.pop(200)
        processes.records[201]["ppid"] = 1  # detached child is reparented
        fixture.primary_data.mkdir(mode=0o700)

        cleanup = fixture.cleanup()

        self.assertTrue(cleanup["passed"])
        self.assertTrue(cleanup["primary_stopped"])
        self.assertTrue(cleanup["owned_processes_stopped"])
        self.assertTrue(cleanup["scratch_removed"])
        self.assertIn((201, signal.SIGKILL), processes.signals)
        self.assertEqual(processes.pidfds.closed, processes.pidfds.opened)
        self.assertEqual(processes.pidfds.live, [])
        self.assertFalse(fixture.root.exists())

    def test_still_live_owned_child_denies_cleanup_and_retains_scratch(self) -> None:
        processes = FakeProcesses()
        processes.add(300, session=300, starttime=30)
        processes.add(301, ppid=300, session=300, pgrp=300, starttime=31)
        processes.ignore_term.add(301)
        processes.ignore_kill.add(301)
        fixture = self.make_fixture(processes)
        fixture.owned.remember_launch(300, "start")
        processes.records.pop(300)
        fixture.primary_data.mkdir(mode=0o700)

        cleanup = fixture.cleanup()

        self.assertFalse(cleanup["passed"])
        self.assertFalse(cleanup["primary_stopped"])
        self.assertFalse(cleanup["owned_processes_stopped"])
        self.assertFalse(cleanup["scratch_removed"])
        self.assertIn("owned:owned_processes_survive", cleanup["errors"])
        self.assertTrue(fixture.root.is_dir())

        processes.records.pop(301, None)
        self.assertTrue(fixture.cleanup()["passed"])

    def test_cleanup_refuses_containment_break_and_does_not_remove_scratch(self) -> None:
        fixture = self.make_fixture()
        outside = fixture.root.parent / (fixture.root.name + "-outside")
        outside.mkdir(mode=0o700)
        self.addCleanup(lambda: outside.exists() and outside.rmdir())
        fixture.primary_data.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(physical.FixtureError) as caught:
            fixture._stop_cluster(fixture.primary_data, None, fixture.primary_port, "cleanup")
        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ("cleanup", "cleanup_containment"))

        cleanup = fixture.cleanup()
        self.assertFalse(cleanup["passed"])
        self.assertFalse(cleanup["scratch_removed"])
        self.assertIn("primary:cleanup_containment", cleanup["errors"])
        self.assertTrue(fixture.root.is_dir())

        fixture.primary_data.unlink()
        self.assertTrue(fixture.cleanup()["passed"])

    def test_identity_mismatch_cannot_kill_foreign_or_remove_scratch(self) -> None:
        processes = FakeProcesses()
        processes.add(os.getpid(), starttime=100)
        fixture = self.make_fixture(processes)
        fixture.primary_data.mkdir(mode=0o700)
        pid_file = fixture.primary_data / "postmaster.pid"
        pid_file.write_text(
            f"{os.getpid()}\n{fixture.primary_data}\n0\n{fixture.primary_port}\n"
            f"{fixture.socket_dir}\n127.0.0.1\n0\nready\n",
            encoding="ascii",
        )
        fixture.primary_identity = {"pid": os.getpid(), "starttime": 99, "state": "S"}

        cleanup = fixture.cleanup()
        self.assertFalse(cleanup["passed"])
        self.assertFalse(cleanup["primary_stopped"])
        self.assertFalse(cleanup["scratch_removed"])
        self.assertIn("primary:pid_identity_mismatch", cleanup["errors"])
        self.assertEqual(processes.signals, [])
        self.assertTrue(fixture.root.is_dir())

        pid_file.unlink()
        fixture.primary_identity = None
        self.assertTrue(fixture.cleanup()["passed"])

    def test_normal_cleanup_stops_verified_postmaster_and_removes_scratch(self) -> None:
        processes = FakeProcesses()
        processes.add(400, session=400, starttime=40)
        fixture = self.make_fixture(processes)
        fixture.owned.remember_postmaster(400, "cleanup")

        cleanup = fixture.cleanup()

        self.assertTrue(cleanup["passed"])
        self.assertTrue(cleanup["owned_processes_stopped"])
        self.assertTrue(cleanup["scratch_removed"])
        self.assertIn((400, signal.SIGTERM), processes.signals)
        self.assertEqual(processes.pidfds.closed, processes.pidfds.opened)
        self.assertEqual(processes.pidfds.live, [])
        self.assertFalse(fixture.root.exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux") and Path("/proc").is_dir(),
        "owned /proc process boundary is Linux-only",
    )
    def test_run_timeout_records_and_cleans_owned_python_descendant(self) -> None:
        script = (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "time.sleep(60)\n"
        )
        tracker = REAL_OWNED()
        with self.assertRaises(physical.FixtureError) as caught:
            physical._run(
                [sys.executable, "-c", script],
                phase="owned-run",
                timeout=0.5,
                owned=tracker,
            )
        self.assertEqual((caught.exception.phase, caught.exception.code),
                         ("owned-run", "timeout"))
        self.assertEqual(tracker.members("owned-run"), {})

    def test_entrypoint_requires_opt_in_and_reports_failure_without_urls(self) -> None:
        report_path = Path(tempfile.mkdtemp(prefix="rootyard-physical-report-")) / "report.json"
        failed = {
            "kind": "rootyard/pando-physical-pitr-fixture-selfcheck",
            "passed": False,
            "failure": {"phase": "start", "code": "command_failed",
                        "exception_class": "FixtureError"},
            "cleanup": {"attempted": True, "passed": True, "primary_stopped": True,
                        "restored_stopped": True, "owned_processes_stopped": True,
                        "scratch_removed": True, "errors": []},
            "topology": physical.TOPOLOGY,
            "limitations": physical.LIMITATIONS,
        }
        with mock.patch.object(physical, "run_self_check", return_value=failed), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            status = physical.main([
                "--self-check", "--pg-bin", "/unused", "--report", str(report_path)
            ])
        self.assertEqual(status, 1)
        written = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertFalse(written["passed"])
        self.assertNotIn("postgresql://", json.dumps(written))

        with mock.patch("sys.stderr", new_callable=io.StringIO), \
                self.assertRaises(SystemExit) as caught:
            physical.main(["--pg-bin", "/unused", "--report", str(report_path)])
        self.assertEqual(caught.exception.code, 2)
        report_path.unlink()
        report_path.parent.rmdir()


if __name__ == "__main__":
    unittest.main()
