"""Pure boundary tests for the owned physical PostgreSQL PITR fixture.

These tests never start PostgreSQL, open a database socket, read a server log or
claim physical qualification.  They exercise fixed failure mapping, recovery
configuration, containment checks and the opt-in self-check report boundary.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pando_pitr_physical_pg as physical  # noqa: E402

FAKE_TOOLS = physical.PgTools(
    initdb=Path("/opt/pg17/bin/initdb"),
    pg_ctl=Path("/opt/pg17/bin/pg_ctl"),
    psql=Path("/opt/pg17/bin/psql"),
    pg_basebackup=Path("/opt/pg17/bin/pg_basebackup"),
)


def completed(stdout: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")


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
    def make_fixture(self) -> physical.PhysicalPitrFixture:
        fixture = physical.PhysicalPitrFixture(Path("/unused"), tools=FAKE_TOOLS)
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
        def fake_run(argv, *, phase, timeout=physical.COMMAND_TIMEOUT_SECONDS):
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
                    mock.patch.object(physical, "_run", side_effect=fake_run):
                report = physical.run_self_check(Path("/unused"), Path(temporary))
            self.assertFalse(report["passed"])
            self.assertEqual(report["failure"],
                             {"phase": "start", "code": "command_failed",
                              "exception_class": "FixtureError"})
            self.assertTrue(report["cleanup"]["passed"])
            self.assertTrue(report["cleanup"]["scratch_removed"])
            self.assertEqual(list(Path(temporary).iterdir()), [])
            self.assertNotIn("postgresql://", json.dumps(report))

    def test_failed_basebackup_reports_no_pass_and_stops_primary(self) -> None:
        state = {"alive": True}

        def fake_run(argv, *, phase, timeout=physical.COMMAND_TIMEOUT_SECONDS):
            name = Path(argv[0]).name
            if name == "initdb":
                data = Path(argv[argv.index("-D") + 1])
                data.mkdir(parents=True)
                (data / "pg_hba.conf").write_text("", encoding="utf-8")
                (data / "postgresql.conf").write_text("", encoding="utf-8")
                return completed()
            if name == "pg_ctl":
                if "stop" in argv:
                    state["alive"] = False
                return completed()
            if name == "psql":
                if "SHOW server_version_num" in argv:
                    return completed(b"170005\n")
                return completed()
            if name == "pg_basebackup":
                raise physical.FixtureError("basebackup", "command_failed")
            raise AssertionError("unexpected command")

        def fake_identity(pid, phase):
            return {"pid": pid, "starttime": 7,
                    "state": "S" if state["alive"] else "Z"}

        with tempfile.TemporaryDirectory(prefix="rootyard-physical-test-") as temporary:
            with mock.patch.object(physical, "_validate_pg17_tools", return_value=FAKE_TOOLS), \
                    mock.patch.object(physical.PhysicalPitrFixture, "_read_postmaster_pid",
                                      return_value=424242), \
                    mock.patch.object(physical, "_process_identity", side_effect=fake_identity), \
                    mock.patch.object(physical, "_run", side_effect=fake_run):
                report = physical.run_self_check(Path("/unused"), Path(temporary))
            self.assertFalse(report["passed"])
            self.assertEqual(report["failure"]["phase"], "basebackup")
            self.assertEqual(report["failure"]["code"], "command_failed")
            self.assertTrue(report["cleanup"]["primary_stopped"])
            self.assertTrue(report["cleanup"]["scratch_removed"])
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

        def fail_start(argv, *, phase, timeout=physical.COMMAND_TIMEOUT_SECONDS):
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

    def test_pid_identity_mismatch_is_not_stopped_or_removed(self) -> None:
        fixture = self.make_fixture()
        fixture.primary_data.mkdir(mode=0o700)
        pid_file = fixture.primary_data / "postmaster.pid"
        pid_file.write_text(
            f"{os.getpid()}\n{fixture.primary_data}\n0\n{fixture.primary_port}\n"
            f"{fixture.socket_dir}\n127.0.0.1\n0\nready\n",
            encoding="ascii",
        )
        fixture.primary_identity = {"pid": os.getpid(), "starttime": 99, "state": "S"}
        observed = {"pid": os.getpid(), "starttime": 100, "state": "S"}

        with mock.patch.object(physical, "_process_identity", return_value=observed):
            cleanup = fixture.cleanup()
        self.assertFalse(cleanup["passed"])
        self.assertFalse(cleanup["primary_stopped"])
        self.assertFalse(cleanup["scratch_removed"])
        self.assertIn("primary:pid_identity_mismatch", cleanup["errors"])
        self.assertTrue(fixture.root.is_dir())

        pid_file.unlink()
        fixture.primary_identity = None
        self.assertTrue(fixture.cleanup()["passed"])


    def test_entrypoint_requires_opt_in_and_reports_failure_without_urls(self) -> None:
        report_path = Path(tempfile.mkdtemp(prefix="rootyard-physical-report-")) / "report.json"
        failed = {
            "kind": "rootyard/pando-physical-pitr-fixture-selfcheck",
            "passed": False,
            "failure": {"phase": "start", "code": "command_failed",
                        "exception_class": "FixtureError"},
            "cleanup": {"attempted": True, "passed": True, "primary_stopped": True,
                        "restored_stopped": True, "scratch_removed": True, "errors": []},
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
