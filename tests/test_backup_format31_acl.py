"""Hermetic checks for the opt-in format 31 PostgreSQL acceptance entrypoint."""
from argparse import Namespace
import json
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import Mock, call, patch

import backup_format31_acl as probe


IDENTITY = {"source_head": "1" * 40, "source_tree": "2" * 40,
            "binary_sha256": "3" * 64, "receipt_sha256": "4" * 64, "source_inputs_sha256": "5" * 64}
ADMIN = "postgresql://rootyard:fixture@127.0.0.1:55432/rootyard_test"


def job_environment(root):
    return {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "ROOTYARD_TEST_DATABASE_URL": ADMIN, "RUNNER_TEMP": str(root), "PATH": "/fixture/bin"}


def sample_manifest():
    return {"format": 31, "schema_versions": probe.SCHEMA_VERSIONS, "binary_sha256": IDENTITY["binary_sha256"],
            "backup_id": "fixture-backup", "volume_id": "fixture-volume", "repositories": [], "lfs_objects": []}


def write_archive(path, manifest=None):
    path.mkdir()
    for name in ("COMPLETE", "metadata.dump"):
        (path / name).touch()
    for name in ("volume", "pando"):
        (path / name).mkdir()
    (path / "manifest.json").write_text(json.dumps(sample_manifest() if manifest is None else manifest))


class Format31QualificationTest(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.temp = Path(temp).resolve()

    def test_job_service_coordinate_and_environment_allowlist(self):
        environ = job_environment(self.temp)
        self.assertEqual(probe.fixture_coordinates(environ), (ADMIN, self.temp))
        controls = (
            ADMIN.replace("127.0.0.1", "external.example"),
            ADMIN.replace("127.0.0.1", "localhost"),
            ADMIN.replace(":55432", ":5432"),
            ADMIN.replace("/rootyard_test", "/postgres"),
            ADMIN + "?host=external.example",
        )
        for url in controls:
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                probe.fixture_coordinates(dict(environ, ROOTYARD_TEST_DATABASE_URL=url))
        with self.assertRaises(RuntimeError):
            probe.fixture_coordinates(dict(environ, RUNNER_ENVIRONMENT="self-hosted"))
        child = probe.child_env(dict(environ, PGSERVICE="foreign", DATABASE_URL="private",
                                      ROOTYARD_RESTORE_TEST_DATABASE_URL="remote"))
        self.assertEqual(child["PGSSLMODE"], "disable")
        self.assertTrue({"PGSERVICE", "DATABASE_URL", "ROOTYARD_RESTORE_TEST_DATABASE_URL"}.isdisjoint(child))

    def harness(self, root):
        root.mkdir()
        harness = probe.Format31Harness("rootyard", ADMIN, root, {}, 1, 2)
        harness.source_db = "owned-source"
        harness.target_db = "owned-target"
        return harness

    def test_granted_acl_refusal_requires_no_output_or_archive_and_always_revokes(self):
        for index, (code, stdout, partial) in enumerate(((1, b"", False), (0, b"", False),
                                                        (1, b"raw", False), (1, b"", True), (-9, b"", False))):
            with self.subTest(code=code, stdout=bool(stdout), partial=partial):
                harness = self.harness(self.temp / str(index))
                harness.query = Mock(side_effect=["", probe.PUBLIC, "", probe.RESTRICTED])

                def backup(path=None, check=True):
                    if check:
                        write_archive(path)
                    elif partial:
                        (harness.root / ".rootyard-backup-owned.partial").mkdir()
                    return CompletedProcess([], code, stdout)

                harness.backup_command = Mock(side_effect=backup)
                if (code, stdout, partial) == (1, b"", False):
                    harness.refuse_public_execute(IDENTITY["binary_sha256"])
                else:
                    with self.assertRaises(RuntimeError):
                        harness.refuse_public_execute(IDENTITY["binary_sha256"])
                self.assertEqual(harness.backup_command.call_args_list,
                                 [call(harness.root / "control-backup"), call(check=False)])
                self.assertEqual(harness.query.call_args_list, [
                    call("owned-source", f"GRANT EXECUTE ON FUNCTION {probe.SIGNATURE} TO PUBLIC"),
                    call("owned-source", probe.ACL_SQL),
                    call("owned-source", f"REVOKE EXECUTE ON FUNCTION {probe.SIGNATURE} FROM PUBLIC"),
                    call("owned-source", probe.ACL_SQL),
                ])
                self.assertEqual(harness.deadline, 1)

    def test_grant_acknowledgment_failure_still_revokes(self):
        harness = self.harness(self.temp / "grant-error")
        harness.backup_command = Mock(side_effect=write_archive)
        harness.query = Mock(side_effect=[OSError("private details"), "", probe.RESTRICTED])
        with self.assertRaises(OSError):
            harness.refuse_public_execute(IDENTITY["binary_sha256"])
        harness.query.assert_any_call("owned-source", f"REVOKE EXECUTE ON FUNCTION {probe.SIGNATURE} FROM PUBLIC")
        harness.backup_command.assert_called_once()

    def test_manifest_requires_exact_roster_format_binary_and_no_paired_state(self):
        archive = self.temp / "archive"
        write_archive(archive)
        self.assertEqual(probe.archive_manifest(archive, IDENTITY["binary_sha256"]), sample_manifest())
        for changed in ({"format": 29}, {"format": 32}, {"schema_versions": probe.SCHEMA_VERSIONS[:-1]},
                        {"binary_sha256": "0" * 64}, {"blob_closure": None}):
            with self.subTest(changed=next(iter(changed))), self.assertRaises(RuntimeError):
                (archive / "manifest.json").write_text(json.dumps(dict(sample_manifest(), **changed)))
                probe.archive_manifest(archive, IDENTITY["binary_sha256"])

    def test_roundtrip_executes_normal_cli_and_queries_the_owned_target(self):
        harness = self.harness(self.temp / "roundtrip")
        manifest = sample_manifest()
        harness.env["DATABASE_URL"] = harness.source_db

        def run(argv, *, env=None, check=True):
            if argv[1] == "backup":
                write_archive(harness.backup)
                payload = {}
            elif argv[1] == "backup-verify":
                payload = {"checksums_verified": True, "backup_id": manifest["backup_id"]}
            else:
                self.assertEqual(env["DATABASE_URL"], harness.target_db)
                self.assertEqual(env["ROOTYARD_DATA_DIR"], str(harness.target))
                harness.target.mkdir()
                (harness.target / ".volume-id").write_text(manifest["volume_id"])
                payload = {"restored": True, "started_service": False,
                           "backup_id": manifest["backup_id"], "blob_artifacts": 0}
            return CompletedProcess(argv, 0, json.dumps(payload).encode())

        harness.run = Mock(side_effect=run)
        harness.query = Mock(return_value="\n".join(map(str, probe.SCHEMA_VERSIONS)))
        harness.roundtrip_archive(IDENTITY["binary_sha256"])
        self.assertEqual([entry.args[0] for entry in harness.run.call_args_list], [
            ["rootyard", "backup", str(harness.backup), "--offline"],
            ["rootyard", "backup-verify", str(harness.backup)],
            ["rootyard", "restore", str(harness.backup), "--isolated", "--trust-backup"],
        ])
        harness.query.assert_called_once_with(harness.target_db,
                                             "SELECT version FROM public.schema_migrations ORDER BY version")

    def test_binding_rejects_dirty_checkout_before_receipt_and_projects_only_digests(self):
        evidence = {**IDENTITY, "attested": True, "workspace_commit": IDENTITY["source_head"],
                    "current_head": IDENTITY["source_head"], "production_inputs_bound": True,
                    "receipt_immutable": True, "receipt_binary_sha256": IDENTITY["binary_sha256"],
                    "receipt_toolchain": {"command": "private selector"}}
        for dirty in (b"", b" M test"):
            responses = [CompletedProcess([], 0, value) for value in (
                IDENTITY["source_head"].encode(), IDENTITY["source_tree"].encode(), dirty)]
            with (patch.object(probe, "run_bounded", side_effect=responses),
                  patch.object(probe.source_bound_binary, "bind", return_value=evidence) as bind):
                if dirty:
                    with self.assertRaises(RuntimeError):
                        probe.capture_binding("rootyard", IDENTITY["source_head"], {}, 1)
                    bind.assert_not_called()
                else:
                    self.assertEqual(probe.capture_binding("rootyard", IDENTITY["source_head"], {}, 1), IDENTITY)

    def test_cleanup_attempts_both_owned_databases(self):
        harness = self.harness(self.temp / "cleanup")
        first = "rootyard_b31_" + "1" * 32
        second = "rootyard_b31_" + "2" * 32
        harness.created = [first, second, "foreign"]
        harness.query = Mock(side_effect=[RuntimeError("private failure"), "", "f"])
        self.assertFalse(harness.cleanup())
        self.assertEqual(harness.query.call_args_list[:2], [
            call(ADMIN, f'DROP DATABASE IF EXISTS "{second}" WITH (FORCE)'),
            call(ADMIN, f'DROP DATABASE IF EXISTS "{first}" WITH (FORCE)'),
        ])

    def test_unproven_target_creation_reports_unverified_cleanup_and_never_drops_target(self):
        binary = self.temp / "rootyard"
        binary.touch()
        args = Namespace(binary=str(binary), expected_commit=IDENTITY["source_head"], job_owned_postgres=True)
        source = "rootyard_b31_" + "1" * 32
        target = "rootyard_b31_" + "2" * 32
        for outcome in ("racing_collision", "lost_acknowledgment", "preexisting_collision"):
            with self.subTest(outcome=outcome):
                databases = {target: "foreign"} if outcome == "preexisting_collision" else {}
                events = []

                def run(argv, **kwargs):
                    if argv[1:] == ["--version"]:
                        return CompletedProcess(argv, 0, f"{argv[0]} (PostgreSQL) 17.0\n".encode())
                    self.assertEqual(argv[0], "psql")
                    self.assertEqual(kwargs["env"]["PGDATABASE"], "rootyard_test")
                    sql = argv[-1]
                    if sql == "SHOW server_version_num":
                        output = b"170000"
                    elif sql.startswith("SELECT current_database()"):
                        output = b"t"
                    elif sql.startswith("SELECT EXISTS"):
                        name = sql.split("'")[1]
                        events.append(("exists", name))
                        output = b"t" if name in databases else b"f"
                    elif sql.startswith("CREATE DATABASE"):
                        name = sql.split('"')[1]
                        events.append(("create", name))
                        if name == target:
                            if outcome == "lost_acknowledgment":
                                databases[name] = "unconfirmed"
                                raise TimeoutError("private create diagnostic")
                            databases[name] = "foreign"
                            return CompletedProcess(argv, 1, b"")
                        databases[name] = "owned"
                        output = b"CREATE DATABASE"
                    else:
                        self.assertTrue(sql.startswith("DROP DATABASE IF EXISTS"))
                        name = sql.split('"')[1]
                        events.append(("drop", name))
                        databases.pop(name)
                        output = b"DROP DATABASE"
                    return CompletedProcess(argv, 0, output)

                names = [Namespace(hex="1" * 32), Namespace(hex="2" * 32)]
                with (patch.object(probe.uuid, "uuid4", side_effect=names),
                      patch.object(probe, "run_bounded", side_effect=run),
                      patch.object(probe, "capture_binding", return_value=IDENTITY)):
                    report = probe.qualify(args, job_environment(self.temp))
                expected = [("exists", source), ("create", source), ("exists", target)]
                if outcome != "preexisting_collision":
                    expected.append(("create", target))
                self.assertEqual(events, [*expected, ("drop", source), ("exists", source)])
                self.assertEqual(databases, {target: "unconfirmed" if outcome == "lost_acknowledgment" else "foreign"})
                self.assertFalse(report["passed"])
                self.assertEqual(report["failure_phase"], "setup")
                self.assertFalse(report["owned_cleanup_verified"])
                self.assertNotIn(target, json.dumps(report))
                self.assertNotIn("private create diagnostic", json.dumps(report))
                self.assertEqual(list(self.temp.iterdir()), [binary])

    def test_output_overflow_kills_and_reaps_the_owned_child_without_raw_output(self):
        child = Mock(pid=42)
        ready = Mock()
        ready.select.return_value = True
        context = Mock()
        with (patch.object(probe.subprocess, "Popen", return_value=child) as spawn,
              patch.object(probe.selectors, "DefaultSelector", return_value=context),
              patch.object(probe.time, "monotonic", return_value=0),
              patch.object(probe.os, "read", return_value=b"s" * (probe.MAX_OUTPUT + 1)),
              patch.object(probe.os, "killpg") as kill):
            context.__enter__ = Mock(return_value=ready)
            context.__exit__ = Mock(return_value=False)
            with self.assertRaisesRegex(RuntimeError, "^qualification assertion failed$"):
                probe.run_bounded(["fixture"], env={}, deadline=1)
        self.assertEqual(spawn.call_args.kwargs["stderr"], probe.subprocess.DEVNULL)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        child.stdout.close.assert_called_once_with()
        kill.assert_called_once_with(42, probe.signal.SIGKILL)
        child.wait.assert_called_once_with(timeout=5)

    def test_report_requires_restored_acl_cleaned_resources_and_identical_after_binding(self):
        binary = self.temp / "rootyard"
        binary.touch()
        args = Namespace(binary=str(binary), expected_commit=IDENTITY["source_head"], job_owned_postgres=True)
        for acl, removed, after, failure in (
            (probe.RESTRICTED, True, IDENTITY, None),
            (probe.PUBLIC, True, IDENTITY, "restored_acl"),
            (probe.RESTRICTED, False, IDENTITY, "owned_cleanup"),
            (probe.RESTRICTED, True, dict(IDENTITY, receipt_sha256="6" * 64), "post_binding"),
        ):
            with self.subTest(failure=failure):
                fixture = Mock(target_db="private-db")
                fixture.query.return_value = acl
                fixture.cleanup.return_value = removed
                with (patch.object(probe, "Format31Harness", return_value=fixture),
                      patch.object(probe, "capture_binding", side_effect=[IDENTITY, after]) as bind):
                    report = probe.qualify(args, job_environment(self.temp))
                self.assertEqual(report["passed"], failure is None)
                self.assertEqual(report["failure_phase"], failure)
                self.assertEqual(report["owned_cleanup_verified"], removed)
                self.assertEqual(report["binding_rechecked"], after == IDENTITY)
                self.assertEqual({key: report[key] for key in IDENTITY}, IDENTITY)
                self.assertEqual([row["name"] for row in report["cases"]], list(probe.CASES))
                self.assertNotIn("private-db", json.dumps(report))
                self.assertNotIn(str(self.temp), json.dumps(report))
                self.assertEqual(bind.call_count, 2)
                fixture.cleanup.assert_called_once_with()
                self.assertEqual(list(self.temp.iterdir()), [binary])


if __name__ == "__main__":
    unittest.main()
