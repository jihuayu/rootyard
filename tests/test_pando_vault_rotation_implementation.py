#!/usr/bin/env python3
"""Pure contract tests for the authored issue #21 rotation harness.

No Docker, Vault, PostgreSQL, HTTP, Git, Cargo, compiler or product binary is
started.  Fakes prove exact case selection, source/receipt binding, hermetic
child environments, owned-cache eviction, SQL argv hygiene, report allowlisting,
cleanup-in-finally and fail-not-skip behavior.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation as main  # noqa: E402
import pando_vault_rotation_negative as negative  # noqa: E402
from pando_vault_rotation_service import GitWorkspace, Psql  # noqa: E402
import pando_vault_rotation_support as support  # noqa: E402


def completed(returncode=0, stdout=b"[]", stderr=b""):
    return support.Completed(["fake"], returncode, stdout, stderr)


class RunnerFake:
    def __init__(self, results=None):
        self.results = list(results or [])
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(([str(item) for item in argv], kwargs))
        if not self.results:
            return completed()
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def ok(self, argv, **kwargs):
        result = self.run(argv, **kwargs)
        if result.returncode != 0:
            raise support.QualificationError(kwargs.get("stage", "x") + "_failed")
        return result

    def json(self, argv, **kwargs):
        return json.loads(self.ok(argv, **kwargs).stdout)


class CaseAndReportContractTest(unittest.TestCase):
    def test_required_cases_are_exactly_five_in_order(self):
        self.assertEqual(list(main.required_cases()), [
            "vault_fixture_and_app_capability_boundary",
            "authentic_envelope_digest_and_cold_read",
            "admin_rotated_target_interrupted_resume_and_new_write",
            "wrong_key_ciphertext_envelope_and_provider_revocation_fail_closed",
            "owned_resource_cleanup",
        ])
        self.assertEqual(len(main.required_cases()), 5)

    def test_report_sanitizer_rejects_markers_tokens_and_unknown_fields(self):
        good = support.sanitize_report({
            "schema": "rootyard/issue21-derived-vault-rotation/v1",
            "passed": True,
            "ciphertext_sha256": ["a" * 64],
            "ciphertext_bytes": [123],
            "derived": True,
        })
        self.assertTrue(good["passed"])
        for value, code in (
            ({"case": "ROOTYARD_ISSUE21_MARKER"}, "report_string_rejected"),
            ({"token": "secret"}, "report_field_rejected"),
            ({"passed": {"nested": "secret"}}, "report_field_rejected"),
            ({"ciphertext_bytes": -1}, "report_integer_rejected"),
        ):
            with self.subTest(code=code):
                with self.assertRaises(support.QualificationError) as caught:
                    support.sanitize_report(value)
                self.assertEqual(caught.exception.code, code)

    def test_fill_cases_always_returns_five_failed_not_skipped(self):
        cleanup = {
            "id": support.CASES[4], "status": "passed", "facts": {"cleanup_ok": True}}
        rows = main.fill_cases(
            [{"id": support.CASES[0], "status": "passed", "facts": {}}],
            "setup_failed", "setup", cleanup)
        self.assertEqual([row["id"] for row in rows], list(support.CASES))
        self.assertEqual(rows[0]["status"], "passed")
        self.assertEqual([row["status"] for row in rows[1:4]], ["failed"] * 3)
        self.assertEqual(rows[4], cleanup)
        self.assertNotIn("skipped", json.dumps(rows))

    def test_build_report_has_no_untrusted_text(self):
        inputs = {
            "source_commit": "a" * 40, "source_tree": "b" * 40,
            "source_clean": True, "binary_sha256": "c" * 64,
            "receipt_sha256": "d" * 64, "harness_sha256": "e" * 64,
        }
        rows = main.fill_cases([], "setup_failed", "setup", {
            "id": support.CASES[4], "status": "failed",
            "code": "cleanup_unresolved",
            "facts": {"cleanup_ok": False}})
        report = main.build_report(inputs, rows, rows[4], False,
                                   "setup_failed", "setup")
        text = json.dumps(report)
        self.assertEqual(report["case_count"], 5)
        self.assertFalse(report["passed"])
        self.assertNotIn("skipped", text)
        self.assertNotIn("ROOTYARD_ISSUE21", text)
        self.assertNotIn("secret", text)

    def test_missing_inputs_write_failed_report_without_skip(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            args = main.parse_args(["--report", str(report_path)])
            report = main.run_qualification(args, environ={})
            self.assertFalse(report["passed"])
            self.assertEqual(report["case_count"], 5)
            self.assertTrue(all(case["status"] == "failed" for case in report["cases"]))
            self.assertEqual(report["cases"][4]["id"], support.CASES[4])
            self.assertTrue(report_path.is_file())
            self.assertNotIn("skipped", report_path.read_text())


class BindingAndEnvironmentTest(unittest.TestCase):
    def test_validate_inputs_binds_receipt_binary_commit_and_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "rootyard-pando-lab"
            binary.write_bytes(b"binary")
            binary.chmod(0o755)
            receipt = root / "receipt.json"
            receipt.write_text("{}")
            report = root / "report.json"
            commit = "a" * 40
            binary_sha = support.sha256_file(binary)
            validated = SimpleNamespace(
                schema="v2",
                payload={"receipt_schema": main.receipts.RECEIPT_SCHEMA_V2},
                artifacts=({"kind": "bin", "target": "rootyard-pando-lab",
                            "executable_sha256": binary_sha},),
                binary_sha256=binary_sha, workspace_commit=commit,
                receipt_sha256="b" * 64)
            args = main.parse_args([
                "--binary", str(binary), "--receipt", str(receipt),
                "--source-root", str(root), "--expected-commit", commit,
                "--report", str(report)])
            environment = {"ROOTYARD_TEST_DATABASE_URL":
                           "postgresql://u:p@127.0.0.1:55432/db"}
            with mock.patch.object(main, "_source_state", return_value={
                    "commit": commit, "tree": "c" * 40, "clean": True}), \
                 mock.patch.object(main.receipts, "load_receipt",
                                   return_value=validated), \
                 mock.patch.object(main, "_harness_sha256", return_value="d" * 64), \
                 mock.patch.object(main.shutil, "which",
                                   return_value="/usr/bin/tool"):
                inputs = main.validate_inputs(args, environment)
            self.assertEqual(inputs["binary_sha256"], binary_sha)
            self.assertEqual(inputs["receipt_sha256"], validated.receipt_sha256)
            self.assertEqual(inputs["harness_sha256"], "d" * 64)

    def test_validate_inputs_rejects_missing_pando_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "rootyard-pando-lab"
            binary.write_bytes(b"binary")
            binary.chmod(0o755)
            receipt = root / "receipt.json"
            receipt.write_text("{}")
            commit = "a" * 40
            validated = SimpleNamespace(
                schema="v2",
                payload={"receipt_schema": main.receipts.RECEIPT_SCHEMA_V2},
                artifacts=({"kind": "bin", "target": "rootyard"},),
                binary_sha256=support.sha256_file(binary),
                workspace_commit=commit, receipt_sha256="b" * 64)
            args = main.parse_args([
                "--binary", str(binary), "--receipt", str(receipt),
                "--source-root", str(root), "--expected-commit", commit,
                "--report", str(root / "report.json")])
            with mock.patch.object(main, "_source_state", return_value={
                    "commit": commit, "tree": "c" * 40, "clean": True}), \
                 mock.patch.object(main.receipts, "load_receipt",
                                   return_value=validated), \
                 mock.patch.object(main, "_harness_sha256", return_value="d" * 64), \
                 mock.patch.object(main.shutil, "which",
                                   return_value="/usr/bin/tool"):
                with self.assertRaises(support.QualificationError) as caught:
                    main.validate_inputs(args, {
                        "ROOTYARD_TEST_DATABASE_URL": "postgresql://u:p@127.0.0.1/db"})
            self.assertEqual(caught.exception.code, "receipt_pando_artifact_missing")

    def test_binding_detects_binary_and_source_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "binary"
            binary.write_bytes(b"one")
            receipt = root / "receipt"
            receipt.write_bytes(b"receipt")
            inputs = {
                "source_root": root, "source_commit": "a" * 40,
                "source_tree": "b" * 40, "binary": binary, "receipt": receipt,
                "binary_sha256": support.sha256_file(binary),
                "receipt_sha256": support.sha256_file(receipt),
                "harness_sha256": "c" * 64,
            }
            state = {"commit": "a" * 40, "tree": "b" * 40, "clean": True}
            with mock.patch.object(main.receipts, "git_state", return_value=state), \
                 mock.patch.object(main, "_harness_sha256", return_value="c" * 64):
                self.assertTrue(main.binding_snapshot(inputs))
                binary.write_bytes(b"two")
                with self.assertRaises(support.QualificationError) as caught:
                    main.binding_snapshot(inputs)
                self.assertEqual(caught.exception.code, "binary_binding_changed")

    def test_expected_failure_runner_returns_status_without_raising(self):
        context = main.Context.__new__(main.Context)
        context.binary = "/fake/rootyard-pando-lab"
        context.environment = {}
        context.runner = RunnerFake([completed(returncode=1),
                                     completed(returncode=1)])
        result = context.run_status(["kms-verify", "repo"], stage="negative")
        self.assertEqual(result.returncode, 1)
        with self.assertRaises(support.QualificationError):
            context.run_cli(["kms-verify", "repo"], stage="negative")

    def test_child_environment_removes_inherited_remote_and_bootstrap(self):
        postgres = SimpleNamespace(
            child_environment=lambda: {"PANDO_DATABASE_URL": "postgresql://child"})
        vault_env = {
            "PANDO_KMS_VAULT_URL": "http://127.0.0.1:1",
            "PANDO_KMS_VAULT_TOKEN": "app-token",
            "PANDO_KMS_VAULT_MOUNT": "transit",
            "PANDO_KMS_VAULT_KEY": "key",
        }
        base = {
            "PATH": "/usr/bin", "ROOTYARD_OBJECT_STORE_ENDPOINT": "http://remote",
            "PANDO_KMS_KEYRING_DIR": "/tmp/kms", "DATABASE_URL": "postgresql://wrong",
            "ROOTYARD_TEST_DATABASE_URL": "postgresql://bootstrap",
            "ROOTYARD_KMS_VAULT_URL": "http://wrong",
        }
        env = support.child_environment(
            base, postgres, "/tmp/pando-root", vault_env, "/usr/bin/git")
        self.assertNotIn("ROOTYARD_OBJECT_STORE_ENDPOINT", env)
        self.assertNotIn("PANDO_KMS_KEYRING_DIR", env)
        self.assertNotIn("DATABASE_URL", env)
        self.assertNotIn("ROOTYARD_TEST_DATABASE_URL", env)
        self.assertNotIn("ROOTYARD_KMS_VAULT_URL", env)
        self.assertEqual(env["PANDO_KMS_VAULT_TOKEN"], "app-token")
        self.assertEqual(env["PANDO_KMS_PROVIDER"], "vault-transit")
        self.assertEqual(env["PANDO_DATABASE_URL"], "postgresql://child")
        self.assertEqual(env["PANDO_GIT"], "/usr/bin/git")
        self.assertEqual(env["PANDO_SYNTHETIC_ONLY"], "1")


class CacheManifestAndSqlTest(unittest.TestCase):
    def test_cache_eviction_is_exact_owned_repo_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, pack = "a" * 36, "b" * 36
            repo = "11111111-1111-4111-8111-111111111111"
            pack = "22222222-2222-4222-8222-222222222222"
            owned = root / "objects" / repo
            owned.mkdir(parents=True)
            for suffix in (".pack", ".idx"):
                (owned / (pack + suffix)).write_bytes(b"cipher-cache")
            foreign = root / "objects" / "33333333-3333-4333-8333-333333333333"
            foreign.mkdir()
            (foreign / (pack + ".pack")).write_bytes(b"foreign")
            result = support.evict_plaintext_cache(root, repo, [pack])
            self.assertEqual(result["cache_files_removed"], 2)
            self.assertTrue(result["plaintext_cache_absent"])
            self.assertTrue((foreign / (pack + ".pack")).is_file())
            with self.assertRaises(support.QualificationError):
                support.evict_plaintext_cache(root, "../escape", [pack])

    def test_local_authority_detection_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = "11111111-1111-4111-8111-111111111111"
            directory = root / "kms" / repo
            directory.mkdir(parents=True)
            (directory / "rotation_state.json").write_text("{}")
            self.assertTrue(support.local_authority_absent(root, repo))
            (directory / "kms_policy.json").write_text("{}")
            self.assertFalse(support.local_authority_absent(root, repo))

    def test_manifest_and_cipher_paths_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = "11111111-1111-4111-8111-111111111111"
            pack = "22222222-2222-4222-8222-222222222222"
            cipher = b"PANDOENC" + b"cipher"
            key = "buckets/b/repos/%s/packs/%s.pack" % (repo, pack)
            path = root / key
            path.parent.mkdir(parents=True)
            path.write_bytes(cipher)
            manifest = {
                "repo": repo, "pack_id": pack, "pack_key": key,
                "idx_key": "buckets/b/repos/%s/packs/%s.idx" % (repo, pack),
                "pack_sha256": "a" * 64, "idx_sha256": "b" * 64,
                "pack_bytes": 14, "idx_bytes": 1, "object_count": 1,
                "encryption_mode": "authenticated-envelope-v1",
                "ciphertext_sha256": support.sha256_bytes(cipher),
                "ciphertext_bytes": len(cipher),
                "cipher_suite": "AES-256-GCM-HMAC-SHA256",
            }
            directory = root / "manifests" / repo
            directory.mkdir(parents=True)
            (directory / (pack + ".json")).write_text(json.dumps(manifest))
            loaded = support.read_manifest(root, repo, pack)
            self.assertEqual(support.read_cipher(root, loaded), cipher)
            manifest["pack_key"] = "../escape"
            (directory / (pack + ".json")).write_text(json.dumps(manifest))
            with self.assertRaises(support.QualificationError) as caught:
                support.read_manifest(root, repo, pack)
            self.assertEqual(caught.exception.code, "manifest_path_escape")

    def test_psql_receives_sql_on_stdin_not_in_argv(self):
        runner = RunnerFake([completed(stdout=b"[]")])
        postgres = SimpleNamespace(
            database="pando_rotation_aaaaaaaaaaaa",
            environment={"PGHOST": "127.0.0.1", "PGPASSWORD": "secret"})
        database = Psql(postgres, runner=runner)
        repo = "11111111-1111-4111-8111-111111111111"
        self.assertEqual(database.manifests(repo), [])
        argv, kwargs = runner.calls[0]
        self.assertNotIn("secret", " ".join(argv))
        self.assertNotIn("postgresql://", " ".join(argv))
        self.assertIn(repo, kwargs["input"].decode())
        self.assertEqual(kwargs["env"]["PGDATABASE"], postgres.database)

    def test_git_push_argv_contains_no_token(self):
        runner = RunnerFake([completed()])
        with mock.patch("pando_vault_rotation_service.shutil.which",
                        return_value="/usr/bin/git"):
            workspace = GitWorkspace({"PATH": "/usr/bin"}, runner=runner)
        with tempfile.TemporaryDirectory() as temporary:
            workspace.push(temporary, "http://127.0.0.1:1/repos/x.git")
        argv, kwargs = runner.calls[0]
        text = " ".join(argv)
        self.assertIn("X-Pando-Principal: alice", text)
        self.assertNotIn("PANDO_KMS", text)
        self.assertEqual(kwargs["cwd"], temporary)


class CleanupAndFinallyTest(unittest.TestCase):
    def _cleanup_ctx(self, failing):
        class Server:
            def stop(self):
                if failing:
                    raise support.QualificationError("server_stop_timeout", "cleanup")
                return True

        class Fixture:
            container_id = "a" * 64
            state_written = True
            state_path = Path("/tmp/does-not-exist-state.json")
            version = "2.2.2"

            def stop(self):
                if failing:
                    raise support.FixtureError("vault_cleanup_failed")
                return "stopped"

        class Postgres:
            prechecked_absent = True
            created = True
            dropped = False
            major = 17

            def drop(self):
                if failing:
                    raise support.FixtureError("pg_command_failed")
                self.dropped = True
                return True

        class Root:
            created = True
            path = Path("/tmp/does-not-exist-root")

            def remove(self):
                if failing:
                    raise support.FixtureError("root_remove_unverified")
                self.removed = True
                return True

        return SimpleNamespace(
            server=Server(), fixture=Fixture(), postgres=Postgres(), root=Root(),
            repo="11111111-1111-4111-8111-111111111111")

    def test_cleanup_failure_is_not_success(self):
        result = negative.case_owned_resource_cleanup(self._cleanup_ctx(True))
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["facts"]["cleanup_ok"])
        self.assertTrue(result["facts"]["no_global_cleanup"])

    def test_cleanup_success_records_exact_booleans(self):
        result = negative.case_owned_resource_cleanup(self._cleanup_ctx(False))
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["facts"]["cleanup_ok"])
        self.assertTrue(result["facts"]["vault_stopped"])
        self.assertTrue(result["facts"]["postgres_dropped"])

    def test_setup_failure_still_runs_cleanup_in_finally(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            args = main.parse_args(["--report", str(report_path)])
            inputs = {"report": report_path, "binary": Path("x"),
                      "receipt": Path("y"), "source_root": Path("z")}
            cleanup = {
                "id": support.CASES[4], "status": "passed",
                "facts": {"cleanup_ok": True}}
            context = SimpleNamespace()

            def fail_start():
                raise support.QualificationError("fixture_setup_failed", "setup")

            context.start_base = fail_start
            with mock.patch.object(main, "validate_inputs", return_value=inputs), \
                 mock.patch.object(main, "binding_snapshot",
                                   return_value={"source_commit": "a" * 40}), \
                 mock.patch.object(main, "Context", return_value=context), \
                 mock.patch.object(main.negative, "case_owned_resource_cleanup",
                                   return_value=cleanup):
                report = main.run_qualification(args, environ={})
            self.assertFalse(report["passed"])
            self.assertEqual(len(report["cases"]), 5)
            self.assertEqual(report["cases"][4]["status"], "passed")
            self.assertTrue(all(case["status"] == "failed"
                                for case in report["cases"][:4]))
            self.assertTrue(report_path.is_file())


if __name__ == "__main__":
    unittest.main()
