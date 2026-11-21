"""Pure contract tests for the exact named-unittest acceptance runner.

These cases do not start the service, PostgreSQL or Garage. They prove the
runner refuses a skipped selection, accepts exactly one passing case, records
only source/build/binary/test anchors, and never copies unittest output into the
receipt.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run_named_unittest.py"
SKIP_CASE = "tests.test_workspace_remote.WorkspaceRemoteTest.test_commit_retry_and_restore_without_source_volume"
PASS_CASE = ("tests.test_workspace_remote_namespace.WorkspaceRemoteNamespaceContractTests."
             "test_remote_and_namespace_types_and_docs_are_present")
CLASS_CASE = "tests.test_workspace_remote.WorkspaceRemoteTest"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class NamedUnittestRunnerContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="named-unittest-runner-"))
        self.binary = self.temp / "rootyard"
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)
        self.receipt = self.temp / "rootyard.build.json"
        self.receipt.write_text("{}\n", encoding="utf-8")
        self.report = self.temp / "report.json"
        self.commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        self.tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True
        ).strip()

    def tearDown(self):
        shutil.rmtree(self.temp)

    def invoke(self, case):
        environment = os.environ.copy()
        for name in (
            "ROOTYARD_OBJECT_STORE_ENDPOINT", "ROOTYARD_OBJECT_STORE_BUCKET",
            "ROOTYARD_OBJECT_STORE_REGION", "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY", "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
            "ROOTYARD_TEST_DATABASE_URL",
        ):
            environment.pop(name, None)
        process = subprocess.run(
            [sys.executable, str(RUNNER), "--test", case, "--binary", str(self.binary),
             "--build-receipt", str(self.receipt), "--expect-commit", self.commit,
             "--report", str(self.report)],
            cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=60, check=False,
        )
        data = json.loads(self.report.read_text(encoding="utf-8"))
        return process, data, self.report.read_text(encoding="utf-8")

    def test_skip_cannot_be_accepted_as_a_pass(self):
        process, data, raw = self.invoke(SKIP_CASE)
        self.assertNotEqual(process.returncode, 0)
        self.assertIs(data["passed"], False)
        self.assertEqual(data["outcome"], "skipped")
        self.assertEqual(data["cases"], [{"name": SKIP_CASE, "status": "skipped"}])
        self.assertEqual(data["counts"]["skipped"], 1)
        self.assertNotIn("Traceback", raw)
        self.assertNotIn(str(self.temp), raw)

    def test_exact_pass_records_only_closed_anchors(self):
        process, data, raw = self.invoke(PASS_CASE)
        self.assertEqual(process.returncode, 0)
        self.assertIs(data["passed"], True)
        self.assertEqual(data["outcome"], "passed")
        self.assertEqual(data["cases"], [{"name": PASS_CASE, "status": "passed"}])
        self.assertEqual(data["source_head"], self.commit)
        self.assertEqual(data["source_tree"], self.tree)
        self.assertEqual(data["binary_sha256"], digest(self.binary))
        self.assertEqual(data["build_receipt_sha256"], digest(self.receipt))
        self.assertEqual(data["counts"]["skipped"], 0)
        self.assertEqual(set(data), {
            "schema", "passed", "outcome", "test_id", "cases", "counts",
            "source_head", "source_tree", "binary_sha256",
            "build_receipt_sha256", "limitations",
        })
        self.assertNotIn(str(self.temp), raw)

    def test_more_than_one_selected_case_is_rejected_before_execution(self):
        process, data, _ = self.invoke(CLASS_CASE)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(data["outcome"], "selection_not_exact")
        self.assertEqual(data["counts"]["tests_run"], 0)


if __name__ == "__main__":
    unittest.main()
