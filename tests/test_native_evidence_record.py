"""Boundary regressions for the public ``native_evidence.record`` hook.

The real e2e HTTP response path and the startup ``native_evidence.started``
path must stay harmless when optional evidence output is unset, and append one
structured JSON row per call when it is configured.  Responses and the service
process are mocked here, so these tests need neither a native binary nor a
database.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import e2e  # noqa: E402
import native_evidence  # noqa: E402


class _FakeResponse:
    def __init__(self, status=200, body=b"ok"):
        self.status = status
        self._body = body
        self.headers = {"X-Test-Response": "yes"}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _FakeProcess:
    pid = 999999999

    def poll(self):
        return None


class NativeEvidenceRecordBoundaryTest(unittest.TestCase):
    schema = "rootyard_e2e_record_boundary"

    def _http_harness(self):
        harness = e2e.Harness.__new__(e2e.Harness)
        harness.base = "http://127.0.0.1:9"
        harness.schema = self.schema
        return harness

    def _startup_harness(self, root, binary):
        harness = e2e.Harness.__new__(e2e.Harness)
        harness.root = Path(root)
        harness.base = "http://127.0.0.1:9"
        harness.schema = self.schema
        harness.args = SimpleNamespace(binary=str(binary))
        harness.env = {}
        harness.proc = None
        harness.sql = mock.Mock(return_value="PostgreSQL 16.4 boundary")
        harness.run = mock.Mock(return_value=SimpleNamespace(stdout=b"git version 2.50.0\n"))
        return harness

    def _rows(self, evidence):
        path = Path(evidence) / (self.schema + ".jsonl")
        self.assertTrue(path.is_file(), "configured evidence file was not appended")
        return [json.loads(line) for line in path.read_text().splitlines()]

    def test_http_response_path_is_harmless_when_evidence_is_unset(self):
        harness = self._http_harness()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ROOTYARD_TEST_EVIDENCE_DIR", None)
            with mock.patch("urllib.request.urlopen", return_value=_FakeResponse(201, b"created")):
                status, body, headers = harness.http(
                    "/api/things?token=secret", method="POST", body={"name": "x"}
                )
            failure = urllib.error.HTTPError(
                harness.base + "/api/failure?token=secret", 409, "Conflict",
                {"X-Test-Response": "error"}, io.BytesIO(b"denied"),
            )
            with mock.patch("urllib.request.urlopen", side_effect=failure):
                error_status, error_body, error_headers = harness.http("/api/failure?token=secret")

        self.assertEqual((status, body, headers["X-Test-Response"]), (201, b"created", "yes"))
        self.assertEqual((error_status, error_body, error_headers["X-Test-Response"]),
                         (409, b"denied", "error"))

    def test_http_response_path_records_structured_rows_when_configured(self):
        harness = self._http_harness()
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            with mock.patch.dict(os.environ, {"ROOTYARD_TEST_EVIDENCE_DIR": str(evidence)}):
                with mock.patch("urllib.request.urlopen", return_value=_FakeResponse(201, b"created")):
                    harness.http("/api/things?token=secret", method="POST", body={"name": "x"})
                failure = urllib.error.HTTPError(
                    harness.base + "/api/failure?token=secret", 409, "Conflict",
                    {"X-Test-Response": "error"}, io.BytesIO(b"denied"),
                )
                with mock.patch("urllib.request.urlopen", side_effect=failure):
                    harness.http("/api/failure?token=secret")

            rows = self._rows(evidence)
            raw = (evidence / (self.schema + ".jsonl")).read_text()

        self.assertEqual(len(rows), 2)
        self.assertNotIn("secret", raw)
        self.assertEqual(
            {key: value for key, value in rows[0].items() if key != "monotonic_ns"},
            {"event": "http_response", "method": "POST", "path": "/api/things",
             "response_bytes": 7, "status": 201},
        )
        self.assertIsInstance(rows[0]["monotonic_ns"], int)
        self.assertEqual(
            {key: value for key, value in rows[1].items() if key != "monotonic_ns"},
            {"event": "http_response", "method": "GET", "path": "/api/failure",
             "response_bytes": 6, "status": 409},
        )
        self.assertIsInstance(rows[1]["monotonic_ns"], int)

    def test_startup_started_path_is_harmless_when_evidence_is_unset(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "rootyard"
            binary.write_bytes(b"native-binary")
            harness = self._startup_harness(directory, binary)
            with mock.patch.dict(os.environ, {}, clear=False), \
                    mock.patch("e2e.subprocess.Popen", return_value=_FakeProcess()), \
                    mock.patch("urllib.request.urlopen", return_value=_FakeResponse(200, b"ready")):
                os.environ.pop("ROOTYARD_TEST_EVIDENCE_DIR", None)
                harness.start()
            harness.log.close()

        self.assertEqual(harness.sql.call_args.args, ("SELECT version()",))
        self.assertEqual(harness.run.call_args.args, (["git", "--version"],))

    def test_startup_started_path_records_structured_row_when_configured(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "rootyard"
            binary.write_bytes(b"native-binary")
            evidence = root / "evidence"
            harness = self._startup_harness(root, binary)
            with mock.patch.dict(os.environ, {"ROOTYARD_TEST_EVIDENCE_DIR": str(evidence)}), \
                    mock.patch("e2e.subprocess.Popen", return_value=_FakeProcess()), \
                    mock.patch("urllib.request.urlopen", return_value=_FakeResponse(200, b"ready")):
                harness.start()
            harness.log.close()

            rows = self._rows(evidence)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["event"], "http_response")
        self.assertEqual((rows[0]["path"], rows[0]["status"], rows[0]["response_bytes"]),
                         ("/health/ready", 200, 5))
        started = rows[1]
        self.assertIsInstance(started["monotonic_ns"], int)
        self.assertEqual(
            {key: value for key, value in started.items() if key != "monotonic_ns"},
            {
                "event": "native_service_started",
                "binary": str(binary.resolve()),
                "binary_sha256": hashlib.sha256(b"native-binary").hexdigest(),
                "pid": _FakeProcess.pid,
                "process_executable": None,
                "schema": self.schema,
                "build": {
                    "attested": False,
                    "reason": "no build receipt; source revision is not inferred",
                },
                "postgres_version": "PostgreSQL 16.4 boundary",
                "git_version": "git version 2.50.0",
            },
        )
        self.assertEqual(harness.sql.call_args.args, ("SELECT version()",))
        self.assertEqual(harness.run.call_args.args, (["git", "--version"],))


if __name__ == "__main__":
    unittest.main()
