#!/usr/bin/env python3
"""Focused static/unit tests for Browse failure diagnostics and its manual fence.

No native binary, PostgreSQL or Cargo is required.  These tests protect the
CI-debuggability contract without retrying or weakening any HTTP assertion.
"""
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browse  # noqa: E402
from browse import BrowseHarness, MANUAL_RECOVERY_REASON  # noqa: E402

REPO_ID = "11111111-1111-1111-1111-111111111111"
SCHEMA = "rootyard_e2e_fixture"


def bare_harness(root, sql=None):
    """Harness with only diagnostics state, avoiding DB/psql/native setup."""
    harness = object.__new__(BrowseHarness)
    harness.root = Path(root)
    harness.schema = SCHEMA
    harness.base_db = "postgresql://fixture:fixture@127.0.0.1:1/rootyard_test"
    harness.db = harness.base_db + "?options=-csearch_path%3Dfixture"
    harness.secrets = []
    harness.actor_labels = {}
    harness.repo = {"id": REPO_ID}
    if sql is not None:
        harness.sql = sql
    return harness


class FailureDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.raw = "browse-owner-token-value"
        self.basic = base64.b64encode(
            ("alice:" + self.raw).encode()
        ).decode()

    def tearDown(self):
        self.temp.cleanup()

    def fixture_sql(self):
        return lambda query: json.dumps(
            {
                "schema": SCHEMA,
                "repository_id": REPO_ID,
                "owner_id": "22222222-2222-2222-2222-222222222222",
                "owner": "alice",
                "name": "demo",
                "state": "recovering",
                "recovery_reason": MANUAL_RECOVERY_REASON,
                "storage_generation": 1,
                "storage_backend": "gitfs",
                "row_effective_identity": {
                    "id": REPO_ID,
                    "owner_id": "22222222-2222-2222-2222-222222222222",
                    "owner": "alice",
                    "name": "demo",
                },
            }
        )

    def test_unexpected_http_diagnostics_are_useful_and_secret_free(self):
        harness = bare_harness(self.root, self.fixture_sql())
        token = {
            "username": "alice",
            "token": self.raw,
            "token_id": "33333333-3333-3333-3333-333333333333",
        }
        harness.register_token(token)
        harness.actor_labels[token["token_id"]] = "owner"
        (self.root / "server.log").write_text(
            "server started\n"
            + "request Authorization: Basic " + self.basic + "\n"
            + "raw fixture token " + self.raw + "\n"
        )
        text = harness.http_failure_detail(
            "/api/repos/alice/demo/refs",
            (200,),
            404,
            json.dumps({"error": "not found " + self.raw}).encode(),
            {"Content-Type": "application/json"},
            token,
        )
        self.assertIn("expected (200,), got 404", text)
        self.assertNotIn(self.raw, text)
        self.assertNotIn(self.basic, text)
        self.assertNotIn(token["token_id"], text)

        detail = json.loads(text.split("\n", 1)[1])
        self.assertEqual(detail["actor"], "owner")
        self.assertEqual(detail["schema"], SCHEMA)
        self.assertEqual(detail["repository_id"], REPO_ID)
        self.assertEqual(detail["current_state"], "recovering")
        self.assertEqual(detail["recovery_reason"], MANUAL_RECOVERY_REASON)
        self.assertEqual(detail["row_effective_identity"]["name"], "demo")
        self.assertIn("server started", detail["server_log_tail"])
        self.assertNotIn(self.raw, detail["response_body"])

    def test_query_failure_reports_only_exception_type(self):
        def exploding_sql(_query):
            raise RuntimeError("psql failed with " + self.raw)

        harness = bare_harness(self.root, exploding_sql)
        text = harness.http_failure_detail(
            "/api/repos/alice/demo/refs",
            200,
            404,
            b'{"error":"missing"}',
            {"content-type": "application/json"},
            {"token_id": "unknown"},
        )
        detail = json.loads(text.split("\n", 1)[1])
        self.assertEqual(detail["current_state"], "query_failed")
        self.assertEqual(detail["diagnostic_error"], "RuntimeError")
        self.assertNotIn(self.raw, text)

    def test_manual_fence_is_not_reconciler_owned_and_always_restored(self):
        calls = []
        harness = bare_harness(self.root, sql=lambda query: calls.append(query))
        with harness.recovery_fence():
            self.assertEqual(len(calls), 1)
            self.assertIn("state='recovering'", calls[0])
            self.assertIn(MANUAL_RECOVERY_REASON, calls[0])
            self.assertNotIn("push_outcome_unknown", calls[0])
        self.assertEqual(len(calls), 2)
        self.assertIn("state='ready'", calls[1])
        self.assertIn("recovery_reason=NULL", calls[1])

        calls.clear()
        with self.assertRaisesRegex(RuntimeError, "fixture body failed"):
            with harness.recovery_fence():
                raise RuntimeError("fixture body failed")
        self.assertEqual(len(calls), 2)
        self.assertIn("state='ready'", calls[1])
        self.assertIn("recovery_reason=NULL", calls[1])

    def test_fixture_uses_the_manual_fence(self):
        source = Path(browse.__file__).read_text()
        start = source.index("with self.recovery_fence():")
        end = source.index("def object_format_and_negotiation", start)
        self.assertNotIn("push_outcome_unknown", source[start:end])


if __name__ == "__main__":
    unittest.main()
