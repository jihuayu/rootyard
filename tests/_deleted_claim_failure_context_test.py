#!/usr/bin/env python3
"""Hermetic contract tests for the deleted-claim failure context.

These tests use no service, database, network, subprocess, or provider. They
exercise the real fixture orchestration with injected API/Git operations so a
regression in branch-rule ordering or phase propagation is visible without
building a second copy of the fixture.
"""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import repository_lifecycle_deleted_claim_acceptance as acceptance  # noqa: E402


def _new_harness():
    harness = object.__new__(acceptance.DeletedClaimAcceptanceHarness)
    harness.results = []
    harness.secrets = []
    harness.diagnostics = acceptance.PhaseDiagnostics()
    return harness


class LeakyFailure(Exception):
    def __str__(self):
        return "TOKEN=ryj_plain_secret response-body=/private/path"

    __repr__ = __str__


class DeletedClaimFailureContextTests(unittest.TestCase):
    def test_phase_names_and_candidate_ordinals_are_fixed(self):
        harness = _new_harness()
        with harness.phase("protect_main", 2):
            self.assertEqual(harness.diagnostics.stage, "protect_main")
            self.assertEqual(harness.diagnostics.ordinal, 2)
        for bad_name in ("invented_stage", "protect_main_extra", ""):
            with self.assertRaises(ValueError):
                harness.phase(bad_name)
        for bad_ordinal in (-1, 3, 4):
            with self.assertRaises(ValueError):
                harness.phase("seed_head_push", bad_ordinal)

    def test_case_failure_serializes_no_exception_text(self):
        harness = _new_harness()

        def fail():
            with harness.phase("protect_main", 2):
                raise LeakyFailure()

        with self.assertRaises(acceptance._SafeFailure):
            harness.case("live_control_secret_claim_and_expired_reclaim", fail)

        self.assertEqual(len(harness.results), 1)
        entry = harness.results[0]
        serialized = json.dumps(harness.results)
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["failed_stage"], "protect_main")
        self.assertEqual(entry["failed_ordinal"], 2)
        self.assertEqual(entry["failure_class_name"], "unexpected_exception")
        self.assertIsNone(entry["http_status"])
        self.assertIsNone(entry["child_return_code"])
        self.assertNotIn("error", entry)
        for forbidden in ("TOKEN", "ryj_plain_secret", "response-body", "/private/path", "LeakyFailure"):
            self.assertNotIn(forbidden, serialized)

    def test_typed_http_and_child_metadata_only_when_observed(self):
        harness = _new_harness()

        def http_fail():
            with harness.phase("webhook_create"):
                harness.diagnostics.begin_http()
                harness.diagnostics.observe_http(409)
                harness.diagnostics.mark_http_mismatch()
                raise AssertionError()

        with self.assertRaises(acceptance._SafeFailure):
            harness.case("live_control_secret_claim_and_expired_reclaim", http_fail)
        entry = harness.results[0]
        self.assertEqual(entry["failure_class_name"], "http_status")
        self.assertEqual(entry["http_status"], 409)
        self.assertIsNone(entry["child_return_code"])

        harness = _new_harness()

        def child_fail():
            with harness.phase("seed_clone"):
                harness.diagnostics.observe_child(128)
                raise AssertionError()

        with self.assertRaises(acceptance._SafeFailure):
            harness.case("live_control_secret_claim_and_expired_reclaim", child_fail)
        entry = harness.results[0]
        self.assertEqual(entry["failure_class_name"], "subprocess_nonzero")
        self.assertEqual(entry["child_return_code"], 128)
        self.assertIsNone(entry["http_status"])

        harness = _new_harness()

        def plain_fail():
            with harness.phase("repository_create"):
                raise AssertionError()

        with self.assertRaises(acceptance._SafeFailure):
            harness.case("live_control_secret_claim_and_expired_reclaim", plain_fail)
        entry = harness.results[0]
        self.assertEqual(entry["failure_class_name"], "assertion")
        self.assertIsNone(entry["http_status"])
        self.assertIsNone(entry["child_return_code"])

    def test_cleanup_failure_does_not_replace_primary_failure(self):
        diagnostics = acceptance.PhaseDiagnostics()
        try:
            with diagnostics.phase("claim_control"):
                raise AssertionError("primary text must never escape")
        except AssertionError as error:
            diagnostics.record_failure(error)
        diagnostics.record_cleanup_failure(OSError("cleanup text must never escape"))

        fields = diagnostics.report_fields()
        self.assertEqual(fields["failed_stage"], "claim_control")
        self.assertEqual(fields["failure_class_name"], "assertion")
        self.assertTrue(fields["cleanup_failed"])
        self.assertEqual(fields["cleanup_failure_class_name"], "transport")
        serialized = json.dumps(fields)
        self.assertNotIn("primary text", serialized)
        self.assertNotIn("cleanup text", serialized)
        allowed = {
            "schema",
            "case",
            "failed_stage",
            "failed_ordinal",
            "failure_class",
            "failure_class_name",
            "http_status",
            "child_return_code",
            "cleanup_failed",
            "cleanup_failure_count",
            "cleanup_failure_class",
            "cleanup_failure_class_name",
        }
        self.assertEqual(set(fields), allowed)

    def test_real_fixture_orders_rule_after_seed_push_before_candidates(self):
        harness = _new_harness()
        harness.fixture = None
        harness.schema_created = True
        harness.REPO_NAME = "deleted-claim"
        harness.CONTEXT = "ci/test"
        harness.HOOK_SECRET = "synthetic-secret"
        harness.alice = {"username": "alice", "token": "token"}
        harness.base = "http://127.0.0.1:1"
        harness.root = Path(tempfile.mkdtemp(prefix="deleted-claim-pure-"))
        self.addCleanup(shutil.rmtree, harness.root, True)
        harness.receiver = types.SimpleNamespace(url="http://127.0.0.1:2/hook")

        events = []
        state = {"oid": 0, "last_oid": None, "pull": 0}

        def record(kind, detail):
            events.append(
                {
                    "stage": harness.diagnostics.stage,
                    "ordinal": harness.diagnostics.ordinal,
                    "kind": kind,
                    "detail": detail,
                }
            )

        def fake_create_repository(payload, token=None):
            record("repository", payload)
            return {
                "id": "repo-id",
                "owner": "alice",
                "name": "deleted-claim",
                "state": "ready",
            }

        def fake_git(*args, cwd=None, token=None, check=True, env=None):
            record("git", args)
            if args[0] == "clone":
                Path(args[2]).mkdir(parents=True, exist_ok=True)
            if args[0] == "rev-parse":
                state["oid"] += 1
                oid = f"{state['oid']:040x}"
                state["last_oid"] = oid
                return types.SimpleNamespace(stdout=oid.encode(), returncode=0)
            return types.SimpleNamespace(stdout=b"", returncode=0)

        def fake_doc(path, code, token=None, **kwargs):
            record("doc", (path, kwargs.get("body")))
            if path.endswith("/webhooks"):
                return {"id": "hook-id"}
            if path.endswith("/trusted-contexts"):
                return None
            if path.endswith("/branch-rules"):
                return None
            if path.endswith("/pulls"):
                state["pull"] += 1
                return {"number": state["pull"], "head_oid": state["last_oid"]}
            raise AssertionError("unexpected injected API path")

        def fake_wait_run(pull_number, head_oid, deadline=20.0):
            record("wait_run", (pull_number, head_oid))
            return {
                "id": f"run-{pull_number}",
                "job_id": f"job-{pull_number}",
                "head_oid": head_oid,
            }

        def fake_wait_pin(job_id, deadline=20.0):
            record("wait_pin", job_id)
            return True

        harness.create_repository = fake_create_repository
        harness.git = fake_git
        harness.doc = fake_doc
        harness._wait_run = fake_wait_run
        harness._wait_pin = fake_wait_pin

        fixture = harness._create_fixture()
        self.assertEqual(fixture["control_run"]["id"], "run-1")
        self.assertEqual(fixture["deleted_run"]["id"], "run-2")
        self.assertEqual(fixture["race_run"]["id"], "run-3")

        high_level = [stage for stage, _ in harness.diagnostics.phase_trace]
        self.assertEqual(
            high_level[:7],
            [
                "repository_create",
                "webhook_create",
                "trust_context_create",
                "seed_clone",
                "seed_commit",
                "seed_main_push",
                "protect_main",
            ],
        )

        main_push_at = next(
            index
            for index, event in enumerate(events)
            if event["stage"] == "seed_main_push"
            and event["detail"][0] == "push"
            and event["detail"][2] == "HEAD:refs/heads/main"
        )
        protect_at = next(
            index
            for index, event in enumerate(events)
            if event["stage"] == "protect_main"
            and event["detail"][0].endswith("/branch-rules")
        )
        first_pull_at = next(
            index
            for index, event in enumerate(events)
            if event["stage"] == "create_pull" and event["ordinal"] == 0
        )
        self.assertLess(main_push_at, protect_at)
        self.assertLess(protect_at, first_pull_at)

        rule_body = events[protect_at]["detail"][1]
        self.assertEqual(
            rule_body,
            {
                "branch_ref": "refs/heads/main",
                "required_approvals": 0,
                "required_checks": ["ci/test"],
            },
        )
        self.assertEqual(
            sum(1 for event in events if event["stage"] == "protect_main"),
            1,
        )

        candidate_pushes = [
            event
            for event in events
            if event["stage"] == "seed_head_push"
            and event["detail"][0] == "push"
            and "refs/heads/feature-" in event["detail"][2]
        ]
        self.assertEqual([event["ordinal"] for event in candidate_pushes], [0, 1, 2])
        self.assertTrue(all(events.index(event) > protect_at for event in candidate_pushes))
        self.assertEqual(
            [event["ordinal"] for event in events if event["stage"] == "create_pull"],
            [0, 1, 2],
        )
        self.assertEqual(
            sorted(
                {
                    event["ordinal"]
                    for event in events
                    if event["stage"] == "await_run_pin"
                }
            ),
            [0, 1, 2],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
