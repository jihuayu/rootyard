"""Focused regression tests for the real PullsHarness.advance_check CAS helper.

The harness is exercised directly with deterministic scripted HTTP responses;
the server state machine is not reimplemented here.
"""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pulls  # noqa: E402

HEADERS = {"cache-control": "no-store", "content-type": "application/json"}

COMMIT = "c0ffee1234567890c0ffee1234567890c0ffee12"
CONTEXT = "ci/test"
OUTPUT = "scripted failure: build step exited 1"
FAILURE_CONCLUSION = "failure"

PATH = f"/api/repos/alice/forge/commits/{COMMIT}/checks"


def _row(
    status,
    conclusion,
    output,
    attempt=1,
    sequence=1,
    context=CONTEXT,
    commit_oid=COMMIT,
):
    return {
        "commit_oid": commit_oid,
        "context": context,
        "attempt": attempt,
        "sequence": sequence,
        "status": status,
        "conclusion": conclusion,
        "output": output,
    }


def _listing(*rows, commit_oid=COMMIT):
    return {"commit_oid": commit_oid, "items": list(rows)}


class ScriptedHttp:
    """Deterministic HTTP closure recording every GET and POST body."""

    def __init__(self, gets, posts):
        self._gets = list(gets)
        self._posts = list(posts)
        self.gets = []
        self.posts = []

    def __call__(self, path, *, token=None, method="GET", body=None):
        if method == "GET":
            if not self._gets:
                raise AssertionError(f"unexpected extra GET {path}")
            self.gets.append({"path": path, "token": token})
            status, payload = self._gets.pop(0)
        else:
            if not self._posts:
                raise AssertionError(f"unexpected extra POST {path}: {body}")
            self.posts.append({"path": path, "token": token, "body": dict(body)})
            status, payload = self._posts.pop(0)
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return status, raw, dict(HEADERS)

    def post_sequences(self):
        return [entry["body"]["sequence"] for entry in self.posts]

    def assert_drained(self, testcase):
        testcase.assertEqual(self._gets, [], "scripted GETs were not all consumed")
        testcase.assertEqual(self._posts, [], "scripted POSTs were not all consumed")


def _harness(script):
    harness = object.__new__(pulls.PullsHarness)
    harness.alice = {"username": "alice", "token": "alice-token"}
    harness.reader = {"username": "reader", "token": "reader-token"}
    harness.http = script
    return harness


def _sleep_patcher():
    return mock.patch.object(pulls.time, "sleep", lambda _seconds: None)


def _conflict(kind="conflicting"):
    if kind == "stale":
        return 409, {"error": "stale check run attempt or sequence"}
    return 409, {"error": "conflicting check run state for same attempt and sequence"}


def _requested_run(sequence):
    return _row("completed", FAILURE_CONCLUSION, OUTPUT, attempt=1, sequence=sequence)


class AdvanceCheckTests(unittest.TestCase):
    def assert_failure_result(self, result):
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["conclusion"], FAILURE_CONCLUSION)
        self.assertEqual(result["output"], OUTPUT)
        self.assertEqual(result["context"], CONTEXT)
        self.assertEqual(result["commit_oid"], COMMIT)
        self.assertEqual(result["attempt"], 1)

    def test_race_retries_and_returns_requested_failure_not_preexisting_success(self):
        first_listing = _listing(
            _row("completed", "success", "all passed", attempt=1, sequence=1)
        )
        second_listing = _listing(
            _row("queued", None, "queued by pull request synchronization",
                 attempt=1, sequence=2)
        )
        script = ScriptedHttp(
            gets=[(200, first_listing), (200, second_listing)],
            posts=[_conflict(), (201, _requested_run(3))],
        )
        harness = _harness(script)
        with _sleep_patcher():
            result = harness.advance_check(
                COMMIT,
                CONTEXT,
                "completed",
                FAILURE_CONCLUSION,
                OUTPUT,
                max_conflicts=2,
                deadline_seconds=5.0,
            )
        self.assert_failure_result(result)
        self.assertEqual(result["sequence"], 3)
        self.assertEqual(script.post_sequences(), [2, 3])
        self.assertEqual(len(script.gets), 2)
        self.assertEqual(len(script.posts), 2)
        self.assertEqual([entry["path"] for entry in script.gets], [PATH, PATH])
        self.assertEqual([entry["token"] for entry in script.gets],
                         [harness.reader, harness.reader])
        for entry in script.posts:
            body = entry["body"]
            self.assertEqual(entry["path"], PATH)
            self.assertEqual(entry["token"], harness.alice)
            self.assertEqual(body["attempt"], 1)
            self.assertEqual(body["context"], CONTEXT)
            self.assertEqual(body["status"], "completed")
            self.assertEqual(body["conclusion"], FAILURE_CONCLUSION)
            self.assertEqual(body["output"], OUTPUT)
        script.assert_drained(self)

    def test_unrelated_409_fails_after_one_write_and_one_read(self):
        script = ScriptedHttp(
            gets=[(200, _listing())],
            posts=[(409, {"error": "some unrelated 409"})],
        )
        harness = _harness(script)
        with _sleep_patcher():
            with self.assertRaises(AssertionError):
                harness.advance_check(
                    COMMIT, CONTEXT, "completed", FAILURE_CONCLUSION, OUTPUT
                )
        self.assertEqual(len(script.posts), 1)
        self.assertEqual(len(script.gets), 1)
        self.assertEqual(script.post_sequences(), [1])
        script.assert_drained(self)

    def test_persistent_exact_conflict_bounded_by_max_conflicts(self):
        script = ScriptedHttp(
            gets=[
                (200, _listing(_row("queued", None, "queued 1", attempt=1, sequence=1))),
                (200, _listing(_row("queued", None, "queued 2", attempt=1, sequence=2))),
            ],
            posts=[_conflict(), _conflict()],
        )
        harness = _harness(script)
        with _sleep_patcher():
            with self.assertRaisesRegex(AssertionError, "still conflicted after 2 attempts"):
                harness.advance_check(
                    COMMIT,
                    CONTEXT,
                    "completed",
                    FAILURE_CONCLUSION,
                    OUTPUT,
                    max_conflicts=2,
                    deadline_seconds=5.0,
                )
        self.assertEqual(len(script.gets), 2)
        self.assertEqual(len(script.posts), 2)
        self.assertEqual(script.post_sequences(), [2, 3])
        script.assert_drained(self)

    def test_wrong_top_level_commit_oid_fails_before_any_write(self):
        script = ScriptedHttp(
            gets=[(200, _listing(commit_oid="f" * 40))],
            posts=[],
        )
        harness = _harness(script)
        with _sleep_patcher():
            with self.assertRaises(AssertionError):
                harness.advance_check(
                    COMMIT, CONTEXT, "completed", FAILURE_CONCLUSION, OUTPUT
                )
        self.assertEqual(len(script.posts), 0)
        self.assertEqual(len(script.gets), 1)
        script.assert_drained(self)

    def test_attempt_two_listing_fails_before_any_write(self):
        script = ScriptedHttp(
            gets=[(200, _listing(_row("queued", None, "queued", attempt=2, sequence=1)))],
            posts=[],
        )
        harness = _harness(script)
        with _sleep_patcher():
            with self.assertRaises(AssertionError):
                harness.advance_check(
                    COMMIT, CONTEXT, "completed", FAILURE_CONCLUSION, OUTPUT
                )
        self.assertEqual(len(script.posts), 0)
        self.assertEqual(len(script.gets), 1)
        script.assert_drained(self)


if __name__ == "__main__":
    unittest.main()
