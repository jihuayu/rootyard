#!/usr/bin/env python3
"""Hermetic tests for finite concurrent-worker outcomes and first-error priority.

These tests use pure fake futures and a fake executor.  They never create a
thread, child, process, Git fixture, network, PG, S3, vault, Docker or native
runtime.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pack_compression_eval import concurrent_outcomes  # noqa: E402
from pack_compression_eval.concurrent_outcomes import (  # noqa: E402
    CONCURRENT_OUTCOME_FIELDS,
    annotate_stale_operations,
    collect_concurrent_outcomes,
    finite_http_subphase,
    finite_worker_outcome,
    sanitize_concurrent_outcomes,
)
from pack_compression_eval.failure_diagnostics import (  # noqa: E402
    LiveEvalFailure,
    build_failure_record,
    enrich_failure_record,
)

SENTINEL = "SENTINEL_SECRET_concurrent_fd3a"


class _FakeFuture:
    def __init__(self, error: BaseException | None = None, *, value: object = None) -> None:
        self.error = error
        self.value = value
        self.called = False

    def result(self) -> object:
        self.called = True
        if self.error is not None:
            raise self.error
        return self.value


class _FakeExecutor:
    def __init__(self) -> None:
        self.exited = False

    def __enter__(self) -> "_FakeExecutor":
        return self

    def __exit__(self, *_args: object) -> bool:
        self.exited = True
        return False


def _valid(branch: int = 0) -> dict:
    return finite_worker_outcome(branch)


class ConcurrentOutcomeTest(unittest.TestCase):
    def test_passed_outcome_is_fixed(self) -> None:
        self.assertEqual(
            _valid(1),
            {
                "branch_ordinal": 1,
                "outcome": "passed",
                "phase": "unknown",
                "failure_class": "unclassified",
                "http_status": None,
                "http_subphase": "unknown",
                "push_ref_verdict": "unknown",
                "operation_verdict": "unknown",
                "git_returncode": None,
                "signal": None,
                "elapsed_ms": None,
            },
        )

    def test_live_failure_uses_only_finite_record_fields(self) -> None:
        record = build_failure_record(
            phase="concurrent_push",
            failure_class="git_push",
            http_status=503,
            http_subphase="receive_pack",
            push_ref_verdict="stale_info",
            git_returncode=1,
            signal=9,
            elapsed_ms=1023.4567,
        )
        outcome = finite_worker_outcome(0, LiveEvalFailure(record))
        self.assertEqual(
            outcome,
            {
                "branch_ordinal": 0,
                "outcome": "failed",
                "phase": "concurrent_push",
                "failure_class": "git_push",
                "http_status": 503,
                "http_subphase": "receive_pack",
                "push_ref_verdict": "stale_info",
                "operation_verdict": "unknown",
                "git_returncode": 1,
                "signal": 9,
                "elapsed_ms": 1023.457,
            },
        )

    def test_generic_error_fails_closed_without_raw_text(self) -> None:
        outcome = finite_worker_outcome(2, RuntimeError(SENTINEL))
        self.assertEqual(outcome["outcome"], "unknown")
        self.assertEqual(outcome["phase"], "unknown")
        self.assertEqual(outcome["failure_class"], "unclassified")
        self.assertIsNone(outcome["elapsed_ms"])
        self.assertNotIn(SENTINEL, json.dumps(outcome, sort_keys=True))

    def test_http_subphase_is_only_unambiguous(self) -> None:
        self.assertEqual(finite_http_subphase(b"error: RPC failed; HTTP 503 curl 22", 503), "receive_pack")
        self.assertEqual(
            finite_http_subphase(
                b"fatal: unable to access 'http://h/git/o/r.git/info/refs?service=git-receive-pack': "
                b"The requested URL returned error: 503",
                503,
            ),
            "info_refs",
        )
        self.assertEqual(
            finite_http_subphase(
                b"fatal: unable to access 'http://h/git/o/r.git': The requested URL returned error: 503",
                503,
            ),
            "unknown",
        )
        self.assertEqual(
            finite_http_subphase(b"error: RPC failed; HTTP 503 info/refs?service=git-receive-pack", 503),
            "receive_pack",
        )
        self.assertEqual(finite_http_subphase(b"info/refs?service=git-receive-pack", None), "unknown")
        self.assertEqual(finite_http_subphase(None, 503), "unknown")

    def test_collect_preserves_original_first_error_and_all_outcomes(self) -> None:
        first = LiveEvalFailure(
            build_failure_record(
                phase="concurrent_push", failure_class="git_push", git_returncode=1, elapsed_ms=12.3456
            )
        )
        second = LiveEvalFailure(
            build_failure_record(
                phase="concurrent_push", failure_class="git_push", git_returncode=1,
                http_status=503, http_subphase="receive_pack", elapsed_ms=42,
            )
        )
        browse = RuntimeError("browse")
        futs = [_FakeFuture(first), _FakeFuture(value=24.1234), _FakeFuture(second)]
        bfut = _FakeFuture(browse)
        progress: dict = {}
        executor = _FakeExecutor()
        with executor:
            returned = collect_concurrent_outcomes(futs, bfut, branch_count=3, progress=progress)
        self.assertTrue(executor.exited)
        self.assertIs(returned, first)
        self.assertTrue(all(f.called for f in futs))
        self.assertTrue(bfut.called)
        outcomes = progress["concurrent_worker_outcomes"]
        self.assertEqual([o["branch_ordinal"] for o in outcomes], [0, 1, 2])
        self.assertEqual([o["outcome"] for o in outcomes], ["failed", "passed", "failed"])
        self.assertEqual([o["elapsed_ms"] for o in outcomes], [12.346, 24.123, 42.0])
        self.assertEqual([o["http_status"] for o in outcomes], [None, None, 503])
        self.assertEqual([o["http_subphase"] for o in outcomes], ["unknown", "unknown", "receive_pack"])
        with self.assertRaises(RuntimeError) as caught:
            if returned is not None:
                raise returned
        self.assertIs(caught.exception, first)

    def test_browse_error_is_first_only_when_all_pushes_pass(self) -> None:
        browse = RuntimeError("browse")
        futs = [_FakeFuture(), _FakeFuture(), _FakeFuture()]
        progress: dict = {}
        returned = collect_concurrent_outcomes(futs, _FakeFuture(browse), branch_count=3, progress=progress)
        self.assertIs(returned, browse)
        self.assertEqual([o["outcome"] for o in progress["concurrent_worker_outcomes"]], ["passed"] * 3)

    def test_unmeasured_failures_leave_elapsed_null(self) -> None:
        for failure_class in ("git_timeout", "git_spawn"):
            with self.subTest(failure_class=failure_class):
                exc = LiveEvalFailure(build_failure_record(phase="concurrent_push", failure_class=failure_class))
                self.assertIsNone(finite_worker_outcome(0, exc)["elapsed_ms"])
        [unknown] = sanitize_concurrent_outcomes([{**_valid(0), "outcome": "unknown", "elapsed_ms": 12.0}])
        self.assertIsNone(unknown["elapsed_ms"])

    def test_elapsed_uses_same_finite_scalar_contract_at_each_boundary(self) -> None:
        self.assertEqual(finite_worker_outcome(0, elapsed_ms=0)["elapsed_ms"], 0.0)
        for value in (None, True, SENTINEL, -1, float("nan"), float("inf"), 10**400):
            with self.subTest(value=value):
                self.assertIsNone(finite_worker_outcome(0, elapsed_ms=value)["elapsed_ms"])
                self.assertIsNone(build_failure_record(elapsed_ms=value)["elapsed_ms"])
                [row] = sanitize_concurrent_outcomes([{**_valid(0), "elapsed_ms": value}])
                self.assertIsNone(row["elapsed_ms"])
                self.assertNotIn(SENTINEL, json.dumps(row, allow_nan=False))

    def test_sanitize_rejects_duplicates_unlisted_keys_and_injection(self) -> None:
        valid = [_valid(0), _valid(1), _valid(2)]
        self.assertEqual(sanitize_concurrent_outcomes(valid), valid)
        duplicated = sanitize_concurrent_outcomes([_valid(0), _valid(0), _valid(2)])
        self.assertEqual([o["branch_ordinal"] for o in duplicated], [0, 2])
        extra = sanitize_concurrent_outcomes([{**_valid(0), "injected": SENTINEL}])
        self.assertEqual(extra, [])
        missing = sanitize_concurrent_outcomes([{"branch_ordinal": 0}])
        self.assertEqual(missing, [])
        wrong_branch = sanitize_concurrent_outcomes([{**_valid(0), "branch_ordinal": True}])
        self.assertEqual(wrong_branch, [])
        wrong_outcome = sanitize_concurrent_outcomes([{**_valid(0), "outcome": SENTINEL}])
        self.assertEqual(wrong_outcome, [])
        normalized = sanitize_concurrent_outcomes(
            [{**_valid(0), "phase": SENTINEL, "http_status": SENTINEL, "git_returncode": SENTINEL}]
        )
        self.assertEqual(normalized[0]["phase"], "unknown")
        self.assertIsNone(normalized[0]["http_status"])
        self.assertIsNone(normalized[0]["git_returncode"])
        self.assertNotIn(SENTINEL, json.dumps(normalized, sort_keys=True))
        self.assertEqual(sanitize_concurrent_outcomes([*valid, _valid(0)]), [])
        self.assertEqual(sanitize_concurrent_outcomes({"branch_ordinal": 0}), [])
        self.assertEqual(set(CONCURRENT_OUTCOME_FIELDS), set(_valid(0)))

    def test_legacy_outcome_gains_null_elapsed_without_relaxing_its_other_fields(self) -> None:
        legacy = _valid(0)
        del legacy["elapsed_ms"]
        self.assertEqual(sanitize_concurrent_outcomes([legacy]), [_valid(0)])
        del legacy["http_subphase"]
        self.assertEqual(sanitize_concurrent_outcomes([legacy]), [])

    def test_legacy_outcome_without_verdict_projects_unknown(self) -> None:
        without_verdict = _valid(1)
        del without_verdict["push_ref_verdict"]
        without_elapsed = dict(without_verdict)
        del without_elapsed["elapsed_ms"]
        projected = sanitize_concurrent_outcomes([without_verdict, {**without_elapsed, "branch_ordinal": 2}])
        self.assertEqual([row["branch_ordinal"] for row in projected], [1, 2])
        self.assertEqual([row["push_ref_verdict"] for row in projected], ["unknown", "unknown"])
        self.assertEqual([row["elapsed_ms"] for row in projected], [None, None])
        # A pre-verdict receipt keeps its own stderr HTTP classification.
        failed_legacy = {
            "branch_ordinal": 1,
            "outcome": "failed",
            "phase": "concurrent_push",
            "failure_class": "git_push",
            "http_status": 503,
            "http_subphase": "receive_pack",
            "git_returncode": 1,
            "signal": None,
            "elapsed_ms": 4.5,
        }
        [projected_failed] = sanitize_concurrent_outcomes([failed_legacy])
        self.assertEqual(projected_failed["push_ref_verdict"], "unknown")
        self.assertEqual(projected_failed["http_status"], 503)
        self.assertEqual(projected_failed["http_subphase"], "receive_pack")
        self.assertEqual(projected_failed["elapsed_ms"], 4.5)

    def test_two_failed_workers_keep_their_own_verdict(self) -> None:
        first = LiveEvalFailure(
            build_failure_record(
                phase="concurrent_push", failure_class="git_push", git_returncode=1,
                http_status=503, http_subphase="receive_pack",
                push_ref_verdict="stale_info", elapsed_ms=11.5,
            )
        )
        second = LiveEvalFailure(
            build_failure_record(
                phase="concurrent_push", failure_class="git_push", git_returncode=1,
                push_ref_verdict="other_ref_rejection", elapsed_ms=22.5,
            )
        )
        progress: dict = {}
        returned = collect_concurrent_outcomes(
            [_FakeFuture(first), _FakeFuture(value=3.0), _FakeFuture(second)],
            _FakeFuture(value=None),
            branch_count=3,
            progress=progress,
        )
        self.assertIs(returned, first)
        outcomes = progress["concurrent_worker_outcomes"]
        self.assertEqual([o["branch_ordinal"] for o in outcomes], [0, 1, 2])
        self.assertEqual([o["push_ref_verdict"] for o in outcomes], ["stale_info", "unknown", "other_ref_rejection"])
        # The first original error and its existing stderr HTTP result stay intact.
        self.assertEqual(returned.record["http_status"], 503)
        self.assertEqual(returned.record["http_subphase"], "receive_pack")
        self.assertEqual(outcomes[0]["http_status"], 503)
        self.assertEqual(outcomes[0]["http_subphase"], "receive_pack")
        self.assertIsNone(outcomes[2]["http_status"])
        self.assertEqual(outcomes[2]["http_subphase"], "unknown")
        self.assertEqual(returned.record["push_ref_verdict"], "stale_info")

    def test_verdict_projection_never_leaks_raw_text(self) -> None:
        injected = sanitize_concurrent_outcomes([{**_valid(0), "push_ref_verdict": SENTINEL}])
        self.assertEqual(injected[0]["push_ref_verdict"], "unknown")
        self.assertNotIn(SENTINEL, json.dumps(injected, sort_keys=True))
        record = build_failure_record(concurrent_worker_outcomes=[{**_valid(0), "push_ref_verdict": SENTINEL}])
        self.assertEqual(record["concurrent_worker_outcomes"][0]["push_ref_verdict"], "unknown")
        self.assertNotIn(SENTINEL, json.dumps(record, sort_keys=True))
        self.assertEqual(build_failure_record(push_ref_verdict=SENTINEL)["push_ref_verdict"], "unknown")

    def test_receipt_carries_annotated_operation_verdict(self) -> None:
        rows = [
            {**finite_worker_outcome(0, self._stale_first_error()), "operation_verdict": "admitted_base_superseded"},
            finite_worker_outcome(1, elapsed_ms=3.0),
            {**finite_worker_outcome(2, self._stale_first_error()), "operation_verdict": "per_ref_cas_rejected"},
        ]
        record = build_failure_record(concurrent_worker_outcomes=rows)
        self.assertEqual(
            [row["operation_verdict"] for row in record["concurrent_worker_outcomes"]],
            ["admitted_base_superseded", "unknown", "per_ref_cas_rejected"],
        )
        self.assertEqual(
            [row["push_ref_verdict"] for row in record["concurrent_worker_outcomes"]],
            ["stale_info", "unknown", "stale_info"],
        )
        enriched = enrich_failure_record(record)
        self.assertEqual(
            [row["operation_verdict"] for row in enriched["concurrent_worker_outcomes"]],
            ["admitted_base_superseded", "unknown", "per_ref_cas_rejected"],
        )

    def test_failure_record_projects_outcomes_defensively(self) -> None:
        valid = [finite_worker_outcome(0, elapsed_ms=27.125), _valid(1), _valid(2)]
        record = build_failure_record(concurrent_worker_outcomes=valid)
        self.assertEqual(record["concurrent_worker_outcomes"], valid)
        self.assertEqual(enrich_failure_record(record)["concurrent_worker_outcomes"], valid)
        bad = build_failure_record(concurrent_worker_outcomes=[{**_valid(0), "injected": SENTINEL}])
        self.assertEqual(bad["concurrent_worker_outcomes"], [])
        self.assertNotIn(SENTINEL, json.dumps(bad, sort_keys=True))
        self.assertEqual(build_failure_record()["concurrent_worker_outcomes"], [])

    def test_every_late_field_is_individually_legacy_compatible(self) -> None:
        full = _valid(0)
        late = ("elapsed_ms", "push_ref_verdict", "operation_verdict")
        for size in range(len(late) + 1):
            for removed in itertools.combinations(late, size):
                legacy = {key: value for key, value in full.items() if key not in removed}
                with self.subTest(removed=removed):
                    [row] = sanitize_concurrent_outcomes([legacy])
                    self.assertEqual(set(row), set(CONCURRENT_OUTCOME_FIELDS))
                    self.assertEqual(row["push_ref_verdict"], "unknown")
                    self.assertEqual(row["operation_verdict"], "unknown")
                    self.assertIsNone(row["elapsed_ms"])

    def _stale_first_error(self, verdict: str = "stale_info") -> LiveEvalFailure:
        return LiveEvalFailure(
            build_failure_record(
                phase="concurrent_push", failure_class="git_push", git_returncode=1, push_ref_verdict=verdict
            )
        )

    def test_annotation_queries_only_stale_workers_once_each(self) -> None:
        first = self._stale_first_error()
        other = self._stale_first_error("other_ref_rejection")
        second = self._stale_first_error()
        progress: dict = {}
        returned = collect_concurrent_outcomes(
            [_FakeFuture(first), _FakeFuture(other), _FakeFuture(second)],
            _FakeFuture(value=None),
            branch_count=3,
            progress=progress,
        )
        operations = {
            0: ("11111111-1111-4111-8111-111111111111", "refs/heads/conc_0"),
            2: ("33333333-3333-4333-8333-333333333333", "refs/heads/conc_2"),
        }
        answers = {
            operations[0][0]: "admitted_base_superseded",
            operations[2][0]: "per_ref_cas_rejected",
        }
        calls = []

        def fake_query(base_url, owner, name, operation_id, token, *, repository_id, expected_ref):
            calls.append((operation_id, expected_ref, repository_id, token))
            return answers[operation_id]

        with mock.patch.object(concurrent_outcomes, "read_operation_verdict", side_effect=fake_query):
            annotate_stale_operations(
                progress, "http://127.0.0.1:1", {"owner": "o", "name": "r", "id": "x"}, "tok", operations
            )
        self.assertIs(returned, first)
        self.assertEqual([call[0] for call in calls], [operations[0][0], operations[2][0]])
        self.assertEqual([call[1] for call in calls], ["refs/heads/conc_0", "refs/heads/conc_2"])
        self.assertEqual([call[2] for call in calls], ["x", "x"])
        self.assertEqual([call[3] for call in calls], ["tok", "tok"])
        outcomes = progress["concurrent_worker_outcomes"]
        self.assertEqual(
            [row["operation_verdict"] for row in outcomes],
            ["admitted_base_superseded", "unknown", "per_ref_cas_rejected"],
        )
        self.assertEqual(outcomes[0]["push_ref_verdict"], "stale_info")
        self.assertEqual(outcomes[1]["push_ref_verdict"], "other_ref_rejection")

    def test_annotation_failures_stay_unknown_and_never_replace_first_error(self) -> None:
        first = self._stale_first_error()
        progress: dict = {}
        returned = collect_concurrent_outcomes(
            [_FakeFuture(first)], _FakeFuture(value=None), branch_count=3, progress=progress
        )
        operations = {0: ("22222222-2222-4222-8222-222222222222", "refs/heads/conc_0")}
        for side_effect in (RuntimeError(SENTINEL), ValueError(SENTINEL), OSError(SENTINEL)):
            with self.subTest(side_effect=type(side_effect).__name__):
                with mock.patch.object(concurrent_outcomes, "read_operation_verdict", side_effect=side_effect):
                    annotate_stale_operations(progress, "http://127.0.0.1:1", {"owner": "o"}, "tok", operations)
                self.assertIs(returned, first)
                self.assertEqual(progress["concurrent_worker_outcomes"][0]["operation_verdict"], "unknown")
                self.assertNotIn(SENTINEL, json.dumps(progress["concurrent_worker_outcomes"], sort_keys=True))

    def test_annotation_normalizes_unlisted_answers_and_malformed_input(self) -> None:
        first = self._stale_first_error()
        progress: dict = {}
        collect_concurrent_outcomes([_FakeFuture(first)], _FakeFuture(value=None), branch_count=3, progress=progress)
        operations = {0: ("44444444-4444-4444-8444-444444444444", "refs/heads/conc_0")}
        with mock.patch.object(concurrent_outcomes, "read_operation_verdict", return_value=SENTINEL):
            annotate_stale_operations(progress, "http://127.0.0.1:1", {"owner": "o", "id": "x"}, "tok", operations)
        self.assertEqual(progress["concurrent_worker_outcomes"][0]["operation_verdict"], "unknown")
        self.assertNotIn(SENTINEL, json.dumps(progress["concurrent_worker_outcomes"], sort_keys=True))
        # Missing ordinal→operation, non-mapping repo and empty outcomes are inert.
        for empty in ({}, {"branch_ordinal": 0}, {"branch_ordinal": 0, "outcome": "unknown"}):
            fresh: dict = {"concurrent_worker_outcomes": [dict(empty)]}
            annotate_stale_operations(fresh, "http://127.0.0.1:1", "not-a-mapping", "tok", {})
            self.assertIsInstance(fresh["concurrent_worker_outcomes"], list)
        blank: dict = {}
        annotate_stale_operations(blank, "http://127.0.0.1:1", {}, "tok", {})
        self.assertNotIn("concurrent_worker_outcomes", blank)


if __name__ == "__main__":
    unittest.main()
