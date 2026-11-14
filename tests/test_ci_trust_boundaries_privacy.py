#!/usr/bin/env python3
"""Offline privacy regression for the trusted-boundary harness.

``PullsHarness.case`` records and prints a redacted failure, but re-raises so a
caller can decide whether to continue. ``ci_trust_boundaries.main`` used to let
that original exception escape, which made Python print the unredacted
assertion payload a second time. These tests use a sentinel claimed checkout
token and prove that neither the boundary diagnostics nor the retained failed
result/report contain it. No native binary, PostgreSQL or network is required.
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_trust_boundaries as module  # noqa: E402
from e2e import Harness  # noqa: E402
from pulls import PullsHarness  # noqa: E402


SENTINEL = "claim-checkout-token-5d41402abc4b2a76b9719d911017c592"
CASE_METHODS = {
    "configure",
    "positive_matrix",
    "revocation_blocks_merge",
    "ordinary_writer_and_cross_scope_refusals",
    "candidate_change_invalidates_evidence",
    "revocation_and_late_attempt_matrix",
    "context_removal_revokes_authority",
    "api_principal_token_revocation",
}


class _BoundaryHarness:
    """Minimal harness state; only the real PullsHarness.case is exercised."""

    def __init__(self):
        self.secrets = [SENTINEL]
        self.results = []
        self.base_db = "postgresql://fixture:fixture@127.0.0.1:1/rootyard_test"
        self.db = self.base_db + "?options=-csearch_path%3Dfixture"
        self.cleaned = False
        self.cleanup_error = None

    def redact(self, value):
        return Harness.redact(self, value)

    def case(self, name, fn):
        return PullsHarness.case(self, name, fn)

    def setup(self):
        pass

    def cleanup(self):
        self.cleaned = True
        if self.cleanup_error is not None:
            raise RuntimeError(self.cleanup_error)

    def __getattr__(self, name):
        if name in CASE_METHODS:
            return lambda: None
        raise AttributeError(name)


def claimed_checkout_assertion():
    claimed = {"checkout": {"token": SENTINEL}}
    assert claimed == {"checkout": {"token": SENTINEL + "-stale"}}, claimed


class HarnessPrivacyTest(unittest.TestCase):
    def run_main(self, harness):
        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = ["ci_trust_boundaries.py", "--binary", "rootyard"]
        with mock.patch.object(
            module, "TrustBoundaryHarness", return_value=harness
        ), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(
            stdout
        ), contextlib.redirect_stderr(stderr):
            code = module.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_failed_claim_assertion_is_redacted_at_outer_boundary(self):
        harness = _BoundaryHarness()

        def failing_case():
            # The real positive matrix registers the claimed capability before
            # any assertion that embeds the response object.
            harness.secrets.append(SENTINEL)
            claimed_checkout_assertion()

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            success = module.run_cases(
                harness, [("claimed checkout assertion", failing_case)]
            )

        self.assertFalse(success)
        self.assertEqual(len(harness.results), 1)
        failed = harness.results[0]
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["name"], "claimed checkout assertion")
        diagnostics = stderr.getvalue()
        self.assertNotIn(SENTINEL, diagnostics)
        self.assertNotIn(SENTINEL, json.dumps(harness.results))
        self.assertIn("[REDACTED]", diagnostics)

    def test_main_keeps_failed_result_cleans_up_and_exits_nonzero(self):
        harness = _BoundaryHarness()
        harness.configure = claimed_checkout_assertion
        code, stdout, stderr = self.run_main(harness)

        self.assertEqual(code, 1)
        self.assertTrue(harness.cleaned)
        self.assertEqual(len(harness.results), 1)
        failed = harness.results[0]
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["name"], "trusted two-repository matrix setup")
        self.assertNotIn(SENTINEL, stderr)
        self.assertNotIn(SENTINEL, stdout)
        self.assertNotIn(SENTINEL, json.dumps(harness.results))
        self.assertIn("[REDACTED]", stderr)

    def test_main_cleanup_failure_is_redacted_and_nonzero(self):
        harness = _BoundaryHarness()
        harness.cleanup_error = "fixture cleanup leaked " + SENTINEL
        code, stdout, stderr = self.run_main(harness)

        self.assertEqual(code, 1)
        self.assertTrue(harness.cleaned)
        cleanup = [row for row in harness.results if row["name"] == "cleanup"]
        self.assertEqual(len(cleanup), 1)
        self.assertEqual(cleanup[0]["status"], "failed")
        self.assertNotIn(SENTINEL, stderr)
        self.assertNotIn(SENTINEL, stdout)
        self.assertNotIn(SENTINEL, json.dumps(harness.results))
        self.assertIn("[REDACTED]", stderr)


if __name__ == "__main__":
    unittest.main()
