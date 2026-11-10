#!/usr/bin/env python3
"""Focused tests for owned-fixture retention in the native baseline runner."""
import inspect
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import state_services_native_baseline as baseline  # noqa: E402


class FixtureRetentionTest(unittest.TestCase):
    def test_passed_run_removes_and_explicit_keep_retains(self):
        self.assertEqual(
            baseline.fixture_retention_decision(False, "passed"),
            (False, "passed run removes its owned temporary fixture by default"),
        )
        self.assertEqual(
            baseline.fixture_retention_decision(True, "passed"),
            (True, "--keep requested"),
        )

    def test_failed_run_requests_retention_for_diagnosis(self):
        self.assertEqual(
            baseline.fixture_retention_decision(False, "failed"),
            (True, "failed run retained for diagnosis"),
        )
        self.assertEqual(
            baseline.fixture_retention_decision(True, "failed"),
            (True, "--keep requested"),
        )

    def test_runner_reports_requested_and_actual_retention(self):
        source = inspect.getsource(baseline.main)
        self.assertIn("fixture_retention_decision(args.keep, report['status'])", source)
        self.assertIn("h.args.keep = retain", source)
        self.assertIn("['retained'] = h.root.exists()", source)
        self.assertIn("'requested': retain", source)
        self.assertIn("help='retain the owned temporary fixture", source)
        # Cleanup must stay limited to the harness-owned schema and temporary root.
        self.assertIn("h.cleanup()", source)
        self.assertNotIn("fusermount", source)
        self.assertNotIn("umount", source)


if __name__ == "__main__":
    unittest.main()
