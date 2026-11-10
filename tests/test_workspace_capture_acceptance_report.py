"""Contract test for the workspace capture acceptance report projection."""

import io
import unittest
from pathlib import Path

from workspace_capture_acceptance import (
    TimedTextTestResult,
    build_report,
    scheduled_test_ids,
)


def _synthetic_suite() -> unittest.TestSuite:
    """Build a tiny suite: one passing case and one unconditionally skipped case."""

    class _PassingCase(unittest.TestCase):
        def test_passes(self) -> None:
            self.assertTrue(True)

    class _SkippedCase(unittest.TestCase):
        @unittest.skip("synthetic skip for contract test")
        def test_skipped(self) -> None:
            self.fail("skipped case must not execute")

    suite = unittest.TestSuite()
    suite.addTest(_PassingCase("test_passes"))
    suite.addTest(_SkippedCase("test_skipped"))
    return suite


class WorkspaceCaptureAcceptanceReportTest(unittest.TestCase):
    def test_report_maps_cases_and_preserves_legacy_tests(self) -> None:
        suite = _synthetic_suite()
        scheduled = scheduled_test_ids(suite)

        runner = unittest.TextTestRunner(
            stream=io.StringIO(),
            verbosity=0,
            resultclass=TimedTextTestResult,
        )
        result = runner.run(suite)

        # Dummy values: never opened, no service or database is required.
        dummy_binary = Path("/nonexistent/workspace-capture-dummy-binary")
        dummy_sha = "0" * 64

        report = build_report(result, scheduled, dummy_binary, dummy_sha)

        cases = report["cases"]
        self.assertEqual(len(cases), 2)
        self.assertEqual(cases[0]["status"], "passed")
        self.assertEqual(cases[1]["status"], "skipped")

        self.assertFalse(report["passed"])

        legacy_tests = report["tests"]
        self.assertEqual(len(legacy_tests), 2)
        self.assertEqual(legacy_tests[0]["status"], "success")
        self.assertEqual(legacy_tests[1]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
