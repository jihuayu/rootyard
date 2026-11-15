"""Unit-test wrapper invoking live Pando PITR service acceptance during CI discovery (#77)."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pando_pitr_service  # noqa: E402
import runtime_binary  # noqa: E402


class PandoPitrServiceTest(unittest.TestCase):
    def test_pando_pitr_pg_dump_clone_and_retention_roots(self) -> None:
        in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
        if os.name == "nt" and not in_ci:
            self.skipTest("live rootyard service tests target Linux runtime")
        if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
            if in_ci:
                self.fail("ROOTYARD_TEST_DATABASE_URL is required in GitHub Actions")
            self.skipTest("ROOTYARD_TEST_DATABASE_URL is unset")
        try:
            binary, _binding = runtime_binary.select_runtime_binary()
        except runtime_binary.RuntimeBinarySelectionError as exc:
            if in_ci:
                self.fail(f"prebuilt rootyard binary unavailable in CI: {exc}")
            self.skipTest(str(exc))

        report = pando_pitr_service.run_suite(str(binary))
        self.assertTrue(report["passed"])
        self.assertTrue(report["clone_fail_closed_zero_deletes"])
        self.assertTrue(report["operator_isolate_recovered"])
        self.assertTrue(report["pitr_epoch_rollback_fenced"])


if __name__ == "__main__":
    unittest.main()
