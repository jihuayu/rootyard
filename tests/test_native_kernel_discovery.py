"""Keep ordinary discovery separate from the strict native kernel entrypoint."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeKernelEntrypointTests(unittest.TestCase):
    def environment(self):
        return {key: value for key, value in os.environ.items() if not key.startswith("ROOTYARD_")}

    def test_discovery_skips_privileged_cases_without_starting_a_harness(self):
        # With no database URL, accidentally constructing the native harness
        # would fail. Discovery must leave the two cases to the strict script.
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_sandbox_cgroup_native.py"],
            cwd=ROOT, env=self.environment(), capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ran 2 tests", result.stderr)
        self.assertIn("skipped=2", result.stderr)
        self.assertNotIn("native failure diagnostics", result.stderr)

    def test_direct_entrypoint_refuses_dev_profile_with_failed_receipt(self):
        with tempfile.TemporaryDirectory(prefix="rootyard-native-discovery-") as directory:
            receipt = Path(directory) / "receipt.json"
            env = self.environment()
            env["ROOTYARD_SANDBOX_MODE"] = "dev"
            env["PYTHONPATH"] = str(ROOT)
            result = subprocess.run(
                [sys.executable, str(ROOT / "tests/test_sandbox_cgroup_native.py"),
                 "--receipt", str(receipt)],
                cwd=ROOT, env=env, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(receipt.is_file(), result.stderr)
            report = json.loads(receipt.read_text())
            self.assertEqual(report["status"], "failed")


if __name__ == "__main__":
    unittest.main()
