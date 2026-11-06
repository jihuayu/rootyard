"""Tests invoke the real entrypoint subprocess; no reference model substitution."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeEntrypointTests(unittest.TestCase):
    def invoke(self, binary, root):
        report = root / "report.json"
        result = subprocess.run([sys.executable, str(ROOT / "tests/e2e_tiers.py"),
                                 "--feature", "F24", "--binary", str(binary),
                                 "--report", str(report)], capture_output=True, timeout=90)
        self.assertNotEqual(result.returncode, 0, result.stdout.decode())
        self.assertFalse(json.loads(report.read_text())["success"])

    def test_missing_binary_fails_before_reference_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.invoke(root / "missing", root)

    @unittest.skipUnless(os.environ.get("ROOTYARD_TEST_DATABASE_URL"), "requires real PostgreSQL")
    def test_executable_nonserver_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / "stub"
            stub.write_text("#!/bin/sh\nexit 0\n")
            stub.chmod(0o700)
            self.invoke(stub, root)


if __name__ == "__main__":
    unittest.main()
