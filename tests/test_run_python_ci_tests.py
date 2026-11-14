#!/usr/bin/env python3
"""Focused offline checks for the CI Python unittest diagnostics runner.

The repository's real unittest tree is not imported here. Temporary fixture
modules exercise discovery selection, verbose progress, skip/failure exits and
faulthandler cleanup without Cargo, a database, a container or a network.
"""
from __future__ import annotations

import faulthandler
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_python_ci_tests", ROOT / "scripts" / "run_python_ci_tests.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

# Run the real faulthandler timer in a child process.  The CI runner already
# owns the process-global timer while this suite runs, so a nested in-process
# dump/cancel would silently disable the outer diagnostics.
_SUBPROCESS_DRIVER = r"""
import importlib.util
import json
from pathlib import Path
import sys
import time

tests_dir = Path(sys.argv[1])
diagnostics = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location(
    "run_python_ci_tests", Path.cwd() / "scripts" / "run_python_ci_tests.py"
)
assert spec is not None and spec.loader is not None
child_runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(child_runner)
with diagnostics.open("w+", encoding="utf-8") as stream:
    code = child_runner.run(
        tests_dir,
        stream=sys.stderr,
        watchdog_stream=stream,
        traceback_interval=0.05,
    )
    # Let an in-flight dump settle, then prove the repeating timer stopped.
    time.sleep(0.1)
    settled = diagnostics.read_text(encoding="utf-8")
    time.sleep(0.15)
    stable = diagnostics.read_text(encoding="utf-8") == settled
print(json.dumps({"code": code, "settled": settled, "stable": stable}))
"""


def flatten(suite: unittest.TestSuite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


class DiagnosticsRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".python-ci-runner-", dir=ROOT
        )
        self.addCleanup(self.temporary.cleanup)
        self.tests = Path(self.temporary.name)
        self.original_path = list(sys.path)
        self.original_modules = set(sys.modules)
        self.addCleanup(self._restore_imports)

    def _restore_imports(self) -> None:
        sys.path[:] = self.original_path
        for name in set(sys.modules) - self.original_modules:
            module = sys.modules.get(name)
            filename = getattr(module, "__file__", None)
            if filename is not None and Path(filename).is_relative_to(self.tests):
                del sys.modules[name]

    def write(self, name: str, source: str) -> None:
        path = self.tests / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source), encoding="utf-8")

    def run_fixture(self) -> tuple[int, str]:
        output = io.StringIO()
        with mock.patch.object(faulthandler, "dump_traceback_later") as start, \
                mock.patch.object(faulthandler, "cancel_dump_traceback_later") as cancel:
            code = runner.run(self.tests, stream=output)
        self.assertEqual(cancel.call_count, 1)
        self.assertEqual(
            start.call_args.args, (runner.TRACEBACK_INTERVAL_SECONDS,)
        )
        self.assertTrue(start.call_args.kwargs["repeat"])
        self.assertIs(start.call_args.kwargs["file"], sys.stderr)
        return code, output.getvalue()

    def test_discovery_selects_the_test_glob_in_unittest_order(self) -> None:
        self.write("test_runner_fixture_beta.py", """
            import unittest
            class Second(unittest.TestCase):
                def test_b(self): pass
                def test_a(self): pass
        """)
        self.write("test_runner_fixture_alpha.py", """
            import unittest
            class First(unittest.TestCase):
                def test_only(self): pass
        """)
        self.write("runner_fixture_helper.py", """
            raise RuntimeError("discovery must not import support modules")
        """)
        self.write("test_runner_fixture_notes.txt", "not a python test")

        ids = [test.id() for test in flatten(runner.discover(self.tests))]
        self.assertEqual(
            ids,
            [
                "test_runner_fixture_alpha.First.test_only",
                "test_runner_fixture_beta.Second.test_a",
                "test_runner_fixture_beta.Second.test_b",
            ],
        )

    def test_passing_and_skipped_cases_exit_zero_with_normal_counts(self) -> None:
        self.write("test_runner_fixture_outcomes.py", """
            import unittest
            class Outcomes(unittest.TestCase):
                def test_passes(self): pass
                def test_skips(self): self.skipTest("fixture skip")
        """)

        code, output = self.run_fixture()
        self.assertEqual(code, 0)
        self.assertIn("test_passes", output)
        self.assertIn("test_skips", output)
        self.assertIn("Ran 2 tests", output)
        self.assertIn("skipped=1", output)

    def test_failure_exits_one_and_keeps_the_failing_case_in_progress_log(self) -> None:
        self.write("test_runner_fixture_failure.py", """
            import unittest
            class Failure(unittest.TestCase):
                def test_fails(self): self.fail("fixture failure")
        """)

        code, output = self.run_fixture()
        self.assertEqual(code, 1)
        self.assertIn("test_fails", output)
        self.assertIn("FAILED (failures=1)", output)

    def test_watchdog_is_cancelled_when_discovery_raises(self) -> None:
        self.write("test_runner_fixture_ok.py", """
            import unittest
            class Ok(unittest.TestCase):
                def test_ok(self): pass
        """)

        with mock.patch.object(
            runner, "discover", side_effect=RuntimeError("fixture discovery error")
        ), mock.patch.object(faulthandler, "dump_traceback_later") as start, \
                mock.patch.object(faulthandler, "cancel_dump_traceback_later") as cancel:
            with self.assertRaisesRegex(RuntimeError, "fixture discovery error"):
                runner.run(self.tests, stream=io.StringIO())
        start.assert_called_once()
        cancel.assert_called_once_with()

    def test_periodic_dump_reports_stacks_without_locals_and_stops_after_run(
        self,
    ) -> None:
        self.write("test_runner_fixture_slow.py", """
            import time
            import unittest
            class Slow(unittest.TestCase):
                def test_slow(self):
                    local_secret = "runner-fixture-local-secret"
                    time.sleep(0.5)
                    self.assertTrue(local_secret)
        """)
        diagnostics = self.tests / "diagnostics.log"
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                _SUBPROCESS_DRIVER,
                str(self.tests),
                str(diagnostics),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["code"], 0)
        self.assertTrue(payload["stable"])
        self.assertIn("test_slow", completed.stderr)
        self.assertIn("in test_slow", payload["settled"])
        self.assertIn("most recent call first", payload["settled"])
        self.assertNotIn("runner-fixture-local-secret", payload["settled"])


if __name__ == "__main__":
    unittest.main()
