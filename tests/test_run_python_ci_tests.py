#!/usr/bin/env python3
"""Focused offline checks for the CI Python unittest diagnostics runner.

The repository's real unittest tree is not imported here. Temporary fixture
modules exercise discovery selection, verbose progress, skip/failure exits and
faulthandler cleanup without Cargo, a database, a container or a network.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
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

# Run the real faulthandler timer in child processes.  The CI runner already
# owns the process-global timer while this suite runs, so a nested in-process
# dump/cancel would silently disable the outer diagnostics.
_INNER_TIMER_DRIVER = r"""
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

_OUTER_TIMER_DRIVER = r"""
import faulthandler
import importlib.util
import json
from pathlib import Path
import sys
import time

runner_path = Path(sys.argv[1])
tests_dir = Path(sys.argv[2])
outer_path = Path(sys.argv[3])
spec = importlib.util.spec_from_file_location("run_python_ci_tests", runner_path)
assert spec is not None and spec.loader is not None
child_runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(child_runner)
with outer_path.open("w+", encoding="utf-8") as outer:
    faulthandler.dump_traceback_later(0.05, repeat=True, file=outer)
    try:
        code = child_runner.run(
            tests_dir,
            stream=sys.stderr,
            start_timer=lambda *args, **kwargs: None,
            stop_timer=lambda: None,
        )
        # The nested run must leave this outer timer alive and repeating.
        before = outer_path.stat().st_size
        time.sleep(0.3)
        after = outer_path.stat().st_size
        outer_tail = outer_path.read_text(encoding="utf-8")
    finally:
        faulthandler.cancel_dump_traceback_later()
print(json.dumps({
    "code": code,
    "outer_grew": after > before,
    "outer_tail": outer_tail,
}))
"""

_STARTED_TEST = re.compile(r"^\S+ \(([^)]+)\) \.\.\. ", re.MULTILINE)


def started_test_ids(output: str) -> list[str]:
    return _STARTED_TEST.findall(output)


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
        # Inject timer callbacks: this fixture run must never touch the real
        # process-global watchdog owned by the outer full-suite runner.
        start = mock.Mock()
        stop = mock.Mock()
        code = runner.run(
            self.tests,
            stream=output,
            start_timer=start,
            stop_timer=stop,
            enable_fatal_handler=mock.Mock(),
            disable_fatal_handler=mock.Mock(),
            is_fatal_handler_enabled=mock.Mock(return_value=True),
        )
        self.assertEqual(stop.call_count, 1)
        self.assertEqual(
            start.call_args.args, (runner.TRACEBACK_INTERVAL_SECONDS,)
        )
        self.assertTrue(start.call_args.kwargs["repeat"])
        self.assertIs(start.call_args.kwargs["file"], sys.stderr)
        return code, output.getvalue()

    def run_child(
        self,
        driver: str,
        *args: object,
        cwd: Path = ROOT,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", driver, *(str(arg) for arg in args)],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def make_fake_repo(self) -> Path:
        fake = self.tests / "fake_repo"
        (fake / "scripts").mkdir(parents=True)
        (fake / "tests").mkdir()
        shutil.copyfile(
            ROOT / "scripts" / "run_python_ci_tests.py",
            fake / "scripts" / "run_python_ci_tests.py",
        )
        return fake

    def run_cli_pair(
        self, fake: Path
    ) -> tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]]:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        old = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
                "-v",
            ],
            cwd=fake,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        new = subprocess.run(
            [sys.executable, "scripts/run_python_ci_tests.py"],
            cwd=fake,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return old, new

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

    def test_import_failure_is_not_swallowed_and_exits_one(self) -> None:
        self.write("test_runner_fixture_broken.py", """
            import missing_runner_fixture_dependency
        """)

        code, output = self.run_fixture()
        self.assertEqual(code, 1)
        self.assertIn("test_runner_fixture_broken", output)
        self.assertIn("ModuleNotFoundError", output)

    def test_watchdog_is_cancelled_when_discovery_raises(self) -> None:
        self.write("test_runner_fixture_ok.py", """
            import unittest
            class Ok(unittest.TestCase):
                def test_ok(self): pass
        """)

        start = mock.Mock()
        stop = mock.Mock()
        with mock.patch.object(
            runner, "discover", side_effect=RuntimeError("fixture discovery error")
        ):
            with self.assertRaisesRegex(RuntimeError, "fixture discovery error"):
                runner.run(
                    self.tests,
                    stream=io.StringIO(),
                    start_timer=start,
                    stop_timer=stop,
                    enable_fatal_handler=mock.Mock(),
                    disable_fatal_handler=mock.Mock(),
                    is_fatal_handler_enabled=mock.Mock(return_value=True),
                )
        start.assert_called_once()
        stop.assert_called_once_with()

    def test_entrypoint_restores_repo_root_imports_and_matches_old_discovery(
        self,
    ) -> None:
        fake = self.make_fake_repo()
        (fake / "tests" / "e2e.py").write_text(
            "class Harness:\n    marker = 'repo-root-import-ok'\n",
            encoding="utf-8",
        )
        (fake / "tests" / "test_import_context_alpha.py").write_text(
            textwrap.dedent("""
                import unittest
                from tests.e2e import Harness

                class Alpha(unittest.TestCase):
                    def test_repo_root_import(self):
                        self.assertEqual(Harness.marker, "repo-root-import-ok")

                    def test_second(self):
                        pass
            """),
            encoding="utf-8",
        )
        (fake / "tests" / "test_import_context_beta.py").write_text(
            textwrap.dedent("""
                import unittest

                class Beta(unittest.TestCase):
                    def test_beta(self):
                        pass
            """),
            encoding="utf-8",
        )

        old, new = self.run_cli_pair(fake)

        self.assertEqual(old.returncode, 0, old.stderr)
        self.assertEqual(new.returncode, 0, new.stderr)
        old_ids = started_test_ids(old.stderr)
        new_ids = started_test_ids(new.stderr)
        self.assertEqual(new_ids, old_ids)
        self.assertEqual(
            new_ids,
            [
                "test_import_context_alpha.Alpha.test_repo_root_import",
                "test_import_context_alpha.Alpha.test_second",
                "test_import_context_beta.Beta.test_beta",
            ],
        )

    def test_empty_selection_matches_unittest_exit_five(self) -> None:
        fake = self.make_fake_repo()
        (fake / "tests" / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")

        old, new = self.run_cli_pair(fake)
        self.assertEqual(old.returncode, 5, old.stderr)
        self.assertEqual(new.returncode, old.returncode, new.stderr)
        self.assertIn("Ran 0 tests", new.stderr)
        self.assertIn("NO TESTS RAN", new.stderr)

    def test_all_skipped_selection_matches_unittest_success(self) -> None:
        fake = self.make_fake_repo()
        (fake / "tests" / "test_skipped.py").write_text(
            textwrap.dedent("""
                import unittest

                class MethodSkip(unittest.TestCase):
                    @unittest.skip("fixture method skip")
                    def test_method_skipped(self):
                        pass

                @unittest.skip("fixture class skip")
                class ClassSkip(unittest.TestCase):
                    def test_class_skipped(self):
                        pass
            """),
            encoding="utf-8",
        )

        old, new = self.run_cli_pair(fake)
        self.assertEqual(old.returncode, 0, old.stderr)
        self.assertEqual(new.returncode, old.returncode, new.stderr)
        self.assertEqual(new.returncode, 0)
        self.assertIn("Ran 2 tests", new.stderr)
        self.assertIn("skipped=2", new.stderr)
        self.assertNotIn("NO TESTS RAN", new.stderr)

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
        completed = self.run_child(
            _INNER_TIMER_DRIVER, self.tests, diagnostics
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["code"], 0)
        self.assertTrue(payload["stable"])
        self.assertIn("test_slow", completed.stderr)
        self.assertIn("in test_slow", payload["settled"])
        self.assertIn("most recent call first", payload["settled"])
        self.assertNotIn("runner-fixture-local-secret", payload["settled"])

    def test_nested_run_does_not_cancel_an_outer_periodic_watchdog(self) -> None:
        self.write("test_runner_fixture_inner.py", """
            import unittest
            class Inner(unittest.TestCase):
                def test_inner(self): pass
        """)
        outer = self.tests / "outer.log"
        completed = self.run_child(
            _OUTER_TIMER_DRIVER,
            ROOT / "scripts" / "run_python_ci_tests.py",
            self.tests,
            outer,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["code"], 0)
        self.assertTrue(payload["outer_grew"])
        self.assertIn("most recent call first", payload["outer_tail"])


class FatalHandlerSeamTest(unittest.TestCase):
    """Pure-mock checks for the fatal-handler ownership seam.

    The real ``faulthandler.enable``/``disable`` functions are never called;
    the outer full-suite runner owns the process-global handler.
    """

    def setUp(self) -> None:
        self.events: list[tuple[str, object]] = []
        self.enable = mock.Mock()
        self.disable = mock.Mock(
            side_effect=lambda: self.events.append(("disable", None))
        )
        self.is_enabled = mock.Mock()
        self.start_timer = mock.Mock(
            side_effect=lambda *args, **kwargs: self.events.append(
                ("timer_start", (args, kwargs))
            )
        )
        self.stop_timer = mock.Mock(
            side_effect=lambda: self.events.append(("timer_stop", None))
        )

    def run_runner(
        self,
        *,
        handler_enabled: bool = False,
        discovery_error: Exception | None = None,
        enable_error: Exception | None = None,
    ) -> int:
        def state() -> bool:
            self.events.append(("state", None))
            return handler_enabled

        def enable(**kwargs: object) -> None:
            self.events.append(("enable", kwargs))
            if enable_error is not None:
                raise enable_error

        def discovery(tests_dir: Path) -> unittest.TestSuite:
            self.events.append(("discover", None))
            if discovery_error is not None:
                raise discovery_error
            return unittest.TestSuite()

        self.is_enabled.side_effect = state
        self.enable.side_effect = enable
        with mock.patch.object(runner, "discover", side_effect=discovery):
            return runner.run(
                ROOT / "tests",
                stream=io.StringIO(),
                start_timer=self.start_timer,
                stop_timer=self.stop_timer,
                enable_fatal_handler=self.enable,
                disable_fatal_handler=self.disable,
                is_fatal_handler_enabled=self.is_enabled,
            )

    def test_handler_is_installed_before_discovery_and_removed_after(self) -> None:
        code = self.run_runner()
        self.assertEqual(code, 5)
        self.assertEqual(
            [name for name, _ in self.events],
            ["state", "enable", "timer_start", "discover", "timer_stop", "disable"],
        )
        self.enable.assert_called_once_with(all_threads=True)
        self.disable.assert_called_once_with()
        self.start_timer.assert_called_once()
        self.assertEqual(
            self.start_timer.call_args.args, (runner.TRACEBACK_INTERVAL_SECONDS,)
        )
        self.assertTrue(self.start_timer.call_args.kwargs["repeat"])
        self.assertIs(self.start_timer.call_args.kwargs["file"], sys.stderr)
        self.stop_timer.assert_called_once_with()

    def test_preexisting_handler_is_left_untouched(self) -> None:
        code = self.run_runner(handler_enabled=True)
        self.assertEqual(code, 5)
        self.assertEqual(
            [name for name, _ in self.events],
            ["state", "timer_start", "discover", "timer_stop"],
        )
        self.enable.assert_not_called()
        self.disable.assert_not_called()

    def test_discovery_error_still_restores_the_owned_handler(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "fixture discovery error"):
            self.run_runner(discovery_error=RuntimeError("fixture discovery error"))
        self.assertEqual(
            [name for name, _ in self.events],
            ["state", "enable", "timer_start", "discover", "timer_stop", "disable"],
        )
        self.disable.assert_called_once_with()

    def test_handler_install_error_fails_before_discovery_and_timer(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "fixture enable error"):
            self.run_runner(enable_error=RuntimeError("fixture enable error"))
        self.assertEqual(
            [name for name, _ in self.events],
            ["state", "enable"],
        )
        self.start_timer.assert_not_called()
        self.stop_timer.assert_not_called()
        self.disable.assert_not_called()


if __name__ == "__main__":
    unittest.main()
