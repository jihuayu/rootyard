#!/usr/bin/env python3
"""Focused offline checks for the CI Python unittest diagnostics runner.

The repository's real unittest tree is not imported here. Temporary fixture
modules exercise discovery selection, verbose progress, skip/failure exits,
the periodic diagnostics lifecycle and fatal-handler ownership without Cargo,
a database, a container or a network.
"""
from __future__ import annotations

import hashlib
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
import threading
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_python_ci_tests", ROOT / "scripts" / "run_python_ci_tests.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

# Run the real Python diagnostics daemon in child processes. The CI runner
# already owns a live diagnostics thread while this suite runs, so a nested
# in-process thread is isolated from the outer test process.
_INNER_WATCHDOG_DRIVER = r"""
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
    # Let an in-flight dump settle, then prove the daemon stopped.
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

class _NoopDiagnostics:
    def start(self):
        pass

    def stop(self):
        pass

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
            diagnostics_factory=lambda interval, stream: _NoopDiagnostics(),
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
_MARKER = re.compile(
    rb"DSH-RUNNER-DIAG v=1 state=(START|DONE) "
    rb"ordinal=(\d{8}) test_sha256=([0-9a-f]{64})\n"
)


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
        # Inject a no-op diagnostics control: this fixture run must never
        # start a thread in the outer full-suite test process.
        watchdog = mock.Mock()
        factory = mock.Mock(return_value=watchdog)
        code = runner.run(
            self.tests,
            stream=output,
            diagnostics_factory=factory,
            enable_fatal_handler=mock.Mock(),
            disable_fatal_handler=mock.Mock(),
            is_fatal_handler_enabled=mock.Mock(return_value=True),
            marker_write=lambda payload: len(payload),
        )
        factory.assert_called_once_with(
            runner.TRACEBACK_INTERVAL_SECONDS, None
        )
        watchdog.start.assert_called_once_with()
        watchdog.stop.assert_called_once_with()
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

        watchdog = mock.Mock()
        factory = mock.Mock(return_value=watchdog)
        with mock.patch.object(
            runner, "discover", side_effect=RuntimeError("fixture discovery error")
        ):
            with self.assertRaisesRegex(RuntimeError, "fixture discovery error"):
                runner.run(
                    self.tests,
                    stream=io.StringIO(),
                    diagnostics_factory=factory,
                    enable_fatal_handler=mock.Mock(),
                    disable_fatal_handler=mock.Mock(),
                    is_fatal_handler_enabled=mock.Mock(return_value=True),
                    marker_write=lambda payload: len(payload),
                )
        watchdog.start.assert_called_once_with()
        watchdog.stop.assert_called_once_with()

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
            _INNER_WATCHDOG_DRIVER, self.tests, diagnostics
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["code"], 0)
        self.assertTrue(payload["stable"])
        self.assertIn("test_slow", completed.stderr)
        self.assertIn("state=PERIODIC", payload["settled"])
        self.assertIn('file="test_runner_fixture_slow.py"', payload["settled"])
        self.assertIn("function=test_slow", payload["settled"])
        self.assertIn("most recent call first", payload["settled"])
        self.assertNotIn("runner-fixture-local-secret", payload["settled"])
        self.assertNotIn("local_secret =", payload["settled"])

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


class PeriodicDiagnosticsTest(unittest.TestCase):
    """Pure checks for the Python-only periodic stack snapshot path."""

    @staticmethod
    def frame(
        filename: object, function: object, lineno: object, back: object = None
    ) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            f_code=types.SimpleNamespace(
                co_filename=filename, co_name=function
            ),
            f_lineno=lineno,
            f_back=back,
        )

    def test_snapshot_uses_basenames_and_omits_hostile_tokens(self) -> None:
        hostile = self.frame(
            "/private/secret/leak\nname.py",
            "bad\nfunction",
            "not-a-line",
        )
        allowed = self.frame(
            "/private/secret/allowed_module.py",
            "AllowedClass.test_case",
            7,
            back=hostile,
        )
        watchdog = runner._PeriodicDiagnostics(
            120, io.StringIO(), frames_snapshot=lambda: {12345: allowed}
        )
        payload = watchdog.render().decode("ascii")
        self.assertIn('file="allowed_module.py"', payload)
        self.assertIn("line=7", payload)
        self.assertIn("function=AllowedClass.test_case", payload)
        self.assertIn("function=<omitted>", payload)
        self.assertIn("line=0", payload)
        for forbidden in (
            "/private/secret",
            "leak",
            "name.py",
            "bad",
            "locals",
            "arguments",
        ):
            self.assertNotIn(forbidden, payload)

    def test_function_allowlist_accepts_known_code_names_only(self) -> None:
        self.assertEqual(runner._safe_function("<module>"), "<module>")
        self.assertEqual(runner._safe_function("<lambda>"), "<lambda>")
        self.assertEqual(
            runner._safe_function("AllowedClass.test_case"),
            "AllowedClass.test_case",
        )
        for hostile in (
            "<script>",
            "has space",
            "path/name",
            "x" * (runner.DIAGNOSTIC_MAX_FUNCTION_LENGTH + 1),
            17,
        ):
            self.assertEqual(
                runner._safe_function(hostile), runner.DIAGNOSTIC_OMITTED
            )

    def test_snapshot_bounds_threads_frames_and_bytes(self) -> None:
        frame = self.frame("module.py", "work", 1)
        frames = {
            ident: frame
            for ident in range(1, runner.DIAGNOSTIC_MAX_THREADS + 6)
        }
        watchdog = runner._PeriodicDiagnostics(
            120, io.StringIO(), frames_snapshot=lambda: frames
        )
        text = watchdog.render().decode("ascii")
        self.assertIn(f"threads={len(frames)}", text)
        self.assertIn(f"shown={runner.DIAGNOSTIC_MAX_THREADS}", text)
        self.assertIn("threads_truncated=", text)
        self.assertLessEqual(len(watchdog.render()), runner.DIAGNOSTIC_MAX_BYTES)

        deep = None
        for index in range(runner.DIAGNOSTIC_MAX_FRAMES + 5):
            deep = self.frame(
                "deep.py", f"level_{index}", index + 1, back=deep
            )
        deep_watchdog = runner._PeriodicDiagnostics(
            120, io.StringIO(), frames_snapshot=lambda: {1: deep}
        )
        deep_text = deep_watchdog.render().decode("ascii")
        self.assertEqual(
            deep_text.count('file="deep.py"'), runner.DIAGNOSTIC_MAX_FRAMES
        )
        self.assertIn("frames_truncated=1", deep_text)

        with mock.patch.object(runner, "DIAGNOSTIC_MAX_BYTES", 256):
            bounded = deep_watchdog.render()
        self.assertLessEqual(len(bounded), 256)
        self.assertTrue(bounded.endswith(runner.DIAGNOSTIC_TRUNCATED))

    def test_snapshot_excludes_the_calling_thread(self) -> None:
        frames = {
            1: self.frame("main.py", "main", 1),
            2: self.frame("other.py", "other", 2),
        }
        watchdog = runner._PeriodicDiagnostics(
            120, io.StringIO(), frames_snapshot=lambda: frames
        )
        text = watchdog.render(exclude_ident=2).decode("ascii")
        self.assertIn("threads=1", text)
        self.assertIn("thread id=1", text)
        self.assertNotIn("thread id=2", text)

    def test_single_daemon_thread_dumps_and_stops_cleanly(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.chunks: list[str] = []
                self.lock = threading.Lock()
                self.written = threading.Event()

            def write(self, text: str) -> None:
                with self.lock:
                    self.chunks.append(text)
                self.written.set()

            def flush(self) -> None:
                pass

            def text(self) -> str:
                with self.lock:
                    return "".join(self.chunks)

        sink = Sink()
        frames = {4242: self.frame("module.py", "work", 3)}
        watchdog = runner._PeriodicDiagnostics(
            0.02, sink, frames_snapshot=lambda: frames
        )
        watchdog.start()
        self.assertTrue(sink.written.wait(1.0))
        self.assertIsNotNone(watchdog._thread)
        assert watchdog._thread is not None
        self.assertTrue(watchdog._thread.daemon)
        watchdog.stop()
        self.assertFalse(watchdog._thread.is_alive())
        settled = sink.text()
        time.sleep(0.1)
        self.assertEqual(sink.text(), settled)
        self.assertIn("state=PERIODIC", settled)
        self.assertIn("thread id=4242", settled)

    def test_broken_sink_cannot_fail_the_suite(self) -> None:
        class Broken:
            def write(self, text: str) -> None:
                raise OSError("diagnostics sink unavailable")

            def flush(self) -> None:
                raise OSError("diagnostics sink unavailable")

        watchdog = runner._PeriodicDiagnostics(
            120, Broken(), frames_snapshot=lambda: {}
        )
        watchdog.dump_once()
        self.assertTrue(watchdog.failed)

    def test_default_run_does_not_use_the_faulthandler_periodic_timer(self) -> None:
        timer_error = AssertionError("periodic faulthandler timer must not be used")
        with (
            mock.patch.object(
                runner, "discover", return_value=unittest.TestSuite()
            ),
            mock.patch.object(
                runner.faulthandler,
                "dump_traceback_later",
                side_effect=timer_error,
            ),
            mock.patch.object(
                runner.faulthandler,
                "cancel_dump_traceback_later",
                side_effect=timer_error,
            ),
        ):
            code = runner.run(
                stream=io.StringIO(),
                watchdog_stream=io.StringIO(),
                is_fatal_handler_enabled=mock.Mock(return_value=True),
                marker_write=lambda payload: len(payload),
            )
        self.assertEqual(code, 5)

    def test_interval_keeps_the_120_second_default_and_stays_positive(self) -> None:
        self.assertEqual(
            runner._PeriodicDiagnostics(
                runner.TRACEBACK_INTERVAL_SECONDS
            ).interval,
            float(runner.TRACEBACK_INTERVAL_SECONDS),
        )
        self.assertGreaterEqual(
            runner._PeriodicDiagnostics(0).interval,
            runner.DIAGNOSTIC_MIN_INTERVAL_SECONDS,
        )


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
        self.watchdog = mock.Mock()
        self.watchdog.start.side_effect = lambda: self.events.append(
            ("watchdog_start", None)
        )
        self.watchdog.stop.side_effect = lambda: self.events.append(
            ("watchdog_stop", None)
        )
        self.watchdog_factory = mock.Mock(
            side_effect=lambda interval, stream: self._make_watchdog(
                interval, stream
            )
        )

    def _make_watchdog(self, interval: object, stream: object):
        self.events.append(("watchdog_factory", (interval, stream)))
        return self.watchdog

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
                diagnostics_factory=self.watchdog_factory,
                enable_fatal_handler=self.enable,
                disable_fatal_handler=self.disable,
                is_fatal_handler_enabled=self.is_enabled,
            )

    def test_handler_is_installed_before_discovery_and_removed_after(self) -> None:
        code = self.run_runner()
        self.assertEqual(code, 5)
        self.assertEqual(
            [name for name, _ in self.events],
            [
                "state",
                "enable",
                "watchdog_factory",
                "watchdog_start",
                "discover",
                "watchdog_stop",
                "disable",
            ],
        )
        self.enable.assert_called_once_with(all_threads=True)
        self.disable.assert_called_once_with()
        self.watchdog_factory.assert_called_once_with(
            runner.TRACEBACK_INTERVAL_SECONDS, None
        )
        self.watchdog.start.assert_called_once_with()
        self.watchdog.stop.assert_called_once_with()

    def test_preexisting_handler_is_left_untouched(self) -> None:
        code = self.run_runner(handler_enabled=True)
        self.assertEqual(code, 5)
        self.assertEqual(
            [name for name, _ in self.events],
            [
                "state",
                "watchdog_factory",
                "watchdog_start",
                "discover",
                "watchdog_stop",
            ],
        )
        self.enable.assert_not_called()
        self.disable.assert_not_called()

    def test_discovery_error_still_restores_the_owned_handler(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "fixture discovery error"):
            self.run_runner(discovery_error=RuntimeError("fixture discovery error"))
        self.assertEqual(
            [name for name, _ in self.events],
            [
                "state",
                "enable",
                "watchdog_factory",
                "watchdog_start",
                "discover",
                "watchdog_stop",
                "disable",
            ],
        )
        self.disable.assert_called_once_with()

    def test_handler_install_error_fails_before_discovery_and_timer(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "fixture enable error"):
            self.run_runner(enable_error=RuntimeError("fixture enable error"))
        self.assertEqual(
            [name for name, _ in self.events],
            ["state", "enable"],
        )
        self.watchdog_factory.assert_not_called()
        self.watchdog.start.assert_not_called()
        self.watchdog.stop.assert_not_called()
        self.disable.assert_not_called()


class MarkerSeamTest(unittest.TestCase):
    """Pure-mock checks for the bounded per-test marker seam."""

    def setUp(self) -> None:
        self.markers: list[bytes] = []
        self.output = io.StringIO()
        self.watchdog = mock.Mock()
        self.diagnostics_factory = mock.Mock(return_value=self.watchdog)
        self.enable_fatal = mock.Mock()
        self.disable_fatal = mock.Mock()
        self.is_fatal_enabled = mock.Mock(return_value=True)

    def write_marker(self, payload: bytes) -> int:
        self.markers.append(payload)
        return len(payload)

    def run_suite(self, suite: unittest.TestSuite, *, write=None, **options) -> int:
        with mock.patch.object(runner, "discover", return_value=suite):
            return runner.run(
                ROOT / "tests",
                stream=self.output,
                diagnostics_factory=self.diagnostics_factory,
                enable_fatal_handler=self.enable_fatal,
                disable_fatal_handler=self.disable_fatal,
                is_fatal_handler_enabled=self.is_fatal_enabled,
                marker_write=self.write_marker if write is None else write,
                **options,
            )

    def parsed_markers(self) -> list[tuple[str, int, str]]:
        parsed: list[tuple[str, int, str]] = []
        for payload in self.markers:
            match = _MARKER.fullmatch(payload)
            self.assertIsNotNone(match, payload)
            assert match is not None
            parsed.append(
                (
                    match.group(1).decode("ascii"),
                    int(match.group(2)),
                    match.group(3).decode("ascii"),
                )
            )
        return parsed

    def test_start_done_order_for_pass_fail_error_skip_and_subtest(self) -> None:
        class Pass(unittest.TestCase):
            def test_pass(self) -> None:
                pass

        class Fail(unittest.TestCase):
            def test_fail(self) -> None:
                self.fail("secret-failure-text")

        class Error(unittest.TestCase):
            def test_error(self) -> None:
                raise RuntimeError("secret-error-text")

        class Skip(unittest.TestCase):
            def test_skip(self) -> None:
                self.skipTest("secret-skip-text")

        class SubTest(unittest.TestCase):
            def test_subtests(self) -> None:
                with self.subTest(value="first"):
                    self.fail("secret-subtest-text")
                with self.subTest(value="second"):
                    pass

        cases = [
            Pass("test_pass"),
            Fail("test_fail"),
            Error("test_error"),
            Skip("test_skip"),
            SubTest("test_subtests"),
        ]
        code = self.run_suite(unittest.TestSuite(cases))

        self.assertEqual(code, 1)
        self.assertIn("Ran 5 tests", self.output.getvalue())
        self.assertIn(
            "FAILED (failures=2, errors=1, skipped=1)", self.output.getvalue()
        )

        parsed = self.parsed_markers()
        self.assertEqual(len(parsed), 10)
        self.assertEqual(
            [state for state, _, _ in parsed], ["START", "DONE"] * 5
        )
        self.assertEqual(
            [ordinal for _, ordinal, _ in parsed],
            [1, 1, 2, 2, 3, 3, 4, 4, 5, 5],
        )
        for index, case in enumerate(cases):
            expected = hashlib.sha256(
                case.id().encode("utf-8", "surrogatepass")
            ).hexdigest()
            self.assertEqual(parsed[index * 2][2], expected)
            self.assertEqual(parsed[index * 2 + 1][2], expected)

        joined = b"".join(self.markers)
        for case in cases:
            self.assertNotIn(
                case.id().encode("utf-8", "surrogatepass"), joined
            )
        for secret in (
            b"secret-failure-text",
            b"secret-error-text",
            b"secret-skip-text",
            b"secret-subtest-text",
        ):
            self.assertNotIn(secret, joined)
        for payload in self.markers:
            self.assertLessEqual(len(payload), runner.MARKER_MAX_BYTES)
        self.watchdog.start.assert_called_once_with()
        self.watchdog.stop.assert_called_once_with()

    def test_markers_preserve_success_and_skip_counts(self) -> None:
        class Outcomes(unittest.TestCase):
            def test_pass(self) -> None:
                pass

            def test_skip(self) -> None:
                self.skipTest("fixture skip")

        code = self.run_suite(
            unittest.TestSuite([Outcomes("test_pass"), Outcomes("test_skip")])
        )
        self.assertEqual(code, 0)
        self.assertIn("Ran 2 tests", self.output.getvalue())
        self.assertIn("skipped=1", self.output.getvalue())
        self.assertEqual(
            [state for state, _, _ in self.parsed_markers()],
            ["START", "DONE", "START", "DONE"],
        )

    def test_empty_selection_emits_no_marker_and_keeps_exit_five(self) -> None:
        code = self.run_suite(unittest.TestSuite())
        self.assertEqual(code, 5)
        self.assertEqual(self.markers, [])
        self.assertIn("Ran 0 tests", self.output.getvalue())

    def test_markers_are_written_immediately_around_the_test_body(self) -> None:
        events: list[str] = []

        class Body(unittest.TestCase):
            def test_body(self) -> None:
                events.append("body")

        def write(payload: bytes) -> int:
            match = _MARKER.fullmatch(payload)
            self.assertIsNotNone(match, payload)
            assert match is not None
            events.append(match.group(1).decode("ascii"))
            self.markers.append(payload)
            return len(payload)

        code = self.run_suite(
            unittest.TestSuite([Body("test_body")]), write=write
        )
        self.assertEqual(code, 0)
        self.assertEqual(events, ["START", "body", "DONE"])

    def test_untrusted_id_is_only_hashed_and_never_serialized(self) -> None:
        raw_id = (
            "untrusted\n"
            + "a" * 64
            + "\nDSH-RUNNER-DIAG v=1 state=START "
            + "ordinal=00000000 test_sha256="
            + "b" * 64
        )

        class Untrusted(unittest.TestCase):
            def id(self) -> str:
                return raw_id

            def runTest(self) -> None:
                pass

        code = self.run_suite(unittest.TestSuite([Untrusted("runTest")]))
        self.assertEqual(code, 0)
        self.assertEqual(len(self.markers), 2)
        expected = hashlib.sha256(
            raw_id.encode("utf-8", "surrogatepass")
        ).hexdigest()
        for payload in self.markers:
            self.assertNotIn(
                raw_id.encode("utf-8", "surrogatepass"), payload
            )
            self.assertEqual(payload.count(expected.encode("ascii")), 1)
            self.assertEqual(len(re.findall(rb"[0-9a-f]{64}", payload)), 1)
        self.assertEqual(
            [digest for _, _, digest in self.parsed_markers()],
            [expected, expected],
        )

    def test_marker_failure_fails_closed_without_changing_real_result(self) -> None:
        class Pass(unittest.TestCase):
            def test_pass(self) -> None:
                pass

        def broken(payload: bytes) -> int:
            raise OSError("marker sink unavailable")

        code = self.run_suite(
            unittest.TestSuite([Pass("test_pass")]), write=broken
        )
        self.assertEqual(code, 1)
        self.assertIn("Ran 1 test", self.output.getvalue())
        self.assertIn("OK", self.output.getvalue())
        self.watchdog.start.assert_called_once_with()
        self.watchdog.stop.assert_called_once_with()

    def test_marker_failure_does_not_mask_a_real_failure(self) -> None:
        class Fail(unittest.TestCase):
            def test_fail(self) -> None:
                self.fail("fixture failure")

        def broken(payload: bytes) -> int:
            raise OSError("marker sink unavailable")

        code = self.run_suite(
            unittest.TestSuite([Fail("test_fail")]), write=broken
        )
        self.assertEqual(code, 1)
        self.assertIn("FAILED (failures=1)", self.output.getvalue())

    def test_marker_failure_preserves_fatal_handler_cleanup(self) -> None:
        class Pass(unittest.TestCase):
            def test_pass(self) -> None:
                pass

        self.is_fatal_enabled.return_value = False

        def broken(payload: bytes) -> int:
            raise OSError("marker sink unavailable")

        code = self.run_suite(
            unittest.TestSuite([Pass("test_pass")]), write=broken
        )
        self.assertEqual(code, 1)
        self.enable_fatal.assert_called_once_with(all_threads=True)
        self.disable_fatal.assert_called_once_with()

    def test_marker_failure_cannot_turn_empty_selection_green(self) -> None:
        calls: list[bytes] = []

        def broken(payload: bytes) -> int:
            calls.append(payload)
            raise OSError("marker sink unavailable")

        code = self.run_suite(unittest.TestSuite(), write=broken)
        self.assertEqual(code, 5)
        self.assertEqual(calls, [])
        self.assertIn("Ran 0 tests", self.output.getvalue())

    def test_report_projects_checkout_counts_and_failed_test_hashes(self) -> None:
        class Cases(unittest.TestCase):
            def test_pass(self):
                pass

            def test_subtest(self):
                with self.subTest(value="private parameter"):
                    self.fail("private assertion")

            def test_error(self):
                raise RuntimeError("private exception")

            def test_skip(self):
                self.skipTest("private reason")

            @unittest.expectedFailure
            def test_expected_failure(self):
                self.fail("private expected failure")

            @unittest.expectedFailure
            def test_unexpected_success(self):
                pass

        commit, tree = "a" * 40, "b" * 40
        git = self.enterContext(mock.patch.object(
            runner.subprocess, "run", return_value=mock.Mock(stdout=f"{commit}\n{tree}\n".encode("ascii")),
        ))
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "results" / "report.json"
        cases = [Cases(name) for name in unittest.defaultTestLoader.getTestCaseNames(Cases)]
        code = self.run_suite(unittest.TestSuite(cases), report_out=path, expected_commit=commit)
        self.assertEqual(code, 1)
        self.assertEqual(git.call_args_list, [mock.call(
            ["git", "--no-replace-objects", "rev-parse", "HEAD^{commit}", "HEAD^{tree}"],
            cwd=runner.ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=5,
        )] * 2)
        data = path.read_bytes()
        self.assertLessEqual(len(data), runner.REPORT_MAX_BYTES)
        report = json.loads(data)
        elapsed_ms = report.pop("elapsed_ms")
        self.assertIs(type(elapsed_ms), int)
        self.assertTrue(0 <= elapsed_ms <= runner.REPORT_MAX_ELAPSED_MS)
        self.assertEqual(report, {
            "version": 1, "source_commit": commit, "source_tree": tree,
            "stage": "suite", "outcome": "failed", "exit_code": 1,
            "counts": {
                "tests_run": 6, "failures": 1, "errors": 1, "skipped": 1,
                "expected_failures": 1, "unexpected_successes": 1,
            },
            "cases": [
                {
                    "outcome": outcome,
                    "test_sha256": hashlib.sha256(Cases(name).id().encode()).hexdigest(),
                }
                for name, outcome in (
                    ("test_subtest", "failure"), ("test_error", "error"),
                    ("test_unexpected_success", "unexpected_success"),
                )
            ],
            "cases_truncated": False,
        })
        for case in cases:
            self.assertNotIn(case.id().encode(), data)
        self.assertNotIn(b"private", data)
        self.assertNotIn(str(root).encode(), data)

    def test_report_bounds_counts_elapsed_time_and_case_rows(self) -> None:
        class Fails(unittest.TestCase):
            def runTest(self):
                self.fail("private failure")

        commit, tree = "a" * 40, "b" * 40
        self.enterContext(mock.patch.object(runner, "_checkout_binding", return_value=(commit, tree)))
        self.enterContext(mock.patch.object(runner, "REPORT_MAX_COUNT", 16))
        end_ns = (runner.REPORT_MAX_ELAPSED_MS + 1) * 1_000_000
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "report.json"
        suite = unittest.TestSuite(Fails() for _ in range(runner.REPORT_MAX_CASES + 1))
        with mock.patch.object(runner.time, "monotonic_ns", side_effect=(0, end_ns)):
            self.assertEqual(self.run_suite(suite, report_out=path, expected_commit=commit), 1)
        data = path.read_bytes()
        self.assertLessEqual(len(data), runner.REPORT_MAX_BYTES)
        report = json.loads(data)
        self.assertEqual(report["elapsed_ms"], runner.REPORT_MAX_ELAPSED_MS)
        self.assertEqual(report["counts"]["tests_run"], 16)
        self.assertEqual(report["counts"]["failures"], 16)
        self.assertEqual(len(report["cases"]), runner.REPORT_MAX_CASES)
        self.assertTrue(report["cases_truncated"])

    def test_requested_report_failure_keeps_suite_exit_semantics(self) -> None:
        class Case(unittest.TestCase):
            def test_pass(self):
                pass

            def test_fail(self):
                self.fail("private failure")

        commit, tree = "a" * 40, "b" * 40
        self.enterContext(mock.patch.object(runner, "_checkout_binding", return_value=(commit, tree)))
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "report.json"
        path.mkdir()
        for cases, expected in (([Case("test_pass")], 1), ([Case("test_fail")], 1), ([], 5)):
            with self.subTest(expected=expected, cases=len(cases)):
                notice = io.StringIO()
                with mock.patch.object(runner.sys, "stderr", notice):
                    code = self.run_suite(unittest.TestSuite(cases), report_out=path, expected_commit=commit)
                self.assertEqual(code, expected)
                self.assertEqual(notice.getvalue(), "Python CI report unavailable\n")
                self.assertEqual(list(root.iterdir()), [path])

    def test_report_rejects_changed_checkout_without_skipping_the_suite(self) -> None:
        body = mock.Mock()

        class Pass(unittest.TestCase):
            def runTest(self):
                body()

        commit, tree = "a" * 40, "b" * 40
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "report.json"
        notice = io.StringIO()
        with (
            mock.patch.object(runner, "_checkout_binding", side_effect=((commit, tree), None)),
            mock.patch.object(runner.sys, "stderr", notice),
        ):
            code = self.run_suite(unittest.TestSuite([Pass()]), report_out=path, expected_commit=commit)
        self.assertEqual(code, 1)
        body.assert_called_once_with()
        self.assertFalse(path.exists())
        self.assertEqual(notice.getvalue(), "Python CI report unavailable\n")

    def test_requested_report_records_empty_and_discovery_exit_without_changing_them(self) -> None:
        commit, tree = "a" * 40, "b" * 40
        self.enterContext(mock.patch.object(runner, "_checkout_binding", return_value=(commit, tree)))
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "report.json"
        self.assertEqual(self.run_suite(unittest.TestSuite(), report_out=path, expected_commit=commit), 5)
        empty = json.loads(path.read_bytes())
        self.assertEqual((empty["stage"], empty["outcome"], empty["exit_code"]), ("suite", "empty", 5))

        error = RuntimeError("private discovery exception")
        with mock.patch.object(runner, "discover", side_effect=error), self.assertRaises(RuntimeError) as caught:
            runner.run(
                stream=self.output,
                diagnostics_factory=self.diagnostics_factory,
                is_fatal_handler_enabled=self.is_fatal_enabled,
                marker_write=self.write_marker,
                report_out=path,
                expected_commit=commit,
            )
        self.assertIs(caught.exception, error)
        data = path.read_bytes()
        report = json.loads(data)
        self.assertEqual((report["stage"], report["outcome"], report["exit_code"]), ("discovery", "incomplete", None))
        self.assertEqual(report["cases"], [])
        self.assertNotIn(b"private", data)

    def test_interrupted_suite_reports_outcomes_already_recorded(self) -> None:
        class Fail(unittest.TestCase):
            def runTest(self):
                self.fail("private failure")

        class InterruptedSuite(unittest.TestSuite):
            def run(self, result, debug=False):
                super().run(result, debug)
                raise KeyboardInterrupt

        commit, tree = "a" * 40, "b" * 40
        self.enterContext(mock.patch.object(runner, "_checkout_binding", return_value=(commit, tree)))
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "report.json"
        case = Fail()
        expected_hash = hashlib.sha256(case.id().encode()).hexdigest()
        with self.assertRaises(KeyboardInterrupt):
            self.run_suite(InterruptedSuite([case]), report_out=path, expected_commit=commit)
        report = json.loads(path.read_bytes())
        self.assertEqual((report["stage"], report["outcome"], report["exit_code"]), ("suite", "incomplete", None))
        self.assertEqual(report["counts"]["tests_run"], 1)
        self.assertEqual(report["cases"], [{"test_sha256": expected_hash, "outcome": "failure"}])
        self.watchdog.stop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
