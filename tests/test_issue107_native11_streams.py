#!/usr/bin/env python3
"""Pure fake-process tests for separate native11 capture streams."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import issue107_native11_inventory as inventory  # noqa: E402
import issue107_native11_runner as runner  # noqa: E402

SECRET = "SECRET_DO_NOT_SERIALIZE_7f91"
META_TARGET = runner.METADATA_REPLAY_TARGET
META_CASE = runner.METADATA_REPLAY_CASE


def frame(phase, site, event, ok="", status="", counts="", checks="",
          iteration="", error_kind=""):
    return "|".join([
        runner.METADATA_REPLAY_PREFIX,
        str(phase), str(site), str(event), ok, status, counts, checks,
        iteration, error_kind,
    ])


def summary(status="ok", passed=1, failed=0, ignored=0):
    return (f"test result: {status}. {passed} passed; {failed} failed; "
            f"{ignored} ignored; 0 measured; 0 filtered out; finished in 0.01s")


class FakePipe:
    def __init__(self, payload=b""):
        self.payload = payload
        self.closed = False

    def read(self, size):
        if self.closed or not self.payload:
            return b""
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0, timeout=False):
        self.stdout = FakePipe(stdout)
        self.stderr = FakePipe(stderr)
        self.returncode = returncode
        self.pid = 4242
        self.killed = False
        self.wait_calls = []
        self._running = True
        self._timeout = timeout
        self._timed_out = False

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if self._timeout and not self._timed_out:
            self._timed_out = True
            raise subprocess.TimeoutExpired("fake", timeout)
        self._running = False
        return self.returncode

    def poll(self):
        return None if self._running else self.returncode

    def kill(self):
        self.killed = True
        self._running = False


class FakeReader:
    def __init__(self, target, args):
        self.target = target
        self.args = args
        self.alive = True
        self.joined = []

    def run(self):
        self.target(*self.args)
        self.alive = False

    def join(self, timeout=None):
        self.joined.append(timeout)
        self.alive = False

    def is_alive(self):
        return self.alive


def synchronous_start(target, *args):
    reader = FakeReader(target, args)
    reader.run()
    return reader


class CaptureBudgetTests(unittest.TestCase):
    def test_stdout_and_stderr_share_one_total_capture_cap(self):
        with mock.patch.object(runner, "MAX_CAPTURE_BYTES", 32):
            capture = runner._BoundedCapture()
            capture.drain(io.BytesIO(b"a" * 20), capture.stdout)
            capture.drain(io.BytesIO(b"b" * 20), capture.stderr)
        self.assertEqual(bytes(capture.stdout), b"a" * 20)
        self.assertEqual(bytes(capture.stderr), b"b" * 12)
        self.assertEqual(len(capture.stdout) + len(capture.stderr), 32)
        self.assertTrue(capture.truncated)

    def test_join_readers_uses_one_aggregate_budget(self):
        readers = [FakeReader(None, ()), FakeReader(None, ())]
        with mock.patch.object(
                runner.time, "monotonic", side_effect=[100.0, 100.0, 102.0]):
            runner._join_readers(readers)
        self.assertEqual([reader.joined for reader in readers], [[5.0], [3.0]])
        self.assertFalse(any(reader.is_alive() for reader in readers))


class BoundedStreamTests(unittest.TestCase):
    def test_success_returns_stdout_only_and_starts_both_readers_first(self):
        process = FakeProcess(stdout=b"test a ... ok\n", stderr=b"diagnostic\n")
        started = []

        def start(target, *args):
            reader = FakeReader(target, args)
            reader.run()
            started.append(reader)
            return reader

        def wait(timeout=None):
            self.assertEqual(len(started), 2)
            process._running = False
            return 0

        process.wait = wait
        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader", side_effect=start):
            output = runner.run_bounded(["fake"], timeout=1)
        self.assertEqual(output, b"test a ... ok\n")
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_stderr_can_never_prefix_stdout(self):
        process = FakeProcess(stdout=b"", stderr=b"test phony ... ok\n")
        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader",
                               side_effect=synchronous_start):
            output = runner.run_bounded(["fake"], timeout=1)
        self.assertEqual(output, b"")

    def test_combined_streams_over_one_cap_fail_without_return(self):
        process = FakeProcess(stdout=b"a" * 10, stderr=b"b" * 10)
        with mock.patch.object(runner, "MAX_CAPTURE_BYTES", 16), \
             mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader",
                               side_effect=synchronous_start):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=1)
        self.assertEqual(raised.exception.code, "native_output_too_large")
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_timeout_keeps_group_kill_and_one_join_deadline(self):
        process = FakeProcess(stdout=b"", stderr=b"", returncode=-9, timeout=True)
        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader",
                               side_effect=synchronous_start), \
             mock.patch.object(runner.os, "getpgid", return_value=4242), \
             mock.patch.object(runner.os, "killpg"):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=0.01)
        self.assertEqual(raised.exception.code, "native_timeout")
        self.assertTrue(process.killed)
        self.assertEqual(process.wait_calls, [0.01, runner.KILL_WAIT_SECONDS])
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_partial_reader_start_cleans_process_and_started_reader(self):
        readers = []

        def start(target, *args):
            if readers:
                raise RuntimeError("second reader start failed")
            reader = FakeReader(target, args)
            reader.run()
            readers.append(reader)
            return reader

        process = FakeProcess(stdout=b"out", stderr=b"err")
        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader", side_effect=start), \
             mock.patch.object(runner.os, "getpgid", return_value=4242), \
             mock.patch.object(runner.os, "killpg"):
            with self.assertRaisesRegex(RuntimeError, "second reader start failed"):
                runner.run_bounded(["fake"], timeout=1)
        self.assertTrue(process.killed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual(len(readers), 1)
        self.assertTrue(readers[0].joined)
        self.assertFalse(readers[0].is_alive())

    def test_startup_failure_kills_reaps_joins_before_closing_pipes(self):
        events = []

        class OrderedPipe(FakePipe):
            def close(self):
                events.append(("close", process.killed))
                super().close()

        class OrderedReader(FakeReader):
            def join(self, timeout=None):
                events.append(("join", timeout))
                super().join(timeout)

        process = FakeProcess(stdout=b"out", stderr=b"err")
        process.stdout = OrderedPipe(b"out")
        process.stderr = OrderedPipe(b"err")
        process.stdout.process = process
        process.stderr.process = process
        original_kill = process.kill
        original_wait = process.wait

        def kill():
            events.append(("kill",))
            original_kill()

        def wait(timeout=None):
            events.append(("wait", timeout))
            return original_wait(timeout)

        process.kill = kill
        process.wait = wait
        readers = []

        def start(target, *args):
            if readers:
                raise RuntimeError("second reader start failed")
            reader = OrderedReader(target, args)
            readers.append(reader)
            return reader

        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader", side_effect=start), \
             mock.patch.object(runner.os, "getpgid", return_value=4242), \
             mock.patch.object(runner.os, "killpg"):
            with self.assertRaisesRegex(RuntimeError, "second reader start failed"):
                runner.run_bounded(["fake"], timeout=1)
        names = [event[0] for event in events]
        self.assertEqual(names, ["kill", "wait", "join", "close", "close"])
        self.assertTrue(all(event[1] for event in events if event[0] == "close"))
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual(len(readers), 1)

    def test_incomplete_startup_cleanup_preserves_primary_and_skips_close(self):
        class NeverReapProcess(FakeProcess):
            def wait(self, timeout=None):
                self.wait_calls.append(timeout)
                raise subprocess.TimeoutExpired("fake", timeout)

            def poll(self):
                return None

        class StuckReader(FakeReader):
            def join(self, timeout=None):
                self.joined.append(timeout)

        process = NeverReapProcess(stdout=b"out", stderr=b"err")
        readers = []

        def start(target, *args):
            if readers:
                raise RuntimeError("second reader start failed")
            reader = StuckReader(target, args)
            readers.append(reader)
            return reader

        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader", side_effect=start), \
             mock.patch.object(runner.os, "getpgid", return_value=4242), \
             mock.patch.object(runner.os, "killpg"):
            with self.assertRaisesRegex(RuntimeError, "second reader start failed"):
                runner.run_bounded(["fake"], timeout=1)
        self.assertEqual(process.wait_calls, [runner.KILL_WAIT_SECONDS])
        self.assertTrue(readers[0].joined)
        self.assertFalse(process.stdout.closed)
        self.assertFalse(process.stderr.closed)

    def test_normal_path_never_closes_while_a_reader_is_still_live(self):
        class StuckReader(FakeReader):
            def join(self, timeout=None):
                self.joined.append(timeout)

        process = FakeProcess(stdout=b"", stderr=b"", returncode=0)
        readers = []

        def start(target, *args):
            reader = StuckReader(target, args)
            readers.append(reader)
            return reader

        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader", side_effect=start):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(["fake"], timeout=1)
        self.assertEqual(raised.exception.code, "cleanup_unresolved")
        self.assertEqual(len(readers), 2)
        self.assertFalse(process.stdout.closed)
        self.assertFalse(process.stderr.closed)


    def test_execution_path_routes_rows_and_frames_to_their_own_streams(self):
        stdout = "\n".join([
            f"test {META_CASE} ... FAILED",
            summary("FAILED", 0, 1, 0),
        ]).encode()
        stderr = "\n".join([
            frame(18, 1, 0),
            frame(18, 1, 1, ok="0", status="409"),
            "thread 'x' panicked at tests/ref_store_pack_snapshots.rs:42:9:",
        ]).encode() + b"\n"
        process = FakeProcess(stdout, stderr=stderr, returncode=101)
        with mock.patch.object(runner.subprocess, "Popen", return_value=process), \
             mock.patch.object(runner, "_start_reader",
                               side_effect=synchronous_start):
            with self.assertRaises(runner.RunnerError) as raised:
                runner.run_bounded(
                    ["fake"], timeout=1,
                    failure_context={
                        "target": META_TARGET,
                        "phase": "run",
                        "selected_case": META_CASE,
                    })
        diag = raised.exception.diagnostic
        self.assertEqual(raised.exception.code, "native_process_failed")
        self.assertEqual([row["status"] for row in diag["cases"]], ["failed"])
        self.assertEqual(diag["case_counts"]["failed"], 1)
        self.assertEqual(diag["case_trace"]["primary"]["status"], 409)
        self.assertEqual(diag["source_locations"],
                         [{"file": "tests/ref_store_pack_snapshots.rs", "line": 42}])


class ProjectionStreamTests(unittest.TestCase):
    def project(self, stdout=b"", stderr=b"", **changes):
        options = {"phase": "run", "selected_case": META_CASE}
        options.update(changes)
        return runner.project_target_failure(
            META_TARGET, stdout, 101, stderr=stderr, **options)

    def test_stdout_success_row_and_stderr_frame_are_independent(self):
        stdout = (f"test {META_CASE} ... ok\n{summary()}\n").encode()
        stderr = "\n".join([
            frame(17, 1, 0),
            frame(17, 1, 1, ok="1"),
            frame(24, 1, 0),
            frame(24, 1, 1, ok="1"),
        ]).encode() + b"\n"
        runner.parse_case_result(stdout, META_CASE)
        diag = self.project(stdout, stderr)
        self.assertEqual([row["status"] for row in diag["cases"]], ["passed"])
        self.assertEqual(diag["libtest_summary"]["passed"], 1)
        self.assertTrue(diag["case_trace"]["known"])
        self.assertTrue(diag["case_trace"]["cleanup_completed"])
        with self.assertRaises(runner.RunnerError) as raised:
            runner.parse_case_result(stderr, META_CASE)
        self.assertEqual(raised.exception.code, "test_not_executed")

    def test_valid_stderr_frame_without_stdout_row_cannot_pass(self):
        stdout = (summary() + "\n").encode()
        stderr = "\n".join([
            frame(18, 1, 0),
            frame(18, 1, 1, ok="0", status="409"),
            frame(24, 1, 0),
            frame(24, 1, 1, ok="1"),
        ]).encode() + b"\n"
        with self.assertRaises(runner.RunnerError) as raised:
            runner.parse_case_result(stdout, META_CASE)
        self.assertEqual(raised.exception.code, "test_not_executed")
        diag = self.project(stdout, stderr)
        self.assertEqual(diag["cases"], [])
        self.assertEqual(diag["case_counts"]["passed"], 0)
        self.assertEqual(diag["case_trace"]["primary"]["status"], 409)
        self.assertTrue(diag["case_trace"]["cleanup_completed"])

    def test_stderr_phony_case_row_cannot_credit_case(self):
        stderr = (f"test {META_CASE} ... ok\n{summary()}\n").encode()
        diag = self.project(b"", stderr)
        self.assertEqual(diag["cases"], [])
        self.assertEqual(diag["case_counts"]["passed"], 0)
        with self.assertRaises(runner.RunnerError) as raised:
            runner.parse_case_result(b"", META_CASE)
        self.assertEqual(raised.exception.code, "test_not_executed")

    def test_stdout_metadata_frames_and_source_location_are_ignored(self):
        stdout = "\n".join([
            frame(17, 1, 0),
            frame(17, 1, 1, ok="1"),
            "thread 'x' panicked at tests/ref_store_operations.rs:9:1:",
        ]).encode() + b"\n"
        diag = self.project(stdout, b"")
        self.assertFalse(diag["case_trace"]["known"])
        self.assertEqual(diag["case_trace"]["frames"], 0)
        self.assertEqual(diag["source_locations"], [])

    def test_rejected_frames_and_safe_rebuild_never_retain_text(self):
        valid = self.project(
            stderr=(frame(17, 1, 0) + "\n" + frame(17, 1, 1, ok="1") + "\n").encode()
        )["case_trace"]
        self.assertTrue(valid["known"])
        unknown = dict(valid)
        unknown["unexpected"] = SECRET
        safe = runner._safe_metadata_replay_trace(unknown)
        self.assertTrue(safe["invalid"])
        self.assertNotIn(SECRET, json.dumps(safe, sort_keys=True))
        bad_frame = dict(valid)
        bad_frame["last_completed"] = dict(
            valid["last_completed"], unexpected=SECRET)
        self.assertTrue(
            runner._safe_metadata_replay_trace(bad_frame)["invalid"])
        boolean = dict(valid)
        boolean["frames"] = True
        self.assertTrue(runner._safe_metadata_replay_trace(boolean)["invalid"])
        negative = dict(valid)
        negative["frames"] = -1
        self.assertTrue(runner._safe_metadata_replay_trace(negative)["invalid"])

        malformed = [
            frame(17, 1, 0) + "\n" + frame(17, 1, 1, ok="1", status="600"),
            frame(17, 1, 0) + "\n" + frame(17, 2, 0),
            frame(17, 1, 0) + "\n" + frame(17, 1, 1, ok="1", status=SECRET),
        ]
        for payload in malformed:
            diag = self.project(stderr=(payload + "\n").encode())
            self.assertTrue(diag["case_trace"]["invalid"])
            self.assertNotIn(SECRET, json.dumps(diag, sort_keys=True))

    def test_metadata_gate_rejects_wrong_target_and_case(self):
        stderr = (frame(17, 1, 0) + "\n" + frame(17, 1, 1, ok="1") + "\n").encode()
        diag = runner.project_target_failure(
            "ref_store_operations", b"", 101, stderr=stderr,
            phase="run", selected_case=inventory.TARGETS[
                "ref_store_operations"]["cases"][0])
        self.assertIsNone(diag["case_trace"])
        diag = self.project(
            stderr=stderr,
            selected_case=inventory.TARGETS[META_TARGET]["cases"][1])
        self.assertIsNone(diag["case_trace"])


if __name__ == "__main__":
    unittest.main()
