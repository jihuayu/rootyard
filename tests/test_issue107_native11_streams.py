#!/usr/bin/env python3
"""Pure fake-process tests for separate native11 capture streams."""
from __future__ import annotations

import io
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
import issue107_native11_runner as runner  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
