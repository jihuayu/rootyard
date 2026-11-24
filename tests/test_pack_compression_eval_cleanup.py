#!/usr/bin/env python3
"""Hermetic cleanup-preservation tests for the live benchmark (Refs #178).

All resources are fake callbacks.  No Git, HTTP, S3, PostgreSQL, proxy,
process, server or network operation is performed.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pack_compression_eval import live_server, pack_matrix, s3_meter  # noqa: E402
from pack_compression_eval.cleanup_diagnostics import (  # noqa: E402
    CLEANUP_FAILURE_CLASSES,
    StopPostcondition,
    remove_tree_checked,
    run_cleanup_steps,
    sanitize_cleanup,
)
from pack_compression_eval.failure_diagnostics import (  # noqa: E402
    LiveEvalFailure,
    build_failure_record,
    finalize_cleanup,
    sanitize_s3_snapshot,
)
from pack_compression_eval.s3_meter import S3MeterProxy  # noqa: E402
from pack_compression_eval.telemetry import ResourceSampler  # noqa: E402

SENTINEL = "SENTINEL_CLEANUP_7f3a91"
HEX64 = "a" * 64
HEX40 = "b" * 40


class CleanupStepTest(unittest.TestCase):
    def test_all_owned_steps_attempted_after_server_stop_failure(self) -> None:
        calls: list[str] = []

        def stop_server() -> None:
            calls.append("server")
            raise subprocess.TimeoutExpired("stop", 1)

        def stop_proxy() -> StopPostcondition:
            calls.append("proxy")
            return StopPostcondition("proxy", True, "closed")

        def stop_sampler() -> StopPostcondition:
            calls.append("sampler")
            return StopPostcondition("sampler", True, "closed")

        def drop_schema() -> SimpleNamespace:
            calls.append("psql")
            return SimpleNamespace(returncode=0)

        def remove_scratch() -> bool:
            calls.append("scratch")
            return True

        cleanup = run_cleanup_steps(
            stop_server=stop_server,
            stop_proxy=stop_proxy,
            stop_sampler=stop_sampler,
            drop_schema=drop_schema,
            remove_scratch=remove_scratch,
        )

        self.assertEqual(calls, ["server", "proxy", "sampler", "psql", "scratch"])
        self.assertTrue(cleanup["all_attempted"])
        self.assertEqual(cleanup["failures"], ["server_stop_timeout"])
        self.assertEqual(cleanup["server"]["status"], "failed")
        self.assertFalse(cleanup["server"]["reaped"])
        self.assertEqual(cleanup["proxy"]["status"], "ok")
        self.assertTrue(cleanup["proxy"]["stopped"])
        self.assertEqual(cleanup["sampler"]["status"], "ok")
        self.assertTrue(cleanup["sampler"]["stopped"])
        self.assertEqual(cleanup["psql"]["status"], "ok")
        self.assertTrue(cleanup["psql"]["completed"])
        self.assertEqual(cleanup["scratch"]["status"], "ok")
        self.assertTrue(cleanup["scratch"]["removed"])

    def test_psql_timeout_or_spawn_still_attempts_scratch(self) -> None:
        for error, expected_class in (
            (subprocess.TimeoutExpired("psql", 15), "psql_timeout"),
            (OSError(SENTINEL), "psql_spawn_error"),
        ):
            calls: list[str] = []

            def drop_schema(error=error) -> None:
                calls.append("psql")
                raise error

            def remove_scratch() -> bool:
                calls.append("scratch")
                return True

            cleanup = run_cleanup_steps(drop_schema=drop_schema, remove_scratch=remove_scratch)

            self.assertEqual(calls, ["psql", "scratch"])
            self.assertEqual(cleanup["failures"], [expected_class])
            self.assertTrue(cleanup["all_attempted"])
            self.assertEqual(cleanup["scratch"]["status"], "ok")
            self.assertTrue(cleanup["scratch"]["removed"])
            self.assertNotIn(SENTINEL, json.dumps(cleanup, sort_keys=True))

    def test_psql_nonzero_is_failure_and_scratch_still_attempted(self) -> None:
        calls: list[str] = []

        def drop_schema() -> SimpleNamespace:
            calls.append("psql")
            return SimpleNamespace(returncode=2)

        def remove_scratch() -> bool:
            calls.append("scratch")
            return True

        cleanup = run_cleanup_steps(drop_schema=drop_schema, remove_scratch=remove_scratch)

        self.assertEqual(calls, ["psql", "scratch"])
        self.assertEqual(cleanup["failures"], ["psql_nonzero"])
        self.assertFalse(cleanup["psql"]["completed"])
        self.assertTrue(cleanup["scratch"]["removed"])

    def test_multiple_cleanup_failures_are_bounded_and_redacted(self) -> None:
        def fail(label: str):
            def callback() -> None:
                raise RuntimeError(f"{SENTINEL}-{label}")
            return callback

        cleanup = run_cleanup_steps(
            stop_server=fail("server"),
            stop_proxy=fail("proxy"),
            stop_sampler=fail("sampler"),
            drop_schema=fail("psql"),
            remove_scratch=lambda: False,
        )

        self.assertEqual(
            cleanup["failures"],
            [
                "proxy_stop_error",
                "psql_error",
                "sampler_stop_error",
                "scratch_remaining",
                "server_stop_error",
            ],
        )
        self.assertTrue(set(cleanup["failures"]).issubset(CLEANUP_FAILURE_CLASSES))
        self.assertEqual(len(cleanup["failures"]), 5)
        self.assertFalse(cleanup["server"]["reaped"])
        self.assertFalse(cleanup["scratch"]["removed"])
        self.assertNotIn(SENTINEL, json.dumps(cleanup, sort_keys=True))

    def test_unowned_steps_are_never_attempted(self) -> None:
        cleanup = run_cleanup_steps()

        for step in ("server", "proxy", "sampler", "psql", "scratch"):
            self.assertEqual(cleanup[step]["status"], "not_needed")
            self.assertFalse(cleanup[step]["attempted"])
        self.assertEqual(cleanup["failures"], [])
        self.assertFalse(cleanup["attempted"])
        self.assertTrue(cleanup["all_attempted"])

    def test_sanitizer_drops_unknown_ids_and_sentinel(self) -> None:
        cleanup = sanitize_cleanup(
            {
                "attempted": True,
                "all_attempted": True,
                "failures": [SENTINEL, "psql_timeout"],
                "server": {"status": SENTINEL, "attempted": True, "reaped": True},
                "proxy": {"status": "ok", "attempted": True, "stopped": True},
                "sampler": {"status": "failed", "attempted": True, "stopped": True},
                "psql": {"status": "ok", "attempted": True, "completed": True},
                "scratch": {"status": "skipped", "attempted": False, "removed": True},
            }
        )

        self.assertEqual(cleanup["failures"], ["psql_timeout"])
        self.assertEqual(cleanup["server"]["status"], "not_needed")
        self.assertFalse(cleanup["server"]["reaped"])
        self.assertTrue(cleanup["proxy"]["stopped"])
        self.assertFalse(cleanup["sampler"]["stopped"])
        self.assertFalse(cleanup["scratch"]["removed"])
        self.assertNotIn(SENTINEL, json.dumps(cleanup, sort_keys=True))

    def test_remove_tree_checked_reports_removed_truthfully(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="pack-eval-cleanup-") as tmp:
            target = Path(tmp) / "owned"
            target.mkdir()
            self.assertTrue(remove_tree_checked(target))
            self.assertFalse(target.exists())
            self.assertTrue(remove_tree_checked(target))


class _FakeLog:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeProc:
    def __init__(self, polls: list[int | None], wait_error: BaseException | None = None) -> None:
        self._polls = iter(polls)
        self._wait_error = wait_error
        self.pid = 123
        self.terminated = False
        self.killed = False
        self.waits: list[float] = []

    def poll(self) -> int | None:
        try:
            return next(self._polls)
        except StopIteration:
            return None

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float) -> int:
        self.waits.append(timeout)
        if self._wait_error is not None:
            raise self._wait_error
        return 0


class _FakeListen:
    def __init__(self, close_fileno: int = -1) -> None:
        self.close_fileno = close_fileno
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def fileno(self) -> int:
        return self.close_fileno if self.closed else 4


class _FakeSocket:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeThread:
    def __init__(self, *, alive: bool = True, advance=None, stop_on_join: bool = False) -> None:
        self.alive = alive
        self.advance = advance
        self.stop_on_join = stop_on_join
        self.join_calls: list[float] = []

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float | None = None) -> None:
        self.join_calls.append(timeout)
        if self.advance is not None and timeout is not None:
            self.advance(timeout)
        if self.stop_on_join:
            self.alive = False


class StopPostconditionTest(unittest.TestCase):
    def test_server_stop_requires_actual_poll_reap(self) -> None:
        proc = _FakeProc([None, 0])
        log = _FakeLog()
        outcome = live_server.stop_serve_blob(proc, log)
        self.assertEqual(outcome, StopPostcondition("server", True, "reaped"))
        self.assertTrue(proc.terminated)
        self.assertTrue(log.closed)

    def test_server_wait_timeout_stays_incomplete_when_not_reaped(self) -> None:
        proc = _FakeProc([None, None], wait_error=subprocess.TimeoutExpired("stop", 5))
        log = _FakeLog()
        with mock.patch.object(live_server, "kill_process_group", return_value=False) as kill:
            outcome = live_server.stop_serve_blob(proc, log)
        self.assertEqual(outcome, StopPostcondition("server", False, "poll_alive"))
        self.assertFalse(log.closed)
        kill.assert_called_once_with(proc)

    def test_kill_process_group_returns_actual_poll_state(self) -> None:
        reaped = _FakeProc([0])
        with mock.patch.object(pack_matrix, "os", SimpleNamespace(name="nt")):
            self.assertTrue(pack_matrix.kill_process_group(reaped))
        self.assertTrue(reaped.killed)

        not_reaped = _FakeProc([None], wait_error=subprocess.TimeoutExpired("stop", 5))
        with mock.patch.object(pack_matrix, "os", SimpleNamespace(name="nt")):
            self.assertFalse(pack_matrix.kill_process_group(not_reaped))

    def test_proxy_stop_uses_aggregate_deadline_and_alive_set(self) -> None:
        clock = [0.0]

        def advance(timeout: float) -> None:
            clock[0] += timeout

        proxy = S3MeterProxy.__new__(S3MeterProxy)
        proxy._stop = threading.Event()
        proxy._lock = threading.Lock()
        proxy._listen = _FakeListen()
        proxy._sockets = {_FakeSocket(), _FakeSocket()}
        proxy._accept_thread = _FakeThread(advance=advance)
        proxy._threads = [_FakeThread(advance=advance)]
        with mock.patch.object(s3_meter, "time", SimpleNamespace(monotonic=lambda: clock[0])):
            outcome = proxy.stop()

        self.assertEqual(outcome, StopPostcondition("proxy", False, "thread_alive"))
        self.assertTrue(proxy._listen.closed)
        self.assertTrue(all(item.closed for item in proxy._sockets))
        self.assertEqual(proxy._accept_thread.join_calls, [2.0])
        self.assertEqual(proxy._threads[0].join_calls, [])
        self.assertEqual(clock[0], 2.0)

    def test_proxy_stop_reports_closed_after_threads_exit(self) -> None:
        proxy = S3MeterProxy.__new__(S3MeterProxy)
        proxy._stop = threading.Event()
        proxy._lock = threading.Lock()
        proxy._listen = _FakeListen()
        proxy._sockets = {_FakeSocket()}
        proxy._accept_thread = _FakeThread(stop_on_join=True)
        proxy._threads = [_FakeThread(stop_on_join=True)]
        outcome = proxy.stop()
        self.assertEqual(outcome, StopPostcondition("proxy", True, "closed"))
        self.assertTrue(proxy._listen.closed)
        self.assertTrue(all(item.closed for item in proxy._sockets))

    def test_sampler_stop_checks_thread_liveness(self) -> None:
        alive = ResourceSampler([])
        alive._thread = _FakeThread()
        alive.sample_once = lambda: None  # type: ignore[method-assign]
        self.assertEqual(alive.stop(), StopPostcondition("sampler", False, "thread_alive"))

        stopped = ResourceSampler([])
        stopped._thread = _FakeThread(stop_on_join=True)
        stopped.sample_once = lambda: None  # type: ignore[method-assign]
        self.assertEqual(stopped.stop(), StopPostcondition("sampler", True, "closed"))

        unstarted = ResourceSampler([])
        unstarted.sample_once = lambda: None  # type: ignore[method-assign]
        self.assertEqual(unstarted.stop(), StopPostcondition("sampler", True, "not_started"))

    def test_void_or_incomplete_stop_is_not_success(self) -> None:
        cleanup = run_cleanup_steps(
            stop_server=lambda: None,
            stop_proxy=lambda: True,
            stop_sampler=lambda: StopPostcondition("sampler", False, "thread_alive"),
            drop_schema=lambda: SimpleNamespace(returncode=0),
            remove_scratch=lambda: True,
        )
        self.assertEqual(
            cleanup["failures"],
            ["proxy_stop_unverified", "sampler_stop_incomplete", "server_stop_unverified"],
        )
        self.assertFalse(cleanup["server"]["reaped"])
        self.assertFalse(cleanup["proxy"]["stopped"])
        self.assertFalse(cleanup["sampler"]["stopped"])
        self.assertTrue(cleanup["psql"]["completed"])
        self.assertTrue(cleanup["scratch"]["removed"])


class FailurePreservationTest(unittest.TestCase):
    def bindings(self) -> dict:
        return {
            "receipt_verified": True,
            "binary_sha256": HEX64,
            "binary_size_bytes": 10,
            "receipt_sha256": HEX64,
            "workspace_commit": HEX40,
            "source_inputs_sha256": HEX64,
            "config_digest": HEX64,
            "receipt_schema": "rootyard/native-build-receipt/v2",
        }

    def failing_cleanup(self) -> dict:
        return run_cleanup_steps(
            stop_server=lambda: (_ for _ in ()).throw(subprocess.TimeoutExpired("stop", 1)),
            stop_proxy=lambda: StopPostcondition("proxy", True, "closed"),
            stop_sampler=lambda: StopPostcondition("sampler", True, "closed"),
            drop_schema=lambda: SimpleNamespace(returncode=0),
            remove_scratch=lambda: True,
        )

    def test_original_push_failure_is_preserved_when_server_stop_fails(self) -> None:
        original = LiveEvalFailure(
            build_failure_record(
                phase="baseline_seed_push",
                failure_class="git_push",
                archetype="text_history",
                object_format="sha1",
                config="baseline",
                repo_ordinal=0,
                git_returncode=128,
                http_status=503,
                elapsed_ms=12.5,
                completed={"baseline_seed_pushes_completed": 0},
                bindings=self.bindings(),
            )
        )
        before = json.loads(json.dumps(original.record, sort_keys=True))
        cleanup = self.failing_cleanup()

        finalize_cleanup(
            original,
            cleanup,
            s3=sanitize_s3_snapshot({"observed": True, "status_counts": {"503": 1}}),
            completed={"baseline_seed_pushes_completed": 0},
            last_completed_phase="live_setup",
            bindings=self.bindings(),
        )

        for key in ("phase", "failure_class", "http_status", "http_subphase", "git_returncode", "elapsed_ms", "bindings"):
            self.assertEqual(original.record[key], before[key])
        self.assertEqual(original.record["phase"], "baseline_seed_push")
        self.assertEqual(original.record["http_status"], 503)
        self.assertEqual(original.record["cleanup"]["failures"], ["server_stop_timeout"])
        self.assertFalse(original.record["cleanup"]["server"]["reaped"])
        self.assertTrue(original.record["cleanup"]["proxy"]["stopped"])
        self.assertTrue(original.record["cleanup"]["sampler"]["stopped"])
        self.assertTrue(original.record["cleanup"]["psql"]["completed"])
        self.assertTrue(original.record["cleanup"]["scratch"]["removed"])
        self.assertNotIn(SENTINEL, json.dumps(original.record, sort_keys=True))

    def test_cleanup_only_failure_raises_failed_live_eval_failure(self) -> None:
        cleanup = self.failing_cleanup()
        with self.assertRaises(LiveEvalFailure) as caught:
            finalize_cleanup(
                None,
                cleanup,
                s3=sanitize_s3_snapshot({"observed": True}),
                completed={"baseline_seed_pushes_completed": 1},
                last_completed_phase="baseline_seed_push",
                bindings=self.bindings(),
            )

        record = caught.exception.record
        self.assertFalse(record["passed"])
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["phase"], "cleanup")
        self.assertEqual(record["failure_class"], "cleanup_failure")
        self.assertIsNone(record["http_status"])
        self.assertEqual(record["cleanup"]["failures"], ["server_stop_timeout"])
        self.assertNotIn(SENTINEL, json.dumps(record, sort_keys=True))

    def test_healthy_cleanup_does_not_fail_success(self) -> None:
        cleanup = run_cleanup_steps(
            stop_server=lambda: StopPostcondition("server", True, "reaped"),
            stop_proxy=lambda: StopPostcondition("proxy", True, "closed"),
            stop_sampler=lambda: StopPostcondition("sampler", True, "closed"),
            drop_schema=lambda: SimpleNamespace(returncode=0),
            remove_scratch=lambda: True,
        )
        finalize_cleanup(
            None,
            cleanup,
            s3={},
            completed={},
            last_completed_phase="completed",
            bindings={},
        )
        self.assertEqual(cleanup["failures"], [])
        self.assertTrue(cleanup["all_attempted"])

    def test_base_exception_is_not_converted_to_success_or_failure(self) -> None:
        stop = KeyboardInterrupt(SENTINEL)
        cleanup = self.failing_cleanup()
        self.assertIsNone(
            finalize_cleanup(
                stop,
                cleanup,
                s3={},
                completed={},
                last_completed_phase="live_setup",
                bindings={},
            )
        )
        self.assertNotIn(SENTINEL, json.dumps(cleanup, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
