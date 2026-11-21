#!/usr/bin/env python3
"""Hermetic partial-startup cleanup tests for the live benchmark (Refs #178).

Proxy, sampler, proxy listener, process and scratch collaborators are mocked.
No Git, HTTP, S3, PostgreSQL, proxy, process, server or network is created.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pack_compression_eval import capacity  # noqa: E402
from pack_compression_eval import e2e_serve_blob as e2e  # noqa: E402
from pack_compression_eval import live_server  # noqa: E402
from pack_compression_eval.cleanup_diagnostics import StopPostcondition  # noqa: E402
from pack_compression_eval.failure_diagnostics import (  # noqa: E402
    LiveEvalFailure,
    build_failure_record,
    finalize_cleanup,
    sanitize_s3_snapshot,
)

HEX64 = "a" * 64
HEX40 = "b" * 40


class PartialStartupCleanupTest(unittest.TestCase):
    def receipt_info(self, root: Path) -> dict:
        return {
            "path": str(root / "binary"),
            "sha256": HEX64,
            "size_bytes": 10,
            "receipt_verified": True,
            "receipt_sha256": HEX64,
            "workspace_commit": HEX40,
            "source_inputs_sha256": HEX64,
            "config_digest": HEX64,
            "receipt_schema": "rootyard/native-build-receipt/v2",
        }

    def run_startup(
        self,
        *,
        proxy_error: BaseException | None = None,
        sampler_error: BaseException | None = None,
    ) -> tuple[BaseException, mock.Mock, mock.Mock, mock.Mock]:
        with tempfile.TemporaryDirectory(prefix="pack-eval-startup-") as tmp:
            root = Path(tmp)
            work_root = root / "work"
            live = SimpleNamespace(
                s3_endpoint="http://127.0.0.1:1234",
                pg_base="postgresql://127.0.0.1/test",
                secrets=[],
            )
            proxy = mock.Mock()
            proxy.start.side_effect = proxy_error
            proxy.stop.return_value = StopPostcondition("proxy", True, "closed")
            proxy.snapshot.return_value = {"observed": True, "status_counts": {"503": 1}}
            sampler = mock.Mock()
            sampler.start.side_effect = sampler_error
            sampler.stop.return_value = StopPostcondition("sampler", True, "closed")
            remove_scratch = mock.Mock(return_value=True)
            with (
                mock.patch.object(e2e, "resolve_live_env", return_value=live),
                mock.patch.object(e2e, "verify_binary_receipt", return_value=self.receipt_info(root)),
                mock.patch.object(e2e, "S3MeterProxy", return_value=proxy),
                mock.patch.object(e2e, "ResourceSampler", return_value=sampler),
                mock.patch.object(e2e, "remove_tree_checked", remove_scratch),
            ):
                with self.assertRaises(BaseException) as caught:
                    e2e.run_live_serve_blob_eval(
                        "binary", "git", 178, "quick", True, work_root, False
                    )
            return caught.exception, proxy, sampler, remove_scratch

    def test_proxy_start_failure_stops_acquired_proxy_and_skips_unstarted_sampler(self) -> None:
        error, proxy, sampler, remove_scratch = self.run_startup(proxy_error=RuntimeError("thread start"))

        self.assertIsInstance(error, LiveEvalFailure)
        record = error.record
        self.assertFalse(record["passed"])
        self.assertEqual(record["phase"], "unknown")
        self.assertEqual(record["cleanup"]["proxy"]["status"], "ok")
        self.assertTrue(record["cleanup"]["proxy"]["stopped"])
        self.assertEqual(record["cleanup"]["sampler"]["status"], "not_needed")
        self.assertFalse(record["cleanup"]["sampler"]["attempted"])
        self.assertEqual(record["cleanup"]["psql"]["status"], "not_needed")
        self.assertEqual(record["cleanup"]["server"]["status"], "not_needed")
        self.assertEqual(record["cleanup"]["scratch"]["status"], "not_needed")
        self.assertFalse(record["cleanup"]["scratch"]["removed"])
        proxy.stop.assert_called_once_with()
        sampler.start.assert_not_called()
        sampler.stop.assert_not_called()
        remove_scratch.assert_not_called()
        self.assertNotIn("thread start", json.dumps(record, sort_keys=True))

    def test_sampler_start_failure_stops_both_acquired_resources(self) -> None:
        error, proxy, sampler, remove_scratch = self.run_startup(sampler_error=RuntimeError("sampler start"))

        self.assertIsInstance(error, LiveEvalFailure)
        record = error.record
        self.assertEqual(record["cleanup"]["proxy"]["status"], "ok")
        self.assertTrue(record["cleanup"]["proxy"]["stopped"])
        self.assertEqual(record["cleanup"]["sampler"]["status"], "ok")
        self.assertTrue(record["cleanup"]["sampler"]["stopped"])
        self.assertEqual(record["cleanup"]["scratch"]["status"], "not_needed")
        self.assertFalse(record["cleanup"]["scratch"]["removed"])
        proxy.stop.assert_called_once_with()
        sampler.stop.assert_called_once_with()
        remove_scratch.assert_not_called()
        self.assertNotIn("sampler start", json.dumps(record, sort_keys=True))

    def test_startup_base_exception_is_not_converted_to_success(self) -> None:
        error, proxy, _sampler, remove_scratch = self.run_startup(proxy_error=KeyboardInterrupt())

        self.assertIsInstance(error, KeyboardInterrupt)
        proxy.stop.assert_called_once_with()
        remove_scratch.assert_not_called()

    def test_constructor_partial_bind_closes_owned_listener(self) -> None:
        from pack_compression_eval import s3_meter

        class FailingSocket:
            def __init__(self) -> None:
                self.closed = False

            def setsockopt(self, *args) -> None:
                pass

            def bind(self, *args) -> None:
                raise OSError("bind failed")

            def close(self) -> None:
                self.closed = True

        owned = FailingSocket()
        with mock.patch.object(s3_meter.socket, "socket", return_value=owned):
            with self.assertRaises(OSError):
                s3_meter.S3MeterProxy("127.0.0.1", 1)
        self.assertTrue(owned.closed)

    def test_original_503_context_is_preserved_across_cleanup(self) -> None:
        original = LiveEvalFailure(
            build_failure_record(
                phase="baseline_seed_push",
                failure_class="git_push",
                archetype="text_history",
                object_format="sha1",
                config="baseline",
                git_returncode=128,
                http_status=503,
                completed={"baseline_seed_pushes_completed": 0},
                bindings={"binary_sha256": HEX64, "workspace_commit": HEX40},
            )
        )
        cleanup = e2e.run_cleanup_steps(
            stop_server=lambda: StopPostcondition("server", True, "reaped"),
            stop_proxy=lambda: StopPostcondition("proxy", True, "closed"),
            stop_sampler=lambda: StopPostcondition("sampler", True, "closed"),
            drop_schema=lambda: SimpleNamespace(returncode=0),
            remove_scratch=lambda: True,
        )
        finalize_cleanup(
            original,
            cleanup,
            s3=sanitize_s3_snapshot({"observed": True, "status_counts": {"503": 1}}),
            completed={"baseline_seed_pushes_completed": 0},
            last_completed_phase="live_setup",
            bindings={"binary_sha256": HEX64, "workspace_commit": HEX40},
        )
        self.assertEqual(original.record["phase"], "baseline_seed_push")
        self.assertEqual(original.record["failure_class"], "git_push")
        self.assertEqual(original.record["http_status"], 503)
        self.assertEqual(original.record["completed"]["baseline_seed_pushes_completed"], 0)
        self.assertEqual(original.record["bindings"]["binary_sha256"], HEX64)
        self.assertEqual(original.record["cleanup"]["failures"], [])


class _FakeLog:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _StartProc:
    pid = 111

    def __init__(self, poll_value: int | None = None) -> None:
        self.poll_value = poll_value
        self.terminated = False
        self.killed = False
        self.waits: list[float] = []

    def poll(self) -> int | None:
        return self.poll_value

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float) -> int:
        self.waits.append(timeout)
        return 0


class ServerOwnerTest(unittest.TestCase):
    def live(self) -> SimpleNamespace:
        return SimpleNamespace(
            s3_bucket="bucket",
            s3_region="region",
            s3_access_key="access",
            s3_secret_key="secret",
            s3_root="root",
            s3_session_token=None,
        )

    def start(
        self,
        *,
        proc: _StartProc | None = None,
        popen_error: BaseException | None = None,
        ready: bool = False,
    ):
        with tempfile.TemporaryDirectory(prefix="pack-eval-owner-") as tmp:
            root = Path(tmp)
            owner = live_server.ServeBlobOwner()
            log = _FakeLog()
            process = proc or _StartProc()
            ticks = iter([0.0, 0.0, 31.0])
            clock = SimpleNamespace(monotonic=lambda: next(ticks, 31.0), sleep=lambda _: None)
            with (
                mock.patch.object(live_server, "_pick_free_port", return_value=12345),
                mock.patch.object(live_server, "open", return_value=log, create=True),
                mock.patch.object(
                    live_server,
                    "http_json_timed",
                    return_value=(200, b"ready", {}, 1.0) if ready else (503, b"", {}, 1.0),
                ),
                mock.patch.object(live_server, "time", clock),
                mock.patch.object(live_server.subprocess, "Popen", return_value=process, side_effect=popen_error),
            ):
                try:
                    result = live_server.start_serve_blob(
                        "binary", "git", self.live(), "dsn", "http://s3",
                        root / "scratch", root / "server.log", owner=owner,
                    )
                except BaseException as caught:
                    return caught, owner, log, process, root
                return result, owner, log, process, root

    def test_popen_failure_closes_log_and_reports_finite_class(self) -> None:
        error, owner, log, _process, _root = self.start(popen_error=OSError("raw process text"))
        self.assertIsInstance(error, LiveEvalFailure)
        self.assertEqual(error.record["phase"], "live_setup")
        self.assertEqual(error.record["failure_class"], "popen_failed")
        self.assertFalse(owner.has_owner)
        self.assertTrue(log.closed)
        self.assertNotIn("raw process text", json.dumps(error.record, sort_keys=True))

    def test_readiness_failure_retains_owned_proc_and_open_log(self) -> None:
        proc = _StartProc()
        error, owner, log, _process, _root = self.start(proc=proc)
        self.assertIsInstance(error, LiveEvalFailure)
        self.assertEqual(error.record["failure_class"], "readiness_timeout")
        self.assertIs(owner.proc, proc)
        self.assertIs(owner.log_f, log)
        self.assertFalse(log.closed)

        outcome = owner.stop()
        self.assertFalse(outcome.stopped)
        self.assertEqual(outcome.reason, "poll_alive")
        self.assertTrue(owner.has_owner)
        self.assertFalse(log.closed)

    def test_early_exit_retains_owner_until_confirmed_reap(self) -> None:
        proc = _StartProc(poll_value=1)
        error, owner, log, _process, _root = self.start(proc=proc)
        self.assertIsInstance(error, LiveEvalFailure)
        self.assertEqual(error.record["failure_class"], "exited_early")
        self.assertIs(owner.proc, proc)
        self.assertFalse(log.closed)

        outcome = owner.stop()
        self.assertTrue(outcome.stopped)
        self.assertEqual(outcome.reason, "reaped")
        self.assertFalse(owner.has_owner)
        self.assertTrue(log.closed)

    def test_success_registers_owner_before_return(self) -> None:
        result, owner, log, proc, _root = self.start(ready=True)
        returned_proc, base_url, returned_log = result
        self.assertIs(returned_proc, proc)
        self.assertEqual(base_url, "http://127.0.0.1:12345")
        self.assertIs(returned_log, log)
        self.assertIs(owner.proc, proc)
        self.assertIs(owner.log_f, log)
        self.assertFalse(log.closed)

    def test_start_uses_checked_capacity_env_builder_not_a_literal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pack-eval-owner-capacity-") as tmp:
            root = Path(tmp)
            owner = live_server.ServeBlobOwner()
            log = _FakeLog()
            process = _StartProc()
            ticks = iter([0.0, 0.0, 31.0])
            clock = SimpleNamespace(monotonic=lambda: next(ticks, 31.0), sleep=lambda _: None)
            builder = mock.Mock(wraps=capacity.build_server_env)
            popen = mock.Mock(return_value=process)
            before = dict(os.environ)
            with (
                mock.patch.object(live_server, "_pick_free_port", return_value=12345),
                mock.patch.object(live_server, "open", return_value=log, create=True),
                mock.patch.object(live_server, "http_json_timed", return_value=(200, b"ready", {}, 1.0)),
                mock.patch.object(live_server, "time", clock),
                mock.patch.object(live_server, "build_server_env", builder),
                mock.patch.object(live_server.subprocess, "Popen", popen),
            ):
                live_server.start_serve_blob(
                    "binary", "git", self.live(), "dsn", "http://s3",
                    root / "scratch", root / "server.log", owner=owner,
                )
            builder.assert_called_once()
            self.assertIs(builder.call_args.args[0], os.environ)
            self.assertEqual(builder.call_args.args[1], capacity.derive_capacity_envelope())
            env = popen.call_args.kwargs["env"]
            self.assertEqual(env[capacity.REQUEST_ENV], "134217728")
            self.assertEqual(env[capacity.INFLIGHT_ENV], "436207616")
            self.assertEqual(dict(os.environ), before)

    def test_start_refuses_to_overwrite_existing_owner(self) -> None:
        owner = live_server.ServeBlobOwner()
        proc = _StartProc()
        log = _FakeLog()
        owner.register_proc(proc)
        owner.register_log(log)
        with self.assertRaises(LiveEvalFailure) as caught:
            live_server.start_serve_blob(
                "binary", "git", self.live(), "dsn", "http://s3",
                Path("/tmp/never-created"), Path("/tmp/never-opened.log"), owner=owner,
            )
        self.assertEqual(caught.exception.record["phase"], "cleanup")
        self.assertEqual(caught.exception.record["failure_class"], "cleanup_failure")
        self.assertIs(owner.proc, proc)
        self.assertIs(owner.log_f, log)
        self.assertFalse(log.closed)

    def test_baseline_restart_rejects_unreaped_owner_before_start(self) -> None:
        owner = live_server.ServeBlobOwner()
        owner.register_proc(_StartProc())
        owner.register_log(_FakeLog())
        start = mock.Mock(side_effect=AssertionError("replacement started"))
        with mock.patch.object(live_server, "kill_process_group", return_value=False):
            with self.assertRaises(LiveEvalFailure) as caught:
                live_server.restart_serve_blob(owner, start)
        self.assertEqual(caught.exception.record["phase"], "cleanup")
        self.assertEqual(caught.exception.record["failure_class"], "cleanup_failure")
        start.assert_not_called()
        self.assertTrue(owner.has_owner)

    def test_candidate_restart_rejects_unreaped_owner_before_start(self) -> None:
        owner = live_server.ServeBlobOwner()
        owner.register_proc(_StartProc())
        owner.register_log(_FakeLog())
        start = mock.Mock(side_effect=AssertionError("replacement started"))
        with mock.patch.object(live_server, "kill_process_group", return_value=False):
            with self.assertRaises(LiveEvalFailure):
                live_server.restart_serve_blob(owner, start)
        start.assert_not_called()
        self.assertTrue(owner.has_owner)

    def test_both_restart_callsites_use_owner_receipt_helper(self) -> None:
        tree = ast.parse(Path(e2e.__file__).read_text(encoding="utf-8"))
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    names.append(func.id)
                elif isinstance(func, ast.Attribute):
                    names.append(func.attr)
        self.assertEqual(names.count("restart_serve_blob"), 2)
        self.assertEqual(names.count("stop_serve_blob"), 0)
        self.assertEqual(names.count("start_serve_blob"), 1)

    def test_confirmed_reap_clears_old_owner_before_fresh_start(self) -> None:
        owner = live_server.ServeBlobOwner()
        old_log = _FakeLog()
        owner.register_proc(_StartProc(poll_value=0))
        owner.register_log(old_log)
        fresh_proc = _StartProc()
        fresh_log = _FakeLog()

        def start() -> str:
            self.assertFalse(owner.has_owner)
            owner.register_proc(fresh_proc)
            owner.register_log(fresh_log)
            return "fresh-owner"

        self.assertEqual(live_server.restart_serve_blob(owner, start), "fresh-owner")
        self.assertTrue(old_log.closed)
        self.assertIs(owner.proc, fresh_proc)
        self.assertIs(owner.log_f, fresh_log)


if __name__ == "__main__":
    unittest.main()
