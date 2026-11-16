#!/usr/bin/env python3
"""Hermetic partial-startup cleanup tests for the live benchmark (Refs #178).

Proxy, sampler, proxy listener, process and scratch collaborators are mocked.
No Git, HTTP, S3, PostgreSQL, proxy, process, server or network is created.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pack_compression_eval import e2e_serve_blob as e2e  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
