#!/usr/bin/env python3
"""Pure boundary tests for the bounded root blob S3 forward gate."""
from __future__ import annotations

import sys
import threading
import time
import unittest
from io import BytesIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "blob_gateway_support"))
import root_blob_fault_gate as fixture_gate
from root_blob_fault_gate import MAX_REQUEST_BYTES, RootBlobFaultGate


class EndpointTests(unittest.TestCase):
    def test_loopback_http_origin_is_accepted(self):
        self.assertEqual(RootBlobFaultGate.validate_endpoint("http://127.0.0.1:9000"), ("127.0.0.1", 9000))
        self.assertEqual(RootBlobFaultGate.validate_endpoint("http://localhost"), ("localhost", 80))

    def test_https_nonloopback_credentials_path_and_query_are_rejected(self):
        for endpoint in (
            "https://127.0.0.1:9000",
            "http://10.0.0.1:9000",
            "http://user:pass@127.0.0.1:9000",
            "http://127.0.0.1:9000/root",
            "http://127.0.0.1:9000?x=1",
            "http://127.0.0.1:9000#frag",
        ):
            with self.assertRaises(ValueError, msg=endpoint):
                RootBlobFaultGate.validate_endpoint(endpoint)


class SelectorTests(unittest.TestCase):
    SUFFIX = "v1/tenants/11111111-1111-4111-8111-111111111111/authorities/22222222-2222-4222-8222-222222222222/g1/attempts/33333333-3333-4333-8333-333333333333/registered-pack/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def test_full_locator_get_matches_but_leaf_does_not(self):
        self.assertTrue(RootBlobFaultGate.full_path_matches("GET", "/bucket/" + self.SUFFIX, True, self.SUFFIX))
        self.assertTrue(RootBlobFaultGate.full_path_matches("GET", "/bucket/" + self.SUFFIX + "?x=1", True, self.SUFFIX))
        self.assertFalse(RootBlobFaultGate.full_path_matches("GET", "/" + self.SUFFIX.rsplit("/", 1)[-1], True, self.SUFFIX))
        other = self.SUFFIX.rsplit("/", 1)[0] + "/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        self.assertFalse(RootBlobFaultGate.full_path_matches("GET", "/bucket/" + other, True, self.SUFFIX))

    def test_only_armed_get_is_targeted(self):
        self.assertFalse(RootBlobFaultGate.full_path_matches("HEAD", "/bucket/" + self.SUFFIX, True, self.SUFFIX))
        self.assertFalse(RootBlobFaultGate.full_path_matches("GET", "/bucket/" + self.SUFFIX, False, self.SUFFIX))


class BoundTests(unittest.TestCase):
    def test_body_limit_boundaries(self):
        self.assertEqual(RootBlobFaultGate.bounded_body_length(None), 0)
        self.assertEqual(RootBlobFaultGate.bounded_body_length("0"), 0)
        self.assertEqual(RootBlobFaultGate.bounded_body_length(str(MAX_REQUEST_BYTES)), MAX_REQUEST_BYTES)
        with self.assertRaises(ValueError):
            RootBlobFaultGate.bounded_body_length(str(MAX_REQUEST_BYTES + 1))
        with self.assertRaises(ValueError):
            RootBlobFaultGate.bounded_body_length("-1")
        with self.assertRaises(ValueError):
            RootBlobFaultGate.bounded_body_length("not-a-number")

    def test_remaining_deadline_is_nonnegative_and_decreases(self):
        future = time.monotonic() + 1.0
        self.assertGreater(RootBlobFaultGate.remaining(future), 0)
        self.assertEqual(RootBlobFaultGate.remaining(time.monotonic() - 1.0), 0.0)


class StopBoundaryTests(unittest.TestCase):
    def test_never_ending_owned_handler_exhausts_stop_deadline(self):
        stop = threading.Event()
        handler = threading.Thread(target=stop.wait, daemon=True)
        handler.start()
        try:
            self.assertFalse(RootBlobFaultGate.join_handlers(
                [handler], None, time.monotonic() + 0.1))
        finally:
            stop.set()
            handler.join(timeout=1.0)

    def test_all_stopped_handlers_join_without_waiting(self):
        handler = threading.Thread(target=lambda: None, daemon=True)
        handler.start()
        handler.join(timeout=1.0)
        self.assertTrue(RootBlobFaultGate.join_handlers(
            [handler], None, time.monotonic() + 0.1))


class StopStateTests(unittest.TestCase):
    def test_stop_returns_false_and_retains_live_handler(self):
        gate = object.__new__(RootBlobFaultGate)
        gate.lock = threading.Lock()
        gate.armed = False
        gate.target_suffix = None
        gate.server = mock.Mock()
        gate.thread = mock.Mock()
        gate.thread.is_alive.return_value = False
        gate.started = True
        live = mock.Mock()
        live.is_alive.return_value = True
        live.join.side_effect = lambda timeout=None: time.sleep(min(0.01, timeout or 0.01))
        request = mock.Mock()
        gate._handlers = {live: request}
        gate._connections = set()
        try:
            self.assertFalse(gate.stop(time.monotonic() + 0.08))
        finally:
            gate._handlers.clear()
        gate.server.shutdown.assert_called_once()
        gate.server.server_close.assert_called_once()
        request.shutdown.assert_called_once()
        request.close.assert_called_once()

    def test_stop_returns_true_when_all_owned_threads_finished(self):
        gate = object.__new__(RootBlobFaultGate)
        gate.lock = threading.Lock()
        gate.armed = False
        gate.target_suffix = None
        gate.server = mock.Mock()
        gate.thread = mock.Mock()
        gate.thread.is_alive.return_value = False
        gate.started = True
        gate._handlers = {}
        gate._connections = set()
        self.assertTrue(gate.stop(time.monotonic() + 0.08))


class MutationAttemptTests(unittest.TestCase):
    def test_failed_upstream_still_counts_forwarded_write_attempt(self):
        gate = object.__new__(RootBlobFaultGate)
        gate.armed = False
        gate.target_suffix = None
        gate.lock = threading.Lock()
        gate.forwarded_methods = {}
        gate.upstream_errors = 0
        gate._connections = set()
        gate.upstream = ("127.0.0.1", 1)
        handler = type("Handler", (), {})()
        handler.command = "PUT"
        handler.path = "/bucket/v1/object"
        handler.headers = {"Content-Length": "3"}
        handler.rfile = BytesIO(b"abc")
        handler.wfile = BytesIO()
        handler.close_connection = False
        handler.connection = mock.Mock()
        handler.send_response_only = mock.Mock()
        handler.send_header = mock.Mock()
        handler.end_headers = mock.Mock()
        with mock.patch.object(fixture_gate.http.client, "HTTPConnection", side_effect=OSError("upstream failed")):
            RootBlobFaultGate._serve_bounded(gate, handler)
        self.assertEqual(gate.forwarded_methods.get("PUT"), 1)
        self.assertEqual(gate.upstream_errors, 1)
        self.assertTrue(handler.close_connection)


if __name__ == "__main__":
    unittest.main()
