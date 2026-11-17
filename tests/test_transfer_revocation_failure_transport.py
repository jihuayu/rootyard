#!/usr/bin/env python3
"""Hermetic actual-wrapper ordering tests for Issue #37 partial evidence."""
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

import transfer_revocation_failure as failure  # noqa: E402
import transfer_revocation_transport as transport  # noqa: E402


class _RaisingConnection:
    requested_so_rcvbuf = 16 * 1024
    effective_so_rcvbuf = 32 * 1024

    def __init__(self, *args, **kwargs):
        self.sock = object()

    def request(self, method, path, body=None, headers=None):
        raise RuntimeError("secret operation text /tmp/path")

    def close(self):
        raise OSError(5, "secret cleanup text /tmp/path")


class _TriggerResponse:
    status = 200

    def getheader(self, name):
        return "4"

    def read(self, size):
        return b"x"

    def close(self):
        pass


class _TriggerConnection:
    requested_so_rcvbuf = 16 * 1024
    effective_so_rcvbuf = 32 * 1024

    def __init__(self, *args, **kwargs):
        self.sock = object()

    def request(self, method, path, body=None, headers=None):
        pass

    def getresponse(self):
        return _TriggerResponse()

    def close(self):
        pass


class _TriggerProbe:
    def __init__(self, **kwargs):
        self.source = {
            "witness_version": 1, "witness_kind_code": 1,
            "witness_available": True, "witness_bound": True,
            "qualified": True, "failure_code": 0, "fatal_failure_code": 0,
            "source_identity_unique": True, "source_position_unchanged": True,
            "source_unfinished": True, "source_position": 1,
            "source_size": 4, "source_remaining": 3,
        }
        self.last_sample = {
            "source_report": self.source, "source_qualified": True,
            "observed_ns": 1, "sample_start_ns": 1,
            "server_tx_queue": 1, "client_rx_queue": 1,
            "server_socket_inode": 1, "same_netns": True,
            "server_fd_owned": True, "client_inode_owned": True,
            "probe0_pending": True, "sample_duration_ns": 1,
        }
        self.persistent = True
        self.window = types.SimpleNamespace(qualified=True)

    def wait_persistent(self):
        return self

    def sample(self):
        return self.last_sample

    def finalize(self):
        return True

    def report(self):
        return {
            "qualified": True, "sample_count": 1,
            "last_reset_reason": "not_started",
            "source_witness": self.source,
        }

    def pre_trigger_valid(self, lower_ns):
        return True


class _NoopThread:
    daemon = True

    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def join(self, timeout=None):
        return None

    def is_alive(self):
        return False


class TransportOrderingTests(unittest.TestCase):
    def test_operation_failure_survives_cleanup_failure_through_wrapper(self):
        with mock.patch.object(
            transport, "SmallBufferHTTPConnection", _RaisingConnection,
        ):
            with self.assertRaises(failure.SafeFailure) as caught:
                transport.run_timed_transfer(
                    base="http://127.0.0.1:1", path="/x", method="GET",
                    headers={}, body=None, expected_size=1, initial_bytes=1,
                    framing="content_length", service_pid=None, bound_ms=1200,
                    trigger=lambda: None, require_group=False,
                    require_backpressure=False,
                )
        snapshot = caught.exception.partial
        self.assertEqual(snapshot["primary_failure_phase"], "transport_request")
        self.assertEqual(snapshot["exception_class"], "runtime_error")
        self.assertEqual(snapshot["cleanup"]["state"], "failed")
        self.assertEqual(snapshot["cleanup"]["exception_class"], "os_error")
        self.assertNotEqual(snapshot["primary_failure_phase"], "transfer_cleanup")
        self.assertNotIn("secret", json.dumps(snapshot))

    def test_trigger_failure_preserves_observed_preproof(self):
        def fail_trigger():
            raise RuntimeError("secret trigger text /tmp/path")

        with mock.patch.object(
            transport, "SmallBufferHTTPConnection", _TriggerConnection,
        ), mock.patch.object(
            transport, "BackpressureProbe", _TriggerProbe,
        ), mock.patch.object(
            transport.threading, "Thread", _NoopThread,
        ):
            with self.assertRaises(failure.SafeFailure) as caught:
                transport.run_timed_transfer(
                    base="http://127.0.0.1:1", path="/x", method="GET",
                    headers={}, body=None, expected_size=4, initial_bytes=1,
                    framing="content_length", service_pid=None, bound_ms=1200,
                    trigger=fail_trigger, require_group=False,
                    require_backpressure=True,
                )
        snapshot = caught.exception.partial
        self.assertEqual(snapshot["primary_failure_phase"], "trigger_commit")
        self.assertEqual(snapshot["exception_class"], "runtime_error")
        self.assertTrue(snapshot["pre_trigger"]["source_witness"]["qualified"])
        self.assertTrue(snapshot["pre_trigger"]["backpressure"]["qualified"])
        self.assertTrue(
            snapshot["pre_trigger"]["backpressure"]["source_witness"]["qualified"])
        self.assertIsNone(snapshot["final_proof"])
        self.assertNotIn("secret", json.dumps(snapshot))


if __name__ == "__main__":
    unittest.main()
