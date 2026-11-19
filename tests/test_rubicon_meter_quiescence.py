"""Pure, synchronous tests for the S3 meter pending lifecycle and atomic boundary."""

from __future__ import annotations

import math
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from rubicon_workload.workloads import (  # noqa: E402
    METER_BOUNDARY_WAIT_SECONDS,
    SOCKET_IO_TIMEOUT_SECONDS,
    MeterQuiescenceTimeout,
    S3MeterProxy,
    _ExchangeToken,
)


class _FakeClock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FakeScheduler:
    def __init__(self) -> None:
        self.on_wait = self._noop

    @staticmethod
    def _noop(cond: "_FakeCondition", remaining: float) -> None:
        return None


class _FakeCondition:
    """Synchronous Condition stand-in that records lock/wait/reacquire order."""

    def __init__(self, clock: _FakeClock, scheduler: _FakeScheduler) -> None:
        self.clock = clock
        self.scheduler = scheduler
        self.locked = False
        self.wait_calls: list[float] = []
        self.notify_calls = 0
        self.trace: list[object] = []

    def __enter__(self) -> "_FakeCondition":
        if self.locked:
            raise AssertionError("fake condition lock re-entered")
        self.locked = True
        self.trace.append("lock")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if not self.locked:
            raise AssertionError("fake condition unlocked without lock")
        self.locked = False
        self.trace.append("unlock")
        return False

    def wait(self, remaining: float) -> None:
        if not self.locked:
            raise AssertionError("fake condition wait without lock")
        if not math.isfinite(remaining):
            raise AssertionError("fake condition wait with non-finite remaining")
        self.wait_calls.append(remaining)
        self.trace.append(("wait", remaining))
        self.locked = False
        self.trace.append("release")
        self.scheduler.on_wait(self, remaining)
        if self.locked:
            raise AssertionError("scheduler must not leave the fake lock held")
        self.locked = True
        self.trace.append("reacquire")

    def notify_all(self) -> None:
        if not self.locked:
            raise AssertionError("fake condition notify without lock")
        self.notify_calls += 1
        self.trace.append("notify")


class _FakeStop:
    def is_set(self) -> bool:
        return False


class _FakeSocket:
    """Fake stream surface sufficient for BufferedConn and _handle_conn."""

    def __init__(self, recv_chunks: list[bytes | BaseException] | None = None, send_error: BaseException | None = None) -> None:
        self._recv = list(recv_chunks or [])
        self._send_error = send_error
        self.sent: list[bytes] = []
        self.timeouts: list[float] = []
        self.closed = False

    def recv(self, size: int) -> bytes:
        if not self._recv:
            return b""
        item = self._recv.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def sendall(self, data: bytes) -> None:
        if self._send_error is not None:
            raise self._send_error
        self.sent.append(bytes(data))

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def close(self) -> None:
        self.closed = True


class _RecordingProxy(S3MeterProxy):
    def _snapshot_locked(self) -> dict[str, object]:
        self.copy_lock_state = self._cond.locked
        self.trace.append(("copy", self._cond.locked))
        return super()._snapshot_locked()


def _new_proxy(cond: _FakeCondition, clock: _FakeClock, cls: type[S3MeterProxy] = S3MeterProxy) -> S3MeterProxy:
    proxy = object.__new__(cls)
    proxy._cond = cond
    proxy._clock = clock.monotonic
    proxy._lock = None
    proxy._pending = 0
    proxy._req_counts = {}
    proxy._req_bytes = {}
    proxy._resp_bytes = {}
    proxy._status_counts = {}
    proxy._error_responses = 0
    proxy._stop = _FakeStop()
    proxy.upstream_host = "127.0.0.1"
    proxy.upstream_port = 9
    return proxy


def _run_handler(proxy: S3MeterProxy, request: bytes, response_chunks: list[bytes | BaseException], send_error: BaseException | None = None) -> tuple[_FakeSocket, _FakeSocket]:
    client = _FakeSocket([request])
    upstream = _FakeSocket(response_chunks, send_error=send_error)
    with patch("rubicon_workload.workloads.socket.create_connection", return_value=upstream):
        proxy._handle_conn(client)
    return client, upstream


class MeterQuiescenceTests(unittest.TestCase):
    def test_atomic_copy_under_lock_after_wait(self) -> None:
        clock = _FakeClock()
        scheduler = _FakeScheduler()
        cond = _FakeCondition(clock, scheduler)
        proxy = _new_proxy(cond, clock, _RecordingProxy)
        proxy.trace = []
        token = proxy._begin_exchange()

        self.assertEqual(proxy.live_snapshot()["get_requests"], 0)
        cond.trace.clear()
        proxy.trace.clear()
        proxy.copy_lock_state = None

        scheduler.on_wait = lambda c, remaining: proxy._terminal_exchange(token, True, "GET", 0, 7, 200)
        snap = proxy.snapshot_after_quiescence(clock.now + 30.0)

        self.assertEqual(snap["get_requests"], 1)
        self.assertEqual(snap["get_bytes"], 7)
        self.assertEqual(proxy._pending, 0)
        self.assertTrue(proxy.copy_lock_state)
        self.assertEqual(len(cond.wait_calls), 1)
        self.assertEqual(cond.notify_calls, 1)
        self.assertEqual(proxy.trace[-1], ("copy", True))
        self.assertEqual(cond.trace[-1], "unlock")
        self.assertIn("release", cond.trace)
        self.assertIn("reacquire", cond.trace)

    def test_live_snapshot_and_alias_are_nonblocking(self) -> None:
        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)
        token = proxy._begin_exchange()

        self.assertEqual(proxy.live_snapshot()["total_requests"], 0)
        self.assertEqual(proxy.snapshot()["total_requests"], 0)
        self.assertEqual(cond.wait_calls, [])
        self.assertEqual(proxy._pending, 1)
        proxy._terminal_exchange(token, False, "GET", 0, 0, 500)
        self.assertEqual(proxy._pending, 0)

    def test_terminal_exactly_once_success_abort_and_reuse(self) -> None:
        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)

        first = proxy._begin_exchange()
        proxy._terminal_exchange(first, True, "PUT", 5, 2, 200)
        second = proxy._begin_exchange()
        proxy._terminal_exchange(second, False, "GET", 0, 9, 500)

        reused_one = proxy._begin_exchange()
        proxy._terminal_exchange(reused_one, True, "GET", 0, 3, 200)
        reused_two = proxy._begin_exchange()
        proxy._terminal_exchange(reused_two, False, "HEAD", 0, 0, 200)

        snap = proxy.live_snapshot()
        self.assertEqual(proxy._pending, 0)
        self.assertEqual(snap["put_requests"], 1)
        self.assertEqual(snap["put_bytes"], 5)
        self.assertEqual(snap["get_requests"], 1)
        self.assertEqual(snap["get_bytes"], 3)
        self.assertEqual(snap["error_responses"], 0)
        self.assertEqual(snap["total_requests"], 2)

        before = proxy.live_snapshot()
        with self.assertRaises(RuntimeError):
            proxy._terminal_exchange(first, True, "PUT", 5, 2, 200)
        self.assertEqual(proxy.live_snapshot(), before)
        self.assertEqual(proxy._pending, 0)

        with self.assertRaises(RuntimeError):
            proxy._terminal_exchange(_ExchangeToken(), True, "GET", 0, 1, 200)
        self.assertEqual(proxy.live_snapshot(), before)
        self.assertEqual(proxy._pending, 0)

    def test_timeout_has_no_snapshot_and_no_state_change(self) -> None:
        clock = _FakeClock()
        scheduler = _FakeScheduler()
        cond = _FakeCondition(clock, scheduler)
        proxy = _new_proxy(cond, clock, _RecordingProxy)
        proxy.trace = []
        token = proxy._begin_exchange()
        before = proxy.live_snapshot()
        cond.trace.clear()
        proxy.trace.clear()
        proxy.copy_lock_state = None

        scheduler.on_wait = lambda c, remaining: clock.advance(30.0)
        with self.assertRaises(MeterQuiescenceTimeout) as ctx:
            proxy.snapshot_after_quiescence(clock.now + 30.0)
        self.assertEqual(ctx.exception.pending, 1)
        self.assertEqual(ctx.exception.deadline, 130.0)
        self.assertEqual(proxy._pending, 1)
        self.assertIsNone(proxy.copy_lock_state)
        self.assertEqual(proxy.trace, [])
        self.assertEqual(proxy.live_snapshot(), before)
        self.assertNotIn(("copy", True), cond.trace)

        wait_count = len(cond.wait_calls)
        with self.assertRaises(MeterQuiescenceTimeout):
            proxy.snapshot_after_quiescence(clock.now - 1.0)
        self.assertEqual(len(cond.wait_calls), wait_count)
        self.assertEqual(proxy._pending, 1)

        for bad in (True, False, float("nan"), float("inf"), float("-inf"), None, "not-a-deadline"):
            with self.assertRaises(ValueError):
                proxy.snapshot_after_quiescence(bad)

        proxy._terminal_exchange(token, False, "GET", 0, 0, 500)
        self.assertEqual(proxy._pending, 0)

    def test_preparse_and_early_failure_cleanup_do_not_leak_pending(self) -> None:
        request = b"GET /bucket/pack.bin HTTP/1.1\r\nHost: 127.0.0.1:4321\r\nConnection: close\r\n\r\n"

        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)
        upstream = _FakeSocket([b""])
        with patch("rubicon_workload.workloads.socket.create_connection", return_value=upstream), patch(
            "rubicon_workload.workloads._parse_http_head", side_effect=ValueError("bad head")
        ):
            proxy._handle_conn(_FakeSocket([request]))
        self.assertEqual(proxy._pending, 0)
        self.assertEqual(proxy.live_snapshot()["total_requests"], 0)
        self.assertEqual(upstream.sent, [])

        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)
        client, upstream = _run_handler(proxy, request, [b""])
        self.assertEqual(proxy._pending, 0)
        self.assertEqual(proxy.live_snapshot()["total_requests"], 0)
        self.assertEqual(b"".join(upstream.sent), request)
        self.assertTrue(client.closed and upstream.closed)

        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)
        _, upstream = _run_handler(proxy, request, [], send_error=OSError("boom"))
        self.assertEqual(proxy._pending, 0)
        self.assertEqual(proxy.live_snapshot()["total_requests"], 0)
        self.assertTrue(upstream.closed)

        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)
        with self.assertRaises(KeyboardInterrupt):
            _run_handler(proxy, request, [], send_error=KeyboardInterrupt())
        self.assertEqual(proxy._pending, 0)
        self.assertEqual(proxy.live_snapshot()["total_requests"], 0)

    def test_lost_wake_and_continuous_arrivals_time_out_without_snapshot(self) -> None:
        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock, _RecordingProxy)
        proxy.trace = []
        token = proxy._begin_exchange()
        proxy._terminal_exchange(token, True, "GET", 0, 1, 200)
        cond.trace.clear()
        snap = proxy.snapshot_after_quiescence(clock.now + 30.0)
        self.assertEqual(snap["get_requests"], 1)
        self.assertEqual(cond.wait_calls, [])

        clock = _FakeClock()
        scheduler = _FakeScheduler()
        cond = _FakeCondition(clock, scheduler)
        proxy = _new_proxy(cond, clock, _RecordingProxy)
        proxy.trace = []
        current = [proxy._begin_exchange()]
        visits = [0]

        def churn(c: _FakeCondition, remaining: float) -> None:
            proxy._terminal_exchange(current[0], True, "GET", 0, 1, 200)
            current[0] = proxy._begin_exchange()
            visits[0] += 1
            clock.advance(10.0)

        scheduler.on_wait = churn
        with self.assertRaises(MeterQuiescenceTimeout):
            proxy.snapshot_after_quiescence(clock.now + 30.0)
        self.assertGreaterEqual(visits[0], 2)
        self.assertEqual(proxy._pending, 1)
        self.assertEqual(proxy.live_snapshot()["get_requests"], visits[0])
        self.assertNotIn(("copy", True), cond.trace)
        proxy._terminal_exchange(current[0], False, "GET", 0, 0, 500)
        self.assertEqual(proxy._pending, 0)

    def test_completed_counter_table_and_wire_behavior(self) -> None:
        n, p, e = 11, 13, 17
        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)

        rows = [
            ("PUT", n, 2, 200),
            ("HEAD", 0, 0, 200),
            ("GET", 0, n, 200),
            ("GET", 0, p, 200),
            ("GET", 0, e, 500),
        ]
        for method, req_bytes, resp_bytes, status in rows:
            proxy._terminal_exchange(proxy._begin_exchange(), True, method, req_bytes, resp_bytes, status)

        snap = proxy.live_snapshot()
        self.assertEqual(snap["put_requests"], 1)
        self.assertEqual(snap["put_bytes"], n)
        self.assertEqual(snap["head_requests"], 1)
        self.assertEqual(snap["get_requests"], 3)
        self.assertEqual(snap["get_bytes"], n + p + e)
        self.assertEqual(snap["error_responses"], 1)
        self.assertEqual(snap["total_requests"], 5)
        self.assertEqual(snap["status_counts"], {"200": 4, "500": 1})
        self.assertEqual(METER_BOUNDARY_WAIT_SECONDS, SOCKET_IO_TIMEOUT_SECONDS)

        put_head = (
            b"PUT /bucket/pack.bin HTTP/1.1\r\n"
            b"Host: 127.0.0.1:4321\r\n"
            b"Content-Length: 4\r\n"
            b"Connection: close\r\n\r\n"
        )
        put_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)
        client, upstream = _run_handler(proxy, put_head + b"data", [put_response])
        self.assertEqual(b"".join(upstream.sent), put_head + b"data")
        self.assertIn(b"Host: 127.0.0.1:4321", upstream.sent[0])
        self.assertEqual(proxy.live_snapshot()["put_bytes"], 4)
        self.assertIn(b"HTTP/1.1 200 OK", b"".join(client.sent))

        get_head = b"GET /bucket/pack.bin HTTP/1.1\r\nHost: 127.0.0.1:4321\r\nConnection: close\r\n\r\n"
        chunked_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        clock = _FakeClock()
        cond = _FakeCondition(clock, _FakeScheduler())
        proxy = _new_proxy(cond, clock)
        client, upstream = _run_handler(proxy, get_head, [chunked_response])
        self.assertEqual(b"".join(upstream.sent), get_head)
        self.assertEqual(proxy.live_snapshot()["get_requests"], 1)
        self.assertEqual(proxy.live_snapshot()["get_bytes"], 5)
        sent = b"".join(client.sent)
        self.assertIn(b"5\r\nhello\r\n0\r\n\r\n", sent)


if __name__ == "__main__":
    unittest.main()
