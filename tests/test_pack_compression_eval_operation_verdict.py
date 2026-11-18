#!/usr/bin/env python3
"""Hermetic tests for the bounded durable-operation verdict (Refs #282).

The classifier is pure Python.  The transport is exercised only against
ephemeral loopback sockets owned by this test: no external network, no service,
no container, no native runtime and no repository.  Those loopback doubles are
the only way to prove the absolute deadline (a slow trickle) and that a
redirect target is never contacted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from pack_compression_eval import operation_verdict  # noqa: E402
from pack_compression_eval.concurrent_outcomes import (  # noqa: E402
    annotate_stale_operations,
    collect_concurrent_outcomes,
)
from pack_compression_eval.failure_diagnostics import (  # noqa: E402
    LiveEvalFailure,
    build_failure_record,
)
from pack_compression_eval.operation_verdict import (  # noqa: E402
    OPERATION_RESPONSE_MAX_BYTES,
    OPERATION_VERDICTS,
    _origin,
    classify_operation_view,
    read_operation_verdict,
)

SENTINEL = "SENTINEL_SECRET_operation_c91f"
OPERATION = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
REPOSITORY = "0f8fad5b-d9cb-469f-a165-70867728950e"
REF = "refs/heads/conc_1"
NOT_APPLIED = {"outcome": "not_applied", "name": REF, "reason": "old_oid_mismatch"}


def view(
    *,
    operation: str = OPERATION,
    repository: str = REPOSITORY,
    state: str = "rejected",
    kind: str = "rejected",
    refs: object = None,
    code: object = "revision_mismatch",
    detail: object = "admitted base was superseded",
) -> dict:
    return {
        "operation_id": operation,
        "state": state,
        "terminal": {
            "kind": kind,
            "repository_id": repository,
            "revision": 9,
            "head_ref": "refs/heads/main",
            "mode": "atomic",
            "refs": [dict(NOT_APPLIED)] if refs is None else refs,
            "registrations": [],
            "rejection": None if code is None else {"code": code, "detail": detail},
        },
    }


def verdict(document: object, **overrides: object) -> str:
    values = {"operation_id": OPERATION, "repository_id": REPOSITORY, "expected_ref": REF}
    values.update(overrides)
    return classify_operation_view(document, **values)


class ClassifyOperationViewTest(unittest.TestCase):
    def test_two_durable_terminal_states_are_distinguished(self) -> None:
        self.assertEqual(verdict(view()), "admitted_base_superseded")
        self.assertEqual(verdict(view(code="no_ref_applied", detail="all_rejected")), "per_ref_cas_rejected")

    def test_identity_bindings_are_strict(self) -> None:
        for document, overrides in (
            (view(operation="11111111-1111-4111-8111-111111111111"), {}),
            (view(repository="22222222-2222-4222-8222-222222222222"), {}),
            (view(), {"operation_id": "33333333-3333-4333-8333-333333333333"}),
            (view(), {"repository_id": "44444444-4444-4444-8444-444444444444"}),
            (view(), {"expected_ref": "refs/heads/conc_2"}),
            (view(operation="not-a-uuid"), {}),
            (view(refs=[{**NOT_APPLIED, "name": "refs/heads/conc_2"}]), {}),
            (view(refs=[{**NOT_APPLIED, "reason": "policy_denied"}]), {}),
            (view(refs=[{**NOT_APPLIED, "outcome": "applied", "old_oid": "a" * 40, "new_oid": "b" * 40}]), {}),
            (view(refs=[]), {}),
            (view(refs=[dict(NOT_APPLIED), dict(NOT_APPLIED)]), {}),
            (view(refs=[SENTINEL]), {}),
        ):
            with self.subTest(document=document, overrides=overrides):
                self.assertEqual(verdict(document, **overrides), "unknown")

    def test_state_kind_and_rejection_must_agree(self) -> None:
        for document in (
            view(state="committed"),
            view(state="pending"),
            view(state="cancelled"),
            view(state="terminal"),
            view(kind="committed"),
            view(kind="unknown"),
            view(code=None),
            view(code="no_ref_applied", detail="admitted base was superseded"),
            view(code="revision_mismatch", detail="all_rejected"),
            view(code="no_ref_applied", detail="admitted base was superseded"),
            view(code="revision_mismatch", detail="other"),
            view(code="other", detail="admitted base was superseded"),
            view(code=SENTINEL, detail=SENTINEL),
            view(code=7, detail=7),
            {"operation_id": OPERATION, "state": "rejected", "terminal": None},
            {"operation_id": OPERATION, "state": "rejected"},
            {"state": "rejected", "terminal": view()["terminal"]},
            [SENTINEL],
        ):
            with self.subTest(document=document):
                self.assertEqual(verdict(document), "unknown")
        self.assertEqual(verdict(view(), expected_ref="main"), "unknown")
        self.assertEqual(verdict(view(), expected_ref=None), "unknown")

    def test_classifier_never_returns_document_text(self) -> None:
        for document in (view(), view(code=SENTINEL, detail=SENTINEL), view(refs=[SENTINEL])):
            result = verdict(document)
            self.assertIn(result, OPERATION_VERDICTS)
            self.assertNotIn(SENTINEL, result)


def _valid_body(code: str = "revision_mismatch", detail: str = "admitted base was superseded") -> bytes:
    return json.dumps(view(code=code, detail=detail)).encode()


def _respond(body: bytes, status: str = "200 OK"):
    def handler(conn: socket.socket, _stop: threading.Event) -> None:
        head = (
            f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        conn.sendall(head + body)

    return handler


def _redirect(location: str):
    def handler(conn: socket.socket, _stop: threading.Event) -> None:
        conn.sendall(
            f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
        )

    return handler


def _trickle_headers(conn: socket.socket, stop: threading.Event) -> None:
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n")
    for _ in range(40):
        if stop.is_set():
            return
        try:
            conn.sendall(b"X")
        except OSError:
            return
        time.sleep(0.05)


def _trickle_body(conn: socket.socket, stop: threading.Event) -> None:
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
    for _ in range(40):
        if stop.is_set():
            return
        try:
            conn.sendall(b"x")
        except OSError:
            return
        time.sleep(0.05)


class _LoopbackDouble:
    """One test-owned loopback HTTP double; never listens beyond 127.0.0.1."""

    def __init__(self, handler) -> None:
        self._handler = handler
        self._stop = threading.Event()
        self.finished = threading.Event()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self._listener.settimeout(0.05)
        self.port = self._listener.getsockname()[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.requests: list[bytes] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            try:
                conn.settimeout(1.0)
                head = b""
                try:
                    while b"\r\n\r\n" not in head and len(head) < 65536:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        head += chunk
                except OSError:
                    pass
                self.requests.append(head)
                try:
                    self._handler(conn, self._stop)
                except OSError:
                    pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
                self.finished.set()

    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)
        if self._thread.is_alive():
            raise AssertionError("loopback double did not stop")


class TransportBoundaryTest(unittest.TestCase):
    def read(self, base_url: str, **overrides: object) -> str:
        operation_id = overrides.pop("operation_id", OPERATION)
        token = overrides.pop("token", "issuer-token")
        values = {"repository_id": REPOSITORY, "expected_ref": REF, "timeout": 2.0, "max_bytes": 4096}
        values.update(overrides)
        return read_operation_verdict(base_url, "owner", "repo", operation_id, token, **values)

    def test_transport_is_anchored_to_a_literal_loopback_origin(self) -> None:
        for base_url in (
            "http://example.invalid:80",
            "https://127.0.0.1:9",
            "http://user:pw@127.0.0.1:9",
            "http://127.0.0.1",
            "http://127.0.0.1:9/prefix",
            "http://127.0.0.1:9?x=1",
            "http://127.0.0.1:9#frag",
            "http://localhost:9",
            "http://0.0.0.0:9",
            "",
            SENTINEL,
        ):
            with self.subTest(base_url=base_url):
                with mock.patch.object(operation_verdict, "_BoundedHTTPConnection") as connection:
                    self.assertEqual(self.read(base_url), "unknown")
                connection.assert_not_called()
        self.assertEqual(_origin("http://127.0.0.1:9"), ("127.0.0.1", 9))
        self.assertEqual(_origin("http://[::1]:9"), ("::1", 9))

    def test_exact_success_is_one_direct_request(self) -> None:
        double = _LoopbackDouble(_respond(_valid_body()))
        self.addCleanup(double.close)
        self.assertEqual(self.read(double.origin), "admitted_base_superseded")
        self.assertTrue(double.finished.wait(1.0))
        self.assertEqual(len(double.requests), 1)
        request = double.requests[0]
        self.assertEqual(
            request.split(b"\r\n")[0], f"GET /api/repos/owner/repo/operations/{OPERATION} HTTP/1.1".encode()
        )
        self.assertIn(b"Authorization: Bearer issuer-token", request)
        self.assertNotIn(SENTINEL, "admitted_base_superseded")

    def test_redirect_is_refused_and_the_second_origin_is_never_contacted(self) -> None:
        second = _LoopbackDouble(_respond(_valid_body()))
        self.addCleanup(second.close)
        first = _LoopbackDouble(_redirect(second.origin + "/steal"))
        self.addCleanup(first.close)
        self.assertEqual(self.read(first.origin), "unknown")
        self.assertTrue(first.finished.wait(1.0))
        time.sleep(0.1)
        self.assertEqual(second.requests, [])
        self.assertEqual(len(first.requests), 1)
        self.assertIn(b"Authorization: Bearer issuer-token", first.requests[0])
        for status in (
            "301 Moved Permanently",
            "303 See Other",
            "307 Temporary Redirect",
            "308 Permanent Redirect",
        ):
            with self.subTest(status=status):
                redirect = _LoopbackDouble(_respond(b"", status=status))
                self.addCleanup(redirect.close)
                self.assertEqual(self.read(redirect.origin), "unknown")

    def test_environment_proxy_is_never_used(self) -> None:
        proxy = _LoopbackDouble(_respond(b"{}"))
        target = _LoopbackDouble(_respond(_valid_body(code="no_ref_applied", detail="all_rejected")))
        self.addCleanup(proxy.close)
        self.addCleanup(target.close)
        environment = {
            "HTTP_PROXY": proxy.origin, "http_proxy": proxy.origin,
            "ALL_PROXY": proxy.origin, "all_proxy": proxy.origin,
            "NO_PROXY": "", "no_proxy": "",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            self.assertEqual(self.read(target.origin), "per_ref_cas_rejected")
        self.assertEqual(proxy.requests, [])
        self.assertEqual(len(target.requests), 1)

    def test_slow_header_trickle_is_stopped_by_the_absolute_deadline(self) -> None:
        double = _LoopbackDouble(_trickle_headers)
        self.addCleanup(double.close)
        started = time.monotonic()
        self.assertEqual(self.read(double.origin, timeout=0.3), "unknown")
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 1.5)
        double.close()
        self.assertTrue(double.finished.is_set())

    def test_slow_body_trickle_is_stopped_by_the_absolute_deadline(self) -> None:
        double = _LoopbackDouble(_trickle_body)
        self.addCleanup(double.close)
        started = time.monotonic()
        self.assertEqual(self.read(double.origin, timeout=0.3, max_bytes=1024), "unknown")
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.2)
        self.assertLess(elapsed, 1.5)
        double.close()
        self.assertTrue(double.finished.is_set())

    def test_non_200_and_malformed_or_oversized_bodies_are_unknown(self) -> None:
        for status in (
            "400 Bad Request",
            "403 Forbidden",
            "404 Not Found",
            "500 Internal Server Error",
            "503 Service Unavailable",
        ):
            with self.subTest(status=status):
                double = _LoopbackDouble(_respond(_valid_body(), status=status))
                self.addCleanup(double.close)
                self.assertEqual(self.read(double.origin), "unknown")
                self.assertEqual(len(double.requests), 1)
        for body in (b"", b"not json", b"\xff\xfe\x00", b"[]", b"null", b'"text"'):
            with self.subTest(body=body):
                double = _LoopbackDouble(_respond(body))
                self.addCleanup(double.close)
                self.assertEqual(self.read(double.origin), "unknown")
        oversized = _LoopbackDouble(_respond(b"x" * 8192))
        self.addCleanup(oversized.close)
        self.assertEqual(self.read(oversized.origin, max_bytes=1024), "unknown")

    def test_transport_failures_are_unknown_and_never_raise(self) -> None:
        for error in (TimeoutError(SENTINEL), OSError(SENTINEL), RuntimeError(SENTINEL), ValueError(SENTINEL)):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(operation_verdict.socket, "create_connection", side_effect=error):
                    result = self.read("http://127.0.0.1:9")
                self.assertEqual(result, "unknown")
                self.assertNotIn(SENTINEL, result)

    def test_connection_construction_failure_is_unknown(self) -> None:
        with mock.patch.object(operation_verdict, "_BoundedHTTPConnection", side_effect=ValueError(SENTINEL)):
            result = self.read("http://127.0.0.1:9")
        self.assertEqual(result, "unknown")
        self.assertNotIn(SENTINEL, result)

    def test_invalid_inputs_issue_no_connection(self) -> None:
        for overrides in (
            {"operation_id": SENTINEL},
            {"operation_id": ""},
            {"token": ""},
            {"token": "bad token"},
            {"token": "bad\ntoken"},
            {"repository_id": SENTINEL},
            {"expected_ref": "main"},
            {"expected_ref": None},
            {"timeout": 0},
            {"timeout": 31},
            {"timeout": True},
            {"max_bytes": 1023},
            {"max_bytes": OPERATION_RESPONSE_MAX_BYTES + 1},
            {"max_bytes": True},
        ):
            with self.subTest(overrides=overrides):
                with mock.patch.object(operation_verdict, "_BoundedHTTPConnection") as connection:
                    result = self.read("http://127.0.0.1:9", **overrides)
                self.assertEqual(result, "unknown")
                connection.assert_not_called()


class _Future:
    def __init__(self, error: BaseException | None = None, *, value: object = None) -> None:
        self.error = error
        self.value = value

    def result(self) -> object:
        if self.error is not None:
            raise self.error
        return self.value


class StaleAnnotationTransportTest(unittest.TestCase):
    def _stale_first_error(self) -> LiveEvalFailure:
        return LiveEvalFailure(
            build_failure_record(
                phase="concurrent_push", failure_class="git_push", git_returncode=1, push_ref_verdict="stale_info"
            )
        )

    def _stale_progress(self) -> dict:
        progress: dict = {}
        collect_concurrent_outcomes(
            [_Future(self._stale_first_error())], _Future(value=None), branch_count=3, progress=progress
        )
        return progress

    def test_annotation_positive_verdict_through_the_real_transport(self) -> None:
        double = _LoopbackDouble(_respond(_valid_body(code="no_ref_applied", detail="all_rejected")))
        self.addCleanup(double.close)
        progress = self._stale_progress()
        annotate_stale_operations(
            progress, double.origin, {"owner": "owner", "name": "repo", "id": REPOSITORY}, "issuer-token",
            {0: (OPERATION, REF)},
        )
        row = progress["concurrent_worker_outcomes"][0]
        self.assertEqual(row["operation_verdict"], "per_ref_cas_rejected")
        self.assertIsNone(row["http_status"])
        self.assertEqual(len(double.requests), 1)

    def test_annotation_transport_failure_leaves_unknown_and_keeps_first_error(self) -> None:
        first = self._stale_first_error()
        progress: dict = {}
        returned = collect_concurrent_outcomes(
            [_Future(first)], _Future(value=None), branch_count=3, progress=progress
        )
        for side_effect in (None, OSError(SENTINEL), ValueError(SENTINEL)):
            with self.subTest(failure=side_effect is not None):
                patch = (
                    mock.patch.object(operation_verdict, "_bounded_request", return_value=None)
                    if side_effect is None
                    else mock.patch.object(operation_verdict, "_bounded_request", side_effect=side_effect)
                )
                with patch:
                    annotate_stale_operations(
                        progress, "http://127.0.0.1:9", {"owner": "o", "name": "r", "id": REPOSITORY},
                        "issuer-token", {0: (OPERATION, REF)},
                    )
                self.assertIs(returned, first)
                self.assertEqual(progress["concurrent_worker_outcomes"][0]["operation_verdict"], "unknown")
                self.assertNotIn(SENTINEL, json.dumps(progress["concurrent_worker_outcomes"], sort_keys=True))


if __name__ == "__main__":
    unittest.main()
