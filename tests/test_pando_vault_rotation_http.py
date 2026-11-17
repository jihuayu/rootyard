#!/usr/bin/env python3
"""Pure fake tests for the owned bounded Vault HTTP transaction.

Only a fake monotonic clock, fake runner, fake opener/response and in-memory
bytes are used.  No real socket, HTTP server, Vault, Docker, PostgreSQL, Git
fixture, thread, process, compiler or Cargo invocation occurs.
"""
from __future__ import annotations

import base64
import io
import json
import socket
from pathlib import Path
import sys
import unittest
import urllib.error

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation_fixture as fixture  # noqa: E402
import pando_vault_rotation_http as http  # noqa: E402
import pando_vault_rotation_http_child as child  # noqa: E402
from pando_vault_rotation_budget import Budget  # noqa: E402
from pando_vault_rotation_support import QualificationError  # noqa: E402

SECRET = "root-token-SECRET-do-not-project"
URL = "http://127.0.0.1:49152/v1/sys/health"


class Clock:
    def __init__(self, now=0.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self, result=None, error=None, advance=0.0, clock=None):
        self.result = result
        self.error = error
        self.advance = advance
        self.clock = clock
        self.calls = []
        self.eof = False

    def run(self, argv, env=None, input=None, timeout=None):
        self.calls.append({
            "argv": list(argv),
            "env": dict(env or {}),
            "input": bytes(input or b""),
            "timeout": timeout,
        })
        if self.advance:
            self.clock.advance(self.advance)
        if self.error is not None:
            raise self.error
        return self.result


def payload(status=200, body=b"{}"):
    return json.dumps({
        "ok": True,
        "status": status,
        "body_b64": base64.b64encode(body).decode("ascii"),
    }).encode()


def request(token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    return http.HttpRequest("POST", URL, b'{"x":1}', headers)


def budget(clock, total=100, reserve=20):
    return Budget(total, reserve, clock=clock,
                  error_factory=QualificationError)


class ParentDeadlineTest(unittest.TestCase):
    def test_success_status_and_body_are_preserved(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=payload(201, b'{"ok":1}')))
        opener = http.BoundedHttpOpener(runner, budget(clock))
        with opener.open(request(), timeout=5) as response:
            self.assertEqual(response.status, 201)
            self.assertEqual(response.read(http.MAX_BODY + 1), b'{"ok":1}')
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0]["timeout"], 5.0)
        sent = json.loads(runner.calls[0]["input"])
        self.assertEqual(set(sent), {"method", "url", "token", "body_b64", "timeout"})
        self.assertEqual(sent["method"], "POST")
        self.assertEqual(sent["url"], URL)
        self.assertEqual(sent["timeout"], 5.0)

    def test_per_request_cap_stays_five_seconds(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=payload()))
        opener = http.BoundedHttpOpener(runner, budget(clock))
        opener.open(request(), timeout=30)
        self.assertEqual(runner.calls[0]["timeout"], 5.0)

    def test_remaining_budget_can_only_lower_the_cap(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=payload()))
        opener = http.BoundedHttpOpener(runner, budget(clock))
        clock.advance(78)
        opener.open(request(), timeout=5)
        self.assertEqual(runner.calls[0]["timeout"], 2.0)

    def test_expired_budget_never_starts_the_child(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=payload()))
        opener = http.BoundedHttpOpener(runner, budget(clock))
        clock.advance(80)
        with self.assertRaises(QualificationError) as caught:
            opener.open(request(), timeout=5)
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(runner.calls, [])

    def test_late_child_return_is_never_green(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=payload()), advance=80, clock=clock)
        opener = http.BoundedHttpOpener(runner, budget(clock))
        with self.assertRaises(QualificationError) as caught:
            opener.open(request(), timeout=5)
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")

    def test_headers_never_finish_times_out_without_eof(self):
        clock = Clock()
        runner = FakeRunner(
            error=QualificationError("subprocess_timeout", "vault_http"))
        opener = http.BoundedHttpOpener(runner, budget(clock))
        with self.assertRaises(QualificationError) as caught:
            opener.open(request(), timeout=5)
        self.assertEqual(caught.exception.code, "vault_api_failed")
        self.assertFalse(runner.eof)
        self.assertEqual(runner.calls[0]["timeout"], 5.0)

    def test_slow_drip_body_times_out_without_eof(self):
        clock = Clock()
        runner = FakeRunner(
            error=QualificationError("subprocess_timeout", "vault_http"))
        opener = http.BoundedHttpOpener(runner, budget(clock))
        with self.assertRaises(QualificationError) as caught:
            opener.open(request(), timeout=5)
        self.assertEqual(caught.exception.code, "vault_api_failed")
        self.assertFalse(runner.eof)

    def test_output_overflow_fails_closed(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=b"x" * (http.MAX_RESULT_BYTES + 1)))
        opener = http.BoundedHttpOpener(runner, budget(clock))
        with self.assertRaises(QualificationError) as caught:
            opener.open(request(), timeout=5)
        self.assertEqual(caught.exception.code, "vault_api_failed")

    def test_duplicate_json_key_fails_closed(self):
        raw = (b'{"body_b64":"e30=","ok":true,"status":200,'
               b'"ok":true}')
        opener = http.BoundedHttpOpener(
            FakeRunner(Result(stdout=raw)), budget(Clock()))
        with self.assertRaises(QualificationError):
            opener.open(request(), timeout=5)

    def test_untrusted_extra_json_key_fails_closed(self):
        raw = json.dumps({
            "ok": True, "status": 200, "body_b64": "e30=",
            "token": SECRET,
        }).encode()
        opener = http.BoundedHttpOpener(
            FakeRunner(Result(stdout=raw)), budget(Clock()))
        with self.assertRaises(QualificationError):
            opener.open(request(), timeout=5)

    def test_unknown_failure_code_fails_closed(self):
        raw = json.dumps({"ok": False, "code": "raw-" + SECRET}).encode()
        opener = http.BoundedHttpOpener(
            FakeRunner(Result(stdout=raw)), budget(Clock()))
        with self.assertRaises(QualificationError):
            opener.open(request(), timeout=5)

    def test_nonzero_and_signal_returncodes_fail_closed(self):
        for returncode in (1, -9, 137):
            with self.subTest(returncode=returncode):
                opener = http.BoundedHttpOpener(
                    FakeRunner(Result(returncode=returncode,
                                      stdout=payload())), budget(Clock()))
                with self.assertRaises(QualificationError):
                    opener.open(request(), timeout=5)

    def test_group_liveness_failure_fails_closed(self):
        opener = http.BoundedHttpOpener(FakeRunner(
            error=QualificationError(
                "subprocess_group_unverified", "vault_http")), budget(Clock()))
        with self.assertRaises(QualificationError) as caught:
            opener.open(request(), timeout=5)
        self.assertEqual(caught.exception.code, "vault_api_failed")

    def test_missing_child_is_not_silently_inlined(self):
        missing = Path("/never-present/pando_vault_rotation_http_child.py")
        runner = FakeRunner(
            error=QualificationError("subprocess_failed", "vault_http"))
        opener = http.BoundedHttpOpener(runner, budget(Clock()), child=missing)
        with self.assertRaises(QualificationError) as caught:
            opener.open(request(), timeout=5)
        self.assertEqual(caught.exception.code, "vault_api_failed")
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0]["argv"][1], str(missing))

    def test_raw_token_url_and_error_are_not_in_failure_projection(self):
        error = RuntimeError("%s %s" % (SECRET, URL))
        opener = http.BoundedHttpOpener(
            FakeRunner(error=error), budget(Clock()))
        with self.assertRaises(QualificationError) as caught:
            opener.open(request(token=SECRET), timeout=5)
        projected = repr(caught.exception) + " " + str(caught.exception)
        self.assertNotIn(SECRET, projected)
        self.assertNotIn(URL, projected)
        self.assertEqual(caught.exception.code, "vault_api_failed")


class FakeResponse:
    def __init__(self, status=200, body=b"{}", read_error=None):
        self.status = status
        self.body = body
        self.read_error = read_error
        self.limits = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False

    def read(self, limit=-1):
        self.limits.append(limit)
        if self.read_error is not None:
            raise self.read_error
        return self.body[:limit] if limit is not None and limit >= 0 else self.body


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def open(self, request, timeout=None):
        self.calls.append({
            "url": request.full_url,
            "method": request.get_method(),
            "timeout": timeout,
        })
        if self.error is not None:
            raise self.error
        return self.response


def value(**overrides):
    base = {
        "method": "GET",
        "url": URL,
        "token": None,
        "body": None,
        "timeout": 5.0,
    }
    base.update(overrides)
    return base


class ChildProtocolTest(unittest.TestCase):
    def test_loopback_url_is_accepted_and_headers_are_bounded(self):
        response = FakeResponse(body=b'{"initialized":true}')
        opener = FakeOpener(response)
        result = child.run_transaction(value(token=SECRET), opener=opener)
        self.assertTrue(result["ok"])
        self.assertEqual(base64.b64decode(result["body_b64"]),
                         b'{"initialized":true}')
        self.assertEqual(opener.calls[0]["timeout"], 5.0)

    def test_non_loopback_url_is_rejected_before_opening(self):
        opener = FakeOpener(FakeResponse())
        for url in (
            "http://example.com/v1/sys/health",
            "http://127.0.0.1@example.com/v1/sys/health",
            "http://127.0.0.1:1/not-v1",
            "ftp://127.0.0.1:1/v1/sys/health",
            "http://127.0.0.1:0/v1/sys/health",
        ):
            with self.subTest(url=url):
                result = child.run_transaction(value(url=url), opener=opener)
                self.assertEqual(result, {"ok": False, "code": "url_invalid"})
        self.assertEqual(opener.calls, [])

    def test_http_error_has_status_but_no_error_body(self):
        error = urllib.error.HTTPError(
            URL, 403, "Forbidden", {}, io.BytesIO(b"RAW-ERROR-BODY"))
        result = child.run_transaction(value(), opener=FakeOpener(error=error))
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 403)
        self.assertEqual(base64.b64decode(result["body_b64"]), b"")
        self.assertNotIn("RAW-ERROR-BODY", json.dumps(result))

    def test_headers_timeout_is_a_fixed_failure(self):
        result = child.run_transaction(
            value(), opener=FakeOpener(error=urllib.error.URLError(
                socket.timeout("headers"))))
        self.assertEqual(result, {"ok": False, "code": "request_failed"})

    def test_slow_drip_body_timeout_is_a_fixed_failure(self):
        response = FakeResponse(read_error=socket.timeout("body"))
        result = child.run_transaction(value(), opener=FakeOpener(response))
        self.assertEqual(result, {"ok": False, "code": "request_failed"})

    def test_body_read_is_capped_at_max_body_plus_one(self):
        response = FakeResponse(body=b"x" * (child.MAX_BODY + 1))
        result = child.run_transaction(value(), opener=FakeOpener(response))
        self.assertEqual(response.limits, [child.MAX_BODY + 1])
        self.assertEqual(len(base64.b64decode(result["body_b64"])),
                         child.MAX_BODY + 1)

    def test_duplicate_input_keys_are_rejected(self):
        raw = (b'{"method":"GET","url":"' + URL.encode() + b'",'
               b'"token":null,"body_b64":null,"timeout":5,'
               b'"timeout":5}')
        decoded, failure = child._decode_input(raw)
        self.assertIsNone(decoded)
        self.assertEqual(failure, {"ok": False, "code": "input_invalid"})

    def test_oversized_input_is_rejected(self):
        decoded, failure = child._decode_input(
            b"{" + b"x" * child.MAX_INPUT_BYTES + b"}")
        self.assertIsNone(decoded)
        self.assertEqual(failure, {"ok": False, "code": "input_too_large"})

    def test_raw_exception_is_not_projected(self):
        opener = FakeOpener(error=RuntimeError(SECRET + " " + URL))
        result = child.run_transaction(value(token=SECRET), opener=opener)
        projected = json.dumps(result)
        self.assertNotIn(SECRET, projected)
        self.assertNotIn(URL, projected)
        self.assertEqual(result, {"ok": False, "code": "request_failed"})

    def test_body_limit_constants_match_the_fixture(self):
        self.assertEqual(http.MAX_BODY, fixture.MAX_BODY)
        self.assertEqual(child.MAX_BODY, fixture.MAX_BODY)


if __name__ == "__main__":
    unittest.main()
