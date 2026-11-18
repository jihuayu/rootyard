#!/usr/bin/env python3
"""Pure fake integration tests for the Vault fixture HTTP boundary.

The fixture's default opener is the owned bounded child, not an inline urllib
call.  Only fake clocks, fake runners and in-memory responses are used; no real
socket, HTTP server, Vault, Docker, PostgreSQL, Git fixture, process or thread
is started.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import unittest

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation_fixture as common  # noqa: E402
import pando_vault_rotation_fixture_vault as vault  # noqa: E402
import pando_vault_rotation_http as http  # noqa: E402
from pando_vault_rotation_budget import Budget  # noqa: E402
from pando_vault_rotation_support import QualificationError  # noqa: E402

SECRET = "app-token-SECRET-do-not-project"
HOST = "http://127.0.0.1:49152"
HEALTH = b'{"initialized":true,"sealed":false,"version":"2.2.2"}'


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


def encoded(status=200, body=b"{}"):
    return json.dumps({
        "ok": True,
        "status": status,
        "body_b64": base64.b64encode(body).decode("ascii"),
    }).encode()


def make_fixture(clock, runner, budget=None):
    fixture = vault.VaultFixture(
        Path("/never-read-state"), runner=runner,
        budget=budget, clock=clock)
    fixture.host_url = HOST
    return fixture


def make_budget(clock):
    return Budget(100, 20, clock=clock, error_factory=QualificationError)


class FixtureHttpIntegrationTest(unittest.TestCase):
    def test_default_opener_is_the_owned_bounded_child(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=encoded(body=HEALTH)))
        fixture = make_fixture(clock, runner, make_budget(clock))
        self.assertIsInstance(fixture.opener, http.BoundedHttpOpener)

    def test_health_success_flows_through_the_child_and_keeps_body_semantics(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=encoded(body=HEALTH)))
        fixture = make_fixture(clock, runner, make_budget(clock))
        self.assertTrue(fixture.health())
        self.assertEqual(len(runner.calls), 1)
        call = runner.calls[0]
        self.assertEqual(call["timeout"], 5.0)
        self.assertEqual(call["argv"][1], str(http.CHILD_SCRIPT))
        sent = json.loads(call["input"])
        self.assertEqual(sent["url"], HOST + "/v1/sys/health")
        self.assertEqual(sent["method"], "GET")
        self.assertIsNone(sent["token"])

    def test_token_and_body_stay_on_stdin_and_out_of_argv_and_env(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=encoded(body=b'{"data":{}}')))
        fixture = make_fixture(clock, runner, make_budget(clock))
        value = fixture.api(
            "POST", "/v1/transit/encrypt/key", {"plaintext": "cGxhaW4="},
            token=SECRET)
        self.assertEqual(value, {"data": {}})
        call = runner.calls[0]
        joined_argv = " ".join(call["argv"])
        self.assertNotIn(SECRET, joined_argv)
        self.assertNotIn(HOST, joined_argv)
        self.assertNotIn("PANDO_KMS_VAULT_TOKEN", call["env"])
        self.assertNotIn(SECRET, json.dumps(call["env"]))
        sent = json.loads(call["input"])
        self.assertEqual(sent["token"], SECRET)
        self.assertEqual(base64.b64decode(sent["body_b64"]),
                         b'{"plaintext": "cGxhaW4="}')

    def test_non_two_hundred_status_is_preserved_by_request_status(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=encoded(status=403, body=b"")))
        fixture = make_fixture(clock, runner, make_budget(clock))
        self.assertEqual(
            fixture.request_status("POST", "/v1/transit/keys/k/rotate"),
            403)
        with self.assertRaises(common.FixtureError) as caught:
            fixture.api("POST", "/v1/transit/keys/k/rotate")
        self.assertEqual(caught.exception.code, "vault_api_failed")

    def test_redirect_and_304_statuses_cannot_satisfy_a_denial_oracle(self):
        clock = Clock()
        for status in (302, 307, 308, 304):
            with self.subTest(status=status):
                runner = FakeRunner(Result(
                    stdout=encoded(status=status, body=b"")))
                fixture = make_fixture(clock, runner, make_budget(clock))
                self.assertEqual(
                    fixture.request_status("GET", "/v1/sys/health"), status)
                with self.assertRaises(common.FixtureError) as caught:
                    fixture.api("GET", "/v1/sys/health")
                self.assertEqual(caught.exception.code, "vault_api_failed")

    def test_oversized_success_body_is_still_rejected_by_the_existing_api(self):
        clock = Clock()
        runner = FakeRunner(Result(
            stdout=encoded(body=b"x" * (common.MAX_BODY + 1))))
        fixture = make_fixture(clock, runner, make_budget(clock))
        with self.assertRaises(common.FixtureError) as caught:
            fixture.api("GET", "/v1/sys/health")
        self.assertEqual(caught.exception.code, "vault_api_response_too_large")

    def test_empty_success_body_remains_an_empty_mapping(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=encoded(body=b"")))
        fixture = make_fixture(clock, runner, make_budget(clock))
        self.assertEqual(fixture.api("DELETE", "/v1/transit/keys/k"), {})

    def test_non_json_success_body_is_invalid(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=encoded(body=b"plain-text")))
        fixture = make_fixture(clock, runner, make_budget(clock))
        with self.assertRaises(common.FixtureError) as caught:
            fixture.api("GET", "/v1/sys/health")
        self.assertEqual(caught.exception.code, "vault_api_invalid")

    def test_expired_budget_never_spawns_the_http_child(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=encoded(body=HEALTH)))
        fixture = make_fixture(clock, runner, make_budget(clock))
        clock.advance(80)
        with self.assertRaises(common.FixtureError) as caught:
            fixture.api("GET", "/v1/sys/health")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")
        self.assertEqual(runner.calls, [])

    def test_late_child_return_is_not_green_through_the_fixture(self):
        clock = Clock()
        runner = FakeRunner(Result(stdout=encoded(body=HEALTH)),
                            advance=80, clock=clock)
        fixture = make_fixture(clock, runner, make_budget(clock))
        with self.assertRaises(common.FixtureError) as caught:
            fixture.api("GET", "/v1/sys/health")
        self.assertEqual(caught.exception.code, "work_deadline_exceeded")

    def test_child_timeout_is_not_green_through_the_fixture(self):
        clock = Clock()
        runner = FakeRunner(
            error=QualificationError("subprocess_timeout", "subprocess"))
        fixture = make_fixture(clock, runner, make_budget(clock))
        with self.assertRaises(common.FixtureError) as caught:
            fixture.api("GET", "/v1/sys/health")
        self.assertEqual(caught.exception.code, "vault_api_failed")

    def test_missing_child_fails_closed_without_an_inline_fallback(self):
        clock = Clock()
        runner = FakeRunner(
            error=QualificationError("subprocess_failed", "subprocess"))
        fixture = make_fixture(clock, runner, make_budget(clock))
        fixture.opener = http.BoundedHttpOpener(
            runner, fixture.budget, child=Path("/never-present/http-child.py"))
        with self.assertRaises(common.FixtureError) as caught:
            fixture.api("GET", "/v1/sys/health")
        self.assertEqual(caught.exception.code, "vault_api_failed")
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0]["argv"][1],
                         "/never-present/http-child.py")


if __name__ == "__main__":
    unittest.main()
