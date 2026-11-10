#!/usr/bin/env python3
"""Native loopback harness for bounded authentication admission (partial #84).

Runs the real service, real PostgreSQL metadata and real TCP peers. It verifies
that login/token exchange and the explicit identity lookup are rejected with a
fixed ``429`` + ``Retry-After`` before credentials are checked, that spoofed
``X-Forwarded-For``/``Forwarded`` headers do not create new per-source buckets,
that an unrelated loopback source keeps its own budget, that the fixed window
recovers, and that no bearer token reaches a response or the server log.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import time
import traceback
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness

RETRY_AFTER = "60"


class AuthAdmissionHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        # Production defaults are conservative; this harness uses a tiny budget
        # so the real rejection path is deterministic without a global sleep.
        self.env.update(
            ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE="3",
            ROOTYARD_AUTH_ADMISSION_SOURCE_WINDOW_SECONDS="2",
            ROOTYARD_AUTH_ADMISSION_MAX_SOURCES="32",
            ROOTYARD_AUTH_ADMISSION_SOURCE_TTL_SECONDS="4",
            ROOTYARD_AUTH_ADMISSION_MAX_INFLIGHT="2",
        )

    def raw(self, source_ip, path, method="GET", body=None, headers=None):
        """Send from a real loopback source address so the service sees a peer."""
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=20, source_address=(source_ip, 0)
        )
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            conn.close()

    @staticmethod
    def header(headers, name):
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def whoami(self, source_ip, extra_headers=None):
        headers = {"Authorization": "Bearer " + self.alice["token"]}
        headers.update(extra_headers or {})
        return self.raw(source_ip, "/api/auth/whoami", headers=headers)

    def login(self, source_ip, token=None, username="alice"):
        body = urllib.parse.urlencode({"username": username, "token": token or self.alice["token"]})
        return self.raw(
            source_ip,
            "/web/login",
            method="POST",
            body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.base,
            },
        )

    def run_flow(self):
        self.setup()
        token = self.alice["token"]
        self.secrets.append(token)

        # Three attempts consume this peer's budget; changing every spoofed
        # forwarding header must not move the bucket.
        for index in range(3):
            spoof = f"203.0.113.{10 + index}"
            status, body, headers = self.whoami(
                "127.0.0.1", {"X-Forwarded-For": spoof, "Forwarded": f"for={spoof}"}
            )
            assert status == 200, (status, body[:200])
            assert token.encode() not in body

        status, body, headers = self.whoami(
            "127.0.0.1", {"X-Forwarded-For": "203.0.113.99", "Forwarded": "for=203.0.113.99"}
        )
        assert status == 429, (status, body[:200])
        assert self.header(headers, "Retry-After") == RETRY_AFTER
        assert self.header(headers, "Cache-Control") == "no-store"
        assert token.encode() not in body
        assert b"alice" not in body
        assert b"127.0.0.1" not in body
        assert b"203.0.113.99" not in body

        # An invalid credential is also rejected by admission first, so an
        # overload cannot be used as a credential oracle.
        status, invalid_body, invalid_headers = self.raw(
            "127.0.0.1",
            "/api/auth/whoami",
            headers={
                "Authorization": "Bearer ryt_" + "0" * 64,
                "X-Forwarded-For": "198.51.100.200",
            },
        )
        assert status == 429, (status, invalid_body[:200])
        assert invalid_body == body, "admission response differs by credential validity"
        assert self.header(invalid_headers, "Retry-After") == RETRY_AFTER

        # A real unrelated loopback peer has an independent budget.
        status, body, _ = self.whoami("127.0.0.2")
        assert status == 200, (status, body[:200])

        # The browser login/token-exchange POST shares the same pre-DB gate.
        for _ in range(3):
            status, body, _ = self.login("127.0.0.3", token="ryt_" + "0" * 64)
            assert status == 401, (status, body[:200])
        status, body, headers = self.login("127.0.0.3", token="ryt_" + "0" * 64)
        assert status == 429, (status, body[:200])
        assert self.header(headers, "Retry-After") == RETRY_AFTER
        # Even the valid token is refused while the source is limited: no
        # credential verification happened for the rejected attempt.
        status, body, headers = self.login("127.0.0.3")
        assert status == 429, (status, body[:200])
        assert self.header(headers, "Retry-After") == RETRY_AFTER

        # The fixed window recovers without any global test sleep.
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            status, body, headers = self.login("127.0.0.3")
            if status != 429:
                break
            time.sleep(0.1)
        assert status == 303, (status, body[:200])
        assert self.header(headers, "Location") == "/web/repos"

        log_text = (self.root / "server.log").read_text(encoding="utf-8", errors="replace")
        for secret in self.secrets:
            if secret:
                assert secret not in log_text, "credential leaked into server log"
        assert token not in log_text

    def no_secret_response_leak(self):
        # The token may only appear in the request header, never in a rejection
        # body or a successful whoami body.
        token = self.alice["token"].encode()
        status, body, _ = self.whoami("127.0.0.4")
        assert status == 200, status
        assert token not in body
        assert b"token_digest" not in body
        assert b"ryt_" not in body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = AuthAdmissionHarness(args)
    harness.limits.extend(
        [
            "Admission state is per process; multi-replica aggregate budgets are not implemented.",
            "Loopback peers are real TCP peers, but proxy/NAT aggregation and trusted-proxy identity are not modeled.",
            "Missing ConnectInfo refusal is covered by Rust unit tests because a served socket always supplies a peer.",
            "MFA, OIDC, identity providers, e-mail binding and distributed rate limiting are explicitly not implemented (partial issue #84).",
        ]
    )
    passed = False
    failure_traceback = None
    try:
        harness.case("spoofed_forwarded_headers_and_429_before_db", harness.run_flow)
        harness.case("no_secret_response_leak", harness.no_secret_response_leak)
        passed = True
    except Exception as exc:
        failure_traceback = harness.redact(traceback.format_exc(limit=12))[-4000:]
        print(harness.redact(exc), file=sys.stderr)
        print(failure_traceback, file=sys.stderr)
    finally:
        harness.cleanup()
        report = {
            "passed": passed,
            "cases": harness.results,
            "limitations": harness.limits,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "failure_traceback": failure_traceback,
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
