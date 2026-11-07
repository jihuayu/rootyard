#!/usr/bin/env python3
"""Real browser-session exchange, workflow, CSRF, expiry and revocation checks.

The harness speaks plain HTTP itself (so it can inspect headers and replay old
cookies), but the session lifecycle under test is the same one used by the
Chromium acceptance harness in tests/browser_ui.py.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import traceback
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness


class BrowserHarness(Harness):
    def request(self, path, method="GET", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        result = (response.status, response.read(), response.getheaders())
        conn.close()
        return result

    @staticmethod
    def response_header(headers, name):
        for key, value in headers:
            if key.lower() == name.lower():
                return value
        return None

    @staticmethod
    def split_cookies(headers):
        cookies = {}
        raw = {}
        for key, value in headers:
            if key.lower() != "set-cookie":
                continue
            name, first = value.split(";", 1)[0].split("=", 1)
            cookies[name] = first
            raw[name] = value
        return cookies, raw

    def login(self, token=None, username="alice", return_to=None, extra_headers=None):
        fields = {"username": username, "token": token or self.alice["token"]}
        if return_to is not None:
            fields["return_to"] = return_to
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.base,
        }
        headers.update(extra_headers or {})
        return self.request(
            "/web/login", "POST", urllib.parse.urlencode(fields), headers
        )

    def sign_in(self, return_to=None):
        status, data, headers = self.login(return_to=return_to)
        assert status == 303, (status, data)
        cookies, raw = self.split_cookies(headers)
        assert cookies["rootyard_session"].startswith("ryt_")
        assert cookies["rootyard_csrf"]
        self.secrets.extend(cookies.values())
        return cookies, raw, headers

    @staticmethod
    def cookie_header(cookies):
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def run_flow(self):
        self.setup()
        self.api()
        self.roundtrip()

        login_page = self.request("/web/login")
        assert login_page[0] == 200 and b"type=\"password\"" in login_page[1]

        # A fresh browser navigation to a locked page is redirected to a usable
        # sign-in page and carries a same-origin return target.
        nav = {"Accept": "text/html", "Sec-Fetch-Mode": "navigate"}
        status, body, headers = self.request("/web/repos/alice/demo", headers=nav)
        assert status == 303, (status, body[:200])
        location = self.response_header(headers, "Location")
        assert location.startswith("/web/login?return_to="), location
        assert "alice%2Fdemo" in location

        cookies, raw, headers = self.sign_in(return_to="/web/repos/alice/demo")
        assert self.response_header(headers, "Location") == "/web/repos/alice/demo"
        session_cookie = cookies["rootyard_session"]
        assert "HttpOnly" in raw["rootyard_session"]
        assert "SameSite=Strict" in raw["rootyard_session"]
        assert "Path=/" in raw["rootyard_session"]
        assert "HttpOnly" not in raw["rootyard_csrf"]
        assert "SameSite=Strict" in raw["rootyard_csrf"]

        headers = {"Cookie": self.cookie_header(cookies)}
        status, page, _ = self.request("/web/repos", headers=headers)
        assert status == 200 and b"alice/demo" in page
        assert self.alice["token"].encode() not in page
        assert session_cookie.encode() not in page
        assert self.request("/web/repos/alice/demo", headers=headers)[0] == 200

        # API/Git reject browser session credentials; the browser session is
        # not a long-lived API token and cannot be used as one.
        assert self.request(
            "/api/repos", headers={"Authorization": "Bearer " + session_cookie}
        )[0] == 401
        assert self.request(
            "/git/alice/demo.git/info/refs?service=git-upload-pack",
            headers={"Authorization": "Bearer " + session_cookie},
        )[0] == 401

        # Raw API cookies/headers are no longer a browser-login bypass.
        assert self.request(
            "/web/repos/alice/demo",
            headers={"Cookie": "rootyard_token=" + self.alice["token"]},
        )[0] == 401
        assert self.request(
            "/web/repos/alice/demo",
            headers={"X-Rootyard-Token": self.alice["token"]},
        )[0] == 401

        # A browser session cannot mint another session by replaying itself in
        # the API-token field, so revocation cannot be extended indefinitely.
        status, body, _ = self.login(token=session_cookie)
        assert status == 401, (status, body[:200])

        # A browser credential is not accepted as an Authorization header on
        # web routes (no cookie/parent binding or CSRF path), while API tokens
        # remain usable independently.
        assert self.request(
            "/web/repos", headers={"Authorization": "Bearer " + session_cookie}
        )[0] == 401
        basic = base64.b64encode(("alice:" + session_cookie).encode()).decode()
        assert self.request(
            "/web/repos", headers={"Authorization": "Basic " + basic}
        )[0] == 401
        assert self.request(
            "/web/repos/alice/demo",
            headers={"Authorization": "Bearer " + self.alice["token"]},
        )[0] == 200

        path = "/web/repos/alice/demo/issues"
        payload = json.dumps({"title": "Browser issue", "body": "Started in UI"})
        mutation = {
            **headers,
            "Content-Type": "application/json",
            "Origin": self.base,
            "X-CSRF-Token": cookies["rootyard_csrf"],
        }
        assert self.request(path, "POST", payload, headers)[0] == 403
        assert self.request(
            path, "POST", payload, {**mutation, "X-CSRF-Token": "0" * 64}
        )[0] == 403
        assert self.request(
            path, "POST", payload, {**mutation, "Origin": "https://evil.example"}
        )[0] == 403
        # A browser credential in Authorization without the cookie must not
        # create an issue or bypass origin/CSRF checks.
        assert self.request(
            path,
            "POST",
            payload,
            {"Authorization": "Bearer " + session_cookie, "Content-Type": "application/json"},
        )[0] == 401
        # A session cookie plus an Authorization header must not bypass CSRF.
        assert self.request(
            path,
            "POST",
            payload,
            {
                **headers,
                "Authorization": "Bearer " + session_cookie,
                "Content-Type": "application/json",
                "Origin": self.base,
            },
        )[0] == 403
        status, body, _ = self.request(path, "POST", payload, mutation)
        assert status == 201, (status, body[:300])
        assert b"Browser issue" in body

        self.git("checkout", "-b", "feature", cwd=self.work)
        (self.work / "browser.txt").write_text("browser PR\n")
        self.git("add", "browser.txt", cwd=self.work)
        self.git("commit", "-m", "browser feature", cwd=self.work)
        head = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:feature", cwd=self.work, token=self.alice)
        path = "/web/repos/alice/demo/pulls"
        payload = json.dumps({"title": "Browser PR", "head_ref": "feature", "base_ref": "main"})
        status, body, _ = self.request(path, "POST", payload, mutation)
        assert status == 201, (status, body[:300])
        assert b"Browser PR" in body
        pull = json.loads(self.expect("/api/repos/alice/demo/pulls/1", 200, token=self.alice))
        merge = json.dumps(
            {
                "expected_version": pull["version"],
                "expected_head_oid": head,
                "expected_base_oid": pull["base_oid"],
            }
        )
        status, body, _ = self.request(path + "/1/merge", "POST", merge, mutation)
        assert status == 200, (status, body[:300])
        assert b"merged" in body

        # Return-to is constrained to same-origin web/UI paths.
        for bad in ("https://evil.example/x", "//evil.example/x", "/\\evil.example", "/web/login"):
            status, _, headers = self.login(return_to=bad)
            assert status == 303, (bad, status)
            assert self.response_header(headers, "Location") == "/web/repos", bad
            ret_cookies, _ = self.split_cookies(headers)
            session_headers = {"Cookie": self.cookie_header(ret_cookies)}
            assert self.request("/web/repos", headers=session_headers)[0] == 200

        # HTTPS/proxy semantics: non-loopback HTTP is rejected, while a trusted
        # HTTPS termination marks the browser cookies Secure.
        status, _, _ = self.login(
            extra_headers={"Host": "example.com", "Origin": "http://example.com"}
        )
        assert status == 403
        status, _, forwarded = self.login(
            extra_headers={
                "Host": "example.com",
                "Origin": "https://example.com",
                "X-Forwarded-Proto": "https",
            }
        )
        assert status == 303, status
        forwarded_cookies, forwarded_raw = self.split_cookies(forwarded)
        assert forwarded_cookies["rootyard_session"]
        assert "Secure" in forwarded_raw["rootyard_session"]
        assert "Secure" in forwarded_raw["rootyard_csrf"]

        # Session fixation: an attacker-supplied cookie is not accepted and is
        # replaced by the login response.
        forged = "ryt_" + "ab" * 32
        assert self.request(
            "/web/repos", headers={"Cookie": "rootyard_session=" + forged}
        )[0] == 401
        cookies, _, _ = self.sign_in()
        assert cookies["rootyard_session"] != forged
        assert self.request(
            "/web/repos", headers={"Cookie": "rootyard_session=" + forged}
        )[0] == 401

        # Expired sessions fail for direct HTTP and redirect browser navigation.
        headers = {"Cookie": self.cookie_header(cookies)}
        token_id = self.sql(
            "SELECT token_id FROM web_sessions ORDER BY created_at DESC LIMIT 1"
        )
        self.sql(
            f"UPDATE web_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE token_id='{token_id}'"
        )
        assert self.request("/web/repos", headers=headers)[0] == 401
        status, _, expired_headers = self.request("/web/repos", headers={**headers, **nav})
        assert status == 303
        assert self.response_header(expired_headers, "Location").startswith("/web/login")

        # Revoked session rows fail even though the parent API token is active.
        cookies, _, _ = self.sign_in()
        headers = {"Cookie": self.cookie_header(cookies)}
        token_id = self.sql(
            "SELECT token_id FROM web_sessions ORDER BY created_at DESC LIMIT 1"
        )
        self.sql(f"UPDATE web_sessions SET revoked=true WHERE token_id='{token_id}'")
        assert self.request("/web/repos", headers=headers)[0] == 401

        # Cross-origin logout is rejected; same-origin logout revokes the old
        # cookie so it cannot be replayed.
        cookies, _, _ = self.sign_in()
        headers = {"Cookie": self.cookie_header(cookies)}
        assert self.request(
            "/web/logout",
            "POST",
            headers={**headers, "Origin": "https://evil.example"},
        )[0] == 403
        assert self.request("/web/repos", headers=headers)[0] == 200
        assert self.request(
            "/web/logout", "POST", headers={**headers, "Origin": self.base}
        )[0] == 303
        assert self.request("/web/repos", headers=headers)[0] == 401

        # Parent API token revocation terminates the derived browser session.
        cookies, _, _ = self.sign_in()
        headers = {"Cookie": self.cookie_header(cookies)}
        assert self.request("/web/repos", headers=headers)[0] == 200
        self.sql(f"UPDATE tokens SET revoked=true WHERE id='{self.alice['token_id']}'")
        assert self.request("/web/repos", headers=headers)[0] == 401
        status, _, revoked_headers = self.request("/web/repos", headers={**headers, **nav})
        assert status == 303
        assert self.response_header(revoked_headers, "Location").startswith("/web/login")
        assert self.login()[0] == 401


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = BrowserHarness(args)
    passed = False
    failure_traceback = None
    try:
        harness.case("browser_session_workflow", harness.run_flow)
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
