#!/usr/bin/env python3
"""Token and browser-session management regression against the REAL binary.

Native end-to-end harness: a real service process, real PostgreSQL schema and
real HTTP requests. The coordinator runs it with --binary/--report; this file is
only py-compiled by the implementation worker and makes no pass claim on its
own.

SQL use (declared): the only SQL statements are fixture/verification via the
existing Harness bootstrap channel (`h.sql`):
  * resolve repository ids the server created (no feature is seeded),
  * verify the stored digest and the absence of plaintext token columns,
  * move one token's `expires_at` into the past to test expiry without waiting,
  * flip one repository to `state='provisioning'` for the rotation-abort case
    and restore it afterwards.
No restricted token, grant or session is SQL-seeded: every managed token and
browser session is created through the real API/UI under test.

Every case asserts an exact HTTP status and response shape. Missing routes,
wrong codes and exception paths fail; there is no TODO/pass placeholder.
"""
import argparse
import base64
import hashlib
import http.client
import json
import sys
import time
import traceback
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from e2e import Harness  # noqa: E402  (reuse the vetted harness)

NOTES = [
    "Every managed token is issued by POST /api/tokens (real service); only repository ids, digest verification, expiry time travel and the repository provisioning-state fixture use SQL.",
    "The browser cases use the real /web/login form and the real cookie/Origin/CSRF middleware. Login is issued with http.client so both Set-Cookie headers (session + CSRF) are observable; all other requests use the shared Harness HTTP path.",
    "Basic Authorization on a web mutation is ambient browser authority and is rejected with 403 regardless of Origin; Bearer remains an explicit non-ambient API credential.",
    "Rotation re-validates every copied grant. Any failure (lost role, non-ready repository, database error) aborts before a new row or revocation, so it cannot silently drop a scope.",
    "The Git CAS parent-token lock and restricted browser-child inheritance are tracked on a separate branch; this suite does not exercise or claim them.",
]


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def header(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def body(name, grants=None, namespaces=None, days=30, read_only=False):
    return {
        "display_name": name,
        "expires_in_days": days,
        "read_only": read_only,
        "repository_grants": grants or [],
        "namespace_grants": namespaces or [],
    }


def repo_grant(repo_id, actions):
    return [{"repository_id": repo_id, "actions": actions}]


def issue(h, token, payload, expected=201):
    status, raw, headers = h.http("/api/tokens", token=token, method="POST", body=payload)
    assert status == expected, f"POST /api/tokens: expected {expected}, got {status}: {raw[:300]!r}"
    data = json.loads(raw)
    if isinstance(data, dict) and "secret" in data:
        h.secrets.append(data["secret"])
    return data, headers


def token_list(h, token, suffix=""):
    raw = h.expect("/api/tokens" + suffix, 200, token=token)
    page = json.loads(raw)
    assert isinstance(page, dict) and isinstance(page.get("items"), list), page
    return page, raw


def ids(page):
    return [item["id"] for item in page["items"]]


def assert_safe_metadata(raw, secret):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    lowered = raw.lower()
    assert secret not in raw, "list/read response leaked the plaintext secret"
    for forbidden in ('"digest"', '"secret"', '"csrf', '"session'):
        assert forbidden not in lowered, f"metadata response contains {forbidden}: {raw[:300]!r}"


def repo_id(h, owner, name):
    value = h.sql(
        "SELECT r.id FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id "
        f"WHERE ns.slug = {quote(owner)} AND r.name = {quote(name)}"
    )
    assert value, f"repository {owner}/{name} not found"
    return value


def login_browser(h, username, token):
    """Real form login; return cookies without following the 303."""
    connection = http.client.HTTPConnection("127.0.0.1", h.port, timeout=20)
    payload = urllib.parse.urlencode({"username": username, "token": token}).encode()
    connection.request(
        "POST",
        "/web/login",
        body=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": h.base,
            "Accept": "text/html",
        },
    )
    response = connection.getresponse()
    raw = response.read()
    status = response.status
    cookies = {}
    for name, value in response.getheaders():
        if name.lower() == "set-cookie":
            pair = value.split(";", 1)[0]
            key, _, cookie_value = pair.partition("=")
            cookies[key] = cookie_value
    connection.close()
    assert status == 303, f"web login: expected 303, got {status}: {raw[:300]!r}"
    assert "rootyard_session" in cookies and "rootyard_csrf" in cookies, cookies
    return cookies


def cookie_header(cookies):
    return "rootyard_session=" + cookies["rootyard_session"] + "; rootyard_csrf=" + cookies["rootyard_csrf"]


def run_case(h, name, fn):
    started = time.monotonic()
    try:
        detail = fn() or ""
        h.results.append(dict(name=name, status="passed",
                              seconds=round(time.monotonic() - started, 4), detail=detail))
    except Exception as error:  # noqa: BLE001 - every failure is reported, never swallowed
        h.results.append(dict(name=name, status="failed",
                              seconds=round(time.monotonic() - started, 4),
                              error=h.redact(error),
                              trace=h.redact(traceback.format_exc())[-2000:]))
    return h.results[-1]


def main():
    parser = argparse.ArgumentParser(description="Token/session management regression (real service)")
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, help="Write machine-readable JSON report (no credentials)")
    parser.add_argument("--keep", action="store_true", help="Keep temporary data directory")
    args = parser.parse_args()

    h = Harness(args)
    exit_code = 1
    try:
        h.setup()
        json.loads(h.expect("/api/repos", 201, method="POST", token=h.alice, body={"name": "demo"}))
        json.loads(h.expect("/api/repos", 201, method="POST", token=h.bob, body={"name": "other"}))
        demo = repo_id(h, "alice", "demo")
        other = repo_id(h, "bob", "other")

        def case_create_once_digest_only():
            data, headers = issue(h, h.alice, body("deploy", repo_grant(demo, ["contents_read", "repo_read"])))
            secret = data["secret"]
            assert secret.startswith("ryt_") and len(secret) == 68, "secret shape is not 68-char ryt_"
            assert data["is_restricted"] is True and data["scope_version"] == 1, data
            assert data["display_name"] == "deploy" and data["expires_at"], data
            assert header(headers, "Cache-Control") == "no-store", headers
            assert header(headers, "X-Content-Type-Options") == "nosniff", headers
            row = h.sql(
                "SELECT encode(digest,'hex') || '|' || (SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name='tokens' "
                "AND column_name IN ('secret','token','plaintext')) "
                f"FROM tokens WHERE id = {quote(data['id'])}"
            )
            digest, plaintext_columns = row.split("|")
            assert digest == hashlib.sha256(secret.encode()).hexdigest(), "stored digest mismatch"
            assert plaintext_columns == "0", "plaintext credential column present"
            page, raw = token_list(h, h.alice)
            assert any(item["id"] == data["id"] for item in page["items"]), "issued token not listed"
            assert_safe_metadata(raw, secret)
            single = h.expect(f"/api/tokens/{data['id']}", 200, token=h.alice)
            assert_safe_metadata(single, secret)
            h.alice_managed = data
            return "create 201 once; digest-only; list/read carry no secret/digest"

        def case_owner_404():
            managed = h.alice_managed
            h.expect(f"/api/tokens/{managed['id']}", 404, token=h.bob)
            h.expect(f"/api/tokens/{managed['id']}", 404, method="PATCH", token=h.bob,
                     body={"expected_scope_version": managed["scope_version"]})
            h.expect(f"/api/tokens/{managed['id']}", 404, method="DELETE", token=h.bob)
            h.expect(f"/api/tokens/{managed['id']}/rotate", 404, method="POST", token=h.bob)
            bob_page, _ = token_list(h, h.bob)
            assert managed["id"] not in ids(bob_page), "cross-user token leaked into list"
            return "cross-user get/patch/delete/rotate 404; list isolated"

        def case_restricted_and_readonly_issuer_403():
            managed = h.alice_managed
            restricted = {"username": "alice", "token": managed["secret"]}
            h.expect("/api/tokens", 403, token=restricted)
            h.expect("/api/tokens", 403, method="POST", token=restricted,
                     body=body("should-fail"))
            h.expect("/api/tokens", 200, token=h.reader)  # read-only may read metadata
            h.expect("/api/tokens", 403, method="POST", token=h.reader, body=body("should-fail"))
            h.expect(f"/api/tokens/{managed['id']}", 403, method="DELETE", token=h.reader)
            return "restricted issuer 403; read-only issuer write 403, read 200"

        def case_scope_patch_subset_and_version():
            data, _ = issue(h, h.alice, body("narrow", repo_grant(demo, ["contents_read", "repo_read"])))
            restricted = {"username": "alice", "token": data["secret"]}
            h.expect("/api/repos/alice/demo", 200, token=restricted)
            narrowed = json.loads(h.expect(
                f"/api/tokens/{data['id']}", 200, method="PATCH", token=h.alice,
                body={"expected_scope_version": 1,
                      "repository_grants": repo_grant(demo, ["contents_read"])},
            ))
            assert narrowed["scope_version"] == 2, narrowed
            actions = narrowed["repository_grants"][0]["actions"]
            assert actions == ["contents_read"], actions
            h.expect("/api/repos/alice/demo", 403, token=restricted)
            h.expect(f"/api/tokens/{data['id']}", 403, method="PATCH", token=h.alice,
                     body={"expected_scope_version": 2,
                           "repository_grants": repo_grant(demo, ["contents_read", "contents_write"])})
            h.expect(f"/api/tokens/{data['id']}", 409, method="PATCH", token=h.alice,
                     body={"expected_scope_version": 1,
                           "repository_grants": repo_grant(demo, ["contents_read"])})
            deny_all = json.loads(h.expect(
                f"/api/tokens/{data['id']}", 200, method="PATCH", token=h.alice,
                body={"expected_scope_version": 2, "repository_grants": [], "namespace_grants": []},
            ))
            assert deny_all["repository_grants"] == [] and deny_all["namespace_grants"] == []
            assert deny_all["scope_version"] == 3, deny_all
            assert json.loads(h.expect("/api/repos", 200, token=restricted)) == [], "deny-all listed a repo"
            h.expect("/api/repos/alice/demo", 403, token=restricted)
            return "patch subset 200/version bump; widening 403; stale CAS 409; empty deny-all"

        def case_rotation():
            data, _ = issue(h, h.alice, body("rotate", repo_grant(demo, ["contents_read", "repo_read"])))
            old = {"username": "alice", "token": data["secret"]}
            status, raw, headers = h.http(f"/api/tokens/{data['id']}/rotate", method="POST",
                                          token=h.alice, body={})
            assert status == 200, f"rotate expected 200, got {status}: {raw[:300]!r}"
            rotated = json.loads(raw)
            h.secrets.append(rotated["secret"])
            assert rotated["id"] != data["id"], "rotation reused the token id"
            assert header(headers, "Cache-Control") == "no-store", headers
            assert rotated["repository_grants"][0]["actions"] == ["contents_read", "repo_read"], rotated
            h.expect("/api/repos", 401, token=old)
            fresh = {"username": "alice", "token": rotated["secret"]}
            pairs = [(item["owner"], item["name"]) for item in json.loads(h.expect("/api/repos", 200, token=fresh))]
            assert pairs == [("alice", "demo")], f"rotated scopes differ: {pairs}"
            h.expect(f"/api/tokens/{data['id']}/rotate", 409, method="POST", token=h.alice, body={})
            return "rotation 200 once; old 401; new exact scopes; repeat 409"

        def case_revoke_idempotent():
            data, _ = issue(h, h.alice, body("revoke-me", repo_grant(demo, ["repo_read"])))
            token = {"username": "alice", "token": data["secret"]}
            h.expect(f"/api/tokens/{data['id']}", 204, method="DELETE", token=h.alice)
            h.expect("/api/repos", 401, token=token)
            h.expect(f"/api/tokens/{data['id']}", 204, method="DELETE", token=h.alice)
            page, _ = token_list(h, h.alice)
            assert data["id"] not in ids(page), "revoked token still listed"
            return "revoke 204, use 401, repeated revoke 204, delisted"

        def case_expiry_bounds_and_time_travel():
            for days in (0, 366):
                h.expect("/api/tokens", 400, method="POST", token=h.alice, body=body("bad-expiry", days=days))
            data, _ = issue(h, h.alice, body("expiring", repo_grant(demo, ["repo_read"]), days=30))
            token = {"username": "alice", "token": data["secret"]}
            h.expect("/api/repos/alice/demo", 200, token=token)
            h.sql(f"UPDATE tokens SET expires_at = clock_timestamp() - interval '1 second' WHERE id = {quote(data['id'])}")
            h.expect("/api/repos/alice/demo", 401, token=token)
            return "days 0/366 rejected 400; expired token 401"

        def case_sessions_own_only():
            cookies_one = login_browser(h, "alice", h.alice["token"])
            page = json.loads(h.expect("/api/sessions", 200, token=h.alice))
            assert page["items"], "own browser session not listed"
            session_id = page["items"][0]["token_id"]
            raw = json.dumps(page)
            assert cookies_one["rootyard_session"] not in raw and cookies_one["rootyard_csrf"] not in raw
            cookies_two = login_browser(h, "alice", h.alice["token"])
            h.expect(f"/api/sessions/{session_id}", 404, method="DELETE", token=h.bob)
            second = json.loads(h.expect("/api/sessions", 200, token=h.alice))
            assert len(second["items"]) >= 2, second
            h.expect(f"/api/sessions/{session_id}", 204, method="DELETE", token=h.alice)
            remaining = json.loads(h.expect("/api/sessions", 200, token=h.alice))
            assert session_id not in [item["token_id"] for item in remaining["items"]], "revoked session still listed"
            # The revoked session secret no longer authenticates the browser UI.
            h.expect("/web/settings/tokens", 401, extra_headers={"Cookie": cookie_header(cookies_one)})
            h.expect(f"/api/sessions/{session_id}", 204, method="DELETE", token=h.alice)
            h.sessions = (session_id, cookies_two)
            return "own sessions listed/revoked 204; other user 404; revoked cookie 401"

        def case_web_cookie_csrf_and_basic():
            cookies = h.sessions[1]
            cookie = cookie_header(cookies)
            csrf = cookies["rootyard_csrf"]
            page_raw = h.expect("/web/settings/tokens", 200, extra_headers={"Cookie": cookie})
            assert b"Personal access tokens" in page_raw, page_raw[:300]
            h.expect("/web/settings/tokens", 403, method="POST", body=body("ui-csrf-missing"),
                     extra_headers={"Cookie": cookie, "Origin": h.base})
            h.expect("/web/settings/tokens", 403, method="POST", body=body("ui-cross-origin"),
                     extra_headers={"Cookie": cookie, "Origin": "http://evil.example",
                                    "X-CSRF-Token": csrf})
            status, raw, headers = h.http("/web/settings/tokens", method="POST",
                                          body=body("ui-created", repo_grant(demo, ["repo_read"])),
                                          extra_headers={"Cookie": cookie, "Origin": h.base,
                                                         "X-CSRF-Token": csrf})
            assert status == 201, f"web create expected 201, got {status}: {raw[:300]!r}"
            created = json.loads(raw)
            h.secrets.append(created["secret"])
            assert header(headers, "Cache-Control") == "no-store", headers
            assert header(headers, "X-Content-Type-Options") == "nosniff", headers
            assert created["secret"].encode() not in h.expect("/web/settings/tokens", 200,
                                                     extra_headers={"Cookie": cookie})
            # Basic is ambient browser authority: a cross-site form post with a
            # Basic credential is rejected, and the target token stays live.
            basic = "Basic " + base64.b64encode(("alice:" + h.alice["token"]).encode()).decode()
            basic_headers = {"Authorization": basic, "Origin": "http://evil.example",
                             "Cookie": cookie}
            for method_path in (f"/web/settings/tokens/{created['id']}/rotate",
                                f"/web/settings/tokens/{created['id']}/revoke"):
                status, _, _ = h.http(method_path, method="POST", body=b"x=1",
                                      content_type="application/x-www-form-urlencoded",
                                      extra_headers=basic_headers)
                assert status == 403, f"Basic ambient {method_path}: expected 403, got {status}"
            h.expect(f"/api/tokens/{created['id']}", 200, token=h.alice)
            # The old secret still authenticates, proving Basic did not rotate/revoke.
            h.expect("/api/repos", 200, token={"username": "alice", "token": created["secret"]})
            # Same-origin cookie + CSRF still rotates, and the old secret dies.
            status, raw, _ = h.http(f"/web/settings/tokens/{created['id']}/rotate", method="POST",
                                    body={}, extra_headers={"Cookie": cookie, "Origin": h.base,
                                                            "X-CSRF-Token": csrf})
            assert status == 200, f"cookie rotate expected 200, got {status}: {raw[:300]!r}"
            rotated = json.loads(raw)
            h.secrets.append(rotated["secret"])
            h.expect("/api/repos", 401, token={"username": "alice", "token": created["secret"]})
            h.sessions_page = h.expect("/web/settings/sessions", 200, extra_headers={"Cookie": cookie})
            assert b"Browser sessions" in h.sessions_page
            return "cookie+CSRF create/rotate 200; missing CSRF/cross-origin/Basic 403; secret once"

        def case_api_authorization_only():
            cookies = h.sessions[1]
            cookie = cookie_header(cookies)
            h.expect("/api/tokens", 401, extra_headers={"Cookie": cookie})
            h.expect("/api/tokens", 401, extra_headers={"Cookie": cookie, "X-Rootyard-Browser": "1"})
            h.expect("/api/tokens", 401, extra_headers={"Cookie": cookie, "Origin": h.base})
            return "API accepts Authorization only; cookie/marker cannot authenticate"

        def case_keyset_and_actor_cursor():
            h.expect("/api/tokens?limit=0", 400, token=h.alice)
            h.expect("/api/tokens?limit=101", 400, token=h.alice)
            for index in range(3):
                issue(h, h.alice, body(f"page-{index}", repo_grant(demo, ["repo_read"])))
            first = json.loads(h.expect("/api/tokens?limit=2", 200, token=h.alice))
            assert len(first["items"]) == 2 and first["next_after"], first
            second = json.loads(h.expect(
                "/api/tokens?limit=2&after=" + urllib.parse.quote(first["next_after"]), 200, token=h.alice))
            assert not ({item["id"] for item in first["items"]} & {item["id"] for item in second["items"]})
            h.expect("/api/tokens?limit=2&after=" + urllib.parse.quote(first["next_after"]), 400, token=h.bob)
            h.expect("/api/tokens?after=not-a-cursor", 400, token=h.alice)
            return "limit 0/101 400; keyset pages disjoint; foreign/invalid cursor 400"

        def case_nonready_rotation_aborts():
            data, _ = issue(h, h.alice, body("nonready", repo_grant(demo, ["contents_read", "repo_read"])))
            old = {"username": "alice", "token": data["secret"]}
            before, _ = token_list(h, h.alice)
            h.sql(f"UPDATE repositories SET state = 'provisioning' WHERE id = {quote(demo)}")
            try:
                h.expect(f"/api/tokens/{data['id']}/rotate", 409, method="POST", token=h.alice, body={})
            finally:
                h.sql(f"UPDATE repositories SET state = 'ready' WHERE id = {quote(demo)}")
            # A live restricted token answers 403 on management; a revoked one
            # would answer 401. No replacement row was inserted either.
            h.expect("/api/tokens", 403, token=old)
            after, _ = token_list(h, h.alice)
            assert len(after["items"]) == len(before["items"]), "aborted rotation inserted a token"
            assert any(item["id"] == data["id"] for item in after["items"]), "aborted rotation revoked the old token"
            return "non-ready rotate 409; old token active and scopes untouched; no new row"

        for name, fn in (
            ("tokens.create_once_digest_only", case_create_once_digest_only),
            ("tokens.owner_cross_user_404", case_owner_404),
            ("tokens.restricted_readonly_issuer_403", case_restricted_and_readonly_issuer_403),
            ("tokens.scope_patch_subset_cas", case_scope_patch_subset_and_version),
            ("tokens.rotation_once_then_409", case_rotation),
            ("tokens.revoke_idempotent", case_revoke_idempotent),
            ("tokens.expiry_bounds", case_expiry_bounds_and_time_travel),
            ("sessions.own_only_revoke", case_sessions_own_only),
            ("web.cookie_csrf_basic", case_web_cookie_csrf_and_basic),
            ("api.authorization_only", case_api_authorization_only),
            ("tokens.keyset_actor_cursor", case_keyset_and_actor_cursor),
            ("tokens.nonready_rotation_aborts", case_nonready_rotation_aborts),
        ):
            run_case(h, name, fn)
        exit_code = 0 if all(case["status"] == "passed" for case in h.results) else 1
    except Exception as error:  # noqa: BLE001
        h.results.append(dict(name="harness", status="failed", error=h.redact(error),
                              trace=h.redact(traceback.format_exc())[-2000:]))
        exit_code = 1
    finally:
        try:
            h.cleanup()
        except Exception as error:  # noqa: BLE001
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error),
                                  trace=h.redact(traceback.format_exc())[-2000:]))
            exit_code = 1
        report = dict(
            suite="token_management",
            executed_native=bool(h.results),
            ok=exit_code == 0,
            coverage_complete=False,
            untested_scope=[
                "Git CAS parent-token lock across publication: separate branch, not claimed here.",
                "Restricted browser-child inheritance for a restricted parent: unimplemented, so only parent login rejection and unrestricted sessions are covered.",
                "The 128-grant ceiling is unit-tested; this suite does not build 129 real grants across multiple repositories.",
                "Long-running concurrency/deadlock probes are not a scalability benchmark on this single loopback process.",
            ],
            cases=h.results,
            notes=NOTES,
            limitations=[
                "Expiry is exercised by moving one token's expires_at with SQL (existing Harness bootstrap channel), not by waiting 30 days.",
                "The non-ready repository case flips repositories.state with SQL and restores it; role and scope data are never SQL-seeded.",
                "Chromium-level rendering is exercised by tests/browser_ui.py; this suite drives the same cookie/Origin/CSRF middleware over HTTP.",
                "The implementation worker did not build or run this native suite; the coordinator must run it with --binary/--report before any pass claim.",
            ],
            release_blocker="Private branch: Git CAS parent-token locking is owned by a parallel branch; restricted token issuance is not released or deployed from here.",
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
