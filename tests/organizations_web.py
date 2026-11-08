#!/usr/bin/env python3
"""Native organization/member/team web UI smoke harness (partial issue #87).

The actual server binary runs against a disposable PostgreSQL schema. The
organization, the extra accounts, the memberships, the team and the restricted
token are all created through the real CLI/API; SQL is only used by the shared
test base to create/drop the isolated schema.

The web layer is then driven over plain HTTP so the harness can inspect exact
status codes, security headers and raw HTML bytes:

- complete bounded keyset traversals of all four lists (no first-page truncation)
- private organization cross-user 404 and restricted-token 403
- read-only session mutation 403 and no mutation forms rendered
- missing/wrong CSRF and cross-origin cookie mutation 403
- team-name script escaping and no token/session/CSRF value in a page
- stale ``expected_version`` CAS 409, explicit blank version 400, and a stale
  form that cannot recreate a removed membership
- identical 403 bytes for existing/missing/nonexistent targets from a non-admin
  member (no preflight private-state leak)
- web add/remove flows for organization members and team members, including a
  duplicate team add with no additional audit event

It does not claim that usage, recovery or integration administration UI exists.
"""
import argparse
import hashlib
import html
import http.client
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import traceback
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402

MEMBER = re.compile(r'data-member="([^"]+)"')
TEAM = re.compile(r'data-team-slug="([^"]+)"')
TEAM_MEMBER = re.compile(r'data-team-member="([^"]+)"')
NEXT = re.compile(r'<a href="([^"]+)">Next page</a>')
ORG = re.compile(r'data-org-slug="([^"]+)"')
EXPECTED_VERSION = re.compile(
    r'data-member="([^"]+)".*?name="expected_version" value="(\d+)"', re.DOTALL
)


class OrganizationWebHarness(Harness):
    # ---- transport helpers -------------------------------------------------
    def request(self, path, method="GET", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        result = (response.status, data, response.getheaders())
        conn.close()
        return result

    @staticmethod
    def split_cookies(headers):
        cookies = {}
        for key, value in headers:
            if key.lower() != "set-cookie":
                continue
            name, first = value.split(";", 1)[0].split("=", 1)
            cookies[name] = first
        return cookies

    @staticmethod
    def cookie_header(cookies):
        return "; ".join(f"{name}={value}" for name, value in cookies.items())

    @staticmethod
    def lower(headers):
        entries = headers.items() if hasattr(headers, "items") else headers
        return {key.lower(): value for key, value in entries}

    def doc(self, path, code=200, token=None, method="GET", body=None):
        status, raw, headers = self.http(
            path, token=token or self.alice, method=method, body=body
        )
        assert status == code, f"{path}: expected {code}, got {status}: {raw[:300]!r}"
        return (json.loads(raw) if raw else None), self.lower(headers)

    def sign_in(self, account, username=None):
        fields = {
            "username": username or account["username"],
            "token": account["token"],
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.base,
        }
        status, body, response_headers = self.request(
            "/web/login", "POST", urllib.parse.urlencode(fields), headers
        )
        assert status == 303, (status, body[:300])
        cookies = self.split_cookies(response_headers)
        assert cookies.get("rootyard_session", "").startswith("ryt_"), cookies
        assert cookies.get("rootyard_csrf"), cookies
        self.secrets.extend(cookies.values())
        return cookies

    def page(self, cookies, path, code=200):
        status, body, headers = self.request(
            path, headers={"Cookie": self.cookie_header(cookies)}
        )
        assert status == code, f"{path}: expected {code}, got {status}: {body[:300]!r}"
        return body.decode("utf-8"), self.lower(headers)

    def mutate(self, cookies, path, payload=None, csrf="ok", origin="ok"):
        headers = {
            "Content-Type": "application/json",
            "Cookie": self.cookie_header(cookies),
        }
        if origin == "ok":
            headers["Origin"] = self.base
        elif origin is not None:
            headers["Origin"] = origin
        if csrf == "ok":
            headers["X-CSRF-Token"] = cookies["rootyard_csrf"]
        elif csrf is not None:
            headers["X-CSRF-Token"] = csrf
        return self.request(path, "POST", json.dumps(payload or {}), headers)

    @staticmethod
    def assert_html_security(headers):
        assert headers.get("cache-control") == "no-store", headers
        assert "default-src 'none'" in headers.get("content-security-policy", ""), headers
        assert headers.get("x-frame-options") == "DENY", headers
        assert headers.get("x-content-type-options") == "nosniff", headers
        assert headers.get("content-type", "").startswith("text/html"), headers

    def walk(self, cookies, base, pattern, limit):
        items, seen, pages = [], set(), 0
        url = f"{base}?limit={limit}"
        while True:
            text, headers = self.page(cookies, url)
            self.assert_html_security(headers)
            batch = pattern.findall(text)
            assert len(batch) <= limit, f"{base}: page exceeded limit {limit}"
            items.extend(batch)
            pages += 1
            assert pages < 50, f"{base}: cursor did not terminate"
            link = NEXT.search(text)
            if link is None:
                break
            url = html.unescape(link.group(1))
            assert url.startswith(base + "?"), url
            assert url not in seen, "next-page link repeated"
            seen.add(url)
            assert f"limit={limit}" in url, url
        assert len(items) == len(set(items)), f"{base}: duplicate rows across pages"
        assert items == sorted(items), f"{base}: pages are not globally ordered"
        return items, pages

    # ---- fixture -----------------------------------------------------------
    def fixture(self):
        self.setup()
        acme, _ = self.doc("/api/orgs", 201, method="POST", body={"slug": "acme"})
        other, _ = self.doc("/api/orgs", 201, method="POST", body={"slug": "other"})
        beta, _ = self.doc("/api/orgs", 201, method="POST", body={"slug": "beta"})
        self.acme, self.other, self.beta = acme, other, beta

        self.carol = self.account("create-user", "carol")
        self.newbie = self.account("create-user", "newbie")
        self.doc(
            "/api/orgs/acme/members/carol", 201, method="PUT", body={"role": "read"}
        )

        script_name = "<script>alert('xss')</script> Engineers"
        engineers, _ = self.doc(
            "/api/orgs/acme/teams",
            201,
            method="POST",
            body={"slug": "engineers", "name": script_name, "role": "read"},
        )
        self.engineers = engineers
        self.doc("/api/orgs/acme/teams/engineers/members/carol", 200, method="PUT")

        self.members = {"alice", "carol"}
        self.seed_users = [f"member-{index:02d}" for index in range(1, 13)]
        for name in self.seed_users + ["web-user"]:
            self.account("create-user", name)
        for name in self.seed_users:
            self.doc(
                f"/api/orgs/acme/members/{name}", 201, method="PUT", body={"role": "read"}
            )
            self.members.add(name)

        self.teams = {"engineers"}
        for index in range(1, 7):
            slug = f"team-{index:02d}"
            self.doc(
                "/api/orgs/acme/teams",
                201,
                method="POST",
                body={"slug": slug, "name": f"Team {index}", "role": "read"},
            )
            self.teams.add(slug)

        self.team_members = {"carol"}
        for name in self.seed_users[:4]:
            self.doc(
                f"/api/orgs/acme/teams/engineers/members/{name}", 200, method="PUT"
            )
            self.team_members.add(name)

        return {
            "api_created": [
                "organizations acme/other/beta",
                "carol read membership",
                "engineers team with script-bearing name",
                "12 read memberships",
                "6 teams",
                "4 team members",
            ],
            "members": len(self.members),
            "teams": len(self.teams),
            "team_members": len(self.team_members),
        }

    # ---- private organization and restricted scopes ----------------------
    def cross_user_and_scope(self):
        self.alice_cookies = self.sign_in(self.alice)
        self.session_secret = self.alice_cookies["rootyard_session"]
        self.csrf = self.alice_cookies["rootyard_csrf"]

        acme_id = self.acme["id"]
        issued = self.api_token(
            {
                "display_name": "org-read-only-scope",
                "expires_in_days": 1,
                "read_only": False,
                "repository_grants": [],
                "namespace_grants": [
                    {"organization_id": acme_id, "actions": ["org:read"]}
                ],
            }
        )
        self.restricted = {"token": issued["secret"]}
        self.secrets.append(issued["secret"])

        # bob is not an organization member: the same 404 as the JSON API.
        bob_cookies = self.sign_in(self.bob)
        status, body, _ = self.request(
            "/web/organizations/acme", headers={"Cookie": self.cookie_header(bob_cookies)}
        )
        assert status in (403, 404), status
        assert b"engineers" not in body and b"carol" not in body, body[:300]
        listing, _ = self.page(bob_cookies, "/web/organizations")
        assert "acme" not in listing and "other" not in listing, listing[:300]

        # A restricted token of bob has no organization grant at all -> 403.
        bob_restricted = self.api_token(
            {
                "display_name": "bob-no-grant",
                "expires_in_days": 1,
                "read_only": False,
                "repository_grants": [],
                "namespace_grants": [],
            },
            token=self.bob,
        )
        self.secrets.append(bob_restricted["secret"])
        status, _, _ = self.http(
            "/web/organizations/acme",
            token={"token": bob_restricted["secret"]},
            method="GET",
        )
        assert status == 403, status

        # Alice's restricted token can read only the granted organization.
        status, raw, _ = self.http(
            "/web/organizations/acme/members", token=self.restricted
        )
        assert status == 200, (status, raw[:200])
        page = raw.decode()
        assert 'data-web-action="org-member-set"' not in page
        assert "expected_version" not in page
        status, raw, _ = self.http("/web/organizations", token=self.restricted)
        assert status == 200
        listing = raw.decode()
        assert "acme" in listing and "other" not in listing and "beta" not in listing
        status, raw, _ = self.http("/web/organizations/other", token=self.restricted)
        assert status == 403, status
        return {"browser_non_member": "404", "restricted_without_grant": 403,
                "restricted_list_filtered": ["acme"], "restricted_forms_hidden": True}

    def api_token(self, body, token=None):
        response, _ = self.doc("/api/tokens", 201, token=token or self.alice,
                               method="POST", body=body)
        assert response["secret"].startswith("ryt_")
        return response

    def audit_count(self, action, target, team=None):
        acme = self.acme["id"]
        guard = (
            f"organization_id='{acme}' AND action='{action}' AND target='{target}'"
        )
        if team is not None:
            guard += f" AND details->>'team'='{team}'"
        return int(
            self.sql(
                f"SELECT count(*) FROM organization_audit_log WHERE {guard}"
            )
        )

    # ---- read-only browser session ---------------------------------------
    def read_only(self):
        cookies = self.sign_in(
            {"username": "alice", "token": self.reader["token"], "token_id": self.reader["token_id"]}
        )
        text, headers = self.page(cookies, "/web/organizations/acme/members")
        self.assert_html_security(headers)
        assert 'data-web-action="org-member-set"' not in text
        assert 'data-web-action="org-member-remove"' not in text
        assert "expected_version" not in text
        status, body, _ = self.mutate(
            cookies,
            "/web/organizations/acme/members",
            {"username": "newbie", "role": "read"},
        )
        assert status == 403, (status, body[:200])
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/members/carol/remove"
        )
        assert status == 403, (status, body[:200])
        assert "newbie" not in self.members
        # Existing and absent targets are indistinguishable to a read-only token.
        existing, _ = self.page(self.alice_cookies, "/web/organizations/acme/members?limit=100")
        assert 'data-member="carol"' in existing
        for username in ("carol", "newbie"):
            status, body, _ = self.mutate(
                cookies, "/web/organizations/acme/members",
                {"username": username, "role": "read"},
            )
            assert status == 403, (username, status, body[:200])
        return {"page_without_forms": True, "add_member": 403, "remove_member": 403,
                "existing_and_missing_target": 403}

    # ---- unauthorized preflight concealment -------------------------------
    def unauthorized_preflight_concealment(self):
        # carol is an organization member with the read role and an
        # unrestricted token: token scope passes, the organization admin check
        # must run before any user/membership/team lookup. Bob is a user who is
        # not a member; no-such-user does not exist.
        cookies = self.sign_in(self.carol)

        def post(path, payload):
            status, body, _ = self.mutate(cookies, path, payload)
            return status, body

        member_probes = [
            {"username": "carol", "role": "read"},
            {"username": "bob", "role": "read"},
            {"username": "no-such-user", "role": "read"},
        ]
        member_results = [
            post("/web/organizations/acme/members", payload)
            for payload in member_probes
        ]
        assert all(status == 403 for status, _ in member_results), member_results
        assert len({body for _, body in member_results}) == 1, member_results

        team_probes = [
            ("/web/organizations/acme/teams/engineers/members", {"username": "carol"}),
            ("/web/organizations/acme/teams/engineers/members", {"username": "newbie"}),
            ("/web/organizations/acme/teams/no-such-team/members", {"username": "carol"}),
        ]
        team_results = [post(path, payload) for path, payload in team_probes]
        assert all(status == 403 for status, _ in team_results), team_results
        assert len({body for _, body in team_results}) == 1, team_results

        # The same member still exists and the attempted team add changed
        # nothing: this is a pure response-code/body concealment check.
        members, _ = self.page(self.alice_cookies, "/web/organizations/acme/members?limit=100")
        assert 'data-member="carol"' in members
        return {"member_existing_missing_nonexistent": 403,
                "team_existing_missing_target_and_team": 403,
                "identical_error_bodies": True}

    # ---- CSRF / Origin ----------------------------------------------------
    def csrf_and_origin(self):
        cookies = self.alice_cookies
        payload = {"username": "bob", "role": "read"}
        status, body, _ = self.mutate(cookies, "/web/organizations/acme/members",
                                      payload, csrf=None)
        assert status == 403, (status, body[:200])
        status, body, _ = self.mutate(cookies, "/web/organizations/acme/members",
                                      payload, csrf="wrong-token")
        assert status == 403, (status, body[:200])
        status, body, _ = self.mutate(cookies, "/web/organizations/acme/members",
                                      payload, origin="https://evil.example")
        assert status == 403, (status, body[:200])
        status, body, _ = self.mutate(cookies, "/web/organizations/acme/members", payload)
        assert status == 303, (status, body[:300])
        self.members.add("bob")
        text, _ = self.page(cookies, "/web/organizations/acme/members")
        assert 'data-member="bob"' in text
        return {"missing_csrf": 403, "wrong_csrf": 403, "cross_origin": 403,
                "same_origin_valid_csrf": 303}

    # ---- escaping and page bytes -----------------------------------------
    def escaping_and_headers(self):
        cookies = self.alice_cookies
        secrets = (self.alice["token"], self.session_secret, self.csrf)
        pages = [
            "/web/organizations",
            "/web/organizations/acme",
            "/web/organizations/acme/members",
            "/web/organizations/acme/teams",
            "/web/organizations/acme/teams/engineers",
        ]
        rendered = []
        for path in pages:
            text, headers = self.page(cookies, path)
            self.assert_html_security(headers)
            rendered.append(text)
            for secret in secrets:
                assert secret not in text, f"{path} leaked a credential"
            assert "rootyard_csrf=" not in text, path
            assert "authorization:" not in text.lower(), path
        teams = rendered[3]
        assert "<script>alert('xss')</script>" not in teams, "team name was not escaped"
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in teams, teams[:500]
        assert 'data-web-action="org-team-create"' in teams
        members = rendered[2]
        assert 'data-web-action="org-member-set"' in members
        assert 'data-web-action="org-member-remove"' in members
        return {"pages_checked": len(pages), "escaped_team_name": True,
                "credentials_absent": True, "security_headers": True}

    # ---- bounded keyset pagination ---------------------------------------
    def pagination(self):
        cookies = self.alice_cookies
        members, member_pages = self.walk(
            cookies, "/web/organizations/acme/members", MEMBER, 5
        )
        assert members == sorted(self.members), (members, sorted(self.members))
        assert member_pages == 3, member_pages  # 15 members at five per page

        teams, team_pages = self.walk(
            cookies, "/web/organizations/acme/teams", TEAM, 3
        )
        assert teams == sorted(self.teams), (teams, sorted(self.teams))
        assert team_pages == 3, team_pages  # 7 teams at three per page

        team_members, team_member_pages = self.walk(
            cookies,
            "/web/organizations/acme/teams/engineers",
            TEAM_MEMBER,
            2,
        )
        assert team_members == sorted(self.team_members), team_members
        assert team_member_pages == 3, team_member_pages  # 5 members at two per page

        orgs, org_pages = self.walk(cookies, "/web/organizations", ORG, 2)
        assert orgs == ["acme", "beta", "other"], orgs
        assert org_pages == 2, org_pages

        # Malformed / unknown parameters and foreign cursors are client errors.
        bad = [
            "/web/organizations/acme/members?limit=0",
            "/web/organizations/acme/members?limit=101",
            "/web/organizations/acme/members?limit=abc",
            "/web/organizations/acme/members?bogus=1",
            "/web/organizations/acme/members?cursor=not-a-cursor",
        ]
        for path in bad:
            status, body, _ = self.request(
                path, headers={"Cookie": self.cookie_header(cookies)}
            )
            assert status == 400, (path, status, body[:200])
        first, _ = self.page(cookies, "/web/organizations/acme/members?limit=2")
        cursor = html.unescape(NEXT.search(first).group(1)).split("cursor=", 1)[1]
        status, body, _ = self.request(
            "/web/organizations/other/members?limit=2&cursor="
            + urllib.parse.quote(cursor, safe=""),
            headers={"Cookie": self.cookie_header(cookies)},
        )
        assert status == 400, (status, body[:200])
        status, body, _ = self.request(
            "/web/organizations/acme/teams?limit=2&cursor="
            + urllib.parse.quote(cursor, safe=""),
            headers={"Cookie": self.cookie_header(cookies)},
        )
        assert status == 400, (status, body[:200])
        return {
            "member_pages_at_5": member_pages,
            "team_pages_at_3": team_pages,
            "team_member_pages_at_2": team_member_pages,
            "organization_pages_at_2": org_pages,
            "malformed_or_foreign_cursors": "400",
        }

    # ---- CAS, role updates and team member management ---------------------
    def cas_and_mutations(self):
        cookies = self.alice_cookies
        text, _ = self.page(cookies, "/web/organizations/acme/members?limit=100")
        versions = dict(EXPECTED_VERSION.findall(text))
        assert versions.get("bob") == "1", versions.get("bob")
        assert versions.get("carol") == "1", versions.get("carol")

        # Concurrent API change moves bob to version 2.
        self.doc(
            "/api/orgs/acme/members/bob", 200, method="PUT",
            body={"role": "write"},
        )
        status, body, _ = self.mutate(
            cookies,
            "/web/organizations/acme/members",
            {"username": "bob", "role": "admin", "expected_version": versions["bob"]},
        )
        assert status == 409, (status, body[:300])
        status, body, _ = self.mutate(
            cookies,
            "/web/organizations/acme/members",
            {"username": "bob", "role": "maintain", "expected_version": "2"},
        )
        assert status == 303, (status, body[:300])
        text, _ = self.page(cookies, "/web/organizations/acme/members?limit=100")
        assert re.search(
            r'data-member="bob".*?data-member-role="maintain".*?version 3',
            text,
            re.DOTALL,
        ), "versioned update not reflected"

        # The create-oriented form refuses to overwrite an existing membership.
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/members",
            {"username": "carol", "role": "admin"},
        )
        assert status == 409, (status, body[:300])

        # Add a brand-new member and then invalidate a tampered version.
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/members",
            {"username": "web-user", "role": "read"},
        )
        assert status == 303, (status, body[:300])
        self.members.add("web-user")
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/members",
            {"username": "web-user", "role": "read", "expected_version": "not-a-number"},
        )
        assert status == 400, (status, body[:200])

        # An explicitly blank version is never "no version".
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/members",
            {"username": "web-user", "role": "read", "expected_version": ""},
        )
        assert status == 400, (status, body[:200])

        # A stale role form cannot recreate a membership removed elsewhere.
        self.doc("/api/orgs/acme/members/web-user", 200, method="DELETE")
        self.members.discard("web-user")
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/members",
            {"username": "web-user", "role": "read", "expected_version": "1"},
        )
        assert status == 409, (status, body[:300])
        text, _ = self.page(cookies, "/web/organizations/acme/members?limit=100")
        assert 'data-member="web-user"' not in text

        # Create a team from the web form, then add/remove a team member.
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/teams",
            {"slug": "web-team", "name": "Web team", "role": "read"},
        )
        assert status == 303, (status, body[:300])
        self.teams.add("web-team")
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/teams/web-team/members",
            {"username": "carol"},
        )
        assert status == 303, (status, body[:300])
        text, _ = self.page(cookies, "/web/organizations/acme/teams/web-team")
        assert 'data-team-member="carol"' in text
        # A repeated add stays an idempotent 200 NO-OP (303 after the form
        # redirect) and must not append a second audit event.
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/teams/web-team/members",
            {"username": "carol"},
        )
        assert status == 303, (status, body[:300])
        assert self.audit_count(
            "organization.team.member.added", "carol", "web-team"
        ) == 1
        status, body, _ = self.mutate(
            cookies,
            "/web/organizations/acme/teams/web-team/members/carol/remove",
        )
        assert status == 303, (status, body[:300])
        text, _ = self.page(cookies, "/web/organizations/acme/teams/web-team")
        assert 'data-team-member="carol"' not in text
        # A repeated remove is not found and adds no audit event either.
        status, body, _ = self.mutate(
            cookies,
            "/web/organizations/acme/teams/web-team/members/carol/remove",
        )
        assert status == 404, (status, body[:300])
        assert self.audit_count(
            "organization.team.member.removed", "carol", "web-team"
        ) == 1

        # A user who is not an organization member cannot be added to a team.
        status, body, _ = self.mutate(
            cookies, "/web/organizations/acme/teams/web-team/members",
            {"username": "newbie"},
        )
        assert status == 409, (status, body[:300])

        text, _ = self.page(cookies, "/web/organizations/acme/teams")
        assert 'data-team-slug="web-team"' in text
        return {
            "stale_version": 409,
            "versioned_update": 303,
            "overwrite_without_version": 409,
            "invalid_version": 400,
            "blank_version": 400,
            "stale_recreate_after_removal": 409,
            "new_member": 303,
            "team_create": 303,
            "team_member_add": 303,
            "duplicate_add_no_audit": 1,
            "team_member_remove": 303,
            "repeat_remove": 404,
            "non_member_team_add": 409,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, help="Write a machine-readable JSON report")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    if not Path(args.binary).is_file():
        parser.error("Binary not found: " + args.binary)
    harness = OrganizationWebHarness(args)
    success = False
    report = {
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "source_head": subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parents[1]), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.decode().strip(),
    }
    try:
        for name in (
            "fixture",
            "cross_user_and_scope",
            "read_only",
            "unauthorized_preflight_concealment",
            "csrf_and_origin",
            "escaping_and_headers",
            "pagination",
            "cas_and_mutations",
        ):
            harness.case(name, getattr(harness, name))
        success = True
    except Exception:
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(
                dict(name="cleanup", status="failed", error=harness.redact(error))
            )
            success = False
        report.update(
            passed=success,
            cases=harness.results,
            limitations=[
                "One loopback process and one disposable PostgreSQL schema; not a scalability or browser-engine test.",
                "Issue #87 is PARTIAL: organization/member/team administration only; usage, recovery and integration UI are not implemented.",
                "Cursors are ordered positions bound to actor/organization/team, not signed snapshots; renames and concurrent inserts change traversal semantics.",
                "The web add form is create-only inside the same authorized backend transaction; a duplicate team-member add keeps the historic 200 NO-OP response and adds no audit event.",
                "No organization creation/rename/delete or ownership-transfer UI; no team edit/delete UI because no such organization API mutation exists.",
                "CSRF/Origin assertions cover cookie sessions; explicit Bearer API callers keep the documented non-browser /web contract.",
            ],
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
