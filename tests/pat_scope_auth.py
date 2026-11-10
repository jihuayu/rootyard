#!/usr/bin/env python3
"""Restricted personal-access-token scope regression against the REAL binary.

Requires the same environment as tests/e2e.py: ROOTYARD_TEST_DATABASE_URL plus a
built CLI supplied with --binary. The server, the CLI and PostgreSQL are real;
nothing is mocked. Tokens are never printed or written to the report.

Seed path (documented limitation, deliberate):
    There is no public issuer for restricted tokens. `create-token` has no
    --restricted/--scope flag and `src/token_scopes.rs` contains no public
    issuer API (verified: `rg -n 'public issuer|public_issuer' src/token_scopes.rs`
    => no matches). The only writers are the `#[cfg(test)]`-only helpers in
    `src/token_scopes/tests.rs` (`grant_repository_for_test`), which need an open
    transaction and never reach a production build.
    This harness therefore creates normal tokens with the real CLI and then
    seeds `tokens.is_restricted`, `token_repository_scopes`,
    `repository_collaborators` and organisation team rows directly in the
    isolated test schema. Everything after the seed (authorization,
    enforcement, revocation, cache invalidation) is exercised through the real
    HTTP surface.

Every case asserts an exact status code and an exact response shape. 404, 405
and 422 are never treated as an inconclusive "pass": 404 is asserted only where
the route itself is absent by design (RBAC denies visibility before the scope
gate), and 405/422 would fail the case.
"""
import argparse
import json
import sys
import time
import traceback
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from e2e import Harness  # noqa: E402  (reuse the vetted harness, do not duplicate it)

NOTES = [
    "Restricted authority is seeded by SQL (tokens.is_restricted + token_repository_scopes): no public issuer or CLI flag exists.",
    "Restricted discovery requires CURRENT RBAC visibility (owner, collaborator, repository team, organisation membership, organisation team) AND an exact repo_read grant. A scope grant alone never lists a repository or returns its metadata.",
    "organisation_team_members has a composite foreign key to organization_memberships, so any SQL-seeded organisation-team case also carries an organisation membership. The organisation-team predicate added to the restricted list query is parity with members/rbac.rs and web/session.rs (defence in depth); this harness cannot isolate it from the membership predicate, and does not claim to.",
    "Restricted parent browser login IS covered: POST /web/login with a form-urlencoded username/token and Origin set to the service origin returns 403 and sets no cookie. Inherited browser-child grants for a restricted parent are unimplemented, so no child-session case exists.",
    "NOT COVERED: token grant list/read API (no such reader is exercised; grants are seeded by SQL and repository ids come from the server).",
    "NOT COVERED: Git CAS parent-token locking across a CAS publication; the scope API remains unreleased and this harness does not claim it released.",
]


def quote(value):
    """Quote a server-issued identifier for the isolated test schema."""
    return "'" + str(value).replace("'", "''") + "'"


def seed_restricted_token(h, token, grants=()):
    """Mark an existing CLI-created token restricted and add repository grants."""
    h.sql(f"UPDATE tokens SET is_restricted = true WHERE id = {quote(token['token_id'])}")
    for repository_id, action in grants:
        h.sql("INSERT INTO token_repository_scopes(token_id, repository_id, action) "
              f"VALUES ({quote(token['token_id'])}, {quote(repository_id)}, {quote(action)})")
    bump_scope_version(h, token)


def bump_scope_version(h, token):
    h.sql("UPDATE tokens SET scope_version = scope_version + 1 "
          f"WHERE id = {quote(token['token_id'])}")


def repo_ids(h, owner, name):
    """Return (repository id, owner/tenant namespace id) for a server-created repo."""
    row = h.sql("SELECT r.id, r.owner_id FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id "
                f"WHERE ns.slug = {quote(owner)} AND r.name = {quote(name)}")
    fields = row.split("|")
    assert len(fields) == 2 and all(fields), f"repository {owner}/{name} not found"
    return fields[0], fields[1]


def user_id(h, username):
    value = h.sql(f"SELECT id FROM users WHERE username = {quote(username)}")
    assert value, f"user {username} not found"
    return value


def list_pairs(body):
    """Assert GET /api/repos returns the handler's JSON array and return (owner, name) pairs.

    The handler returns `Vec<db::Repository>` (array of objects with owner/name);
    any other envelope is a failure, never a fuzzy name match.
    """
    items = json.loads(body)
    assert isinstance(items, list), f"/api/repos must return a JSON array, got {type(items).__name__}"
    pairs = []
    for item in items:
        assert isinstance(item, dict), f"unexpected /api/repos item: {item!r}"
        assert isinstance(item.get("owner"), str) and isinstance(item.get("name"), str), item
        pairs.append((item["owner"], item["name"]))
    return sorted(pairs)


def run_case(h, name, fn):
    started = time.monotonic()
    try:
        detail = fn() or ""
        h.results.append(dict(name=name, status="passed",
                              seconds=round(time.monotonic() - started, 4), detail=detail))
    except Exception as error:  # noqa: BLE001 - every failure is reported, never swallowed
        h.results.append(dict(name=name, status="failed",
                              seconds=round(time.monotonic() - started, 4),
                              error=h.redact(error)))
    return h.results[-1]


def main():
    parser = argparse.ArgumentParser(description="Restricted PAT scope regression (real service)")
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, help="Write machine-readable JSON report (no credentials)")
    parser.add_argument("--keep", action="store_true", help="Keep temporary data directory")
    args = parser.parse_args()

    h = Harness(args)
    exit_code = 1
    try:
        h.setup()
        demo = json.loads(h.expect("/api/repos", 201, method="POST", token=h.alice, body={"name": "demo"}))
        other = json.loads(h.expect("/api/repos", 201, method="POST", token=h.bob, body={"name": "other"}))
        # A repository alice owns but never granted to the restricted token.
        json.loads(h.expect("/api/repos", 201, method="POST", token=h.alice, body={"name": "otherrepo"}))
        demo_id, demo_owner_id = repo_ids(h, "alice", "demo")
        other_id, other_owner_id = repo_ids(h, "bob", "other")
        alice_id = user_id(h, "alice")
        bob_id = user_id(h, "bob")
        assert demo["id"] == demo_id, "server repository id and SQL id disagree"
        assert other["id"] == other_id, "server repository id and SQL id disagree"
        assert other_owner_id == bob_id, "repository tenant is not bob's namespace"

        # 1: a restricted token with two grants on demo sees exactly that repo.
        scoped = h.account("create-token", "alice")
        seed_restricted_token(h, scoped, [(demo_id, "repo_read"), (demo_id, "contents_read")])

        def case_list_only_granted():
            pairs = list_pairs(h.expect("/api/repos", 200, token=scoped))
            assert pairs == [("alice", "demo")], f"restricted discovery returned {pairs}"
            return "restricted list == [alice/demo]"

        def case_metadata_granted():
            repo = json.loads(h.expect("/api/repos/alice/demo", 200, token=scoped))
            assert (repo["owner"], repo["name"]) == ("alice", "demo"), repo
            return "granted metadata -> 200"

        # 5: personal ownership bypasses the role lookup, never the scope gate.
        def case_own_repo_without_grant():
            h.expect("/api/repos/alice/otherrepo", 403, token=scoped)
            pairs = list_pairs(h.expect("/api/repos", 200, token=scoped))
            assert pairs == [("alice", "demo")], f"ungranted own repo leaked: {pairs}"
            return "own repo without grant -> 403 and not listed"

        # 2: cross-user access needs RBAC *and* the exact scope grant.
        def case_cross_user_rbac_then_scope():
            # No RBAC row yet: visibility is denied before the scope gate.
            h.expect("/api/repos/bob/other", 404, token=scoped)
            assert list_pairs(h.expect("/api/repos", 200, token=scoped)) == [("alice", "demo")]
            h.sql("INSERT INTO repository_collaborators(repository_id, tenant_id, user_id, role) "
                  f"VALUES ({quote(other_id)}, {quote(bob_id)}, {quote(alice_id)}, 'read')")
            # RBAC read now exists, the token has no grant on bob/other: scope narrows to 403.
            h.expect("/api/repos/bob/other", 403, token=scoped)
            pairs = list_pairs(h.expect("/api/repos", 200, token=scoped))
            assert pairs == [("alice", "demo")], f"collaborator row leaked through discovery: {pairs}"
            return "no RBAC -> 404; collaborator read without grant -> 403; list unchanged"

        # 3: an empty restricted token lists nothing and reads no metadata.
        def case_empty_restricted():
            empty = h.account("create-token", "alice")
            seed_restricted_token(h, empty)
            body = h.expect("/api/repos", 200, token=empty)
            assert json.loads(body) == [], f"empty restricted token listed {body[:200]!r}"
            h.expect("/api/repos/alice/demo", 403, token=empty)
            return "empty grants -> list 200 [] and metadata 403"

        # 1 (continued): the issues route is real and exact-status asserted in both directions.
        def case_issues_write_grant_allowed():
            token = h.account("create-token", "alice")
            seed_restricted_token(h, token, [(demo_id, "repo_read"), (demo_id, "contents_read"),
                                             (demo_id, "issues_write")])
            issue = json.loads(h.expect("/api/repos/alice/demo/issues", 201, method="POST", token=token,
                                       body={"title": "restricted issue"}))
            assert issue.get("title") == "restricted issue", issue
            return "issues_write grant -> 201 (route proven live)"

        def case_readonly_issues_write_denied():
            token = h.account("create-token", "alice", "--read-only")
            seed_restricted_token(h, token, [(demo_id, "repo_read"), (demo_id, "contents_read"),
                                             (demo_id, "issues_write")])
            h.expect("/api/repos/alice/demo", 200, token=token)
            h.expect("/api/repos/alice/demo/issues", 403, method="POST", token=token,
                     body={"title": "read-only must not write"})
            return "read-only + issues_write -> 403; metadata read still 200"

        # 6: restricted discovery needs current RBAC (organisation team included)
        # together with the exact repo_read grant.
        def case_org_team_visibility():
            org = json.loads(h.expect("/api/orgs", 201, method="POST", token=h.bob, body={"slug": "boborg"}))
            assert org.get("id") and org.get("slug") == "boborg", org
            h.expect("/api/repos", 201, method="POST", token=h.bob, body={"name": "orgrepo", "owner": "boborg"})
            org_repo_id, _ = repo_ids(h, "boborg", "orgrepo")
            token = h.account("create-token", "alice")
            seed_restricted_token(h, token, [(org_repo_id, "repo_read")])
            # Scope alone is not visibility: no membership, collaborator or team row yet.
            assert list_pairs(h.expect("/api/repos", 200, token=token)) == [], "scope alone listed an agency repo"
            h.expect("/api/repos/boborg/orgrepo", 404, token=token)
            h.sql("INSERT INTO organization_memberships(organization_id, user_id, role) "
                  f"VALUES ({quote(org['id'])}, {quote(alice_id)}, 'read')")
            team = str(uuid.uuid4())
            h.sql("INSERT INTO organization_teams(id, organization_id, slug, name, role) "
                  f"VALUES ({quote(team)}, {quote(org['id'])}, 'reviewers', 'Reviewers', 'read')")
            h.sql("INSERT INTO organization_team_members(team_id, organization_id, user_id) "
                  f"VALUES ({quote(team)}, {quote(org['id'])}, {quote(alice_id)})")
            pairs = list_pairs(h.expect("/api/repos", 200, token=token))
            assert pairs == [("boborg", "orgrepo")], f"RBAC + grant did not list the org repo: {pairs}"
            h.expect("/api/repos/boborg/orgrepo", 200, token=token)
            # RBAC alone (grant removed) must not list or read.
            h.sql("DELETE FROM token_repository_scopes "
                  f"WHERE token_id = {quote(token['token_id'])} AND repository_id = {quote(org_repo_id)}")
            bump_scope_version(h, token)
            h.expect("/api/repos/boborg/orgrepo", 403, token=token)
            assert list_pairs(h.expect("/api/repos", 200, token=token)) == [], "RBAC alone listed the repo"
            return "scope alone -> 404/[]; org team RBAC + grant -> 200/listed; RBAC without grant -> 403/[]"

        # 4: deleting the grants narrows the token to nothing.
        def case_grant_removal_revokes_access():
            h.sql("DELETE FROM token_repository_scopes "
                  f"WHERE token_id = {quote(scoped['token_id'])} AND repository_id = {quote(demo_id)}")
            bump_scope_version(h, scoped)
            h.expect("/api/repos/alice/demo", 403, token=scoped)
            assert list_pairs(h.expect("/api/repos", 200, token=scoped)) == [], "deleted grant still listed"
            return "grant deleted -> 403 and empty list"

        # 5: revocation of the restricted token itself.
        def case_revoked_token_401():
            h.cli("revoke-token", scoped["token_id"])
            h.expect("/api/repos", 401, token=scoped)
            h.expect("/api/repos/alice/demo", 401, token=scoped)
            return "revoked -> 401"

        # 7: a restricted parent must not be able to mint a browser session.
        def case_restricted_browser_login_403():
            token = h.account("create-token", "alice")
            seed_restricted_token(h, token, [(demo_id, "repo_read")])
            form = ("username=alice&token=" + urllib.parse.quote(token["token"], safe="")).encode()
            status, payload, headers = h.http(
                "/web/login", method="POST", body=form,
                content_type="application/x-www-form-urlencoded",
                extra_headers={"Origin": h.base},
            )
            assert status == 403, f"/web/login restricted parent: expected 403, got {status}: {payload[:300]!r}"
            assert not any(name.lower() == "set-cookie" for name in headers), f"restricted parent login set a cookie: {sorted(headers)}"
            return "restricted parent browser login -> 403 and no Set-Cookie"

        # 6: legacy unrestricted tokens keep current RBAC read/write.
        def case_legacy_unrestricted():
            pairs = list_pairs(h.expect("/api/repos", 200, token=h.alice))
            assert pairs == [("alice", "demo"), ("alice", "otherrepo"), ("bob", "other"),
                             ("boborg", "orgrepo")], f"unrestricted visibility changed: {pairs}"
            h.expect("/api/repos/alice/demo", 200, token=h.alice)
            created = json.loads(h.expect("/api/repos", 201, method="POST", token=h.alice,
                                          body={"name": "legacy-write"}))
            assert (created["owner"], created["name"]) == ("alice", "legacy-write"), created
            return "unrestricted read+write still allowed"

        for name, fn in (
            ("restricted.list_only_granted", case_list_only_granted),
            ("restricted.metadata_granted_200", case_metadata_granted),
            ("restricted.own_repo_without_grant_403", case_own_repo_without_grant),
            ("restricted.cross_user_rbac_then_scope", case_cross_user_rbac_then_scope),
            ("restricted.empty_list_200_and_metadata_403", case_empty_restricted),
            ("restricted.issues_write_grant_201", case_issues_write_grant_allowed),
            ("restricted.readonly_issues_write_403", case_readonly_issues_write_denied),
            ("restricted.org_team_requires_rbac_and_grant", case_org_team_visibility),
            ("restricted.grant_deleted_403", case_grant_removal_revokes_access),
            ("restricted.revoked_401", case_revoked_token_401),
            ("restricted.browser_login_403", case_restricted_browser_login_403),
            ("legacy.unrestricted_read_write", case_legacy_unrestricted),
        ):
            run_case(h, name, fn)
        exit_code = 0 if all(case["status"] == "passed" for case in h.results) else 1
    except Exception as error:  # noqa: BLE001
        h.results.append(dict(name="harness", status="failed", error=h.redact(error),
                              trace=h.redact(traceback.format_exc())[-2000:]))
        exit_code = 1
    finally:
        # Cleanup failures are reported and fail the run; they are never swallowed
        # and the directory is never removed with ignore_errors=True.
        try:
            h.cleanup()
        except Exception as error:  # noqa: BLE001
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error),
                                  trace=h.redact(traceback.format_exc())[-2000:]))
            exit_code = 1
        report = dict(
            suite="pat_scope_auth",
            executed_native=bool(h.results),
            ok=exit_code == 0,
            # False only because the scope below is not exercised by this harness;
            # every case that did run asserts an exact status and shape.
            coverage_complete=False,
            untested_scope=[
                "Browser-child inheritance for a restricted parent is unimplemented, so this harness covers login rejection only.",
                "The Git HTTP publication path still authorises through a bare client, so the parent token is not locked FOR SHARE across the CAS.",
                "Token grant list/read API is not covered; grants are seeded by SQL and ids come from the server.",
                "Git CAS parent-token locking across a CAS publication is not covered; no scope issuance API is released.",
            ],
            cases=h.results,
            notes=NOTES,
            limitations=[
                "Restricted tokens are seeded by SQL because no public issuer exists.",
                "Organisation-team visibility cannot be isolated from organisation membership because organization_team_members references organization_memberships.",
                "Timings from a loopback single-process run are not a scalability benchmark.",
            ],
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
