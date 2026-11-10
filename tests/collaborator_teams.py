#!/usr/bin/env python3
"""Issue #4 harness: repository-team inherited read/write/admin authorization.

The direct-collaborator matrix in the sibling modules grants roles only through
``repository_collaborators``. This module covers the other inheritance source
read from ``src/members/rbac.rs`` (``resolve_effective_role``): a member of a
``repository_teams`` team inherits the team's role, and the effective role is
``max(direct, team)``. The grants are made only through the owner's real
``POST /api/repos/{owner}/{name}/teams`` and ``PUT .../teams/{slug}/members/
{user}`` calls; no SQL row authorizes an actor, and the team row is read back
from the team API (``role``, ``version``, ``id``) before any actor touches Git.

Contract exercised per team role (``read``, ``write``, ``admin``):

  clone/fetch          read
  git push             write
  POST /ref-transactions  write; ``Idempotency-Key`` replays the same body
  POST /pulls          write; its author is the requesting team user
  POST /pulls/{n}/merge write; its ``merge_commit_oid`` is the target OID

Receipts are joined through ``git_operations.operation_id`` (the owning source
for ``outbox_events``); actor and token come from that table, never from the PR
response's ``author_id``. Every refusal is preceded by distinct, existing refs
for a valid ``write``-level PR command, so a denial cannot pass as a ``400``.

Earlier cases of the direct collaborator matrix leave a ``repository_collaborators``
row on mona (triage), nina (write) and olga (read); an inherited role could then
not be told apart from ``max(direct, team)``. Before the role matrix the owner
reads each actor's real ``GET /permissions/{user}`` row and only when its
``direct_role`` is present removes that row through the real ``DELETE
/api/repos/{owner}/{name}/collaborators/{user}`` call, reading the absence back
from the permissions API, the collaborator API and the owner's audit log
(``collaborator.removed``). A row an earlier case already revoked (olga) sends
no DELETE: its read-back must show no direct source. Only then does the row's
own before-check require no direct role.
The read actor never pushes: the owner prepares its distinct base/head refs, and
the read actor's own push is only an expected failure verified as a server-side
``receive-pack`` 403 with no ref, object or receipt left behind. The write/admin
actors push their own base/head commits, with ``ops_before``/``events_before``
taken after the owner's fixture and before the actor's first push.
"""
import json

from collaborator_contract import ZERO

# Actors of this run's team cases. The contract assertion before each grant is
# direct_role == None: the effective role the cases then exercise can only be
# inherited from the team (write/admin accept an equal direct role by max()).
TEAM_ACTORS = (("mona", "read"), ("nina", "write"), ("olga", "admin"))
TEAM_SMOKE_USER = "peggy"
TEAM_ROLES = ("read", "write", "admin")
# Direct collaborator rows the earlier cases granted to the same three actors.
PRIOR_DIRECT_ROLES = {"mona": "triage", "nina": "write", "olga": "read"}
# Effective-role field matrix of GET /api/repos/alice/demo/permissions/{user}.
EXPECTED_PERMISSIONS = {
    "read": {"role": "read", "team_role": "read"},
    "write": {"role": "write", "team_role": "write"},
    "admin": {"role": "admin", "team_role": "admin"},
}
# Shared proof that a command is one the product would serve for a writer: it
# carries two distinct, already-existing branch refs whose OIDs differ.
WRITER_LEVEL_COMMAND = "head_oid != base_oid and both branch refs exist"
RULE = {"required_approvals": 0, "required_checks": [], "require_fast_forward": True,
        "prevent_deletion": True, "prevent_force_push": True}


class teams:
    """Team fixtures, the inherited-role matrix and its receipt assertions."""

    # ---- fixtures --------------------------------------------------------
    def owner_account(self, owner):
        """The fixture owner's own CLI-created account (alice is created by setup())."""
        assert owner == "alice", "team fixtures are granted by the repository owner only"
        return self.alice

    def team_create(self, owner, repo, slug, role):
        """Owner creates a repository team through the team API; SQL is never the grant."""
        path = f"/api/repos/{owner}/{repo}/teams"
        status, raw, _ = self.http(path, token=self.owner_account(owner), method="POST",
                                   body={"slug": slug, "name": "Team " + slug,
                                         "description": "issue #4 team matrix", "role": role})
        assert status == 201, (path, status, raw[:300])
        team = json.loads(raw)
        assert (team["slug"], team["role"], team["version"]) == (slug, role, 1), team
        listed = json.loads(self.expect(path, 200, token=self.owner_account(owner)))
        assert [item["id"] for item in listed["items"] if item["slug"] == slug] == [team["id"]], listed
        return team

    def team_add(self, owner, repo, slug, user, team_id, repository_id):
        """Owner adds a member through the team API and reads the row back."""
        # src/members.rs routes /teams/{team_slug}/members/{username}: {username}
        # here is the member being added, so the row lands on the team above.
        path = f"/api/repos/{owner}/{repo}/teams/{slug}/members/{user}"
        status, raw, _ = self.http(path, token=self.owner_account(owner), method="PUT",
                                   body={"username": user})
        assert status in (200, 201), (path, status, raw[:300])
        member = json.loads(raw)
        assert member["repository_id"] == repository_id, member
        assert (member["team_id"], member["username"], member["user_id"]) == (
            team_id, user, self.users[user]["user_id"]), (member, team_id)
        listed = json.loads(self.expect(f"/api/repos/{owner}/{repo}/teams/{slug}/members", 200,
                                        token=self.owner_account(owner)))
        assert user in [item["username"] for item in listed["items"]], listed
        return member

    def team_remove(self, owner, repo, slug, user):
        path = f"/api/repos/{owner}/{repo}/teams/{slug}/members/{user}"
        removed = json.loads(self.expect(path, 200, token=self.owner_account(owner),
                                         method="DELETE"))
        assert (removed["removed"], removed["team_slug"], removed["username"]) == (True, slug, user)
        return removed

    def inherited_permission(self, owner, repo, user, role=None):
        """GET permissions/{user}; with ``role`` the effective role is that team role."""
        path = f"/api/repos/{owner}/{repo}/permissions/{user}"
        permission = json.loads(self.expect(path, 200, token=self.owner_account(owner)))
        assert permission["username"] == user and permission["is_owner"] is False, permission
        assert permission["user_id"] == self.users[user]["user_id"], permission
        if role is not None:
            expected = dict(EXPECTED_PERMISSIONS[role], username=user)
            for key, value in expected.items():
                assert permission[key] == value, (path, key, permission, role)
        return permission

    def team_member_row(self, repo, slug, user):
        """The grant's own row: exactly one team membership, no direct collaborator row."""
        repo_id = self.repo["id"]
        return json.loads(self.sql(
            "SELECT json_build_object("
            "'teams', (SELECT coalesce(json_agg(json_build_object("
            "'slug', t.slug, 'role', t.role, 'version', t.version)), '[]'::json) "
            "FROM repository_team_members tm JOIN repository_teams t ON t.id=tm.team_id "
            "WHERE tm.repository_id='" + repo_id + "' AND tm.user_id='" + self.users[user]["user_id"] +
            "'), "
            "'collaborators', (SELECT count(*) FROM repository_collaborators "
            "WHERE repository_id='" + repo_id + "' AND user_id='" + self.users[user]["user_id"] + "'))"))

    def team_clear_direct(self, user):
        """Owner clears the actor's earlier direct row only when one still exists.

        Earlier cases may already have revoked that row (olga is removed by the
        admin case), so the owner first reads the real ``GET /permissions/{user}``
        row. With no ``direct_role`` there is nothing to revoke: no ``DELETE`` is
        sent, and the read must resolve no role or one whose ``team_role``
        accounts for it, so nothing but the team source remains.
        A ``direct_role`` on that read means the DELETE path is the only one
        allowed; it must be 200, the read-back null on every field, and the
        owner's audit log must attribute one ``collaborator.removed``. The
        DELETE is only sent after this read showed the direct role, so a 404
        from it is a failure, not an accepted outcome.
        """
        assert user in PRIOR_DIRECT_ROLES, (user, "not an actor of the direct matrix")
        path = "/api/repos/alice/demo/collaborators/" + user
        prior = self.inherited_permission("alice", "demo", user)
        if prior["direct_role"] is None:
            # The earlier cases already revoked this row; the effective role, if
            # any, is inherited from a team, so the matrix grant stays the only
            # direct source to clear and no DELETE is sent.
            assert (prior["role"] is None) == (prior["team_role"] is None), prior
            return {"cleared": user, "prior_direct_role": None, "delete": "not_sent",
                    "effective_after": prior["role"], "team_after": prior["team_role"],
                    "read_back": "no_direct_source"}
        assert prior["direct_role"] == PRIOR_DIRECT_ROLES[user], (user, prior)
        removed = json.loads(self.expect(path, 200, method="DELETE",
                                         token=self.owner_account("alice")))
        assert (removed["removed"], removed["username"]) == (True, user), removed
        after = self.inherited_permission("alice", "demo", user)
        assert after["direct_role"] is None, after
        assert self.http(path, token=self.owner_account("alice"))[0] == 404
        # The owner's own audit rows (target filters do not exist; actor does).
        events = json.loads(self.expect("/api/repos/alice/demo/audit?actor=alice&limit=100", 200,
                                        token=self.owner_account("alice")))["items"]
        attributions = [e for e in events if e["action"] == "collaborator.removed"
                        and e["target_type"] == "collaborator" and e["target_name"] == user]
        assert attributions, ("no owner audit row for the removal", events)
        latest = attributions[-1]
        assert (latest["actor_name"], latest["actor_id"]) == ("alice", self.alice["user_id"]), latest
        assert latest["repository_id"] == self.repo["id"], latest
        return {"cleared": user, "prior_direct_role": PRIOR_DIRECT_ROLES[user], "delete": 200,
                "effective_after": after["role"], "team_after": after["team_role"],
                "audit_id": latest["id"], "read_back": "no_direct_role"}

    # ---- fast-forward relation -------------------------------------------
    def rev_list(self, work, tip, not_rev=None):
        """Commit OIDs reachable from ``tip`` (and not from ``not_rev``), read in ``work``."""
        return self.git("rev-list", tip, *([("^" + not_rev)] if not_rev else []),
                        cwd=work).stdout.decode().split()

    def ff_relation(self, work, before, after):
        """``before`` is an ancestor of (or equal to) ``after``: the pushed ff relation.

        ``a..b`` lists what ``b`` adds on top of ``a``. The range is explicit:
        a fast-forward of one commit, or a push of an already-contained commit,
        enumerates exactly for a real ancestor, while ``git rev-list b`` alone
        with an exclusion in its arguments never does. ``before`` must exist in
        the same clone, so the claim is about real commits.
        """
        if before == after:
            assert not self.rev_list(work, after, before), (before, after)
        else:
            assert self.rev_list(work, after, before) == [after], (before, after)
        assert self.git("rev-parse", "--verify", before + "^{commit}", cwd=work,
                        check=False).returncode == 0, before

    # ---- smoke and matrix ------------------------------------------------
    def team_write_smoke(self):
        """One real team ``write`` traversal on alice/demo before the read/write/admin matrix.

        The owner publishes ``team-smoke`` at the ``main`` seed. The team user
        clones that branch, commits its own child of the seed there and pushes
        that branch; the server may only move ``team-smoke`` seed -> its new
        commit (a fast-forward), recorded against the team user's token. Only
        the owner pushes from the owner's clone: the team user's commit exists
        in the team user's clone first, so it needs no local object of Alice.
        """
        remote = self.remote
        alice = self.root / "owned-work-alice-team-smoke"
        self.git("clone", remote, str(alice), token=self.alice)
        self.git("config", "user.name", "Alice", cwd=alice)
        self.git("config", "user.email", "alice@collaborator.invalid", cwd=alice)
        branch = "team-smoke"
        seed = self.seed
        self.git("checkout", "-B", branch, seed, cwd=alice)
        assert self.push_branch(alice, self.alice, branch) == seed and self.ref("refs/heads/" + branch) == seed
        self.assert_smoke_ref(branch, seed)
        slug = "smoke-writers"
        team = self.team_create("alice", "demo", slug, "write")
        unjoined = self.inherited_permission("alice", "demo", TEAM_SMOKE_USER)
        # Before the owner adds the member: no role at all, so the grant below can
        # only come from this team (every fixture user starts without a membership).
        assert (unjoined["role"], unjoined["direct_role"], unjoined["team_role"]) == (
            None, None, None), unjoined
        self.team_add("alice", "demo", slug, TEAM_SMOKE_USER, team["id"], self.repo["id"])
        permission = self.inherited_permission("alice", "demo", TEAM_SMOKE_USER, "write")
        assert (permission["role"], permission["direct_role"], permission["team_role"]) == (
            "write", None, "write"), permission
        token = self.users[TEAM_SMOKE_USER]
        work = self.root / ("owned-work-" + TEAM_SMOKE_USER + "-team-smoke")
        self.git("clone", remote, str(work), token=token)
        self.git("config", "user.name", TEAM_SMOKE_USER.title(), cwd=work)
        self.git("config", "user.email", TEAM_SMOKE_USER + "@collaborator.invalid", cwd=work)
        # The team user's clone has the remote seed and commits its own child of it.
        self.ff_relation(work, seed, seed)
        assert self.rev_list(work, "origin/" + branch) == [seed]
        self.git("checkout", "-B", branch, "origin/" + branch, cwd=work)
        assert self.git("rev-parse", "origin/" + branch, cwd=work).stdout.decode().strip() == seed
        oid = self.commit(work, "smoke.txt", "team smoke push")
        # HEAD is a real child of the remote seed in the team user's own clone...
        assert self.rev_list(work, "HEAD", seed) == [oid] and oid != seed
        # ...so the push a team writer sends is the fast-forward seed -> oid, and
        # the server source (weaker than a writer) holds that commit afterwards.
        self.git("push", "origin", "HEAD:refs/heads/" + branch, cwd=work, token=token)
        assert self.ref("refs/heads/" + branch) == oid
        # Only the team writer's push may be recorded; the server holds its commit.
        operation = self.team_assert_operation(self.last_operation("recorded"),
                                               TEAM_SMOKE_USER, "demo")
        [event] = self.events_for("refs/heads/" + branch, operation["id"])
        assert (event["old_oid"], event["new_oid"]) == (seed, oid), event
        self.ff_relation(work, event["old_oid"], event["new_oid"])
        self.assert_smoke_ref(branch, oid)
        return {"team": {"slug": team["slug"], "role": team["role"], "version": team["version"]},
                "member": TEAM_SMOKE_USER, "effective": permission["role"], "direct_role": None,
                "clone": True, "fetch": True, "push": branch}

    def assert_smoke_ref(self, branch, oid):
        """The server source itself holds ``branch`` at ``oid`` (weaker than a writer)."""
        name = "refs/heads/" + branch
        stored = self.git("--git-dir=" + str(self.bare), "rev-parse", name).stdout.decode().strip()
        assert stored == oid, (name, stored, oid)
        # A peer `git ls-remote` of the source (a valid actor reads it) lists the
        # same OID; an unreachable or unrecorded object cannot be listed.
        remote = self.base + self.repo["clone_path"]
        listed = self.git("ls-remote", remote, name, token=self.alice).stdout.decode().split()
        assert listed == [oid, name], (name, listed)

    def team_matrix(self):
        """One registered case: team write smoke, then read/write/admin, then withdrawal."""
        smoke = self.team_write_smoke()
        rows = self.team_role_matrix()
        self.team_withdrawal()
        admin = self.team_admin_withdrawal()
        return {"smoke": smoke, "roles": rows, "withdrawal": "nina",
                "admin_after_withdrawal": admin}

    def team_role_matrix(self):
        """read/write/admin team roles: clone, fetch, push, ref-transactions, PR merge."""
        cleared = [self.team_clear_direct(user) for user, _ in TEAM_ACTORS]
        rows = {}
        for user, role in TEAM_ACTORS:
            rows[role] = self.team_role_row(user, role)
        assert [rows[role]["push"] for role in TEAM_ROLES] == ["denied", "recorded", "recorded"]
        assert [rows[role]["merge"] for role in TEAM_ROLES] == ["denied", "merged", "merged"]
        assert all(rows[role]["refs"] == "distinct_existing" for role in TEAM_ROLES)
        assert all(row["direct_role"] is None and row["effective"] == role
                   for role, row in rows.items()), rows
        return {"direct_cleared": cleared, "roles": rows}

    def team_role_row(self, user, role):
        """One actor, one team, one inherited role, checked on every surface."""
        demo = self.repo
        team = self.team_create("alice", "demo", "role-" + role + "-" + user, role)
        before = self.inherited_permission("alice", "demo", user)
        assert (before["role"], before["direct_role"], before["team_role"]) == (None, None, None), before
        self.team_add("alice", "demo", team["slug"], user, team["id"], demo["id"])
        permission = self.inherited_permission("alice", "demo", user, role)
        assert (permission["direct_role"], permission["team_role"]) == (None, role), permission
        token = self.users[user]
        work = self.worker(user, "team-" + role)
        assert (work / "README.md").read_text() == "collaborator matrix seed\n"
        self.git("fetch", "origin", cwd=work, token=token)
        assert self.git("rev-parse", "origin/main", cwd=work).stdout.decode().strip() == self.seed
        # One base/head pair per role: two distinct, existing refs at distinct OIDs.
        base_ref, head_ref = "team-base-" + user, "team-head-" + user
        if role == "read":
            # The read actor never creates a ref: the owner prepares its distinct
            # base/head refs (already exists), then the read actor tries write paths.
            base, head = self.team_owner_fixture(base_ref, head_ref, user, role)
            assert self.ref("refs/heads/" + base_ref) == base
            assert self.ref("refs/heads/" + head_ref) == head
            ops_before, events_before = len(self.operations()), len(self.events())
            return self.team_read_refusals(user, work, base_ref, head_ref, base, head,
                                           ops_before, events_before)
        # The write/admin actor pushes its own real base and head commits; the
        # receipt baseline is taken after the owner's fixture and before the
        # actor's first push, so both pushes are counted, never replayed.
        ops_before, events_before = len(self.operations()), len(self.events())
        assert self.receive_refs_status(token) == 200, user
        self.git("checkout", "-B", base_ref, self.seed, cwd=work)
        base = self.commit(work, "base-" + user + ".txt", "role base " + role)
        self.git("push", "origin", "HEAD:refs/heads/" + base_ref, cwd=work, token=token)
        # Capture this push's receipt before the next push moves the head, so
        # each ref is bound to its own operation instead of the final one.
        base_operation = self.team_assert_operation(self.last_operation("recorded"), user, "demo")
        self.git("checkout", "-B", head_ref, base, cwd=work)
        head = self.commit(work, "head-" + user + ".txt", "role head " + role)
        self.git("push", "origin", "HEAD:refs/heads/" + head_ref, cwd=work, token=token)
        head_operation = self.team_assert_operation(self.last_operation("recorded"), user, "demo")
        pushed = [self.ref("refs/heads/" + base_ref), self.ref("refs/heads/" + head_ref)]
        assert pushed == [base, head] and base != head, pushed
        self.team_no_rule(base_ref, head_ref)
        assert len(self.operations()) == ops_before + 2, (user, len(self.operations()), ops_before)
        assert len(self.events()) == events_before + 2, (user, len(self.events()), events_before)
        assert base_operation["id"] != head_operation["id"], (base_operation, head_operation)
        for ref, oid, operation in (
                ("refs/heads/" + base_ref, base, base_operation),
                ("refs/heads/" + head_ref, head, head_operation)):
            [event] = self.events_for(ref, operation["id"])
            assert event["new_oid"] == oid, event
        receipt = self.team_ref_transaction(user, head)
        pull = self.team_pull_merge(user, base_ref, head_ref, base, head)
        return {"role": role, "team": {"slug": team["slug"], "version": team["version"]},
                "effective": permission["role"], "direct_role": None, "clone": True,
                "fetch": True, "push": "recorded", "refs": "distinct_existing",
                "ref_transaction": receipt, "merge": "merged", "pull": pull}

    def team_owner_fixture(self, base_ref, head_ref, user, role):
        """The owner publishes distinct base/head refs as real commits in the owner's clone."""
        owner = self.root / "owned-work-alice"
        self.git("checkout", "-B", base_ref, self.seed, cwd=owner)
        base = self.commit(owner, "owner-base-" + user + ".txt", "fixture base " + role)
        self.git("push", "origin", "HEAD:refs/heads/" + base_ref, cwd=owner, token=self.alice)
        base_operation = self.last_operation("recorded")
        self.git("checkout", "-B", head_ref, base, cwd=owner)
        head = self.commit(owner, "owner-head-" + user + ".txt", "fixture head " + role)
        self.git("push", "origin", "HEAD:refs/heads/" + head_ref, cwd=owner, token=self.alice)
        head_operation = self.last_operation("recorded")
        assert base != head, (base, head)
        assert base_operation["id"] != head_operation["id"], (base_operation, head_operation)
        for ref, oid, operation in (
                ("refs/heads/" + base_ref, base, base_operation),
                ("refs/heads/" + head_ref, head, head_operation)):
            self.team_assert_operation(operation, "alice", "demo")
            [event] = self.events_for(ref, operation["id"])
            assert event["new_oid"] == oid, event
        return base, head

    def team_no_rule(self, base_ref, head_ref):
        """No branch rule may explain a refusal on the pair (an absent row is not a 409)."""
        assert self.sql("SELECT count(*) FROM forge_branch_rules WHERE repository_id='" +
                        self.repo["id"] + "' AND branch_ref IN ('refs/heads/" + base_ref + "',"
                        " 'refs/heads/" + head_ref + "')") == "0"

    def team_read_refusals(self, user, work, base_ref, head_ref, base, head, ops_before,
                           events_before):
        """A read team member is refused on every write path, with no ref/outbox change.

        The refs and both commits exist already and belong to the owner, so every
        refusal below targets a valid request; the read actor's own push is only
        expected to fail and is verified to fail at the server's gate.
        """
        token = self.users[user]
        assert self.git("fetch", "origin", cwd=work, token=token).returncode == 0
        assert self.receive_refs_status(token) == 403
        self.team_no_rule(base_ref, head_ref)
        self.git("checkout", "-B", "read-push-" + user, "origin/main", cwd=work)
        staged = self.commit(work, "read-push.txt", "read team push")
        assert staged not in (base, head)
        denied = self.git("push", "origin", "HEAD:refs/heads/team-read-push", cwd=work,
                          token=token, check=False)
        assert denied.returncode != 0, "a read team member's push was accepted"
        # The refusal is the server's permission gate (receive-pack 403), not a
        # client-side preflight: the denied ref, its object and any receipt of it
        # are absent, while Git ran the push it was asked to run.
        assert self.ref("refs/heads/team-read-push") is None, "denied push moved a ref"
        assert not self.events_for("refs/heads/team-read-push"), "denied push left a receipt"
        assert self.git("--git-dir=" + str(self.bare), "cat-file", "-e", staged + "^{commit}",
                        check=False).returncode != 0, "denied push transferred its commit"
        error = denied.stderr.decode(errors="replace")
        assert "403" in error, ("the push was not refused by the server", error[-400:])
        # The ref-transaction and pull carry the owner's real, existing commit/refs.
        body = {"updates": [{"ref_name": "refs/heads/team-read-tx", "old_oid": ZERO,
                             "new_oid": head}], "atomic": True}
        refused = {}
        for label, path, payload in (
                ("ref_transaction", "/api/repos/alice/demo/ref-transactions", body),
                ("pull_create", "/api/repos/alice/demo/pulls",
                 {"title": "team read " + user, "head_ref": "refs/heads/" + head_ref,
                  "base_ref": "refs/heads/" + base_ref}),
                ("pull_merge", "/api/repos/alice/demo/pulls/1/merge",
                 {"expected_version": 1, "expected_head_oid": head,
                  "expected_base_oid": base, "strategy": "fast_forward"})):
            status, raw, _ = self.http(path, token=token, method="POST", body=payload,
                                       extra_headers={"Idempotency-Key": "team-" + label + "-" + user})
            assert status == 403, (user, label, status, raw[:200])
            refused[label] = status
        assert refused == {"ref_transaction": 403, "pull_create": 403, "pull_merge": 403}
        assert self.ref("refs/heads/team-read-tx") is None, "denied ref transaction applied"
        assert not self.events_for("refs/heads/team-read-tx"), "denied ref transaction emitted"
        assert self.sql("SELECT count(*) FROM forge_pulls WHERE repository_id='" +
                        self.repo["id"] + "' AND head_ref='refs/heads/" + head_ref + "'") == "0"
        assert len(self.operations()) == ops_before and len(self.events()) == events_before
        # The owner's fixture refs are untouched by every refusal above.
        assert [self.ref("refs/heads/" + base_ref), self.ref("refs/heads/" + head_ref)] == [base, head]
        return {"role": "read", "effective": "read", "direct_role": None, "clone": True,
                "fetch": True, "push": "denied", "push_gate": "receive-pack 403",
                "refs": "distinct_existing", **refused,
                "ref_transaction": 403, "merge": "denied", "no_new_refs_or_outbox": True}

    # ---- write paths -----------------------------------------------------
    def team_ref_transaction(self, user, oid):
        """A team writer's keyed ref transaction applies once; the replay is identical."""
        token = self.users[user]
        ref = "refs/heads/team-tx-" + user
        body = {"updates": [{"ref_name": ref, "old_oid": ZERO, "new_oid": oid}],
                "atomic": True, "storage_generation": 1}
        key = {"Idempotency-Key": "team-tx-" + user}
        status, raw, _ = self.http("/api/repos/alice/demo/ref-transactions", token=token,
                                   method="POST", body=body, extra_headers=key)
        assert status == 200, (user, status, raw[:300])
        applied = json.loads(raw)
        assert applied["updates"] == body["updates"] and self.ref(ref) == oid, applied
        assert len(self.events_for(ref)) == 1 and self.events_for(ref)[0]["new_oid"] == oid
        operation = self.team_assert_operation(self.last_operation("recorded"), user, "demo")
        replay = self.expect("/api/repos/alice/demo/ref-transactions", 200, token=token,
                             method="POST", body=body, extra_headers=key)
        assert replay == raw and len(self.events_for(ref)) == 1, (replay[:300], raw[:300])
        return {"status": 200, "operation": operation["id"], "replay": "identical",
                "events_for_ref": 1}

    def team_pull_merge(self, user, base_ref, head_ref, base, head):
        """A team writer creates and merges its own PR; the receipt names that writer."""
        token = self.users[user]
        pulls = "/api/repos/alice/demo/pulls"
        pull = json.loads(self.expect(pulls, 201, token=token, method="POST",
                                      body={"title": "team PR " + user,
                                            "head_ref": "refs/heads/" + head_ref,
                                            "base_ref": "refs/heads/" + base_ref}))
        assert pull["author_id"] == self.users[user]["user_id"], pull
        assert (pull["head_oid"], pull["base_oid"], pull["state"]) == (head, base, "open")
        merge = f"{pulls}/{pull['number']}/merge"
        body = {"expected_version": pull["version"], "expected_head_oid": head,
                "expected_base_oid": base, "storage_generation": 1,
                "strategy": "fast_forward"}
        key = {"Idempotency-Key": "team-merge-" + user}
        status, raw, _ = self.http(merge, token=token, method="POST", body=body,
                                   extra_headers=key)
        assert status == 200, (user, status, raw[:300])
        result = json.loads(raw)
        assert (result["state"], result["merge_commit_oid"]) == ("merged", head), result
        assert result["version"] == pull["version"] + 1 and result["author_id"] == pull["author_id"]
        assert self.ref("refs/heads/" + base_ref) == head
        merged = self.team_assert_operation(self.last_operation("recorded"), user, "demo")
        assert merged["evidence"]["kind"] == "pull_merge", merged["evidence"]
        [event] = self.events_for("refs/heads/" + base_ref, merged["id"])
        assert (event["old_oid"], event["new_oid"]) == (base, head), event
        replay = self.expect(merge, 200, token=token, method="POST", body=body,
                             extra_headers=key)
        assert replay == raw and len(self.events_for("refs/heads/" + base_ref)) == 1
        assert self.http(merge, token=token, method="POST", body=body)[0] == 409
        return {"number": pull["number"], "author": user, "merged_by": user,
                "merge_commit_oid": head, "operation": merged["id"]}

    def team_assert_operation(self, operation, user, repo):
        """The owning receipt names the team user and its token; the tenant stays alice."""
        # self.users holds the collaborators only; the owner's record is self.alice.
        account = self.owner_account(user) if user == "alice" else self.users[user]
        assert operation["outcome"] == "recorded", operation
        assert (operation["actor_id"], operation["actor_name"], operation["token_id"]) == (
            account["user_id"], user, account["token_id"]), operation
        assert (operation["token_id"] == self.alice["token_id"]) == (user == "alice"), \
            "non-owner token recorded" if user != "alice" else "owner must use its own token"
        owner = self.sql("SELECT ns.slug FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id"
                         " WHERE r.name='" + repo + "'")
        assert owner == "alice", owner
        return operation

    # ---- withdrawal ------------------------------------------------------
    def team_withdrawal(self):
        """Removing team members ends inherited requests; receipts keep the team actor."""
        work = self.worker("nina", "team-withdrawal")
        base, merged = self.team_merge_nina()
        assert self.ref("refs/heads/team-base-nina") == merged
        removed = self.team_remove("alice", "demo", "role-write-nina", "nina")
        assert removed["team_slug"] == "role-write-nina"
        after = json.loads(self.expect("/api/repos/alice/demo/permissions/nina", 200,
                                       token=self.alice))
        assert after["role"] is None and after["team_role"] is None and after["direct_role"] is None
        assert self.upload_status(self.users["nina"]) == 404
        assert self.receive_refs_status(self.users["nina"]) == 404
        assert self.commit(work, "after.txt", "after team withdrawal")
        denied = self.git("push", "origin", "HEAD:refs/heads/team-after", cwd=work,
                          token=self.users["nina"], check=False)
        assert denied.returncode != 0 and self.ref("refs/heads/team-after") is None
        assert self.http("/api/repos/alice/demo/ref-transactions", token=self.users["nina"],
                         method="POST", body={"updates": [{"ref_name": "refs/heads/team-after-tx",
                                                           "old_oid": ZERO, "new_oid": base}],
                                               "atomic": True})[0] == 404
        assert self.git("fetch", "origin", cwd=work, token=self.users["nina"],
                        check=False).returncode != 0
        return {"removed_team_member": "nina", "team_role_after": None, "upload_pack": 404,
                "receive_pack": 404, "push_denied": True, "retained_actor": "nina",
                "retained_operation": base}

    def team_merge_nina(self):
        """Nina's second, non-fast-forward PR merge; its receipt must survive withdrawal."""
        pull = json.loads(self.expect("/api/repos/alice/demo/pulls", 201, token=self.users["nina"],
                                      method="POST", body={"title": "nina merges again",
                                                           "head_ref": "refs/heads/team-head-nina",
                                                           "base_ref": "refs/heads/team-base-nina"}))
        body = {"expected_version": pull["version"], "expected_head_oid": pull["head_oid"],
                "expected_base_oid": pull["base_oid"], "strategy": "merge_commit"}
        status, raw, _ = self.http(f"/api/repos/alice/demo/pulls/{pull['number']}/merge",
                                   token=self.users["nina"], method="POST", body=body)
        assert status == 200, (status, raw[:300])
        merged = json.loads(raw)["merge_commit_oid"]
        operation = self.team_assert_operation(self.last_operation("recorded"), "nina", "demo")
        return operation["id"], merged

    def team_admin_withdrawal(self):
        """The admin team member also serves the admin surface until the team removes it."""
        token = self.users["olga"]
        pull = json.loads(self.expect("/api/repos/alice/demo/pulls", 201, token=token,
                                      method="POST", body={"title": "team admin merges",
                                                           "head_ref": "refs/heads/team-head-olga",
                                                           "base_ref": "refs/heads/team-base-olga"}))
        body = {"expected_version": pull["version"], "expected_head_oid": pull["head_oid"],
                "expected_base_oid": pull["base_oid"], "strategy": "merge_commit"}
        status, raw, _ = self.http(f"/api/repos/alice/demo/pulls/{pull['number']}/merge",
                                   token=token, method="POST", body=body)
        assert status == 200, (status, raw[:300])
        merged = json.loads(raw)["merge_commit_oid"]
        operation = self.team_assert_operation(self.last_operation("recorded"), "olga", "demo")
        rule_path = "/api/repos/alice/demo/branch-rules/refs/heads/team-rule"
        assert self.http(rule_path, token=token, method="PUT", body=RULE)[0] == 201
        assert self.http(rule_path, token=token, method="DELETE")[0] == 200
        self.team_remove("alice", "demo", "role-admin-olga", "olga")
        assert self.http(rule_path, token=token, method="PUT", body=RULE)[0] == 404
        assert self.http("/api/repos/alice/demo/collaborators/heidi", token=token,
                         method="PUT", body={"role": "read"})[0] == 404
        assert self.http("/api/repos/alice/demo/pulls", token=token, method="POST",
                         body={"title": "after", "head_ref": "refs/heads/team-head-nina",
                               "base_ref": "refs/heads/team-base-nina"})[0] == 404
        return {"merge_commit_oid": merged, "merge_operation": operation["id"],
                "rule_manage": 201, "after_removal": 404}
