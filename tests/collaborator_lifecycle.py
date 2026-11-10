#!/usr/bin/env python3
"""Issue #4 harness: owned environment, Git transport matrix, grants and receipt lookups.

Roles resolve as ``read < triage < write < maintain < admin``
(``resolve_effective_role``). Transport and the write endpoints require:

  upload-pack (clone/fetch/ls-remote)  read
  Git receive-pack / push              write
  POST /ref-transactions               write
  POST /pulls, POST /pulls/{n}/merge   write
  PUT|DELETE /branch-rules/...         maintain
  POST|PUT|DELETE /collaborators/...   admin, but never the direct collaborator
                                       rows the owner itself holds

So ``read``/``triage`` are deliberately expected to be refused on every write
path; ``write``, ``maintain`` and ``admin`` succeed. A read-only token stays
403 on every mutating path even for a ``write`` collaborator; a
non-collaborator gets 404 without enumeration; a withdrawn collaborator loses
new requests without erasing the receipts recorded while the grant was live.
"""
import json

from collaborator_contract import (
    FIXTURE_USERS, RECEIVE, RECEIVE_ENDPOINT, RECEIVE_REFS, STAFF_USERS, UPLOAD_REFS, ZERO,
)


class lifecycle:
    """Owned service, fixture users, owner grants and read-side receipt helpers."""

    # ---- helpers ---------------------------------------------------------
    def identity(self):
        return {"schema": self.schema, "database_url": self.redact(self.db),
                "server_pid": self.proc.pid if self.proc else None,
                "repository": self.repo["id"], "owner": self.repo["owner"],
                "name": self.repo["name"]}

    def worker(self, user):
        """A fresh clone for ``user`` so Git never reads or writes a peer's tree."""
        work = self.root / ("owned-work-" + user)
        self.git("clone", self.remote, str(work), token=self.users[user])
        self.git("config", "user.name", user.title(), cwd=work)
        self.git("config", "user.email", user + "@collaborator.invalid", cwd=work)
        return work

    def commit(self, work, filename, message):
        (work / filename).write_text(message + "\n")
        self.git("add", filename, cwd=work)
        self.git("commit", "-m", message, cwd=work)
        return self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()

    def push_branch(self, work, token, branch, base="origin"):
        self.git("push", base, "HEAD:refs/heads/" + branch, cwd=work, token=token)
        return self.ref("refs/heads/" + branch)

    def receive_refs_status(self, token):
        return self.http(self.repo["clone_path"] + RECEIVE_REFS, token=token)[0]

    def upload_status(self, token):
        return self.http(self.repo["clone_path"] + UPLOAD_REFS, token=token)[0]

    def grant(self, user, role):
        """Owner grants a direct role through the real API (201 then 200)."""
        path = f"/api/repos/alice/demo/collaborators/{user}"
        created = json.loads(self.expect(path, 201, method="PUT", token=self.alice,
                                         body={"role": role, "username": user}))
        assert created["username"] == user and created["role"] == role, created
        assert self.sql("SELECT role FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.users[user]["user_id"] + "'") == role
        return created

    def events_for(self, ref_name, operation_id=None):
        return [event for event in self.events()
                if event["ref_name"] == ref_name
                and (operation_id is None or event["operation_id"] == operation_id)]

    def rules(self):
        """Branch rules of alice/demo only; other owned repositories never decide these cases."""
        return json.loads(self.sql(
            "SELECT COALESCE(json_agg(t), '[]'::json) FROM (SELECT branch_ref, version, "
            "require_fast_forward FROM forge_branch_rules WHERE repository_id='" +
            self.repo["id"] + "') t"))

    # ---- cases -----------------------------------------------------------
    def environment(self):
        # ``git_matrix_version`` resolved but never started the service: this is
        # the single initialization of the owned schema, users and data root.
        self.setup()
        for name in FIXTURE_USERS:
            if name not in ("alice", "bob"):
                self.users[name] = self.account("create-user", name)
        self.repo = self.create_repository({"name": "demo"}, token=self.alice)
        assert self.repo["state"] == "ready" and self.repo["clone_path"] == "/git/alice/demo.git"
        self.remote = self.base + self.repo["clone_path"]
        self.bare = self.root / "data/repos" / (self.repo["id"] + ".git")
        # Owner-only fixture history; it is never evidence of a collaborator action.
        work = self.root / "owned-work-alice"
        self.git("clone", self.remote, str(work), token=self.alice)
        self.git("config", "user.name", "Alice", cwd=work)
        self.git("config", "user.email", "alice@collaborator.invalid", cwd=work)
        self.seed = self.commit(work, "README.md", "collaborator matrix seed")
        assert self.push_branch(work, self.alice, "main") == self.seed
        return {"collaborator_rows": 0, "ready_via": "POST /api/repos",
                "schema_initializations": 1, **self.identity()}

    def staff_fixtures(self):
        """Write users author a real PR in their own API-created repository first."""
        made = {}
        for user in STAFF_USERS:
            own = self.create_repository({"name": "staff-" + user}, token=self.users[user])
            work = self.root / ("owned-staff-" + user)
            self.git("clone", self.base + own["clone_path"], str(work), token=self.users[user])
            self.git("config", "user.name", user.title(), cwd=work)
            self.git("config", "user.email", user + "@collaborator.invalid", cwd=work)
            self.commit(work, "staff.txt", "staff fixture " + user)
            self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.users[user])
            self.git("checkout", "-B", "feature", cwd=work)
            self.commit(work, "staff-feature.txt", "staff feature " + user)
            self.push_branch(work, self.users[user], "feature")
            pull = json.loads(self.expect(f"/api/repos/{user}/staff-{user}/pulls", 201,
                                          token=self.users[user], method="POST",
                                          body={"title": "staff " + user,
                                                "head_ref": "refs/heads/feature",
                                                "base_ref": "refs/heads/main"}))
            made[user] = pull["number"]
        return made

    def role_matrix(self):
        """clone/fetch/push per direct role; read/triage legitimately cannot write."""
        rows = {}
        for user, role in {"carol": "read", "dave": "triage", "erin": "write",
                           "frank": "maintain", "grace": "admin"}.items():
            self.grant(user, role)
            token = self.users[user]
            permission = json.loads(self.expect(f"/api/repos/alice/demo/permissions/{user}", 200,
                                                token=self.alice))
            assert (permission["role"], permission["direct_role"], permission["is_owner"]) == (
                role, role, False), permission
            work = self.worker(user)
            assert (work / "README.md").read_text() == "collaborator matrix seed\n"
            self.git("fetch", "origin", cwd=work, token=token)
            assert self.git("rev-parse", "origin/main", cwd=work).stdout.decode().strip() == self.seed
            assert self.upload_status(token) == 200
            branch = "role-push-" + user
            oid = self.commit(work, "role.txt", "push as " + role)
            if role in ("read", "triage"):
                # Deleting an absent branch reaches receive-pack with no object
                # transfer, so Git cannot answer from a client-side preflight.
                deleted = self.git("push", "origin", ":" + branch, cwd=work, token=token,
                                   check=False)
                assert deleted.returncode != 0
                denied = self.git("push", "origin", "HEAD:refs/heads/" + branch, cwd=work,
                                  token=token, check=False)
                assert denied.returncode != 0
                assert self.receive_refs_status(token) == 403
                assert self.ref("refs/heads/" + branch) is None
                assert not self.events_for("refs/heads/" + branch)
                outcome = "denied"
            else:
                assert self.push_branch(work, token, branch) == oid
                operation = self.last_operation("recorded")
                assert operation["actor_id"] == self.users[user]["user_id"]
                assert operation["actor_name"] == user
                assert operation["token_id"] == token["token_id"]
                events = self.events_for("refs/heads/" + branch, operation["id"])
                assert [(e["old_oid"], e["new_oid"]) for e in events] == [(ZERO, oid)], events
                outcome = "recorded"
            rows[user] = {"role": role, "clone": True, "fetch": True, "push": outcome}
        assert [row["push"] for row in rows.values()] == [
            "denied", "denied", "recorded", "recorded", "recorded"]
        return rows

    def fetch_propagation(self):
        """The owner's later commit reaches every role; read rows still cannot publish."""
        branch = "owner-feature"
        work = self.root / "owned-work-alice"
        self.git("checkout", "-B", "publish", self.seed, cwd=work)
        oid = self.commit(work, "feature.txt", "owner feature")
        assert self.push_branch(work, self.alice, branch) == oid
        received = {}
        for user, role in (("carol", "read"), ("dave", "triage"), ("erin", "write"),
                           ("frank", "maintain"), ("grace", "admin")):
            peer = self.worker("fetch-" + user)
            if role in ("read", "triage"):
                denied = self.git("push", "origin", "HEAD:refs/heads/fetch-" + user, cwd=peer,
                                  token=self.users[user], check=False)
                assert denied.returncode != 0 and self.ref("refs/heads/fetch-" + user) is None
            self.git("fetch", "origin", cwd=peer, token=self.users[user])
            assert self.git("rev-parse", "origin/" + branch, cwd=peer).stdout.decode().strip() == oid
            received[user] = True
        return received

    def outsider_isolation(self):
        """A valid non-collaborator gets 404 on API/Git and no enumerable difference."""
        token = self.users["quinn"]
        reads = ["/api/repos/alice/demo", "/api/repos/alice/demo/refs",
                 "/api/repos/alice/demo/commits", "/api/repos/alice/demo/pulls"]
        for path in reads:
            status, body, _ = self.http(path, token=token)
            assert status == 404, (path, status)
            assert b"alice" not in body and b"demo" not in body, (path, body[:200])
        writes = (("/api/repos/alice/demo/issues", {"title": "outsider"}),
                  ("/api/repos/alice/demo/ref-transactions",
                   {"updates": [{"ref_name": "refs/heads/outsider", "old_oid": ZERO,
                                 "new_oid": self.seed}], "atomic": True}),
                  ("/api/repos/alice/demo/pulls",
                   {"title": "outsider", "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main"}),
                  ("/api/repos/alice/demo/pulls/1/merge",
                   {"expected_version": 1, "expected_head_oid": self.seed,
                    "expected_base_oid": self.seed}))
        for path, body in writes:
            status, raw, _ = self.http(path, token=token, method="POST", body=body)
            assert status == 404, (path, status, raw[:200])
        assert self.upload_status(token) == 404
        assert self.receive_refs_status(token) == 404
        # No-body receive-pack POST is refused before hooks; the ref must stay absent.
        status, _, _ = self.http(self.repo["clone_path"] + RECEIVE_ENDPOINT, 404, token=token,
                                 method="POST", body=b"0000", content_type=RECEIVE)
        assert status == 404
        denied = self.git("ls-remote", self.remote, token=token, check=False)
        assert denied.returncode != 0 and self.seed.encode() not in denied.stdout
        assert self.ref("refs/heads/outsider") is None
        assert self.sql("SELECT count(*) FROM repository_collaborators WHERE user_id='" +
                        token["user_id"] + "'") == "0"
        return {"api_read": "404", "api_write": "404", "upload_pack": 404,
                "receive_pack": 404, "ls_remote": "denied"}

    def read_only_token(self):
        """A read-only token of the write collaborator keeps 403 on every write path."""
        token = self.account("create-token", "erin", "--read-only")
        work = self.root / "owned-work-erin_ro"
        self.git("clone", self.remote, str(work), token=token)
        assert (work / "README.md").is_file()
        assert self.upload_status(token) == 200
        assert self.receive_refs_status(token) == 403
        (work / "ro.txt").write_text("read-only push\n")
        self.git("add", "ro.txt", cwd=work)
        self.git("commit", "-m", "read-only push", cwd=work)
        denied = self.git("push", "origin", "HEAD:refs/heads/read-only-token", cwd=work,
                          token=token, check=False)
        assert denied.returncode != 0 and self.ref("refs/heads/read-only-token") is None
        rules_before = self.rules()
        before_ops, before_events = self.operations(), self.events()
        status, wire = self.raw_receive(token)
        assert status == 403, (status, wire[:200])
        writes = (("/api/repos/alice/demo/ref-transactions",
                   {"updates": [{"ref_name": "refs/heads/ro-tx", "old_oid": ZERO,
                                 "new_oid": self.seed}], "atomic": True}),
                  ("/api/repos/alice/demo/pulls",
                   {"title": "read-only PR", "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main"}),
                  ("/api/repos/alice/demo/pulls/1/merge",
                   {"expected_version": 1, "expected_head_oid": self.seed,
                    "expected_base_oid": self.seed}),
                  ("/api/repos/alice/demo/branch-rules/refs/heads/main", {"required_approvals": 0}))
        for path, body in writes:
            method = "PUT" if "branch-rules" in path else "POST"
            code, raw, _ = self.http(path, token=token, method=method, body=body)
            assert code == 403, (path, code, raw[:200])
        code, _, _ = self.http("/api/repos/alice/demo/collaborators/heidi", token=token,
                               method="PUT", body={"role": "admin"})
        assert code == 403, code
        # Nothing mutating reached SQL: the demo rule set and every receipt are untouched.
        assert self.rules() == rules_before == []
        assert self.ref("refs/heads/ro-tx") is None
        assert self.operations() == before_ops and self.events() == before_events
        return {"read": "allowed", "receive_pack": status, "raw_receive_pack": status,
                "push": "denied", "write_endpoints": "403", "ref_transactions": "unchanged"}

    def raw_receive(self, token):
        """A complete but table-less receive-pack request: the gate answers 403."""
        import base64
        import http.client
        auth = "Basic " + base64.b64encode(
            (token["username"] + ":" + token["token"]).encode()).decode()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            connection.request("POST", self.repo["clone_path"] + RECEIVE_ENDPOINT,
                               body=b"0000", headers={"Authorization": auth, "Content-Type": RECEIVE})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def non_fast_forward(self):
        """Higher roles add no capability: fast-forward-only still refuses a rewind.

        Production sets ``receive.denyNonFastForwards`` (src/storage.rs) and no
        branch rule exists on these branches yet.
        """
        assert self.rules() == []
        results = {}
        for user, role in (("erin", "write"), ("grace", "admin")):
            work = self.worker("ff-" + user)
            self.git("checkout", "-B", "ff-" + user, cwd=work)
            self.commit(work, "ff.txt", "first " + user)
            first = self.push_branch(work, self.users[user], "ff-" + user)
            self.commit(work, "ff.txt", "second " + user)
            second = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            self.git("reset", "--hard", first, cwd=work)
            stale = self.commit(work, "stale.txt", "stale " + user)
            assert stale not in (first, second)
            denied = self.git("push", "--force", "origin", "HEAD:refs/heads/ff-" + user, cwd=work,
                              token=self.users[user], check=False)
            assert denied.returncode != 0 and self.ref("refs/heads/ff-" + user) == first
            results[role] = "rejected"
        return results

    def withdrawal(self):
        """API removal denies new requests without erasing the live-grant receipts."""
        self.grant("judy", "write")
        work = self.worker("judy")
        oid = self.commit(work, "before.txt", "before withdrawal")
        assert self.push_branch(work, self.users["judy"], "judy-before") == oid
        operation = self.last_operation("recorded")
        receipts = self.events_for("refs/heads/judy-before", operation["id"])
        assert receipts
        removed = json.loads(self.expect("/api/repos/alice/demo/collaborators/judy", 200,
                                         method="DELETE", token=self.alice))
        assert (removed["removed"], removed["username"]) == (True, "judy")
        assert self.sql("SELECT count(*) FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.users["judy"]["user_id"] + "'") == "0"
        assert self.upload_status(self.users["judy"]) == 404
        assert self.receive_refs_status(self.users["judy"]) == 404
        after = self.commit(work, "after.txt", "after withdrawal")
        denied = self.git("push", "origin", "HEAD:refs/heads/judy-after", cwd=work,
                          token=self.users["judy"], check=False)
        assert denied.returncode != 0 and self.ref("refs/heads/judy-after") is None
        assert self.git("fetch", "origin", cwd=work, token=self.users["judy"], check=False).returncode != 0
        # Receipts retained exactly as recorded while the grant was live.
        [operation_after] = [op for op in self.operations() if op["id"] == operation["id"]]
        assert operation_after["outcome"] == "recorded"
        assert [e["event_id"] for e in self.events_for("refs/heads/judy-before")] == [
            e["event_id"] for e in receipts]
        assert self.ref("refs/heads/judy-before") == oid and oid != after
        return {"removal": "api_collaborator_delete", "upload_pack": 404, "receive_pack": 404,
                "push_denied": True, "receipts_preserved": len(receipts),
                "receipt_actor": operation["actor_name"]}

    def token_revocation(self):
        """A revoked collaborator token is 401 on the next transport request; role intact."""
        self.grant("linda", "admin")
        token = self.account("create-token", "linda")
        assert self.upload_status(token) == 200
        self.cli("revoke-token", token["token_id"])
        assert self.upload_status(token) == 401
        denied = self.git("ls-remote", self.remote, token=token, check=False)
        assert denied.returncode != 0
        assert self.sql("SELECT role FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.users["linda"]["user_id"] + "'") == "admin"
        return {"before": 200, "after": 401}
