#!/usr/bin/env python3
"""Issue #4 harness: write-endpoint contract (ref transactions, pulls, rules, audit).

Every mutation below is one real HTTP request of the running service; the
receipts (``git_operations``/``outbox_events``), refs and policy rows are read
back from the owned schema and bare repository. Git transport writes
``git_operations``/``outbox_events``, never ``repository_audit_log``; that table
is only written by Forge/member writes, which also append ``audit_events`` to
the outbox for the demo repository.
"""
import json

from collaborator_contract import ZERO


class writes:
    """Write endpoints, their authorization and their durable receipts."""

    def ref_transactions(self):
        """read/triage 403; write and above 200 with actor-bound events and idempotency."""
        outcomes = {}
        vendor = self.root / "owned-work-alice"
        for user, role in (("carol", "read"), ("dave", "triage"), ("erin", "write"),
                           ("frank", "maintain"), ("grace", "admin")):
            self.git("checkout", "-B", "vendor-" + user, self.seed, cwd=vendor)
            oid = self.commit(vendor, "vendor-" + user + ".txt", "vendor " + user)
            self.push_branch(vendor, self.alice, "vendor-" + user)
            ref = "refs/heads/tx-" + user
            body = {"updates": [{"ref_name": ref, "old_oid": ZERO, "new_oid": oid}],
                    "atomic": True, "storage_generation": 1}
            status, raw, _ = self.http("/api/repos/alice/demo/ref-transactions",
                                       token=self.users[user], method="POST", body=body)
            if role in ("read", "triage"):
                assert status == 403, (user, role, status, raw[:200])
                assert self.ref(ref) is None and not self.events_for(ref)
                outcomes[role] = status
                continue
            assert status == 200, (user, role, status, raw[:300])
            applied = json.loads(raw)
            assert applied["atomic"] is True and applied["updates"] == body["updates"], applied
            assert self.ref(ref) == oid
            [operation] = [op for op in self.operations() if op["id"] == applied["operation_id"]]
            assert operation["outcome"] == "recorded", operation
            assert (operation["actor_id"], operation["actor_name"], operation["token_id"]) == (
                self.users[user]["user_id"], user, self.users[user]["token_id"])
            events = self.events_for(ref, operation["id"])
            assert [(e["old_oid"], e["new_oid"]) for e in events] == [(ZERO, oid)], events
            key = {"Idempotency-Key": "tx-" + user + "-key"}
            first = self.expect("/api/repos/alice/demo/ref-transactions", 200, token=self.users[user],
                                method="POST", body=body, extra_headers=key)
            second = self.expect("/api/repos/alice/demo/ref-transactions", 200, token=self.users[user],
                                 method="POST", body=body, extra_headers=key)
            assert first == second == raw and len(self.events_for(ref)) == 1
            changed = {"updates": [{"ref_name": "refs/heads/other-" + user, "old_oid": ZERO,
                                    "new_oid": oid}], "atomic": True}
            conflict = self.http("/api/repos/alice/demo/ref-transactions", token=self.users[user],
                                 method="POST", body=changed, extra_headers=key)[0]
            assert conflict == 409, conflict
            outcomes[role] = 200
        assert outcomes == {"read": 403, "triage": 403, "write": 200, "maintain": 200, "admin": 200}
        return outcomes

    def pull_lifecycle(self):
        """PR create and merge require write; every write+ role merges a real FF.

        ``src/pulls/merge.rs`` records the merge response under
        ``Idempotency-Key``; the same key replays that response (200) with no
        second ref update, while the same payload without a key sees the merged
        state (409).
        """
        pulls = "/api/repos/alice/demo/pulls"
        vendor = self.root / "owned-work-alice"
        merged = {}
        for user, role in (("erin", "write"), ("frank", "maintain"), ("grace", "admin")):
            # One base/head pair per role: a merged base cannot be rewound for
            # the next role (receive.denyNonFastForwards would reject it).
            base_ref = "base-" + user
            head_ref = "feature-" + user
            self.git("checkout", "-B", "pr-" + base_ref, self.seed, cwd=vendor)
            self.push_branch(vendor, self.alice, base_ref)
            base = self.ref("refs/heads/" + base_ref)
            for outsider in ("carol", "dave"):
                status, raw, _ = self.http(pulls, token=self.users[outsider], method="POST",
                                           body={"title": "denied " + outsider,
                                                 "head_ref": "refs/heads/main",
                                                 "base_ref": "refs/heads/" + base_ref})
                assert status == 403, (outsider, status, raw[:200])
            assert self.sql("SELECT count(*) FROM forge_pulls WHERE repository_id='" +
                            self.repo["id"] + "' AND base_ref='refs/heads/" +
                            base_ref + "'") == "0"
            self.git("checkout", "-B", head_ref, self.seed, cwd=vendor)
            head = self.commit(vendor, "pr-" + user + ".txt", "pull request head " + user)
            assert self.push_branch(vendor, self.alice, head_ref) == head
            status, raw, _ = self.http(pulls, token=self.users[user], method="POST",
                                       body={"title": "collaborator PR " + user,
                                             "head_ref": "refs/heads/" + head_ref,
                                             "base_ref": "refs/heads/" + base_ref})
            assert status == 201, (user, role, status, raw[:300])
            pull = json.loads(raw)
            assert (pull["head_oid"], pull["base_oid"], pull["state"]) == (head, base, "open")
            assert pull["author_id"] == self.users[user]["user_id"]
            merge = f"{pulls}/{pull['number']}/merge"
            body = {"expected_version": pull["version"], "expected_head_oid": head,
                    "expected_base_oid": base, "storage_generation": 1,
                    "strategy": "fast_forward"}
            key = {"Idempotency-Key": "merge-" + user}
            status, raw, _ = self.http(merge, token=self.users[user], method="POST", body=body,
                                       extra_headers=key)
            assert status == 200, (user, role, status, raw[:300])
            result = json.loads(raw)
            assert (result["state"], result["merge_commit_oid"]) == ("merged", head), result
            assert result["version"] == pull["version"] + 1
            assert self.ref("refs/heads/" + base_ref) == head
            replay = self.expect(merge, 200, token=self.users[user], method="POST", body=body,
                                 extra_headers=key)
            assert replay == raw, (replay[:300], raw[:300])
            assert self.ref("refs/heads/" + base_ref) == head
            again = self.http(merge, token=self.users[user], method="POST", body=body)[0]
            assert again == 409, again
            merged[role] = {"number": pull["number"], "merge_commit_oid": head}
        return {"create_denied_read_and_triage": True, "merged": merged,
                "replay_same_key": 200, "merge_without_key_after_merge": 409}

    def rule_refusals(self):
        """Rule upsert needs maintain: write is refused; no rule means no 409 to hide it."""
        self.grant("nina", "write")
        self.grant("karl", "maintain")
        rule = {"required_approvals": 0, "required_checks": [], "require_fast_forward": True,
                "prevent_deletion": True, "prevent_force_push": True}
        rule_path = "/api/repos/alice/demo/branch-rules/refs/heads/main"
        status, raw, _ = self.http(rule_path, token=self.users["nina"], method="PUT", body=rule)
        assert status == 403, (status, raw[:200])
        assert self.rules() == []
        status, _, _ = self.http(rule_path, token=self.alice)
        assert status == 404, status
        return {"write_collaborator_rule": 403, "rules": 0}

    def maintain_rule_matrix(self):
        """``Role::Maintain`` may upsert/delete branch rules (src/pulls/rules.rs).

        The create also proves the absent default: with no rule, a ``merge_commit``
        merge is allowed (nothing to require fast-forward yet).
        """
        vendor = self.root / "owned-work-alice"
        self.git("checkout", "-B", "maint-base", self.seed, cwd=vendor)
        base = self.push_branch(vendor, self.alice, "maint-base")
        self.git("checkout", "-B", "maint-head", self.seed, cwd=vendor)
        head = self.commit(vendor, "maint.txt", "maintain head")
        assert self.push_branch(vendor, self.alice, "maint-head") == head
        pull = json.loads(self.expect("/api/repos/alice/demo/pulls", 201,
                                      token=self.users["karl"], method="POST",
                                      body={"title": "maintainer without rule",
                                            "head_ref": "refs/heads/maint-head",
                                            "base_ref": "refs/heads/maint-base"}))
        merge = f"/api/repos/alice/demo/pulls/{pull['number']}/merge"
        body = {"expected_version": pull["version"], "expected_head_oid": head,
                "expected_base_oid": base, "strategy": "merge_commit"}
        status, raw, _ = self.http(merge, token=self.users["karl"], method="POST", body=body,
                                   extra_headers={"Idempotency-Key": "maint-merge-1"})
        assert status == 200, (status, raw[:300])
        result = json.loads(raw)
        assert result["state"] == "merged" and result["merge_commit_oid"] != head, result
        assert self.ref("refs/heads/maint-base") == result["merge_commit_oid"]
        rule_path = "/api/repos/alice/demo/branch-rules/refs/heads/maintenance"
        rule = {"required_approvals": 0, "required_checks": [], "require_fast_forward": True,
                "prevent_deletion": True, "prevent_force_push": True}
        status, raw, _ = self.http(rule_path, token=self.users["karl"], method="PUT", body=rule)
        assert status == 201, (status, raw[:300])
        created = json.loads(raw)
        assert (created["branch_ref"], created["version"]) == ("refs/heads/maintenance", 1), created
        assert self.rules() == [{"branch_ref": "refs/heads/maintenance", "version": 1,
                                 "require_fast_forward": True}], self.rules()
        stale = self.http(rule_path, token=self.users["karl"], method="PUT",
                          body={**rule, "expected_version": created["version"] + 1})[0]
        assert stale == 409, stale
        updated = self.http(rule_path, token=self.users["karl"], method="PUT",
                            body={**rule, "expected_version": created["version"]})[0]
        assert updated == 200, updated
        removed = self.http(rule_path, token=self.users["karl"], method="DELETE")[0]
        assert removed == 200, removed
        assert self.rules() == []
        return {"maintain_rule_create": status, "maintain_rule_update": updated,
                "maintain_rule_delete": removed, "merge_without_rule": "merge_commit allowed",
                "merge_commit_oid": result["merge_commit_oid"]}

    def admin_management(self):
        """``Role::Admin`` manages other collaborators and rules, never the owner.

        ``src/members/rbac.rs`` resolves the namespace owner as admin and refuses
        the owner row itself with 409 ("cannot modify or remove repository owner").
        The admin-created rule is removed again inside this case so later cases
        observe the documented empty rule set.
        """
        self.grant("heidi", "admin")
        self.grant("olga", "read")
        rule_path = "/api/repos/alice/demo/branch-rules/refs/heads/delivery"
        fresh = {"required_approvals": 0, "required_checks": [], "require_fast_forward": True,
                 "prevent_deletion": True, "prevent_force_push": True}
        created = self.http(rule_path, token=self.users["heidi"], method="PUT", body=fresh)[0]
        assert created == 201, created
        rule = json.loads(self.expect(rule_path, 200, token=self.alice))
        assert rule["version"] == 1, rule
        stale = self.http(rule_path, token=self.users["heidi"], method="PUT",
                          body={**fresh, "expected_version": rule["version"] + 1})[0]
        assert stale == 409, stale
        updated = self.http(rule_path, token=self.users["heidi"], method="PUT",
                            body={**fresh, "expected_version": rule["version"],
                                  "prevent_deletion": False})[0]
        assert updated == 200, updated
        for username in ("alice", "heidi"):
            status, raw, _ = self.http(f"/api/repos/alice/demo/collaborators/{username}",
                                       token=self.users["heidi"], method="PUT",
                                       body={"role": "admin"})
            assert status == 409, (username, status, raw[:200])
            assert b"cannot modify or remove repository owner" in raw, raw[:200]
        removed = json.loads(self.expect("/api/repos/alice/demo/collaborators/olga", 200,
                                         method="DELETE", token=self.users["heidi"]))
        assert (removed["removed"], removed["username"]) == (True, "olga")
        self.grant("mona", "triage")
        promoted = self.http("/api/repos/alice/demo/collaborators/karl", token=self.users["heidi"],
                             method="PUT", body={"role": "maintain"})[0]
        assert promoted == 200, promoted
        dropped = self.http(rule_path, token=self.users["heidi"], method="DELETE")[0]
        assert dropped == 200, dropped
        assert self.rules() == []
        rows = json.loads(self.sql(
            "SELECT coalesce(json_object_agg(u.username, c.role), '{}'::json) FROM "
            "repository_collaborators c JOIN users u ON u.id=c.user_id WHERE c.repository_id='" +
            self.repo["id"] + "'"))
        assert rows.get("alice") is None, rows
        assert rows["heidi"] == "admin" and rows["karl"] == "maintain", rows
        return {"admin_rule_create": created, "stale_admin_cas": stale,
                "admin_rule_update": updated, "admin_rule_delete": dropped,
                "owner_row_by_admin": 409, "admin_removed_collaborator": "olga",
                "collaborator_roles": rows}

    def pull_merge_under_rule(self):
        """A real PR merged under the fast-forward rule karl maintains."""
        rules = self.rules()
        assert [(r["branch_ref"], r["require_fast_forward"]) for r in rules] == [
            ("refs/heads/maint-base", True)], rules
        vendor = self.root / "owned-work-alice"
        self.git("checkout", "-B", "rule-base", self.seed, cwd=vendor)
        base = self.push_branch(vendor, self.alice, "rule-base")
        self.git("checkout", "-B", "rule-head", self.seed, cwd=vendor)
        head = self.commit(vendor, "rule-merge.txt", "rule head")
        assert self.push_branch(vendor, self.alice, "rule-head") == head
        self.git("checkout", "-B", "rule-under-maint-base", self.seed, cwd=vendor)
        assert self.push_branch(vendor, self.alice, "rule-under-maint-base") == self.seed
        pull = json.loads(self.expect("/api/repos/alice/demo/pulls", 201,
                                      token=self.users["karl"], method="POST",
                                      body={"title": "merge under maintainer rule",
                                            "head_ref": "refs/heads/rule-head",
                                            "base_ref": "refs/heads/maint-base"}))
        pr = f"/api/repos/alice/demo/pulls/{pull['number']}/merge"
        body = {"expected_version": pull["version"], "expected_head_oid": head,
                "expected_base_oid": self.seed, "strategy": "merge_commit"}
        status, raw, _ = self.http(pr, token=self.users["karl"], method="POST", body=body,
                                   extra_headers={"Idempotency-Key": "rule-merge-1"})
        assert status == 409, (status, raw[:200])
        # The frozen product text proves the rule, not an unrelated conflict, refused it.
        assert b"requires fast-forward merge" in raw, raw[:200]
        assert self.ref("refs/heads/maint-base") == self.seed
        body["strategy"] = "fast_forward"
        status, raw, _ = self.http(pr, token=self.users["karl"], method="POST", body=body)
        assert status == 200, (status, raw[:300])
        assert self.ref("refs/heads/maint-base") == head
        return {"rule_creator": "karl(maintain)", "rule_branch": "refs/heads/maint-base",
                "merger": "karl(maintain)", "merge_commit_under_rule": status,
                "fast_forward_merge": 200, "base": head, }


    def audit_boundary(self):
        """Git transport writes git_operations/outbox_events, never repository_audit_log.

        Every receipt is read for the demo repository only: ``GET /api/repos/
        alice/demo/events`` (``src/reliability.rs``, newest 1000 of that
        repository) and the demo rows of ``repository_audit_log``.
        """
        repo = self.repo["id"]
        rows = json.loads(self.expect("/api/repos/alice/demo/events", 200, token=self.alice))
        assert rows and len(rows) < 1000, len(rows)
        keys = {(e["operation_id"], e["ref_name"]) for e in rows}
        assert len(keys) == len(rows), "duplicate receipts for one ref change"
        actions = json.loads(self.sql(
            "SELECT COALESCE(json_agg(DISTINCT action), '[]'::json) FROM repository_audit_log "
            "WHERE repository_id='" + repo + "'"))
        assert not [a for a in actions if a == "git" or a.startswith("push") or a.startswith("git_")], actions
        assert self.sql("SELECT count(*) FROM repository_audit_log WHERE repository_id='" + repo +
                        "' AND (action LIKE 'git%' OR action LIKE 'push%' OR "
                        "target_type IN ('git_operation','outbox_event'))") == "0"
        # Membership/branch-rule writes are the only demo audit rows, one per
        # such mutation this run performed through the API.
        performed = getattr(self, "member_mutations", 0)
        mutation_rows = [row for row in json.loads(self.sql(
            "SELECT COALESCE(json_agg(t), '[]'::json) FROM (SELECT actor_name, action, "
            "count(*) AS n FROM repository_audit_log WHERE repository_id='" + repo +
            "' GROUP BY 1,2) t"))
            if row["action"].startswith(("collaborator.", "branch_rule."))]
        assert sum(int(row["n"]) for row in mutation_rows) == performed, (mutation_rows, performed)
        assert all(row["actor_name"] in ("alice", "heidi") for row in mutation_rows), mutation_rows
        return {"git_operations_recorded": len([op for op in self.operations()
                                                if op["outcome"] == "recorded"]),
                "demo_outbox_events": len(rows),
                "git_transport_wrote_repository_audit_log": False,
                "member_mutations_via_api": performed,
                "repository_audit_log_rows": int(self.sql(
                    "SELECT count(*) FROM repository_audit_log WHERE repository_id='" + repo + "'")),
                "repository_audit_log_git_rows": 0, "audit_actions": actions}
