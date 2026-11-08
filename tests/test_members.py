#!/usr/bin/env python3
"""Offline unit and contract tests for Track B (F24 Collaborator/Team 5-Role RBAC & F25 Multi-Reviewer PR Policy + Audit Log)."""
import ast
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import members  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class MembersTrackBContractTest(unittest.TestCase):
    def test_members_module_layout_and_anti_monolith_bounds(self):
        members_rs = ROOT / "src/members.rs"
        self.assertTrue(members_rs.is_file(), "src/members.rs must be a regular file")
        self.assertFalse(
            (ROOT / "src/members/mod.rs").exists(),
            "src/members/mod.rs must never exist (Rust 2024 module layout)",
        )
        members_src = members_rs.read_text(encoding="utf-8")
        members_lines = members_src.splitlines()
        self.assertLess(
            len(members_lines),
            100,
            f"src/members.rs must remain < 100 lines, got {len(members_lines)}",
        )
        self.assertIn("pub fn routes() -> Router<Arc<AppState>>", members_src)

        for sql_kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "):
            self.assertNotIn(sql_kw, members_src, f"src/members.rs must not embed inline SQL ({sql_kw})")
        self.assertNotIn("Command::new", members_src)

        for sub in ("models", "rbac", "audit"):
            self.assertIn(f"pub mod {sub};", members_src)
            sub_path = ROOT / "src/members" / f"{sub}.rs"
            self.assertTrue(sub_path.is_file(), f"Missing submodule {sub_path}")
            sub_lines = sub_path.read_text(encoding="utf-8").splitlines()
            self.assertGreater(len(sub_lines), 50, f"{sub}.rs is unexpectedly small ({len(sub_lines)} lines)")
            self.assertLess(
                len(sub_lines),
                550,
                f"{sub}.rs exceeds 550-line anti-monolith bound ({len(sub_lines)} lines)",
            )

        expected_routes = (
            "/api/repos/{owner}/{name}/collaborators",
            "/api/repos/{owner}/{name}/collaborators/{username}",
            "/api/repos/{owner}/{name}/teams",
            "/api/repos/{owner}/{name}/teams/{team_slug}",
            "/api/repos/{owner}/{name}/teams/{team_slug}/members",
            "/api/repos/{owner}/{name}/teams/{team_slug}/members/{username}",
            "/api/repos/{owner}/{name}/permissions/{username}",
            "/api/repos/{owner}/{name}/audit",
        )
        for route in expected_routes:
            self.assertIn(route, members_src, f"Route {route} missing from src/members.rs")
        self.assertNotIn("/:", members_src)
        self.assertNotIn("{*", members_src)

        for pull_sub in ("models", "handlers", "rules"):
            p_path = ROOT / "src/pulls" / f"{pull_sub}.rs"
            p_lines = p_path.read_text(encoding="utf-8").splitlines()
            self.assertGreater(len(p_lines), 50)
            self.assertLess(
                len(p_lines),
                600,
                f"src/pulls/{pull_sub}.rs exceeds 600-line bound ({len(p_lines)} lines)",
            )

    def test_migration_050_sql_contract_and_zero_between_clauses(self):
        sql_path = members.migration_050_path()
        self.assertTrue(sql_path.is_file(), f"Missing SQL migration at {sql_path}")
        sql = sql_path.read_text(encoding="utf-8")

        self.assertIsNone(
            re.search(r"\bBETWEEN\b", sql, flags=re.IGNORECASE),
            "050_members_rbac.sql must not use BETWEEN (use >= and <= for pg_dump invariance)",
        )

        tables = (
            "repository_collaborators",
            "repository_teams",
            "repository_team_members",
            "repository_audit_log",
        )
        positions = {}
        for table in tables:
            match = re.search(rf"CREATE\s+TABLE\s+{table}\s*\(", sql)
            self.assertIsNotNone(match, f"Missing CREATE TABLE {table}")
            positions[table] = match.start()

        self.assertLess(
            positions["repository_teams"],
            positions["repository_team_members"],
            "repository_teams must be created before repository_team_members",
        )

        self.assertIn("ADD COLUMN IF NOT EXISTS prevent_self_approval BOOLEAN NOT NULL DEFAULT false", sql)
        self.assertEqual(sql.count("role IN ('read', 'triage', 'write', 'maintain', 'admin')"), 2)
        self.assertIn("CHECK (user_id <> tenant_id)", sql)
        self.assertIn("enforce_repository_actor_membership()", sql)
        for trigger_tbl in (
            "forge_issues",
            "forge_issue_comments",
            "forge_pulls",
            "forge_pull_reviews",
            "git_operations",
        ):
            self.assertIn(f"ON {trigger_tbl}", sql)
        self.assertRegex(
            sql.strip(),
            r"INSERT INTO schema_migrations \(version\) VALUES \(50\)(?:\s+ON CONFLICT(?:\s*\(version\))?\s+DO NOTHING)?;$",
        )

    def test_shared_auth_forge_and_pulls_rbac_integration_in_rust_sources(self):
        auth_src = (ROOT / "src/auth.rs").read_text(encoding="utf-8")
        forge_src = (ROOT / "src/forge.rs").read_text(encoding="utf-8")
        models_src = (ROOT / "src/members/models.rs").read_text(encoding="utf-8")
        rbac_src = (ROOT / "src/members/rbac.rs").read_text(encoding="utf-8")
        audit_src = (ROOT / "src/members/audit.rs").read_text(encoding="utf-8")
        pulls_handlers = (ROOT / "src/pulls/handlers.rs").read_text(encoding="utf-8")
        pulls_rules = (ROOT / "src/pulls/rules.rs").read_text(encoding="utf-8")

        self.assertGreaterEqual(models_src.count("#[serde(deny_unknown_fields)]"), 6)
        self.assertIn("#[cfg(test)]", models_src)
        self.assertIn("#[cfg(test)]", audit_src)

        for sig in (
            "pub fn idempotency_key(",
            "pub async fn authorize_repo_with_role(",
            "pub async fn authorize_repo_action_by_id(",
            "pub async fn verify_token(",
            "pub async fn finish_tx(",
        ):
            self.assertIn(sig, auth_src)

        # Repository authorization must name the explicit PAT action. The old
        # untyped wrapper is gone, so neither name may reappear.
        self.assertNotIn("pub async fn authorize_repo(", auth_src)
        self.assertRegex(
            auth_src,
            r"pub async fn authorize_repo_with_role\([^)]*action: crate::token_scopes::RepoAction",
        )
        self.assertRegex(
            auth_src,
            r"pub async fn authorize_repo_action_by_id\([^)]*action: crate::token_scopes::RepoAction",
        )

        for module in ("handlers", "comments"):
            self.assertIn(f'#[path = "forge/{module}.rs"]', forge_src)
            self.assertIn(f"mod {module};", forge_src)
            self.assertIn(f"{module}::", forge_src)
            implementation = (ROOT / f"src/forge/{module}.rs").read_text(encoding="utf-8")
            self.assertIn("Role::Triage", implementation)
            self.assertIn("Role::Read", implementation)
        self.assertIn("resolve_effective_role", rbac_src)
        self.assertIn("check_review_permission", rbac_src)
        self.assertIn("is_self_approval_disallowed", pulls_rules)
        self.assertIn("check_review_permission", pulls_handlers)
        self.assertIn("pull_review.submitted", pulls_handlers)
        self.assertIn("branch_rule.upserted", pulls_rules)

    def test_five_role_hierarchy_and_cross_surface_permission_matrix(self):
        eng = members.MembersReferenceEngine()
        alice = eng.create_user("alice")
        bob = eng.create_user("bob")
        carol = eng.create_user("carol")
        dave = eng.create_user("dave")
        erin = eng.create_user("erin")
        outsider = eng.create_user("outsider")
        eng.create_repo(alice, "core")

        # Outsider always receives 404 Not Found on private repo endpoints
        self.assertEqual(eng.authorize_repo_with_role(outsider, "alice", "core", "read")[0], 404)
        self.assertEqual(eng.create_issue(outsider, "alice", "core", "Hack")[0], 404)
        self.assertEqual(eng.list_audit_events(outsider, "alice", "core")[0], 404)

        # Assign roles: bob=read, carol=triage, dave=write, erin=maintain
        self.assertEqual(eng.upsert_collaborator(alice, "alice", "core", "bob", "read")[0], 201)
        self.assertEqual(eng.upsert_collaborator(alice, "alice", "core", "carol", "triage")[0], 201)
        self.assertEqual(eng.upsert_collaborator(alice, "alice", "core", "dave", "write")[0], 201)
        self.assertEqual(eng.upsert_collaborator(alice, "alice", "core", "erin", "maintain")[0], 201)

        # Read: can read permissions, cannot create issue (403)
        self.assertEqual(eng.get_effective_permission(bob, "alice", "core", "bob")[0], 200)
        self.assertEqual(eng.create_issue(bob, "alice", "core", "Bug")[0], 403)

        # Triage: can create issue (201), cannot create PR (403)
        self.assertEqual(eng.create_issue(carol, "alice", "core", "Triaged bug")[0], 201)
        c1 = "1" * 40
        c2 = "2" * 40
        self.assertEqual(eng.create_pull(carol, "alice", "core", "PR", "feat", "main", c2, c1)[0], 403)

        # Write: can create PR (201), cannot upsert branch rule (403) or view audit log (403)
        self.assertEqual(eng.create_pull(dave, "alice", "core", "Dave PR", "feat", "main", c2, c1)[0], 201)
        self.assertEqual(eng.upsert_branch_rule(dave, "alice", "core", "main", required_approvals=1)[0], 403)
        self.assertEqual(eng.list_audit_events(dave, "alice", "core")[0], 403)

        # Triage can submit 'commented' review (201) but NOT 'approved' or 'changes_requested' (403)
        self.assertEqual(
            eng.create_review(carol, "alice", "core", 1, "commented", c2, body="Triage note")[0],
            201,
        )
        self.assertEqual(
            eng.create_review(carol, "alice", "core", 1, "approved", c2)[0],
            403,
        )
        self.assertEqual(
            eng.create_review(carol, "alice", "core", 1, "changes_requested", c2, body="No")[0],
            403,
        )

        # Maintain: can upsert branch rules (201) and view audit log (200), cannot manage collaborators (403)
        self.assertEqual(eng.upsert_branch_rule(erin, "alice", "core", "main", required_approvals=1)[0], 201)
        self.assertEqual(eng.list_audit_events(erin, "alice", "core")[0], 200)
        self.assertEqual(eng.upsert_collaborator(erin, "alice", "core", "bob", "write")[0], 403)

        # Read-only token on admin actor is rejected with 403 on mutations
        alice_ro = {**alice, "read_only": True}
        self.assertEqual(eng.create_issue(alice_ro, "alice", "core", "RO issue")[0], 403)

    def test_collaborator_and_team_inheritance_cas_and_owner_invariants(self):
        eng = members.MembersReferenceEngine()
        alice = eng.create_user("alice")
        bob = eng.create_user("bob")
        eng.create_repo(alice, "repo1")

        # Cannot add/modify/remove owner as collaborator or team member
        self.assertEqual(eng.upsert_collaborator(alice, "alice", "repo1", "alice", "admin")[0], 409)
        self.assertEqual(eng.remove_collaborator(alice, "alice", "repo1", "alice")[0], 409)

        # Idempotent collaborator creation and conflict detection
        s1, c1 = eng.upsert_collaborator(
            alice, "alice", "repo1", "bob", "read", idempotency_key="k-bob-1"
        )
        s2, c2 = eng.upsert_collaborator(
            alice, "alice", "repo1", "bob", "read", idempotency_key="k-bob-1"
        )
        self.assertEqual((s1, s2), (201, 201))
        self.assertEqual(c1, c2)
        self.assertEqual(
            eng.upsert_collaborator(
                alice, "alice", "repo1", "bob", "write", idempotency_key="k-bob-1"
            )[0],
            409,
        )

        # CAS version check on collaborator update
        self.assertEqual(
            eng.upsert_collaborator(alice, "alice", "repo1", "bob", "triage", expected_version=99)[0],
            409,
        )
        st_u, updated = eng.upsert_collaborator(
            alice, "alice", "repo1", "bob", "triage", expected_version=1
        )
        self.assertEqual(st_u, 200)
        self.assertEqual((updated["role"], updated["version"]), ("triage", 2))

        # Create two teams: 'qa' (write) and 'ops' (maintain)
        self.assertEqual(eng.create_team(alice, "alice", "repo1", "qa", "QA Team", "write")[0], 201)
        self.assertEqual(eng.create_team(alice, "alice", "repo1", "ops", "Ops Team", "maintain")[0], 201)
        self.assertEqual(eng.add_team_member(alice, "alice", "repo1", "qa", "alice")[0], 409)
        self.assertEqual(eng.add_team_member(alice, "alice", "repo1", "qa", "bob")[0], 201)
        self.assertEqual(eng.add_team_member(alice, "alice", "repo1", "ops", "bob")[0], 201)

        # Effective role is max(direct=triage, team=max(write, maintain)) = maintain
        _, perm = eng.get_effective_permission(bob, "alice", "repo1", "bob")
        self.assertEqual(
            (perm["role"], perm["direct_role"], perm["team_role"], perm["is_owner"]),
            ("maintain", "triage", "maintain", False),
        )

        # Removing bob from 'ops' downgrades team_role to 'write'
        self.assertEqual(eng.remove_team_member(alice, "alice", "repo1", "ops", "bob")[0], 200)
        _, perm2 = eng.get_effective_permission(bob, "alice", "repo1", "bob")
        self.assertEqual((perm2["role"], perm2["team_role"]), ("write", "write"))

        # Deleting 'qa' team leaves only direct_role = 'triage'
        self.assertEqual(eng.delete_team(alice, "alice", "repo1", "qa")[0], 200)
        _, perm3 = eng.get_effective_permission(bob, "alice", "repo1", "bob")
        self.assertEqual((perm3["role"], perm3["direct_role"], perm3["team_role"]), ("triage", "triage", None))

    def test_multi_reviewer_self_approval_prohibition_and_distinct_approver_policy(self):
        eng = members.MembersReferenceEngine()
        alice = eng.create_user("alice")
        bob = eng.create_user("bob")
        carol = eng.create_user("carol")
        eng.create_repo(alice, "service")

        eng.upsert_collaborator(alice, "alice", "service", "bob", "write")
        eng.upsert_collaborator(alice, "alice", "service", "carol", "write")
        eng.upsert_branch_rule(
            alice, "alice", "service", "main", required_approvals=2, prevent_self_approval=True
        )

        h_oid = "a" * 40
        b_oid = "b" * 40
        _, pr = eng.create_pull(bob, "alice", "service", "Bob feature", "feat", "main", h_oid, b_oid)
        pr_num = pr["number"]

        # Bob (PR author) cannot approve his own PR -> 403 Forbidden
        self.assertEqual(eng.create_review(bob, "alice", "service", pr_num, "approved", h_oid)[0], 403)
        # Bob CAN comment on his own PR -> 201 Created
        self.assertEqual(
            eng.create_review(bob, "alice", "service", pr_num, "commented", h_oid, body="Self comment")[0],
            201,
        )

        # Carol approves twice -> still only 1 distinct approver (< 2 required)
        self.assertEqual(eng.create_review(carol, "alice", "service", pr_num, "approved", h_oid)[0], 201)
        self.assertEqual(eng.create_review(carol, "alice", "service", pr_num, "approved", h_oid)[0], 201)
        pol1 = eng.evaluate_branch_policy("alice", "service", pr_num)
        self.assertFalse(pol1["allowed"])
        self.assertEqual(pol1["current_approvals"], 1)

        # Alice (owner/admin) requests changes -> resets approvals to 0
        self.assertEqual(
            eng.create_review(alice, "alice", "service", pr_num, "changes_requested", h_oid, body="Fix race")[0],
            201,
        )
        pol2 = eng.evaluate_branch_policy("alice", "service", pr_num)
        self.assertFalse(pol2["allowed"])
        self.assertEqual(pol2["current_approvals"], 0)

        # Alice and Carol both approve after changes_requested -> 2 distinct Write+ approvers -> allowed!
        self.assertEqual(eng.create_review(alice, "alice", "service", pr_num, "approved", h_oid)[0], 201)
        self.assertEqual(eng.create_review(carol, "alice", "service", pr_num, "approved", h_oid)[0], 201)
        pol3 = eng.evaluate_branch_policy("alice", "service", pr_num)
        self.assertTrue(pol3["allowed"])
        self.assertEqual(pol3["current_approvals"], 2)

    def test_audit_log_filtering_and_cursor_pagination(self):
        eng = members.MembersReferenceEngine()
        alice = eng.create_user("alice")
        bob = eng.create_user("bob")
        carol = eng.create_user("carol")
        eng.create_repo(alice, "audit-repo")

        eng.upsert_collaborator(alice, "alice", "audit-repo", "bob", "maintain")
        eng.upsert_collaborator(alice, "alice", "audit-repo", "carol", "write")
        eng.create_team(alice, "alice", "audit-repo", "sec", "Security", "maintain")
        eng.add_team_member(alice, "alice", "audit-repo", "sec", "carol")
        eng.upsert_branch_rule(bob, "alice", "audit-repo", "main", required_approvals=1)

        # Cursor pagination with limit=2
        st1, p1 = eng.list_audit_events(bob, "alice", "audit-repo", limit=2)
        self.assertEqual(st1, 200)
        self.assertEqual(len(p1["items"]), 2)
        self.assertIsNotNone(p1["next_after"])

        st2, p2 = eng.list_audit_events(bob, "alice", "audit-repo", after=p1["next_after"], limit=2)
        self.assertEqual(st2, 200)
        self.assertEqual(len(p2["items"]), 2)
        self.assertGreater(p2["items"][0]["id"], p1["items"][-1]["id"])

        # Filter by actor=bob and action=branch_rule.upserted
        _, by_bob = eng.list_audit_events(alice, "alice", "audit-repo", filter_actor="bob")
        self.assertEqual(len(by_bob["items"]), 1)
        self.assertEqual(by_bob["items"][0]["action"], "branch_rule.upserted")

        # Invalid query parameters rejected with 400
        self.assertEqual(eng.list_audit_events(alice, "alice", "audit-repo", since=500, until=100)[0], 400)
        self.assertEqual(eng.list_audit_events(alice, "alice", "audit-repo", limit=0)[0], 400)
        self.assertEqual(eng.list_audit_events(alice, "alice", "audit-repo", after=-1)[0], 400)

    def test_e2e_harness_script_parses_and_exposes_expected_cases(self):
        members_py = ROOT / "tests/members.py"
        src = members_py.read_text(encoding="utf-8")
        ast.parse(src)
        for case_name in (
            "setup",
            "migration",
            "collaborators_and_5_role_hierarchy",
            "teams_and_max_role_inheritance",
            "multi_reviewer_self_approval_and_distinct_approvers",
            "audit_log_filters_and_cursor_pagination",
            "access_and_boundaries",
            "concurrency_and_idempotency",
            "restart",
            "run_all",
        ):
            self.assertIn(f"def {case_name}(", src)


if __name__ == "__main__":
    unittest.main()
