#!/usr/bin/env python3
"""Real PG 17 + Git + HTTP E2E + Backup/Restore suite for Issue #86 collaboration features."""

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import traceback
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backup import BackupHarness
from web_sessions import BrowserHarness


class ForgeCollaborationHarness(BackupHarness, BrowserHarness):
    def prepare_fixtures(self):
        self.cli("migrate")
        self.alice = self.account("create-user", "alice")
        self.bob = self.account("create-user", "bob")
        self.carol = self.account("create-user", "carol")
        self.dave = self.account("create-user", "dave")
        self.start()

        # Setup personal repo alice/demo + org repo collab-org/team-repo with live Git branches
        self.demo = self.create_repository({"name": "demo"}, token=self.alice)
        self.expect(
            "/api/repos/alice/demo/collaborators/bob",
            201,
            token=self.alice,
            method="PUT",
            body={"username": "bob", "role": "maintain"},
        )
        self.expect(
            "/api/repos/alice/demo/collaborators/carol",
            201,
            token=self.alice,
            method="PUT",
            body={"username": "carol", "role": "triage"},
        )
        self.expect("/api/orgs", 201, token=self.alice, method="POST", body={"slug": "collab-org"})
        self.expect(
            "/api/orgs/collab-org/members/bob",
            (200, 201),
            token=self.alice,
            method="PUT",
            body={"role": "maintain"},
        )
        self.team_repo = json.loads(
            self.expect(
                "/api/repos",
                201,
                token=self.alice,
                method="POST",
                body={"owner": "collab-org", "name": "team-repo"},
            )
        )

        # Push real multi-line commits on main and feat branches in alice/demo
        work = self.root / "demo-work"
        remote = self.base + self.demo["clone_path"]
        self.git("clone", remote, str(work), token=self.alice)
        self.git("config", "user.name", "Alice", cwd=work)
        self.git("config", "user.email", "alice@example.test", cwd=work)
        (work / "README.md").write_text("line1\nline2\n", encoding="utf-8")
        (work / "src").mkdir(exist_ok=True)
        (work / "src" / "app.py").write_text("def a():\n    return 1\n", encoding="utf-8")
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "init", cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        base_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()

        (work / "src" / "app.py").write_text(
            "def a():\n    x = 10\n    y = 20\n    return x + y\n", encoding="utf-8"
        )
        self.git("add", "src/app.py", cwd=work)
        self.git("commit", "-m", "feat v1", cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/feat", cwd=work, token=self.alice)
        head_v1 = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.work = work
        self.base_oid = base_oid
        self.head_v1 = head_v1
        return {"work_repo_ready": True, "base_oid": base_oid, "head_v1": head_v1}

    def run_all(self):
        results = {}
        results["setup_fixtures"] = self.prepare_fixtures()
        results["subscriptions_and_notifications"] = self.exercise_subscriptions_and_notifications()
        results["labels_and_assignees"] = self.exercise_labels_and_assignees()
        results["inline_review_and_moderation"] = self.exercise_inline_review_and_moderation(
            self.work, self.base_oid, self.head_v1
        )
        results["search_and_rbac"] = self.exercise_search_and_rbac()
        results["web_ui_and_csrf"] = self.exercise_web_ui()
        results["backup_and_restore"] = self.exercise_backup_restore()
        return results

    def exercise_subscriptions_and_notifications(self):
        # Bob watches alice/demo; Carol watches repo then ignores Issue #1
        sub_b = json.loads(
            self.expect(
                "/api/repos/alice/demo/subscription",
                200,
                token=self.bob,
                method="PUT",
                body={"state": "subscribed"},
            )
        )
        assert sub_b["state"] == "subscribed" and sub_b["version"] == 1
        self.expect(
            "/api/repos/alice/demo/subscription",
            409,
            token=self.bob,
            method="PUT",
            body={"state": "ignored", "expected_version": 99},
        )
        self.expect(
            "/api/repos/alice/demo/subscription",
            200,
            token=self.carol,
            method="PUT",
            body={"state": "subscribed"},
        )

        # Alice opens Issue #1 and Issue #2 -> Bob & Carol get in-app notifications
        iss1 = json.loads(
            self.expect(
                "/api/repos/alice/demo/issues",
                201,
                token=self.alice,
                method="POST",
                body={"title": "Search latency needle", "body": "First issue"},
            )
        )
        self.expect(
            "/api/repos/alice/demo/issues/1/subscription",
            200,
            token=self.carol,
            method="PUT",
            body={"state": "ignored"},
        )
        iss2 = json.loads(
            self.expect(
                "/api/repos/alice/demo/issues",
                201,
                token=self.alice,
                method="POST",
                body={"title": "Pagination token needle", "body": "Second issue"},
            )
        )
        c1 = json.loads(
            self.expect(
                "/api/repos/alice/demo/issues/1/comments",
                201,
                token=self.alice,
                method="POST",
                body={"body": "Secret comment body for search and moderation"},
            )
        )
        assert iss1["number"] == 1 and iss2["number"] == 2 and c1["number"] == 1

        # Verify channel='in_app', 90-day retention metadata, Carol did NOT get issue #1 comment notif
        bob_notifs = json.loads(self.expect("/api/notifications", 200, token=self.bob))
        assert bob_notifs["channel"] == "in_app" and bob_notifs["retention_days"] == 90
        bob_events = [n["event_kind"] for n in bob_notifs["items"]]
        assert "issue_opened" in bob_events and "issue_commented" in bob_events
        carol_notifs = json.loads(self.expect("/api/notifications", 200, token=self.carol))
        assert not any(
            n["target_number"] == 1 and n["event_kind"] == "issue_commented"
            for n in carol_notifs["items"]
        )

        # Idempotent delivery key check on forge_notifications UNIQUE(recipient_id, delivery_key)
        sample_n = bob_notifs["items"][0]
        inserted_dup = self.query(
            self.db,
            f"INSERT INTO forge_notifications(tenant_id,repository_id,recipient_id,channel,target_type,target_number,event_kind,delivery_key,title,body_excerpt) "
            f"SELECT tenant_id,repository_id,recipient_id,channel,target_type,target_number,event_kind,delivery_key,title,body_excerpt "
            f"FROM forge_notifications WHERE id='{sample_n['id']}' ON CONFLICT (recipient_id, delivery_key) DO NOTHING",
        )
        assert inserted_dup == "" or "INSERT 0 0" in inserted_dup

        # Idempotent read ack: first already_read=false, second already_read=true
        ack1 = json.loads(
            self.expect(f"/api/notifications/{sample_n['id']}/read", 200, token=self.bob, method="POST")
        )
        ack2 = json.loads(
            self.expect(f"/api/notifications/{sample_n['id']}/read", 200, token=self.bob, method="POST")
        )
        assert ack1["already_read"] is False and ack2["already_read"] is True

        # Expired (>90d) notification is excluded from reads and removed by /api/notifications/prune
        self.query(
            self.db,
            f"INSERT INTO forge_notifications(tenant_id,repository_id,recipient_id,channel,target_type,target_number,event_kind,delivery_key,title,body_excerpt,expires_at) "
            f"SELECT tenant_id,repository_id,recipient_id,'in_app','issue',1,'issue_opened','expired-key-1','Old','Old',clock_timestamp()-INTERVAL '1 day' "
            f"FROM forge_notifications WHERE id='{sample_n['id']}'",
        )
        bob_after_exp = json.loads(self.expect("/api/notifications", 200, token=self.bob))
        assert all(n["delivery_key"] != "expired-key-1" for n in bob_after_exp["items"])
        pruned = json.loads(self.expect("/api/notifications/prune", 200, token=self.bob, method="POST"))
        assert pruned["pruned_count"] >= 1 and pruned["retention_days"] == 90
        return {"in_app_channel": True, "ignored_override": True, "idempotent_ack": True, "pruned_expired": True}

    def exercise_labels_and_assignees(self):
        # Create repo label with Idempotency-Key replay, rename cascade, attached label & assignee CAS
        hdrs = {"Idempotency-Key": "lbl-create-1"}
        lbl1 = json.loads(
            self.expect(
                "/api/repos/alice/demo/labels",
                201,
                token=self.alice,
                method="POST",
                body={"name": "bug", "color": "#D73A4A", "description": "Defect"},
                extra_headers=hdrs,
            )
        )
        lbl1_replay = json.loads(
            self.expect(
                "/api/repos/alice/demo/labels",
                201,
                token=self.alice,
                method="POST",
                body={"name": "bug", "color": "#D73A4A", "description": "Defect"},
                extra_headers=hdrs,
            )
        )
        assert lbl1["version"] == 1 and lbl1_replay == lbl1
        self.expect(
            "/api/repos/alice/demo/labels",
            201,
            token=self.alice,
            method="POST",
            body={"name": "triage", "color": "0e8a16"},
        )

        # Attach label to Issue #1, test 409 CAS, rename label -> cascades to attached issue label
        attached = json.loads(
            self.expect(
                "/api/repos/alice/demo/issues/1/labels",
                200,
                token=self.alice,
                method="PUT",
                body={"expected_version": 1, "labels": ["bug"]},
            )
        )
        assert attached["label_version"] == 2 and [x["name"] for x in attached["items"]] == ["bug"]
        self.expect(
            "/api/repos/alice/demo/issues/1/labels",
            409,
            token=self.alice,
            method="POST",
            body={"expected_version": 1, "labels": ["triage"]},
        )
        renamed = json.loads(
            self.expect(
                "/api/repos/alice/demo/labels/bug",
                200,
                token=self.alice,
                method="PATCH",
                body={"expected_version": 1, "name": "defect", "color": "b60205"},
            )
        )
        assert renamed["version"] == 2
        iss_labels = json.loads(self.expect("/api/repos/alice/demo/issues/1/labels", 200, token=self.alice))
        assert [x["name"] for x in iss_labels["items"]] == ["defect"]

        # Assignees: non-member dave rejected, collaborator bob succeeds, 409 CAS rejected
        code, _, _ = self.http(
            "/api/repos/alice/demo/issues/1/assignees",
            token=self.alice,
            method="PUT",
            body={"expected_version": 1, "assignees": ["dave"]},
        )
        assert code in (400, 403, 404, 422), f"expected non-member rejection, got {code}"
        asgn = json.loads(
            self.expect(
                "/api/repos/alice/demo/issues/1/assignees",
                200,
                token=self.alice,
                method="PUT",
                body={"expected_version": 1, "assignees": ["bob"]},
            )
        )
        assert asgn["assignee_version"] == 2 and [a["username"] for a in asgn["items"]] == ["bob"]
        self.expect(
            "/api/repos/alice/demo/issues/1/assignees",
            409,
            token=self.alice,
            method="POST",
            body={"expected_version": 1, "assignees": ["carol"]},
        )
        return {"cascade_rename": True, "optimistic_409": True, "non_member_assignee_rejected": True}

    def exercise_inline_review_and_moderation(self, work, base_oid, head_v1):
        # Create PR #1 on alice/demo (feat -> main)
        pr = json.loads(
            self.expect(
                "/api/repos/alice/demo/pulls",
                201,
                token=self.alice,
                method="POST",
                body={"title": "Searchable PR fix", "body": "PR needle", "head_ref": "feat", "base_ref": "main"},
            )
        )
        assert pr["number"] == 1 and pr["head_oid"] == head_v1

        # Create PR labels/assignees
        self.expect(
            "/api/repos/alice/demo/pulls/1/labels",
            200,
            token=self.alice,
            method="PUT",
            body={"expected_version": 1, "labels": ["triage"]},
        )
        self.expect(
            "/api/repos/alice/demo/pulls/1/assignees",
            200,
            token=self.alice,
            method="PUT",
            body={"expected_version": 1, "assignees": ["bob"]},
        )

        # Out-of-bounds line / non-diff file rejected with 400
        self.expect(
            "/api/repos/alice/demo/pulls/1/review-comments",
            400,
            token=self.bob,
            method="POST",
            body={"path": "src/app.py", "side": "right", "line": 99, "body": "too far"},
        )
        self.expect(
            "/api/repos/alice/demo/pulls/1/review-comments",
            400,
            token=self.bob,
            method="POST",
            body={"path": "README.md", "side": "right", "line": 1, "body": "not in diff"},
        )

        # Valid inline review comment + review + reply
        rc1 = json.loads(
            self.expect(
                "/api/repos/alice/demo/pulls/1/review-comments",
                201,
                token=self.bob,
                method="POST",
                body={"path": "src/app.py", "side": "right", "line": 2, "body": "Inline v1 comment"},
            )
        )
        assert rc1["outdated"] is False and rc1["commit_oid"] == head_v1 and rc1["base_oid"] == base_oid
        self.expect(
            "/api/repos/alice/demo/pulls/1/review-comments",
            400,
            token=self.carol,
            method="POST",
            body={"path": "src/app.py", "side": "right", "line": 3, "body": "wrong line", "in_reply_to_number": rc1["number"]},
        )
        rc2 = json.loads(
            self.expect(
                "/api/repos/alice/demo/pulls/1/review-comments",
                201,
                token=self.carol,
                method="POST",
                body={"path": "src/app.py", "side": "right", "line": 2, "body": "Reply matches anchor", "in_reply_to_number": rc1["number"]},
            )
        )
        assert rc2["in_reply_to_number"] == rc1["number"]

        rev1 = json.loads(
            self.expect(
                "/api/repos/alice/demo/pulls/1/reviews",
                201,
                token=self.bob,
                method="POST",
                body={"state": "approved", "commit_oid": head_v1, "body": "LGTM v1"},
            )
        )
        assert rev1["outdated"] is False

        # Advance feat branch to v2 and synchronize PR -> v1 review & v1 line comment become outdated=true!
        (work / "src" / "app.py").write_text(
            "def a():\n    x = 11\n    y = 22\n    return x + y\n", encoding="utf-8"
        )
        self.git("add", "src/app.py", cwd=work)
        self.git("commit", "-m", "feat v2", cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/feat", cwd=work, token=self.alice)
        head_v2 = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()

        self.expect(
            "/api/repos/alice/demo/pulls/1",
            200,
            token=self.alice,
            method="PATCH",
            body={"expected_version": pr["version"], "head_oid": head_v2},
        )
        revs = json.loads(self.expect("/api/repos/alice/demo/pulls/1/reviews", 200, token=self.alice))
        assert any(r["number"] == rev1["number"] and r["outdated"] is True for r in revs["items"])
        rcs_outdated = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/review-comments?outdated=true", 200, token=self.alice)
        )
        assert any(c["number"] == rc1["number"] and c["commit_oid"] == head_v1 and c["outdated"] is True for c in rcs_outdated["items"])

        # Edit, Hide, Unhide, Soft-Delete + Revision History & Audit Log on Issue comment & PR review comment
        c_edit = json.loads(
            self.expect(
                "/api/repos/alice/demo/issues/1/comments/1",
                200,
                token=self.alice,
                method="PATCH",
                body={"expected_version": 1, "body": "Edited comment searchneedle"},
            )
        )
        assert c_edit["version"] == 2 and c_edit["edited_at"] is not None

        # Carol (triage) cannot moderate (403); Bob (maintain) can hide & unhide preserving body
        self.expect(
            "/api/repos/alice/demo/issues/1/comments/1/moderate",
            403,
            token=self.carol,
            method="POST",
            body={"expected_version": 2, "action": "hide", "reason": "nope"},
        )
        c_hidden = json.loads(
            self.expect(
                "/api/repos/alice/demo/issues/1/comments/1/moderate",
                200,
                token=self.bob,
                method="POST",
                body={"expected_version": 2, "action": "hide", "reason": "spam"},
            )
        )
        assert c_hidden["body"] == "[hidden by moderator]" and c_hidden["moderation_state"] == "hidden"

        # Hidden comment is excluded from search!
        hidden_hits = json.loads(
            self.expect("/api/search?q=searchneedle&scope=comments", 200, token=self.alice)
        )
        assert not hidden_hits["items"]

        c_unhidden = json.loads(
            self.expect(
                "/api/repos/alice/demo/issues/1/comments/1/moderate",
                200,
                token=self.bob,
                method="POST",
                body={"expected_version": 3, "action": "unhide", "reason": "cleared"},
            )
        )
        assert c_unhidden["body"] == "Edited comment searchneedle" and c_unhidden["moderation_state"] == "visible"

        # Now moderate -> delete (soft-delete) inline review comment rc2, check revisions & audit log
        rc2_del = json.loads(
            self.expect(
                f"/api/repos/alice/demo/pulls/1/review-comments/{rc2['number']}?expected_version={rc2['version']}",
                200,
                token=self.bob,
                method="DELETE",
            )
        )
        assert rc2_del["moderation_state"] == "deleted" and rc2_del["body"] == "[deleted]"
        # Re-editing a deleted review comment must return 409 Conflict
        self.expect(
            f"/api/repos/alice/demo/pulls/1/review-comments/{rc2['number']}",
            409,
            token=self.bob,
            method="PATCH",
            body={"expected_version": rc2_del["version"], "body": "resurrect"},
        )
        revs_c = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/comments/1/revisions", 200, token=self.bob)
        )
        assert [r["action"] for r in revs_c["items"]] == ["edited", "hidden", "unhidden"]
        audit_cnt = int(
            self.query(
                self.db,
                "SELECT count(*) FROM repository_audit_log WHERE action LIKE 'pull_review_comment.%' OR action LIKE 'issue_comment.%'",
            )
        )
        assert audit_cnt >= 4

        # An invalid anchor under a key must repeat the same 400. The read-only
        # first phase must not leave a committed placeholder that poisons retry.
        invalid_key = "review-comment-invalid-anchor"
        invalid_anchor = {"path": "README.md", "side": "right", "line": 1, "body": "outside diff"}
        for _ in range(2):
            status, body, _ = self.http(
                "/api/repos/alice/demo/pulls/1/review-comments",
                token=self.bob,
                method="POST",
                body=invalid_anchor,
                extra_headers={"Idempotency-Key": invalid_key},
            )
            assert status == 400, (status, body[:300])
        assert self.sql(
            f"SELECT count(*) FROM forge_creation_requests WHERE idempotency_key='{invalid_key}'"
        ) == "0"

        # A transient final-transaction failure after anchor validation must roll
        # back the key, allocation and resource together. The identical retry
        # (same digest) then creates once and replays the saved response.
        fault_key = "review-comment-final-phase-fault"
        fault_body = "final phase fault"
        pull_counter_sql = (
            "SELECT next_review_comment_number FROM forge_pulls "
            f"WHERE repository_id='{self.demo['id']}' AND number=1"
        )
        before_fault = int(self.sql(pull_counter_sql))
        self.sql(
            "ALTER TABLE forge_pull_review_comments ADD CONSTRAINT fixture_review_comment_final_phase "
            f"CHECK (body <> '{fault_body}')"
        )
        try:
            status, body, _ = self.http(
                "/api/repos/alice/demo/pulls/1/review-comments",
                token=self.bob,
                method="POST",
                body={"path": "src/app.py", "side": "right", "line": 2, "body": fault_body},
                extra_headers={"Idempotency-Key": fault_key},
            )
            assert status == 503, (status, body[:300])
        finally:
            self.sql("ALTER TABLE forge_pull_review_comments DROP CONSTRAINT fixture_review_comment_final_phase")
        assert self.sql(
            f"SELECT count(*) FROM forge_creation_requests WHERE idempotency_key='{fault_key}'"
        ) == "0"
        assert int(self.sql(pull_counter_sql)) == before_fault
        fault_payload = {"path": "src/app.py", "side": "right", "line": 2, "body": fault_body}
        retried = json.loads(
            self.expect(
                "/api/repos/alice/demo/pulls/1/review-comments",
                201,
                token=self.bob,
                method="POST",
                body=fault_payload,
                extra_headers={"Idempotency-Key": fault_key},
            )
        )
        assert retried["number"] == before_fault and retried["body"] == fault_body
        replayed = json.loads(
            self.expect(
                "/api/repos/alice/demo/pulls/1/review-comments",
                201,
                token=self.bob,
                method="POST",
                body=fault_payload,
                extra_headers={"Idempotency-Key": fault_key},
            )
        )
        assert replayed == retried
        assert int(self.sql(pull_counter_sql)) == before_fault + 1

        # Concurrent identical keyed requests start from a real barrier and must
        # allocate exactly one comment/counter slot while all return that result.
        concurrent_key = "review-comment-concurrent-identical"
        concurrent_body = "concurrent identical comment"
        concurrent_payload = {"path": "src/app.py", "side": "right", "line": 2, "body": concurrent_body}
        before_concurrent = int(self.sql(pull_counter_sql))
        barrier = threading.Barrier(4)

        def create_concurrent(_):
            barrier.wait(timeout=20)
            return self.http(
                "/api/repos/alice/demo/pulls/1/review-comments",
                token=self.bob,
                method="POST",
                body=concurrent_payload,
                extra_headers={"Idempotency-Key": concurrent_key},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(create_concurrent, range(4)))
        assert all(status == 201 for status, _, _ in results), [status for status, _, _ in results]
        created = [json.loads(body) for _, body, _ in results]
        assert all(item == created[0] for item in created)
        assert created[0]["body"] == concurrent_body and created[0]["number"] == before_concurrent
        status, body, _ = self.http(
            "/api/repos/alice/demo/pulls/1/review-comments",
            token=self.bob,
            method="POST",
            body={**concurrent_payload, "body": concurrent_body + " changed"},
            extra_headers={"Idempotency-Key": concurrent_key},
        )
        assert status == 409, (status, body[:300])
        assert int(self.sql(pull_counter_sql)) == before_concurrent + 1
        assert self.sql(
            f"SELECT count(*) FROM forge_creation_requests WHERE idempotency_key='{concurrent_key}'"
        ) == "1"
        assert self.sql(
            "SELECT count(*) FROM forge_pull_review_comments "
            f"WHERE repository_id='{self.demo['id']}' AND pull_number=1 AND body='{concurrent_body}'"
        ) == "1"
        return {"outdated_detected": True, "hide_unhide_roundtrip": True, "soft_delete_and_audit": True}

    def exercise_search_and_rbac(self):
        # Create issue on org repo collab-org/team-repo so Bob sees both repos, Carol sees only alice/demo
        self.expect(
            "/api/repos/collab-org/team-repo/issues",
            201,
            token=self.alice,
            method="POST",
            body={"title": "Org repo needle", "body": "org body"},
        )
        # Global search with limit=1 exercises deterministic cursor pagination across pages
        p1 = json.loads(self.expect("/api/search?q=needle&scope=all&sort=number&limit=1", 200, token=self.bob))
        assert len(p1["items"]) == 1 and p1["next_cursor"]
        cur = urllib.parse.quote(p1["next_cursor"], safe="")
        p2 = json.loads(self.expect(f"/api/search?q=needle&scope=all&sort=number&limit=1&cursor={cur}", 200, token=self.bob))
        assert len(p2["items"]) == 1 and (p1["items"][0]["number"], p1["items"][0]["repository_id"]) != (p2["items"][0]["number"], p2["items"][0]["repository_id"])
        # Cross-scope cursor tampered -> 400
        self.expect(f"/api/search?q=needle&scope=issues&sort=number&limit=1&cursor={cur}", 400, token=self.bob)

        # Restricted PAT on Bob granting ONLY issues_read on alice/demo hides pulls and team-repo
        pat = json.loads(
            self.expect(
                "/api/tokens",
                201,
                token=self.bob,
                method="POST",
                body={
                    "display_name": "issues-only",
                    "expires_in_days": 1,
                    "read_only": True,
                    "repository_grants": [{"repository_id": self.demo["id"], "actions": ["issues_read"]}],
                    "namespace_grants": [],
                },
            )
        )
        self.secrets.append(pat["secret"])
        bob_pat = {"username": "bob", "token": pat["secret"]}
        pat_hits = json.loads(self.expect("/api/search?q=needle&scope=all", 200, token=bob_pat))
        assert pat_hits["items"] and all(
            h["kind"] in ("issue", "issue_comment") and h["repository_id"] == self.demo["id"]
            for h in pat_hits["items"]
        )

        # A restricted parent PAT can sign in a browser child; live parent grants
        # must drive both the search result filter and the notification inbox.
        browser_pat = json.loads(
            self.expect(
                "/api/tokens",
                201,
                token=self.bob,
                method="POST",
                body={
                    "display_name": "browser-scope-inheritance",
                    "expires_in_days": 1,
                    "read_only": True,
                    "repository_grants": [
                        {
                            "repository_id": self.demo["id"],
                            "actions": ["repo_read", "issues_read", "pulls_read"],
                        }
                    ],
                    "namespace_grants": [],
                },
            )
        )
        self.secrets.append(browser_pat["secret"])
        browser_cookies, _, _ = self.sign_in(username="bob", token=browser_pat["secret"])
        browser_headers = {"Cookie": self.cookie_header(browser_cookies)}
        status, page, _ = self.request("/web/search?q=needle&scope=all", headers=browser_headers)
        assert status == 200
        assert b'data-hit-count="0"' not in page
        assert b'data-hit-kind="issue"' in page and b'data-hit-kind="pull"' in page
        assert b'data-hit-owner="alice"' in page and b'data-hit-owner="collab-org"' not in page
        status, page, _ = self.request("/web/notifications", headers=browser_headers)
        assert status == 200
        assert b'data-notification-count="0"' not in page
        assert b"/issues/" in page and b"/pulls/1" in page
        narrowed = json.loads(
            self.expect(
                f"/api/tokens/{browser_pat['id']}",
                200,
                token=self.bob,
                method="PATCH",
                body={
                    "expected_scope_version": browser_pat["scope_version"],
                    "repository_grants": [],
                    "namespace_grants": [],
                },
            )
        )
        assert narrowed["scope_version"] == browser_pat["scope_version"] + 1
        assert narrowed["repository_grants"] == [] and narrowed["namespace_grants"] == []
        status, page, _ = self.request("/web/search?q=needle&scope=all", headers=browser_headers)
        assert status == 200 and b'data-hit-count="0"' in page
        status, page, _ = self.request("/web/notifications", headers=browser_headers)
        assert status == 200 and b'data-notification-count="0"' in page
        status, _, _ = self.request("/web/repos/alice/demo/search?q=needle", headers=browser_headers)
        assert status == 403, status

        # Live permission revocation immediately hides search hits AND notifications for Carol
        before_carol = json.loads(self.expect("/api/search?q=needle&scope=all", 200, token=self.carol))
        assert before_carol["items"]
        self.expect("/api/repos/alice/demo/collaborators/carol", 200, token=self.alice, method="DELETE")
        after_carol = json.loads(self.expect("/api/search?q=needle&scope=all", 200, token=self.carol))
        assert not after_carol["items"]
        carol_notifs_after = json.loads(self.expect("/api/notifications", 200, token=self.carol))
        assert not carol_notifs_after["items"]
        return {"deterministic_pagination": True, "restricted_pat": True, "immediate_revocation": True}

    def exercise_web_ui(self):
        cookies, _, _ = self.sign_in(username="alice", token=self.alice["token"])
        get_hdrs = {"Cookie": self.cookie_header(cookies)}
        post_hdrs = {
            "Cookie": self.cookie_header(cookies),
            "Origin": self.base,
            "Content-Type": "application/json",
            "X-CSRF-Token": cookies["rootyard_csrf"],
        }
        for path in (
            "/web/search?q=needle",
            "/ui/search?q=needle",
            "/web/notifications",
            "/ui/notifications",
            "/web/repos/alice/demo/labels",
            "/ui/repos/alice/demo/labels",
            "/web/repos/alice/demo/pulls/1",
        ):
            st, body, hdrs = self.request(path, headers=get_hdrs)
            assert st == 200, f"GET {path} -> {st}"
            hmap = {k.lower(): v for k, v in hdrs}
            assert "content-security-policy" in hmap and hmap["x-frame-options"] == "DENY"
            assert hmap["x-content-type-options"] == "nosniff"
            if path.endswith("/pulls/1"):
                text = body.decode("utf-8")
                assert 'data-outdated-reviews="1"' in text and 'data-rc-outdated="true"' in text
                assert "[deleted]" in text

        # CSRF-protected FormData-style JSON mutation under /web/
        st, _, _ = self.request(
            "/web/repos/alice/demo/pulls/1/subscription",
            method="POST",
            body=json.dumps({"action": "subscribe", "expected_version": ""}),
            headers=post_hdrs,
        )
        assert st == 200, f"web subscription failed: {st}"
        return {"web_and_ui_parity": True, "security_headers": True, "csrf_mutations": True}

    def exercise_backup_restore(self):
        def search_identity(payload):
            return tuple(sorted(
                (item["kind"], item["repository_id"], int(item["number"]))
                for item in payload["items"]
            ))

        def label_state(payload):
            return (
                int(payload["label_version"]),
                tuple(sorted((item["name"], int(item["version"])) for item in payload["items"])),
            )

        def assignee_state(payload):
            return (
                int(payload["assignee_version"]),
                tuple(sorted(item["username"] for item in payload["items"])),
            )

        def subscription_identity(payload):
            sub = payload.get("subscription")
            if sub is None:
                return (payload.get("subscribed") is True, None)
            return (
                payload.get("subscribed") is True,
                (sub.get("state"), int(sub.get("version"))),
            )

        def notification_identity(payload):
            return tuple(sorted(
                (item["id"], item["event_kind"], int(item["target_number"]))
                for item in payload["items"]
            ))

        def outdated_identity(payload):
            return tuple(sorted(
                (int(item["number"]), item["commit_oid"], item["base_oid"])
                for item in payload["items"]
                if item.get("body") == "Inline v1 comment" and item.get("outdated") is True
            ))

        def review_identity(payload):
            return tuple(sorted(
                (int(item["number"]), str(item.get("commit_oid") or ""), bool(item.get("outdated")))
                for item in payload["items"]
            ))

        # Real API-seeded restricted credentials. These are restored rows, not
        # direct SQL users/authority, and their secrets remain in RAM only.
        issues_token = json.loads(
            self.expect(
                "/api/tokens",
                201,
                token=self.bob,
                method="POST",
                body={
                    "display_name": "restore-issues-only",
                    "expires_in_days": 1,
                    "read_only": True,
                    "repository_grants": [{
                        "repository_id": self.demo["id"],
                        "actions": ["issues_read"],
                    }],
                    "namespace_grants": [],
                },
            )
        )
        self.secrets.append(issues_token["secret"])
        issues_auth = {"username": "bob", "token": issues_token["secret"]}

        browser_token = json.loads(
            self.expect(
                "/api/tokens",
                201,
                token=self.bob,
                method="POST",
                body={
                    "display_name": "restore-browser-scope",
                    "expires_in_days": 1,
                    "read_only": True,
                    "repository_grants": [{
                        "repository_id": self.demo["id"],
                        "actions": ["repo_read", "issues_read", "pulls_read"],
                    }],
                    "namespace_grants": [],
                },
            )
        )
        self.secrets.append(browser_token["secret"])

        bob_search_pre = json.loads(
            self.expect("/api/search?q=needle&scope=all&limit=100", 200, token=self.bob)
        )
        carol_search_pre = json.loads(
            self.expect("/api/search?q=needle&scope=all", 200, token=self.carol)
        )
        issues_search_pre = json.loads(
            self.expect("/api/search?q=needle&scope=all", 200, token=issues_auth)
        )
        assert bob_search_pre["items"], "pre-backup search was empty"
        assert any(item["repository_id"] == self.demo["id"] for item in bob_search_pre["items"])
        assert any(item["repository_id"] == self.team_repo["id"] for item in bob_search_pre["items"])
        assert carol_search_pre["items"] == [], "revoked collaborator still had search hits before backup"
        assert issues_search_pre["items"], "restricted issues-only token had no issue/comment hits"
        assert all(
            item["kind"] in ("issue", "issue_comment")
            and item["repository_id"] == self.demo["id"]
            for item in issues_search_pre["items"]
        )
        bob_search_pre_identity = search_identity(bob_search_pre)
        issues_search_pre_identity = search_identity(issues_search_pre)

        issue_labels_pre = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/labels", 200, token=self.alice)
        )
        pr_labels_pre = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/labels", 200, token=self.alice)
        )
        issue_assignees_pre = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/assignees", 200, token=self.alice)
        )
        pr_assignees_pre = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/assignees", 200, token=self.alice)
        )
        repo_labels_pre = json.loads(
            self.expect("/api/repos/alice/demo/labels?limit=100", 200, token=self.alice)
        )
        issue_labels_pre_state = label_state(issue_labels_pre)
        pr_labels_pre_state = label_state(pr_labels_pre)
        issue_assignees_pre_state = assignee_state(issue_assignees_pre)
        pr_assignees_pre_state = assignee_state(pr_assignees_pre)
        assert issue_labels_pre_state[0] >= 2
        assert issue_labels_pre_state[1] == (("defect", 2),), issue_labels_pre_state
        assert pr_labels_pre_state[0] >= 2
        assert pr_labels_pre_state[1] == (("triage", 1),), pr_labels_pre_state
        assert issue_assignees_pre_state[0] >= 2
        assert issue_assignees_pre_state[1] == ("bob",), issue_assignees_pre_state
        assert pr_assignees_pre_state[0] >= 2
        assert pr_assignees_pre_state[1] == ("bob",), pr_assignees_pre_state
        pre_repo_label_names = {item["name"] for item in repo_labels_pre["items"]}
        assert {"defect", "triage"} <= pre_repo_label_names

        bob_sub_pre = json.loads(
            self.expect("/api/repos/alice/demo/subscription", 200, token=self.bob)
        )
        carol_issue_sub_pre = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/subscription", 200, token=self.carol)
        )
        alice_pr_sub_pre = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/subscription", 200, token=self.alice)
        )
        bob_sub_pre_identity = subscription_identity(bob_sub_pre)
        carol_issue_sub_pre_identity = subscription_identity(carol_issue_sub_pre)
        alice_pr_sub_pre_identity = subscription_identity(alice_pr_sub_pre)
        assert bob_sub_pre_identity[0] is True and bob_sub_pre_identity[1][0] == "subscribed"
        assert carol_issue_sub_pre_identity[0] is False
        assert carol_issue_sub_pre_identity[1][0] == "ignored"
        assert alice_pr_sub_pre_identity[0] is True
        assert alice_pr_sub_pre_identity[1][0] == "subscribed"

        bob_notifications_pre = json.loads(
            self.expect("/api/notifications?limit=100", 200, token=self.bob)
        )
        carol_notifications_pre = json.loads(
            self.expect("/api/notifications?limit=100", 200, token=self.carol)
        )
        assert bob_notifications_pre["channel"] == "in_app"
        assert bob_notifications_pre["retention_days"] == 90
        assert bob_notifications_pre["items"], "pre-backup notification inbox was empty"
        assert carol_notifications_pre["items"] == [], "revoked collaborator had notifications before backup"
        bob_notification_pre_identity = notification_identity(bob_notifications_pre)
        unread_notification = next(
            (item for item in bob_notifications_pre["items"] if item.get("unread") is True),
            None,
        )
        assert unread_notification is not None, "pre-backup notification inbox had no unread item"
        unread_notification_id = unread_notification["id"]
        dedupe_notification_id = bob_notifications_pre["items"][0]["id"]
        assert bob_notifications_pre["items"][0]["delivery_key"]

        review_comments_pre = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/review-comments?limit=100", 200, token=self.alice)
        )
        reviews_pre = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/reviews", 200, token=self.alice)
        )
        issue_comment_pre = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/comments/1", 200, token=self.bob)
        )
        revisions_pre = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/comments/1/revisions", 200, token=self.bob)
        )
        outdated_pre_identity = outdated_identity(review_comments_pre)
        reviews_pre_identity = review_identity(reviews_pre)
        revision_actions_pre = tuple(item["action"] for item in revisions_pre["items"])
        assert outdated_pre_identity, "pre-backup inline review was not outdated"
        assert reviews_pre_identity and any(item[2] is True for item in reviews_pre_identity)
        assert any(
            item.get("body") == "[deleted]" and item.get("moderation_state") == "deleted"
            for item in review_comments_pre["items"]
        ), "pre-backup soft-deleted review comment missing"
        assert issue_comment_pre["body"] == "Edited comment searchneedle"
        assert issue_comment_pre["moderation_state"] == "visible"
        assert issue_comment_pre["version"] >= 4
        assert revision_actions_pre == ("edited", "hidden", "unhidden")

        self.stop()
        self.backup_command()
        self.restore_command()
        for tbl in (
            "forge_labels",
            "forge_issue_labels",
            "forge_pull_labels",
            "forge_issue_assignees",
            "forge_pull_assignees",
            "forge_pull_review_comments",
            "forge_comment_revisions",
            "forge_subscriptions",
            "forge_notifications",
        ):
            cnt = int(self.query(self.target_db, f"SELECT count(*) FROM {tbl}"))
            assert cnt >= 1, f"restored table {tbl} empty"

        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        self.db = self.target_db
        self.start()

        # Preserved legacy post-restore checks.
        rcs = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/review-comments?outdated=true", 200, token=self.alice)
        )
        assert rcs["items"] and rcs["items"][0]["outdated"] is True
        post_lbl = json.loads(
            self.expect(
                "/api/repos/alice/demo/labels",
                201,
                token=self.alice,
                method="POST",
                body={"name": "post-restore", "color": "5319e7"},
            )
        )
        assert post_lbl["name"] == "post-restore"

        bob_search_post = json.loads(
            self.expect("/api/search?q=needle&scope=all&limit=100", 200, token=self.bob)
        )
        carol_search_post = json.loads(
            self.expect("/api/search?q=needle&scope=all", 200, token=self.carol)
        )
        issues_search_post = json.loads(
            self.expect("/api/search?q=needle&scope=all", 200, token=issues_auth)
        )
        assert bob_search_post["items"]
        assert search_identity(bob_search_post) == bob_search_pre_identity
        assert carol_search_post["items"] == []
        assert issues_search_post["items"]
        assert search_identity(issues_search_post) == issues_search_pre_identity
        assert all(
            item["kind"] in ("issue", "issue_comment")
            and item["repository_id"] == self.demo["id"]
            for item in issues_search_post["items"]
        )

        issue_labels_post = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/labels", 200, token=self.alice)
        )
        pr_labels_post = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/labels", 200, token=self.alice)
        )
        issue_assignees_post = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/assignees", 200, token=self.alice)
        )
        pr_assignees_post = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/assignees", 200, token=self.alice)
        )
        repo_labels_post = json.loads(
            self.expect("/api/repos/alice/demo/labels?limit=100", 200, token=self.alice)
        )
        assert label_state(issue_labels_post) == issue_labels_pre_state
        assert label_state(pr_labels_post) == pr_labels_pre_state
        assert assignee_state(issue_assignees_post) == issue_assignees_pre_state
        assert assignee_state(pr_assignees_post) == pr_assignees_pre_state
        post_repo_label_names = {item["name"] for item in repo_labels_post["items"]}
        assert {"defect", "triage", "post-restore"} <= post_repo_label_names
        self.expect(
            "/api/repos/alice/demo/issues/1/labels",
            409,
            token=self.alice,
            method="POST",
            body={
                "expected_version": max(0, issue_labels_pre_state[0] - 1),
                "labels": ["triage"],
            },
        )
        self.expect(
            "/api/repos/alice/demo/issues/1/assignees",
            409,
            token=self.alice,
            method="POST",
            body={
                "expected_version": max(0, issue_assignees_pre_state[0] - 1),
                "assignees": ["carol"],
            },
        )
        assert label_state(
            json.loads(self.expect("/api/repos/alice/demo/issues/1/labels", 200, token=self.alice))
        ) == issue_labels_pre_state
        assert assignee_state(
            json.loads(self.expect("/api/repos/alice/demo/issues/1/assignees", 200, token=self.alice))
        ) == issue_assignees_pre_state

        bob_sub_post = json.loads(
            self.expect("/api/repos/alice/demo/subscription", 200, token=self.bob)
        )
        carol_issue_sub_post = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/subscription", 200, token=self.carol)
        )
        alice_pr_sub_post = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/subscription", 200, token=self.alice)
        )
        assert subscription_identity(bob_sub_post) == bob_sub_pre_identity
        assert subscription_identity(carol_issue_sub_post) == carol_issue_sub_pre_identity
        assert subscription_identity(alice_pr_sub_post) == alice_pr_sub_pre_identity
        self.expect(
            "/api/repos/alice/demo/subscription",
            409,
            token=self.bob,
            method="PUT",
            body={
                "state": "ignored",
                "expected_version": max(0, bob_sub_pre_identity[1][1] - 1),
            },
        )
        assert subscription_identity(
            json.loads(self.expect("/api/repos/alice/demo/subscription", 200, token=self.bob))
        ) == bob_sub_pre_identity

        bob_notifications_post = json.loads(
            self.expect("/api/notifications?limit=100", 200, token=self.bob)
        )
        carol_notifications_post = json.loads(
            self.expect("/api/notifications?limit=100", 200, token=self.carol)
        )
        assert bob_notifications_post["channel"] == "in_app"
        assert bob_notifications_post["retention_days"] == 90
        assert notification_identity(bob_notifications_post) == bob_notification_pre_identity
        assert carol_notifications_post["items"] == []
        ack1 = json.loads(
            self.expect(f"/api/notifications/{unread_notification_id}/read", 200, token=self.bob, method="POST")
        )
        ack2 = json.loads(
            self.expect(f"/api/notifications/{unread_notification_id}/read", 200, token=self.bob, method="POST")
        )
        assert ack1["already_read"] is False and ack2["already_read"] is True
        notification_count_before = int(self.query(
            self.target_db,
            f"SELECT count(*) FROM forge_notifications WHERE recipient_id='{self.bob['user_id']}'",
        ))
        inserted_dup = self.query(
            self.target_db,
            "INSERT INTO forge_notifications(tenant_id,repository_id,recipient_id,channel,target_type,target_number,event_kind,delivery_key,title,body_excerpt) "
            "SELECT tenant_id,repository_id,recipient_id,channel,target_type,target_number,event_kind,delivery_key,title,body_excerpt "
            f"FROM forge_notifications WHERE id='{dedupe_notification_id}' ON CONFLICT (recipient_id, delivery_key) DO NOTHING",
        )
        notification_count_after = int(self.query(
            self.target_db,
            f"SELECT count(*) FROM forge_notifications WHERE recipient_id='{self.bob['user_id']}'",
        ))
        assert inserted_dup == "" or "INSERT 0 0" in inserted_dup
        assert notification_count_before == notification_count_after

        review_comments_post = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/review-comments?limit=100", 200, token=self.alice)
        )
        reviews_post = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/reviews", 200, token=self.alice)
        )
        issue_comment_post = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/comments/1", 200, token=self.bob)
        )
        revisions_post = json.loads(
            self.expect("/api/repos/alice/demo/issues/1/comments/1/revisions", 200, token=self.bob)
        )
        assert outdated_identity(review_comments_post) == outdated_pre_identity
        assert review_identity(reviews_post) == reviews_pre_identity
        assert any(
            item.get("body") == "[deleted]" and item.get("moderation_state") == "deleted"
            for item in review_comments_post["items"]
        )
        assert issue_comment_post["body"] == issue_comment_pre["body"]
        assert issue_comment_post["moderation_state"] == issue_comment_pre["moderation_state"]
        assert issue_comment_post["version"] == issue_comment_pre["version"]
        assert tuple(item["action"] for item in revisions_post["items"]) == revision_actions_pre

        alice_cookies, _, _ = self.sign_in(username="alice", token=self.alice["token"])
        alice_headers = {"Cookie": self.cookie_header(alice_cookies)}
        for path in (
            "/web/search?q=needle",
            "/ui/search?q=needle",
            "/web/notifications",
            "/ui/notifications",
            "/web/repos/alice/demo/labels",
            "/ui/repos/alice/demo/labels",
            "/web/repos/alice/demo/pulls/1",
        ):
            status, page, headers = self.request(path, headers=alice_headers)
            assert status == 200, f"post-restore GET {path} -> {status}"
            header_map = {key.lower(): value for key, value in headers}
            assert "content-security-policy" in header_map
            assert header_map["x-frame-options"] == "DENY"
            assert header_map["x-content-type-options"] == "nosniff"
            if path.endswith("search?q=needle"):
                assert b'data-hit-count="0"' not in page
                assert b'data-hit-kind="issue"' in page
            if path.endswith("/pulls/1"):
                assert b'data-outdated-reviews="1"' in page
                assert b'data-rc-outdated="true"' in page
                assert b"[deleted]" in page

        bob_cookies, _, _ = self.sign_in(username="bob", token=browser_token["secret"])
        bob_headers = {"Cookie": self.cookie_header(bob_cookies)}
        status, page, _ = self.request("/web/search?q=needle&scope=all", headers=bob_headers)
        assert status == 200
        assert b'data-hit-count="0"' not in page
        assert b'data-hit-kind="issue"' in page and b'data-hit-kind="pull"' in page
        assert b'data-hit-owner="alice"' in page and b'data-hit-owner="collab-org"' not in page
        status, page, _ = self.request("/web/notifications", headers=bob_headers)
        assert status == 200
        assert b'data-notification-count="0"' not in page
        assert b"/issues/" in page or b"/pulls/" in page
        assert self.request("/web/repos/alice/demo/search?q=needle", headers=bob_headers)[0] == 200
        assert self.request("/web/repos/collab-org/team-repo/search?q=needle", headers=bob_headers)[0] == 403

        pr_sub_current = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/subscription", 200, token=self.alice)
        )
        current_sub = pr_sub_current.get("subscription")
        expected_version = "" if current_sub is None else str(current_sub["version"])
        post_headers = {
            "Cookie": self.cookie_header(alice_cookies),
            "Origin": self.base,
            "Content-Type": "application/json",
            "X-CSRF-Token": alice_cookies["rootyard_csrf"],
        }
        status, _, _ = self.request(
            "/web/repos/alice/demo/pulls/1/subscription",
            method="POST",
            body=json.dumps({"action": "subscribe", "expected_version": expected_version}),
            headers=post_headers,
        )
        assert status == 200
        pr_sub_after = json.loads(
            self.expect("/api/repos/alice/demo/pulls/1/subscription", 200, token=self.alice)
        )
        assert pr_sub_after["subscribed"] is True and pr_sub_after["subscription"]["state"] == "subscribed"

        self.stop()
        return {
            "all_9_tables_restored": True,
            "post_restore_writes": True,
            "restored_search_hits": len(bob_search_post["items"]),
            "restored_notification_count": len(bob_notifications_post["items"]),
            "search_restored": True,
            "auth_filter_restored": True,
            "labels_assignees_restored": True,
            "subscriptions_restored": True,
            "notifications_restored": True,
            "inline_moderation_restored": True,
            "web_ui_restored": True,
        }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", "--json-report", dest="report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    for exe in ("git", "psql", "pg_dump", "pg_restore", args.binary):
        if not shutil.which(exe):
            parser.error("Required executable not found: " + exe)
    harness = ForgeCollaborationHarness(args)
    passed = False
    try:
        for name, fn in [
            ("setup_fixtures", harness.prepare_fixtures),
            ("subscriptions_and_notifications", harness.exercise_subscriptions_and_notifications),
            ("labels_and_assignees", harness.exercise_labels_and_assignees),
            (
                "inline_review_and_moderation",
                lambda: harness.exercise_inline_review_and_moderation(
                    harness.work, harness.base_oid, harness.head_v1
                ),
            ),
            ("search_and_rbac", harness.exercise_search_and_rbac),
            ("web_ui_and_csrf", harness.exercise_web_ui),
            ("backup_and_restore", harness.exercise_backup_restore),
        ]:
            harness.case(name, fn)
        passed = True
    except Exception:
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as exc:
            harness.results.append(dict(name="cleanup", status="failed", error=harness.redact(exc)))
            passed = False
        report = {
            "passed": passed,
            "cases": harness.results,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
