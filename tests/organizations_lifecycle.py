#!/usr/bin/env python3
"""End-to-end acceptance suite for Issue #46 organization namespaces, teams,
cross-surface RBAC, revocation, restart, and offline PostgreSQL backup/restore."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import urllib.parse

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from backup import BackupHarness  # noqa: E402
from web_sessions import BrowserHarness  # noqa: E402

LFS_MIME = "application/vnd.git-lfs+json"


class OrganizationLifecycleHarness(BackupHarness, BrowserHarness):
    def doc(self, path, code, token=None, **kwargs):
        return json.loads(self.expect(path, code, token=token or self.alice, **kwargs))

    def collect_pages(self, base_path, limit, token=None):
        items = []
        cursor = None
        seen_cursors = set()
        pages = 0
        while True:
            query = f"limit={limit}" + (f"&cursor={urllib.parse.quote(cursor, safe='')}" if cursor else "")
            status, body, headers = self.http(f"{base_path}?{query}", token=token or self.alice)
            assert status == 200, (base_path, status, body[:200])
            page = json.loads(body)
            pages += 1
            items.extend(page["items"])
            next_cursor = page["next_cursor"]
            header_cursor = self.response_header(headers, "x-next-cursor")
            if next_cursor is None:
                assert not page["truncated"], page
                assert header_cursor is None, header_cursor
                break
            assert page["truncated"], page
            assert header_cursor == next_cursor, (header_cursor, next_cursor)
            link = self.response_header(headers, "link") or ""
            assert 'rel="next"' in link and urllib.parse.quote(next_cursor, safe="") in link, link
            assert next_cursor not in seen_cursors
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        return items, pages

    def api_token(self, payload, token=None):
        data = self.doc("/api/tokens", 201, token=token or self.alice, method="POST", body=payload)
        self.secrets.append(data["secret"])
        return {"username": (token or self.alice)["username"], "token": data["secret"], "id": data["id"]}

    def push_file(self, owner, repo, work_dir, filename, content, branch, message, token):
        if not work_dir.exists():
            self.git("clone", self.base + f"/git/{owner}/{repo}.git", str(work_dir), token=token)
            self.git("config", "user.name", token["username"], cwd=work_dir)
            self.git("config", "user.email", f"{token['username']}@example.invalid", cwd=work_dir)
        (work_dir / filename).parent.mkdir(parents=True, exist_ok=True)
        (work_dir / filename).write_text(content)
        self.git("add", filename, cwd=work_dir)
        self.git("commit", "-m", message, cwd=work_dir)
        oid = self.git("rev-parse", "HEAD", cwd=work_dir).stdout.decode().strip()
        self.git("push", "origin", f"HEAD:{branch}", cwd=work_dir, token=token)
        return oid

    def batch_upload(self, owner, repo, raw_bytes, token):
        oid = hashlib.sha256(raw_bytes).hexdigest()
        batch = f"/git/{owner}/{repo}.git/info/lfs/objects/batch"
        status, body, _ = self.http(
            batch,
            token=token,
            method="POST",
            content_type=LFS_MIME,
            extra_headers={"Accept": LFS_MIME},
            body=json.dumps({
                "operation": "upload",
                "transfers": ["basic"],
                "objects": [{"oid": oid, "size": len(raw_bytes)}],
                "hash_algo": "sha256",
            }).encode(),
        )
        assert status == 200, (status, body[:200])
        obj = json.loads(body)["objects"][0]
        actions = obj.get("actions") or {}
        if "upload" in actions:
            upload_action = actions["upload"]
            parsed = urllib.parse.urlsplit(upload_action["href"])
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            status, body, _ = self.http(
                target,
                token=token,
                method="PUT",
                body=raw_bytes,
                content_type="application/octet-stream",
                extra_headers=upload_action.get("header") or {},
            )
            assert status in (200, 201), (status, body[:200])
        if "verify" in actions:
            verify_action = actions["verify"]
            parsed = urllib.parse.urlsplit(verify_action["href"])
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            v_headers = {"Accept": LFS_MIME}
            v_headers.update(verify_action.get("header") or {})
            self.expect(
                target,
                200,
                token=token,
                method="POST",
                content_type=LFS_MIME,
                extra_headers=v_headers,
                body=json.dumps({"oid": oid, "size": len(raw_bytes)}).encode(),
            )
        return oid

    def prepare_and_org_crud(self):
        self.setup()
        self.carol = self.account("create-user", "carol")
        self.dave = self.account("create-user", "dave")
        self.oscar = self.account("create-user", "oscar")
        self.erin = self.account("create-user", "erin")
        self.start()

        # AC1: human vs org namespace isolation in both directions + Idempotency-Key.
        acme = self.doc(
            "/api/orgs", 201, method="POST", body={"slug": "acme"},
            extra_headers={"Idempotency-Key": "org-acme-1"},
        )
        replay = self.doc(
            "/api/orgs", 201, method="POST", body={"slug": "acme"},
            extra_headers={"Idempotency-Key": "org-acme-1"},
        )
        assert replay["id"] == acme["id"]
        self.expect("/api/orgs", 409, token=self.alice, method="POST", body={"slug": "beta"},
                    extra_headers={"Idempotency-Key": "org-acme-1"})
        self.expect("/api/orgs", 409, token=self.alice, method="POST", body={"slug": "alice"})
        collide = self.run([self.args.binary, "create-user", "acme"], check=False)
        assert collide.returncode != 0, "create-user unexpectedly succeeded for existing org slug"

        self.beta = self.doc("/api/orgs", 201, method="POST", body={"slug": "beta"})
        self.solo = self.doc("/api/orgs", 201, method="POST", body={"slug": "solo-org"})
        self.other = self.doc("/api/orgs", 201, token=self.oscar, method="POST", body={"slug": "other-org"})
        self.acme = acme

        # Restricted PAT cannot create organizations and GET /api/orgs filters by org:read.
        acme_only = self.api_token({
            "display_name": "acme-org-read",
            "expires_in_days": 1,
            "read_only": False,
            "repository_grants": [],
            "namespace_grants": [{"organization_id": acme["id"], "actions": ["org:read"]}],
        })
        self.expect("/api/orgs", 403, token=acme_only, method="POST", body={"slug": "nope"})
        filtered_orgs, _ = self.collect_pages("/api/orgs", 2, token=acme_only)
        assert [o["slug"] for o in filtered_orgs] == ["acme"], filtered_orgs
        all_orgs, pages = self.collect_pages("/api/orgs", 2, token=self.alice)
        assert [o["slug"] for o in all_orgs] == ["acme", "beta", "solo-org"], all_orgs
        assert pages == 2
        self.expect("/api/orgs?cursor=" + urllib.parse.quote(
            self.doc("/api/orgs?limit=1", 200)["next_cursor"], safe=""
        ), 400, token=self.oscar)

        # Direct org members and non-member rejection when adding team members.
        self.doc("/api/orgs/acme/members/bob", 201, method="PUT", body={"role": "maintain"})
        self.doc("/api/orgs/acme/members/dave", 201, method="PUT", body={"role": "read"})
        self.doc("/api/orgs/acme/members/carol", 201, method="PUT", body={"role": "read"})

        eng = self.doc("/api/orgs/acme/teams", 201, method="POST",
                       body={"slug": "engineers", "name": "Engineers", "role": "write"})
        triage = self.doc("/api/orgs/acme/teams", 201, method="POST",
                          body={"slug": "triage", "name": "Triage", "role": "triage"})
        temp = self.doc("/api/orgs/acme/teams", 201, method="POST",
                        body={"slug": "temp-team", "name": "Temp", "role": "maintain"})
        assert eng["role"] == "write" and triage["role"] == "triage" and temp["role"] == "maintain"

        # Non-member cannot join a team; adding org members populates paginated list.
        self.expect("/api/orgs/acme/teams/engineers/members/erin", 409, token=self.alice, method="PUT")
        self.doc("/api/orgs/acme/teams/engineers/members/dave", 200, method="PUT")
        self.doc("/api/orgs/acme/teams/engineers/members/carol", 200, method="PUT")
        self.doc("/api/orgs/acme/teams/triage/members/carol", 200, method="PUT")
        self.doc("/api/orgs/acme/teams/temp-team/members/dave", 200, method="PUT")

        detail = self.doc("/api/orgs/acme/teams/engineers", 200)
        assert detail["version"] == 1 and detail["member_count"] == 2, detail
        members, mpages = self.collect_pages("/api/orgs/acme/teams/engineers/members", 1)
        assert [m["username"] for m in members] == ["carol", "dave"] and mpages == 2

        # Cross-team / cross-actor team-member cursor replay -> 400.
        first_page = self.doc("/api/orgs/acme/teams/engineers/members?limit=1", 200)
        tm_cursor = urllib.parse.quote(first_page["next_cursor"], safe="")
        self.expect(f"/api/orgs/acme/teams/triage/members?limit=1&cursor={tm_cursor}", 400, token=self.alice)
        self.expect(f"/api/orgs/acme/teams/engineers/members?limit=1&cursor={tm_cursor}", 400, token=self.bob)

        # Team PATCH CAS, unknown field refusal, authz, and DELETE cascade.
        self.expect("/api/orgs/acme/teams/engineers", 400, token=self.alice, method="PATCH",
                    body={"expected_version": 1})
        self.expect("/api/orgs/acme/teams/engineers", (400, 422), token=self.alice, method="PATCH",
                    body={"expected_version": 1, "name": "Core", "extra": True})
        self.expect("/api/orgs/acme/teams/engineers", 409, token=self.alice, method="PATCH",
                    body={"expected_version": 99, "role": "read"})
        self.expect("/api/orgs/acme/teams/engineers", 403, token=self.bob, method="PATCH",
                    body={"expected_version": 1, "role": "admin"})
        self.expect("/api/orgs/acme/teams/engineers", 404, token=self.oscar, method="PATCH",
                    body={"expected_version": 1, "role": "admin"})
        self.expect("/api/orgs/acme/teams/engineers", 403, token=acme_only, method="PATCH",
                    body={"expected_version": 1, "role": "read"})

        patched = self.doc("/api/orgs/acme/teams/engineers", 200, method="PATCH",
                           body={"expected_version": 1, "name": "Core Engineers", "role": "maintain"})
        assert patched["version"] == 2 and patched["role"] == "maintain" and patched["name"] == "Core Engineers"
        patched = self.doc("/api/orgs/acme/teams/engineers", 200, method="PATCH",
                           body={"expected_version": 2, "role": "write"})
        assert patched["version"] == 3 and patched["role"] == "write"

        # Remove carol from engineers so carol's effective role comes from triage (triage).
        self.doc("/api/orgs/acme/teams/engineers/members/carol", 200, method="DELETE")
        self.doc("/api/orgs/acme/teams/temp-team", 200, method="DELETE")
        self.expect("/api/orgs/acme/teams/temp-team", 404, token=self.alice)

        # Audit log API access control and keyset pagination.
        self.expect("/api/orgs/acme/audit", 404, token=self.oscar)
        self.expect("/api/orgs/acme/audit", 403, token=self.dave)
        self.expect("/api/orgs/acme/audit", 403, token=self.carol)
        audit_bob, apages = self.collect_pages("/api/orgs/acme/audit", 3, token=self.bob)
        assert apages >= 2
        actions = [entry["action"] for entry in audit_bob]
        for required in ("organization.created", "organization.member.upserted", "organization.team.created",
                         "organization.team.updated", "organization.team.deleted",
                         "organization.team.member.added", "organization.team.member.removed"):
            assert required in actions, actions
        audit_cursor = urllib.parse.quote(self.doc("/api/orgs/acme/audit?limit=1", 200, token=self.alice)["next_cursor"], safe="")
        self.expect(f"/api/orgs/acme/audit?limit=1&cursor={audit_cursor}", 400, token=self.bob)

        # Transfer remains explicitly 409 Conflict.
        self.app_repo = self.create_repository({"owner": "acme", "name": "app"}, token=self.alice)
        self.other_repo = self.create_repository({"owner": "other-org", "name": "secret"}, token=self.oscar)
        self.expect("/api/repos/acme/app/transfer", 409, token=self.alice, method="POST",
                    body={"new_owner": "alice"})
        # Non-maintain org member cannot create repo inside org even via write team.
        self.expect("/api/repos", 403, token=self.dave, method="POST", body={"owner": "acme", "name": "forbidden"})
        return {"orgs": len(all_orgs), "audit_events": len(audit_bob), "team_version": patched["version"]}

    def consistent_rbac_and_revocation(self):
        # Seed acme/app on main with pkg/lib.rs for Views & main commit for PRs/Workspaces.
        self.alice_app_work = self.root / "alice-app-work"
        base_oid = self.push_file(
            "acme", "app", self.alice_app_work, "pkg/lib.rs", "pub fn ok() -> u32 { 1 }\n",
            "main", "init app", self.alice,
        )
        self.app_base_oid = base_oid

        # Secret org repo in other-org.
        self.oscar_work = self.root / "oscar-secret-work"
        oscar_oid = self.push_file(
            "other-org", "secret", self.oscar_work, "secret.txt", "top secret\n",
            "main", "secret init", self.oscar,
        )
        self.oscar_oid = oscar_oid

        # dave (direct read + team engineers=write) clones/pushes Git, uploads LFS + creates LFS lock.
        self.dave_work = self.root / "dave-app-work"
        feat_oid = self.push_file(
            "acme", "app", self.dave_work, "feature.txt", "from engineers team\n",
            "refs/heads/feature", "team feature", self.dave,
        )
        self.feat_oid = feat_oid

        # carol (direct read + team triage) can read/clone & open issue, cannot push or upload/lock LFS.
        carol_work = self.root / "carol-app-work"
        self.git("clone", self.base + "/git/acme/app.git", str(carol_work), token=self.carol)
        self.git("config", "user.name", "carol", cwd=carol_work)
        self.git("config", "user.email", "carol@example.invalid", cwd=carol_work)
        (carol_work / "carol.txt").write_text("no push\n")
        self.git("add", "carol.txt", cwd=carol_work)
        self.git("commit", "-m", "denied push", cwd=carol_work)
        assert self.git("push", "origin", "HEAD:refs/heads/carol-nope", cwd=carol_work,
                        token=self.carol, check=False).returncode != 0

        # LFS upload + locks.
        lfs_bytes = b"team lfs payload\n" * 64
        self.lfs_oid = self.batch_upload("acme", "app", lfs_bytes, self.dave)
        assert self.expect(f"/git/acme/app.git/info/lfs/objects/{self.lfs_oid}/{len(lfs_bytes)}",
                           200, token=self.carol) == lfs_bytes
        self.expect(f"/git/acme/app.git/info/lfs/objects/{self.lfs_oid}/{len(lfs_bytes)}",
                    404, token=self.oscar)

        lock_path = "/git/acme/app.git/info/lfs/locks"
        lock = json.loads(self.expect(
            lock_path, 201, token=self.dave, method="POST", content_type=LFS_MIME,
            extra_headers={"Accept": LFS_MIME}, body=json.dumps({"path": "docs/spec.md"}).encode(),
        ))
        self.lock_id = lock["lock"]["id"]
        self.expect(lock_path, 403, token=self.carol, method="POST", content_type=LFS_MIME,
                    extra_headers={"Accept": LFS_MIME}, body=json.dumps({"path": "docs/denied.md"}).encode())

        # Forge issue + branch rule requiring 1 approval + PR approved by dave.
        issue = self.doc("/api/repos/acme/app/issues", 201, token=self.carol, method="POST",
                         body={"title": "Triage org issue", "body": "created by triage team"})
        self.issue_num = issue["number"]
        self.doc("/api/repos/acme/app/branch-rules/refs/heads/main", 201, token=self.bob, method="PUT",
                 body={"required_approvals": 1, "required_checks": [], "require_fast_forward": False,
                       "prevent_deletion": True, "prevent_force_push": True, "prevent_self_approval": True})
        pr = self.doc("/api/repos/acme/app/pulls", 201, token=self.alice, method="POST",
                      body={"title": "Feature PR", "head_ref": "refs/heads/feature", "base_ref": "refs/heads/main"})
        self.pr_num = pr["number"]
        # 0 approvals -> blocked by branch rule.
        self.expect(f"/api/repos/acme/app/pulls/{self.pr_num}/merge", 409, token=self.alice, method="POST",
                    body={"expected_version": pr["version"], "expected_head_oid": feat_oid,
                          "expected_base_oid": base_oid, "strategy": "merge_commit"},
                    extra_headers={"Idempotency-Key": "blocked-before-approval"})
        self.doc(f"/api/repos/acme/app/pulls/{self.pr_num}/reviews", 201, token=self.dave, method="POST",
                 body={"state": "approved", "commit_oid": feat_oid, "body": "LGTM"})
        self.expect(f"/api/repos/acme/app/pulls/{self.pr_num}/reviews", 403, token=self.carol, method="POST",
                    body={"state": "approved", "commit_oid": feat_oid})

        # Views (namespace_service) and Workspaces on org repo.
        ns = self.doc("/api/namespaces", 201, token=self.dave, method="POST",
                      body={"name": "acme-pkg-view", "mounts": [{
                          "path": "pkg", "owner": "acme", "repository": "app", "base_oid": base_oid,
                      }]})
        self.dave_ns = ns
        view = self.doc(f"/api/namespaces/{ns['id']}/views", 201, token=self.dave, method="POST",
                        body={"mount_path": "pkg", "subdir": "pkg"})
        self.dave_view = view
        assert len(self.expect(f"/api/views/{view['id']}/bundle", 200, token=self.dave)) > 0

        ws = self.doc("/api/workspaces", 201, token=self.dave, method="POST",
                      body={"owner": "acme", "repository": "app", "agent_id": "dave-ws", "base_oid": base_oid},
                      extra_headers={"Idempotency-Key": "dave-ws-1"})
        self.dave_ws = ws
        self.doc(f"/api/workspaces/{ws['id']}/files?path=notes.txt", 200, token=self.dave, method="PUT",
                 body={"content_base64": base64.b64encode(b"dave workspace\n").decode(),
                       "expected_entry_version": 0, "expected_workspace_revision": 0,
                       "lease_epoch": ws["lease_epoch"]},
                 extra_headers={"Idempotency-Key": "dave-ws-edit-1"})
        # Creator privacy within same org: carol cannot inspect/edit dave's workspace.
        self.expect(f"/api/workspaces/{ws['id']}", 404, token=self.carol)

        # Web UI access via dave session before revocation.
        dave_cookies, _, _ = self.sign_in(username="dave", token=self.dave["token"])
        st, body, _ = self.request("/web/repos", headers={"Cookie": self.cookie_header(dave_cookies)})
        assert st == 200 and b"acme" in body and b"app" in body and b"secret" not in body
        assert self.request("/web/repos/acme/app", headers={"Cookie": self.cookie_header(dave_cookies)})[0] == 200
        assert self.request("/web/repos/acme/app/issues", headers={"Cookie": self.cookie_header(dave_cookies)})[0] == 200
        assert self.request("/web/repos/acme/app/pulls", headers={"Cookie": self.cookie_header(dave_cookies)})[0] == 200
        assert self.request("/web/repos/other-org/secret", headers={"Cookie": self.cookie_header(dave_cookies)})[0] == 404

        # Downgrade team engineers write -> read (version 3 -> 4) & verify immediate revocation!
        self.doc("/api/orgs/acme/teams/engineers", 200, method="PATCH",
                 body={"expected_version": 3, "role": "read"})
        # dave's write team approval no longer counts -> merge blocked by branch rule!
        pr_now = self.doc(f"/api/repos/acme/app/pulls/{self.pr_num}", 200)
        self.expect(f"/api/repos/acme/app/pulls/{self.pr_num}/merge", 409, token=self.alice, method="POST",
                    body={"expected_version": pr_now["version"], "expected_head_oid": feat_oid,
                          "expected_base_oid": base_oid, "strategy": "merge_commit"},
                    extra_headers={"Idempotency-Key": "blocked-after-team-downgrade"})
        assert self.git("push", "origin", f"{feat_oid}:refs/heads/dave-after-downgrade",
                        cwd=self.dave_work, token=self.dave, check=False).returncode != 0
        self.expect(lock_path, 403, token=self.dave, method="POST", content_type=LFS_MIME,
                    extra_headers={"Accept": LFS_MIME}, body=json.dumps({"path": "docs/after-downgrade.md"}).encode())
        self.expect(f"/api/workspaces/{ws['id']}/files?path=notes2.txt", 403, token=self.dave, method="PUT",
                    body={"content_base64": base64.b64encode(b"denied\n").decode(),
                          "expected_entry_version": 0, "expected_workspace_revision": 1,
                          "lease_epoch": ws["lease_epoch"]},
                    extra_headers={"Idempotency-Key": "dave-ws-denied-1"})

        # Upgrade team back to write (version 4 -> 5) and remove carol from org entirely (pre-backup revocation).
        self.doc("/api/orgs/acme/teams/engineers", 200, method="PATCH",
                 body={"expected_version": 4, "role": "write"})
        self.doc("/api/orgs/acme/members/carol", 200, method="DELETE")
        self.expect("/api/orgs/acme", 404, token=self.carol)
        self.expect("/api/repos/acme/app", 404, token=self.carol)
        self.expect(f"/api/repos/acme/app/issues/{self.issue_num}", 404, token=self.carol)
        assert self.git("ls-remote", self.base + "/git/acme/app.git", token=self.carol, check=False).returncode != 0

        # Org repo admin (alice via org ownership) can force-unlock lingering lock owned by dave.
        self.doc(f"{lock_path}/{self.lock_id}/unlock", 200, token=self.alice, method="POST",
                 content_type=LFS_MIME, extra_headers={"Accept": LFS_MIME}, body=json.dumps({"force": True}).encode())
        return {
            "branch_rule_revoked_approval_blocked_merge": True,
            "namespace_view_and_workspace_isolation_verified": True,
            "team_downgrade_and_member_removal_immediate": True,
        }

    def restart_backup_restore_and_isolation(self):
        # 1. Process restart durability before backup.
        self.stop()
        self.start()
        self.expect("/api/orgs/acme", 200, token=self.dave)
        self.expect("/api/orgs/acme", 404, token=self.carol)
        self.expect("/api/repos/acme/app", 200, token=self.dave)

        # 2. Offline backup -> verify -> restore to target_db + restored-data.
        self.stop()
        self.backup_command()
        self.cli("backup-verify", str(self.backup))
        self.restore_command()
        self.db = self.target_db
        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        self.start()

        # Restored pre-backup revocations and cross-tenant isolation hold cleanly.
        self.expect("/api/orgs/acme", 404, token=self.carol)
        self.expect("/api/repos/acme/app", 404, token=self.carol)
        self.expect("/api/orgs/other-org", 404, token=self.alice)
        self.expect("/api/repos/other-org/secret", 404, token=self.alice)
        self.expect("/api/repos/other-org/secret", 404, token=self.dave)
        self.expect("/api/orgs/acme", 404, token=self.oscar)
        self.expect("/api/repos/acme/app", 404, token=self.oscar)
        self.expect(f"/api/workspaces/{self.dave_ws['id']}", 404, token=self.oscar)
        assert self.git("ls-remote", self.base + "/git/other-org/secret.git",
                        token=self.alice, check=False).returncode != 0

        # Restored team inheritance enables dave to push a post-restore commit, inspect workspace, and access LFS.
        post_oid = self.push_file(
            "acme", "app", self.dave_work, "restored.txt", "post-restore commit\n",
            "refs/heads/post-restore", "post restore team commit", self.dave,
        )
        assert post_oid
        self.expect(f"/api/repos/acme/app/issues/{self.issue_num}", 200, token=self.dave)
        assert len(self.expect(f"/git/acme/app.git/info/lfs/objects/{self.lfs_oid}/{len(b'team lfs payload\n' * 64)}",
                               200, token=self.dave)) > 0
        renewed_lease = self.doc(
            f"/api/workspaces/{self.dave_ws['id']}/lease", 200, token=self.dave, method="POST",
            body={"expected_lease_epoch": self.dave_ws["lease_epoch"] + 1},
        )
        self.doc(
            f"/api/workspaces/{self.dave_ws['id']}/files?path=restored.txt", 200, token=self.dave, method="PUT",
            body={"content_base64": base64.b64encode(b"restored ws edit\n").decode(),
                  "expected_entry_version": 0, "expected_workspace_revision": 1,
                  "lease_epoch": renewed_lease["lease_epoch"]},
            extra_headers={"Idempotency-Key": "dave-ws-restored-edit"},
        )

        # Post-restore team removal revokes dave immediately (Git push blocked, workspace edit blocked).
        self.doc("/api/orgs/acme/teams/engineers/members/dave", 200, method="DELETE")
        assert self.git("push", "origin", f"{post_oid}:refs/heads/dave-revoked",
                        cwd=self.dave_work, token=self.dave, check=False).returncode != 0
        self.expect(f"/api/workspaces/{self.dave_ws['id']}/files?path=denied.txt", 403, token=self.dave, method="PUT",
                    body={"content_base64": base64.b64encode(b"no\n").decode(),
                          "expected_entry_version": 0, "expected_workspace_revision": 2,
                          "lease_epoch": renewed_lease["lease_epoch"]},
                    extra_headers={"Idempotency-Key": "dave-ws-after-team-remove"})
        # Full org removal strips all remaining access including Views, Workspaces, and Web UI.
        self.doc("/api/orgs/acme/members/dave", 200, method="DELETE")
        self.expect("/api/orgs/acme", 404, token=self.dave)
        self.expect(f"/api/namespaces/{self.dave_ns['id']}", 404, token=self.dave)
        self.expect(f"/api/views/{self.dave_view['id']}/bundle", 404, token=self.dave)
        self.expect(f"/api/workspaces/{self.dave_ws['id']}", 404, token=self.dave)
        dave_cookies, _, _ = self.sign_in(username="dave", token=self.dave["token"])
        assert self.request("/web/repos/acme/app", headers={"Cookie": self.cookie_header(dave_cookies)})[0] == 404
        assert self.request("/web/repos/acme/app/issues", headers={"Cookie": self.cookie_header(dave_cookies)})[0] == 404

        # Last-administrator protection survives backup/restore and never orphans org ownership.
        self.expect("/api/orgs/solo-org/members/alice", 409, token=self.alice, method="DELETE")
        self.expect("/api/orgs/solo-org/members/alice", 409, token=self.alice, method="PUT",
                    body={"role": "maintain"})
        self.doc("/api/orgs/solo-org/members/bob", 201, method="PUT", body={"role": "admin"})
        self.doc("/api/orgs/solo-org/members/alice", 200, method="DELETE")
        self.expect("/api/orgs/solo-org/members/bob", 409, token=self.bob, method="DELETE")

        # Audit log survives restore and continues recording post-restore events cleanly.
        post_audit, _ = self.collect_pages("/api/orgs/acme/audit", 10, token=self.alice)
        ids = [entry["id"] for entry in post_audit]
        assert ids == sorted(ids) and len(set(ids)) == len(ids), ids
        assert any(entry["action"] == "organization.member.removed" and entry["target"] == "dave"
                   for entry in post_audit), post_audit
        return {
            "restart_and_backup_restore_ok": True,
            "cross_org_isolation_ok": True,
            "post_restore_revocation_and_last_admin_ok": True,
            "post_restore_audit_entries": len(post_audit),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    for exe in ("git", "git-lfs", "psql", "pg_dump", "pg_restore", args.binary):
        if not shutil.which(exe):
            parser.error("Required executable not found: " + exe)
    h = OrganizationLifecycleHarness(args)
    passed = False
    try:
        for name, fn in [
            ("namespace_and_org_team_crud", h.prepare_and_org_crud),
            ("consistent_rbac_and_revocation_across_surfaces", h.consistent_rbac_and_revocation),
            ("restart_backup_restore_and_tenant_isolation", h.restart_backup_restore_and_isolation),
        ]:
            h.case(name, fn)
        passed = True
    except Exception as exc:
        print(h.redact(exc), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as exc:
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(exc)))
            passed = False
        report = {
            "passed": passed,
            "cases": h.results,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
