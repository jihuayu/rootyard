#!/usr/bin/env python3
"""Native E2E acceptance suite for Issue #85 repository archive, rename/308
aliases (authz-before-redirect), soft-delete/restore/fail-closed purge, and
crash-recoverable ownership transfer against the real binary and PostgreSQL."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback
import urllib.parse
import uuid

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from web_sessions import BrowserHarness  # noqa: E402

LFS_MIME = "application/vnd.git-lfs+json"


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


class RepositoryLifecycleHarness(BrowserHarness):
    def doc(self, path, code, token=None, **kwargs):
        status, body, _ = self.http(path, token=token or self.alice, **kwargs)
        expected = code if isinstance(code, tuple) else (code,)
        assert status in expected, f"{path}: expected {code}, got {status}: {body[:300]!r}"
        return json.loads(body) if body and status < 300 else None

    def raw_http(self, path, token=None, method="GET", body=None, content_type=None, basic=False, extra_headers=None, cookies=None):
        headers = {}
        if token:
            if basic:
                cred = base64.b64encode((token["username"] + ":" + token["token"]).encode()).decode()
                headers["Authorization"] = "Basic " + cred
            else:
                headers["Authorization"] = "Bearer " + token["token"]
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            content_type = content_type or "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        if cookies:
            headers["Cookie"] = self.cookie_header(cookies)
        headers.update(extra_headers or {})
        status, data, raw_headers = self.request(path, method=method, body=body, headers=headers)
        lowered = {}
        for k, v in raw_headers:
            lowered[k.lower()] = v
        return status, data, lowered

    def push_file(self, owner, repo, work_dir, filename, content, branch, message, token):
        if not work_dir.exists():
            self.git("clone", self.base + f"/git/{owner}/{repo}.git", str(work_dir), token=token)
            self.git("config", "user.name", token["username"], cwd=work_dir)
            self.git("config", "user.email", f"{token['username']}@example.invalid", cwd=work_dir)
        target = work_dir / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
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
        assert status == 200, (batch, status, body[:200])
        obj = json.loads(body)["objects"][0]
        actions = obj.get("actions") or {}
        if "upload" in actions:
            upload_action = actions["upload"]
            parsed = urllib.parse.urlsplit(upload_action["href"])
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            st, put_body, _ = self.http(
                target,
                token=token,
                method="PUT",
                body=raw_bytes,
                content_type="application/octet-stream",
                extra_headers=upload_action.get("header") or {},
            )
            assert st in (200, 201), (st, put_body[:200])
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

    def archive_read_write_boundary(self):
        self.setup()
        self.charlie = self.account("create-user", "charlie")
        self.alpha = self.create_repository({"owner": "alice", "name": "alpha"}, token=self.alice)
        self.expect("/api/repos/alice/alpha/collaborators/bob", 201, token=self.alice, method="PUT", body={"role": "write"})
        self.alpha_work = self.root / "alpha-work"
        base_oid = self.push_file("alice", "alpha", self.alpha_work, "README.md", "v1\n", "main", "init alpha", self.alice)
        self.alpha_lfs = b"archive-lfs-payload-" * 64
        self.alpha_lfs_oid = self.batch_upload("alice", "alpha", self.alpha_lfs, self.alice)
        self.doc("/api/repos/alice/alpha/issues", 201, token=self.bob, method="POST", body={"title": "Before archive"})
        ws = self.doc(
            "/api/workspaces",
            201,
            token=self.bob,
            method="POST",
            body={"owner": "alice", "repository": "alpha", "agent_id": "bob-ws", "base_oid": base_oid},
            extra_headers={"Idempotency-Key": "ws-create-alpha"},
        )
        self.alpha_ws = ws

        lc = self.doc("/api/repos/alice/alpha/lifecycle", 200, token=self.alice)
        assert not lc["archived"] and not lc["deleted"], lc
        # Stale version rejected with 409; matching version + Idempotency-Key succeeds.
        self.expect(
            "/api/repos/alice/alpha/archive",
            409,
            token=self.alice,
            method="POST",
            body={"expected_version": lc["version"] + 5},
            extra_headers={"Idempotency-Key": "arch-stale"},
        )
        archived = self.doc(
            "/api/repos/alice/alpha/archive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": lc["version"]},
            extra_headers={"Idempotency-Key": "arch-1"},
        )
        assert archived["archived"] and archived["version"] == lc["version"] + 1, archived
        # Idempotent replay matches exact version & body; parameter mismatch returns 409.
        replay = self.doc(
            "/api/repos/alice/alpha/archive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": lc["version"]},
            extra_headers={"Idempotency-Key": "arch-1"},
        )
        assert replay == archived, (replay, archived)
        self.expect(
            "/api/repos/alice/alpha/archive",
            409,
            token=self.alice,
            method="POST",
            body={"expected_version": lc["version"] + 1},
            extra_headers={"Idempotency-Key": "arch-1"},
        )

        # Read paths remain open across REST, Git, LFS, Workspaces, Web UI.
        self.doc("/api/repos/alice/alpha", 200, token=self.bob)
        self.doc("/api/repos/alice/alpha/issues", 200, token=self.bob)
        self.doc(f"/api/workspaces/{ws['id']}", 200, token=self.bob)
        assert self.expect(
            f"/git/alice/alpha.git/info/lfs/objects/{self.alpha_lfs_oid}/{len(self.alpha_lfs)}",
            200,
            token=self.bob,
        ) == self.alpha_lfs
        bob_clone = self.root / "bob-arch-clone"
        self.git("clone", self.base + "/git/alice/alpha.git", str(bob_clone), token=self.bob)
        alice_cookies, _, _ = self.sign_in(username="alice", token=self.alice["token"])
        assert self.request("/web/repos/alice/alpha", headers={"Cookie": self.cookie_header(alice_cookies)})[0] == 200

        # Mutating paths return 403 Forbidden (or push failure) while archived.
        self.expect("/api/repos/alice/alpha/issues", 403, token=self.bob, method="POST", body={"title": "Denied"})
        self.expect(
            f"/api/workspaces/{ws['id']}/files?path=blocked.txt",
            403,
            token=self.bob,
            method="PUT",
            body={
                "content_base64": base64.b64encode(b"no\n").decode(),
                "expected_entry_version": 0,
                "expected_workspace_revision": 0,
                "lease_epoch": ws["lease_epoch"],
            },
            extra_headers={"Idempotency-Key": "ws-arch-denied"},
        )
        self.expect(
            "/api/repos/alice/alpha/rename",
            403,
            token=self.alice,
            method="POST",
            body={"new_name": "alpha2", "expected_version": archived["version"]},
            extra_headers={"Idempotency-Key": "rename-arch-denied"},
        )
        (bob_clone / "blocked.txt").write_text("blocked\n")
        self.git("config", "user.name", "Bob", cwd=bob_clone)
        self.git("config", "user.email", "bob@example.invalid", cwd=bob_clone)
        self.git("add", "blocked.txt", cwd=bob_clone)
        self.git("commit", "-m", "blocked commit", cwd=bob_clone)
        assert self.git("push", "origin", "HEAD:main", cwd=bob_clone, token=self.bob, check=False).returncode != 0

        # Unarchive restores write capability cleanly.
        unarchived = self.doc(
            "/api/repos/alice/alpha/unarchive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": archived["version"]},
            extra_headers={"Idempotency-Key": "unarch-1"},
        )
        assert not unarchived["archived"] and unarchived["version"] == archived["version"] + 1, unarchived
        self.push_file("alice", "alpha", self.alpha_work, "after_unarchive.txt", "ok\n", "main", "post unarchive", self.alice)
        self.doc("/api/repos/alice/alpha/issues", 201, token=self.bob, method="POST", body={"title": "After unarchive"})
        return {"archived_version": archived["version"], "unarchived_version": unarchived["version"]}

    def rename_aliases_and_authz_before_redirect(self):
        lc = self.doc("/api/repos/alice/alpha/lifecycle", 200, token=self.alice)
        # Demote bob to read-only so we also verify read authz suffices for GET redirects.
        self.expect("/api/repos/alice/alpha/collaborators/bob", 200, token=self.alice, method="PUT", body={"role": "read"})
        renamed = self.doc(
            "/api/repos/alice/alpha/rename",
            200,
            token=self.alice,
            method="POST",
            body={"new_name": "beta", "expected_version": lc["version"]},
            extra_headers={"Idempotency-Key": "rename-alpha-beta"},
        )
        assert renamed["name"] == "beta" and any(a["name"] == "alpha" and a["owner"] == "alice" for a in renamed["aliases"]), renamed
        assert self.sql(f"SELECT repository_name FROM workspaces WHERE id = {quote(self.alpha_ws['id'])}") == "beta"

        # 1) Unauthenticated callers never observe 308 or Location disclosure.
        for path in ("/api/repos/alice/alpha", "/git/alice/alpha.git/info/refs?service=git-upload-pack"):
            st, _, hdrs = self.raw_http(path)
            assert st == 401 and "location" not in hdrs, (path, st, hdrs)
        web_st, _, web_hdrs = self.raw_http("/web/repos/alice/alpha", extra_headers={"Accept": "text/html"})
        assert web_st == 303 and web_hdrs.get("location", "").startswith("/web/login"), (web_st, web_hdrs)

        # 2) Authenticated outsider charlie receives 404 with ZERO Location disclosure.
        charlie_cookies, _, _ = self.sign_in(username="charlie", token=self.charlie["token"])
        for st, hdrs in [
            self.raw_http("/api/repos/alice/alpha", token=self.charlie)[::2],
            self.raw_http("/git/alice/alpha.git/info/refs?service=git-upload-pack", token=self.charlie, basic=True)[::2],
            self.raw_http(
                "/git/alice/alpha.git/info/lfs/objects/batch",
                token=self.charlie,
                method="POST",
                content_type=LFS_MIME,
                extra_headers={"Accept": LFS_MIME},
                body=json.dumps({"operation": "download", "transfers": ["basic"], "objects": [{"oid": self.alpha_lfs_oid, "size": len(self.alpha_lfs)}], "hash_algo": "sha256"}).encode(),
            )[::2],
            self.raw_http("/web/repos/alice/alpha", cookies=charlie_cookies)[::2],
        ]:
            assert st == 404 and "location" not in hdrs, (st, hdrs)

        # 3) Authorized reader bob receives 308 Permanent Redirect + Cache-Control: no-store across REST, Git, LFS, Web.
        bob_cookies, _, _ = self.sign_in(username="bob", token=self.bob["token"])
        expected_redirects = [
            (self.raw_http("/api/repos/alice/alpha", token=self.bob), "/api/repos/alice/beta"),
            (self.raw_http("/git/alice/alpha.git/info/refs?service=git-upload-pack", token=self.bob, basic=True), "/git/alice/beta.git/info/refs?service=git-upload-pack"),
            (
                self.raw_http(
                    "/git/alice/alpha.git/info/lfs/objects/batch",
                    token=self.bob,
                    method="POST",
                    content_type=LFS_MIME,
                    extra_headers={"Accept": LFS_MIME},
                    body=json.dumps({"operation": "download", "transfers": ["basic"], "objects": [{"oid": self.alpha_lfs_oid, "size": len(self.alpha_lfs)}], "hash_algo": "sha256"}).encode(),
                ),
                "/git/alice/beta.git/info/lfs/objects/batch",
            ),
            (self.raw_http("/web/repos/alice/alpha", cookies=bob_cookies), "/web/repos/alice/beta"),
        ]
        for (st, _, hdrs), expected_loc in expected_redirects:
            assert st == 308, (expected_loc, st, hdrs)
            assert hdrs.get("location") == expected_loc, (expected_loc, hdrs)
            assert hdrs.get("cache-control") == "no-store", hdrs

        # Real Git CLI follows 308 redirect from old clone path.
        redirected_clone = self.root / "bob-redirected-clone"
        self.git("-c", "http.followRedirects=true", "clone", self.base + "/git/alice/alpha.git", str(redirected_clone), token=self.bob)
        assert (redirected_clone / "after_unarchive.txt").read_text() == "ok\n"

        # 4) Alias collision & self-alias reclaim + explicit alias deletion.
        decoy = self.create_repository({"owner": "alice", "name": "decoy"}, token=self.alice)
        self.expect(
            "/api/repos",
            409,
            token=self.alice,
            method="POST",
            body={"owner": "alice", "name": "alpha"},
        )
        self.expect(
            "/api/repos/alice/decoy/rename",
            409,
            token=self.alice,
            method="POST",
            body={"new_name": "alpha", "expected_version": 1},
            extra_headers={"Idempotency-Key": "decoy-hijack-alpha"},
        )
        # Reclaim self-alias alice/beta -> alice/alpha cleanly.
        reclaimed = self.doc(
            "/api/repos/alice/beta/rename",
            200,
            token=self.alice,
            method="POST",
            body={"new_name": "alpha", "expected_version": renamed["version"]},
            extra_headers={"Idempotency-Key": "reclaim-alpha"},
        )
        assert reclaimed["name"] == "alpha" and not any(a["name"] == "alpha" for a in reclaimed["aliases"]), reclaimed
        st_rev, _, hdr_rev = self.raw_http("/api/repos/alice/beta", token=self.bob)
        assert st_rev == 308 and hdr_rev.get("location") == "/api/repos/alice/alpha", (st_rev, hdr_rev)
        self.doc("/api/repos/alice/alpha/aliases/alice/beta", 200, token=self.alice, method="DELETE")
        self.expect("/api/repos/alice/beta", 404, token=self.bob)
        self.expect("/api/repos/alice/alpha/aliases/alice/beta", 404, token=self.alice, method="DELETE")
        assert decoy["id"]
        return {"redirect_count": len(expected_redirects), "reclaimed_version": reclaimed["version"]}

    def soft_delete_restore_and_purge_holds(self):
        shared_payload = b"shared-lfs-blob-" * 128
        repo_a = self.create_repository({"owner": "alice", "name": "shared-a"}, token=self.alice)
        repo_b = self.create_repository({"owner": "alice", "name": "shared-b"}, token=self.alice)
        shared_oid = self.batch_upload("alice", "shared-a", shared_payload, self.alice)
        self.batch_upload("alice", "shared-b", shared_payload, self.alice)
        work_a = self.root / "shared-a-work"
        base_a = self.push_file("alice", "shared-a", work_a, "data.txt", "keep me\n", "main", "seed a", self.alice)

        # Rename shared-a -> shared-a-old? No: rename decoy first -> create alias pointing to shared-a then verify alias stops redirecting once soft-deleted.
        lc_a = self.doc("/api/repos/alice/shared-a/lifecycle", 200, token=self.alice)
        renamed_a = self.doc(
            "/api/repos/alice/shared-a/rename",
            200,
            token=self.alice,
            method="POST",
            body={"new_name": "shared-a2", "expected_version": lc_a["version"]},
            extra_headers={"Idempotency-Key": "rename-shared-a"},
        )

        # Soft-delete with 7-day grace window hides repo & aliases across every surface.
        deleted_a = self.doc(
            "/api/repos/alice/shared-a2",
            200,
            token=self.alice,
            method="DELETE",
            body={"expected_version": renamed_a["version"], "grace_period_seconds": 7 * 24 * 3600},
            extra_headers={"Idempotency-Key": "del-shared-a-7d"},
        )
        assert deleted_a["deleted"], deleted_a
        self.expect("/api/repos/alice/shared-a2", 404, token=self.alice)
        st_al, _, hdr_al = self.raw_http("/api/repos/alice/shared-a", token=self.alice)
        assert st_al == 404 and "location" not in hdr_al, (st_al, hdr_al)
        assert self.git("ls-remote", self.base + "/git/alice/shared-a2.git", token=self.alice, check=False).returncode != 0
        self.expect("/api/repos", 409, token=self.alice, method="POST", body={"owner": "alice", "name": "shared-a2"})

        # Purge during open grace window fails closed with recovery_window_open.
        st_w, raw_w, _ = self.raw_http(
            "/api/repos/alice/shared-a2/purge",
            token=self.alice,
            method="POST",
            body={"expected_version": deleted_a["version"], "confirm_repository": "alice/shared-a2"},
            extra_headers={"Idempotency-Key": "purge-during-grace"},
        )
        assert st_w == 409, (st_w, raw_w)
        assert any(h["kind"] == "recovery_window_open" for h in json.loads(raw_w)["holds"]), raw_w

        # Restore preserves Git & LFS data verbatim.
        restored = self.doc(
            "/api/repos/alice/shared-a2/restore",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": deleted_a["version"]},
            extra_headers={"Idempotency-Key": "restore-shared-a2"},
        )
        assert not restored["deleted"] and restored["version"] == deleted_a["version"] + 1, restored
        assert self.git("ls-remote", self.base + "/git/alice/shared-a2.git", "refs/heads/main", token=self.alice).stdout.decode().split()[0] == base_a
        assert self.expect(f"/git/alice/shared-a2.git/info/lfs/objects/{shared_oid}/{len(shared_payload)}", 200, token=self.alice) == shared_payload

        # Re-delete with 0s grace period to test operational holds + fail-closed final purge.
        del_now = self.doc(
            "/api/repos/alice/shared-a2",
            200,
            token=self.alice,
            method="DELETE",
            body={"expected_version": restored["version"], "grace_period_seconds": 0},
            extra_headers={"Idempotency-Key": "del-shared-a-0s"},
        )
        # Seed active storage_maintenance_jobs + storage_write_admissions rows and verify both block purge.
        maint_id = str(uuid.uuid4())
        admin_id = str(uuid.uuid4())
        owner_token = str(uuid.uuid4())
        self.sql(
            "INSERT INTO storage_maintenance_jobs "
            "(id, repository_id, tenant_id, kind, state, repository_generation, lease_owner, lease_until) "
            f"VALUES ({quote(maint_id)}, {quote(repo_a['id'])}, {quote(self.alice['user_id'])}, "
            f"'gitfs_repack', 'running', 1, {quote(owner_token)}, clock_timestamp() + interval '1 hour')"
        )
        self.sql(
            "INSERT INTO storage_write_admissions (id, repository_id, gc_epoch, owner, kind, state, lease_until) "
            f"VALUES ({quote(admin_id)}, {quote(repo_a['id'])}, 1, {quote(owner_token)}, 'git_push', 'active', clock_timestamp() + interval '1 hour')"
        )
        st_h, raw_h, _ = self.raw_http(
            "/api/repos/alice/shared-a2/purge",
            token=self.alice,
            method="POST",
            body={"expected_version": del_now["version"], "confirm_repository": "alice/shared-a2"},
            extra_headers={"Idempotency-Key": "purge-blocked-holds"},
        )
        assert st_h == 409, (st_h, raw_h)
        hold_kinds = {h["kind"] for h in json.loads(raw_h)["holds"]}
        assert "active_storage_maintenance" in hold_kinds and "active_write_admission" in hold_kinds, hold_kinds

        self.sql(
            f"UPDATE storage_maintenance_jobs SET state = 'succeeded', lease_owner = NULL, lease_until = NULL "
            f"WHERE id = {quote(maint_id)}"
        )
        self.sql(
            "UPDATE storage_write_admissions SET state = 'finished', finished_at = clock_timestamp() "
            f"WHERE id = {quote(admin_id)}"
        )
        purged = self.doc(
            "/api/repos/alice/shared-a2/purge",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": del_now["version"], "confirm_repository": "alice/shared-a2"},
            extra_headers={"Idempotency-Key": "purge-final"},
        )
        assert purged["purged"] and purged["repository_id"] == repo_a["id"], purged
        assert self.sql(f"SELECT count(*) FROM repositories WHERE id = {quote(repo_a['id'])}") == "0"
        # Shared sibling repo_b MUST remain 100% readable!
        assert self.expect(
            f"/git/{repo_b['owner']}/{repo_b['name']}.git/info/lfs/objects/{shared_oid}/{len(shared_payload)}",
            200,
            token=self.alice,
        ) == shared_payload
        return {"blocked_hold_kinds": sorted(hold_kinds), "purged_repo": repo_a["id"]}

    def ownership_transfer_and_crash_recovery(self):
        org = self.doc("/api/orgs", 201, token=self.alice, method="POST", body={"slug": "dest-org"}, extra_headers={"Idempotency-Key": "org-dest"})
        gamma = self.create_repository({"owner": "alice", "name": "gamma"}, token=self.alice)
        self.expect("/api/repos/alice/gamma/collaborators/bob", 201, token=self.alice, method="PUT", body={"role": "write"})
        gamma_work = self.root / "gamma-work"
        gamma_oid = self.push_file("alice", "gamma", gamma_work, "app.py", "print('ok')\n", "main", "init gamma", self.alice)
        gamma_lfs = b"gamma-transfer-lfs-" * 48
        gamma_lfs_oid = self.batch_upload("alice", "gamma", gamma_lfs, self.alice)
        ws_gamma = self.doc(
            "/api/workspaces",
            201,
            token=self.alice,
            method="POST",
            body={"owner": "alice", "repository": "gamma", "agent_id": "alice-ws", "base_oid": gamma_oid},
            extra_headers={"Idempotency-Key": "ws-gamma"},
        )

        # Compatibility contract: omitting expected_version still returns 409 without mutating owner.
        self.expect("/api/repos/alice/gamma/transfer", 409, token=self.alice, method="POST", body={"new_owner": "dest-org"})
        assert self.sql(f"SELECT owner_id FROM repositories WHERE id = {quote(gamma['id'])}") == self.alice["user_id"]

        lc_g = self.doc("/api/repos/alice/gamma/lifecycle", 200, token=self.alice)
        xfer = self.doc(
            "/api/repos/alice/gamma/transfer",
            200,
            token=self.alice,
            method="POST",
            body={"new_owner": "dest-org", "expected_version": lc_g["version"], "revoke_collaborators": True},
            extra_headers={"Idempotency-Key": "xfer-gamma-to-org"},
        )
        assert xfer["state"] == "completed" and xfer["to_owner"] == "dest-org", xfer
        assert self.sql(f"SELECT owner_id FROM repositories WHERE id = {quote(gamma['id'])}") == org["id"]
        assert self.sql(f"SELECT count(*) FROM repository_collaborators WHERE repository_id = {quote(gamma['id'])}") == "0"
        assert self.sql(f"SELECT owner_slug FROM workspaces WHERE id = {quote(ws_gamma['id'])}") == "dest-org"

        # Old personal path now emits 308 -> dest-org/gamma for org admin; outsider bob now gets 404.
        self.expect("/api/repos/alice/gamma", 404, token=self.bob)
        st_x, _, hdr_x = self.raw_http("/api/repos/alice/gamma", token=self.alice)
        assert st_x == 308 and hdr_x.get("location") == "/api/repos/dest-org/gamma", (st_x, hdr_x)
        assert self.expect(f"/git/dest-org/gamma.git/info/lfs/objects/{gamma_lfs_oid}/{len(gamma_lfs)}", 200, token=self.alice) == gamma_lfs
        assert self.doc("/api/repos/dest-org/gamma/transfer", 200, token=self.alice)["state"] == "completed"

        # Crash/restart recovery simulation: seed an interrupted in-flight org -> personal transfer on restart.
        rec = self.create_repository({"owner": "dest-org", "name": "recover-me"}, token=self.alice)
        rec_work = self.root / "recover-work"
        self.push_file("dest-org", "recover-me", rec_work, "state.txt", "before crash\n", "main", "seed recover", self.alice)
        lc_r = self.doc("/api/repos/dest-org/recover-me/lifecycle", 200, token=self.alice)

        self.stop(hard=True)
        xfer_id = str(uuid.uuid4())
        self.sql(
            "INSERT INTO repository_transfers "
            "(id, repository_id, from_owner_id, to_owner_id, from_name, to_name, "
            " initiated_by, state, expected_version, revoke_collaborators, keep_alias, copied_objects) "
            f"VALUES ({quote(xfer_id)}, {quote(rec['id'])}, {quote(org['id'])}, {quote(self.alice['user_id'])}, "
            "'recover-me', 'recover-me', "
            f"{quote(self.alice['user_id'])}, 'rekeying_db', {lc_r['version']}, true, true, '[]'::jsonb)"
        )
        self.start()

        deadline = time.monotonic() + 20
        recovered_view = None
        while time.monotonic() < deadline:
            st, body, _ = self.http("/api/repos/alice/recover-me/transfer", token=self.alice)
            if st == 200:
                recovered_view = json.loads(body)
                if recovered_view["state"] == "completed":
                    break
            time.sleep(0.25)
        assert recovered_view and recovered_view["state"] == "completed", recovered_view
        assert self.sql(f"SELECT owner_id FROM repositories WHERE id = {quote(rec['id'])}") == self.alice["user_id"]
        st_rec, _, hdr_rec = self.raw_http("/api/repos/dest-org/recover-me", token=self.alice)
        assert st_rec == 308 and hdr_rec.get("location") == "/api/repos/alice/recover-me", (st_rec, hdr_rec)
        return {"transferred_repo": gamma["id"], "recovered_transfer_id": xfer_id}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    for exe in ("git", "git-lfs", "psql", args.binary):
        if not shutil.which(exe):
            parser.error("Required executable not found: " + exe)
    h = RepositoryLifecycleHarness(args)
    passed = False
    try:
        for name, fn in [
            ("archive_read_write_boundary", h.archive_read_write_boundary),
            ("rename_aliases_and_authz_before_redirect", h.rename_aliases_and_authz_before_redirect),
            ("soft_delete_restore_and_purge_holds", h.soft_delete_restore_and_purge_holds),
            ("ownership_transfer_and_crash_recovery", h.ownership_transfer_and_crash_recovery),
        ]:
            h.case(name, fn)
        passed = True
    except Exception:
        print(h.redact(traceback.format_exc()), file=sys.stderr)
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
