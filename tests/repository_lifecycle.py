#!/usr/bin/env python3
"""Native E2E acceptance suite for Issue #85 repository archive, rename/308
aliases (authz-before-redirect), soft-delete/restore/fail-closed purge, and
crash-recoverable ownership transfer against the real binary and PostgreSQL."""
import argparse
import base64
import concurrent.futures
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
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
REMOTE_TENANT_LFS_CASE = "remote_tenant_lfs_cold_retention"
OBJECT_STORE_FIELDS = tuple(
    "ROOTYARD_OBJECT_STORE_" + field for field in ("ENDPOINT", "BUCKET", "REGION", "ACCESS_KEY", "SECRET_KEY")
)


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def remote_tenant_lfs_env(environ):
    fixture = {name: environ.get(name, "") for name in OBJECT_STORE_FIELDS}
    if not all(value and value == value.strip() for value in fixture.values()):
        raise ValueError("remote tenant LFS requires explicit object-store fixture settings")
    try:
        endpoint = urllib.parse.urlsplit(fixture["ROOTYARD_OBJECT_STORE_ENDPOINT"])
        port = endpoint.port
    except ValueError:
        raise ValueError("remote tenant LFS requires a loopback HTTP object-store origin") from None
    if not port or fixture["ROOTYARD_OBJECT_STORE_ENDPOINT"] != f"http://127.0.0.1:{port}":
        raise ValueError("remote tenant LFS requires a loopback HTTP object-store origin")
    return fixture


def verify_owned_lfs_cache(root, repository_id, payload, *, evict=False):
    oid = hashlib.sha256(payload).hexdigest()
    uid = os.geteuid()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as owners:
        directory = os.open(root, directory_flags)
        owners.callback(os.close, directory)
        if os.fstat(directory).st_uid != uid:
            raise ValueError("LFS scratch directory is not owned")
        for component in ("data", "lfs", str(uuid.UUID(repository_id))):
            directory = os.open(component, directory_flags, dir_fd=directory)
            owners.callback(os.close, directory)
            if os.fstat(directory).st_uid != uid:
                raise ValueError("LFS cache directory is not owned")
        entry = os.stat(oid, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(entry.st_mode) or entry.st_uid != uid or entry.st_nlink != 1:
            raise ValueError("LFS cache is not an owned regular file")
        fd = os.open(oid, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        owners.callback(os.close, fd)
        if not os.path.samestat(entry, os.fstat(fd)) or os.read(fd, len(payload) + 1) != payload:
            raise ValueError("LFS cache bytes do not match the fixture")
        if evict:
            if not os.path.samestat(entry, os.stat(oid, dir_fd=directory, follow_symlinks=False)):
                raise ValueError("LFS cache was replaced before eviction")
            os.unlink(oid, dir_fd=directory)
            try:
                os.stat(oid, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise ValueError("LFS cache still exists after eviction")


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

        if self.args.remote_tenant_lfs:
            peer_repo = self.create_repository({"owner": "charlie", "name": "purge-peer"}, token=self.charlie)
            alice_tenant, peer_tenant = self.alice["user_id"], self.charlie["user_id"]
            assert alice_tenant != peer_tenant
            peer_payload = b"cross-tenant-purge-lfs-" * 64
            alice_oid = self.batch_upload("alice", "shared-a", peer_payload, self.alice)
            peer_oid = self.batch_upload("charlie", "purge-peer", peer_payload, self.charlie)
            assert alice_oid == peer_oid == hashlib.sha256(peer_payload).hexdigest()
            assert peer_oid != shared_oid
            bindings = self.sql(
                "SELECT repository_id::text || ':' || tenant_id::text || ':' || size::text || ':' || state "
                f"FROM lfs_objects WHERE oid = {quote(peer_oid)}"
            ).splitlines()
            assert set(bindings) == {
                f"{repo_a['id']}:{alice_tenant}:{len(peer_payload)}:ready",
                f"{peer_repo['id']}:{peer_tenant}:{len(peer_payload)}:ready",
            }
            object_path = f"/info/lfs/objects/{peer_oid}/{len(peer_payload)}"
            peer_download = f"/git/charlie/purge-peer.git{object_path}"
            assert self.expect(f"/git/alice/shared-a.git{object_path}", 200, token=self.alice) == peer_payload
            self.expect(peer_download, 404, token=self.alice)
            assert self.expect(peer_download, 200, token=self.charlie) == peer_payload

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

        repo_path = "/api/repos/alice/shared-a2"
        issue_path = f"{repo_path}/issues"
        issue_body = {"title": "Read-only collaborator must not create issues"}
        self.expect(repo_path, 404, token=self.bob)
        self.expect(f"{repo_path}/collaborators/bob", 201, token=self.alice, method="PUT", body={"role": "read"})
        assert self.doc(repo_path, 200, token=self.bob)["id"] == repo_a["id"]
        self.expect(issue_path, 403, token=self.bob, method="POST", body=issue_body)

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
        self.expect(repo_path, 404, token=self.bob)
        self.expect(issue_path, 404, token=self.bob, method="POST", body=issue_body)
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
        assert self.doc(repo_path, 200, token=self.bob)["id"] == repo_a["id"]
        self.expect(issue_path, 403, token=self.bob, method="POST", body=issue_body)

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
        detail = {
            "blocked_hold_kinds": sorted(hold_kinds),
            "purged_repo": repo_a["id"],
            "restored_collaborator_role": "read",
        }
        if self.args.remote_tenant_lfs:
            assert purged["deleted_lfs_keys"] == 1 and purged["preserved_shared_lfs_keys"] == 1
            verify_owned_lfs_cache(self.root, peer_repo["id"], peer_payload, evict=True)
            status, body, _ = self.raw_http(peer_download, token=self.charlie)
            assert status == 200 and body == peer_payload, "cold LFS download did not return the fixture bytes"
            verify_owned_lfs_cache(self.root, peer_repo["id"], peer_payload)
            detail[REMOTE_TENANT_LFS_CASE] = True
        return detail

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

    def issue_scoped_token(self, owner_token, name, grants, read_only=False):
        st, raw, _ = self.http(
            "/api/tokens",
            token=owner_token,
            method="POST",
            body={
                "display_name": name,
                "expires_in_days": 7,
                "read_only": read_only,
                "repository_grants": grants,
                "namespace_grants": [],
            },
        )
        assert st == 201, (st, raw)
        data = json.loads(raw)
        self.secrets.append(data["secret"])
        return {**owner_token, "token": data["secret"], "id": data["id"]}

    def remediation_lifecycle_and_alias_scope_boundaries(self):
        # 1. Archived repos may be unarchived and soft-deleted; idempotency replays after state/version transitions.
        repo = self.create_repository({"owner": "alice", "name": "scope-old"}, token=self.alice)
        arch = self.doc(
            "/api/repos/alice/scope-old/archive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": 1},
            extra_headers={"Idempotency-Key": "rem-arch-1"},
        )
        assert arch["archived"] and arch["version"] == 2, arch
        arch_replay = self.doc(
            "/api/repos/alice/scope-old/archive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": 1},
            extra_headers={"Idempotency-Key": "rem-arch-1"},
        )
        assert arch_replay == arch, (arch_replay, arch)

        unarch = self.doc(
            "/api/repos/alice/scope-old/unarchive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": 2},
            extra_headers={"Idempotency-Key": "rem-unarch-1"},
        )
        assert not unarch["archived"] and unarch["version"] == 3, unarch
        unarch_replay = self.doc(
            "/api/repos/alice/scope-old/unarchive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": 2},
            extra_headers={"Idempotency-Key": "rem-unarch-1"},
        )
        assert unarch_replay == unarch, (unarch_replay, unarch)

        arch2 = self.doc(
            "/api/repos/alice/scope-old/archive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": 3},
            extra_headers={"Idempotency-Key": "rem-arch-2"},
        )
        assert arch2["archived"] and arch2["version"] == 4, arch2

        del_body = {"expected_version": 4, "grace_period_seconds": 600}
        deleted = self.doc(
            "/api/repos/alice/scope-old",
            200,
            token=self.alice,
            method="DELETE",
            body=del_body,
            extra_headers={"Idempotency-Key": "rem-del-arch-1"},
        )
        assert deleted["deleted"] and deleted["version"] == 5, deleted
        del_replay = self.doc(
            "/api/repos/alice/scope-old",
            200,
            token=self.alice,
            method="DELETE",
            body=del_body,
            extra_headers={"Idempotency-Key": "rem-del-arch-1"},
        )
        assert del_replay == deleted, (del_replay, deleted)

        restored = self.doc(
            "/api/repos/alice/scope-old/restore",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": 5},
            extra_headers={"Idempotency-Key": "rem-restore-1"},
        )
        assert not restored["deleted"] and restored["archived"], restored

        unarch2 = self.doc(
            "/api/repos/alice/scope-old/unarchive",
            200,
            token=self.alice,
            method="POST",
            body={"expected_version": restored["version"]},
            extra_headers={"Idempotency-Key": "rem-unarch-2"},
        )
        assert not unarch2["archived"], unarch2

        renamed = self.doc(
            "/api/repos/alice/scope-old/rename",
            200,
            token=self.alice,
            method="POST",
            body={"new_name": "scope-canon", "expected_version": unarch2["version"]},
            extra_headers={"Idempotency-Key": "rem-rename-1"},
        )
        assert renamed["name"] == "scope-canon", renamed

        # 2. Fine-grained Web and LFS alias scope checks before 308 redirect.
        repo_read_tok = self.issue_scoped_token(
            self.alice, "rem-repo-read", [{"repository_id": repo["id"], "actions": ["repo_read"]}]
        )
        repo_read_cookies, _, _ = self.sign_in(username="alice", token=repo_read_tok["token"])
        st_w_ok, _, hdr_w_ok = self.raw_http("/web/repos/alice/scope-old", cookies=repo_read_cookies)
        assert st_w_ok == 308 and hdr_w_ok.get("location") == "/web/repos/alice/scope-canon", (st_w_ok, hdr_w_ok)
        for blocked_web in ("/tree", "/issues", "/pulls", "/audit", "/commits/" + ("0" * 40) + "/checks"):
            st_wb, _, _ = self.raw_http("/web/repos/alice/scope-old" + blocked_web, cookies=repo_read_cookies)
            assert st_wb == 403, (blocked_web, st_wb)

        dummy_oid = "a" * 64
        st_lfs_get, _, _ = self.raw_http(f"/git/alice/scope-old.git/info/lfs/objects/{dummy_oid}", token=repo_read_tok)
        assert st_lfs_get == 403, st_lfs_get

        contents_read_tok = self.issue_scoped_token(
            self.alice, "rem-contents-read", [{"repository_id": repo["id"], "actions": ["contents_read"]}]
        )
        cr_cookies, _, _ = self.sign_in(username="alice", token=contents_read_tok["token"])
        st_tree, _, hdr_tree = self.raw_http("/web/repos/alice/scope-old/tree", cookies=cr_cookies)
        assert st_tree == 308 and hdr_tree.get("location") == "/web/repos/alice/scope-canon/tree", (st_tree, hdr_tree)

        st_dl, _, hdr_dl = self.raw_http(
            "/git/alice/scope-old.git/info/lfs/objects/batch",
            token=contents_read_tok,
            method="POST",
            body=json.dumps({"operation": "download", "objects": [{"oid": dummy_oid, "size": 4}]}).encode(),
            content_type="application/vnd.git-lfs+json",
            extra_headers={"Accept": "application/vnd.git-lfs+json"},
        )
        assert st_dl == 308 and hdr_dl.get("location") == "/git/alice/scope-canon.git/info/lfs/objects/batch", (
            st_dl,
            hdr_dl,
        )

        for method, tail, body_obj in [
            ("POST", "/info/lfs/objects/batch", {"operation": "upload", "objects": [{"oid": dummy_oid, "size": 4}]}),
            ("POST", "/info/lfs/verify", {"oid": dummy_oid, "size": 4}),
            ("POST", "/info/lfs/locks/verify", {}),
        ]:
            st_blk, _, _ = self.raw_http(
                "/git/alice/scope-old.git" + tail,
                token=contents_read_tok,
                method=method,
                body=json.dumps(body_obj).encode(),
                content_type="application/vnd.git-lfs+json",
                extra_headers={"Accept": "application/vnd.git-lfs+json"},
            )
            assert st_blk == 403, (tail, st_blk)

        ro_tok = self.issue_scoped_token(
            self.alice,
            "rem-ro-flag",
            [{"repository_id": repo["id"], "actions": ["contents_read", "contents_write"]}],
            read_only=True,
        )
        st_ro_up, _, _ = self.raw_http(
            "/git/alice/scope-old.git/info/lfs/objects/batch",
            token=ro_tok,
            method="POST",
            body=json.dumps({"operation": "upload", "objects": [{"oid": dummy_oid, "size": 4}]}).encode(),
            content_type="application/vnd.git-lfs+json",
            extra_headers={"Accept": "application/vnd.git-lfs+json"},
        )
        assert st_ro_up == 403, st_ro_up
        return {"scoped_repo": repo["id"]}

    def remediation_fault_injection_and_concurrency(self):
        # 1. Concurrent create_repo vs rename unified reservation constraint (23505 -> 409, zero 500).
        for idx in range(3):
            src_name = f"race-src-{idx}"
            slot_name = f"race-slot-{idx}"
            self.create_repository({"owner": "alice", "name": src_name}, token=self.alice)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                f_create = pool.submit(
                    self.http, "/api/repos", token=self.alice, method="POST", body={"owner": "alice", "name": slot_name}
                )
                f_rename = pool.submit(
                    self.http,
                    f"/api/repos/alice/{src_name}/rename",
                    token=self.alice,
                    method="POST",
                    body={"new_name": slot_name, "expected_version": 1},
                    extra_headers={"Idempotency-Key": f"rem-race-ren-{idx}"},
                )
                c_st, c_raw, _ = f_create.result(timeout=15)
                r_st, r_raw, _ = f_rename.result(timeout=15)
            assert c_st in (200, 201, 409) and r_st in (200, 409), (c_st, c_raw, r_st, r_raw)
            kinds = self.sql(
                "SELECT count(*) FROM repository_name_reservations "
                f"WHERE namespace_id = {quote(self.alice['user_id'])} AND name = {quote(slot_name)}"
            )
            assert kinds == "1", (slot_name, kinds)

        # 2. Active foreign transfer lease non-stealing & lost-COMMIT rekeying_db forward recovery.
        org_id = self.sql("SELECT id FROM namespaces WHERE slug = 'dest-org'")
        assert org_id, "expected dest-org namespace from ownership transfer case"
        lease_repo = self.create_repository({"owner": "alice", "name": "lease-stay"}, token=self.alice)
        stay_xfer = str(uuid.uuid4())
        self.stop()
        self.sql(
            "INSERT INTO repository_transfers "
            "(id, repository_id, from_owner_id, to_owner_id, from_name, to_name, initiated_by, state, "
            " expected_version, revoke_collaborators, keep_alias, copied_objects, lease_owner, lease_until, lease_epoch) "
            f"VALUES ({quote(stay_xfer)}, {quote(lease_repo['id'])}, {quote(self.alice['user_id'])}, {quote(org_id)}, "
            "'lease-stay', 'lease-stay', "
            f"{quote(self.alice['user_id'])}, 'copying_remote', 1, true, true, '[]'::jsonb, "
            "'foreign-live-worker', clock_timestamp() + interval '45 seconds', 7)"
        )
        self.start()
        time.sleep(0.5)
        stay_row = self.sql(
            f"SELECT state || ':' || lease_owner || ':' || lease_epoch::text FROM repository_transfers WHERE id = {quote(stay_xfer)}"
        )
        assert stay_row == "copying_remote:foreign-live-worker:7", stay_row
        self.sql(f"DELETE FROM repository_transfers WHERE id = {quote(stay_xfer)}")

        lost_repo = self.create_repository({"owner": "alice", "name": "lost-ack"}, token=self.alice)
        lost_xfer = str(uuid.uuid4())
        self.stop()
        self.sql(
            f"UPDATE repositories SET owner_id = {quote(org_id)}, version = version + 1 WHERE id = {quote(lost_repo['id'])}"
        )
        self.sql(
            "INSERT INTO repository_transfers "
            "(id, repository_id, from_owner_id, to_owner_id, from_name, to_name, initiated_by, state, "
            " expected_version, revoke_collaborators, keep_alias, copied_objects, lease_owner, lease_until, lease_epoch) "
            f"VALUES ({quote(lost_xfer)}, {quote(lost_repo['id'])}, {quote(self.alice['user_id'])}, {quote(org_id)}, "
            "'lost-ack', 'lost-ack', "
            f"{quote(self.alice['user_id'])}, 'rekeying_db', 1, true, true, '[]'::jsonb, "
            "'crashed-worker', clock_timestamp() - interval '5 minutes', 2)"
        )
        self.start()
        deadline = time.monotonic() + 20
        lost_state = None
        while time.monotonic() < deadline:
            st, body, _ = self.http("/api/repos/dest-org/lost-ack/transfer", token=self.alice)
            if st == 200:
                view = json.loads(body)
                lost_state = view["state"]
                if lost_state == "completed":
                    break
            time.sleep(0.25)
        assert lost_state == "completed", lost_state
        assert self.sql(f"SELECT owner_id FROM repositories WHERE id = {quote(lost_repo['id'])}") == org_id

        # 3. Remote delete claim barrier forces waiting/flushing stale claims before LFS upload reservation.
        claim_repo = self.create_repository({"owner": "alice", "name": "claim-race"}, token=self.alice)
        claim_bytes = b"fresh-upload-never-trust-stale-claim"
        claim_oid = hashlib.sha256(claim_bytes).hexdigest()
        self.sql(
            "INSERT INTO remote_object_delete_claims "
            "(tenant_id, namespace, digest, claim_generation, deleting, lease_until) "
            f"VALUES ({quote(self.alice['user_id'])}, 'lfs', {quote(claim_oid)}, 1, true, "
            "clock_timestamp() + interval '1 second') "
            "ON CONFLICT (tenant_id, namespace, digest) DO UPDATE SET "
            "claim_generation = remote_object_delete_claims.claim_generation + 1, "
            "deleting = true, lease_until = clock_timestamp() + interval '1 second'"
        )
        st_b, raw_b, _ = self.http(
            "/git/alice/claim-race.git/info/lfs/objects/batch",
            token=self.alice,
            method="POST",
            body={
                "operation": "upload",
                "transfers": ["basic"],
                "objects": [{"oid": claim_oid, "size": len(claim_bytes)}],
                "hash_algo": "sha256",
            },
            content_type="application/vnd.git-lfs+json",
            extra_headers={"Accept": "application/vnd.git-lfs+json"},
        )
        assert st_b == 200, (st_b, raw_b)
        obj_resp = json.loads(raw_b)["objects"][0]
        assert "upload" in obj_resp.get("actions", {}), obj_resp
        claim_after = self.sql(
            "SELECT deleting::text || ':' || claim_generation::text FROM remote_object_delete_claims "
            f"WHERE tenant_id = {quote(self.alice['user_id'])} AND namespace = 'lfs' AND digest = {quote(claim_oid)}"
        )
        assert claim_after == "false:2", claim_after

        # 4. Transfer drain waits beyond 1.5s for valid write admission while ignoring expired admissions.
        drain_repo = self.create_repository({"owner": "alice", "name": "drain-guard"}, token=self.alice)
        exp_id = str(uuid.uuid4())
        live_id = str(uuid.uuid4())
        owner_uuid = str(uuid.uuid4())
        self.sql(
            "INSERT INTO storage_write_admissions "
            "(id, repository_id, gc_epoch, owner, kind, state, lease_until) VALUES "
            f"({quote(exp_id)}, {quote(drain_repo['id'])}, 0, {quote(owner_uuid)}, 'workspace_publish', 'active', "
            "clock_timestamp() - interval '5 seconds'), "
            f"({quote(live_id)}, {quote(drain_repo['id'])}, 0, {quote(owner_uuid)}, 'workspace_publish', 'active', "
            "clock_timestamp() + interval '2200 milliseconds')"
        )
        xfer_view = self.doc(
            "/api/repos/alice/drain-guard/transfer",
            200,
            token=self.alice,
            method="POST",
            body={"new_owner": "dest-org", "expected_version": 1},
            extra_headers={"Idempotency-Key": "rem-drain-wait"},
        )
        assert xfer_view["state"] == "completed", xfer_view
        return {"lost_ack_repo": lost_repo["id"], "drain_transfer_id": xfer_view["transfer_id"]}

    def remediation_alias_parity_and_uncertain_claim_fail_closed(self):
        # 1. Seed a real PR on an aliased repository so alias prechecks match canonical handlers end-to-end.
        repo = self.create_repository({"owner": "alice", "name": "parity-old"}, token=self.alice)
        work = self.root / "parity-work"
        self.push_file("alice", "parity-old", work, "README.md", "base\n", "main", "base commit", self.alice)
        self.git("checkout", "-b", "feature", cwd=work)
        (work / "feat.txt").write_text("feature\n")
        self.git("add", "feat.txt", cwd=work)
        self.git("commit", "-m", "feature commit", cwd=work)
        self.git("push", "-u", "origin", "feature", cwd=work, token=self.alice)
        head_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        pr = self.doc(
            "/api/repos/alice/parity-old/pulls",
            201,
            token=self.alice,
            method="POST",
            body={
                "title": "Parity review test",
                "body": "alias precheck parity",
                "head_ref": "refs/heads/feature",
                "base_ref": "refs/heads/main",
            },
        )
        pr_num = pr["number"]

        self.expect(
            "/api/repos/alice/parity-old/collaborators/bob",
            201,
            token=self.alice,
            method="PUT",
            body={"role": "triage"},
        )
        self.expect(
            "/api/repos/alice/parity-old/collaborators/charlie",
            201,
            token=self.alice,
            method="PUT",
            body={"role": "write"},
        )
        self.doc(
            "/api/repos/alice/parity-old/rename",
            200,
            token=self.alice,
            method="POST",
            body={"new_name": "parity-canon", "expected_version": 1},
            extra_headers={"Idempotency-Key": "parity-rename-1"},
        )

        # Triage cannot mint a scoped `pulls_write` grant (`repository_min_role(PullsWrite) == Write`),
        # so triage alias review checks use bob's unscoped PAT while `bob_triage_repo_r` verifies missing scope 403.
        st_bad_grant, _, _ = self.http(
            "/api/tokens",
            token=self.bob,
            method="POST",
            body={
                "display_name": "par-bob-pw-denied",
                "expires_in_days": 7,
                "read_only": False,
                "repository_grants": [{"repository_id": repo["id"], "actions": ["pulls_write"]}],
                "namespace_grants": [],
            },
        )
        assert st_bad_grant == 403, st_bad_grant
        bob_triage_repo_r = self.issue_scoped_token(
            self.bob, "par-bob-rr", [{"repository_id": repo["id"], "actions": ["repo_read"]}]
        )
        charlie_write_pulls_w = self.issue_scoped_token(
            self.charlie, "par-ch-pw", [{"repository_id": repo["id"], "actions": ["pulls_write"]}]
        )
        alice_repo_r = self.issue_scoped_token(
            self.alice, "par-al-rr", [{"repository_id": repo["id"], "actions": ["repo_read"]}]
        )
        alice_contents_r = self.issue_scoped_token(
            self.alice, "par-al-cr", [{"repository_id": repo["id"], "actions": ["contents_read"]}]
        )
        alice_pulls_r = self.issue_scoped_token(
            self.alice, "par-al-pr", [{"repository_id": repo["id"], "actions": ["pulls_read"]}]
        )
        alice_admin_only = self.issue_scoped_token(
            self.alice, "par-al-admin", [{"repository_id": repo["id"], "actions": ["repo_admin"]}]
        )

        # Reviews: triage allowed only for state=commented across API, /web, and /ui;
        # approved/changes_requested require Role::Write+pulls_write; oversized (>64KiB) -> 413 after auth.
        comment_body = {"state": "commented", "commit_oid": head_oid, "body": "lgtm comment"}
        approve_body = {"state": "approved", "commit_oid": head_oid, "body": "approved"}
        changes_body = {"state": "changes_requested", "commit_oid": head_oid, "body": "fix please"}

        st_api_triage_c, _, hdr_api_c = self.raw_http(
            f"/api/repos/alice/parity-old/pulls/{pr_num}/reviews",
            token=self.bob,
            method="POST",
            body=comment_body,
        )
        assert st_api_triage_c == 308 and hdr_api_c.get("location") == (
            f"/api/repos/alice/parity-canon/pulls/{pr_num}/reviews"
        ), (st_api_triage_c, hdr_api_c)
        self.doc(hdr_api_c["location"], 201, token=self.bob, method="POST", body=comment_body)

        for denied_body in (approve_body, changes_body):
            st_deny, _, _ = self.raw_http(
                f"/api/repos/alice/parity-old/pulls/{pr_num}/reviews",
                token=self.bob,
                method="POST",
                body=denied_body,
            )
            assert st_deny == 403, (denied_body["state"], st_deny)

        st_no_scope, _, _ = self.raw_http(
            f"/api/repos/alice/parity-old/pulls/{pr_num}/reviews",
            token=bob_triage_repo_r,
            method="POST",
            body=comment_body,
        )
        assert st_no_scope == 403, st_no_scope

        st_api_write_a, _, hdr_api_a = self.raw_http(
            f"/api/repos/alice/parity-old/pulls/{pr_num}/reviews",
            token=charlie_write_pulls_w,
            method="POST",
            body=approve_body,
        )
        assert st_api_write_a == 308 and hdr_api_a.get("location") == (
            f"/api/repos/alice/parity-canon/pulls/{pr_num}/reviews"
        ), (st_api_write_a, hdr_api_a)

        oversized_review = json.dumps(
            {"state": "commented", "commit_oid": head_oid, "body": "x" * (65 * 1024)}
        ).encode()
        st_unauth_big, _, _ = self.raw_http(
            f"/api/repos/alice/parity-old/pulls/{pr_num}/reviews",
            token={**self.alice, "token": "ryt_invalid_token_before_body_read"},
            method="POST",
            body=oversized_review,
            content_type="application/json",
        )
        assert st_unauth_big in (401, 403), st_unauth_big

        st_auth_big, _, _ = self.raw_http(
            f"/api/repos/alice/parity-old/pulls/{pr_num}/reviews",
            token=charlie_write_pulls_w,
            method="POST",
            body=oversized_review,
            content_type="application/json",
        )
        assert st_auth_big == 413, st_auth_big

        st_bad_state, _, _ = self.raw_http(
            f"/api/repos/alice/parity-old/pulls/{pr_num}/reviews",
            token=charlie_write_pulls_w,
            method="POST",
            body={"state": "invalid_state", "commit_oid": head_oid, "body": "x"},
        )
        assert st_bad_state == 400, st_bad_state

        bob_cookies, _, _ = self.sign_in(username="bob", token=self.bob["token"])
        bob_web_hdrs = {"Origin": self.base, "x-csrf-token": bob_cookies["rootyard_csrf"]}
        charlie_cookies, _, _ = self.sign_in(username="charlie", token=charlie_write_pulls_w["token"])
        charlie_web_hdrs = {"Origin": self.base, "x-csrf-token": charlie_cookies["rootyard_csrf"]}

        for web_prefix in ("/web", "/ui"):
            st_wc, _, hdr_wc = self.raw_http(
                f"{web_prefix}/repos/alice/parity-old/pulls/{pr_num}/reviews",
                cookies=bob_cookies,
                method="POST",
                body=comment_body,
                extra_headers=bob_web_hdrs,
            )
            assert st_wc == 308 and hdr_wc.get("location") == (
                f"{web_prefix}/repos/alice/parity-canon/pulls/{pr_num}/reviews"
            ), (web_prefix, st_wc, hdr_wc)
            st_wa_deny, _, _ = self.raw_http(
                f"{web_prefix}/repos/alice/parity-old/pulls/{pr_num}/reviews",
                cookies=bob_cookies,
                method="POST",
                body=approve_body,
                extra_headers=bob_web_hdrs,
            )
            assert st_wa_deny == 403, (web_prefix, st_wa_deny)
            st_wc_allow, _, hdr_wc_a = self.raw_http(
                f"{web_prefix}/repos/alice/parity-old/pulls/{pr_num}/reviews",
                cookies=charlie_cookies,
                method="POST",
                body=approve_body,
                extra_headers=charlie_web_hdrs,
            )
            assert st_wc_allow == 308 and hdr_wc_a.get("location") == (
                f"{web_prefix}/repos/alice/parity-canon/pulls/{pr_num}/reviews"
            ), (web_prefix, st_wc_allow, hdr_wc_a)

        st_web_big, _, _ = self.raw_http(
            f"/web/repos/alice/parity-old/pulls/{pr_num}/reviews",
            cookies=charlie_cookies,
            method="POST",
            body=oversized_review,
            content_type="application/json",
            extra_headers=charlie_web_hdrs,
        )
        assert st_web_big == 413, st_web_big

        # LFS upload-waiters requires (Role::Admin, RepoAction::RepoRead).
        st_wait_ok, _, hdr_wait = self.raw_http(
            "/api/repos/alice/parity-old/lfs/upload-waiters", token=alice_repo_r
        )
        assert st_wait_ok == 308 and hdr_wait.get("location") == "/api/repos/alice/parity-canon/lfs/upload-waiters", (
            st_wait_ok,
            hdr_wait,
        )
        self.doc(hdr_wait["location"], 200, token=alice_repo_r)
        for bad_wait_tok in (alice_contents_r, charlie_write_pulls_w):
            st_w_deny, _, _ = self.raw_http("/api/repos/alice/parity-old/lfs/upload-waiters", token=bad_wait_tok)
            assert st_w_deny == 403, st_w_deny

        # Branch rules: GET -> (Read, PullsRead); mutating POST/PUT/DELETE -> (Maintain, PullsWrite).
        st_br_get, _, hdr_br = self.raw_http("/api/repos/alice/parity-old/branch-rules", token=alice_pulls_r)
        assert st_br_get == 308 and hdr_br.get("location") == "/api/repos/alice/parity-canon/branch-rules", (
            st_br_get,
            hdr_br,
        )
        self.doc(hdr_br["location"], 200, token=alice_pulls_r)
        st_br_deny_r, _, _ = self.raw_http("/api/repos/alice/parity-old/branch-rules", token=alice_repo_r)
        assert st_br_deny_r == 403, st_br_deny_r

        rule_body = {"branch_ref": "refs/heads/main", "required_approvals": 1, "required_checks": []}
        st_br_write_deny, _, _ = self.raw_http(
            "/api/repos/alice/parity-old/branch-rules",
            token=charlie_write_pulls_w,
            method="POST",
            body=rule_body,
        )
        assert st_br_write_deny == 403, st_br_write_deny

        st_br_admin_only, _, _ = self.raw_http(
            "/api/repos/alice/parity-old/branch-rules",
            token=alice_admin_only,
            method="POST",
            body=rule_body,
        )
        assert st_br_admin_only == 403, st_br_admin_only

        self.expect(
            "/api/repos/alice/parity-canon/collaborators/charlie",
            200,
            token=self.alice,
            method="PUT",
            body={"role": "maintain"},
        )
        st_br_maint_post, _, hdr_br_post = self.raw_http(
            "/api/repos/alice/parity-old/branch-rules",
            token=charlie_write_pulls_w,
            method="POST",
            body=rule_body,
        )
        assert st_br_maint_post == 308 and hdr_br_post.get("location") == "/api/repos/alice/parity-canon/branch-rules", (
            st_br_maint_post,
            hdr_br_post,
        )
        self.doc(hdr_br_post["location"], (200, 201), token=charlie_write_pulls_w, method="POST", body=rule_body)
        for m_rule in ("PUT", "DELETE"):
            st_m, _, hdr_m = self.raw_http(
                "/api/repos/alice/parity-old/branch-rules/main",
                token=charlie_write_pulls_w,
                method=m_rule,
                body=rule_body if m_rule == "PUT" else None,
            )
            assert st_m == 308 and hdr_m.get("location") == "/api/repos/alice/parity-canon/branch-rules/main", (
                m_rule,
                st_m,
                hdr_m,
            )

        # 2. Uncertain delete claim remains permanently fenced fail-closed (503) across lease expiry and restart recovery.
        uncertain_oid = hashlib.sha256(b"uncertain-delete-fail-closed-oid").hexdigest()
        self.sql(
            "INSERT INTO remote_object_delete_claims "
            "(tenant_id, namespace, digest, claim_generation, deleting, delete_uncertain, lease_until) "
            f"VALUES ({quote(self.alice['user_id'])}, 'lfs', {quote(uncertain_oid)}, 1, true, true, "
            "clock_timestamp() - interval '10 seconds') "
            "ON CONFLICT (tenant_id, namespace, digest) DO UPDATE SET "
            "deleting = true, delete_uncertain = true, lease_until = clock_timestamp() - interval '10 seconds'"
        )
        st_u_batch, raw_u_batch, _ = self.http(
            "/git/alice/parity-canon.git/info/lfs/objects/batch",
            token=self.alice,
            method="POST",
            content_type=LFS_MIME,
            extra_headers={"Accept": LFS_MIME},
            body=json.dumps({
                "operation": "upload",
                "transfers": ["basic"],
                "objects": [{"oid": uncertain_oid, "size": 32}],
                "hash_algo": "sha256",
            }).encode(),
        )
        assert st_u_batch == 503, (st_u_batch, raw_u_batch)
        st_u_put, raw_u_put, _ = self.http(
            f"/git/alice/parity-canon.git/info/lfs/objects/{uncertain_oid}",
            token=self.alice,
            method="PUT",
            body=b"uncertain-delete-fail-closed-oid",
            content_type="application/octet-stream",
        )
        assert st_u_put == 503, (st_u_put, raw_u_put)
        assert (
            self.sql(
                "SELECT deleting::text || ':' || delete_uncertain::text FROM remote_object_delete_claims "
                f"WHERE tenant_id = {quote(self.alice['user_id'])} AND namespace = 'lfs' "
                f"AND digest = {quote(uncertain_oid)}"
            )
            == "true:true"
        )

        # Restart recovery sweeps ONLY unstarted expired claims (`delete_uncertain = false`);
        # uncertain claims across LFS and workspace MUST stay permanently fail-closed (`true:true:1` & 503).
        ws_uncertain = hashlib.sha256(b"uncertain-ws-fail-closed-digest").hexdigest()
        ws_clean_stale = hashlib.sha256(b"clean-unstarted-ws-stale-digest").hexdigest()
        self.stop(hard=True)
        self.sql(
            "INSERT INTO remote_object_delete_claims "
            "(tenant_id, namespace, digest, claim_generation, deleting, delete_uncertain, lease_until) VALUES "
            f"({quote(self.alice['user_id'])}, 'workspace', {quote(ws_uncertain)}, 1, true, true, "
            "clock_timestamp() - interval '10 seconds'), "
            f"({quote(self.alice['user_id'])}, 'workspace', {quote(ws_clean_stale)}, 1, true, false, "
            "clock_timestamp() - interval '10 seconds') "
            "ON CONFLICT (tenant_id, namespace, digest) DO UPDATE SET "
            "claim_generation = 1, deleting = true, delete_uncertain = EXCLUDED.delete_uncertain, "
            "lease_until = EXCLUDED.lease_until"
        )
        self.start()
        rec_deadline = time.monotonic() + 15
        clean_state = None
        while time.monotonic() < rec_deadline:
            clean_state = self.sql(
                "SELECT deleting::text || ':' || delete_uncertain::text || ':' || claim_generation::text "
                "FROM remote_object_delete_claims "
                f"WHERE tenant_id = {quote(self.alice['user_id'])} AND namespace = 'workspace' "
                f"AND digest = {quote(ws_clean_stale)}"
            )
            if clean_state == "false:false:2":
                break
            time.sleep(0.25)
        assert clean_state == "false:false:2", clean_state

        for ns, dig in (("lfs", uncertain_oid), ("workspace", ws_uncertain)):
            st_row = self.sql(
                "SELECT deleting::text || ':' || delete_uncertain::text || ':' || claim_generation::text "
                "FROM remote_object_delete_claims "
                f"WHERE tenant_id = {quote(self.alice['user_id'])} AND namespace = {quote(ns)} AND digest = {quote(dig)}"
            )
            assert st_row == "true:true:1", (ns, dig, st_row)

        st_u_after, _, _ = self.http(
            f"/git/alice/parity-canon.git/info/lfs/objects/{uncertain_oid}",
            token=self.alice,
            method="PUT",
            body=b"uncertain-delete-fail-closed-oid",
            content_type="application/octet-stream",
        )
        assert st_u_after == 503, st_u_after
        self.sql(
            "DELETE FROM remote_object_delete_claims "
            f"WHERE tenant_id = {quote(self.alice['user_id'])} AND digest IN ({quote(uncertain_oid)}, {quote(ws_uncertain)})"
        )
        return {"parity_repo": repo["id"], "ws_uncertain_kept_closed": ws_uncertain}


def run_remote_tenant_lfs(args, fixture):
    h = None
    passed = False
    binary_sha256 = source_head = None
    try:
        binary_sha256 = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
        head = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"], cwd=TESTS_DIR.parent,
            capture_output=True, check=True, text=True, timeout=5,
        ).stdout.strip()
        if len(head) != 40 or any(char not in "0123456789abcdef" for char in head):
            raise ValueError("remote tenant LFS source commit is invalid")
        source_head = head
        h = RepositoryLifecycleHarness(args)
        h.env = {
            name: value for name, value in h.env.items()
            if not name.startswith(("AWS_", "ROOTYARD_OBJECT_STORE_"))
        }
        h.env.update(fixture)
        h.setup()
        h.charlie = h.account("create-user", "charlie")
        passed = h.soft_delete_restore_and_purge_holds().get(REMOTE_TENANT_LFS_CASE) is True
    except Exception:
        print("remote tenant LFS qualification failed", file=sys.stderr)
    finally:
        if h is not None:
            try:
                h.cleanup()
            except Exception:
                passed = False
                print("remote tenant LFS scratch cleanup failed", file=sys.stderr)
    report = {
        "passed": passed,
        "cases": [{
            "name": REMOTE_TENANT_LFS_CASE,
            "status": "passed" if passed else "failed",
            "detail": {REMOTE_TENANT_LFS_CASE: passed},
        }],
        "binary_sha256": binary_sha256,
        "source_head": source_head,
    }
    try:
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
    except OSError:
        print("remote tenant LFS report write failed", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument(
        "--remote-tenant-lfs", action="store_true",
        help="Run only the soft-delete case with an explicit loopback object-store fixture",
    )
    args = parser.parse_args()
    fixture = None
    if args.remote_tenant_lfs:
        if args.keep or not __debug__:
            parser.error("--remote-tenant-lfs requires scratch cleanup and enabled assertions")
        try:
            fixture = remote_tenant_lfs_env(os.environ)
        except ValueError as exc:
            parser.error(str(exc))
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    for exe in ("git", "git-lfs", "psql", args.binary):
        if not shutil.which(exe):
            parser.error("Required executable not found: " + exe)
    if fixture is not None:
        return run_remote_tenant_lfs(args, fixture)
    h = RepositoryLifecycleHarness(args)
    passed = False
    try:
        for name, fn in [
            ("archive_read_write_boundary", h.archive_read_write_boundary),
            ("rename_aliases_and_authz_before_redirect", h.rename_aliases_and_authz_before_redirect),
            ("soft_delete_restore_and_purge_holds", h.soft_delete_restore_and_purge_holds),
            ("ownership_transfer_and_crash_recovery", h.ownership_transfer_and_crash_recovery),
            ("remediation_lifecycle_and_alias_scope_boundaries", h.remediation_lifecycle_and_alias_scope_boundaries),
            ("remediation_fault_injection_and_concurrency", h.remediation_fault_injection_and_concurrency),
            (
                "remediation_alias_parity_and_uncertain_claim_fail_closed",
                h.remediation_alias_parity_and_uncertain_claim_fail_closed,
            ),
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
