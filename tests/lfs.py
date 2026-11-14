#!/usr/bin/env python3
"""Git LFS Batch API, verified streaming object storage, and paired backup/restore tests."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402
import schema_baseline  # noqa: E402
from lfs_remote_contract import (  # noqa: E402
    cleanup_run_tenant_lfs_prefix,
    configure_metrics_listener,
    run_remote_outage_contract,
)

LFS_MIME = "application/vnd.git-lfs+json"


class LfsHarness(Harness):
    def setup_lfs(self):
        super().setup()
        self.api()
        self.roundtrip()
        self.other = json.loads(
            self.expect("/api/repos", 201, token=self.alice, method="POST", body={"name": "other"})
        )
        self.bob_repo = json.loads(
            self.expect("/api/repos", 201, token=self.bob, method="POST", body={"name": "demo"})
        )
        if self.sql("SELECT to_regclass('lfs_objects') IS NOT NULL") != "t":
            sql_path = Path(__file__).resolve().parents[1] / "src" / "lfs" / "020_lfs_objects.sql"
            self.sql(sql_path.read_text())

    def _rel_path(self, path_or_href):
        if path_or_href.startswith("http://") or path_or_href.startswith("https://"):
            parsed = urllib.parse.urlparse(path_or_href)
            return parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return path_or_href

    def lfs_batch(
        self,
        operation,
        objects,
        repo="demo",
        owner="alice",
        prefix="/git",
        suffix=".git",
        token=None,
        code=200,
    ):
        path = f"{prefix}/{owner}/{repo}{suffix}/info/lfs/objects/batch"
        status, body, headers = self.http(
            path,
            token=token if token is not False else None,
            method="POST",
            body=json.dumps(
                {
                    "operation": operation,
                    "transfers": ["basic"],
                    "objects": objects,
                    "hash_algo": "sha256",
                }
            ).encode(),
            content_type=LFS_MIME,
            extra_headers={"Accept": LFS_MIME},
        )
        norm_headers = {k.lower(): v for k, v in headers.items()}
        if isinstance(code, tuple):
            assert status in code, f"{path}: expected {code}, got {status}: {body[:300]!r}"
        else:
            assert status == code, f"{path}: expected {code}, got {status}: {body[:300]!r}"
        assert norm_headers.get("cache-control") == "no-store", norm_headers
        if status == 200:
            assert LFS_MIME in norm_headers.get("content-type", ""), norm_headers
        return json.loads(body)

    def lfs_put(self, path_or_href, data, token=None, code=200, extra_headers=None):
        path = self._rel_path(path_or_href)
        status, body, headers = self.http(
            path,
            token=token if token is not False else None,
            method="PUT",
            body=data,
            content_type="application/octet-stream",
            extra_headers=extra_headers,
        )
        norm_headers = {k.lower(): v for k, v in headers.items()}
        if isinstance(code, tuple):
            assert status in code, f"PUT {path}: expected {code}, got {status}: {body[:300]!r}"
        else:
            assert status == code, f"PUT {path}: expected {code}, got {status}: {body[:300]!r}"
        return status, body, norm_headers

    def lfs_get(self, path_or_href, token=None, code=200):
        path = self._rel_path(path_or_href)
        status, body, headers = self.http(
            path,
            token=token if token is not False else None,
            method="GET",
        )
        norm_headers = {k.lower(): v for k, v in headers.items()}
        if isinstance(code, tuple):
            assert status in code, f"GET {path}: expected {code}, got {status}: {body[:300]!r}"
        else:
            assert status == code, f"GET {path}: expected {code}, got {status}: {body[:300]!r}"
        return status, body, norm_headers

    def lfs_verify(self, path_or_href, oid, size, token=None, code=200):
        path = self._rel_path(path_or_href)
        status, body, headers = self.http(
            path,
            token=token if token is not False else None,
            method="POST",
            body=json.dumps({"oid": oid, "size": size}).encode(),
            content_type=LFS_MIME,
            extra_headers={"Accept": LFS_MIME},
        )
        norm_headers = {k.lower(): v for k, v in headers.items()}
        if isinstance(code, tuple):
            assert status in code, f"POST {path}: expected {code}, got {status}: {body[:300]!r}"
        else:
            assert status == code, f"POST {path}: expected {code}, got {status}: {body[:300]!r}"
        return json.loads(body)

    def _lfs_lock_http(self, path, token, method="GET", body=None, code=200,
                       extra_headers=None):
        request_headers = {"Accept": LFS_MIME}
        request_headers.update(extra_headers or {})
        status, raw, headers = self.http(
            self._rel_path(path),
            token=token if token is not False else None,
            method=method,
            body=None if body is None else json.dumps(body).encode(),
            content_type=None if body is None else LFS_MIME,
            extra_headers=request_headers,
        )
        norm_headers = {k.lower(): v for k, v in headers.items()}
        expected = code if isinstance(code, tuple) else (code,)
        assert status in expected, (
            f"{method} {path}: expected {code}, got {status}: {raw[:300]!r}"
        )
        assert norm_headers.get("cache-control") == "no-store", norm_headers
        return status, raw, norm_headers

    def _lfs_lock_json(self, path, token, method="GET", body=None, code=200):
        _, raw, headers = self._lfs_lock_http(path, token, method, body, code)
        assert LFS_MIME in headers.get("content-type", ""), headers
        return json.loads(raw)

    def lfs_lock_create(self, base, path, token):
        body = self._lfs_lock_json(base, token, method="POST", body={"path": path}, code=201)
        return body["lock"]

    def lfs_lock_list(self, base, token, path=None, lock_id=None):
        query = {}
        if path is not None:
            query["path"] = path
        if lock_id is not None:
            query["id"] = str(lock_id)
        suffix = "?" + urllib.parse.urlencode(query) if query else ""
        return self._lfs_lock_json(base + suffix, token)

    def lfs_lock_verify(self, base, token):
        return self._lfs_lock_json(base + "/verify", token, method="POST", body={})

    def lfs_lock_unlock(self, base, lock_id, token, force=False):
        body = self._lfs_lock_json(
            f"{base}/{lock_id}/unlock",
            token,
            method="POST",
            body={"force": force},
        )
        return body["lock"]

    def lfs_lock_audit_rows(self, path):
        raw = self.sql(
            "SELECT json_build_object("
            "'actor_id', actor_id::text,"
            "'actor_name', actor_name,"
            "'action', action,"
            "'target_type', target_type,"
            "'target_name', target_name,"
            "'details', details,"
            "'tenant_id', tenant_id::text,"
            "'repository_id', repository_id::text"
            ")::text FROM repository_audit_log "
            f"WHERE repository_id='{self.repo['id']}' AND target_name='{path}' "
            "AND action IN ('lfs_lock.created','lfs_lock.removed') ORDER BY id"
        )
        return [json.loads(row) for row in raw.splitlines()]

    def lfs_lock_idempotency_rows(self, key):
        return int(self.sql(
            "SELECT count(*) FROM forge_creation_requests "
            f"WHERE repository_id='{self.repo['id']}' AND idempotency_key='{key}'"
        ))

    def batch_upload_stream_verify_and_download(self):
        # 64 KiB payload exceeds the global 16 KiB DefaultBodyLimit on JSON routes
        self.payload = os.urandom(64 * 1024)
        self.oid = hashlib.sha256(self.payload).hexdigest()
        self.size = len(self.payload)

        batch_up = self.lfs_batch(
            "upload", [{"oid": self.oid, "size": self.size}], token=self.alice
        )
        assert batch_up["transfer"] == "basic"
        assert len(batch_up["objects"]) == 1
        obj = batch_up["objects"][0]
        assert obj["oid"] == self.oid and obj["size"] == self.size
        upload_action = obj["actions"]["upload"]
        verify_action = obj["actions"]["verify"]

        # Row is initially pending; download before PUT must fail with 404
        db_row = self.sql(
            f"SELECT state || '|' || size FROM lfs_objects WHERE repository_id='{self.repo['id']}' AND oid='{self.oid}'"
        )
        assert db_row == f"pending|{self.size}", db_row
        dl_before = self.lfs_batch(
            "download", [{"oid": self.oid, "size": self.size}], token=self.alice
        )
        assert dl_before["objects"][0]["error"]["code"] == 404
        self.lfs_get(upload_action["href"], token=self.alice, code=404)

        # Stream PUT (also passing action header to test duplicate Authorization header deduplication)
        self.lfs_put(
            upload_action["href"],
            self.payload,
            token=self.alice,
            code=200,
            extra_headers=upload_action.get("header"),
        )

        # Verify on-disk layout & permissions
        self.repo_lfs_dir = self.root / "data" / "lfs" / self.repo["id"]
        self.obj_file = self.repo_lfs_dir / self.oid
        assert self.obj_file.is_file() and not self.obj_file.is_symlink()
        st = self.obj_file.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600, oct(st.st_mode)
        assert st.st_nlink == 1, st.st_nlink
        assert st.st_size == self.size
        assert hashlib.sha256(self.obj_file.read_bytes()).hexdigest() == self.oid
        assert list(self.repo_lfs_dir.glob(".tmp-*")) == []

        # Verify endpoint confirms ready state
        ver = self.lfs_verify(verify_action["href"], self.oid, self.size, token=self.alice, code=200)
        assert ver["verified"] is True

        # Second batch upload deduplicates (omits actions)
        batch_dedup = self.lfs_batch(
            "upload", [{"oid": self.oid, "size": self.size}], token=self.alice
        )
        assert "actions" not in batch_dedup["objects"][0]

        # Download via reader token
        batch_dl = self.lfs_batch(
            "download", [{"oid": self.oid, "size": self.size}], token=self.reader
        )
        dl_action = batch_dl["objects"][0]["actions"]["download"]
        _, body, headers = self.lfs_get(dl_action["href"], token=self.reader, code=200)
        assert body == self.payload
        assert headers.get("content-type") == "application/octet-stream"
        assert headers.get("content-length") == str(self.size)
        assert headers.get("cache-control") == "no-store"
        assert headers.get("x-content-type-options") == "nosniff"

        # Verify route aliases (/alice/demo.git/... and /api/repos/alice/demo/lfs/...)
        alias1 = self.lfs_batch(
            "download",
            [{"oid": self.oid, "size": self.size}],
            prefix="",
            suffix=".git",
            token=self.reader,
        )
        assert "download" in alias1["objects"][0]["actions"]

    def hash_and_size_mismatch_rejection(self):
        good_bytes = b"verified-lfs-object-" * 64
        oid2 = hashlib.sha256(good_bytes).hexdigest()
        size2 = len(good_bytes)

        batch_up = self.lfs_batch("upload", [{"oid": oid2, "size": size2}], token=self.alice)
        href2 = batch_up["objects"][0]["actions"]["upload"]["href"]
        verify_href = batch_up["objects"][0]["actions"]["verify"]["href"]

        # 1. Wrong SHA-256 content with matching length
        bad_content = b"X" * size2
        self.lfs_put(href2, bad_content, token=self.alice, code=(400, 422))
        assert not (self.repo_lfs_dir / oid2).exists()
        assert list(self.repo_lfs_dir.glob(".tmp-*")) == []
        assert (
            self.sql(
                f"SELECT state FROM lfs_objects WHERE repository_id='{self.repo['id']}' AND oid='{oid2}'"
            )
            == "pending"
        )

        # 2. Truncated & oversized body
        self.lfs_put(href2, good_bytes[:-10], token=self.alice, code=(400, 422))
        self.lfs_put(href2, good_bytes + b"extra", token=self.alice, code=(400, 413, 422))
        assert not (self.repo_lfs_dir / oid2).exists()
        assert list(self.repo_lfs_dir.glob(".tmp-*")) == []

        # 3. Verify before valid upload fails
        self.lfs_verify(verify_href, oid2, size2, token=self.alice, code=(404, 422))

        # 4. Retry with valid bytes succeeds
        self.lfs_put(href2, good_bytes, token=self.alice, code=200)
        assert (self.repo_lfs_dir / oid2).read_bytes() == good_bytes
        _, dl_bytes, _ = self.lfs_get(href2, token=self.reader, code=200)
        assert dl_bytes == good_bytes

        # 5. Conflicting size or invalid OID in batch
        mismatch_batch = self.lfs_batch(
            "upload",
            [
                {"oid": oid2, "size": size2 + 99},
                {"oid": "not-a-sha256", "size": 10},
                {"oid": "a" * 64, "size": -5},
            ],
            token=self.alice,
        )
        for item in mismatch_batch["objects"]:
            assert item["error"]["code"] == 422, item

    def permissions_and_tenant_isolation(self):
        # Reader cannot initiate upload, PUT, or verify
        self.lfs_batch(
            "upload", [{"oid": self.oid, "size": self.size}], token=self.reader, code=403
        )
        self.lfs_put(
            f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
            self.payload,
            token=self.reader,
            code=403,
        )
        self.lfs_verify(
            "/git/alice/demo.git/info/lfs/verify",
            self.oid,
            self.size,
            token=self.reader,
            code=403,
        )

        # Cross-tenant Bob gets 404 Not Found
        self.lfs_batch(
            "download", [{"oid": self.oid, "size": self.size}], token=self.bob, code=404
        )
        self.lfs_get(
            f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
            token=self.bob,
            code=404,
        )

        # The repository owner is the LFS tenant even when Bob is the actor.
        self.expect("/api/repos/alice/demo/collaborators/bob", 201, token=self.alice,
                    method="PUT", body={"role": "admin"})
        self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
                     token=self.bob, code=200)
        bob_bytes = b"collaborator upload" * 32
        bob_oid = hashlib.sha256(bob_bytes).hexdigest()
        bob_batch = self.lfs_batch("upload", [{"oid": bob_oid, "size": len(bob_bytes)}], token=self.bob)
        self.lfs_put(bob_batch["objects"][0]["actions"]["upload"]["href"], bob_bytes, token=self.bob)
        self.lfs_verify("/git/alice/demo.git/info/lfs/verify", bob_oid, len(bob_bytes), token=self.bob)
        assert self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{bob_oid}/{len(bob_bytes)}",
                            token=self.alice)[1] == bob_bytes
        self.expect("/api/repos/alice/demo/collaborators/bob", 200, token=self.alice, method="DELETE")
        self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
                     token=self.bob, code=404)

        # Cross-repository isolation within same owner
        other_dl = self.lfs_batch(
            "download",
            [{"oid": self.oid, "size": self.size}],
            repo="other",
            token=self.alice,
        )
        assert other_dl["objects"][0]["error"]["code"] == 404

        # Unauthenticated gets 401
        self.lfs_batch(
            "download", [{"oid": self.oid, "size": self.size}], token=False, code=401
        )
        self.lfs_get(
            f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
            token=False,
            code=401,
        )

        # Repository recovering fence
        self.sql(
            f"UPDATE repositories SET state='recovering', recovery_reason='push_outcome_unknown' WHERE id='{self.repo['id']}'"
        )
        try:
            self.lfs_batch(
                "download", [{"oid": self.oid, "size": self.size}], token=self.alice, code=409
            )
            self.lfs_get(
                f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
                token=self.alice,
                code=409,
            )
        finally:
            self.sql(
                f"UPDATE repositories SET state='ready', recovery_reason=NULL WHERE id='{self.repo['id']}'"
            )

    def _partial_put(self, oid, size, token):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("PUT", f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}")
        conn.putheader("Authorization", "Bearer " + token["token"])
        conn.putheader("Content-Type", "application/octet-stream")
        conn.putheader("Content-Length", str(size))
        conn.endheaders()
        return conn

    def _await_staging(self):
        directory = self.root / "data" / "lfs" / self.repo["id"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if list(directory.glob(".tmp-*")):
                return
            time.sleep(.02)
        raise AssertionError("LFS staging file did not appear")

    def concurrent_upload_revocation(self):
        payload = os.urandom(1024)
        oid = hashlib.sha256(payload).hexdigest()
        self.lfs_batch("upload", [{"oid": oid, "size": len(payload)}], token=self.alice)
        second = self.account("create-token", "alice")
        a = self._partial_put(oid, len(payload), self.alice)
        a.send(payload[:1])
        self._await_staging()
        b = self._partial_put(oid, len(payload), second)
        b.send(payload[:1])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status, body, _ = self.http("/api/repos/alice/demo/lfs/upload-waiters", token=self.alice)
            assert status == 200
            if json.loads(body)["waiters"] >= 1:
                break
            time.sleep(.02)
        else:
            raise AssertionError("second upload did not pass metadata authorization and queue for lock")
        self.sql(f"UPDATE tokens SET revoked=true WHERE id='{second['token_id']}'")
        a.send(payload[1:])
        response_a = a.getresponse()
        assert response_a.status == 200, response_a.read()
        response_a.read()
        a.close()
        response_b = b.getresponse()
        assert response_b.status == 401, response_b.read()
        response_b.read()
        b.close()
        assert self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{oid}/{len(payload)}", token=self.alice)[1] == payload
        assert self.sql(f"SELECT state FROM lfs_objects WHERE repository_id='{self.repo['id']}' AND oid='{oid}'") == "ready"

    def stalled_body_deadline(self):
        self.stop()
        self.env["ROOTYARD_GIT_TIMEOUT_SECONDS"] = "1"
        self.start()
        try:
            for trickle in (False, True):
                payload = os.urandom(1024)
                oid = hashlib.sha256(payload).hexdigest()
                self.lfs_batch("upload", [{"oid": oid, "size": len(payload)}], token=self.alice)
                conn = self._partial_put(oid, len(payload), self.alice)
                conn.send(payload[:1])
                self._await_staging()
                if trickle:
                    for byte in payload[1:5]:
                        time.sleep(.3)
                        try:
                            conn.send(bytes([byte]))
                        except OSError:
                            break
                else:
                    time.sleep(1.3)
                response = conn.getresponse()
                assert response.status == 504, response.read()
                response.read()
                conn.close()
                assert list((self.root / "data" / "lfs" / self.repo["id"]).glob(".tmp-*")) == []
                next_payload = os.urandom(64)
                next_oid = hashlib.sha256(next_payload).hexdigest()
                batch = self.lfs_batch("upload", [{"oid": next_oid, "size": len(next_payload)}], token=self.alice)
                self.lfs_put(batch["objects"][0]["actions"]["upload"]["href"], next_payload, token=self.alice)
        finally:
            self.stop()
            self.env.pop("ROOTYARD_GIT_TIMEOUT_SECONDS", None)
            self.start()

    def corrupted_on_disk_blob_fails_closed(self):
        original = self.obj_file.read_bytes()
        corrupted = bytes([original[0] ^ 0xFF]) + original[1:]
        os.chmod(self.obj_file, 0o600)
        self.obj_file.write_bytes(corrupted)
        # With no remote configured, corruption must fail closed. With a
        # configured remote, the cold path may hydrate a verified copy, but the
        # bytes served must still be the original object, never the tampered
        # local bytes. This keeps the local-failure requirement intact.
        endpoint_configured = bool(self.env.get("ROOTYARD_OBJECT_STORE_ENDPOINT"))
        failure_codes = (422, 500, 503)
        try:
            if endpoint_configured:
                _, recovered, _ = self.lfs_get(
                    f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
                    token=self.reader,
                    code=200,
                )
                assert recovered == original, "remote recovery served unverified bytes"
            else:
                self.lfs_get(
                    f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
                    token=self.reader,
                    code=failure_codes,
                )
            self.lfs_verify(
                "/git/alice/demo.git/info/lfs/verify",
                self.oid,
                self.size,
                token=self.alice,
                code=200 if endpoint_configured else failure_codes,
            )
        finally:
            self.obj_file.write_bytes(original)
            os.chmod(self.obj_file, 0o600)
        _, restored_bytes, _ = self.lfs_get(
            f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
            token=self.reader,
            code=200,
        )
        assert restored_bytes == original

    def stock_lfs_locks(self):
        self.git("lfs", "install", "--local", cwd=self.work)
        lock = self.git("lfs", "lock", "docs/design.bin", cwd=self.work, token=self.alice)
        assert b"Locked docs/design.bin" in lock.stdout
        listed = self.git("lfs", "locks", cwd=self.work, token=self.alice)
        assert b"docs/design.bin" in listed.stdout
        self.stop()
        self.start()
        listed = self.git("lfs", "locks", cwd=self.work, token=self.alice)
        assert b"docs/design.bin" in listed.stdout
        verify = self.http("/git/alice/demo.git/info/lfs/locks/verify", token=self.alice,
                           method="POST", body={}, content_type=LFS_MIME)
        assert verify[0] == 200 and len(json.loads(verify[1])["ours"]) == 1

        # Lock IDs, path filters and verify results are repository-scoped even
        # when one actor administers both repositories. Alice can access
        # alice/other, Bob owns bob/demo, and both repos may lock the same path.
        source_locks = self.repo["clone_path"] + "/info/lfs/locks"
        other_locks = self.other["clone_path"] + "/info/lfs/locks"
        bob_locks = self.bob_repo["clone_path"] + "/info/lfs/locks"
        cross_path = "docs/cross-repo.bin"
        source_lock = self.lfs_lock_create(source_locks, cross_path, self.alice)
        other_lock = self.lfs_lock_create(other_locks, cross_path, self.alice)
        bob_lock = self.lfs_lock_create(bob_locks, cross_path, self.bob)
        assert len({source_lock["id"], other_lock["id"], bob_lock["id"]}) == 3
        scopes = (
            (source_locks, self.alice, source_lock["id"], other_lock["id"]),
            (other_locks, self.alice, other_lock["id"], source_lock["id"]),
            (bob_locks, self.bob, bob_lock["id"], source_lock["id"]),
        )
        for base, token, own_id, foreign_id in scopes:
            listed = self.lfs_lock_list(base, token, path=cross_path)
            assert [lock["id"] for lock in listed["locks"]] == [own_id], listed
            hidden = self.lfs_lock_list(base, token, lock_id=foreign_id)
            assert hidden["locks"] == [], hidden
            verified = self.lfs_lock_verify(base, token)
            ours = [lock["id"] for lock in verified["ours"]]
            visible = ours + [lock["id"] for lock in verified["theirs"]]
            assert own_id in ours, verified
            assert foreign_id not in visible, verified

        # Stock `locks --verify` uses the verify endpoint and marks this
        # repository's locks with O. A same-actor lock with a unique path in
        # another repository must not appear in either CLI mode.
        foreign_path = "docs/other-only.bin"
        foreign_lock = self.lfs_lock_create(other_locks, foreign_path, self.alice)
        design_id = self.lfs_lock_list(
            source_locks, self.alice, path="docs/design.bin"
        )["locks"][0]["id"]
        cli_verify = self.git("lfs", "locks", "--verify", cwd=self.work, token=self.alice)
        cli_lines = cli_verify.stdout.decode().splitlines()
        assert len(cli_lines) == 2, cli_lines
        assert all(line.startswith("O ") for line in cli_lines), cli_lines
        assert {line.split()[1] for line in cli_lines} == {
            "docs/design.bin", cross_path
        }, cli_lines
        assert b"alice" in cli_verify.stdout
        cli_json_result = self.git(
            "lfs", "locks", "--verify", "--json", cwd=self.work, token=self.alice
        )
        cli_json = json.loads(cli_json_result.stdout)
        assert set(cli_json) == {"ours", "theirs"}, cli_json
        assert cli_json["theirs"] == [], cli_json
        assert {lock["id"] for lock in cli_json["ours"]} == {
            design_id, source_lock["id"]
        }, cli_json
        assert {lock["path"] for lock in cli_json["ours"]} == {
            "docs/design.bin", cross_path
        }, cli_json
        assert {lock["owner"]["name"] for lock in cli_json["ours"]} == {"alice"}, cli_json
        for foreign_id in (other_lock["id"], bob_lock["id"], foreign_lock["id"]):
            assert foreign_id.encode() not in cli_verify.stdout, foreign_id
            assert foreign_id.encode() not in cli_json_result.stdout, foreign_id
        assert foreign_path.encode() not in cli_verify.stdout
        assert foreign_path.encode() not in cli_json_result.stdout

        # Force unlock through the wrong repository URL must hide the source
        # lock (404, no path/ID echo), even when the caller owns the other repo.
        for base, token in ((other_locks, self.alice), (bob_locks, self.bob)):
            status, raw, _ = self._lfs_lock_http(
                f"{base}/{source_lock['id']}/unlock",
                token,
                method="POST",
                body={"force": True},
                code=404,
            )
            assert cross_path.encode() not in raw, raw
            assert source_lock["id"].encode() not in raw, raw

        # Rejected cross-repository attempts must leave every lock intact.
        for base, token, own_id in (
            (source_locks, self.alice, source_lock["id"]),
            (other_locks, self.alice, other_lock["id"]),
            (bob_locks, self.bob, bob_lock["id"]),
        ):
            listed = self.lfs_lock_list(base, token, path=cross_path)
            assert [lock["id"] for lock in listed["locks"]] == [own_id], listed

        # The source owner can still unlock by path, and this removes only the
        # source repository's same-path lock.
        unlocked = self.git("lfs", "unlock", cross_path, cwd=self.work, token=self.alice)
        assert b"Unlocked docs/cross-repo.bin" in unlocked.stdout
        assert self.lfs_lock_list(source_locks, self.alice, path=cross_path)["locks"] == []
        assert [
            lock["id"]
            for lock in self.lfs_lock_list(other_locks, self.alice, path=cross_path)["locks"]
        ] == [other_lock["id"]]
        assert [
            lock["id"]
            for lock in self.lfs_lock_list(bob_locks, self.bob, path=cross_path)["locks"]
        ] == [bob_lock["id"]]

        # Authorized owners in the other repositories retain positive unlock
        # control over their own locks.
        for base, lock, token in (
            (other_locks, other_lock, self.alice),
            (other_locks, foreign_lock, self.alice),
            (bob_locks, bob_lock, self.bob),
        ):
            assert self.lfs_lock_unlock(base, lock["id"], token)["id"] == lock["id"]
        assert self.lfs_lock_list(other_locks, self.alice, path=cross_path)["locks"] == []
        assert self.lfs_lock_list(other_locks, self.alice, path=foreign_path)["locks"] == []
        assert self.lfs_lock_list(bob_locks, self.bob, path=cross_path)["locks"] == []

        # Native mutation semantics: same-key replay returns the saved body
        # without a second lock or audit row; reusing the key for another path
        # conflicts; a released path re-locks under a new immutable ID and the
        # stale ID cannot remove the replacement.
        mutation_path = "docs/mutation.bin"
        conflict_path = "docs/mutation-conflict.bin"
        mutation_key = "lfs-mutation-" + self.repo["id"]
        alice_actor_id = self.alice["user_id"]
        bob_actor_id = self.bob["user_id"]
        tenant_id = alice_actor_id
        repo_id = self.repo["id"]
        audit_count_sql = (
            f"SELECT count(*) FROM repository_audit_log WHERE repository_id='{repo_id}'"
        )
        audit_before = int(self.sql(audit_count_sql))
        key_headers = {"Idempotency-Key": mutation_key}
        _, first_raw, _ = self._lfs_lock_http(
            source_locks, self.alice, method="POST", body={"path": mutation_path},
            code=201, extra_headers=key_headers)
        first = json.loads(first_raw)["lock"]
        assert first["id"] and first["path"] == mutation_path
        assert first["owner"] == {"name": "alice"}
        creation_audit = {
            "actor_id": alice_actor_id,
            "actor_name": "alice",
            "action": "lfs_lock.created",
            "target_type": "lfs_lock",
            "target_name": mutation_path,
            "details": {"id": first["id"]},
            "tenant_id": tenant_id,
            "repository_id": repo_id,
        }
        assert self.lfs_lock_audit_rows(mutation_path) == [creation_audit]
        assert self.lfs_lock_idempotency_rows(mutation_key) == 1
        assert int(self.sql(audit_count_sql)) == audit_before + 1

        _, replay_raw, _ = self._lfs_lock_http(
            source_locks, self.alice, method="POST", body={"path": mutation_path},
            code=201, extra_headers=key_headers)
        replay = json.loads(replay_raw)
        assert replay == json.loads(first_raw)
        assert replay["lock"]["id"] == first["id"]
        assert self.lfs_lock_audit_rows(mutation_path) == [creation_audit]
        assert self.lfs_lock_idempotency_rows(mutation_key) == 1
        assert int(self.sql(audit_count_sql)) == audit_before + 1

        _, conflict_raw, _ = self._lfs_lock_http(
            source_locks, self.alice, method="POST", body={"path": conflict_path},
            code=409, extra_headers=key_headers)
        assert conflict_raw
        assert self.lfs_lock_list(source_locks, self.alice, path=conflict_path)["locks"] == []
        assert self.lfs_lock_audit_rows(conflict_path) == []
        assert self.lfs_lock_idempotency_rows(mutation_key) == 1
        assert self.sql(
            "SELECT request->>'path' FROM forge_creation_requests "
            f"WHERE repository_id='{repo_id}' AND idempotency_key='{mutation_key}'"
        ) == mutation_path
        assert int(self.sql(audit_count_sql)) == audit_before + 1

        removed = self.lfs_lock_unlock(source_locks, first["id"], self.alice)
        assert removed["id"] == first["id"]
        owner_removal_audit = {
            "actor_id": alice_actor_id,
            "actor_name": "alice",
            "action": "lfs_lock.removed",
            "target_type": "lfs_lock",
            "target_name": mutation_path,
            "details": {"id": first["id"], "force": False},
            "tenant_id": tenant_id,
            "repository_id": repo_id,
        }
        assert self.lfs_lock_audit_rows(mutation_path) == [
            creation_audit, owner_removal_audit
        ]
        assert int(self.sql(audit_count_sql)) == audit_before + 2

        replacement_key = mutation_key + "-replacement"
        _, replacement_raw, _ = self._lfs_lock_http(
            source_locks, self.alice, method="POST", body={"path": mutation_path},
            code=201, extra_headers={"Idempotency-Key": replacement_key})
        replacement = json.loads(replacement_raw)["lock"]
        assert replacement["id"] != first["id"]
        replacement_create_audit = {
            "actor_id": alice_actor_id,
            "actor_name": "alice",
            "action": "lfs_lock.created",
            "target_type": "lfs_lock",
            "target_name": mutation_path,
            "details": {"id": replacement["id"]},
            "tenant_id": tenant_id,
            "repository_id": repo_id,
        }
        assert [
            lock["id"]
            for lock in self.lfs_lock_list(source_locks, self.alice, path=mutation_path)["locks"]
        ] == [replacement["id"]]
        assert self.lfs_lock_audit_rows(mutation_path) == [
            creation_audit, owner_removal_audit, replacement_create_audit
        ]
        assert self.lfs_lock_idempotency_rows(replacement_key) == 1
        assert int(self.sql(audit_count_sql)) == audit_before + 3

        _, stale_raw, _ = self._lfs_lock_http(
            f"{source_locks}/{first['id']}/unlock", self.alice, method="POST",
            body={"force": False}, code=404)
        assert first["id"].encode() not in stale_raw
        assert mutation_path.encode() not in stale_raw
        assert [
            lock["id"]
            for lock in self.lfs_lock_list(source_locks, self.alice, path=mutation_path)["locks"]
        ] == [replacement["id"]]
        assert self.lfs_lock_audit_rows(mutation_path) == [
            creation_audit, owner_removal_audit, replacement_create_audit
        ]
        assert int(self.sql(audit_count_sql)) == audit_before + 3

        removed_replacement = self.lfs_lock_unlock(
            source_locks, replacement["id"], self.alice)
        assert removed_replacement["id"] == replacement["id"]
        replacement_removal_audit = {
            "actor_id": alice_actor_id,
            "actor_name": "alice",
            "action": "lfs_lock.removed",
            "target_type": "lfs_lock",
            "target_name": mutation_path,
            "details": {"id": replacement["id"], "force": False},
            "tenant_id": tenant_id,
            "repository_id": repo_id,
        }
        assert self.lfs_lock_audit_rows(mutation_path) == [
            creation_audit, owner_removal_audit, replacement_create_audit,
            replacement_removal_audit,
        ]
        assert int(self.sql(audit_count_sql)) == audit_before + 4
        assert self.lfs_lock_list(source_locks, self.alice, path=mutation_path)["locks"] == []

        self.expect("/api/repos/alice/demo/collaborators/bob", 201, token=self.alice,
                    method="PUT", body={"role": "write"})
        denied = self.git("lfs", "unlock", "docs/design.bin", cwd=self.work, token=self.bob, check=False)
        assert denied.returncode != 0
        denied_force = self.git("lfs", "unlock", "--force", "docs/design.bin", cwd=self.work,
                                token=self.bob, check=False)
        assert denied_force.returncode != 0
        self.expect("/api/repos/alice/demo/collaborators/bob", 200, token=self.alice,
                    method="PUT", body={"role": "admin"})
        forced = self.git("lfs", "unlock", "--force", "docs/design.bin", cwd=self.work, token=self.bob)
        assert b"Unlocked docs/design.bin" in forced.stdout
        assert self.lfs_lock_audit_rows("docs/design.bin") == [
            {
                "actor_id": alice_actor_id,
                "actor_name": "alice",
                "action": "lfs_lock.created",
                "target_type": "lfs_lock",
                "target_name": "docs/design.bin",
                "details": {"id": design_id},
                "tenant_id": tenant_id,
                "repository_id": repo_id,
            },
            {
                "actor_id": bob_actor_id,
                "actor_name": "bob",
                "action": "lfs_lock.removed",
                "target_type": "lfs_lock",
                "target_name": "docs/design.bin",
                "details": {"id": design_id, "force": True},
                "tenant_id": tenant_id,
                "repository_id": repo_id,
            },
        ]

        def lock_attempt(_):
            return self.http("/git/alice/demo.git/info/lfs/locks", token=self.alice,
                             method="POST", body={"path": "docs/concurrent.bin"},
                             content_type=LFS_MIME)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(lock_attempt, range(8)))
        assert statuses.count(201) == 1 and statuses.count(409) == 7, statuses
        self.expect("/api/repos/alice/demo/collaborators/bob", 200, token=self.alice, method="DELETE")
        return {
            "same_path_locks_in_three_repositories": 3,
            "cross_repository_force_unlock_denied": 2,
            "cross_repository_id_path_verify_hidden": True,
            "stock_locks_verify_owner_marked": True,
            "stock_locks_verify_foreign_ids_paths_hidden": True,
            "source_owner_unlock": True,
            "other_repository_owner_unlock": True,
            "lock_create_idempotency_replay": True,
            "lock_key_path_conflict_without_rows": True,
            "stale_lock_id_cannot_remove_replacement": True,
            "lock_audit_attributes": True,
        }

    def storage_layout_for_backup(self):
        # Verify volume layout invariants required by src/backup.rs::inventory
        lfs_root = self.root / "data" / "lfs"
        assert lfs_root.is_dir() and not lfs_root.is_symlink()
        assert stat.S_IMODE(lfs_root.stat().st_mode) == 0o700
        for entry in lfs_root.rglob("*"):
            assert not entry.is_symlink(), f"Unexpected symlink in LFS storage: {entry}"
            assert not entry.name.startswith(".tmp-"), f"Leftover staging file: {entry}"
            st = entry.stat()
            if entry.is_dir():
                assert stat.S_IMODE(st.st_mode) == 0o700, oct(st.st_mode)
            else:
                assert stat.S_IMODE(st.st_mode) == 0o600, oct(st.st_mode)
                assert st.st_nlink == 1, st.st_nlink

    def paired_backup_and_restore(self):
        before = self.git("ls-remote", self.remote, token=self.alice).stdout
        before_locks = self.git("lfs", "locks", cwd=self.work, token=self.alice).stdout
        assert b"docs/concurrent.bin" in before_locks
        before_bytes = self.obj_file.read_bytes()
        self.stop()
        dump = self.root / "lfs-metadata.dump"
        self.run(["pg_dump", "--dbname", self.db, "--format=custom",
                  "--schema=" + self.schema, "--file", str(dump)])
        restored = self.root / "restored-data"
        shutil.copytree(self.env["ROOTYARD_DATA_DIR"], restored, symlinks=True)
        # This run's random schema is the only database object removed.
        self.sql('DROP SCHEMA "' + self.schema + '" CASCADE', isolated=False)
        self.run(["pg_restore", "--dbname", self.base_db, "--exit-on-error", str(dump)])
        self.env["ROOTYARD_DATA_DIR"] = str(restored)
        self.start()
        assert self.git("ls-remote", self.remote, token=self.alice).stdout == before
        assert self.git("lfs", "locks", cwd=self.work, token=self.alice).stdout == before_locks
        _, downloaded, _ = self.lfs_get(
            f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
            token=self.reader, code=200)
        assert downloaded == before_bytes
        self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
                     token=self.bob, code=404)
        return {"metadata": "pg_dump/pg_restore of isolated schema",
                "storage": "offline full directory copy", "lfs_bytes_and_locks_preserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--remote-read-contract", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    remote_read_contract = args.remote_read_contract
    if remote_read_contract:
        required_remote_vars = (
            "ROOTYARD_OBJECT_STORE_ENDPOINT",
            "ROOTYARD_OBJECT_STORE_BUCKET",
            "ROOTYARD_OBJECT_STORE_REGION",
            "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
            "ROOTYARD_OBJECT_STORE_SECRET_KEY",
        )
        missing_remote_vars = [
            name for name in required_remote_vars if not os.environ.get(name)
        ]
        if missing_remote_vars:
            parser.error(
                "--remote-read-contract requires nonempty environment variables: "
                + ", ".join(missing_remote_vars)
            )
    harness = LfsHarness(args)
    if remote_read_contract:
        configure_metrics_listener(harness)
    success = False
    try:
        for name in (
            "setup_lfs",
            "batch_upload_stream_verify_and_download",
            "hash_and_size_mismatch_rejection",
            "permissions_and_tenant_isolation",
            "concurrent_upload_revocation",
            "stalled_body_deadline",
            "stock_lfs_locks",
            "corrupted_on_disk_blob_fails_closed",
            "storage_layout_for_backup",
            "paired_backup_and_restore",
        ):
            harness.case(name, getattr(harness, name))
            if name == "setup_lfs" and remote_read_contract:
                harness.case(
                    "remote_read_contract",
                    lambda: run_remote_outage_contract(harness),
                )
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        if (
            os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT")
            and getattr(harness, "repo", None)
        ):
            try:
                deleted = cleanup_run_tenant_lfs_prefix(harness)
            except Exception:
                harness.results.append(
                    dict(
                        name="garage_lfs_cleanup",
                        status="failed",
                        error="garage_lfs_cleanup failed",
                    )
                )
                success = False
            else:
                harness.results.append(
                    dict(
                        name="garage_lfs_cleanup",
                        status="passed",
                        deleted=int((deleted or {}).get("deleted", 0)),
                    )
                )
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(
                dict(name="cleanup", status="failed", error=harness.redact(error))
            )
            success = False
        binary_path = Path(args.binary)
        binary_sha = (
            hashlib.sha256(binary_path.read_bytes()).hexdigest()
            if binary_path.is_file()
            else None
        )
        report = dict(
            passed=success,
            cases=harness.results,
            binary_sha256=binary_sha,
            schema_versions=schema_baseline.SCHEMA_VERSIONS,
            limitations=[
                "Only the Git LFS basic transfer adapter and sha256 object digests are supported.",
                "LFS objects are scoped per repository and subject to repository disk quotas.",
            ],
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
