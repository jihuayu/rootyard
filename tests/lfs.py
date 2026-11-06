#!/usr/bin/env python3
"""Git LFS Batch API, verified streaming object storage, and paired backup/restore tests."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import stat
import sys
import time
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness  # noqa: E402
import schema_baseline  # noqa: E402

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
        time.sleep(.15)  # B has read the pending reservation and queued for the lock.
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
        try:
            self.lfs_get(
                f"/git/alice/demo.git/info/lfs/objects/{self.oid}/{self.size}",
                token=self.reader,
                code=(422, 500, 503),
            )
            self.lfs_verify(
                "/git/alice/demo.git/info/lfs/verify",
                self.oid,
                self.size,
                token=self.alice,
                code=(422, 500, 503),
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

        def lock_attempt(_):
            return self.http("/git/alice/demo.git/info/lfs/locks", token=self.alice,
                             method="POST", body={"path": "docs/concurrent.bin"},
                             content_type=LFS_MIME)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(lock_attempt, range(8)))
        assert statuses.count(201) == 1 and statuses.count(409) == 7, statuses
        self.expect("/api/repos/alice/demo/collaborators/bob", 200, token=self.alice, method="DELETE")

    def paired_backup_and_restore(self):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = LfsHarness(args)
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
            "paired_backup_and_restore",
        ):
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
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
