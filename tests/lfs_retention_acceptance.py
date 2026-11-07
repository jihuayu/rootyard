#!/usr/bin/env python3
"""Focused native acceptance for LFS publication compatibility (#40) and
committed-object retention under failed/permission-removed clients (#39).

Runs a real Rust binary, PostgreSQL 17, stock git and stock git-lfs clients on
loopback. No object-store endpoint is configured; remote-store coverage lives
in tests/lfs_remote.py and tests/backup_capabilities.py --remote-lfs.
"""
import argparse
import hashlib
import json
import os
import stat
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lfs import LfsHarness


class RetentionHarness(LfsHarness):
    def _fixture(self):
        if not getattr(self, "_fixture_ready", False):
            self.setup_lfs()
            self._fixture_ready = True

    def valid_and_compatible_publication(self):
        self._fixture()
        self.git("lfs", "install", "--local", cwd=self.work)
        self.git("lfs", "track", "*.dat", cwd=self.work)
        payload = os.urandom(256 * 1024)
        oid = hashlib.sha256(payload).hexdigest()
        (self.work / "tracked.dat").write_bytes(payload)
        self.git("add", ".gitattributes", "tracked.dat", cwd=self.work)
        self.git("commit", "-m", "stock LFS pointer commit", cwd=self.work)
        head = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        # The stock client uploads bytes and publishes the pointer in one push.
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", "refs/heads/main"
                        ).stdout.decode().strip() == head
        assert self.sql("SELECT state FROM lfs_objects WHERE repository_id='"
                        f"{self.repo['id']}' AND oid='{oid}'") == "ready"
        stored = Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / self.repo["id"] / oid
        assert stored.is_file() and hashlib.sha256(stored.read_bytes()).hexdigest() == oid
        clone = self.root / "stock-clone"
        self.git("clone", self.remote, str(clone), token=self.alice)
        self.git("lfs", "install", "--local", cwd=clone)
        self.git("lfs", "pull", cwd=clone, token=self.alice)
        assert (clone / "tracked.dat").read_bytes() == payload

        # Repository without LFS content: ordinary and atomic multi-ref pushes
        # must pass the bounded pointer inspection unchanged.
        other = self.root / "plain-work"
        self.git("clone", self.base + "/git/alice/other.git", str(other), token=self.alice)
        self.git("config", "user.name", "Alice", cwd=other)
        self.git("config", "user.email", "alice@rootyard.local", cwd=other)
        (other / "src").mkdir()
        for index in range(300):
            (other / "src" / f"f{index:04d}.txt").write_text(f"plain {index}\n")
        self.git("add", "src", cwd=other)
        self.git("commit", "-m", "300 small non-LFS files", cwd=other)
        self.git("push", "origin", "HEAD:main", cwd=other, token=self.alice)
        self.git("push", "--atomic", "origin", "HEAD:refs/heads/one",
                 "HEAD:refs/heads/two", cwd=other, token=self.alice)
        refs = self.git("ls-remote", self.base + "/git/alice/other.git",
                        token=self.alice).stdout
        assert b"refs/heads/one" in refs and b"refs/heads/two" in refs

        # Previously retained history: a tag of an already-published pointer
        # commit and a new non-LFS commit on top must both publish.
        self.git("tag", "lfs-v1", head, cwd=self.work)
        self.git("push", "origin", "refs/tags/lfs-v1", cwd=self.work, token=self.alice)
        (self.work / "notes.txt").write_text("advance\n")
        self.git("add", "notes.txt", cwd=self.work)
        self.git("commit", "-m", "advance retained pointer history", cwd=self.work)
        self.git("push", "origin", "HEAD:refs/heads/advance", cwd=self.work, token=self.alice)
        _, body, _ = self.lfs_get(
            f"/git/alice/demo.git/info/lfs/objects/{oid}/{len(payload)}",
            token=self.alice, code=200)
        assert body == payload
        return {"stock_lfs_push": True, "ready_row": True, "non_lfs_files": 300,
                "non_lfs_plain_push": True, "atomic_multi_ref_push": True,
                "retained_history_tag": "refs/tags/lfs-v1",
                "retained_history_advance": "refs/heads/advance",
                "pointer_object_still_downloadable": True}

    def committed_bytes_survive_failed_duplicates_and_permission_removal(self):
        self._fixture()
        payload = os.urandom(64 * 1024)
        oid = hashlib.sha256(payload).hexdigest()
        size = len(payload)
        batch = self.lfs_batch("upload", [{"oid": oid, "size": size}], token=self.alice)
        href = batch["objects"][0]["actions"]["upload"]["href"]
        object_file = Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / self.repo["id"] / oid
        self.lfs_put(href, payload, token=self.alice, code=200)
        assert object_file.is_file() and hashlib.sha256(object_file.read_bytes()).hexdigest() == oid

        # A duplicate client that uploads wrong bytes must fail without deleting
        # or rewriting the already committed object.
        # A ready object short-circuits duplicate uploads before the body is
        # read (idempotent re-upload); the committed digest must not change.
        corrupt = bytes([payload[0] ^ 0xFF]) + payload[1:]
        self.lfs_put(f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}",
                     corrupt, token=self.alice, code=(200, 422))
        # An interrupted duplicate connection must also leave the winner intact.
        conn = self._partial_put(oid, size, self.alice)
        conn.send(payload[:8])
        conn.close()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not list(object_file.parent.glob(".tmp-*")):
                break
            time.sleep(.05)
        meta = object_file.stat()
        assert stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1, oct(meta.st_mode)
        assert hashlib.sha256(object_file.read_bytes()).hexdigest() == oid
        assert self.sql("SELECT state FROM lfs_objects WHERE repository_id='"
                        f"{self.repo['id']}' AND oid='{oid}'") == "ready"
        _, body, _ = self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}",
                                  token=self.alice, code=200)
        assert body == payload

        # Removing a collaborator denies new reads; the committed bytes stay
        # retained so a re-granted collaborator reads the identical content.
        self.expect("/api/repos/alice/demo/collaborators/bob", 201, token=self.alice,
                    method="PUT", body={"role": "read"})
        assert self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}",
                            token=self.bob, code=200)[1] == payload
        self.expect("/api/repos/alice/demo/collaborators/bob", 200, token=self.alice,
                    method="DELETE")
        self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}",
                     token=self.bob, code=404)
        self.lfs_batch("download", [{"oid": oid, "size": size}], token=self.bob, code=404)
        assert hashlib.sha256(object_file.read_bytes()).hexdigest() == oid
        self.expect("/api/repos/alice/demo/collaborators/bob", 201, token=self.alice,
                    method="PUT", body={"role": "read"})
        assert self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{oid}/{size}",
                            token=self.bob, code=200)[1] == payload
        return {"duplicate_corrupt_upload_idempotent_200_or_rejected_422": True, "interrupted_duplicate": True,
                "committed_digest_preserved": True, "permission_removal_denied_new_read": True,
                "bytes_retained_after_regrant": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    assert not os.environ.get("ROOTYARD_OBJECT_STORE_ENDPOINT"), \
        "this local-retention suite must run without a remote object store"
    h = RetentionHarness(args)
    passed = False
    try:
        h.case("valid_and_compatible_publication", h.valid_and_compatible_publication)
        h.case("committed_bytes_survive_failures",
               h.committed_bytes_survive_failed_duplicates_and_permission_removal)
        passed = True
    except Exception:
        print(h.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        h.cleanup()
    report = {"passed": passed, "cases": h.results,
              "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              "limitations": [
                  "Loopback single node, local data volume; S3/Garage recovery is covered by lfs_remote.py.",
                  "Non-LFS push uses 300 small files; publication.rs bounds are MAX_SMALL_BLOBS=4096 and MAX_OBJECTS=20000.",
                  "No LFS delete/GC API exists; committed-object retention is asserted against failed uploads and role removal.",
                  "Interrupted duplicate uses a truncated HTTP body; exhaustive transport fault injection is not covered."]}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
