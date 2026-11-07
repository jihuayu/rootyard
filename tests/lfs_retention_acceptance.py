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
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime
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

        # An interrupted FIRST upload must never become ready or publish bytes.
        fresh = os.urandom(32 * 1024)
        fresh_oid = hashlib.sha256(fresh).hexdigest()
        self.lfs_batch("upload", [{"oid": fresh_oid, "size": len(fresh)}], token=self.alice)
        fresh_path = object_file.parent / fresh_oid
        conn = self._partial_put(fresh_oid, len(fresh), self.alice)
        conn.send(fresh[:8])
        conn.close()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            state = self.sql("SELECT state FROM lfs_objects WHERE repository_id='"
                             f"{self.repo['id']}' AND oid='{fresh_oid}'")
            if state == "pending" and not fresh_path.exists()                     and not list(fresh_path.parent.glob(".tmp-*")):
                break
            time.sleep(.05)
        assert state == "pending", state
        assert not fresh_path.exists()
        assert list(fresh_path.parent.glob(".tmp-*")) == [], \
            "interrupted first upload left staging temp files"
        self.lfs_get(f"/git/alice/demo.git/info/lfs/objects/{fresh_oid}/{len(fresh)}",
                     token=self.alice, code=404)
        self.lfs_put(f"/git/alice/demo.git/info/lfs/objects/{fresh_oid}/{len(fresh)}",
                     fresh, token=self.alice, code=200)
        assert self.sql("SELECT state FROM lfs_objects WHERE repository_id='"
                        f"{self.repo['id']}' AND oid='{fresh_oid}'") == "ready"
        assert hashlib.sha256(fresh_path.read_bytes()).hexdigest() == fresh_oid

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
        return {"duplicate_corrupt_upload_idempotent_200_or_rejected_422": True,
                "interrupted_duplicate": True,
                "interrupted_first_upload_stayed_pending": True,
                "interrupted_first_upload_retry_became_ready": True,
                "committed_digest_preserved": True, "permission_removal_denied_new_read": True,
                "bytes_retained_after_regrant": True}


    def gitfs_maintenance_during_pointer_publication(self):
        self._fixture()
        self.stop()
        policy = {"ROOTYARD_STORAGE_MAINTENANCE": "true",
                  "ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS": "1",
                  "ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS": "1",
                  "ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS": "30",
                  "ROOTYARD_STORAGE_MAINTENANCE_QUIESCENCE_SECONDS": "1",
                  "ROOTYARD_STORAGE_STAGE_AGE_SECONDS": "1",
                  "ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS": "1"}
        self.env.update(policy)
        self.start()
        repo_id = self.repo["id"]
        jobs_path = "/api/repos/alice/demo/maintenance-jobs"
        lfs_dir = Path(self.env["ROOTYARD_DATA_DIR"]) / "lfs" / repo_id
        payload = os.urandom(256 * 1024)
        oid = hashlib.sha256(payload).hexdigest()
        batch = self.lfs_batch("upload", [{"oid": oid, "size": len(payload)}], token=self.alice)
        self.lfs_put(batch["objects"][0]["actions"]["upload"]["href"], payload,
                     token=self.alice, code=200)
        self.git("lfs", "install", "--local", cwd=self.work)
        self.git("lfs", "track", "*.dat", cwd=self.work)
        (self.work / "gc-race.dat").write_bytes(payload)
        self.git("add", ".gitattributes", "gc-race.dat", cwd=self.work)
        self.git("commit", "-m", "pointer published during GitFS maintenance", cwd=self.work)
        (self.work / "bulk.bin").write_bytes(os.urandom(8 * 1024 * 1024))
        self.git("add", "bulk.bin", cwd=self.work)
        self.git("commit", "-m", "bulk receive during maintenance", cwd=self.work)
        object_file = lfs_dir / oid
        # Real PostgreSQL reader lease: the same shared advisory key native
        # readers hold. The maintenance worker claims a job and waits in
        # `running` for the exclusive lease until this reader releases, which
        # happens only after the real native pointer publication finishes.
        # NATIVE LEASE BARRIER (test-only fault injection on the synthetic data
        # dir): the fixture holds ONLY the product ref-publication key. The real
        # native HTTP push acquires its own read_leases::shared lease on
        # rootyard-data-v1 (application_name=rootyard) and blocks in
        # ref_publication::acquire waiting for this ref key, so the data lease
        # holder is the application backend, never this fixture session.
        data_key = ("hashtextextended('rootyard-data-v1:' || '" + str(repo_id)
                    + "'::uuid::text, 0)")
        ref_name = "refs/heads/gc-race-native"
        ref_key = ("hashtextextended('rootyard-ref-v1:' || '" + str(repo_id)
                   + "'::uuid::text || ':" + ref_name + "', 0)")
        blocker = subprocess.Popen(
            ["psql", "--dbname", self.db, "-X", "-q", "-A", "-t",
             "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=self.env)
        blocker.stdin.write(b"SELECT pg_backend_pid();\n")
        blocker.stdin.flush()
        fixture_pid = blocker.stdout.readline().decode().strip()
        blocker.stdin.write(("SELECT pg_try_advisory_lock(" + ref_key + ");\n").encode())
        blocker.stdin.flush()
        assert blocker.stdout.readline().decode().strip() == "t", \
            "ref publication barrier not acquired"
        pushes = {}
        def push():
            start = time.time()
            result = self.git("push", "origin", "HEAD:" + ref_name, cwd=self.work,
                              token=self.alice, check=False)
            pushes.update(rc=result.returncode, start=start, end=time.time())
        thread = threading.Thread(target=push)
        thread.start()
        thread_started = True
        lease_sql = (
            "SELECT l.pid||'|'||a.application_name||'|'||l.mode FROM pg_locks l "
            "JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' "
            "AND l.granted AND l.mode='ShareLock' AND l.objsubid=1 "
            "AND l.classid=(((" + data_key + ")::bigint >> 32) & 4294967295)::oid "
            "AND l.objid=(((" + data_key + ")::bigint) & 4294967295)::oid "
            "AND a.application_name='rootyard'")
        native_pid = None
        lease_app = lease_mode = None
        streak = {}
        deadline = time.monotonic() + 20
        try:
            while time.monotonic() < deadline:
                rows = [row for row in self.sql(lease_sql).splitlines() if row]
                current = {}
                for row in rows:
                    pid, app, mode = row.split("|")
                    if pid != fixture_pid:
                        current[pid] = (app, mode)
                for pid in list(streak):
                    if pid not in current:
                        streak[pid] = 0
                for pid in current:
                    streak[pid] = streak.get(pid, 0) + 1
                if streak and max(streak.values()) >= 5:
                    native_pid = max(streak, key=streak.get)
                    lease_app, lease_mode = current[native_pid]
                    break
                time.sleep(.05)
            assert native_pid is not None, "native push never held the data read lease"
            rows = [row for row in self.sql(lease_sql).splitlines() if row]
            current = {row.split("|")[0]: row.split("|")[1:] for row in rows}
            assert native_pid in current, {"pid": native_pid, "current": current}
            assert native_pid != fixture_pid, (native_pid, fixture_pid)
            assert current[native_pid][0] == "rootyard"
            # 4,000 stale staging files are created only after the native lease
            # is provably held, so the real cleanup cannot delete them early.
            stale = time.time() - 30
            owned = []
            for _ in range(4000):
                path = lfs_dir / (".tmp-" + str(uuid.uuid4()))
                path.write_bytes(b"stale")
                os.utime(path, (stale, stale))
                owned.append(path)
            assert list(lfs_dir.glob(".tmp-*"))
            cleanup = None
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and cleanup is None:
                page = json.loads(self.expect(jobs_path, 200, token=self.alice))
                for item in page["items"]:
                    if item["kind"] == "gitfs_stage_cleanup" and item["state"] == "running":
                        cleanup = item
                        break
                if cleanup is None:
                    time.sleep(.05)
            assert cleanup is not None, "stage cleanup was not claimed during the native lease"
            assert all(path.exists() for path in owned), \
                "cleanup deleted staging files while the native lease was held"
            assert any(row.split("|")[0] == native_pid
                       for row in self.sql(lease_sql).splitlines()), \
                "native lease was released before the leak check"
            exclusive = self.sql("SELECT pg_try_advisory_lock(" + data_key + ");")
            assert exclusive == "f", \
                "exclusive cleanup lease was not denied by the native shared lease"
            untouched = sum(1 for path in owned if path.exists())
            blocker.stdin.close()
            blocker.wait(timeout=15)
            thread.join(90)
        finally:
            try:
                blocker.stdin.close()
            except Exception:
                pass
            blocker.wait(timeout=15)
            if thread_started and thread.is_alive():
                thread.join(15)
        assert pushes.get("rc") == 0, pushes
        window = {"start": pushes["start"], "end": pushes["end"]}
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            detail = json.loads(self.expect(jobs_path + "/" + cleanup["id"], 200,
                                            token=self.alice))
            if detail["state"] in ("succeeded", "failed"):
                break
            time.sleep(.05)
        assert detail["state"] == "succeeded", detail
        completed = datetime.fromisoformat(
            detail["completed_at"].replace("Z", "+00:00")).timestamp()
        assert completed >= window["end"], {"completed": completed, "push": window}
        result = detail.get("result") or {}
        deleted = result.get("staging_files_deleted", 0)
        assert deleted >= 4000, result
        assert not any(path.exists() for path in owned)
        self.stop()
        for name in policy:
            self.env.pop(name, None)
        self.start()
        assert self.sql("SELECT state FROM lfs_objects WHERE repository_id='"
                        f"{repo_id}' AND oid='{oid}'") == "ready"
        refs = self.git("ls-remote", self.remote, token=self.alice).stdout
        assert ref_name.encode() in refs, refs
        assert hashlib.sha256(object_file.read_bytes()).hexdigest() == oid
        assert object_file.stat().st_size == len(payload)
        _, body, _ = self.lfs_get(
            f"/git/alice/demo.git/info/lfs/objects/{oid}/{len(payload)}",
            token=self.alice, code=200)
        assert body == payload
        assert list(lfs_dir.glob(".tmp-*")) == []
        return {"job_kind": detail["kind"], "job_state": detail["state"],
                "job_result": result,
                "job_observed_running_during_push": True,
                "cleanup_observed_running_during_push": True,
                "native_lease": {
                    "backend_pid": int(native_pid),
                    "application_name": lease_app,
                    "mode": lease_mode,
                    "consecutive_samples": streak.get(native_pid, 0),
                    "fixture_backend_pid": int(fixture_pid),
                    "fixture_lock_scope": "rootyard-ref-v1 only: " + ref_name},
                "exclusive_probe_denied_while_native_lease_held": True,
                "cleanup_running_while_native_lease_held": True,
                "stale_files_untouched_before_release": untouched,
                "job_completed_after_push": completed,
                "push_window": window,
                "native_lease_barrier": "fixture holds rootyard-ref-v1; native push holds rootyard-data-v1 ShareLock (application_name=rootyard) until publication",
                "staging_files_deleted_after_native_release": deleted,
                "lfs_bytes_retained": True}

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
        h.case("gitfs_maintenance_during_pointer_publication",
               h.gitfs_maintenance_during_pointer_publication)
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
