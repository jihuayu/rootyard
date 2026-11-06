#!/usr/bin/env python3
"""Native PostgreSQL/GitFS maintenance scheduling, reclaim, and retention test."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness


class LifecycleHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.env.update(ROOTYARD_STORAGE_MAINTENANCE="true",
                        ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS="1",
                        ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS="1",
                        ROOTYARD_STORAGE_REPACK_LOOSE_OBJECTS="1",
                        ROOTYARD_STORAGE_REPACK_PACKS="100",
                        ROOTYARD_STORAGE_STAGE_AGE_SECONDS="1",
                        ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS="5")

    def wait_sql(self, query, expected, seconds=30):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if self.sql(query) == expected:
                return
            time.sleep(.2)
        raise AssertionError("maintenance state did not reach " + expected + ": " + self.sql(query))

    def scheduled_repack_and_staging(self):
        self.setup()
        repo = json.loads(self.expect("/api/repos", 201, token=self.alice,
                                      method="POST", body={"name": "maint"}))
        self.repo = repo
        remote = self.base + repo["clone_path"]
        work = self.root / "maint-work"
        self.git("clone", remote, str(work), token=self.alice)
        self.git("config", "user.name", "Alice", cwd=work)
        self.git("config", "user.email", "alice@rootyard.local", cwd=work)
        (work / "README.md").write_text("retain this commit\n")
        self.git("add", "README.md", cwd=work)
        self.git("commit", "-m", "maintenance root", cwd=work)
        oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=work, token=self.alice)
        q = "SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='" + repo["id"] + "' AND kind='gitfs_repack' AND state='succeeded'"
        self.wait_sql(q, "1")
        self.wait_sql("SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='"
                      + repo["id"] + "' AND kind='gitfs_cache_hydrate' AND state='succeeded'", "1")
        bare = self.root / "data" / "repos" / (repo["id"] + ".git")
        assert (bare / "objects" / "info" / "commit-graph").is_file()
        self.git("--git-dir", str(bare), "cat-file", "-e", oid)
        self.git("fetch", "origin", cwd=work, token=self.alice)
        time.sleep(2)
        assert self.sql(q) == "1", "unchanged Git object counts caused repeated repacking"
        orphan = self.run(["git", "--git-dir", str(bare), "hash-object", "-w", "--stdin"],
                          data=b"unreferenced maintenance candidate\n").stdout.decode().strip()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                      + repo["id"] + "' AND oid='" + orphan + "'", "pending")
        assert (bare / "objects" / orphan[:2] / orphan[2:]).is_file()
        tree = self.git("--git-dir", str(bare), "rev-parse", "main^{tree}").stdout.decode().strip()
        pinned = self.git("-c", "user.name=Alice", "-c", "user.email=alice@rootyard.local",
                          "--git-dir", str(bare), "commit-tree", tree, "-p", oid,
                          "-m", "CI retained source").stdout.decode().strip()
        pin_job = str(uuid.uuid4())
        self.expect("/api/repos/alice/maint/ci-pins", (200, 201), token=self.alice,
                    method="POST", body={"job_id": pin_job, "target_oid": pinned,
                                         "storage_generation": 1})
        assert self.git("--git-dir", str(bare), "rev-parse",
                        "refs/rootyard-ci/jobs/" + pin_job).stdout.decode().strip() == pinned
        assert pinned not in self.git("--git-dir", str(bare), "fsck", "--unreachable",
                                      "--no-progress").stdout.decode()

        # A stale LFS transfer temporary file is independent of Git objects.
        staging = self.root / "data" / "lfs" / repo["id"]
        staging.mkdir(parents=True, exist_ok=True)
        stale = staging / (".tmp-" + str(uuid.uuid4()))
        stale.write_bytes(b"interrupted upload")
        os.utime(stale, (time.time() - 10, time.time() - 10))
        until = time.monotonic() + 20
        while stale.exists() and time.monotonic() < until:
            time.sleep(.2)
        assert not stale.exists(), "stale upload was not reclaimed"
        self.wait_sql("SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='"
                      + repo["id"] + "' AND kind='gitfs_cache_hydrate' AND state IN ('queued','running')", "0")
        assert self.sql("SELECT count(*) FROM storage_maintenance_tombstones WHERE repository_id='" + repo["id"] + "' AND state='deleted'") == "0"
        return {"repack_succeeded": True, "commit_graph_hydrated": True,
                "stale_stage_reclaimed": True,
                "retained_commit": oid, "ci_pin_root": pinned,
                "unreachable_oid_tombstoned_without_delete": orphan}

    def expired_claim_reclaim(self):
        self.stop()
        repo = self.repo["id"]
        fake = str(uuid.uuid4())
        owner = str(uuid.uuid4())
        self.sql("INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation,state,attempt,claim_generation,lease_owner,lease_until) "
                 "VALUES('" + fake + "','" + repo + "','" + self.alice["user_id"] + "','gitfs_cache_hydrate',1,'running',1,1,'" + owner + "',clock_timestamp()-interval '1 second')")
        duplicate = self.run(["psql", "--dbname", self.db, "-X", "-v", "ON_ERROR_STOP=1", "-c",
                              "INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation) VALUES('"
                              + str(uuid.uuid4()) + "','" + repo + "','" + self.alice["user_id"]
                              + "','gitfs_cache_hydrate',1)"], check=False)
        assert duplicate.returncode != 0, "duplicate queued wakeup bypassed unique active-kind index"
        self.start()
        self.wait_sql("SELECT state FROM storage_maintenance_jobs WHERE id='" + fake + "'", "succeeded")
        assert self.sql("SELECT attempt||':'||claim_generation FROM storage_maintenance_jobs WHERE id='" + fake + "'") == "2:2"
        assert self.sql("SELECT lease_owner IS NULL FROM storage_maintenance_jobs WHERE id='" + fake + "'") == "t"
        return {"expired_attempt_reclaimed": 2, "late_owner_fenced": True,
                "duplicate_active_kind_rejected": True}

    def killed_worker_volume_barrier(self):
        self.stop()
        repo = self.repo["id"]
        job = str(uuid.uuid4())
        self.sql("INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation) "
                 "VALUES('" + job + "','" + repo + "','" + self.alice["user_id"] + "','gitfs_repack',1)")
        wrapper = self.root / "slow-git"
        entered = self.root / "repack-entered"
        wrapper.write_text("#!/bin/sh\ncase \" $* \" in\n  *\" repack \"*) sleep 8 & echo entered > "
                           + str(entered) + "; wait;;\nesac\nexec /usr/bin/git \"$@\"\n")
        wrapper.chmod(0o700)
        self.env["ROOTYARD_GIT"] = str(wrapper)
        self.start()
        until = time.monotonic() + 10
        while not entered.exists() and time.monotonic() < until:
            time.sleep(.05)
        assert entered.exists(), "worker never entered the Git child"
        os.kill(self.proc.pid, signal.SIGKILL)
        self.proc.wait(timeout=5)
        self.proc = None
        self.log.close()
        self.log = None

        # A descendant still holds the inherited flock after its direct
        # parent died. The successor cannot open the volume before it exits.
        p = subprocess.Popen([self.args.binary, "serve"], env=self.env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
        try:
            _, stderr = p.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=5)
            raise AssertionError("successor opened a volume held by Git descendant")
        assert p.returncode != 0 and b"data directory already in use" in stderr, stderr[-500:]
        time.sleep(8)
        self.env.pop("ROOTYARD_GIT")
        self.start()
        self.wait_sql("SELECT state FROM storage_maintenance_jobs WHERE id='" + job + "'", "succeeded")
        assert self.sql("SELECT attempt FROM storage_maintenance_jobs WHERE id='" + job + "'") == "2"
        return {"server_sigkill_recovered": True, "descendant_volume_lock_held": True,
                "claimed_attempt_after_restart": 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    h = LifecycleHarness(args)
    passed = False
    try:
        h.case("scheduled_repack_and_staging", h.scheduled_repack_and_staging)
        h.case("expired_claim_reclaim", h.expired_claim_reclaim)
        h.case("killed_worker_volume_barrier", h.killed_worker_volume_barrier)
        passed = True
    except Exception:
        print(h.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        h.cleanup()
    report = {"passed": passed, "cases": h.results,
              "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
