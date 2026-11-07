#!/usr/bin/env python3
"""Stock-Git/HTTP acceptance for automatic Pando background maintenance.

Requires a built `rootyard` binary plus real PostgreSQL, Garage/S3 and Vault
Transit. The test cuts a normal GitFS repository over to Pando with the shipped
operator command, then lets the running server schedule compaction, cache
hydration/eviction and a backup-fenced retry without any maintenance API call.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness

REQUIRED_ENV = (
    "ROOTYARD_TEST_DATABASE_URL",
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_KMS_VAULT_URL",
    "ROOTYARD_KMS_VAULT_TOKEN",
    "ROOTYARD_KMS_VAULT_KEY",
)


class PandoMaintenanceHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.env.update(
            ROOTYARD_STORAGE_MAINTENANCE="true",
            ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS="1",
            ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS="1",
            ROOTYARD_STORAGE_REPACK_PACKS="3",
            ROOTYARD_STORAGE_REPACK_LOOSE_OBJECTS="1000000",
            ROOTYARD_STORAGE_CACHE_MAX_AGE_SECONDS="60",
            ROOTYARD_STORAGE_STAGE_AGE_SECONDS="1",
            ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS="5",
            ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS="2",
        )

    def wait_sql(self, query, predicate, seconds=60, label="condition"):
        until = time.monotonic() + seconds
        last = None
        while time.monotonic() < until:
            last = self.sql(query)
            if predicate(last):
                return last
            time.sleep(.2)
        raise AssertionError(f"{label} did not settle: {last}")

    def wait_count(self, query, expected="1", seconds=60, label="condition"):
        return self.wait_sql(query, lambda value: value == expected, seconds, label)

    def repo_setup(self, name):
        repo = json.loads(self.expect("/api/repos", 201, token=self.alice,
                                      method="POST", body={"name": name}))
        work = self.root / (name + "-work")
        self.git("init", "--initial-branch=main", str(work))
        self.git("config", "user.name", "Pando Maint", cwd=work)
        self.git("config", "user.email", "pando-maint@example.invalid", cwd=work)
        self.git("remote", "add", "origin", self.base + repo["clone_path"], cwd=work)
        (work / "base.txt").write_text("gitfs to pando base\n")
        self.git("add", "base.txt", cwd=work)
        self.git("commit", "-m", "base", cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        return repo, work

    def pando_push(self, work, index):
        (work / f"commit-{index}.txt").write_text(f"pando maintenance commit {index}\n")
        self.git("add", f"commit-{index}.txt", cwd=work)
        self.git("commit", "-m", f"pando {index}", cwd=work)
        oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        return oid

    def automatic_compaction_and_cache(self):
        repo, work = self.repo_setup("pando-maint")
        self.stop()
        report = json.loads(self.cli("pando-transition", "cutover", "--repository", repo["id"]))
        assert report["direction"] == "gitfs_to_pando", report
        self.start()
        # A commit removed through the supported gateway is not reachable from
        # any ref. Its object must still survive automatic pack compaction.
        self.git("checkout", "-b", "retained", cwd=work)
        (work / "retained-only.txt").write_text("retained only before ref deletion")
        self.git("add", "retained-only.txt", cwd=work)
        self.git("commit", "-m", "retained only", cwd=work)
        retained_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/retained", cwd=work, token=self.alice)
        self.git("push", "origin", ":refs/heads/retained", cwd=work, token=self.alice)
        self.git("checkout", "main", cwd=work)
        base = "repository_id='" + repo["id"] + "'"
        self.wait_sql("SELECT COALESCE((SELECT deleted::text FROM repository_ref_projection WHERE " + base
                      + " AND ref_name='refs/heads/retained'),'missing')", lambda value: value == "true", 30,
                      "retained ref projection deletion")
        assert self.sql("SELECT count(*) FROM pando_refs WHERE " + base
                        + " AND ref_name='refs/heads/retained'") == "0"
        # Three full Pando pushes create additional immutable packs; the
        # configured pack threshold must schedule compaction without any API call.
        latest = None
        for index in (1, 2, 3):
            latest = self.pando_push(work, index)
        self.wait_count(
            "SELECT count(*) FROM storage_maintenance_jobs WHERE " + base
            + " AND kind='pando_repack' AND state='succeeded'", seconds=90,
            label="automatic pando_repack")
        packs = self.sql("SELECT cardinality(pack_ids) FROM pando_repository_states WHERE " + base)
        assert packs == "1", "automatic compaction did not replace the serving pack set: " + packs
        result = self.sql("SELECT result::text FROM storage_maintenance_jobs WHERE " + base
                          + " AND kind='pando_repack' AND state='succeeded' ORDER BY completed_at DESC LIMIT 1")
        result = json.loads(result)
        assert result["old_pack_manifests_retained"] is True, result
        assert result["remote_deleted"] is False, result
        manifests = int(self.sql("SELECT count(*) FROM pando_pack_manifests WHERE " + base))
        assert manifests >= 4, manifests
        assert self.sql("SELECT oid FROM pando_refs WHERE " + base
                        + " AND ref_name='refs/heads/main'") == latest

        # A fresh stock clone must fetch and fsck the compacted authoritative closure.
        clone = self.root / "pando-maint-clone"
        self.git("clone", self.base + repo["clone_path"], str(clone), token=self.alice)
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == latest
        self.git("fsck", "--full", "--strict", cwd=clone)

        cache = self.root / "data" / "pando-cache" / repo["id"]
        serving_pack = self.sql("SELECT pack_ids[1]::text FROM pando_repository_states WHERE " + base)
        cached = cache / ("pack-" + serving_pack + ".pack")
        cached_idx = cached.with_suffix(".idx")
        until = time.monotonic() + 90
        while time.monotonic() < until and not (cached.exists() and cached_idx.exists()):
            time.sleep(.2)
        assert cached.exists() and cached_idx.exists(), "automatic cache hydration did not materialize the compacted pack"
        assert cached_idx.is_file(), cached

        # Disable the background worker while corrupting both cache files so an
        # automatic hydration cannot hide the read-path integrity check. A
        # same-length pair must be rejected and recovered from real remote bytes.
        good_pack = cached.read_bytes()
        good_idx = cached_idx.read_bytes()
        self.stop()
        self.env["ROOTYARD_STORAGE_MAINTENANCE"] = "false"
        self.start()
        for path in (cached, cached_idx):
            corrupt = bytearray(path.read_bytes())
            corrupt[len(corrupt) // 2] ^= 0xFF
            path.write_bytes(bytes(corrupt))
        tampered_clone = self.root / "pando-maint-tamper-clone"
        self.git("clone", self.base + repo["clone_path"], str(tampered_clone), token=self.alice)
        assert self.git("rev-parse", "HEAD", cwd=tampered_clone).stdout.decode().strip() == latest
        self.git("fsck", "--full", "--strict", cwd=tampered_clone)
        assert cached.read_bytes() == good_pack, "corrupt cache pack was not rebuilt from remote storage"
        assert cached_idx.read_bytes() == good_idx, "corrupt cache index was not rebuilt from remote storage"
        self.stop()
        self.env["ROOTYARD_STORAGE_MAINTENANCE"] = "true"
        self.start()

        old = time.time() - 7200
        os.utime(cached, (old, old))
        os.utime(cached_idx, (old, old))
        self.wait_count(
            "SELECT count(*) FROM storage_maintenance_jobs WHERE " + base
            + " AND kind='pando_cache_evict' AND state='succeeded'", seconds=60,
            label="automatic pando_cache_evict")
        assert not cached.exists() and not cached_idx.exists(), "expired cache pair was not evicted"
        self.wait_sql("SELECT count(*) FROM pando_pack_manifests WHERE " + base,
                      lambda value: int(value) == manifests, 10,
                      "cache eviction must not touch manifests")
        until = time.monotonic() + 90
        while time.monotonic() < until and not (cached.exists() and cached_idx.exists()):
            time.sleep(.2)
        assert cached.exists() and cached_idx.exists(), "automatic rehydration did not restore the cache"

        # A held backup/migration barrier must leave a destructive-looking
        # maintenance job retryable rather than committing a pack-set change.
        before = self.sql("SELECT array_to_string(pack_ids,',') FROM pando_repository_states WHERE " + base)
        lock = subprocess.Popen(
            ["psql", "--dbname", self.db, "-X", "-At", "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            lock.stdin.write("BEGIN; SELECT pg_advisory_xact_lock(738390103); SELECT 'ready';\n")
            lock.stdin.flush()
            until = time.monotonic() + 5
            while time.monotonic() < until:
                ready, _, _ = select.select([lock.stdout], [], [], max(0, until - time.monotonic()))
                if not ready:
                    break
                if lock.stdout.readline().strip() == "ready":
                    break
            else:
                raise AssertionError("could not acquire the backup barrier")
            job = self.sql(
                "WITH inserted AS (INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation) "
                "SELECT gen_random_uuid(),id,owner_id,'pando_repack',storage_generation "
                "FROM repositories WHERE id='" + repo["id"] + "' RETURNING id) SELECT id FROM inserted")
            self.wait_sql(
                "SELECT count(*) FROM storage_maintenance_jobs WHERE id='" + job + "'"
                " AND state='queued' AND last_error LIKE '%backup or migration barrier%'",
                lambda value: value == "1", 30, "backup-fenced Pando retry")
            assert self.sql("SELECT array_to_string(pack_ids,',') FROM pando_repository_states WHERE " + base) == before
        finally:
            lock.stdin.write("COMMIT;\n")
            lock.stdin.flush()
            lock.stdin.close()
            lock.wait(timeout=5)
        self.wait_count(
            "SELECT count(*) FROM storage_maintenance_jobs WHERE id='" + job + "' AND state='succeeded'",
            seconds=90, label="Pando job after backup barrier release")
        assert self.sql("SELECT cardinality(pack_ids) FROM pando_repository_states WHERE " + base) == "1"

        # Rollback reconstructs GitFS exclusively from the current Pando serving
        # pack set. The deleted-ref object is absent from all refs but must still
        # be present because compaction copied every old packed object.
        self.stop()
        rollback = json.loads(self.cli("pando-transition", "rollback", "--repository", repo["id"]))
        assert rollback["direction"] == "pando_to_gitfs", rollback
        bare = self.root / "data" / "repos" / (repo["id"] + ".git")
        self.git("--git-dir", str(bare), "cat-file", "-e", retained_oid)
        self.git("--git-dir", str(bare), "fsck", "--full", "--strict")
        self.start()
        final_clone = self.root / "pando-maint-final-clone"
        self.git("clone", self.base + repo["clone_path"], str(final_clone), token=self.alice)
        assert self.git("rev-parse", "HEAD", cwd=final_clone).stdout.decode().strip() == latest
        self.git("fsck", "--full", "--strict", cwd=final_clone)
        return {
            "automatic_compaction": True,
            "serving_packs": 1,
            "old_pack_manifests_retained": manifests,
            "cache_hydrated_evicted_rehydrated": True,
            "cache_tamper_recovered": True,
            "backup_barrier_retried": True,
            "non_ref_oid_survived_compaction_and_rollback": retained_oid,
            "latest_oid": latest,
            "remote_deleted": False,
        }


def require_environment():
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise RuntimeError("Pando maintenance service test requires real Garage/Vault: missing " + ", ".join(missing))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    try:
        require_environment()
        if not os.access(args.binary, os.X_OK):
            raise RuntimeError("binary is not executable: " + args.binary)
    except RuntimeError as error:
        parser.error(str(error))
    h = PandoMaintenanceHarness(args)
    passed = False
    try:
        h.case("setup", h.setup)
        h.case("automatic_compaction_and_cache", h.automatic_compaction_and_cache)
        passed = True
    except Exception:
        args.keep = True
        print(h.redact(traceback.format_exc()), file=sys.stderr)
        log = h.root / "server.log"
        if log.exists():
            print(h.redact(log.read_text(errors="replace")[-8000:]), file=sys.stderr)
    finally:
        h.cleanup()
    report = {"passed": passed, "cases": h.results,
              "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              "limitations": ["Loopback single-node fixture; no remote-delete qualification."]}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
