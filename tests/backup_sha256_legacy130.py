#!/usr/bin/env python3
"""Real format6/schema130 backup restored by the current format8 binary.

The pre-migration-131 binary creates a genuine archive and SHA-256 repository
plus a SHA-1 checkout grant and cancellation tombstone. The current binary must
reject that archive without explicit opt-in, verify the frozen format6/schema130
catalog, restore the volume, apply migration 132, and preserve the SHA-256
objects/refs/pin, repository generation and checkout authority semantics.

Requires a disposable ROOTYARD_TEST_DATABASE_URL with CREATEDB and a trusted
--legacy-binary built from the schema130 baseline. Only random task-owned
databases and temporary storage are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import urllib.parse
import uuid

from e2e import Harness


class Legacy130Harness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.admin = self.base_db
        self.created = []
        self.source_db = self.new_database()
        self.target_db = self.new_database()
        self.source_data = self.root / "legacy-data"
        self.target_data = self.root / "restored-data"
        self.backup = self.root / "legacy-backup"
        self.audience = str(uuid.uuid4())

    def query(self, db, sql):
        env = self.env.copy()
        parts = urllib.parse.urlsplit(db)
        env.update(PGHOST=parts.hostname or "", PGPORT=str(parts.port or 5432),
                   PGDATABASE=parts.path.lstrip("/"), PGUSER=parts.username or "",
                   PGPASSWORD=parts.password or "")
        return self.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
                        env=env).stdout.decode().strip()

    def new_database(self):
        name = "rootyard_sha256_legacy130_" + uuid.uuid4().hex
        self.query(self.admin, 'CREATE DATABASE "' + name + '" TEMPLATE template0')
        self.created.append(name)
        return urllib.parse.urlunsplit(
            urllib.parse.urlsplit(self.admin)._replace(path="/" + name, query=""))

    def use_legacy(self):
        self.env.update(DATABASE_URL=self.source_db,
                        ROOTYARD_DATA_DIR=str(self.source_data),
                        ROOTYARD_CI_MIRROR_AUDIENCE=self.audience)
        self.db = self.source_db

    def use_candidate(self):
        self.env.update(DATABASE_URL=self.target_db,
                        ROOTYARD_DATA_DIR=str(self.target_data),
                        ROOTYARD_CI_MIRROR_AUDIENCE=self.audience)
        self.db = self.target_db

    def create_sha256_source(self):
        self.use_legacy()
        self.args.binary = self.args.legacy_binary
        self.cli("migrate")
        self.alice = self.account("create-user", "alice")
        self.reader = self.account("create-token", "alice", "--read-only")
        self.start()
        sha = json.loads(self.expect("/api/repos", 201, token=self.alice, method="POST",
                                     body={"name": "sha256", "object_format": "sha256"}))
        assert sha["object_format"] == "sha256"
        self.sha_repo = sha
        self.sha_remote = self.base + sha["clone_path"]
        work = self.root / "sha256-work"
        self.git("init", "--object-format=sha256", "--initial-branch=main", str(work))
        self.git("config", "user.name", "Legacy", cwd=work)
        self.git("config", "user.email", "legacy@example.invalid", cwd=work)
        self.git("remote", "add", "origin", self.sha_remote, cwd=work)
        (work / "legacy.txt").write_text("legacy format6 sha256\n")
        self.git("add", "legacy.txt", cwd=work)
        self.git("commit", "-m", "legacy sha256 fixture", cwd=work)
        self.sha_head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        assert len(self.sha_head) == 64
        self.git("push", "origin", "HEAD:main", cwd=work, token=self.alice)
        self.generation = int(self.sql(
            "SELECT storage_generation FROM repositories WHERE id='" + sha["id"] + "'"))
        self.pin_job = str(uuid.uuid4())
        pin = json.loads(self.expect("/api/repos/alice/sha256/ci-pins", (200, 201),
                                     token=self.alice, method="POST",
                                     body={"job_id": self.pin_job, "target_oid": self.sha_head,
                                           "storage_generation": self.generation}))
        assert pin["object_format"] == "sha256"

        # A SHA-1 checkout grant exists in schema130; it must survive restore as
        # authority evidence but with its bearer permanently revoked.
        legacy = json.loads(self.expect("/api/repos", 201, token=self.alice, method="POST",
                                        body={"name": "legacy", "object_format": "sha1"}))
        legacy_remote = self.base + legacy["clone_path"]
        legacy_work = self.root / "legacy-work"
        self.git("clone", legacy_remote, str(legacy_work), token=self.alice)
        self.git("config", "user.name", "Legacy", cwd=legacy_work)
        self.git("config", "user.email", "legacy@example.invalid", cwd=legacy_work)
        (legacy_work / "legacy.txt").write_text("legacy sha1 checkout fixture\n")
        self.git("add", "legacy.txt", cwd=legacy_work)
        self.git("commit", "-m", "legacy sha1 checkout", cwd=legacy_work)
        self.legacy_head = self.git("rev-parse", "HEAD", cwd=legacy_work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=legacy_work, token=self.alice)
        self.checkout_job = str(uuid.uuid4())
        self.expect("/api/repos/alice/legacy/ci-pins", (200, 201), token=self.alice,
                    method="POST", body={"job_id": self.checkout_job,
                                         "target_oid": self.legacy_head,
                                         "storage_generation": 1})
        issued = json.loads(self.expect("/api/repos/alice/legacy/ci-checkouts",
                                        (200, 201), token=self.alice, method="POST",
                                        body={"job_id": self.checkout_job,
                                              "target_oid": self.legacy_head,
                                              "storage_generation": 1,
                                              "mirror_audience": self.audience,
                                              "expires_unix": int(time.time()) + 1800}))
        assert issued["plan"]["object_format"] == "sha1"
        self.secrets.append(issued["token"])
        self.tombstone_job = str(uuid.uuid4())
        self.expect(f"/api/repos/alice/legacy/ci-checkouts/{self.tombstone_job}/cancel",
                    (200, 204), token=self.alice, method="POST", body=b"")
        self.stop()

        legacy_backup = self.run([self.args.legacy_binary, "backup", str(self.backup),
                                  "--offline"], env=self.env)
        result = json.loads(legacy_backup.stdout)
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert manifest["format"] == 6, manifest["format"]
        assert manifest["schema_versions"][-1] == 130
        assert manifest["binary_sha256"] == hashlib.sha256(
            Path(self.args.legacy_binary).read_bytes()).hexdigest()
        assert result["complete"] is True
        self.run([self.args.legacy_binary, "backup-verify", str(self.backup)])
        return dict(format=manifest["format"], schema_last=manifest["schema_versions"][-1],
                    legacy_binary_sha256=manifest["binary_sha256"],
                    sha256_head=self.sha_head, generation=self.generation)

    def candidate_rejects_without_opt_in(self):
        self.use_candidate()
        self.args.binary = self.args.binary_current
        result = self.run([self.args.binary, "restore", str(self.backup), "--isolated",
                           "--trust-backup"], env=self.env, check=False)
        assert result.returncode != 0
        assert not self.target_data.exists()
        assert not (self.target_data.parent /
                    ('.' + self.target_data.name + '.rootyard-restoring')).exists()
        return dict(explicit_opt_in_required=True, no_target_or_guard_written=True)

    def candidate_restores_and_upgrades(self):
        self.use_candidate()
        self.args.binary = self.args.binary_current
        self.run([self.args.binary, "restore", str(self.backup), "--isolated",
                  "--trust-backup", "--allow-legacy-schema130"], env=self.env)
        assert self.query(self.target_db,
                          "SELECT max(version) FROM schema_migrations") == "132"
        names = self.query(self.target_db,
                           "SELECT string_agg(conname, ',' ORDER BY conname) FROM pg_constraint "
                           "WHERE conrelid='public.ci_checkout_jobs'::regclass")
        assert "ci_checkout_jobs_plan_shape" in names
        assert "ci_checkout_jobs_plan_presence" in names
        assert "ci_checkout_jobs_check1" not in names
        self.start()
        restored = json.loads(self.expect("/api/repos/alice/sha256", 200, token=self.alice))
        assert restored["object_format"] == "sha256"
        assert int(restored["storage_generation"]) == self.generation
        clone = self.root / "restored-sha256"
        self.git("clone", self.sha_remote, str(clone), token=self.reader)
        assert self.git("rev-parse", "--show-object-format", cwd=clone).stdout.strip() == b"sha256"
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == self.sha_head
        self.git("fsck", "--full", "--strict", cwd=clone)
        pin = json.loads(self.expect("/api/repos/alice/sha256/ci-pins/" + self.pin_job,
                                     200, token=self.alice))
        assert pin["state"] == "pinned" and pin["object_format"] == "sha256"
        assert pin["target_oid"] == self.sha_head
        rows = json.loads(self.query(self.target_db,
            "SELECT json_agg(json_build_object('job',job_id::text,'plan',plan IS NOT NULL,"
            "'revoked',revoked,'cancelled',cancelled) ORDER BY job_id) FROM ci_checkout_jobs"))
        grant = next(row for row in rows if row["job"] == self.checkout_job)
        tombstone = next(row for row in rows if row["job"] == self.tombstone_job)
        assert grant["plan"] is True and grant["revoked"] is True
        assert tombstone["plan"] is False and tombstone["cancelled"] is True
        self.stop()
        return dict(schema_upgraded_to_132=True, sha256_clone_exact=True,
                    pin_preserved=True, generation_preserved=True,
                    issued_grant_revoked=True, cancellation_tombstone_preserved=True)

    def cleanup(self):
        self.stop()
        for name in reversed(self.created):
            self.query(self.admin, 'DROP DATABASE "' + name + '" WITH (FORCE)')
        if not self.args.keep:
            shutil.rmtree(self.root)
        self.created = []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--legacy-binary", required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    args.legacy_binary = str(Path(args.legacy_binary).resolve())
    args.binary_current = args.binary
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = Legacy130Harness(args)
    success = False
    try:
        harness.case("create_real_format6_schema130_archive",
                     harness.create_sha256_source)
        harness.case("candidate_rejects_without_opt_in",
                     harness.candidate_rejects_without_opt_in)
        harness.case("candidate_restores_and_upgrades",
                     harness.candidate_restores_and_upgrades)
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed",
                                        error=harness.redact(error)))
            success = False
        report = dict(passed=success, cases=harness.results,
                      binary_sha256=hashlib.sha256(Path(args.binary_current).read_bytes()).hexdigest(),
                      legacy_binary_sha256=hashlib.sha256(Path(args.legacy_binary).read_bytes()).hexdigest(),
                      limitations=[
                          "Synthetic loopback backup/restore, not a production RPO/RTO claim.",
                          "The legacy archive is produced by the trusted baseline binary, not rewritten.",
                      ])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
