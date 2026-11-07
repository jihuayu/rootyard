#!/usr/bin/env python3
"""Real offline backup/restore of a SHA-256 repository.

Creates a SHA-256 repository through the supported service flow, pushes stock
Git commits, retains an exact CI source pin, takes an offline backup into a new
database/volume pair, restores with ``--isolated --trust-backup`` and proves a
stock Git clone still gets the exact 64-hex OID and object format. This closes
the restore part of issue #38 without reusing a SHA-1 fixture.

Requires CREATEDB on a disposable ROOTYARD_TEST_DATABASE_URL. The run creates
and drops only its own random databases and temporary storage directory.
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


class Sha256RestoreHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.admin = self.base_db
        self.created = []
        self.source_db = self.new_database()
        self.target_db = self.new_database()
        self.db = self.source_db
        self.env["DATABASE_URL"] = self.db
        self.backup = self.root / "backup"
        self.target = self.root / "restored-data"

    def query(self, db, sql):
        env = self.env.copy()
        parts = urllib.parse.urlsplit(db)
        env.update(PGHOST=parts.hostname or "", PGPORT=str(parts.port or 5432),
                   PGDATABASE=parts.path.lstrip("/"), PGUSER=parts.username or "",
                   PGPASSWORD=parts.password or "")
        return self.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql],
                        env=env).stdout.decode().strip()

    def new_database(self):
        name = "rootyard_sha256_restore_" + uuid.uuid4().hex
        self.query(self.admin, 'CREATE DATABASE "' + name + '" TEMPLATE template0')
        self.created.append(name)
        return urllib.parse.urlunsplit(
            urllib.parse.urlsplit(self.admin)._replace(path="/" + name, query=""))

    def wait_repo_ready(self, name, seconds=30):
        """The repo API may provision asynchronously (202); poll to ready."""
        until = time.monotonic() + seconds
        last = None
        while time.monotonic() < until:
            last = json.loads(self.expect("/api/repos/alice/" + name, 200, token=self.alice))
            if last.get("state") == "ready":
                return last
            time.sleep(.1)
        raise AssertionError("repository did not become ready: " + json.dumps(last))

    def source_setup(self):
        self.cli("migrate")
        self.alice = self.account("create-user", "alice")
        self.reader = self.account("create-token", "alice", "--read-only")
        self.start()
        created = json.loads(self.expect(
            "/api/repos", (201, 202), token=self.alice, method="POST",
            body={"name": "restore", "object_format": "sha256"}))
        assert created["object_format"] == "sha256"
        self.repo = self.wait_repo_ready("restore")
        assert self.repo["object_format"] == "sha256" and self.repo["state"] == "ready"
        self.remote = self.base + self.repo["clone_path"]
        work = self.root / "source-work"
        self.git("init", "--object-format=sha256", "--initial-branch=main", str(work))
        self.git("config", "user.name", "Restore", cwd=work)
        self.git("config", "user.email", "restore@example.invalid", cwd=work)
        self.git("remote", "add", "origin", self.remote, cwd=work)
        (work / "content.txt").write_text("sha256 restored content\n")
        self.git("add", "content.txt", cwd=work)
        self.git("commit", "-m", "sha256 restore fixture", cwd=work)
        self.head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        assert len(self.head) == 64
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        self.job = str(uuid.uuid4())
        pin = json.loads(self.expect(
            f"/api/repos/alice/restore/ci-pins", (200, 201), token=self.alice,
            method="POST",
            body={"job_id": self.job, "target_oid": self.head, "storage_generation": 1}))
        assert pin["object_format"] == "sha256" and pin["target_oid"] == self.head
        assert pin["retention_ref"] == "refs/rootyard-ci/jobs/" + self.job
        self.before_refs = self.git("ls-remote", self.remote, token=self.alice).stdout
        self.stop()
        # Sanity: the backup source must be non-empty and contain the SHA-256
        # repository before restore can be claimed.
        self.bare = self.root / "data" / "repos" / (self.repo["id"] + ".git")
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", "--show-object-format").stdout.strip() == b"sha256"
        result = json.loads(self.run([self.args.binary, "backup", str(self.backup),
                                      "--offline"]).stdout)
        assert result["complete"] is True, result
        manifest = json.loads((self.backup / "manifest.json").read_text())
        entries = [entry for entry in manifest["repositories"]
                   if entry["id"] == self.repo["id"]]
        assert len(entries) == 1, manifest["repositories"]
        self.cli("backup-verify", str(self.backup))
        return dict(source_database=self.source_db != self.target_db,
                    backup_seconds=result["elapsed_seconds"],
                    repositories=len(manifest["repositories"]),
                    pin_descriptor_retained=(self.backup / "volume" / "ci-pins" /
                                             self.repo["id"] / (self.job + ".pinned.json")).is_file())

    def restore_and_clone(self):
        env = self.env.copy()
        env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        result = json.loads(self.run([self.args.binary, "restore", str(self.backup),
                                      "--isolated", "--trust-backup"], env=env).stdout)
        self.env.update(DATABASE_URL=self.target_db, ROOTYARD_DATA_DIR=str(self.target))
        self.db = self.target_db
        self.start()
        restored = json.loads(self.expect("/api/repos/alice/restore", 200,
                                          token=self.alice))
        assert restored["object_format"] == "sha256", restored
        assert self.git("ls-remote", self.remote, token=self.alice).stdout == self.before_refs
        clone = self.root / "restored-clone"
        self.git("clone", self.remote, str(clone), token=self.reader)
        assert self.git("rev-parse", "--show-object-format", cwd=clone).stdout.strip() == b"sha256"
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == self.head
        assert (clone / "content.txt").read_text() == "sha256 restored content\n"
        self.git("fsck", "--full", "--strict", cwd=clone)
        pin = json.loads(self.expect("/api/repos/alice/restore/ci-pins/" + self.job,
                                     200, token=self.alice))
        assert pin["state"] == "pinned" and pin["object_format"] == "sha256"
        assert pin["target_oid"] == self.head
        retention = self.git("--git-dir=" + str(self.root / "restored-data" / "repos" /
                                                (self.repo["id"] + ".git")),
                             "rev-parse", "refs/rootyard-ci/jobs/" + self.job)
        assert retention.stdout.decode().strip() == self.head
        self.stop()
        return dict(restore_seconds=result["elapsed_seconds"],
                    exact_head_and_format=True, clone_fsck=True,
                    retained_pin_preserved=True)

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
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = Sha256RestoreHarness(args)
    success = False
    try:
        harness.case("source_setup_and_backup", harness.source_setup)
        harness.case("restore_and_clone", harness.restore_and_clone)
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
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=[
                          "Synthetic loopback processes and disposable databases, not a production RPO/RTO promise.",
                          "Both databases and the backup volume are local to this run.",
                          "The restore verifies Git objects, refs, pin receipt and repository format; it does not test host power loss.",
                      ])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
