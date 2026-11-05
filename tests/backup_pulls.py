#!/usr/bin/env python3
"""Offline paired backup, verify, and isolated restore of PRs, Reviews, Check Runs, Branch Rules, and Merged Git Refs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pulls import PullsHarness, migration_009_path  # noqa: E402
from restored_workers import RestoredWorkers  # noqa: E402
from schema_baseline import EXPECTED_TABLES, SCHEMA_VERSION_CSV, SCHEMA_VERSIONS, TABLE_COUNT  # noqa: E402


PULL_TABLES = (
    "forge_creation_requests",
    "forge_pull_counters",
    "forge_pulls",
    "forge_pull_reviews",
    "forge_check_runs",
    "forge_branch_rules",
)


class BackupPullsHarness(RestoredWorkers):
    document = PullsHarness.document
    ensure_migration_009 = PullsHarness.ensure_migration_009

    def pull_rows(self):
        return {
            table: self.rows(
                "SELECT * FROM " + table + " t ORDER BY to_jsonb(t)::text"
            )
            for table in PULL_TABLES
        }

    def git_authority(self):
        repos = self.rows(
            "SELECT id,storage_generation FROM repositories ORDER BY id"
        )
        root = Path(self.env["ROOTYARD_DATA_DIR"])
        return dict(
            repositories=repos,
            operations=self.rows(
                "SELECT * FROM git_operations t ORDER BY to_jsonb(t)::text"
            ),
            outbox=self.rows(
                "SELECT * FROM outbox_events t ORDER BY to_jsonb(t)::text"
            ),
            refs={
                r["id"]: self.git(
                    "--git-dir=" + str(root / "repos" / (r["id"] + ".git")),
                    "for-each-ref",
                    "--format=%(refname) %(objectname)",
                ).stdout.decode()
                for r in repos
            },
        )

    def populated_pulls_source(self):
        super().recovery_source()
        self.ensure_migration_009()
        self.start()
        self.pullspath = "/api/repos/alice/demo/pulls"
        self.checkspath = "/api/repos/alice/demo/checks"
        self.rulespath = "/api/repos/alice/demo/branch-rules"

        work = self.root / "work-backup-pulls"
        self.git("clone", self.base + "/git/alice/demo.git", str(work), token=self.alice)
        self.git("config", "user.name", "alice", cwd=work)
        self.git("config", "user.email", "alice@rootyard.local", cwd=work)

        (work / "base.txt").write_text("base\n")
        self.git("add", "base.txt", cwd=work)
        self.git("commit", "-m", "base commit", cwd=work)
        self.base_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)

        (work / "pr1.txt").write_text("merged before backup\n")
        self.git("add", "pr1.txt", cwd=work)
        self.git("commit", "-m", "pr1 commit", cwd=work)
        self.pr1_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git(
            "push", "origin", "HEAD:refs/heads/pr-merged", cwd=work, token=self.alice
        )

        (work / "pr2.txt").write_text("closed before backup\n")
        self.git("add", "pr2.txt", cwd=work)
        self.git("commit", "-m", "pr2 commit", cwd=work)
        self.pr2_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git(
            "push", "origin", "HEAD:refs/heads/pr-closed", cwd=work, token=self.alice
        )

        (work / "pr3.txt").write_text("open at backup, merged after restore\n")
        self.git("add", "pr3.txt", cwd=work)
        self.git("commit", "-m", "pr3 commit", cwd=work)
        self.pr3_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git(
            "push", "origin", "HEAD:refs/heads/pr-open", cwd=work, token=self.alice
        )

        (work / "pr4.txt").write_text("created after backup\n")
        self.git("add", "pr4.txt", cwd=work)
        self.git("commit", "-m", "pr4 commit", cwd=work)
        self.pr4_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git(
            "push",
            "origin",
            "HEAD:refs/heads/pr-post-restore",
            cwd=work,
            token=self.alice,
        )

        # Configure branch rule on refs/heads/main.
        self.rule = self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "required_approvals": 1,
                "required_checks": ["ci/build"],
                "require_fast_forward": True,
            },
        )

        # PR #1: approved, passing check, merged before backup.
        self.pr1 = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "PR 1 Merged",
                "body": "Merged before backup",
                "head_ref": "refs/heads/pr-merged",
                "base_ref": "refs/heads/main",
            },
        )
        self.document(
            f"{self.pullspath}/1/reviews",
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.pr1_oid,
                "body": "Approve PR 1",
            },
        )
        self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.pr1_oid,
                "context": "ci/build",
                "status": "completed",
                "conclusion": "success",
            },
        )
        self.pr1_merge_payload = {
            "expected_version": 1,
            "expected_head_oid": self.pr1_oid,
            "expected_base_oid": self.base_oid,
            "storage_generation": 1,
            "strategy": "fast_forward",
        }
        self.pr1_merged = self.document(
            f"{self.pullspath}/1/merge",
            200,
            method="POST",
            body=self.pr1_merge_payload,
            extra_headers={"Idempotency-Key": "backup-merge-1"},
        )
        self.drain()

        # PR #2: changes_requested and closed before backup.
        self.pr2 = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "PR 2 Closed",
                "head_ref": "refs/heads/pr-closed",
                "base_ref": "refs/heads/main",
            },
        )
        self.document(
            f"{self.pullspath}/2/reviews",
            201,
            method="POST",
            body={
                "state": "changes_requested",
                "commit_oid": self.pr2_oid,
                "body": "Close for now",
            },
        )
        self.pr2_closed = self.document(
            f"{self.pullspath}/2",
            method="PATCH",
            body={"expected_version": 1, "state": "closed"},
        )

        # PR #3: open at backup with approval and passing check on pr3_oid, ready to merge post-restore.
        self.pr3 = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "PR 3 Open",
                "head_ref": "refs/heads/pr-open",
                "base_ref": "refs/heads/main",
            },
        )
        self.document(
            f"{self.pullspath}/3/reviews",
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.pr3_oid,
                "body": "Ready for post-restore merge",
            },
        )
        self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.pr3_oid,
                "context": "ci/build",
                "status": "completed",
                "conclusion": "success",
            },
        )

        self.stop()
        self.source_rows = self.all_rows()
        self.backed_up_pulls = self.pull_rows()
        self.initial_git_authority = self.git_authority()
        self.pull_counters = {
            r["repository_id"]: r["next_number"]
            for r in self.source_rows["forge_pull_counters"]
        }
        self.backup = self.root / "pulls-backup"
        self.backup_result = json.loads(self.backup_command().stdout)
        self.cli("backup-verify", str(self.backup))
        return dict(
            pulls_backed_up=len(self.source_rows["forge_pulls"]),
            reviews_backed_up=len(self.source_rows["forge_pull_reviews"]),
            checks_backed_up=len(self.source_rows["forge_check_runs"]),
            rules_backed_up=len(self.source_rows["forge_branch_rules"]),
        )

    def post_backup_mutations_not_in_snapshot(self):
        self.start()
        self.after_pr = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "after-backup-pr",
                "head_ref": "refs/heads/pr-post-restore",
                "base_ref": "refs/heads/main",
            },
        )
        self.document(
            f"{self.pullspath}/3",
            method="PATCH",
            body={"expected_version": 1, "state": "closed"},
        )
        self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "expected_version": 1,
                "required_approvals": 2,
                "required_checks": ["ci/build"],
                "require_fast_forward": True,
            },
        )
        self.stop()
        assert self.pull_rows() != self.backed_up_pulls
        return dict(post_backup_pr_number=self.after_pr["number"])

    def restore_pulls_exact(self):
        result = super().restore_exact()
        assert self.all_rows() == self.source_rows
        assert self.pull_rows() == self.backed_up_pulls
        assert (
            self.sql("SELECT count(*) FROM forge_pulls WHERE title='after-backup-pr'")
            == "0"
        )
        assert (
            self.sql(
                "SELECT state FROM forge_pulls WHERE number=1"
            )
            == "merged"
        )
        assert (
            self.sql(
                "SELECT state FROM forge_pulls WHERE number=2"
            )
            == "closed"
        )
        assert (
            self.sql(
                "SELECT state FROM forge_pulls WHERE number=3"
            )
            == "open"
        )
        assert self.git_authority() == self.initial_git_authority
        return {**result, "pull_tables_restored_exact": True}

    def restored_pulls_access_and_post_restore_merge(self):
        self.start()
        assert self.document(f"{self.pullspath}/1") == self.pr1_merged
        assert self.document(f"{self.pullspath}/2") == self.pr2_closed
        assert self.document(f"{self.pullspath}/3") == self.pr3
        assert self.document(self.rulespath)["items"] == [self.rule]

        # Idempotent replay of PR #1 merge on restored node returns saved response without new git op.
        ops_list = self.document("/api/repos/alice/demo/operations")
        assert isinstance(ops_list, list)
        ops_before = len(ops_list)
        replayed = self.document(
            f"{self.pullspath}/1/merge",
            200,
            method="POST",
            body=self.pr1_merge_payload,
            extra_headers={"Idempotency-Key": "backup-merge-1"},
        )
        assert replayed == self.pr1_merged
        assert (
            len(self.document("/api/repos/alice/demo/operations"))
            == ops_before
        )

        # Merge restored open PR #3 using pre-backup approval and check run!
        merged3 = self.document(
            f"{self.pullspath}/3/merge",
            200,
            method="POST",
            body={
                "expected_version": 1,
                "expected_head_oid": self.pr3_oid,
                "expected_base_oid": self.pr1_oid,
                "storage_generation": 1,
                "strategy": "fast_forward",
            },
        )
        assert merged3["state"] == "merged"
        assert merged3["merge_commit_oid"] == self.pr3_oid

        # Allocate new PR in restored environment -> reuses snapshot counter (4).
        new_pr = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "Restored PR 4",
                "head_ref": "refs/heads/pr-post-restore",
                "base_ref": "refs/heads/main",
            },
        )
        assert new_pr["number"] == self.pull_counters[self.repo["id"]]

        self.drain()
        verify_clone = self.root / "verify-restored-clone"
        self.git(
            "clone",
            self.base + "/git/alice/demo.git",
            str(verify_clone),
            token=self.alice,
        )
        self.git("fsck", "--full", "--strict", cwd=verify_clone)
        self.stop()
        return dict(
            restored_pr3_merged=True,
            restored_counter_reused=new_pr["number"],
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    h = BackupPullsHarness(args)
    success = False
    try:
        for name in (
            "populated_pulls_source",
            "post_backup_mutations_not_in_snapshot",
            "restore_pulls_exact",
            "restored_pulls_access_and_post_restore_merge",
        ):
            h.case(name, getattr(h, name))
        success = True
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:
            success = False
            h.results.append(
                dict(name="cleanup", status="failed", error=h.redact(error))
            )
        report = dict(
            passed=success,
            cases=h.results,
            binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            limitations=[
                "Synthetic local PostgreSQL clusters and fresh test-owned volumes, not production failover.",
                "Backup is a point-in-time boundary: acknowledged later PR mutations are intentionally not recovered.",
            ],
        )
        if args.keep:
            report["retained_directory"] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
