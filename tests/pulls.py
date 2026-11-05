#!/usr/bin/env python3
"""Private-owner Pull Request, Review, Check Run, Branch Rule, and Atomic Merge contract."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from forge import ForgeHarness  # noqa: E402
from schema_baseline import SCHEMA_VERSION_CSV, SCHEMA_VERSIONS  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def migration_009_path() -> Path:
    promoted = ROOT / "migrations/009_forge_pulls.sql"
    if promoted.is_file():
        return promoted
    return ROOT / "src/pulls/009_forge_pulls.sql"


class PullsHarness(ForgeHarness):
    def document(self, path, code=200, token=None, **kwargs):
        status, body, headers = self.http(path, token=token or self.alice, **kwargs)
        expected = code if isinstance(code, tuple) else (code,)
        assert status in expected, f"{path}: expected {code}, got {status}: {body[:200]!r}"
        assert headers.get("cache-control") == "no-store", headers
        assert "application/json" in headers.get("content-type", "")
        return json.loads(body)

    def ensure_migration_009(self):
        if self.sql("SELECT to_regclass('forge_pulls') IS NOT NULL") != "t":
            self.run(
                [
                    "psql",
                    self.db,
                    "-X",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-f",
                    str(migration_009_path()),
                ]
            )

    def init_repo_branches(self, clone_url_path: str, work_dir: Path, token: dict):
        self.git("clone", self.base + clone_url_path, str(work_dir), token=token)
        self.git("config", "user.name", token["username"], cwd=work_dir)
        self.git(
            "config",
            "user.email",
            f"{token['username']}@rootyard.local",
            cwd=work_dir,
        )
        (work_dir / "README.md").write_text("rootyard\n")
        self.git("add", "README.md", cwd=work_dir)
        self.git("commit", "-m", "initial main commit", cwd=work_dir)
        base_oid = (
            self.git("rev-parse", "HEAD", cwd=work_dir).stdout.decode().strip()
        )
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work_dir, token=token)

        (work_dir / "feature.txt").write_text("feature v1\n")
        self.git("add", "feature.txt", cwd=work_dir)
        self.git("commit", "-m", "add feature v1", cwd=work_dir)
        feat1_oid = (
            self.git("rev-parse", "HEAD", cwd=work_dir).stdout.decode().strip()
        )
        self.git(
            "push", "origin", "HEAD:refs/heads/feature", cwd=work_dir, token=token
        )
        return base_oid, feat1_oid

    def setup(self):
        super().setup()
        self.ensure_migration_009()
        self.pullspath = "/api/repos/alice/forge/pulls"
        self.checkspath = "/api/repos/alice/forge/checks"
        self.rulespath = "/api/repos/alice/forge/branch-rules"
        self.other_pullspath = "/api/repos/alice/other/pulls"
        self.bob_pullspath = "/api/repos/bob/forge/pulls"

        self.work = self.root / "work-alice-forge"
        self.base_oid, self.feat1_oid = self.init_repo_branches(
            "/git/alice/forge.git", self.work, self.alice
        )
        (self.work / "feature.txt").write_text("feature v2\n")
        self.git("add", "feature.txt", cwd=self.work)
        self.git("commit", "-m", "update feature v2", cwd=self.work)
        self.feat2_oid = (
            self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        )
        self.git(
            "push",
            "origin",
            "HEAD:refs/heads/feature-v2",
            cwd=self.work,
            token=self.alice,
        )

        # Create non-fast-forward diverged branches from base_oid.
        self.git("checkout", "--detach", self.base_oid, cwd=self.work)
        (self.work / "other_file.txt").write_text("target branch change\n")
        self.git("add", "other_file.txt", cwd=self.work)
        self.git("commit", "-m", "diverged target", cwd=self.work)
        self.diverged_base_oid = (
            self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        )
        self.git(
            "push",
            "origin",
            "HEAD:refs/heads/target-nonff",
            cwd=self.work,
            token=self.alice,
        )

        self.git("checkout", "--detach", self.base_oid, cwd=self.work)
        (self.work / "source_file.txt").write_text("source branch change\n")
        self.git("add", "source_file.txt", cwd=self.work)
        self.git("commit", "-m", "diverged source", cwd=self.work)
        self.diverged_head_oid = (
            self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        )
        self.git(
            "push",
            "origin",
            "HEAD:refs/heads/source-nonff",
            cwd=self.work,
            token=self.alice,
        )

        self.other_base_oid, self.other_feat_oid = self.init_repo_branches(
            "/git/alice/other.git", self.root / "work-alice-other", self.alice
        )
        self.bob_base_oid, self.bob_feat_oid = self.init_repo_branches(
            "/git/bob/forge.git", self.root / "work-bob-forge", self.bob
        )

    def migration(self):
        self.stop()
        assert (
            self.sql("SELECT count(*) FROM schema_migrations WHERE version=9") == "1"
        )
        self.sql(
            "DROP TABLE forge_pull_reviews, forge_pulls, forge_pull_counters, forge_check_runs, forge_branch_rules; "
            "DELETE FROM schema_migrations WHERE version=9; "
            "CREATE TABLE forge_pull_reviews(dummy integer)"
        )
        if 9 in SCHEMA_VERSIONS:
            failed = self.run([self.args.binary, "migrate"], check=False)
        else:
            failed = self.run(
                [
                    "psql",
                    self.db,
                    "-X",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "--single-transaction",
                    "-f",
                    str(migration_009_path()),
                ],
                check=False,
            )
        assert failed.returncode != 0
        assert (
            self.sql("SELECT count(*) FROM schema_migrations WHERE version=9") == "0"
        )
        assert (
            self.sql(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema=current_schema() AND table_name IN ("
                "'forge_pulls','forge_pull_counters','forge_check_runs','forge_branch_rules')"
            )
            == "0"
        )
        self.sql("DROP TABLE forge_pull_reviews")
        if 9 in SCHEMA_VERSIONS:
            self.cli("migrate")
            self.cli("migrate")
            assert (
                self.sql(
                    "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations"
                )
                == SCHEMA_VERSION_CSV
            )
        else:
            self.ensure_migration_009()
        assert (
            self.sql("SELECT count(*) FROM schema_migrations WHERE version=9") == "1"
        )
        self.start()

    def lifecycle_and_diff(self):
        self.pr1 = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "Add feature",
                "body": "Initial PR\n<script>raw</script>",
                "head_ref": "refs/heads/feature",
                "base_ref": "refs/heads/main",
            },
            extra_headers={"Idempotency-Key": "create-pr-1"},
        )
        assert (
            self.pr1["number"] == 1
            and self.pr1["state"] == "open"
            and self.pr1["version"] == 1
        )
        assert self.pr1["head_oid"] == self.feat1_oid
        assert self.pr1["base_oid"] == self.base_oid
        assert self.pr1["merge_commit_oid"] is None
        assert self.pr1["merged_storage_generation"] is None

        # Idempotent replay of PR creation returns identical 201 response.
        replayed = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "Add feature",
                "body": "Initial PR\n<script>raw</script>",
                "head_ref": "refs/heads/feature",
                "base_ref": "refs/heads/main",
            },
            extra_headers={"Idempotency-Key": "create-pr-1"},
        )
        assert replayed == self.pr1

        self.pr1_path = self.pullspath + "/1"
        fetched = self.document(self.pr1_path, token=self.reader)
        assert fetched == self.pr1

        diff = self.document(self.pr1_path + "/diff", token=self.reader)
        assert diff["pull_number"] == 1
        assert diff["base_oid"] == self.base_oid
        assert diff["head_oid"] == self.feat1_oid
        assert diff["fast_forward"] is True
        assert "+feature v1" in diff["diff"]

        closed = self.document(
            self.pr1_path,
            method="PATCH",
            body={
                "expected_version": 1,
                "title": "Add feature (updated)",
                "state": "closed",
            },
        )
        assert closed["version"] == 2 and closed["state"] == "closed"
        self.document(
            self.pr1_path,
            409,
            method="PATCH",
            body={"expected_version": 1, "title": "Stale"},
        )
        self.document(
            self.pr1_path,
            400,
            method="PATCH",
            body={"expected_version": 2, "state": "merged"},
        )
        reopened = self.document(
            self.pr1_path,
            method="PATCH",
            body={"expected_version": 2, "state": "open", "body": "Reopened"},
        )
        assert reopened["version"] == 3 and reopened["state"] == "open"

    def reviews_and_head_binding(self):
        reviews_path = self.pr1_path + "/reviews"
        # Wrong/stale commit_oid must be rejected with 409 Conflict.
        self.document(
            reviews_path,
            409,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.base_oid,
                "body": "Wrong commit",
            },
        )
        r1 = self.document(
            reviews_path,
            201,
            method="POST",
            body={
                "state": "commented",
                "commit_oid": self.feat1_oid,
                "body": "Looks promising",
            },
        )
        assert (
            r1["number"] == 1
            and r1["pull_number"] == 1
            and r1["pull_version"] == 3
        )
        r2 = self.document(
            reviews_path,
            201,
            method="POST",
            body={
                "state": "changes_requested",
                "commit_oid": self.feat1_oid,
                "body": "Needs tests",
            },
        )
        assert r2["number"] == 2 and r2["state"] == "changes_requested"
        r3 = self.document(
            reviews_path,
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.feat1_oid,
                "body": "LGTM",
            },
            extra_headers={"Idempotency-Key": "review-pr1-3"},
        )
        assert r3["number"] == 3 and r3["state"] == "approved"
        assert (
            self.document(
                reviews_path,
                201,
                method="POST",
                body={
                    "state": "approved",
                    "commit_oid": self.feat1_oid,
                    "body": "LGTM",
                },
                extra_headers={"Idempotency-Key": "review-pr1-3"},
            )
            == r3
        )
        # Reviews do not increment PR content version.
        assert self.document(self.pr1_path)["version"] == 3

        page1 = self.document(reviews_path + "?limit=2", token=self.reader)
        assert [i["number"] for i in page1["items"]] == [1, 2]
        assert page1["next_after"] == 2
        page2 = self.document(reviews_path + "?limit=2&after=2", token=self.reader)
        assert [i["number"] for i in page2["items"]] == [3]
        assert page2["next_after"] is None

    def checks_and_monotonic_ordering(self):
        c1 = self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "queued",
                "attempt": 1,
                "sequence": 1,
            },
        )
        assert c1["status"] == "queued" and c1["attempt"] == 1 and c1["sequence"] == 1

        c2 = self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "in_progress",
                "attempt": 1,
                "sequence": 2,
            },
        )
        assert c2["status"] == "in_progress" and c2["sequence"] == 2

        # Out-of-order lower sequence must fail with 409.
        self.document(
            self.checkspath,
            409,
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "queued",
                "attempt": 1,
                "sequence": 1,
            },
        )

        self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "completed",
                "conclusion": "failure",
                "output": "1 failed",
                "attempt": 1,
                "sequence": 3,
            },
        )
        self.document(
            self.checkspath,
            409,
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "in_progress",
                "attempt": 1,
                "sequence": 2,
            },
        )

        # Retry attempt 2 supersedes attempt 1.
        commit_checks_path = f"/api/repos/alice/forge/commits/{self.feat1_oid}/checks"
        c_attempt2 = self.document(
            commit_checks_path,
            (200, 201),
            method="POST",
            body={
                "context": "ci/test",
                "status": "completed",
                "conclusion": "success",
                "output": "all passed",
                "attempt": 2,
                "sequence": 1,
            },
        )
        assert c_attempt2["attempt"] == 2 and c_attempt2["conclusion"] == "success"

        # Stale attempt 1 is rejected even with high sequence.
        self.document(
            commit_checks_path,
            409,
            method="POST",
            body={
                "context": "ci/test",
                "status": "completed",
                "conclusion": "failure",
                "attempt": 1,
                "sequence": 99,
            },
        )

        # Idempotent retry at exact (attempt=2, sequence=1) with identical payload succeeds.
        self.document(
            commit_checks_path,
            (200, 201),
            method="POST",
            body={
                "context": "ci/test",
                "status": "completed",
                "conclusion": "success",
                "output": "all passed",
                "attempt": 2,
                "sequence": 1,
            },
        )
        # Conflicting state at same (attempt=2, sequence=1) is rejected with 409.
        self.document(
            commit_checks_path,
            409,
            method="POST",
            body={
                "context": "ci/test",
                "status": "completed",
                "conclusion": "failure",
                "output": "all passed",
                "attempt": 2,
                "sequence": 1,
            },
        )

        self.document(
            commit_checks_path,
            (200, 201),
            method="POST",
            body={
                "context": "ci/lint",
                "status": "completed",
                "conclusion": "success",
                "attempt": 1,
                "sequence": 1,
            },
        )

        by_commit = self.document(commit_checks_path, token=self.reader)
        assert [c["context"] for c in by_commit["items"]] == ["ci/lint", "ci/test"]
        by_pull = self.document(self.pr1_path + "/checks", token=self.reader)
        assert [c["context"] for c in by_pull["items"]] == ["ci/lint", "ci/test"]

    def branch_rules_and_stale_invalidation(self):
        rule = self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "required_approvals": 1,
                "required_checks": ["ci/test"],
                "require_fast_forward": True,
            },
        )
        assert rule["version"] == 1 and rule["branch_ref"] == "refs/heads/main"

        self.document(
            self.rulespath,
            409,
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "expected_version": 99,
                "required_approvals": 1,
                "required_checks": ["ci/test", "ci/lint"],
                "require_fast_forward": True,
            },
        )
        updated_rule = self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "expected_version": 1,
                "required_approvals": 1,
                "required_checks": ["ci/test", "ci/lint"],
                "require_fast_forward": True,
            },
        )
        assert updated_rule["version"] == 2
        listed = self.document(self.rulespath, token=self.reader)
        assert len(listed["items"]) == 1 and listed["items"][0]["version"] == 2

        # Advance refs/heads/feature in native Git to feat2_oid.
        self.git(
            "push",
            "origin",
            f"{self.feat2_oid}:refs/heads/feature",
            cwd=self.work,
            token=self.alice,
        )
        # Merge with old expected_head_oid must fail because live ref moved to feat2_oid.
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": 3,
                "expected_head_oid": self.feat1_oid,
                "expected_base_oid": self.base_oid,
            },
        )

        # Update PR #1 head_oid to feat2_oid.
        updated_pr = self.document(
            self.pr1_path,
            method="PATCH",
            body={"expected_version": 3, "head_oid": self.feat2_oid},
        )
        assert updated_pr["version"] == 4 and updated_pr["head_oid"] == self.feat2_oid

        # Merge must now fail with 409 because reviews and checks on feat1_oid do not apply to feat2_oid!
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": 4,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )

        # Approve feat2_oid, but required checks are still missing on feat2_oid.
        self.document(
            self.pr1_path + "/reviews",
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.feat2_oid,
                "body": "Approved v2",
            },
        )
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": 4,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )

        # Add passing ci/test and failing ci/lint on feat2_oid -> merge still blocked.
        self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat2_oid,
                "context": "ci/test",
                "status": "completed",
                "conclusion": "success",
                "attempt": 1,
                "sequence": 1,
            },
        )
        self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat2_oid,
                "context": "ci/lint",
                "status": "completed",
                "conclusion": "failure",
                "attempt": 1,
                "sequence": 1,
            },
        )
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": 4,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )

        # Advance ci/lint to success on feat2_oid -> all branch rules satisfied.
        self.document(
            self.checkspath,
            (200, 201),
            method="POST",
            body={
                "commit_oid": self.feat2_oid,
                "context": "ci/lint",
                "status": "completed",
                "conclusion": "success",
                "attempt": 1,
                "sequence": 2,
            },
        )

        # Require 2 approvals; an intervening changes_requested must invalidate prior approvals on feat2_oid.
        self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/main",
                "expected_version": 2,
                "required_approvals": 2,
                "required_checks": ["ci/test", "ci/lint"],
                "require_fast_forward": True,
            },
        )
        self.document(
            self.pr1_path + "/reviews",
            201,
            method="POST",
            body={
                "state": "changes_requested",
                "commit_oid": self.feat2_oid,
                "body": "Request changes after first approval",
            },
        )
        self.document(
            self.pr1_path + "/reviews",
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.feat2_oid,
                "body": "First approval after changes_requested",
            },
        )
        # Only 1 approval after changes_requested -> merge must still be blocked with 409.
        self.document(
            self.pr1_path + "/merge",
            409,
            method="POST",
            body={
                "expected_version": 4,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )
        # Second approval after changes_requested satisfies required_approvals=2.
        self.document(
            self.pr1_path + "/reviews",
            201,
            method="POST",
            body={
                "state": "approved",
                "commit_oid": self.feat2_oid,
                "body": "Second approval after changes_requested",
            },
        )

    def atomic_merge_and_idempotency(self):
        merge_path = self.pr1_path + "/merge"
        # CAS precondition mismatches must return 409.
        for bad_payload in (
            {
                "expected_version": 3,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
            {
                "expected_version": 4,
                "expected_head_oid": self.feat1_oid,
                "expected_base_oid": self.base_oid,
            },
            {
                "expected_version": 4,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.feat1_oid,
            },
            {
                "expected_version": 4,
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
                "storage_generation": 99,
            },
        ):
            self.document(merge_path, 409, method="POST", body=bad_payload)

        merge_payload = {
            "expected_version": 4,
            "expected_head_oid": self.feat2_oid,
            "expected_base_oid": self.base_oid,
            "storage_generation": 1,
            "strategy": "fast_forward",
        }
        merged = self.document(
            merge_path,
            200,
            method="POST",
            body=merge_payload,
            extra_headers={"Idempotency-Key": "merge-pr-1"},
        )
        assert merged["state"] == "merged" and merged["version"] == 5
        assert merged["merge_commit_oid"] == self.feat2_oid
        assert merged["merged_storage_generation"] == 1

        # Verify native Git ref refs/heads/main moved to feat2_oid.
        ls_out = (
            self.git(
                "ls-remote",
                self.base + "/git/alice/forge.git",
                "refs/heads/main",
                token=self.alice,
            )
            .stdout.decode()
            .strip()
        )
        assert ls_out.startswith(self.feat2_oid), ls_out

        # Verify operations and outbox recorded the merge ref update.
        ops = self.document("/api/repos/alice/forge/operations")
        assert isinstance(ops, list)
        assert any(
            op["outcome"] == "recorded"
            and op["evidence_summary"]["kind"] == "pull_merge"
            for op in ops
        )

        # Idempotent replay of merge returns identical 200 response.
        replayed = self.document(
            merge_path,
            200,
            method="POST",
            body=merge_payload,
            extra_headers={"Idempotency-Key": "merge-pr-1"},
        )
        assert replayed == merged

        # Conflicting payload with same Idempotency-Key returns 409.
        self.document(
            merge_path,
            409,
            method="POST",
            body={**merge_payload, "strategy": "merge_commit"},
            extra_headers={"Idempotency-Key": "merge-pr-1"},
        )

        # Merged PR is terminal.
        self.document(
            self.pr1_path,
            409,
            method="PATCH",
            body={"expected_version": 5, "state": "open"},
        )
        self.document(
            self.pr1_path + "/reviews",
            409,
            method="POST",
            body={
                "state": "commented",
                "commit_oid": self.feat2_oid,
                "body": "After merge",
            },
        )
        self.document(merge_path, 409, method="POST", body=merge_payload)

        # Non-fast-forward PR #2 with merge_commit strategy.
        pr2 = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "Non-FF merge",
                "head_ref": "refs/heads/source-nonff",
                "base_ref": "refs/heads/target-nonff",
            },
        )
        assert pr2["number"] == 2
        diff2 = self.document(f"{self.pullspath}/2/diff")
        assert diff2["fast_forward"] is False

        self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/target-nonff",
                "required_approvals": 0,
                "required_checks": [],
                "require_fast_forward": True,
            },
        )
        # Fast-forward fails because branches diverged; merge_commit fails because rule requires FF.
        for strat in ("fast_forward", "merge_commit"):
            self.document(
                f"{self.pullspath}/2/merge",
                409,
                method="POST",
                body={
                    "expected_version": 1,
                    "expected_head_oid": self.diverged_head_oid,
                    "expected_base_oid": self.diverged_base_oid,
                    "strategy": strat,
                },
            )
        # Allow merge_commit on target-nonff and merge PR #2.
        self.document(
            self.rulespath,
            (200, 201),
            method="PUT",
            body={
                "branch_ref": "refs/heads/target-nonff",
                "expected_version": 1,
                "required_approvals": 0,
                "required_checks": [],
                "require_fast_forward": False,
            },
        )
        merged2 = self.document(
            f"{self.pullspath}/2/merge",
            200,
            method="POST",
            body={
                "expected_version": 1,
                "expected_head_oid": self.diverged_head_oid,
                "expected_base_oid": self.diverged_base_oid,
                "strategy": "merge_commit",
            },
        )
        assert merged2["state"] == "merged"
        assert (
            merged2["merge_commit_oid"] is not None
            and merged2["merge_commit_oid"] != self.diverged_head_oid
        )

    def access_and_boundaries(self):
        read_paths = [
            self.pullspath,
            self.pr1_path,
            self.pr1_path + "/diff",
            self.pr1_path + "/reviews",
            self.pr1_path + "/checks",
            f"/api/repos/alice/forge/commits/{self.feat2_oid}/checks",
            self.rulespath,
        ]
        for path in read_paths:
            self.expect(path, 401)
            self.document(path, 404, token=self.bob)
            self.document(path, token=self.reader)

        write_calls = [
            (
                self.pullspath,
                "POST",
                {
                    "title": "Denied",
                    "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main",
                },
            ),
            (
                self.pr1_path,
                "PATCH",
                {"expected_version": 5, "title": "Denied"},
            ),
            (
                self.pr1_path + "/reviews",
                "POST",
                {
                    "state": "approved",
                    "commit_oid": self.feat2_oid,
                    "body": "Denied",
                },
            ),
            (
                self.checkspath,
                "POST",
                {
                    "commit_oid": self.feat2_oid,
                    "context": "ci/denied",
                    "status": "queued",
                },
            ),
            (
                self.rulespath,
                "PUT",
                {"branch_ref": "refs/heads/main", "required_approvals": 1},
            ),
            (
                self.pr1_path + "/merge",
                "POST",
                {
                    "expected_version": 5,
                    "expected_head_oid": self.feat2_oid,
                    "expected_base_oid": self.base_oid,
                },
            ),
        ]
        for path, method, body in write_calls:
            self.document(path, 403, token=self.reader, method=method, body=body)
            self.document(path, 404, token=self.bob, method=method, body=body)

        # Validation boundaries (400 and 422).
        for bad_title in ("", " \t", "a\nb", "a\0b", "x" * 257):
            self.document(
                self.pullspath,
                400,
                method="POST",
                body={
                    "title": bad_title,
                    "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main",
                },
            )
        self.document(
            self.pullspath,
            400,
            method="POST",
            body={
                "title": "Same branch",
                "head_ref": "refs/heads/main",
                "base_ref": "refs/heads/main",
            },
        )
        for spoof_field in (
            "author_id",
            "tenant_id",
            "repository_id",
            "state",
            "number",
            "merge_commit_oid",
        ):
            self.expect(
                self.pullspath,
                422,
                token=self.alice,
                method="POST",
                body={
                    "title": "spoof",
                    "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main",
                    spoof_field: str(uuid.uuid4()),
                },
            )
        for suffix in (
            "?limit=0",
            "?limit=101",
            "?after=-1",
            "?extra=1",
            "?state=invalid",
        ):
            self.expect(self.pullspath + suffix, 400, token=self.alice)

        # Recovering repository freezes all Track 1 endpoints with 409.
        self.sql(
            f"UPDATE repositories SET state='recovering' WHERE id='{self.repo['id']}'"
        )
        try:
            for path in read_paths:
                self.document(path, 409)
            for path, method, body in write_calls:
                self.document(path, 409, method=method, body=body)
        finally:
            self.sql(
                f"UPDATE repositories SET state='ready' WHERE id='{self.repo['id']}'"
            )

    def concurrency_and_pagination(self):
        before = int(
            self.sql(
                f"SELECT count(*) FROM forge_pulls WHERE repository_id='{self.repo['id']}'"
            )
        )

        def create_pr(i):
            return self.document(
                self.pullspath,
                201,
                method="POST",
                body={
                    "title": f"Concurrent PR {i}",
                    "head_ref": "refs/heads/feature-v2",
                    "base_ref": "refs/heads/target-nonff",
                },
            )["number"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            numbers = list(ex.map(create_pr, range(12)))
        assert len(set(numbers)) == 12
        assert sorted(numbers) == list(range(before + 1, before + 13))

        target_pr_path = f"{self.pullspath}/{numbers[0]}"
        current = self.document(target_pr_path)

        def patch_pr(i):
            return self.http(
                target_pr_path,
                token=self.alice,
                method="PATCH",
                body={
                    "expected_version": current["version"],
                    "title": f"CAS title {i}",
                },
            )[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            codes = list(ex.map(patch_pr, range(8)))
        assert codes.count(200) == 1 and codes.count(409) == 7, codes

        seen = []
        cursor = 0
        while cursor is not None:
            page = self.document(f"{self.pullspath}?limit=5&after={cursor}")
            assert len(page["items"]) <= 5
            seen.extend(p["number"] for p in page["items"])
            cursor = page["next_after"]
        assert seen == list(range(1, before + 13)), seen

    def database_boundaries_and_rollback(self):
        tenant, repo, wrong = (
            self.alice["user_id"],
            self.repo["id"],
            self.bob["user_id"],
        )
        bad_sqls = [
            f"INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,head_ref,base_ref,head_oid,base_oid) "
            f"VALUES('{wrong}','{repo}',900,'{wrong}','cross tenant','refs/heads/feature','refs/heads/main','{self.feat1_oid}','{self.base_oid}')",
            f"INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,head_ref,base_ref,head_oid,base_oid) "
            f"VALUES('{tenant}','{repo}',900,'{wrong}','spoof author','refs/heads/feature','refs/heads/main','{self.feat1_oid}','{self.base_oid}')",
            f"INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,state,head_ref,base_ref,head_oid,base_oid) "
            f"VALUES('{tenant}','{repo}',900,'{tenant}','merged without oid','merged','refs/heads/feature','refs/heads/main','{self.feat1_oid}','{self.base_oid}')",
            f"INSERT INTO forge_check_runs(tenant_id,repository_id,commit_oid,context,status) "
            f"VALUES('{tenant}','{repo}','{self.feat1_oid}','ci/bad','completed')",
        ]
        for stmt in bad_sqls:
            res = self.run(
                ["psql", self.db, "-X", "-v", "ON_ERROR_STOP=1", "-c", stmt],
                check=False,
            )
            assert res.returncode != 0

        counter = self.sql(
            f"SELECT next_number FROM forge_pull_counters WHERE repository_id='{repo}'"
        )
        self.sql(
            "ALTER TABLE forge_pulls ADD CONSTRAINT fixture_failure CHECK (title <> 'injected pull failure')"
        )
        try:
            self.document(
                self.pullspath,
                503,
                method="POST",
                body={
                    "title": "injected pull failure",
                    "head_ref": "refs/heads/feature-v2",
                    "base_ref": "refs/heads/target-nonff",
                },
            )
        finally:
            self.sql("ALTER TABLE forge_pulls DROP CONSTRAINT fixture_failure")
        assert (
            self.sql(
                f"SELECT next_number FROM forge_pull_counters WHERE repository_id='{repo}'"
            )
            == counter
        )

    def restart(self):
        pr1 = self.document(self.pr1_path)
        reviews = self.document(self.pr1_path + "/reviews")
        checks = self.document(self.pr1_path + "/checks")
        rules = self.document(self.rulespath)
        self.stop(hard=True)
        self.start()
        assert self.document(self.pr1_path) == pr1
        assert self.document(self.pr1_path + "/reviews") == reviews
        assert self.document(self.pr1_path + "/checks") == checks
        assert self.document(self.rulespath) == rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = PullsHarness(args)
    success = False
    try:
        for name in (
            "setup",
            "migration",
            "lifecycle_and_diff",
            "reviews_and_head_binding",
            "checks_and_monotonic_ordering",
            "branch_rules_and_stale_invalidation",
            "atomic_merge_and_idempotency",
            "access_and_boundaries",
            "concurrency_and_pagination",
            "database_boundaries_and_rollback",
            "restart",
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
        report = dict(
            passed=success,
            cases=harness.results,
            binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            limitations=[
                "Personal owner-only tenancy, not organization/collaborator ACLs.",
                "Same-generation atomic merge covers local bare repositories and PostgreSQL outbox.",
            ],
        )
        if args.keep:
            report["retained_directory"] = str(harness.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
