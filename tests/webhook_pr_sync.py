#!/usr/bin/env python3
"""Native issues #69/#72 regression: no-hook PR reconciliation is independent of delivery.

The Rust service's background worker must advance open Pull Requests from
authoritative Git refs even when the repository has no active webhook. Head and
base branch updates are exercised separately, and paused/deleted hooks must not
suppress PR/pin/check reconciliation or leak deliveries.

No ``/webhooks/dispatch`` call exists here. Receivers are owned loopback
listeners; repository metadata and refs are read back from PostgreSQL and native
Git. Each case uses its own repository so earlier ref movement cannot satisfy a
later assertion.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from webhooks import WebhooksHarness  # noqa: E402

SECRET = "pr-sync-native-secret-0123456789"


def wait_for(label, fn, timeout=30.0, interval=0.15):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = fn()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f"timeout after {timeout}s waiting for {label}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")

    repo_root = Path(__file__).resolve().parents[1]
    h = WebhooksHarness(args)
    cases = []
    report = {
        "issues": [69, 72],
        "binary": args.binary,
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "source_head": subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, check=True,
        ).stdout.decode().strip(),
        "manual_dispatch_calls": 0,
        "cases": cases,
    }
    success = False

    def case(name, fn):
        started = time.monotonic()
        try:
            detail = fn()
            cases.append(dict(name=name, status="passed", seconds=round(time.monotonic() - started, 3), detail=detail))
            print(name + ": passed", flush=True)
        except Exception as error:
            cases.append(dict(name=name, status="failed", seconds=round(time.monotonic() - started, 3),
                              error=h.redact(error)))
            raise

    def marker(repository_id, pull_number, version, head, base):
        row = h.sql(
            "SELECT pull_version::text || ',' || head_oid || ',' || base_oid "
            f"FROM ci_pull_sync_progress WHERE repository_id='{repository_id}' "
            f"AND pull_number={pull_number} AND pull_version={version}")
        return row if row == f"{version},{head},{base}" else None

    def queued_run(repository_id, pull_number, version, head, base):
        row = h.sql(
            "SELECT job_id::text FROM ci_runs "
            f"WHERE repository_id='{repository_id}' AND pull_number={pull_number} "
            f"AND pull_version={version} AND context='ci/test' AND head_oid='{head}' "
            f"AND base_oid='{base}' AND state='queued'")
        return row or None

    def pin_oid(repository_id, job_id):
        bare = h.root / "data" / "repos" / (repository_id + ".git")
        return h.git("--git-dir=" + str(bare), "rev-parse", "refs/rootyard-ci/jobs/" + job_id).stdout.decode().strip()

    def paths(user, repo_name):
        root = f"/api/repos/{user}/{repo_name}"
        return root + "/webhooks", root + "/pulls", root + "/branch-rules"

    def create_pr(webhooks, pulls, rules, token):
        rule = h.document(rules, 201, method="POST", token=token, body={
            "branch_ref": "refs/heads/main", "required_approvals": 0,
            "required_checks": ["ci/test"], "require_fast_forward": True,
            "prevent_deletion": True, "prevent_force_push": True,
        })
        assert rule["branch_ref"] == "refs/heads/main", rule
        pr = h.document(pulls, 201, method="POST", token=token, body={
            "title": "No-hook PR reconciliation", "body": "stock Git drives this PR",
            "head_ref": "refs/heads/feature", "base_ref": "refs/heads/main",
        })
        return pr

    def wait_initial(repo_id, pr, base_oid, feat_oid):
        return wait_for("initial pin, queued run and progress marker", lambda: (
            lambda job: job if marker(repo_id, pr["number"], pr["version"], feat_oid, base_oid)
            and pin_oid(repo_id, job) == feat_oid else None
        )(queued_run(repo_id, pr["number"], pr["version"], feat_oid, base_oid)))

    def push_head(work, feat_oid, token):
        h.git("checkout", "-B", "feature", feat_oid, cwd=work)
        (work / "head-sync.txt").write_text("head update\n")
        h.git("add", "head-sync.txt", cwd=work)
        h.git("commit", "-m", "head update", cwd=work)
        head = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:refs/heads/feature", cwd=work, token=token)
        return head

    def push_base(work, base_oid, token):
        h.git("checkout", "-B", "base-sync", base_oid, cwd=work)
        (work / "base-sync.txt").write_text("base update\n")
        h.git("add", "base-sync.txt", cwd=work)
        h.git("commit", "-m", "base update", cwd=work)
        base = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=token)
        return base

    def sync_head_and_base(repo_id, pr, pulls, base_oid, feat_oid, work, token):
        initial_job = wait_initial(repo_id, pr, base_oid, feat_oid)
        head = push_head(work, feat_oid, token)
        updated = wait_for("background PR head update", lambda: (
            lambda p: p if p["head_oid"] == head and p["version"] > pr["version"] else None
        )(h.document(f"{pulls}/{pr['number']}", token=token)))
        head_job = wait_for("queued run and marker for pushed head", lambda: (
            lambda job: job if marker(repo_id, pr["number"], updated["version"], head, base_oid)
            and pin_oid(repo_id, job) == head else None
        )(queued_run(repo_id, pr["number"], updated["version"], head, base_oid)))
        assert h.document(f"{pulls}/{pr['number']}/checks", token=token)["items"], "pushed head has no check runs"

        base = push_base(work, base_oid, token)
        base_updated = wait_for("background PR base update", lambda: (
            lambda p: p if p["base_oid"] == base and p["version"] > updated["version"] else None
        )(h.document(f"{pulls}/{pr['number']}", token=token)))
        base_job = wait_for("queued run and marker for updated base", lambda: (
            lambda job: job if marker(repo_id, pr["number"], base_updated["version"], head, base)
            and pin_oid(repo_id, job) == head else None
        )(queued_run(repo_id, pr["number"], base_updated["version"], head, base)))
        assert base_job == head_job, (base_job, head_job)
        return {
            "repository_id": repo_id, "pull_number": pr["number"],
            "initial_job_id": initial_job, "head_job_id": head_job,
            "head_oid": head, "base_oid": base,
            "version_after_head": updated["version"],
            "version_after_base": base_updated["version"],
            "pin_oid_after_base": pin_oid(repo_id, base_job),
            "queued_check_contexts": ["ci/test"],
        }

    def assert_no_deliveries(repo_id, hook_id=None):
        assert h.receiver.requests == [], "repository without an active hook received a webhook"
        if hook_id:
            assert h.sql(f"SELECT count(*) FROM forge_webhook_deliveries WHERE webhook_id='{hook_id}'") == "0"
        else:
            assert h.sql(f"SELECT count(*) FROM forge_webhook_deliveries WHERE repository_id='{repo_id}'") == "0"

    def no_active_hook_initial_and_updates():
        webhooks, pulls, rules = paths("alice", "forge")
        assert h.sql(f"SELECT count(*) FROM forge_webhooks WHERE repository_id='{h.repo['id']}'") == "0"
        pr = create_pr(webhooks, pulls, rules, h.alice)
        assert pr["head_oid"] == h.feat1_oid, pr
        initial = wait_initial(h.repo["id"], pr, h.base_oid, h.feat1_oid)
        assert pin_oid(h.repo["id"], initial) == h.feat1_oid
        assert h.document(f"{pulls}/{pr['number']}/checks")["items"]
        assert_no_deliveries(h.repo["id"])
        detail = sync_head_and_base(h.repo["id"], pr, pulls, h.base_oid, h.feat1_oid, h.work, h.alice)
        assert_no_deliveries(h.repo["id"])
        detail.update({"active_hooks": 0, "receiver_requests": 0, "delivery_rows": 0})
        return detail

    def paused_hook_does_not_block_pr_sync():
        webhooks, pulls, rules = paths("alice", "other")
        hook = h.document(webhooks, 201, method="POST", body={
            "url": h.receiver.url, "secret": SECRET, "events": ["pull_request"],
            "auto_ci_pin": True, "timeout_ms": 2000,
        })
        paused = h.document(f"{webhooks}/{hook['id']}", 200, method="PATCH",
                            body={"expected_version": 1, "active": False})
        assert paused["active"] is False and paused["version"] == 2, paused
        pr = create_pr(webhooks, pulls, rules, h.alice)
        assert pr["head_oid"] == other_feat, pr
        initial = wait_initial(h.other["id"], pr, other_base, other_feat)
        assert pin_oid(h.other["id"], initial) == other_feat
        detail = sync_head_and_base(h.other["id"], pr, pulls, other_base, other_feat, other_work, h.alice)
        assert_no_deliveries(h.other["id"], hook["id"])
        detail.update({"hook_active": False, "hook_version": paused["version"],
                       "hook_deliveries": 0, "receiver_requests": 0})
        return detail

    def deleted_hook_does_not_block_pr_sync():
        webhooks, pulls, rules = paths("bob", "forge")
        hook = h.document(webhooks, 201, method="POST", token=h.bob, body={
            "url": h.receiver.url, "secret": SECRET, "events": ["pull_request"],
            "auto_ci_pin": True, "timeout_ms": 2000,
        })
        deleted = h.document(f"{webhooks}/{hook['id']}", 200, method="DELETE", token=h.bob)
        assert deleted["deleted"] is True
        pr = create_pr(webhooks, pulls, rules, h.bob)
        assert pr["head_oid"] == bob_feat, pr
        initial = wait_initial(h.bob_repo["id"], pr, bob_base, bob_feat)
        assert pin_oid(h.bob_repo["id"], initial) == bob_feat
        detail = sync_head_and_base(h.bob_repo["id"], pr, pulls, bob_base, bob_feat, bob_work, h.bob)
        assert h.receiver.requests == [], "deleted hook received a delivery"
        assert h.sql(f"SELECT count(*) FROM forge_webhooks WHERE id='{hook['id']}'") == "0"
        assert h.sql(f"SELECT count(*) FROM forge_webhook_deliveries WHERE webhook_id='{hook['id']}'") == "0"
        detail.update({"hook_deleted": True, "hook_deliveries": 0, "receiver_requests": 0})
        return detail


    def fair_pull_cursor_beyond_first_page():
        pulls, rules = paths("alice", "cursor")[1:]
        assert h.sql(f"SELECT count(*) FROM forge_webhooks WHERE repository_id='{cursor_repo['id']}'" ) == "0"
        h.document(rules, 201, method="POST", body={
            "branch_ref": "refs/heads/main", "required_approvals": 0,
            "required_checks": ["ci/test"], "require_fast_forward": True,
            "prevent_deletion": True, "prevent_force_push": True,
        })
        branches = [f"refs/heads/cursor-{number}" for number in range(1, 18)]
        h.git("push", "origin", *[f"{cursor_feat}:{branch}" for branch in branches],
              cwd=cursor_work, token=h.alice)
        created = []
        for number in range(1, 18):
            pr = h.document(pulls, 201, method="POST", body={
                "title": f"cursor PR {number}", "body": "fair cursor regression",
                "head_ref": f"refs/heads/cursor-{number}", "base_ref": "refs/heads/main",
            })
            assert pr["head_oid"] == cursor_feat, pr
            created.append(pr)

        # A second commit on every head branch leaves a historical outbox event
        # with the old OID for the first sixteen PRs. An EXISTS-over-history
        # query would keep those sixteen selected forever and starve PR 17.
        h.git("checkout", "-B", "cursor-source", cursor_feat, cwd=cursor_work)
        (cursor_work / "cursor-second.txt").write_text("second cursor commit\n")
        h.git("add", "cursor-second.txt", cwd=cursor_work)
        h.git("commit", "-m", "second cursor commit", cwd=cursor_work)
        second = h.git("rev-parse", "HEAD", cwd=cursor_work).stdout.decode().strip()
        h.git("push", "origin", *[f"{second}:{branch}" for branch in branches],
              cwd=cursor_work, token=h.alice)

        for index in range(16):
            wait_for(f"first-page PR {index + 1} head update", lambda index=index: (
                lambda p: p if p["head_oid"] == second and p["version"] > created[index]["version"] else None
            )(h.document(f"{pulls}/{created[index]['number']}")), timeout=45)
        seventeenth = wait_for("seventeenth PR head update beyond the first page", lambda: (
            lambda p: p if p["head_oid"] == second and p["version"] > created[16]["version"] else None
        )(h.document(f"{pulls}/{created[16]['number']}")), timeout=45)
        job = wait_for("seventeenth PR marker and queued run", lambda: (
            lambda job: job if marker(cursor_repo["id"], seventeenth["number"],
                                      seventeenth["version"], second, cursor_base)
            and pin_oid(cursor_repo["id"], job) == second else None
        )(queued_run(cursor_repo["id"], seventeenth["number"], seventeenth["version"],
                     second, cursor_base)), timeout=30)
        assert h.receiver.requests == []
        assert h.sql(f"SELECT count(*) FROM forge_webhook_deliveries WHERE repository_id='{cursor_repo['id']}'" ) == "0"
        return {"pull_count": 17, "first_page_updated": 16,
                "seventeenth_number": seventeenth["number"],
                "seventeenth_job_id": job, "seventeenth_version": seventeenth["version"],
                "historical_old_oid": cursor_feat, "current_oid": second}

    try:
        h.setup()
        other_work = h.root / "pr-sync-other"
        other_base, other_feat = h.init_repo_branches("/git/alice/other.git", other_work, h.alice)
        bob_work = h.root / "pr-sync-bob"
        bob_base, bob_feat = h.init_repo_branches("/git/bob/forge.git", bob_work, h.bob)
        cursor_repo = h.document("/api/repos", 201, method="POST", body={"name": "cursor"})
        cursor_work = h.root / "pr-sync-cursor"
        cursor_base, cursor_feat = h.init_repo_branches("/git/alice/cursor.git", cursor_work, h.alice)
        case("no_active_hook_open_pull_updates_on_head_and_base_push", no_active_hook_initial_and_updates)
        case("fair_pull_cursor_beyond_first_page", fair_pull_cursor_beyond_first_page)
        case("paused_hook_does_not_block_pr_sync", paused_hook_does_not_block_pr_sync)
        case("deleted_hook_does_not_block_pr_sync", deleted_hook_does_not_block_pr_sync)
        success = True
    except Exception as error:
        print(h.redact(error), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:
            cases.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            success = False
        report["passed"] = success
        if args.keep:
            report["retained_directory"] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
