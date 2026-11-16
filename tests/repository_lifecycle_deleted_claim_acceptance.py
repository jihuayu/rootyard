#!/usr/bin/env python3
"""Real HTTP/Git/PostgreSQL acceptance for the deleted-repository claim fence.

The fixture creates a real API repository, real Git pull candidates, an active
CI integration, trusted context, and otherwise valid queued runs with retained
pins through supported endpoints. It then exercises three independent paths:

* a live control run proves the integration secret and queued-run fixture can
  claim successfully, including a reclaim after test-owned lease metadata
  expiry;
* a second live run is claimed, its lease metadata is expired, the repository
  is soft-deleted through the real API, and the expired reclaim must return 404
  without inserting a new ``ci_integration_checkout_jobs`` row;
* a queued run's claim is paused on the exact repository policy advisory lock
  after its early integration lookup. The API soft-delete commits while the
  claim is paused, then the claim resumes and must be rejected by the final
  repository-row lifecycle lock, with the checkout-job row set unchanged.

No row here serializes a raw checkout token. The SQL snapshots select only the
canonical non-secret columns (plan, credential digest, metadata). Private SQL is
limited to expiring this test's own run lease metadata and inspecting rows; it
never fabricates a ready/pinned repository, ref, acknowledgement, or grant.

The source-contract case parses Rust function bodies and SQL literals to prove
the early lookup includes ``deleted_at`` and the final transaction locks the
exact live repository row before the run lock, lease update, or grant persist.
This is static source evidence, not a substitute for the runtime cases.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback
import uuid

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from repository_lifecycle import RepositoryLifecycleHarness, quote  # noqa: E402
from webhooks import LocalWebhookReceiver  # noqa: E402

POLICY_LOCK_DOMAIN = "rootyard-publication-v1:"
CASE_NAMES = (
    "source_claim_fence_contract",
    "live_control_secret_claim_and_expired_reclaim",
    "live_main_run_expired_lease_fixture",
    "deleted_claim_after_early_lookup_rejected_by_final_row_lock",
    "deleted_expired_lease_reclaim_denied_without_new_grant",
)


def _rust_function_body(source, marker):
    """Return one Rust function body by matching its outer braces.

    The scanner ignores line/block comments and double-quoted strings so braces
    inside SQL text cannot end the function early.
    """
    starts = [match.start() for match in re.finditer(re.escape(marker), source)]
    assert len(starts) == 1, (marker, len(starts))
    body_start = source.index("{", starts[0])
    depth = 0
    in_string = False
    in_line_comment = False
    in_block_comment = False
    index = body_start
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
        elif in_block_comment:
            if char == "*" and following == "/":
                in_block_comment = False
                index += 1
        elif in_string:
            if char == "\\":
                index += 1
            elif char == '"':
                in_string = False
        elif char == "/" and following == "/":
            in_line_comment = True
            index += 1
        elif char == "/" and following == "*":
            in_block_comment = True
            index += 1
        elif char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[body_start : index + 1]
        index += 1
    raise AssertionError("unterminated Rust function body: " + marker)


def _sql_literals(source):
    """Return ``(offset, normalized_sql)`` for SQL-bearing Rust literals."""
    literals = []
    for match in re.finditer(r'"(?:\\.|[^"\\])*"', source, re.S):
        raw = match.group(0)[1:-1]
        normalized = re.sub(r"\\\s*\n\s*", " ", raw)
        normalized = normalized.replace('\\"', '"').replace("\\\\", "\\")
        normalized = " ".join(normalized.split())
        if re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", normalized, re.I):
            literals.append((match.start(), normalized))
    return literals


def source_claim_fence_findings(source_path):
    """Semantically inspect the claim fence and its statement ordering."""
    source = Path(source_path).read_text()
    lock_body = _rust_function_body(source, "async fn lock_claim_repository_tx(")
    claim_body = _rust_function_body(source, "pub async fn claim(")
    all_literals = _sql_literals(source)
    lock_literals = _sql_literals(lock_body)

    lock_sql = [text for _, text in lock_literals if "FOR SHARE OF r" in text]
    assert len(lock_sql) == 1, lock_sql
    lock_sql = lock_sql[0]
    for required in (
        "FROM repositories r",
        "r.id=$1",
        "n.slug=$2",
        "r.name=$3",
        "r.state='ready'",
        "r.deleted_at IS NULL",
        "FOR SHARE OF r",
    ):
        assert required in lock_sql, (required, lock_sql)
    assert "archived_at" not in lock_sql, "unrequested archive blocking entered the claim fence"

    early = [
        text
        for _, text in all_literals
        if "FROM repositories r" in text
        and "JOIN forge_webhooks w" in text
        and "w.id=$3" in text
        and "r.state='ready'" in text
    ]
    assert len(early) == 1, early
    assert "r.deleted_at IS NULL" in early[0], early[0]

    prepare_at = claim_body.index("ci_checkouts::integration::prepare")
    transaction_at = claim_body.index("let tx = client.transaction()")
    policy_at = claim_body.index("lock_policy_tx")
    repo_lock_at = claim_body.index("lock_claim_repository_tx")
    hook_verify_at = claim_body.index("verify_hook_tx")
    run_lock_at = claim_body.index("FOR UPDATE OF c")
    lease_mint_at = claim_body.index("UPDATE ci_runs SET state='leased'")
    persist_at = claim_body.index("ci_checkouts::integration::persist")
    assert prepare_at < transaction_at, "slow checkout preparation entered the claim transaction"
    assert transaction_at < policy_at < repo_lock_at < hook_verify_at < run_lock_at, (
        prepare_at,
        transaction_at,
        policy_at,
        repo_lock_at,
        hook_verify_at,
        run_lock_at,
    )
    assert repo_lock_at < lease_mint_at < persist_at, (repo_lock_at, lease_mint_at, persist_at)

    return {
        "early_lookup_deleted_filter": True,
        "final_repository_lock": "FOR SHARE OF r",
        "final_repository_scope": "id/owner-slug/name/state/deleted_at",
        "repository_lock_before_run_lock": True,
        "repository_lock_before_lease_and_grant": True,
        "prepare_outside_transaction": True,
        "archive_contract_unchanged": True,
    }


class DeletedClaimAcceptanceHarness(RepositoryLifecycleHarness):
    REPO_NAME = "deleted-claim"
    CONTEXT = "ci/test"
    HOOK_SECRET = "synthetic-deleted-claim-webhook-secret-0123456789"

    def setup(self):
        # The service defaults to denying loopback webhook targets. This suite
        # owns only loopback listeners and opts in for this isolated process.
        self.env["ROOTYARD_WEBHOOK_ALLOW_LOOPBACK"] = "true"
        self.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        self.env["ROOTYARD_CI_ORIGIN_FALLBACK_GLOBAL"] = "8"
        self.env["ROOTYARD_CI_ORIGIN_FALLBACK_PER_REPO"] = "8"
        self.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = str(uuid.uuid4())
        super().setup()
        self.secrets.append(self.HOOK_SECRET)
        self.receiver = LocalWebhookReceiver(self.HOOK_SECRET)
        self.fixture = None
        self.deleted = None
        self._policy_holder = None

    def cleanup(self):
        self._close_policy_holder()
        if getattr(self, "receiver", None) is not None:
            try:
                self.receiver.close()
            except Exception:
                pass
        super().cleanup()

    # ------------------------------------------------------------------
    # Real API/Git fixture
    # ------------------------------------------------------------------
    def _wait_run(self, pull_number, expected_head, deadline=20.0):
        stop = time.monotonic() + deadline
        last = None
        while True:
            raw = self.sql(
                "SELECT id::text || '|' || job_id::text || '|' || head_oid || '|' || "
                "state || '|' || attempt::text || '|' || lease_generation::text "
                "FROM ci_runs "
                f"WHERE repository_id={quote(self.repo['id'])} "
                f"AND pull_number={int(pull_number)} AND context={quote(self.CONTEXT)} "
                "ORDER BY id"
            )
            rows = [line for line in raw.splitlines() if line]
            assert len(rows) <= 1, (pull_number, rows)
            if rows:
                run_id, job_id, head_oid, state, attempt, lease_generation = rows[0].split("|")
                row = {
                    "id": run_id,
                    "job_id": job_id,
                    "head_oid": head_oid,
                    "state": state,
                    "attempt": int(attempt),
                    "lease_generation": int(lease_generation),
                }
                assert row["head_oid"] == expected_head, (row, expected_head)
                last = row
                if row["state"] == "queued":
                    return row
            if time.monotonic() >= stop:
                raise AssertionError(
                    f"pull {pull_number} never produced a queued {self.CONTEXT} run: {last!r}"
                )
            time.sleep(0.1)

    def _wait_pin(self, job_id, deadline=20.0):
        """Wait for the supported API/PR synchronization to publish this pin.

        The pin is created by the product path, never by this harness. The
        check only observes the owned test data directory.
        """
        pin = (
            Path(self.env["ROOTYARD_DATA_DIR"])
            / "ci-pins"
            / self.repo["id"]
            / f"{job_id}.pinned.json"
        )
        stop = time.monotonic() + deadline
        while not pin.is_file():
            if time.monotonic() >= stop:
                raise AssertionError(f"CI source pin was not published for job {job_id}")
            time.sleep(0.1)
        return True

    def _create_fixture(self):
        if self.fixture is not None:
            return self.fixture
        if not getattr(self, "schema_created", False):
            self.setup()
        name = self.REPO_NAME
        self.repo = self.create_repository({"name": name}, token=self.alice)
        self.hook = self.doc(
            f"/api/repos/alice/{name}/webhooks",
            201,
            token=self.alice,
            method="POST",
            body={
                "url": self.receiver.url,
                "secret": self.HOOK_SECRET,
                "events": ["pull_request"],
                "ci_contexts": [self.CONTEXT],
                "auto_ci_pin": True,
                "max_attempts": 1,
            },
        )
        self.doc(
            f"/api/repos/alice/{name}/integrations/{self.hook['id']}/trusted-contexts",
            200,
            token=self.alice,
            method="PUT",
            body={"context": self.CONTEXT},
        )
        work = self.root / "deleted-claim-work"
        self.git("clone", self.base + f"/git/alice/{name}.git", str(work), token=self.alice)
        self.git("config", "user.name", self.alice["username"], cwd=work)
        self.git(
            "config",
            "user.email",
            f"{self.alice['username']}@example.invalid",
            cwd=work,
        )
        (work / "README.md").write_text("rootyard deleted-claim fixture\n")
        self.git("add", "README.md", cwd=work)
        self.git("commit", "-m", "seed deleted-claim fixture", cwd=work)
        base_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)

        self.doc(
            f"/api/repos/alice/{name}/branch-rules",
            201,
            token=self.alice,
            method="POST",
            body={
                "branch_ref": "refs/heads/main",
                "required_approvals": 0,
                "required_checks": [self.CONTEXT],
            },
        )

        branches = (
            ("feature-control", "control.txt", "control"),
            ("feature-deleted", "deleted.txt", "deleted"),
            ("feature-race", "race.txt", "race"),
        )
        runs = {}
        for branch, filename, label in branches:
            self.git("checkout", "-B", branch, base_oid, cwd=work)
            (work / filename).write_text(label + " candidate\n")
            self.git("add", filename, cwd=work)
            self.git("commit", "-m", f"{label} CI candidate", cwd=work)
            head_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            self.git(
                "push",
                "origin",
                f"HEAD:refs/heads/{branch}",
                cwd=work,
                token=self.alice,
            )
            pull = self.doc(
                f"/api/repos/alice/{name}/pulls",
                201,
                token=self.alice,
                method="POST",
                body={
                    "title": f"deleted claim {label}",
                    "body": "real Git candidate for claim fence acceptance",
                    "head_ref": f"refs/heads/{branch}",
                    "base_ref": "refs/heads/main",
                },
            )
            assert pull["head_oid"] == head_oid, (pull, head_oid)
            run = self._wait_run(pull["number"], head_oid)
            self._wait_pin(run["job_id"])
            runs[label] = run

        self.fixture = {
            "repository": self.repo["id"],
            "hook": self.hook["id"],
            "control_run": runs["control"],
            "deleted_run": runs["deleted"],
            "race_run": runs["race"],
        }
        return self.fixture

    # ------------------------------------------------------------------
    # Claim/DB helpers
    # ------------------------------------------------------------------
    def _claim_raw(self, run_id, runner_id):
        return self.http(
            f"/api/repos/alice/{self.REPO_NAME}/integrations/{self.hook['id']}/runs/{run_id}/claim",
            method="POST",
            body={"runner_id": runner_id},
            extra_headers={"Authorization": "Bearer " + self.HOOK_SECRET},
        )

    def _remember_claim_token(self, raw):
        try:
            document = json.loads(raw)
        except ValueError:
            return
        token = ((document.get("checkout") or {}).get("token")) if isinstance(document, dict) else None
        if isinstance(token, str):
            self.secrets.append(token)

    def claim(self, run_id, runner_id, expected=200):
        status, raw, headers = self._claim_raw(run_id, runner_id)
        if status == 200:
            claim = json.loads(raw)
            token = (claim.get("checkout") or {}).get("token")
            if isinstance(token, str):
                self.secrets.append(token)
            assert headers.get("cache-control") == "no-store", headers
            if expected != 200:
                raise AssertionError(
                    f"claim unexpectedly succeeded: status={status} runner={runner_id}"
                )
            return claim
        assert expected != 200 and status == expected, (
            f"claim expected {expected}, got {status}: {self.redact(raw[:300])!r}"
        )
        assert headers.get("cache-control") == "no-store", headers
        return raw

    def checkout_rows(self):
        """Exact non-secret row snapshot for this repository's integration jobs.

        Never select or serialize the raw capability token; the persisted row
        contains only the credential digest and the immutable plan.
        """
        raw = self.sql(
            "SELECT run_id::text || '|' || attempt::text || '|' || lease_generation::text || '|' || "
            "repository_id::text || '|' || job_id::text || '|' || owner_id::text || '|' || "
            "issuer_webhook_id::text || '|' || plan::text || '|' || "
            "encode(credential_digest,'hex') || '|' || expires_unix::text || '|' || "
            "created_at::text "
            "FROM ci_integration_checkout_jobs "
            f"WHERE repository_id={quote(self.repo['id'])} "
            "ORDER BY run_id,attempt,lease_generation,job_id"
        )
        rows = [line for line in raw.splitlines() if line]
        assert all("ryj_" not in line for line in rows), "raw token entered the SQL snapshot"
        return rows

    def run_row(self, run_id):
        raw = self.sql(
            "SELECT state || '|' || attempt::text || '|' || lease_generation::text || '|' || "
            "lease_expires_unix::text "
            f"FROM ci_runs WHERE id={quote(run_id)}"
        )
        state, attempt, lease_generation, expires = raw.split("|")
        return {
            "state": state,
            "attempt": int(attempt),
            "lease_generation": int(lease_generation),
            "lease_expires_unix": int(expires),
        }

    def expire_lease_metadata(self, run_id):
        """Expire only this test's owned run lease; never fake a grant or pin."""
        updated = self.sql(
            "UPDATE ci_runs SET lease_expires_unix="
            "(extract(epoch FROM clock_timestamp()))::bigint-1,"
            "updated_at=clock_timestamp() "
            f"WHERE id={quote(run_id)} AND state='leased' RETURNING id::text"
        )
        row = self.run_row(run_id)
        assert row["lease_expires_unix"] < int(time.time()), run_id
        # A background reconciler may have moved the expired row to queued
        # before the update; either way this owned run's lease is now expired.
        assert updated or row["state"] == "queued", (updated, row)
        return True

    # ------------------------------------------------------------------
    # Repository policy barrier (deterministic early/final race)
    # ------------------------------------------------------------------
    def _hold_policy_lock(self, repo_id):
        assert self._policy_holder is None
        sql = (
            "SELECT pg_advisory_xact_lock(hashtextextended("
            f"'{POLICY_LOCK_DOMAIN}' || '{repo_id}'::uuid::text, 0));"
        )
        process = subprocess.Popen(
            ["psql", "--dbname", self.db, "-X", "-v", "ON_ERROR_STOP=1", "-qAt"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self.env,
            text=True,
        )
        process.stdin.write("BEGIN;\n" + sql + "\n")
        process.stdin.flush()
        self._policy_holder = process
        deadline = time.monotonic() + 10
        while True:
            held = self.sql(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname=current_database() "
                "AND state LIKE 'idle in transaction%' "
                f"AND query LIKE '%{POLICY_LOCK_DOMAIN}%'"
            )
            if int(held) >= 1:
                return True
            if process.poll() is not None:
                raise AssertionError("repository policy lock holder exited before acquiring")
            if time.monotonic() >= deadline:
                raise AssertionError("repository policy lock was not acquired")
            time.sleep(0.05)

    def _release_policy_lock(self):
        process = getattr(self, "_policy_holder", None)
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.write("COMMIT;\n\\q\n")
                process.stdin.flush()
                process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        self._policy_holder = None

    def _close_policy_holder(self):
        process = getattr(self, "_policy_holder", None)
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.write("ROLLBACK;\n\\q\n")
                process.stdin.flush()
                process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        self._policy_holder = None

    def _wait_claim_blocked(self, future, deadline=20.0):
        stop = time.monotonic() + deadline
        while True:
            waiting = self.sql(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname=current_database() AND state='active' "
                "AND wait_event_type='Lock' "
                "AND query LIKE '%pg_advisory_xact_lock(hashtextextended(%'"
            )
            if int(waiting) >= 1:
                return True
            if future.done():
                status, raw, _ = future.result()
                self._remember_claim_token(raw)
                raise AssertionError(
                    f"claim finished before the final policy fence: {status} "
                    f"{self.redact(raw[:200])!r}"
                )
            if time.monotonic() >= stop:
                raise AssertionError("claim did not block on the final policy fence")
            time.sleep(0.05)

    def delete_repository(self):
        lifecycle = self.doc(
            f"/api/repos/alice/{self.REPO_NAME}/lifecycle", 200, token=self.alice
        )
        deleted = self.doc(
            f"/api/repos/alice/{self.REPO_NAME}",
            200,
            token=self.alice,
            method="DELETE",
            body={
                "expected_version": lifecycle["version"],
                "grace_period_seconds": 7 * 24 * 3600,
            },
            extra_headers={"Idempotency-Key": "deleted-claim-soft-delete"},
        )
        assert deleted["deleted"] is True, deleted
        self.expect(f"/api/repos/alice/{self.REPO_NAME}", 404, token=self.alice)
        self.deleted = deleted
        return deleted

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------
    def source_claim_fence_contract(self):
        return source_claim_fence_findings(ROOT / "src/webhooks/runs.rs")

    def live_control_secret_claim_and_expired_reclaim(self):
        fixture = self._create_fixture()
        control = fixture["control_run"]
        before = self.checkout_rows()
        assert before == [], before

        first = self.claim(control["id"], "control-first")
        assert first["attempt"] == 1, first
        assert first["checkout"]["plan"]["target_oid"] == control["head_oid"], first["checkout"]["plan"]
        assert first["checkout"]["token"].startswith("ryj_"), "claim did not return a capability token"
        after_first = self.checkout_rows()
        assert len(after_first) == 1, after_first

        self.expire_lease_metadata(control["id"])
        second = self.claim(control["id"], "control-reclaim")
        assert second["attempt"] == 2, second
        assert second["lease_generation"] > first["lease_generation"], (first, second)
        after_second = self.checkout_rows()
        assert len(after_second) == 2, after_second
        return {
            "control_claim_status": 200,
            "live_expired_lease_reclaim_status": 200,
            "control_checkout_rows": len(after_second),
        }

    def live_main_run_expired_lease_fixture(self):
        fixture = self._create_fixture()
        deleted = fixture["deleted_run"]
        claim = self.claim(deleted["id"], "deleted-first")
        assert claim["attempt"] == 1, claim
        rows = self.checkout_rows()
        assert len(rows) == 3, rows
        self.expire_lease_metadata(deleted["id"])
        row = self.run_row(deleted["id"])
        assert row["state"] in ("leased", "queued"), row
        assert row["lease_expires_unix"] <= int(time.time()), row
        return {
            "first_lease_claim_status": 200,
            "owned_lease_metadata_expired": True,
            "checkout_rows": len(rows),
        }

    def deleted_claim_after_early_lookup_rejected_by_final_row_lock(self):
        fixture = self._create_fixture()
        race = fixture["race_run"]
        before = self.checkout_rows()
        assert len(before) == 3, before
        before_run = self.run_row(race["id"])
        assert before_run["state"] == "queued" and before_run["attempt"] == 0, before_run

        self._hold_policy_lock(self.repo["id"])
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self._claim_raw, race["id"], "race-runner")
                # Release the owned barrier inside the executor scope, before
                # ThreadPoolExecutor.__exit__ waits for the claim future. A
                # failure in delete/snapshot must not strand the blocked claim
                # behind a barrier whose outer finally cannot run until shutdown.
                try:
                    self._wait_claim_blocked(future)
                    self.delete_repository()
                    assert self.checkout_rows() == before, "soft delete changed checkout rows"
                finally:
                    self._release_policy_lock()
                status, raw, headers = future.result(timeout=20)
        finally:
            # Idempotent outer failsafe; the inner finally above is the release
            # that must precede executor shutdown/future waiting.
            self._release_policy_lock()

        self._remember_claim_token(raw)
        assert status == 404, (status, self.redact(raw[:200]))
        assert json.loads(raw) == {"error": "not found"}, self.redact(raw[:300])
        assert headers.get("cache-control") == "no-store", headers
        after = self.checkout_rows()
        assert after == before, (before, after)
        after_run = self.run_row(race["id"])
        assert after_run["state"] == "queued" and after_run["attempt"] == 0, after_run
        assert all(race["id"] not in line for line in after), "deleted claim minted a new hold"
        return {
            "claim_status_after_delete": 404,
            "early_lookup_completed_before_delete": True,
            "final_repository_row_lock_denied": True,
            "checkout_rows_before": len(before),
            "checkout_rows_after": len(after),
            "race_run_state": after_run["state"],
        }

    def deleted_expired_lease_reclaim_denied_without_new_grant(self):
        fixture = self._create_fixture()
        deleted = fixture["deleted_run"]
        assert self.deleted is not None, "delete case must run first"
        before = self.checkout_rows()
        before_run = self.run_row(deleted["id"])
        assert before_run["attempt"] == 1, before_run
        assert before_run["lease_expires_unix"] <= int(time.time()), before_run

        status, raw, headers = self._claim_raw(deleted["id"], "deleted-expired-reclaim")
        self._remember_claim_token(raw)
        assert status == 404, (status, self.redact(raw[:200]))
        assert json.loads(raw) == {"error": "not found"}, self.redact(raw[:300])
        assert headers.get("cache-control") == "no-store", headers
        after = self.checkout_rows()
        assert after == before, (before, after)
        after_run = self.run_row(deleted["id"])
        assert after_run["attempt"] == before_run["attempt"], (before_run, after_run)
        assert after_run["lease_generation"] == before_run["lease_generation"], (
            before_run,
            after_run,
        )
        assert all(deleted["id"] not in line for line in after), "deleted reclaim minted a new hold"
        return {
            "expired_reclaim_status_after_delete": 404,
            "checkout_rows_before": len(before),
            "checkout_rows_after": len(after),
            "no_new_hold": True,
        }


def _binary_receipt(binary):
    """Best-effort read of the adjacent canonical source-bound receipt."""
    try:
        import source_bound_binary

        return {"bound": True, "receipt": source_bound_binary.bind(binary, environ=os.environ)}
    except Exception as error:
        return {"bound": False, "reason": type(error).__name__ + ": " + str(error)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    for executable in ("git", "git-lfs", "psql", args.binary):
        if not shutil.which(executable):
            parser.error("Required executable not found: " + executable)

    harness = DeletedClaimAcceptanceHarness(args)
    passed = False
    cleanup_ok = False
    try:
        harness.case(
            "source_claim_fence_contract",
            harness.source_claim_fence_contract,
        )
        harness.case(
            "live_control_secret_claim_and_expired_reclaim",
            harness.live_control_secret_claim_and_expired_reclaim,
        )
        harness.case(
            "live_main_run_expired_lease_fixture",
            harness.live_main_run_expired_lease_fixture,
        )
        harness.case(
            "deleted_claim_after_early_lookup_rejected_by_final_row_lock",
            harness.deleted_claim_after_early_lookup_rejected_by_final_row_lock,
        )
        harness.case(
            "deleted_expired_lease_reclaim_denied_without_new_grant",
            harness.deleted_expired_lease_reclaim_denied_without_new_grant,
        )
        passed = True
    except Exception:
        print(harness.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
            cleanup_ok = True
        except Exception as error:
            harness.results.append(
                {"name": "cleanup", "status": "failed", "error": harness.redact(error)}
            )
            passed = False
        report = {
            "passed": passed,
            "skip": 0,
            "case_inventory": list(CASE_NAMES),
            "cases": harness.results,
            "cleanup": {
                "ok": cleanup_ok,
                "service_stopped": cleanup_ok,
                "owned_schema_dropped": cleanup_ok,
                "loopback_receiver_closed": cleanup_ok,
                "policy_barrier_released": getattr(harness, "_policy_holder", None) is None,
            },
            "binary_path": args.binary,
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "binary_receipt": _binary_receipt(args.binary),
            "limits": [
                "This is a synthetic loopback fixture, not production qualification.",
                "No raw capability token is read back or serialized in the report.",
                "Static source parsing proves ordering and predicates, not runtime behavior.",
            ],
        }
        if args.keep:
            report["retained_directory"] = str(harness.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
