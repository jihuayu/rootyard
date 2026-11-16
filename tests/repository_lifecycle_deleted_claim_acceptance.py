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

Failure reporting is limited to a fixed stage allowlist, bounded candidate
ordinals, a finite failure class, and typed numeric HTTP/child status. It never
serializes exception text, tracebacks, response bodies or headers, SQL, command
arguments, environment values, credentials, or provider output.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time
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

# Fixed, source-owned phase inventory. No caller may synthesize a stage name.
STAGES = (
    "case_start",
    "server_setup",
    "repository_create",
    "webhook_create",
    "trust_context_create",
    "seed_clone",
    "seed_commit",
    "seed_main_push",
    "protect_main",
    "seed_head_push",
    "create_pull",
    "await_run_pin",
    "source_contract",
    "checkout_snapshot",
    "claim_control",
    "control_assertions",
    "expire_lease",
    "reclaim_control",
    "reclaim_assertions",
    "deleted_first_claim",
    "deleted_lease_assertions",
    "policy_lock_acquire",
    "race_claim_start",
    "race_claim_wait",
    "delete_repository",
    "checkout_snapshot_after_delete",
    "policy_lock_release",
    "race_claim_result",
    "deleted_claim_assertions",
    "deleted_reclaim",
    "deleted_reclaim_assertions",
    "cleanup",
)
_STAGE_SET = frozenset(STAGES)
_CANDIDATE_ORDINALS = frozenset((0, 1, 2))

FAILURE_CLASSES = {
    "none": 0,
    "assertion": 1,
    "http_status": 2,
    "transport": 3,
    "subprocess_nonzero": 4,
    "deadline": 5,
    "decode_or_shape": 6,
    "unexpected_exception": 7,
}
_FAILURE_NAMES = {code: name for name, code in FAILURE_CLASSES.items()}
_FAILURE_CLASS_ALLOWLIST = frozenset(_FAILURE_NAMES)


class _SafeFailure(Exception):
    """A message-free stop marker; original exception text never escapes."""


def _classify_failure(error):
    """Map a raised exception to a fixed numeric class without stringifying it."""
    if isinstance(error, AssertionError):
        return FAILURE_CLASSES["assertion"]
    if isinstance(error, (TimeoutError, concurrent.futures.TimeoutError, subprocess.TimeoutExpired)):
        return FAILURE_CLASSES["deadline"]
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError)):
        return FAILURE_CLASSES["decode_or_shape"]
    if isinstance(error, subprocess.CalledProcessError):
        return FAILURE_CLASSES["subprocess_nonzero"]
    if isinstance(error, (OSError, http.client.HTTPException)):
        return FAILURE_CLASSES["transport"]
    return FAILURE_CLASSES["unexpected_exception"]


class _PhaseScope:
    def __init__(self, diagnostics, stage, ordinal):
        if stage not in _STAGE_SET:
            raise ValueError("unknown phase")
        if ordinal is not None and ordinal not in _CANDIDATE_ORDINALS:
            raise ValueError("candidate ordinal must be 0, 1, 2 or None")
        self.diagnostics = diagnostics
        self.stage = stage
        self.ordinal = ordinal
        self.previous = None

    def __enter__(self):
        diagnostics = self.diagnostics
        self.previous = (
            diagnostics.stage,
            diagnostics.ordinal,
            diagnostics.last_http_status,
            diagnostics.child_return_code,
            diagnostics._pending_class,
            diagnostics._pending_http_status,
            diagnostics._pending_child_return_code,
        )
        diagnostics.stage = self.stage
        diagnostics.ordinal = self.ordinal
        diagnostics.last_http_status = None
        diagnostics.child_return_code = None
        diagnostics._pending_class = None
        diagnostics._pending_http_status = None
        diagnostics._pending_child_return_code = None
        if len(diagnostics.phase_trace) < diagnostics.trace_limit:
            diagnostics.phase_trace.append((self.stage, self.ordinal))
        return diagnostics

    def __exit__(self, exc_type, exc, traceback_object):
        diagnostics = self.diagnostics
        if exc is not None:
            diagnostics.capture_failure(exc)
        (
            diagnostics.stage,
            diagnostics.ordinal,
            diagnostics.last_http_status,
            diagnostics.child_return_code,
            diagnostics._pending_class,
            diagnostics._pending_http_status,
            diagnostics._pending_child_return_code,
        ) = self.previous
        return False


class PhaseDiagnostics:
    """Bounded, finite failure context for this suite only.

    The object records stage/ordinal/class and typed HTTP or child-process
    numbers. It never retains exception text, response bodies, headers, SQL,
    commands, environment values, credentials, or filesystem paths.
    """

    trace_limit = 128

    def __init__(self):
        self.active_case = None
        self.stage = "case_start"
        self.ordinal = None
        self.last_http_status = None
        self.child_return_code = None
        self.phase_trace = []
        self._pending_class = None
        self._pending_http_status = None
        self._pending_child_return_code = None
        self._failure = None
        self._cleanup_failure = None
        self.cleanup_failure_count = 0

    def begin_case(self, name):
        self.active_case = name
        self.stage = "case_start"
        self.ordinal = None
        self.last_http_status = None
        self.child_return_code = None
        self._pending_class = None
        self._pending_http_status = None
        self._pending_child_return_code = None
        self._failure = None
        self.phase_trace = []

    def phase(self, stage, ordinal=None):
        return _PhaseScope(self, stage, ordinal)

    def begin_http(self):
        self.last_http_status = None
        self._pending_class = None
        self._pending_http_status = None
        self._pending_child_return_code = None

    def observe_http(self, status):
        self.last_http_status = int(status)

    def mark_http_mismatch(self):
        self._pending_class = FAILURE_CLASSES["http_status"]
        self._pending_http_status = self.last_http_status

    def observe_child(self, returncode):
        self.child_return_code = int(returncode)
        self._pending_class = FAILURE_CLASSES["subprocess_nonzero"]
        self._pending_child_return_code = int(returncode)

    def _snapshot(self, error):
        class_id = self._pending_class
        if class_id is None:
            class_id = _classify_failure(error)
        if class_id not in _FAILURE_CLASS_ALLOWLIST:
            class_id = FAILURE_CLASSES["unexpected_exception"]
        http_status = self._pending_http_status
        if http_status is None:
            http_status = self.last_http_status
        child_return_code = self._pending_child_return_code
        if child_return_code is None:
            child_return_code = self.child_return_code
        return {
            "failed_stage": self.stage,
            "failed_ordinal": self.ordinal,
            "failure_class": class_id,
            "failure_class_name": _FAILURE_NAMES[class_id],
            "http_status": int(http_status) if http_status is not None else None,
            "child_return_code": int(child_return_code) if child_return_code is not None else None,
        }

    def capture_failure(self, error):
        if self._failure is None:
            self._failure = self._snapshot(error)

    def record_failure(self, error):
        self.capture_failure(error)

    def record_cleanup_failure(self, error):
        self.cleanup_failure_count += 1
        class_id = _classify_failure(error)
        if class_id not in _FAILURE_CLASS_ALLOWLIST:
            class_id = FAILURE_CLASSES["unexpected_exception"]
        if self._cleanup_failure is None:
            self._cleanup_failure = {
                "cleanup_failure_class": class_id,
                "cleanup_failure_class_name": _FAILURE_NAMES[class_id],
            }
        if self._failure is None:
            self._failure = {
                "failed_stage": "cleanup",
                "failed_ordinal": None,
                "failure_class": class_id,
                "failure_class_name": _FAILURE_NAMES[class_id],
                "http_status": None,
                "child_return_code": None,
            }

    def failure_fields(self):
        if self._failure is None:
            return {
                "failed_stage": None,
                "failed_ordinal": None,
                "failure_class": None,
                "failure_class_name": None,
                "http_status": None,
                "child_return_code": None,
            }
        return dict(self._failure)

    def cleanup_fields(self):
        fields = {
            "cleanup_failed": self.cleanup_failure_count > 0,
            "cleanup_failure_count": self.cleanup_failure_count,
            "cleanup_failure_class": None,
            "cleanup_failure_class_name": None,
        }
        if self._cleanup_failure is not None:
            fields.update(self._cleanup_failure)
        return fields

    def report_fields(self):
        fields = {
            "schema": "rootyard.deleted-claim-failure-context.v1",
            "case": self.active_case,
        }
        fields.update(self.failure_fields())
        fields.update(self.cleanup_fields())
        return fields


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

    def __init__(self, args):
        super().__init__(args)
        self.diagnostics = PhaseDiagnostics()

    # ------------------------------------------------------------------
    # Finite diagnostics hooks
    # ------------------------------------------------------------------
    def phase(self, stage, ordinal=None):
        return self.diagnostics.phase(stage, ordinal)

    def http(self, *args, **kwargs):
        self.diagnostics.begin_http()
        status, body, headers = super().http(*args, **kwargs)
        self.diagnostics.observe_http(status)
        return status, body, headers

    def doc(self, path, code, token=None, **kwargs):
        expected = code if isinstance(code, tuple) else (code,)
        try:
            return super().doc(path, code, token=token, **kwargs)
        except AssertionError:
            if self.diagnostics.last_http_status not in expected:
                self.diagnostics.mark_http_mismatch()
            raise AssertionError() from None

    def expect(self, path, code, **kwargs):
        status, body, _ = self.http(path, **kwargs)
        expected = code if isinstance(code, tuple) else (code,)
        if status not in expected:
            self.diagnostics.mark_http_mismatch()
            raise AssertionError() from None
        return body

    def create_repository(self, payload, token=None):
        try:
            return super().create_repository(payload, token=token)
        except AssertionError:
            if self.diagnostics.last_http_status not in (200, 201, 202):
                self.diagnostics.mark_http_mismatch()
            raise AssertionError() from None

    def git(self, *args, cwd=None, token=None, check=True, env=None):
        if not check:
            return super().git(*args, cwd=cwd, token=token, check=False, env=env)
        completed = super().git(*args, cwd=cwd, token=token, check=False, env=env)
        if completed.returncode:
            self.diagnostics.observe_child(completed.returncode)
            raise AssertionError() from None
        return completed

    def case(self, name, fn):
        start = time.monotonic()
        self.diagnostics.begin_case(name)
        try:
            detail = fn()
        except Exception as error:
            self.diagnostics.record_failure(error)
            self.results.append(
                dict(
                    name=name,
                    status="failed",
                    seconds=round(time.monotonic() - start, 4),
                    **self.diagnostics.failure_fields(),
                )
            )
            raise _SafeFailure() from None
        self.results.append(
            dict(name=name, status="passed", seconds=round(time.monotonic() - start, 4), detail=detail)
        )
        print(name + ": passed", flush=True)

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
        def close_receiver():
            if getattr(self, "receiver", None) is not None:
                self.receiver.close()

        attempts = (
            self._close_policy_holder,
            close_receiver,
            super().cleanup,
        )
        for attempt in attempts:
            try:
                with self.phase("cleanup"):
                    attempt()
            except Exception as error:
                self.diagnostics.record_cleanup_failure(error)
        if self.diagnostics.cleanup_failure_count:
            raise _SafeFailure() from None

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
                raise AssertionError()
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
                raise AssertionError()
            time.sleep(0.1)
        return True

    def _create_fixture(self):
        if self.fixture is not None:
            return self.fixture
        if not getattr(self, "schema_created", False):
            with self.phase("server_setup"):
                self.setup()
        name = self.REPO_NAME
        with self.phase("repository_create"):
            self.repo = self.create_repository({"name": name}, token=self.alice)
        with self.phase("webhook_create"):
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
        with self.phase("trust_context_create"):
            self.doc(
                f"/api/repos/alice/{name}/integrations/{self.hook['id']}/trusted-contexts",
                200,
                token=self.alice,
                method="PUT",
                body={"context": self.CONTEXT},
            )

        work = self.root / "deleted-claim-work"
        with self.phase("seed_clone"):
            self.git("clone", self.base + f"/git/alice/{name}.git", str(work), token=self.alice)
            self.git("config", "user.name", self.alice["username"], cwd=work)
            self.git(
                "config",
                "user.email",
                f"{self.alice['username']}@example.invalid",
                cwd=work,
            )
        with self.phase("seed_commit"):
            (work / "README.md").write_text("rootyard deleted-claim fixture\n")
            self.git("add", "README.md", cwd=work)
            self.git("commit", "-m", "seed deleted-claim fixture", cwd=work)
        with self.phase("seed_main_push"):
            base_oid = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)

        with self.phase("protect_main"):
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
        for ordinal, (branch, filename, label) in enumerate(branches):
            with self.phase("seed_head_push", ordinal):
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
            with self.phase("create_pull", ordinal):
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
            with self.phase("await_run_pin", ordinal):
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
            if headers.get("cache-control") != "no-store":
                raise AssertionError() from None
            if expected != 200:
                self.diagnostics.mark_http_mismatch()
                raise AssertionError() from None
            return claim
        if status != expected:
            self.diagnostics.mark_http_mismatch()
            raise AssertionError() from None
        if headers.get("cache-control") != "no-store":
            raise AssertionError() from None
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
                raise AssertionError()
            if time.monotonic() >= stop:
                raise AssertionError()
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
        with self.phase("source_contract"):
            return source_claim_fence_findings(ROOT / "src/webhooks/runs.rs")

    def live_control_secret_claim_and_expired_reclaim(self):
        fixture = self._create_fixture()
        control = fixture["control_run"]
        with self.phase("checkout_snapshot"):
            before = self.checkout_rows()
            assert before == [], before

        with self.phase("claim_control"):
            first = self.claim(control["id"], "control-first")
        with self.phase("control_assertions"):
            assert first["attempt"] == 1, first
            assert first["checkout"]["plan"]["target_oid"] == control["head_oid"], first["checkout"]["plan"]
            assert first["checkout"]["token"].startswith("ryj_"), "claim did not return a capability token"
            after_first = self.checkout_rows()
            assert len(after_first) == 1, after_first

        with self.phase("expire_lease"):
            self.expire_lease_metadata(control["id"])
        with self.phase("reclaim_control"):
            second = self.claim(control["id"], "control-reclaim")
        with self.phase("reclaim_assertions"):
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
        with self.phase("deleted_first_claim"):
            claim = self.claim(deleted["id"], "deleted-first")
            assert claim["attempt"] == 1, claim
        with self.phase("deleted_lease_assertions"):
            rows = self.checkout_rows()
            assert len(rows) == 3, rows
        with self.phase("expire_lease"):
            self.expire_lease_metadata(deleted["id"])
        with self.phase("deleted_lease_assertions"):
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
        with self.phase("checkout_snapshot"):
            before = self.checkout_rows()
            assert len(before) == 3, before
            before_run = self.run_row(race["id"])
            assert before_run["state"] == "queued" and before_run["attempt"] == 0, before_run

        with self.phase("policy_lock_acquire"):
            self._hold_policy_lock(self.repo["id"])
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                with self.phase("race_claim_start"):
                    future = pool.submit(self._claim_raw, race["id"], "race-runner")
                # Release the owned barrier inside the executor scope, before
                # ThreadPoolExecutor.__exit__ waits for the claim future. A
                # failure in delete/snapshot must not strand the blocked claim
                # behind a barrier whose outer finally cannot run until shutdown.
                try:
                    with self.phase("race_claim_wait"):
                        self._wait_claim_blocked(future)
                    with self.phase("delete_repository"):
                        self.delete_repository()
                    with self.phase("checkout_snapshot_after_delete"):
                        assert self.checkout_rows() == before, "soft delete changed checkout rows"
                finally:
                    with self.phase("policy_lock_release"):
                        self._release_policy_lock()
                with self.phase("race_claim_result"):
                    status, raw, headers = future.result(timeout=20)
        finally:
            # Idempotent outer failsafe; the inner finally above is the release
            # that must precede executor shutdown/future waiting.
            with self.phase("policy_lock_release"):
                self._release_policy_lock()

        with self.phase("race_claim_result"):
            self._remember_claim_token(raw)
        with self.phase("deleted_claim_assertions"):
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
        with self.phase("deleted_reclaim_assertions"):
            assert self.deleted is not None, "delete case must run first"
            before = self.checkout_rows()
            before_run = self.run_row(deleted["id"])
            assert before_run["attempt"] == 1, before_run
            assert before_run["lease_expires_unix"] <= int(time.time()), before_run

        with self.phase("deleted_reclaim"):
            status, raw, headers = self._claim_raw(deleted["id"], "deleted-expired-reclaim")
            self._remember_claim_token(raw)
        with self.phase("deleted_reclaim_assertions"):
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
    except Exception:
        return {"bound": False, "reason": "source_binding_unavailable"}


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
        passed = harness.diagnostics.failure_fields()["failed_stage"] is None
    except _SafeFailure:
        pass
    except Exception as error:
        harness.diagnostics.record_failure(error)
    finally:
        try:
            harness.cleanup()
            cleanup_ok = True
        except _SafeFailure:
            pass
        except Exception as error:
            harness.diagnostics.record_cleanup_failure(error)
        if not cleanup_ok:
            harness.results.append(
                {
                    "name": "cleanup",
                    "status": "failed",
                    **harness.diagnostics.cleanup_fields(),
                }
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
            "diagnostics": harness.diagnostics.report_fields(),
            "phase_allowlist": list(STAGES),
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
