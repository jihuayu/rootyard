#!/usr/bin/env python3
"""Track A End-to-End contract: External CI Webhooks, HMAC-SHA256 Delivery, Backoff Retry & Auto PR CI Pipeline."""
import argparse
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import sys
import threading
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from forge import ForgeHarness  # noqa: E402
from pulls import PullsHarness  # noqa: E402
from schema_baseline import SCHEMA_VERSION_CSV, SCHEMA_VERSIONS  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def migration_040_path() -> Path:
    promoted = ROOT / "migrations/040_webhooks.sql"
    if promoted.is_file():
        return promoted
    return ROOT / "src/webhooks/040_webhooks.sql"


def compute_hmac_sha256_header(secret: str, payload_bytes: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class LocalWebhookReceiver:
    """Thread-safe local loopback HTTP/1.1 receiver for testing webhook deliveries and retries."""

    def __init__(self, secret: str):
        self.secret = secret
        self.lock = threading.Lock()
        self.requests: list[dict] = []
        self.planned_statuses: list[int] = []
        self.default_status: int = 200
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b""
                sig = self.headers.get("X-Rootyard-Signature-256", "")
                expected_sig = compute_hmac_sha256_header(outer.secret, raw_body)
                sig_valid = hmac.compare_digest(sig, expected_sig)
                try:
                    parsed_json = json.loads(raw_body.decode("utf-8")) if raw_body else None
                except Exception:
                    parsed_json = None

                with outer.lock:
                    status_code = (
                        outer.planned_statuses.pop(0)
                        if outer.planned_statuses
                        else outer.default_status
                    )
                    outer.requests.append(
                        {
                            "path": self.path,
                            "headers": {k.lower(): v for k, v in self.headers.items()},
                            "raw_body": raw_body,
                            "json": parsed_json,
                            "signature": sig,
                            "signature_valid": sig_valid,
                            "response_status": status_code,
                        }
                    )

                resp_bytes = json.dumps({"ok": 200 <= status_code < 300}).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(resp_bytes)

            def log_message(self, format, *args):
                return

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/webhook"

    def clear(self):
        with self.lock:
            self.requests.clear()
            self.planned_statuses.clear()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


class WebhooksHarness(PullsHarness):
    def ensure_migration_040(self):
        if self.sql("SELECT to_regclass('forge_webhooks') IS NOT NULL") != "t":
            self.run(
                [
                    "psql",
                    self.db,
                    "-X",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-f",
                    str(migration_040_path()),
                ]
            )

    def json_response(self, path: str, expected, **kwargs):
        """Send one raw request and return its status and parsed JSON body.

        ``expected`` is one status or a minimal tuple of statuses the caller
        judges further from the parsed error vocabulary. Any other status, a
        missing Cache-Control/Content-Type header or a non-object JSON body
        fails here, so no caller can absorb a 401, 500 or opaque conflict.
        """
        allowed = expected if isinstance(expected, tuple) else (expected,)
        assert allowed, "at least one expected status is required"
        status, body, headers = self.http(
            path, token=kwargs.pop("token", None) or self.alice, **kwargs
        )
        norm_headers = {k.lower(): v for k, v in headers.items()}
        assert status in allowed, f"{path}: expected {expected}, got {status}: {body[:200]!r}"
        assert norm_headers.get("cache-control") == "no-store", norm_headers
        assert "application/json" in norm_headers.get("content-type", ""), norm_headers
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        assert isinstance(parsed, dict), (status, body[:200])
        return status, parsed

    def check_rows(self) -> dict:
        """Current check-run rows for the PR head, keyed by context."""
        return {
            c["context"]: c
            for c in self.document(f"{self.pr1_path}/checks", token=self.reader)["items"]
        }

    def signed_callback(
        self,
        path: str,
        secret: str,
        payload: dict,
        code=200,
        extra_headers: dict | None = None,
    ):
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        sig = compute_hmac_sha256_header(secret, raw)
        hdrs = {
            "Content-Type": "application/json",
            "X-Rootyard-Signature-256": sig,
        }
        if extra_headers:
            hdrs.update(extra_headers)
        status, body, headers = self.http(
            path,
            method="POST",
            body=raw,
            extra_headers=hdrs,
        )
        norm_headers = {k.lower(): v for k, v in headers.items()}
        expected = code if isinstance(code, tuple) else (code,)
        assert status in expected, f"{path}: expected {code}, got {status}: {body[:200]!r}"
        assert norm_headers.get("cache-control") == "no-store", norm_headers
        return json.loads(body)

    def setup(self):
        # Every receiver in this harness is a test-owned loopback listener. The
        # service default denies loopback webhook targets, so the harness opts in
        # explicitly; ``webhook_loopback_default_deny_and_operator_opt_in`` starts
        # a second, opted-out server to prove the default and the send-time check.
        self.env["ROOTYARD_WEBHOOK_ALLOW_LOOPBACK"] = "true"
        super().setup()
        self.ensure_migration_040()
        self.webhookspath = "/api/repos/alice/forge/webhooks"
        self.dispatchpath = "/api/repos/alice/forge/webhooks/dispatch"
        self.pins_path = "/api/repos/alice/forge/ci-pins"
        self.webhook_secret = "whsec_alice_forge_secret_key_0123456789"
        self.receiver = LocalWebhookReceiver(self.webhook_secret)

    def cleanup(self):
        if hasattr(self, "receiver") and self.receiver is not None:
            try:
                self.receiver.close()
            except Exception:
                pass
        super().cleanup()

    def migration(self):
        self.ensure_migration_040()
        assert (
            self.sql(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema=current_schema() AND table_name IN ("
                "'forge_webhooks','forge_webhook_deliveries','forge_webhook_callbacks')"
            )
            == "3"
        )
        if 40 in SCHEMA_VERSIONS:
            assert (
                self.sql(
                    "SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations"
                )
                == SCHEMA_VERSION_CSV
            )

    def webhook_crud_and_secret_redaction(self):
        # Reject SSRF and insecure non-loopback HTTP URLs.
        for bad_url in (
            "http://example.com/webhook",
            "https://10.0.0.1/webhook",
            "https://169.254.169.254/latest/meta-data/",
            "https://192.168.1.10/hook",
            "https://user:pass@example.com/hook",
        ):
            self.document(
                self.webhookspath,
                400,
                method="POST",
                body={"url": bad_url, "secret": self.webhook_secret},
            )

        # Create webhook with idempotency key and verify secret redaction.
        self.hook = self.document(
            self.webhookspath,
            201,
            method="POST",
            body={
                "url": self.receiver.url,
                "secret": self.webhook_secret,
                "events": ["push", "pull_request", "check_run"],
                "ci_contexts": ["ci/test", "ci/lint"],
                "auto_ci_pin": True,
                "max_attempts": 3,
                "timeout_ms": 3000,
            },
            extra_headers={"Idempotency-Key": "create-hook-1"},
        )
        assert "secret" not in self.hook
        assert self.hook["secret_configured"] is True
        assert (
            self.hook["secret_sha256"]
            == hashlib.sha256(self.webhook_secret.encode("utf-8")).hexdigest()
        )
        assert self.hook["version"] == 1

        # Idempotent replay returns 200 OK with identical representation.
        replay = self.document(
            self.webhookspath,
            200,
            method="POST",
            body={
                "url": self.receiver.url,
                "secret": self.webhook_secret,
                "events": ["push", "pull_request", "check_run"],
                "ci_contexts": ["ci/test", "ci/lint"],
                "auto_ci_pin": True,
                "max_attempts": 3,
                "timeout_ms": 3000,
            },
            extra_headers={"Idempotency-Key": "create-hook-1"},
        )
        assert replay["id"] == self.hook["id"]

        hook_id = self.hook["id"]
        self.hook_path = f"{self.webhookspath}/{hook_id}"
        fetched = self.document(self.hook_path)
        assert fetched["id"] == hook_id and "secret" not in fetched

        # PATCH with optimistic version CAS.
        self.document(
            self.hook_path,
            409,
            method="PATCH",
            body={"expected_version": 99, "timeout_ms": 4000},
        )
        updated = self.document(
            self.hook_path,
            200,
            method="PATCH",
            body={"expected_version": 1, "timeout_ms": 4000},
        )
        assert updated["version"] == 2 and updated["timeout_ms"] == 4000

    def ping_and_hmac_sha256_signature_verification(self):
        self.receiver.clear()
        ping_delivery = self.document(
            f"{self.hook_path}/ping",
            200,
            method="POST",
            body={"zen": "Rootyard HMAC verification test", "event_id": "ping-fixed-1"},
        )
        assert ping_delivery["state"] == "delivered"
        assert ping_delivery["response_status"] == 200
        assert ping_delivery["signature_256"].startswith("sha256=")
        assert len(self.receiver.requests) == 1
        req = self.receiver.requests[0]
        assert req["signature_valid"] is True
        assert req["headers"]["x-rootyard-event"] == "ping"
        assert req["headers"]["x-rootyard-hook-id"] == self.hook["id"]

    def auto_pr_ci_pin_and_queued_check_orchestration(self):
        # Configure branch protection requiring ci/test and ci/lint on refs/heads/main.
        self.document(
            self.rulespath,
            201,
            method="POST",
            body={
                "branch_ref": "refs/heads/main",
                "required_approvals": 0,
                "required_checks": ["ci/test", "ci/lint"],
                "require_fast_forward": True,
                "prevent_deletion": True,
                "prevent_force_push": True,
            },
        )

        # Open PR #1 at feat1_oid.
        self.pr1 = self.document(
            self.pullspath,
            201,
            method="POST",
            body={
                "title": "Auto CI Pipeline PR",
                "body": "Triggers CI Source Pin and queued checks",
                "head_ref": "refs/heads/feature",
                "base_ref": "refs/heads/main",
            },
        )
        self.pr1_path = f"{self.pullspath}/{self.pr1['number']}"

        # Dispatch webhooks: scans open PRs + outbox events, creates CI pin & queued checks.
        self.receiver.clear()
        summary = self.document(self.dispatchpath, 200, method="POST", body={})
        assert summary["orchestrated_pulls"] >= 1
        assert summary["delivered_count"] >= 1

        # Verify CI Source Pin was created for feat1_oid.
        pins = self.document(self.pins_path)
        pin_items = pins if isinstance(pins, list) else pins.get("items", [])
        matching_pins = [p for p in pin_items if p.get("target_oid") == self.feat1_oid]
        assert len(matching_pins) == 1, f"Expected 1 CI pin for {self.feat1_oid}, got {pin_items}"
        assert matching_pins[0]["state"] == "pinned"

        # Verify queued check runs were automatically registered on feat1_oid.
        pr_checks = self.document(f"{self.pr1_path}/checks")["items"]
        by_ctx = {c["context"]: c for c in pr_checks}
        assert "ci/test" in by_ctx and "ci/lint" in by_ctx
        assert by_ctx["ci/test"]["status"] == "queued"
        assert by_ctx["ci/lint"]["status"] == "queued"

    def idempotent_ci_callbacks_and_monotonic_check_runs(self):
        cb_path = f"{self.hook_path}/callback"
        alt_cb_path = f"/api/repos/alice/forge/integrations/{self.hook['id']}/check-runs"

        # Invalid HMAC signature must be rejected with 401.
        status, _, _ = self.http(
            cb_path,
            method="POST",
            body={
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "completed",
                "conclusion": "success",
            },
            extra_headers={"X-Rootyard-Signature-256": "sha256=" + ("0" * 64)},
        )
        assert status == 401

        # Complete ci/test via signed callback with event_id.
        res1 = self.signed_callback(
            cb_path,
            self.webhook_secret,
            {
                "event_id": "cb-event-1",
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "completed",
                "conclusion": "success",
                "attempt": 1,
                "sequence": 2,
                "output": "All unit tests passed",
            },
            code=200,
        )
        assert res1["status"] == "completed" and res1["conclusion"] == "success"
        assert res1["sequence"] == 2

        # Exact replay of event_id="cb-event-1" returns 200 OK idempotently.
        res1_replay = self.signed_callback(
            cb_path,
            self.webhook_secret,
            {
                "event_id": "cb-event-1",
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "completed",
                "conclusion": "success",
                "attempt": 1,
                "sequence": 2,
                "output": "All unit tests passed",
            },
            code=200,
        )
        assert res1_replay == res1

        # Mutated payload with same event_id="cb-event-1" returns 409 Conflict.
        self.signed_callback(
            cb_path,
            self.webhook_secret,
            {
                "event_id": "cb-event-1",
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "completed",
                "conclusion": "failure",
                "attempt": 1,
                "sequence": 2,
                "output": "Mutated payload",
            },
            code=409,
        )

        # Stale sequence (attempt=1, sequence=1) on ci/test must be rejected with 409 Conflict.
        self.signed_callback(
            alt_cb_path,
            self.webhook_secret,
            {
                "event_id": "cb-event-stale",
                "commit_oid": self.feat1_oid,
                "context": "ci/test",
                "status": "in_progress",
                "attempt": 1,
                "sequence": 1,
            },
            code=409,
        )

        # Complete ci/lint on feat1_oid via integrations endpoint.
        self.signed_callback(
            alt_cb_path,
            self.webhook_secret,
            {
                "event_id": "cb-event-lint-1",
                "commit_oid": self.feat1_oid,
                "context": "ci/lint",
                "status": "completed",
                "conclusion": "success",
            },
            code=200,
        )

        # Now update feature branch and PR #1 head_oid to feat2_oid: old CI on feat1_oid must NOT allow merge!
        self.pr1_version_before_push = self.pr1["version"]
        self.git(
            "push",
            "origin",
            f"{self.feat2_oid}:refs/heads/feature",
            cwd=self.work,
            token=self.alice,
        )
        # Background reconciliation may already have advanced PR #1 from the
        # authoritative `feature` ref (head_oid=feat2_oid, version bumped). Read
        # the live row instead of assuming the pre-push version is still
        # current, and only PATCH against a version just read.
        pr_now = self.document(self.pr1_path)
        assert pr_now["base_oid"] == self.base_oid, pr_now
        if pr_now["head_oid"] == self.feat2_oid:
            # Already advanced: the returned row itself must be the feat2 bump.
            assert pr_now["version"] > self.pr1_version_before_push, pr_now
        else:
            # Not yet auto-advanced: the old head must still be stored, so the
            # manual PATCH is the one legitimate single use of a just-read version.
            assert pr_now["head_oid"] == self.pr1["head_oid"], pr_now
            status, patched = self.json_response(
                self.pr1_path,
                (200, 409),
                method="PATCH",
                body={"expected_version": pr_now["version"], "head_oid": self.feat2_oid},
            )
            if status == 409:
                # A 409 is only the legitimate background win when it is exactly
                # the version conflict, i.e. a concurrent writer committed a
                # version bump. Any other 409 (head_oid/base_oid mismatch,
                # closed/merged PR, ...) fails here. The one bounded read-back
                # must then prove the writer landed exactly feat2/base and a
                # version past the pre-push one; a stale old-head row fails on
                # the shared oracle below instead of being retried.
                assert patched.get("error") == "pull request version conflict", patched
                # Exactly one bounded read-back; it must show the feat2 bump.
                pr_now = self.document(self.pr1_path)
            else:
                pr_now = patched
        # 200 uses the real returned row; both paths must satisfy the same
        # feat2/base/version oracle before the merge below can mean anything.
        assert pr_now["head_oid"] == self.feat2_oid, pr_now
        assert pr_now["base_oid"] == self.base_oid, pr_now
        assert pr_now["version"] > self.pr1_version_before_push, pr_now
        # The feat2 checks must still be queued, so the merge below is refused by
        # the required-check policy and not by any other conflict.
        for context in ("ci/test", "ci/lint"):
            row = self.check_rows()[context]
            assert row["status"] == "queued" and row["conclusion"] is None, row
        self.pr1 = self.document(self.pr1_path)
        assert self.pr1["head_oid"] == self.feat2_oid, self.pr1
        self.document(self.dispatchpath, 200, method="POST", body={})
        # Orchestration runs concurrently with the background worker, so read the
        # version the merge will fence on from the row as it is now.
        self.pr1 = self.document(self.pr1_path)

        # Merge at feat2_oid must fail with exactly the branch-policy 409 because
        # feat2_oid's check runs are still 'queued'. A version conflict only means
        # the background worker advanced the row after our read: re-read the
        # version a bounded number of times, always re-fencing on feat2_oid, and
        # fail on any other status or error.
        for _ in range(5):
            merge_body = {
                "expected_version": self.pr1["version"],
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            }
            _, merge = self.json_response(
                f"{self.pr1_path}/merge", 409, method="POST", body=merge_body
            )
            if merge.get("error") == "required check runs have not succeeded":
                break
            assert merge.get("error") == "pull request version conflict", merge
            self.pr1 = self.document(self.pr1_path)
            assert self.pr1["head_oid"] == self.feat2_oid, self.pr1
        else:
            raise AssertionError(f"merge never reached the check-run oracle: {merge}")
        assert self.pr1["head_oid"] == self.feat2_oid, self.pr1

    def outbox_push_and_pull_request_event_dispatch(self):
        deliveries = self.document(f"{self.hook_path}/deliveries")["items"]
        event_types = {d["event_type"] for d in deliveries}
        assert "push" in event_types
        assert "pull_request" in event_types
        # Verify internal refs/rootyard-ci/* outbox events were never emitted as push deliveries.
        for d in deliveries:
            if d["event_type"] == "push":
                assert not d["payload"]["ref_name"].startswith("refs/rootyard-ci/")

    def exponential_backoff_retry_and_dead_letter(self):
        # Plan two 502 responses followed by 200 on manual retry.
        self.receiver.clear()
        self.receiver.planned_statuses = [502, 502, 502, 200]
        ping_fail = self.document(
            f"{self.hook_path}/ping",
            200,
            method="POST",
            body={"zen": "Backoff test", "event_id": "ping-backoff-1"},
        )
        delivery_id = ping_fail["id"]
        assert ping_fail["state"] == "failed"
        assert ping_fail["attempts"] == 1
        assert ping_fail["next_attempt_unix"] > 0

        # Advance virtual clock past backoff window twice until max_attempts (3) transitions to dead_letter.
        far_future = ping_fail["next_attempt_unix"] + 600
        self.document(
            self.dispatchpath,
            200,
            method="POST",
            body={"now_unix": far_future, "sync_outbox": False, "sync_pulls": False},
        )
        d_after_2 = self.document(f"{self.hook_path}/deliveries/{delivery_id}")
        assert d_after_2["state"] == "failed" and d_after_2["attempts"] == 2

        self.document(
            self.dispatchpath,
            200,
            method="POST",
            body={"now_unix": far_future + 1200, "sync_outbox": False, "sync_pulls": False},
        )
        d_dead = self.document(f"{self.hook_path}/deliveries/{delivery_id}")
        assert d_dead["state"] == "dead_letter" and d_dead["attempts"] == 3

        # Manual retry resets dead_letter and delivers cleanly (200 OK).
        retried = self.document(
            f"{self.hook_path}/deliveries/{delivery_id}/retry",
            200,
            method="POST",
            body={"deliver_now": True, "reset_attempts": True},
        )
        assert retried["state"] == "delivered"
        assert retried["response_status"] == 200

    def webhook_loopback_default_deny_and_operator_opt_in(self):
        # A separate service process without ROOTYARD_WEBHOOK_ALLOW_LOOPBACK keeps
        # the secure default. The opt-in is never taken from a request body.
        deny = ForgeHarness(self.args)
        deny.env.pop("ROOTYARD_WEBHOOK_ALLOW_LOOPBACK", None)
        receiver = LocalWebhookReceiver("whsec_deny_loopback_secret_0123456789")
        try:
            deny.setup()
            deny.document("/api/repos", 201, method="POST", body={"name": "deny"})
            hooks_path = "/api/repos/alice/deny/webhooks"
            for bad_url in (
                receiver.url,
                "http://localhost:%d/owned-internal" % receiver.port,
                "http://[::1]:%d/owned-internal" % receiver.port,
                "https://127.0.0.1/owned-internal",
                "https://localhost/owned-internal",
                "https://10.0.0.1/hook",
                "https://192.168.1.10/hook",
                "https://169.254.169.254/latest/meta-data/",
                "https://[fe80::1]/hook",
                "https://[fc00::1]/hook",
            ):
                deny.document(
                    hooks_path,
                    400,
                    method="POST",
                    body={"url": bad_url, "secret": "whsec_deny_loopback_secret_0123456789"},
                )
            # Non-loopback HTTPS targets stay accepted, and switching an existing
            # hook to loopback is rejected by the update path as well.
            https_hook = deny.document(
                hooks_path,
                201,
                method="POST",
                body={
                    "url": "https://ci.example.com/hook",
                    "secret": "whsec_deny_loopback_secret_0123456789",
                },
            )
            deny.document(
                hooks_path + "/" + https_hook["id"],
                400,
                method="PATCH",
                body={"expected_version": https_hook["version"], "url": receiver.url},
            )

            # A row persisted while loopback was allowed must not deliver once the
            # policy is the default: the send path re-validates the target.
            legacy_id = deny.sql(
                "WITH inserted AS (INSERT INTO forge_webhooks (id,tenant_id,repository_id,url,secret,secret_sha256) "
                "SELECT gen_random_uuid(), r.owner_id, r.id, '"
                + receiver.url
                + "', 'whsec_deny_loopback_secret_0123456789', "
                "'" + hashlib.sha256(b"whsec_deny_loopback_secret_0123456789").hexdigest() + "' "
                "FROM repositories r JOIN namespaces n ON n.id=r.owner_id "
                "WHERE n.slug='alice' AND r.name='deny' RETURNING id) SELECT id FROM inserted"
            )
            denial = deny.document(
                hooks_path + "/" + legacy_id + "/ping",
                200,
                method="POST",
                body={"event_id": "deny-ping-1", "deliver_now": True},
            )
            assert denial["state"] in ("failed", "dead_letter"), denial
            assert "blocked" in (denial.get("last_error") or ""), denial
            assert receiver.requests == [], receiver.requests
        finally:
            receiver.close()
            deny.cleanup()

        # The opted-in harness process still accepts and delivers to loopback.
        assert self.hook["url"].startswith("http://127.0.0.1:")
        self.receiver.clear()
        ping = self.document(
            self.hook_path + "/ping",
            200,
            method="POST",
            body={"event_id": "opt-in-ping-1", "deliver_now": True},
        )
        assert ping["state"] == "delivered"
        assert len(self.receiver.requests) == 1

    def collaborator_team_and_organization_tenant_scope(self):
        # The tenant column is the repository owner. A direct collaborator, a
        # repository team member, an organization administrator and an
        # organization team member all act on the owner's rows, while an
        # unrelated tenant still receives 404.
        owner_rows = self.document(self.webhookspath)["items"]
        assert [h["id"] for h in owner_rows] == [self.hook["id"]]

        carol = self.issue_token("carol", create_user=True)
        self.document(
            "/api/repos/alice/forge/collaborators/" + carol["username"],
            (200, 201),
            method="PUT",
            body={"role": "admin"},
        )
        collab_rows = self.document(self.webhookspath, token=carol)["items"]
        assert [h["id"] for h in collab_rows] == [self.hook["id"]], collab_rows
        fetched = self.document(self.hook_path, token=carol)
        assert fetched["id"] == self.hook["id"]
        patched = self.document(
            self.hook_path,
            200,
            token=carol,
            method="PATCH",
            body={"expected_version": fetched["version"], "max_attempts": 4},
        )
        assert patched["max_attempts"] == 4

        # ping/retry/dispatch/deliveries under the collaborator identity.
        self.receiver.clear()
        ping = self.document(
            self.hook_path + "/ping",
            200,
            token=carol,
            method="POST",
            body={"event_id": "collab-ping-1", "deliver_now": True},
        )
        assert ping["event_id"] == "collab-ping-1" and ping["state"] == "delivered"
        deliveries = self.document(self.hook_path + "/deliveries", token=carol)["items"]
        assert any(d["event_id"] == "collab-ping-1" for d in deliveries), deliveries
        retried = self.document(
            self.hook_path + "/deliveries/" + ping["id"] + "/retry",
            200,
            token=carol,
            method="POST",
            body={"deliver_now": False},
        )
        assert retried["state"] == "pending"
        summary = self.document(
            self.dispatchpath,
            200,
            token=carol,
            method="POST",
            body={"limit": 5, "sync_outbox": False, "sync_pulls": False},
        )
        assert summary["delivered_count"] >= 1, summary

        # Creation and idempotent replay are scoped to the owner tenant as well.
        collab_body = {
            "url": self.receiver.url,
            "secret": "whsec_carol_collaborator_secret_0123456789",
        }
        collab_hook = self.document(
            self.webhookspath,
            201,
            token=carol,
            method="POST",
            body=collab_body,
            extra_headers={"Idempotency-Key": "collab-create-1"},
        )
        replay = self.document(
            self.webhookspath,
            200,
            token=carol,
            method="POST",
            body=collab_body,
            extra_headers={"Idempotency-Key": "collab-create-1"},
        )
        assert replay["id"] == collab_hook["id"]
        bound = self.sql(
            "SELECT count(*) FROM forge_webhooks w JOIN repositories r "
            "ON r.id=w.repository_id AND r.owner_id=w.tenant_id "
            "WHERE w.id='%s'" % collab_hook["id"]
        )
        assert bound == "1", bound
        self.document(
            self.webhookspath + "/" + collab_hook["id"], 200, token=carol, method="DELETE"
        )

        # Repository team membership (write role) is enough to manage hooks.
        dave = self.issue_token("dave", create_user=True)
        self.document(
            "/api/repos/alice/forge/teams",
            201,
            method="POST",
            body={"slug": "ci", "name": "CI", "role": "write"},
        )
        self.document(
            "/api/repos/alice/forge/teams/ci/members/" + dave["username"],
            (200, 201),
            method="PUT",
        )
        team_hook = self.document(
            self.webhookspath,
            201,
            token=dave,
            method="POST",
            body={"url": self.receiver.url, "secret": "whsec_dave_team_secret_0123456789"},
        )
        team_rows = self.document(self.webhookspath, token=dave)["items"]
        assert team_hook["id"] in [h["id"] for h in team_rows]
        self.document(
            self.webhookspath + "/" + team_hook["id"], 200, token=dave, method="DELETE"
        )

        # Organization administrator (alice created the organization) and an
        # organization team member (bob holds write on the org team).
        self.document(
            "/api/orgs", 201, method="POST", body={"slug": "webhookorg"}
        )
        self.document(
            "/api/repos",
            201,
            method="POST",
            body={"name": "orgdemo", "owner": "webhookorg"},
        )
        org_hooks = "/api/repos/webhookorg/orgdemo/webhooks"
        org_hook = self.document(
            org_hooks,
            201,
            method="POST",
            body={
                "url": self.receiver.url,
                "secret": "whsec_org_admin_secret_0123456789",
                "events": ["ping"],
            },
        )
        assert self.document(org_hooks)["items"][0]["id"] == org_hook["id"]
        org_bound = self.sql(
            "SELECT count(*) FROM forge_webhooks w JOIN repositories r "
            "ON r.id=w.repository_id AND r.owner_id=w.tenant_id "
            "WHERE w.id='%s'" % org_hook["id"]
        )
        assert org_bound == "1", org_bound
        org_ping = self.document(
            org_hooks + "/" + org_hook["id"] + "/ping",
            200,
            method="POST",
            body={"event_id": "org-ping-1", "deliver_now": True},
        )
        assert org_ping["state"] == "delivered"

        self.document(
            "/api/orgs/webhookorg/members/bob", (200, 201), method="PUT",
            body={"role": "read"},
        )
        self.document(
            "/api/orgs/webhookorg/teams",
            201,
            method="POST",
            body={"slug": "ci", "name": "CI", "role": "write"},
        )
        self.document("/api/orgs/webhookorg/teams/ci/members/bob", (200, 201), method="PUT")
        bob_hook = self.document(
            org_hooks,
            201,
            token=self.bob,
            method="POST",
            body={"url": self.receiver.url, "secret": "whsec_org_team_secret_0123456789"},
        )
        assert bob_hook["id"] in [h["id"] for h in self.document(org_hooks, token=self.bob)["items"]]
        self.document(org_hooks + "/" + bob_hook["id"], 200, token=self.bob, method="DELETE")

        # Different tenant: no role on alice/other or the organization repository.
        self.document("/api/repos/alice/other/webhooks", 404, token=carol)
        self.document(org_hooks, 404, token=carol)

    def access_and_boundaries(self):
        # Non-owner (bob) receives 404 Not Found; read-only token receives 403 Forbidden on mutations.
        self.document(self.webhookspath, 404, token=self.bob)
        self.document(
            self.webhookspath,
            403,
            token=self.alice_read,
            method="POST",
            body={"url": self.receiver.url, "secret": self.webhook_secret},
        )
        # Delete webhook and verify 404 afterwards.
        deleted = self.document(self.hook_path, 200, method="DELETE")
        assert deleted["deleted"] is True
        self.document(self.hook_path, 404)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    harness = WebhooksHarness(args)
    success = False
    try:
        for name in (
            "setup",
            "migration",
            "webhook_crud_and_secret_redaction",
            "ping_and_hmac_sha256_signature_verification",
            "auto_pr_ci_pin_and_queued_check_orchestration",
            "idempotent_ci_callbacks_and_monotonic_check_runs",
            "outbox_push_and_pull_request_event_dispatch",
            "exponential_backoff_retry_and_dead_letter",
            "webhook_loopback_default_deny_and_operator_opt_in",
            "collaborator_team_and_organization_tenant_scope",
            "access_and_boundaries",
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
