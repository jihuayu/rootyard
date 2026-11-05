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
            raw_body=raw,
            extra_headers=hdrs,
        )
        expected = code if isinstance(code, tuple) else (code,)
        assert status in expected, f"{path}: expected {code}, got {status}: {body[:200]!r}"
        assert headers.get("cache-control") == "no-store", headers
        return json.loads(body)

    def setup(self):
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
        self.git(
            "push",
            "origin",
            f"{self.feat2_oid}:refs/heads/feature",
            cwd=self.work,
            token=self.alice,
        )
        self.pr1 = self.document(
            self.pr1_path,
            200,
            method="PATCH",
            body={
                "expected_version": self.pr1["version"],
                "head_oid": self.feat2_oid,
            },
        )
        self.document(self.dispatchpath, 200, method="POST", body={})

        # Merge at feat2_oid must fail with 409 because feat2_oid's check runs are still 'queued'.
        self.document(
            f"{self.pr1_path}/merge",
            409,
            method="POST",
            body={
                "expected_version": self.pr1["version"],
                "expected_head_oid": self.feat2_oid,
                "expected_base_oid": self.base_oid,
            },
        )

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
