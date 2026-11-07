#!/usr/bin/env python3
"""Offline unit and contract tests for Milestone M7 (Track A: External CI Webhooks & Auto Pipeline)."""
from __future__ import annotations

import ast
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import urllib.request
import urllib.error
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tier5_adversarial as t5  # noqa: E402
import webhooks  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def _rust_hmac_sha256_bytes(secret: bytes, payload: bytes) -> bytes:
    """Exact mirror of src/webhooks/signing.rs RFC 2104 64-byte block HMAC-SHA256."""
    block_size = 64
    if len(secret) > block_size:
        secret = hashlib.sha256(secret).digest()
    key_block = secret.ljust(block_size, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key_block)
    opad = bytes(b ^ 0x5C for b in key_block)
    inner = hashlib.sha256(ipad + payload).digest()
    return hashlib.sha256(opad + inner).digest()


def _validate_webhook_url_py(raw: str, allow_loopback: bool = False) -> dict:
    """Reference validator matching models.rs::validate_webhook_url_with_policy.

    Loopback targets are denied unless the operator explicitly opted in through
    ROOTYARD_WEBHOOK_ALLOW_LOOPBACK; the decision never comes from the request body.
    """
    if not (8 <= len(raw) <= 1024) or "#" in raw or any(ord(c) <= 32 or ord(c) == 127 for c in raw):
        raise ValueError("invalid length, fragment, or control char")
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme")
    if "@" in parsed.netloc or not parsed.hostname:
        raise ValueError("credentials or missing host forbidden")
    host = parsed.hostname.lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port <= 0 or port > 65535:
        raise ValueError("invalid port")

    is_loopback = host in ("127.0.0.1", "::1", "localhost") or host.endswith(".localhost")
    if parsed.scheme == "http" and not is_loopback:
        raise ValueError("non-loopback http forbidden")
    if is_loopback and not allow_loopback:
        raise ValueError("loopback target requires explicit operator opt-in")

    if not is_loopback:
        try:
            ip = ipaddress.ip_address(host)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_unspecified
                or ip.is_reserved
                or (isinstance(ip, ipaddress.IPv4Address) and ip.packed[0] == 100 and (ip.packed[1] & 0xC0) == 64)
            ):
                raise ValueError("blocked IP range")
        except ValueError as exc:
            if "blocked IP" in str(exc):
                raise
            if (
                host in ("metadata.google.internal", "metadata", "instance-data")
                or host.endswith(".internal")
                or host.endswith(".local")
                or "." not in host
            ):
                raise ValueError("blocked internal hostname") from exc

    return {
        "scheme": parsed.scheme,
        "host": host,
        "port": port,
        "is_loopback": is_loopback,
    }


def _pull_ci_job_id_py(repo_id: uuid.UUID, pull_number: int, head_oid: str, storage_generation: int) -> uuid.UUID:
    """Reference implementation of src/webhooks/delivery.rs::pull_ci_job_id."""
    h = hashlib.sha256()
    h.update(b"rootyard-pull-ci-pin-v1\0")
    h.update(repo_id.bytes)
    h.update(pull_number.to_bytes(8, "big", signed=True))
    h.update(storage_generation.to_bytes(8, "big", signed=True))
    h.update(head_oid.encode("ascii"))
    raw = bytearray(h.digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(raw))


def _backoff_delay_seconds_py(attempt: int, base_seconds: int = 2, max_seconds: int = 300) -> int:
    base = max(1, base_seconds)
    cap = max(base, max_seconds)
    shift = min(30, max(0, attempt - 1))
    return min(cap, base * (1 << shift))


class WebhooksTrackAContractTest(unittest.TestCase):
    def test_webhooks_module_layout_and_anti_monolith_bounds(self):
        webhooks_rs = ROOT / "src/webhooks.rs"
        mod_rs = ROOT / "src/webhooks/mod.rs"
        self.assertTrue(webhooks_rs.is_file(), "src/webhooks.rs must be a regular file")
        self.assertFalse(mod_rs.exists(), "src/webhooks/mod.rs must never exist")

        src = webhooks_rs.read_text(encoding="utf-8")
        lines = src.splitlines()
        self.assertLess(
            len(lines),
            100,
            f"src/webhooks.rs must remain < 100 lines, got {len(lines)}",
        )
        self.assertIn("pub const MIGRATION_040_SQL: &str = include_str!(\"webhooks/040_webhooks.sql\");", src)
        self.assertIn("pub fn routes() -> Router<Arc<AppState>>", src)

        for sql_kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "):
            self.assertNotIn(sql_kw, src, f"src/webhooks.rs must not contain inline SQL ({sql_kw})")
        self.assertNotIn("Command::new", src, "src/webhooks.rs must not spawn subprocesses directly")

        submodules = ("models", "signing", "delivery", "handlers")
        for sub in submodules:
            self.assertIn(f"pub mod {sub};", src)
            sub_path = ROOT / "src/webhooks" / f"{sub}.rs"
            self.assertTrue(sub_path.is_file(), f"Missing submodule {sub_path}")
            sub_lines = sub_path.read_text(encoding="utf-8").splitlines()
            self.assertGreater(
                len(sub_lines),
                50,
                f"src/webhooks/{sub}.rs must be > 50 lines (got {len(sub_lines)})",
            )
            self.assertLess(
                len(sub_lines),
                550,
                f"src/webhooks/{sub}.rs must be < 550 lines (got {len(sub_lines)})",
            )

        expected_routes = {
            "/api/repos/{owner}/{name}/webhooks": ["GET", "POST"],
            "/api/repos/{owner}/{name}/webhooks/dispatch": ["POST"],
            "/api/repos/{owner}/{name}/webhooks/{hook_id}": ["GET", "PATCH", "DELETE"],
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/ping": ["POST"],
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/callback": ["POST"],
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/deliveries": ["GET"],
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/deliveries/{delivery_id}": ["GET"],
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/deliveries/{delivery_id}/retry": ["POST"],
            "/api/repos/{owner}/{name}/integrations/{hook_id}/check-runs": ["POST"],
        }
        extracted = dict(t5._extract_route_registrations(webhooks_rs))
        self.assertEqual(extracted, expected_routes)

        # Verify zero collisions with all existing domain routers.
        existing_bindings: dict[tuple[str, str], tuple[str, str]] = {}
        for rel in t5.TestTier5RouterAndParameterNonCollision.PRIMARY_ROUTER_FILES:
            for raw_path, methods in t5._extract_route_registrations(ROOT / rel):
                norm = t5._normalize_route_pattern(raw_path)
                for m in methods:
                    existing_bindings[(norm, m)] = (rel, raw_path)

        for raw_path, methods in extracted.items():
            norm = t5._normalize_route_pattern(raw_path)
            for m in methods:
                self.assertNotIn(
                    (norm, m),
                    existing_bindings,
                    f"Webhook route {(norm, m)} collides with {existing_bindings.get((norm, m))}",
                )

    def test_migration_040_webhooks_sql_contract_and_zero_between(self):
        sql_path = webhooks.migration_040_path()
        self.assertTrue(sql_path.is_file(), f"Missing SQL migration at {sql_path}")
        sql = sql_path.read_text(encoding="utf-8")

        self.assertIsNone(
            re.search(r"\bBETWEEN\b", sql, flags=re.IGNORECASE),
            "040_webhooks.sql must contain zero BETWEEN clauses",
        )

        tables = (
            "forge_webhooks",
            "forge_webhook_deliveries",
            "forge_webhook_callbacks",
        )
        positions = {}
        for tbl in tables:
            match = re.search(rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{tbl}\s*\(", sql)
            self.assertIsNotNone(match, f"Missing CREATE TABLE for {tbl}")
            positions[tbl] = match.start()

        self.assertLess(positions["forge_webhooks"], positions["forge_webhook_deliveries"])
        self.assertLess(positions["forge_webhook_deliveries"], positions["forge_webhook_callbacks"])

        repo_fks = re.findall(
            r"FOREIGN KEY\s*\(\s*repository_id\s*,\s*tenant_id\s*\)\s*REFERENCES\s+repositories\s*\(\s*id\s*,\s*owner_id\s*\)\s*ON\s+DELETE\s+CASCADE",
            sql,
        )
        self.assertEqual(len(repo_fks), 3, "Expected 3 composite tenant FKs with ON DELETE CASCADE")
        self.assertIn("UNIQUE (webhook_id, event_id)", sql)
        self.assertIn("PRIMARY KEY (repository_id, event_id)", sql)
        self.assertIn("event_type IN ('push', 'pull_request', 'check_run', 'ping')", sql)
        self.assertIn("state IN ('pending', 'leased', 'delivered', 'failed', 'dead_letter')", sql)
        self.assertIn("signature_256 LIKE 'sha256=%' AND octet_length(signature_256) = 71", sql)
        self.assertIn(
            "INSERT INTO schema_migrations (version) VALUES (40) ON CONFLICT (version) DO NOTHING;",
            sql,
        )

    def test_rust_source_invariants_auth_serde_and_ci_pin_reliability(self):
        models_src = (ROOT / "src/webhooks/models.rs").read_text(encoding="utf-8")
        signing_src = (ROOT / "src/webhooks/signing.rs").read_text(encoding="utf-8")
        delivery_src = (ROOT / "src/webhooks/delivery.rs").read_text(encoding="utf-8")
        handlers_src = (ROOT / "src/webhooks/handlers.rs").read_text(encoding="utf-8")

        self.assertGreaterEqual(models_src.count("#[serde(deny_unknown_fields)]"), 8)
        self.assertIn("#[cfg(test)]", models_src)
        self.assertIn("#[cfg(test)]", signing_src)
        self.assertIn("#[cfg(test)]", delivery_src)

        for token in (
            "auth::authenticate",
            "authorize_repo_with_role(",
            "finish(",
            "idempotency_key",
            "tokio::spawn",
            "verify_signature_header",
        ):
            self.assertIn(token, handlers_src, f"handlers.rs missing required token: {token}")

        for token in (
            "pub async fn on_pull_synchronized(",
            "pub async fn orchestrate_pull_ci(",
            "pub async fn sync_outbox_events(",
            "pub fn backoff_delay_seconds(",
            "git_slots",
            "write_lock(",
            "reliability::before_push(",
            "core.hooksPath=/dev/null",
            "update-ref",
            "--no-deref",
            "journal::begin(",
            "journal::finish(",
            "events::publish(",
            "state.dispatch.committed()",
            "journal::retire(",
        ):
            self.assertIn(token, delivery_src, f"delivery.rs missing required token: {token}")

    def test_rfc2104_hmac_sha256_vectors_and_constant_time_verification(self):
        # Verify RFC 4231 vectors match both Python stdlib hmac and our block-level implementation.
        vectors = [
            (bytes([0x0B] * 20), b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (bytes([0xAA] * 20), bytes([0xDD] * 50), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (
                bytes([0xAA] * 131),
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
        ]
        for key, data, expected_hex in vectors:
            self.assertEqual(_rust_hmac_sha256_bytes(key, data).hex(), expected_hex)

        secret = "whsec_test_signing_secret_987654321"
        payload = b'{"event":"push","ref_name":"refs/heads/main"}'
        hdr = webhooks.compute_hmac_sha256_header(secret, payload)
        self.assertTrue(hdr.startswith("sha256="))
        self.assertEqual(len(hdr), 71)

    def test_ssrf_url_validation_and_loopback_default_deny(self):
        valid_urls = [
            "https://ci.example.com/webhooks/rootyard",
            "https://hooks.example.org:8443/v1/events?env=prod",
        ]
        for u in valid_urls:
            for allow_loopback in (False, True):
                parsed = _validate_webhook_url_py(u, allow_loopback=allow_loopback)
                self.assertIn(parsed["scheme"], ("http", "https"))
                self.assertFalse(parsed["is_loopback"])

        # Loopback targets are rejected by default and accepted only after the
        # explicit operator opt-in.
        loopback_urls = [
            "http://127.0.0.1:9000/hook",
            "http://[::1]:9001/callback",
            "http://localhost:8080/ci",
            "https://127.0.0.1/hook",
            "https://[::1]/hook",
            "https://localhost/hook",
            "https://ci.localhost/hook",
        ]
        for u in loopback_urls:
            with self.assertRaises(ValueError, msg=f"Expected loopback denial for {u}"):
                _validate_webhook_url_py(u)
            parsed = _validate_webhook_url_py(u, allow_loopback=True)
            self.assertTrue(parsed["is_loopback"])

        blocked_urls = [
            "http://ci.example.com/webhooks",
            "http://127.0.0.2/hook",
            "https://127.0.0.2/hook",
            "https://0.0.0.0/hook",
            "https://10.0.0.1/hook",
            "https://100.64.0.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://172.16.0.1/hook",
            "https://192.168.1.1/hook",
            "https://[fe80::1]/hook",
            "https://[fc00::1]/hook",
            "https://user:pass@ci.example.com/hook",
            "https://ci.example.com/hook#frag",
            "https://metadata.google.internal/computeMetadata/v1/",
        ]
        for bad in blocked_urls:
            for allow_loopback in (False, True):
                with self.assertRaises(ValueError, msg=f"Expected SSRF rejection for {bad}"):
                    _validate_webhook_url_py(bad, allow_loopback=allow_loopback)

    def test_loopback_policy_module_and_owner_tenant_binding_contract(self):
        policy_src = (ROOT / "src/webhooks/policy.rs").read_text(encoding="utf-8")
        self.assertIn(
            'pub const ALLOW_LOOPBACK_ENV: &str = "ROOTYARD_WEBHOOK_ALLOW_LOOPBACK";', policy_src
        )
        self.assertIn("pub fn loopback_targets_allowed() -> bool", policy_src)
        self.assertIn("pub fn permitted_peer(", policy_src)
        # Anything except a case-insensitive `true` keeps the deny default.
        self.assertIn('eq_ignore_ascii_case("true")', policy_src)
        self.assertIn("pub mod policy;", (ROOT / "src/webhooks.rs").read_text(encoding="utf-8"))

        # The send path re-validates against the live policy instead of trusting
        # the URL accepted when the hook was created.
        signing_src = (ROOT / "src/webhooks/signing.rs").read_text(encoding="utf-8")
        self.assertIn("policy::loopback_targets_allowed()", signing_src)
        self.assertIn("validate_webhook_url_with_policy(url, loopback_allowed)", signing_src)
        self.assertIn(
            "policy::permitted_peer(target.is_loopback, a.ip(), loopback_allowed)", signing_src
        )

        # Tenant scope is the repository owner, never the acting user.
        handlers_src = (ROOT / "src/webhooks/handlers.rs").read_text(encoding="utf-8")
        self.assertIn(
            "authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::", handlers_src
        )
        self.assertNotIn("authorize_repo(&tx, &actor", handlers_src)
        self.assertNotIn("&actor.id, &access.repo_id", handlers_src)
        self.assertNotIn("&access.owner_id, &actor.id", handlers_src)
        self.assertNotIn("&actor.id", handlers_src)

    def test_live_loopback_http_delivery_exponential_backoff_and_manual_retry(self):
        secret = "whsec_loopback_live_test_secret"
        receiver = webhooks.LocalWebhookReceiver(secret)
        try:
            receiver.planned_statuses = [502, 503, 500, 200]
            payload = {"event": "pull_request", "action": "opened", "pull_number": 7}
            raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            sig = webhooks.compute_hmac_sha256_header(secret, raw_body)

            max_attempts = 3
            state = "pending"
            attempts = 0
            next_attempt_unix = 0
            now_unix = 1_700_000_000

            def attempt_delivery(cur_unix: int):
                nonlocal state, attempts, next_attempt_unix
                attempts += 1
                req = urllib.request.Request(
                    receiver.url,
                    data=raw_body,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "X-Rootyard-Event": "pull_request",
                        "X-Rootyard-Delivery": str(uuid.uuid4()),
                        "X-Rootyard-Hook-Id": str(uuid.uuid4()),
                        "X-Rootyard-Signature-256": sig,
                        "X-Rootyard-Attempt": str(attempts),
                    },
                )
                try:
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        code = resp.status
                except urllib.error.HTTPError as err:
                    code = err.code

                if 200 <= code <= 299:
                    state = "delivered"
                    next_attempt_unix = 0
                elif attempts >= max_attempts:
                    state = "dead_letter"
                    next_attempt_unix = 0
                else:
                    state = "failed"
                    next_attempt_unix = cur_unix + _backoff_delay_seconds_py(attempts, 2, 300)
                return code

            # Attempt 1 -> 502 -> failed with +2s backoff
            self.assertEqual(attempt_delivery(now_unix), 502)
            self.assertEqual(state, "failed")
            self.assertEqual(attempts, 1)
            self.assertEqual(next_attempt_unix, now_unix + 2)

            # Attempt 2 -> 503 -> failed with +4s backoff
            now_unix = next_attempt_unix
            self.assertEqual(attempt_delivery(now_unix), 503)
            self.assertEqual(state, "failed")
            self.assertEqual(attempts, 2)
            self.assertEqual(next_attempt_unix, now_unix + 4)

            # Attempt 3 -> 500 -> reaches max_attempts (3) -> dead_letter
            now_unix = next_attempt_unix
            self.assertEqual(attempt_delivery(now_unix), 500)
            self.assertEqual(state, "dead_letter")
            self.assertEqual(attempts, 3)

            # Manual retry resets dead_letter -> pending (attempts = 0) and succeeds (200 -> delivered)
            state = "pending"
            attempts = 0
            self.assertEqual(attempt_delivery(now_unix + 10), 200)
            self.assertEqual(state, "delivered")
            self.assertEqual(attempts, 1)
            self.assertEqual(len(receiver.requests), 4)
            self.assertTrue(all(r["signature_valid"] for r in receiver.requests))
        finally:
            receiver.close()

    def test_auto_pr_ci_pin_queued_checks_idempotent_callbacks_and_stale_head_invalidation(self):
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
            "GIT_AUTHOR_NAME": "alice",
            "GIT_AUTHOR_EMAIL": "alice@rootyard.local",
            "GIT_COMMITTER_NAME": "alice",
            "GIT_COMMITTER_EMAIL": "alice@rootyard.local",
        }

        def run_git(*args, cwd=None):
            return subprocess.run(
                ["git", *args],
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bare = root / "repo.git"
            work = root / "work"
            pins_dir = root / "ci-pins"
            run_git("init", "--bare", "--initial-branch=main", str(bare))
            run_git("clone", str(bare), str(work))

            (work / "README.md").write_text("rootyard\n", encoding="utf-8")
            run_git("add", "README.md", cwd=work)
            run_git("commit", "-m", "base", cwd=work)
            base_oid = run_git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            run_git("push", "origin", "HEAD:refs/heads/main", cwd=work)

            (work / "ci.txt").write_text("v1\n", encoding="utf-8")
            run_git("add", "ci.txt", cwd=work)
            run_git("commit", "-m", "feat v1", cwd=work)
            feat1_oid = run_git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            run_git("push", "origin", "HEAD:refs/heads/feature", cwd=work)

            (work / "ci.txt").write_text("v2\n", encoding="utf-8")
            run_git("add", "ci.txt", cwd=work)
            run_git("commit", "-m", "feat v2", cwd=work)
            feat2_oid = run_git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            run_git("push", "origin", "HEAD:refs/heads/feature", cwd=work)

            repo_id = uuid.uuid4()
            owner_id = uuid.uuid4()

            conn = sqlite3.connect(":memory:")
            conn.executescript(
                """
                CREATE TABLE forge_check_runs (
                    tenant_id TEXT NOT NULL,
                    repository_id TEXT NOT NULL,
                    commit_oid TEXT NOT NULL,
                    context TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt > 0),
                    sequence INTEGER NOT NULL DEFAULT 1 CHECK (sequence > 0),
                    status TEXT NOT NULL CHECK (status IN ('queued', 'in_progress', 'completed')),
                    conclusion TEXT CHECK (conclusion IN ('success', 'failure', 'neutral', 'cancelled', 'timed_out', 'skipped')),
                    output TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, repository_id, commit_oid, context)
                );
                CREATE TABLE forge_webhook_callbacks (
                    tenant_id TEXT NOT NULL,
                    repository_id TEXT NOT NULL,
                    webhook_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    response TEXT NOT NULL,
                    PRIMARY KEY (repository_id, event_id)
                );
                """
            )

            def on_pull_sync(pull_number: int, head_oid: str, required_checks: list[str]):
                job_id = _pull_ci_job_id_py(repo_id, pull_number, head_oid, 1)
                retention_ref = f"refs/rootyard-ci/jobs/{job_id}"
                intent = {
                    "version": 1,
                    "job_id": str(job_id),
                    "owner_id": str(owner_id),
                    "repository_id": str(repo_id),
                    "storage_generation": 1,
                    "object_format": "sha1",
                    "target_oid": head_oid,
                    "retention_ref": retention_ref,
                }
                repo_pin_dir = pins_dir / str(repo_id)
                repo_pin_dir.mkdir(parents=True, exist_ok=True)
                intent_bytes = json.dumps(intent, separators=(",", ":")).encode("utf-8")
                (repo_pin_dir / f"{job_id}.json").write_bytes(intent_bytes)
                run_git(
                    "--no-replace-objects",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "--git-dir",
                    str(bare),
                    "update-ref",
                    "--no-deref",
                    retention_ref,
                    head_oid,
                )
                (repo_pin_dir / f"{job_id}.pinned.json").write_bytes(intent_bytes)
                for ctx in required_checks:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO forge_check_runs
                        (tenant_id, repository_id, commit_oid, context, attempt, sequence, status, conclusion, output)
                        VALUES (?, ?, ?, ?, 1, 1, 'queued', NULL, 'queued by pull request synchronization')
                        """,
                        (str(owner_id), str(repo_id), head_oid, ctx),
                    )
                conn.commit()
                return job_id, retention_ref

            # 1. Synchronize PR #1 on feat1_oid
            job1, ref1 = on_pull_sync(1, feat1_oid, ["ci/test", "ci/lint"])
            job1_repeat, _ = on_pull_sync(1, feat1_oid, ["ci/test", "ci/lint"])
            self.assertEqual(job1, job1_repeat, "Deterministic job_id must be idempotent")
            resolved_ref1 = (
                run_git("--git-dir", str(bare), "rev-parse", f"{ref1}^{{commit}}")
                .stdout.decode()
                .strip()
            )
            self.assertEqual(resolved_ref1, feat1_oid)

            # 2. Process idempotent CI callback on feat1_oid
            hook_id = str(uuid.uuid4())

            def process_callback(event_id: str, commit_oid: str, context: str, status: str, conclusion: str | None, attempt: int, sequence: int):
                req_sha = hashlib.sha256(
                    json.dumps(
                        [hook_id, commit_oid, context, status, conclusion, attempt, sequence],
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                row = conn.execute(
                    "SELECT request_sha256, response FROM forge_webhook_callbacks WHERE repository_id=? AND event_id=?",
                    (str(repo_id), event_id),
                ).fetchone()
                if row is not None:
                    if row[0] != req_sha:
                        return 409, {"error": "callback idempotency key conflict"}
                    return 200, json.loads(row[1])

                cur = conn.execute(
                    "SELECT attempt, sequence, status, conclusion FROM forge_check_runs WHERE tenant_id=? AND repository_id=? AND commit_oid=? AND context=?",
                    (str(owner_id), str(repo_id), commit_oid, context),
                ).fetchone()
                if cur is None:
                    conn.execute(
                        "INSERT INTO forge_check_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, '')",
                        (str(owner_id), str(repo_id), commit_oid, context, attempt, sequence, status, conclusion),
                    )
                else:
                    if (attempt, sequence) > (cur[0], cur[1]):
                        conn.execute(
                            "UPDATE forge_check_runs SET attempt=?, sequence=?, status=?, conclusion=? WHERE tenant_id=? AND repository_id=? AND commit_oid=? AND context=?",
                            (attempt, sequence, status, conclusion, str(owner_id), str(repo_id), commit_oid, context),
                        )
                    elif (attempt, sequence) == (cur[0], cur[1]):
                        if (cur[2], cur[3]) != (status, conclusion):
                            return 409, {"error": "conflicting check run state"}
                    else:
                        return 409, {"error": "stale check run attempt or sequence"}

                resp = {"commit_oid": commit_oid, "context": context, "status": status, "conclusion": conclusion, "attempt": attempt, "sequence": sequence}
                conn.execute(
                    "INSERT INTO forge_webhook_callbacks VALUES (?, ?, ?, ?, ?, ?)",
                    (str(owner_id), str(repo_id), hook_id, event_id, req_sha, json.dumps(resp)),
                )
                conn.commit()
                return 200, resp

            code, resp = process_callback("cb-1", feat1_oid, "ci/test", "completed", "success", 1, 2)
            self.assertEqual(code, 200)
            # Replay same event_id + same payload -> 200 OK
            code_replay, resp_replay = process_callback("cb-1", feat1_oid, "ci/test", "completed", "success", 1, 2)
            self.assertEqual(code_replay, 200)
            self.assertEqual(resp_replay, resp)
            # Same event_id + mutated payload -> 409 Conflict
            code_conflict, _ = process_callback("cb-1", feat1_oid, "ci/test", "completed", "failure", 1, 2)
            self.assertEqual(code_conflict, 409)
            # Stale sequence (1, 1) -> 409 Conflict
            code_stale, _ = process_callback("cb-stale", feat1_oid, "ci/test", "in_progress", None, 1, 1)
            self.assertEqual(code_stale, 409)

            # 3. Synchronize PR #1 on new head feat2_oid -> creates new pin & fresh 'queued' checks
            job2, ref2 = on_pull_sync(1, feat2_oid, ["ci/test", "ci/lint"])
            self.assertNotEqual(job1, job2)
            feat2_checks = conn.execute(
                "SELECT context, status, conclusion FROM forge_check_runs WHERE commit_oid=? ORDER BY context",
                (feat2_oid,),
            ).fetchall()
            self.assertEqual(
                feat2_checks,
                [("ci/lint", "queued", None), ("ci/test", "queued", None)],
            )
            conn.close()

    def test_webhooks_e2e_harness_ast_and_cli_flags(self):
        webhooks_py = ROOT / "tests/webhooks.py"
        src = webhooks_py.read_text(encoding="utf-8")
        ast.parse(src)

        expected_cases = (
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
        )
        for method_name in expected_cases:
            self.assertTrue(
                callable(getattr(webhooks.WebhooksHarness, method_name, None)),
                f"WebhooksHarness missing method {method_name}",
            )

        self.assertNotIn('ops["items"]', src)
        proc = subprocess.run(
            [sys.executable, str(webhooks_py), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        for flag in ("--binary", "--report", "--keep"):
            self.assertIn(flag, proc.stdout)


if __name__ == "__main__":
    unittest.main()
