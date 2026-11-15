#!/usr/bin/env python3
"""Live-service PostgreSQL pg_dump/pg_restore + loopback-S3 Pando PITR fencing acceptance (#77)."""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_FIXTURE_BODY = 32 * 1024 * 1024
S3_BUCKET = "rootyard-pitr-e2e"
S3_REGION = "garage"


class _DaemonHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class TrackingLoopbackS3:
    """Thread-safe loopback path-style S3 server enforcing If-None-Match: * and recording DELETEs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._objects: dict[tuple[str, str], bytes] = {}
        self.delete_requests: list[str] = []
        parent = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:
                pass

            def do_HEAD(self) -> None:
                self._serve()

            def do_GET(self) -> None:
                self._serve()

            def do_PUT(self) -> None:
                self._serve()

            def do_DELETE(self) -> None:
                self._serve()

            def _reply(self, code: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
                self.send_response_only(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                if body and self.command != "HEAD":
                    self.wfile.write(body)

            def _serve(self) -> None:
                raw_path = self.path.split("?", 1)[0].lstrip("/")
                bucket, _, key = raw_path.partition("/")
                if not bucket:
                    self._reply(200, b"<ListAllMyBucketsResult/>", {"Content-Type": "application/xml"})
                    return
                if self.command == "PUT":
                    if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                        chunks: list[bytes] = []
                        total = 0
                        while True:
                            size_line = self.rfile.readline().split(b";", 1)[0].strip()
                            if not size_line:
                                break
                            chunk_len = int(size_line, 16)
                            if chunk_len == 0:
                                while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                                    pass
                                break
                            total += chunk_len
                            if total > MAX_FIXTURE_BODY:
                                self._reply(413, b"<Error><Code>EntityTooLarge</Code></Error>")
                                return
                            chunks.append(self.rfile.read(chunk_len))
                            self.rfile.read(2)
                        payload = b"".join(chunks)
                    else:
                        length = int(self.headers.get("Content-Length") or 0)
                        if length > MAX_FIXTURE_BODY:
                            self._reply(413, b"<Error><Code>EntityTooLarge</Code></Error>")
                            return
                        payload = self.rfile.read(length) if length else b""
                    if not key:
                        self._reply(200)
                        return
                    etag = f'"{hashlib.md5(payload).hexdigest()}"'
                    with parent._lock:
                        if self.headers.get("If-None-Match") == "*" and (bucket, key) in parent._objects:
                            self._reply(
                                412,
                                b"<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>",
                                {"Content-Type": "application/xml"},
                            )
                            return
                        parent._objects[(bucket, key)] = payload
                    self._reply(200, b"", {"ETag": etag})
                elif self.command in ("GET", "HEAD"):
                    if not key:
                        xml = (
                            f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                            f"<Name>{bucket}</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated>"
                            f"</ListBucketResult>"
                        ).encode()
                        self._reply(200, xml, {"Content-Type": "application/xml"})
                        return
                    with parent._lock:
                        stored = parent._objects.get((bucket, key))
                    if stored is None:
                        self._reply(
                            404,
                            b"<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>",
                            {"Content-Type": "application/xml"},
                        )
                        return
                    etag = f'"{hashlib.md5(stored).hexdigest()}"'
                    if self.command == "HEAD":
                        self.send_response_only(200)
                        self.send_header("ETag", etag)
                        self.send_header("Content-Length", str(len(stored)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.close_connection = True
                    else:
                        self._reply(200, stored, {"ETag": etag})
                elif self.command == "DELETE":
                    with parent._lock:
                        parent.delete_requests.append(key)
                        parent._objects.pop((bucket, key), None)
                    self._reply(204)
                else:
                    self._reply(405)

        self._server = _DaemonHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def put_raw(self, key: str, payload: bytes) -> None:
        with self._lock:
            self._objects[(S3_BUCKET, key)] = payload

    def contains(self, key: str) -> bool:
        with self._lock:
            return (S3_BUCKET, key) in self._objects

    def take_deletes(self) -> list[str]:
        with self._lock:
            items = list(self.delete_requests)
            self.delete_requests.clear()
            return items

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def db_url_with_db(base_url: str, db_name: str) -> str:
    parts = urllib.parse.urlsplit(base_url)
    return urllib.parse.urlunsplit(parts._replace(path="/" + db_name))


def alloc_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_cmd(argv: list[str], env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    res = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    if check and res.returncode != 0:
        raise AssertionError(
            f"command failed ({res.returncode}): {argv[0]}: "
            f"{res.stderr.decode(errors='replace')[-2000:]}"
        )
    return res


def sql_query(db_url: str, query: str) -> str:
    res = run_cmd(["psql", "--dbname", db_url, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", query])
    return res.stdout.decode().strip()


class ServiceHandle:
    def __init__(self, binary: str, env: dict[str, str], log_path: Path) -> None:
        self.binary = binary
        self.env = dict(env)
        self.log_path = log_path
        self.port = alloc_port()
        self.env["ROOTYARD_BIND"] = f"127.0.0.1:{self.port}"
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen[bytes] | None = None
        self._log_file = None

    def start(self) -> None:
        self._log_file = open(self.log_path, "ab")
        kwargs: dict[str, object] = {}
        if os.name != "nt":
            kwargs["start_new_session"] = True
        self.proc = subprocess.Popen(
            [self.binary, "serve"],
            env=self.env,
            stdout=self._log_file,
            stderr=self._log_file,
            **kwargs,
        )
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"rootyard serve exited early ({self.proc.returncode}); see {self.log_path}")
            try:
                with urllib.request.urlopen(self.base_url + "/health/ready", timeout=2) as resp:
                    if resp.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.1)
        raise RuntimeError("rootyard serve /health/ready timed out")

    def http_json(self, path: str, token: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
        headers = {"Authorization": f"Bearer {token}"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, {"raw": raw}

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            if os.name != "nt":
                os.killpg(self.proc.pid, signal.SIGTERM)
            else:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                if os.name != "nt":
                    os.killpg(self.proc.pid, signal.SIGKILL)
                else:
                    self.proc.kill()
                self.proc.wait(timeout=5)
        self.proc = None
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None


def wait_until(predicate, timeout: float = 30.0, label: str = "condition") -> object:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(0.2)
    raise AssertionError(f"timed out waiting for {label}; last={last!r}")


def seed_synthetic_manifest(
    db_url: str,
    s3: TrackingLoopbackS3,
    repo_id: str,
    tenant_id: str,
    authority_id: str,
    tag: str,
) -> tuple[str, list[str]]:
    """Insert valid Pando manifest + active authority-scoped artifact rows + S3 objects."""
    manifest_id = str(uuid.uuid4())
    roles_info = {}
    remote_keys: list[str] = []

    def make_receipt(subtag: str) -> dict:
        plain = f"plain-{tag}-{subtag}".encode()
        cipher = f"cipher-{tag}-{subtag}".encode()
        p_sha = hashlib.sha256(plain).hexdigest()
        c_sha = hashlib.sha256(cipher).hexdigest()
        env_obj = {
            "version": 1,
            "generation": 1,
            "object_id": str(uuid.uuid4()),
            "cipher": "aes-256-gcm",
            "provider": "vault-transit",
            "key_name": "pando",
            "wrapped_key": "vault:v1:synthetic-e2e-key",
            "plaintext_sha256": p_sha,
            "plaintext_bytes": len(plain),
            "ciphertext_sha256": c_sha,
            "ciphertext_bytes": len(cipher),
            "chunk_bytes": 65536,
        }
        env_bytes = json.dumps(env_obj, separators=(",", ":")).encode()
        e_sha = hashlib.sha256(env_bytes).hexdigest()
        roles_info[subtag] = (c_sha, cipher, e_sha, env_bytes)
        return {
            "plaintext_sha256": p_sha,
            "plaintext_bytes": len(plain),
            "ciphertext_sha256": c_sha,
            "ciphertext_bytes": len(cipher),
            "envelope_sha256": e_sha,
            "envelope_bytes": len(env_bytes),
            "envelope": env_obj,
        }

    pack_r = make_receipt("pack")
    idx_r = make_receipt("index")
    manifest_json = json.dumps(
        {
            "version": 1,
            "id": manifest_id,
            "repository_id": repo_id,
            "tenant_id": tenant_id,
            "storage_generation": 1,
            "object_format": "sha1",
            "pack": pack_r,
            "index": idx_r,
        }
    )

    statements = [
        f"INSERT INTO pando_pack_manifests(id,repository_id,tenant_id,storage_generation,object_format,manifest) "
        f"VALUES('{manifest_id}','{repo_id}','{tenant_id}',1,'sha1',$${manifest_json}$$::jsonb);"
    ]
    for subtag in ("pack", "index"):
        c_sha, cipher, e_sha, env_bytes = roles_info[subtag]
        for ns, sha, data, role in (
            ("pando-cipher", c_sha, cipher, f"{subtag}-cipher"),
            ("pando-envelope", e_sha, env_bytes, f"{subtag}-envelope"),
        ):
            rpath = f"tenants/{tenant_id}/authorities/{authority_id}/g1/{ns}/{sha}"
            s3.put_raw(rpath, data)
            remote_keys.append(rpath)
            statements.append(
                "INSERT INTO pando_remote_artifacts"
                "(authority_id,tenant_id,namespace,sha256,size,object_generation,remote_path,state) "
                f"VALUES('{authority_id}','{tenant_id}','{ns}','{sha}',{len(data)},1,'{rpath}','active') "
                "ON CONFLICT DO NOTHING;"
            )
            statements.append(
                "INSERT INTO pando_manifest_artifacts"
                "(manifest_id,repository_id,authority_id,tenant_id,namespace,sha256,artifact_role) "
                f"VALUES('{manifest_id}','{repo_id}','{authority_id}','{tenant_id}','{ns}','{sha}','{role}');"
            )

    sql_query(db_url, "BEGIN;\n" + "\n".join(statements) + "\nCOMMIT;")
    return manifest_id, remote_keys


def run_suite(binary: str) -> dict:
    admin_url = os.environ["ROOTYARD_TEST_DATABASE_URL"]
    root = Path(tempfile.mkdtemp(prefix="rootyard-pitr-svc-"))
    suffix = uuid.uuid4().hex[:12]
    src_db_name = f"rootyard_pitr_src_{suffix}"
    clone_db_name = f"rootyard_pitr_clone_{suffix}"
    src_url = db_url_with_db(admin_url, src_db_name)
    clone_url = db_url_with_db(admin_url, clone_db_name)

    s3 = TrackingLoopbackS3()
    services: list[ServiceHandle] = []
    results: dict[str, object] = {}

    try:
        sql_query(admin_url, f'CREATE DATABASE "{src_db_name}";')
        sql_query(admin_url, f'CREATE DATABASE "{clone_db_name}";')

        src_data = root / "src-data"
        clone_data = root / "clone-data"
        src_data.mkdir(parents=True, exist_ok=True)
        clone_data.mkdir(parents=True, exist_ok=True)

        base_env = os.environ.copy()
        base_env.update(
            {
                "ROOTYARD_OBJECT_STORE_ENDPOINT": s3.endpoint,
                "ROOTYARD_OBJECT_STORE_BUCKET": S3_BUCKET,
                "ROOTYARD_OBJECT_STORE_REGION": S3_REGION,
                "ROOTYARD_OBJECT_STORE_ACCESS_KEY": "pitr-ak",
                "ROOTYARD_OBJECT_STORE_SECRET_KEY": "pitr-sk",
                "ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS": "1",
                "ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS": "5",
                "ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS": "1",
                "ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS": "1",
                "ROOTYARD_STORAGE_MAINTENANCE_QUIESCENCE_SECONDS": "1",
                "ROOTYARD_STORAGE_MAINTENANCE_MAX_ATTEMPTS": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "LC_ALL": "C",
            }
        )
        base_env.pop("ROOTYARD_OBJECT_STORE_SESSION_TOKEN", None)

        src_env = {**base_env, "DATABASE_URL": src_url, "ROOTYARD_DATA_DIR": str(src_data)}

        # 1. Invalid ROOTYARD_PANDO_REMOTE_DELETE value fails closed at startup.
        run_cmd([binary, "migrate"], env=src_env)
        bogus_env = {**src_env, "ROOTYARD_PANDO_REMOTE_DELETE": "maybe", "ROOTYARD_BIND": f"127.0.0.1:{alloc_port()}"}
        bogus = run_cmd([binary, "serve"], env=bogus_env, check=False)
        assert bogus.returncode != 0, "invalid ROOTYARD_PANDO_REMOTE_DELETE must fail serve startup"
        assert b"ROOTYARD_PANDO_REMOTE_DELETE" in bogus.stderr, bogus.stderr

        # 2. Live source service attests epoch 1 proof and exposes CLI status/verify.
        alice = json.loads(run_cmd([binary, "create-user", "alice"], env=src_env).stdout.decode())
        src_live_env = {**src_env, "ROOTYARD_PANDO_REMOTE_DELETE": "true", "ROOTYARD_STORAGE_MAINTENANCE": "false"}
        src_svc = ServiceHandle(binary, src_live_env, root / "src.log")
        services.append(src_svc)
        src_svc.start()

        status_1 = json.loads(run_cmd([binary, "pando-authority", "status"], env=src_live_env).stdout.decode())
        src_auth_id = status_1["authority"]["authority_id"]
        assert status_1["authority"]["authority_epoch"] == 1
        assert status_1["authority"]["remote_delete_fenced"] is False
        assert status_1["external_bucket"]["current_epoch_proof_present"] is True
        assert status_1["external_bucket"]["successor_epoch_proof_present"] is False
        verify_1 = json.loads(run_cmd([binary, "pando-authority", "verify"], env=src_live_env).stdout.decode())
        assert verify_1["authority_id"] == src_auth_id

        # 3. Create repo via live HTTP API, switch repo to serving Pando, test retention roots + safe pruning.
        code, repo = src_svc.http_json("/api/repos", alice["token"], method="POST", payload={"name": "pitr-live"})
        assert code in (200, 201, 202), (code, repo)
        repo_id = repo["id"]
        owner_id = alice["user_id"]
        wait_until(
            lambda: sql_query(src_url, f"SELECT state FROM repositories WHERE id='{repo_id}'") == "ready",
            label="repository provisioning ready",
        )
        src_svc.stop()

        sql_query(
            src_url,
            f"UPDATE repositories SET storage_backend='pando', transition_state='stable' WHERE id='{repo_id}';"
            f"INSERT INTO pando_repository_states(repository_id,tenant_id,storage_generation,state,object_format,pack_ids) "
            f"VALUES('{repo_id}','{owner_id}',1,'serving','sha1','{{}}');",
        )
        m_prod_id, prod_keys = seed_synthetic_manifest(src_url, s3, repo_id, owner_id, src_auth_id, "prod")
        m_pin_id, pin_keys = seed_synthetic_manifest(src_url, s3, repo_id, owner_id, src_auth_id, "pinned")
        m_drop_id, drop_keys = seed_synthetic_manifest(src_url, s3, repo_id, owner_id, src_auth_id, "drop")
        legacy_sha = hashlib.sha256(b"legacy-v1-live-bytes").hexdigest()
        legacy_key = f"tenants/{owner_id}/pando-cipher/{legacy_sha}"
        s3.put_raw(legacy_key, b"legacy-v1-live-bytes")

        sql_query(
            src_url,
            f"UPDATE pando_repository_states SET pack_ids=ARRAY['{m_prod_id}'::uuid, '{m_pin_id}'::uuid] "
            f"WHERE repository_id='{repo_id}';",
        )
        pin_out = json.loads(
            run_cmd(
                [
                    binary,
                    "pando-authority",
                    "pin-recovery-point",
                    "--tenant",
                    owner_id,
                    "--repository",
                    repo_id,
                    "--kind",
                    "pitr_recovery_point",
                    "--note",
                    "nightly-e2e-pitr",
                    "--ttl-seconds",
                    "3600",
                ],
                env=src_live_env,
            ).stdout.decode()
        )
        assert pin_out["state"] == "active" and pin_out["external_lsn"], pin_out
        assert pin_out["manifest_count"] == 2, pin_out

        # Drop m_pin from serving pack_ids too; retention root still protects m_pin while m_drop gets deleted.
        sql_query(
            src_url,
            f"UPDATE pando_repository_states SET pack_ids=ARRAY['{m_prod_id}'::uuid] WHERE repository_id='{repo_id}';",
        )
        s3.take_deletes()
        src_maint_env = {**src_live_env, "ROOTYARD_STORAGE_MAINTENANCE": "true"}
        src_svc_maint = ServiceHandle(binary, src_maint_env, root / "src.log")
        services.append(src_svc_maint)
        src_svc_maint.start()

        wait_until(
            lambda: sql_query(
                src_url,
                f"SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='{repo_id}' "
                "AND kind='pando_tombstone_delete' AND state='succeeded' AND (result->>'deleted')::int = 4",
            ) == "1",
            timeout=30.0,
            label="source pando_tombstone_delete deleting only unpinned m_drop",
        )
        src_svc_maint.stop()

        deleted_on_src = set(s3.take_deletes())
        assert deleted_on_src == set(drop_keys), f"unexpected deletes: {deleted_on_src}"
        for preserved in [*prod_keys, *pin_keys, legacy_key]:
            assert s3.contains(preserved), f"expected {preserved} preserved"
        run_cmd([binary, "pando-authority", "release-recovery-point", "--root", pin_out["id"]], env=src_live_env)
        status_post_release = json.loads(run_cmd([binary, "pando-authority", "status"], env=src_live_env).stdout.decode())
        assert status_post_release["active_retention_roots"] == []
        results["source_retention_and_pruning"] = True

        # 4. Real pg_dump + pg_restore clone sharing the SAME bucket MUST fail closed.
        dump_file = root / "src-metadata.dump"
        run_cmd(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", str(dump_file), src_url])
        run_cmd(
            ["pg_restore", "--dbname", clone_url, "--no-owner", "--no-privileges", "--exit-on-error", str(dump_file)]
        )

        # Force due retired artifacts + queued delete job on clone_db pointing at m_prod live objects.
        sql_query(
            clone_url,
            f"UPDATE pando_remote_artifacts SET state='retired', delete_after=clock_timestamp()-interval '60 seconds' "
            f"WHERE remote_path = '{prod_keys[0]}';"
            f"UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id='{repo_id}';"
            f"INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation) "
            f"VALUES(gen_random_uuid(),'{repo_id}','{owner_id}','pando_tombstone_delete',1) ON CONFLICT DO NOTHING;",
        )

        clone_env = {
            **base_env,
            "DATABASE_URL": clone_url,
            "ROOTYARD_DATA_DIR": str(clone_data),
            "ROOTYARD_PANDO_REMOTE_DELETE": "true",
            "ROOTYARD_STORAGE_MAINTENANCE": "true",
        }
        s3.take_deletes()
        clone_svc = ServiceHandle(binary, clone_env, root / "clone.log")
        services.append(clone_svc)
        clone_svc.start()

        wait_until(
            lambda: sql_query(clone_url, "SELECT remote_delete_fenced::text FROM pando_storage_authorities WHERE singleton")
            == "t",
            timeout=20.0,
            label="clone remote_delete_fenced=true",
        )
        wait_until(
            lambda: sql_query(
                clone_url,
                f"SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='{repo_id}' "
                "AND kind='pando_tombstone_delete' AND state='failed'",
            )
            == "1",
            timeout=20.0,
            label="clone pando_tombstone_delete fail closed",
        )
        assert s3.take_deletes() == [], "metadata clone issued DELETE against shared bucket"
        assert s3.contains(prod_keys[0]), "metadata clone deleted live production object"
        verify_clone = run_cmd([binary, "pando-authority", "verify"], env=clone_env, check=False)
        assert verify_clone.returncode != 0
        clone_svc.stop()
        results["clone_fail_closed_zero_deletes"] = True

        # 5. Operator isolate --confirm-shared-bucket rotates clone authority cleanly without touching old S3 keys.
        isolated = json.loads(
            run_cmd([binary, "pando-authority", "isolate", "--confirm-shared-bucket"], env=clone_env).stdout.decode()
        )
        assert isolated["authority_id"] != src_auth_id
        assert isolated["restore_generation"] == status_post_release["authority"]["restore_generation"] + 1
        assert isolated["authority_epoch"] == 1
        assert isolated["remote_delete_fenced"] is False
        run_cmd([binary, "pando-authority", "verify"], env=clone_env)
        assert s3.contains(prod_keys[0])
        results["operator_isolate_recovered"] = True

        # 6. Simulated PITR epoch rollback on source DB fails closed and latches fence.
        sql_query(src_url, "UPDATE pando_storage_authorities SET authority_epoch = authority_epoch - 1 WHERE singleton;")
        verify_rollback = run_cmd([binary, "pando-authority", "verify"], env=src_live_env, check=False)
        assert verify_rollback.returncode != 0
        assert (
            sql_query(src_url, "SELECT remote_delete_fenced::text FROM pando_storage_authorities WHERE singleton") == "t"
        )
        results["pitr_epoch_rollback_fenced"] = True
        results["passed"] = True
        return results
    finally:
        for svc in services:
            try:
                svc.stop()
            except Exception:
                pass
        s3.close()
        for db_name in (clone_db_name, src_db_name):
            try:
                sql_query(admin_url, f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE);')
            except Exception:
                pass
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=os.environ.get("ROOTYARD_BIN") or "target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    for tool in ("psql", "pg_dump", "pg_restore"):
        if not shutil.which(tool):
            parser.error(f"Required PostgreSQL CLI tool missing: {tool}")
    binary = str(Path(args.binary).resolve())
    if not Path(binary).is_file():
        parser.error(f"rootyard binary not found: {binary}")
    report = run_suite(binary)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
