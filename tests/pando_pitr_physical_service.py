#!/usr/bin/env python3
"""AC1 physical PostgreSQL + real Garage + real Vault Pando PITR service harness.

The harness runs the prebuilt Rootyard service against an owned PostgreSQL 17
physical backup/restore fixture and Root-supplied real Garage/Vault fixtures.  It
does not use loopback S3/Vault doubles, a logical pg_dump clone, synthetic Pando
manifests, or SQL-created success authority.

The public entrypoint is bound through the existing shared
``pando_pitr_service.run_acceptance`` pre/postflight reader.  All service
stdout/stderr is discarded; process output, provider URLs, DSNs, tokens, object
locators and bytes never enter the report or exception text.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import native_build_receipt as receipts  # noqa: E402
import pando_pitr_service as binding  # noqa: E402
from pando_pitr_physical_pg import PhysicalPitrFixture  # noqa: E402
from workspace_remote_delete_policy import CountingProxy, s3_get_bytes  # noqa: E402

PHYSICAL_MANDATORY_CASES = (
    "physical_restore_to_named_target",
    "source_external_authority_advanced_after_restore_point",
    "source_verify_after_clone_gc",
    "due_unpinned_candidate_observed_before_clone_gc",
    "stale_clone_fenced_before_remote_delete",
    "remote_delete_method_count_zero",
    "known_live_and_pinned_recovery_objects_head_get_digest_unchanged",
    "clone_isolate_succeeded",
    "clone_cache_wiped",
    "real_service_stock_git_clone_fetch_fsck",
    "owned_resource_cleanup_passed",
)
PHYSICAL_TOPOLOGY = {
    "rootyard": "actual prebuilt Rootyard serve/migrate and stock Git over loopback HTTP",
    "postgres": "owned PG17 physical base backup, named restore point, WAL archive and isolated promoted restore",
    "object_store": "real owned Garage fixture via supplied ROOTYARD_OBJECT_STORE_* environment",
    "vault": "real Vault Transit fixture via supplied ROOTYARD_KMS_VAULT_* environment",
    "clone_transport": "pass-through loopback proxy forwarding genuine Garage/SigV4 requests; counts methods only",
    "scope": "AC1 physical PITR/fencing/isolate slice only; not AC2 backup/restore lifecycle or a full service qualification",
}
PHYSICAL_LIMITATIONS = (
    "Requires an actual prebuilt Rootyard binary/build receipt and Root-supplied real Garage/Vault fixtures.",
    "No loopback S3/Vault test double, synthetic Pando manifest, SQL-created authority success or logical clone is accepted.",
    "The report records hashes/booleans/counts only; locator strings, credentials, SQL bodies, object bytes and raw process output are excluded.",
    "Existing signed/pass-through S3 helpers used for the known-key probe are HTTP loopback; TLS Garage transport is outside this harness.",
    "A successful run is AC1 source execution evidence only; AC2 backup/restore, permission/lease/generation matrix and full Issue #77 closure remain open.",
)
PHYSICAL_SPEC = binding.AcceptanceSpec(
    kind="rootyard/pando-pitr-physical-service-acceptance",
    mandatory_cases=PHYSICAL_MANDATORY_CASES,
    topology=PHYSICAL_TOPOLOGY,
    limitations=PHYSICAL_LIMITATIONS,
)
VAULT_IMAGE_PIN = "hashicorp/vault@sha256:44fa1e5a57d0bcf7fb163159872263b79a575e5dbfefd5b9bde1b7e4aada2f32"
REQUIRED_PROVIDER_ENV = (
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_KMS_VAULT_URL",
    "ROOTYARD_KMS_VAULT_TOKEN",
    "ROOTYARD_KMS_VAULT_KEY",
    "ROOTYARD_GARAGE_IMAGE_DIGEST",
    "ROOTYARD_VAULT_IMAGE_DIGEST",
)
MAX_SELECTED_OBJECTS = 128
MAX_SELECTED_OBJECT_BYTES = 64 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 1800.0
IMAGE_DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})$")
HARNESS_FILES = (
    ROOT / "tests/pando_pitr_physical_service.py",
    ROOT / "tests/test_pando_pitr_physical_service.py",
    ROOT / "tests/pando_pitr_service.py",
    ROOT / "tests/pando_pitr_physical_pg.py",
    ROOT / "tests/pando_maintenance_service.py",
    ROOT / "tests/e2e.py",
    ROOT / "tests/lfs.py",
    ROOT / "tests/lfs_hydration_concurrency.py",
    ROOT / "tests/lfs_remote_contract.py",
    ROOT / "tests/schema_baseline.py",
    ROOT / "tests/native_evidence.py",
    ROOT / "tests/owned_fuse_cleanup.py",
    ROOT / "tests/workspace_remote_delete_policy.py",
    ROOT / "scripts/native_build_receipt.py",
)


class PhysicalFailure(RuntimeError):
    """Fixed safe stage/code for one physical AC1 failure."""

    def __init__(self, stage: str, code: str) -> None:
        super().__init__(f"{stage}: {code}")
        self.stage = stage
        self.code = code


@dataclass(frozen=True)
class _ProviderConfig:
    endpoint: str = field(repr=False)
    bucket: str
    region: str
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    session_token: str = field(repr=False)
    vault_url: str = field(repr=False)
    vault_token: str = field(repr=False)
    vault_mount: str
    vault_key: str
    garage_image: str
    vault_image: str


def _missing_environment(environ: dict[str, str]) -> list[str]:
    return [name for name in REQUIRED_PROVIDER_ENV if not environ.get(name)]


def _image_digest(value: str, stage: str) -> str:
    match = IMAGE_DIGEST_RE.search(value.strip())
    if match is None:
        raise PhysicalFailure(stage, "image_digest_invalid")
    return "sha256:" + match.group(1)


def preflight_providers(environ: dict[str, str] | None = None) -> tuple[_ProviderConfig, dict]:
    """Validate Root-supplied real provider names/pins without printing values."""
    environ = os.environ if environ is None else environ
    if _missing_environment(environ):
        raise PhysicalFailure("providers", "missing_environment")
    parsed = urllib.parse.urlsplit(environ["ROOTYARD_OBJECT_STORE_ENDPOINT"])
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise PhysicalFailure("providers", "garage_endpoint_invalid")
    vault_url = urllib.parse.urlsplit(environ["ROOTYARD_KMS_VAULT_URL"])
    if (
        vault_url.scheme not in ("http", "https")
        or not vault_url.hostname
        or vault_url.username
        or vault_url.password
        or vault_url.query
        or vault_url.fragment
    ):
        raise PhysicalFailure("providers", "vault_endpoint_invalid")
    vault_image = environ["ROOTYARD_VAULT_IMAGE_DIGEST"].strip()
    known_vault_digest = VAULT_IMAGE_PIN.rsplit("sha256:", 1)[1]
    if vault_image not in (VAULT_IMAGE_PIN, "sha256:" + known_vault_digest):
        raise PhysicalFailure("providers", "vault_image_pin_mismatch")
    vault_image = VAULT_IMAGE_PIN
    garage_image = environ["ROOTYARD_GARAGE_IMAGE_DIGEST"].strip()
    garage_image = _image_digest(garage_image, "providers")
    config = _ProviderConfig(
        endpoint=environ["ROOTYARD_OBJECT_STORE_ENDPOINT"],
        bucket=environ["ROOTYARD_OBJECT_STORE_BUCKET"],
        region=environ["ROOTYARD_OBJECT_STORE_REGION"],
        access_key=environ["ROOTYARD_OBJECT_STORE_ACCESS_KEY"],
        secret_key=environ["ROOTYARD_OBJECT_STORE_SECRET_KEY"],
        session_token=environ.get("ROOTYARD_OBJECT_STORE_SESSION_TOKEN", ""),
        vault_url=environ["ROOTYARD_KMS_VAULT_URL"],
        vault_token=environ["ROOTYARD_KMS_VAULT_TOKEN"],
        vault_mount=environ.get("ROOTYARD_KMS_VAULT_MOUNT", "transit"),
        vault_key=environ["ROOTYARD_KMS_VAULT_KEY"],
        garage_image=garage_image,
        vault_image=vault_image,
    )
    metadata = {
        "garage_image_digest": garage_image,
        "vault_image_digest": vault_image,
        "garage_environment_present": True,
        "vault_environment_present": True,
        "loopback_provider_double_used": False,
    }
    return config, metadata


def _s3_endpoint(endpoint: str) -> tuple[str, int, bool]:
    parsed = urllib.parse.urlsplit(endpoint)
    return parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80), parsed.scheme == "https"


def _s3_path(bucket: str, key: str) -> str:
    return "/" + bucket + "/" + urllib.parse.quote(key, safe="/~")


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _s3_head(host: str, port: int, tls: bool, bucket: str, key: str, region: str,
             access_key: str, secret_key: str, session_token: str = "", timeout: float = 30.0) -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    date, timestamp = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
    host_header = host if ":" not in host else "[" + host + "]"
    if port:
        host_header += ":" + str(port)
    path = _s3_path(bucket, key)
    headers = [("host", host_header), ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
               ("x-amz-date", timestamp)]
    if session_token:
        headers.append(("x-amz-security-token", session_token))
    headers.sort(key=lambda item: item[0])
    canonical_headers = "".join(f"{name}:{value.strip()}\n" for name, value in headers)
    signed_headers = ";".join(name for name, _ in headers)
    canonical = "\n".join(["HEAD", path, "", canonical_headers, signed_headers, "UNSIGNED-PAYLOAD"])
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = "AWS4-HMAC-SHA256\n{}\n{}\n{}".format(
        timestamp, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest())
    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, "s3")
    signing = _hmac(k_service, "aws4_request")
    signature = hmac.new(signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}".format(
            access_key, scope, signed_headers, signature)
    )
    request_headers = {"Authorization": authorization}
    for name, value in headers:
        request_headers[name] = value
    connection = (http.client.HTTPSConnection if tls else http.client.HTTPConnection)(
        host, port, timeout=timeout)
    try:
        connection.request("HEAD", path, headers=request_headers)
        response = connection.getresponse()
        length = int(response.getheader("Content-Length") or 0)
        response.read()
        return response.status, length
    finally:
        connection.close()


class _ArtifactProbe:
    def __init__(self, config: _ProviderConfig) -> None:
        self.config = config
        self.host, self.port, self.tls = _s3_endpoint(config.endpoint)

    def head(self, locator: str) -> tuple[int, int]:
        try:
            return _s3_head(self.host, self.port, self.tls, self.config.bucket, locator,
                            self.config.region, self.config.access_key, self.config.secret_key,
                            self.config.session_token)
        except (OSError, http.client.HTTPException, ValueError):
            raise PhysicalFailure("garage", "head_failed") from None

    def get_digest(self, locator: str) -> tuple[int, str]:
        try:
            payload = s3_get_bytes(
                self.host, self.port, self.config.bucket, locator, self.config.region,
                self.config.access_key, self.config.secret_key,
                self.config.session_token or None, timeout=30)
        except (OSError, AssertionError, http.client.HTTPException):
            raise PhysicalFailure("garage", "get_failed") from None
        return len(payload), hashlib.sha256(payload).hexdigest()


def _psql_env(db_url: str) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(db_url)
    env = dict(os.environ)
    env.update({
        "PGHOST": parsed.hostname or "127.0.0.1",
        "PGPORT": str(parsed.port or 5432),
        "PGUSER": urllib.parse.unquote(parsed.username or ""),
        "PGDATABASE": (parsed.path or "/postgres").lstrip("/") or "postgres",
        "PGSSLMODE": "disable",
        "LC_ALL": "C",
    })
    for name in ("PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGPASSFILE", "PGSYSCONFDIR"):
        env.pop(name, None)
    if parsed.password:
        env["PGPASSWORD"] = urllib.parse.unquote(parsed.password)
    else:
        env.pop("PGPASSWORD", None)
    return env


def _psql(db_url: str, query: str, timeout: float = 60.0) -> str:
    try:
        result = subprocess.run(
            ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", query],
            env=_psql_env(db_url), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PhysicalFailure("sql", "query_failed") from None
    if result.returncode != 0:
        raise PhysicalFailure("sql", "query_failed")
    return result.stdout.decode("utf-8", "replace").strip()


def _sql_json(db_url: str, query: str, timeout: float = 60.0) -> object:
    try:
        return json.loads(_psql(db_url, query, timeout))
    except (TypeError, ValueError):
        raise PhysicalFailure("sql", "json_invalid") from None


def _sql_scalar(db_url: str, query: str, timeout: float = 60.0) -> str:
    return _psql(db_url, query, timeout)


def _sql_int(db_url: str, query: str, timeout: float = 60.0) -> int:
    try:
        return int(_sql_scalar(db_url, query, timeout))
    except ValueError:
        raise PhysicalFailure("sql", "integer_invalid") from None


def _cli(binary: str, args: list[str], env: dict[str, str], timeout: float = 120.0,
         json_output: bool = True) -> dict:
    try:
        result = subprocess.run(
            [binary, *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PhysicalFailure("cli", "command_failed") from None
    if result.returncode != 0:
        raise PhysicalFailure("cli", "command_failed")
    if not json_output:
        return {}
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PhysicalFailure("cli", "json_invalid") from None
    if not isinstance(value, dict):
        raise PhysicalFailure("cli", "json_invalid")
    return value


def _git_clean_env(base: dict[str, str]) -> dict[str, str]:
    env = dict(base)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_SYSTEM",
                 "GIT_CONFIG_COUNT"):
        env.pop(name, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    return env


def _git_env(base: dict[str, str], remote: str, token: str | None = None) -> dict[str, str]:
    env = _git_clean_env(base)
    values = [
        ("remote.origin.url", remote),
        ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
    ]
    if token:
        auth = base64.b64encode(f"alice:{token}".encode()).decode()
        values.append(("http.extraHeader", f"Authorization: Basic {auth}"))
    env["GIT_CONFIG_COUNT"] = str(len(values))
    for index, (name, value) in enumerate(values):
        env[f"GIT_CONFIG_KEY_{index}"] = name
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _git(args: list[str], *, env: dict[str, str], cwd: Path | None = None, timeout: float = 120.0) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            ["git", *args], env=env, cwd=cwd, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PhysicalFailure("git", "command_failed") from None
    if result.returncode != 0:
        raise PhysicalFailure("git", "command_failed")
    return result


def _git_clone(remote: str, token: str, base_env: dict[str, str], destination: Path) -> None:
    base_env = _git_clean_env(base_env)
    env = _git_env(base_env, remote, token)
    _git(["init", str(destination)], env=base_env)
    _git(["fetch", "origin"], env=env, cwd=destination)
    _git(["checkout", "-B", "main", "FETCH_HEAD"], env=base_env, cwd=destination)
    _git(["config", "user.name", "AC1 Physical"], env=base_env, cwd=destination)
    _git(["config", "user.email", "ac1-physical@example.invalid"], env=base_env, cwd=destination)


class _Service:
    """Bounded serve wrapper; stdout/stderr are discarded, never logged."""

    def __init__(self, binary: str, env: dict[str, str]) -> None:
        self.binary = binary
        self.env = dict(env)
        self.port = self._free_port()
        self.env["ROOTYARD_BIND"] = "127.0.0.1:" + str(self.port)
        self.base_url = "http://127.0.0.1:" + str(self.port)
        self.proc: subprocess.Popen[bytes] | None = None

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def start(self) -> None:
        try:
            self.proc = subprocess.Popen(
                [self.binary, "serve"], env=self.env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            raise PhysicalFailure("service", "start_failed") from None
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise PhysicalFailure("service", "start_failed")
            try:
                with urllib.request.urlopen(self.base_url + "/health/ready", timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise PhysicalFailure("service", "start_timeout")

    def http_json(self, path: str, token: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Authorization": "Bearer " + token}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                value = json.loads(response.read().decode("utf-8"))
                return response.status, value if isinstance(value, dict) else {}
        except urllib.error.HTTPError as error:
            try:
                value = json.loads(error.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                value = {}
            return error.code, value if isinstance(value, dict) else {}
        except (OSError, urllib.error.URLError, UnicodeDecodeError, json.JSONDecodeError):
            raise PhysicalFailure("http", "request_failed") from None

    def health(self) -> bool:
        try:
            with urllib.request.urlopen(self.base_url + "/health/ready", timeout=5) as response:
                return response.status == 200
        except (OSError, urllib.error.URLError):
            return False

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=10)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise PhysicalFailure("cleanup", "service_stop_failed") from None
            except OSError:
                raise PhysicalFailure("cleanup", "service_stop_failed") from None
        self.proc = None


def _wait_until(predicate, timeout: float, stage: str, code: str):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    raise PhysicalFailure(stage, code)


def _marker_copy(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for name in (".volume-id", ".pando-deployment-id"):
        path = source / name
        if not path.is_file():
            raise PhysicalFailure("clone", "identity_marker_missing")
        shutil.copy2(path, destination / name)


def _artifact_rows(db_url: str, authority: str, tenant: str, repository: str) -> dict[str, list[dict]]:
    serving = (
        "EXISTS (SELECT 1 FROM pando_manifest_artifacts ma "
        "JOIN pando_repository_states s ON s.repository_id = ma.repository_id "
        "WHERE ma.authority_id = a.authority_id AND ma.tenant_id = a.tenant_id "
        "AND ma.namespace = a.namespace AND ma.sha256 = a.sha256 "
        f"AND ma.repository_id = '{repository}' AND ma.manifest_id = ANY(s.pack_ids))"
    )
    pinned = (
        "EXISTS (SELECT 1 FROM pando_retention_root_manifests rm "
        "JOIN pando_retention_roots r ON r.id = rm.root_id AND r.authority_id = rm.authority_id "
        "JOIN pando_manifest_artifacts ma ON ma.manifest_id = rm.manifest_id "
        "AND ma.repository_id = rm.repository_id AND ma.tenant_id = rm.tenant_id "
        "WHERE ma.authority_id = a.authority_id AND ma.tenant_id = a.tenant_id "
        "AND ma.namespace = a.namespace AND ma.sha256 = a.sha256 "
        "AND r.state = 'active' AND (r.retain_until IS NULL OR r.retain_until > clock_timestamp()))"
    )
    fence = (
        "NOT EXISTS (SELECT 1 FROM pando_publication_fences f "
        "WHERE f.authority_id = a.authority_id AND f.tenant_id = a.tenant_id "
        "AND f.namespace = a.namespace AND f.sha256 = a.sha256 "
        "AND f.lease_until > clock_timestamp())"
    )
    base = (
        f"FROM pando_remote_artifacts a WHERE a.authority_id = '{authority}' "
        f"AND a.tenant_id = '{tenant}' AND a.state = 'active'"
    )
    query = (
        "SELECT coalesce(json_agg(row_to_json(t)), '[]'::json) FROM ("
        f"SELECT 'live' AS category, a.namespace, a.sha256, a.remote_path, a.size {base} AND {serving} "
        "UNION ALL "
        f"SELECT 'pinned' AS category, a.namespace, a.sha256, a.remote_path, a.size {base} AND {pinned} "
        "UNION ALL "
        "SELECT 'candidate' AS category, a.namespace, a.sha256, a.remote_path, a.size "
        f"FROM pando_remote_artifacts a WHERE a.authority_id = '{authority}' "
        f"AND a.tenant_id = '{tenant}' AND a.state IN ('retired','deleting') "
        "AND a.delete_after IS NOT NULL AND a.delete_after <= clock_timestamp() "
        f"AND NOT {serving} AND NOT {pinned} AND {fence}"
        ") t"
    )
    rows = _sql_json(db_url, query)
    result = {"live": [], "pinned": [], "candidate": []}
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and row.get("category") in result:
                result[row["category"]].append(row)
    return result


def _probe_artifacts(probe: _ArtifactProbe, rows: list[dict], category: str) -> list[dict]:
    captured = []
    for row in rows[:MAX_SELECTED_OBJECTS]:
        locator = row.get("remote_path")
        if not isinstance(locator, str) or not locator:
            raise PhysicalFailure("garage", "locator_missing")
        status, length = probe.head(locator)
        if status != 200:
            raise PhysicalFailure("garage", "head_status_mismatch")
        if length > MAX_SELECTED_OBJECT_BYTES:
            raise PhysicalFailure("garage", "object_too_large")
        body_length, digest = probe.get_digest(locator)
        if body_length != length or body_length != int(row.get("size", body_length)):
            raise PhysicalFailure("garage", "object_identity_mismatch")
        captured.append({
            "category": category,
            "namespace": row.get("namespace"),
            "content_sha256": row.get("sha256"),
            "locator_sha256": hashlib.sha256(locator.encode()).hexdigest(),
            "size": body_length,
            "head_length": length,
            "byte_sha256": digest,
        })
    if len(rows) > MAX_SELECTED_OBJECTS:
        raise PhysicalFailure("garage", "object_selection_too_large")
    return captured


def _map_fence_reason(reason: str | None) -> str:
    text = (reason or "").lower()
    if "successor" in text or "epoch" in text:
        return "epoch_or_successor_proof"
    if "timeline" in text or "system_identifier" in text or "database" in text or "schema" in text:
        return "database_or_timeline_identity"
    if "volume" in text or "deployment" in text or "backend" in text:
        return "local_or_backend_identity"
    return "unknown"


def _physical_metadata(fixture: PhysicalPitrFixture) -> dict:
    primary = fixture.primary_url
    restored = fixture.restored_url
    return {
        "postgres_version": _sql_scalar(primary, "SHOW server_version", 30),
        "primary_timeline": _sql_int(primary, "SELECT timeline_id FROM pg_control_checkpoint()", 30),
        "restored_timeline": _sql_int(restored, "SELECT timeline_id FROM pg_control_checkpoint()", 30),
        "primary_system_identifier": _sql_scalar(primary, "SELECT system_identifier FROM pg_control_system()", 30),
        "restored_system_identifier": _sql_scalar(restored, "SELECT system_identifier FROM pg_control_system()", 30),
        "restore_point_lsn": fixture.restore_point_lsn,
        "restored_endpoint_is_new": fixture.primary_port != fixture.restored_port,
    }


def _run_physical_scenario(binary: str, pg_bin: Path, environ: dict[str, str],
                           extra: dict) -> dict[str, bool]:
    cases = {name: False for name in PHYSICAL_MANDATORY_CASES}
    extra.update({
        "physical_cases": list(PHYSICAL_MANDATORY_CASES),
        "remaining_ac2": "authority restore_generation/rotation, old-claim revocation, backup/restore API, permission/lease/failure-cleanup matrix",
    })
    config = None
    fixture = None
    private_root = None
    proxy = None
    services: list[_Service] = []
    cleanup_ok = False
    try:
        config, provider_meta = preflight_providers(environ)
        extra["providers"] = provider_meta
        for tool in ("psql", "git"):
            if not shutil.which(tool):
                raise PhysicalFailure("precondition", "required_cli_missing")
        private_root = Path(tempfile.mkdtemp(prefix="rootyard-ac1-physical-service-"))
        private_root.chmod(0o700)
        source_data = private_root / "source-data"
        clone_data = private_root / "clone-data"
        source_data.mkdir(mode=0o700)
        fixture = PhysicalPitrFixture(pg_bin, scratch_parent=private_root / "pg")
        fixture.start_primary()
        extra["physical_pg"] = {"pg_major": 17, "primary_started": True}

        base_env = dict(environ)
        base_env.update({
            "DATABASE_URL": fixture.primary_url,
            "ROOTYARD_DATA_DIR": str(source_data),
            "ROOTYARD_PANDO_REMOTE_DELETE": "false",
            "ROOTYARD_STORAGE_MAINTENANCE": "false",
            "ROOTYARD_STORAGE_REPACK_PACKS": "2",
            "ROOTYARD_STORAGE_REPACK_LOOSE_OBJECTS": "1000000",
            "ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS": "1",
            "ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS": "1",
            "ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS": "5",
            "ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS": "1",
            "ROOTYARD_STORAGE_MAINTENANCE_QUIESCENCE_SECONDS": "1",
            "ROOTYARD_STORAGE_MAINTENANCE_MAX_ATTEMPTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C",
        })
        git_base = _git_clean_env(base_env)
        _cli(binary, ["migrate"], base_env, json_output=False)
        alice = _cli(binary, ["create-user", "alice"], base_env)
        token = alice.get("token")
        if not isinstance(token, str) or not token:
            raise PhysicalFailure("service", "user_token_missing")
        source = _Service(binary, base_env)
        services.append(source)
        source.start()
        status_before = _cli(binary, ["pando-authority", "status"], base_env)
        epoch_before = int(status_before["authority"]["authority_epoch"])
        extra["source_remote_delete_env_enabled"] = status_before.get("remote_delete_env_enabled")

        code, repo = source.http_json("/api/repos", token, method="POST", payload={"name": "ac1-physical"})
        if code not in (200, 201, 202) or not isinstance(repo.get("id"), str):
            raise PhysicalFailure("provision", "repository_create_failed")
        repo_id = repo["id"]
        _wait_until(
            lambda: _sql_scalar(
                fixture.primary_url,
                f"SELECT state FROM repositories WHERE id='{repo_id}'", 30,
            ) == "ready",
            60.0, "provision", "repository_not_ready")
        work = private_root / "work"
        _git(["init", "--initial-branch=main", str(work)], env=git_base)
        _git(["config", "user.name", "AC1 Physical"], env=git_base, cwd=work)
        _git(["config", "user.email", "ac1@example.invalid"], env=git_base, cwd=work)
        remote = source.base_url + repo["clone_path"]
        (work / "base.txt").write_text("ac1 physical base\n")
        _git(["add", "base.txt"], env=git_base, cwd=work)
        _git(["commit", "-m", "base"], env=git_base, cwd=work)
        _git(["push", "origin", "HEAD:refs/heads/main"], env=_git_env(base_env, remote, token), cwd=work)
        source.stop()
        cutover = _cli(binary, ["pando-transition", "cutover", "--repository", repo_id], base_env)
        if cutover.get("direction") != "gitfs_to_pando":
            raise PhysicalFailure("cutover", "direction_mismatch")
        _wait_until(
            lambda: _sql_scalar(
                fixture.primary_url,
                f"SELECT storage_backend || '/' || transition_state FROM repositories WHERE id='{repo_id}'",
                30,
            ) == "pando/stable",
            60.0, "cutover", "backend_not_stable")
        source = _Service(binary, {**base_env, "ROOTYARD_STORAGE_MAINTENANCE": "true"})
        services.append(source)
        source.start()
        remote = source.base_url + repo["clone_path"]
        latest = None
        for index in (1, 2, 3):
            (work / f"pando-{index}.txt").write_text(f"pando physical {index}\n")
            _git(["add", f"pando-{index}.txt"], env=git_base, cwd=work)
            _git(["commit", "-m", f"pando {index}"], env=git_base, cwd=work)
            latest = _git(["rev-parse", "HEAD"], env=git_base, cwd=work).stdout.decode().strip()
            _git(["push", "origin", "HEAD:refs/heads/main"], env=_git_env(base_env, remote, token), cwd=work)
        def repack_converged() -> bool:
            value = _sql_scalar(
                fixture.primary_url,
                "SELECT cardinality(pack_ids)::text || '/' || "
                "(SELECT count(*) FROM storage_maintenance_jobs "
                f"WHERE repository_id='{repo_id}' AND kind='pando_repack' "
                "AND state IN ('queued','running')) "
                f"FROM pando_repository_states WHERE repository_id='{repo_id}'",
                30,
            )
            return value == "1/0"

        _wait_until(repack_converged, 180.0, "precondition", "repack_not_converged")
        if _sql_int(
            fixture.primary_url,
            "SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id="
            f"'{repo_id}' AND kind='pando_repack' AND state='succeeded'", 30,
        ) < 1:
            raise PhysicalFailure("precondition", "repack_not_converged")
        owner_id = _sql_scalar(fixture.primary_url,
                               f"SELECT owner_id::text FROM repositories WHERE id='{repo_id}'", 30)
        authority = _sql_scalar(fixture.primary_url,
                                "SELECT authority_id::text FROM pando_storage_authorities WHERE singleton", 30)
        _wait_until(
            lambda: _sql_int(fixture.primary_url,
                             "SELECT count(*) FROM pando_remote_artifacts a WHERE a.authority_id='"
                             f"{authority}' AND a.tenant_id='{owner_id}' AND a.state IN ('retired','deleting') "
                             "AND a.delete_after IS NOT NULL AND a.delete_after <= clock_timestamp()",
                             30) >= 1,
            240.0, "precondition", "stale_candidate_missing")
        rows_before = _artifact_rows(fixture.primary_url, authority, owner_id, repo_id)
        if not rows_before["candidate"]:
            raise PhysicalFailure("precondition", "stale_candidate_missing")
        protected = {row["sha256"] for row in rows_before["live"] + rows_before["pinned"]}
        if any(row["sha256"] in protected for row in rows_before["candidate"]):
            raise PhysicalFailure("precondition", "candidate_not_disjoint")
        pin_one = _cli(
            binary,
            ["pando-authority", "pin-recovery-point", "--tenant", owner_id,
             "--repository", repo_id, "--kind", "pitr_recovery_point",
             "--note", "ac1-physical-live", "--ttl-seconds", "3600"],
            base_env,
        )
        if not pin_one.get("external_lsn") or int(pin_one.get("manifest_count", 0)) < 1:
            raise PhysicalFailure("pin", "summary_missing")
        status_before_point = _cli(binary, ["pando-authority", "status"], base_env)
        epoch_before_point = int(status_before_point["authority"]["authority_epoch"])
        rows_after_pin = _artifact_rows(fixture.primary_url, authority, owner_id, repo_id)
        probe = _ArtifactProbe(config)
        before_probe = (
            _probe_artifacts(probe, rows_after_pin["live"], "live")
            + _probe_artifacts(probe, rows_after_pin["pinned"], "pinned")
        )
        if not before_probe:
            raise PhysicalFailure("garage", "protected_objects_missing")
        extra["artifact_baseline"] = before_probe
        restore_lsn = fixture.capture_base_backup_and_restore_point("rootyard_ac1_physical")
        pin_two = _cli(
            binary,
            ["pando-authority", "pin-recovery-point", "--tenant", owner_id,
             "--repository", repo_id, "--kind", "pitr_recovery_point",
             "--note", "ac1-physical-after-point", "--ttl-seconds", "3600"],
            base_env,
        )
        if not pin_two.get("external_lsn") or int(pin_two.get("manifest_count", 0)) < 1:
            raise PhysicalFailure("pin", "summary_missing")
        archive = fixture.force_wal_archive()
        status_after = _cli(binary, ["pando-authority", "status"], base_env)
        epoch_after = int(status_after["authority"]["authority_epoch"])
        _cli(binary, ["pando-authority", "verify"], base_env)
        source_probe = source.health()
        extra["physical_pg"].update({
            "captured_restore_point_lsn": restore_lsn,
            "archive_count_after_advance": archive["archive_count"],
            "source_authority_epoch_before": epoch_before,
            "source_authority_epoch_before_restore_point": epoch_before_point,
            "source_authority_epoch_after": epoch_after,
            "source_epoch_advanced": epoch_after > epoch_before_point,
            "source_healthy_after_advance": source_probe,
        })
        cases["source_external_authority_advanced_after_restore_point"] = epoch_after > epoch_before_point
        if not cases["source_external_authority_advanced_after_restore_point"]:
            raise PhysicalFailure("authority", "epoch_not_advanced")
        if not source_probe:
            cases["source_external_authority_advanced_after_restore_point"] = False
            raise PhysicalFailure("source", "health_after_advance_failed")

        fixture.restore_to_point()
        physical_pg = _physical_metadata(fixture)
        restored_recovery = _sql_scalar(fixture.restored_url, "SELECT pg_is_in_recovery()", 30)
        physical_pg["restored_promoted"] = restored_recovery == "f"
        physical_pg["restored_timeline_differs"] = (
            physical_pg["restored_timeline"] != physical_pg["primary_timeline"]
        )
        extra["physical_pg"].update(physical_pg)
        cases["physical_restore_to_named_target"] = bool(
            restore_lsn and restored_recovery == "f"
            and physical_pg["restored_endpoint_is_new"]
            and physical_pg["restored_timeline_differs"]
        )
        if not cases["physical_restore_to_named_target"]:
            raise PhysicalFailure("restore", "named_target_not_verified")
        _marker_copy(source_data, clone_data)
        clone = _Service(binary, {
            **base_env,
            "DATABASE_URL": fixture.restored_url,
            "ROOTYARD_DATA_DIR": str(clone_data),
            "ROOTYARD_PANDO_REMOTE_DELETE": "true",
            "ROOTYARD_STORAGE_MAINTENANCE": "true",
        })
        services.append(clone)
        proxy = CountingProxy(*_s3_endpoint(config.endpoint)[:2])
        proxy.start()
        clone.env["ROOTYARD_OBJECT_STORE_ENDPOINT"] = f"http://127.0.0.1:{proxy.port}"
        clone.start()
        fence_row = _wait_until(
            lambda: _sql_json(
                fixture.restored_url,
                "SELECT row_to_json(t) FROM (SELECT remote_delete_fenced, "
                "remote_delete_fence_reason FROM pando_storage_authorities WHERE singleton) t",
                30,
            ),
            120.0, "clone", "fence_timeout")
        if not isinstance(fence_row, dict) or fence_row.get("remote_delete_fenced") is not True:
            raise PhysicalFailure("clone", "fence_missing")
        clone_candidates = _artifact_rows(fixture.restored_url, authority, owner_id, repo_id)["candidate"]
        if not clone_candidates:
            raise PhysicalFailure("clone", "due_candidate_missing")
        if proxy.method_counts.get("DELETE", 0) != 0:
            raise PhysicalFailure("clone", "delete_attempted")
        cases["due_unpinned_candidate_observed_before_clone_gc"] = True
        cases["stale_clone_fenced_before_remote_delete"] = True
        cases["remote_delete_method_count_zero"] = True
        extra["clone_fence"] = {
            "fence_reason_category": _map_fence_reason(fence_row.get("remote_delete_fence_reason")),
            "due_candidate_count": len(clone_candidates),
            "delete_method_count": proxy.method_counts.get("DELETE", 0),
        }
        _cli(binary, ["pando-authority", "verify"], base_env)
        if not source.health():
            raise PhysicalFailure("source", "health_after_clone_failed")
        after_clone_probe = (
            _probe_artifacts(probe, rows_after_pin["live"], "live")
            + _probe_artifacts(probe, rows_after_pin["pinned"], "pinned")
        )
        if after_clone_probe != before_probe:
            cases["known_live_and_pinned_recovery_objects_head_get_digest_unchanged"] = False
            raise PhysicalFailure("garage", "protected_object_changed")
        cases["known_live_and_pinned_recovery_objects_head_get_digest_unchanged"] = True
        source_remote = source.base_url + repo["clone_path"]
        _git(["fetch", "origin"], env=_git_env(base_env, source_remote, token), cwd=work)
        (work / "after-clone.txt").write_text("source still writable after clone fence\n")
        _git(["add", "after-clone.txt"], env=git_base, cwd=work)
        _git(["commit", "-m", "after clone fence"], env=git_base, cwd=work)
        _git(["push", "origin", "HEAD:refs/heads/main"], env=_git_env(base_env, source_remote, token), cwd=work)
        _cli(binary, ["pando-authority", "verify"], base_env)
        if not source.health():
            raise PhysicalFailure("source", "health_after_source_push_failed")
        cases["source_verify_after_clone_gc"] = True

        clone.stop()
        isolated = _cli(binary, ["pando-authority", "isolate", "--confirm-shared-bucket"], {
            **base_env,
            "DATABASE_URL": fixture.restored_url,
            "ROOTYARD_DATA_DIR": str(clone_data),
            "ROOTYARD_PANDO_REMOTE_DELETE": "true",
            "ROOTYARD_STORAGE_MAINTENANCE": "false",
        })
        if not isolated.get("authority_id"):
            raise PhysicalFailure("isolate", "summary_missing")
        cases["clone_isolate_succeeded"] = True
        shutil.rmtree(clone_data / "pando-cache", ignore_errors=True)
        if (clone_data / "pando-cache").exists():
            raise PhysicalFailure("isolate", "cache_remove_failed")
        cases["clone_cache_wiped"] = True
        clone = _Service(binary, {
            **base_env,
            "DATABASE_URL": fixture.restored_url,
            "ROOTYARD_DATA_DIR": str(clone_data),
            "ROOTYARD_PANDO_REMOTE_DELETE": "true",
            "ROOTYARD_STORAGE_MAINTENANCE": "false",
        })
        services.append(clone)
        clone.start()
        clone_remote = clone.base_url + repo["clone_path"]
        checkout = private_root / "clone-read"
        _git_clone(clone_remote, token, base_env, checkout)
        _git(["fsck", "--full", "--strict"], env=git_base, cwd=checkout)
        cases["real_service_stock_git_clone_fetch_fsck"] = True
        final_probe = (
            _probe_artifacts(probe, rows_after_pin["live"], "live")
            + _probe_artifacts(probe, rows_after_pin["pinned"], "pinned")
        )
        if final_probe != before_probe:
            cases["known_live_and_pinned_recovery_objects_head_get_digest_unchanged"] = False
            raise PhysicalFailure("garage", "protected_object_changed_after_isolate")
        _cli(binary, ["pando-authority", "verify"], base_env)
        if not source.health():
            cases["source_verify_after_clone_gc"] = False
            raise PhysicalFailure("source", "health_after_isolate_failed")
        final_delete_count = proxy.method_counts.get("DELETE", 0)
        extra["remote_delete_method_count_final"] = final_delete_count
        if final_delete_count != 0:
            cases["remote_delete_method_count_zero"] = False
            raise PhysicalFailure("clone", "remote_delete_observed")
        cases["source_verify_after_clone_gc"] = True
    except PhysicalFailure as error:
        extra["physical_failure"] = {"stage": error.stage, "code": error.code}
    except Exception as error:  # fixed class only; never native output or paths
        extra["physical_failure"] = {
            "stage": "internal", "code": "unexpected", "exception_class": type(error).__name__}
    finally:
        services_stopped = True
        for service in reversed(services):
            try:
                service.stop()
            except Exception:
                services_stopped = False
        proxy_stopped = True
        if proxy is not None:
            try:
                proxy.stop()
            except Exception:
                proxy_stopped = False
        pg_cleanup = None
        if fixture is not None:
            try:
                pg_cleanup = fixture.cleanup()
            except Exception:
                pg_cleanup = {"passed": False}
        fixture_ok = isinstance(pg_cleanup, dict) and pg_cleanup.get("passed") is True
        if services_stopped and proxy_stopped and fixture_ok and private_root is not None:
            try:
                shutil.rmtree(private_root)
                private_root = None
            except OSError:
                pass
        cleanup_ok = bool(
            services_stopped and proxy_stopped and fixture_ok
            and private_root is None
        )
        cases["owned_resource_cleanup_passed"] = cleanup_ok
        extra["cleanup"] = {
            "all_service_children_stopped": services_stopped,
            "proxy_stopped": proxy_stopped,
            "physical_fixture": pg_cleanup,
            "private_scratch_removed": private_root is None,
        }
        if not cleanup_ok and "physical_failure" not in extra:
            extra["physical_failure"] = {"stage": "cleanup", "code": "owned_resource_cleanup_failed"}
        cases["passed"] = (
            "physical_failure" not in extra
            and all(cases[name] for name in PHYSICAL_MANDATORY_CASES)
        )
    return cases


def run_physical_suite(binary: str, pg_bin: Path, environ: dict[str, str] | None = None) -> tuple[dict[str, bool], dict]:
    extra: dict = {}
    cases = _run_physical_scenario(binary, pg_bin, os.environ if environ is None else environ, extra)
    return cases, extra


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="explicit prebuilt rootyard binary")
    parser.add_argument("--build-receipt", required=True, help="build receipt for that binary")
    parser.add_argument("--expect-commit", required=True, help="compiled source commit")
    parser.add_argument("--pg-bin", required=True, type=Path, help="explicit PostgreSQL 17 bin directory")
    parser.add_argument("--report", required=True, type=Path, help="credential-free JSON report")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    extra: dict = {}
    try:
        extra["source_tree"] = receipts.git_state(ROOT).get("tree")
    except Exception:
        extra["source_tree"] = None

    def suite(binary: str) -> dict:
        return _run_physical_scenario(binary, args.pg_bin, os.environ, extra)

    try:
        report = binding.run_acceptance(
            binary=args.binary,
            build_receipt=args.build_receipt,
            expect_commit=args.expect_commit,
            report_path=args.report,
            timeout=args.timeout,
            harness_files=list(HARNESS_FILES),
            suite=suite,
            spec=PHYSICAL_SPEC,
            extra_report=extra,
        )
    except OSError:
        print("physical PITR service acceptance: report write failed", file=sys.stderr)
        return 1
    except Exception as error:
        print(
            "physical PITR service acceptance: failed "
            f"({type(error).__name__})",
            file=sys.stderr,
        )
        return 1
    print(json.dumps({
        "kind": report.get("kind"),
        "passed": report.get("passed"),
        "failure": report.get("failure"),
        "cases": report.get("cases"),
        "physical_failure": report.get("physical_failure"),
        "cleanup": report.get("cleanup"),
    }, sort_keys=True))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
