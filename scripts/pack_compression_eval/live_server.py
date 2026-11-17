"""Live rootyard serve-blob process, PG schema, and Smart HTTP helpers (Refs #178)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
from typing import Any
import urllib.parse

from .capacity import build_server_env, derive_capacity_envelope
from .cleanup_diagnostics import StopPostcondition
from .corpus import run_git, url_quote_repo
from .failure_diagnostics import LiveEvalFailure, build_failure_record
from .failure_diagnostics import LiveEvalFailure, git_failure_record
from .pack_matrix import PackConfigSpec, kill_process_group
from .telemetry import http_json_timed, verify_binary_receipt

__all__ = [
    "LiveEnvSpec",
    "ServeBlobOwner",
    "append_search_path",
    "cli_exec",
    "clone_and_fsck",
    "create_repo",
    "exercise_browse",
    "push_with_pack_config",
    "query_repo_pg_pack_bytes",
    "resolve_live_env",
    "restart_serve_blob",
    "start_serve_blob",
    "stop_serve_blob",
    "verify_binary_receipt",
]


@dataclass(frozen=True)
class LiveEnvSpec:
    """Resolved PG17 and S3 endpoint configuration for serve-blob execution."""

    pg_base: str
    s3_endpoint: str
    s3_bucket: str
    s3_region: str
    s3_access_key: str
    s3_secret_key: str
    s3_session_token: str | None
    s3_root: str
    secrets: list[str]


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def append_search_path(base_dsn: str, schema: str) -> str:
    parsed = urllib.parse.urlsplit(base_dsn)
    opt = f"-csearch_path={schema},public"
    pairs = [(k, v) for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) if k != "options"]
    pairs.append(("options", opt))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(pairs), parsed.fragment)
    )


def resolve_live_env(env: dict[str, str]) -> LiveEnvSpec:
    """Require real PostgreSQL DSN and S3 object store config; never mock or fall back."""
    pg_base = env.get("ROOTYARD_TEST_DATABASE_URL") or env.get("DATABASE_URL") or ""
    if not pg_base:
        raise RuntimeError("ROOTYARD_TEST_DATABASE_URL or DATABASE_URL is required in --mode full")
    s3_endpoint = env.get("ROOTYARD_BLOB_ENDPOINT") or env.get("ROOTYARD_OBJECT_STORE_ENDPOINT") or ""
    s3_bucket = env.get("ROOTYARD_BLOB_BUCKET") or env.get("ROOTYARD_OBJECT_STORE_BUCKET") or ""
    s3_region = env.get("ROOTYARD_BLOB_REGION") or env.get("ROOTYARD_OBJECT_STORE_REGION") or "garage"
    s3_access = env.get("ROOTYARD_BLOB_ACCESS_KEY_ID") or env.get("ROOTYARD_OBJECT_STORE_ACCESS_KEY") or ""
    s3_secret = env.get("ROOTYARD_BLOB_SECRET_ACCESS_KEY") or env.get("ROOTYARD_OBJECT_STORE_SECRET_KEY") or ""
    s3_tok = env.get("ROOTYARD_BLOB_SESSION_TOKEN") or env.get("ROOTYARD_OBJECT_STORE_SESSION_TOKEN")
    s3_root = env.get("ROOTYARD_BLOB_ROOT") or "pack-eval-default"
    missing = [
        name
        for name, val in (
            ("ROOTYARD_BLOB_ENDPOINT", s3_endpoint),
            ("ROOTYARD_BLOB_BUCKET", s3_bucket),
            ("ROOTYARD_BLOB_ACCESS_KEY_ID", s3_access),
            ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", s3_secret),
        )
        if not val
    ]
    if missing:
        raise RuntimeError(f"missing required S3 settings for --mode full: {', '.join(missing)}")
    secrets = [pg_base]
    parsed_pg = urllib.parse.urlsplit(pg_base)
    if parsed_pg.password:
        secrets.append(parsed_pg.password)
    for sec in (s3_access, s3_secret, s3_tok or ""):
        if sec:
            secrets.append(sec)
    return LiveEnvSpec(pg_base, s3_endpoint, s3_bucket, s3_region, s3_access, s3_secret, s3_tok, s3_root, secrets)


def cli_exec(binary: str, cli_env: dict[str, str], *args: str) -> str:
    proc = subprocess.run([binary, *args], env=cli_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"rootyard {' '.join(args)} failed ({proc.returncode}): {proc.stderr.decode(errors='replace')[:300]}")
    return proc.stdout.decode("utf-8").strip()


def create_repo(base_url: str, token: str, name: str, object_format: str = "sha1") -> dict[str, Any]:
    code, raw, _, _ = http_json_timed(
        base_url, "/api/repos", token=token, method="POST", body={"name": name, "object_format": object_format}
    )
    if code not in (200, 201, 202):
        raise RuntimeError(f"POST /api/repos ({name}) failed status={code}: {raw.decode(errors='replace')[:240]}")
    created = json.loads(raw)
    owner_q, name_q = url_quote_repo(created["owner"], created["name"])
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        st, body, _, _ = http_json_timed(base_url, f"/api/repos/{owner_q}/{name_q}", token=token)
        if st == 200:
            doc = json.loads(body)
            if doc.get("state") == "ready":
                return doc
        time.sleep(0.1)
    raise RuntimeError(f"repo {name} failed to reach ready state in 30s")


def query_repo_pg_pack_bytes(pg_url: str, env: dict[str, str], repo_id: str) -> dict[str, int]:
    sql = (
        "SELECT json_build_object("
        f"'pack_count', (SELECT COUNT(DISTINCT pack_id)::bigint FROM ref_store_core_pack_memberships WHERE repository_id='{repo_id}'::uuid),"
        f"'artifact_bytes', (SELECT COALESCE(SUM(content_length), 0)::bigint FROM ref_store_core_pack_artifacts WHERE repository_id='{repo_id}'::uuid),"
        f"'pack_bytes', (SELECT COALESCE(SUM(content_length), 0)::bigint FROM ref_store_core_pack_artifacts WHERE repository_id='{repo_id}'::uuid AND role='pack'),"
        f"'idx_bytes', (SELECT COALESCE(SUM(content_length), 0)::bigint FROM ref_store_core_pack_artifacts WHERE repository_id='{repo_id}'::uuid AND role='idx')"
        ")::text"
    )
    out = subprocess.check_output(
        ["psql", "--dbname", pg_url, "-X", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql],
        env=env,
        text=True,
        stderr=subprocess.PIPE,
        timeout=15,
    ).strip()
    return json.loads(out)


class ServeBlobOwner:
    """Mutable owner for the log handle and Popen acquired by start_serve_blob."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen[bytes] | None = None
        self.log_f: Any = None

    @property
    def has_owner(self) -> bool:
        return self.proc is not None or self.log_f is not None

    def register_log(self, log_f: Any) -> None:
        self.log_f = log_f

    def register_proc(self, proc: subprocess.Popen[bytes]) -> None:
        self.proc = proc

    def close_log(self) -> None:
        if self.log_f is not None:
            try:
                self.log_f.close()
            except Exception:  # noqa: BLE001 - preserve the primary startup outcome
                pass
            self.log_f = None

    def stop(self) -> StopPostcondition:
        if self.proc is None:
            self.close_log()
            return StopPostcondition("server", True, "not_started")
        outcome = stop_serve_blob(self.proc, self.log_f)
        if outcome.stopped:
            self.proc = None
            self.log_f = None
        return outcome


def restart_serve_blob(owner: ServeBlobOwner, start: Callable[[], Any]) -> Any:
    """Start a replacement only after the old owner reports a confirmed reap."""
    outcome = owner.stop()
    if not outcome.stopped:
        raise LiveEvalFailure(build_failure_record(phase="cleanup", failure_class="cleanup_failure"))
    return start()


def start_serve_blob(
    binary: str,
    git_bin: str,
    live: LiveEnvSpec,
    pg_url: str,
    s3_endpoint: str,
    scratch_dir: Path,
    log_path: Path,
    *,
    owner: ServeBlobOwner | None = None,
    capacity: dict[str, int] | None = None,
) -> tuple[subprocess.Popen[bytes], str, Any]:
    owned = owner if owner is not None else ServeBlobOwner()
    if owned.has_owner:
        raise LiveEvalFailure(build_failure_record(phase="cleanup", failure_class="cleanup_failure"))
    if scratch_dir.exists():
        shutil.rmtree(scratch_dir)
    scratch_dir.mkdir(parents=True, mode=0o700)
    os.chmod(scratch_dir, 0o700)
    port = _pick_free_port()
    bind = f"127.0.0.1:{port}"
    base_url = f"http://{bind}"
    envelope = capacity if capacity is not None else derive_capacity_envelope()
    proc_env = build_server_env(os.environ, envelope)
    proc_env.pop("ROOTYARD_DATA_DIR", None)
    proc_env.update(
        {
            "DATABASE_URL": pg_url,
            "ROOTYARD_SCHEMA_MODE": "external",
            "ROOTYARD_BIND": bind,
            "ROOTYARD_GIT": git_bin,
            "ROOTYARD_SCRATCH_DIR": str(scratch_dir),
            "ROOTYARD_BLOB_DRIVER": "opendal",
            "ROOTYARD_BLOB_SERVICE": "s3",
            "ROOTYARD_BLOB_ENDPOINT": s3_endpoint,
            "ROOTYARD_BLOB_BUCKET": live.s3_bucket,
            "ROOTYARD_BLOB_REGION": live.s3_region,
            "ROOTYARD_BLOB_ACCESS_KEY_ID": live.s3_access_key,
            "ROOTYARD_BLOB_SECRET_ACCESS_KEY": live.s3_secret_key,
            "ROOTYARD_BLOB_ROOT": live.s3_root,
            "ROOTYARD_MAX_CONCURRENT_GIT": "16",
            "ROOTYARD_GIT_TIMEOUT_SECONDS": "180",
        }
    )
    if live.s3_session_token:
        proc_env["ROOTYARD_BLOB_SESSION_TOKEN"] = live.s3_session_token
    log_f = open(log_path, "ab")
    owned.register_log(log_f)
    kw: dict[str, Any] = {"env": proc_env, "stdout": log_f, "stderr": subprocess.STDOUT}
    if hasattr(os, "setsid"):
        kw["start_new_session"] = True
    try:
        proc = subprocess.Popen([binary, "serve-blob"], **kw)
    except Exception:  # noqa: BLE001 - fixed finite startup failure, no raw process text
        owned.close_log()
        raise LiveEvalFailure(
            build_failure_record(phase="live_setup", failure_class="popen_failed")
        ) from None
    except BaseException:
        owned.close_log()
        raise
    owned.register_proc(proc)
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            if owner is None:
                owned.stop()
            raise LiveEvalFailure(
                build_failure_record(phase="live_setup", failure_class="exited_early")
            )
        st, body, _, _ = http_json_timed(base_url, "/health/ready", timeout=2)
        if st == 200 and body == b"ready":
            return proc, base_url, log_f
        time.sleep(0.1)
    if owner is None:
        outcome = owned.stop()
        if not outcome.stopped:
            kill_process_group(proc)
            owned.close_log()
    raise LiveEvalFailure(
        build_failure_record(phase="live_setup", failure_class="readiness_timeout")
    )


def stop_serve_blob(proc: subprocess.Popen[bytes], log_f: Any) -> StopPostcondition:
    if proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            kill_process_group(proc)
    reaped = proc.poll() is not None
    if reaped and log_f is not None:
        try:
            log_f.close()
        except OSError:
            pass
    return StopPostcondition("server", reaped, "reaped" if reaped else "poll_alive")


def exercise_browse(
    base_url: str, owner: str, name: str, token: str, base_oid: str, head_oid: str, file_path: str
) -> list[float]:
    owner_q, name_q = url_quote_repo(owner, name)
    file_q = urllib.parse.quote(file_path, safe="")
    endpoints = (
        f"/api/repos/{owner_q}/{name_q}/refs",
        f"/api/repos/{owner_q}/{name_q}/commits",
        f"/api/repos/{owner_q}/{name_q}/tree",
        f"/api/repos/{owner_q}/{name_q}/blob?oid={head_oid}&path={file_q}",
        f"/api/repos/{owner_q}/{name_q}/compare?base={base_oid}&head={head_oid}",
    )
    samples: list[float] = []
    for ep in endpoints:
        st, _, _, ms = http_json_timed(base_url, ep, token=token, timeout=30)
        if st != 200:
            raise RuntimeError(f"Browse GET {ep} failed status={st}")
        samples.append(ms)
    return samples


def push_with_pack_config(
    git_bin: str,
    work_dir: Path,
    remote_url: str,
    spec: PackConfigSpec | None,
    ref_target: str,
    env: dict[str, str],
    *,
    context: dict[str, Any] | None = None,
) -> float:
    args: list[str] = ["-c", "credential.helper="]
    if spec is not None:
        args.extend(spec.git_config_args())
    args.extend(["push", "--quiet", "--porcelain", remote_url, ref_target])
    try:
        proc, ms = run_git(git_bin, args, work_dir, env)
    except subprocess.TimeoutExpired:
        raise LiveEvalFailure(git_failure_record(context, failure_class="git_timeout")) from None
    except OSError:
        raise LiveEvalFailure(git_failure_record(context, failure_class="git_spawn")) from None
    if proc.returncode != 0:
        raise LiveEvalFailure(
            git_failure_record(context, returncode=proc.returncode, elapsed_ms=ms, stderr=proc.stderr)
        ) from None
    return ms


def clone_and_fsck(git_bin: str, remote_url: str, dest: Path, env: dict[str, str]) -> float:
    if dest.exists():
        shutil.rmtree(dest)
    proc, ms = run_git(git_bin, ["-c", "credential.helper=", "clone", "--quiet", remote_url, str(dest)], None, env)
    if proc.returncode != 0:
        raise RuntimeError(f"HTTP git clone failed: {proc.stderr.decode(errors='replace')[:300]}")
    fsck, _ = run_git(git_bin, ["-C", str(dest), "fsck", "--full", "--strict"], None, env)
    if fsck.returncode != 0:
        raise RuntimeError(f"cloned repo fsck failed: {fsck.stderr.decode(errors='replace')[:300]}")
    return ms
