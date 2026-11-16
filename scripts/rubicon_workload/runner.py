"""Self-hosted serve-blob + PG17 + S3 Rubicon mixed workload runner (Refs #164)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
import uuid
from typing import Any

from .corpus import (
    DATASET_CLASSES,
    CommitSpec,
    build_git_env,
    classify_git_push,
    classify_http_status,
    clone_and_fsck,
    generate_repo_corpus,
    git_remote_refs,
    init_seeded_worktree,
    materialize_commit_spec,
    parse_push_porcelain,
    push_has_rejection,
    push_has_success,
    run_git,
    write_askpass_script,
)
from .report import compute_overlap_metrics, percentile_stats, redact_text, validate_report
from .workloads import ResourceSampler, S3MeterProxy, http_json, query_pg_snapshot_json

BLOB_REQUIRED_VARS = (
    "ROOTYARD_BLOB_SERVICE",
    "ROOTYARD_BLOB_ENDPOINT",
    "ROOTYARD_BLOB_REGION",
    "ROOTYARD_BLOB_BUCKET",
    "ROOTYARD_BLOB_ACCESS_KEY_ID",
    "ROOTYARD_BLOB_SECRET_ACCESS_KEY",
)


@dataclass
class WorkloadConfig:
    binary: str
    report: str
    git: str | None = None
    summary_md: str | None = None
    seed: int = 16420261116
    tiers: str = "auto"
    duration_seconds: int = 12
    warmup_seconds: int = 4
    s3_meter: str = "auto"
    require_build_receipt: bool = True
    keep: bool = False


class PreflightError(RuntimeError):
    """Fail-closed configuration or runtime dependency refusal."""


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise PreflightError(msg)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _with_search_path(base_db: str, schema: str) -> str:
    parts = urllib.parse.urlsplit(base_db)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    _need(not any(k == "options" for k, _ in query), "ROOTYARD_TEST_DATABASE_URL must not contain options")
    query.append(("options", f"-csearch_path={schema}"))
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))


def _resolve_tiers(spec: str, logical_cpus: int) -> tuple[list[int], list[str]]:
    notes: list[str] = []
    if spec == "auto":
        if logical_cpus >= 4:
            return [1, 2, 4], notes
        notes.append(f"Skipped 4-process compute tier because logical_cpus={logical_cpus} < 4.")
        return [1, 2], notes
    tiers = sorted({int(item.strip()) for item in spec.split(",") if item.strip()})
    _need(tiers and all(t in (1, 2, 4) for t in tiers), f"tiers must be subset of 1,2,4, got {spec!r}")
    return tiers, notes


def _validate_blob_profile(env: dict[str, str]) -> tuple[str, int, bool]:
    missing = [name for name in BLOB_REQUIRED_VARS if not env.get(name)]
    _need(not missing, "missing ROOTYARD_BLOB_* fields: " + ", ".join(missing))
    _need(env.get("ROOTYARD_BLOB_DRIVER", "opendal") == "opendal", "ROOTYARD_BLOB_DRIVER must be opendal")
    _need(env["ROOTYARD_BLOB_SERVICE"] == "s3", "ROOTYARD_BLOB_SERVICE must be s3")
    _need(env.get("ROOTYARD_BLOB_DELETE", "") in ("", "disabled"), "ROOTYARD_BLOB_DELETE must stay disabled")
    parsed = urllib.parse.urlsplit(env["ROOTYARD_BLOB_ENDPOINT"])
    _need(parsed.scheme in ("http", "https") and bool(parsed.hostname), "invalid ROOTYARD_BLOB_ENDPOINT")
    _need(not parsed.username and not parsed.password, "ROOTYARD_BLOB_ENDPOINT must not carry credentials")
    is_loopback = parsed.hostname in ("127.0.0.1", "::1", "localhost")
    _need(parsed.scheme == "https" or is_loopback, "non-loopback S3 endpoint requires HTTPS")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return str(parsed.hostname), int(port), parsed.scheme == "http" and is_loopback


def _git_source_state(repo_root: Path) -> tuple[str, bool]:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, text=True, timeout=15).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repo_root, text=True, timeout=15).strip())
    return commit, dirty


def _load_receipt_or_fail(
    binary_path: Path,
    repo_root: Path,
    require_receipt: bool,
    expected_commit: str,
) -> dict[str, Any]:
    receipt_path = binary_path.with_name(binary_path.name + ".build.json")
    if not receipt_path.exists():
        _need(not require_receipt, f"missing adjacent build receipt {receipt_path}")
        return {"receipt_verified": False}
    _need(receipt_path.is_file() and not receipt_path.is_symlink(), "build receipt must be regular non-symlink file")
    scripts_dir = str(repo_root / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    import native_build_receipt  # noqa: E402

    validated = native_build_receipt.load_receipt(
        receipt_path,
        source_root=repo_root,
        binary_path=binary_path,
        expected_commit=expected_commit,
        verify_source_files=True,
    )
    return {
        "receipt_verified": True,
        "receipt_schema": validated.schema,
        "workspace_commit": validated.workspace_commit,
        "receipt_sha256": validated.receipt_sha256,
        "config_digest": validated.config_digest,
        "source_inputs_sha256": validated.source_inputs_sha256,
    }


def _preflight(config: WorkloadConfig, env: dict[str, str], repo_root: Path) -> dict[str, Any]:
    _need(sys.platform.startswith("linux"), "serve-blob mixed workload benchmark requires Linux")
    _need(Path("/proc/self/stat").is_file(), "readable Linux /proc/self/stat is required")
    bin_path = Path(config.binary)
    _need(bin_path.is_absolute() and bin_path.is_file() and os.access(bin_path, os.X_OK),
          f"--binary must be an absolute executable path: {config.binary}")
    resolved_bin = bin_path.resolve(strict=True)
    source_commit, source_dirty = _git_source_state(repo_root)
    receipt_info = _load_receipt_or_fail(resolved_bin, repo_root, config.require_build_receipt, source_commit)

    git_raw = config.git or env.get("ROOTYARD_GIT") or env.get("ROOTYARD_TEST_GIT")
    _need(bool(git_raw), "--git or ROOTYARD_GIT/ROOTYARD_TEST_GIT is required")
    git_path = Path(git_raw)
    _need(git_path.is_absolute() and git_path.is_file() and os.access(git_path, os.X_OK),
          f"git executable missing or not executable: {git_raw}")
    resolved_git = git_path.resolve(strict=True)
    _need(bool(shutil.which("psql")), "psql executable missing from PATH")

    pg_base = env.get("ROOTYARD_TEST_DATABASE_URL", "")
    _need(pg_base.startswith(("postgres://", "postgresql://")), "ROOTYARD_TEST_DATABASE_URL is required")
    s3_host, s3_port, s3_loopback_http = _validate_blob_profile(env)
    s3_parsed = urllib.parse.urlsplit(env["ROOTYARD_BLOB_ENDPOINT"])
    s3_scheme = s3_parsed.scheme or "http"
    s3_is_loopback = s3_parsed.hostname in ("127.0.0.1", "::1", "localhost")
    logical_cpus = os.cpu_count() or 1
    tiers, tier_notes = _resolve_tiers(config.tiers, logical_cpus)
    return {
        "binary": str(resolved_bin),
        "binary_sha256": _sha256_file(resolved_bin),
        "binary_size_bytes": resolved_bin.stat().st_size,
        **receipt_info,
        "source_commit": source_commit,
        "source_dirty": source_dirty,
        "git": str(resolved_git),
        "git_version": subprocess.check_output([str(resolved_git), "--version"], text=True, timeout=10).strip(),
        "psql_version": subprocess.check_output(["psql", "--version"], text=True, timeout=10).strip(),
        "pg_base": pg_base,
        "s3_host": s3_host,
        "s3_port": s3_port,
        "s3_loopback_http": s3_loopback_http,
        "s3_scheme": s3_scheme,
        "s3_is_loopback": s3_is_loopback,
        "logical_cpus": logical_cpus,
        "tiers": tiers,
        "tier_notes": tier_notes,
    }


def _collect_secrets(env: dict[str, str], pg_base: str, pg_url: str) -> list[str]:
    secrets = [pg_base, pg_url]
    parsed = urllib.parse.urlsplit(pg_base)
    if parsed.password:
        secrets.append(parsed.password)
    for k in ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", "ROOTYARD_BLOB_ACCESS_KEY_ID", "ROOTYARD_BLOB_SESSION_TOKEN", "ROOTYARD_BLOB_ENDPOINT"):
        if env.get(k):
            secrets.append(env[k])
    return secrets


def _cli(binary: str, cli_env: dict[str, str], *args: str) -> str:
    proc = subprocess.run([binary, *args], env=cli_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"rootyard {' '.join(args)} failed ({proc.returncode}): {proc.stderr.decode(errors='replace')[:300]}")
    return proc.stdout.decode("utf-8").strip()


def _create_user_and_tokens(binary: str, cli_env: dict[str, str], username: str, secrets: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    rw = json.loads(_cli(binary, cli_env, "create-user", username))
    ro = json.loads(_cli(binary, cli_env, "create-token", username, "--read-only"))
    secrets.extend([rw["token"], ro["token"]])
    return rw, ro


def _start_fleet(
    count: int,
    binary: str,
    base_env: dict[str, str],
    git_bin: str,
    pg_url: str,
    s3_endpoint: str,
    scratch_root: Path,
) -> list[tuple[subprocess.Popen[bytes], str, Path, Any]]:
    fleet: list[tuple[subprocess.Popen[bytes], str, Path, Any]] = []
    for idx in range(count):
        bind = f"127.0.0.1:{_free_port()}"
        sdir = scratch_root / f"scratch-{idx}"
        if sdir.exists():
            shutil.rmtree(sdir)
        sdir.mkdir(parents=True, mode=0o700)
        os.chmod(sdir, 0o700)
        env = base_env.copy()
        env.pop("ROOTYARD_DATA_DIR", None)
        env.update(
            {
                "DATABASE_URL": pg_url,
                "ROOTYARD_SCHEMA_MODE": "external",
                "ROOTYARD_BIND": bind,
                "ROOTYARD_GIT": git_bin,
                "ROOTYARD_SCRATCH_DIR": str(sdir),
                "ROOTYARD_BLOB_ENDPOINT": s3_endpoint,
                "ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE": "1000",
            }
        )
        # Ensure single-process tier handles 6-way concurrent push + 4-way CI fetch
        # without tripping default 256 MiB / 128 MiB = 2 inflight transfer slots.
        env.setdefault("ROOTYARD_MAX_CONCURRENT_GIT", "16")
        env.setdefault("ROOTYARD_MAX_REQUEST_BYTES", str(16 * 1024 * 1024))
        env.setdefault("ROOTYARD_MAX_INFLIGHT_BYTES", str(256 * 1024 * 1024))
        log_f = open(scratch_root / f"serve-blob-{idx}.log", "ab")
        proc = subprocess.Popen([binary, "serve-blob"], env=env, stdout=log_f, stderr=log_f, start_new_session=True)
        fleet.append((proc, f"http://{bind}", sdir, log_f))

    deadline = time.monotonic() + 30.0
    pending = set(range(count))
    while pending and time.monotonic() < deadline:
        for idx in list(pending):
            proc, base_url, _, _ = fleet[idx]
            if proc.poll() is not None:
                _stop_fleet(fleet)
                raise RuntimeError(f"serve-blob[{idx}] exited during startup with {proc.returncode}")
            if http_json(base_url, "/health/ready", timeout=3)[0] == 200:
                pending.remove(idx)
        if pending:
            time.sleep(0.1)
    if pending:
        _stop_fleet(fleet)
        raise RuntimeError(f"serve-blob readiness timed out for workers {sorted(pending)}")
    return fleet


def _stop_fleet(fleet: list[tuple[subprocess.Popen[bytes], str, Path, Any]]) -> None:
    for proc, _, _, _ in fleet:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for proc, _, _, log_f in fleet:
        try:
            if proc.poll() is None:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
        except OSError:
            pass
        finally:
            try:
                log_f.close()
            except OSError:
                pass


def _verify_public_cluster_authority(pg_base: str, env: dict[str, str]) -> None:
    """Fail fast unless base DB public schema holds migration-085 cluster_authority."""
    try:
        authority = subprocess.check_output(
            [
                "psql", "--dbname", pg_base, "-X", "-t", "-A", "-v", "ON_ERROR_STOP=1",
                "-c", "SELECT to_regclass('public.cluster_authority') IS NOT NULL",
            ],
            env=env, text=True, stderr=subprocess.PIPE, timeout=15,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"failed checking public.cluster_authority on base database (exit={exc.returncode})") from None
    if authority != "t":
        raise RuntimeError(
            "public.cluster_authority is absent from base database; "
            "run 'rootyard migrate' on the base DATABASE_URL before running rubicon_mixed_workload"
        )


def _create_repo_and_wait(base_url: str, name: str, token: dict[str, str]) -> dict[str, Any]:
    code, raw, _, _ = http_json(base_url, "/api/repos", token=token, method="POST", body={"name": name, "object_format": "sha1"})
    secret_list = [token.get("token", "")] if token.get("token") else []
    if code not in (201, 202):
        err_body = redact_text(raw.decode("utf-8", "replace")[:240], secret_list)
        raise RuntimeError(f"POST /api/repos failed: status={code} body={err_body}")
    created = json.loads(raw)
    path = f"/api/repos/{urllib.parse.quote(created['owner'], safe='')}/{urllib.parse.quote(created['name'], safe='')}"
    deadline = time.monotonic() + 30.0
    last_code = 0
    last_body = ""
    while time.monotonic() < deadline:
        g_code, g_raw, _, _ = http_json(base_url, path, token=token)
        last_code = g_code
        last_body = redact_text(g_raw.decode("utf-8", "replace")[:240], secret_list)
        if g_code == 200:
            data = json.loads(g_raw)
            if data.get("state") == "ready":
                return data
            if data.get("state") != "provisioning":
                raise RuntimeError(f"unexpected repo provisioning state: {data.get('state')}")
        elif g_code in (400, 401, 403, 404, 500):
            raise RuntimeError(f"GET {path} failed for repo {name}: status={g_code} body={last_body}")
        time.sleep(0.1)
    raise RuntimeError(f"repo {name} did not become ready in 30s (last_status={last_code}, last_body={last_body})")


def _record_op(records: list[dict[str, Any]], op_class: str, ds_class: str, outcome: str, wall_ms: float, phase: str) -> None:
    records.append({"op_class": op_class, "dataset_class": ds_class, "outcome": outcome, "wall_ms": round(wall_ms, 3), "phase": phase})


def _upsert_acked(
    acked: list[dict[str, Any]],
    repo_key: str,
    entry: dict[str, Any],
    ref_name: str,
    expected_oid: str,
) -> None:
    """Record or update an ACKed (repo, ref) -> oid target for 100% end-of-tier audit."""
    for item in acked:
        if item["repo_key"] == repo_key and item["ref_name"] == ref_name:
            item["expected_oid"] = expected_oid
            return
    acked.append(
        {
            "repo_key": repo_key,
            "repo": entry["info"],
            "ref_name": ref_name,
            "expected_oid": expected_oid,
            "token": entry["rw"],
        }
    )


def _phase_seed(
    n_procs: int,
    config: WorkloadConfig,
    pre: dict[str, Any],
    base_env: dict[str, str],
    users: list[tuple[dict[str, str], dict[str, str]]],
    bases: list[str],
    tier_dir: Path,
    askpass: Path,
    records: list[dict[str, Any]],
    acked: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    repo_specs = [
        ("text_history", "txt-hist", 0, 0, "README.md"),
        ("similar_files", "sim-files", 1, 1, "templates/part_0.txt"),
        ("compressed_media", "media-bin", 2, 2, "assets/manifest.txt"),
        ("small_deltas", "tiny-delta", 0, 3, "counter.txt"),
        ("multi_repo_a", "multi-a", 1, 4, "README.md"),
        ("multi_repo_b", "multi-b", 2, 5, "README.md"),
        ("cas_race", "cas-race", 0, 6, "README.md"),
        ("atomic_subset", "atomic-sub", 1, 7, "README.md"),
        ("fault_repo", "fault-win", 2, 8, "README.md"),
    ]
    repos: dict[str, dict[str, Any]] = {}
    for key, slug, u_idx, r_idx, browse_file in repo_specs:
        rw_tok, ro_tok = users[u_idx]
        ds_class = "multi_repo" if key.startswith("multi_repo") else (key if key in DATASET_CLASSES else "small_deltas")
        info = _create_repo_and_wait(bases[r_idx % n_procs], f"{slug}-t{n_procs}", rw_tok)
        remote = bases[(r_idx + 1) % n_procs] + info["clone_path"]
        wdir = tier_dir / f"work-{key}"
        seed_commits, delta_commits = generate_repo_corpus(ds_class, config.seed, r_idx, variant_index=n_procs)
        seed_oid, push_ms = init_seeded_worktree(pre["git"], remote, wdir, base_env, askpass, rw_tok, seed_commits)
        _record_op(records, "seed_push", ds_class, "committed_success", push_ms, "warmup")
        repos[key] = {
            "info": info,
            "rw": rw_tok,
            "ro": ro_tok,
            "work": wdir,
            "seed_oid": seed_oid,
            "ds_class": ds_class,
            "deltas": delta_commits,
            "browse_file": browse_file if browse_file in seed_commits[-1].files else next(iter(seed_commits[-1].files)),
        }
        acked.append({"repo_key": key, "repo": info, "ref_name": "refs/heads/main", "expected_oid": seed_oid, "token": rw_tok})
    if config.warmup_seconds > 0:
        time.sleep(min(0.5, float(config.warmup_seconds)))
    return repos


def _collect_barrier_futures(futures: list[Any]) -> list[Any]:
    """Wait on all futures and raise any non-BrokenBarrierError root cause first."""
    results: list[Any] = []
    primary: BaseException | None = None
    barrier_err: BaseException | None = None
    for fut in futures:
        try:
            results.append(fut.result())
        except threading.BrokenBarrierError as exc:
            if barrier_err is None:
                barrier_err = exc
        except BaseException as exc:
            if primary is None:
                primary = exc
    if primary is not None:
        raise primary
    if barrier_err is not None:
        raise barrier_err
    return results


def _phase_concurrent_overlap(
    n_procs: int,
    config: WorkloadConfig,
    pre: dict[str, Any],
    base_env: dict[str, str],
    pg_url: str,
    bases: list[str],
    tier_dir: Path,
    askpass: Path,
    repos: dict[str, dict[str, Any]],
    records: list[dict[str, Any]],
    acked: list[dict[str, Any]],
) -> dict[str, Any]:
    indep_keys = ["text_history", "similar_files", "compressed_media", "small_deltas", "multi_repo_a", "multi_repo_b"]
    prepared: dict[str, tuple[Path, str, dict[str, str]]] = {}
    for idx, rkey in enumerate(indep_keys):
        entry = repos[rkey]
        remote = bases[idx % n_procs] + entry["info"]["clone_path"]
        env = build_git_env(base_env, askpass, entry["rw"])
        wdir = tier_dir / f"indep-{rkey}"
        clone_proc, _ = run_git(pre["git"], ["clone", remote, str(wdir)], None, env)
        if clone_proc.returncode != 0:
            err = clone_proc.stderr.decode("utf-8", errors="replace").strip()[:300]
            raise RuntimeError(f"indep clone failed for {rkey} (rc={clone_proc.returncode}): {err}")
        for k, v in (("user.name", "Rubicon Worker"), ("user.email", "worker@example.invalid")):
            run_git(pre["git"], ["config", k, v], wdir, env)
        new_oid = materialize_commit_spec(wdir, entry["deltas"][0], pre["git"], env)
        prepared[rkey] = (wdir, new_oid, env)

    barrier = threading.Barrier(len(indep_keys) + 2)
    intervals: list[tuple[int, int]] = []
    lock = threading.Lock()
    browse_stop, maint_stop = threading.Event(), threading.Event()

    def _push_worker(idx: int, rkey: str) -> None:
        entry = repos[rkey]
        wdir, new_oid, env = prepared[rkey]
        ref_name = f"refs/heads/indep_{idx}"
        try:
            barrier.wait(timeout=30)
            s_ns = time.monotonic_ns()
            proc, ms = run_git(pre["git"], ["push", "--porcelain", "origin", f"HEAD:{ref_name}"], wdir, env)
            e_ns = time.monotonic_ns()
        except BaseException:
            barrier.abort()
            raise
        outcome, _ = classify_git_push(proc, ref_name)
        with lock:
            intervals.append((s_ns, e_ns))
            _record_op(records, "concurrent_push", entry["ds_class"], outcome, ms, "measured")
            if outcome == "committed_success":
                _upsert_acked(acked, rkey, entry, ref_name, new_oid)

    def _browse_worker() -> None:
        try:
            barrier.wait(timeout=30)
        except BaseException:
            barrier.abort()
            raise
        for cycle in range(18):
            if browse_stop.is_set():
                break
            entry = repos[indep_keys[cycle % len(indep_keys)]]
            base = bases[(cycle + 1) % n_procs]
            owner, name = urllib.parse.quote(entry["info"]["owner"], safe=""), urllib.parse.quote(entry["info"]["name"], safe="")
            ep = ("refs", "commits", "tree", f"blob?oid={entry['seed_oid']}&path={urllib.parse.quote(entry['browse_file'])}")[cycle % 4]
            st, _, _, ms = http_json(base, f"/api/repos/{owner}/{name}/{ep}", token=entry["ro"])
            with lock:
                _record_op(records, "browse_api", entry["ds_class"], classify_http_status(st), ms, "measured")

    def _maint_worker() -> None:
        try:
            barrier.wait(timeout=30)
        except BaseException:
            barrier.abort()
            raise
        for _ in range(10):
            if maint_stop.is_set():
                break
            t0 = time.monotonic()
            try:
                query_pg_snapshot_json(pg_url, base_env)
                out = "committed_success"
            except Exception:  # noqa: BLE001
                out = "unknown_outcome"
            with lock:
                _record_op(records, "maintenance_query", "multi_repo", out, (time.monotonic() - t0) * 1000.0, "measured")
            time.sleep(0.05)

    with ThreadPoolExecutor(max_workers=len(indep_keys) + 2) as pool:
        futs = [pool.submit(_push_worker, i, rk) for i, rk in enumerate(indep_keys)]
        bf, mf = pool.submit(_browse_worker), pool.submit(_maint_worker)
        try:
            _collect_barrier_futures(futs)
        except BaseException as exc:
            browse_stop.set()
            maint_stop.set()
            try:
                _collect_barrier_futures([bf, mf])
            except BaseException as worker_exc:
                if isinstance(exc, threading.BrokenBarrierError) and not isinstance(worker_exc, threading.BrokenBarrierError):
                    raise worker_exc from None
            raise
        browse_stop.set()
        maint_stop.set()
        _collect_barrier_futures([bf, mf])

    wave_deadline = time.monotonic() + float(config.duration_seconds)
    wave_idx = 1
    while time.monotonic() < wave_deadline and wave_idx < 3:
        for i, rk in enumerate(indep_keys):
            entry = repos[rk]
            if wave_idx >= len(entry["deltas"]):
                continue
            env = build_git_env(base_env, askpass, entry["rw"])
            wdir = tier_dir / f"indep-{rk}"
            new_oid = materialize_commit_spec(wdir, entry["deltas"][wave_idx], pre["git"], env)
            ref_name = f"refs/heads/indep_{i}"
            proc, ms = run_git(pre["git"], ["push", "--porcelain", "origin", f"HEAD:{ref_name}"], wdir, env)
            outcome, _ = classify_git_push(proc, ref_name)
            _record_op(records, "mixed_push", entry["ds_class"], outcome, ms, "measured")
            if outcome == "committed_success":
                _upsert_acked(acked, rk, entry, ref_name, new_oid)
        wave_idx += 1
    return {"scope": "cross_repo_distinct_repositories", **compute_overlap_metrics(intervals)}


def _phase_same_repo_mixed(
    n_procs: int,
    seed: int,
    pre: dict[str, Any],
    base_env: dict[str, str],
    pg_url: str,
    bases: list[str],
    tier_dir: Path,
    askpass: Path,
    repos: dict[str, dict[str, Any]],
    records: list[dict[str, Any]],
    acked: list[dict[str, Any]],
) -> dict[str, Any]:
    """Exercise concurrent independent-ref pushes, read/Browse, and PG SELECTs on ONE repository."""
    entry = repos["small_deltas"]
    branches = 3
    prepared: list[tuple[Path, str, str, dict[str, str]]] = []
    for idx in range(branches):
        wdir = tier_dir / f"same-{idx}"
        env = build_git_env(base_env, askpass, entry["rw"])
        remote = bases[idx % n_procs] + entry["info"]["clone_path"]
        clone_proc, _ = run_git(pre["git"], ["clone", remote, str(wdir)], None, env)
        if clone_proc.returncode != 0:
            err = clone_proc.stderr.decode("utf-8", errors="replace").strip()[:300]
            raise RuntimeError(f"same-repo clone failed idx={idx} (rc={clone_proc.returncode}): {err}")
        for k, v in (("user.name", f"SameRepo{idx}"), ("user.email", f"same{idx}@example.invalid")):
            run_git(pre["git"], ["config", k, v], wdir, env)
        new_oid = materialize_commit_spec(
            wdir,
            CommitSpec(f"same-repo branch {idx}", {f"same_branch_{idx}.txt": f"branch={idx} seed={seed}\n".encode()}),
            pre["git"],
            env,
        )
        prepared.append((wdir, f"refs/heads/same_branch_{idx}", new_oid, env))

    barrier = threading.Barrier(branches + 2)
    intervals: list[tuple[int, int]] = []
    lock = threading.Lock()
    stop_readers = threading.Event()
    counters = {"committed_success": 0, "contention_retries": 0, "read_browse_ops": 0, "maintenance_pg_select_ops": 0}

    def _push_worker(idx: int) -> None:
        wdir, ref_name, new_oid, env = prepared[idx]
        try:
            barrier.wait(timeout=30)
            s_ns = time.monotonic_ns()
            proc, ms = run_git(pre["git"], ["push", "--porcelain", "origin", f"HEAD:{ref_name}"], wdir, env)
            e_ns = time.monotonic_ns()
        except BaseException:
            barrier.abort()
            raise
        outcome, _ = classify_git_push(proc, ref_name)
        retries = 0
        with lock:
            intervals.append((s_ns, e_ns))
            _record_op(records, "same_repo_push", entry["ds_class"], outcome, ms, "measured")
        for attempt in range(3):
            if outcome == "committed_success":
                break
            retries += 1
            time.sleep(0.05 * (attempt + 1))
            proc, r_ms = run_git(pre["git"], ["push", "--porcelain", "origin", f"HEAD:{ref_name}"], wdir, env)
            outcome, _ = classify_git_push(proc, ref_name)
            with lock:
                _record_op(records, "same_repo_push_retry", entry["ds_class"], outcome, r_ms, "measured")
        with lock:
            counters["contention_retries"] += retries
            if outcome == "committed_success":
                counters["committed_success"] += 1
                _upsert_acked(acked, "small_deltas", entry, ref_name, new_oid)

    def _read_browse_worker() -> None:
        try:
            barrier.wait(timeout=30)
        except BaseException:
            barrier.abort()
            raise
        owner, name = urllib.parse.quote(entry["info"]["owner"], safe=""), urllib.parse.quote(entry["info"]["name"], safe="")
        for cycle in range(8):
            if stop_readers.is_set():
                break
            if cycle % 2 == 0:
                _, ls_ms = git_remote_refs(pre["git"], bases[cycle % n_procs] + entry["info"]["clone_path"], base_env, askpass, entry["ro"])
                with lock:
                    counters["read_browse_ops"] += 1
                    _record_op(records, "same_repo_read", entry["ds_class"], "committed_success", ls_ms, "measured")
            else:
                ep = ("refs", "commits", "tree")[cycle % 3]
                st, _, _, b_ms = http_json(bases[cycle % n_procs], f"/api/repos/{owner}/{name}/{ep}", token=entry["ro"])
                with lock:
                    counters["read_browse_ops"] += 1
                    _record_op(records, "same_repo_browse", entry["ds_class"], classify_http_status(st), b_ms, "measured")

    def _maint_select_worker() -> None:
        try:
            barrier.wait(timeout=30)
        except BaseException:
            barrier.abort()
            raise
        for _ in range(6):
            if stop_readers.is_set():
                break
            t0 = time.monotonic()
            try:
                query_pg_snapshot_json(pg_url, base_env)
                out = "committed_success"
            except Exception:  # noqa: BLE001
                out = "unknown_outcome"
            with lock:
                counters["maintenance_pg_select_ops"] += 1
                _record_op(records, "maintenance_query", entry["ds_class"], out, (time.monotonic() - t0) * 1000.0, "measured")
            time.sleep(0.05)

    with ThreadPoolExecutor(max_workers=branches + 2) as pool:
        futs = [pool.submit(_push_worker, i) for i in range(branches)]
        rf, mf = pool.submit(_read_browse_worker), pool.submit(_maint_select_worker)
        try:
            _collect_barrier_futures(futs)
        except BaseException as exc:
            stop_readers.set()
            try:
                _collect_barrier_futures([rf, mf])
            except BaseException as worker_exc:
                if isinstance(exc, threading.BrokenBarrierError) and not isinstance(worker_exc, threading.BrokenBarrierError):
                    raise worker_exc from None
            raise
        stop_readers.set()
        _collect_barrier_futures([rf, mf])

    return {
        "scope": "same_repository_distinct_refs",
        "repo": entry["info"]["name"],
        **compute_overlap_metrics(intervals),
        **counters,
    }


def _phase_cas_race(
    n_procs: int,
    seed: int,
    pre: dict[str, Any],
    base_env: dict[str, str],
    bases: list[str],
    tier_dir: Path,
    askpass: Path,
    repos: dict[str, dict[str, Any]],
    records: list[dict[str, Any]],
    acked: list[dict[str, Any]],
) -> dict[str, Any]:
    cas_entry = repos["cas_race"]
    participants = 4
    clones: list[tuple[Path, str, str]] = []
    for idx in range(participants):
        cdir = tier_dir / f"cas-c{idx}"
        c_env = build_git_env(base_env, askpass, cas_entry["rw"])
        clone_proc, _ = run_git(pre["git"], ["clone", bases[idx % n_procs] + cas_entry["info"]["clone_path"], str(cdir)], None, c_env)
        if clone_proc.returncode != 0:
            err = clone_proc.stderr.decode("utf-8", errors="replace").strip()[:300]
            raise RuntimeError(f"cas clone failed idx={idx} (rc={clone_proc.returncode}): {err}")
        run_git(pre["git"], ["config", "user.name", f"Cas{idx}"], cdir, c_env)
        run_git(pre["git"], ["config", "user.email", f"cas{idx}@example.invalid"], cdir, c_env)
        c_oid = materialize_commit_spec(cdir, CommitSpec(f"cas racer {idx}", {f"cas_{idx}.txt": f"racer={idx} seed={seed}\n".encode()}), pre["git"], c_env)
        clones.append((cdir, c_oid, str(uuid.uuid4())))
    barrier = threading.Barrier(participants)

    def _push(idx: int) -> tuple[str, str, float]:
        cdir, c_oid, op_id = clones[idx]
        c_env = build_git_env(base_env, askpass, cas_entry["rw"])
        try:
            barrier.wait(timeout=20)
        except BaseException:
            barrier.abort()
            raise
        proc, ms = run_git(pre["git"], ["-c", f"http.extraHeader=X-Rootyard-Operation: {op_id}", "push", "--porcelain", "origin", "HEAD:refs/heads/main"], cdir, c_env)
        return classify_git_push(proc, "refs/heads/main")[0], c_oid, ms

    with ThreadPoolExecutor(max_workers=participants) as pool:
        results = _collect_barrier_futures([pool.submit(_push, i) for i in range(participants)])
    winners = [r for r in results if r[0] == "committed_success"]
    losers = [r for r in results if r[0] == "typed_refusal"]
    for out, _, ms in results:
        _record_op(records, "cas_race_winner" if out == "committed_success" else "cas_race_loser", "small_deltas", out, ms, "measured")
    winner_oid = winners[0][1] if len(winners) == 1 else ""
    live_refs, _ = git_remote_refs(pre["git"], bases[0] + cas_entry["info"]["clone_path"], base_env, askpass, cas_entry["ro"])
    matches = bool(winner_oid and live_refs.get("refs/heads/main") == winner_oid)
    if matches:
        _upsert_acked(acked, "cas_race", cas_entry, "refs/heads/main", winner_oid)
    return {"participants": participants, "winner_count": len(winners), "loser_refused": len(losers), "false_ok": max(0, len(winners) - 1), "remote_ref_matches_winner": matches}


def _phase_atomic_subset(
    pre: dict[str, Any],
    base_env: dict[str, str],
    bases: list[str],
    askpass: Path,
    repos: dict[str, dict[str, Any]],
    records: list[dict[str, Any]],
    acked: list[dict[str, Any]],
) -> dict[str, bool]:
    at = repos["atomic_subset"]
    at_env = build_git_env(base_env, askpass, at["rw"])
    at_dir, at_remote, base_oid = at["work"], bases[0] + at["info"]["clone_path"], at["seed_oid"]
    adv_oid = materialize_commit_spec(at_dir, CommitSpec("atomic advance", {"adv.txt": b"advance\n"}), pre["git"], at_env)
    sib_tree = run_git(pre["git"], ["rev-parse", f"{base_oid}^{{tree}}"], at_dir, at_env)[0].stdout.decode().strip()
    sib_oid = run_git(pre["git"], ["commit-tree", sib_tree, "-p", base_oid, "-m", "sibling"], at_dir, at_env)[0].stdout.decode().strip()
    run_git(pre["git"], ["push", "--porcelain", "origin", f"{adv_oid}:refs/heads/protected"], at_dir, at_env)

    p_fail, ms_f = run_git(pre["git"], ["push", "--atomic", "--porcelain", "origin", f"{adv_oid}:refs/heads/main", f"{sib_oid}:refs/heads/protected"], at_dir, at_env)
    refs_f, _ = git_remote_refs(pre["git"], at_remote, base_env, askpass, at["ro"])
    atomic_rej = p_fail.returncode != 0 and refs_f.get("refs/heads/main") == base_oid and refs_f.get("refs/heads/protected") == adv_oid
    _record_op(records, "atomic_push", "small_deltas", "typed_refusal" if atomic_rej else "unknown_outcome", ms_f, "measured")

    p_sub, ms_s = run_git(pre["git"], ["push", "--porcelain", "origin", f"{adv_oid}:refs/heads/main", f"{sib_oid}:refs/heads/protected"], at_dir, at_env)
    entries = parse_push_porcelain(p_sub.stdout.decode("utf-8", errors="replace"))
    refs_s, _ = git_remote_refs(pre["git"], at_remote, base_env, askpass, at["ro"])
    sub_exact = p_sub.returncode != 0 and push_has_success(entries, "refs/heads/main") and push_has_rejection(entries, "refs/heads/protected") and refs_s.get("refs/heads/main") == adv_oid and refs_s.get("refs/heads/protected") == adv_oid
    _record_op(records, "subset_push", "small_deltas", "typed_refusal" if sub_exact else "unknown_outcome", ms_s, "measured")

    p_ok, ms_ok = run_git(pre["git"], ["push", "--atomic", "--porcelain", "origin", f"{adv_oid}:refs/heads/atom-a", f"{sib_oid}:refs/heads/atom-b"], at_dir, at_env)
    refs_ok, _ = git_remote_refs(pre["git"], at_remote, base_env, askpass, at["ro"])
    atom_ok = p_ok.returncode == 0 and refs_ok.get("refs/heads/atom-a") == adv_oid and refs_ok.get("refs/heads/atom-b") == sib_oid
    _record_op(records, "atomic_push", "small_deltas", "committed_success" if atom_ok else "unknown_outcome", ms_ok, "measured")
    _upsert_acked(acked, "atomic_subset", at, "refs/heads/main", adv_oid)
    _upsert_acked(acked, "atomic_subset", at, "refs/heads/protected", adv_oid)
    _upsert_acked(acked, "atomic_subset", at, "refs/heads/atom-a", adv_oid)
    _upsert_acked(acked, "atomic_subset", at, "refs/heads/atom-b", sib_oid)
    return {"atomic_rejected_unchanged": atomic_rej, "subset_partial_exact": sub_exact, "atomic_positive_committed": atom_ok}


def _phase_cold_warm_and_ci(
    n_procs: int,
    pre: dict[str, Any],
    base_env: dict[str, str],
    pg_url: str,
    s3_endpoint: str,
    s3_proxy: S3MeterProxy | None,
    tier_scratch: Path,
    tier_dir: Path,
    askpass: Path,
    repos: dict[str, dict[str, Any]],
    records: list[dict[str, Any]],
    fleet: list[tuple[subprocess.Popen[bytes], str, Path, Any]],
    sampler: ResourceSampler,
) -> tuple[list[tuple[subprocess.Popen[bytes], str, Path, Any]], dict[str, Any], dict[str, Any]]:
    bases = [item[1] for item in fleet]
    ci_targets = ("text_history", "compressed_media")
    s3_b_ci = s3_proxy.snapshot() if s3_proxy else None
    ci_ms: list[float] = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = [pool.submit(clone_and_fsck, pre["git"], bases[k % n_procs] + repos[ci_targets[k % 2]]["info"]["clone_path"], tier_dir / f"ci-{k}", base_env, askpass, repos[ci_targets[k % 2]]["ro"]) for k in range(4)]
        for k, f in enumerate(futs):
            ok, ms, _ = f.result()
            _record_op(records, "ci_fetch", repos[ci_targets[k % 2]]["ds_class"], "committed_success" if ok else "unknown_outcome", ms, "measured")
            ci_ms.append(ms)
    ci_info = {"burst_latencies": percentile_stats(ci_ms), "s3_wire": S3MeterProxy.delta(s3_proxy.snapshot(), s3_b_ci) if s3_proxy and s3_b_ci else {"observed": False}}

    sampler.sample_once()
    _stop_fleet(fleet)
    fleet = _start_fleet(n_procs, pre["binary"], base_env, pre["git"], pg_url, s3_endpoint, tier_scratch)
    bases = [item[1] for item in fleet]
    sampler.set_targets([item[0].pid for item in fleet], [item[2] for item in fleet], new_epoch=True, worktree_dirs=[tier_dir])

    def _run_pass(label: str) -> tuple[list[float], list[float], dict[str, Any]]:
        s3_b = s3_proxy.snapshot() if s3_proxy else None
        clone_ms, browse_ms = [], []
        for idx, ck in enumerate(ci_targets):
            entry = repos[ck]
            ok, ms, _ = clone_and_fsck(pre["git"], bases[idx % n_procs] + entry["info"]["clone_path"], tier_dir / f"{label}-{ck}", base_env, askpass, entry["ro"])
            _record_op(records, f"{label}_clone", entry["ds_class"], "committed_success" if ok else "unknown_outcome", ms, "measured")
            clone_ms.append(ms)
            owner, name = urllib.parse.quote(entry["info"]["owner"], safe=""), urllib.parse.quote(entry["info"]["name"], safe="")
            for ep in ("refs", "commits", "tree", f"blob?oid={entry['seed_oid']}&path={urllib.parse.quote(entry['browse_file'])}"):
                st, _, _, b_ms = http_json(bases[(idx + 1) % n_procs], f"/api/repos/{owner}/{name}/{ep}", token=entry["ro"])
                _record_op(records, f"{label}_browse", entry["ds_class"], classify_http_status(st), b_ms, "measured")
                browse_ms.append(b_ms)
        return clone_ms, browse_ms, (S3MeterProxy.delta(s3_proxy.snapshot(), s3_b) if s3_proxy and s3_b else {"observed": False})

    cold_c, cold_b, s3_cold = _run_pass("cold")
    warm_c, warm_b, s3_warm = _run_pass("warm")
    return fleet, ci_info, {
        "cold_clone": percentile_stats(cold_c),
        "warm_clone": percentile_stats(warm_c),
        "cold_browse": percentile_stats(cold_b),
        "warm_browse": percentile_stats(warm_b),
        "cold_s3_wire": s3_cold,
        "warm_s3_wire": s3_warm,
        "cold_semantics": "service_restart_empty_scratch_view_only_provider_cache_unobserved",
    }


def _phase_fault_and_audit(
    pre: dict[str, Any],
    base_env: dict[str, str],
    cli_env: dict[str, str],
    bases: list[str],
    tier_dir: Path,
    askpass: Path,
    repos: dict[str, dict[str, Any]],
    records: list[dict[str, Any]],
    acked: list[dict[str, Any]],
    rev_tok: dict[str, str],
) -> tuple[dict[str, int], dict[str, int]]:
    fault_entry = repos["fault_repo"]
    if http_json(bases[0], "/api/repos", token=rev_tok)[0] != 200:
        raise RuntimeError("pre-revocation API probe did not return 200")
    _cli(pre["binary"], cli_env, "revoke-token", rev_tok["token_id"])
    fault_counts = {"total_attempts": 0, "committed_success": 0, "typed_refusal": 0, "unknown_outcome": 0}

    rev_st, _, _, rev_ms = http_json(bases[0], "/api/repos", token=rev_tok)
    rev_out = classify_http_status(rev_st)
    fault_counts["total_attempts"] += 1
    fault_counts[rev_out] += 1
    _record_op(records, "fault_window_refusal", "multi_repo", rev_out, rev_ms, "fault_window")

    rev_env = build_git_env(base_env, askpass, rev_tok)
    materialize_commit_spec(fault_entry["work"], CommitSpec("revoked commit", {"rev.txt": b"denied\n"}), pre["git"], rev_env)
    p_rev, ms_rev = run_git(pre["git"], ["push", "--porcelain", "origin", "HEAD:refs/heads/revoked-denied"], fault_entry["work"], rev_env)
    rev_push_out = classify_git_push(p_rev, "refs/heads/revoked-denied")[0]
    fault_counts["total_attempts"] += 1
    fault_counts[rev_push_out] += 1
    _record_op(records, "fault_window_refusal", "multi_repo", rev_push_out, ms_rev, "fault_window")

    down_env = build_git_env(base_env, askpass, fault_entry["rw"])
    down_env["GIT_HTTP_LOW_SPEED_TIME"] = "3"
    p_down, ms_down = run_git(pre["git"], ["push", "--porcelain", f"http://127.0.0.1:1{fault_entry['info']['clone_path']}", "HEAD:refs/heads/down-denied"], fault_entry["work"], down_env, timeout=15)
    down_out = classify_git_push(p_down, "refs/heads/down-denied")[0]
    fault_counts["total_attempts"] += 1
    fault_counts[down_out] += 1
    _record_op(records, "fault_window_refusal", "multi_repo", down_out, ms_down, "fault_window")

    fault_live, _ = git_remote_refs(pre["git"], bases[0] + fault_entry["info"]["clone_path"], base_env, askpass, fault_entry["ro"])
    if "refs/heads/revoked-denied" in fault_live or "refs/heads/down-denied" in fault_live:
        raise RuntimeError("fault/revocation window unexpectedly mutated remote refs")

    verified, fsck_failed, ref_mismatch = 0, 0, 0
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for item in acked:
        by_repo.setdefault(item["repo_key"], []).append(item)
    for rk, items in by_repo.items():
        entry = repos[rk]
        r_url = bases[0] + entry["info"]["clone_path"]
        live_refs, _ = git_remote_refs(pre["git"], r_url, base_env, askpass, entry["ro"])
        cdir = tier_dir / f"audit-{rk}"
        c_env = build_git_env(base_env, askpass, entry["ro"])
        cl_p, _ = run_git(pre["git"], ["clone", "--mirror", r_url, str(cdir)], None, c_env)
        fsck_ok = cl_p.returncode == 0 and run_git(pre["git"], ["fsck", "--full", "--strict"], cdir, c_env)[0].returncode == 0
        if not fsck_ok:
            fsck_failed += 1
        for item in items:
            if live_refs.get(item["ref_name"]) != item["expected_oid"] or not fsck_ok:
                ref_mismatch += 1
            elif run_git(pre["git"], ["rev-parse", "--verify", f"{item['expected_oid']}^{{commit}}"], cdir, c_env)[0].returncode == 0:
                verified += 1
            else:
                ref_mismatch += 1
    return fault_counts, {"acked_targets_total": len(acked), "verified_exact": verified, "fsck_failed": fsck_failed, "ref_mismatch": ref_mismatch}


def _run_tier(
    n_procs: int,
    config: WorkloadConfig,
    pre: dict[str, Any],
    base_env: dict[str, str],
    cli_env: dict[str, str],
    pg_url: str,
    s3_endpoint: str,
    s3_proxy: S3MeterProxy | None,
    tier_dir: Path,
    askpass: Path,
    secrets: list[str],
) -> dict[str, Any]:
    users = [_create_user_and_tokens(pre["binary"], cli_env, f"rubicon_t{n_procs}_u{i}", secrets) for i in range(3)]
    # Pre-mint the sacrificial token before starting serve-blob because CLI
    # `create-token` invokes `db::migrate` (exclusive advisory lock) which
    # contends on ServingBarrier's shared lock while serve-blob is active.
    rev_tok = json.loads(_cli(pre["binary"], cli_env, "create-token", f"rubicon_t{n_procs}_u2"))
    secrets.append(rev_tok["token"])
    tier_scratch = tier_dir / "scratches"
    tier_scratch.mkdir(parents=True, mode=0o700)
    fleet = _start_fleet(n_procs, pre["binary"], base_env, pre["git"], pg_url, s3_endpoint, tier_scratch)
    sampler = ResourceSampler(pg_url=pg_url, base_env=base_env, interval_seconds=0.4)
    sampler.set_targets([item[0].pid for item in fleet], [item[2] for item in fleet], worktree_dirs=[tier_dir])
    sampler.start()

    tier_start = time.monotonic()
    records: list[dict[str, Any]] = []
    acked: list[dict[str, Any]] = []
    s3_before_tier = s3_proxy.snapshot() if s3_proxy is not None else None
    try:
        bases = [item[1] for item in fleet]
        repos = _phase_seed(n_procs, config, pre, base_env, users, bases, tier_dir, askpass, records, acked)
        overlap = _phase_concurrent_overlap(n_procs, config, pre, base_env, pg_url, bases, tier_dir, askpass, repos, records, acked)
        same_repo = _phase_same_repo_mixed(n_procs, config.seed, pre, base_env, pg_url, bases, tier_dir, askpass, repos, records, acked)
        cas = _phase_cas_race(n_procs, config.seed, pre, base_env, bases, tier_dir, askpass, repos, records, acked)
        atomic = _phase_atomic_subset(pre, base_env, bases, askpass, repos, records, acked)
        fleet, ci_info, cold_warm = _phase_cold_warm_and_ci(
            n_procs, pre, base_env, pg_url, s3_endpoint, s3_proxy, tier_scratch, tier_dir, askpass, repos, records, fleet, sampler
        )
        bases = [item[1] for item in fleet]
        fault_counts, audit = _phase_fault_and_audit(pre, base_env, cli_env, bases, tier_dir, askpass, repos, records, acked, rev_tok)
        pg_final = query_pg_snapshot_json(pg_url, base_env)
        sampler.stop()
    finally:
        sampler.stop()
        _stop_fleet(fleet)

    tier_wall = time.monotonic() - tier_start
    s3_tier = S3MeterProxy.delta(s3_proxy.snapshot(), s3_before_tier) if s3_proxy and s3_before_tier else {"observed": False}
    outcomes = {
        "total_ops": len(records),
        "committed_success": sum(1 for r in records if r["outcome"] == "committed_success"),
        "typed_refusal": sum(1 for r in records if r["outcome"] == "typed_refusal"),
        "unknown_outcome": sum(1 for r in records if r["outcome"] == "unknown_outcome"),
    }
    committed = max(1, outcomes["committed_success"])
    cpu_total_s = sampler.total_cpu_seconds()
    return {
        "compute_processes": n_procs,
        "wall_seconds": round(tier_wall, 3),
        "committed_ops_per_sec": round(outcomes["committed_success"] / max(0.001, tier_wall), 4),
        "outcomes": outcomes,
        "independent_ref_overlap": overlap,
        "same_repo_mixed_concurrency": same_repo,
        "cas_race": cas,
        "atomic_vs_subset": atomic,
        "ci_read_amplification": ci_info,
        "cold_vs_warm": cold_warm,
        "fault_revocation_window": fault_counts,
        "audit": audit,
        "storage_accounting": {
            "pack_count": pg_final["pack_count"],
            "publication_count": pg_final["publication_count"],
            "serving_pack_bytes": pg_final["serving_pack_bytes"],
            "coexisting_pack_bytes": pg_final["coexisting_pack_bytes"],
            "uncommitted_or_stale_registered_bytes": max(0, pg_final["coexisting_pack_bytes"] - pg_final["serving_pack_bytes"]),
            "gc_executed": False,
            "gc_reclaimed_physical_bytes": 0,
            "physical_savings_claimed": False,
        },
        "s3_wire": s3_tier,
        "resource_peaks": {
            "cpu_seconds_total": cpu_total_s,
            "max_total_rss_kib": sampler.max_rss_kib,
            "max_total_hwm_kib": sampler.max_hwm_kib,
            "max_temp_disk_bytes": sampler.max_temp_disk_bytes,
            "max_server_scratch_bytes": sampler.max_server_scratch_bytes,
            "max_client_worktree_bytes": sampler.max_client_worktree_bytes,
            "max_pg_active": sampler.max_pg_active,
            "max_pg_lock_waiters": sampler.max_pg_lock_waiters,
            "sampler_errors": sampler.errors,
        },
        "cost_units": {
            "cpu_ms_per_committed_op": round((cpu_total_s * 1000.0) / committed, 3),
            "s3_get_requests_per_committed_op": round(s3_tier.get("get_requests", 0) / committed, 3) if s3_tier.get("observed") else None,
            "s3_put_requests_per_committed_op": round(s3_tier.get("put_requests", 0) / committed, 3) if s3_tier.get("observed") else None,
        },
        "latency_by_op_class": {c: percentile_stats([r["wall_ms"] for r in records if r["op_class"] == c]) for c in sorted({r["op_class"] for r in records})},
        "latency_by_dataset_class": {ds: percentile_stats([r["wall_ms"] for r in records if r["dataset_class"] == ds and r["phase"] in ("warmup", "measured")]) for ds in DATASET_CLASSES},
        "time_series": sampler.time_series,
    }


def _analyze_scaling(tiers: list[dict[str, Any]], tier_notes: list[str]) -> dict[str, Any]:
    notes = list(tier_notes)
    base = tiers[0]
    ratios: dict[str, Any] = {}
    for tier in tiers[1:]:
        n = tier["compute_processes"]
        key = f"throughput_ratio_{n}_vs_{base['compute_processes']}"
        ratios[key] = round(tier["committed_ops_per_sec"] / max(0.0001, base["committed_ops_per_sec"]), 3)
        cold_base = base["cold_vs_warm"]["cold_clone"].get("p50_ms") or 0.0
        cold_cur = tier["cold_vs_warm"]["cold_clone"].get("p50_ms") or 0.0
        if cold_base > 0 and cold_cur > 0:
            ratios[f"cold_p50_ratio_{n}_vs_{base['compute_processes']}"] = round(cold_base / cold_cur, 3)
        notes.append(
            f"{n}-process tier throughput={tier['committed_ops_per_sec']:.3f} ops/s "
            f"(ratio vs {base['compute_processes']}-proc: {ratios[key]}x), "
            f"cpu={tier['resource_peaks']['cpu_seconds_total']}s, peak_rss={tier['resource_peaks']['max_total_rss_kib']} KiB, "
            f"pg_lock_waiters_peak={tier['resource_peaks']['max_pg_lock_waiters']}."
        )
    notes.append("Single-host shared PostgreSQL and single Garage S3 container mean compute tiers contend on host CPUs and shared DB/S3.")
    return {"ratios": ratios, "bottlenecks": notes}


def _format_topology(tiers: list[int], s3_scheme: str, s3_is_loopback: bool, s3_metered: bool) -> str:
    scheme_upper = (s3_scheme or "http").upper()
    if s3_metered:
        s3_desc = "one loopback HTTP S3 provider (metered via loopback proxy)"
    elif s3_is_loopback:
        s3_desc = f"one loopback {scheme_upper} S3 provider (unmetered)"
    else:
        s3_desc = f"one external {scheme_upper} S3 provider (unmetered)"
    return f"1..{max(tiers)} serve-blob processes on one host sharing one PostgreSQL schema + {s3_desc}"


def run_rubicon_workload(config: WorkloadConfig, env: dict[str, str] | None = None) -> dict[str, Any]:
    """Execute the full self-hosted Rubicon mixed workload and compute scaling benchmark."""
    run_env = dict(os.environ if env is None else env)
    repo_root = Path(__file__).resolve().parents[2]
    pre = _preflight(config, run_env, repo_root)

    work_root = Path(tempfile.mkdtemp(prefix="rubicon-mix-"))
    schema = f"rubicon_mix_{uuid.uuid4().hex[:12]}"
    pg_url = _with_search_path(pre["pg_base"], schema)
    secrets = _collect_secrets(run_env, pre["pg_base"], pg_url)
    schema_created = False
    s3_proxy: S3MeterProxy | None = None
    s3_endpoint = run_env["ROOTYARD_BLOB_ENDPOINT"]

    try:
        _verify_public_cluster_authority(pre["pg_base"], run_env)
        subprocess.run(
            ["psql", "--dbname", pre["pg_base"], "-X", "-v", "ON_ERROR_STOP=1", "-c", f'CREATE SCHEMA "{schema}"'],
            env=run_env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        schema_created = True
        cli_env = run_env.copy()
        cli_env["DATABASE_URL"] = pg_url
        cli_env["ROOTYARD_DATA_DIR"] = str(work_root / "cli-data")
        cli_env["ROOTYARD_SCHEMA_MODE"] = "auto"
        _cli(pre["binary"], cli_env, "migrate")
        # Switch CLI calls to read-only schema verification once migrated so
        # create-user/create-token/revoke-token never block on exclusive
        # migration locks against live serve-blob shared ServingBarrier locks.
        cli_env["ROOTYARD_SCHEMA_MODE"] = "external"
        pg_ver = subprocess.check_output(["psql", "--dbname", pg_url, "-X", "-t", "-A", "-c", "SHOW server_version"], env=run_env, text=True, timeout=15).strip()

        if config.s3_meter != "off" and pre["s3_loopback_http"]:
            s3_proxy = S3MeterProxy(pre["s3_host"], pre["s3_port"])
            s3_proxy.start()
            s3_endpoint = s3_proxy.endpoint

        askpass = write_askpass_script(work_root / "askpass.sh")
        tiers_out = [_run_tier(n, config, pre, run_env, cli_env, pg_url, s3_endpoint, s3_proxy, work_root / f"tier-{n}", askpass, secrets) for n in pre["tiers"]]
        source_sha, source_dirty = _git_source_state(repo_root)
        source_obj: dict[str, Any] = {"commit": source_sha, "dirty": source_dirty}
        binary_obj: dict[str, Any] = {
            "path": pre["binary"],
            "sha256": pre["binary_sha256"],
            "size_bytes": pre["binary_size_bytes"],
            "receipt_verified": pre["receipt_verified"],
        }
        if pre.get("receipt_verified"):
            source_obj["receipt_workspace_commit"] = pre["workspace_commit"]
            source_obj["source_inputs_sha256"] = pre["source_inputs_sha256"]
            binary_obj.update(
                {
                    "receipt_schema": pre["receipt_schema"],
                    "receipt_sha256": pre["receipt_sha256"],
                    "workspace_commit": pre["workspace_commit"],
                    "config_digest": pre["config_digest"],
                    "source_inputs_sha256": pre["source_inputs_sha256"],
                }
            )
        report: dict[str, Any] = {
            "schema_version": "rootyard/rubicon-mixed-workload/v1",
            "issue": "#164",
            "measurement_kind": "native_execution",
            "simulated": False,
            "seed": config.seed,
            "source": source_obj,
            "binary": binary_obj,
            "tools": {"git": pre["git_version"], "postgres": f"PostgreSQL {pg_ver}", "psql": pre["psql_version"]},
            "hardware": {"logical_cpus": pre["logical_cpus"], "machine": platform.machine(), "kernel": platform.release()},
            "topology": _format_topology(pre["tiers"], pre["s3_scheme"], pre["s3_is_loopback"], s3_proxy is not None),
            "workload_scope": {
                "cross_repo_overlap": "6 barrier-synchronized independent-ref pushes across 6 distinct repositories",
                "same_repo_overlap": "3 barrier-synchronized independent-ref pushes on one shared repository alongside read/Browse and PG SELECT queries",
                "maintenance": "read_only_pg_pack_snapshot_inspection_select (no background compaction/repack or physical Blob GC in serve-blob)",
                "temp_disk_scope": "tier_dir recursive bytes (server ROOTYARD_SCRATCH_DIR + client git clones/worktrees)",
            },
            "tiers": tiers_out,
            "scaling_comparison": _analyze_scaling(tiers_out, pre["tier_notes"]),
            "limitations": [
                "Single Linux host sharing one PostgreSQL instance and one S3-compatible provider; not multi-host HA failover (see #157).",
                "GitHub Rubicon's 7200 pushes/s external figure is not a Rootyard SLA target; self-measured baselines reflect this host and workload.",
                "Maintenance traffic runs read-only PostgreSQL pack/snapshot/operations inspection SELECT queries only; serve-blob runs no background compaction/repack.",
                "Cold reads follow service restart with empty ROOTYARD_SCRATCH_DIR only; provider/OS cache state is not reset or observed.",
                "Physical Blob deletion/GC is disabled; coexisting_pack_bytes reflects retained registered artifacts with zero physical storage savings claimed.",
            ],
        }
        validate_report(report, secrets=secrets)
        out_path = Path(config.report)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        return report
    except Exception as exc:
        msg = redact_text(exc, secrets) or type(exc).__name__
        tb = redact_text(traceback.format_exc(), secrets)
        tb_tail = tb[-2500:] if len(tb) > 2500 else tb
        if config.report:
            try:
                diag_path = Path(config.report).parent / "failure-diagnostics.log"
                diag_path.parent.mkdir(parents=True, exist_ok=True)
                lines = [f"error: {type(exc).__name__}: {msg}", tb]
                for log_p in sorted(work_root.glob("tier-*/serve-blob-*.log")):
                    raw_log = log_p.read_bytes()[-8192:].decode("utf-8", errors="replace")
                    lines.append(f"--- {log_p.parent.name}/{log_p.name} ---")
                    lines.append(redact_text(raw_log, secrets))
                diag_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            except Exception:
                pass
        raise RuntimeError(f"{type(exc).__name__}: {msg}\n{tb_tail}") from None
    finally:
        if s3_proxy is not None:
            s3_proxy.stop()
        if schema_created:
            subprocess.run(["psql", "--dbname", pre["pg_base"], "-X", "-c", f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'], env=run_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if not config.keep:
            shutil.rmtree(work_root, ignore_errors=True)
