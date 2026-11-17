#!/usr/bin/env python3
"""Reproducible evaluator and benchmark for Issue #163 Rubicon disposable replica cache."""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

WORKLOAD_PROFILES: dict[str, dict[str, int]] = {
    "small": {"base_commits": 10, "delta_commits": 4, "payload_bytes": 1024, "warm_iters": 15},
    "medium": {"base_commits": 28, "delta_commits": 10, "payload_bytes": 4096, "warm_iters": 15},
}


def _git(cwd: Path, args: list[str], env_extra: dict[str, str] | None = None) -> str:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Eval Bot",
            "GIT_AUTHOR_EMAIL": "eval@rootyard.local",
            "GIT_COMMITTER_NAME": "Eval Bot",
            "GIT_COMMITTER_EMAIL": "eval@rootyard.local",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int((pct / 100.0) * (len(ordered) - 1) + 0.5)))
    return round(ordered[idx], 3)


def _peak_rss_bytes() -> int:
    if os.name != "nt":
        import resource

        ru_self = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        ru_child = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        scale = 1 if sys.platform == "darwin" else 1024
        return int(max(ru_self, ru_child) * scale)

    import ctypes
    from ctypes import wintypes

    class _ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = _ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(_ProcessMemoryCounters)
    k32 = ctypes.windll.kernel32
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessMemoryCounters), wintypes.DWORD]
    k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
    proc = k32.GetCurrentProcess()
    if k32.K32GetProcessMemoryInfo(proc, ctypes.byref(counters), counters.cb):
        return int(counters.PeakWorkingSetSize)
    return 0


def _seed_two_epoch_packs(case_dir: Path, fmt: str, spec: dict[str, int]) -> dict[str, Any]:
    work = case_dir / "work"
    bare = case_dir / "authoritative.git"
    blob_dir = case_dir / "blob-store"
    blob_dir.mkdir(parents=True, exist_ok=True)
    _git(case_dir, ["init", f"--object-format={fmt}", "--initial-branch=main", str(work)])
    _git(case_dir, ["init", "--bare", f"--object-format={fmt}", str(bare)])

    payload = b"rubicon-replica-cache-" * max(1, spec["payload_bytes"] // 22)
    for i in range(spec["base_commits"]):
        p = work / f"base_{i % 4}.txt"
        p.write_bytes(payload + f"-base-{i}\n".encode("utf-8"))
        _git(work, ["add", "."])
        _git(work, ["commit", "-q", "-m", f"base commit {i}"])
    tip_v1 = _git(work, ["rev-parse", "HEAD"])
    _git(work, ["push", "-q", str(bare), "refs/heads/main:refs/heads/main"])
    _git(bare, ["repack", "-a", "-d", "-q"])

    base_packs = sorted((bare / "objects" / "pack").glob("*.pack"))
    if len(base_packs) != 1:
        raise RuntimeError(f"Expected 1 base pack, got {len(base_packs)}")
    base_pack = base_packs[0]
    base_idx = base_pack.with_suffix(".idx")
    packs_v1 = _stage_packs_to_blob([(base_pack, base_idx, "base")], blob_dir)

    for j in range(spec["delta_commits"]):
        p = work / f"delta_{j % 3}.txt"
        p.write_bytes(payload + f"-delta-{j}\n".encode("utf-8"))
        _git(work, ["add", "."])
        _git(work, ["commit", "-q", "-m", f"delta commit {j}"])
    tip_v2 = _git(work, ["rev-parse", "HEAD"])
    _git(work, ["push", "-q", str(bare), "refs/heads/main:refs/heads/main"])
    _git(bare, ["repack", "-d", "-q"])

    delta_packs = sorted(p for p in (bare / "objects" / "pack").glob("*.pack") if p.name != base_pack.name)
    if not delta_packs:
        raise RuntimeError("Expected incremental delta pack in v2")
    delta_specs = [(p, p.with_suffix(".idx"), f"delta_{idx}") for idx, p in enumerate(delta_packs)]
    packs_v2 = packs_v1 + _stage_packs_to_blob(delta_specs, blob_dir)
    return {
        "blob_dir": blob_dir,
        "fmt": fmt,
        "tip_v1": tip_v1,
        "tip_v2": tip_v2,
        "packs_v1": packs_v1,
        "packs_v2": packs_v2,
    }


def _stage_packs_to_blob(pairs: list[tuple[Path, Path, str]], blob_dir: Path) -> list[dict[str, Any]]:
    staged: list[dict[str, Any]] = []
    for pack_p, idx_p, label in pairs:
        b_pack = blob_dir / pack_p.name
        b_idx = blob_dir / idx_p.name
        shutil.copy2(pack_p, b_pack)
        shutil.copy2(idx_p, b_idx)
        staged.append(
            {
                "label": label,
                "pack_name": pack_p.name,
                "idx_name": idx_p.name,
                "pack_sha256": _sha256_file(b_pack),
                "idx_sha256": _sha256_file(b_idx),
                "pack_bytes": b_pack.stat().st_size,
                "idx_bytes": b_idx.stat().st_size,
            }
        )
    return staged


def _materialize_two_layer(
    blob_dir: Path,
    replica_dir: Path,
    fmt: str,
    packs: list[dict[str, Any]],
    refs: dict[str, str],
    view_key: str,
) -> dict[str, Any]:
    pack_layer = replica_dir / "packs"
    view_dir = replica_dir / "views" / view_key
    pack_layer.mkdir(parents=True, exist_ok=True)
    if view_dir.exists():
        shutil.rmtree(view_dir)

    t0 = time.perf_counter()
    blob_gets = 0
    blob_get_bytes = 0
    reused_packs = 0
    replicated_bytes = 0
    verify_s = 0.0

    for spec in packs:
        for kind in ("pack", "idx"):
            name = spec[f"{kind}_name"]
            expected_sha = spec[f"{kind}_sha256"]
            cached = pack_layer / name
            vt0 = time.perf_counter()
            if cached.exists() and _sha256_file(cached) == expected_sha:
                verify_s += time.perf_counter() - vt0
                if kind == "pack":
                    reused_packs += 1
            else:
                src = blob_dir / name
                data = src.read_bytes()
                blob_gets += 1
                blob_get_bytes += len(data)
                replicated_bytes += len(data)
                actual = hashlib.sha256(data).hexdigest()
                if actual != expected_sha:
                    raise RuntimeError(f"Digest mismatch for {name}")
                cached.write_bytes(data)
                verify_s += time.perf_counter() - vt0

    tmp_view = replica_dir / "views" / f".tmp-{view_key}"
    if tmp_view.exists():
        shutil.rmtree(tmp_view)
    _git(replica_dir, ["init", "--bare", f"--object-format={fmt}", str(tmp_view)])
    view_pack_dir = tmp_view / "objects" / "pack"
    view_pack_dir.mkdir(parents=True, exist_ok=True)
    for spec in packs:
        for kind in ("pack", "idx"):
            name = spec[f"{kind}_name"]
            shutil.copyfile(pack_layer / name, view_pack_dir / name)
            replicated_bytes += (pack_layer / name).stat().st_size
    (tmp_view / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8", newline="\n")
    packed_lines = "".join(f"{oid} {ref}\n" for ref, oid in sorted(refs.items()))
    (tmp_view / "packed-refs").write_text(
        f"# pack-refs with: peeled fully-peeled sorted\n{packed_lines}", encoding="utf-8", newline="\n"
    )
    tmp_view.replace(view_dir)
    total_ms = (time.perf_counter() - t0) * 1000.0
    _git(view_dir, ["fsck", "--full", "--strict"])
    return {
        "view_dir": str(view_dir),
        "materialize_ms": round(total_ms, 3),
        "verify_ms": round(verify_s * 1000.0, 3),
        "blob_get_count": blob_gets,
        "blob_get_bytes": blob_get_bytes,
        "reused_pack_count": reused_packs,
        "replicated_bytes": replicated_bytes,
    }


def _serve_verify_clone(view_dir: Path, work_dir: Path, expected_tip: str) -> float:
    t0 = time.perf_counter()
    if work_dir.exists():
        shutil.rmtree(work_dir)
    _git(view_dir.parent, ["clone", "-q", str(view_dir), str(work_dir)])
    tip = _git(work_dir, ["rev-parse", "HEAD"])
    if tip != expected_tip:
        raise RuntimeError(f"Clone tip mismatch: {tip} != {expected_tip}")
    _git(work_dir, ["fsck", "--full", "--strict"])
    return (time.perf_counter() - t0) * 1000.0


def _test_push_scratch_isolation(replica_dir: Path, view_dir: Path, expected_tip: str) -> dict[str, Any]:
    scratch = replica_dir / "scratch" / "push-isolated.git"
    shutil.copytree(view_dir, scratch)
    _git(scratch, ["update-ref", "refs/heads/scratch-only", expected_tip])
    scratch_bytes = sum(p.stat().st_size for p in scratch.rglob("*") if p.is_file())
    view_refs = _git(view_dir, ["for-each-ref", "--format=%(refname) %(objectname)"])
    shutil.rmtree(scratch)
    if "scratch-only" in view_refs:
        raise RuntimeError("Push scratch leaked mutable ref into shared read-only view")
    residual = sum(p.stat().st_size for p in (replica_dir / "scratch").rglob("*") if p.is_file())
    return {"scratch_peak_bytes": scratch_bytes, "scratch_residual_bytes": residual, "view_isolated": True}


def _benchmark_drr_fairness(concurrent_slots: int = 2) -> dict[str, Any]:
    """Run real threaded DRR admission under noisy-tenant flood + normal-tenant steady stream."""
    queues: dict[str, deque[tuple[str, float]]] = {"noisy": deque(), "normal": deque()}
    max_per_tenant = 6
    quantum = 2
    lock = threading.Lock()
    sem = threading.Semaphore(concurrent_slots)
    stats: dict[str, dict[str, Any]] = {
        "noisy": {"admitted": 0, "rejected": 0, "waits_ms": []},
        "normal": {"admitted": 0, "rejected": 0, "waits_ms": []},
    }
    order = deque(["noisy", "normal"])
    credits = {"noisy": 0, "normal": 0}
    stop = False

    def submit(tenant: str, work_s: float) -> None:
        with lock:
            q = queues[tenant]
            if len(q) >= max_per_tenant:
                stats[tenant]["rejected"] += 1
                return
            q.append((tenant, time.perf_counter()))
        while True:
            sem.acquire()
            picked = None
            with lock:
                for _ in range(len(order)):
                    cur = order[0]
                    order.rotate(-1)
                    if not queues[cur]:
                        credits[cur] = 0
                        continue
                    if credits[cur] <= 0:
                        credits[cur] += quantum
                    if credits[cur] > 0:
                        credits[cur] -= 1
                        picked = queues[cur].popleft()
                        ten, enqueued_at = picked
                        stats[ten]["waits_ms"].append((time.perf_counter() - enqueued_at) * 1000.0)
                        stats[ten]["admitted"] += 1
                        break
            if picked is not None:
                time.sleep(work_s)
                sem.release()
                return
            sem.release()
            time.sleep(0.0005)
            if stop:
                return

    threads: list[threading.Thread] = []
    for _ in range(24):
        threads.append(threading.Thread(target=submit, args=("noisy", 0.004)))
    for _ in range(6):
        threads.append(threading.Thread(target=submit, args=("normal", 0.002)))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    stop = True
    if stats["normal"]["admitted"] != 6 or stats["normal"]["rejected"] != 0 or stats["noisy"]["rejected"] == 0:
        raise RuntimeError(f"Fairness invariant violated: {stats}")
    return {
        "noisy_admitted": stats["noisy"]["admitted"],
        "noisy_rejected": stats["noisy"]["rejected"],
        "normal_admitted": stats["normal"]["admitted"],
        "normal_rejected": stats["normal"]["rejected"],
        "normal_wait_p50_ms": _percentile(stats["normal"]["waits_ms"], 50),
        "normal_wait_p95_ms": _percentile(stats["normal"]["waits_ms"], 95),
        "noisy_wait_p95_ms": _percentile(stats["noisy"]["waits_ms"], 95),
    }


def _worker_main(payload_json: str) -> int:
    req = json.loads(payload_json)
    mat = _materialize_two_layer(
        Path(req["blob_dir"]),
        Path(req["replica_dir"]),
        req["fmt"],
        req["packs"],
        {"refs/heads/main": req["expected_tip"]},
        "v2-subproc",
    )
    clone_ms = _serve_verify_clone(Path(mat["view_dir"]), Path(req["clone_dir"]), req["expected_tip"])
    print(json.dumps({**mat, "clone_ms": round(clone_ms, 3), "peak_rss_bytes": _peak_rss_bytes()}), flush=True)
    if req.get("hold_after_ready"):
        while True:
            time.sleep(0.05)
    return 0


def run_benchmark(profiles: list[str], formats: list[str]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="rubicon-replica-cache-eval-") as tmp:
        root = Path(tmp)
        for profile in profiles:
            spec = WORKLOAD_PROFILES[profile]
            for fmt in formats:
                cdir = root / f"{profile}-{fmt}"
                cdir.mkdir(parents=True, exist_ok=True)
                seed = _seed_two_epoch_packs(cdir, fmt, spec)
                r1 = cdir / "replica-hot"
                r2 = cdir / "replica-cold"

                cold_v1 = _materialize_two_layer(
                    seed["blob_dir"], r1, fmt, seed["packs_v1"], {"refs/heads/main": seed["tip_v1"]}, "v1"
                )
                cold_clone_ms = _serve_verify_clone(Path(cold_v1["view_dir"]), cdir / "clone-v1", seed["tip_v1"])

                incr_v2 = _materialize_two_layer(
                    seed["blob_dir"], r1, fmt, seed["packs_v2"], {"refs/heads/main": seed["tip_v2"]}, "v2"
                )
                incr_clone_ms = _serve_verify_clone(Path(incr_v2["view_dir"]), cdir / "clone-v2", seed["tip_v2"])

                warm_lat_ms: list[float] = []
                for _ in range(spec["warm_iters"]):
                    wt0 = time.perf_counter()
                    tip = _git(Path(incr_v2["view_dir"]), ["rev-parse", "refs/heads/main"])
                    if tip != seed["tip_v2"]:
                        raise RuntimeError("Warm tip mismatch")
                    warm_lat_ms.append((time.perf_counter() - wt0) * 1000.0)

                scratch_info = _test_push_scratch_isolation(r1, Path(incr_v2["view_dir"]), seed["tip_v2"])

                def _worker_args(replica_path: Path, tag: str, hold: bool) -> list[str]:
                    p_req = json.dumps(
                        {
                            "blob_dir": str(seed["blob_dir"]),
                            "replica_dir": str(replica_path),
                            "fmt": fmt,
                            "packs": seed["packs_v2"],
                            "expected_tip": seed["tip_v2"],
                            "clone_dir": str(cdir / f"subproc-clone-{tag}"),
                            "hold_after_ready": hold,
                        }
                    )
                    return [sys.executable, __file__, "--worker-json", p_req]

                hot_popen = subprocess.Popen(_worker_args(cdir / "proc-hot", "hot", True), stdout=subprocess.PIPE, text=True)
                assert hot_popen.stdout is not None
                hot_line = hot_popen.stdout.readline()
                hot_popen.stdout.close()
                if not hot_line:
                    raise RuntimeError(f"Hot worker failed before ready (rc={hot_popen.wait()})")
                hot_proc = json.loads(hot_line)
                hot_popen.kill()
                hot_exit_code = hot_popen.wait(timeout=5)
                kill_mech = "SIGKILL" if os.name == "posix" else "TerminateProcess"
                shutil.rmtree(cdir / "proc-hot")

                t_fail = time.perf_counter()
                cold_out = subprocess.check_output(_worker_args(r2, "cold", False), text=True)
                cold_proc = json.loads(cold_out.strip().splitlines()[-1])
                failover_total_ms = (time.perf_counter() - t_fail) * 1000.0

                rows.append(
                    {
                        "profile": profile,
                        "object_format": fmt,
                        "parity_verified": True,
                        "cold": {**cold_v1, "clone_verify_ms": round(cold_clone_ms, 3)},
                        "incremental_pack_reuse": {
                            **incr_v2,
                            "clone_verify_ms": round(incr_clone_ms, 3),
                            "base_packs_reused": incr_v2["reused_pack_count"],
                        },
                        "warm": {
                            "blob_get_count": 0,
                            "replicated_bytes": 0,
                            "p50_ms": _percentile(warm_lat_ms, 50),
                            "p95_ms": _percentile(warm_lat_ms, 95),
                            "p99_ms": _percentile(warm_lat_ms, 99),
                        },
                        "model_failover_two_process": {
                            "hot_node_killed": hot_exit_code != 0,
                            "hot_worker_terminated_via": kill_mech,
                            "hot_worker_exit_code": hot_exit_code,
                            "cold_rebuild_ms": cold_proc["materialize_ms"],
                            "failover_e2e_ms": round(failover_total_ms, 3),
                            "cold_blob_get_count": cold_proc["blob_get_count"],
                            "cold_blob_get_bytes": cold_proc["blob_get_bytes"],
                            "hot_rss_bytes": hot_proc["peak_rss_bytes"],
                            "cold_rss_bytes": cold_proc["peak_rss_bytes"],
                        },
                        "push_scratch": scratch_info,
                    }
                )

    fairness = _benchmark_drr_fairness()
    return {
        "issue": 163,
        "benchmark_kind": "python_reference_model_with_stock_git",
        "covers_rust_runtime_acceptance": False,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "peak_rss_bytes": _peak_rss_bytes(),
        "drr_thread_simulation": fairness,
        "results": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Issue #163 Rubicon replica cache.")
    parser.add_argument("--profiles", default="small,medium")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--worker-json", default=None)
    args = parser.parse_args(argv)
    if args.worker_json is not None:
        return _worker_main(args.worker_json)
    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    report = run_benchmark(profiles, formats)
    rendered = json.dumps(report, indent=2)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
