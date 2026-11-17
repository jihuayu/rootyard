#!/usr/bin/env python3
"""Reproducible capacity benchmark evaluator for Issue #177 (Blob-only Pando).

Measures multi-pack streaming growth across <= 16 and > 16 pack counts for both
SHA-1 and SHA-256 repositories with interleaved no-new-pack ref updates,
bounded worker queues, and no-delete compaction using real stock Git.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

try:
    import resource
except ImportError:  # Windows
    resource = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
NULL_CONFIG = "NUL" if os.name == "nt" else "/dev/null"


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": NULL_CONFIG,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "pando-cap-bench",
            "GIT_AUTHOR_EMAIL": "pando-cap@example.com",
            "GIT_COMMITTER_NAME": "pando-cap-bench",
            "GIT_COMMITTER_EMAIL": "pando-cap@example.com",
        }
    )
    return env


def _run_git(repo: Path, args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "--no-replace-objects", "-C", str(repo), *args],
        input=input_bytes,
        capture_output=True,
        env=_git_env(),
        check=True,
    )
    return proc.stdout


def _peak_rss_kib() -> int:
    if resource is not None:
        self_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        child_rss = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        if sys.platform == "darwin":
            return max(self_rss, child_rss) // 1024
        return max(self_rss, child_rss)

    class _ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
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
    counters.cb = ctypes.sizeof(counters)
    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    k32.K32GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ProcessMemoryCounters), ctypes.c_ulong]
    k32.K32GetProcessMemoryInfo.restype = ctypes.c_int
    handle = k32.GetCurrentProcess()
    if k32.K32GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        return int(counters.PeakWorkingSetSize) // 1024
    return 0


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 3)


def _dir_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for root, _, files in os.walk(path):
        for name in files:
            total += (Path(root) / name).stat().st_size
    return total


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _source_binding(binary: Path | None, build_receipt: Path | None) -> dict[str, Any]:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    tracked = sorted(
        [
            ROOT / "src" / "blob_store" / "capacity_contract.rs",
            *(ROOT / "src" / "blob_store" / "capacity_contract").glob("*.rs"),
            ROOT / "scripts" / "eval_pando_capacity.py",
        ]
    )
    hashes = {p.relative_to(ROOT).as_posix(): _sha256_file(p) for p in tracked if p.is_file()}
    binding: dict[str, Any] = {
        "source_commit": commit,
        "source_dirty": dirty,
        "source_files_sha256": hashes,
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "platform": f"{sys.platform}/{platform.machine()}",
        "receipt_verified": False,
    }
    if build_receipt is not None:
        scripts_dir = str(ROOT / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        import native_build_receipt  # noqa: E402

        raw = build_receipt.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        validated = native_build_receipt.validate_receipt(
            payload,
            source_root=ROOT,
            receipt_path=build_receipt,
            receipt_sha256=hashlib.sha256(raw).hexdigest(),
            binary_path=binary,
            expected_commit=commit,
            verify_source_files=True,
        )
        binding["receipt_verified"] = True
        binding["receipt_schema"] = validated.schema
        binding["receipt_sha256"] = validated.receipt_sha256
        binding["binary_sha256"] = validated.binary_sha256
    return binding


def _verify_pack_window(
    work_dir: Path,
    fmt: str,
    packs: list[tuple[Path, Path]],
    refs: dict[str, str],
    full_fsck: bool,
) -> tuple[int, int]:
    bare = work_dir / "verify.git"
    _run_git(work_dir, ["init", "--bare", "--quiet", f"--object-format={fmt}", str(bare)])
    get_bytes = 0
    peak_scratch = _dir_bytes(work_dir)
    for idx, (pack_src, idx_src) in enumerate(packs):
        p_tmp = work_dir / f"in-{idx:04}.pack"
        i_tmp = work_dir / f"in-{idx:04}.idx"
        shutil.copyfile(pack_src, p_tmp)
        shutil.copyfile(idx_src, i_tmp)
        get_bytes += p_tmp.stat().st_size + i_tmp.stat().st_size
        peak_scratch = max(peak_scratch, _dir_bytes(work_dir))
        _run_git(bare, ["verify-pack", str(i_tmp)])
        _run_git(bare, ["-c", "pack.writeReverseIndex=false", "index-pack", "--stdin"], input_bytes=p_tmp.read_bytes())
        p_tmp.unlink()
        i_tmp.unlink()
        peak_scratch = max(peak_scratch, _dir_bytes(work_dir))
    for name, oid in refs.items():
        _run_git(bare, ["update-ref", "--no-deref", name, oid])
    fsck_flag = ["--full", "--strict"] if full_fsck else ["--connectivity-only", "--no-dangling"]
    _run_git(bare, ["fsck", *fsck_flag, "--no-progress"])
    peak_scratch = max(peak_scratch, _dir_bytes(work_dir))
    return get_bytes, peak_scratch


def _compact_frontier(
    work_dir: Path,
    blob_dir: Path,
    fmt: str,
    packs: list[tuple[Path, Path]],
    refs: dict[str, str],
    compact_idx: int,
) -> tuple[tuple[Path, Path], int, int, int]:
    bare = work_dir / "compact.git"
    _run_git(work_dir, ["init", "--bare", "--quiet", f"--object-format={fmt}", str(bare)])
    get_bytes = 0
    for idx, (pack_src, idx_src) in enumerate(packs):
        p_tmp = work_dir / f"c-{idx:04}.pack"
        i_tmp = work_dir / f"c-{idx:04}.idx"
        shutil.copyfile(pack_src, p_tmp)
        shutil.copyfile(idx_src, i_tmp)
        get_bytes += p_tmp.stat().st_size + i_tmp.stat().st_size
        _run_git(bare, ["-c", "pack.writeReverseIndex=false", "index-pack", "--stdin"], input_bytes=p_tmp.read_bytes())
        p_tmp.unlink()
        i_tmp.unlink()
    for name, oid in refs.items():
        _run_git(bare, ["update-ref", "--no-deref", name, oid])
    pre = sorted(set(_run_git(bare, ["rev-list", "--objects", "--all"]).decode().splitlines()))
    _run_git(bare, ["-c", "pack.writeReverseIndex=false", "repack", "-a", "-d", "--no-write-bitmap-index"])
    _run_git(bare, ["fsck", "--full", "--strict", "--no-progress"])
    post = sorted(set(_run_git(bare, ["rev-list", "--objects", "--all"]).decode().splitlines()))
    if pre != post:
        raise RuntimeError("compaction changed object closure")
    pack_dir = bare / "objects" / "pack"
    out_p = next(pack_dir.glob("*.pack"))
    out_i = next(pack_dir.glob("*.idx"))
    dst_p = blob_dir / f"compacted-{compact_idx:03}.pack"
    dst_i = blob_dir / f"compacted-{compact_idx:03}.idx"
    shutil.copyfile(out_p, dst_p)
    shutil.copyfile(out_i, dst_i)
    put_bytes = dst_p.stat().st_size + dst_i.stat().st_size
    peak_scratch = _dir_bytes(work_dir)
    return (dst_p, dst_i), get_bytes, put_bytes, peak_scratch


def _run_case(pack_count: int, fmt: str, compact_trigger: int, max_workers: int, max_queue: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"pando-cap-{fmt}-{pack_count}-") as tmp:
        root = Path(tmp)
        seed_repo = root / "seed"
        blob_dir = root / "blob"
        blob_dir.mkdir(parents=True)
        _run_git(root, ["init", f"--object-format={fmt}", "--initial-branch=main", str(seed_repo)])

        # Pre-seed incremental pack artifacts for deterministic commits.
        commits: list[tuple[str, Path, Path]] = []
        prev_oid = ""
        for idx in range(1, pack_count + 1):
            (seed_repo / "stream.txt").write_text(f"step-{idx}\n", encoding="utf-8")
            _run_git(seed_repo, ["add", "."])
            _run_git(seed_repo, ["commit", "-m", f"step {idx}"])
            oid = _run_git(seed_repo, ["rev-parse", "HEAD"]).decode().strip()
            rng = oid if idx == 1 else f"{prev_oid}..{oid}"
            objs = _run_git(seed_repo, ["rev-list", "--objects", rng]).decode()
            oid_lines = "".join(line.split()[0] + "\n" for line in objs.splitlines() if line.strip()).encode()
            p_dir = root / f"gen-{idx:03}"
            p_dir.mkdir()
            _run_git(seed_repo, ["-c", "pack.writeReverseIndex=false", "pack-objects", "-q", str(p_dir / "inc")], input_bytes=oid_lines)
            commits.append((oid, next(p_dir.glob("*.pack")), next(p_dir.glob("*.idx"))))
            prev_oid = oid

        active_packs: list[tuple[Path, Path]] = []
        retained_old_packs: list[tuple[Path, Path]] = []
        acked_refs: dict[str, str] = {}
        latencies_ms: list[float] = []
        queue_waits_ms: list[float] = []
        blob_put_bytes = 0
        blob_get_bytes = 0
        peak_scratch_bytes = 0
        compactions = 0
        no_new_pack_ops = 0
        sem = threading.BoundedSemaphore(max_workers)
        q_lock = threading.Lock()
        queued = 0
        wall_t0 = time.perf_counter()

        def execute_verify(step_idx: int, frontier_snapshot: list[tuple[Path, Path]], refs_snapshot: dict[str, str], full: bool = False) -> tuple[int, int, float, float]:
            nonlocal queued
            enq_t0 = time.perf_counter()
            with q_lock:
                if queued >= max_queue:
                    raise queue.Full("bounded queue full")
                queued += 1
            with sem:
                with q_lock:
                    queued -= 1
                wait_ms = (time.perf_counter() - enq_t0) * 1000.0
                v_dir = root / f"view-{step_idx:05}"
                v_dir.mkdir(exist_ok=True)
                g_b, s_b = _verify_pack_window(v_dir, fmt, frontier_snapshot, refs_snapshot, full)
                shutil.rmtree(v_dir, ignore_errors=True)
                op_ms = (time.perf_counter() - enq_t0) * 1000.0
                return g_b, s_b, wait_ms, op_ms

        with ThreadPoolExecutor(max_workers=max_workers * 2) as pool:
            for idx, (oid, p_src, i_src) in enumerate(commits, start=1):
                if len(active_packs) >= compact_trigger:
                    compactions += 1
                    c_dir = root / f"compact-{compactions:03}"
                    c_dir.mkdir()
                    new_pack, c_get, c_put, c_scratch = _compact_frontier(c_dir, blob_dir, fmt, active_packs, acked_refs, compactions)
                    shutil.rmtree(c_dir, ignore_errors=True)
                    retained_old_packs.extend(active_packs)
                    active_packs = [new_pack]
                    blob_get_bytes += c_get
                    blob_put_bytes += c_put
                    peak_scratch_bytes = max(peak_scratch_bytes, c_scratch)

                dst_p = blob_dir / f"pack-{idx:03}.pack"
                dst_i = blob_dir / f"pack-{idx:03}.idx"
                shutil.copyfile(p_src, dst_p)
                shutil.copyfile(i_src, dst_i)
                blob_put_bytes += dst_p.stat().st_size + dst_i.stat().st_size
                active_packs.append((dst_p, dst_i))
                acked_refs["refs/heads/main"] = oid
                g_b, s_b, wait_ms, op_ms = execute_verify(idx, list(active_packs), dict(acked_refs))
                blob_get_bytes += g_b
                peak_scratch_bytes = max(peak_scratch_bytes, s_b)
                queue_waits_ms.append(wait_ms)
                latencies_ms.append(op_ms)

                if idx % 4 == 0:
                    no_new_pack_ops += 1
                    acked_refs[f"refs/tags/v{idx}"] = oid
                    futs = [
                        pool.submit(execute_verify, idx * 100 + w, list(active_packs), dict(acked_refs))
                        for w in range(max_workers * 2)
                    ]
                    for fut in futs:
                        g_b, s_b, wait_ms, op_ms = fut.result()
                        blob_get_bytes += g_b
                        peak_scratch_bytes = max(peak_scratch_bytes, s_b)
                        queue_waits_ms.append(wait_ms)
                        latencies_ms.append(op_ms)

        final_dir = root / "final-view"
        final_dir.mkdir()
        fg, fs_b = _verify_pack_window(final_dir, fmt, active_packs, acked_refs, True)
        blob_get_bytes += fg
        peak_scratch_bytes = max(peak_scratch_bytes, fs_b)
        total_wall_s = max(1e-6, time.perf_counter() - wall_t0)
        total_ops = len(latencies_ms)
        active_bytes = sum(p.stat().st_size + i.stat().st_size for p, i in active_packs)
        retained_bytes = sum(p.stat().st_size + i.stat().st_size for p, i in retained_old_packs)
        return {
            "object_format": fmt,
            "target_packs": pack_count,
            "no_new_pack_updates": no_new_pack_ops,
            "total_ops": total_ops,
            "compactions_completed": compactions,
            "active_frontier_final": len(active_packs),
            "closure_verified": True,
            "throughput_ops_per_sec": round(total_ops / total_wall_s, 3),
            "latency_ms": {
                "p50": _percentile(latencies_ms, 50),
                "p95": _percentile(latencies_ms, 95),
                "p99": _percentile(latencies_ms, 99),
                "max": round(max(latencies_ms), 3),
            },
            "queue_wait_ms": {
                "p50": _percentile(queue_waits_ms, 50),
                "p95": _percentile(queue_waits_ms, 95),
                "total": round(sum(queue_waits_ms), 3),
            },
            "peak_rss_kib": _peak_rss_kib(),
            "peak_scratch_disk_bytes": peak_scratch_bytes,
            "blob_bytes": {
                "put_total": blob_put_bytes,
                "get_total": blob_get_bytes,
                "active_serving_pack_bytes": active_bytes,
                "retained_old_pack_bytes": retained_bytes,
                "total_physical_blob_bytes": active_bytes + retained_bytes,
            },
        }


def run_benchmark(
    pack_counts: list[int],
    formats: list[str],
    *,
    compact_trigger: int = 12,
    max_workers: int = 2,
    max_queue: int = 16,
    binary: Path | None = None,
    build_receipt: Path | None = None,
) -> dict[str, Any]:
    rows = [
        _run_case(count, fmt, compact_trigger, max_workers, max_queue)
        for count in pack_counts
        for fmt in formats
    ]
    return {
        "issue": 177,
        "sla_policy": "observed_baseline_only_no_production_sla",
        "target_calibration_issue": 164,
        "binding": _source_binding(binary, build_receipt),
        "parameters": {
            "pack_counts": pack_counts,
            "formats": formats,
            "compact_trigger": compact_trigger,
            "max_workers": max_workers,
            "max_queue": max_queue,
        },
        "results": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Issue #177 Pando capacity growth.")
    parser.add_argument("--pack-counts", default="8,16,24,32")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--compact-trigger", type=int, default=12)
    parser.add_argument("--max-workers", type=int, default=2)
    parser.add_argument("--max-queue", type=int, default=16)
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--build-receipt", type=Path, default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)
    counts = [int(x.strip()) for x in args.pack_counts.split(",") if x.strip()]
    formats = [x.strip() for x in args.formats.split(",") if x.strip()]
    report = run_benchmark(
        counts,
        formats,
        compact_trigger=args.compact_trigger,
        max_workers=args.max_workers,
        max_queue=args.max_queue,
        binary=args.binary,
        build_receipt=args.build_receipt,
    )
    rendered = json.dumps(report, indent=2)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
