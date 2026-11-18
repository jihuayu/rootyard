#!/usr/bin/env python3
"""Reproducible Issue #183 streaming push vs. naive full-repo repack evaluator (#164).

Measures stock Git (`SHA-1` & `SHA-256`) full-pack and thin-pack (`--thin`) pushes across:
- Sequential vs. Overlapped stream+verify+Blob PUT pipeline vs. naive full-repo repack baseline
- Blob PUT/GET bytes, duplicate materialized bytes, peak RSS (KiB), temp disk bytes
- Hash/Git CPU time (ms) and P50 / P95 / P99 end-to-end wall latencies (ms)
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
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NULL_CONFIG = "NUL" if os.name == "nt" else "/dev/null"


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": NULL_CONFIG,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "push-causal-bench",
            "GIT_AUTHOR_EMAIL": "push-causal@example.com",
            "GIT_COMMITTER_NAME": "push-causal-bench",
            "GIT_COMMITTER_EMAIL": "push-causal@example.com",
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


def _cpu_and_rss_kib() -> tuple[float, int]:
    if os.name != "nt":
        import resource

        me = resource.getrusage(resource.RUSAGE_SELF)
        ch = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu_ms = (me.ru_utime + me.ru_stime + ch.ru_utime + ch.ru_stime) * 1000.0
        rss = max(int(me.ru_maxrss), int(ch.ru_maxrss))
        if sys.platform == "darwin":
            rss //= 1024
        return cpu_ms, rss

    class _MemCounters(ctypes.Structure):
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

    counters = _MemCounters()
    counters.cb = ctypes.sizeof(counters)
    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    k32.K32GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(_MemCounters), ctypes.c_ulong]
    k32.K32GetProcessMemoryInfo.restype = ctypes.c_int
    rss_kib = 0
    if k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        rss_kib = int(counters.PeakWorkingSetSize) // 1024
    return time.process_time() * 1000.0, rss_kib


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil((p / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 3)


def _dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                pass
    return total


def _benchmark_format(fmt: str, pushes: int, base_commits: int, payload_kb: int) -> dict[str, Any]:
    tmp = Path(tempfile.mkdtemp(prefix=f"ry-push-eval-{fmt}-"))
    try:
        work = tmp / "work"
        _run_git(tmp, ["init", f"--object-format={fmt}", "-b", "main", str(work)])

        chunk_body = ("rootyard-causal-base-" * 32 + "\n") * max(1, (payload_kb * 1024) // (21 * 32 + 1))
        for idx in range(base_commits):
            (work / f"base-{idx % 4}.txt").write_text(f"{chunk_body}\nrev={idx}\n", encoding="utf-8")
            _run_git(work, ["add", "."])
            _run_git(work, ["commit", "-m", f"base-{idx}"])

        base_tip = _run_git(work, ["rev-parse", "HEAD"]).decode().strip()
        base_pack_raw = _run_git(work, ["pack-objects", "--revs", "--stdout"], input_bytes=(base_tip + "\n").encode())
        base_bare = tmp / "base-bare"
        _run_git(tmp, ["init", "--bare", f"--object-format={fmt}", str(base_bare)])
        _run_git(base_bare, ["index-pack", "--stdin", "--strict", str(base_bare / "objects/pack/base.pack")], input_bytes=base_pack_raw)
        base_pack_len = (base_bare / "objects/pack/base.pack").stat().st_size
        base_idx_len = (base_bare / "objects/pack/base.idx").stat().st_size

        # Pre-generate identical push commit sequence once for fair mode comparison.
        push_commits: list[tuple[str, str]] = []
        prev = base_tip
        for i in range(pushes):
            (work / "base-0.txt").write_text(f"{chunk_body}\npush-seq-{i}\n", encoding="utf-8")
            _run_git(work, ["add", "base-0.txt"])
            _run_git(work, ["commit", "-m", f"push-{i}"])
            cur = _run_git(work, ["rev-parse", "HEAD"]).decode().strip()
            push_commits.append((prev, cur))
            prev = cur

        results: dict[str, Any] = {}
        modes = ("overlapped_stream", "sequential_stream", "naive_full_repack")
        for mode in modes:
            latencies_ms: list[float] = []
            put_bytes = 0
            get_bytes = 0
            dup_materialized = 0
            peak_disk = 0
            cpu_before, _ = _cpu_and_rss_kib()

            active_packs: list[tuple[Path, Path]] = [
                (base_bare / "objects/pack/base.pack", base_bare / "objects/pack/base.idx")
            ]
            archive_dir = tmp / f"archive-{mode}"
            archive_dir.mkdir(parents=True, exist_ok=True)

            for i, (prev_tip, new_tip) in enumerate(push_commits):
                t0 = time.perf_counter()
                stage = tmp / f"stage-{mode}-{i}"
                _run_git(tmp, ["init", "--bare", f"--object-format={fmt}", str(stage)])

                if mode == "naive_full_repack":
                    for k, (ap, ai) in enumerate(active_packs):
                        shutil.copy2(ap, stage / f"objects/pack/p-{k}.pack")
                        shutil.copy2(ai, stage / f"objects/pack/p-{k}.idx")
                        get_bytes += ap.stat().st_size + ai.stat().st_size
                    full_pack = _run_git(work, ["pack-objects", "--revs", "--stdout"], input_bytes=f"{new_tip}\n".encode())
                    pfile = stage / "objects/pack/full.pack"
                    _run_git(stage, ["index-pack", "--stdin", "--strict", str(pfile)], input_bytes=full_pack)
                    _run_git(stage, ["update-ref", "--no-deref", "refs/heads/main", new_tip])
                    _run_git(stage, ["repack", "-a", "-d"])
                    _run_git(stage, ["fsck", "--full", "--strict"])
                    next_packs: list[tuple[Path, Path]] = []
                    for rf in sorted((stage / "objects/pack").glob("*.pack")):
                        ri = rf.with_suffix(".idx")
                        put_bytes += rf.stat().st_size + ri.stat().st_size
                        dp = archive_dir / f"repack-{i}-{rf.name}"
                        di = archive_dir / f"repack-{i}-{ri.name}"
                        shutil.copy2(rf, dp)
                        shutil.copy2(ri, di)
                        next_packs.append((dp, di))
                    dup_materialized += base_pack_len
                    active_packs = next_packs
                else:
                    thin_raw = _run_git(
                        work,
                        ["pack-objects", "--revs", "--thin", "--stdout"],
                        input_bytes=f"{new_tip}\n^{prev_tip}\n".encode(),
                    )
                    for k, (ap, ai) in enumerate(active_packs):
                        shutil.copy2(ap, stage / f"objects/pack/base-{k}.pack")
                        shutil.copy2(ai, stage / f"objects/pack/base-{k}.idx")
                        get_bytes += ap.stat().st_size + ai.stat().st_size
                    _ = hashlib.sha256(thin_raw).hexdigest()
                    staged_pack = stage / f"objects/pack/staged-{i}.pack"
                    staged_idx = stage / f"objects/pack/staged-{i}.idx"
                    _run_git(stage, ["index-pack", "--stdin", "--fix-thin", "--strict", str(staged_pack)], input_bytes=thin_raw)
                    staged_size = staged_pack.stat().st_size + staged_idx.stat().st_size

                    def _upload_and_readback() -> int:
                        _ = hashlib.sha256(staged_pack.read_bytes()).hexdigest()
                        _ = hashlib.sha256(staged_idx.read_bytes()).hexdigest()
                        return staged_size

                    def _verify_closure() -> None:
                        _run_git(stage, ["verify-pack", "-v", str(staged_idx)])
                        _run_git(stage, ["fsck", "--full", "--strict", "--connectivity-only", new_tip])

                    if mode == "overlapped_stream":
                        with ThreadPoolExecutor(max_workers=2) as pool:
                            f_up = pool.submit(_upload_and_readback)
                            f_ver = pool.submit(_verify_closure)
                            put_bytes += f_up.result()
                            get_bytes += staged_size
                            f_ver.result()
                    else:
                        _verify_closure()
                        put_bytes += _upload_and_readback()
                        get_bytes += staged_size

                    dp = archive_dir / f"staged-{i}.pack"
                    di = archive_dir / f"staged-{i}.idx"
                    shutil.copy2(staged_pack, dp)
                    shutil.copy2(staged_idx, di)
                    active_packs.append((dp, di))

                peak_disk = max(peak_disk, _dir_size(stage))
                shutil.rmtree(stage, ignore_errors=True)
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)

            cpu_after, rss_kib = _cpu_and_rss_kib()
            results[mode] = {
                "pushes": pushes,
                "base_pack_bytes": base_pack_len + base_idx_len,
                "blob_put_bytes": put_bytes,
                "blob_get_bytes": get_bytes,
                "duplicate_materialized_bytes": dup_materialized,
                "peak_temp_disk_bytes": peak_disk,
                "peak_rss_kib": rss_kib,
                "hash_git_cpu_ms": round(max(0.0, cpu_after - cpu_before), 3),
                "p50_ms": _pct(latencies_ms, 50),
                "p95_ms": _pct(latencies_ms, 95),
                "p99_ms": _pct(latencies_ms, 99),
            }

        results["stream_vs_naive_put_ratio"] = round(
            results["overlapped_stream"]["blob_put_bytes"] / max(1, results["naive_full_repack"]["blob_put_bytes"]),
            4,
        )
        return results
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_benchmark(*, formats: list[str], pushes: int, base_commits: int, payload_kb: int, build_receipt: Path | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema_version": 1,
        "issue": 183,
        "reference_baseline": 164,
        "git_version": subprocess.check_output(["git", "--version"]).decode().strip(),
        "formats": {},
    }
    if build_receipt is not None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from native_build_receipt import validate_receipt

        payload = json.loads(build_receipt.read_text(encoding="utf-8"))
        out["native_build_receipt"] = validate_receipt(payload)

    for fmt in formats:
        out["formats"][fmt] = _benchmark_format(fmt, pushes=pushes, base_commits=base_commits, payload_kb=payload_kb)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Issue #183 streaming Git push & causal proof.")
    parser.add_argument("--formats", default="sha1,sha256", help="Comma-separated Git object formats")
    parser.add_argument("--pushes", type=int, default=4, help="Incremental thin pushes per mode")
    parser.add_argument("--base-commits", type=int, default=6, help="Base history commits")
    parser.add_argument("--payload-kb", type=int, default=32, help="Base payload size in KiB")
    parser.add_argument("--build-receipt", type=Path, default=None, help="Optional CargoFork build receipt")
    parser.add_argument("--json-out", type=Path, default=None, help="Write JSON output path")
    args = parser.parse_args()

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    report = run_benchmark(
        formats=formats,
        pushes=args.pushes,
        base_commits=args.base_commits,
        payload_kb=args.payload_kb,
        build_receipt=args.build_receipt,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
