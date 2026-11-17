#!/usr/bin/env python3
"""Reproducible full vs incremental Merkle scan, chunk upload, and restore benchmark for Issue #181."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

CHUNK_SIZE_BYTES = 16 * 1024
DIR_DOMAIN = b"rootyard.merkle-sync.v1:dir-node\0"
FILE_DOMAIN = b"rootyard.merkle-sync.v1:file-entry\0"

PROFILES: dict[str, dict[str, int]] = {
    "small": {"subtrees": 8, "files_per_subtree": 6, "file_bytes": 24 * 1024, "iterations": 5},
    "medium": {"subtrees": 16, "files_per_subtree": 6, "file_bytes": 32 * 1024, "iterations": 5},
}


def _git_env() -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "rootyard-bench",
        "GIT_AUTHOR_EMAIL": "bench@example.com",
        "GIT_COMMITTER_NAME": "rootyard-bench",
        "GIT_COMMITTER_EMAIL": "bench@example.com",
    }
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    if "COMSPEC" in os.environ:
        env["COMSPEC"] = os.environ["COMSPEC"]
    return env


def _git(repo: Path, args: list[str]) -> str:
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C", str(repo), *args]
    res = subprocess.run(cmd, env=_git_env(), capture_output=True, text=True, check=True)
    return res.stdout.strip()


def _rmtree(path: Path) -> None:
    def _on_err(func: Any, target: str, _exc: Any) -> None:
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        func(target)

    if path.exists():
        kw = {"onexc": _on_err} if sys.version_info >= (3, 12) else {"onerror": _on_err}
        shutil.rmtree(path, **kw)


def _peak_rss_kib() -> int:
    try:
        import resource

        raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return raw // 1024 if sys.platform == "darwin" else raw
    except ImportError:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            class _MemCounters(ctypes.Structure):
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

            cnt = _MemCounters()
            cnt.cb = ctypes.sizeof(_MemCounters)
            k32 = ctypes.WinDLL("kernel32")
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
            proc = k32.GetCurrentProcess()
            if k32.K32GetProcessMemoryInfo(proc, ctypes.byref(cnt), cnt.cb):
                return int(cnt.PeakWorkingSetSize // 1024)
        return 0


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    idx = (len(ordered) - 1) * (pct / 100.0)
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return round(ordered[lo], 4)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (idx - lo), 4)


def _chunk_file(path: Path) -> tuple[str, list[tuple[str, bytes]], int]:
    data = path.read_bytes()
    file_hasher = hashlib.sha256()
    file_hasher.update(FILE_DOMAIN)
    chunks: list[tuple[str, bytes]] = []
    for off in range(0, max(1, len(data)), CHUNK_SIZE_BYTES):
        part = data[off : off + CHUNK_SIZE_BYTES]
        digest = hashlib.sha256(part).hexdigest()
        chunks.append((digest, part))
        file_hasher.update(digest.encode("ascii"))
    return file_hasher.hexdigest(), chunks, len(data)


def _build_manifest(
    repo: Path,
    prev_nodes: dict[str, tuple[str, list[tuple[str, str, int, list[tuple[str, bytes]]]]]] | None,
    dirty_subtree: str | None,
) -> tuple[str, dict[str, Any], dict[str, bytes], dict[str, int]]:
    metrics = {"scanned_bytes": 0, "hashed_bytes": 0, "recomputed_nodes": 0, "reused_nodes": 0}
    nodes: dict[str, Any] = {}
    chunk_map: dict[str, bytes] = {}
    subtree_dirs = sorted(p.name for p in repo.iterdir() if p.is_dir() and p.name != ".git")
    root_entries: list[tuple[str, str]] = []

    for sub in subtree_dirs:
        if prev_nodes is not None and dirty_subtree is not None and sub != dirty_subtree and sub in prev_nodes:
            prev_digest, prev_files = prev_nodes[sub]
            nodes[sub] = (prev_digest, prev_files)
            metrics["reused_nodes"] += 1
            for _fname, _fhash, _fsize, fchunks in prev_files:
                for cdigest, cbytes in fchunks:
                    chunk_map[cdigest] = cbytes
            root_entries.append((sub, prev_digest))
            continue

        dir_hasher = hashlib.sha256()
        dir_hasher.update(DIR_DOMAIN)
        sub_files: list[tuple[str, str, int, list[tuple[str, bytes]]]] = []
        sub_path = repo / sub
        for fpath in sorted(sub_path.iterdir(), key=lambda p: p.name):
            if not fpath.is_file():
                continue
            fdigest, fchunks, fsize = _chunk_file(fpath)
            metrics["scanned_bytes"] += fsize
            metrics["hashed_bytes"] += fsize
            for cdigest, cbytes in fchunks:
                chunk_map[cdigest] = cbytes
            dir_hasher.update(fpath.name.encode("utf-8"))
            dir_hasher.update(fdigest.encode("ascii"))
            sub_files.append((fpath.name, fdigest, fsize, fchunks))
        sub_digest = dir_hasher.hexdigest()
        nodes[sub] = (sub_digest, sub_files)
        metrics["recomputed_nodes"] += 1
        root_entries.append((sub, sub_digest))

    root_hasher = hashlib.sha256()
    root_hasher.update(DIR_DOMAIN)
    for sub, sub_digest in root_entries:
        root_hasher.update(sub.encode("utf-8"))
        root_hasher.update(sub_digest.encode("ascii"))
    root_digest = root_hasher.hexdigest()
    metrics["recomputed_nodes"] += 1
    return root_digest, nodes, chunk_map, metrics


def _sync_to_cas(
    cas_dir: Path,
    nodes: dict[str, Any],
    chunk_map: dict[str, bytes],
) -> tuple[int, int, int]:
    uploaded = 0
    downloaded = 0
    cas_dir.mkdir(parents=True, exist_ok=True)
    for digest, payload in chunk_map.items():
        obj = cas_dir / f"{digest}.blk"
        if not obj.exists():
            obj.write_bytes(payload)
            uploaded += len(payload)
            readback = obj.read_bytes()
            if hashlib.sha256(readback).hexdigest() != digest:
                raise RuntimeError(f"readback verification failed for {digest}")
            downloaded += len(readback)
    manifest_bytes = json.dumps(
        {k: v[0] for k, v in nodes.items()}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    manifest_path = cas_dir / f"manifest-{manifest_digest}.json"
    if not manifest_path.exists():
        manifest_path.write_bytes(manifest_bytes)
        uploaded += len(manifest_bytes)
        downloaded += len(manifest_path.read_bytes())
    temp_disk = sum(p.stat().st_size for p in cas_dir.rglob("*") if p.is_file())
    return uploaded, downloaded, temp_disk


def _seed_dataset(repo: Path, fmt: str, spec: dict[str, int]) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, ["init", f"--object-format={fmt}", "--initial-branch=main"])
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (repo / "ignored.log").write_text("ignore-me\n", encoding="utf-8")
    empty_dir = repo / "empty_kept"
    empty_dir.mkdir(exist_ok=True)

    ds_hasher = hashlib.sha256()
    ds_hasher.update(f"{fmt}:{spec}".encode("ascii"))
    fbytes = spec["file_bytes"]
    for s in range(spec["subtrees"]):
        sdir = repo / f"sub_{s:02d}"
        sdir.mkdir(parents=True, exist_ok=True)
        for f in range(spec["files_per_subtree"]):
            seed = hashlib.sha256(f"{s}:{f}".encode("ascii")).digest()
            parts = []
            rem = fbytes
            blk = 0
            while rem > 0:
                take = min(CHUNK_SIZE_BYTES, rem)
                hdr = f"{s:02d}:{f:02d}:{blk:04d}:".encode("ascii")
                chunk_raw = hdr + (seed * ((take // len(seed)) + 1))
                parts.append(chunk_raw[:take])
                rem -= take
                blk += 1
            payload = b"".join(parts)
            (sdir / f"file_{f:02d}.bin").write_bytes(payload)
            ds_hasher.update(payload)
    _git(repo, ["add", "--all"])
    _git(repo, ["commit", "-m", "benchmark-seed"])
    return ds_hasher.hexdigest()


def _bench_case(profile: str, fmt: str, iterations: int | None = None) -> dict[str, Any]:
    spec = PROFILES[profile]
    iters = spec["iterations"] if iterations is None else max(1, iterations)
    full_samples: list[float] = []
    inc_samples: list[float] = []
    res_samples: list[float] = []
    full_stats: dict[str, int] = {}
    inc_stats: dict[str, int] = {}
    res_stats: dict[str, Any] = {}
    dataset_digest = ""
    any_fsck_ok = False

    for it in range(iters):
        with tempfile.TemporaryDirectory(prefix="rootyard-merkle-eval-") as td_raw:
            td = Path(td_raw)
            repo = td / "repo"
            cas_dir = td / "cas"
            dataset_digest = _seed_dataset(repo, fmt, spec)

            t0 = time.perf_counter()
            c0 = time.process_time()
            _root1, nodes1, chunks1, m1 = _build_manifest(repo, None, None)
            up1, dl1, disk1 = _sync_to_cas(cas_dir, nodes1, chunks1)
            full_ms = (time.perf_counter() - t0) * 1000.0
            full_cpu = (time.process_time() - c0) * 1000.0
            full_samples.append(full_ms)
            full_stats = {
                **m1,
                "uploaded_bytes": up1,
                "downloaded_bytes": dl1,
                "uploaded_downloaded_bytes": up1 + dl1,
                "cpu_ms": round(full_cpu, 4),
                "temp_disk_bytes": disk1,
            }

            mut_file = repo / "sub_00" / "file_00.bin"
            orig = mut_file.read_bytes()
            mut_file.write_bytes(b"MUTATED-WORKTREE-DELTA" + orig[22:])

            t1 = time.perf_counter()
            c1 = time.process_time()
            root2, nodes2, chunks2, m2 = _build_manifest(repo, nodes1, "sub_00")
            up2, dl2, disk2 = _sync_to_cas(cas_dir, nodes2, chunks2)
            inc_ms = (time.perf_counter() - t1) * 1000.0
            inc_cpu = (time.process_time() - c1) * 1000.0
            inc_samples.append(inc_ms)
            inc_stats = {
                **m2,
                "uploaded_bytes": up2,
                "downloaded_bytes": dl2,
                "uploaded_downloaded_bytes": up2 + dl2,
                "cpu_ms": round(inc_cpu, 4),
                "temp_disk_bytes": disk2,
            }

            bundle_dir = td / "git_bundle"
            (repo / ".git").rename(bundle_dir)
            _rmtree(repo)

            tr0 = time.perf_counter()
            cr0 = time.process_time()
            target = td / "restored"
            target.mkdir()
            bundle_dir.rename(target / ".git")
            restored_dl = 0
            for sub, (_sd, sfiles) in nodes2.items():
                sdir = target / sub
                sdir.mkdir(parents=True, exist_ok=True)
                for fname, _fh, _fs, fchunks in sfiles:
                    buf = bytearray()
                    for cdigest, _cbytes in fchunks:
                        raw = (cas_dir / f"{cdigest}.blk").read_bytes()
                        restored_dl += len(raw)
                        if hashlib.sha256(raw).hexdigest() != cdigest:
                            raise RuntimeError("restore integrity mismatch")
                        buf.extend(raw)
                    (sdir / fname).write_bytes(bytes(buf))
            rroot, _, _, _ = _build_manifest(target, None, None)
            if rroot != root2:
                raise RuntimeError("restored tree root mismatch")
            if it == 0:
                _git(target, ["fsck", "--full", "--strict"])
                any_fsck_ok = True
            res_ms = (time.perf_counter() - tr0) * 1000.0
            res_cpu = (time.process_time() - cr0) * 1000.0
            res_samples.append(res_ms)
            res_stats = {
                "uploaded_bytes": 0,
                "downloaded_bytes": restored_dl,
                "uploaded_downloaded_bytes": restored_dl,
                "cpu_ms": round(res_cpu, 4),
                "temp_disk_bytes": disk2,
                "git_fsck_ok": any_fsck_ok,
            }
            _rmtree(td)

    rss_kib = _peak_rss_kib()
    for d, samp in ((full_stats, full_samples), (inc_stats, inc_samples), (res_stats, res_samples)):
        d["p50_ms"] = _percentile(samp, 50.0)
        d["p95_ms"] = _percentile(samp, 95.0)
        d["p99_ms"] = _percentile(samp, 99.0)
        d["peak_rss_kib"] = rss_kib

    return {
        "profile": profile,
        "object_format": fmt,
        "dataset_digest": dataset_digest,
        "iterations": iters,
        "full": full_stats,
        "incremental": inc_stats,
        "restore_fork": res_stats,
        "reduction": {
            "hashed_bytes_saved_ratio": round(
                1.0 - (inc_stats["hashed_bytes"] / max(1, full_stats["hashed_bytes"])), 4
            ),
            "wire_bytes_saved_ratio": round(
                1.0 - (inc_stats["uploaded_downloaded_bytes"] / max(1, full_stats["uploaded_downloaded_bytes"])), 4
            ),
            "p50_speedup": round(full_stats["p50_ms"] / max(0.001, inc_stats["p50_ms"]), 2),
        },
    }


def run_benchmark(profiles: list[str], formats: list[str], iterations: int | None = None) -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parent.parent
    try:
        source_rev = _git(repo_root, ["rev-parse", "HEAD"])
    except Exception:
        source_rev = "unknown"
    git_version = subprocess.run(["git", "--version"], capture_output=True, text=True, check=True).stdout.strip()
    results = [_bench_case(p, f, iterations=iterations) for p in profiles for f in formats]
    return {
        "issue": 181,
        "benchmark": "workspace_merkle_sync",
        "mode": "python-dataset-git-plus-chunked-cas",
        "source_git_rev": source_rev,
        "git_version": git_version,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "chunk_size_bytes": CHUNK_SIZE_BYTES,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark Issue #181 full vs incremental Merkle checkpoint sync.")
    parser.add_argument("--profiles", default="small,medium", help="Comma-separated profiles (small,medium)")
    parser.add_argument("--formats", default="sha1,sha256", help="Comma-separated Git object formats (sha1,sha256)")
    parser.add_argument("--json-out", default="", help="Optional path to write JSON benchmark report")
    args = parser.parse_args(argv)
    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    for p in profiles:
        if p not in PROFILES:
            raise SystemExit(f"unknown profile: {p}")
    for f in formats:
        if f not in {"sha1", "sha256"}:
            raise SystemExit(f"unknown git object format: {f}")

    report = run_benchmark(profiles, formats)
    payload = json.dumps(report, indent=2, sort_keys=False)
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="utf-8", newline="\n")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
