#!/usr/bin/env python3
"""Reproducible concurrent push/read/compaction evaluator for Issue #162.

Executes real stock Git (`SHA-1` & `SHA-256`) multi-pack ingest, `open -> sealed`
pack-hash-sharded no-delete compaction across 1 vs N maintenance workers, concurrent
push/read latency (P50/P95/P99), backlog drain, equivalence parity, and separated
physical byte accounting (`serving_pack_bytes`, `newly_written_bytes`,
`retained_old_pack_bytes`, `total_physical_blob_bytes`).
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import tempfile
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NULL_CONFIG = "/dev/null" if os.name != "nt" else "NUL"
PROFILES: dict[str, dict[str, int]] = {
    "small": {"seed_packs": 4, "stream_pushes": 8, "files_per_push": 2, "shards": 4, "max_seg_packs": 2},
    "sustained": {"seed_packs": 6, "stream_pushes": 16, "files_per_push": 3, "shards": 4, "max_seg_packs": 2},
}
SOURCE_FILES = [
    "src/storage_lifecycle.rs",
    "src/storage_lifecycle/rubicon_compaction.rs",
    "src/storage_lifecycle/rubicon_compaction/sharding.rs",
    "src/storage_lifecycle/rubicon_compaction/segment.rs",
    "src/storage_lifecycle/rubicon_compaction/lease.rs",
    "src/storage_lifecycle/rubicon_compaction/store.rs",
    "src/storage_lifecycle/rubicon_compaction/store_cas.rs",
    "src/storage_lifecycle/rubicon_compaction/executor.rs",
    "scripts/eval_rubicon_compaction.py",
]


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": NULL_CONFIG,
            "GIT_CONFIG_GLOBAL": NULL_CONFIG,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "rubicon-compaction",
            "GIT_AUTHOR_EMAIL": "compaction@example.com",
            "GIT_COMMITTER_NAME": "rubicon-compaction",
            "GIT_COMMITTER_EMAIL": "compaction@example.com",
        }
    )
    return env


def _run_git(repo: Path | None, args: list[str], *, input_bytes: bytes | None = None) -> tuple[bytes, float]:
    cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "gc.auto=0",
        "-c",
        "gc.autoDetach=false",
        "-c",
        "maintenance.auto=0",
        "-c",
        "maintenance.autoDetach=false",
        "--no-replace-objects",
    ]
    if repo is not None:
        cmd.extend(["-C", str(repo)])
    cmd.extend(args)
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, input=input_bytes, capture_output=True, env=_git_env(), check=True)
    return proc.stdout, (time.perf_counter() - t0) * 1000.0


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 3)


def _latency_summary(values: list[float]) -> dict[str, float]:
    return {
        "p50": round(statistics.median(values), 3) if values else 0.0,
        "p95": _pct(values, 95.0),
        "p99": _pct(values, 99.0),
    }


def _shard_for_pack(pack_sha256: str, shard_count: int) -> int:
    digest = hashlib.sha256(b"rubicon-compaction-shard-v1\0" + pack_sha256.encode()).digest()
    return int.from_bytes(digest[:8], "big") % shard_count


def _pair_bytes(pack_path: Path) -> int:
    return pack_path.stat().st_size + pack_path.with_suffix(".idx").stat().st_size


def _make_pack_from_commit(
    src_work: Path, fmt: str, out_dir: Path, seq: int, files_per_push: int, parent: str | None
) -> tuple[dict[str, Any], str]:
    blob_payload = f"base-shared-window-{'x' * 120}-seq-{seq}\n"
    (src_work / "shared.txt").write_text(blob_payload, encoding="utf-8")
    for f_idx in range(files_per_push):
        (src_work / f"item_{f_idx}.txt").write_text(f"push-{seq}-file-{f_idx}\n", encoding="utf-8")
    _run_git(src_work, ["add", "."])
    _run_git(src_work, ["commit", "-m", f"push-{seq}"])
    tip = _run_git(src_work, ["rev-parse", "HEAD"])[0].decode().strip()
    range_arg = f"{parent}..{tip}" if parent else tip
    objs = _run_git(src_work, ["rev-list", "--objects", range_arg])[0]
    oids = b"\n".join(line.split()[0] for line in objs.splitlines() if line.strip()) + b"\n"
    pack_prefix = out_dir / f"in-{seq}"
    _run_git(src_work, ["pack-objects", "-q", str(pack_prefix)], input_bytes=oids)
    pack_file = next(out_dir.glob(f"in-{seq}-*.pack"))
    idx_file = pack_file.with_suffix(".idx")
    sha = hashlib.sha256(pack_file.read_bytes()).hexdigest()
    return {
        "pack_id": f"in-{seq}",
        "pack_path": pack_file,
        "idx_path": idx_file,
        "sha256": sha,
        "bytes": _pair_bytes(pack_file),
        "format": fmt,
    }, tip


def _verify_repo_equivalence(
    baseline_packs: list[dict[str, Any]],
    serving_packs: list[dict[str, Any]],
    refs: dict[str, str],
    fmt: str,
    root: Path,
) -> dict[str, Any]:
    def materialize_and_inspect(name: str, packs: list[dict[str, Any]], check_clone: bool) -> tuple[list[str], str]:
        bare = root / f"{name}.git"
        _run_git(None, ["init", "--bare", "--quiet", f"--object-format={fmt}", str(bare)])
        pdir = bare / "objects" / "pack"
        for idx, p in enumerate(packs):
            stem = f"pack-{idx:04d}-{p['sha256'][:12]}"
            shutil.copyfile(p["pack_path"], pdir / f"{stem}.pack")
            shutil.copyfile(p["idx_path"], pdir / f"{stem}.idx")
        for rname, oid in refs.items():
            _run_git(bare, ["update-ref", rname, oid])
        _run_git(bare, ["symbolic-ref", "HEAD", "refs/heads/main"])
        _run_git(bare, ["fsck", "--full", "--strict"])
        inv = sorted(_run_git(bare, ["cat-file", "--batch-check", "--batch-all-objects"])[0].decode().splitlines())
        if check_clone:
            clone_dir = root / f"{name}-clone.git"
            _run_git(None, ["clone", "--no-local", "--bare", "--quiet", str(bare), str(clone_dir)])
            _run_git(clone_dir, ["fsck", "--full", "--strict"])
        rev_hash = hashlib.sha256(_run_git(bare, ["rev-list", "--objects", "--all"])[0]).hexdigest()[:16]
        return inv, rev_hash

    base_inv, base_rev = materialize_and_inspect("baseline", baseline_packs, False)
    comp_inv, comp_rev = materialize_and_inspect("compacted", serving_packs, True)
    if base_inv != comp_inv or base_rev != comp_rev:
        raise RuntimeError("Compaction equivalence check failed against uncompacted baseline")
    return {"object_count": len(comp_inv), "closure_digest": comp_rev, "fsck_and_clone_verified": True}


def _run_case(profile_name: str, fmt: str, workers: int, tmp_root: Path) -> dict[str, Any]:
    spec = PROFILES[profile_name]
    case_dir = tmp_root / f"{profile_name}-{fmt}-w{workers}"
    work = case_dir / "work"
    blob_packs = case_dir / "blob-packs"
    work.mkdir(parents=True, exist_ok=True)
    blob_packs.mkdir(parents=True, exist_ok=True)
    _run_git(work, ["init", f"--object-format={fmt}", "--initial-branch=main"])

    shard_count = spec["shards"]
    all_created: list[dict[str, Any]] = []
    parent: str | None = None
    for seq in range(spec["seed_packs"]):
        pkt, parent = _make_pack_from_commit(work, fmt, blob_packs, seq, spec["files_per_push"], parent)
        pkt["shard"] = _shard_for_pack(pkt["sha256"], shard_count)
        all_created.append(pkt)

    lock = threading.Lock()
    open_by_shard: dict[int, list[dict[str, Any]]] = {s: [] for s in range(shard_count)}
    sealed_by_shard: dict[int, list[list[dict[str, Any]]]] = {s: [] for s in range(shard_count)}
    serving_packs: dict[str, dict[str, Any]] = {}
    retained_old: list[dict[str, Any]] = []
    newly_written_bytes = 0
    backlog_samples: list[int] = []
    push_latencies: list[float] = []
    read_latencies: list[float] = []
    compact_latencies: list[float] = []
    compacted_input_packs = 0
    compacted_input_bytes = 0
    compaction_runs = 0
    current_tip = parent

    def ingest_locked(pkt: dict[str, Any]) -> None:
        serving_packs[pkt["pack_id"]] = pkt
        s = pkt["shard"]
        open_by_shard[s].append(pkt)
        if len(open_by_shard[s]) >= spec["max_seg_packs"]:
            sealed_by_shard[s].append(open_by_shard[s])
            open_by_shard[s] = []
        backlog_samples.append(sum(len(v) for v in sealed_by_shard.values()))

    with lock:
        for pkt in all_created:
            ingest_locked(pkt)

    push_done = threading.Event()
    stop_readers = threading.Event()

    def push_producer() -> None:
        nonlocal current_tip
        for offset in range(spec["stream_pushes"]):
            seq = spec["seed_packs"] + offset
            t0 = time.perf_counter()
            pkt, tip = _make_pack_from_commit(work, fmt, blob_packs, seq, spec["files_per_push"], current_tip)
            pkt["shard"] = _shard_for_pack(pkt["sha256"], shard_count)
            current_tip = tip
            with lock:
                all_created.append(pkt)
                ingest_locked(pkt)
            push_latencies.append((time.perf_counter() - t0) * 1000.0)
        with lock:
            for s, open_seg in open_by_shard.items():
                if open_seg:
                    sealed_by_shard[s].append(open_seg)
                    open_by_shard[s] = []
        push_done.set()

    def reader_loop() -> None:
        while not stop_readers.is_set():
            _, ms = _run_git(work, ["rev-list", "--count", "--all"])
            read_latencies.append(ms)
            time.sleep(0.005)

    def compact_worker(worker_idx: int) -> None:
        nonlocal newly_written_bytes, compacted_input_packs, compacted_input_bytes, compaction_runs
        my_shards = [s for s in range(shard_count) if s % workers == worker_idx]
        scratch_dir = case_dir / f"worker-{worker_idx}"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        run_seq = 0
        while True:
            batch: list[dict[str, Any]] = []
            picked_shard: int | None = None
            with lock:
                for s in my_shards:
                    segs = sealed_by_shard[s]
                    if len(segs) >= 2 or (len(segs) == 1 and len(segs[0]) >= 2):
                        batch = [p for seg in segs for p in seg]
                        sealed_by_shard[s] = []
                        picked_shard = s
                        break
            if not batch:
                if push_done.is_set():
                    break
                time.sleep(0.005)
                continue

            run_seq += 1
            t0 = time.perf_counter()
            tmp_bare = scratch_dir / f"run-{run_seq}.git"
            _run_git(None, ["init", "--bare", "--quiet", f"--object-format={fmt}", str(tmp_bare)])
            for i, p in enumerate(batch):
                shutil.copyfile(p["pack_path"], tmp_bare / "objects/pack" / f"in-{i}.pack")
                shutil.copyfile(p["idx_path"], tmp_bare / "objects/pack" / f"in-{i}.idx")
            all_raw = _run_git(tmp_bare, ["cat-file", "--batch-check", "--batch-all-objects"])[0]
            oids = b"\n".join(line.split()[0] for line in all_raw.splitlines() if line.strip()) + b"\n"
            out_prefix = blob_packs / f"compacted-w{worker_idx}-r{run_seq}"
            _run_git(tmp_bare, ["pack-objects", "-q", str(out_prefix)], input_bytes=oids)
            out_pack = next(blob_packs.glob(f"compacted-w{worker_idx}-r{run_seq}-*.pack"))
            out_idx = out_pack.with_suffix(".idx")
            _run_git(tmp_bare, ["verify-pack", "-v", str(out_idx)])
            shutil.rmtree(tmp_bare, ignore_errors=True)

            out_sha = hashlib.sha256(out_pack.read_bytes()).hexdigest()
            out_bytes = _pair_bytes(out_pack)
            new_pkt = {
                "pack_id": f"c-w{worker_idx}-r{run_seq}",
                "pack_path": out_pack,
                "idx_path": out_idx,
                "sha256": out_sha,
                "bytes": out_bytes,
                "shard": _shard_for_pack(out_sha, shard_count),
            }
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            with lock:
                for old in batch:
                    serving_packs.pop(old["pack_id"], None)
                    retained_old.append(old)
                serving_packs[new_pkt["pack_id"]] = new_pkt
                newly_written_bytes += out_bytes
                compacted_input_packs += len(batch)
                compacted_input_bytes += sum(p["bytes"] for p in batch)
                compaction_runs += 1
                compact_latencies.append(elapsed_ms)
                backlog_samples.append(sum(len(v) for v in sealed_by_shard.values()))
            assert picked_shard is not None

    t_wall0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers + 2) as pool:
        futs = [pool.submit(push_producer), pool.submit(reader_loop)]
        comp_futs = [pool.submit(compact_worker, w) for w in range(workers)]
        futs[0].result()
        for cf in comp_futs:
            cf.result()
        stop_readers.set()
        futs[1].result()
    wall_s = max(0.001, time.perf_counter() - t_wall0)

    refs = {"refs/heads/main": current_tip or ""}
    final_serving = list(serving_packs.values())
    eq = _verify_repo_equivalence(all_created, final_serving, refs, fmt, case_dir / "verify")

    serving_bytes = sum(p["bytes"] for p in final_serving)
    retained_bytes = sum(p["bytes"] for p in retained_old)
    total_physical = serving_bytes + retained_bytes
    mergeable_backlog = sum(
        1 for segs in sealed_by_shard.values() if len(segs) >= 2 or (len(segs) == 1 and len(segs[0]) >= 2)
    )
    tail_segments = sum(len(segs) for segs in sealed_by_shard.values())
    return {
        "profile": profile_name,
        "object_format": fmt,
        "maintenance_workers": workers,
        "uncompacted_serving_pack_count": len(all_created),
        "compacted_serving_pack_count": len(final_serving),
        "retained_old_pack_count": len(retained_old),
        "max_backlog_sealed_segments": max(backlog_samples, default=0),
        "final_mergeable_backlog_segments": mergeable_backlog,
        "final_sealed_tail_segments": tail_segments,
        "compaction_runs": compaction_runs,
        "compacted_input_packs": compacted_input_packs,
        "maintenance_throughput_packs_per_sec": round(compacted_input_packs / wall_s, 3),
        "maintenance_throughput_bytes_per_sec": round(compacted_input_bytes / wall_s, 1),
        "compaction_latency_ms": _latency_summary(compact_latencies),
        "concurrent_push_latency_ms": _latency_summary(push_latencies),
        "concurrent_read_latency_ms": _latency_summary(read_latencies),
        "serving_pack_bytes": serving_bytes,
        "newly_written_bytes": newly_written_bytes,
        "retained_old_pack_bytes": retained_bytes,
        "total_physical_blob_bytes": total_physical,
        "delete_disabled": True,
        "physical_bytes_deleted": 0,
        "claims_physical_savings": False,
        "equivalence": eq,
    }


def _provenance() -> dict[str, Any]:
    hashes = {}
    for rel in SOURCE_FILES:
        p = ROOT / rel
        if p.is_file():
            hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    git_head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True)
    return {
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "repo_head": git_head.stdout.strip() if git_head.returncode == 0 else "unknown",
        "source_sha256_prefixes": hashes,
    }


def run_benchmark(profiles: list[str], formats: list[str], workers: list[int]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="rubicon-compaction-eval-") as tmp:
        root = Path(tmp)
        for profile in profiles:
            for fmt in formats:
                for w in workers:
                    rows.append(_run_case(profile, fmt, w, root))
    return {"issue": 162, "delete_disabled": True, "provenance": _provenance(), "results": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Issue #162 no-delete sharded Rubicon compaction.")
    parser.add_argument("--profiles", default="small,sustained")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--workers", default="1,2")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)
    report = run_benchmark(
        [p.strip() for p in args.profiles.split(",") if p.strip()],
        [f.strip() for f in args.formats.split(",") if f.strip()],
        [int(w.strip()) for w in args.workers.split(",") if w.strip()],
    )
    rendered = json.dumps(report, indent=2)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
