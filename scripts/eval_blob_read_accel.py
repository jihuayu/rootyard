#!/usr/bin/env python3
"""Reproducible benchmark evaluator for Issue #165 Blob read-acceleration sidecars.

Measures maintenance build cost, separated Blob GET count/bytes (authoritative packs
vs non-authoritative MIDX/bitmap/commit-graph + manifest), cold materialization cost,
and stock Git history/reachability latency with strict disabled-vs-enabled parity checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any

NULL_CONFIG = "/dev/null" if os.name != "nt" else "NUL"
WORKLOAD_SPECS: dict[str, dict[str, int]] = {
    "small": {"base_commits": 16, "branch_commits": 8, "branches": 2, "files_per_commit": 2, "iterations": 5},
    "medium": {"base_commits": 48, "branch_commits": 24, "branches": 4, "files_per_commit": 3, "iterations": 5},
    "history": {"base_commits": 120, "branch_commits": 40, "branches": 4, "files_per_commit": 2, "iterations": 5},
}


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": NULL_CONFIG,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "rubicon-bench",
            "GIT_AUTHOR_EMAIL": "rubicon@example.com",
            "GIT_COMMITTER_NAME": "rubicon-bench",
            "GIT_COMMITTER_EMAIL": "rubicon@example.com",
        }
    )
    return env


def _run_git(repo: Path, args: list[str], *, input_bytes: bytes | None = None) -> tuple[bytes, float, float]:
    env = _git_env()
    t_wall0 = time.perf_counter()
    c0 = os.times()
    proc = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C", str(repo), *args],
        input=input_bytes,
        capture_output=True,
        env=env,
        check=True,
    )
    wall_ms = (time.perf_counter() - t_wall0) * 1000.0
    c1 = os.times()
    child_cpu_ms = max(0.0, ((c1.children_user - c0.children_user) + (c1.children_system - c0.children_system)) * 1000.0)
    return proc.stdout, wall_ms, child_cpu_ms


def _seed_multi_pack_repo(root: Path, fmt: str, spec: dict[str, int]) -> dict[str, Any]:
    work = root / f"work-{fmt}"
    work.mkdir(parents=True, exist_ok=True)
    _run_git(work, ["init", f"--object-format={fmt}", "--initial-branch=main"])
    commit_seq = 0
    fast_import_lines: list[str] = []

    def emit_commit(branch: str, parent_mark: int | None, msg: str, tree_count: int) -> int:
        nonlocal commit_seq
        commit_seq += 1
        mark = commit_seq
        fast_import_lines.append(f"commit refs/heads/{branch}")
        fast_import_lines.append(f"mark :{mark}")
        fast_import_lines.append(f"author Bench <b@example.com> {1700000000 + commit_seq} +0000")
        fast_import_lines.append(f"committer Bench <b@example.com> {1700000000 + commit_seq} +0000")
        payload = msg.encode()
        fast_import_lines.append(f"data {len(payload)}")
        fast_import_lines.append(msg)
        if parent_mark is not None:
            fast_import_lines.append(f"from :{parent_mark}")
        for idx in range(tree_count):
            content = f"{msg}-file-{idx}-{commit_seq}\n".encode()
            fast_import_lines.append(f"M 100644 inline dir{idx % 4}/f_{idx}.txt")
            fast_import_lines.append(f"data {len(content)}")
            fast_import_lines.append(content.decode())
        return mark

    last_main: int | None = None
    for idx in range(spec["base_commits"]):
        last_main = emit_commit("main", last_main, f"base-{idx}", spec["files_per_commit"])

    base_mark = last_main
    branch_names = ["main"]
    for b_idx in range(1, spec["branches"]):
        b_name = f"topic-{b_idx}"
        branch_names.append(b_name)
        parent = base_mark
        for c_idx in range(spec["branch_commits"]):
            parent = emit_commit(b_name, parent, f"{b_name}-{c_idx}", spec["files_per_commit"])

    fast_import_lines.append("done")
    stream = ("\n".join(fast_import_lines) + "\n").encode()
    bare = root / f"auth-{fmt}.git"
    _run_git(work, ["init", "--bare", f"--object-format={fmt}", str(bare)])
    _run_git(bare, ["fast-import", "--done", "--quiet"], input_bytes=stream)

    # Split commits across >= 2 packs without any pre-existing bitmaps/commit-graphs.
    _run_git(bare, ["repack", "-ad", "--no-write-bitmap-index"])
    tip_commit = _run_git(bare, ["rev-parse", "refs/heads/main"])[0].decode().strip()
    extra_stream = (
        f"commit refs/heads/main\nmark :1\nauthor B <b@example.com> 1700009999 +0000\n"
        f"committer B <b@example.com> 1700009999 +0000\ndata 5\nextra\nfrom {tip_commit}\n"
        f"M 100644 inline delta.txt\ndata 6\ndelta\n\ndone\n"
    ).encode()
    _run_git(bare, ["fast-import", "--done", "--quiet"], input_bytes=extra_stream)
    _run_git(bare, ["repack", "--no-write-bitmap-index"])

    pack_dir = bare / "objects" / "pack"
    packs = sorted(pack_dir.glob("*.pack"))
    idxs = sorted(pack_dir.glob("*.idx"))
    pack_bytes = sum(p.stat().st_size for p in packs) + sum(i.stat().st_size for i in idxs)
    refs = {
        line.split()[1]: line.split()[0]
        for line in _run_git(bare, ["show-ref"])[0].decode().splitlines()
        if line.strip()
    }
    return {
        "bare": bare,
        "packs": packs,
        "idxs": idxs,
        "pack_count": len(packs),
        "pack_bytes": pack_bytes,
        "refs": refs,
        "branch_tips": [refs[f"refs/heads/{name}"] for name in branch_names if f"refs/heads/{name}" in refs],
    }


def _copy_authoritative_packs(src_bare: Path, dst_bare: Path, fmt: str, refs: dict[str, str]) -> float:
    t0 = time.perf_counter()
    _run_git(dst_bare.parent, ["init", "--bare", f"--object-format={fmt}", str(dst_bare)])
    for ext in ("*.pack", "*.idx"):
        for src in (src_bare / "objects" / "pack").glob(ext):
            shutil.copyfile(src, dst_bare / "objects" / "pack" / src.name)
    for ref_name, oid in refs.items():
        _run_git(dst_bare, ["update-ref", ref_name, oid])
    return (time.perf_counter() - t0) * 1000.0


def _build_sidecars(src_bare: Path, build_dir: Path, fmt: str, refs: dict[str, str]) -> dict[str, Any]:
    _copy_authoritative_packs(src_bare, build_dir, fmt, refs)
    _, midx_wall, midx_cpu = _run_git(build_dir, ["multi-pack-index", "write", "--bitmap"])
    _, cg_wall, cg_cpu = _run_git(build_dir, ["commit-graph", "write", "--reachable", "--changed-paths"])
    _, v_midx_w, v_midx_c = _run_git(build_dir, ["multi-pack-index", "verify"])
    _, v_cg_w, v_cg_c = _run_git(build_dir, ["commit-graph", "verify"])

    midx_file = build_dir / "objects" / "pack" / "multi-pack-index"
    bm_files = list((build_dir / "objects" / "pack").glob("multi-pack-index-*.bitmap"))
    cg_file = build_dir / "objects" / "info" / "commit-graph"
    sidecars = [midx_file, *bm_files, cg_file]
    manifest_payload = json.dumps(
        {
            "format": fmt,
            "artifacts": [
                {"name": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size}
                for p in sidecars
            ],
        }
    ).encode()
    sidecar_bytes = sum(p.stat().st_size for p in sidecars) + len(manifest_payload)
    return {
        "midx_file": midx_file,
        "bitmap_files": bm_files,
        "commit_graph_file": cg_file,
        "sidecar_count": len(sidecars) + 1,  # artifacts + immutable manifest
        "sidecar_bytes": sidecar_bytes,
        "build_wall_ms": round(midx_wall + cg_wall + v_midx_w + v_cg_w, 3),
        "build_cpu_ms": round(midx_cpu + cg_cpu + v_midx_c + v_cg_c, 3),
    }


def _apply_sidecars(built: dict[str, Any], target_bare: Path) -> float:
    t0 = time.perf_counter()
    shutil.copyfile(built["midx_file"], target_bare / "objects" / "pack" / built["midx_file"].name)
    for bm in built["bitmap_files"]:
        shutil.copyfile(bm, target_bare / "objects" / "pack" / bm.name)
    (target_bare / "objects" / "info").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(built["commit_graph_file"], target_bare / "objects" / "info" / "commit-graph")
    _run_git(target_bare, ["multi-pack-index", "verify"])
    _run_git(target_bare, ["commit-graph", "verify"])
    return (time.perf_counter() - t0) * 1000.0


def _measure_queries(bare: Path, tips: list[str], use_bitmap: bool, iterations: int) -> dict[str, Any]:
    count_args = ["rev-list", "--count", *(["--use-bitmap-index"] if use_bitmap else []), "--all"]
    obj_args = ["rev-list", "--objects", *(["--use-bitmap-index"] if use_bitmap else []), "--all"]
    topo_args = ["rev-list", "--topo-order", "-n", "100", tips[0]]
    mb_args = ["merge-base", tips[0], tips[-1]]

    def bench(args: list[str]) -> tuple[bytes, float, float]:
        walls: list[float] = []
        cpus: list[float] = []
        last_out = b""
        for _ in range(iterations):
            out, wall_ms, cpu_ms = _run_git(bare, args)
            last_out = out
            walls.append(wall_ms)
            cpus.append(cpu_ms)
        return last_out, round(statistics.median(walls), 3), round(statistics.median(cpus), 3)

    c_out, c_w, c_c = bench(count_args)
    o_out, o_w, o_c = bench(obj_args)
    t_out, t_w, t_c = bench(topo_args)
    m_out, m_w, m_c = bench(mb_args)
    return {
        "count_digest": hashlib.sha256(c_out).hexdigest()[:16],
        "objects_count": len(o_out.splitlines()),
        "topo_digest": hashlib.sha256(t_out).hexdigest()[:16],
        "merge_base": m_out.decode().strip(),
        "median_wall_ms": {
            "rev_list_count": c_w,
            "rev_list_objects": o_w,
            "rev_list_topo": t_w,
            "merge_base": m_w,
            "total_suite": round(c_w + o_w + t_w + m_w, 3),
        },
        "median_cpu_ms": {
            "rev_list_count": c_c,
            "rev_list_objects": o_c,
            "rev_list_topo": t_c,
            "merge_base": m_c,
            "total_suite": round(c_c + o_c + t_c + m_c, 3),
        },
    }


def run_benchmark(profiles: list[str], formats: list[str]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="rubicon-read-accel-eval-") as tmp:
        root = Path(tmp)
        for profile_name in profiles:
            spec = WORKLOAD_SPECS[profile_name]
            for fmt in formats:
                case_dir = root / f"{profile_name}-{fmt}"
                case_dir.mkdir(parents=True, exist_ok=True)
                seeded = _seed_multi_pack_repo(case_dir, fmt, spec)

                build_dir = case_dir / "builder.git"
                built = _build_sidecars(seeded["bare"], build_dir, fmt, seeded["refs"])

                disabled_dir = case_dir / "replica-disabled.git"
                pack_mat_ms = _copy_authoritative_packs(seeded["bare"], disabled_dir, fmt, seeded["refs"])
                disabled_q = _measure_queries(disabled_dir, seeded["branch_tips"], False, spec["iterations"])

                enabled_dir = case_dir / "replica-enabled.git"
                enabled_pack_ms = _copy_authoritative_packs(seeded["bare"], enabled_dir, fmt, seeded["refs"])
                sidecar_apply_ms = _apply_sidecars(built, enabled_dir)
                enabled_q = _measure_queries(enabled_dir, seeded["branch_tips"], True, spec["iterations"])

                parity_ok = (
                    disabled_q["count_digest"] == enabled_q["count_digest"]
                    and disabled_q["objects_count"] == enabled_q["objects_count"]
                    and disabled_q["topo_digest"] == enabled_q["topo_digest"]
                    and disabled_q["merge_base"] == enabled_q["merge_base"]
                )
                if not parity_ok:
                    raise RuntimeError(f"Parity mismatch for {profile_name}/{fmt}")

                pack_gets = seeded["pack_count"] * 2
                sidecar_gets = built["sidecar_count"]
                cold_disabled_ms = round(pack_mat_ms + disabled_q["median_wall_ms"]["total_suite"], 3)
                cold_enabled_ms = round(
                    enabled_pack_ms + sidecar_apply_ms + enabled_q["median_wall_ms"]["total_suite"], 3
                )
                warm_speedup = (
                    round(disabled_q["median_wall_ms"]["total_suite"] / enabled_q["median_wall_ms"]["total_suite"], 3)
                    if enabled_q["median_wall_ms"]["total_suite"] > 0
                    else 1.0
                )
                rows.append(
                    {
                        "profile": profile_name,
                        "object_format": fmt,
                        "parity_verified": parity_ok,
                        "authoritative_pack_count": seeded["pack_count"],
                        "authoritative_pack_gets": pack_gets,
                        "authoritative_pack_bytes": seeded["pack_bytes"],
                        "sidecar_get_count": sidecar_gets,
                        "sidecar_bytes": built["sidecar_bytes"],
                        "sidecar_byte_overhead_pct": round((built["sidecar_bytes"] * 100.0) / seeded["pack_bytes"], 2),
                        "build_wall_ms": built["build_wall_ms"],
                        "build_cpu_ms": built["build_cpu_ms"],
                        "pack_materialize_ms": round(pack_mat_ms, 3),
                        "sidecar_apply_verify_ms": round(sidecar_apply_ms, 3),
                        "disabled_queries": disabled_q,
                        "enabled_queries": enabled_q,
                        "cold_total_disabled_ms": cold_disabled_ms,
                        "cold_total_enabled_ms": cold_enabled_ms,
                        "cold_speedup_ratio": round(cold_disabled_ms / cold_enabled_ms, 3) if cold_enabled_ms else 1.0,
                        "warm_query_speedup_ratio": warm_speedup,
                    }
                )

    cold_wins = sum(1 for row in rows if row["cold_speedup_ratio"] >= 1.25 and row["sidecar_byte_overhead_pct"] < 25.0)
    recommend_enable = cold_wins > (len(rows) // 2)
    return {
        "issue": 165,
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "default_enabled_policy": False,
        "default_enabled_recommended": recommend_enable,
        "criterion": "Enable by default only when cold_speedup_ratio >= 1.25 and sidecar_byte_overhead_pct < 25% across most workloads",
        "results": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Issue #165 Blob read-acceleration sidecars.")
    parser.add_argument("--profiles", default="small,medium,history")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)
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
