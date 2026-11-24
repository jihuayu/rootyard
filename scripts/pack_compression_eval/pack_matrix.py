"""Controlled native Git pack/delta parameter matrix and compaction runner (Refs #178)."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from typing import Any

from .corpus import apply_commit_spec, build_archetype_commits, init_bare_repo, measure_bare_repo_stats, run_git
from .telemetry import ResourceSampler, percentile_stats, sum_dir_bytes


@dataclass(frozen=True)
class PackConfigSpec:
    """Controlled native Git pack compaction parameters (never push-time aggressive repack)."""

    name: str
    compression: int  # -1 = Git default zlib level, 0 = store only, 1..9 = zlib levels
    window: int
    depth: int
    window_memory: str
    threads: int
    delta_base_offset: bool = True
    recompute_deltas: bool = False
    description: str = ""

    def git_config_args(self) -> list[str]:
        return [
            "-c", f"pack.compression={self.compression}",
            "-c", f"pack.window={self.window}",
            "-c", f"pack.depth={self.depth}",
            "-c", f"pack.windowMemory={self.window_memory}",
            "-c", f"pack.threads={self.threads}",
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "pack_compression": self.compression,
            "pack_window": self.window,
            "pack_depth": self.depth,
            "pack_window_memory": self.window_memory,
            "pack_threads": self.threads,
            "delta_base_offset": self.delta_base_offset,
            "recompute_deltas": self.recompute_deltas,
            "description": self.description,
        }


CANDIDATE_CONFIGS: tuple[PackConfigSpec, ...] = (
    PackConfigSpec(
        name="rootyard_default",
        compression=-1,
        window=10,
        depth=50,
        window_memory="32m",
        threads=1,
        recompute_deltas=False,
        description="Current Rootyard native pack baseline (pack-objects -q with source delta/blob reuse, w=10, d=50, 32m, t=1)",
    ),
    PackConfigSpec(
        name="recompute_c6_w10",
        compression=6,
        window=10,
        depth=50,
        window_memory="32m",
        threads=1,
        recompute_deltas=True,
        description="Default window/depth with --no-reuse-delta --no-reuse-object to measure pure recomputation cost",
    ),
    PackConfigSpec(
        name="zlib_store_c0",
        compression=0,
        window=10,
        depth=50,
        window_memory="32m",
        threads=1,
        recompute_deltas=True,
        description="Uncompressed zlib store (c=0, recompute) to isolate inflate/deflate CPU cost on incompressible payloads",
    ),
    PackConfigSpec(
        name="zlib_fast_c1",
        compression=1,
        window=10,
        depth=50,
        window_memory="32m",
        threads=1,
        recompute_deltas=True,
        description="Low-CPU zlib level 1 with default delta bounds (c=1, w=10, d=50, 32m, t=1, recompute)",
    ),
    PackConfigSpec(
        name="balanced_c6_w25",
        compression=6,
        window=25,
        depth=50,
        window_memory="64m",
        threads=1,
        recompute_deltas=True,
        description="Moderate delta window expansion (c=6, w=25, d=50, 64m, t=1, recompute)",
    ),
    PackConfigSpec(
        name="wide_window_c6_w50_t2",
        compression=6,
        window=50,
        depth=50,
        window_memory="128m",
        threads=2,
        recompute_deltas=True,
        description="Wider cross-file/history delta matching with 2 bounded threads (c=6, w=50, d=50, 128m, t=2, recompute)",
    ),
    PackConfigSpec(
        name="deep_archive_c9_w50_d100",
        compression=9,
        window=50,
        depth=100,
        window_memory="256m",
        threads=1,
        recompute_deltas=True,
        description="High-effort zlib c=9 with deeper chain (w=50, d=100, 256m, t=1, recompute) to measure CPU/RSS vs chain cost",
    ),
    PackConfigSpec(
        name="threaded_c6_w25_t4",
        compression=6,
        window=25,
        depth=50,
        window_memory="64m",
        threads=4,
        recompute_deltas=True,
        description="4-thread variant at identical window/compression to isolate multi-thread scaling & peak memory",
    ),
)

LIVE_COMPARISON_CONFIG_NAMES: tuple[str, ...] = (
    "rootyard_default",
    "zlib_store_c0",
    "wide_window_c6_w50_t2",
    "deep_archive_c9_w50_d100",
)


def list_all_object_oids(git_bin: str | Path, bare_dir: Path, env: dict[str, str]) -> dict[str, str]:
    """Return {oid: object_type} for all objects present in bare_dir."""
    proc, _ = run_git(
        git_bin,
        ["--git-dir", str(bare_dir), "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"],
        None,
        env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cat-file failed on {bare_dir}: {proc.stderr.decode(errors='replace')[:300]}")
    out: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            out[parts[0]] = parts[1]
    return out


def list_all_refs(git_bin: str | Path, bare_dir: Path, env: dict[str, str]) -> tuple[dict[str, str], str]:
    """Return ({refname: oid}, head_symref) from bare_dir."""
    proc, _ = run_git(
        git_bin,
        ["--git-dir", str(bare_dir), "for-each-ref", "--format=%(refname) %(objectname)"],
        None,
        env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"for-each-ref failed: {proc.stderr.decode(errors='replace')[:300]}")
    refs: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8").splitlines():
        if " " in line:
            name, oid = line.split(" ", 1)
            refs[name] = oid
    head_proc, _ = run_git(git_bin, ["--git-dir", str(bare_dir), "symbolic-ref", "HEAD"], None, env)
    head_ref = head_proc.stdout.decode("utf-8").strip() if head_proc.returncode == 0 else "refs/heads/main"
    return refs, head_ref


def parse_verify_pack_verbose(
    git_bin: str | Path, pack_path: Path, env: dict[str, str], bare_dir: Path | None = None
) -> dict[str, Any]:
    """Run git verify-pack -v (with optional --git-dir for SHA-256 repos) and return metrics."""
    args = (["--git-dir", str(bare_dir)] if bare_dir is not None else []) + ["verify-pack", "-v", str(pack_path)]
    proc, wall_ms = run_git(git_bin, args, None, env)
    if proc.returncode != 0:
        raise RuntimeError(f"verify-pack failed on {pack_path}: {proc.stderr.decode(errors='replace')[:300]}")
    objects: dict[str, str] = {}
    delta_objects = 0
    non_delta_objects = 0
    max_depth = 0
    depth_hist: dict[str, int] = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[1] not in ("commit", "tree", "blob", "tag"):
            continue
        oid, kind = fields[0], fields[1]
        objects[oid] = kind
        # Format: <oid> <type> <size> <size-in-pack> <offset> [<depth> <base-oid>]
        if len(fields) >= 7 and fields[5].isdigit():
            delta_objects += 1
            depth = int(fields[5])
            if depth > max_depth:
                max_depth = depth
            dk = str(depth)
            depth_hist[dk] = depth_hist.get(dk, 0) + 1
        else:
            non_delta_objects += 1
    return {
        "verify_pack_ms": round(wall_ms, 3),
        "objects": objects,
        "total_objects": len(objects),
        "non_delta_objects": non_delta_objects,
        "delta_objects": delta_objects,
        "max_delta_chain_depth": max_depth,
        "delta_depth_histogram": depth_hist,
    }


def _run_pack_objects_instrumented(
    git_bin: str | Path,
    bare_dir: Path,
    oid_input: bytes,
    out_prefix: Path,
    spec: PackConfigSpec,
    env: dict[str, str],
) -> dict[str, Any]:
    """Execute git pack-objects once while measuring CPU, peak RSS, and scratch bytes."""
    cmd = [
        str(git_bin),
        "--git-dir",
        str(bare_dir),
        *spec.git_config_args(),
        "pack-objects",
        "-q",
    ]
    if spec.delta_base_offset:
        cmd.append("--delta-base-offset")
    if spec.recompute_deltas:
        cmd.extend(["--no-reuse-delta", "--no-reuse-object"])
    cmd.append(str(out_prefix))

    out_dir = out_prefix.parent
    sampler = ResourceSampler([out_dir], interval_seconds=0.05)
    t0 = time.monotonic()
    popen_kw: dict[str, Any] = {
        "env": env,
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if hasattr(os, "setsid"):
        popen_kw["start_new_session"] = True
    proc = subprocess.Popen(cmd, **popen_kw)
    sampler.set_pids([proc.pid])
    sampler.start()
    max_rss_kib: int | None = None
    cpu_seconds: float | None = None
    try:
        assert proc.stdin is not None
        proc.stdin.write(oid_input)
        proc.stdin.close()
        if hasattr(os, "wait4"):
            _, status, rusage = os.wait4(proc.pid, 0)
            rc = os.waitstatus_to_exitcode(status)
            proc.returncode = rc  # wait4 reaped the child outside Popen.
            cpu_seconds = round(float(rusage.ru_utime) + float(rusage.ru_stime), 4)
            raw_rss = int(rusage.ru_maxrss)
            if raw_rss > 0:
                max_rss_kib = raw_rss // 1024 if sys.platform == "darwin" else raw_rss
            stderr_bytes = proc.stderr.read() if proc.stderr else b""
        else:
            _, stderr_bytes = proc.communicate(timeout=240)
            rc = proc.returncode
    finally:
        sampler.stop()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

    wall_ms = round((time.monotonic() - t0) * 1000.0, 3)
    s_sum = sampler.summary()
    if max_rss_kib is None and s_sum["max_hwm_kib"] is not None:
        max_rss_kib = s_sum["max_hwm_kib"]
    if cpu_seconds is None:
        cpu_seconds = s_sum["cpu_seconds"]
    if rc != 0:
        err = stderr_bytes.decode("utf-8", errors="replace")[:400]
        raise RuntimeError(f"git pack-objects failed for {spec.name} (rc={rc}): {err}")

    packs = sorted(out_dir.glob("pack-*.pack"))
    if len(packs) != 1:
        raise RuntimeError(f"expected exactly 1 pack for {spec.name}, found {len(packs)}")
    pack_path = packs[0]
    idx_path = pack_path.with_suffix(".idx")
    if not idx_path.is_file():
        raise RuntimeError(f"missing .idx for {pack_path}")
    return {
        "pack_path": pack_path,
        "idx_path": idx_path,
        "wall_ms": wall_ms,
        "cpu_seconds": cpu_seconds,
        "peak_rss_kib": max_rss_kib,
        "peak_scratch_disk_bytes": max(s_sum["max_scratch_disk_bytes"], sum_dir_bytes([out_dir])),
        "pack_bytes": pack_path.stat().st_size,
        "idx_bytes": idx_path.stat().st_size,
        "pack_idx_total_bytes": pack_path.stat().st_size + idx_path.stat().st_size,
    }


def materialize_isolated_pack_repo(
    git_bin: str | Path,
    target_dir: Path,
    object_format: str,
    pack_path: Path,
    idx_path: Path,
    refs: dict[str, str],
    head_ref: str,
    env: dict[str, str],
) -> None:
    """Create a disposable bare repo holding ONLY the candidate single pack+idx and refs."""
    if target_dir.exists():
        shutil.rmtree(target_dir)
    init_bare_repo(git_bin, target_dir, env, object_format=object_format)
    pack_dir = target_dir / "objects" / "pack"
    pack_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(pack_path, pack_dir / "pack-candidate.pack")
    shutil.copy2(idx_path, pack_dir / "pack-candidate.idx")
    for ref_name, oid in refs.items():
        p_ref, _ = run_git(git_bin, ["--git-dir", str(target_dir), "update-ref", "--no-deref", ref_name, oid], None, env)
        if p_ref.returncode != 0:
            raise RuntimeError(f"update-ref {ref_name} failed: {p_ref.stderr.decode(errors='replace')[:200]}")
    run_git(git_bin, ["--git-dir", str(target_dir), "symbolic-ref", "HEAD", head_ref], None, env)


def _measure_local_clones(
    git_bin: str | Path,
    isolated_bare: Path,
    scratch_root: Path,
    env: dict[str, str],
    runs: int = 3,
) -> list[float]:
    latencies: list[float] = []
    uri = isolated_bare.resolve().as_uri()
    for i in range(runs):
        dest = scratch_root / f"clone-{i}"
        proc, ms = run_git(git_bin, ["clone", "--quiet", "--no-local", uri, str(dest)], None, env)
        if proc.returncode != 0:
            raise RuntimeError(f"local clone verification failed: {proc.stderr.decode(errors='replace')[:250]}")
        fsck, _ = run_git(git_bin, ["-C", str(dest), "fsck", "--full", "--strict"], None, env)
        if fsck.returncode != 0:
            raise RuntimeError(f"cloned repo fsck failed: {fsck.stderr.decode(errors='replace')[:250]}")
        latencies.append(ms)
        shutil.rmtree(dest, ignore_errors=True)
    return latencies


def evaluate_repo_pack_matrix(
    git_bin: str | Path,
    repo_entry: dict[str, Any],
    configs: tuple[PackConfigSpec, ...],
    work_root: Path,
    env: dict[str, str],
    clone_runs: int = 2,
) -> dict[str, Any]:
    """Run controlled compaction matrix across all candidate configs for one repository."""
    bare_dir: Path = repo_entry["bare_dir"]
    object_format: str = repo_entry["object_format"]
    pre = repo_entry["pre_compaction"]
    pre_pack_idx = int(pre["pack_idx_total_bytes"])
    indep_bytes = int(pre["independent_logical_bytes"])

    source_objects = list_all_object_oids(git_bin, bare_dir, env)
    refs, head_ref = list_all_refs(git_bin, bare_dir, env)
    oid_input = ("\n".join(sorted(source_objects.keys())) + "\n").encode("utf-8")

    results: list[dict[str, Any]] = []
    default_bytes: int | None = None

    for spec in configs:
        cfg_dir = work_root / spec.name
        stage_dir = cfg_dir / "stage"
        stage_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(stage_dir, 0o700)

        pack_run = _run_pack_objects_instrumented(git_bin, bare_dir, oid_input, stage_dir / "pack", spec, env)
        vp = parse_verify_pack_verbose(git_bin, pack_run["pack_path"], env, bare_dir=bare_dir)

        isolated_bare = cfg_dir / "isolated.git"
        materialize_isolated_pack_repo(
            git_bin, isolated_bare, object_format, pack_run["pack_path"], pack_run["idx_path"], refs, head_ref, env
        )
        fsck_proc, fsck_ms = run_git(git_bin, ["--git-dir", str(isolated_bare), "fsck", "--full", "--strict"], None, env)
        if fsck_proc.returncode != 0:
            raise RuntimeError(f"isolated fsck failed for {spec.name}: {fsck_proc.stderr.decode(errors='replace')[:300]}")
        clone_samples = _measure_local_clones(git_bin, isolated_bare, cfg_dir, env, runs=clone_runs)

        compacted_bytes = int(pack_run["pack_idx_total_bytes"])
        if spec.name == "rootyard_default":
            default_bytes = compacted_bytes
        diff_vs_default = (compacted_bytes - default_bytes) if default_bytes is not None else 0
        diff_vs_default_pct = round((diff_vs_default / float(default_bytes)) * 100.0, 2) if default_bytes else 0.0
        compaction_rewrite_bytes = pre_pack_idx + compacted_bytes
        coexisting_non_gc_bytes = pre_pack_idx + compacted_bytes

        # Note: isolated_bare only stores the single compacted pack after removing old packs locally;
        # remote/PG physical savings MUST NOT be claimed unless remote GC actually executed.
        post_local_gc = measure_bare_repo_stats(git_bin, isolated_bare, env)

        results.append(
            {
                "config": spec.to_dict(),
                "compaction_wall_ms": pack_run["wall_ms"],
                "compaction_cpu_seconds": pack_run["cpu_seconds"],
                "peak_rss_kib": pack_run["peak_rss_kib"],
                "peak_scratch_disk_bytes": pack_run["peak_scratch_disk_bytes"],
                "pack_bytes": pack_run["pack_bytes"],
                "idx_bytes": pack_run["idx_bytes"],
                "compacted_pack_idx_bytes": compacted_bytes,
                "vs_rootyard_default_bytes": diff_vs_default,
                "vs_rootyard_default_pct": diff_vs_default_pct,
                "vs_uncompacted_pack_idx_bytes": compacted_bytes - pre_pack_idx,
                "vs_uncompacted_pack_idx_pct": round(((compacted_bytes - pre_pack_idx) / float(pre_pack_idx)) * 100.0, 2)
                if pre_pack_idx > 0
                else 0.0,
                "pack_to_logical_ratio": round(compacted_bytes / float(indep_bytes), 4) if indep_bytes > 0 else None,
                "total_objects": vp["total_objects"],
                "delta_objects": vp["delta_objects"],
                "non_delta_objects": vp["non_delta_objects"],
                "max_delta_chain_depth": vp["max_delta_chain_depth"],
                "compaction_rewrite_bytes": compaction_rewrite_bytes,
                "coexisting_non_gc_bytes": coexisting_non_gc_bytes,
                "local_isolated_post_unlink_pack_idx_bytes": post_local_gc["pack_idx_total_bytes"],
                "fsck_ms": round(fsck_ms, 3),
                "local_clone_stats": percentile_stats(clone_samples),
                "objects_exact_match": vp["objects"] == source_objects,
                "isolated_bare_dir": str(isolated_bare),
                "pack_path": str(pack_run["pack_path"]),
                "idx_path": str(pack_run["idx_path"]),
            }
        )
    return {
        "archetype": repo_entry["archetype"],
        "object_format": object_format,
        "pre_compaction": pre,
        "ref_count": len(refs),
        "candidates": results,
    }


def kill_process_group(proc: subprocess.Popen[bytes]) -> bool:
    """Terminate and reap a child process group cleanly across POSIX and Windows."""
    try:
        if os.name != "nt" and hasattr(os, "killpg"):
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGKILL)
        else:
            proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return proc.poll() is not None
