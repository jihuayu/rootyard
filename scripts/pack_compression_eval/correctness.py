"""Stock-Git SHA-1/SHA-256 parity, closure, cancellation, and failure checks (Refs #178)."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from typing import Any

from .corpus import run_git, seed_multi_push_bare_repo
from .pack_matrix import (
    CANDIDATE_CONFIGS,
    PackConfigSpec,
    evaluate_repo_pack_matrix,
    kill_process_group,
    list_all_object_oids,
    list_all_refs,
    parse_verify_pack_verbose,
)


def _check_candidate_invariants(
    git_bin: str | Path,
    source_objects: dict[str, str],
    source_refs: dict[str, str],
    cand_row: dict[str, Any],
    spec: PackConfigSpec,
    env: dict[str, str],
) -> dict[str, Any]:
    isolated_bare = Path(cand_row["isolated_bare_dir"])
    pack_path = Path(cand_row["pack_path"])
    vp = parse_verify_pack_verbose(git_bin, pack_path, env, bare_dir=isolated_bare)
    refs_after, _ = list_all_refs(git_bin, isolated_bare, env)
    objects_after = list_all_object_oids(git_bin, isolated_bare, env)
    fsck_proc, _ = run_git(git_bin, ["--git-dir", str(isolated_bare), "fsck", "--full", "--strict"], None, env)
    depth_ok = vp["max_delta_chain_depth"] <= spec.depth
    parity_ok = objects_after == source_objects and vp["objects"] == source_objects
    refs_ok = refs_after == source_refs
    fsck_ok = fsck_proc.returncode == 0
    return {
        "config_name": spec.name,
        "passed": parity_ok and refs_ok and fsck_ok and depth_ok,
        "objects_parity_ok": parity_ok,
        "refs_parity_ok": refs_ok,
        "fsck_strict_ok": fsck_ok,
        "delta_depth_bound_ok": depth_ok,
        "observed_max_delta_depth": vp["max_delta_chain_depth"],
        "configured_max_delta_depth": spec.depth,
        "delta_objects": vp["delta_objects"],
        "total_objects": vp["total_objects"],
    }


def _verify_pack_cancellation_and_failures(
    git_bin: str | Path,
    bare_dir: Path,
    source_pack: Path,
    source_objects: dict[str, str],
    source_refs: dict[str, str],
    work_dir: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    """Check cancellation during pack input and refusal of incomplete packs or invalid bounds."""
    before_packs = sorted((bare_dir / "objects" / "pack").glob("pack-*.pack"))
    # Keep input open so Git is still waiting for the rest of the object list.
    cancel_stage = work_dir / "cancel-stage"
    cancel_stage.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(git_bin),
        "--git-dir",
        str(bare_dir),
        "-c",
        "pack.compression=9",
        "-c",
        "pack.window=50",
        "pack-objects",
        "-q",
        str(cancel_stage / "pack"),
    ]
    popen_kw: dict[str, Any] = {
        "env": env,
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if hasattr(os, "setsid"):
        popen_kw["start_new_session"] = True
    proc = subprocess.Popen(cmd, **popen_kw)
    try:
        assert proc.stdin is not None
        first_oid = next(iter(source_objects.keys()))
        proc.stdin.write((first_oid + "\n").encode("utf-8"))
        proc.stdin.flush()
        time.sleep(0.01)
    finally:
        was_running = proc.poll() is None
        reaped = not was_running or kill_process_group(proc)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
    after_packs = sorted((bare_dir / "objects" / "pack").glob("pack-*.pack"))
    fsck_after_cancel, _ = run_git(git_bin, ["--git-dir", str(bare_dir), "fsck", "--full", "--strict"], None, env)
    refs_after_cancel, _ = list_all_refs(git_bin, bare_dir, env)
    killed_status = 1 if os.name == "nt" else -signal.SIGKILL
    cancel_ok = (
        was_running
        and reaped
        and proc.returncode == killed_status
        and before_packs == after_packs
        and fsck_after_cancel.returncode == 0
        and refs_after_cancel == source_refs
    )

    # 2. Truncated pack bytes fail verify-pack closed.
    trunc_pack = work_dir / "truncated.pack"
    raw_pack = source_pack.read_bytes()
    trunc_pack.write_bytes(raw_pack[:-16] if len(raw_pack) > 32 else raw_pack[:4])
    trunc_idx = trunc_pack.with_suffix(".idx")
    shutil.copy2(source_pack.with_suffix(".idx"), trunc_idx)
    p_trunc, _ = run_git(git_bin, ["--git-dir", str(bare_dir), "verify-pack", "-v", str(trunc_pack)], None, env)
    truncated_refused = p_trunc.returncode != 0

    # 3. Missing .idx fails verify-pack closed.
    orphan_pack = work_dir / "missing_idx.pack"
    orphan_pack.write_bytes(raw_pack)
    p_missing_idx, _ = run_git(git_bin, ["--git-dir", str(bare_dir), "verify-pack", "-v", str(orphan_pack)], None, env)
    missing_idx_refused = p_missing_idx.returncode != 0

    # 4. Invalid pack.depth config value fails closed.
    p_bad_cfg, _ = run_git(
        git_bin,
        ["--git-dir", str(bare_dir), "-c", "pack.depth=invalid", "pack-objects", "--stdout"],
        None,
        env,
        stdin_bytes=b"",
    )
    bad_depth_refused = p_bad_cfg.returncode != 0

    all_ok = cancel_ok and truncated_refused and missing_idx_refused and bad_depth_refused
    return {
        "passed": all_ok,
        "cancel_mid_repack_preserves_serving_pack": cancel_ok,
        "truncated_pack_refused": truncated_refused,
        "missing_idx_refused": missing_idx_refused,
        "invalid_depth_refused": bad_depth_refused,
    }


def run_correctness_suite(
    git_bin: str | Path,
    seed: int,
    scale: str,
    work_root: Path,
    env: dict[str, str],
    configs: tuple[PackConfigSpec, ...] = CANDIDATE_CONFIGS,
) -> dict[str, Any]:
    """Run SHA-1 and SHA-256 candidate compaction parity, fsck, cancellation, and failure tests."""
    by_format: dict[str, Any] = {}
    spec_map = {s.name: s for s in configs}
    all_passed = True

    for obj_fmt in ("sha1", "sha256"):
        fmt_root = work_root / f"correctness-{obj_fmt}"
        fmt_root.mkdir(parents=True, exist_ok=True)
        seeded = seed_multi_push_bare_repo(
            git_bin,
            "similar_files",
            seed,
            scale="quick",
            root_dir=fmt_root / "repo",
            env=env,
            object_format=obj_fmt,
        )
        source_objects = list_all_object_oids(git_bin, seeded["bare_dir"], env)
        source_refs, _ = list_all_refs(git_bin, seeded["bare_dir"], env)
        matrix = evaluate_repo_pack_matrix(
            git_bin, seeded, configs, fmt_root / "matrix", env, clone_runs=1
        )
        checks = []
        for cand in matrix["candidates"]:
            spec = spec_map[cand["config"]["name"]]
            chk = _check_candidate_invariants(git_bin, source_objects, source_refs, cand, spec, env)
            if not chk["passed"]:
                all_passed = False
            checks.append(chk)
        default_cand = matrix["candidates"][0]
        safety = _verify_pack_cancellation_and_failures(
            git_bin,
            seeded["bare_dir"],
            Path(default_cand["pack_path"]),
            source_objects,
            source_refs,
            fmt_root / "safety",
            env,
        )
        if not safety["passed"]:
            all_passed = False
        by_format[obj_fmt] = {
            "passed": all(c["passed"] for c in checks) and safety["passed"],
            "object_count": len(source_objects),
            "ref_count": len(source_refs),
            "candidate_checks": checks,
            "safety_and_failure_checks": safety,
        }

    return {"passed": all_passed, "formats": by_format}
