"""Measure the live benchmark's repository reads and associated S3 traffic."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import subprocess
from typing import Any

from .corpus import build_git_http_env
from .failure_diagnostics import push_context
from .live_server import ServeBlobOwner, clone_and_fsck, exercise_browse, fetch_and_fsck, restart_serve_blob
from .s3_meter import S3MeterProxy, SOCKET_IO_TIMEOUT_SECONDS
from .telemetry import ResourceSampler, percentile_stats


def measure_baseline_reads(
    git_bin: str,
    base_url: str,
    targets: list[dict[str, Any]],
    work_root: Path,
    run_env: dict[str, str],
    askpass: Path,
    proxy: S3MeterProxy,
    progress: dict[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for temperature, repetitions in (("cold", 1), ("warm", 2)):
        proxy.reset_counters()
        clones, browse = [], []
        for index, target in enumerate(targets):
            reader = target["ro"]
            repo = target["repo"]
            git_env = build_git_http_env(run_env, askpass, reader["username"], reader["token"])
            for repeat in range(repetitions):
                clones.append(clone_and_fsck(
                    git_bin, base_url + repo["clone_path"], work_root / f"{temperature}-clone-{index}-{repeat}", git_env,
                ))
                progress["completed"][f"{temperature}_clone_samples_completed"] += 1
                samples = exercise_browse(
                    base_url, repo["owner"], repo["name"], reader["token"],
                    target["seed_oid"], target["head_oid"], target["browse_path"],
                )
                browse.extend(samples)
                progress["completed"]["browse_requests_completed"] += len(samples)
                progress["last_completed_phase"] = "baseline_reads"
        result[f"{temperature}_clone_stats"] = percentile_stats(clones)
        result[f"{temperature}_browse_stats"] = percentile_stats(browse)
        result[f"s3_{temperature}_read"] = proxy.snapshot()
    return result


def measure_fetches(
    git_bin: str,
    targets: list[dict[str, Any]],
    work_root: Path,
    run_env: dict[str, str],
    askpass: Path,
    proxy: S3MeterProxy,
    progress: dict[str, Any],
    *,
    config: str,
    owner: ServeBlobOwner,
    sampler: ResourceSampler,
    start: Callable[[str], tuple[subprocess.Popen[bytes], str, Any]],
) -> tuple[str, dict[str, Any]]:
    """Measure fresh-client fetches across an owned server restart and its warm phase."""
    phase = "baseline_fetch" if config == "baseline" else "candidate_fetch"
    proc, base_url, _ = restart_serve_blob(owner, lambda: start(f"serve-blob-fetch-{config}.log"))
    sampler.set_pids([proc.pid], new_epoch=True)
    samples = [
        {"repo_ordinal": index, "archetype": target["archetype"], "object_format": target["object_format"]}
        for index, target in enumerate(targets)
    ]
    result: dict[str, Any] = {"fetch_samples": samples}
    for temperature in ("cold", "warm"):
        proxy.reset_counters(settle_timeout=SOCKET_IO_TIMEOUT_SECONDS)
        timings = []
        for index, (sample, target) in enumerate(zip(samples, targets, strict=True)):
            reader = target["ro"]
            git_env = build_git_http_env(run_env, askpass, reader["username"], reader["token"])
            elapsed = fetch_and_fsck(
                git_bin,
                base_url + target["repo"]["clone_path"],
                work_root / f"fetch-{config}-{temperature}-{index}.git",
                git_env,
                target["head_oid"],
                target["object_format"],
                context=push_context(
                    progress, phase, archetype=target["archetype"], object_format=target["object_format"],
                    config=config, repo_ordinal=index,
                ),
            )
            sample[f"{temperature}_fetch_ms"] = elapsed
            timings.append(elapsed)
            progress["completed"][f"{temperature}_fetch_samples_completed"] += 1
            progress["last_completed_phase"] = phase
        result[f"{temperature}_fetch_stats"] = percentile_stats(timings)
        result[f"s3_fetch_{temperature}"] = proxy.snapshot(settle_timeout=SOCKET_IO_TIMEOUT_SECONDS)
    return base_url, result
