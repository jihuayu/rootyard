"""Three-repository first incremental pushes under one candidate config (Refs #178/#282).

"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import math
import os
from pathlib import Path
import re
import threading
import time
from typing import Any

from .corpus import BASE_UNIX_TIME, build_git_http_env, run_git
from .failure_diagnostics import LiveEvalFailure, build_failure_record, push_context
from .live_server import clone_and_fsck, push_with_pack_config
from .multi_repo_diagnostics import MULTI_REPO_COMPLETED_FIELD
from .pack_matrix import PackConfigSpec
from .s3_meter import SOCKET_IO_TIMEOUT_SECONDS, S3MeterProxy
from .telemetry import percentile_stats

MULTI_REPO_REF = "refs/heads/multi-repo-eval"
MULTI_REPO_REMOTE_REF = "refs/remotes/origin/multi-repo-eval"
MULTI_REPO_GROUP = "multi_repo_first_pushes"
MULTI_REPO_PUSH_PHASE = "multi_repo_first_push"
MULTI_REPO_VERIFY_PHASE = "multi_repo_verify"
MULTI_REPO_COHORT = (
    ("compressed_media", "sha1"),
    ("large_binary", "sha1"),
    ("text_history", "sha256"),
)
MULTI_REPO_SAMPLE_COUNT = 3
MULTI_REPO_BARRIER_TIMEOUT_SECONDS = 30
_COMMIT = re.compile(r"^[0-9a-f]{40,64}$")


def select_multi_repo_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Select first two plus final enrolled target for quick and full scales."""
    if not isinstance(targets, list) or len(targets) < MULTI_REPO_SAMPLE_COUNT:
        raise ValueError("multi-repo checkpoint requires at least three enrolled targets")
    return [targets[0], targets[1], targets[-1]]


def _fail(progress: dict[str, Any], failure_class: str, **values: Any) -> LiveEvalFailure:
    completed = progress.get("completed") if isinstance(progress.get("completed"), dict) else {}
    return LiveEvalFailure(
        build_failure_record(
            phase=values.pop("phase", MULTI_REPO_PUSH_PHASE),
            failure_class=failure_class,
            completed=completed,
            last_completed_phase=progress.get("last_completed_phase"),
            multi_repo_completed=progress.get(MULTI_REPO_COMPLETED_FIELD),
            **values,
        )
    )


def _finite_ms(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("duration must be a finite number")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError("duration must be a finite non-negative number")
    return round(number, 3)


def _checked_targets(
    targets: list[dict[str, Any]], progress: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    rows = list(targets)
    if len(rows) != MULTI_REPO_SAMPLE_COUNT:
        raise _fail(progress, "multi_repo_cohort", phase=MULTI_REPO_VERIFY_PHASE)
    repository_ids: list[str] = []
    clone_paths: list[str] = []
    writers: set[str] = set()
    for ordinal, row in enumerate(rows):
        repo = row.get("repo") if isinstance(row, dict) else None
        writer = row.get("rw") if isinstance(row, dict) else None
        reader = row.get("ro") if isinstance(row, dict) else None
        work_dir = row.get("work_dir") if isinstance(row, dict) else None
        head_oid = row.get("head_oid") if isinstance(row, dict) else None
        archetype = row.get("archetype") if isinstance(row, dict) else None
        object_format = row.get("object_format") if isinstance(row, dict) else None
        if not (
            isinstance(repo, dict)
            and isinstance(writer, dict)
            and isinstance(reader, dict)
            and isinstance(work_dir, (str, Path))
            and isinstance(head_oid, str)
            and _COMMIT.fullmatch(head_oid)
            and isinstance(archetype, str)
            and object_format in ("sha1", "sha256")
            and (archetype, object_format) == MULTI_REPO_COHORT[ordinal]
            and len(head_oid) == (40 if object_format == "sha1" else 64)
            and isinstance(repo.get("id"), str)
            and repo["id"]
            and isinstance(repo.get("clone_path"), str)
            and repo["clone_path"]
            and isinstance(writer.get("username"), str)
            and writer["username"]
            and isinstance(writer.get("token"), str)
            and writer["token"]
            and isinstance(reader.get("username"), str)
            and reader["username"]
            and isinstance(reader.get("token"), str)
            and reader["token"]
        ):
            raise _fail(
                progress, "multi_repo_cohort",
                phase=MULTI_REPO_VERIFY_PHASE,
                repo_ordinal=ordinal, archetype=archetype, object_format=object_format,
            )
        repository_ids.append(repo["id"])
        clone_paths.append(repo["clone_path"])
        writers.add(writer["username"])
    if len(set(repository_ids)) != MULTI_REPO_SAMPLE_COUNT:
        raise _fail(progress, "multi_repo_cohort", phase=MULTI_REPO_VERIFY_PHASE)
    if len(set(clone_paths)) != MULTI_REPO_SAMPLE_COUNT:
        raise _fail(progress, "multi_repo_cohort", phase=MULTI_REPO_VERIFY_PHASE)
    if len(writers) != 1:
        raise _fail(progress, "multi_repo_cohort", phase=MULTI_REPO_VERIFY_PHASE)
    return rows, repository_ids


def _prepare_client(
    git_bin: str,
    target: dict[str, Any],
    ordinal: int,
    config: str,
    work_root: Path,
    run_env: dict[str, str],
    askpass: Path,
    progress: dict[str, Any],
) -> dict[str, Any]:
    writer = target["rw"]
    writer_env = build_git_http_env(run_env, askpass, writer["username"], writer["token"])
    reader = target["ro"]
    reader_env = build_git_http_env(run_env, askpass, reader["username"], reader["token"])
    source = Path(target["work_dir"])
    local_dir = work_root / f"multi-repo-client-{config}-{ordinal}"
    proc, _ = run_git(
        git_bin, ["clone", "--quiet", "--no-hardlinks", "--template=", str(source), str(local_dir)],
        None, writer_env,
    )
    if proc.returncode != 0:
        raise _fail(
            progress, "multi_repo_fixture", phase=MULTI_REPO_VERIFY_PHASE,
            config=config, repo_ordinal=ordinal,
            archetype=target["archetype"], object_format=target["object_format"],
        )
    head, _ = run_git(git_bin, ["rev-parse", "HEAD"], local_dir, writer_env)
    expected = target["head_oid"].encode("ascii")
    object_format, _ = run_git(git_bin, ["rev-parse", "--show-object-format"], local_dir, writer_env)
    if (
        head.returncode or head.stdout.strip() != expected
        or object_format.returncode or object_format.stdout.strip() != target["object_format"].encode("ascii")
    ):
        raise _fail(
            progress, "multi_repo_head_mismatch", phase=MULTI_REPO_VERIFY_PHASE,
            config=config, repo_ordinal=ordinal,
            archetype=target["archetype"], object_format=target["object_format"],
        )
    branch, _ = run_git(git_bin, ["checkout", "--quiet", "-b", "multi-repo-eval"], local_dir, writer_env)
    if branch.returncode != 0:
        raise _fail(
            progress, "multi_repo_fixture", phase=MULTI_REPO_VERIFY_PHASE,
            config=config, repo_ordinal=ordinal,
            archetype=target["archetype"], object_format=target["object_format"],
        )
    fixture_path = f"eval/multi_repo_first_push_{ordinal}.txt"
    fixture_content = (
        f"multi-repo first incremental push\nrepo_ordinal={ordinal}\nseeded_head={target['head_oid']}\n"
    ).encode("ascii")
    fixture = local_dir / fixture_path
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_bytes(fixture_content)
    commit_env = writer_env.copy()
    stamp = f"{BASE_UNIX_TIME + 1000 + ordinal} +0000"
    commit_env["GIT_AUTHOR_DATE"] = stamp
    commit_env["GIT_COMMITTER_DATE"] = stamp
    added, _ = run_git(git_bin, ["add", "--", fixture_path], local_dir, commit_env)
    committed, _ = run_git(
        git_bin, ["commit", "--quiet", "-m", f"multi-repo first incremental push {ordinal}"],
        local_dir, commit_env,
    )
    if added.returncode != 0 or committed.returncode != 0:
        raise _fail(
            progress, "multi_repo_fixture", phase=MULTI_REPO_VERIFY_PHASE,
            config=config, repo_ordinal=ordinal,
            archetype=target["archetype"], object_format=target["object_format"],
        )
    own_head, _ = run_git(git_bin, ["rev-parse", "HEAD"], local_dir, writer_env)
    push_oid = own_head.stdout.decode("ascii", errors="replace").strip()
    if own_head.returncode != 0 or not _COMMIT.fullmatch(push_oid) or push_oid == target["head_oid"]:
        raise _fail(
            progress, "multi_repo_fixture", phase=MULTI_REPO_VERIFY_PHASE,
            config=config, repo_ordinal=ordinal,
            archetype=target["archetype"], object_format=target["object_format"],
        )
    return {
        "target": target,
        "ordinal": ordinal,
        "writer_env": writer_env,
        "reader_env": reader_env,
        "local_dir": local_dir,
        "head_oid": target["head_oid"],
        "push_oid": push_oid,
        "fixture_path": fixture_path,
        "fixture_content": fixture_content,
        "repository_id": target["repo"]["id"],
        "clone_path_sha256": hashlib.sha256(target["repo"]["clone_path"].encode("utf-8")).hexdigest(),
    }


def _push_one(
    git_bin: str,
    base_url: str,
    prepared: dict[str, Any],
    spec: PackConfigSpec | None,
    config: str,
    barrier: threading.Barrier,
    lock: threading.Lock,
    progress: dict[str, Any],
) -> dict[str, Any]:
    ordinal = prepared["ordinal"]
    target = prepared["target"]
    try:
        barrier.wait(timeout=MULTI_REPO_BARRIER_TIMEOUT_SECONDS)
    except threading.BrokenBarrierError:
        raise _fail(
            progress, "multi_repo_fixture", phase=MULTI_REPO_PUSH_PHASE,
            config=config, repo_ordinal=ordinal,
            archetype=target["archetype"], object_format=target["object_format"],
        ) from None
    start = time.monotonic()
    elapsed = push_with_pack_config(
        git_bin, prepared["local_dir"], base_url + target["repo"]["clone_path"], spec,
        f"HEAD:{MULTI_REPO_REF}", prepared["writer_env"],
        context=push_context(
            progress, MULTI_REPO_PUSH_PHASE,
            archetype=target["archetype"], object_format=target["object_format"],
            config=config, repo_ordinal=ordinal, target_ordinal=ordinal,
        ),
        expect_new_ref=True,
    )
    end = time.monotonic()
    with lock:
        progress["completed"]["multi_repo_pushes_completed"] += 1
        progress["last_completed_phase"] = MULTI_REPO_PUSH_PHASE
    return {"start": start, "end": end, "push_ms": _finite_ms(elapsed)}


def _run_pushes(
    git_bin: str,
    base_url: str,
    prepared: list[dict[str, Any]],
    spec: PackConfigSpec | None,
    config: str,
    proxy: S3MeterProxy,
    progress: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    barrier = threading.Barrier(MULTI_REPO_SAMPLE_COUNT)
    lock = threading.Lock()
    proxy.reset_counters(settle_timeout=SOCKET_IO_TIMEOUT_SECONDS)
    with ThreadPoolExecutor(max_workers=MULTI_REPO_SAMPLE_COUNT) as executor:
        futures = [
            executor.submit(
                _push_one, git_bin, base_url, entry, spec, config, barrier, lock, progress,
            )
            for entry in prepared
        ]
        # All workers are released together. A failure still waits for every
        # already-started invocation before the server and fixtures are cleaned up.
        for future in as_completed(futures):
            future.result()
    return [future.result() for future in futures], proxy.snapshot(settle_timeout=SOCKET_IO_TIMEOUT_SECONDS)


def _verify_pushes(
    git_bin: str,
    base_url: str,
    prepared: list[dict[str, Any]],
    config: str,
    work_root: Path,
    progress: dict[str, Any],
) -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    for entry in prepared:
        target = entry["target"]
        dest = work_root / f"multi-repo-verify-{config}-{entry['ordinal']}"
        try:
            clone_and_fsck(git_bin, base_url + target["repo"]["clone_path"], dest, entry["reader_env"])
        except LiveEvalFailure:
            raise
        except Exception:  # noqa: BLE001 - retain only the finite classification
            raise _fail(
                progress, "multi_repo_verify", phase=MULTI_REPO_VERIFY_PHASE,
                config=config, repo_ordinal=entry["ordinal"],
                archetype=target["archetype"], object_format=target["object_format"],
            ) from None
        ref, _ = run_git(
            git_bin, ["rev-parse", "--verify", f"{MULTI_REPO_REMOTE_REF}^{{commit}}"],
            dest, entry["reader_env"],
        )
        main_ref, _ = run_git(
            git_bin, ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
            dest, entry["reader_env"],
        )
        shown, _ = run_git(
            git_bin, ["show", f"{MULTI_REPO_REMOTE_REF}:{entry['fixture_path']}"],
            dest, entry["reader_env"],
        )
        exact_ref = ref.returncode == 0 and ref.stdout.strip() == entry["push_oid"].encode("ascii")
        main_unchanged = main_ref.returncode == 0 and main_ref.stdout.strip() == entry["head_oid"].encode("ascii")
        known_file = shown.returncode == 0 and shown.stdout == entry["fixture_content"]
        if not (exact_ref and main_unchanged and known_file):
            raise _fail(
                progress, "multi_repo_ref_mismatch", phase=MULTI_REPO_VERIFY_PHASE,
                config=config, repo_ordinal=entry["ordinal"],
                archetype=target["archetype"], object_format=target["object_format"],
            )
        verified.append(
            {
                "repo_ordinal": entry["ordinal"],
                "repository_id": entry["repository_id"],
                "clone_path_sha256": entry["clone_path_sha256"],
                "archetype": target["archetype"],
                "object_format": target["object_format"],
                "base_oid": entry["head_oid"],
                "push_oid": entry["push_oid"],
                "push_ref": MULTI_REPO_REF,
                "fixture": entry["fixture_path"],
                "fixture_sha256": hashlib.sha256(entry["fixture_content"]).hexdigest(),
                "first_attempt": True,
                "retry_count": 0,
                "push_verified": True,
                "verified_ref_oid": ref.stdout.decode("ascii", errors="replace").strip(),
                "verified_main_oid": main_ref.stdout.decode("ascii", errors="replace").strip(),
                "known_file_verified": True,
            }
        )
        progress["completed"]["multi_repo_verifications_completed"] += 1
        progress["last_completed_phase"] = MULTI_REPO_VERIFY_PHASE
    return verified


def invocation_overlap(samples: list[dict[str, Any]]) -> dict[str, Any]:
    starts = [sample["client_invocation_start_ms"] for sample in samples]
    ends = [sample["client_invocation_end_ms"] for sample in samples]
    overlap_ms = round(max(0.0, min(ends) - max(starts)), 3)
    return {
        "scope": "client_invocations_only",
        "all_overlap": overlap_ms > 0,
        "overlap_ms": overlap_ms,
        "server_internal_overlap_claimed": False,
    }


def run_multi_repo_first_pushes(
    git_bin: str,
    base_url: str,
    targets: list[dict[str, Any]],
    spec: PackConfigSpec | None,
    proxy: S3MeterProxy,
    work_root: Path,
    progress: dict[str, Any],
    *,
    config: str | None = None,
    run_env: dict[str, str] | None = None,
    askpass: Path | None = None,
) -> dict[str, Any]:
    """Prepare and measure three first incremental pushes for one candidate config."""
    work_root = Path(work_root)
    run_env = {
        key: value for key, value in (os.environ if run_env is None else run_env).items()
        if not key.startswith("GIT_")
    }
    askpass = Path(work_root / "askpass.sh" if askpass is None else askpass)
    config = config or (spec.name if spec is not None else "baseline")
    rows, repository_ids = _checked_targets(select_multi_repo_targets(targets), progress)
    prepared = [
        _prepare_client(git_bin, row, ordinal, config, work_root, run_env, askpass, progress)
        for ordinal, row in enumerate(rows)
    ]
    outcomes, push_s3 = _run_pushes(git_bin, base_url, prepared, spec, config, proxy, progress)
    origin = min(outcome["start"] for outcome in outcomes)
    for outcome in outcomes:
        outcome["client_invocation_start_ms"] = round((outcome["start"] - origin) * 1000.0, 3)
        outcome["client_invocation_end_ms"] = round((outcome["end"] - origin) * 1000.0, 3)
        outcome.pop("start", None)
        outcome.pop("end", None)
    overlap = invocation_overlap(outcomes)
    if not overlap["all_overlap"]:
        raise _fail(progress, "multi_repo_overlap", config=config)
    # Verification happens after the measured push phase and its S3 snapshot.
    verified = _verify_pushes(git_bin, base_url, prepared, config, work_root, progress)
    samples = [
        {
            **sample,
            "push_ms": outcome["push_ms"],
            "client_invocation_start_ms": outcome["client_invocation_start_ms"],
            "client_invocation_end_ms": outcome["client_invocation_end_ms"],
        }
        for sample, outcome in zip(verified, outcomes, strict=True)
    ]
    progress["completed"]["multi_repo_configs_completed"] += 1
    progress["last_completed_phase"] = MULTI_REPO_VERIFY_PHASE
    return {
        "config_name": config,
        "fixed_ref": MULTI_REPO_REF,
        "cohort_size": MULTI_REPO_SAMPLE_COUNT,
        "cohort": list(MULTI_REPO_COHORT),
        "repository_ids": repository_ids,
        "repository_ids_distinct": True,
        "clone_paths_distinct": True,
        "same_writer_cohort": True,
        "writer_cohort_size": 1,
        "push_samples": samples,
        "push_stats": percentile_stats([sample["push_ms"] for sample in samples]),
        "s3_push": push_s3,
        "verified_samples": len(verified),
        "all_verified": len(verified) == MULTI_REPO_SAMPLE_COUNT,
        "verification": {
            "fresh_stock_clone": True,
            "strict_fsck": True,
            "exact_oid": True,
            "known_file": True,
            "main_unchanged": True,
            "outside_push_and_s3_timing": True,
        },
        "client_invocation_overlap": overlap,
        "first_attempt_only": True,
        "physical_savings_claimed": False,
    }
