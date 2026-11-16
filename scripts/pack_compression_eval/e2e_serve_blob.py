"""Live rootyard serve-blob + PG17 + Garage S3 pack/delta E2E runner (Refs #178)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
from typing import Any
import urllib.parse
import uuid

from .corpus import (
    DATASET_ARCHETYPES,
    CommitSpec,
    apply_commit_spec,
    build_archetype_commits,
    build_git_http_env,
    init_work_repo,
    measure_bare_repo_stats,
    run_git,
    write_askpass_script,
)
from .live_server import (
    append_search_path,
    cli_exec,
    clone_and_fsck,
    create_repo,
    exercise_browse,
    push_with_pack_config,
    query_repo_pg_pack_bytes,
    resolve_live_env,
    start_serve_blob,
    stop_serve_blob,
    verify_binary_receipt,
)
from .pack_matrix import CANDIDATE_CONFIGS
from .s3_meter import S3MeterProxy
from .telemetry import ResourceSampler, percentile_stats, query_pg_refstore_stats, sum_dir_bytes


def _create_tenant_pair(
    binary: str, pg_env: dict[str, str], label: str, secrets: list[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    uname = f"pe_{label}_{uuid.uuid4().hex[:6]}"
    rw = json.loads(cli_exec(binary, pg_env, "create-user", uname))
    ro = json.loads(cli_exec(binary, pg_env, "create-token", rw["username"], "--read-only"))
    secrets.extend([rw["token"], ro["token"]])
    return rw, ro


def run_live_serve_blob_eval(
    binary: str,
    git_bin: str,
    seed: int,
    scale: str,
    require_receipt: bool,
    work_root: Path,
    keep: bool,
) -> dict[str, Any]:
    """Run real PG17 + Garage S3 + serve-blob E2E evaluation across baseline and candidate configs."""
    work_root.mkdir(parents=True, exist_ok=True)
    os.chmod(work_root, 0o700)
    live = resolve_live_env(os.environ)
    receipt_info = verify_binary_receipt(Path(binary), require_receipt=require_receipt)
    parsed_s3 = urllib.parse.urlsplit(live.s3_endpoint)
    if parsed_s3.scheme != "http" or not parsed_s3.hostname:
        raise RuntimeError("S3 endpoint must be plain HTTP loopback or host:port for wire metering")
    proxy = S3MeterProxy(parsed_s3.hostname, parsed_s3.port or 80)
    proxy.start()

    schema = f"ry_pack_eval_{uuid.uuid4().hex[:12]}"
    pg_url = append_search_path(live.pg_base, schema)
    run_env = os.environ.copy()
    schema_created = False
    proc: subprocess.Popen[bytes] | None = None
    log_f: Any = None
    scratch_dir = work_root / "server-scratch"
    sampler = ResourceSampler([scratch_dir, work_root / "pack-stage"], interval_seconds=0.1)
    sampler.start()

    try:
        subprocess.check_call(
            ["psql", "--dbname", live.pg_base, "-X", "-v", "ON_ERROR_STOP=1", "-c", f'CREATE SCHEMA "{schema}"'],
            env=run_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        schema_created = True
        pg_env = run_env.copy()
        pg_env["DATABASE_URL"] = pg_url
        pg_env["ROOTYARD_SCHEMA_MODE"] = "external"
        cli_exec(binary, pg_env, "migrate")

        askpass = write_askpass_script(work_root / "askpass.sh")
        archetype_specs: list[tuple[str, str]] = [(arch, "sha1") for arch in DATASET_ARCHETYPES] + [("text_history", "sha256")]
        compare_names = ("rootyard_default", "zlib_store_c0", "wide_window_c6_w50_t2", "deep_archive_c9_w50_d100")
        compare_specs = [s for s in CANDIDATE_CONFIGS if s.name in compare_names]

        # Pre-create all tenant user/token pairs BEFORE starting serve-blob so `create-user`
        # (`db::migrate`) never contends against serve-blob's PostgreSQL lifecycle barrier.
        p1_tenants = [_create_tenant_pair(binary, pg_env, f"p1_{idx}", live.secrets) for idx in range(len(archetype_specs))]
        cmp_tenants = [_create_tenant_pair(binary, pg_env, f"cmp_{s_idx}", live.secrets) for s_idx in range(len(compare_specs))]

        proc, base_url, log_f = start_serve_blob(
            binary, git_bin, live, pg_url, proxy.endpoint, scratch_dir, work_root / "serve-blob-1.log"
        )
        sampler.set_pids([proc.pid])

        # Phase 1: Incremental multi-wave pushes (isolated tenant per archetype to respect schema 142 quotas).
        repos: list[dict[str, Any]] = []
        multi_push_latencies: list[float] = []
        proxy.reset_counters()
        acked: list[tuple[str, str, str, str, str, str]] = []

        for idx, (arch, obj_fmt) in enumerate(archetype_specs):
            rw, ro = p1_tenants[idx]
            git_rw_env = build_git_http_env(run_env, askpass, rw["username"], rw["token"])
            repo_info = create_repo(base_url, rw["token"], f"eval-{arch}-{obj_fmt}-{idx}", object_format=obj_fmt)
            wdir = work_root / f"client-{arch}-{obj_fmt}-{idx}"
            init_work_repo(git_bin, wdir, git_rw_env, object_format=obj_fmt)
            seed_commits, waves, browse_path = build_archetype_commits(arch, seed, scale=scale, repo_index=idx)
            remote_url = base_url + repo_info["clone_path"]
            step = 0
            seed_oid = ""
            for cs in seed_commits:
                seed_oid = apply_commit_spec(git_bin, wdir, cs, git_rw_env, step)
                step += 1
            head_oid = seed_oid
            multi_push_latencies.append(push_with_pack_config(git_bin, wdir, remote_url, None, "HEAD:refs/heads/main", git_rw_env))
            for wave in waves:
                for cs in wave:
                    head_oid = apply_commit_spec(git_bin, wdir, cs, git_rw_env, step)
                    step += 1
                multi_push_latencies.append(
                    push_with_pack_config(git_bin, wdir, remote_url, None, "HEAD:refs/heads/main", git_rw_env)
                )
            acked.append((repo_info["clone_path"], "refs/heads/main", head_oid, arch, ro["username"], ro["token"]))
            bare_mirror = work_root / f"ref-bare-{idx}.git"
            run_git(git_bin, ["clone", "--bare", "--quiet", str(wdir), str(bare_mirror)], None, git_rw_env)
            logical = measure_bare_repo_stats(git_bin, bare_mirror, git_rw_env)
            pg_bytes = query_repo_pg_pack_bytes(pg_url, run_env, repo_info["id"])
            repos.append(
                {
                    "archetype": arch,
                    "object_format": obj_fmt,
                    "repo": repo_info,
                    "rw": rw,
                    "ro": ro,
                    "work_dir": wdir,
                    "seed_oid": seed_oid,
                    "head_oid": head_oid,
                    "browse_path": browse_path,
                    "independent_logical_bytes": logical["independent_logical_bytes"],
                    "uncompacted_pg": pg_bytes,
                }
            )
        baseline_push_s3 = proxy.snapshot()

        # Restart serve-blob with empty scratch for genuine cold clone & cold browse measurements.
        stop_serve_blob(proc, log_f)
        proc, base_url, log_f = start_serve_blob(
            binary, git_bin, live, pg_url, proxy.endpoint, scratch_dir, work_root / "serve-blob-2.log"
        )
        sampler.set_pids([proc.pid], new_epoch=True)

        proxy.reset_counters()
        cold_clone_ms: list[float] = []
        cold_browse_ms: list[float] = []
        for idx, entry in enumerate(repos):
            ro_tok = entry["ro"]["token"]
            git_ro_env = build_git_http_env(run_env, askpass, entry["ro"]["username"], ro_tok)
            remote_url = base_url + entry["repo"]["clone_path"]
            cold_clone_ms.append(clone_and_fsck(git_bin, remote_url, work_root / f"cold-clone-{idx}", git_ro_env))
            cold_browse_ms.extend(
                exercise_browse(
                    base_url, entry["repo"]["owner"], entry["repo"]["name"], ro_tok,
                    entry["seed_oid"], entry["head_oid"], entry["browse_path"],
                )
            )
        cold_read_s3 = proxy.snapshot()

        proxy.reset_counters()
        warm_clone_ms: list[float] = []
        warm_browse_ms: list[float] = []
        for idx, entry in enumerate(repos):
            ro_tok = entry["ro"]["token"]
            git_ro_env = build_git_http_env(run_env, askpass, entry["ro"]["username"], ro_tok)
            remote_url = base_url + entry["repo"]["clone_path"]
            for rep in range(2):
                warm_clone_ms.append(clone_and_fsck(git_bin, remote_url, work_root / f"warm-clone-{idx}-{rep}", git_ro_env))
                warm_browse_ms.extend(
                    exercise_browse(
                        base_url, entry["repo"]["owner"], entry["repo"]["name"], ro_tok,
                        entry["seed_oid"], entry["head_oid"], entry["browse_path"],
                    )
                )
        warm_read_s3 = proxy.snapshot()

        # Phase 2: Candidate compacted single-pack serving comparison on live serve-blob + PG17 + Garage S3.
        target_arches = ("text_history", "similar_files", "compressed_media", "large_binary", "small_deltas")
        eval_targets = [r for r in repos if r["archetype"] in target_arches and r["object_format"] == "sha1"]
        if scale == "quick":
            eval_targets = eval_targets[:3]
        candidate_serving: list[dict[str, Any]] = []
        for s_idx, spec in enumerate(compare_specs):
            cmp_rw, cmp_ro = cmp_tenants[s_idx]
            cmp_rw_env = build_git_http_env(run_env, askpass, cmp_rw["username"], cmp_rw["token"])
            cmp_ro_env = build_git_http_env(run_env, askpass, cmp_ro["username"], cmp_ro["token"])
            push_ms: list[float] = []
            c_cold_ms: list[float] = []
            c_warm_ms: list[float] = []
            c_browse_ms: list[float] = []
            serving_sum = 0
            coexist_sum = 0
            proxy.reset_counters()
            cmp_repos: list[dict[str, Any]] = []
            for t_idx, target in enumerate(eval_targets):
                crepo = create_repo(
                    base_url, cmp_rw["token"], f"cmp-{spec.name}-{t_idx}-{uuid.uuid4().hex[:4]}",
                    object_format=target["object_format"],
                )
                c_remote = base_url + crepo["clone_path"]
                push_ms.append(push_with_pack_config(git_bin, target["work_dir"], c_remote, spec, "HEAD:refs/heads/main", cmp_rw_env))
                c_pg = query_repo_pg_pack_bytes(pg_url, run_env, crepo["id"])
                serving_sum += c_pg["artifact_bytes"]
                coexist_sum += target["uncompacted_pg"]["artifact_bytes"] + c_pg["artifact_bytes"]
                acked.append(
                    (crepo["clone_path"], "refs/heads/main", target["head_oid"], f"{target['archetype']}:{spec.name}", cmp_ro["username"], cmp_ro["token"])
                )
                cmp_repos.append(crepo)
            put_s3 = proxy.snapshot()

            stop_serve_blob(proc, log_f)
            proc, base_url, log_f = start_serve_blob(
                binary, git_bin, live, pg_url, proxy.endpoint, scratch_dir, work_root / f"serve-blob-cmp-{spec.name}.log"
            )
            sampler.set_pids([proc.pid], new_epoch=True)
            proxy.reset_counters()
            for t_idx, target in enumerate(eval_targets):
                crepo = cmp_repos[t_idx]
                c_remote = base_url + crepo["clone_path"]
                c_cold_ms.append(clone_and_fsck(git_bin, c_remote, work_root / f"cmp-cold-{spec.name}-{t_idx}", cmp_ro_env))
                c_browse_ms.extend(
                    exercise_browse(base_url, crepo["owner"], crepo["name"], cmp_ro["token"], target["seed_oid"], target["head_oid"], target["browse_path"])
                )
                c_warm_ms.append(clone_and_fsck(git_bin, c_remote, work_root / f"cmp-warm-{spec.name}-{t_idx}", cmp_ro_env))
            read_s3 = proxy.snapshot()
            candidate_serving.append(
                {
                    "config_name": spec.name,
                    "push_stats": percentile_stats(push_ms),
                    "cold_clone_stats": percentile_stats(c_cold_ms),
                    "warm_clone_stats": percentile_stats(c_warm_ms),
                    "browse_stats": percentile_stats(c_browse_ms),
                    "serving_pack_bytes": serving_sum,
                    "coexisting_non_gc_bytes": coexist_sum,
                    "physical_savings_claimed": False,
                    "s3_ingest": put_s3,
                    "s3_read": read_s3,
                }
            )

        # Phase 3: Concurrent pushes across distinct branches + Browse + PG inspection.
        conc_target = repos[0]
        conc_rw_env = build_git_http_env(run_env, askpass, conc_target["rw"]["username"], conc_target["rw"]["token"])
        conc_ro_user = conc_target["ro"]["username"]
        conc_ro_tok = conc_target["ro"]["token"]
        conc_branches = 3
        barrier = threading.Barrier(conc_branches + 1)
        conc_results: list[tuple[float, str]] = []
        conc_lock = threading.Lock()
        conc_clones: list[tuple[Path, str]] = []
        for bi in range(conc_branches):
            cdir = work_root / f"conc-branch-{bi}"
            clone_and_fsck(git_bin, base_url + conc_target["repo"]["clone_path"], cdir, conc_rw_env)
            for k, v in (("user.name", "Conc Worker"), ("user.email", "conc@rootyard.invalid")):
                run_git(git_bin, ["config", k, v], cdir, conc_rw_env)
            oid_b = apply_commit_spec(git_bin, cdir, CommitSpec(f"conc {bi}", {f"conc_{bi}.txt": f"branch={bi}\n".encode()}), conc_rw_env, 100 + bi)
            conc_clones.append((cdir, oid_b))

        def _conc_push(bi: int) -> None:
            cdir, oid_b = conc_clones[bi]
            branch_ref = f"refs/heads/conc_{bi}"
            barrier.wait(timeout=30)
            ms = push_with_pack_config(git_bin, cdir, base_url + conc_target["repo"]["clone_path"], None, f"HEAD:{branch_ref}", conc_rw_env)
            with conc_lock:
                conc_results.append((ms, oid_b))
                acked.append((conc_target["repo"]["clone_path"], branch_ref, oid_b, "concurrent", conc_ro_user, conc_ro_tok))

        def _conc_browse_and_pg() -> None:
            barrier.wait(timeout=30)
            exercise_browse(base_url, conc_target["repo"]["owner"], conc_target["repo"]["name"], conc_ro_tok, conc_target["seed_oid"], conc_target["head_oid"], conc_target["browse_path"])
            query_pg_refstore_stats(pg_url, run_env)

        with ThreadPoolExecutor(max_workers=conc_branches + 1) as pool:
            futs = [pool.submit(_conc_push, bi) for bi in range(conc_branches)]
            bfut = pool.submit(_conc_browse_and_pg)
            for fut in futs + [bfut]:
                fut.result()

        verified_acked = 0
        for clone_path, ref_name, exp_oid, _, ro_user, ro_tok in acked:
            ls_proc, _ = run_git(
                git_bin,
                ["-c", "credential.helper=", "ls-remote", base_url + clone_path, ref_name],
                None,
                build_git_http_env(run_env, askpass, ro_user, ro_tok),
            )
            if ls_proc.returncode != 0 or exp_oid not in ls_proc.stdout.decode("utf-8"):
                raise RuntimeError(f"ACK verification mismatch for {ref_name} expected {exp_oid}")
            verified_acked += 1

        pg_final = query_pg_refstore_stats(pg_url, run_env)
        sampler.stop()
        return {
            "executed": True,
            "binary": receipt_info,
            "pg_schema": schema,
            "uncompacted_baseline": {
                "repos": [
                    {
                        "archetype": r["archetype"],
                        "object_format": r["object_format"],
                        "independent_logical_bytes": r["independent_logical_bytes"],
                        "uncompacted_pack_count": r["uncompacted_pg"]["pack_count"],
                        "uncompacted_artifact_bytes": r["uncompacted_pg"]["artifact_bytes"],
                    }
                    for r in repos
                ],
                "push_stats": percentile_stats(multi_push_latencies),
                "cold_clone_stats": percentile_stats(cold_clone_ms),
                "cold_browse_stats": percentile_stats(cold_browse_ms),
                "warm_clone_stats": percentile_stats(warm_clone_ms),
                "warm_browse_stats": percentile_stats(warm_browse_ms),
                "s3_push": baseline_push_s3,
                "s3_cold_read": cold_read_s3,
                "s3_warm_read": warm_read_s3,
            },
            "candidate_serving_comparison": candidate_serving,
            "concurrent_push_and_browse": {
                "branches": conc_branches,
                "push_stats": percentile_stats([x[0] for x in conc_results]),
                "acked_verified": verified_acked,
                "acked_total": len(acked),
            },
            "pg_refstore_final": pg_final,
            "resource_peaks": {**sampler.summary(), "work_root_disk_bytes": sum_dir_bytes([work_root])},
            "physical_savings_claimed": False,
        }
    finally:
        if proc is not None:
            stop_serve_blob(proc, log_f)
        proxy.stop()
        sampler.stop()
        if schema_created:
            subprocess.run(
                ["psql", "--dbname", live.pg_base, "-X", "-c", f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'],
                env=run_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
        if not keep:
            shutil.rmtree(scratch_dir, ignore_errors=True)
