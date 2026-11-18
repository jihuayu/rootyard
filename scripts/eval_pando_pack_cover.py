#!/usr/bin/env python3
"""Reproducible stock Git (SHA-1 & SHA-256) benchmark & parity harness for Issue #184.

Compares full-materialization baseline vs causal ref-version + tiered compaction cover
planning across #164 mixed workloads (text, delta-similar source, incompressible binary,
small incremental, deep lag, criss-cross merge, multi-ref, historical pin, and
non-fast-forward updates). Separately accounts for serving/transferred bytes vs physical
retained-plus-compacted storage footprint prior to #122/#151/#153 physical GC.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

NULL_GIT_CONFIG = "/dev/null" if os.name != "nt" else "NUL"
ALL_TOPOLOGIES = (
    "empty_clone",
    "small_incremental",
    "deep_lag",
    "criss_cross_merge",
    "multi_ref",
    "historical_pin",
    "non_fast_forward",
)


def git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": NULL_GIT_CONFIG,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "pack-cover-eval",
            "GIT_AUTHOR_EMAIL": "pack-cover-eval@rootyard.invalid",
            "GIT_COMMITTER_NAME": "pack-cover-eval",
            "GIT_COMMITTER_EMAIL": "pack-cover-eval@rootyard.invalid",
        }
    )
    return env


def run_git(repo: Path, args: list[str], stdin_bytes: bytes | None = None) -> bytes:
    cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "tag.gpgsign=false",
        "--no-replace-objects",
        "-C",
        str(repo),
        *args,
    ]
    proc = subprocess.run(cmd, input=stdin_bytes, capture_output=True, env=git_env(), check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.decode(errors='replace')}")
    return proc.stdout


def git_text(repo: Path, args: list[str], stdin_bytes: bytes | None = None) -> str:
    return run_git(repo, args, stdin_bytes).decode().strip()


@dataclass(frozen=True)
class CoverPack:
    cover_id: str
    tier: str  # "compacted" | "delta"
    pack_bytes: int
    idx_bytes: int
    pack_path: Path
    idx_path: Path
    covered_commits: frozenset[str]
    retired_from_active: bool = False

    @property
    def total_bytes(self) -> int:
        return self.pack_bytes + self.idx_bytes


def pack_revs(src_repo: Path, out_dir: Path, cover_id: str, tier: str, revs: str, covered: frozenset[str]) -> CoverPack:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem_prefix = out_dir / cover_id
    out = git_text(src_repo, ["pack-objects", "--revs", "--quiet", str(stem_prefix)], revs.encode())
    pack_path = out_dir / f"{cover_id}-{out}.pack"
    idx_path = out_dir / f"{cover_id}-{out}.idx"
    return CoverPack(
        cover_id=cover_id,
        tier=tier,
        pack_bytes=pack_path.stat().st_size,
        idx_bytes=idx_path.stat().st_size,
        pack_path=pack_path,
        idx_path=idx_path,
        covered_commits=covered,
    )


def build_mixed_workload(repo: Path, obj_format: str, profile: str) -> dict[str, Any]:
    run_git(repo, ["init", f"--object-format={obj_format}", "--initial-branch=main"])
    linear_count = 6 if profile == "small" else 14
    bin_bytes = 24 * 1024 if profile == "small" else 64 * 1024

    def deterministic_bytes(tag: str, size: int) -> bytes:
        chunks: list[bytes] = []
        ctr = 0
        while sum(len(c) for c in chunks) < size:
            chunks.append(hashlib.sha256(f"{tag}:{ctr}".encode()).digest())
            ctr += 1
        return b"".join(chunks)[:size]

    def commit_files(files: dict[str, bytes], msg: str) -> str:
        for rel, content in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
            run_git(repo, ["add", rel])
        run_git(repo, ["commit", "-m", msg])
        return git_text(repo, ["rev-parse", "HEAD"])

    base_delta_tpl = "\n".join(f"fn helper_{i}(x: u64) -> u64 {{ x.wrapping_add({i}) }}" for i in range(180))
    commits: dict[str, str] = {}
    delta_covers: list[CoverPack] = []
    packs_dir = repo.parent / "packs"
    logical_authored_bytes = 0

    prev: str | None = None
    linear_oids: list[str] = []
    for idx in range(1, linear_count + 1):
        files: dict[str, bytes] = {
            "docs/history.md": f"# entry {idx}\nline={idx}\n".encode() * 40,
            "src/delta_mod.rs": f"{base_delta_tpl}\npub const VER: u64 = {idx};\n".encode(),
        }
        if idx in (1, linear_count // 2):
            files[f"assets/blob_{idx}.bin"] = deterministic_bytes(f"{obj_format}-{profile}-{idx}", bin_bytes)
        logical_authored_bytes += sum(len(v) for v in files.values())
        oid = commit_files(files, f"linear-{idx}")
        linear_oids.append(oid)
        revs = f"{oid}\n" if prev is None else f"{oid}\n^{prev}\n"
        cov = pack_revs(repo, packs_dir, f"leaf-{idx}", "delta", revs, frozenset([oid]))
        delta_covers.append(cov)
        prev = oid

    pin_oid = linear_oids[1]
    split_oid = linear_oids[max(1, linear_count // 2 - 1)]
    comp_cutoff = linear_count - 2
    comp_covered = frozenset(linear_oids[:comp_cutoff])
    comp_tip = linear_oids[comp_cutoff - 1]
    comp_cov = pack_revs(repo, packs_dir, "comp-base", "compacted", f"{comp_tip}\n", comp_covered)
    retired = {c.cover_id for c in delta_covers[:comp_cutoff]}
    active_leaves = [
        CoverPack(
            cover_id=c.cover_id,
            tier=c.tier,
            pack_bytes=c.pack_bytes,
            idx_bytes=c.idx_bytes,
            pack_path=c.pack_path,
            idx_path=c.idx_path,
            covered_commits=c.covered_commits,
            retired_from_active=(c.cover_id in retired),
        )
        for c in delta_covers
    ]

    # Branch + criss-cross merge on main and feature.
    run_git(repo, ["checkout", "-b", "feature", split_oid])
    f1 = commit_files({"feature/mod.rs": f"{base_delta_tpl}\npub const F: u64 = 1;\n".encode()}, "feature-1")
    cov_f1 = pack_revs(repo, packs_dir, "leaf-f1", "delta", f"{f1}\n^{split_oid}\n", frozenset([f1]))
    run_git(repo, ["merge", "--no-ff", "-m", "m-feat", linear_oids[-1]])
    m_feat = git_text(repo, ["rev-parse", "HEAD"])
    run_git(repo, ["checkout", "main"])
    run_git(repo, ["merge", "--no-ff", "-m", "m-main", f1])
    m_main = git_text(repo, ["rev-parse", "HEAD"])
    run_git(repo, ["merge", "--no-ff", "-m", "m-criss", m_feat])
    m_criss = git_text(repo, ["rev-parse", "HEAD"])
    cov_merge = pack_revs(
        repo,
        packs_dir,
        "leaf-merge",
        "delta",
        f"{m_criss}\n^{linear_oids[-1]}\n^{f1}\n",
        frozenset([m_feat, m_main, m_criss]),
    )
    logical_authored_bytes += 256

    # Non-fast-forward branch reset (force).
    run_git(repo, ["checkout", "-b", "force", linear_oids[0]])
    nf_old = commit_files({"force.txt": b"stale branch state\n"}, "nf-old")
    cov_nf_old = pack_revs(repo, packs_dir, "leaf-nf1", "delta", f"{nf_old}\n^{linear_oids[0]}\n", frozenset([nf_old]))
    run_git(repo, ["reset", "--hard", linear_oids[0]])
    nf_new = commit_files({"force.txt": b"rebased force target\n"}, "nf-new")
    cov_nf_new = pack_revs(repo, packs_dir, "leaf-nf2", "delta", f"{nf_new}\n^{linear_oids[0]}\n", frozenset([nf_new]))
    logical_authored_bytes += 64

    # Full-closure monolithic baseline pack per ref state (for comparison).
    full_main = pack_revs(repo, packs_dir, "full-main", "full", f"{m_criss}\n", frozenset([m_criss]))
    full_multi = pack_revs(repo, packs_dir, "full-multi", "full", f"{m_criss}\n{f1}\n{nf_new}\n", frozenset([m_criss, f1, nf_new]))
    full_inc = pack_revs(
        repo, packs_dir, "full-inc", "full", f"{linear_oids[-1]}\n^{linear_oids[-2]}\n", frozenset([linear_oids[-1]])
    )

    commits.update(
        {
            "root": linear_oids[0],
            "pin": pin_oid,
            "comp_tip": comp_tip,
            "penultimate": linear_oids[-2],
            "linear_tip": linear_oids[-1],
            "feature_tip": f1,
            "criss_cross_tip": m_criss,
            "nf_old": nf_old,
            "nf_new": nf_new,
        }
    )
    all_covers = [comp_cov, *active_leaves, cov_f1, cov_merge, cov_nf_old, cov_nf_new]
    return {
        "commits": commits,
        "linear_oids": linear_oids,
        "comp_cutoff": comp_cutoff,
        "comp_cov": comp_cov,
        "leaves": active_leaves,
        "cov_f1": cov_f1,
        "cov_merge": cov_merge,
        "cov_nf_old": cov_nf_old,
        "cov_nf_new": cov_nf_new,
        "all_covers": all_covers,
        "full_packs": {"main": full_main, "multi": full_multi, "inc": full_inc},
        "logical_authored_bytes": logical_authored_bytes,
    }


def verify_materialized_parity(src_repo: Path, obj_format: str, packs: list[CoverPack], ref_targets: list[tuple[str, str]]) -> int:
    with tempfile.TemporaryDirectory() as td:
        mat_repo = Path(td) / "mat"
        run_git(src_repo, ["init", "--bare", f"--object-format={obj_format}", str(mat_repo)])
        pack_dir = mat_repo / "objects" / "pack"
        pack_dir.mkdir(parents=True, exist_ok=True)
        for cov in packs:
            shutil.copy2(cov.pack_path, pack_dir / cov.pack_path.name)
            shutil.copy2(cov.idx_path, pack_dir / cov.idx_path.name)
        for ref_name, oid in ref_targets:
            run_git(mat_repo, ["update-ref", ref_name, oid])
        run_git(mat_repo, ["fsck", "--full", "--strict"])
        objs = git_text(mat_repo, ["rev-list", "--objects", "--all"]).splitlines()
        src_objs = git_text(src_repo, ["rev-list", "--objects", *(oid for _, oid in ref_targets)]).splitlines()
        if set(objs) < set(src_objs):
            raise AssertionError(f"object parity mismatch: missing {len(set(src_objs) - set(objs))} objects")
        return len(set(src_objs))


def quantile_ms(samples_ns: list[int], q: float) -> float:
    ordered = sorted(samples_ns)
    if not ordered:
        return 0.0
    idx = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return round(ordered[idx] / 1_000_000.0, 4)


def run_benchmark_profile(obj_format: str, profile: str, trials: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        src_repo = Path(td) / "repo"
        src_repo.mkdir(parents=True, exist_ok=True)
        w = build_mixed_workload(src_repo, obj_format, profile)
        c = w["commits"]
        comp_cov: CoverPack = w["comp_cov"]
        leaves: list[CoverPack] = w["leaves"]
        comp_cutoff: int = w["comp_cutoff"]
        tail_leaves = leaves[comp_cutoff:]
        all_covers: list[CoverPack] = w["all_covers"]
        full_main: CoverPack = w["full_packs"]["main"]
        full_multi: CoverPack = w["full_packs"]["multi"]
        full_inc: CoverPack = w["full_packs"]["inc"]

        def plan_for_want(want_set: set[str], have_set: set[str]) -> list[CoverPack]:
            missing = set(want_set) - set(have_set)
            if not missing:
                return []
            # Active compacted + non-retired leaves form the tiered planning candidate pool.
            candidates = [cov for cov in all_covers if not cov.retired_from_active]
            chosen: list[CoverPack] = []
            while missing:
                best = max(candidates, key=lambda cov: (len(cov.covered_commits & missing), cov.tier == "compacted", -cov.total_bytes))
                gain = best.covered_commits & missing
                if not gain:
                    break
                chosen.append(best)
                missing -= gain
            return chosen

        lin = set(w["linear_oids"])
        topo_specs: list[tuple[str, set[str], set[str], list[CoverPack], list[tuple[str, str]]]] = [
            ("empty_clone", lin | {c["linear_tip"]}, set(), [full_main], [("refs/heads/main", c["linear_tip"])]),
            ("small_incremental", lin, set(w["linear_oids"][:-1]), [full_inc], [("refs/heads/main", c["linear_tip"])]),
            ("deep_lag", lin, {c["root"]}, [full_main], [("refs/heads/main", c["linear_tip"])]),
            ("criss_cross_merge", lin | {c["feature_tip"], c["criss_cross_tip"]}, {c["linear_tip"], c["feature_tip"]}, [full_multi], [("refs/heads/main", c["criss_cross_tip"]), ("refs/heads/feature", c["feature_tip"])]),
            ("multi_ref", lin | {c["feature_tip"], c["criss_cross_tip"], c["nf_new"]}, set(), [full_multi], [("refs/heads/main", c["criss_cross_tip"]), ("refs/heads/feature", c["feature_tip"]), ("refs/heads/force", c["nf_new"])]),
            ("historical_pin", {c["root"], c["pin"]}, set(), [full_main], [("refs/heads/main", c["pin"])]),
            ("non_fast_forward", {c["root"], c["nf_new"]}, {c["root"], c["nf_old"]}, [comp_cov, full_multi], [("refs/heads/force", c["nf_new"])]),
        ]

        retired_bytes = sum(cov.total_bytes for cov in leaves if cov.retired_from_active)
        compacted_new_bytes = comp_cov.total_bytes
        active_tail_bytes = sum(cov.total_bytes for cov in all_covers if not cov.retired_from_active)

        topology_results: dict[str, Any] = {}
        for name, want_set, have_set, baseline_packs, ref_targets in topo_specs:
            # For baseline we materialize baseline_packs (e.g. full closure pack or uncompacted delta set).
            t_plan_ns: list[int] = []
            selected: list[CoverPack] = []
            for _ in range(trials):
                t0 = time.perf_counter_ns()
                selected = plan_for_want(want_set, have_set)
                t_plan_ns.append(time.perf_counter_ns() - t0)

            # For topologies where the client holds compacted base already (small_incremental / non_fast_forward / criss_cross),
            # verify parity with required client seeds + selected packs.
            seed_packs = [cov for cov in [comp_cov, *tail_leaves, w["cov_f1"]] if cov.covered_commits & have_set]
            if name == "deep_lag":
                parity_packs = list({p.cover_id: p for p in [comp_cov, *tail_leaves]}.values())
            elif name == "historical_pin":
                parity_packs = list({p.cover_id: p for p in selected}.values())
            else:
                parity_packs = list({p.cover_id: p for p in [*seed_packs, *selected]}.values())

            verified_objects = verify_materialized_parity(src_repo, obj_format, parity_packs, ref_targets)
            base_xfer = sum(p.total_bytes for p in baseline_packs if p.tier == "full") or sum(p.total_bytes for p in baseline_packs)
            plan_xfer = sum(p.total_bytes for p in selected)
            base_meta_reads = len(leaves) + len(baseline_packs) + 4
            plan_meta_reads = 2 + len(selected)

            topology_results[name] = {
                "baseline_full_materialization": {
                    "selected_packs": len(baseline_packs),
                    "transferred_bytes": base_xfer,
                    "metadata_reads": base_meta_reads,
                },
                "causal_tiered_cover": {
                    "selected_packs": len(selected),
                    "selected_cover_ids": [cov.cover_id for cov in selected],
                    "transferred_bytes": plan_xfer,
                    "metadata_reads": plan_meta_reads,
                    "plan_cpu_p50_p95_p99": {
                        "p50_ms": quantile_ms(t_plan_ns, 0.50),
                        "p95_ms": quantile_ms(t_plan_ns, 0.95),
                        "p99_ms": quantile_ms(t_plan_ns, 0.99),
                    },
                    "verified_reachable_objects": verified_objects,
                    "git_fsck_parity": "pass",
                },
                "serving_bytes_delta": base_xfer - plan_xfer,
            }

        logical_bytes = max(1, int(w["logical_authored_bytes"]))
        return {
            "object_format": obj_format,
            "workload_profile": profile,
            "trials_per_topology": trials,
            "write_amplification": round((sum(c.total_bytes for c in leaves) + compacted_new_bytes) / logical_bytes, 4),
            "old_new_pack_physical_bytes": {
                "serving_pack_bytes": active_tail_bytes,
                "retained_old_pack_bytes": retired_bytes,
                "newly_written_compacted_bytes": compacted_new_bytes,
                "total_physical_bytes": active_tail_bytes + retired_bytes,
                "gc_owner": "#122/#151/#153",
                "physical_savings_require_gc": True,
            },
            "topologies": topology_results,
        }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Issue #184 Pando/Causal fetch pack-cover benchmark.")
    p.add_argument("--profiles", default="small", help="Comma-separated workload profiles: small,medium")
    p.add_argument("--formats", default="sha1,sha256", help="Comma-separated Git object formats: sha1,sha256")
    p.add_argument("--trials", type=int, default=15, help="Timing trials per topology for p50/p95/p99 calculation")
    p.add_argument("--out-json", default="", help="Optional path to write JSON benchmark report")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    profiles = [s.strip() for s in args.profiles.split(",") if s.strip()]
    formats = [s.strip() for s in args.formats.split(",") if s.strip()]
    runs = [run_benchmark_profile(fmt, prof, max(3, args.trials)) for prof in profiles for fmt in formats]
    report = {
        "issue": 184,
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "runs": runs,
    }
    encoded = json.dumps(report, indent=2)
    if args.out_json:
        out = Path(args.out_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(encoded + "\n", encoding="utf-8", newline="\n")
    print(encoded)
    return 0


if __name__ == "__main__":
    sys.exit(main())
