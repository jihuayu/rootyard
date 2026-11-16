#!/usr/bin/env python3
"""CLI entrypoint for Issue #178 Git native pack compression and delta cost-benefit evaluation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from pack_compression_eval.corpus import (  # noqa: E402
    DATASET_ARCHETYPES,
    isolated_git_env,
    resolve_trusted_git,
    seed_multi_push_bare_repo,
)
from pack_compression_eval.correctness import run_correctness_suite  # noqa: E402
from pack_compression_eval.e2e_serve_blob import run_live_serve_blob_eval  # noqa: E402
from pack_compression_eval.failure_diagnostics import (  # noqa: E402
    FailureArtifactError,
    failure_path_for,
    failure_record_from_exception,
    write_failure_json,
)
from pack_compression_eval.live_server import resolve_live_env  # noqa: E402
from pack_compression_eval.pack_matrix import CANDIDATE_CONFIGS, evaluate_repo_pack_matrix  # noqa: E402
from pack_compression_eval.report import (  # noqa: E402
    _derive_candidate_summary,
    build_recommendations,
    render_summary_markdown,
    validate_report,
)


@dataclass(frozen=True)
class EvalConfig:
    """Configuration inputs for pando_pack_compression_eval."""

    mode: str
    scale: str
    report_path: Path
    summary_md: Path | None
    binary: str | None
    git: str | None
    seed: int
    require_receipt: bool
    keep: bool


def _git_source_meta() -> dict[str, Any]:
    root = SCRIPT_DIR.parent
    try:
        commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True, timeout=10).strip()
        dirty = bool(subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True, timeout=10).strip())
        return {"source_commit": commit, "source_dirty": dirty}
    except Exception:  # noqa: BLE001
        return {"source_commit": None, "source_dirty": None}


def run_evaluation(config: EvalConfig) -> dict[str, Any]:
    """Execute controlled pack matrix, SHA-1/SHA-256 verification, and optional full E2E."""
    secrets: list[str] = []
    work_root: Path | None = None
    try:
        git_bin = resolve_trusted_git(config.git)
        git_ver = subprocess.check_output([str(git_bin), "--version"], text=True, timeout=10).strip()
        work_root = Path(tempfile.mkdtemp(prefix="rootyard-pack-eval-"))
        os.chmod(work_root, 0o700)

        if config.mode == "full":
            if not config.binary:
                raise RuntimeError("--binary is required in --mode full")
            secrets.extend(resolve_live_env(os.environ).secrets)

        base_env = isolated_git_env(os.environ)
        matrices: list[dict[str, Any]] = []
        clone_runs = 3 if config.scale == "full" else 1
        for arch in DATASET_ARCHETYPES:
            arch_root = work_root / "matrix" / arch
            arch_root.mkdir(parents=True, exist_ok=True)
            seeded = seed_multi_push_bare_repo(
                git_bin, arch, config.seed, config.scale, arch_root / "repo", base_env, object_format="sha1"
            )
            matrices.append(
                evaluate_repo_pack_matrix(git_bin, seeded, CANDIDATE_CONFIGS, arch_root / "eval", base_env, clone_runs=clone_runs)
            )

        correctness = run_correctness_suite(git_bin, config.seed, config.scale, work_root / "correctness", base_env, CANDIDATE_CONFIGS)
        candidate_totals = _derive_candidate_summary(matrices)

        e2e_summary: dict[str, Any] | None = None
        if config.mode == "full":
            assert config.binary is not None
            e2e_summary = run_live_serve_blob_eval(
                config.binary,
                str(git_bin),
                config.seed,
                config.scale,
                config.require_receipt,
                work_root / "e2e",
                config.keep,
            )

        recommendations = build_recommendations(matrices, candidate_totals, e2e_summary)
        src_meta = _git_source_meta()
        report: dict[str, Any] = {
            "schema_version": "rootyard/pando-pack-compression-eval/v1",
            "issue": "#178",
            "simulated": False,
            "mode": config.mode,
            "scale": config.scale,
            "seed": config.seed,
            "environment": {
                "git": str(git_bin),
                "git_version": git_ver,
                "platform": platform.system(),
                "machine": platform.machine(),
                "logical_cpus": os.cpu_count() or 1,
                **src_meta,
            },
            "pack_matrix": matrices,
            "candidate_totals": candidate_totals,
            "correctness": correctness,
            "e2e_serve_blob": e2e_summary,
            "recommendations": recommendations,
            "limitations": [
                "Single-host controlled evaluation; results depend on CPU/NVMe/S3 host hardware and must not be claimed as cross-host cluster throughput.",
                "Push-time aggressive repack stays disabled; only controlled background compaction candidates are compared.",
                "serve-blob runs leave RefStore/Blob physical GC disabled: coexisting_non_gc_bytes quantifies retained uncompacted + compacted packs with zero physical billing savings claimed.",
                "local_isolated_post_unlink_pack_idx_bytes reflects an isolated local bare copy after removing pre-compaction packs and does not prove remote S3 physical deletion in serve-blob.",
                "Non-Linux hosts without /proc or os.wait4 leave peak_rss_kib and CPU ticks null rather than fabricating memory usage.",
            ],
        }
        validate_report(report, secrets=secrets)
        config.report_path.parent.mkdir(parents=True, exist_ok=True)
        config.report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        if config.summary_md is not None:
            config.summary_md.parent.mkdir(parents=True, exist_ok=True)
            config.summary_md.write_text(render_summary_markdown(report), encoding="utf-8", newline="\n")
        return report
    except Exception as exc:  # noqa: BLE001
        source_meta = _git_source_meta()
        record = failure_record_from_exception(
            exc, mode=config.mode, scale=config.scale, seed=config.seed, source_meta=source_meta
        )
        try:
            write_failure_json(failure_path_for(config.report_path), record)
        except Exception:  # noqa: BLE001 - preserve the original failure exit
            pass
        raise FailureArtifactError(record) from None
    finally:
        if work_root is not None and not config.keep:
            shutil.rmtree(work_root, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate native Git pack compression & delta trade-offs (Refs #178)")
    parser.add_argument("--mode", choices=("full", "git-only"), default="full", help="full requires live PG17+S3+serve-blob; git-only runs stock Git matrix locally")
    parser.add_argument("--scale", choices=("quick", "full"), default="full", help="Corpus scale")
    parser.add_argument("--binary", default=None, help="Path to built rootyard binary (required in full mode)")
    parser.add_argument("--git", default=None, help="Explicit stock git executable path")
    parser.add_argument("--report", type=Path, required=True, help="Output JSON report path")
    parser.add_argument("--summary-md", type=Path, default=None, help="Optional Markdown summary output path")
    parser.add_argument("--seed", type=int, default=17820261116, help="Deterministic RNG seed")
    parser.add_argument("--allow-missing-build-receipt", action="store_true", help="Allow binary without .build.json receipt locally")
    parser.add_argument("--keep", action="store_true", help="Preserve temporary directories")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = EvalConfig(
        mode=args.mode,
        scale=args.scale,
        report_path=args.report,
        summary_md=args.summary_md,
        binary=args.binary,
        git=args.git,
        seed=args.seed,
        require_receipt=not args.allow_missing_build_receipt,
        keep=args.keep,
    )
    try:
        run_evaluation(cfg)
    except FailureArtifactError as exc:
        print(f"pando-pack-compression-eval failed: {exc.summary}", file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001 - final boundary never prints raw exception text
        print("pando-pack-compression-eval failed: phase=unknown failure_class=unclassified", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
