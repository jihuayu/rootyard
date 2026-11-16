#!/usr/bin/env python3
"""CLI entrypoint for the self-hosted Rubicon mixed Git/HTTP/PG/Blob benchmark (Refs #164)."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rubicon_workload.report import render_summary_markdown  # noqa: E402
from rubicon_workload.runner import PreflightError, WorkloadConfig, run_rubicon_workload  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run self-hosted Rubicon mixed workload benchmark (Refs #164)")
    parser.add_argument("--binary", required=True, help="Absolute path to built rootyard binary")
    parser.add_argument("--git", default=None, help="Absolute path to trusted stock git binary")
    parser.add_argument("--report", required=True, help="Output JSON report path")
    parser.add_argument("--summary-md", default=None, help="Optional Markdown summary output path")
    parser.add_argument("--seed", type=int, default=16420261116, help="Deterministic RNG seed")
    parser.add_argument("--tiers", default="auto", help="Compute process tiers ('auto' or comma list e.g. '1,2,4')")
    parser.add_argument("--duration-seconds", type=int, default=12, help="Mixed push wave duration budget per tier")
    parser.add_argument("--warmup-seconds", type=int, default=2, help="Warmup pause budget after repo seeding")
    parser.add_argument("--s3-meter", choices=("auto", "off"), default="auto", help="Loopback S3 HTTP wire-tap meter mode")
    parser.add_argument(
        "--allow-missing-build-receipt",
        action="store_true",
        help="Allow local unreceipted binaries (disallowed in CI gates)",
    )
    parser.add_argument("--keep", action="store_true", help="Keep scratch directories on disk (PG schema still dropped)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = WorkloadConfig(
        binary=args.binary,
        report=args.report,
        git=args.git,
        summary_md=args.summary_md,
        seed=args.seed,
        tiers=args.tiers,
        duration_seconds=args.duration_seconds,
        warmup_seconds=args.warmup_seconds,
        s3_meter=args.s3_meter,
        require_build_receipt=not args.allow_missing_build_receipt,
        keep=args.keep,
    )
    try:
        report = run_rubicon_workload(config)
    except (PreflightError, RuntimeError, ValueError) as exc:
        print(f"rubicon-mixed-workload failed: {exc}", file=sys.stderr)
        return 1

    if args.summary_md:
        summary_path = Path(args.summary_md)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(render_summary_markdown(report), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
