#!/usr/bin/env python3
"""Issue #179 CLI runner for Pando OID localization & Blob Range GET evaluation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.pando_range_eval.benchmarks import run_evaluation  # noqa: E402


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Issue #179 Evaluation Summary (`scale={report['scale']}`)",
        "",
        f"- **Git**: `{report['git_version']}`",
        f"- **Simulated GET RTT**: `{report['simulated_rtt_ms']} ms`",
        "",
        "## Fixture Profiles",
        "",
        "| Format | Packs | Pack Bytes | Index Bytes | Total Objects | MIDX Entries | Cross-Pack Thin Deltas |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for algo, f in report["fixtures"].items():
        lines.append(
            f"| `{algo}` | {f['packs']} | {f['total_pack_bytes']} | {f['total_idx_bytes']} | "
            f"{f['total_objects']} | {f['midx_objects']} | {f['cross_pack_thin_deltas']} |"
        )
    lines.extend([
        "",
        "## Workload Comparison (Range-Read vs Full-Pack Cached `#163`)",
        "",
        "| Algo | Workload | Mode | Full GETs | Range GETs | Bytes Downloaded | Logical Bytes | Amp | P50 ms | P95 ms | P99 ms | Scratch B |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for row in report["benchmarks"]:
        lines.append(
            f"| `{row['algo']}` | `{row['workload']}` | `{row['mode']}` | {row['full_gets']} | {row['range_gets']} | "
            f"{row['bytes_downloaded']} | {row['logical_bytes']} | {row['download_amplification']}x | "
            f"{row['p50_ms']} | {row['p95_ms']} | {row['p99_ms']} | {row['scratch_disk_bytes']} |"
        )
    lines.extend(["", "## Adversarial Fail-Closed Experiments", ""])
    for algo, cases in report["adversarial"].items():
        lines.append(f"- `{algo}`: {len(cases)}/{len(cases)} fail-closed (`" + ", ".join(c["observed_code"] for c in cases) + "`)")
    if report.get("garage_s3_range_probe"):
        g = report["garage_s3_range_probe"]
        lines.extend([
            "",
            "## Live Garage S3 Range Probe",
            "",
            f"- `206 Partial Content` `{g['range_bytes']}B` out of `{g['pack_total_bytes']}B` pack (`Content-Range: {g['content_range']}`, `wrong If-Match -> HTTP {g['wrong_if_match_status']}`, `{g['latency_ms']} ms`).",
        ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Issue #179 OID->pack/offset Range GET feasibility suite")
    parser.add_argument("--scale", choices=("quick", "full"), default="quick")
    parser.add_argument("--simulated-rtt-ms", type=float, default=0.0)
    parser.add_argument("--s3-env", type=Path, default=None)
    parser.add_argument("--require-s3", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--markdown-out", type=Path, default=None)
    args = parser.parse_args(argv)

    report = run_evaluation(
        scale=args.scale,
        simulated_rtt_ms=args.simulated_rtt_ms,
        s3_env_file=args.s3_env,
        require_s3=args.require_s3,
    )
    rendered_json = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered_json, encoding="utf-8")
    else:
        print(rendered_json, end="")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
