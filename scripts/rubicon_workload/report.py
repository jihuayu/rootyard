"""Report statistics, redaction, schema validation, and markdown rendering (Refs #164)."""

from __future__ import annotations

import json
from typing import Any

from .corpus import DATASET_CLASSES

OUTCOME_CLASSES: tuple[str, ...] = ("committed_success", "typed_refusal", "unknown_outcome")


def percentile_stats(samples_ms: list[float]) -> dict[str, Any]:
    """Compute min, p50, p95, p99, max, and mean milliseconds without smoothing artifacts."""
    if not samples_ms:
        return {
            "count": 0,
            "min_ms": None,
            "p50_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "max_ms": None,
            "mean_ms": None,
        }
    ordered = sorted(float(v) for v in samples_ms)
    n = len(ordered)

    def pct(p: int) -> float:
        idx = max(0, min(n - 1, (n * p + 99) // 100 - 1))
        return round(ordered[idx], 3)

    return {
        "count": n,
        "min_ms": round(ordered[0], 3),
        "p50_ms": pct(50),
        "p95_ms": pct(95),
        "p99_ms": pct(99),
        "max_ms": round(ordered[-1], 3),
        "mean_ms": round(sum(ordered) / n, 3),
    }


def compute_overlap_metrics(intervals_ns: list[tuple[int, int]]) -> dict[str, Any]:
    """Measure true concurrent wall-clock overlap across (start_ns, end_ns) intervals."""
    if not intervals_ns:
        return {
            "total_ops": 0,
            "max_concurrent_overlap": 0,
            "overlapped_pairs": 0,
            "wall_span_ms": 0.0,
            "sum_op_durations_ms": 0.0,
        }
    events: list[tuple[int, int]] = []
    min_start = intervals_ns[0][0]
    max_end = intervals_ns[0][1]
    sum_ns = 0
    for s, e in intervals_ns:
        if e < s:
            s, e = e, s
        min_start = min(min_start, s)
        max_end = max(max_end, e)
        sum_ns += e - s
        events.append((s, 1))
        events.append((e, -1))
    # Process end events (-1) before simultaneous start events (+1) at equal timestamps.
    events.sort(key=lambda item: (item[0], item[1]))
    active = 0
    max_overlap = 0
    for _, delta in events:
        active += delta
        if active > max_overlap:
            max_overlap = active
    overlapped_pairs = 0
    for i in range(len(intervals_ns)):
        s_i, e_i = intervals_ns[i]
        for j in range(i + 1, len(intervals_ns)):
            s_j, e_j = intervals_ns[j]
            if s_i < e_j and s_j < e_i:
                overlapped_pairs += 1
    return {
        "total_ops": len(intervals_ns),
        "max_concurrent_overlap": max_overlap,
        "overlapped_pairs": overlapped_pairs,
        "wall_span_ms": round((max_end - min_start) / 1_000_000.0, 3),
        "sum_op_durations_ms": round(sum_ns / 1_000_000.0, 3),
    }


def redact_text(value: Any, secrets: tuple[str, ...] | list[str]) -> str:
    """Replace sensitive credentials/DSNs/tokens with [REDACTED]."""
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def find_secret_leaks(report: Any, secrets: tuple[str, ...] | list[str]) -> list[str]:
    """Scan serialized JSON report for accidental leakage of secrets or credentials."""
    serialized = json.dumps(report, sort_keys=True)
    leaked: list[str] = []
    for idx, secret in enumerate(secrets):
        if secret and len(secret) >= 4 and secret in serialized:
            leaked.append(f"secret[{idx}]")
    return leaked


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _check_nonneg_int(val: Any, name: str) -> int:
    _require(isinstance(val, int) and not isinstance(val, bool) and val >= 0, f"{name} must be non-negative int")
    return val


def validate_tier(tier: dict[str, Any]) -> None:
    """Validate invariants for a single compute-process scaling tier."""
    procs = tier.get("compute_processes")
    _require(procs in (1, 2, 4), f"unexpected compute_processes={procs!r}")
    outcomes = tier.get("outcomes")
    _require(isinstance(outcomes, dict), "tier.outcomes missing")
    total_ops = _check_nonneg_int(outcomes.get("total_ops"), "tier.outcomes.total_ops")
    counts = {cls: _check_nonneg_int(outcomes.get(cls), f"tier.outcomes.{cls}") for cls in OUTCOME_CLASSES}
    _require(sum(counts.values()) == total_ops and total_ops > 0, "tier.outcomes must partition total_ops > 0")

    overlap = tier.get("independent_ref_overlap")
    _require(isinstance(overlap, dict), "tier.independent_ref_overlap missing")
    _require(
        _check_nonneg_int(overlap.get("max_concurrent_overlap"), "max_concurrent_overlap") >= 2,
        "independent_ref_overlap failed to demonstrate simultaneous overlap >= 2",
    )

    same_repo = tier.get("same_repo_mixed_concurrency")
    _require(isinstance(same_repo, dict), "tier.same_repo_mixed_concurrency missing")
    _require(
        _check_nonneg_int(same_repo.get("max_concurrent_overlap"), "same_repo.max_concurrent_overlap") >= 2,
        "same_repo_mixed_concurrency failed to demonstrate simultaneous overlap >= 2",
    )
    _require(
        _check_nonneg_int(same_repo.get("committed_success"), "same_repo.committed_success") >= 1,
        "same_repo_mixed_concurrency committed no branch",
    )

    cas = tier.get("cas_race")
    _require(isinstance(cas, dict), "tier.cas_race missing")
    participants = _check_nonneg_int(cas.get("participants"), "cas_race.participants")
    _require(participants >= 2, "cas_race requires >= 2 participants")
    _require(cas.get("winner_count") == 1, "cas_race must have exactly 1 winner")
    _require(cas.get("loser_refused") == participants - 1, "cas_race loser count mismatch")
    _require(cas.get("false_ok") == 0, "cas_race recorded false ok")
    _require(cas.get("remote_ref_matches_winner") is True, "cas_race remote ref mismatch")

    atomic = tier.get("atomic_vs_subset")
    _require(isinstance(atomic, dict), "tier.atomic_vs_subset missing")
    _require(atomic.get("atomic_rejected_unchanged") is True, "atomic push mutated refs")
    _require(atomic.get("subset_partial_exact") is True, "subset push partial outcome mismatch")
    _require(atomic.get("atomic_positive_committed") is True, "positive atomic push failed")

    fault = tier.get("fault_revocation_window")
    _require(isinstance(fault, dict), "tier.fault_revocation_window missing")
    fault_total = _check_nonneg_int(fault.get("total_attempts"), "fault.total_attempts")
    _require(fault_total >= 2, "fault_revocation_window requires >= 2 attempts")
    _require(fault.get("committed_success") == 0, "fault_revocation_window counted refusal/unknown as success")
    fault_refused = _check_nonneg_int(fault.get("typed_refusal"), "fault.typed_refusal")
    fault_unknown = _check_nonneg_int(fault.get("unknown_outcome"), "fault.unknown_outcome")
    _require(fault_refused + fault_unknown == fault_total, "fault_revocation_window outcomes mismatch")

    audit = tier.get("audit")
    _require(isinstance(audit, dict), "tier.audit missing")
    acked = _check_nonneg_int(audit.get("acked_targets_total"), "audit.acked_targets_total")
    verified = _check_nonneg_int(audit.get("verified_exact"), "audit.verified_exact")
    _require(acked >= 1 and verified == acked, "steady-state audit did not verify 100% of ACKed targets")
    _require(audit.get("fsck_failed") == 0, "steady-state audit detected git fsck failures")
    _require(audit.get("ref_mismatch") == 0, "steady-state audit detected ref mismatches")

    storage = tier.get("storage_accounting")
    _require(isinstance(storage, dict), "tier.storage_accounting missing")
    serving_bytes = _check_nonneg_int(storage.get("serving_pack_bytes"), "storage.serving_pack_bytes")
    coexisting_bytes = _check_nonneg_int(storage.get("coexisting_pack_bytes"), "storage.coexisting_pack_bytes")
    _require(coexisting_bytes >= serving_bytes, "coexisting_pack_bytes must be >= serving_pack_bytes")
    gc_executed = storage.get("gc_executed")
    _require(isinstance(gc_executed, bool), "storage.gc_executed must be bool")
    reclaimed = _check_nonneg_int(storage.get("gc_reclaimed_physical_bytes"), "storage.gc_reclaimed_physical_bytes")
    if not gc_executed or reclaimed == 0:
        _require(
            storage.get("physical_savings_claimed") is False,
            "cannot claim physical storage savings without actual GC deletion",
        )

    by_dataset = tier.get("latency_by_dataset_class")
    _require(isinstance(by_dataset, dict), "tier.latency_by_dataset_class missing")
    for ds_name in DATASET_CLASSES:
        stats = by_dataset.get(ds_name)
        _require(isinstance(stats, dict) and _check_nonneg_int(stats.get("count"), f"{ds_name}.count") >= 1,
                 f"missing measured dataset class {ds_name}")

    by_op = tier.get("latency_by_op_class")
    _require(isinstance(by_op, dict) and len(by_op) >= 1, "tier.latency_by_op_class missing")

    cold_warm = tier.get("cold_vs_warm")
    _require(isinstance(cold_warm, dict), "tier.cold_vs_warm missing")
    for metric in ("cold_clone", "warm_clone", "cold_browse", "warm_browse"):
        _require(
            isinstance(cold_warm.get(metric), dict) and cold_warm[metric].get("count", 0) >= 1,
            f"{metric} measurements missing",
        )

    series = tier.get("time_series")
    _require(isinstance(series, list) and len(series) >= 1, "tier.time_series must be non-empty")
    for sample in series:
        for key in ("pack_count", "coexisting_pack_bytes", "serving_pack_bytes", "active_serving_reads", "pending_ops"):
            _check_nonneg_int(sample.get(key), f"time_series.{key}")


def validate_report(report: dict[str, Any], secrets: tuple[str, ...] | list[str] = ()) -> None:
    """Validate top-level Rubicon mixed-workload report provenance, invariants, and secret hygiene."""
    _require(isinstance(report, dict), "report must be a dict")
    _require(report.get("schema_version") == "rootyard/rubicon-mixed-workload/v1", "invalid schema_version")
    _require(report.get("issue") == "#164", "issue must be #164")
    _require(report.get("measurement_kind") == "native_execution", "measurement_kind must be native_execution")
    _require(not report.get("simulated", False), "simulated benchmarks cannot satisfy gate")

    source = report.get("source")
    _require(isinstance(source, dict) and bool(source.get("commit")), "source commit missing")
    binary = report.get("binary")
    _require(isinstance(binary, dict) and len(str(binary.get("sha256", ""))) == 64, "binary.sha256 missing")
    if binary.get("receipt_verified"):
        _require(
            binary.get("workspace_commit") == source.get("commit"),
            "receipt workspace_commit differs from report source.commit",
        )
        _require(
            source.get("receipt_workspace_commit") == source.get("commit"),
            "source.receipt_workspace_commit differs from source.commit",
        )
        _require(
            len(str(binary.get("source_inputs_sha256", ""))) == 64,
            "binary.source_inputs_sha256 missing for verified receipt",
        )
        _require(
            len(str(binary.get("receipt_sha256", ""))) == 64,
            "binary.receipt_sha256 missing for verified receipt",
        )
        if binary.get("receipt_schema") == "v2":
            _require(
                len(str(binary.get("config_digest", ""))) == 64,
                "binary.config_digest missing for v2 receipt",
            )
    tools = report.get("tools")
    _require(isinstance(tools, dict) and bool(tools.get("git")) and bool(tools.get("postgres")), "tools metadata missing")
    _require(isinstance(report.get("seed"), int), "seed must be int")
    _require(isinstance(report.get("topology"), str) and bool(report.get("topology")), "topology description missing")
    _require(isinstance(report.get("limitations"), list) and len(report["limitations"]) >= 1, "limitations missing")

    tiers = report.get("tiers")
    _require(isinstance(tiers, list) and len(tiers) >= 1, "at least one compute tier required")
    seen_procs: list[int] = []
    for tier in tiers:
        validate_tier(tier)
        seen_procs.append(tier["compute_processes"])
    _require(seen_procs == sorted(seen_procs) and len(seen_procs) == len(set(seen_procs)),
             "tiers must be strictly ascending unique compute process counts")

    scaling = report.get("scaling_comparison")
    _require(isinstance(scaling, dict) and isinstance(scaling.get("bottlenecks"), list), "scaling_comparison missing")

    leaks = find_secret_leaks(report, secrets)
    _require(not leaks, f"report leaked sensitive values: {leaks}")


def render_summary_markdown(report: dict[str, Any]) -> str:
    """Render a concise human-readable markdown summary from a validated report."""
    binary = report["binary"]
    receipt_details = ""
    if binary.get("receipt_verified"):
        receipt_details = (
            f" | receipt commit `{binary.get('workspace_commit')}`, "
            f"config_digest `{binary.get('config_digest')}`"
        )
    lines = [
        "# Rubicon Mixed Workload & Compute Scaling Baseline (Issue #164)",
        "",
        f"- **Source Commit**: `{report['source']['commit']}` (dirty: `{report['source'].get('dirty')}`)",
        f"- **Binary SHA-256**: `{binary['sha256']}` (receipt verified: `{binary.get('receipt_verified')}`{receipt_details})",
        f"- **Git / PostgreSQL**: `{report['tools'].get('git')}` / `{report['tools'].get('postgres')}`",
        f"- **Seed / Topology**: `{report['seed']}` — {report['topology']}",
        "",
        "| Compute Processes | Wall (s) | Committed / Total Ops | Throughput (ops/s) | Cross-Repo / Same-Repo Overlap | Cold Clone P50 (ms) | Warm Clone P50 (ms) | Peak RSS (KiB) | Peak Temp Disk (B) | Serving / Coexisting Pack Bytes | S3 GET / PUT (wire) |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for tier in report["tiers"]:
        out = tier["outcomes"]
        cw = tier["cold_vs_warm"]
        st = tier["storage_accounting"]
        s3 = tier.get("s3_wire") or {}
        s3_str = (
            f"{s3.get('get_requests', 0)} ({s3.get('get_bytes', 0)} B) / {s3.get('put_requests', 0)} ({s3.get('put_bytes', 0)} B)"
            if s3.get("observed")
            else "unmetered (external)"
        )
        peaks = tier.get("resource_peaks", {})
        rss_val = peaks.get("max_total_rss_kib")
        rss_str = str(rss_val) if rss_val is not None else "n/a"
        disk_val = peaks.get("max_temp_disk_bytes")
        disk_str = str(disk_val) if disk_val is not None else "n/a"
        cross_ov = tier["independent_ref_overlap"]["max_concurrent_overlap"]
        same_ov = tier["same_repo_mixed_concurrency"]["max_concurrent_overlap"]
        lines.append(
            f"| {tier['compute_processes']} | {tier['wall_seconds']:.2f} | "
            f"{out['committed_success']} / {out['total_ops']} | "
            f"{tier['committed_ops_per_sec']:.3f} | "
            f"{cross_ov} / {same_ov} | "
            f"{cw['cold_clone']['p50_ms']} | {cw['warm_clone']['p50_ms']} | "
            f"{rss_str} | {disk_str} | {st['serving_pack_bytes']} / {st['coexisting_pack_bytes']} | {s3_str} |"
        )
    lines.append("")
    lines.append("## Scaling & Bottleneck Observations")
    for note in report["scaling_comparison"]["bottlenecks"]:
        lines.append(f"- {note}")
    lines.append("")
    lines.append("## Truth Boundaries & Limitations")
    for lim in report["limitations"]:
        lines.append(f"- {lim}")
    return "\n".join(lines) + "\n"
