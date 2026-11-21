"""Report synthesis, fail-closed validation, redaction, and Markdown rendering (Refs #178)."""

from __future__ import annotations

import json
import math
import re
from typing import Any

from .corpus import DATASET_ARCHETYPES, OBJECT_FORMATS
from .telemetry import percentile_stats

_TOKEN_RE = re.compile(r"ryt_[0-9A-Za-z_-]{16,}")
_BEARER_RE = re.compile(r"(?i)(Bearer\s+)[0-9A-Za-z._~+/=-]{8,}")
_PG_URL_RE = re.compile(r"postgres(?:ql)?://[^\s\"'<>]+")


FETCH_MEASUREMENT_NOTES = {
    "transport": "stock_git_smart_http",
    "ref": "refs/heads/main",
    "cold": "first_fetch_per_repo_after_owned_server_restart_with_clean_scratch",
    "warm": "second_fetch_per_repo_in_same_server_process",
    "client": "new_empty_bare_client_explicit_object_format",
    "timed_operation": "git_fetch_only",
    "verification": "exact_expected_oid_and_strict_fsck",
    "os_page_cache_isolated": False,
    "physical_store_cache_claimed": False,
}


def redact_text(value: Any, secrets: tuple[str, ...] | list[str]) -> str:
    """Scrub tokens, bearer headers, DSNs, and explicit secrets from text."""
    text = str(value)
    for sec in secrets:
        if sec:
            text = text.replace(sec, "[REDACTED]")
    text = _TOKEN_RE.sub("[REDACTED]", text)
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _PG_URL_RE.sub("postgresql://[REDACTED]", text)
    return text


def find_secret_leaks(payload: Any, secrets: tuple[str, ...] | list[str]) -> list[str]:
    """Return identifiers of any secret fragments present in serialized JSON."""
    serialized = json.dumps(payload, sort_keys=True)
    leaked: list[str] = []
    for idx, sec in enumerate(secrets):
        if sec and len(sec) >= 4 and sec in serialized:
            leaked.append(f"secret[{idx}]")
    if _TOKEN_RE.search(serialized):
        leaked.append("ryt_token_pattern")
    return leaked


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _derive_candidate_summary(matrices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate purely measured per-config deltas across all measured archetypes."""
    by_cfg: dict[str, list[dict[str, Any]]] = {}
    for entry in matrices:
        for cand in entry["candidates"]:
            by_cfg.setdefault(cand["config"]["name"], []).append(
                {
                    "archetype": entry["archetype"],
                    "pre_bytes": entry["pre_compaction"]["pack_idx_total_bytes"],
                    **cand,
                }
            )
    rows: list[dict[str, Any]] = []
    for cfg_name, items in by_cfg.items():
        total_pre = sum(int(i["pre_bytes"]) for i in items)
        total_compacted = sum(int(i["compacted_pack_idx_bytes"]) for i in items)
        total_default = sum(
            int(next(c["compacted_pack_idx_bytes"] for c in m["candidates"] if c["config"]["name"] == "rootyard_default"))
            for m in matrices
        )
        total_wall_ms = round(sum(float(i["compaction_wall_ms"]) for i in items), 3)
        cpu_vals = [float(i["compaction_cpu_seconds"]) for i in items if i["compaction_cpu_seconds"] is not None]
        rss_vals = [int(i["peak_rss_kib"]) for i in items if i["peak_rss_kib"] is not None]
        rows.append(
            {
                "config_name": cfg_name,
                "config": items[0]["config"],
                "archetypes_measured": len(items),
                "total_pre_compaction_bytes": total_pre,
                "total_compacted_pack_idx_bytes": total_compacted,
                "total_coexisting_non_gc_bytes": total_pre + total_compacted,
                "vs_rootyard_default_bytes": total_compacted - total_default,
                "vs_rootyard_default_pct": round(((total_compacted - total_default) / float(total_default)) * 100.0, 2)
                if total_default > 0
                else 0.0,
                "vs_uncompacted_pct": round(((total_compacted - total_pre) / float(total_pre)) * 100.0, 2)
                if total_pre > 0
                else 0.0,
                "sum_compaction_wall_ms": total_wall_ms,
                "sum_compaction_cpu_seconds": round(sum(cpu_vals), 4) if cpu_vals else None,
                "max_peak_rss_kib": max(rss_vals) if rss_vals else None,
                "max_delta_chain_depth": max(int(i["max_delta_chain_depth"]) for i in items),
                "physical_savings_claimed": False,
            }
        )
    return rows


def build_recommendations(
    matrices: list[dict[str, Any]],
    candidate_totals: list[dict[str, Any]],
    e2e_serve_blob: dict[str, Any] | None,
) -> dict[str, Any]:
    """Synthesize strict evidence-backed parameter recommendations and rollback criteria."""
    by_arch = {m["archetype"]: m for m in matrices}
    media = by_arch.get("compressed_media")
    sim = by_arch.get("similar_files")
    small = by_arch.get("small_deltas")

    media_c0_delta = None
    if media:
        c0 = next((c for c in media["candidates"] if c["config"]["name"] == "zlib_store_c0"), None)
        dflt = next((c for c in media["candidates"] if c["config"]["name"] == "rootyard_default"), None)
        if c0 and dflt:
            media_c0_delta = {
                "pack_bytes_diff": c0["compacted_pack_idx_bytes"] - dflt["compacted_pack_idx_bytes"],
                "c0_wall_ms": c0["compaction_wall_ms"],
                "default_wall_ms": dflt["compaction_wall_ms"],
            }

    sim_wide_delta = None
    if sim:
        wide = next((c for c in sim["candidates"] if c["config"]["name"] == "wide_window_c6_w50_t2"), None)
        dflt = next((c for c in sim["candidates"] if c["config"]["name"] == "rootyard_default"), None)
        if wide and dflt:
            sim_wide_delta = {
                "pack_bytes_diff": wide["compacted_pack_idx_bytes"] - dflt["compacted_pack_idx_bytes"],
                "wide_wall_ms": wide["compaction_wall_ms"],
                "default_wall_ms": dflt["compaction_wall_ms"],
            }

    small_consolidation = None
    if small:
        dflt = next((c for c in small["candidates"] if c["config"]["name"] == "rootyard_default"), None)
        if dflt:
            small_consolidation = {
                "pre_pack_count": small["pre_compaction"]["pack_count"],
                "pre_bytes": small["pre_compaction"]["pack_idx_total_bytes"],
                "consolidated_default_bytes": dflt["compacted_pack_idx_bytes"],
                "coexisting_non_gc_bytes": dflt["coexisting_non_gc_bytes"],
            }

    return {
        "default_push_path": {
            "action": "keep_status_quo",
            "config": "pack.compression=-1, pack.window=10, pack.depth=50, pack.windowMemory=32m, pack.threads=1",
            "rationale": "Never enable aggressive repack or wide windows on interactive Smart HTTP git-receive-pack; compaction consolidation alone already collapses multi-pack overhead in small_deltas/text repos without inflating push tail latency or RSS.",
        },
        "background_compaction_candidate": {
            "action": "keep_32m_default_baseline_and_allow_opt_in_balanced_w25_t2_only_when_gc_active",
            "primary_evidence": {
                "compressed_media_c0_vs_default": media_c0_delta,
                "similar_files_wide_w50_vs_default": sim_wide_delta,
                "small_deltas_consolidation": small_consolidation,
                "e2e_serve_blob_executed": bool(e2e_serve_blob and e2e_serve_blob.get("executed")),
            },
            "applicability": {
                "text_and_similar_code_repos": "Moderate window=25, depth=50, windowMemory=64m..128m, compression=6 recovers cross-file delta savings on similar/renamed templates without c=9/depth=100 tail latency & RSS inflation.",
                "compressed_media_or_large_binary_repos": "Keep compression=-1/1 with narrow window=10 or skip aggressive repack; zlib=9 adds CPU cost for negligible byte reduction on incompressible payloads.",
                "multi_pack_small_deltas": "Multi-pack count consolidation (N packs -> 1 pack) matters more than tuning zlib level 6 vs 9.",
            },
            "rollback_and_fallback_conditions": [
                "If serve-blob / RefStore physical Blob GC is disabled or unexecuted, do not run frequent compaction expecting storage billing reduction (non-GC coexistence amplifies total S3 bytes).",
                "Fallback immediately to threads=1, windowMemory=32m, window=10 if background pack-objects peak RSS approaches worker RLIMIT_AS or multi-repo CPU contention degrades foreground Smart HTTP P95/P99.",
                "Refuse promotion whenever git fsck --full --strict, object OID/type parity, or delta depth bound <= configured depth fails.",
            ],
        },
        "physical_billing_claim": {
            "serve_blob_physical_savings_claimed": False,
            "reason": "Without executed and verified remote Blob GC/deletion, compacted packs coexist alongside prior packs in ref_store_core_pack_artifacts.",
        },
    }



def _validate_fetch_group(
    group: dict[str, Any], label: str, cohort: list[tuple[str, str]],
) -> None:
    samples = group.get("fetch_samples")
    _require(isinstance(samples, list) and len(samples) == len(cohort), f"{label} fetch cohort size mismatch")
    for ordinal, (sample, (archetype, object_format)) in enumerate(zip(samples, cohort, strict=True)):
        _require(
            isinstance(sample, dict)
            and type(sample.get("repo_ordinal")) is int
            and sample["repo_ordinal"] == ordinal
            and (sample.get("archetype"), sample.get("object_format")) == (archetype, object_format),
            f"{label} fetch cohort mismatch at repository {ordinal}",
        )
    for temperature in ("cold", "warm"):
        durations = [sample.get(f"{temperature}_fetch_ms") for sample in samples]
        _require(
            all(type(value) in (int, float) and 0 <= value < math.inf for value in durations),
            f"{label} {temperature} fetch duration invalid",
        )
        _require(
            group.get(f"{temperature}_fetch_stats") == percentile_stats(durations),
            f"{label} {temperature} fetch statistics do not match samples",
        )
        s3 = group.get(f"s3_fetch_{temperature}")
        _require(isinstance(s3, dict) and s3.get("observed") is True, f"{label} {temperature} fetch S3 evidence missing")
        _require(
            all(type(s3.get(field)) is int and s3[field] >= 0 for field in ("get_requests", "get_bytes")),
            f"{label} {temperature} fetch S3 counts invalid",
        )


def validate_report(report: dict[str, Any], secrets: list[str] | tuple[str, ...] = ()) -> None:
    """Fail-closed validation of Issue #178 report structure, truthfulness, and secret hygiene."""
    _require(report.get("schema_version") == "rootyard/pando-pack-compression-eval/v1", "invalid schema_version")
    _require(report.get("issue") == "#178", "invalid issue tag")
    _require(report.get("simulated") is False, "simulated must be False")
    mode = report.get("mode")
    _require(mode in ("full", "git-only"), f"unexpected mode {mode!r}")

    env_meta = report.get("environment") or {}
    _require(bool(env_meta.get("git_version")), "environment.git_version missing")
    _require(isinstance(report.get("seed"), int), "seed must be int")

    matrices = report.get("pack_matrix")
    _require(isinstance(matrices, list) and len(matrices) == len(DATASET_ARCHETYPES), "pack_matrix must cover all 6 archetypes")
    seen_arch = {m["archetype"] for m in matrices}
    _require(seen_arch == set(DATASET_ARCHETYPES), f"missing archetypes: {set(DATASET_ARCHETYPES) - seen_arch}")

    for m in matrices:
        _require(m["pre_compaction"]["pack_count"] >= 1, f"pre_compaction empty for {m['archetype']}")
        for cand in m["candidates"]:
            _require(cand["objects_exact_match"] is True, f"object parity failed for {m['archetype']}/{cand['config']['name']}")
            _require(cand["coexisting_non_gc_bytes"] >= cand["compacted_pack_idx_bytes"], "coexisting_non_gc_bytes invalid")

    corr = report.get("correctness") or {}
    _require(corr.get("passed") is True, "correctness checks did not pass")
    formats = corr.get("formats") or {}
    for fmt in OBJECT_FORMATS:
        _require(formats.get(fmt, {}).get("passed") is True, f"correctness failed for {fmt}")

    e2e = report.get("e2e_serve_blob")
    if mode == "full":
        _require(isinstance(e2e, dict) and e2e.get("executed") is True, "full mode requires executed serve-blob E2E")
        _require(e2e.get("physical_savings_claimed") is False, "serve-blob must not claim unverified physical savings")
        conc = e2e.get("concurrent_push_and_browse") or {}
        _require(conc.get("acked_verified") == conc.get("acked_total") and conc.get("acked_total", 0) > 0, "E2E ACK verification incomplete")
        _require(e2e.get("fetch_method") == FETCH_MEASUREMENT_NOTES, "fetch measurement method missing or invalid")
        baseline = [(archetype, "sha1") for archetype in DATASET_ARCHETYPES] + [("text_history", "sha256")]
        _validate_fetch_group(e2e.get("uncompacted_baseline") or {}, "baseline", baseline)
        candidate_cohort = baseline if report.get("scale") == "full" else baseline[:2] + baseline[-1:]
        candidates = e2e.get("candidate_serving_comparison") or []
        _require(bool(candidates), "candidate serving fetch coverage missing")
        for row in candidates:
            _require(row.get("physical_savings_claimed") is False, "candidate serving must not claim unverified physical savings")
            _validate_fetch_group(row, row["config_name"], candidate_cohort)
    else:
        _require(e2e is None, "git-only mode must leave e2e_serve_blob null")

    leaks = find_secret_leaks(report, secrets)
    _require(not leaks, f"report leaked secrets: {leaks}")


def render_summary_markdown(report: dict[str, Any]) -> str:
    """Render concise factual Markdown benchmark summary for #178."""
    env_meta = report["environment"]
    lines = [
        "# Pando Git Pack Compression & Delta Cost-Benefit Evaluation (Issue #178)",
        "",
        f"- **Mode / Scale / Seed**: `{report['mode']}` / `{report['scale']}` / `{report['seed']}`",
        f"- **Git / Host**: `{env_meta.get('git_version')}` / `{env_meta.get('machine')} ({env_meta.get('logical_cpus')} vCPUs)`",
    ]
    if env_meta.get("source_commit"):
        lines.append(f"- **Source Commit**: `{env_meta['source_commit']}` (dirty: `{env_meta.get('source_dirty')}`)")
    if report.get("e2e_serve_blob"):
        b = report["e2e_serve_blob"]["binary"]
        lines.append(f"- **Binary SHA-256**: `{b['sha256']}` (receipt verified: `{b.get('receipt_verified')}`)")
    lines.append("")
    lines.append("## Aggregate Candidate Compaction Matrix Across All 6 Archetypes")
    lines.append("")
    lines.append("| Config | Compaction Sum (pack+idx B) | vs Default (%) | vs Uncompacted (%) | Non-GC Coexisting (B) | Sum Wall (ms) | Sum CPU (s) | Max RSS (KiB) | Max Delta Depth |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in report["candidate_totals"]:
        cpu = row["sum_compaction_cpu_seconds"] if row["sum_compaction_cpu_seconds"] is not None else "n/a"
        rss = row["max_peak_rss_kib"] if row["max_peak_rss_kib"] is not None else "n/a"
        lines.append(
            f"| `{row['config_name']}` | {row['total_compacted_pack_idx_bytes']} | "
            f"{row['vs_rootyard_default_pct']:+.2f}% | {row['vs_uncompacted_pct']:+.2f}% | "
            f"{row['total_coexisting_non_gc_bytes']} | {row['sum_compaction_wall_ms']} | "
            f"{cpu} | {rss} | {row['max_delta_chain_depth']} |"
        )
    lines.append("")
    lines.append("## Per-Archetype Pack+Idx Comparison (Selected Configs)")
    lines.append("")
    lines.append("| Archetype | Independent Data (B) | Uncompacted Packs | Uncompacted (B) | `rootyard_default` (B) | `zlib_store_c0` (B) | `balanced_c6_w25` (B) | `wide_window_c6_w50_t2` (B) | `deep_archive_c9_w50_d100` (B) |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for m in report["pack_matrix"]:
        cmap = {c["config"]["name"]: c["compacted_pack_idx_bytes"] for c in m["candidates"]}
        pre = m["pre_compaction"]
        lines.append(
            f"| `{m['archetype']}` | {pre['independent_logical_bytes']} | {pre['pack_count']} | {pre['pack_idx_total_bytes']} | "
            f"{cmap.get('rootyard_default')} | {cmap.get('zlib_store_c0')} | {cmap.get('balanced_c6_w25')} | "
            f"{cmap.get('wide_window_c6_w50_t2')} | {cmap.get('deep_archive_c9_w50_d100')} |"
        )
    if report.get("e2e_serve_blob"):
        e2e = report["e2e_serve_blob"]
        lines.extend(["", "## Live `rootyard serve-blob` (PG17 + Garage S3) Serving Comparison", ""])
        lines.append("| Config | Serving Pack (B) | Non-GC Coexisting (B) | Push P50/P95 (ms) | Cold Clone P50/P95 (ms) | Warm Clone P50/P95 (ms) | Browse P50/P95 (ms) | S3 PUT (reqs/B) | S3 GET (reqs/B) |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |")
        for row in e2e["candidate_serving_comparison"]:
            ps, cs, ws, bs = row["push_stats"], row["cold_clone_stats"], row["warm_clone_stats"], row["browse_stats"]
            put_s3, read_s3 = row["s3_ingest"], row["s3_read"]
            lines.append(
                f"| `{row['config_name']}` | {row['serving_pack_bytes']} | {row['coexisting_non_gc_bytes']} | "
                f"{ps['p50_ms']}/{ps['p95_ms']} | {cs['p50_ms']}/{cs['p95_ms']} | {ws['p50_ms']}/{ws['p95_ms']} | "
                f"{bs['p50_ms']}/{bs['p95_ms']} | {put_s3['put_requests']}/{put_s3['put_bytes']} | "
                f"{read_s3['get_requests']}/{read_s3['get_bytes']} |"
            )

        lines.extend([
            "", "## Smart HTTP fetch with fresh clients", "",
            "| Config | Repositories | Cold P50/P95/P99 (ms) | Warm P50/P95/P99 (ms) | Cold S3 GET (reqs/B) | Warm S3 GET (reqs/B) |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ])
        groups = [("baseline", e2e["uncompacted_baseline"])]
        groups.extend((row["config_name"], row) for row in e2e["candidate_serving_comparison"])
        for config, row in groups:
            cold, warm = row["cold_fetch_stats"], row["warm_fetch_stats"]
            cold_s3, warm_s3 = row["s3_fetch_cold"], row["s3_fetch_warm"]
            lines.append(
                f"| `{config}` | {cold['count']} | {cold['p50_ms']}/{cold['p95_ms']}/{cold['p99_ms']} | "
                f"{warm['p50_ms']}/{warm['p95_ms']}/{warm['p99_ms']} | "
                f"{cold_s3['get_requests']}/{cold_s3['get_bytes']} | {warm_s3['get_requests']}/{warm_s3['get_bytes']} |"
            )
    lines.extend(["", "## Correctness & Safety Gates", ""])
    for fmt, res in report["correctness"]["formats"].items():
        s = res["safety_and_failure_checks"]
        lines.append(
            f"- `{fmt}`: passed=`{res['passed']}`, objects=`{res['object_count']}`, refs=`{res['ref_count']}`, "
            f"cancel_safe=`{s['cancel_mid_repack_preserves_serving_pack']}`, "
            f"trunc_refused=`{s['truncated_pack_refused']}`, missing_idx_refused=`{s['missing_idx_refused']}`, "
            f"bad_depth_refused=`{s['invalid_depth_refused']}`"
        )
    lines.extend(["", "## Limitations & Truth Boundaries", ""])
    for lim in report["limitations"]:
        lines.append(f"- {lim}")
    return "\n".join(lines) + "\n"
