"""Comparative quantitative benchmarks and adversarial fail-closed suite for #179."""
from __future__ import annotations

import ctypes
import math
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
from typing import Any

from .clients import FullPackCachedClient, RangeReadClient, RunCounters
from .fixture_builder import RepoArtifactSet, build_real_git_fixtures
from .git_pack_codec import (
    FailClosedError,
    HashAlgo,
    decode_pack_entry_header,
    verify_commit_closure,
)
from .range_server import GarageS3Client, RangeObjectServer, ServerFault


def _cpu_seconds() -> float:
    t = os.times()
    return round(float(t.user + t.system), 6)


def _peak_rss_kib() -> int:
    try:
        import resource  # type: ignore[import-not-found]

        rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return rss // 1024 if platform.system() == "Darwin" else rss
    except ImportError:
        pass
    if os.name == "nt":
        class _Counters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        c = _Counters()
        c.cb = ctypes.sizeof(_Counters)
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        psapi = ctypes.windll.psapi  # type: ignore[attr-defined]
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Counters), ctypes.c_ulong]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        proc = k32.GetCurrentProcess()
        if psapi.GetProcessMemoryInfo(proc, ctypes.byref(c), c.cb):
            return int(c.PeakWorkingSetSize // 1024)
    return 0


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return round(s[lo] if lo == hi else s[lo] + (s[hi] - s[lo]) * (k - lo), 4)


def _summarize(
    algo: HashAlgo, name: str, mode: str, counters: RunCounters, cpu_s: float, scratch_bytes: int, wall_ms: float
) -> dict[str, Any]:
    return {
        "algo": algo,
        "workload": name,
        "mode": mode,
        "requests": len(counters.latencies_ms),
        "full_gets": counters.get_requests_full,
        "range_gets": counters.get_requests_range,
        "total_gets": counters.total_gets,
        "bytes_downloaded": counters.bytes_downloaded,
        "logical_bytes": counters.logical_bytes,
        "download_amplification": counters.amplification(),
        "wall_ms": round(wall_ms, 3),
        "p50_ms": _pct(counters.latencies_ms, 50.0),
        "p95_ms": _pct(counters.latencies_ms, 95.0),
        "p99_ms": _pct(counters.latencies_ms, 99.0),
        "cpu_seconds": round(max(0.0, cpu_s), 6),
        "peak_rss_kib": _peak_rss_kib(),
        "scratch_disk_bytes": scratch_bytes,
    }


def _verify_git_parity(work_dir: Path, algo: HashAlgo, oids: list[str], client: RangeReadClient) -> None:
    repo_dir = work_dir / f"repo_{algo}"
    for oid in oids[:6]:
        otype, raw = client.fetch_object(oid)
        expected = subprocess.run(
            ["git", "-C", str(repo_dir), "cat-file", otype, oid],
            check=True,
            capture_output=True,
        ).stdout
        if raw != expected:
            raise AssertionError(f"parity mismatch for {algo} {oid}: got {len(raw)}B expected {len(expected)}B")


def _run_pair(
    work_dir: Path,
    art: RepoArtifactSet,
    workload: str,
    oids: list[str],
    simulated_rtt_ms: float,
    *,
    warm_rounds: int = 1,
    verify_closure_tip: bool = False,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for mode in ("range_read", "full_pack_cache"):
        srv = RangeObjectServer(art, simulated_rtt_ms=simulated_rtt_ms).start()
        srv.add_grant("tok-alpha", art.tenant_id, art.repo_id)
        try:
            scratch = work_dir / f"scratch_{art.algo}_{workload}_{mode}"
            client = (
                RangeReadClient(srv.base_url, art, "tok-alpha", scratch)
                if mode == "range_read"
                else FullPackCachedClient(srv.base_url, art, "tok-alpha", scratch)
            )
            c0 = _cpu_seconds()
            t0 = time.perf_counter()
            if isinstance(client, RangeReadClient):
                client.load_indices(srv.pack_etags)
                if workload == "warm_repeated_lookup":
                    # Simulate distinct compute call or cold-to-warm rounds on cached idx/objects.
                    for r_idx in range(warm_rounds):
                        for oid in oids:
                            if r_idx == 0:
                                client.fetch_object(oid)
                            else:
                                client.fetch_object(oid)
                else:
                    for oid in oids:
                        client.fetch_object(oid, verify_closure=verify_closure_tip and oid == art.commit_oids[-1])
            else:
                for _ in range(warm_rounds):
                    for oid in oids:
                        client.fetch_object(oid)
            wall_ms = (time.perf_counter() - t0) * 1000.0
            cpu_delta = _cpu_seconds() - c0
            results.append(
                _summarize(art.algo, workload, mode, client.counters, cpu_delta, client.scratch_disk_bytes(), wall_ms)
            )
            if mode == "range_read" and workload == "sparse_cold_single_oid":
                _verify_git_parity(work_dir, art.algo, oids, client)  # type: ignore[arg-type]
        finally:
            srv.stop()
    return results


def _expect_fail_closed(label: str, fn: Any, expected_codes: tuple[str, ...]) -> dict[str, Any]:
    try:
        fn()
    except FailClosedError as exc:
        if exc.code not in expected_codes:
            raise AssertionError(f"{label}: expected {expected_codes}, got {exc.code}: {exc.detail}") from exc
        return {"experiment": label, "status": "fail_closed_ok", "observed_code": exc.code, "detail": exc.detail}
    raise AssertionError(f"{label}: unexpectedly succeeded instead of failing closed!")


def run_adversarial_suite(work_dir: Path, art: RepoArtifactSet) -> list[dict[str, Any]]:
    """Run all 10 adversarial fail-closed integrity, auth, drift, and pin/GC experiments."""
    srv = RangeObjectServer(art).start()
    srv.add_grant("tok-alpha", art.tenant_id, art.repo_id)
    srv.add_grant("tok-beta", "tenant-beta", art.repo_id)
    srv.acquire_pin("pin-active")
    outcomes: list[dict[str, Any]] = []
    target_oid = art.sparse_blob_oids[0]
    delta_oid = art.cross_pack_delta_oids[0] if art.cross_pack_delta_oids else art.sparse_blob_oids[0]
    thin_pack_name = next((n for n in art.pack_bytes if n.startswith("pack-thin-")), sorted(art.pack_bytes)[0])
    base_pack_name = next((n for n in sorted(art.pack_bytes) if not n.startswith("pack-thin-")), thin_pack_name)

    def fresh_client(tag: str, tok: str = "tok-alpha", **kw: Any) -> RangeReadClient:
        cli = RangeReadClient(srv.base_url, art, tok, work_dir / f"adv_{art.algo}_{tag}", **kw)
        if tok == "tok-alpha" and not kw:
            cli.load_indices(srv.pack_etags)
        return cli

    try:
        # 1. Truncated 206 HTTP response
        c1 = fresh_client("trunc")
        srv.fault = ServerFault(mode="truncate_206")
        outcomes.append(_expect_fail_closed("truncated_206_range", lambda: c1.fetch_object(target_oid), ("truncated_range",)))

        # 2. Bit-flipped 206 payload caught by CRC32 / checksum
        srv.fault = ServerFault(mode="bitflip_206")
        c2 = fresh_client("bitflip")
        outcomes.append(_expect_fail_closed("bitflipped_206_payload", lambda: c2.fetch_object(target_oid), ("corrupt_checksum",)))

        # 3. ETag / If-Match drift on Range GET
        srv.fault = ServerFault(mode="etag_mismatch", target_pack=c2.oid_map[target_oid])
        c3 = fresh_client("etag")
        outcomes.append(_expect_fail_closed("etag_if_match_drift", lambda: c3.fetch_object(target_oid), ("corrupt_checksum",)))
        srv.fault = ServerFault()

        # 4. Spoofed .idx offset pointing oid_0 -> oid_1 bytes (fails Git object hash identity)
        c4 = fresh_client("spoof")
        other_oid = next(o for o in art.sparse_blob_oids if o != target_oid)
        other_pack = c4.oid_map[other_oid]
        other_span = c4.indices[other_pack].entries[other_oid]
        c4.oid_map[target_oid] = other_pack
        c4.indices[other_pack].entries[target_oid] = other_span
        outcomes.append(
            _expect_fail_closed(
                "idx_offset_identity_spoof",
                lambda: c4.fetch_object(target_oid),
                ("object_identity_mismatch",),
            )
        )

        # 5. Missing cross-pack delta base pack (route delta_oid through thin pack, drop base pack)
        c5 = fresh_client("missbase")
        if art.cross_pack_delta_bases and base_pack_name != thin_pack_name:
            actual_base_oid = art.cross_pack_delta_bases[delta_oid]
            actual_base_pack = next(
                p for p, idx in art.idx_parsed.items() if p != thin_pack_name and actual_base_oid in idx.entries
            )
            c5.oid_map[delta_oid] = thin_pack_name
            c5.oid_map[actual_base_oid] = actual_base_pack
            srv.fault = ServerFault(drop_pack=actual_base_pack)
            outcomes.append(
                _expect_fail_closed(
                    "missing_cross_pack_delta_base",
                    lambda: c5.fetch_object(delta_oid),
                    ("pin_evicted", "missing_delta_base"),
                )
            )
        else:
            del c5.oid_map[delta_oid]
            outcomes.append(_expect_fail_closed("missing_object", lambda: c5.fetch_object(delta_oid), ("missing_object",)))
        srv.fault = ServerFault()

        # 6. Corrupted cross-pack delta base (bitflip ONLY on base pack while thin delta pack intact)
        c6 = fresh_client("badbase")
        if art.cross_pack_delta_bases and base_pack_name != thin_pack_name:
            actual_base_oid = art.cross_pack_delta_bases[delta_oid]
            actual_base_pack = next(
                p for p, idx in art.idx_parsed.items() if p != thin_pack_name and actual_base_oid in idx.entries
            )
            c6.oid_map[delta_oid] = thin_pack_name
            c6.oid_map[actual_base_oid] = actual_base_pack
            srv.fault = ServerFault(mode="bitflip_206", target_pack=actual_base_pack)
        else:
            srv.fault = ServerFault(mode="bitflip_206", target_pack=base_pack_name)
        outcomes.append(
            _expect_fail_closed(
                "corrupt_cross_pack_delta_base",
                lambda: c6.fetch_object(delta_oid),
                ("corrupt_checksum",),
            )
        )
        srv.fault = ServerFault()

        # 7. Incomplete commit/tree closure verification (missing subtree/blob fails closed)
        c7 = fresh_client("closure")
        missing_child = art.sparse_blob_oids[-1]
        c7.oid_map.pop(missing_child, None)
        outcomes.append(
            _expect_fail_closed(
                "incomplete_tree_closure",
                lambda: verify_commit_closure(lambda o: c7.fetch_object(o), art.algo, art.commit_oids[-1]),
                ("missing_object", "missing_delta_base", "incomplete_closure"),
            )
        )

        # 8. Cross-tenant isolation denial + permission revocation even after object cache warm
        c8_warm = fresh_client("revoke")
        assert c8_warm.fetch_object(target_oid)[1]
        c8_cross = RangeReadClient(srv.base_url, art, "tok-beta", work_dir / f"adv_{art.algo}_cross")
        outcomes.append(_expect_fail_closed("cross_tenant_denial", lambda: c8_cross.fetch_object(target_oid), ("unauthorized",)))
        srv.revoke_grant("tok-alpha")
        outcomes.append(
            _expect_fail_closed("revoked_token_warm_cache", lambda: c8_warm.fetch_object(target_oid), ("unauthorized",))
        )
        srv.add_grant("tok-alpha2", art.tenant_id, art.repo_id)

        # 9. History incarnation and membership version drift rejection
        c9 = RangeReadClient(srv.base_url, art, "tok-alpha2", work_dir / f"adv_{art.algo}_drift")
        c9.load_indices(srv.pack_etags)
        srv.advance_history("hist-0002")
        outcomes.append(_expect_fail_closed("history_incarnation_drift", lambda: c9.fetch_object(target_oid), ("history_drift",)))
        srv.advance_history(art.history_incarnation)
        srv.advance_membership(2)
        outcomes.append(_expect_fail_closed("membership_version_drift", lambda: c9.fetch_object(target_oid), ("membership_drift",)))
        srv.advance_membership(art.membership_version)

        # 10. Concurrent pin prevents GC sweep (#122/#151/#153); after release, GC sweeps and read fails closed
        c10 = RangeReadClient(srv.base_url, art, "tok-alpha2", work_dir / f"adv_{art.algo}_pin")
        c10.load_indices(srv.pack_etags)
        unpinned_target = art.sparse_blob_oids[1]
        gc_pack = c10.oid_map[unpinned_target]
        if srv.try_gc_sweep_pack(gc_pack, art.history_incarnation, art.membership_version):
            raise AssertionError("GC swept pack despite active retention pin!")
        assert c10.fetch_object(target_oid)[1]
        srv.release_pin("pin-active")
        if not srv.try_gc_sweep_pack(gc_pack, art.history_incarnation, art.membership_version):
            raise AssertionError("GC failed to sweep unpinned pack after lease release")
        outcomes.append(
            _expect_fail_closed("unpinned_gc_sweep_read", lambda: c10.fetch_object(unpinned_target), ("pin_evicted",))
        )
        outcomes[-1]["pin_blocked_gc_while_active"] = True
    finally:
        srv.stop()
    return outcomes


def evaluate_garage_s3(art: RepoArtifactSet, s3_env_file: Path) -> dict[str, Any]:
    """Verify real Garage 2.1 S3 `Range: bytes=start-end` -> `206 Partial Content` + `If-Match`."""
    client = GarageS3Client.from_env_file(s3_env_file)
    pname = sorted(art.pack_bytes)[0]
    key_prefix = f"pando-eval/{art.repo_id}/{os.getpid()}"
    pack_key = f"{key_prefix}/{pname}"
    etag = client.put_object(pack_key, art.pack_bytes[pname])
    idx = art.idx_parsed[pname]
    sample_oid = next(iter(idx.entries))
    span = idx.entries[sample_oid]
    t0 = time.perf_counter()
    st, hdrs, body = client.get_range(pack_key, span.offset, span.next_offset - 1, if_match=etag)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    if st != 206 or len(body) != (span.next_offset - span.offset):
        raise AssertionError(f"Garage S3 range read failed: status={st}, len={len(body)}")
    otype, _sz, hdr_len, _bo, _boid = decode_pack_entry_header(body, span.offset, art.algo)
    st_bad, _hdrs_bad, _ = client.get_range(pack_key, span.offset, span.next_offset - 1, if_match="wrong-etag-0000")
    return {
        "provider": "garage-2.1-s3",
        "pack_total_bytes": len(art.pack_bytes[pname]),
        "range_status": st,
        "range_bytes": len(body),
        "content_range": hdrs.get("content-range", ""),
        "entry_type": otype,
        "hdr_bytes": hdr_len,
        "wrong_if_match_status": st_bad,
        "latency_ms": elapsed_ms,
    }


def run_evaluation(
    scale: str = "quick",
    simulated_rtt_ms: float = 0.0,
    s3_env_file: Path | None = None,
    require_s3: bool = False,
) -> dict[str, Any]:
    """Run complete Issue #179 quantitative benchmark + adversarial fail-closed matrix."""
    git_ver = subprocess.run(["git", "--version"], check=True, capture_output=True, text=True).stdout.strip()
    benchmarks: list[dict[str, Any]] = []
    adversarial: dict[str, list[dict[str, Any]]] = {}
    fixtures_meta: dict[str, dict[str, Any]] = {}
    garage_receipt: dict[str, Any] | None = None

    with tempfile.TemporaryDirectory(prefix="pando-range-eval-") as tmp:
        root = Path(tmp)
        for algo in ("sha1", "sha256"):
            art = build_real_git_fixtures(root, algo, scale=scale)  # type: ignore[arg-type]
            total_pack = sum(len(b) for b in art.pack_bytes.values())
            total_idx = sum(len(b) for b in art.idx_bytes.values())
            fixtures_meta[algo] = {
                "packs": len(art.pack_bytes),
                "total_pack_bytes": total_pack,
                "total_idx_bytes": total_idx,
                "total_objects": len(art.all_oids),
                "midx_objects": len(art.midx_parsed.mapping) if art.midx_parsed else 0,
                "cross_pack_thin_deltas": len(art.cross_pack_delta_oids),
            }
            benchmarks.extend(_run_pair(root, art, "sparse_cold_single_oid", art.sparse_blob_oids, simulated_rtt_ms))
            benchmarks.extend(
                _run_pair(
                    root,
                    art,
                    "shallow_tree_slice",
                    [art.commit_oids[-1], art.tree_root_oid, *art.sparse_blob_oids[:3]],
                    simulated_rtt_ms,
                    verify_closure_tip=True,
                )
            )
            if art.cross_pack_delta_oids:
                benchmarks.extend(_run_pair(root, art, "cross_pack_delta_walk", art.cross_pack_delta_oids[:4], simulated_rtt_ms))
            benchmarks.extend(
                _run_pair(root, art, "warm_repeated_lookup", art.sparse_blob_oids[:6], simulated_rtt_ms, warm_rounds=3)
            )
            benchmarks.extend(_run_pair(root, art, "full_clone_parity", art.all_oids[:40], simulated_rtt_ms))
            adversarial[algo] = run_adversarial_suite(root, art)
            if algo == "sha256" and s3_env_file is not None:
                garage_receipt = evaluate_garage_s3(art, s3_env_file)
            elif require_s3 and s3_env_file is None:
                raise RuntimeError("--require-s3 specified without --s3-env")

    return {
        "issue": 179,
        "scale": scale,
        "git_version": git_ver,
        "simulated_rtt_ms": simulated_rtt_ms,
        "non_claims": [
            "Research feasibility harness only; not a production Rootyard serving route or proprietary Git protocol.",
            "Does not mark #179 production feature active or enable physical Blob deletion (#122/#151/#153).",
        ],
        "fixtures": fixtures_meta,
        "benchmarks": benchmarks,
        "adversarial": adversarial,
        "garage_s3_range_probe": garage_receipt,
    }
