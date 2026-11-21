"""/proc + PostgreSQL RefStore samplers, latency percentiles, and build-receipt verifier (Refs #178)."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any
import urllib.error
import urllib.request

from .s3_meter import S3MeterProxy

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

try:
    import native_build_receipt as build_receipt_mod
except ImportError:  # pragma: no cover - optional when native receipt helpers absent on minimal envs
    build_receipt_mod = None

__all__ = [
    "ResourceSampler",
    "S3MeterProxy",
    "http_json_timed",
    "percentile_stats",
    "query_pg_refstore_stats",
    "read_proc_snapshot",
    "sum_dir_bytes",
    "verify_binary_receipt",
]


def sum_dir_bytes(dirs: list[Path]) -> int:
    """Measure recursive file bytes in owned directories (never following symlinks)."""
    total = 0
    seen: set[Path] = set()
    for base in dirs:
        if not base.exists():
            continue
        resolved = base.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        for root, _, files in os.walk(resolved, followlinks=False):
            rp = Path(root)
            for fn in files:
                fp = rp / fn
                try:
                    if not fp.is_symlink():
                        total += fp.stat().st_size
                except OSError:
                    pass
    return total


def read_proc_snapshot(pids: list[int], scratch_dirs: list[Path]) -> dict[str, Any]:
    """Read Linux /proc RSS/HWM/CPU for live PIDs plus scratch disk bytes; clean null on non-Linux."""
    disk_bytes = sum_dir_bytes(scratch_dirs)
    if not Path("/proc").is_dir():
        return {"supported": False, "rss_kib": None, "hwm_kib": None, "cpu_seconds": None, "disk_bytes": disk_bytes}
    rss_kib = 0
    hwm_kib = 0
    cpu_ticks = 0
    alive = 0
    for pid in pids:
        pdir = Path("/proc") / str(pid)
        if not pdir.is_dir():
            continue
        try:
            st_txt = (pdir / "status").read_text(encoding="utf-8", errors="replace")
            stat_txt = (pdir / "stat").read_text(encoding="utf-8", errors="replace")
            alive += 1
            for line in st_txt.splitlines():
                if line.startswith("VmRSS:"):
                    rss_kib += int(line.split()[1])
                elif line.startswith("VmHWM:"):
                    hwm_kib += int(line.split()[1])
            rparen = stat_txt.rfind(")")
            if rparen != -1:
                fields = stat_txt[rparen + 2 :].split()
                cpu_ticks += int(fields[11]) + int(fields[12])
        except (OSError, ValueError, IndexError):
            continue
    clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    return {
        "supported": True,
        "alive_pids": alive,
        "rss_kib": rss_kib,
        "hwm_kib": hwm_kib,
        "cpu_seconds": round(cpu_ticks / float(clk_tck), 4),
        "disk_bytes": disk_bytes,
    }


def query_pg_refstore_stats(pg_url: str, env: dict[str, str]) -> dict[str, Any]:
    """Query exact RefStore pack artifact bytes (serving vs coexisting) via psql."""
    sql = (
        "SELECT json_build_object("
        "'pack_memberships', (SELECT COUNT(*)::bigint FROM ref_store_core_pack_memberships),"
        "'pack_artifacts', (SELECT COUNT(*)::bigint FROM ref_store_core_pack_artifacts),"
        "'publications', (SELECT COUNT(*)::bigint FROM ref_store_core_pack_publications),"
        "'serving_pack_bytes', (SELECT COALESCE(SUM(a.content_length), 0)::bigint "
        "FROM ref_store_core_pack_artifacts a "
        "JOIN (SELECT DISTINCT repository_id, registration_id, pack_id FROM ref_store_core_pack_memberships) m "
        "ON m.repository_id = a.repository_id AND m.registration_id = a.registration_id AND m.pack_id = a.pack_id),"
        "'coexisting_pack_bytes', (SELECT COALESCE(SUM(content_length), 0)::bigint FROM ref_store_core_pack_artifacts),"
        "'pending_ops', (SELECT COUNT(*)::bigint FROM ref_store_operations WHERE state = 'pending'),"
        "'pg_active', (SELECT COUNT(*)::bigint FROM pg_stat_activity WHERE datname = current_database() AND state = 'active' AND pid <> pg_backend_pid())"
        ")::text"
    )
    out = subprocess.check_output(
        ["psql", "--dbname", pg_url, "-X", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql],
        env=env,
        text=True,
        stderr=subprocess.PIPE,
        timeout=15,
    ).strip()
    return json.loads(out)


@dataclass
class ResourceSampler:
    """Periodic monitor recording peak RSS/HWM, scratch disk, and cumulative CPU."""

    scratch_dirs: list[Path]
    interval_seconds: float = 0.1
    _pids: list[int] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    max_rss_kib: int | None = None
    max_hwm_kib: int | None = None
    max_disk_bytes: int = 0
    _epoch_cpu: dict[int, float] = field(default_factory=dict)
    _completed_cpu: float = 0.0
    _epoch: int = 0

    def set_pids(self, pids: list[int], new_epoch: bool = False) -> None:
        with self._lock:
            if new_epoch and self._epoch in self._epoch_cpu:
                self._completed_cpu += self._epoch_cpu[self._epoch]
                self._epoch += 1
            self._pids = list(pids)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self.sample_once()

    def sample_once(self) -> None:
        with self._lock:
            pids = list(self._pids)
            epoch = self._epoch
        snap = read_proc_snapshot(pids, self.scratch_dirs)
        with self._lock:
            self.max_disk_bytes = max(self.max_disk_bytes, int(snap["disk_bytes"]))
            if snap["supported"]:
                if snap["rss_kib"] is not None:
                    self.max_rss_kib = max(self.max_rss_kib or 0, snap["rss_kib"])
                if snap["hwm_kib"] is not None:
                    self.max_hwm_kib = max(self.max_hwm_kib or 0, snap["hwm_kib"])
                if snap["cpu_seconds"] is not None and snap.get("alive_pids", 0) > 0:
                    self._epoch_cpu[epoch] = max(self._epoch_cpu.get(epoch, 0.0), snap["cpu_seconds"])

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.sample_once()
            self._stop.wait(self.interval_seconds)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            cur_cpu = self._epoch_cpu.get(self._epoch, 0.0)
            total_cpu = round(self._completed_cpu + cur_cpu, 4) if (self._epoch_cpu or self._completed_cpu > 0) else None
            return {
                "max_rss_kib": self.max_rss_kib,
                "max_hwm_kib": self.max_hwm_kib,
                "max_scratch_disk_bytes": self.max_disk_bytes,
                "cpu_seconds": total_cpu,
            }


def percentile_stats(samples_ms: list[float]) -> dict[str, Any]:
    """Compute exact min, p50, p95, p99, max, and mean milliseconds over sorted samples."""
    if not samples_ms:
        return {"count": 0, "min_ms": None, "p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None, "mean_ms": None}
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


def http_json_timed(
    base_url: str,
    path: str,
    token: str | None = None,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: int = 30,
) -> tuple[int | None, bytes, dict[str, str], float]:
    """Execute one HTTP request and return (status, raw_bytes, headers, wall_ms)."""
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data: bytes | None = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers), (time.monotonic() - t0) * 1000.0
    except urllib.error.HTTPError as err:
        return err.code, err.read(), dict(err.headers), (time.monotonic() - t0) * 1000.0
    except Exception:  # noqa: BLE001
        return None, b"", {}, (time.monotonic() - t0) * 1000.0


def verify_binary_receipt(binary: Path, require_receipt: bool) -> dict[str, Any]:
    """Verify binary existence, SHA-256, and sibling .build.json receipt when required."""
    resolved = binary.resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"rootyard binary unavailable or not executable: {resolved}")
    sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
    receipt_path = resolved.with_name(resolved.name + ".build.json")
    info: dict[str, Any] = {
        "path": str(resolved),
        "sha256": sha256,
        "size_bytes": resolved.stat().st_size,
        "receipt_verified": False,
    }
    if not receipt_path.is_file():
        if require_receipt:
            raise RuntimeError(f"missing binary build receipt: {receipt_path}")
        return info
    data = json.loads(receipt_path.read_text(encoding="utf-8"))
    if build_receipt_mod is not None and hasattr(build_receipt_mod, "verify_receipt"):
        build_receipt_mod.verify_receipt(data, resolved)
    info.update(
        {
            "receipt_verified": True,
            "receipt_schema": data.get("schema_version") or data.get("schema"),
            "receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            "workspace_commit": data.get("workspace_commit"),
            "config_digest": data.get("config_digest"),
            "source_inputs_sha256": data.get("source_inputs_sha256"),
        }
    )
    return info
