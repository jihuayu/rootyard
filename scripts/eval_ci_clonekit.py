#!/usr/bin/env python3
"""Empirical evaluation harness for Issue #182 CloneKit vs stock Git checkouts.

Measures real Git (SHA-1 & SHA-256) against loopback Smart HTTP (`git http-backend`)
and a Bearer-protected CloneKit HTTP cache, reporting origin wire TX, kit cache HTTP
GET bytes/requests, scratch disk, per-process client Git CPU (`wait4`/`GetProcessTimes`),
P50/P95/P99 latency, and miss/corrupt fallback resilience.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import http.server
import json
import math
import os
import pathlib
import platform
import secrets
import shutil
import socketserver
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from typing import Any


def _child_cpu_seconds(proc: subprocess.Popen[bytes]) -> tuple[int, bytes, bytes, float]:
    if os.name == "posix":
        out = proc.stdout.read() if proc.stdout else b""
        err = proc.stderr.read() if proc.stderr else b""
        _, status, rusage = os.wait4(proc.pid, 0)
        return os.waitstatus_to_exitcode(status), out, err, float(rusage.ru_utime + rusage.ru_stime)
    out, err = proc.communicate()
    cpu_s = 0.0
    try:
        ct, et, kt, ut = (ctypes.c_uint64() for _ in range(4))
        ok = ctypes.windll.kernel32.GetProcessTimes(  # type: ignore[attr-defined]
            int(proc._handle), ctypes.byref(ct), ctypes.byref(et), ctypes.byref(kt), ctypes.byref(ut)  # noqa: SLF001
        )
        if ok:
            cpu_s = (kt.value + ut.value) * 1e-7
    except Exception:
        cpu_s = 0.0
    return proc.returncode, out, err, cpu_s


def _run_git(
    git_bin: str, args: list[str], cwd: pathlib.Path | None = None, stdin_bytes: bytes | None = None
) -> tuple[bytes, float]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    proc = subprocess.Popen(
        [git_bin, *args],
        cwd=str(cwd) if cwd else None,
        stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if stdin_bytes is not None and proc.stdin is not None:
        proc.stdin.write(stdin_bytes)
        proc.stdin.close()
    rc, out, err, cpu_s = _child_cpu_seconds(proc)
    if rc != 0:
        raise RuntimeError(f"git {args} failed ({rc}): {err.decode(errors='replace')}")
    return out, cpu_s


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return 0.0 if not ordered else ordered[min(len(ordered) - 1, max(0, math.ceil((pct / 100.0) * len(ordered)) - 1))]


def _dir_bytes(path: pathlib.Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _find_http_backend(git_bin: str) -> pathlib.Path:
    exec_dir = pathlib.Path(_run_git(git_bin, ["--exec-path"])[0].decode().strip())
    for name in ("git-http-backend.exe", "git-http-backend"):
        if (exec_dir / name).exists():
            return exec_dir / name
    raise RuntimeError(f"git-http-backend not found under {exec_dir}")


class _BenchServerState:
    def __init__(self, origins_root: pathlib.Path, backend: pathlib.Path, bearer: str) -> None:
        self.origins_root, self.backend, self.bearer = origins_root, backend, bearer
        self.cache_blobs: dict[str, tuple[bytes, str]] = {}
        self.lock = threading.Lock()
        self.origin_requests = self.origin_get_requests = 0
        self.origin_wire_tx_bytes = self.kit_get_requests = self.kit_wire_tx_bytes = 0

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return {
                "origin_requests": self.origin_requests,
                "origin_get_requests": self.origin_get_requests,
                "origin_wire_tx_bytes": self.origin_wire_tx_bytes,
                "kit_get_requests": self.kit_get_requests,
                "kit_wire_tx_bytes": self.kit_wire_tx_bytes,
            }


def _make_handler(state: _BenchServerState) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send(self, code: int, ctype: str, body: bytes, etag: str | None = None) -> None:
            self.close_connection = True
            self.send_response(code)
            self.send_header("Connection", "close")
            self.send_header("Content-Type", ctype)
            if etag:
                self.send_header("ETag", f'"{etag}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _handle(self) -> None:
            if not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {state.bearer}"):
                self._send(401, "text/plain", b"")
                return
            length = int(self.headers.get("Content-Length", "0") or "0")
            req_body = self.rfile.read(length) if length > 0 else b""
            path, _, query = self.path.partition("?")
            if path.startswith("/kit/"):
                entry = state.cache_blobs.get(path)
                with state.lock:
                    state.kit_get_requests += 1
                    if entry is not None:
                        state.kit_wire_tx_bytes += len(entry[0])
                if entry is None:
                    self._send(404, "application/octet-stream", b"")
                else:
                    self._send(200, "application/octet-stream", entry[0], entry[1])
                return

            env = {
                **os.environ,
                "GIT_PROJECT_ROOT": str(state.origins_root),
                "GIT_HTTP_EXPORT_ALL": "1",
                "PATH_INFO": path,
                "QUERY_STRING": query,
                "REQUEST_METHOD": self.command,
                "CONTENT_LENGTH": str(len(req_body)),
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""),
            }
            raw = subprocess.run([str(state.backend)], input=req_body, capture_output=True, env=env, check=False).stdout
            sep_idx, sep_len = next(((raw.find(s), len(s)) for s in (b"\r\n\r\n", b"\n\n") if raw.find(s) != -1), (-1, 0))
            hdr_bytes, resp_body = (raw[:sep_idx], raw[sep_idx + sep_len :]) if sep_idx != -1 else (b"", raw)
            status, ctype = 200, "application/octet-stream"
            for line in hdr_bytes.decode(errors="replace").splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    if k.strip().lower() == "status":
                        status = int(v.strip().split()[0])
                    elif k.strip().lower() == "content-type":
                        ctype = v.strip()
            with state.lock:
                state.origin_requests += 1
                if self.command == "GET":
                    state.origin_get_requests += 1
                state.origin_wire_tx_bytes += len(resp_body)
            self._send(status, ctype, resp_body)

        def do_GET(self) -> None:  # noqa: N802
            self._handle()

        def do_POST(self) -> None:  # noqa: N802
            self._handle()

    return Handler


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _init_repo(
    git_bin: str, parent: pathlib.Path, name: str, fmt: str, history_kb: int, num_deltas: int
) -> tuple[pathlib.Path, str, list[str]]:
    repo = parent / name
    repo.mkdir(parents=True, exist_ok=True)
    flag = "--object-format=sha256" if fmt == "sha256" else "--object-format=sha1"
    for cmd in (["init", "--quiet", flag], ["config", "user.name", "bench"], ["config", "user.email", "bench@rootyard.invalid"], ["config", "uploadpack.allowAnySHA1InWant", "true"]):
        _run_git(git_bin, cmd, cwd=repo)
    blob = bytearray()
    digest = hashlib.sha256(bytes([0x5A if fmt == "sha1" else 0xA5])).digest()
    while len(blob) < history_kb * 1024:
        digest = hashlib.sha256(digest).digest()
        blob.extend(digest)
    (repo / "assets").mkdir(exist_ok=True)
    (repo / "assets" / "base.bin").write_bytes(bytes(blob[: history_kb * 1024]))
    (repo / "README.md").write_text(f"# benchmark ({fmt})\n", encoding="utf-8")
    _run_git(git_bin, ["add", "."], cwd=repo)
    _run_git(git_bin, ["commit", "--quiet", "-m", "base"], cwd=repo)
    base_oid = _run_git(git_bin, ["rev-parse", "HEAD"], cwd=repo)[0].decode().strip()
    deltas: list[str] = []
    for idx in range(1, num_deltas + 1):
        (repo / "delta.txt").write_text(f"commit-{fmt}-{idx}\n", encoding="utf-8")
        _run_git(git_bin, ["add", "delta.txt"], cwd=repo)
        _run_git(git_bin, ["commit", "--quiet", "-m", f"delta-{idx}"], cwd=repo)
        deltas.append(_run_git(git_bin, ["rev-parse", "HEAD"], cwd=repo)[0].decode().strip())
    return repo, base_oid, deltas


def _build_clonekit(git_bin: str, repo: pathlib.Path, base_oid: str, stage_dir: pathlib.Path) -> dict[str, Any]:
    stage_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    objs, cpu1 = _run_git(git_bin, ["rev-list", "--objects", base_oid], cwd=repo)
    out, cpu2 = _run_git(git_bin, ["pack-objects", "--quiet", str(stage_dir / "kit")], cwd=repo, stdin_bytes=objs)
    pack_hash = out.decode().strip().splitlines()[-1].strip()
    pack_bytes = (stage_dir / f"kit-{pack_hash}.pack").read_bytes()
    idx_path = stage_dir / f"kit-{pack_hash}.idx"
    idx_bytes = idx_path.read_bytes()
    _, cpu3 = _run_git(git_bin, ["verify-pack", "-s", str(idx_path)], cwd=repo)
    return {
        "pack_hash": pack_hash,
        "pack_bytes": pack_bytes,
        "idx_bytes": idx_bytes,
        "pack_sha256": _sha256_bytes(pack_bytes),
        "idx_sha256": _sha256_bytes(idx_bytes),
        "build_wall_ms": (time.perf_counter() - t0) * 1000.0,
        "build_cpu_s": cpu1 + cpu2 + cpu3,
    }


def _http_get(url: str, bearer: str) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer}"}), timeout=15) as r:
        return r.read()


def _checkout_once(
    git_bin: str,
    workdir: pathlib.Path,
    remote_url: str,
    bearer: str,
    fmt: str,
    target_oid: str,
    kit: dict[str, Any] | None = None,
    kit_urls: tuple[str, str] | None = None,
    base_oid: str | None = None,
    local_kit_dir: pathlib.Path | None = None,
) -> dict[str, Any]:
    t0 = time.perf_counter()
    flag = "--object-format=sha256" if fmt == "sha256" else "--object-format=sha1"
    header = f"http.extraheader=Authorization: Bearer {bearer}"
    _, cpu_s = _run_git(git_bin, ["init", "--quiet", flag, str(workdir)])
    strategy, fallback_reason, kit_used = "stock_git_direct", None, False

    if kit is not None and base_oid is not None:
        pack_dir = workdir / ".git" / "objects" / "pack"
        pack_dir.mkdir(parents=True, exist_ok=True)
        try:
            if local_kit_dir is not None:
                p_bytes = (local_kit_dir / f"pack-{kit['pack_hash']}.pack").read_bytes()
                i_bytes = (local_kit_dir / f"pack-{kit['pack_hash']}.idx").read_bytes()
                strategy = "clonekit_warm_cache"
            elif kit_urls is not None:
                p_bytes, i_bytes = _http_get(kit_urls[0], bearer), _http_get(kit_urls[1], bearer)
                strategy = "clonekit_cold_http"
            else:
                raise RuntimeError("missing kit source")
            if _sha256_bytes(p_bytes) != kit["pack_sha256"] or _sha256_bytes(i_bytes) != kit["idx_sha256"]:
                raise ValueError("kit_corrupt")
            dst_idx = pack_dir / f"pack-{kit['pack_hash']}.idx"
            (pack_dir / f"pack-{kit['pack_hash']}.pack").write_bytes(p_bytes)
            dst_idx.write_bytes(i_bytes)
            cpu_s += _run_git(git_bin, ["-C", str(workdir), "verify-pack", "-s", str(dst_idx)])[1]
            cpu_s += _run_git(git_bin, ["-C", str(workdir), "update-ref", "refs/rootyard-clonekit-base", base_oid])[1]
            kit_used = True
        except Exception as exc:
            strategy = "stock_git_fallback"
            fallback_reason = "kit_corrupt" if "kit_corrupt" in str(exc) else "kit_miss_or_error"
            for leftover in pack_dir.glob("pack-*"):
                leftover.unlink(missing_ok=True)

    cpu_s += _run_git(git_bin, ["-C", str(workdir), "-c", header, "fetch", "--quiet", "--no-tags", remote_url, target_oid])[1]
    if kit_used:
        cpu_s += _run_git(git_bin, ["-C", str(workdir), "update-ref", "-d", "refs/rootyard-clonekit-base"])[1]
    head_raw, c = _run_git(git_bin, ["-C", str(workdir), "rev-parse", f"{target_oid}^{{commit}}"])
    cpu_s += c
    if head_raw.decode().strip() != target_oid:
        raise RuntimeError("target oid verification failed")
    cpu_s += _run_git(git_bin, ["-C", str(workdir), "checkout", "--quiet", "--detach", target_oid])[1]
    cpu_s += _run_git(git_bin, ["-C", str(workdir), "fsck", "--full", "--strict"])[1]
    return {
        "strategy": strategy,
        "fallback_reason": fallback_reason,
        "wall_ms": (time.perf_counter() - t0) * 1000.0,
        "cpu_s": cpu_s,
        "scratch_disk_bytes": _dir_bytes(workdir / ".git"),
    }


def _aggregate(samples: list[dict[str, Any]], b0: dict[str, int], b1: dict[str, int]) -> dict[str, Any]:
    walls, cpus, disks = ([s[k] for s in samples] for k in ("wall_ms", "cpu_s", "scratch_disk_bytes"))
    n = max(1, len(samples))
    d_o_tx, d_k_tx = b1["origin_wire_tx_bytes"] - b0["origin_wire_tx_bytes"], b1["kit_wire_tx_bytes"] - b0["kit_wire_tx_bytes"]
    return {
        "runs": len(samples),
        "origin_requests_per_run": round((b1["origin_requests"] - b0["origin_requests"]) / n, 2),
        "origin_get_requests_per_run": round((b1["origin_get_requests"] - b0["origin_get_requests"]) / n, 2),
        "origin_wire_tx_bytes_per_run": round(d_o_tx / n, 1),
        "kit_get_requests_per_run": round((b1["kit_get_requests"] - b0["kit_get_requests"]) / n, 2),
        "kit_wire_tx_bytes_per_run": round(d_k_tx / n, 1),
        "total_wire_tx_bytes_per_run": round((d_o_tx + d_k_tx) / n, 1),
        "scratch_disk_bytes_mean": round(statistics.mean(disks), 1),
        "cpu_s_mean": round(statistics.mean(cpus), 4),
        "wall_ms_p50": round(_percentile(walls, 50), 2),
        "wall_ms_p95": round(_percentile(walls, 95), 2),
        "wall_ms_p99": round(_percentile(walls, 99), 2),
    }


def run_benchmark(scale: str, git_bin: str) -> dict[str, Any]:
    """Execute full or quick empirical evaluation and return structured JSON report."""
    history_kb, num_deltas = (256, 2) if scale == "quick" else (1536, 8)
    git_ver, backend, bearer = _run_git(git_bin, ["--version"])[0].decode().strip(), _find_http_backend(git_bin), secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix="clonekit_eval_") as tmp_str:
        tmp = pathlib.Path(tmp_str)
        origins = tmp / "origins"
        origins.mkdir()
        state = _BenchServerState(origins, backend, bearer)
        server = _ThreadedHTTPServer(("127.0.0.1", 0), _make_handler(state))
        host, port = server.server_address[:2]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base_url, formats_report = f"http://{host}:{port}", {}
            for fmt in ("sha1", "sha256"):
                repo_name = f"bench_{fmt}.git"
                repo, base_oid, deltas = _init_repo(git_bin, origins, repo_name, fmt, history_kb, num_deltas)
                kit = _build_clonekit(git_bin, repo, base_oid, tmp / f"stage_{fmt}")
                p_uri, i_uri = f"/kit/{fmt}/pack-{kit['pack_hash']}.pack", f"/kit/{fmt}/pack-{kit['pack_hash']}.idx"
                state.cache_blobs[p_uri] = (kit["pack_bytes"], kit["pack_sha256"])
                state.cache_blobs[i_uri] = (kit["idx_bytes"], kit["idx_sha256"])
                warm_dir = tmp / f"warm_{fmt}"
                warm_dir.mkdir()
                (warm_dir / f"pack-{kit['pack_hash']}.pack").write_bytes(kit["pack_bytes"])
                (warm_dir / f"pack-{kit['pack_hash']}.idx").write_bytes(kit["idx_bytes"])
                remote_url, kit_urls = f"{base_url}/{repo_name}", (f"{base_url}{p_uri}", f"{base_url}{i_uri}")

                b0 = state.snapshot()
                stock = _aggregate([_checkout_once(git_bin, tmp / f"w_s_{fmt}_{i}", remote_url, bearer, fmt, o) for i, o in enumerate(deltas)], b0, state.snapshot())
                b1 = state.snapshot()
                cold_ck = _aggregate([_checkout_once(git_bin, tmp / f"w_c_{fmt}_{i}", remote_url, bearer, fmt, o, kit, kit_urls, base_oid) for i, o in enumerate(deltas)], b1, state.snapshot())
                b2 = state.snapshot()
                warm_ck = _aggregate([_checkout_once(git_bin, tmp / f"w_w_{fmt}_{i}", remote_url, bearer, fmt, o, kit, None, base_oid, warm_dir) for i, o in enumerate(deltas)], b2, state.snapshot())

                miss = _checkout_once(git_bin, tmp / f"w_m_{fmt}", remote_url, bearer, fmt, deltas[-1], kit, (f"{base_url}/kit/{fmt}/missing.pack", f"{base_url}{i_uri}"), base_oid)
                bad = bytearray(kit["pack_bytes"])
                bad[16] ^= 0xFF
                state.cache_blobs[f"/kit/{fmt}/corrupt.pack"] = (bytes(bad), "bad")
                corrupt = _checkout_once(git_bin, tmp / f"w_x_{fmt}", remote_url, bearer, fmt, deltas[-1], kit, (f"{base_url}/kit/{fmt}/corrupt.pack", kit_urls[1]), base_oid)

                formats_report[fmt] = {
                    "history_payload_bytes": history_kb * 1024,
                    "kit_build": {"pack_bytes": len(kit["pack_bytes"]), "idx_bytes": len(kit["idx_bytes"]), "build_wall_ms": round(kit["build_wall_ms"], 2), "build_cpu_s": round(kit["build_cpu_s"], 4)},
                    "stock_git_direct": stock,
                    "clonekit_cold_http": cold_ck,
                    "clonekit_warm_cache": warm_ck,
                    "origin_wire_reduction_factor": round(stock["origin_wire_tx_bytes_per_run"] / max(1.0, warm_ck["origin_wire_tx_bytes_per_run"]), 2),
                    "faults": {"kit_miss_fallback": miss["strategy"] == "stock_git_fallback", "kit_corrupt_fallback": corrupt["strategy"] == "stock_git_fallback" and corrupt["fallback_reason"] == "kit_corrupt"},
                }
            return {"schema_version": 1, "scale": scale, "git_version": git_ver, "platform": platform.platform(), "default_clonekit_enabled": False, "formats": formats_report}
        finally:
            server.shutdown()
            server.server_close()


def format_markdown(report: dict[str, Any]) -> str:
    """Render concise Markdown summary table from benchmark JSON report."""
    lines = [
        f"## Issue #182 Empirical CloneKit Evaluation (`scale={report['scale']}`)", "",
        f"- Git: `{report['git_version']}`", f"- Platform: `{report['platform']}`",
        f"- Default policy: `use_clonekit={report['default_clonekit_enabled']}` (opt-in only)", "",
        "| Format | Mode | Origin Wire TX (B/run) | Kit HTTP GET (B/run) | Scratch Disk (B) | Client CPU (s) | P50 (ms) | P95 (ms) | P99 (ms) |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for fmt, data in report["formats"].items():
        for k, label in (("stock_git_direct", "Stock Git Direct"), ("clonekit_cold_http", "CloneKit Cold HTTP"), ("clonekit_warm_cache", "CloneKit Warm Cache")):
            m = data[k]
            lines.append(f"| `{fmt}` | {label} | {m['origin_wire_tx_bytes_per_run']} | {m['kit_wire_tx_bytes_per_run']} | {m['scratch_disk_bytes_mean']} | {m['cpu_s_mean']} | {m['wall_ms_p50']} | {m['wall_ms_p95']} | {m['wall_ms_p99']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate CloneKit vs stock Git checkout over Smart HTTP")
    parser.add_argument("--scale", choices=("quick", "full"), default="quick")
    parser.add_argument("--git-bin", default=shutil.which("git") or "git")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--markdown-out", type=pathlib.Path)
    args = parser.parse_args()
    report = run_benchmark(args.scale, args.git_bin)
    raw_json = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(raw_json, encoding="utf-8", newline="\n")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(format_markdown(report), encoding="utf-8", newline="\n")
    sys.stdout.write(raw_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
