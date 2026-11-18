#!/usr/bin/env python3
"""Reproducible benchmark & stock-Git evaluator for Issue #185 packfile-uris offload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

WORKLOAD_PROFILES: dict[str, dict[str, int]] = {
    "small": {"base_files": 4, "file_bytes": 16_384, "delta_commits": 2, "warm_iters": 4},
    "medium": {"base_files": 8, "file_bytes": 32_768, "delta_commits": 3, "warm_iters": 5},
}


def _find_openssl() -> str:
    found = shutil.which("openssl")
    if found:
        return found
    proc = subprocess.run(["git", "--exec-path"], capture_output=True, text=True, check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        exec_dir = Path(proc.stdout.strip()).resolve()
        for parent in exec_dir.parents:
            for rel in ("bin/openssl.exe", "mingw64/bin/openssl.exe"):
                candidate = parent / rel
                if candidate.exists():
                    return str(candidate)
    raise RuntimeError("openssl binary required for ephemeral HTTPS test cert generation")


def _pkt(payload: bytes | str) -> bytes:
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    return f"{len(raw) + 4:04x}".encode("ascii") + raw


def _sideband_pack(pack_bytes: bytes) -> list[bytes]:
    return [_pkt(b"\x01" + pack_bytes[i:i + 65515]) for i in range(0, len(pack_bytes), 65515)]


def _git(args: list[str], cwd: Path | None = None, stdin_data: bytes | None = None) -> bytes:
    env = os.environ.copy()
    env.update({
        "GIT_AUTHOR_NAME": "Eval Bot",
        "GIT_AUTHOR_EMAIL": "eval@rootyard.test",
        "GIT_COMMITTER_NAME": "Eval Bot",
        "GIT_COMMITTER_EMAIL": "eval@rootyard.test",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    })
    proc = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        cwd=str(cwd) if cwd else None,
        env=env,
        input=stdin_data,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace')}")
    return proc.stdout


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int((pct / 100.0) * (len(ordered) - 1) + 0.5)))
    return round(ordered[idx], 3)


def _peak_rss_bytes() -> int:
    if os.name != "nt":
        import resource

        ru_self = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        ru_child = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        scale = 1 if sys.platform == "darwin" else 1024
        return int(max(ru_self, ru_child) * scale)
    import ctypes
    from ctypes import wintypes

    class _MemCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    c = _MemCounters()
    c.cb = ctypes.sizeof(_MemCounters)
    if ctypes.windll.kernel32.K32GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb):
        return int(c.PeakWorkingSetSize)
    return 0


class _BenchmarkOriginServer:
    """In-process Smart HTTP v2 origin + TLS CONNECT CDN proxy measuring origin CPU & bytes."""

    def __init__(self, cert: Path, key: Path, fmt: str, c_base: str, head_oid: str, base_pack: bytes, pack_hash: str,
                 residual_pack: bytes, full_pack: bytes, bare_repo: Path, offload_enabled: bool) -> None:
        self.fmt = fmt
        self.c_base = c_base
        self.head_oid = head_oid
        self.base_pack = base_pack
        self.pack_hash = pack_hash
        self.residual_pack = residual_pack
        self.full_pack = full_pack
        self.bare_repo = bare_repo
        self.offload_enabled = offload_enabled
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.cdn_cached = False
        self.stats = {
            "origin_bytes_sent": 0, "cdn_bytes_sent": 0, "origin_pack_objects_calls": 0,
            "origin_cpu_ms": 0.0, "cdn_cache_hits": 0, "blob_get_count": 0, "blob_get_bytes": 0,
            "duplicate_retransmit_bytes": 0,
        }
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _loop(self) -> None:
        self.sock.settimeout(0.1)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    def _serve_conn(self, conn: socket.socket) -> None:
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                ch = conn.recv(4096)
                if not ch:
                    return
                head += ch
            idx = head.find(b"\r\n\r\n") + 4
            hdr_txt, rest = head[:idx].decode("latin1"), head[idx:]
            first = hdr_txt.splitlines()[0]
            if first.startswith("CONNECT "):
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                sconn = self.ctx.wrap_socket(conn, server_side=True)
                try:
                    h2 = b""
                    while b"\r\n\r\n" not in h2:
                        ch = sconn.recv(4096)
                        if not ch:
                            return
                        h2 += ch
                    with self.lock:
                        if self.cdn_cached:
                            self.stats["cdn_cache_hits"] += 1
                        else:
                            self.cdn_cached = True
                            self.stats["blob_get_count"] += 1
                            self.stats["blob_get_bytes"] += len(self.base_pack)
                        self.stats["cdn_bytes_sent"] += len(self.base_pack)
                    sconn.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                                   f"Content-Length: {len(self.base_pack)}\r\nConnection: close\r\n\r\n").encode() + self.base_pack)
                finally:
                    sconn.close()
                return

            if first.startswith("GET /repo.git/info/refs"):
                fetch_cap = "fetch=shallow wait-for-done packfile-uris\n" if self.offload_enabled else "fetch=shallow wait-for-done\n"
                body = b"".join([
                    _pkt("# service=git-upload-pack\n"), b"0000", _pkt("version 2\n"), _pkt("agent=rootyard/eval\n"),
                    _pkt("ls-refs=unborn\n"), _pkt(fetch_cap), _pkt(f"object-format={self.fmt}\n"), b"0000",
                ])
                ct = "application/x-git-upload-pack-advertisement"
            elif first.startswith("POST /repo.git/git-upload-pack"):
                cl = 0
                for line in hdr_txt.splitlines()[1:]:
                    if line.lower().startswith("content-length:"):
                        cl = int(line.split(":", 1)[1].strip())
                while len(rest) < cl:
                    rest += conn.recv(4096)
                if b"command=ls-refs" in rest:
                    body = b"".join([_pkt(f"{self.head_oid} refs/heads/main\n"), b"0000"])
                elif self.offload_enabled and b"packfile-uris" in rest:
                    t0 = time.perf_counter()
                    res_out = _git(["-C", str(self.bare_repo), "pack-objects", "--revs", "--stdout"],
                                   stdin_data=f"{self.head_oid}\n^{self.c_base}\n".encode())
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    body = b"".join([
                        _pkt("packfile-uris\n"), _pkt(f"{self.pack_hash} https://cdn.rootyard.test/v1/packs/base.pack\n"),
                        b"0001", _pkt("packfile\n"), *_sideband_pack(res_out), b"0000",
                    ])
                    with self.lock:
                        self.stats["origin_pack_objects_calls"] += 1
                        self.stats["origin_cpu_ms"] += dt_ms
                        self.stats["origin_bytes_sent"] += len(res_out)
                else:
                    t0 = time.perf_counter()
                    pack_out = _git(["-C", str(self.bare_repo), "pack-objects", "--revs", "--stdout"],
                                    stdin_data=f"{self.head_oid}\n".encode())
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    body = b"".join([_pkt("packfile\n"), *_sideband_pack(pack_out), b"0000"])
                    with self.lock:
                        self.stats["origin_pack_objects_calls"] += 1
                        self.stats["origin_cpu_ms"] += dt_ms
                        self.stats["blob_get_count"] += 1
                        self.stats["blob_get_bytes"] += len(self.full_pack)
                        self.stats["origin_bytes_sent"] += len(pack_out)
                ct = "application/x-git-upload-pack-result"
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            conn.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _incompressible_bytes(seed: str, length: int) -> bytes:
    chunks = []
    cur = seed.encode("utf-8")
    total = 0
    while total < length:
        cur = hashlib.sha256(cur).digest()
        chunks.append(cur)
        total += len(cur)
    return b"".join(chunks)[:length]


def _prepare_dataset(root: Path, fmt: str, cfg: dict[str, int]) -> dict[str, Any]:
    bare = root / f"bare_{fmt}.git"
    work = root / f"work_{fmt}"
    _git(["init", "--bare", f"--object-format={fmt}", str(bare)])
    _git(["clone", str(bare), str(work)])
    for i in range(cfg["base_files"]):
        (work / f"base_{i}.bin").write_bytes(_incompressible_bytes(f"{fmt}:base:{i}", cfg["file_bytes"]))
    _git(["add", "."], cwd=work)
    _git(["commit", "-m", "base"], cwd=work)
    _git(["push", "origin", "HEAD:refs/heads/main"], cwd=work)
    _git(["repack", "-ad"], cwd=bare)
    c_base = _git(["rev-parse", "refs/heads/main"], cwd=bare).decode().strip()
    pack_path = next((bare / "objects" / "pack").glob("*.pack"))
    base_pack = pack_path.read_bytes()
    trailer_len = 20 if fmt == "sha1" else 32
    pack_hash = base_pack[-trailer_len:].hex()

    for j in range(cfg["delta_commits"]):
        (work / f"delta_{j}.txt").write_text(f"delta commit {j} ({fmt})\n")
        _git(["add", "."], cwd=work)
        _git(["commit", "-m", f"delta-{j}"], cwd=work)
    _git(["push", "origin", "HEAD:refs/heads/main"], cwd=work)
    c_head = _git(["rev-parse", "refs/heads/main"], cwd=bare).decode().strip()
    residual_pack = _git(["pack-objects", "--revs", "--stdout"], cwd=bare, stdin_data=f"{c_head}\n^{c_base}\n".encode())
    full_pack = _git(["pack-objects", "--revs", "--stdout"], cwd=bare, stdin_data=f"{c_head}\n".encode())
    return {
        "bare": bare, "c_base": c_base, "head_oid": c_head, "base_pack": base_pack,
        "pack_hash": pack_hash, "residual_pack": residual_pack, "full_pack": full_pack,
    }


def _run_mode(root: Path, cert: Path, key: Path, fmt: str, ds: dict[str, Any], iters: int, offload: bool) -> dict[str, Any]:
    srv = _BenchmarkOriginServer(
        cert, key, fmt, ds["c_base"], ds["head_oid"], ds["base_pack"], ds["pack_hash"],
        ds["residual_pack"], ds["full_pack"], ds["bare"], offload_enabled=offload,
    )
    latencies: list[float] = []
    try:
        for i in range(iters):
            dst = root / f"clone_{fmt}_{'offload' if offload else 'inline'}_{i}"
            args = ["-c", "protocol.version=2"]
            if offload:
                args += [
                    "-c", "fetch.uriprotocols=https",
                    "-c", f"http.https://cdn.rootyard.test/.sslCAInfo={cert}",
                    "-c", f"http.https://cdn.rootyard.test/.proxy=http://127.0.0.1:{srv.port}",
                ]
            else:
                args += ["-c", "fetch.uriprotocols="]
            args += ["clone", f"http://127.0.0.1:{srv.port}/repo.git", str(dst)]
            t0 = time.perf_counter()
            _git(args)
            latencies.append((time.perf_counter() - t0) * 1000.0)
            _git(["fsck", "--full", "--strict"], cwd=dst)
    finally:
        srv.close()

    total_egress = srv.stats["origin_bytes_sent"] + srv.stats["cdn_bytes_sent"]
    origin_share = round(srv.stats["origin_bytes_sent"] / max(1, total_egress), 4)
    return {
        "iterations": iters,
        "latency_ms": {"p50": _pct(latencies, 50), "p95": _pct(latencies, 95), "p99": _pct(latencies, 99)},
        "origin_bytes_sent": srv.stats["origin_bytes_sent"],
        "cdn_bytes_sent": srv.stats["cdn_bytes_sent"],
        "origin_egress_share": origin_share,
        "origin_pack_objects_calls": srv.stats["origin_pack_objects_calls"],
        "origin_cpu_ms": round(srv.stats["origin_cpu_ms"], 3),
        "cdn_cache_hits": srv.stats["cdn_cache_hits"],
        "blob_get_count": srv.stats["blob_get_count"],
        "blob_get_bytes": srv.stats["blob_get_bytes"],
        "duplicate_retransmit_bytes": srv.stats["duplicate_retransmit_bytes"],
        "fsck_verified": True,
    }


def run_benchmark(profiles: list[str], formats: list[str]) -> dict[str, Any]:
    openssl = _find_openssl()
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cert, key = root / "cdn.cert.pem", root / "cdn.key.pem"
        subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=cdn.rootyard.test", "-addext", "subjectAltName=DNS:cdn.rootyard.test",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for prof in profiles:
            cfg = WORKLOAD_PROFILES[prof]
            results[prof] = {}
            for fmt in formats:
                sub = root / f"{prof}_{fmt}"
                sub.mkdir(parents=True, exist_ok=True)
                ds = _prepare_dataset(sub, fmt, cfg)
                inline = _run_mode(sub, cert, key, fmt, ds, cfg["warm_iters"], offload=False)
                offload = _run_mode(sub, cert, key, fmt, ds, cfg["warm_iters"], offload=True)
                offload_reduction = round(
                    1.0 - (offload["origin_bytes_sent"] / max(1, inline["origin_bytes_sent"])),
                    4,
                )
                results[prof][fmt] = {
                    "base_pack_bytes": len(ds["base_pack"]),
                    "residual_pack_bytes": len(ds["residual_pack"]),
                    "full_inline_pack_bytes": len(ds["full_pack"]),
                    "inline_baseline_164": inline,
                    "packfile_uris_offload_185": offload,
                    "origin_egress_reduction_ratio": offload_reduction,
                }
    return {
        "schema_version": 1,
        "issue": 185,
        "baseline_issue": 164,
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "git": _git(["--version"]).decode().strip(),
            "peak_rss_bytes": _peak_rss_bytes(),
        },
        "scope_note": (
            "Measured on real local stock Git CLI over Smart HTTP v2 + loopback TLS CONNECT proxy. "
            "Does not claim cross-region WAN CDN latency or multi-region SLA."
        ),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", default="small,medium")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)
    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    report = run_benchmark(profiles, formats)
    payload = json.dumps(report, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
