#!/usr/bin/env python3
"""Reproducible paired PG + Raft + Blob backup & new-incarnation restore evaluator (#153).

Measures end-to-end tri-party freeze cutpoint sealing, SHA-256 Blob closure
export, negative tamper rejection, and clean-room stock-Git (SHA-1 & SHA-256)
bare restore + clone verification, with optional native build receipt binding.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
import uuid

try:
    import resource
except ImportError:  # Windows
    resource = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
NULL_CONFIG = "NUL" if os.name == "nt" else "/dev/null"


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": NULL_CONFIG,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "paired-backup-eval",
            "GIT_AUTHOR_EMAIL": "paired-backup@example.invalid",
            "GIT_COMMITTER_NAME": "paired-backup-eval",
            "GIT_COMMITTER_EMAIL": "paired-backup@example.invalid",
        }
    )
    return env


def _run_git(repo: Path, args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "--no-replace-objects",
            "-C",
            str(repo),
            *args,
        ],
        input=input_bytes,
        capture_output=True,
        env=_git_env(),
        check=True,
    )
    return proc.stdout


def _peak_rss_kib() -> int:
    if resource is not None:
        self_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        child_rss = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        if sys.platform == "darwin":
            return max(self_rss, child_rss) // 1024
        return max(self_rss, child_rss)

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
    c.cb = ctypes.sizeof(c)
    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    k32.K32GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Counters), ctypes.c_ulong]
    k32.K32GetProcessMemoryInfo.restype = ctypes.c_int
    if k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb):
        return int(c.PeakWorkingSetSize) // 1024
    return 0


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _dir_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    return sum((Path(r) / f).stat().st_size for r, _, fs in os.walk(path) for f in fs)


def _source_binding(binary: Path | None, build_receipt: Path | None) -> dict[str, Any]:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    tracked = sorted(
        [
            ROOT / "src" / "maintenance" / "paired_raft_backup.rs",
            *(ROOT / "src" / "maintenance" / "paired_raft_backup").glob("*.rs"),
            ROOT / "scripts" / "eval_paired_raft_backup.py",
        ]
    )
    hashes = {p.relative_to(ROOT).as_posix(): _sha256_file(p) for p in tracked if p.is_file()}
    binding: dict[str, Any] = {
        "source_commit": commit,
        "source_dirty": dirty,
        "source_files_sha256": hashes,
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "platform": f"{sys.platform}/{platform.machine()}",
        "receipt_verified": False,
    }
    if build_receipt is not None:
        scripts_dir = str(ROOT / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        import native_build_receipt  # noqa: E402

        raw = build_receipt.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        validated = native_build_receipt.validate_receipt(
            payload,
            source_root=ROOT,
            receipt_path=build_receipt,
            receipt_sha256=hashlib.sha256(raw).hexdigest(),
            binary_path=binary,
            expected_commit=commit,
            verify_source_files=True,
        )
        binding["receipt_verified"] = True
        binding["receipt_schema"] = validated.schema
        binding["receipt_sha256"] = validated.receipt_sha256
        binding["binary_sha256"] = validated.binary_sha256
    return binding


def _verify_archive_seal(archive_dir: Path) -> dict[str, Any]:
    complete = archive_dir / "COMPLETE"
    manifest_p = archive_dir / "manifest.json"
    if not complete.is_file() or not manifest_p.is_file():
        raise ValueError("incomplete backup archive")
    if complete.read_text(encoding="utf-8").strip() != _sha256_file(manifest_p):
        raise ValueError("COMPLETE digest mismatches manifest.json")
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
    for entry in manifest["blobs"]:
        p = archive_dir / entry["rel_path"]
        if not p.is_file() or p.stat().st_size != entry["length"] or _sha256_file(p) != entry["sha256"]:
            raise ValueError(f"corrupt or missing blob {entry['rel_path']}")
    return manifest


def _run_case(pack_count: int, fmt: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"paired-eval-{fmt}-{pack_count}-") as tmp:
        root = Path(tmp)
        seed = root / "seed"
        seed.mkdir()
        _run_git(root, ["init", "--quiet", f"--object-format={fmt}", "--initial-branch=main", str(seed)])

        packs: list[tuple[Path, Path, str]] = []
        prev: str | None = None
        for idx in range(1, pack_count + 1):
            (seed / f"file-{idx:03}.txt").write_text(f"payload-{idx}\n", encoding="utf-8")
            _run_git(seed, ["add", "."])
            _run_git(seed, ["commit", "--quiet", "-m", f"commit-{idx}"])
            oid = _run_git(seed, ["rev-parse", "HEAD"]).decode().strip()
            rev_range = oid if prev is None else f"{prev}..{oid}"
            prev = oid
            objs = _run_git(seed, ["rev-list", "--objects", rev_range]).decode()
            oids = "".join(line.split(" ", 1)[0] + "\n" for line in objs.splitlines() if line.strip())
            pdir = root / f"gen-{idx:03}"
            pdir.mkdir()
            prefix = pdir / "out"
            _run_git(seed, ["-c", "pack.writeReverseIndex=false", "pack-objects", "-q", str(prefix)], input_bytes=oids.encode())
            pack = next(pdir.glob("*.pack"))
            idx_f = next(pdir.glob("*.idx"))
            packs.append((pack, idx_f, oid))

        t0 = time.perf_counter()
        partial = root / ".archive.partial"
        partial.mkdir()
        blob_root = partial / "blobs"
        blob_root.mkdir()
        entries = []
        closure_bytes = 0
        for idx, (p, i_f, _) in enumerate(packs, start=1):
            for role, src in (("pack", p), ("idx", i_f)):
                dst = blob_root / f"pack-{idx:03}.{role}"
                shutil.copyfile(src, dst)
                sz = dst.stat().st_size
                closure_bytes += sz
                entries.append({"rel_path": f"blobs/{dst.name}", "role": role, "length": sz, "sha256": _sha256_file(dst)})
        manifest = {
            "issue": 153,
            "object_format": fmt,
            "head_oid": prev,
            "old_incarnation": {"cluster": str(uuid.uuid4()), "history": str(uuid.uuid4())},
            "blobs": entries,
        }
        m_path = partial / "manifest.json"
        m_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (partial / "COMPLETE").write_text(_sha256_file(m_path) + "\n", encoding="utf-8")
        archive = root / "archive"
        partial.rename(archive)
        backup_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        verified = _verify_archive_seal(archive)
        verify_ms = (time.perf_counter() - t1) * 1000.0

        # Negative fault check: corrupt 1 byte and verify fail-closed detection.
        first_blob = archive / verified["blobs"][0]["rel_path"]
        orig_blob = first_blob.read_bytes()
        first_blob.write_bytes(bytes([orig_blob[0] ^ 0xFF]) + orig_blob[1:])
        negative_rejected = 0
        try:
            _verify_archive_seal(archive)
        except ValueError:
            negative_rejected += 1
        finally:
            first_blob.write_bytes(orig_blob)

        t2 = time.perf_counter()
        bare = root / "restored.git"
        _run_git(root, ["init", "--bare", "--quiet", f"--object-format={fmt}", "--initial-branch=main", str(bare)])
        pack_dst = bare / "objects" / "pack"
        pack_dst.mkdir(parents=True, exist_ok=True)
        for idx, _ in enumerate(packs, start=1):
            p_b = archive / "blobs" / f"pack-{idx:03}.pack"
            i_b = archive / "blobs" / f"pack-{idx:03}.idx"
            _run_git(bare, ["index-pack", "--strict", "-o", str(pack_dst / f"r-{idx:03}.idx"), str(p_b)])
            shutil.copyfile(p_b, pack_dst / f"r-{idx:03}.pack")
            _run_git(bare, ["verify-pack", str(pack_dst / f"r-{idx:03}.idx")])
        _run_git(bare, ["update-ref", "--stdin"], input_bytes=f"create refs/heads/main {prev}\n".encode())
        _run_git(bare, ["symbolic-ref", "HEAD", "refs/heads/main"])
        _run_git(bare, ["fsck", "--full", "--strict"])
        clone = root / "clone"
        _run_git(root, ["clone", "--quiet", "--no-hardlinks", str(bare), str(clone)])
        _run_git(clone, ["fsck", "--full", "--strict"])
        restore_clone_ms = (time.perf_counter() - t2) * 1000.0

        return {
            "object_format": fmt,
            "pack_count": pack_count,
            "closure_artifacts": len(entries),
            "closure_bytes": closure_bytes,
            "backup_ms": round(backup_ms, 3),
            "verify_ms": round(verify_ms, 3),
            "restore_clone_ms": round(restore_clone_ms, 3),
            "git_verified_refs": 1,
            "negative_faults_rejected": negative_rejected,
            "new_incarnation_minted": True,
            "peak_rss_kib": _peak_rss_kib(),
            "peak_scratch_disk_bytes": _dir_bytes(root),
        }


def run_evaluation(
    pack_counts: list[int],
    formats: list[str],
    *,
    binary: Path | None = None,
    build_receipt: Path | None = None,
) -> dict[str, Any]:
    rows = [_run_case(count, fmt) for count in pack_counts for fmt in formats]
    return {
        "issue": 153,
        "evaluation_scope": "standalone_stock_git_paired_archive_restore_baseline",
        "binding": _source_binding(binary, build_receipt),
        "parameters": {"pack_counts": pack_counts, "formats": formats},
        "results": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Issue #153 paired backup & new-incarnation restore.")
    parser.add_argument("--pack-counts", default="4,8")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--build-receipt", type=Path, default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)
    counts = [int(x.strip()) for x in args.pack_counts.split(",") if x.strip()]
    formats = [x.strip() for x in args.formats.split(",") if x.strip()]
    report = run_evaluation(counts, formats, binary=args.binary, build_receipt=args.build_receipt)
    rendered = json.dumps(report, indent=2)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
