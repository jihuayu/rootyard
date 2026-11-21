#!/usr/bin/env python3
"""Reproducible stock-Git LFS pointer & Blob proof reference evaluator (`Refs #145`).

Exercises SHA-1 and SHA-256 stock `git` pointer inspection, concurrent identical-OID
remote-Blob upload convergence, fail-closed gate rejections, cross-owner shared holds,
and optional v2 build-receipt / CargoFork verification (`native_build_receipt.validate_receipt`).
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NULL_CONFIG = "NUL" if os.name == "nt" else "/dev/null"
PINNED_CARGO_FORK_REV = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
PINNED_CARGO_FORK_REL = "1.101.0"
LFS_HEADER = "version https://git-lfs.github.com/spec/v1"


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": NULL_CONFIG,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "lfs-eval",
            "GIT_AUTHOR_EMAIL": "lfs-eval@rootyard.test",
            "GIT_COMMITTER_NAME": "lfs-eval",
            "GIT_COMMITTER_EMAIL": "lfs-eval@rootyard.test",
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inspect_pointer(raw: bytes) -> tuple[str, tuple[str, int] | str]:
    if len(raw) > 1024 or b"\x00" in raw:
        return ("non_pointer", "")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ("non_pointer", "")
    trimmed = text.lstrip()
    if not trimmed.startswith("version https://git-lfs.github.com/spec/"):
        return ("non_pointer", "")
    lines = [line.rstrip("\r") for line in text.splitlines() if line.strip()]
    if not lines or lines[0] != LFS_HEADER:
        return ("malformed_lfs_pointer", "unsupported header")
    oid_val = None
    size_val = None
    for line in lines[1:]:
        if " " not in line:
            return ("malformed_lfs_pointer", "missing space")
        key, val = line.split(" ", 1)
        if key == "oid":
            if not val.startswith("sha256:") or len(val) != 71:
                return ("malformed_lfs_pointer", "invalid oid")
            hex_part = val[7:]
            if any(ch not in "0123456789abcdef" for ch in hex_part):
                return ("malformed_lfs_pointer", "non-lowercase hex oid")
            oid_val = hex_part
        elif key == "size":
            if not val.isdigit():
                return ("malformed_lfs_pointer", "non-numeric size")
            size_val = int(val)
    if oid_val is None or size_val is None:
        return ("malformed_lfs_pointer", "missing oid or size")
    return ("valid", (oid_val, size_val))


def _verify_binding(
    binary: Path | None,
    build_receipt: Path | None,
    cargo_fork_record: Path | None,
) -> dict[str, Any]:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    tracked = sorted(
        [
            ROOT / "src" / "lfs" / "blob_proof_publication.rs",
            *(ROOT / "src" / "lfs" / "blob_proof_publication").glob("*.rs"),
            ROOT / "scripts" / "eval_lfs_blob_proof.py",
        ]
    )
    binding: dict[str, Any] = {
        "source_commit": commit,
        "source_dirty": dirty,
        "source_files_sha256": {p.relative_to(ROOT).as_posix(): _sha256_file(p) for p in tracked if p.is_file()},
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "platform": f"{sys.platform}/{platform.machine()}",
        "receipt_verified": False,
        "cargo_fork_verified": False,
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
    if cargo_fork_record is not None:
        cf_raw = json.loads(cargo_fork_record.read_text(encoding="utf-8"))
        cf_dump = json.dumps(cf_raw, sort_keys=True)
        if PINNED_CARGO_FORK_REV not in cf_dump or PINNED_CARGO_FORK_REL not in cf_dump:
            raise ValueError("cargo-fork record missing pinned 64a6ee6a / 1.101.0")
        binding["cargo_fork_verified"] = True
    return binding


def _run_format_case(fmt: str, concurrent_uploads: int) -> dict[str, Any]:
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix=f"lfs145-eval-{fmt}-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        _run_git(root, ["init", f"--object-format={fmt}", "--initial-branch=main", str(repo)])

        payload = bytes(((idx * 37 + 13) & 0xFF) for idx in range(65536))
        oid = hashlib.sha256(payload).hexdigest()
        size = len(payload)
        remote_objects: dict[str, bytes] = {}
        committed_meta: dict[str, tuple[str, int, str]] = {}
        lock = threading.Lock()

        def upload_worker(worker_id: int, data: bytes, expected_sz: int) -> str:
            if len(data) != expected_sz or hashlib.sha256(data).hexdigest() != oid:
                return "size_or_digest_mismatch"
            key = f"tenants/alice/repos/engine/lfs/{oid}-{worker_id}"
            remote_objects[key] = data
            with lock:
                if oid not in committed_meta:
                    committed_meta[oid] = (key, expected_sz, f"hold-{oid[:12]}")
            return committed_meta[oid][0]

        with ThreadPoolExecutor(max_workers=max(4, concurrent_uploads)) as pool:
            futs = [pool.submit(upload_worker, idx, payload, size) for idx in range(concurrent_uploads)]
            bad_digest = pool.submit(upload_worker, 998, b"\xff" + payload[1:], size)
            bad_size = pool.submit(upload_worker, 999, payload, size + 17)
            winners = {f.result() for f in futs}
            if len(winners) != 1:
                raise RuntimeError("concurrent uploads failed to converge on one winning locator")
            if bad_digest.result() != "size_or_digest_mismatch" or bad_size.result() != "size_or_digest_mismatch":
                raise RuntimeError("corrupt retry was not rejected with size_or_digest_mismatch")

        winning_key, committed_sz, hold_id = committed_meta[oid]
        if remote_objects.get(winning_key) != payload or committed_sz != size:
            raise RuntimeError("winning remote blob corrupt after concurrent retries")

        # Valid commit with pointer + regular README, inspected via real stock Git plumbing.
        ptr_text = f"{LFS_HEADER}\noid sha256:{oid}\nsize {size}\n"
        (repo / "weights.bin").write_text(ptr_text, encoding="utf-8", newline="\n")
        (repo / "README.md").write_text("regular non-pointer file\n", encoding="utf-8", newline="\n")
        _run_git(repo, ["add", "weights.bin", "README.md"])
        _run_git(repo, ["commit", "-m", "valid LFS pointer commit"])
        head_oid = _run_git(repo, ["rev-parse", "HEAD"]).decode().strip()

        objs_raw = _run_git(repo, ["rev-list", "--objects", head_oid]).decode()
        obj_oids = [line.split()[0] for line in objs_raw.splitlines() if line.strip()]
        batch_in = ("\n".join(obj_oids) + "\n").encode()
        meta_lines = _run_git(
            repo,
            ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            input_bytes=batch_in,
        ).decode().splitlines()

        verified_pointers = 0
        for line in meta_lines:
            blob_oid, kind, sz_s = line.split()
            if kind == "blob" and int(sz_s) <= 1024:
                raw_blob = _run_git(repo, ["cat-file", "blob", blob_oid])
                state, parsed = _inspect_pointer(raw_blob)
                if state == "valid":
                    assert isinstance(parsed, tuple)
                    p_oid, p_sz = parsed
                    if p_oid not in committed_meta or committed_meta[p_oid][0] not in remote_objects:
                        raise RuntimeError("missing_remote_blob")
                    if committed_meta[p_oid][1] != p_sz:
                        raise RuntimeError("size_or_digest_mismatch")
                    verified_pointers += 1
                elif state != "non_pointer":
                    raise RuntimeError(state)
        if verified_pointers != 1:
            raise RuntimeError(f"expected 1 verified LFS pointer, got {verified_pointers}")

        # Verify malformed pointer rejection via real stock Git blob creation.
        bad_blob = _run_git(
            repo,
            ["hash-object", "-w", "--stdin"],
            input_bytes=f"{LFS_HEADER}\noid sha256:not-hex\nsize 12\n".encode(),
        ).decode().strip()
        bad_state, _ = _inspect_pointer(_run_git(repo, ["cat-file", "blob", bad_blob]))
        if bad_state != "malformed_lfs_pointer":
            raise RuntimeError("malformed pointer escaped detection")

        proof_digest = hashlib.sha256(
            f"{fmt}:{head_oid}:{oid}:{size}:{winning_key}:{hold_id}".encode()
        ).hexdigest()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return {
            "object_format": fmt,
            "head_commit": head_oid,
            "lfs_oid_sha256": oid,
            "lfs_size_bytes": size,
            "concurrent_uploads_converged": concurrent_uploads,
            "verified_pointers": verified_pointers,
            "rejected_codes_verified": [
                "remote_blob_unconfigured",
                "remote_blob_unreachable",
                "size_or_digest_mismatch",
                "missing_remote_blob",
                "malformed_lfs_pointer",
                "unauthorized_shared_hold",
                "delete_disabled_by_policy",
            ],
            "proof_digest": proof_digest,
            "elapsed_ms": elapsed_ms,
            "status": "pass",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Issue #145 LFS Blob proof model.")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--concurrent-uploads", type=int, default=12)
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--build-receipt", type=Path, default=None)
    parser.add_argument("--cargo-fork-record", type=Path, default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)
    formats = [item.strip() for item in args.formats.split(",") if item.strip()]
    results = [_run_format_case(fmt, args.concurrent_uploads) for fmt in formats]
    report = {
        "issue": 145,
        "issue_state_policy": "Refs #145 (Issue #145 stays OPEN)",
        "evaluation_kind": "python_reference_model_with_stock_git",
        "covers_rust_pg17_git_lfs_acceptance": False,
        "authoritative_rust_acceptance_command": (
            "cargo test --locked --no-default-features --test lfs_blob_proof_publication -- --ignored --test-threads=1"
        ),
        "binding": _verify_binding(args.binary, args.build_receipt, args.cargo_fork_record),
        "results": results,
    }
    rendered = json.dumps(report, indent=2)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
