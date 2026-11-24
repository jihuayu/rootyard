"""Deterministic multi-archetype Git corpus builders and stock-Git helpers (Refs #178)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import random
import shutil
import subprocess
import time
from typing import Any
import urllib.parse

DATASET_ARCHETYPES: tuple[str, ...] = (
    "compressed_media",
    "large_binary",
    "text_history",
    "small_deltas",
    "similar_files",
    "multi_repo",
)

OBJECT_FORMATS: tuple[str, ...] = ("sha1", "sha256")
BASE_UNIX_TIME = 1763251200  # 2025-11-16T00:00:00Z fixed commit epoch


@dataclass(frozen=True)
class CommitSpec:
    """One deterministic commit payload for repository seeding or push waves."""

    message: str
    files: dict[str, bytes]

    @property
    def raw_bytes(self) -> int:
        return sum(len(content) for content in self.files.values())


def resolve_trusted_git(explicit_git: str | None) -> Path:
    """Locate stock git binary and verify executability."""
    candidate = explicit_git or os.environ.get("ROOTYARD_GIT") or shutil.which("git")
    if not candidate:
        raise RuntimeError("trusted stock git executable is required")
    path = Path(candidate).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"git executable is missing or not executable: {path}")
    return path


def isolated_git_env(base_env: dict[str, str], extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build deterministic non-interactive Git environment without ambient user config."""
    env = base_env.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
            "GIT_AUTHOR_NAME": "Rootyard Eval",
            "GIT_AUTHOR_EMAIL": "pack-eval@rootyard.invalid",
            "GIT_COMMITTER_NAME": "Rootyard Eval",
            "GIT_COMMITTER_EMAIL": "pack-eval@rootyard.invalid",
        }
    )
    if extra:
        env.update(extra)
    return env


def run_git(
    git_bin: str | Path,
    args: list[str],
    cwd: Path | None,
    env: dict[str, str],
    stdin_bytes: bytes | None = None,
    timeout: int = 180,
) -> tuple[subprocess.CompletedProcess[bytes], float]:
    """Run stock git and return (CompletedProcess, wall_ms)."""
    start = time.monotonic()
    proc = subprocess.run(
        [str(git_bin), *args],
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        input=stdin_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return proc, (time.monotonic() - start) * 1000.0


def _code_block(rng: random.Random, tag: str, line_count: int) -> bytes:
    lines = []
    for idx in range(line_count):
        token = f"{rng.getrandbits(32):08x}"
        lines.append(f"pub fn {tag}_{idx:03d}(seq: u64) -> u64 {{ seq.wrapping_add(0x{token}) }} // {tag}\n")
    return "".join(lines).encode("utf-8")


def _png_like_blob(rng: random.Random, size_bytes: int) -> bytes:
    header = b"\x89PNG\r\n\x1a\n"
    if size_bytes <= len(header):
        return header[:size_bytes]
    return header + rng.randbytes(size_bytes - len(header))


def build_archetype_commits(
    archetype: str,
    seed: int,
    scale: str = "quick",
    repo_index: int = 0,
    variant_index: int = 0,
) -> tuple[list[CommitSpec], list[list[CommitSpec]], str]:
    """Generate deterministic (seed_commits, push_waves, primary_browse_path) for one archetype."""
    if archetype not in DATASET_ARCHETYPES:
        raise ValueError(f"unsupported archetype: {archetype}")
    if scale not in ("quick", "full"):
        raise ValueError(f"unsupported scale: {scale}")

    local_seed = int.from_bytes(
        hashlib.sha256(f"{seed}:{archetype}:{scale}:{repo_index}:{variant_index}".encode("utf-8")).digest()[:8],
        "big",
    )
    rng = random.Random(local_seed)
    mult = 2 if scale == "full" else 1

    if archetype == "compressed_media":
        chunk_sz = 96 * 1024 if scale == "full" else 48 * 1024
        files: dict[str, bytes] = {
            "assets/frame_00.png": _png_like_blob(rng, chunk_sz * 2),
            "assets/clip_00.bin": rng.randbytes(chunk_sz),
            "assets/manifest.json": f'{{"archetype":"compressed_media","seed":{seed}}}\n'.encode("utf-8"),
        }
        seed_commits = [CommitSpec(f"seed compressed media r{repo_index}", dict(files))]
        waves: list[list[CommitSpec]] = []
        for w in range(2 * mult):
            w_files = dict(files)
            w_files[f"assets/frame_{w + 1:02d}.png"] = _png_like_blob(rng, chunk_sz)
            w_files["assets/manifest.json"] = f'{{"archetype":"compressed_media","wave":{w + 1}}}\n'.encode("utf-8")
            files = w_files
            waves.append([CommitSpec(f"media wave {w + 1}", dict(w_files))])
        return seed_commits, waves, "assets/manifest.json"

    if archetype == "large_binary":
        blob_sz = 384 * 1024 if scale == "full" else 160 * 1024
        base_buf = bytearray(b"BINHEADER-ROOTYARD-178\n" * 64)
        base_buf.extend((idx & 0xFF for idx in range(blob_sz - len(base_buf))))
        files = {
            "artifacts/firmware.bin": bytes(base_buf),
            "artifacts/checksums.txt": f"size={len(base_buf)} seed={seed}\n".encode("utf-8"),
        }
        seed_commits = [CommitSpec("seed large binary v0", dict(files))]
        waves = []
        for w in range(2 * mult):
            patched = bytearray(base_buf)
            patch_off = (w + 1) * 4096
            patched[patch_off : patch_off + 2048] = rng.randbytes(2048)
            files = dict(files)
            files["artifacts/firmware.bin"] = bytes(patched)
            files["artifacts/checksums.txt"] = f"wave={w + 1} patch_off={patch_off}\n".encode("utf-8")
            base_buf = patched
            waves.append([CommitSpec(f"binary revision {w + 1}", dict(files))])
        return seed_commits, waves, "artifacts/checksums.txt"

    if archetype == "text_history":
        files = {
            "README.md": f"# Rootyard Text Corpus r{repo_index}\nseed={seed}\n".encode("utf-8"),
            "src/engine.rs": _code_block(rng, f"engine_{repo_index}", 140 * mult),
            "src/index.rs": _code_block(rng, f"index_{repo_index}", 120 * mult),
        }
        seed_commits = [CommitSpec("seed text base", dict(files))]
        for s in range(2 * mult):
            files = dict(files)
            files["src/engine.rs"] += _code_block(rng, f"eng_inc_{s}", 30 * mult)
            files[f"docs/changelog_{s}.md"] = (
                f"## Entry {s}\n" + ("details line\n" * (20 * mult))
            ).encode("utf-8")
            seed_commits.append(CommitSpec(f"seed text step {s}", dict(files)))
        waves = []
        for w in range(3 * mult):
            w_files = dict(files)
            w_files["src/index.rs"] += _code_block(rng, f"idx_wave_{w}", 25 * mult)
            w_files["README.md"] += f"- release note {w}\n".encode("utf-8")
            files = w_files
            waves.append([CommitSpec(f"text wave {w}", dict(w_files))])
        return seed_commits, waves, "README.md"

    if archetype == "small_deltas":
        files = {
            "counter.txt": f"seed={seed} seq=0\n".encode("utf-8"),
            "notes.log": "init\n".encode("utf-8"),
        }
        seed_commits = [CommitSpec("seed small deltas", dict(files))]
        waves = []
        wave_count = 8 if scale == "full" else 4
        commits_per_wave = 3
        seq = 1
        for w in range(wave_count):
            batch: list[CommitSpec] = []
            for _ in range(commits_per_wave):
                d_files = dict(files)
                d_files["counter.txt"] = f"seed={seed} seq={seq}\n".encode("utf-8")
                d_files["notes.log"] = files["notes.log"] + f"event={seq} token={rng.getrandbits(32):08x}\n".encode("utf-8")
                files = d_files
                batch.append(CommitSpec(f"small delta seq={seq}", dict(d_files)))
                seq += 1
            waves.append(batch)
        return seed_commits, waves, "counter.txt"

    if archetype == "similar_files":
        shared = (
            f"// Shared deterministic template corpus seed={seed} repo={repo_index}\n"
            + ("const SHARED_ROW: &str = \"rootyard-pando-pack-delta-template-line\";\n" * (160 * mult))
        ).encode("utf-8")
        # Interleave 14 filenames and tiny size deltas so narrow window=10 sees partial matches while window=25/50 spans more.
        files = {}
        for k in range(14):
            pad = b" " * (k * 3)
            files[f"templates/layer_{k % 3}/item_{k:02d}_mod.rs"] = (
                shared + pad + f"\nconst PART: usize = {k}; // salt={rng.getrandbits(32):08x}\n".encode("utf-8")
            )
        seed_commits = [CommitSpec("seed similar files", dict(files))]
        waves = []
        for w in range(3 * mult):
            w_files = dict(files)
            renamed = f"templates/archive/renamed_{w:02d}_mod.rs"
            w_files[renamed] = shared + f"\nconst RENAMED_WAVE: usize = {w}; // salt={rng.getrandbits(32):08x}\n".encode("utf-8")
            files = w_files
            waves.append([CommitSpec(f"similar/renamed wave {w}", dict(w_files))])
        return seed_commits, waves, "templates/layer_0/item_00_mod.rs"

    # multi_repo
    files = {
        "README.md": f"# Multi Repo Member r{repo_index} seed={seed}\n".encode("utf-8"),
        "src/lib.rs": _code_block(rng, f"mr_{repo_index}", 90 * mult),
        "assets/thumb.png": _png_like_blob(rng, 24 * 1024 * mult),
    }
    seed_commits = [CommitSpec(f"seed multi_repo r{repo_index}", dict(files))]
    waves = []
    for w in range(2 * mult):
        w_files = dict(files)
        w_files["src/lib.rs"] += _code_block(rng, f"mr_{repo_index}_w{w}", 25 * mult)
        w_files["README.md"] += f"wave={w}\n".encode("utf-8")
        files = w_files
        waves.append([CommitSpec(f"multi_repo wave {w}", dict(w_files))])
    return seed_commits, waves, "README.md"


def init_bare_repo(git_bin: str | Path, bare_dir: Path, env: dict[str, str], object_format: str = "sha1") -> None:
    """Initialize a non-auto-GC bare repository matching server ingestion defaults."""
    if object_format not in OBJECT_FORMATS:
        raise ValueError(f"unsupported object_format: {object_format}")
    bare_dir.mkdir(parents=True, exist_ok=True)
    proc, _ = run_git(
        git_bin,
        ["init", "--bare", "--quiet", f"--object-format={object_format}", "--initial-branch=main", str(bare_dir)],
        None,
        env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git init --bare failed: {proc.stderr.decode(errors='replace')[:300]}")
    for k, v in (
        ("gc.auto", "0"),
        ("maintenance.auto", "false"),
        ("receive.autogc", "false"),
        ("receive.unpackLimit", "0"),
        ("receive.fsckObjects", "true"),
        ("transfer.fsckObjects", "true"),
        ("pack.windowMemory", "32m"),
        ("pack.threads", "1"),
    ):
        cfg_proc, _ = run_git(git_bin, ["--git-dir", str(bare_dir), "config", k, v], None, env)
        if cfg_proc.returncode != 0:
            raise RuntimeError(f"git config {k}={v} failed")


def init_work_repo(git_bin: str | Path, work_dir: Path, env: dict[str, str], object_format: str = "sha1") -> None:
    """Initialize a clean working repository for deterministic commits."""
    work_dir.mkdir(parents=True, exist_ok=True)
    proc, _ = run_git(
        git_bin,
        ["init", "--quiet", f"--object-format={object_format}", "--initial-branch=main", str(work_dir)],
        None,
        env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git init failed: {proc.stderr.decode(errors='replace')[:300]}")
    for k, v in (("user.name", "Rootyard Eval"), ("user.email", "pack-eval@rootyard.invalid")):
        run_git(git_bin, ["config", k, v], work_dir, env)


def apply_commit_spec(
    git_bin: str | Path,
    work_dir: Path,
    spec: CommitSpec,
    env: dict[str, str],
    step_offset: int,
) -> str:
    """Replace tracked content cleanly and create one deterministic commit."""
    keep_git = work_dir / ".git"
    for item in list(work_dir.iterdir()):
        if item == keep_git:
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    for rel_path, content in spec.files.items():
        target = work_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    ts = f"{BASE_UNIX_TIME + step_offset} +0000"
    commit_env = env.copy()
    commit_env["GIT_AUTHOR_DATE"] = ts
    commit_env["GIT_COMMITTER_DATE"] = ts
    add_proc, _ = run_git(git_bin, ["add", "-A"], work_dir, commit_env)
    if add_proc.returncode != 0:
        raise RuntimeError(f"git add failed: {add_proc.stderr.decode(errors='replace')[:300]}")
    c_proc, _ = run_git(git_bin, ["commit", "--quiet", "-m", spec.message], work_dir, commit_env)
    if c_proc.returncode != 0:
        raise RuntimeError(f"git commit failed: {c_proc.stderr.decode(errors='replace')[:300]}")
    rev_proc, _ = run_git(git_bin, ["rev-parse", "HEAD"], work_dir, commit_env)
    return rev_proc.stdout.decode("utf-8").strip()


def measure_bare_repo_stats(git_bin: str | Path, bare_dir: Path, env: dict[str, str]) -> dict[str, Any]:
    """Measure unique logical object bytes, loose/pack counts, and pack+idx bytes."""
    proc, _ = run_git(
        git_bin,
        ["--git-dir", str(bare_dir), "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        None,
        env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cat-file failed: {proc.stderr.decode(errors='replace')[:300]}")
    unique_objects = 0
    independent_logical_bytes = 0
    counts_by_type: dict[str, int] = {}
    for line in proc.stdout.decode("utf-8").splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        unique_objects += 1
        counts_by_type[parts[1]] = counts_by_type.get(parts[1], 0) + 1
        independent_logical_bytes += int(parts[2])
    pack_dir = bare_dir / "objects" / "pack"
    pack_bytes = 0
    idx_bytes = 0
    pack_count = 0
    if pack_dir.is_dir():
        for p in sorted(pack_dir.iterdir()):
            if p.suffix == ".pack" and p.is_file():
                pack_count += 1
                pack_bytes += p.stat().st_size
            elif p.suffix == ".idx" and p.is_file():
                idx_bytes += p.stat().st_size
    return {
        "unique_objects": unique_objects,
        "counts_by_type": counts_by_type,
        "independent_logical_bytes": independent_logical_bytes,
        "pack_count": pack_count,
        "pack_bytes": pack_bytes,
        "idx_bytes": idx_bytes,
        "pack_idx_total_bytes": pack_bytes + idx_bytes,
    }


def seed_multi_push_bare_repo(
    git_bin: str | Path,
    archetype: str,
    seed: int,
    scale: str,
    root_dir: Path,
    env: dict[str, str],
    object_format: str = "sha1",
) -> dict[str, Any]:
    """Create a multi-pack bare repository via incremental stock-Git pushes (no repack)."""
    bare_dir = root_dir / "bare.git"
    work_dir = root_dir / "work"
    init_bare_repo(git_bin, bare_dir, env, object_format=object_format)
    init_work_repo(git_bin, work_dir, env, object_format=object_format)
    seed_commits, waves, browse_path = build_archetype_commits(archetype, seed, scale=scale)
    remote_url = bare_dir.resolve().as_uri()
    run_git(git_bin, ["remote", "add", "origin", remote_url], work_dir, env)
    step = 0
    head_oid = ""
    for cs in seed_commits:
        head_oid = apply_commit_spec(git_bin, work_dir, cs, env, step)
        step += 1
    push0, _ = run_git(git_bin, ["push", "--quiet", "origin", "HEAD:refs/heads/main"], work_dir, env)
    if push0.returncode != 0:
        raise RuntimeError(f"seed push failed: {push0.stderr.decode(errors='replace')[:300]}")
    for wave_idx, wave in enumerate(waves, start=1):
        for cs in wave:
            head_oid = apply_commit_spec(git_bin, work_dir, cs, env, step)
            step += 1
        pw, _ = run_git(
            git_bin,
            ["push", "--quiet", "origin", "HEAD:refs/heads/main", f"HEAD:refs/heads/wave_{wave_idx}"],
            work_dir,
            env,
        )
        if pw.returncode != 0:
            raise RuntimeError(f"wave push failed: {pw.stderr.decode(errors='replace')[:300]}")
    stats = measure_bare_repo_stats(git_bin, bare_dir, env)
    return {
        "archetype": archetype,
        "object_format": object_format,
        "bare_dir": bare_dir,
        "work_dir": work_dir,
        "head_oid": head_oid,
        "browse_path": browse_path,
        "pre_compaction": stats,
    }


def build_git_http_env(
    base_env: dict[str, str], askpass_path: Path, username: str, token_secret: str
) -> dict[str, str]:
    """Construct Smart HTTP non-interactive git environment using askpass secret."""
    env = isolated_git_env(base_env)
    env.update(
        {
            "GIT_ASKPASS": str(askpass_path),
            "GIT_ASKPASS_REQUIRE": "force",
            "ROOTYARD_ASKPASS_USER": username,
            "ROOTYARD_ASKPASS_SECRET": token_secret,
            "GCM_INTERACTIVE": "never",
        }
    )
    return env


def write_askpass_script(path: Path) -> Path:
    """Create 0700 askpass script reading username/password from env (never argv)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        bat = path.with_suffix(".cmd")
        bat.write_text(
            "@echo off\r\nif \"%~1\"==\"\" exit /b 1\r\n"
            "echo %~1 | findstr /I \"Username\" >nul && (echo %ROOTYARD_ASKPASS_USER% & exit /b 0)\r\n"
            "echo %ROOTYARD_ASKPASS_SECRET%\r\n",
            encoding="ascii",
        )
        return bat
    path.write_text(
        "#!/bin/sh\ncase \"$1\" in *Username*) printf '%s\\n' \"$ROOTYARD_ASKPASS_USER\" ;;\n"
        "*) printf '%s\\n' \"$ROOTYARD_ASKPASS_SECRET\" ;; esac\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return path


def url_quote_repo(owner: str, name: str) -> tuple[str, str]:
    return urllib.parse.quote(owner, safe=""), urllib.parse.quote(name, safe="")
