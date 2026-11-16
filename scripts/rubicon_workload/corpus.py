"""Deterministic corpus generation and stock Git HTTP client helpers (Refs #164)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import random
import subprocess
import time

DATASET_CLASSES: tuple[str, ...] = (
    "text_history",
    "similar_files",
    "compressed_media",
    "small_deltas",
    "multi_repo",
)


@dataclass(frozen=True)
class CommitSpec:
    """One deterministic commit payload for repository seeding or workload pushes."""

    message: str
    files: dict[str, bytes]

    @property
    def raw_bytes(self) -> int:
        return sum(len(content) for content in self.files.values())


def _text_block(rng: random.Random, tag: str, line_count: int) -> bytes:
    lines = []
    for idx in range(line_count):
        token = f"{rng.getrandbits(32):08x}"
        lines.append(f"pub fn {tag}_{idx:03d}(seq: u64) -> u64 {{ seq.wrapping_add(0x{token}) }} // {tag}\n")
    return "".join(lines).encode("utf-8")


def generate_repo_corpus(
    dataset_class: str,
    seed: int,
    repo_index: int,
    variant_index: int = 0,
) -> tuple[list[CommitSpec], list[CommitSpec]]:
    """Return deterministic (seed_commits, delta_commits) well within schema 142 quotas."""
    if dataset_class not in DATASET_CLASSES:
        raise ValueError(f"unsupported dataset class: {dataset_class}")
    local_seed = int.from_bytes(
        hashlib.sha256(f"{seed}:{dataset_class}:{repo_index}:{variant_index}".encode("utf-8")).digest()[:8],
        "big",
    )
    rng = random.Random(local_seed)

    if dataset_class == "text_history":
        files: dict[str, bytes] = {
            "README.md": f"# Rubicon text history repo {repo_index}\nseed={seed}\n".encode("utf-8"),
            "src/module_a.rs": _text_block(rng, f"alpha_{repo_index}", 140),
            "src/module_b.rs": _text_block(rng, f"beta_{repo_index}", 140),
        }
        seed_commits = [CommitSpec(f"seed text base r{repo_index}", dict(files))]
        for step in range(1, 4):
            files = dict(files)
            files["src/module_a.rs"] = files["src/module_a.rs"] + _text_block(rng, f"alpha_inc_{step}", 35)
            files[f"docs/note_{step}.md"] = f"iteration={step} seed={local_seed}\n".encode("utf-8")
            seed_commits.append(CommitSpec(f"seed text history step {step}", files))
        delta_commits = []
        for step in range(4):
            d_files = dict(files)
            d_files["src/module_b.rs"] = _text_block(rng, f"beta_d_{step}_{variant_index}", 80)
            delta_commits.append(CommitSpec(f"text delta {step} v{variant_index}", d_files))
        return seed_commits, delta_commits

    if dataset_class == "similar_files":
        shared_prefix = (
            f"// Shared deterministic template seed={seed} repo={repo_index}\n"
            + ("const TEMPLATE_PAD: &str = \"rootyard-rubicon-delta-shared-prefix-line\";\n" * 180)
        ).encode("utf-8")
        files = {
            f"templates/part_{k}.txt": shared_prefix + f"\nvariant_part={k} salt={rng.getrandbits(32):08x}\n".encode()
            for k in range(4)
        }
        seed_commits = [CommitSpec(f"seed similar files r{repo_index}", files)]
        delta_commits = []
        for step in range(4):
            d_files = dict(files)
            d_files[f"templates/part_{step % 4}.txt"] = (
                shared_prefix + f"\ndelta_step={step} v={variant_index} salt={rng.getrandbits(32):08x}\n".encode()
            )
            delta_commits.append(CommitSpec(f"similar delta {step} v{variant_index}", d_files))
        return seed_commits, delta_commits

    if dataset_class == "compressed_media":
        files = {
            "assets/media_a.bin": rng.randbytes(112 * 1024),
            "assets/media_b.bin": rng.randbytes(48 * 1024),
            "assets/manifest.txt": f"format=binary repo={repo_index} seed={seed}\n".encode("utf-8"),
        }
        seed_commits = [CommitSpec(f"seed compressed media r{repo_index}", files)]
        delta_commits = []
        for step in range(3):
            d_files = dict(files)
            d_files[f"assets/chunk_{step}.bin"] = rng.randbytes(48 * 1024)
            delta_commits.append(CommitSpec(f"compressed media delta {step} v{variant_index}", d_files))
        return seed_commits, delta_commits

    if dataset_class == "small_deltas":
        base = {
            "counter.txt": f"seed={seed} repo={repo_index} seq=0\n".encode("utf-8"),
            "meta.json": f'{{"repo":{repo_index},"seed":{seed}}}\n'.encode("utf-8"),
        }
        seed_commits = [CommitSpec(f"seed small delta r{repo_index}", base)]
        delta_commits = []
        for step in range(5):
            payload = dict(base)
            payload["counter.txt"] = f"seed={seed} repo={repo_index} seq={step + 1} v={variant_index}\n".encode("utf-8")
            payload["delta_pad.txt"] = f"line={step} val={rng.getrandbits(64):016x}\n".encode("utf-8") * 24
            delta_commits.append(CommitSpec(f"small delta {step} v{variant_index}", payload))
        return seed_commits, delta_commits

    # multi_repo
    files = {
        "README.md": f"# Multi-repo tenant item {repo_index} (variant {variant_index})\n".encode("utf-8"),
        "src/lib.rs": _text_block(rng, f"mr_{repo_index}", 90),
        "blobs/data.bin": rng.randbytes(32 * 1024),
    }
    seed_commits = [CommitSpec(f"seed multi_repo r{repo_index}", files)]
    delta_commits = []
    for step in range(4):
        d_files = dict(files)
        d_files["src/lib.rs"] = d_files["src/lib.rs"] + _text_block(rng, f"mr_upd_{step}", 25)
        d_files["blobs/inc.bin"] = rng.randbytes(8 * 1024)
        delta_commits.append(CommitSpec(f"multi_repo delta {step} v{variant_index}", d_files))
    return seed_commits, delta_commits


def write_askpass_script(path: Path) -> Path:
    """Create a 0700 askpass script reading username/token strictly from env."""
    path.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  *Username*) printf \'%s\\n\' "$ROOTYARD_GIT_USERNAME" ;;\n'
        '  *Password*) printf \'%s\\n\' "$ROOTYARD_GIT_TOKEN" ;;\n'
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
        newline="\n",
    )
    os.chmod(path, 0o700)
    return path


def build_git_env(
    base_env: dict[str, str],
    askpass_path: Path | None = None,
    token: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return an isolated process environment for real stock Git Smart HTTP invocations."""
    env = {
        key: base_env[key]
        for key in (
            "PATH",
            "HOME",
            "GIT_HTTP_LOW_SPEED_LIMIT",
            "GIT_HTTP_LOW_SPEED_TIME",
        )
        if key in base_env
    }
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "GIT_HTTP_LOW_SPEED_LIMIT": "1",
            "GIT_HTTP_LOW_SPEED_TIME": "30",
        }
    )
    if askpass_path is not None and token is not None:
        env["GIT_ASKPASS"] = str(askpass_path)
        env["GIT_ASKPASS_REQUIRE"] = "force"
        env["ROOTYARD_GIT_USERNAME"] = token["username"]
        env["ROOTYARD_GIT_TOKEN"] = token["token"]
    return env


def run_git(
    git_bin: str,
    args: list[str],
    cwd: Path | None,
    env: dict[str, str],
    timeout: int = 60,
) -> tuple[subprocess.CompletedProcess[bytes], float]:
    """Execute stock Git directly and measure wall-clock latency in milliseconds."""
    cmd = [
        git_bin,
        "--no-pager",
        "-c",
        "credential.helper=",
        "-c",
        "http.lowSpeedLimit=1",
        "-c",
        "http.lowSpeedTime=30",
        *args,
    ]
    start = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    elapsed_ms = (time.monotonic() - start) * 1000.0
    return proc, elapsed_ms


def materialize_commit_spec(work_dir: Path, spec: CommitSpec, git_bin: str, env: dict[str, str]) -> str:
    """Write files from CommitSpec into a Git worktree, commit, and return the commit OID."""
    for rel_path, payload in spec.files.items():
        dest = work_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
    add_proc, _ = run_git(git_bin, ["add", "-A"], work_dir, env)
    if add_proc.returncode != 0:
        raise RuntimeError(f"git add failed: {add_proc.stderr.decode(errors='replace')[:400]}")
    commit_proc, _ = run_git(git_bin, ["commit", "-m", spec.message], work_dir, env)
    if commit_proc.returncode != 0:
        raise RuntimeError(f"git commit failed: {commit_proc.stderr.decode(errors='replace')[:400]}")
    rev_proc, _ = run_git(git_bin, ["rev-parse", "HEAD"], work_dir, env)
    if rev_proc.returncode != 0:
        raise RuntimeError(f"git rev-parse HEAD failed: {rev_proc.stderr.decode(errors='replace')[:400]}")
    return rev_proc.stdout.decode("utf-8").strip()


def parse_push_porcelain(stdout_text: str) -> list[dict[str, str]]:
    """Parse `git push --porcelain` lines into flag, target ref, and status summary."""
    entries: list[dict[str, str]] = []
    for line in stdout_text.splitlines():
        if len(line) < 3 or line[0] not in "*+=!- " or "\t" not in line:
            continue
        parts = line.split("\t")
        refspec = parts[1] if len(parts) > 1 else ""
        summary = parts[2] if len(parts) > 2 else ""
        entries.append(
            {
                "flag": line[0],
                "target": refspec.rsplit(":", 1)[-1],
                "summary": summary,
            }
        )
    return entries


def push_has_success(entries: list[dict[str, str]], target_ref: str) -> bool:
    return any(entry["flag"] in "*+= " and entry["target"] == target_ref for entry in entries)


def push_has_rejection(entries: list[dict[str, str]], target_ref: str) -> bool:
    return any(entry["flag"] == "!" and entry["target"] == target_ref for entry in entries)


def classify_git_push(proc: subprocess.CompletedProcess[bytes], target_ref: str) -> tuple[str, str]:
    """Classify a Git push strictly into committed_success, typed_refusal, or unknown_outcome."""
    stdout_text = (proc.stdout or b"").decode("utf-8", errors="replace")
    stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace")
    entries = parse_push_porcelain(stdout_text)
    if proc.returncode == 0 and push_has_success(entries, target_ref):
        return "committed_success", "ok"

    lower_err = stderr_text.lower()
    if push_has_rejection(entries, target_ref) or any(
        marker in lower_err
        for marker in (
            "[rejected]",
            "non-fast-forward",
            "fetch first",
            "stale info",
            "atomic push failed",
            "pre-receive hook declined",
            "authentication failed",
            "returned error: 401",
            "returned error: 403",
            "returned error: 404",
            "returned error: 409",
            "returned error: 422",
            "returned error: 503",
            "repository not found",
        )
    ):
        return "typed_refusal", "rejected_or_denied"

    return "unknown_outcome", f"exit_{proc.returncode}"


def classify_http_status(status: int | None, err: Exception | None = None) -> str:
    """Classify an HTTP API operation strictly into committed_success, typed_refusal, or unknown_outcome."""
    if err is not None or status is None:
        return "unknown_outcome"
    if 200 <= status < 300:
        return "committed_success"
    if 400 <= status < 500 or status in (501, 503):
        return "typed_refusal"
    return "unknown_outcome"


def git_remote_refs(
    git_bin: str,
    remote_url: str,
    base_env: dict[str, str],
    askpass_path: Path,
    token: dict[str, str],
) -> tuple[dict[str, str], float]:
    """Query remote refs via real stock `git ls-remote` over HTTP."""
    env = build_git_env(base_env, askpass_path, token)
    proc, ms = run_git(git_bin, ["ls-remote", remote_url], cwd=None, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-remote failed ({proc.returncode}): {proc.stderr.decode(errors='replace')[:300]}")
    refs: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if "\t" in line:
            oid, name = line.split("\t", 1)
            refs[name] = oid
    return refs, ms


def init_seeded_worktree(
    git_bin: str,
    remote_url: str,
    work_dir: Path,
    base_env: dict[str, str],
    askpass_path: Path,
    token: dict[str, str],
    seed_commits: list[CommitSpec],
) -> tuple[str, float]:
    """Clone empty repo, configure author, materialize seed_commits, push HEAD:refs/heads/main."""
    env = build_git_env(base_env, askpass_path, token)
    clone_proc, _ = run_git(git_bin, ["clone", remote_url, str(work_dir)], cwd=None, env=env)
    if clone_proc.returncode != 0:
        raise RuntimeError(f"empty clone failed ({clone_proc.returncode}): {clone_proc.stderr.decode(errors='replace')[:300]}")
    for key, val in (("user.name", "Rubicon Harness"), ("user.email", "rubicon@example.invalid")):
        cfg_proc, _ = run_git(git_bin, ["config", key, val], cwd=work_dir, env=env)
        if cfg_proc.returncode != 0:
            raise RuntimeError(f"git config {key} failed")
    last_oid = ""
    for spec in seed_commits:
        last_oid = materialize_commit_spec(work_dir, spec, git_bin, env)
    push_proc, push_ms = run_git(git_bin, ["push", "--porcelain", "origin", "HEAD:refs/heads/main"], cwd=work_dir, env=env)
    outcome, detail = classify_git_push(push_proc, "refs/heads/main")
    if outcome != "committed_success":
        raise RuntimeError(f"seed push failed ({outcome}/{detail}): {push_proc.stderr.decode(errors='replace')[:300]}")
    return last_oid, push_ms


def clone_and_fsck(
    git_bin: str,
    remote_url: str,
    dest_dir: Path,
    base_env: dict[str, str],
    askpass_path: Path,
    token: dict[str, str],
    branch: str | None = None,
) -> tuple[bool, float, str | None]:
    """Clone repository via Smart HTTP, measure clone time, and verify `git fsck --full --strict`."""
    env = build_git_env(base_env, askpass_path, token)
    args = ["clone"]
    if branch:
        args.extend(["--branch", branch])
    args.extend([remote_url, str(dest_dir)])
    clone_proc, clone_ms = run_git(git_bin, args, cwd=None, env=env)
    if clone_proc.returncode != 0:
        return False, clone_ms, None
    rev_proc, _ = run_git(git_bin, ["rev-parse", "HEAD"], cwd=dest_dir, env=env)
    if rev_proc.returncode != 0:
        return False, clone_ms, None
    head_oid = rev_proc.stdout.decode("utf-8").strip()
    fsck_proc, _ = run_git(git_bin, ["fsck", "--full", "--strict"], cwd=dest_dir, env=env)
    if fsck_proc.returncode != 0:
        return False, clone_ms, head_oid
    return True, clone_ms, head_oid
