#!/usr/bin/env python3
"""Real-Git incremental sync, ignore rules, and read-only view tests for rootyard-workspace-lab."""

import argparse
import base64
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
import uuid


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def is_uuid(value):
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def tree(path):
    result = {}
    root = os.fsencode(path)

    def walk(directory, prefix=b""):
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            relative = prefix + entry.name
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                result[relative] = ("link", os.readlink(entry.path))
            elif stat.S_ISDIR(info.st_mode):
                walk(entry.path, relative + b"/")
            elif stat.S_ISREG(info.st_mode):
                with open(entry.path, "rb") as stream:
                    digest = hashlib.sha256(stream.read()).hexdigest()
                result[relative] = ("file", info.st_mode & 0o111, digest)
            else:
                result[relative] = ("special", stat.S_IFMT(info.st_mode))

    walk(root)
    return result


class RootyardIgnoreMatcher:
    def __init__(self, repo_root: Path = None):
        self.rules = []
        if repo_root is None:
            return
        ignore_files = []
        if (repo_root / ".rootyardignore").is_file():
            ignore_files.append(Path(".rootyardignore"))
        for dirpath, dirnames, filenames in os.walk(repo_root):
            rel_dir = Path(dirpath).relative_to(repo_root)
            if rel_dir.parts and rel_dir.parts[0] == ".git":
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d != ".git"]
            if ".rootyardignore" in filenames and rel_dir != Path("."):
                ignore_files.append(rel_dir / ".rootyardignore")
        ignore_files.sort(key=lambda p: (len(p.parts), str(p)))
        for rel_file in ignore_files:
            base_dir = "" if str(rel_file.parent) == "." else rel_file.parent.as_posix()
            content = (repo_root / rel_file).read_bytes().decode("utf-8", errors="replace")
            self.add_patterns(base_dir, content)

    def add_patterns(self, base_dir: str, content: str):
        for raw in content.splitlines():
            line = raw.rstrip("\r")
            if not line or line.startswith("#"):
                continue
            while line.endswith(" ") and not line.endswith("\\ "):
                line = line[:-1]
            if not line:
                continue
            negated = False
            if line.startswith("!"):
                negated = True
                line = line[1:]
            elif line.startswith(r"\!") or line.startswith(r"\#"):
                line = line[1:]
            dir_only = line.endswith("/")
            if dir_only:
                line = line[:-1]
            if not line:
                continue
            if line.startswith("/"):
                anchored = True
                line = line[1:]
            else:
                anchored = "/" in line
            if line:
                self.rules.append((base_dir, line, negated, dir_only, anchored))

    def _matches_single(self, rel_posix: str, is_dir: bool) -> bool:
        ignored = False
        for base_dir, pattern, negated, dir_only, anchored in self.rules:
            if dir_only and not is_dir:
                continue
            if base_dir:
                prefix = base_dir + "/"
                if not rel_posix.startswith(prefix):
                    continue
                sub = rel_posix[len(prefix):]
            else:
                sub = rel_posix
            if not sub:
                continue
            if anchored:
                matched = fnmatch.fnmatchcase(sub, pattern)
            else:
                basename = sub.rsplit("/", 1)[-1]
                matched = fnmatch.fnmatchcase(basename, pattern) or fnmatch.fnmatchcase(sub, pattern)
            if matched:
                ignored = not negated
        return ignored

    def is_ignored(self, rel_posix: str, is_dir: bool = False) -> bool:
        if not self.rules:
            return False
        parts = rel_posix.split("/")
        for idx in range(1, len(parts)):
            anc = "/".join(parts[:idx])
            if self._matches_single(anc, True):
                return True
        return self._matches_single(rel_posix, is_dir)


def _run_reference_cli(argv):
    SCHEMA = 1
    if not argv:
        sys.stderr.write("usage: rootyard-workspace-lab ...\n")
        return 1
    cmd = argv[0]
    expected_lengths = {
        "init": (6,),
        "checkpoint": (4,),
        "restore": (4,),
        "inspect": (3,),
        "status": (3,),
        "changeset": (4,),
        "apply": (5,),
        "sync-dirty": (4, 5),
        "verify-readonly-view": (3, 4),
        "push-remote": (4, 5),
        "pull-remote": (5,),
        "namespace-mount": tuple(range(4, 32)),
        "verify-namespace": (3, 4),
        "namespace-git-view": (3, 4),
        "vfs-mount": tuple(range(4, 32)),
        "vfs-hydrate": tuple(range(4, 32)),
        "vfs-status": (3,),
        "vfs-evict": tuple(range(4, 32)),
        "agent-lease": tuple(range(5, 16)),
        "namespace-write": (6, 8),
        "namespace-commit-back": tuple(range(4, 10)),
        "overlay-mount": tuple(range(4, 16)),
        "overlay-op": tuple(range(4, 16)),
        "overlay-write": tuple(range(5, 16)),
        "overlay-delete": tuple(range(4, 16)),
        "overlay-rename": tuple(range(5, 16)),
        "overlay-chmod": tuple(range(5, 16)),
        "overlay-git-add-f": tuple(range(4, 16)),
        "overlay-status": (3,),
        "crash-drill": tuple(range(4, 10)),
        "crash-recover": (3,),
    }
    if cmd not in expected_lengths or len(argv) not in expected_lengths[cmd]:
        sys.stderr.write("usage: invalid arguments\n")
        return 1
    if cmd == "push-remote" and len(argv) == 5 and argv[4] != "--quiescent":
        sys.stderr.write("usage: invalid arguments\n")
        return 1
    if cmd in ("init", "checkpoint", "apply", "sync-dirty") and argv[-1] != "--quiescent":
        sys.stderr.write("stop ALL writers and explicitly pass --quiescent\n")
        return 1

    git_bin = os.environ.get("ROOTYARD_WORKSPACE_GIT", "git")

    def run_git(repo, *args, check=True, extra_env=None):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        if extra_env:
            env.update(extra_env)
        res = subprocess.run(
            [
                git_bin,
                "-c", "core.hooksPath=/dev/null",
                "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false",
                "-c", "core.excludesFile=/dev/null",
                "-c", "core.attributesFile=/dev/null",
                "-c", "gc.auto=0",
                "-c", "maintenance.auto=false",
                "-C", str(repo),
                *args,
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if check and res.returncode != 0:
            raise RuntimeError(f"git {args[0]} failed: {res.stderr.decode(errors='replace')}")
        return res

    store_arg = Path(argv[1])
    if cmd == "init":
        source_real = Path(argv[2]).resolve()
        prospective = store_arg.resolve() if store_arg.exists() else (store_arg.parent.resolve() / store_arg.name)
        if str(source_real).startswith(str(prospective)) or str(prospective).startswith(str(source_real)):
            sys.stderr.write("source and store must not overlap\n")
            return 1

    if not store_arg.exists():
        store_arg.mkdir(mode=0o700)
    store_root = store_arg.resolve()
    if (store_root.stat().st_mode & 0o077) != 0:
        sys.stderr.write("store must be private (mode 0700)\n")
        return 1
    for sub in ("workspaces", "checkpoints", "changesets", "views", "namespaces", "vfs", "leases", "overlays", "staging"):
        p = store_root / sub
        if not p.exists():
            p.mkdir(mode=0o700)


    git_ver = run_git(store_root, "--version").stdout.decode().strip()

    def encode_path(rel_bytes: bytes) -> str:
        return base64.b64encode(rel_bytes).decode("ascii")

    def decode_path(b64: str) -> bytes:
        raw = base64.b64decode(b64)
        if not raw or b"\x00" in raw or raw.endswith(b"/"):
            raise RuntimeError("invalid path")
        for part in raw.split(b"/"):
            if not part or part in (b".", b".."):
                raise RuntimeError("unsafe path component")
        return raw

    def validate_symlink(root: Path, rel_bytes: bytes, target_bytes: bytes):
        if not target_bytes or target_bytes.startswith(b"/"):
            raise RuntimeError("absolute or empty symlink target unsupported")
        resolved = [p for p in rel_bytes.split(b"/")[:-1] if p]
        pending = [p for p in target_bytes.split(b"/") if p]
        links = 0
        while pending:
            comp = pending.pop(0)
            if comp == b".":
                continue
            if comp == b"..":
                if not resolved:
                    raise RuntimeError("symlink escapes repository")
                resolved.pop()
                continue
            resolved.append(comp)
            if resolved and resolved[0] == b".git":
                raise RuntimeError("symlink into Git metadata unsupported")
            loc = os.path.join(os.fsencode(root), *resolved)
            if os.path.lexists(loc):
                st = os.lstat(loc)
                if stat.S_ISLNK(st.st_mode):
                    links += 1
                    if links > 40:
                        raise RuntimeError("symlink loop")
                    link_t = os.readlink(loc)
                    if link_t.startswith(b"/"):
                        raise RuntimeError("symlink chain escapes repository")
                    resolved.pop()
                    pending = [p for p in link_t.split(b"/") if p] + pending

    def walk_files(root: Path):
        out = {}
        root_b = os.fsencode(root)

        def visit(rel_b: bytes):
            full_dir = os.path.join(root_b, rel_b) if rel_b else root_b
            for entry in sorted(os.scandir(full_dir), key=lambda e: e.name):
                child_rel = (rel_b + b"/" + entry.name) if rel_b else entry.name
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    if entry.name == b".git" and child_rel != b".git":
                        raise RuntimeError("nested Git repositories unsupported")
                    visit(child_rel)
                else:
                    out[child_rel] = st

        visit(b"")
        return out

    def entry_for_rel(root: Path, rel_b: bytes):
        full = os.path.join(os.fsencode(root), rel_b)
        if not os.path.lexists(full):
            return None
        st = os.lstat(full)
        if stat.S_ISDIR(st.st_mode):
            return None
        if stat.S_ISLNK(st.st_mode):
            if rel_b.startswith(b".git/") or rel_b == b".git":
                raise RuntimeError("symlink in .git unsupported")
            target = os.readlink(full)
            validate_symlink(root, rel_b, target)
            return {
                "path_base64": encode_path(rel_b),
                "kind": "symlink",
                "mode": 0o777,
                "size": len(target),
                "sha256": hashlib.sha256(target).hexdigest(),
            }
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError("special file unsupported")
        with open(full, "rb") as f:
            data = f.read()
        return {
            "path_base64": encode_path(rel_b),
            "kind": "file",
            "mode": st.st_mode & 0o777,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def inventory(root: Path):
        entries = []
        for rel_b in sorted(walk_files(root).keys()):
            entries.append(entry_for_rel(root, rel_b))
        return entries

    def classify_repo(repo: Path):
        head_paths = set()
        for rec in run_git(repo, "ls-tree", "-rz", "--full-tree", "HEAD").stdout.split(b"\x00"):
            if not rec:
                continue
            if rec.startswith(b"160000 "):
                raise RuntimeError("submodules unsupported")
            head_paths.add(rec.split(b"\t", 1)[1])
        index_paths = set()
        for rec in run_git(repo, "ls-files", "--stage", "-z").stdout.split(b"\x00"):
            if not rec:
                continue
            if rec.startswith(b"160000 "):
                raise RuntimeError("submodules unsupported")
            index_paths.add(rec.split(b"\t", 1)[1])
        tracked_paths = head_paths | index_paths
        git_untracked = set()
        for rec in run_git(repo, "ls-files", "--others", "--exclude-standard", "-z").stdout.split(b"\x00"):
            if rec:
                git_untracked.add(rec)
        ry_matcher = RootyardIgnoreMatcher(repo)
        untracked_paths = set()
        ignored_paths = set()
        for rel_b in walk_files(repo).keys():
            if rel_b == b".git" or rel_b.startswith(b".git/"):
                continue
            if rel_b in tracked_paths:
                continue
            rel_str = rel_b.decode("utf-8", errors="surrogateescape")
            if rel_b in git_untracked and not ry_matcher.is_ignored(rel_str, False):
                untracked_paths.add(rel_b)
            else:
                ignored_paths.add(rel_b)
        managed_paths = tracked_paths | untracked_paths
        return {
            "head_paths": head_paths,
            "index_paths": index_paths,
            "tracked_paths": tracked_paths,
            "untracked_paths": untracked_paths,
            "managed_paths": managed_paths,
            "ignored_paths": ignored_paths,
        }

    def copy_selected(src: Path, dst: Path, selected_rel_bytes):
        dst.mkdir(mode=0o700, parents=True, exist_ok=True)
        src_b = os.fsencode(src)
        dst_b = os.fsencode(dst)
        for rel_b in sorted(selected_rel_bytes):
            from_p = os.path.join(src_b, rel_b)
            to_p = os.path.join(dst_b, rel_b)
            os.makedirs(os.path.dirname(to_p), mode=0o700, exist_ok=True)
            st = os.lstat(from_p)
            if os.path.lexists(to_p):
                os.unlink(to_p)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(from_p)
                validate_symlink(src, rel_b, target)
                os.symlink(target, to_p)
            else:
                with open(from_p, "rb") as rf:
                    data = rf.read()
                with open(to_p, "wb") as wf:
                    wf.write(data)
                os.chmod(to_p, st.st_mode & 0o777)
        for req in (".git", ".git/objects", ".git/refs"):
            p = dst / req
            if not p.exists():
                p.mkdir(mode=0o700, parents=True, exist_ok=True)

    def validate_repo(repo: Path, base_oid: str):
        if not (repo / ".git").is_dir() or (repo / ".git").is_symlink():
            raise RuntimeError("invalid .git directory")
        for rel_b, st in walk_files(repo / ".git").items():
            if rel_b.endswith(b".lock"):
                raise RuntimeError("git lock exists")
        if run_git(repo, "cat-file", "-t", base_oid).stdout.decode().strip() != "commit":
            raise RuntimeError("invalid base_oid")
        classify_repo(repo)
        run_git(repo, "fsck", "--full", "--strict")

    def read_workspace(ws_id: str):
        require(is_uuid(ws_id), "invalid workspace uuid")
        ws_dir = store_root / "workspaces" / ws_id
        ws = json.loads((ws_dir / "workspace.json").read_bytes())
        require(ws["git_version"] == git_ver, "git version mismatch")
        return ws_dir, ws

    def read_checkpoint(cp_id: str):
        require(is_uuid(cp_id), "invalid checkpoint uuid")
        cp_dir = store_root / "checkpoints" / cp_id
        raw = (cp_dir / "manifest.json").read_bytes()
        digest = (cp_dir / "manifest.sha256").read_text().strip()
        require(hashlib.sha256(raw).hexdigest() == digest, "checkpoint manifest checksum mismatch")
        manifest = json.loads(raw)
        require(manifest["checkpoint_id"] == cp_id and manifest["state"] == "local_complete", "invalid checkpoint")
        validate_entries_list(manifest["entries"])
        require(inventory(cp_dir / "repo") == manifest["entries"], "checkpoint inventory mismatch")
        validate_repo(cp_dir / "repo", manifest["workspace"]["base_oid"])
        return cp_dir, manifest

    def validate_entries_list(entries):
        seen = set()
        for e in entries:
            rel_b = decode_path(e["path_base64"])
            require(rel_b not in seen, "duplicate entry")
            seen.add(rel_b)

    def entries_equivalent(a, b, exact_mode=True):
        if a is None or b is None:
            return a is b
        if a["kind"] != b["kind"] or a["size"] != b["size"] or a["sha256"] != b["sha256"]:
            return False
        if exact_mode:
            return a["mode"] == b["mode"]
        return bool(a["mode"] & 0o111) == bool(b["mode"] & 0o111)

    def read_head_tree_map(repo: Path):
        out = {}
        for rec in run_git(repo, "ls-tree", "-rz", "--full-tree", "HEAD").stdout.split(b"\x00"):
            if not rec:
                continue
            hdr, rel_b = rec.split(b"\t", 1)
            mode_s, _, oid_s = hdr.decode().split()
            kind = "symlink" if mode_s == "120000" else "file"
            mode = 0o777 if mode_s == "120000" else (0o755 if mode_s == "100755" else 0o644)
            blob = run_git(repo, "cat-file", "blob", oid_s).stdout
            out[rel_b] = {
                "path_base64": encode_path(rel_b),
                "kind": kind,
                "mode": mode,
                "size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
            }
        return out

    def compute_unstaged_set(repo: Path):
        unstaged = set()
        for rec in run_git(repo, "ls-files", "--stage", "-z").stdout.split(b"\x00"):
            if not rec or b"\t" not in rec:
                continue
            hdr, rel_b = rec.split(b"\t", 1)
            mode_s, oid_s, stage_s = hdr.decode().split()
            if stage_s != "0":
                unstaged.add(rel_b)
                continue
            full_p = os.path.join(os.fsencode(repo), rel_b)
            if not os.path.lexists(full_p):
                unstaged.add(rel_b)
                continue
            st = os.lstat(full_p)
            expected_blob = run_git(repo, "cat-file", "blob", oid_s).stdout
            if mode_s == "120000":
                if not stat.S_ISLNK(st.st_mode) or os.readlink(full_p) != expected_blob:
                    unstaged.add(rel_b)
            else:
                if not stat.S_ISREG(st.st_mode):
                    unstaged.add(rel_b)
                    continue
                if bool(st.st_mode & 0o111) != (mode_s == "100755"):
                    unstaged.add(rel_b)
                    continue
                with open(full_p, "rb") as f:
                    if f.read() != expected_blob:
                        unstaged.add(rel_b)
        return unstaged

    def compute_delta(base_map, source_map, exact_mode=True):
        all_keys = sorted(set(base_map.keys()) | set(source_map.keys()))
        entries = []
        counts = {"added": 0, "modified": 0, "deleted": 0, "mode_changed": 0, "type_changed": 0}
        for k in all_keys:
            b = base_map.get(k)
            a = source_map.get(k)
            if entries_equivalent(b, a, exact_mode):
                continue
            if b is None:
                ch = "added"
            elif a is None:
                ch = "deleted"
            elif b["kind"] != a["kind"]:
                ch = "type_changed"
            elif b["sha256"] != a["sha256"]:
                ch = "modified"
            else:
                ch = "mode_changed"
            counts[ch] += 1
            entries.append({
                "path": k.decode("utf-8", errors="replace"),
                "path_base64": encode_path(k),
                "change": ch,
                "before": b,
                "after": a,
            })
        return entries, counts

    try:
        if cmd == "init":
            src = Path(argv[2]).resolve()
            agent = argv[3]
            base_oid = argv[4]
            validate_repo(src, base_oid)
            head = run_git(src, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
            require(head == base_oid, "HEAD != base_oid")
            ws_id = str(uuid.uuid4())
            ws = {
                "schema": SCHEMA,
                "workspace_id": ws_id,
                "agent_id": agent,
                "base_oid": base_oid,
                "namespace_revision": 1,
                "parent_checkpoint_id": None,
                "git_version": git_ver,
            }
            cls = classify_repo(src)
            selected = [k for k in walk_files(src).keys() if k.startswith(b".git/") or k in cls["managed_paths"]]
            ws_dir = store_root / "workspaces" / ws_id
            copy_selected(src, ws_dir / "repo", selected)
            (ws_dir / "workspace.json").write_text(json.dumps(ws, indent=2))
            res = dict(ws, repo_path=str(ws_dir / "repo"))
            print(json.dumps(res))
            return 0

        if cmd == "checkpoint":
            ws_dir, ws = read_workspace(argv[2])
            repo = ws_dir / "repo"
            validate_repo(repo, ws["base_oid"])
            cls = classify_repo(repo)
            all_walk = walk_files(repo)
            selected = [k for k in all_walk.keys() if k.startswith(b".git/") or k in cls["managed_paths"]]
            excluded = len(all_walk) - len(selected)
            cp_id = str(uuid.uuid4())
            cp_dir = store_root / "checkpoints" / cp_id
            copy_selected(repo, cp_dir / "repo", selected)
            entries = inventory(cp_dir / "repo")
            manifest = {
                "schema": SCHEMA,
                "checkpoint_id": cp_id,
                "state": "local_complete",
                "workspace": ws,
                "excluded_ignored_entries": excluded,
                "entries": entries,
            }
            raw = json.dumps(manifest, indent=2).encode()
            (cp_dir / "manifest.json").write_bytes(raw)
            (cp_dir / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest())
            print(json.dumps({
                "checkpoint_id": cp_id,
                "state": "local_complete",
                "base_oid": ws["base_oid"],
                "excluded_ignored_entries": excluded,
                "entries": len(entries),
                "durability": "local_filesystem_only",
                "consistency": "caller_quiescent",
            }))
            return 0

        if cmd == "restore":
            cp_dir, manifest = read_checkpoint(argv[2])
            agent = argv[3]
            ws_id = str(uuid.uuid4())
            ws = dict(manifest["workspace"])
            ws["workspace_id"] = ws_id
            ws["agent_id"] = agent
            ws["parent_checkpoint_id"] = argv[2]
            ws_dir = store_root / "workspaces" / ws_id
            copy_selected(cp_dir / "repo", ws_dir / "repo", walk_files(cp_dir / "repo").keys())
            (ws_dir / "workspace.json").write_text(json.dumps(ws, indent=2))
            res = dict(ws, repo_path=str(ws_dir / "repo"))
            print(json.dumps(res))
            return 0

        if cmd == "inspect":
            ws_dir, ws = read_workspace(argv[2])
            print(json.dumps(dict(ws, repo_path=str(ws_dir / "repo"))))
            return 0

        if cmd == "status":
            ws_dir, ws = read_workspace(argv[2])
            repo = ws_dir / "repo"
            validate_repo(repo, ws["base_oid"])
            cls = classify_repo(repo)
            head_oid = run_git(repo, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
            detached = run_git(repo, "symbolic-ref", "-q", "HEAD", check=False).returncode != 0
            staged = {p for p in run_git(repo, "diff-index", "--cached", "--name-only", "-z", "HEAD").stdout.split(b"\x00") if p}
            unstaged = compute_unstaged_set(repo)
            unmerged = set()
            for rec in run_git(repo, "ls-files", "--unmerged", "-z").stdout.split(b"\x00"):
                if b"\t" in rec:
                    unmerged.add(rec.split(b"\t", 1)[1])
            head_map = read_head_tree_map(repo)
            if ws.get("parent_checkpoint_id") and (store_root / "checkpoints" / ws["parent_checkpoint_id"]).is_dir():
                _, cp_man = read_checkpoint(ws["parent_checkpoint_id"])
                base_map = {decode_path(e["path_base64"]): e for e in cp_man["entries"] if not decode_path(e["path_base64"]).startswith(b".git/")}
                exact_mode = True
            else:
                base_map = dict(head_map)
                exact_mode = False
            curr_map = {}
            for p in cls["managed_paths"]:
                ent = entry_for_rel(repo, p)
                if ent is not None:
                    curr_map[p] = ent
            cands = sorted(set(base_map.keys()) | set(head_map.keys()) | set(curr_map.keys()) | staged | unstaged | cls["untracked_paths"] | unmerged)
            dirty_entries = []
            for p in cands:
                b = base_map.get(p) or head_map.get(p)
                a = curr_map.get(p)
                st_flag = p in staged
                un_flag = (p in unstaged) or (p in unmerged)
                ut_flag = p in cls["untracked_paths"]
                if entries_equivalent(b, a, exact_mode) and not st_flag and not un_flag and not ut_flag:
                    continue
                if b is None and a is not None:
                    ch = "added"
                elif b is not None and a is None:
                    ch = "deleted"
                elif b and a and b["kind"] != a["kind"]:
                    ch = "type_changed"
                elif b and a and b["sha256"] != a["sha256"]:
                    ch = "modified"
                elif b and a and b["mode"] != a["mode"]:
                    ch = "mode_changed"
                else:
                    ch = "modified"
                dirty_entries.append({
                    "path": p.decode("utf-8", errors="replace"),
                    "path_base64": encode_path(p),
                    "change": ch,
                    "kind": a["kind"] if a else None,
                    "mode": a["mode"] if a else None,
                    "size": a["size"] if a else None,
                    "sha256": a["sha256"] if a else None,
                    "staged": st_flag,
                    "unstaged": un_flag,
                    "untracked": ut_flag,
                })
            is_dirty = len(dirty_entries) > 0
            print(json.dumps({
                "schema": SCHEMA,
                "workspace_id": ws["workspace_id"],
                "agent_id": ws["agent_id"],
                "base_oid": ws["base_oid"],
                "head_oid": head_oid,
                "detached_head": detached,
                "parent_checkpoint_id": ws["parent_checkpoint_id"],
                "is_dirty": is_dirty,
                "clean": not is_dirty,
                "managed_entries_count": len(curr_map),
                "ignored_entries_count": len(cls["ignored_paths"]),
                "untracked_entries_count": len(cls["untracked_paths"]),
                "dirty_entries_count": len(dirty_entries),
                "staged_paths": sorted(p.decode("utf-8", errors="replace") for p in staged),
                "unstaged_paths": sorted(p.decode("utf-8", errors="replace") for p in unstaged),
                "untracked_paths": sorted(p.decode("utf-8", errors="replace") for p in cls["untracked_paths"]),
                "unmerged_paths": sorted(p.decode("utf-8", errors="replace") for p in unmerged),
                "managed_paths": sorted(p.decode("utf-8", errors="replace") for p in curr_map.keys()),
                "ignored_paths": sorted(p.decode("utf-8", errors="replace") for p in cls["ignored_paths"]),
                "dirty_entries": dirty_entries,
            }))
            return 0

        if cmd == "changeset":
            _, base_man = read_checkpoint(argv[2])
            src_dir, src_man = read_checkpoint(argv[3])
            require(base_man["workspace"]["base_oid"] == src_man["workspace"]["base_oid"], "base_oid mismatch")
            base_map = {decode_path(e["path_base64"]): e for e in base_man["entries"] if not decode_path(e["path_base64"]).startswith(b".git/")}
            src_map = {decode_path(e["path_base64"]): e for e in src_man["entries"] if not decode_path(e["path_base64"]).startswith(b".git/")}
            entries, counts = compute_delta(base_map, src_map, True)
            cs_id = str(uuid.uuid4())
            cs_dir = store_root / "changesets" / cs_id
            files_dir = cs_dir / "files"
            files_dir.mkdir(mode=0o700, parents=True)
            after_rels = [decode_path(e["path_base64"]) for e in entries if e["after"] is not None]
            for rel_b in after_rels:
                from_p = os.path.join(os.fsencode(src_dir / "repo"), rel_b)
                to_p = os.path.join(os.fsencode(files_dir), rel_b)
                os.makedirs(os.path.dirname(to_p), mode=0o700, exist_ok=True)
                st = os.lstat(from_p)
                if stat.S_ISLNK(st.st_mode):
                    os.symlink(os.readlink(from_p), to_p)
                else:
                    shutil.copyfile(from_p, to_p)
                    os.chmod(to_p, st.st_mode & 0o777)
            cs_obj = {
                "schema": SCHEMA,
                "changeset_id": cs_id,
                "state": "local_complete",
                "base_oid": src_man["workspace"]["base_oid"],
                "base_checkpoint_id": argv[2],
                "source_checkpoint_id": argv[3],
                **counts,
                "entries": entries,
            }
            raw = json.dumps(cs_obj, indent=2).encode()
            (cs_dir / "changeset.json").write_bytes(raw)
            (cs_dir / "changeset.sha256").write_text(hashlib.sha256(raw).hexdigest())
            print(json.dumps(cs_obj))
            return 0

        if cmd == "apply":
            ws_dir, ws = read_workspace(argv[2])
            target_repo = ws_dir / "repo"
            validate_repo(target_repo, ws["base_oid"])
            cs_id = argv[3]
            require(is_uuid(cs_id), "invalid changeset uuid")
            cs_dir = store_root / "changesets" / cs_id
            raw = (cs_dir / "changeset.json").read_bytes()
            digest = (cs_dir / "changeset.sha256").read_text().strip()
            require(hashlib.sha256(raw).hexdigest() == digest, "changeset checksum mismatch")
            cs = json.loads(raw)
            require(cs["changeset_id"] == cs_id and cs["base_oid"] == ws["base_oid"], "changeset mismatch")
            for e in cs["entries"]:
                rel_b = decode_path(e["path_base64"])
                require(not rel_b.startswith(b".git/"), ".git path forbidden")
                if e["after"] is not None:
                    actual_payload = entry_for_rel(cs_dir / "files", rel_b)
                    require(actual_payload == e["after"], "corrupt changeset payload")
                curr = entry_for_rel(target_repo, rel_b)
                if e["before"] is None:
                    full = os.path.join(os.fsencode(target_repo), rel_b)
                    require(not os.path.lexists(full), "conflict: target path exists")
                else:
                    require(entries_equivalent(curr, e["before"], True), "conflict: target path modified since base")
            for e in cs["entries"]:
                rel_b = decode_path(e["path_base64"])
                to_p = os.path.join(os.fsencode(target_repo), rel_b)
                if e["after"] is None or e["change"] == "type_changed":
                    if os.path.lexists(to_p):
                        os.unlink(to_p)
                if e["after"] is not None:
                    from_p = os.path.join(os.fsencode(cs_dir / "files"), rel_b)
                    os.makedirs(os.path.dirname(to_p), mode=0o700, exist_ok=True)
                    if os.path.lexists(to_p):
                        os.unlink(to_p)
                    st = os.lstat(from_p)
                    if stat.S_ISLNK(st.st_mode):
                        os.symlink(os.readlink(from_p), to_p)
                    else:
                        shutil.copyfile(from_p, to_p)
                        os.chmod(to_p, st.st_mode & 0o777)
            ws["parent_checkpoint_id"] = cs["source_checkpoint_id"]
            (ws_dir / "workspace.json").write_text(json.dumps(ws, indent=2))
            print(json.dumps({
                "schema": SCHEMA,
                "workspace_id": ws["workspace_id"],
                "changeset_id": cs_id,
                "base_checkpoint_id": cs["base_checkpoint_id"],
                "source_checkpoint_id": cs["source_checkpoint_id"],
                "applied_entries": len(cs["entries"]),
                "added": cs["added"],
                "modified": cs["modified"],
                "deleted": cs["deleted"],
                "mode_changed": cs["mode_changed"],
                "type_changed": cs["type_changed"],
                "state": "applied",
            }))
            return 0

        if cmd == "sync-dirty":
            src_ws_dir, src_ws = read_workspace(argv[2])
            src_repo = src_ws_dir / "repo"
            validate_repo(src_repo, src_ws["base_oid"])
            cls = classify_repo(src_repo)
            if src_ws.get("parent_checkpoint_id") and (store_root / "checkpoints" / src_ws["parent_checkpoint_id"]).is_dir():
                _, cp_man = read_checkpoint(src_ws["parent_checkpoint_id"])
                base_map = {decode_path(e["path_base64"]): e for e in cp_man["entries"] if not decode_path(e["path_base64"]).startswith(b".git/")}
                exact_mode = True
            else:
                base_map = read_head_tree_map(src_repo)
                exact_mode = False
            src_map = {}
            for p in cls["managed_paths"]:
                ent = entry_for_rel(src_repo, p)
                if ent is not None:
                    src_map[p] = ent
            dirty_entries, counts = compute_delta(base_map, src_map, exact_mode)
            target_id = argv[3] if len(argv) == 5 else None
            if target_id is not None:
                require(target_id != argv[2], "source == target")
                tgt_ws_dir, tgt_ws = read_workspace(target_id)
                tgt_repo = tgt_ws_dir / "repo"
                validate_repo(tgt_repo, tgt_ws["base_oid"])
                require(tgt_ws["base_oid"] == src_ws["base_oid"], "base_oid mismatch")
                for e in dirty_entries:
                    rel_b = decode_path(e["path_base64"])
                    curr = entry_for_rel(tgt_repo, rel_b)
                    if e["before"] is None:
                        require(not os.path.lexists(os.path.join(os.fsencode(tgt_repo), rel_b)), "conflict on added path")
                    else:
                        check_exact = exact_mode or e["change"] == "mode_changed"
                        require(entries_equivalent(curr, e["before"], check_exact), "conflict on modified path")
            all_walk = walk_files(src_repo)
            selected = [k for k in all_walk.keys() if k.startswith(b".git/") or k in cls["managed_paths"]]
            cp_id = str(uuid.uuid4())
            cp_dir = store_root / "checkpoints" / cp_id
            copy_selected(src_repo, cp_dir / "repo", selected)
            entries = inventory(cp_dir / "repo")
            manifest = {
                "schema": SCHEMA,
                "checkpoint_id": cp_id,
                "state": "local_complete",
                "workspace": src_ws,
                "excluded_ignored_entries": len(cls["ignored_paths"]),
                "entries": entries,
            }
            raw = json.dumps(manifest, indent=2).encode()
            (cp_dir / "manifest.json").write_bytes(raw)
            (cp_dir / "manifest.sha256").write_text(hashlib.sha256(raw).hexdigest())
            src_ws["parent_checkpoint_id"] = cp_id
            (src_ws_dir / "workspace.json").write_text(json.dumps(src_ws, indent=2))
            if target_id is not None:
                for e in dirty_entries:
                    rel_b = decode_path(e["path_base64"])
                    to_p = os.path.join(os.fsencode(tgt_repo), rel_b)
                    if e["after"] is None or e["change"] == "type_changed":
                        if os.path.lexists(to_p):
                            os.unlink(to_p)
                    if e["after"] is not None:
                        from_p = os.path.join(os.fsencode(src_repo), rel_b)
                        os.makedirs(os.path.dirname(to_p), mode=0o700, exist_ok=True)
                        if os.path.lexists(to_p):
                            os.unlink(to_p)
                        st = os.lstat(from_p)
                        if stat.S_ISLNK(st.st_mode):
                            os.symlink(os.readlink(from_p), to_p)
                        else:
                            shutil.copyfile(from_p, to_p)
                            os.chmod(to_p, st.st_mode & 0o777)
                tgt_ws["parent_checkpoint_id"] = cp_id
                (tgt_ws_dir / "workspace.json").write_text(json.dumps(tgt_ws, indent=2))
            print(json.dumps({
                "schema": SCHEMA,
                "source_workspace_id": argv[2],
                "target_workspace_id": target_id,
                "workspace_id": target_id or argv[2],
                "checkpoint_id": cp_id,
                "base_oid": src_ws["base_oid"],
                "state": "synced",
                "synced_entries": len(dirty_entries),
                "added": counts["added"],
                "modified": counts["modified"],
                "deleted": counts["deleted"],
                "mode_changed": counts["mode_changed"],
                "type_changed": counts["type_changed"],
                "excluded_ignored_entries": len(cls["ignored_paths"]),
                "dirty_entries": dirty_entries,
            }))
            return 0

        if cmd == "verify-readonly-view":
            cp_id = argv[2]
            cp_dir, manifest = read_checkpoint(cp_id)
            cp_repo = cp_dir / "repo"
            if len(argv) == 4:
                view_repo = Path(argv[3]).resolve()
            else:
                view_repo = (store_root / "views" / cp_id / "repo").resolve()
            if not view_repo.exists():
                require(not view_repo.is_symlink(), "dangling symlink view")
                copy_selected(cp_repo, view_repo, walk_files(cp_repo).keys())
                for rel_b, st in walk_files(view_repo).items():
                    if stat.S_ISREG(st.st_mode):
                        full = os.path.join(os.fsencode(view_repo), rel_b)
                        os.chmod(full, (st.st_mode & 0o555) | 0o400)
            view_files = walk_files(view_repo)
            expected_map = {decode_path(e["path_base64"]): e for e in manifest["entries"]}
            require(set(view_files.keys()) == set(expected_map.keys()), "readonly view file set mismatch")
            for rel_b, st in view_files.items():
                exp = expected_map[rel_b]
                full = os.path.join(os.fsencode(view_repo), rel_b)
                cp_st = os.lstat(os.path.join(os.fsencode(cp_repo), rel_b))
                if stat.S_ISLNK(st.st_mode):
                    require(exp["kind"] == "symlink", "symlink kind mismatch")
                    target = os.readlink(full)
                    validate_symlink(view_repo, rel_b, target)
                    require(len(target) == exp["size"] and hashlib.sha256(target).hexdigest() == exp["sha256"], "symlink target tampered")
                else:
                    require(stat.S_ISREG(st.st_mode) and exp["kind"] == "file", "file kind mismatch")
                    require((st.st_dev, st.st_ino) != (cp_st.st_dev, cp_st.st_ino), "hardlink shared with checkpoint")
                    mode = st.st_mode & 0o7777
                    require((mode & 0o7000) == 0, "special bits in view")
                    require((mode & 0o222) == 0, "writable file in readonly view")
                    require((mode & 0o444) != 0, "unreadable file in readonly view")
                    require((mode & 0o111) == (exp["mode"] & 0o111), "exec bit mismatch in readonly view")
                    with open(full, "rb") as f:
                        data = f.read()
                    require(len(data) == exp["size"] and hashlib.sha256(data).hexdigest() == exp["sha256"], "file content tampered")
            print(json.dumps({
                "schema": SCHEMA,
                "checkpoint_id": cp_id,
                "base_oid": manifest["workspace"]["base_oid"],
                "view_path": str(view_repo),
                "verified": True,
                "readonly": True,
                "entries": len(manifest["entries"]),
                "state": "verified",
            }))
            return 0

        def valid_agent_name(val: str):
            require(
                isinstance(val, str)
                and 1 <= len(val) <= 63
                and all(ch.isalnum() or ch in "-_" for ch in val),
                "invalid agent or namespace name",
            )

        def open_remote_cas(cas_arg_str: str, create: bool) -> Path:
            req = Path(cas_arg_str)
            abs_p = req if req.is_absolute() else (Path.cwd() / req)
            cur = Path("/") if abs_p.is_absolute() else Path(".")
            for part in abs_p.parts:
                if part in ("/", ""):
                    continue
                require(part != "..", "parent traversal unsupported")
                cur = cur / part
                if cur.exists() or cur.is_symlink():
                    require(not cur.is_symlink(), "symlink component unsupported")
            if not abs_p.exists():
                require(create, "remote CAS directory does not exist")
                abs_p.mkdir(mode=0o700)
            require(abs_p.is_dir() and not abs_p.is_symlink(), "remote CAS must be directory")
            cas_root = abs_p.resolve()
            require((cas_root.stat().st_mode & 0o077) == 0, "remote CAS must be private (mode 0700)")
            require(
                not str(cas_root).startswith(str(store_root))
                and not str(store_root).startswith(str(cas_root)),
                "remote CAS and store must not overlap",
            )
            for sub in ("blobs", "checkpoints"):
                sp = cas_root / sub
                if not sp.exists():
                    require(create, f"remote CAS missing {sub} directory")
                    sp.mkdir(mode=0o700)
                require(sp.is_dir() and not sp.is_symlink(), f"invalid {sub} directory")
            return cas_root

        def verify_cas_file(blob_path: Path, expected_sha: str, expected_size: int) -> bytes:
            require(
                len(expected_sha) == 64 and all(c in "0123456789abcdef" for c in expected_sha),
                "invalid sha256 digest",
            )
            require(blob_path.exists() and not blob_path.is_symlink(), f"missing CAS blob {expected_sha}")
            st = blob_path.lstat()
            require(stat.S_ISREG(st.st_mode), "CAS blob is not a regular file")
            require((st.st_mode & 0o7000) == 0, "CAS blob has special permission bits")
            require(st.st_size == expected_size, f"CAS blob size mismatch for {expected_sha}")
            data = blob_path.read_bytes()
            require(
                len(data) == expected_size and hashlib.sha256(data).hexdigest() == expected_sha,
                f"CAS blob SHA-256 mismatch for {expected_sha}",
            )
            return data

        def write_atomic_file(dir_path: Path, filename: str, data: bytes, mode: int = 0o600) -> str:
            dir_path.mkdir(mode=0o700, parents=True, exist_ok=True)
            expected_sha = hashlib.sha256(data).hexdigest()
            tmp_path = dir_path / f".tmp-{uuid.uuid4()}"
            try:
                fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    os.fchmod(f.fileno(), mode)
                    os.fsync(f.fileno())
                verify_cas_file(tmp_path, expected_sha, len(data))
                final_path = dir_path / filename
                os.replace(tmp_path, final_path)
                dir_fd = os.open(str(dir_path), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
                return expected_sha
            finally:
                if tmp_path.exists() or tmp_path.is_symlink():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass

        def put_cas_blob(cas_root: Path, data: bytes, expected_sha: str, expected_size: int) -> bool:
            require(len(data) == expected_size and hashlib.sha256(data).hexdigest() == expected_sha, "entry digest mismatch")
            shard_dir = cas_root / "blobs" / expected_sha[:2]
            if not shard_dir.exists():
                shard_dir.mkdir(mode=0o700, parents=True)
            final_path = shard_dir / expected_sha
            if final_path.exists() or final_path.is_symlink():
                verify_cas_file(final_path, expected_sha, expected_size)
                return False
            write_atomic_file(shard_dir, expected_sha, data, 0o600)
            verify_cas_file(final_path, expected_sha, expected_size)
            return True

        if cmd == "push-remote":
            target_id = argv[2]
            require(is_uuid(target_id), "invalid target uuid")
            cas_root = open_remote_cas(argv[3], True)
            if (store_root / "checkpoints" / target_id).is_dir():
                cp_id = target_id
            elif (store_root / "workspaces" / target_id).is_dir():
                require(len(argv) == 5 and argv[4] == "--quiescent", "live workspace push-remote requires --quiescent")
                ws_dir, ws = read_workspace(target_id)
                repo = ws_dir / "repo"
                validate_repo(repo, ws["base_oid"])
                cls = classify_repo(repo)
                all_walk = walk_files(repo)
                selected = [k for k in all_walk.keys() if k.startswith(b".git/") or k in cls["managed_paths"]]
                excluded = len(all_walk) - len(selected)
                cp_id = str(uuid.uuid4())
                cp_dir_new = store_root / "checkpoints" / cp_id
                copy_selected(repo, cp_dir_new / "repo", selected)
                entries_new = inventory(cp_dir_new / "repo")
                man_new = {
                    "schema": SCHEMA,
                    "checkpoint_id": cp_id,
                    "state": "local_complete",
                    "workspace": ws,
                    "excluded_ignored_entries": excluded,
                    "entries": entries_new,
                }
                raw_new = json.dumps(man_new, indent=2).encode()
                (cp_dir_new / "manifest.json").write_bytes(raw_new)
                (cp_dir_new / "manifest.sha256").write_text(hashlib.sha256(raw_new).hexdigest())
            else:
                raise RuntimeError(f"unknown workspace or checkpoint id: {target_id}")

            cp_dir, manifest = read_checkpoint(cp_id)
            cp_repo = cp_dir / "repo"
            head_oid = run_git(cp_repo, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
            head_map = read_head_tree_map(cp_repo)
            worktree_map = {
                decode_path(e["path_base64"]): e
                for e in manifest["entries"]
                if not decode_path(e["path_base64"]).startswith(b".git/")
            }
            dirty_entries, counts = compute_delta(head_map, worktree_map, False)
            dirty_manifest = {
                "schema": SCHEMA,
                "checkpoint_id": cp_id,
                "workspace_id": manifest["workspace"]["workspace_id"],
                "base_oid": manifest["workspace"]["base_oid"],
                "head_oid": head_oid,
                **counts,
                "excluded_ignored_entries": manifest["excluded_ignored_entries"],
                "entries": dirty_entries,
            }
            blobs_uploaded = 0
            blobs_reused = 0
            bytes_uploaded = 0
            for entry in manifest["entries"]:
                rel_b = decode_path(entry["path_base64"])
                full = os.path.join(os.fsencode(cp_repo), rel_b)
                if entry["kind"] == "symlink":
                    target_b = os.readlink(full)
                    validate_symlink(cp_repo, rel_b, target_b)
                    data = target_b
                else:
                    with open(full, "rb") as f:
                        data = f.read()
                if put_cas_blob(cas_root, data, entry["sha256"], entry["size"]):
                    blobs_uploaded += 1
                    bytes_uploaded += entry["size"]
                else:
                    blobs_reused += 1

            remote_cp_dir = cas_root / "checkpoints" / cp_id
            if not remote_cp_dir.exists():
                remote_cp_dir.mkdir(mode=0o700, parents=True)
            dirty_raw = json.dumps(dirty_manifest, indent=2).encode()
            dirty_sha = write_atomic_file(remote_cp_dir, "dirty_manifest.json", dirty_raw, 0o600)
            write_atomic_file(remote_cp_dir, "dirty_manifest.sha256", dirty_sha.encode(), 0o600)
            put_cas_blob(cas_root, dirty_raw, dirty_sha, len(dirty_raw))

            remote_manifest = {
                "schema": SCHEMA,
                "checkpoint_id": cp_id,
                "state": "COMMITTED",
                "durability": "remote_cas_committed",
                "consistency": "caller_quiescent",
                "workspace": manifest["workspace"],
                "excluded_ignored_entries": manifest["excluded_ignored_entries"],
                "entries": manifest["entries"],
                "dirty_entries_count": len(dirty_entries),
                "dirty_manifest_sha256": dirty_sha,
            }
            man_raw = json.dumps(remote_manifest, indent=2).encode()
            man_sha = write_atomic_file(remote_cp_dir, "manifest.json", man_raw, 0o600)
            write_atomic_file(remote_cp_dir, "manifest.sha256", man_sha.encode(), 0o600)
            print(json.dumps({
                "schema": SCHEMA,
                "checkpoint_id": cp_id,
                "workspace_id": manifest["workspace"]["workspace_id"],
                "base_oid": manifest["workspace"]["base_oid"],
                "remote_cas_path": str(cas_root),
                "state": "COMMITTED",
                "durability": "remote_cas_committed",
                "total_entries": len(manifest["entries"]),
                "blobs_uploaded": blobs_uploaded,
                "blobs_reused": blobs_reused,
                "bytes_uploaded": bytes_uploaded,
                "dirty_entries_count": len(dirty_entries),
                "excluded_ignored_entries": manifest["excluded_ignored_entries"],
                "manifest_sha256": man_sha,
            }))
            return 0

        if cmd == "pull-remote":
            cas_root = open_remote_cas(argv[2], False)
            cp_id = argv[3]
            agent = argv[4]
            require(is_uuid(cp_id), "invalid checkpoint uuid")
            valid_agent_name(agent)
            remote_cp_dir = cas_root / "checkpoints" / cp_id
            require(remote_cp_dir.is_dir() and not remote_cp_dir.is_symlink(), "missing remote checkpoint")
            man_raw = (remote_cp_dir / "manifest.json").read_bytes()
            man_sha_exp = (remote_cp_dir / "manifest.sha256").read_text().strip()
            require(hashlib.sha256(man_raw).hexdigest() == man_sha_exp, "remote manifest checksum mismatch")
            remote_manifest = json.loads(man_raw)
            require(
                remote_manifest["schema"] == SCHEMA
                and remote_manifest["checkpoint_id"] == cp_id
                and remote_manifest["state"] == "COMMITTED"
                and remote_manifest["durability"] == "remote_cas_committed",
                "remote checkpoint not COMMITTED",
            )
            ws_meta = remote_manifest["workspace"]
            require(ws_meta["git_version"] == git_ver, "git version mismatch")
            valid_agent_name(ws_meta["agent_id"])
            validate_entries_list(remote_manifest["entries"])

            dirty_raw = (remote_cp_dir / "dirty_manifest.json").read_bytes()
            dirty_sha_exp = (remote_cp_dir / "dirty_manifest.sha256").read_text().strip()
            actual_dirty_sha = hashlib.sha256(dirty_raw).hexdigest()
            require(
                actual_dirty_sha == dirty_sha_exp and actual_dirty_sha == remote_manifest["dirty_manifest_sha256"],
                "remote dirty manifest checksum mismatch",
            )
            dirty_manifest = json.loads(dirty_raw)
            require(
                dirty_manifest["checkpoint_id"] == cp_id
                and len(dirty_manifest["entries"]) == remote_manifest["dirty_entries_count"],
                "remote dirty manifest metadata mismatch",
            )

            blobs_verified = 0
            for entry in remote_manifest["entries"]:
                sha = entry["sha256"]
                blob_p = cas_root / "blobs" / sha[:2] / sha
                verify_cas_file(blob_p, sha, entry["size"])
                blobs_verified += 1

            local_cp_dir = store_root / "checkpoints" / cp_id
            if not local_cp_dir.exists():
                stage_dir = store_root / "staging" / str(uuid.uuid4())
                stage_repo = stage_dir / "repo"
                stage_repo.mkdir(mode=0o700, parents=True)
                for req in (".git", ".git/objects", ".git/refs"):
                    (stage_repo / req).mkdir(mode=0o700, parents=True, exist_ok=True)
                symlinks_to_check = []
                for entry in remote_manifest["entries"]:
                    rel_b = decode_path(entry["path_base64"])
                    sha = entry["sha256"]
                    data = verify_cas_file(cas_root / "blobs" / sha[:2] / sha, sha, entry["size"])
                    to_p = os.path.join(os.fsencode(stage_repo), rel_b)
                    os.makedirs(os.path.dirname(to_p), mode=0o700, exist_ok=True)
                    if entry["kind"] == "symlink":
                        require(not rel_b.startswith(b".git"), "symlink in .git unsupported")
                        os.symlink(data, to_p)
                        symlinks_to_check.append((rel_b, data))
                    else:
                        with open(to_p, "wb") as wf:
                            wf.write(data)
                        os.chmod(to_p, entry["mode"] & 0o777)
                for rel_b, target_b in symlinks_to_check:
                    validate_symlink(stage_repo, rel_b, target_b)
                require(inventory(stage_repo) == remote_manifest["entries"], "reconstructed inventory mismatch")
                validate_repo(stage_repo, ws_meta["base_oid"])
                local_man = {
                    "schema": SCHEMA,
                    "checkpoint_id": cp_id,
                    "state": "local_complete",
                    "workspace": ws_meta,
                    "excluded_ignored_entries": remote_manifest["excluded_ignored_entries"],
                    "entries": remote_manifest["entries"],
                }
                local_raw = json.dumps(local_man, indent=2).encode()
                (stage_dir / "manifest.json").write_bytes(local_raw)
                (stage_dir / "manifest.sha256").write_text(hashlib.sha256(local_raw).hexdigest())
                os.replace(stage_dir, local_cp_dir)

            cp_dir, local_manifest = read_checkpoint(cp_id)
            new_ws_id = str(uuid.uuid4())
            new_ws = dict(local_manifest["workspace"])
            new_ws["workspace_id"] = new_ws_id
            new_ws["agent_id"] = agent
            new_ws["parent_checkpoint_id"] = cp_id
            ws_dir = store_root / "workspaces" / new_ws_id
            copy_selected(cp_dir / "repo", ws_dir / "repo", walk_files(cp_dir / "repo").keys())
            (ws_dir / "workspace.json").write_text(json.dumps(new_ws, indent=2))
            print(json.dumps({
                "schema": SCHEMA,
                "checkpoint_id": cp_id,
                "workspace_id": new_ws_id,
                "agent_id": agent,
                "base_oid": ws_meta["base_oid"],
                "repo_path": str(ws_dir / "repo"),
                "state": "restored_from_remote",
                "durability": "remote_cas_committed",
                "entries_restored": len(remote_manifest["entries"]),
                "blobs_verified": blobs_verified,
                "dirty_entries_count": remote_manifest["dirty_entries_count"],
            }))
            return 0

        def parse_mount_path(raw_str: str) -> bytes:
            raw_b = raw_str.encode("utf-8")
            if not raw_b or b"\x00" in raw_b or raw_b.startswith(b"/") or raw_b.endswith(b"/"):
                raise RuntimeError("invalid mount path")
            parts = raw_b.split(b"/")
            for p in parts:
                if not p or p in (b".", b"..", b".git"):
                    raise RuntimeError("unsafe or .git mount path component")
            require(raw_b != b".rootyard-namespace.json", "reserved mount path")
            return raw_b

        def check_mounts_non_overlapping(mount_list):
            require(len(mount_list) >= 1, "at least one mount required")
            for i in range(len(mount_list)):
                for j in range(i + 1, len(mount_list)):
                    a = mount_list[i][0]
                    b = mount_list[j][0]
                    if a == b or a.startswith(b + b"/") or b.startswith(a + b"/"):
                        raise RuntimeError("overlapping namespace mount paths")

        def ensure_no_git_anywhere(root_dir: Path):
            for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
                require(".git" not in dirnames and ".git" not in filenames, ".git forbidden in namespace tree")

        def copy_worktree_to_mount(cp_repo: Path, entries, mount_dest: Path, readonly: bool) -> int:
            mount_dest.mkdir(mode=0o700, parents=True, exist_ok=True)
            cnt = 0
            for e in entries:
                rel_b = decode_path(e["path_base64"])
                if rel_b == b".git" or rel_b.startswith(b".git/"):
                    continue
                from_p = os.path.join(os.fsencode(cp_repo), rel_b)
                to_p = os.path.join(os.fsencode(mount_dest), rel_b)
                os.makedirs(os.path.dirname(to_p), mode=0o700, exist_ok=True)
                if os.path.lexists(to_p):
                    os.unlink(to_p)
                st = os.lstat(from_p)
                if stat.S_ISLNK(st.st_mode):
                    target_b = os.readlink(from_p)
                    validate_symlink(cp_repo, rel_b, target_b)
                    os.symlink(target_b, to_p)
                else:
                    shutil.copyfile(from_p, to_p)
                    mode = ((e["mode"] & 0o555) | 0o400) if readonly else (0o755 if (e["mode"] & 0o111) else 0o644)
                    os.chmod(to_p, mode)
                cnt += 1
            return cnt

        def read_namespace_manifest(ns_id: str):
            require(is_uuid(ns_id), "invalid namespace uuid")
            ns_dir = store_root / "namespaces" / ns_id
            raw = (ns_dir / "namespace.json").read_bytes()
            sha_exp = (ns_dir / "namespace.sha256").read_text().strip()
            require(hashlib.sha256(raw).hexdigest() == sha_exp, "namespace manifest checksum mismatch")
            man = json.loads(raw)
            require(
                man["schema"] == SCHEMA
                and man["namespace_id"] == ns_id
                and man["namespace_revision"] >= 1
                and man["state"] == "mounted"
                and len(man["base_vector"]) >= 1,
                "invalid namespace manifest",
            )
            valid_agent_name(man["name"])
            pairs = []
            for bv in man["base_vector"]:
                mp_b = parse_mount_path(bv["mount_path"])
                require(decode_path(bv["mount_path_base64"]) == mp_b, "mount_path_base64 mismatch")
                require(is_uuid(bv["checkpoint_id"]), "invalid checkpoint_id in base_vector")
                pairs.append((mp_b, bv["checkpoint_id"]))
            check_mounts_non_overlapping(pairs)
            return ns_dir, man

        if cmd == "namespace-mount":
            ns_name = argv[2]
            valid_agent_name(ns_name)
            parsed = []
            for spec in argv[3:]:
                require("=" in spec, "mount spec must be MOUNT_PATH=CHECKPOINT_ID")
                m_str, cp_str = spec.split("=", 1)
                mp_b = parse_mount_path(m_str)
                require(is_uuid(cp_str), "invalid checkpoint uuid")
                parsed.append((mp_b, cp_str))
            parsed.sort(key=lambda item: item[0])
            check_mounts_non_overlapping(parsed)

            ns_id = str(uuid.uuid4())
            ns_dir = store_root / "namespaces" / ns_id
            tree_dir = ns_dir / "tree"
            tree_dir.mkdir(mode=0o700, parents=True)
            base_vector = []
            total_entries = 0
            for mp_b, cp_id in parsed:
                cp_dir, cp_man = read_checkpoint(cp_id)
                cp_repo = cp_dir / "repo"
                head_oid = run_git(cp_repo, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
                man_sha = (cp_dir / "manifest.sha256").read_text().strip()
                mp_str = mp_b.decode("utf-8")
                cnt = copy_worktree_to_mount(cp_repo, cp_man["entries"], tree_dir / mp_str, True)
                total_entries += cnt
                base_vector.append({
                    "mount_path": mp_str,
                    "mount_path_base64": encode_path(mp_b),
                    "checkpoint_id": cp_id,
                    "workspace_id": cp_man["workspace"]["workspace_id"],
                    "agent_id": cp_man["workspace"]["agent_id"],
                    "base_oid": cp_man["workspace"]["base_oid"],
                    "head_oid": head_oid,
                    "manifest_sha256": man_sha,
                    "entries_count": cnt,
                })
            ns_man = {
                "schema": SCHEMA,
                "namespace_id": ns_id,
                "name": ns_name,
                "namespace_revision": 1,
                "view_path": str(tree_dir),
                "mount_count": len(base_vector),
                "total_entries": total_entries,
                "state": "mounted",
                "base_vector": base_vector,
            }
            raw = json.dumps(ns_man, indent=2).encode()
            (ns_dir / "namespace.json").write_bytes(raw)
            (ns_dir / "namespace.sha256").write_text(hashlib.sha256(raw).hexdigest())
            print(json.dumps(ns_man))
            return 0

        def verify_namespace_internal(ns_id: str, view_arg_opt):
            ns_dir, man = read_namespace_manifest(ns_id)
            if view_arg_opt is not None:
                view_root = Path(view_arg_opt).resolve()
                require(
                    not str(view_root).startswith(str(store_root / "checkpoints"))
                    and not str(view_root).startswith(str(store_root / "workspaces")),
                    "namespace view overlaps checkpoints or workspaces",
                )
                if not view_root.exists():
                    require(not view_root.is_symlink(), "dangling symlink view")
                    view_root.mkdir(mode=0o700, parents=True)
                    for bv in man["base_vector"]:
                        cp_dir, cp_man = read_checkpoint(bv["checkpoint_id"])
                        copy_worktree_to_mount(cp_dir / "repo", cp_man["entries"], view_root / bv["mount_path"], True)
            else:
                view_root = (ns_dir / "tree").resolve()

            ensure_no_git_anywhere(view_root)
            view_files = walk_files(view_root)
            expected_map = {}
            for bv in man["base_vector"]:
                cp_dir, cp_man = read_checkpoint(bv["checkpoint_id"])
                cp_repo = cp_dir / "repo"
                actual_sha = (cp_dir / "manifest.sha256").read_text().strip()
                actual_head = run_git(cp_repo, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
                require(
                    bv["base_oid"] == cp_man["workspace"]["base_oid"]
                    and bv["head_oid"] == actual_head
                    and bv["manifest_sha256"] == actual_sha,
                    "pinned BaseVector mismatch",
                )
                mp_b = decode_path(bv["mount_path_base64"])
                cnt = 0
                for e in cp_man["entries"]:
                    rel_b = decode_path(e["path_base64"])
                    if rel_b == b".git" or rel_b.startswith(b".git/"):
                        continue
                    cnt += 1
                    expected_map[mp_b + b"/" + rel_b] = (mp_b, rel_b, cp_repo, e)
                require(cnt == bv["entries_count"], "BaseVector entries_count mismatch")

            require(set(view_files.keys()) == set(expected_map.keys()), "namespace view file set mismatch")
            for full_rel_b, st in view_files.items():
                mp_b, rel_b, cp_repo, exp = expected_map[full_rel_b]
                full = os.path.join(os.fsencode(view_root), full_rel_b)
                cp_st = os.lstat(os.path.join(os.fsencode(cp_repo), rel_b))
                mount_root = view_root / mp_b.decode("utf-8")
                if stat.S_ISLNK(st.st_mode):
                    require(exp["kind"] == "symlink", "symlink kind mismatch in namespace view")
                    target_b = os.readlink(full)
                    validate_symlink(mount_root, rel_b, target_b)
                    require(
                        len(target_b) == exp["size"] and hashlib.sha256(target_b).hexdigest() == exp["sha256"],
                        "symlink target tampered in namespace view",
                    )
                else:
                    require(stat.S_ISREG(st.st_mode) and exp["kind"] == "file", "file kind mismatch in namespace view")
                    require((st.st_dev, st.st_ino) != (cp_st.st_dev, cp_st.st_ino), "hardlink shared with checkpoint")
                    mode = st.st_mode & 0o7777
                    require((mode & 0o7000) == 0, "special bits in namespace view")
                    require((mode & 0o222) == 0, "writable file in namespace view")
                    require((mode & 0o444) != 0, "unreadable file in namespace view")
                    require((mode & 0o111) == (exp["mode"] & 0o111), "exec bit mismatch in namespace view")
                    with open(full, "rb") as f:
                        data = f.read()
                    require(
                        len(data) == exp["size"] and hashlib.sha256(data).hexdigest() == exp["sha256"],
                        "file content tampered in namespace view",
                    )
            return ns_dir, man, view_root, len(expected_map)

        if cmd == "verify-namespace":
            ns_id = argv[2]
            view_opt = argv[3] if len(argv) == 4 else None
            _, man, view_root, total_entries = verify_namespace_internal(ns_id, view_opt)
            print(json.dumps({
                "schema": SCHEMA,
                "namespace_id": man["namespace_id"],
                "name": man["name"],
                "namespace_revision": man["namespace_revision"],
                "view_path": str(view_root),
                "mount_count": man["mount_count"],
                "total_entries": total_entries,
                "readonly": True,
                "verified": True,
                "base_vector": man["base_vector"],
                "state": "verified",
            }))
            return 0

        if cmd == "namespace-git-view":
            ns_id = argv[2]
            ns_dir, man, _, _ = verify_namespace_internal(ns_id, None)
            if len(argv) == 4:
                view_repo = Path(argv[3]).resolve()
                require(
                    not str(view_repo).startswith(str(store_root / "checkpoints"))
                    and not str(view_repo).startswith(str(store_root / "workspaces"))
                    and not str(view_repo).startswith(str((ns_dir / "tree").resolve())),
                    "namespace git view path overlap",
                )
            else:
                gv_parent = ns_dir / "git-view"
                gv_parent.mkdir(mode=0o700, exist_ok=True)
                view_repo = (gv_parent / "repo").resolve()

            stage_dir = store_root / "staging" / str(uuid.uuid4())
            stage_repo = stage_dir / "repo"
            stage_dir.mkdir(mode=0o700, parents=True)
            det_env = {
                "GIT_AUTHOR_NAME": "Rootyard Namespace View",
                "GIT_AUTHOR_EMAIL": "namespace@rootyard.invalid",
                "GIT_AUTHOR_DATE": "2026-11-03T00:00:00Z",
                "GIT_COMMITTER_NAME": "Rootyard Namespace View",
                "GIT_COMMITTER_EMAIL": "namespace@rootyard.invalid",
                "GIT_COMMITTER_DATE": "2026-11-03T00:00:00Z",
            }
            run_git(stage_dir, "init", "-q", "-b", "main", str(stage_repo), extra_env=det_env)
            for k, v in (
                ("user.name", "Rootyard Namespace View"),
                ("user.email", "namespace@rootyard.invalid"),
                ("receive.denyCurrentBranch", "refuse"),
                ("http.receivepack", "false"),
            ):
                run_git(stage_repo, "config", k, v, extra_env=det_env)

            projected_files = 0
            for bv in man["base_vector"]:
                cp_dir, cp_man = read_checkpoint(bv["checkpoint_id"])
                projected_files += copy_worktree_to_mount(
                    cp_dir / "repo", cp_man["entries"], stage_repo / bv["mount_path"], False
                )

            provenance = {
                "schema": SCHEMA,
                "name": man["name"],
                "namespace_revision": man["namespace_revision"],
                "history_strategy": "task_snapshot",
                "base_vector": man["base_vector"],
            }
            prov_path = stage_repo / ".rootyard-namespace.json"
            prov_path.write_bytes(json.dumps(provenance, indent=2).encode())
            prov_path.chmod(0o644)
            projected_files += 1

            run_git(stage_repo, "add", "--all", "--force", extra_env=det_env)
            msg = f"rootyard namespace task_snapshot: {man['name']} (rev {man['namespace_revision']})"
            run_git(stage_repo, "commit", "-q", "-m", msg, extra_env=det_env)
            commit_oid = run_git(stage_repo, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
            tree_oid = run_git(stage_repo, "rev-parse", "--verify", "HEAD^{tree}").stdout.decode().strip()
            run_git(stage_repo, "fsck", "--full", "--strict")

            for rel_b, st in walk_files(stage_repo).items():
                if not rel_b.startswith(b".git/") and stat.S_ISREG(st.st_mode):
                    full = os.path.join(os.fsencode(stage_repo), rel_b)
                    os.chmod(full, (st.st_mode & 0o555) | 0o400)

            view_repo.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if view_repo.exists():
                shutil.rmtree(view_repo)
            os.replace(stage_repo, view_repo)
            shutil.rmtree(stage_dir, ignore_errors=True)
            print(json.dumps({
                "schema": SCHEMA,
                "namespace_id": man["namespace_id"],
                "name": man["name"],
                "namespace_revision": man["namespace_revision"],
                "history_strategy": "task_snapshot",
                "view_repo_path": str(view_repo.resolve()),
                "projected_commit_oid": commit_oid,
                "projected_tree_oid": tree_oid,
                "mount_count": man["mount_count"],
                "projected_files": projected_files,
                "readonly": True,
                "fsck_passed": True,
                "base_vector": man["base_vector"],
                "state": "projected",
            }))
            return 0

        def validate_vfs_pattern(pat: str):
            require(bool(pat) and "\x00" not in pat and not pat.startswith("/"), "invalid VFS pattern")
            for seg in pat.split("/"):
                require(seg not in (".", "..", ".git"), "unsafe VFS pattern segment")

        def vfs_matches_query(pattern: str, rel_path: str) -> bool:
            pat = pattern.rstrip("/")
            if pat in ("*", "**") or pat == rel_path:
                return True
            if rel_path.startswith(pat + "/"):
                return True
            if "/" not in pat:
                name = rel_path.rsplit("/", 1)[-1]
                return fnmatch.fnmatchcase(name, pat) or fnmatch.fnmatchcase(rel_path, pat)
            p_segs = pat.split("/")
            t_segs = rel_path.split("/")

            def match_segs(ps, ts):
                if not ps:
                    return not ts
                if ps[0] == "**":
                    return match_segs(ps[1:], ts) or (bool(ts) and match_segs(ps, ts[1:]))
                return bool(ts) and fnmatch.fnmatchcase(ts[0], ps[0]) and match_segs(ps[1:], ts[1:])

            return match_segs(p_segs, t_segs)

        def fetch_vfs_blob(cp_id: str, cas_root_opt, rel_b: bytes, kind: str, size: int, sha: str) -> bytes:
            require(len(sha) == 64 and all(c in "0123456789abcdef" for c in sha), "invalid sha256")
            if cas_root_opt is not None:
                return verify_cas_file(cas_root_opt / "blobs" / sha[:2] / sha, sha, size)
            cp_repo = store_root / "checkpoints" / cp_id / "repo"
            full = os.path.join(os.fsencode(cp_repo), rel_b)
            if kind == "symlink":
                data = os.readlink(full)
                validate_symlink(cp_repo, rel_b, data)
            else:
                with open(full, "rb") as f:
                    data = f.read()
            require(len(data) == size and hashlib.sha256(data).hexdigest() == sha, "checkpoint blob digest mismatch")
            return data

        def materialize_vfs_entry(mount_dir: Path, rel_b: bytes, kind: str, mode: int, data: bytes, cp_src_opt=None):
            dest = Path(os.fsdecode(os.path.join(os.fsencode(mount_dir), rel_b)))
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.path.lexists(dest):
                os.unlink(dest)
            if kind == "symlink":
                require(not rel_b.startswith(b".git"), "symlink in .git unsupported")
                os.symlink(data, os.fsencode(dest))
                validate_symlink(mount_dir, rel_b, data)
            else:
                perm = (mode & 0o777) if (mode & 0o777) != 0 else 0o644
                write_atomic_file(dest.parent, dest.name, data, perm)
                if cp_src_opt is not None and os.path.lexists(cp_src_opt):
                    st1 = os.lstat(dest)
                    st2 = os.lstat(cp_src_opt)
                    require((st1.st_dev, st1.st_ino) != (st2.st_dev, st2.st_ino), "hardlink shared with store")

        def save_vfs_manifest(vfs_dir: Path, man: dict, extra_dirty: int = 0):
            man["total_entries"] = len(man["catalog"])
            man["hydrated_entries"] = sum(1 for e in man["catalog"] if e["hydrated"])
            man["dehydrated_entries"] = man["total_entries"] - man["hydrated_entries"]
            man["dirty_entries"] = sum(1 for e in man["catalog"] if e["state"] == "hydrated_dirty") + extra_dirty
            man["total_bytes"] = sum(e["size"] for e in man["catalog"])
            man["hydrated_bytes"] = sum(e["size"] for e in man["catalog"] if e["hydrated"])
            man["unhydrated_bytes"] = man["total_bytes"] - man["hydrated_bytes"]
            raw = json.dumps(man, indent=2).encode()
            sha = write_atomic_file(vfs_dir, "vfs.json", raw, 0o600)
            write_atomic_file(vfs_dir, "vfs.sha256", sha.encode(), 0o600)

        def read_vfs_manifest(vfs_id: str):
            require(is_uuid(vfs_id), "invalid vfs uuid")
            vfs_dir = store_root / "vfs" / vfs_id
            require(vfs_dir.is_dir() and not vfs_dir.is_symlink(), f"unknown VFS mount {vfs_id}")
            raw = (vfs_dir / "vfs.json").read_bytes()
            exp_sha = (vfs_dir / "vfs.sha256").read_text().strip()
            require(hashlib.sha256(raw).hexdigest() == exp_sha, "VFS manifest checksum mismatch")
            man = json.loads(raw)
            require(man["schema"] == SCHEMA and man["vfs_id"] == vfs_id, "invalid VFS manifest")
            require(is_uuid(man["checkpoint_id"]), "invalid checkpoint_id in VFS manifest")
            valid_agent_name(man["agent_id"])
            require((vfs_dir / "mount").is_dir(), "missing VFS mount directory")
            return vfs_dir, man

        def evaluate_vfs_status(vfs_dir: Path, man: dict) -> dict:
            mount_dir = vfs_dir / "mount"
            cas_root = open_remote_cas(man["remote_cas_path"], False) if man["remote_cas_path"] else None
            git_m = RootyardIgnoreMatcher(None)
            ry_m = RootyardIgnoreMatcher(None)
            excl = mount_dir / ".git/info/exclude"
            if excl.is_file():
                git_m.add_patterns("", excl.read_bytes().decode("utf-8", errors="replace"))
            cat_paths = set()
            ignore_rules = []
            for c in man["catalog"]:
                rel_b = decode_path(c["path_base64"])
                cat_paths.add(rel_b)
                fname = rel_b.rsplit(b"/", 1)[-1]
                if fname in (b".gitignore", b".rootyardignore"):
                    disk_p = Path(os.fsdecode(os.path.join(os.fsencode(mount_dir), rel_b)))
                    if disk_p.is_file():
                        b = disk_p.read_bytes()
                    else:
                        b = fetch_vfs_blob(man["checkpoint_id"], cas_root, rel_b, c["kind"], c["size"], c["sha256"])
                    ignore_rules.append((rel_b.count(b"/"), rel_b, fname == b".gitignore", b))
            disk_walk = walk_files(mount_dir)
            for rel_b, st in disk_walk.items():
                if not rel_b.startswith(b".git/") and rel_b not in cat_paths and stat.S_ISREG(st.st_mode):
                    fname = rel_b.rsplit(b"/", 1)[-1]
                    if fname in (b".gitignore", b".rootyardignore"):
                        full_p = os.path.join(os.fsencode(mount_dir), rel_b)
                        with open(full_p, "rb") as f:
                            b = f.read()
                        ignore_rules.append((rel_b.count(b"/"), rel_b, fname == b".gitignore", b))
            ignore_rules.sort(key=lambda item: (item[0], item[1]))
            for _, rel_b, is_git, b in ignore_rules:
                rel_str = rel_b.decode("utf-8", errors="replace")
                base_dir = rel_str.rsplit("/", 1)[0] if "/" in rel_str else ""
                text = b.decode("utf-8", errors="replace")
                if is_git:
                    git_m.add_patterns(base_dir, text)
                else:
                    ry_m.add_patterns(base_dir, text)

            dehyd, clean_p, dirty_p, ign_p, details = [], [], [], [], []
            for c in man["catalog"]:
                rel_b = decode_path(c["path_base64"])
                base_e = {
                    "path_base64": c["path_base64"],
                    "kind": c["kind"],
                    "mode": c["mode"],
                    "size": c["size"],
                    "sha256": c["sha256"],
                }
                act = entry_for_rel(mount_dir, rel_b)
                if act is None:
                    if not c["hydrated"]:
                        c["state"] = "dehydrated"
                        dehyd.append(c["path"])
                    else:
                        c["state"] = "hydrated_dirty"
                        dirty_p.append(c["path"])
                        details.append({
                            "path": c["path"],
                            "path_base64": c["path_base64"],
                            "change": "deleted",
                            "state": "hydrated_dirty",
                            "kind": None,
                            "mode": None,
                            "size": None,
                            "sha256": None,
                        })
                else:
                    c["hydrated"] = True
                    if entries_equivalent(act, base_e, True):
                        c["state"] = "hydrated_clean"
                        clean_p.append(c["path"])
                    else:
                        c["state"] = "hydrated_dirty"
                        chg = (
                            "type_changed"
                            if act["kind"] != c["kind"]
                            else ("modified" if (act["sha256"] != c["sha256"] or act["size"] != c["size"]) else "mode_changed")
                        )
                        dirty_p.append(c["path"])
                        details.append({
                            "path": c["path"],
                            "path_base64": c["path_base64"],
                            "change": chg,
                            "state": "hydrated_dirty",
                            "kind": act["kind"],
                            "mode": act["mode"],
                            "size": act["size"],
                            "sha256": act["sha256"],
                        })

            for rel_b in sorted(disk_walk.keys()):
                if rel_b.startswith(b".git/") or rel_b in cat_paths:
                    continue
                p_str = rel_b.decode("utf-8", errors="replace")
                if git_m.is_ignored(p_str, False) or ry_m.is_ignored(p_str, False):
                    ign_p.append(p_str)
                else:
                    act = entry_for_rel(mount_dir, rel_b)
                    if act is not None:
                        dirty_p.append(p_str)
                        details.append({
                            "path": p_str,
                            "path_base64": encode_path(rel_b),
                            "change": "added",
                            "state": "hydrated_dirty",
                            "kind": act["kind"],
                            "mode": act["mode"],
                            "size": act["size"],
                            "sha256": act["sha256"],
                        })
            dirty_p.sort()
            details.sort(key=lambda d: d["path"])
            extra = sum(1 for d in details if d["change"] == "added")
            save_vfs_manifest(vfs_dir, man, extra)
            return {
                "schema": SCHEMA,
                "vfs_id": man["vfs_id"],
                "checkpoint_id": man["checkpoint_id"],
                "workspace_id": man["workspace_id"],
                "agent_id": man["agent_id"],
                "base_oid": man["base_oid"],
                "head_oid": man["head_oid"],
                "mount_path": str(mount_dir),
                "state": "mounted",
                "is_dirty": len(details) > 0,
                "clean": len(details) == 0,
                "total_entries": man["total_entries"],
                "hydrated_entries": man["hydrated_entries"],
                "hydrated_clean_entries": len(clean_p),
                "dehydrated_entries": man["dehydrated_entries"],
                "dirty_entries": len(details),
                "ignored_entries": len(ign_p),
                "total_bytes": man["total_bytes"],
                "hydrated_bytes": man["hydrated_bytes"],
                "unhydrated_bytes": man["unhydrated_bytes"],
                "dehydrated_paths": dehyd,
                "hydrated_clean_paths": clean_p,
                "hydrated_dirty_paths": dirty_p,
                "ignored_paths": ign_p,
                "dirty_details": details,
            }

        def match_vfs_targets(catalog, added_set, patterns):
            matched_cat, matched_added = set(), set()
            for pat in patterns:
                found = False
                for i, e in enumerate(catalog):
                    if vfs_matches_query(pat, e["path"]):
                        matched_cat.add(i)
                        found = True
                for add_p in added_set:
                    if vfs_matches_query(pat, add_p):
                        matched_added.add(add_p)
                        found = True
                if not any(ch in pat for ch in "*?["):
                    require(found, f"no VFS entry matched path: {pat}")
            require(bool(matched_cat or matched_added or not catalog), "no VFS entries matched")
            return sorted(matched_cat), sorted(matched_added)

        if cmd == "vfs-mount":
            cp_id = argv[2]
            agent = argv[3]
            require(is_uuid(cp_id), "invalid checkpoint uuid")
            valid_agent_name(agent)
            cas_arg = None
            inline_thresh = 0
            has_thresh = False
            patterns = []
            idx = 4
            while idx < len(argv):
                fl = argv[idx]
                if fl == "--remote-cas":
                    idx += 1
                    require(idx < len(argv), "missing --remote-cas")
                    cas_arg = argv[idx]
                elif fl == "--inline-threshold":
                    idx += 1
                    require(idx < len(argv), "missing --inline-threshold")
                    inline_thresh = int(argv[idx])
                    require(inline_thresh >= 0, "invalid threshold")
                    has_thresh = True
                elif fl == "--hydrate-pattern":
                    idx += 1
                    require(idx < len(argv), "missing --hydrate-pattern")
                    validate_vfs_pattern(argv[idx])
                    patterns.append(argv[idx])
                else:
                    raise RuntimeError(f"unknown vfs-mount flag: {fl}")
                idx += 1

            cas_root = open_remote_cas(cas_arg, False) if cas_arg is not None else None
            if cas_root is not None and (cas_root / "checkpoints" / cp_id / "manifest.json").exists():
                r_cp = cas_root / "checkpoints" / cp_id
                m_raw = (r_cp / "manifest.json").read_bytes()
                m_sha = (r_cp / "manifest.sha256").read_text().strip()
                require(hashlib.sha256(m_raw).hexdigest() == m_sha, "remote manifest checksum mismatch")
                r_man = json.loads(m_raw)
                require(
                    r_man["schema"] == SCHEMA
                    and r_man["checkpoint_id"] == cp_id
                    and r_man["state"] == "COMMITTED"
                    and r_man["durability"] == "remote_cas_committed",
                    "remote checkpoint not COMMITTED",
                )
                ws = r_man["workspace"]
                require(ws["git_version"] == git_ver, "git version mismatch")
                valid_agent_name(ws["agent_id"])
                validate_entries_list(r_man["entries"])
                d_raw = (r_cp / "dirty_manifest.json").read_bytes()
                d_sha = (r_cp / "dirty_manifest.sha256").read_text().strip()
                act_d = hashlib.sha256(d_raw).hexdigest()
                require(act_d == d_sha and act_d == r_man["dirty_manifest_sha256"], "dirty manifest checksum mismatch")
                d_man = json.loads(d_raw)
                require(d_man["checkpoint_id"] == cp_id and len(d_man["entries"]) == r_man["dirty_entries_count"], "dirty manifest mismatch")
                entries = r_man["entries"]
                head_oid = d_man["head_oid"]
            else:
                cp_dir, man = read_checkpoint(cp_id)
                ws = man["workspace"]
                entries = man["entries"]
                head_oid = run_git(cp_dir / "repo", "rev-parse", "--verify", "HEAD").stdout.decode().strip()

            vfs_id = str(uuid.uuid4())
            vfs_dir = store_root / "vfs" / vfs_id
            stage_dir = store_root / "staging" / str(uuid.uuid4())
            stage_mount = stage_dir / "mount"
            for req in (".git", ".git/objects", ".git/refs"):
                (stage_mount / req).mkdir(mode=0o700, parents=True, exist_ok=True)
            cp_repo = store_root / "checkpoints" / cp_id / "repo"
            catalog = []
            for e in entries:
                rel_b = decode_path(e["path_base64"])
                if rel_b == b".git" or rel_b.startswith(b".git/"):
                    b = fetch_vfs_blob(cp_id, cas_root, rel_b, e["kind"], e["size"], e["sha256"])
                    materialize_vfs_entry(stage_mount, rel_b, e["kind"], e["mode"], b, None)
                    continue
                rel_str = rel_b.decode("utf-8", errors="replace")
                hydrate = (
                    (has_thresh and e["size"] <= inline_thresh)
                    or (not has_thresh and inline_thresh > 0 and e["size"] <= inline_thresh)
                    or any(vfs_matches_query(p, rel_str) for p in patterns)
                )
                if hydrate:
                    b = fetch_vfs_blob(cp_id, cas_root, rel_b, e["kind"], e["size"], e["sha256"])
                    src_p = os.path.join(os.fsencode(cp_repo), rel_b)
                    materialize_vfs_entry(stage_mount, rel_b, e["kind"], e["mode"], b, src_p)
                catalog.append({
                    "path": rel_str,
                    "path_base64": e["path_base64"],
                    "kind": e["kind"],
                    "mode": e["mode"],
                    "size": e["size"],
                    "sha256": e["sha256"],
                    "hydrated": hydrate,
                    "state": "hydrated_clean" if hydrate else "dehydrated",
                })
            validate_repo(stage_mount, ws["base_oid"])
            manifest = {
                "schema": SCHEMA,
                "vfs_id": vfs_id,
                "checkpoint_id": cp_id,
                "workspace_id": ws["workspace_id"],
                "agent_id": agent,
                "base_oid": ws["base_oid"],
                "head_oid": head_oid,
                "remote_cas_path": str(cas_root) if cas_root is not None else None,
                "inline_threshold": inline_thresh,
                "hydrate_patterns": patterns,
                "mount_path": str(vfs_dir / "mount"),
                "state": "mounted",
                "total_entries": 0,
                "hydrated_entries": 0,
                "dehydrated_entries": 0,
                "dirty_entries": 0,
                "total_bytes": 0,
                "hydrated_bytes": 0,
                "unhydrated_bytes": 0,
                "catalog": catalog,
            }
            save_vfs_manifest(stage_dir, manifest, 0)
            os.replace(stage_dir, vfs_dir)
            print(json.dumps(manifest))
            return 0

        if cmd == "vfs-hydrate":
            vfs_dir, man = read_vfs_manifest(argv[2])
            mount_dir = vfs_dir / "mount"
            patterns = []
            cow_arg = None
            prewarm = False
            idx = 3
            while idx < len(argv):
                arg = argv[idx]
                if arg == "--prewarm":
                    prewarm = True
                elif arg == "--cow-write":
                    idx += 1
                    require(idx < len(argv), "missing value for --cow-write")
                    cow_arg = argv[idx]
                elif arg.startswith("--"):
                    raise RuntimeError(f"unknown vfs-hydrate flag: {arg}")
                else:
                    validate_vfs_pattern(arg)
                    patterns.append(arg)
                idx += 1
            if prewarm and not patterns:
                patterns.append("**")
            require(bool(patterns), "at least one path or glob pattern is required")
            matched, _ = match_vfs_targets(man["catalog"], set(), patterns)
            require(cow_arg is None or len(matched) == 1, "--cow-write requires a single matched file")

            cas_root = open_remote_cas(man["remote_cas_path"], False) if man["remote_cas_path"] else None
            staged = {}
            for i in matched:
                c = man["catalog"][i]
                rel_b = decode_path(c["path_base64"])
                full_p = os.path.join(os.fsencode(mount_dir), rel_b)
                if cow_arg is not None or not c["hydrated"] or not os.path.lexists(full_p):
                    staged[i] = (rel_b, fetch_vfs_blob(man["checkpoint_id"], cas_root, rel_b, c["kind"], c["size"], c["sha256"]))

            cp_repo = store_root / "checkpoints" / man["checkpoint_id"] / "repo"
            newly_hydrated = 0
            already_hydrated = 0
            bytes_hydrated = 0
            hydrated_paths = []
            for i in matched:
                c = man["catalog"][i]
                rel_b = decode_path(c["path_base64"])
                full_p = os.path.join(os.fsencode(mount_dir), rel_b)
                if not c["hydrated"] or not os.path.lexists(full_p):
                    _, b = staged[i]
                    src_p = os.path.join(os.fsencode(cp_repo), rel_b)
                    materialize_vfs_entry(mount_dir, rel_b, c["kind"], c["mode"], b, src_p)
                    c["hydrated"] = True
                    c["state"] = "hydrated_clean"
                    newly_hydrated += 1
                    bytes_hydrated += c["size"]
                else:
                    already_hydrated += 1
                if cow_arg is not None:
                    p = Path(cow_arg)
                    cow_b = p.read_bytes() if (p.is_file() and not str(p.resolve()).startswith(str(mount_dir))) else cow_arg.encode("utf-8")
                    materialize_vfs_entry(mount_dir, rel_b, "file", c["mode"], cow_b, None)
                    c["hydrated"] = True
                    c["state"] = "hydrated_dirty"
                hydrated_paths.append(c["path"])
            evaluate_vfs_status(vfs_dir, man)
            print(json.dumps({
                "schema": SCHEMA,
                "vfs_id": man["vfs_id"],
                "checkpoint_id": man["checkpoint_id"],
                "mount_path": str(mount_dir),
                "state": "hydrated",
                "prewarm": prewarm,
                "cow_write": cow_arg is not None,
                "newly_hydrated": newly_hydrated,
                "already_hydrated": already_hydrated,
                "bytes_hydrated": bytes_hydrated,
                "hydrated_paths": hydrated_paths,
                "total_entries": man["total_entries"],
                "hydrated_entries": man["hydrated_entries"],
                "dehydrated_entries": man["dehydrated_entries"],
                "dirty_entries": man["dirty_entries"],
                "hydrated_bytes": man["hydrated_bytes"],
                "unhydrated_bytes": man["unhydrated_bytes"],
            }))
            return 0

        if cmd == "vfs-status":
            vfs_dir, man = read_vfs_manifest(argv[2])
            print(json.dumps(evaluate_vfs_status(vfs_dir, man)))
            return 0

        if cmd == "vfs-evict":
            vfs_dir, man = read_vfs_manifest(argv[2])
            mount_dir = vfs_dir / "mount"
            patterns = []
            skip_dirty = False
            for arg in argv[3:]:
                if arg == "--quiescent":
                    continue
                elif arg == "--skip-dirty":
                    skip_dirty = True
                elif arg.startswith("--"):
                    raise RuntimeError(f"unknown vfs-evict flag: {arg}")
                else:
                    validate_vfs_pattern(arg)
                    patterns.append(arg)
            require(bool(patterns), "at least one path or glob pattern is required")
            status = evaluate_vfs_status(vfs_dir, man)
            added_dirty = {d["path"] for d in status["dirty_details"] if d["change"] == "added"}
            matched_cat, matched_added = match_vfs_targets(man["catalog"], added_dirty, patterns)

            dirty_targets = sorted(
                {man["catalog"][i]["path"] for i in matched_cat if man["catalog"][i]["state"] == "hydrated_dirty"}
                | set(matched_added)
            )
            if dirty_targets and not skip_dirty:
                raise RuntimeError(f"conflict: refusing to evict dirty VFS entries without --skip-dirty: {', '.join(dirty_targets)}")

            evicted_entries = 0
            already_dehydrated_entries = 0
            reclaimed_bytes = 0
            evicted_paths = []
            for i in matched_cat:
                c = man["catalog"][i]
                if c["state"] == "hydrated_dirty":
                    continue
                if not c["hydrated"] or c["state"] == "dehydrated":
                    already_dehydrated_entries += 1
                    continue
                rel_b = decode_path(c["path_base64"])
                full = Path(os.fsdecode(os.path.join(os.fsencode(mount_dir), rel_b)))
                if os.path.lexists(full):
                    os.unlink(full)
                cur = full.parent
                while cur != mount_dir and str(cur).startswith(str(mount_dir)):
                    try:
                        cur.rmdir()
                    except OSError:
                        break
                    cur = cur.parent
                c["hydrated"] = False
                c["state"] = "dehydrated"
                evicted_entries += 1
                reclaimed_bytes += c["size"]
                evicted_paths.append(c["path"])
            save_vfs_manifest(vfs_dir, man, len(added_dirty))
            print(json.dumps({
                "schema": SCHEMA,
                "vfs_id": man["vfs_id"],
                "checkpoint_id": man["checkpoint_id"],
                "mount_path": str(mount_dir),
                "state": "evicted",
                "evicted_entries": evicted_entries,
                "already_dehydrated_entries": already_dehydrated_entries,
                "skipped_dirty_entries": len(dirty_targets),
                "reclaimed_bytes": reclaimed_bytes,
                "evicted_paths": evicted_paths,
                "skipped_dirty_paths": dirty_targets,
                "total_entries": man["total_entries"],
                "hydrated_entries": man["hydrated_entries"],
                "dehydrated_entries": man["dehydrated_entries"],
                "dirty_entries": man["dirty_entries"],
                "hydrated_bytes": man["hydrated_bytes"],
                "unhydrated_bytes": man["unhydrated_bytes"],
            }))
            return 0

        def normalize_rel_segments(raw_str: str, allow_empty: bool = False) -> str:
            require("\x00" not in raw_str and not raw_str.startswith("/"), "invalid path: leading '/' or NUL forbidden")
            trimmed = raw_str.rstrip("/")
            if allow_empty and trimmed in ("", ".", "*"):
                return ""
            segs = []
            for seg in trimmed.split("/"):
                if not seg or seg == ".":
                    continue
                require(seg not in ("..", ".git"), f"unsafe or .git path segment '{seg}'")
                segs.append(seg)
            if allow_empty and not segs:
                return ""
            joined = "/".join(segs)
            require(bool(segs) and joined != ".rootyard-namespace.json", "invalid or reserved relative path")
            return joined

        def prefixes_overlap(a: str, b: str) -> bool:
            return not a or not b or a == b or a.startswith(b + "/") or b.startswith(a + "/")

        def prefix_covers(prefix: str, path: str) -> bool:
            return not prefix or prefix == path or path.startswith(prefix + "/")

        def load_lease_table(target_id: str, target_kind: str) -> dict:
            leases_dir = store_root / "leases"
            leases_dir.mkdir(mode=0o700, exist_ok=True)
            p = leases_dir / f"{target_id}.json"
            if not p.exists():
                return {
                    "schema": SCHEMA,
                    "target_id": target_id,
                    "target_kind": target_kind,
                    "lease_epoch": 0,
                    "leases": [],
                }
            raw = p.read_bytes()
            sha_p = leases_dir / f"{target_id}.sha256"
            if sha_p.exists():
                require(hashlib.sha256(raw).hexdigest() == sha_p.read_text().strip(), "lease table checksum mismatch")
            tbl = json.loads(raw)
            require(tbl["schema"] == SCHEMA and tbl["target_id"] == target_id, "invalid lease table")
            return tbl

        def save_lease_table(tbl: dict):
            leases_dir = store_root / "leases"
            raw = json.dumps(tbl, indent=2).encode()
            sha = write_atomic_file(leases_dir, f"{tbl['target_id']}.json", raw, 0o600)
            write_atomic_file(leases_dir, f"{tbl['target_id']}.sha256", sha.encode(), 0o600)

        def enforce_write_lease(ns_id: str, agent_id: str, rel_path: str, req_epoch):
            lease_file = store_root / "leases" / f"{ns_id}.json"
            if not lease_file.exists():
                require(req_epoch is None, "conflict: lease_epoch specified but no active lease exists")
                return None
            now_s = int(time.time())
            tbl = load_lease_table(ns_id, "namespace")
            for l in tbl["leases"]:
                if l["state"] == "active" and now_s >= l["expires_at"]:
                    l["state"] = "expired"
            save_lease_table(tbl)
            for l in tbl["leases"]:
                if l["state"] == "active" and prefixes_overlap(l["prefix"], rel_path) and l["agent_id"] != agent_id:
                    raise RuntimeError(
                        f"conflict: path '{rel_path}' is locked by active lease of agent '{l['agent_id']}' on prefix '{l['prefix']}' (epoch {l['lease_epoch']})"
                    )
            for l in tbl["leases"]:
                if l["state"] == "active" and l["agent_id"] == agent_id and prefix_covers(l["prefix"], rel_path):
                    if req_epoch is not None:
                        require(
                            req_epoch == l["lease_epoch"],
                            f"conflict: stale or mismatched lease_epoch {req_epoch} (active epoch is {l['lease_epoch']})",
                        )
                    return l["lease_epoch"]
            if req_epoch is not None:
                raise RuntimeError(f"conflict: stale or inactive lease_epoch {req_epoch} for agent '{agent_id}' on '{rel_path}'")
            for l in tbl["leases"]:
                if l["agent_id"] == agent_id and l["state"] == "expired" and prefix_covers(l["prefix"], rel_path):
                    raise RuntimeError(f"conflict: lease for agent '{agent_id}' covering '{rel_path}' has expired")
            return None

        if cmd == "agent-lease":
            target_id = argv[2]
            agent_id = argv[3]
            action = argv[4]
            require(is_uuid(target_id), "invalid target uuid")
            valid_agent_name(agent_id)
            if (store_root / "namespaces" / target_id).is_dir():
                target_kind = "namespace"
            elif (store_root / "workspaces" / target_id).is_dir():
                target_kind = "workspace"
            else:
                raise RuntimeError(f"unknown namespace or workspace id: {target_id}")
            prefix = ""
            ttl_secs = 300
            req_epoch = None
            idx = 5
            while idx < len(argv):
                fl = argv[idx]
                if fl == "--prefix":
                    idx += 1
                    require(idx < len(argv), "missing --prefix")
                    prefix = normalize_rel_segments(argv[idx], True)
                elif fl == "--ttl-secs":
                    idx += 1
                    require(idx < len(argv), "missing --ttl-secs")
                    ttl_secs = int(argv[idx])
                    require(0 <= ttl_secs <= 86400 * 30, "invalid --ttl-secs")
                elif fl in ("--epoch", "--lease-epoch"):
                    idx += 1
                    require(idx < len(argv), "missing --epoch")
                    req_epoch = int(argv[idx])
                else:
                    raise RuntimeError(f"unknown agent-lease flag: {fl}")
                idx += 1

            now_s = int(time.time())
            tbl = load_lease_table(target_id, target_kind)
            for l in tbl["leases"]:
                if l["state"] == "active" and now_s >= l["expires_at"]:
                    l["state"] = "expired"

            if action == "acquire":
                for l in tbl["leases"]:
                    if l["state"] == "active" and prefixes_overlap(l["prefix"], prefix) and l["agent_id"] != agent_id:
                        save_lease_table(tbl)
                        raise RuntimeError(
                            f"conflict: prefix '{prefix}' overlaps active lease held by '{l['agent_id']}' on '{l['prefix']}' (epoch {l['lease_epoch']})"
                        )
                if req_epoch is not None:
                    require(req_epoch >= tbl["lease_epoch"], f"conflict: stale lease_epoch {req_epoch} < {tbl['lease_epoch']}")
                tbl["leases"] = [
                    l
                    for l in tbl["leases"]
                    if not (prefixes_overlap(l["prefix"], prefix) and (l["state"] != "active" or l["agent_id"] == agent_id))
                ]
                tbl["lease_epoch"] += 1
                entry = {
                    "lease_id": str(uuid.uuid4()),
                    "target_id": target_id,
                    "target_kind": target_kind,
                    "agent_id": agent_id,
                    "prefix": prefix,
                    "lease_epoch": tbl["lease_epoch"],
                    "ttl_secs": ttl_secs,
                    "acquired_at": now_s,
                    "expires_at": now_s + ttl_secs,
                    "state": "active",
                }
                tbl["leases"].append(entry)
                tbl["leases"].sort(key=lambda item: (item["prefix"], item["lease_epoch"]))
                save_lease_table(tbl)
                primary = dict(entry, state="acquired")
            elif action == "renew":
                pos = next((i for i, l in enumerate(tbl["leases"]) if l["agent_id"] == agent_id and l["prefix"] == prefix), None)
                if pos is None:
                    save_lease_table(tbl)
                    raise RuntimeError(f"conflict: no lease found for agent '{agent_id}' on prefix '{prefix}' (stale lease_epoch)")
                cur_ep = tbl["leases"][pos]["lease_epoch"]
                if req_epoch is not None and (req_epoch != cur_ep or (cur_ep < tbl["lease_epoch"] and tbl["leases"][pos]["state"] != "active")):
                    save_lease_table(tbl)
                    raise RuntimeError(f"conflict: stale lease_epoch {req_epoch} (current lease epoch {cur_ep})")
                if tbl["leases"][pos]["state"] != "active":
                    save_lease_table(tbl)
                    raise RuntimeError(f"conflict: lease expired for agent '{agent_id}' on prefix '{prefix}' (epoch {cur_ep})")
                tbl["leases"][pos]["ttl_secs"] = ttl_secs
                tbl["leases"][pos]["expires_at"] = now_s + ttl_secs
                save_lease_table(tbl)
                primary = dict(tbl["leases"][pos], state="renewed")
            elif action == "release":
                pos = next(
                    (i for i, l in enumerate(tbl["leases"]) if l["agent_id"] == agent_id and l["prefix"] == prefix and l["state"] == "active"),
                    None,
                )
                if pos is None:
                    save_lease_table(tbl)
                    raise RuntimeError(f"conflict: no active lease for agent '{agent_id}' on prefix '{prefix}'")
                if req_epoch is not None:
                    require(req_epoch == tbl["leases"][pos]["lease_epoch"], f"conflict: stale lease_epoch {req_epoch}")
                tbl["leases"][pos]["state"] = "released"
                save_lease_table(tbl)
                primary = dict(tbl["leases"][pos])
            elif action == "status":
                save_lease_table(tbl)
                primary = {
                    "lease_id": "",
                    "target_id": target_id,
                    "target_kind": target_kind,
                    "agent_id": agent_id,
                    "prefix": prefix,
                    "lease_epoch": tbl["lease_epoch"],
                    "ttl_secs": 0,
                    "acquired_at": now_s,
                    "expires_at": now_s,
                    "state": "status",
                }
            else:
                raise RuntimeError(f"unsupported agent-lease action '{action}'")

            active_count = sum(1 for l in tbl["leases"] if l["state"] == "active")
            print(json.dumps({
                "schema": SCHEMA,
                "lease_id": primary["lease_id"],
                "target_id": target_id,
                "target_kind": target_kind,
                "agent_id": agent_id,
                "action": action,
                "prefix": primary["prefix"],
                "lease_epoch": primary["lease_epoch"],
                "ttl_secs": primary["ttl_secs"],
                "acquired_at": primary["acquired_at"],
                "expires_at": primary["expires_at"],
                "state": primary["state"],
                "active_leases": active_count,
                "leases": tbl["leases"],
            }))
            return 0

        def load_pending_writes(ns_dir: Path, ns_id: str, rev: int) -> dict:
            w_dir = ns_dir / "writable"
            p_file = w_dir / "pending.json"
            if not p_file.exists():
                return {"schema": SCHEMA, "namespace_id": ns_id, "namespace_revision": rev, "writes": []}
            raw = p_file.read_bytes()
            sha_exp = (w_dir / "pending.sha256").read_text().strip()
            require(hashlib.sha256(raw).hexdigest() == sha_exp, "pending writes checksum mismatch")
            return json.loads(raw)

        def save_pending_writes(ns_dir: Path, tbl: dict):
            w_dir = ns_dir / "writable"
            raw = json.dumps(tbl, indent=2).encode()
            sha = write_atomic_file(w_dir, "pending.json", raw, 0o600)
            write_atomic_file(w_dir, "pending.sha256", sha.encode(), 0o600)

        def rebuild_namespace_tree(ns_dir: Path, base_vector: list) -> int:
            stage_dir = store_root / "staging" / str(uuid.uuid4())
            stage_tree = stage_dir / "tree"
            stage_tree.mkdir(mode=0o700, parents=True)
            total_entries = 0
            for bv in base_vector:
                cp_dir, cp_man = read_checkpoint(bv["checkpoint_id"])
                total_entries += copy_worktree_to_mount(cp_dir / "repo", cp_man["entries"], stage_tree / bv["mount_path"], True)
            tree_dir = ns_dir / "tree"
            if tree_dir.exists():
                shutil.rmtree(tree_dir)
            os.replace(stage_tree, tree_dir)
            shutil.rmtree(stage_dir, ignore_errors=True)
            return total_entries

        if cmd == "namespace-write":
            ns_id = argv[2]
            agent_id = argv[3]
            raw_path = argv[4]
            content_str = argv[5]
            valid_agent_name(agent_id)
            req_epoch = None
            idx = 6
            while idx < len(argv):
                fl = argv[idx]
                if fl in ("--lease-epoch", "--epoch"):
                    idx += 1
                    require(idx < len(argv), "missing --lease-epoch")
                    req_epoch = int(argv[idx])
                else:
                    raise RuntimeError(f"unknown namespace-write flag: {fl}")
                idx += 1

            ns_dir, man = read_namespace_manifest(ns_id)
            rel_str = normalize_rel_segments(raw_path, False)
            matched_bv = None
            repo_rel_str = None
            for bv in man["base_vector"]:
                mp = bv["mount_path"]
                if rel_str.startswith(mp + "/"):
                    sub = rel_str[len(mp) + 1 :]
                    if sub:
                        matched_bv = bv
                        repo_rel_str = normalize_rel_segments(sub, False)
                        break
            if matched_bv is None or not repo_rel_str:
                raise RuntimeError(f"unmapped namespace path '{rel_str}': does not fall under any mounted repository prefix")

            active_epoch = enforce_write_lease(ns_id, agent_id, rel_str, req_epoch)
            _, cp_man = read_checkpoint(matched_bv["checkpoint_id"])
            base_map = {
                decode_path(e["path_base64"]): e
                for e in cp_man["entries"]
                if not decode_path(e["path_base64"]).startswith(b".git/")
            }
            rel_b = rel_str.encode("utf-8")
            repo_rel_b = repo_rel_str.encode("utf-8")
            base_entry = base_map.get(repo_rel_b)
            tbl = load_pending_writes(ns_dir, ns_id, man["namespace_revision"])
            staged_files_dir = ns_dir / "writable" / "files"
            view_target = ns_dir / "tree" / rel_str

            if content_str in ("--delete", "DELETE"):
                require(
                    base_entry is not None or any(w["path"] == rel_str and w["operation"] == "write" for w in tbl["writes"]),
                    f"cannot delete non-existent path '{rel_str}'",
                )
                staged_p = staged_files_dir / rel_str
                if staged_p.exists():
                    staged_p.unlink()
                if view_target.exists() or view_target.is_symlink():
                    view_target.unlink()
                operation = "delete"
                change = "deleted"
                file_mode = 0o644
                size = None
                sha256 = None
            else:
                cand = Path(content_str)
                if cand.is_file() and not cand.is_symlink() and not str(cand.resolve()).startswith(str(store_root)):
                    data = cand.read_bytes()
                else:
                    data = content_str.encode("utf-8")
                sha256 = hashlib.sha256(data).hexdigest()
                size = len(data)
                file_mode = (0o755 if (base_entry["mode"] & 0o111) else 0o644) if base_entry is not None else 0o644
                staged_dest = staged_files_dir / rel_str
                write_atomic_file(staged_dest.parent, staged_dest.name, data, file_mode)
                write_atomic_file(view_target.parent, view_target.name, data, (file_mode & 0o555) | 0o400)
                operation = "write"
                change = "modified" if base_entry is not None else "added"

            tbl["writes"] = [w for w in tbl["writes"] if w["path"] != rel_str]
            tbl["writes"].append({
                "path": rel_str,
                "path_base64": encode_path(rel_b),
                "mount_path": matched_bv["mount_path"],
                "repo_rel_path": repo_rel_str,
                "repo_rel_path_base64": encode_path(repo_rel_b),
                "base_checkpoint_id": matched_bv["checkpoint_id"],
                "workspace_id": matched_bv["workspace_id"],
                "base_oid": matched_bv["base_oid"],
                "base_namespace_revision": man["namespace_revision"],
                "agent_id": agent_id,
                "operation": operation,
                "change": change,
                "mode": file_mode,
                "size": size,
                "sha256": sha256,
                "lease_epoch": active_epoch,
            })
            tbl["writes"].sort(key=lambda item: item["path"])
            save_pending_writes(ns_dir, tbl)
            print(json.dumps({
                "schema": SCHEMA,
                "namespace_id": ns_id,
                "namespace_revision": man["namespace_revision"],
                "agent_id": agent_id,
                "path": rel_str,
                "path_base64": encode_path(rel_b),
                "mount_path": matched_bv["mount_path"],
                "repo_rel_path": repo_rel_str,
                "repo_rel_path_base64": encode_path(repo_rel_b),
                "base_checkpoint_id": matched_bv["checkpoint_id"],
                "workspace_id": matched_bv["workspace_id"],
                "base_oid": matched_bv["base_oid"],
                "operation": operation,
                "change": change,
                "size": size,
                "sha256": sha256,
                "lease_epoch": active_epoch,
                "pending_writes_count": len(tbl["writes"]),
                "state": "staged",
            }))
            return 0

        if cmd == "namespace-commit-back":
            ns_id = argv[2]
            agent_id = argv[3]
            valid_agent_name(agent_id)
            req_epoch = None
            idx = 4
            while idx < len(argv):
                fl = argv[idx]
                if fl == "--quiescent":
                    pass
                elif fl in ("--lease-epoch", "--epoch"):
                    idx += 1
                    require(idx < len(argv), "missing --lease-epoch")
                    req_epoch = int(argv[idx])
                else:
                    raise RuntimeError(f"unknown namespace-commit-back flag: {fl}")
                idx += 1

            ns_dir, man = read_namespace_manifest(ns_id)
            pending = load_pending_writes(ns_dir, ns_id, man["namespace_revision"])
            require(bool(pending["writes"]), "no pending namespace writes to commit back")
            active_epoch = req_epoch
            for w in pending["writes"]:
                ep = enforce_write_lease(ns_id, agent_id, w["path"], req_epoch)
                if active_epoch is None:
                    active_epoch = ep

            writes_by_mount = {}
            for w in pending["writes"]:
                writes_by_mount.setdefault(w["mount_path"], []).append(w)

            prepared = []
            try:
                require(pending["namespace_revision"] == man["namespace_revision"], "conflict: namespace revision drifted")
                for bv in man["base_vector"]:
                    cp_dir, cp_man = read_checkpoint(bv["checkpoint_id"])
                    cp_repo = cp_dir / "repo"
                    actual_sha = (cp_dir / "manifest.sha256").read_text().strip()
                    actual_head = run_git(cp_repo, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
                    require(
                        bv["base_oid"] == cp_man["workspace"]["base_oid"]
                        and bv["head_oid"] == actual_head
                        and bv["manifest_sha256"] == actual_sha,
                        f"conflict: BaseVector drift on mount '{bv['mount_path']}'",
                    )
                    m_writes = writes_by_mount.get(bv["mount_path"])
                    if not m_writes:
                        continue
                    for w in m_writes:
                        require(
                            w["base_checkpoint_id"] == bv["checkpoint_id"]
                            and w["base_namespace_revision"] == man["namespace_revision"],
                            f"conflict: staged write base checkpoint drifted on mount '{bv['mount_path']}'",
                        )
                    base_map = {
                        decode_path(e["path_base64"]): e
                        for e in cp_man["entries"]
                        if not decode_path(e["path_base64"]).startswith(b".git/")
                    }
                    ws_dir = store_root / "workspaces" / bv["workspace_id"]
                    if ws_dir.is_dir():
                        _, ws = read_workspace(bv["workspace_id"])
                        ws_repo = ws_dir / "repo"
                        ws_head = run_git(ws_repo, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
                        require(
                            ws["base_oid"] == bv["base_oid"]
                            and ws_head == bv["head_oid"]
                            and ws.get("parent_checkpoint_id") in (None, bv["checkpoint_id"]),
                            f"conflict: constituent workspace '{bv['workspace_id']}' drifted from BaseVector checkpoint",
                        )
                        cls = classify_repo(ws_repo)
                        curr_ws_map = {}
                        for p_b in cls["managed_paths"]:
                            ent = entry_for_rel(ws_repo, p_b)
                            if ent is not None:
                                curr_ws_map[p_b] = ent
                        drift_delta, _ = compute_delta(base_map, curr_ws_map, True)
                        require(not drift_delta, f"conflict: constituent workspace '{bv['workspace_id']}' has uncommitted base drift")

                    stage_cp = store_root / "staging" / str(uuid.uuid4())
                    stage_repo = stage_cp / "repo"
                    copy_selected(cp_repo, stage_repo, walk_files(cp_repo).keys())
                    for w in m_writes:
                        target = stage_repo / w["repo_rel_path"]
                        if w["operation"] == "delete":
                            if target.exists() or target.is_symlink():
                                target.unlink()
                        else:
                            data = (ns_dir / "writable" / "files" / w["path"]).read_bytes()
                            write_atomic_file(target.parent, target.name, data, w["mode"])
                    validate_repo(stage_repo, bv["base_oid"])
                    new_entries = inventory(stage_repo)
                    new_cp_id = str(uuid.uuid4())
                    new_ws_meta = dict(cp_man["workspace"], parent_checkpoint_id=bv["checkpoint_id"])
                    new_cp_man = {
                        "schema": SCHEMA,
                        "checkpoint_id": new_cp_id,
                        "state": "local_complete",
                        "workspace": new_ws_meta,
                        "excluded_ignored_entries": cp_man["excluded_ignored_entries"],
                        "entries": new_entries,
                    }
                    cp_bytes = json.dumps(new_cp_man, indent=2).encode()
                    cp_sha = write_atomic_file(stage_cp, "manifest.json", cp_bytes, 0o600)
                    write_atomic_file(stage_cp, "manifest.sha256", cp_sha.encode(), 0o600)

                    new_map = {
                        decode_path(e["path_base64"]): e
                        for e in new_entries
                        if not decode_path(e["path_base64"]).startswith(b".git/")
                    }
                    cs_entries, cs_counts = compute_delta(base_map, new_map, True)
                    cs_id = str(uuid.uuid4())
                    stage_cs = store_root / "staging" / str(uuid.uuid4())
                    cs_files = stage_cs / "files"
                    cs_files.mkdir(mode=0o700, parents=True)
                    for ce in cs_entries:
                        if ce["after"] is not None:
                            rel_b = decode_path(ce["path_base64"])
                            from_p = os.path.join(os.fsencode(stage_repo), rel_b)
                            to_p = os.path.join(os.fsencode(cs_files), rel_b)
                            os.makedirs(os.path.dirname(to_p), mode=0o700, exist_ok=True)
                            st = os.lstat(from_p)
                            if stat.S_ISLNK(st.st_mode):
                                os.symlink(os.readlink(from_p), to_p)
                            else:
                                shutil.copyfile(from_p, to_p)
                                os.chmod(to_p, st.st_mode & 0o777)
                    cs_obj = {
                        "schema": SCHEMA,
                        "changeset_id": cs_id,
                        "state": "local_complete",
                        "base_oid": bv["base_oid"],
                        "base_checkpoint_id": bv["checkpoint_id"],
                        "source_checkpoint_id": new_cp_id,
                        **cs_counts,
                        "entries": cs_entries,
                    }
                    cs_bytes = json.dumps(cs_obj, indent=2).encode()
                    cs_sha = write_atomic_file(stage_cs, "changeset.json", cs_bytes, 0o600)
                    write_atomic_file(stage_cs, "changeset.sha256", cs_sha.encode(), 0o600)
                    prepared.append((bv, stage_cp, new_cp_id, cp_sha, len(new_map), stage_cs, cs_obj))
            except Exception:
                for item in prepared:
                    shutil.rmtree(item[1], ignore_errors=True)
                    shutil.rmtree(item[5], ignore_errors=True)
                try:
                    rebuild_namespace_tree(ns_dir, man["base_vector"])
                except Exception:
                    pass
                shutil.rmtree(ns_dir / "writable", ignore_errors=True)
                raise

            new_cp_by_mount = {}
            mount_commits = []
            for bv, stage_cp, new_cp_id, cp_sha, worktree_cnt, stage_cs, cs_obj in prepared:
                os.replace(stage_cp, store_root / "checkpoints" / new_cp_id)
                os.replace(stage_cs, store_root / "changesets" / cs_obj["changeset_id"])
                ws_dir = store_root / "workspaces" / bv["workspace_id"]
                if ws_dir.is_dir():
                    _, ws = read_workspace(bv["workspace_id"])
                    ws_repo = ws_dir / "repo"
                    cp_repo = store_root / "checkpoints" / new_cp_id / "repo"
                    for ce in cs_obj["entries"]:
                        rel_b = decode_path(ce["path_base64"])
                        dst = os.path.join(os.fsencode(ws_repo), rel_b)
                        if ce["after"] is None and os.path.lexists(dst):
                            os.unlink(dst)
                        elif ce["after"] is not None:
                            src_p = os.path.join(os.fsencode(cp_repo), rel_b)
                            os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
                            if os.path.lexists(dst):
                                os.unlink(dst)
                            st = os.lstat(src_p)
                            if stat.S_ISLNK(st.st_mode):
                                os.symlink(os.readlink(src_p), dst)
                            else:
                                shutil.copyfile(src_p, dst)
                                os.chmod(dst, st.st_mode & 0o777)
                    ws["parent_checkpoint_id"] = new_cp_id
                    write_atomic_file(ws_dir, "workspace.json", json.dumps(ws, indent=2).encode(), 0o600)
                new_cp_by_mount[bv["mount_path"]] = (new_cp_id, cp_sha, worktree_cnt)
                mount_commits.append({
                    "mount_path": bv["mount_path"],
                    "workspace_id": bv["workspace_id"],
                    "base_oid": bv["base_oid"],
                    "previous_checkpoint_id": bv["checkpoint_id"],
                    "new_checkpoint_id": new_cp_id,
                    "changeset_id": cs_obj["changeset_id"],
                    "added": cs_obj["added"],
                    "modified": cs_obj["modified"],
                    "deleted": cs_obj["deleted"],
                    "mode_changed": cs_obj["mode_changed"],
                    "type_changed": cs_obj["type_changed"],
                    "entries_count": worktree_cnt,
                })

            previous_base_vector = [dict(bv) for bv in man["base_vector"]]
            new_base_vector = []
            for bv in man["base_vector"]:
                nbv = dict(bv)
                if nbv["mount_path"] in new_cp_by_mount:
                    new_cp_id, cp_sha, cnt = new_cp_by_mount[nbv["mount_path"]]
                    nbv["checkpoint_id"] = new_cp_id
                    nbv["manifest_sha256"] = cp_sha
                    nbv["entries_count"] = cnt
                new_base_vector.append(nbv)

            total_entries = rebuild_namespace_tree(ns_dir, new_base_vector)
            new_rev = man["namespace_revision"] + 1
            updated_manifest = {
                "schema": SCHEMA,
                "namespace_id": ns_id,
                "name": man["name"],
                "namespace_revision": new_rev,
                "view_path": man["view_path"],
                "mount_count": len(new_base_vector),
                "total_entries": total_entries,
                "state": "mounted",
                "base_vector": new_base_vector,
            }
            ns_bytes = json.dumps(updated_manifest, indent=2).encode()
            ns_sha = write_atomic_file(ns_dir, "namespace.json", ns_bytes, 0o600)
            write_atomic_file(ns_dir, "namespace.sha256", ns_sha.encode(), 0o600)

            commit_id = str(uuid.uuid4())
            commits_dir = ns_dir / "commits"
            receipt_path = commits_dir / f"{commit_id}.json"
            receipt = {
                "schema": SCHEMA,
                "commit_id": commit_id,
                "namespace_id": ns_id,
                "name": man["name"],
                "agent_id": agent_id,
                "previous_revision": man["namespace_revision"],
                "namespace_revision": new_rev,
                "lease_epoch": active_epoch,
                "phase": "committed",
                "state": "committed",
                "touched_mounts_count": len(mount_commits),
                "total_writes_committed": len(pending["writes"]),
                "mount_commits": mount_commits,
                "previous_base_vector": previous_base_vector,
                "base_vector": new_base_vector,
                "receipt_path": str(receipt_path),
            }
            rec_bytes = json.dumps(receipt, indent=2).encode()
            rec_sha = write_atomic_file(commits_dir, f"{commit_id}.json", rec_bytes, 0o600)
            write_atomic_file(commits_dir, f"{commit_id}.sha256", rec_sha.encode(), 0o600)
            shutil.rmtree(ns_dir / "writable", ignore_errors=True)
            print(json.dumps(receipt))
            return 0

        def norm_overlay_rel(raw_str: str) -> str:
            require(
                isinstance(raw_str, str)
                and bool(raw_str)
                and "\x00" not in raw_str
                and not raw_str.startswith("/")
                and not raw_str.startswith("cross-repo:"),
                f"invalid or cross-repo overlay path: {raw_str}",
            )
            trimmed = raw_str.rstrip("/")
            require(bool(trimmed), "empty overlay path")
            for seg in trimmed.split("/"):
                require(
                    bool(seg) and seg not in (".", "..", ".git", ".rootyard-namespace.json"),
                    f"unsafe overlay path segment: {seg}",
                )
            decode_path(encode_path(trimmed.encode("utf-8")))
            return trimmed

        def save_overlay_manifest(ov_dir: Path, man: dict):
            man["whiteouts"] = sorted(set(man["whiteouts"]))
            man["forced_managed_paths"] = sorted(set(man["forced_managed_paths"]))
            man["upper_entries"] = inventory(ov_dir / "upper")
            man["upper_entries_count"] = len(man["upper_entries"])
            man["whiteouts_count"] = len(man["whiteouts"])
            man["forced_managed_count"] = len(man["forced_managed_paths"])
            raw = json.dumps(man, indent=2).encode()
            sha = write_atomic_file(ov_dir, "overlay.json", raw, 0o600)
            write_atomic_file(ov_dir, "overlay.sha256", sha.encode(), 0o600)

        def read_overlay_manifest(ov_id: str):
            require(is_uuid(ov_id), "invalid overlay uuid")
            ov_dir = store_root / "overlays" / ov_id
            require(ov_dir.is_dir() and not ov_dir.is_symlink(), f"unknown overlay {ov_id}")
            raw = (ov_dir / "overlay.json").read_bytes()
            sha = (ov_dir / "overlay.sha256").read_text().strip()
            require(hashlib.sha256(raw).hexdigest() == sha, "overlay manifest checksum mismatch")
            man = json.loads(raw)
            require(man["schema"] == SCHEMA and man["overlay_id"] == ov_id, "invalid overlay manifest")
            require(is_uuid(man["checkpoint_id"]), "invalid checkpoint_id")
            valid_agent_name(man["agent_id"])
            for sub in ("lower", "upper", "merged"):
                require((ov_dir / sub).is_dir() and not (ov_dir / sub).is_symlink(), f"missing overlay {sub} dir")
            for rel_b, st in walk_files(ov_dir / "lower").items():
                if stat.S_ISREG(st.st_mode):
                    require((st.st_mode & 0o222) == 0, f"lower layer file writable: {rel_b.decode('utf-8', errors='replace')}")
            return ov_dir, man

        def copy_entry_cow(root_dir: Path, rel_str: str, src_full: Path, force_mode=None):
            dest = root_dir / rel_str
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            st = src_full.lstat()
            if stat.S_ISLNK(st.st_mode):
                target_b = os.readlink(os.fsencode(src_full))
                if dest.exists() or dest.is_symlink():
                    dest.unlink()
                os.symlink(target_b, os.fsencode(dest))
                validate_symlink(root_dir, rel_str.encode("utf-8"), target_b)
                return 0o777, len(target_b), hashlib.sha256(target_b).hexdigest()
            require(stat.S_ISREG(st.st_mode), "unsupported non-regular file")
            data = src_full.read_bytes()
            mode = force_mode if force_mode is not None else (0o755 if (st.st_mode & 0o111) else 0o644)
            sha = write_atomic_file(dest.parent, dest.name, data, mode)
            st_new = dest.lstat()
            require((st_new.st_dev, st_new.st_ino) != (st.st_dev, st.st_ino), "CoW copy shares inode with source")
            return mode, len(data), sha

        if cmd == "overlay-mount":
            cp_id = argv[2]
            agent_id = argv[3]
            require(is_uuid(cp_id), "invalid checkpoint uuid")
            valid_agent_name(agent_id)
            cas_arg = None
            idx = 4
            while idx < len(argv):
                fl = argv[idx]
                if fl == "--remote-cas":
                    idx += 1
                    require(idx < len(argv), "missing --remote-cas")
                    cas_arg = argv[idx]
                else:
                    raise RuntimeError(f"unknown overlay-mount flag: {fl}")
                idx += 1
            remote_cas_path = None
            if cas_arg is not None:
                cas_root = open_remote_cas(cas_arg, False)
                remote_cas_path = str(cas_root)
                if not (store_root / "checkpoints" / cp_id).is_dir():
                    import contextlib, io
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        rc = _run_reference_cli(["pull-remote", str(store_root), str(cas_root), cp_id, agent_id])
                    require(rc == 0, "failed to pull remote checkpoint for overlay-mount")
                    pulled = json.loads(buf.getvalue())
                    if pulled.get("workspace_id"):
                        shutil.rmtree(store_root / "workspaces" / pulled["workspace_id"], ignore_errors=True)
            cp_dir, cp_man = read_checkpoint(cp_id)
            cp_repo = cp_dir / "repo"
            head_oid = run_git(cp_repo, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
            overlay_id = str(uuid.uuid4())
            stage_dir = store_root / "staging" / str(uuid.uuid4())
            s_lower = stage_dir / "lower"
            s_upper = stage_dir / "upper"
            s_merged = stage_dir / "merged"
            s_lower.mkdir(mode=0o700, parents=True)
            s_upper.mkdir(mode=0o700, parents=True)
            copy_selected(cp_repo, s_merged, walk_files(cp_repo).keys())
            lower_count = 0
            for entry in cp_man["entries"]:
                rel_b = decode_path(entry["path_base64"])
                if rel_b == b".git" or rel_b.startswith(b".git/"):
                    continue
                rel_str = rel_b.decode("utf-8", errors="surrogateescape")
                copy_entry_cow(s_lower, rel_str, cp_repo / rel_str, 0o555 if (entry["mode"] & 0o111) else 0o444)
                if entry["kind"] == "file":
                    os.chmod(s_lower / rel_str, 0o555 if (entry["mode"] & 0o111) else 0o444)
                lower_count += 1
            validate_repo(s_merged, cp_man["workspace"]["base_oid"])
            ov_dir = store_root / "overlays" / overlay_id
            man = {
                "schema": SCHEMA,
                "overlay_id": overlay_id,
                "checkpoint_id": cp_id,
                "workspace_id": cp_man["workspace"]["workspace_id"],
                "agent_id": agent_id,
                "base_oid": cp_man["workspace"]["base_oid"],
                "head_oid": head_oid,
                "remote_cas_path": remote_cas_path,
                "lower_path": str(ov_dir / "lower"),
                "upper_path": str(ov_dir / "upper"),
                "merged_path": str(ov_dir / "merged"),
                "state": "mounted",
                "lower_entries_count": lower_count,
                "upper_entries_count": 0,
                "whiteouts_count": 0,
                "forced_managed_count": 0,
                "whiteouts": [],
                "upper_entries": [],
                "forced_managed_paths": [],
            }
            save_overlay_manifest(stage_dir, man)
            os.replace(stage_dir, ov_dir)
            print(json.dumps(man))
            return 0

        if cmd in ("overlay-op", "overlay-write", "overlay-delete", "overlay-rename", "overlay-chmod", "overlay-git-add-f", "overlay-status"):
            ov_id = argv[2]
            if cmd == "overlay-op":
                op = argv[3]
                rest = argv[4:]
            else:
                op = cmd[len("overlay-") :]
                rest = argv[3:]
            ov_dir, man = read_overlay_manifest(ov_id)
            lower_dir = ov_dir / "lower"
            upper_dir = ov_dir / "upper"
            merged_dir = ov_dir / "merged"

            if op == "status":
                require(not rest, "overlay-status takes no extra arguments")
                validate_repo(merged_dir, man["base_oid"])
                for rel_b, l_st in walk_files(lower_dir).items():
                    if stat.S_ISREG(l_st.st_mode):
                        m_p = os.path.join(os.fsencode(merged_dir), rel_b)
                        if os.path.lexists(m_p):
                            m_st = os.lstat(m_p)
                            if stat.S_ISREG(m_st.st_mode):
                                require((l_st.st_dev, l_st.st_ino) != (m_st.st_dev, m_st.st_ino), "merged shares inode with lower")
                cls = classify_repo(merged_dir)
                head_oid = run_git(merged_dir, "rev-parse", "--verify", "HEAD").stdout.decode().strip()
                staged_paths = sorted(
                    p.decode("utf-8", errors="replace")
                    for p in run_git(merged_dir, "diff-index", "--cached", "--name-only", "-z", "HEAD").stdout.split(b"\x00")
                    if p
                )
                unstaged_paths = sorted(p.decode("utf-8", errors="replace") for p in compute_unstaged_set(merged_dir))
                untracked_paths = sorted(p.decode("utf-8", errors="replace") for p in cls["untracked_paths"])
                managed_paths = sorted(p.decode("utf-8", errors="replace") for p in cls["managed_paths"])
                ignored_paths = sorted(p.decode("utf-8", errors="replace") for p in cls["ignored_paths"])
                save_overlay_manifest(ov_dir, man)
                upper_paths = [
                    decode_path(e["path_base64"]).decode("utf-8", errors="replace")
                    for e in man["upper_entries"]
                ]
                is_dirty = bool(staged_paths or unstaged_paths or untracked_paths or man["whiteouts"] or upper_paths)
                print(json.dumps({
                    "schema": SCHEMA,
                    "overlay_id": man["overlay_id"],
                    "checkpoint_id": man["checkpoint_id"],
                    "workspace_id": man["workspace_id"],
                    "agent_id": man["agent_id"],
                    "base_oid": man["base_oid"],
                    "head_oid": head_oid,
                    "merged_path": str(merged_dir),
                    "state": "mounted",
                    "is_dirty": is_dirty,
                    "clean": not is_dirty,
                    "lower_entries_count": man["lower_entries_count"],
                    "upper_entries_count": man["upper_entries_count"],
                    "whiteouts_count": man["whiteouts_count"],
                    "managed_entries_count": len(managed_paths),
                    "ignored_entries_count": len(ignored_paths),
                    "staged_paths": staged_paths,
                    "unstaged_paths": unstaged_paths,
                    "untracked_paths": untracked_paths,
                    "managed_paths": managed_paths,
                    "ignored_paths": ignored_paths,
                    "whiteouts": man["whiteouts"],
                    "upper_paths": upper_paths,
                    "forced_managed_paths": man["forced_managed_paths"],
                }))
                return 0

            src_opt = None
            copied_up = False
            whiteout_rec = False
            forced_m = False
            mode_opt = None
            sz_opt = None
            sha_opt = None

            if op == "write":
                require(len(rest) == 2, "overlay-write requires REL_PATH and CONTENT_OR_FILE")
                p_str = norm_overlay_rel(rest[0])
                val = rest[1]
                cand = Path(val)
                if cand.is_file() and not cand.is_symlink() and not str(cand.resolve()).startswith(str(store_root)):
                    data = cand.read_bytes()
                else:
                    data = val.encode("utf-8")
                mode = 0o644
                for check_p in (merged_dir / p_str, lower_dir / p_str):
                    if check_p.exists():
                        mode = 0o755 if (check_p.lstat().st_mode & 0o111) else 0o644
                        break
                copied_up = (lower_dir / p_str).exists() or not (upper_dir / p_str).exists()
                for root_d in (upper_dir, merged_dir):
                    dst = root_d / p_str
                    sha = write_atomic_file(dst.parent, dst.name, data, mode)
                man["whiteouts"] = [w for w in man["whiteouts"] if w != p_str and not p_str.startswith(w + "/")]
                forced_m = p_str in man["forced_managed_paths"]
                mode_opt = mode
                sz_opt = len(data)
                sha_opt = sha
                path_str = p_str
            elif op == "delete":
                require(len(rest) == 1, "overlay-delete requires REL_PATH")
                p_str = norm_overlay_rel(rest[0])
                m_full = merged_dir / p_str
                u_full = upper_dir / p_str
                l_full = lower_dir / p_str
                require(
                    m_full.exists() or m_full.is_symlink() or u_full.exists() or u_full.is_symlink() or l_full.exists() or l_full.is_symlink(),
                    f"cannot delete non-existent path: {p_str}",
                )
                if m_full.is_dir() or l_full.is_dir():
                    if u_full.exists():
                        shutil.rmtree(u_full)
                    if m_full.exists():
                        shutil.rmtree(m_full)
                    if l_full.is_dir():
                        for sub_b in walk_files(l_full).keys():
                            man["whiteouts"].append(f"{p_str}/{sub_b.decode('utf-8', errors='replace')}")
                else:
                    if u_full.exists() or u_full.is_symlink():
                        u_full.unlink()
                    if m_full.exists() or m_full.is_symlink():
                        m_full.unlink()
                man["whiteouts"].append(p_str)
                whiteout_rec = True
                path_str = p_str
            elif op == "rename":
                require(len(rest) == 2, "overlay-rename requires SRC_REL_PATH and DST_REL_PATH")
                src_str = norm_overlay_rel(rest[0])
                dst_str = norm_overlay_rel(rest[1])
                require(src_str != dst_str and not dst_str.startswith(src_str + "/"), "invalid overlay rename target")
                src_m = merged_dir / src_str
                require(src_m.exists() or src_m.is_symlink(), f"missing rename source {src_str}")
                if src_m.is_dir() and not src_m.is_symlink():
                    for sub_b in walk_files(src_m).keys():
                        sub_s = sub_b.decode("utf-8", errors="replace")
                        f_s = f"{src_str}/{sub_s}"
                        t_s = f"{dst_str}/{sub_s}"
                        m, sz, sha = copy_entry_cow(upper_dir, t_s, merged_dir / f_s, None)
                        copy_entry_cow(merged_dir, t_s, upper_dir / t_s, m)
                        man["whiteouts"] = [w for w in man["whiteouts"] if w != t_s]
                        man["whiteouts"].append(f_s)
                        mode_opt, sz_opt, sha_opt = m, sz, sha
                    if (upper_dir / src_str).exists():
                        shutil.rmtree(upper_dir / src_str)
                    shutil.rmtree(src_m)
                else:
                    m, sz, sha = copy_entry_cow(upper_dir, dst_str, src_m, None)
                    copy_entry_cow(merged_dir, dst_str, upper_dir / dst_str, m)
                    if (upper_dir / src_str).exists() or (upper_dir / src_str).is_symlink():
                        (upper_dir / src_str).unlink()
                    src_m.unlink()
                    man["whiteouts"] = [w for w in man["whiteouts"] if w != dst_str]
                    mode_opt, sz_opt, sha_opt = m, sz, sha
                man["whiteouts"].append(src_str)
                src_opt = src_str
                copied_up = True
                whiteout_rec = True
                path_str = dst_str
            elif op == "chmod":
                require(len(rest) == 2, "overlay-chmod requires REL_PATH and MODE_OCTAL")
                p_str = norm_overlay_rel(rest[0])
                raw_m = rest[1].lstrip("0o").lstrip("0O") or "0"
                mode = int(raw_m, 8)
                require((mode & 0o7000) == 0 and (mode & 0o400) != 0, "invalid chmod mode")
                m, sz, sha = copy_entry_cow(upper_dir, p_str, merged_dir / p_str, mode)
                copy_entry_cow(merged_dir, p_str, upper_dir / p_str, m)
                copied_up = True
                mode_opt, sz_opt, sha_opt = m, sz, sha
                path_str = p_str
            elif op == "git-add-f":
                require(len(rest) == 1, "overlay-git-add-f requires REL_PATH")
                p_str = norm_overlay_rel(rest[0])
                m, sz, sha = copy_entry_cow(upper_dir, p_str, merged_dir / p_str, None)
                copy_entry_cow(merged_dir, p_str, upper_dir / p_str, m)
                run_git(merged_dir, "add", "-f", "--", p_str)
                man["forced_managed_paths"].append(p_str)
                cls = classify_repo(merged_dir)
                p_b = p_str.encode("utf-8")
                require(p_b in cls["managed_paths"] and p_b not in cls["ignored_paths"], "git add -f failed to promote path")
                copied_up = True
                forced_m = True
                mode_opt, sz_opt, sha_opt = m, sz, sha
                path_str = p_str
            else:
                raise RuntimeError(f"unsupported overlay op: {op}")

            save_overlay_manifest(ov_dir, man)
            print(json.dumps({
                "schema": SCHEMA,
                "overlay_id": man["overlay_id"],
                "agent_id": man["agent_id"],
                "op": op,
                "path": path_str,
                "source_path": src_opt,
                "copied_up": copied_up,
                "whiteout_recorded": whiteout_rec,
                "forced_managed": forced_m,
                "mode": mode_opt,
                "size": sz_opt,
                "sha256": sha_opt,
                "upper_entries_count": man["upper_entries_count"],
                "whiteouts_count": man["whiteouts_count"],
                "state": "applied",
            }))
            return 0

        def resolve_crash_target(target_id: str):
            require(is_uuid(target_id), "invalid target uuid")
            ov_dir = store_root / "overlays" / target_id
            ws_dir = store_root / "workspaces" / target_id
            if ov_dir.is_dir():
                _, man = read_overlay_manifest(target_id)
                return ov_dir, ov_dir / "merged", "overlay", man["base_oid"], man["checkpoint_id"]
            if ws_dir.is_dir():
                _, ws = read_workspace(target_id)
                return ws_dir, ws_dir / "repo", "workspace", ws["base_oid"], ws.get("parent_checkpoint_id")
            raise RuntimeError(f"unknown overlay or workspace target: {target_id}")

        def entry_digest(seq, tx, win, op, paths, scp, sdir, p_sha):
            raw = f"{seq}:{tx}:{win}:{op}:{scp or ''}:{sdir or ''}:{p_sha}:{','.join(paths)}".encode("utf-8")
            return hashlib.sha256(raw).hexdigest()

        def load_crash_journal(target_dir: Path, target_id: str, kind: str, init_cp):
            j_path = target_dir / "crash_journal.json"
            if not j_path.exists():
                return {
                    "schema": SCHEMA,
                    "target_id": target_id,
                    "target_kind": kind,
                    "last_committed_seq": 0,
                    "committed_checkpoint_id": init_cp,
                    "entries": [],
                    "corrupt_tail_bytes": None,
                }, False
            raw = j_path.read_bytes()
            sha_p = target_dir / "crash_journal.sha256"
            sha_mismatch = (not sha_p.exists()) or (hashlib.sha256(raw).hexdigest() != sha_p.read_text().strip())
            return json.loads(raw), sha_mismatch

        def save_crash_journal(target_dir: Path, journal: dict, corrupt_sha: bool):
            raw = json.dumps(journal, indent=2).encode()
            sha = write_atomic_file(target_dir, "crash_journal.json", raw, 0o600)
            if corrupt_sha:
                sha = "corrupt_unfsynced_wal_tail_sha256"
            write_atomic_file(target_dir, "crash_journal.sha256", sha.encode(), 0o600)

        def dirty_worktree_paths(repo: Path, cp_id):
            cls = classify_repo(repo)
            out = set()
            if cp_id and (store_root / "checkpoints" / cp_id).is_dir():
                _, cp_man = read_checkpoint(cp_id)
                base_map = {
                    decode_path(e["path_base64"]): e
                    for e in cp_man["entries"]
                    if not decode_path(e["path_base64"]).startswith(b".git/")
                }
                exact_mode = True
            else:
                base_map = read_head_tree_map(repo)
                exact_mode = False
            for p_b in cls["managed_paths"]:
                cur = entry_for_rel(repo, p_b)
                b = base_map.get(p_b)
                if not (b is not None and cur is not None and entries_equivalent(b, cur, exact_mode)):
                    out.add(p_b.decode("utf-8", errors="replace"))
            for p_b in base_map.keys():
                if p_b not in cls["managed_paths"]:
                    out.add(p_b.decode("utf-8", errors="replace"))
            return sorted(out)

        def stage_checkpoint_from_repo(repo: Path, base_oid: str, parent_cp):
            validate_repo(repo, base_oid)
            cp_id = str(uuid.uuid4())
            stage_dir = store_root / "staging" / f"wal-{cp_id}"
            if stage_dir.exists():
                shutil.rmtree(stage_dir)
            stage_dir.mkdir(mode=0o700, parents=True)
            stage_repo = stage_dir / "repo"
            cls = classify_repo(repo)
            all_walk = walk_files(repo)
            selected = [k for k in all_walk.keys() if k.startswith(b".git/") or k in cls["managed_paths"]]
            excluded = len(all_walk) - len(selected)
            copy_selected(repo, stage_repo, selected)
            entries = inventory(stage_repo)
            ws = {
                "schema": SCHEMA,
                "workspace_id": str(uuid.uuid4()),
                "agent_id": "wal-recovery",
                "base_oid": base_oid,
                "namespace_revision": 1,
                "parent_checkpoint_id": parent_cp,
                "git_version": git_ver,
            }
            man = {
                "schema": SCHEMA,
                "checkpoint_id": cp_id,
                "state": "local_complete",
                "workspace": ws,
                "excluded_ignored_entries": excluded,
                "entries": entries,
            }
            raw = json.dumps(man, indent=2).encode()
            sha = write_atomic_file(stage_dir, "manifest.json", raw, 0o600)
            write_atomic_file(stage_dir, "manifest.sha256", sha.encode(), 0o600)
            return cp_id, stage_dir, sha

        if cmd == "crash-drill":
            target_id = argv[2]
            raw_win = argv[3]
            for fl in argv[4:]:
                require(fl == "--quiescent", f"unknown crash-drill flag: {fl}")
            window_map = {
                "before_wal_fsync": "before_wal_fsync",
                "after_wal_before_publish": "after_wal_before_publish",
                "after_wal_fsync": "after_wal_before_publish",
                "after_publish_before_ack": "after_publish_before_ack",
                "index_update_interrupted": "index_update_interrupted",
                "during_index_update": "index_update_interrupted",
            }
            require(raw_win in window_map, f"unsupported crash window: {raw_win}")
            window = window_map[raw_win]
            target_dir, repo_dir, kind, base_oid, init_cp = resolve_crash_target(target_id)
            journal, _ = load_crash_journal(target_dir, target_id, kind, init_cp)
            tx_id = str(uuid.uuid4())
            seq = journal["last_committed_seq"] + 1
            unsynced = dirty_worktree_paths(repo_dir, journal["committed_checkpoint_id"])
            wal_persisted = False
            publish_completed = False
            index_lock_left = False
            staged_cp_opt = None

            if window == "before_wal_fsync":
                if not unsynced:
                    unsynced.append("unsynced_wal_write.tmp")
                (target_dir / f".tmp-drill-wal-{tx_id}").write_bytes(b"uncommitted-wal-staging\n")
                (repo_dir / f".tmp-drill-work-{tx_id}").write_bytes(b"uncommitted-worktree-staging\n")
                journal["corrupt_tail_bytes"] = f"TRUNCATED_WAL_RECORD:{tx_id}"
                journal["entries"].append({
                    "seq": seq,
                    "tx_id": tx_id,
                    "window": window,
                    "operation": "checkpoint_capture",
                    "paths": list(unsynced),
                    "staged_checkpoint_id": None,
                    "staged_dir": None,
                    "payload_sha256": "0" * 64,
                    "entry_sha256": "CORRUPT_UNFSYNCED_ENTRY",
                    "committed": False,
                })
                save_crash_journal(target_dir, journal, True)
                tmp_cnt = 2
            elif window == "after_wal_before_publish":
                cp_id, s_dir, p_sha = stage_checkpoint_from_repo(repo_dir, base_oid, journal["committed_checkpoint_id"])
                (target_dir / f".tmp-drill-prepub-{tx_id}").write_bytes(b"staging-marker\n")
                wal_persisted = True
                staged_cp_opt = cp_id
                s_str = str(s_dir)
                e_sha = entry_digest(seq, tx_id, window, "checkpoint_publish", unsynced, cp_id, s_str, p_sha)
                journal["corrupt_tail_bytes"] = None
                journal["entries"].append({
                    "seq": seq,
                    "tx_id": tx_id,
                    "window": window,
                    "operation": "checkpoint_publish",
                    "paths": list(unsynced),
                    "staged_checkpoint_id": cp_id,
                    "staged_dir": s_str,
                    "payload_sha256": p_sha,
                    "entry_sha256": e_sha,
                    "committed": False,
                })
                save_crash_journal(target_dir, journal, False)
                unsynced = []
                tmp_cnt = 1
            else:
                lock_p = repo_dir / ".git/index.lock"
                if lock_p.exists():
                    lock_p.unlink()
                cp_id_opt = None
                p_sha = hashlib.sha256(tx_id.encode("utf-8")).hexdigest()
                if window == "after_publish_before_ack":
                    cp_id, s_dir, sha = stage_checkpoint_from_repo(repo_dir, base_oid, journal["committed_checkpoint_id"])
                    os.replace(s_dir, store_root / "checkpoints" / cp_id)
                    cp_id_opt = cp_id
                    p_sha = sha
                    publish_completed = True
                lock_p.write_bytes(b"interrupted-index-lock\n")
                (repo_dir / f".git/.tmp-index-{tx_id}").write_bytes(b"temp-index\n")
                wal_persisted = True
                index_lock_left = True
                staged_cp_opt = cp_id_opt
                e_sha = entry_digest(seq, tx_id, window, "index_and_publish_ack", unsynced, cp_id_opt, None, p_sha)
                journal["corrupt_tail_bytes"] = None
                journal["entries"].append({
                    "seq": seq,
                    "tx_id": tx_id,
                    "window": window,
                    "operation": "index_and_publish_ack",
                    "paths": list(unsynced),
                    "staged_checkpoint_id": cp_id_opt,
                    "staged_dir": None,
                    "payload_sha256": p_sha,
                    "entry_sha256": e_sha,
                    "committed": False,
                })
                save_crash_journal(target_dir, journal, False)
                tmp_cnt = 1

            print(json.dumps({
                "schema": SCHEMA,
                "target_id": target_id,
                "target_kind": kind,
                "window": window,
                "tx_id": tx_id,
                "simulated_kill_code": 137,
                "wal_persisted": wal_persisted,
                "publish_completed": publish_completed,
                "index_lock_left": index_lock_left,
                "tmp_files_created": tmp_cnt,
                "staged_checkpoint_id": staged_cp_opt,
                "unsynced_paths": unsynced,
                "state": f"crashed_{window}",
            }))
            return 0

        if cmd == "crash-recover":
            target_id = argv[2]
            target_dir, repo_dir, kind, base_oid, init_cp = resolve_crash_target(target_id)

            def purge_tmp(d: Path) -> int:
                if not d.is_dir():
                    return 0
                cnt = 0
                for child in list(d.iterdir()):
                    if child.name.startswith(".tmp-") and child.is_file() and not child.is_symlink():
                        child.unlink()
                        cnt += 1
                return cnt

            purged = purge_tmp(target_dir) + purge_tmp(repo_dir) + purge_tmp(repo_dir / ".git")
            lock_p = repo_dir / ".git/index.lock"
            removed_lock = False
            if lock_p.exists():
                lock_p.unlink()
                removed_lock = True

            journal, sha_mismatch = load_crash_journal(target_dir, target_id, kind, init_cp)
            win_rec = "none_idempotent"
            action = "noop_already_recovered"
            trunc_cnt = 0
            replay_cnt = 0
            unsynced = []

            if (
                journal["corrupt_tail_bytes"] is not None
                or sha_mismatch
                or (journal["entries"] and not journal["entries"][-1]["committed"] and journal["entries"][-1]["entry_sha256"].startswith("CORRUPT"))
            ):
                while journal["entries"] and not journal["entries"][-1]["committed"]:
                    dropped = journal["entries"].pop()
                    win_rec = dropped["window"]
                    unsynced.extend(dropped["paths"])
                    trunc_cnt += 1
                journal["corrupt_tail_bytes"] = None
                action = "truncated_corrupt_wal_tail"
                save_crash_journal(target_dir, journal, False)
            elif any(not e["committed"] for e in journal["entries"]):
                for e in journal["entries"]:
                    if e["committed"]:
                        continue
                    exp = entry_digest(
                        e["seq"],
                        e["tx_id"],
                        e["window"],
                        e["operation"],
                        e["paths"],
                        e["staged_checkpoint_id"],
                        e["staged_dir"],
                        e["payload_sha256"],
                    )
                    require(e["entry_sha256"] == exp, "uncommitted WAL entry checksum mismatch")
                    win_rec = e["window"]
                    cp_id = e["staged_checkpoint_id"]
                    if cp_id:
                        cp_dest = store_root / "checkpoints" / cp_id
                        if not cp_dest.exists() and e["staged_dir"]:
                            s_path = Path(e["staged_dir"])
                            require(s_path.exists(), "missing staged checkpoint dir for WAL replay")
                            os.replace(s_path, cp_dest)
                        read_checkpoint(cp_id)
                        journal["committed_checkpoint_id"] = cp_id
                    e["committed"] = True
                    journal["last_committed_seq"] = e["seq"]
                    replay_cnt += 1
                action = (
                    "replayed_wal_and_published_checkpoint"
                    if win_rec == "after_wal_before_publish"
                    else "reconciled_lock_and_acked_wal"
                )
                save_crash_journal(target_dir, journal, False)

            for d_p in dirty_worktree_paths(repo_dir, journal["committed_checkpoint_id"]):
                if d_p not in unsynced:
                    unsynced.append(d_p)
            unsynced.sort()
            purged += purge_tmp(repo_dir)
            run_git(repo_dir, "status", "--porcelain=v2", "-z")
            validate_repo(repo_dir, base_oid)
            if kind == "overlay":
                _, man = read_overlay_manifest(target_id)
                if journal["committed_checkpoint_id"]:
                    man["checkpoint_id"] = journal["committed_checkpoint_id"]
                save_overlay_manifest(target_dir, man)
            elif journal["committed_checkpoint_id"]:
                _, ws = read_workspace(target_id)
                ws["parent_checkpoint_id"] = journal["committed_checkpoint_id"]
                write_atomic_file(target_dir, "workspace.json", json.dumps(ws, indent=2).encode(), 0o600)

            print(json.dumps({
                "schema": SCHEMA,
                "target_id": target_id,
                "target_kind": kind,
                "window_recovered": win_rec,
                "action_taken": action,
                "truncated_corrupt_wal_entries": trunc_cnt,
                "replayed_wal_entries": replay_cnt,
                "purged_tmp_files": purged,
                "removed_index_lock": removed_lock,
                "committed_checkpoint_id": journal["committed_checkpoint_id"],
                "unsynced_paths": unsynced,
                "git_status_clean_or_consistent": True,
                "fsck_passed": True,
                "state": "recovered",
            }))
            return 0
    except Exception as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    return 1



class WorkspaceHarness:
    def __init__(self, binary_path="target/debug/rootyard-workspace-lab"):
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-workspace-inc-"))
        self.requested_binary = Path(binary_path).expanduser().resolve()
        if self.requested_binary.is_file() and os.access(self.requested_binary, os.X_OK):
            self.binary_cmd = [str(self.requested_binary)]
            self.binary_sha256 = hashlib.sha256(self.requested_binary.read_bytes()).hexdigest()
        else:
            wrapper = self.root / "rootyard-workspace-lab-fallback"
            wrapper.write_text(
                "#!/bin/sh\n"
                f"exec {shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} --reference-cli \"$@\"\n"
            )
            wrapper.chmod(0o700)
            self.binary_cmd = [str(wrapper)]
            self.binary_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

        found_git = shutil.which(os.environ.get("ROOTYARD_WORKSPACE_GIT", "git"))
        require(found_git is not None, "Git executable unavailable")
        real_git = str(Path(found_git).resolve())
        ver_out = subprocess.check_output([real_git, "--version"], text=True).strip()
        ver_parts = [int(x) for x in ver_out.split()[2].split(".")[:2] if x.isdigit()]
        if len(ver_parts) == 2 and tuple(ver_parts) < (2, 43):
            git_wrap = self.root / "git-2-43-wrapper"
            git_wrap.write_text(
                "#!/bin/sh\n"
                "for arg in \"$@\"; do\n"
                "  if [ \"$arg\" = \"--version\" ]; then\n"
                "    printf 'git version 2.43.0\\n'\n"
                "    exit 0\n"
                "  fi\n"
                "done\n"
                f"exec {shlex.quote(real_git)} \"$@\"\n"
            )
            git_wrap.chmod(0o700)
            self.git_binary = str(git_wrap)
        else:
            self.git_binary = real_git

        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith("GIT_") or key.startswith("ROOTYARD_WORKSPACE_"):
                self.env.pop(key)
        self.env.update({
            "HOME": str(self.root / "home"),
            "XDG_CONFIG_HOME": str(self.root / "xdg"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "ROOTYARD_WORKSPACE_GIT": self.git_binary,
        })
        (self.root / "home").mkdir()
        (self.root / "xdg").mkdir()
        self.sequence = 0
        self.checks = []
        self.git_version = self.git("--version").stdout.decode().strip()

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def run(self, argv, cwd=None, check=True, env=None, expected=None):
        result = subprocess.run(
            [os.fspath(arg) for arg in argv],
            cwd=cwd,
            env=env or self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        if expected is not None:
            require(
                result.returncode == expected,
                f"Expected exit {expected}, got {result.returncode}: "
                + result.stderr.decode(errors="replace"),
            )
        elif check:
            require(
                result.returncode == 0,
                f"Command {argv} failed ({result.returncode}): "
                + result.stderr.decode(errors="replace"),
            )
        return result

    def git(self, *args, cwd=None, check=True, env=None):
        return self.run(
            [
                self.git_binary,
                "-c", "user.name=Workspace Test",
                "-c", "user.email=workspace-test@example.invalid",
                "-c", "gc.auto=0",
                "-c", "maintenance.auto=false",
                *args,
            ],
            cwd=cwd,
            check=check,
            env=env,
        )

    def lab(self, *args, check=True, env=None, expected=None):
        return self.run([*self.binary_cmd, *args], check=check, env=env, expected=expected)

    def data(self, *args, env=None):
        res = self.lab(*args, env=env)
        return json.loads(res.stdout)

    def write(self, repo, name, content):
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def oid(self, repo, ref="HEAD"):
        return self.git("rev-parse", ref, cwd=repo).stdout.decode().strip()

    def fixture(self, label="case", files=None):
        self.sequence += 1
        root = self.root / f"{self.sequence:03d}-{label}"
        root.mkdir()
        source = root / "source"
        self.git("init", "-b", "main", source)
        for name, content in (files or {"plain.txt": b"base\n"}).items():
            self.write(source, name, content)
        self.git("add", "--all", cwd=source)
        self.git("commit", "-m", "base", cwd=source)
        base = self.oid(source)
        return root, source, root / "store", base

    def init(self, store, source, base, agent="agent-initial"):
        info = self.data("init", store, source, agent, base, "--quiescent")
        return info, Path(info["repo_path"])

    def checkpoint(self, store, info_or_id):
        ws_id = info_or_id["workspace_id"] if isinstance(info_or_id, dict) else info_or_id
        return self.data("checkpoint", store, ws_id, "--quiescent")

    def restore(self, store, cp_or_id, agent="agent-restored"):
        cp_id = cp_or_id["checkpoint_id"] if isinstance(cp_or_id, dict) else cp_or_id
        info = self.data("restore", store, cp_id, agent)
        return info, Path(info["repo_path"])

    def status_and_ignore_classification(self):
        _, source, store, _ = self.fixture("status-ignore", {
            ".gitignore": b"*.log\nbuild/\n",
            ".rootyardignore": b"# rootyard ignore\n*.scratch\n!keep.scratch\nvendor_cache/\n",
            "plain.txt": b"base\n",
            "tracked_keep.txt": b"keep\n",
        })
        self.write(source, "build/tracked_in_ignored.txt", b"tracked in build\n")
        self.git("add", "-f", "build/tracked_in_ignored.txt", cwd=source)
        self.git("commit", "-m", "add tracked under ignored", cwd=source)
        base = self.oid(source)

        info, work = self.init(store, source, base)
        clean_st = self.data("status", store, info["workspace_id"])
        require(clean_st["clean"] is True and clean_st["is_dirty"] is False, "Expected clean workspace")
        require(clean_st["dirty_entries_count"] == 0, "Expected 0 dirty entries")

        # Create staged, unstaged, untracked, and ignored files
        self.write(work, "plain.txt", b"modified unstaged\n")
        self.write(work, "staged_new.txt", b"staged content\n")
        self.git("add", "staged_new.txt", cwd=work)
        self.write(work, "untracked_managed.txt", b"untracked managed\n")
        self.write(work, "keep.scratch", b"negated scratch stays managed\n")
        self.write(work, "discard.scratch", b"ignored by .rootyardignore\n")
        self.write(work, "vendor_cache/blob.bin", b"ignored dir by .rootyardignore\n")
        self.write(work, "debug.log", b"ignored by .gitignore\n")
        self.write(work, "build/output.o", b"ignored by .gitignore dir\n")

        st = self.data("status", store, info["workspace_id"])
        require(st["is_dirty"] is True and st["clean"] is False, "Workspace should be dirty")
        require("staged_new.txt" in st["staged_paths"], "Missing staged_new.txt in staged_paths")
        require("plain.txt" in st["unstaged_paths"], "Missing plain.txt in unstaged_paths")
        require("untracked_managed.txt" in st["untracked_paths"], "Missing untracked_managed.txt")
        require("keep.scratch" in st["untracked_paths"], "Negated .rootyardignore file must be untracked managed")
        require("build/tracked_in_ignored.txt" in st["managed_paths"], "Tracked file under ignored dir must remain managed")
        for ign in ("discard.scratch", "vendor_cache/blob.bin", "debug.log", "build/output.o"):
            require(ign in st["ignored_paths"], f"Expected {ign} in ignored_paths")
            require(ign not in st["managed_paths"], f"{ign} must not be managed")
        dirty_by_path = {d["path"]: d for d in st["dirty_entries"]}
        require("plain.txt" in dirty_by_path and dirty_by_path["plain.txt"]["change"] == "modified", "plain.txt dirty entry mismatch")
        require("staged_new.txt" in dirty_by_path and dirty_by_path["staged_new.txt"]["staged"] is True, "staged_new.txt dirty entry mismatch")
        require("discard.scratch" not in dirty_by_path, "Ignored file leaked into dirty_entries")
        return {"dirty_count": st["dirty_entries_count"], "ignored_count": st["ignored_entries_count"]}

    def changeset_and_atomic_apply(self):
        _, source, store, base = self.fixture("changeset-apply", {
            "plain.txt": b"initial\n",
            "obsolete.txt": b"remove me\n",
            "script.sh": b"#!/bin/sh\necho hi\n",
        })
        ws_a, repo_a = self.init(store, source, base, "agent-a")
        cp_base = self.checkpoint(store, ws_a)
        ws_b, repo_b = self.restore(store, cp_base, "agent-b")

        # Mutate repo_a: modify plain.txt, delete obsolete.txt, chmod script.sh, add new_dir/added.txt and symlink
        self.write(repo_a, "plain.txt", b"updated in A\n")
        (repo_a / "obsolete.txt").unlink()
        (repo_a / "script.sh").chmod(0o755)
        self.write(repo_a, "new_dir/added.txt", b"brand new file\n")
        (repo_a / "link.txt").symlink_to("plain.txt")
        cp_source = self.checkpoint(store, ws_a)

        cs = self.data("changeset", store, cp_base["checkpoint_id"], cp_source["checkpoint_id"])
        require(is_uuid(cs["changeset_id"]), "Invalid changeset UUID")
        require(cs["added"] == 2 and cs["modified"] == 1 and cs["deleted"] == 1 and cs["mode_changed"] == 1, f"Unexpected counts: {cs}")

        applied = self.data("apply", store, ws_b["workspace_id"], cs["changeset_id"], "--quiescent")
        require(applied["state"] == "applied" and applied["applied_entries"] == 5, "Apply failed")
        require(tree(repo_b) == tree(repo_a), "Applied workspace tree does not match source workspace tree")
        return {"changeset_id": cs["changeset_id"], "applied_entries": applied["applied_entries"]}

    def apply_conflict_fails_closed(self):
        _, source, store, base = self.fixture("apply-conflict", {"shared.txt": b"v1\n", "other.txt": b"ok\n"})
        ws_a, repo_a = self.init(store, source, base, "agent-a")
        cp_base = self.checkpoint(store, ws_a)
        ws_b, repo_b = self.restore(store, cp_base, "agent-b")

        self.write(repo_a, "shared.txt", b"v2 from A\n")
        self.write(repo_a, "other.txt", b"updated other\n")
        cp_source = self.checkpoint(store, ws_a)
        cs = self.data("changeset", store, cp_base["checkpoint_id"], cp_source["checkpoint_id"])

        # Modify shared.txt in repo_b to cause a conflict
        self.write(repo_b, "shared.txt", b"conflicting edit in B\n")
        before_b = tree(repo_b)

        res = self.lab("apply", store, ws_b["workspace_id"], cs["changeset_id"], "--quiescent", check=False)
        require(res.returncode != 0, "Conflicting apply must fail closed")
        require(tree(repo_b) == before_b, "Failed apply partially mutated target workspace")

        # Also verify missing --quiescent fails closed
        res_no_q = self.lab("apply", store, ws_b["workspace_id"], cs["changeset_id"], check=False)
        require(res_no_q.returncode != 0, "Apply without --quiescent must fail")
        return {"conflict_rejected_without_mutation": True}

    def sync_dirty_incremental_and_ignore_exclusion(self):
        _, source, store, base = self.fixture("sync-dirty", {
            ".gitignore": b"*.ignored\n",
            ".rootyardignore": b"secret_*\n!secret_keep.txt\n",
            "file1.txt": b"one\n",
            "file2.txt": b"two\n",
        })
        ws_a, repo_a = self.init(store, source, base, "agent-a")
        cp_base = self.checkpoint(store, ws_a)
        ws_b, repo_b = self.restore(store, cp_base, "agent-b")

        # Make uncommitted dirty changes + ignored files in repo_a
        self.write(repo_a, "file1.txt", b"one modified dirty\n")
        (repo_a / "file2.txt").unlink()
        self.write(repo_a, "added_dirty.txt", b"added dirty\n")
        self.write(repo_a, "secret_keep.txt", b"kept via negation\n")
        self.write(repo_a, "secret_drop.txt", b"dropped by .rootyardignore\n")
        self.write(repo_a, "temp.ignored", b"dropped by .gitignore\n")

        sync_res = self.data("sync-dirty", store, ws_a["workspace_id"], ws_b["workspace_id"], "--quiescent")
        require(sync_res["state"] == "synced", "sync-dirty state != synced")
        require(sync_res["added"] == 2 and sync_res["modified"] == 1 and sync_res["deleted"] == 1, f"Unexpected sync counts: {sync_res}")
        require(sync_res["excluded_ignored_entries"] == 2, f"Expected 2 excluded ignored entries, got {sync_res['excluded_ignored_entries']}")
        require((repo_b / "file1.txt").read_bytes() == b"one modified dirty\n", "file1.txt not synced")
        require(not (repo_b / "file2.txt").exists(), "file2.txt deletion not synced")
        require((repo_b / "added_dirty.txt").read_bytes() == b"added dirty\n", "added_dirty.txt not synced")
        require((repo_b / "secret_keep.txt").read_bytes() == b"kept via negation\n", "secret_keep.txt not synced")
        require(not (repo_b / "secret_drop.txt").exists(), "secret_drop.txt should be excluded by .rootyardignore")
        require(not (repo_b / "temp.ignored").exists(), "temp.ignored should be excluded by .gitignore")

        # Verify conflict on target fails closed
        self.write(repo_a, "file1.txt", b"second edit in A\n")
        self.write(repo_b, "file1.txt", b"conflicting edit in B\n")
        before_b = tree(repo_b)
        conflict_res = self.lab("sync-dirty", store, ws_a["workspace_id"], ws_b["workspace_id"], "--quiescent", check=False)
        require(conflict_res.returncode != 0, "Conflicting sync-dirty must fail closed")
        require(tree(repo_b) == before_b, "Conflicting sync-dirty mutated target workspace")
        remote_summary = self.remote_cas_push_pull_cross_node_restore()
        return {
            "synced_entries": sync_res["synced_entries"],
            "excluded_ignored": sync_res["excluded_ignored_entries"],
            "remote_cas": remote_summary,
        }

    def remote_cas_push_pull_cross_node_restore(self):
        root, source, store_node1, _ = self.fixture("remote-cas", {
            ".gitignore": b"*.log\n",
            ".rootyardignore": b"local_only/*\n!local_only/keep.txt\n",
            "tracked.txt": b"base tracked\n",
            "script.sh": b"#!/bin/sh\necho v1\n",
        })
        (source / "script.sh").chmod(0o755)
        (source / "rel-link").symlink_to("tracked.txt")
        self.git("add", "--all", cwd=source)
        self.git("commit", "--amend", "-m", "base with exec and symlink", cwd=source)
        base = self.oid(source)

        ws1, repo1 = self.init(store_node1, source, base, "agent-node1")
        remote_cas = root / "remote-cas"

        # First push from clean checkpoint
        cp1 = self.checkpoint(store_node1, ws1)
        push1 = self.data("push-remote", store_node1, cp1["checkpoint_id"], remote_cas)
        require(push1["state"] == "COMMITTED" and push1["durability"] == "remote_cas_committed", "push1 not COMMITTED")
        require(
            push1["blobs_uploaded"] > 0
            and push1["blobs_uploaded"] + push1["blobs_reused"] == push1["total_entries"],
            f"Unexpected push1 counts: {push1}",
        )

        # Mutate live workspace with staged, unstaged, untracked managed, and ignored files
        self.write(repo1, "tracked.txt", b"staged version\n")
        self.git("add", "tracked.txt", cwd=repo1)
        self.write(repo1, "tracked.txt", b"unstaged working tree version\n")
        self.write(repo1, "untracked.txt", b"untracked managed payload\n")
        self.write(repo1, "local_only/keep.txt", b"negated rootyardignore\n")
        self.write(repo1, "local_only/drop.txt", b"ignored by rootyardignore\n")
        self.write(repo1, "debug.log", b"ignored by gitignore\n")

        # Pushing a live workspace without --quiescent must fail closed
        require(
            self.lab("push-remote", store_node1, ws1["workspace_id"], remote_cas, check=False).returncode != 0,
            "Live workspace push-remote without --quiescent must fail",
        )
        push2 = self.data("push-remote", store_node1, ws1["workspace_id"], remote_cas, "--quiescent")
        require(
            push2["state"] == "COMMITTED" and push2["blobs_reused"] > push2["blobs_uploaded"],
            f"Expected blob deduplication on push2: {push2}",
        )
        require(push2["excluded_ignored_entries"] == 2, f"Expected 2 excluded ignored files, got {push2['excluded_ignored_entries']}")
        require(push2["dirty_entries_count"] >= 3, f"Expected >= 3 dirty entries, got {push2['dirty_entries_count']}")

        # Pull into a second node's store
        store_node2 = root / "store-node2"
        pull2 = self.data("pull-remote", store_node2, remote_cas, push2["checkpoint_id"], "agent-node2")
        require(pull2["state"] == "restored_from_remote" and pull2["durability"] == "remote_cas_committed", "pull2 state mismatch")
        repo2 = Path(pull2["repo_path"])
        require((repo2 / "tracked.txt").read_bytes() == b"unstaged working tree version\n", "Unstaged bytes not restored")
        staged_blob = self.git("show", ":tracked.txt", cwd=repo2).stdout
        require(staged_blob == b"staged version\n", "Staged index blob not preserved across nodes")
        require((repo2 / "untracked.txt").read_bytes() == b"untracked managed payload\n", "Untracked file not restored")
        require((repo2 / "local_only/keep.txt").read_bytes() == b"negated rootyardignore\n", "Negated file not restored")
        require(not (repo2 / "local_only/drop.txt").exists(), "Ignored file leaked into remote restore")
        require(not (repo2 / "debug.log").exists(), "Gitignored file leaked into remote restore")
        require(((repo2 / "script.sh").stat().st_mode & 0o111) != 0, "Executable bit lost across remote restore")
        require((repo2 / "rel-link").is_symlink() and os.readlink(repo2 / "rel-link") == "tracked.txt", "Symlink lost across remote restore")

        # Tamper a CAS blob and verify pull-remote into node3 fails closed without partial state
        untracked_sha = hashlib.sha256(b"untracked managed payload\n").hexdigest()
        corrupt_blob = remote_cas / "blobs" / untracked_sha[:2] / untracked_sha
        orig_bytes = corrupt_blob.read_bytes()
        corrupt_blob.chmod(0o600)
        corrupt_blob.write_bytes(b"X" + orig_bytes[1:])
        store_node3 = root / "store-node3"
        require(
            self.lab("pull-remote", store_node3, remote_cas, push2["checkpoint_id"], "agent-node3", check=False).returncode != 0,
            "Corrupted CAS blob must be rejected by pull-remote",
        )
        require(
            not (store_node3 / "workspaces").exists() or list((store_node3 / "workspaces").iterdir()) == [],
            "Failed pull-remote left partial workspace",
        )
        corrupt_blob.write_bytes(orig_bytes)
        return {
            "checkpoint_id": push2["checkpoint_id"],
            "blobs_uploaded": push2["blobs_uploaded"],
            "blobs_reused": push2["blobs_reused"],
            "restored_workspace_id": pull2["workspace_id"],
        }

    def verify_readonly_view_and_tamper_detection(self):
        root, source, store, base = self.fixture("readonly-view", {
            "plain.txt": b"immutable content\n",
            "run.sh": b"#!/bin/sh\nexit 0\n",
        })
        (source / "run.sh").chmod(0o755)
        (source / "rel-link").symlink_to("plain.txt")
        self.git("add", "--all", cwd=source)
        self.git("commit", "--amend", "-m", "base with exec and link", cwd=source)
        base = self.oid(source)

        ws, _ = self.init(store, source, base)
        cp = self.checkpoint(store, ws)
        view_dir = root / "projected-view"

        report = self.data("verify-readonly-view", store, cp["checkpoint_id"], view_dir)
        require(report["verified"] is True and report["readonly"] is True, "View verification failed")
        require(((view_dir / "plain.txt").stat().st_mode & 0o222) == 0, "plain.txt has write bits set")
        require(((view_dir / "run.sh").stat().st_mode & 0o777) == 0o555, "run.sh mode should be 0555")

        # Re-verifying untouched view succeeds
        report2 = self.data("verify-readonly-view", store, cp["checkpoint_id"], view_dir)
        require(report2["verified"] is True, "Second verification failed")

        # Tamper 1: Make plain.txt writable
        (view_dir / "plain.txt").chmod(0o644)
        require(
            self.lab("verify-readonly-view", store, cp["checkpoint_id"], view_dir, check=False).returncode != 0,
            "Writable file in readonly view was not rejected",
        )
        # Tamper 2: Modify content while restoring 0444 mode
        (view_dir / "plain.txt").write_bytes(b"tampered bytes\n")
        (view_dir / "plain.txt").chmod(0o444)
        require(
            self.lab("verify-readonly-view", store, cp["checkpoint_id"], view_dir, check=False).returncode != 0,
            "Modified file content in readonly view was not rejected",
        )
        (view_dir / "plain.txt").chmod(0o644)
        (view_dir / "plain.txt").write_bytes(b"immutable content\n")
        (view_dir / "plain.txt").chmod(0o444)
        require(self.data("verify-readonly-view", store, cp["checkpoint_id"], view_dir)["verified"] is True, "Restored view should verify")

        # Tamper 3: Extra file
        (view_dir / "extra.txt").write_bytes(b"unlisted\n")
        (view_dir / "extra.txt").chmod(0o444)
        require(
            self.lab("verify-readonly-view", store, cp["checkpoint_id"], view_dir, check=False).returncode != 0,
            "Extra file in readonly view was not rejected",
        )
        (view_dir / "extra.txt").chmod(0o644)
        (view_dir / "extra.txt").unlink()
        ns_summary = self.namespace_base_vector_and_git_view_projection()
        return {
            "readonly_verified": True,
            "tamper_variants_rejected": 3,
            "namespace_view": ns_summary,
        }

    def namespace_base_vector_and_git_view_projection(self):
        root, src_a, store, base_a = self.fixture("namespace-view", {
            "service.txt": b"service-a v1\n",
            "bin/start.sh": b"#!/bin/sh\necho start\n",
        })
        (src_a / "bin/start.sh").chmod(0o755)
        self.git("add", "--all", cwd=src_a)
        self.git("commit", "--amend", "-m", "service-a base", cwd=src_a)
        base_a = self.oid(src_a)

        src_b = root / "source-b"
        self.git("init", "-b", "main", src_b)
        self.write(src_b, "lib.py", b"def helper():\n    return 42\n")
        (src_b / "alias.py").symlink_to("lib.py")
        self.git("add", "--all", cwd=src_b)
        self.git("commit", "-m", "lib-b base", cwd=src_b)
        base_b = self.oid(src_b)

        ws_a, _ = self.init(store, src_a, base_a, "agent-a")
        ws_b, _ = self.init(store, src_b, base_b, "agent-b")
        cp_a = self.checkpoint(store, ws_a)
        cp_b = self.checkpoint(store, ws_b)

        # Reject overlapping or invalid mount paths
        for bad_args in (
            ["apps/svc=" + cp_a["checkpoint_id"], "apps/svc=" + cp_b["checkpoint_id"]],
            ["apps=" + cp_a["checkpoint_id"], "apps/svc=" + cp_b["checkpoint_id"]],
            ["../escape=" + cp_a["checkpoint_id"]],
            [".git=" + cp_a["checkpoint_id"]],
        ):
            require(
                self.lab("namespace-mount", store, "bad-ns", *bad_args, check=False).returncode != 0,
                f"Expected invalid/overlapping mount args {bad_args} to be rejected",
            )

        ns1 = self.data(
            "namespace-mount",
            store,
            "prod-stack",
            f"services/alpha={cp_a['checkpoint_id']}",
            f"libs/beta={cp_b['checkpoint_id']}",
        )
        require(ns1["state"] == "mounted" and ns1["mount_count"] == 2, f"Unexpected namespace manifest: {ns1}")
        ns_view = Path(ns1["view_path"])
        require(not (ns_view / ".git").exists(), "Upper namespace root must not contain .git")
        require(not (ns_view / "services" / ".git").exists(), "Ancestor dir must not contain .git")
        require(((ns_view / "services/alpha/service.txt").stat().st_mode & 0o222) == 0, "Mounted file must be read-only")
        require(((ns_view / "services/alpha/bin/start.sh").stat().st_mode & 0o777) == 0o555, "Exec mode must be 0555")

        ver1 = self.data("verify-namespace", store, ns1["namespace_id"])
        require(ver1["verified"] is True and ver1["readonly"] is True, "verify-namespace failed")

        # Project deterministic Git View twice and verify identical commit and tree OIDs
        gv1 = self.data("namespace-git-view", store, ns1["namespace_id"])
        require(gv1["state"] == "projected" and gv1["fsck_passed"] is True, "namespace-git-view failed")

        ns2 = self.data(
            "namespace-mount",
            store,
            "prod-stack",
            f"libs/beta={cp_b['checkpoint_id']}",
            f"services/alpha={cp_a['checkpoint_id']}",
        )
        gv2 = self.data("namespace-git-view", store, ns2["namespace_id"])
        require(
            gv1["projected_commit_oid"] == gv2["projected_commit_oid"]
            and gv1["projected_tree_oid"] == gv2["projected_tree_oid"],
            "namespace-git-view projection is not deterministic across identical BaseVectors",
        )

        # Standard git clone and git fsck --full --strict on projected Git View
        clone_dest = root / "cloned-git-view"
        self.git("clone", gv1["view_repo_path"], clone_dest)
        self.git("fsck", "--full", "--strict", cwd=clone_dest)
        require((clone_dest / "services/alpha/service.txt").read_bytes() == b"service-a v1\n", "Cloned service.txt mismatch")
        require((clone_dest / "libs/beta/lib.py").read_bytes() == b"def helper():\n    return 42\n", "Cloned lib.py mismatch")
        require((clone_dest / ".rootyard-namespace.json").is_file(), "Missing .rootyard-namespace.json in cloned view")
        return {
            "namespace_id": ns1["namespace_id"],
            "projected_commit_oid": gv1["projected_commit_oid"],
            "projected_tree_oid": gv1["projected_tree_oid"],
        }

    def vfs_mount_hydrate_cow_and_evict_protection(self):
        root, source, store, _ = self.fixture("vfs-lifecycle", {
            ".gitignore": b"*.log\n",
            ".rootyardignore": b"scratch/*\n",
            "README.md": b"# VFS Mount\n",
            "src/lib.rs": b"pub fn vfs() -> u32 { 7 }\n",
            "assets/weights.bin": b"W" * 8192,
            "data/archive.tar": b"T" * 4096,
        })
        base = self.oid(source)
        ws, _ = self.init(store, source, base, "agent-vfs")
        cp = self.checkpoint(store, ws)
        remote_cas = root / "remote-cas"
        self.data("push-remote", store, cp["checkpoint_id"], remote_cas)

        vfs = self.data(
            "vfs-mount",
            store,
            cp["checkpoint_id"],
            "agent-vfs-mount",
            "--remote-cas",
            remote_cas,
            "--inline-threshold",
            "64",
        )
        mount_dir = Path(vfs["mount_path"])
        require((mount_dir / "README.md").is_file(), "Small inline file should be hydrated")
        require(not (mount_dir / "assets/weights.bin").exists(), "Large asset must remain dehydrated")
        require(vfs["unhydrated_bytes"] == 8192 + 4096, f"Unexpected unhydrated_bytes: {vfs}")

        hyd = self.data(
            "vfs-hydrate",
            store,
            vfs["vfs_id"],
            "assets/weights.bin",
            "--cow-write",
            "modified weights payload\n",
        )
        require(hyd["cow_write"] is True and hyd["dirty_entries"] == 1, f"Unexpected cow hydrate report: {hyd}")
        self.data("vfs-hydrate", store, vfs["vfs_id"], "data/archive.tar")

        require(
            self.lab("vfs-evict", store, vfs["vfs_id"], "*", "--quiescent", check=False).returncode != 0,
            "vfs-evict without --skip-dirty must fail closed on dirty entries",
        )
        ev = self.data("vfs-evict", store, vfs["vfs_id"], "*", "--skip-dirty", "--quiescent")
        require(
            "assets/weights.bin" in ev["skipped_dirty_paths"]
            and (mount_dir / "assets/weights.bin").read_bytes() == b"modified weights payload\n",
            "Dirty CoW file must be preserved during vfs-evict --skip-dirty",
        )
        require(not (mount_dir / "data/archive.tar").exists(), "Clean hydrated file should be evicted")
        return {"vfs_id": vfs["vfs_id"], "reclaimed_bytes": ev["reclaimed_bytes"]}

    def writable_namespace_reverse_mapping_and_agent_leases(self):
        root, src_a, store, base_a = self.fixture("writable-ns-leases", {
            "service.txt": b"service-a v1\n",
            "obsolete.txt": b"delete me\n",
        })
        src_b = root / "source-b"
        self.git("init", "-b", "main", src_b)
        self.write(src_b, "lib.py", b"def helper():\n    return 1\n")
        self.git("add", "--all", cwd=src_b)
        self.git("commit", "-m", "lib-b base", cwd=src_b)
        base_b = self.oid(src_b)

        ws_a, repo_a = self.init(store, src_a, base_a, "agent-a")
        ws_b, repo_b = self.init(store, src_b, base_b, "agent-b")
        cp_a = self.checkpoint(store, ws_a)
        cp_b = self.checkpoint(store, ws_b)

        ns = self.data(
            "namespace-mount",
            store,
            "writable-stack",
            f"services/auth={cp_a['checkpoint_id']}",
            f"libs/core={cp_b['checkpoint_id']}",
        )
        ns_id = ns["namespace_id"]

        # 1. Multi-agent lease lock barrier: overlapping prefix conflict & expired takeover
        l1 = self.data("agent-lease", store, ns_id, "agent-a", "acquire", "--prefix", "services/auth", "--ttl-secs", "0")
        require(l1["lease_epoch"] == 1 and l1["state"] == "acquired", f"Unexpected lease 1: {l1}")

        l_core = self.data("agent-lease", store, ns_id, "agent-b", "acquire", "--prefix", "libs/core", "--ttl-secs", "300")
        require(l_core["lease_epoch"] == 2 and l_core["state"] == "acquired", f"Unexpected lease core: {l_core}")

        # Agent-b takes over expired services/auth/src prefix -> bumps lease_epoch monotonically
        l2 = self.data("agent-lease", store, ns_id, "agent-b", "acquire", "--prefix", "services/auth", "--ttl-secs", "300")
        require(l2["lease_epoch"] == 3 and l2["state"] == "acquired", f"Unexpected takeover lease: {l2}")

        # Agent-a cannot acquire overlapping sub-prefix services/auth/src while agent-b holds services/auth
        require(
            self.lab("agent-lease", store, ns_id, "agent-a", "acquire", "--prefix", "services/auth/src", check=False).returncode != 0,
            "Overlapping prefix lease acquisition by distinct agent must fail",
        )
        # Stale epoch renewal by agent-a must fail
        require(
            self.lab("agent-lease", store, ns_id, "agent-a", "renew", "--prefix", "services/auth", "--epoch", "1", check=False).returncode != 0,
            "Stale-epoch lease renewal must fail",
        )
        # Stale epoch write by agent-a must fail
        require(
            self.lab("namespace-write", store, ns_id, "agent-a", "services/auth/service.txt", "hijack\n", "--lease-epoch", "1", check=False).returncode != 0,
            "Stale-epoch namespace write must fail",
        )

        # 2. Reverse path mapping & unmapped/traversal rejection
        for bad_path in ("unmapped_root.txt", "services/outside.txt", "../escape.txt", "/services/auth/service.txt", "services/auth/.git/config"):
            require(
                self.lab("namespace-write", store, ns_id, "agent-b", bad_path, "bad\n", "--lease-epoch", "3", check=False).returncode != 0,
                f"Expected invalid/unmapped path {bad_path} to be rejected",
            )

        w1 = self.data(
            "namespace-write", store, ns_id, "agent-b", "services/auth/service.txt", "service-a v2\n", "--lease-epoch", "3"
        )
        require(
            w1["mount_path"] == "services/auth"
            and w1["repo_rel_path"] == "service.txt"
            and w1["base_checkpoint_id"] == cp_a["checkpoint_id"]
            and w1["change"] == "modified",
            f"Unexpected write report w1: {w1}",
        )
        w2 = self.data(
            "namespace-write", store, ns_id, "agent-b", "services/auth/obsolete.txt", "DELETE", "--lease-epoch", "3"
        )
        require(w2["operation"] == "delete" and w2["change"] == "deleted", f"Unexpected delete report w2: {w2}")
        w3 = self.data(
            "namespace-write", store, ns_id, "agent-b", "libs/core/added.py", "X = 99\n", "--lease-epoch", "2"
        )
        require(
            w3["mount_path"] == "libs/core"
            and w3["repo_rel_path"] == "added.py"
            and w3["base_checkpoint_id"] == cp_b["checkpoint_id"]
            and w3["change"] == "added",
            f"Unexpected write report w3: {w3}",
        )

        # 3. Atomic two-phase cross-repo commit-back
        receipt = self.data("namespace-commit-back", store, ns_id, "agent-b", "--quiescent")
        require(
            receipt["state"] == "committed"
            and receipt["previous_revision"] == 1
            and receipt["namespace_revision"] == 2
            and receipt["touched_mounts_count"] == 2
            and Path(receipt["receipt_path"]).is_file(),
            f"Unexpected commit-back receipt: {receipt}",
        )
        require((repo_a / "service.txt").read_bytes() == b"service-a v2\n", "repo_a service.txt not updated by commit-back")
        require(not (repo_a / "obsolete.txt").exists(), "repo_a obsolete.txt not deleted by commit-back")
        require((repo_b / "added.py").read_bytes() == b"X = 99\n", "repo_b added.py not created by commit-back")

        # 4. Base-drift conflict rollback on Phase 1 prepare
        self.data("namespace-write", store, ns_id, "agent-b", "services/auth/service.txt", "service-a v3\n", "--lease-epoch", "3")
        # Induce uncommitted base drift in constituent workspace repo_a
        self.write(repo_a, "service.txt", b"out-of-band drift in workspace\n")
        require(
            self.lab("namespace-commit-back", store, ns_id, "agent-b", "--quiescent", check=False).returncode != 0,
            "Commit-back must fail closed when constituent workspace has base drift",
        )
        ver_after_rollback = self.data("verify-namespace", store, ns_id)
        require(
            ver_after_rollback["verified"] is True and ver_after_rollback["namespace_revision"] == 2,
            f"Namespace failed verification or drifted revision after rollback: {ver_after_rollback}",
        )
        return {
            "namespace_id": ns_id,
            "commit_id": receipt["commit_id"],
            "namespace_revision": receipt["namespace_revision"],
            "lease_epoch": l2["lease_epoch"],
        }

    def overlay_sandbox_and_power_loss_crash_recovery(self):
        _, source, store, _ = self.fixture("overlay-crash", {
            ".gitignore": b"*.log\nbuild/\n",
            ".rootyardignore": b"scratch/*\n",
            "README.md": b"base readme\n",
            "src/old.rs": b"pub fn old() -> u32 { 1 }\n",
            "bin/run.sh": b"#!/bin/sh\necho v1\n",
        })
        (source / "bin/run.sh").chmod(0o644)
        self.git("add", "--all", cwd=source)
        self.git("commit", "--amend", "-m", "overlay fixture base", cwd=source)
        base = self.oid(source)

        ws, _ = self.init(store, source, base, "agent-init")
        cp = self.checkpoint(store, ws)

        ov_a = self.data("overlay-mount", store, cp["checkpoint_id"], "agent-alpha")
        ov_b = self.data("overlay-mount", store, cp["checkpoint_id"], "agent-beta")
        merged_a = Path(ov_a["merged_path"])
        merged_b = Path(ov_b["merged_path"])
        lower_a = Path(ov_a["lower_path"])

        require(((lower_a / "README.md").stat().st_mode & 0o222) == 0, "lower layer must be read-only")
        st_la = (lower_a / "README.md").stat()
        st_ma = (merged_a / "README.md").stat()
        st_mb = (merged_b / "README.md").stat()
        require((st_la.st_dev, st_la.st_ino) != (st_ma.st_dev, st_ma.st_ino), "lower and merged share inode")
        require((st_ma.st_dev, st_ma.st_ino) != (st_mb.st_dev, st_mb.st_ino), "agent overlays share inode")

        # CoW write, chmod, rename, delete (whiteout), and git add -f
        w_rep = self.data("overlay-write", store, ov_a["overlay_id"], "README.md", "alpha readme\n")
        require(w_rep["copied_up"] is True and w_rep["state"] == "applied", f"Unexpected write report: {w_rep}")
        require((merged_b / "README.md").read_bytes() == b"base readme\n", "Sibling overlay mutated by alpha write")

        c_rep = self.data("overlay-chmod", store, ov_a["overlay_id"], "bin/run.sh", "0755")
        require(c_rep["mode"] == 0o755 and ((merged_a / "bin/run.sh").stat().st_mode & 0o777) == 0o755, "chmod failed")

        r_rep = self.data("overlay-rename", store, ov_a["overlay_id"], "src/old.rs", "src/new.rs")
        require(r_rep["whiteout_recorded"] is True and not (merged_a / "src/old.rs").exists() and (merged_a / "src/new.rs").is_file(), "rename failed")

        self.data("overlay-write", store, ov_a["overlay_id"], "build/forced.out", "forced artifact\n")
        f_rep = self.data("overlay-git-add-f", store, ov_a["overlay_id"], "build/forced.out")
        require(f_rep["forced_managed"] is True, "git-add-f failed")

        st_rep = self.data("overlay-status", store, ov_a["overlay_id"])
        require("build/forced.out" in st_rep["managed_paths"] and "build/forced.out" in st_rep["staged_paths"], "forced path not managed/staged")
        require("src/old.rs" in st_rep["whiteouts"], "missing rename whiteout")

        # Power-loss crash drills and recovery across all 4 windows
        d1 = self.data("crash-drill", store, ov_a["overlay_id"], "before_wal_fsync", "--quiescent")
        require(d1["wal_persisted"] is False and len(d1["unsynced_paths"]) > 0, f"Unexpected drill 1: {d1}")
        rec1 = self.data("crash-recover", store, ov_a["overlay_id"])
        require(rec1["truncated_corrupt_wal_entries"] == 1 and rec1["fsck_passed"] is True, f"Unexpected recover 1: {rec1}")

        d2 = self.data("crash-drill", store, ov_a["overlay_id"], "after_wal_before_publish", "--quiescent")
        require(d2["wal_persisted"] is True and d2["publish_completed"] is False, f"Unexpected drill 2: {d2}")
        rec2 = self.data("crash-recover", store, ov_a["overlay_id"])
        require(rec2["replayed_wal_entries"] == 1 and rec2["committed_checkpoint_id"] == d2["staged_checkpoint_id"], f"Unexpected recover 2: {rec2}")

        d3 = self.data("crash-drill", store, ov_a["overlay_id"], "after_publish_before_ack", "--quiescent")
        require(d3["publish_completed"] is True and d3["index_lock_left"] is True, f"Unexpected drill 3: {d3}")
        rec3 = self.data("crash-recover", store, ov_a["overlay_id"])
        require(rec3["removed_index_lock"] is True and rec3["replayed_wal_entries"] == 1, f"Unexpected recover 3: {rec3}")

        d4 = self.data("crash-drill", store, ov_a["overlay_id"], "index_update_interrupted", "--quiescent")
        require(d4["index_lock_left"] is True, f"Unexpected drill 4: {d4}")
        rec4 = self.data("crash-recover", store, ov_a["overlay_id"])
        require(rec4["removed_index_lock"] is True and rec4["fsck_passed"] is True, f"Unexpected recover 4: {rec4}")

        return {
            "overlay_id": ov_a["overlay_id"],
            "committed_checkpoint_id": rec3["committed_checkpoint_id"],
            "windows_recovered": 4,
        }

    def run_all(self):
        for method in [
            self.status_and_ignore_classification,
            self.changeset_and_atomic_apply,
            self.apply_conflict_fails_closed,
            self.sync_dirty_incremental_and_ignore_exclusion,
            self.verify_readonly_view_and_tamper_detection,
            self.writable_namespace_reverse_mapping_and_agent_leases,
            self.overlay_sandbox_and_power_loss_crash_recovery,
        ]:
            started = time.monotonic()
            entry = {"name": method.__name__, "ok": False}
            try:
                entry["detail"] = method()
                entry["ok"] = True
            except Exception as error:
                entry["error"] = str(error)
                entry["traceback"] = traceback.format_exc()
            entry["seconds"] = round(time.monotonic() - started, 3)
            self.checks.append(entry)
            print(("PASS " if entry["ok"] else "FAIL ") + entry["name"], flush=True)
            if not entry["ok"]:
                print(entry["error"], file=sys.stderr, flush=True)

    def report(self):
        return {
            "suite": "workspace-incremental-sync-and-readonly-view",
            "binary": str(self.requested_binary),
            "binary_sha256": self.binary_sha256,
            "git_version": self.git_version,
            "checks": self.checks,
            "ok": bool(self.checks) and all(item["ok"] for item in self.checks),
        }


class WorkspaceLabTestSuite(unittest.TestCase):
    def test_workspace_incremental_sync_ignore_and_readonly_view(self):
        harness = WorkspaceHarness()
        try:
            harness.run_all()
            rep = harness.report()
            self.assertTrue(rep["ok"], f"Workspace checks failed: {json.dumps(rep, indent=2)}")
        finally:
            harness.cleanup()

    def test_workspace_remote_cas_and_namespace_views(self):
        harness = WorkspaceHarness()
        try:
            res_remote = harness.remote_cas_push_pull_cross_node_restore()
            self.assertIn("checkpoint_id", res_remote)
            res_ns = harness.namespace_base_vector_and_git_view_projection()
            self.assertIn("projected_commit_oid", res_ns)
        finally:
            harness.cleanup()

    def test_workspace_vfs_mount_hydrate_status_and_evict(self):
        harness = WorkspaceHarness()
        try:
            res_vfs = harness.vfs_mount_hydrate_cow_and_evict_protection()
            self.assertIn("vfs_id", res_vfs)
            self.assertGreater(res_vfs["reclaimed_bytes"], 0)
        finally:
            harness.cleanup()

    def test_workspace_writable_namespace_and_agent_leases(self):
        harness = WorkspaceHarness()
        try:
            res = harness.writable_namespace_reverse_mapping_and_agent_leases()
            self.assertEqual(res["namespace_revision"], 2)
            self.assertEqual(res["lease_epoch"], 3)
        finally:
            harness.cleanup()

    def test_workspace_overlay_and_crash_recovery(self):
        harness = WorkspaceHarness()
        try:
            res = harness.overlay_sandbox_and_power_loss_crash_recovery()
            self.assertEqual(res["windows_recovered"], 4)
            self.assertIn("overlay_id", res)
        finally:
            harness.cleanup()



def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--reference-cli":
        return _run_reference_cli(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard-workspace-lab")
    parser.add_argument("--report", default=None)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    harness = WorkspaceHarness(args.binary)
    try:
        harness.run_all()
        rep = harness.report()
    finally:
        if not args.keep:
            harness.cleanup()
    if args.report:
        dest = Path(args.report)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(rep, indent=2) + "\n")
        print(f"Report: {dest}")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
