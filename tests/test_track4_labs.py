import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zlib

from tests.workspace import WorkspaceHarness

ROOT = Path(__file__).resolve().parent.parent


def _git_object_oid(obj_type: str, data: bytes) -> str:
    header = f"{obj_type} {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _read_delta_varint(buf: bytes, pos: int):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7


def _apply_git_delta(base: bytes, delta: bytes, max_size: int) -> bytes:
    base_size, pos = _read_delta_varint(delta, 0)
    if base_size != len(base):
        raise ValueError("base size mismatch")
    target_size, pos = _read_delta_varint(delta, pos)
    if target_size > max_size:
        raise ValueError("target size exceeds limit")
    out = bytearray()
    while pos < len(delta):
        cmd = delta[pos]
        pos += 1
        if cmd & 0x80:
            cp_off = 0
            cp_size = 0
            for bit in range(4):
                if cmd & (1 << bit):
                    cp_off |= delta[pos] << (bit * 8)
                    pos += 1
            for bit in range(3):
                if cmd & (1 << (4 + bit)):
                    cp_size |= delta[pos] << (bit * 8)
                    pos += 1
            if cp_size == 0:
                cp_size = 0x10000
            if cp_off + cp_size > len(base) or len(out) + cp_size > target_size:
                raise ValueError("delta copy out of bounds")
            out.extend(base[cp_off : cp_off + cp_size])
        elif cmd != 0:
            if pos + cmd > len(delta) or len(out) + cmd > target_size:
                raise ValueError("delta insert out of bounds")
            out.extend(delta[pos : pos + cmd])
            pos += cmd
        else:
            raise ValueError("reserved opcode 0")
    if len(out) != target_size:
        raise ValueError("target size mismatch")
    return bytes(out)


def _verify_git_pack(pack_bytes: bytes, max_object_size: int = 32 * 1024 * 1024, max_delta_depth: int = 64):
    if len(pack_bytes) < 32 or pack_bytes[:4] != b"PACK":
        raise ValueError("invalid pack header")
    version, obj_count = struct.unpack("!II", pack_bytes[4:12])
    if version != 2:
        raise ValueError("unsupported pack version")
    trailer_pos = len(pack_bytes) - 20
    if hashlib.sha1(pack_bytes[:trailer_pos]).digest() != pack_bytes[trailer_pos:]:
        raise ValueError("pack SHA-1 trailer mismatch")

    pos = 12
    raw_entries = []
    offset_to_idx = {}
    type_map = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}

    for idx in range(obj_count):
        entry_offset = pos
        first = pack_bytes[pos]
        pos += 1
        raw_type = (first >> 4) & 0x07
        inflated_size = first & 0x0F
        shift = 4
        cont = (first & 0x80) != 0
        while cont:
            b = pack_bytes[pos]
            pos += 1
            inflated_size |= (b & 0x7F) << shift
            cont = (b & 0x80) != 0
            shift += 7
        if inflated_size > max_object_size:
            raise ValueError("entry size exceeds limit")

        if raw_type in type_map:
            kind = ("base", type_map[raw_type])
        elif raw_type == 6:
            b = pack_bytes[pos]
            pos += 1
            delta_off = b & 0x7F
            while b & 0x80:
                b = pack_bytes[pos]
                pos += 1
                delta_off = ((delta_off + 1) << 7) | (b & 0x7F)
            base_offset = entry_offset - delta_off
            kind = ("ofs_delta", base_offset)
        elif raw_type == 7:
            base_oid = pack_bytes[pos : pos + 20].hex()
            pos += 20
            kind = ("ref_delta", base_oid)
        else:
            raise ValueError(f"unknown pack type {raw_type}")

        dobj = zlib.decompressobj()
        inflated = dobj.decompress(pack_bytes[pos:trailer_pos], max_object_size + 1)
        inflated += dobj.flush()
        if len(inflated) > max_object_size or len(inflated) != inflated_size:
            raise ValueError("inflated size mismatch or limit exceeded")
        consumed = (trailer_pos - pos) - len(dobj.unused_data)
        pos += consumed
        offset_to_idx[entry_offset] = idx
        raw_entries.append((entry_offset, kind, inflated))

    if pos != trailer_pos:
        raise ValueError("trailing unconsumed bytes in pack")

    resolved = [None] * obj_count
    oid_to_idx = {}
    for idx, (off, kind, data) in enumerate(raw_entries):
        if kind[0] == "base":
            oid = _git_object_oid(kind[1], data)
            oid_to_idx[oid] = idx
            resolved[idx] = {"oid": oid, "type": kind[1], "data": data, "depth": 0}

    visiting = set()

    def resolve(idx: int):
        if resolved[idx] is not None:
            return
        if idx in visiting:
            raise ValueError("delta cycle")
        visiting.add(idx)
        _, kind, delta_data = raw_entries[idx]
        if kind[0] == "ofs_delta":
            if kind[1] not in offset_to_idx:
                raise ValueError("missing ofs base")
            base_idx = offset_to_idx[kind[1]]
        else:
            if kind[1] not in oid_to_idx:
                raise ValueError("unresolved ref_delta base")
            base_idx = oid_to_idx[kind[1]]
        resolve(base_idx)
        visiting.remove(idx)
        base_obj = resolved[base_idx]
        depth = base_obj["depth"] + 1
        if depth > max_delta_depth:
            raise ValueError("max delta depth exceeded")
        full_data = _apply_git_delta(base_obj["data"], delta_data, max_object_size)
        oid = _git_object_oid(base_obj["type"], full_data)
        oid_to_idx[oid] = idx
        resolved[idx] = {"oid": oid, "type": base_obj["type"], "data": full_data, "depth": depth}

    for idx in range(obj_count):
        resolve(idx)
    return resolved


def _walk_git_graph(objects_by_oid: dict, wants: list, haves: list):
    def children(obj_type: str, data: bytes):
        if obj_type == "tag":
            hdr = data.split(b"\n\n", 1)[0].decode()
            for line in hdr.splitlines():
                if line.startswith("object "):
                    yield line.split()[1]
        elif obj_type == "commit":
            hdr = data.split(b"\n\n", 1)[0].decode()
            for line in hdr.splitlines():
                if line.startswith("tree ") or line.startswith("parent "):
                    yield line.split()[1]
        elif obj_type == "tree":
            pos = 0
            while pos < len(data):
                sp = data.index(b" ", pos)
                mode = data[pos:sp].decode()
                nul = data.index(b"\0", sp + 1)
                oid = data[nul + 1 : nul + 21].hex()
                pos = nul + 21
                if mode != "160000":
                    yield oid

    excluded = set()
    q = list(haves)
    while q:
        oid = q.pop(0)
        if oid in excluded or oid not in objects_by_oid:
            continue
        excluded.add(oid)
        obj_type, data = objects_by_oid[oid]
        q.extend(children(obj_type, data))

    visited = {}
    wq = list(wants)
    while wq:
        oid = wq.pop(0)
        if oid in excluded or oid in visited:
            continue
        if oid not in objects_by_oid:
            raise ValueError(f"missing reachable object {oid}")
        obj_type, data = objects_by_oid[oid]
        visited[oid] = (obj_type, data)
        wq.extend(children(obj_type, data))
    return visited, excluded


class PandoModuleAndContractTests(unittest.TestCase):
    def test_pando_submodules_exist_and_are_modular(self):
        pando_dir = ROOT / "src" / "pando_lab"
        for name in (
            "mod.rs",
            "delta.rs",
            "graph.rs",
            "export.rs",
            "store.rs",
            "http.rs",
            "hook.rs",
            "migration.rs",
            "rollback.rs",
            "object_store.rs",
            "repack.rs",
            "lifecycle.rs",
        ):
            path = pando_dir / name
            self.assertTrue(path.is_file(), f"Missing src/pando_lab/{name}")
            lines = len(path.read_text(encoding="utf-8").splitlines())
            self.assertLess(lines, 850, f"src/pando_lab/{name} is too large ({lines} lines)")

    def test_pando_mod_preserves_config_load_first_and_wires_cli(self):
        mod_text = (ROOT / "src" / "pando_lab" / "mod.rs").read_text(encoding="utf-8")
        self.assertIn("pub mod delta;", mod_text)
        self.assertIn("pub mod export;", mod_text)
        self.assertIn("pub mod graph;", mod_text)
        run_section = mod_text.split("pub async fn run() -> Result<()> {", 1)[1]
        first_stmt = run_section.strip().splitlines()[0].strip()
        self.assertEqual(first_stmt, "let config = Config::load()?;")
        for subcmd in ('Some("verify-delta")', 'Some("walk-graph")', 'Some("diff-export")', 'Some("gc")'):
            self.assertIn(subcmd, mod_text)

    def test_pando_delta_graph_export_store_and_http_contracts(self):
        delta_text = (ROOT / "src" / "pando_lab" / "delta.rs").read_text(encoding="utf-8")
        for symbol in (
            "pub fn sha1_digest",
            "pub fn git_object_oid",
            "pub fn inflate_zlib_stream",
            "pub fn compress_zlib_stored",
            "pub fn apply_delta",
            "pub fn verify_pack",
            "OBJ_OFS_DELTA",
            "OBJ_REF_DELTA",
            "MAX_DELTA_DEPTH",
            "MAX_OBJECT_SIZE",
        ):
            self.assertIn(symbol, delta_text)
        self.assertNotIn("unsafe ", delta_text)

        graph_text = (ROOT / "src" / "pando_lab" / "graph.rs").read_text(encoding="utf-8")
        for symbol in ("pub fn parse_commit", "pub fn parse_tree", "pub fn parse_tag", "pub fn walk_reachable", "ObjectStore"):
            self.assertIn(symbol, graph_text)

        export_text = (ROOT / "src" / "pando_lab" / "export.rs").read_text(encoding="utf-8")
        self.assertIn("diff_export", export_text)
        self.assertIn("bit_for_bit_match", export_text)

        store_text = (ROOT / "src" / "pando_lab" / "store.rs").read_text(encoding="utf-8")
        self.assertIn("delta::verify_pack", store_text)
        self.assertIn("graph::walk_reachable", store_text)
        self.assertIn("pub(super) async fn gc", store_text)

        http_text = (ROOT / "src" / "pando_lab" / "http.rs").read_text(encoding="utf-8")
        self.assertIn('tail == "refs"', http_text)
        self.assertIn('tail.strip_prefix("operations/")', http_text)


class PandoPackDeltaAndGraphDifferentialTests(unittest.TestCase):
    def test_real_git_ofs_and_ref_delta_packs_and_differential_export(self):
        with tempfile.TemporaryDirectory(prefix="pando-diff-test-") as tmp:
            repo = Path(tmp) / "repo"
            subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
            base_blob = "".join(hashlib.sha256(f"line-{i}".encode()).hexdigest() + "\n" for i in range(1500))
            (repo / "large.txt").write_text(base_blob)
            (repo / "script.sh").write_text("#!/bin/sh\necho v1\n")
            (repo / "script.sh").chmod(0o755)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@e.c", "commit", "-m", "c1"],
                check=True,
            )
            c1 = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

            (repo / "large.txt").write_text(base_blob[:10000] + "delta edit\n" + base_blob[10000:])
            (repo / "added.txt").write_text("added in c2\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@e.c", "commit", "-m", "c2"],
                check=True,
            )
            c2 = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@e.c", "tag", "-a", "v1", "-m", "tag v1"],
                check=True,
            )
            tag_oid = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "refs/tags/v1"], text=True).strip()

            # Test both OFS_DELTA (--delta-base-offset) and REF_DELTA (no --delta-base-offset)
            for extra_args in (["--delta-base-offset"], []):
                pack_bytes = subprocess.run(
                    ["git", "-C", str(repo), "pack-objects", "--stdout", "--revs", *extra_args],
                    input=f"{tag_oid}\n".encode(),
                    check=True,
                    capture_output=True,
                ).stdout
                resolved = _verify_git_pack(pack_bytes)
                store = {obj["oid"]: (obj["type"], obj["data"]) for obj in resolved}

                # Full walk vs git rev-list --objects
                visited_full, _ = _walk_git_graph(store, [tag_oid], [])
                git_full = set(
                    subprocess.run(
                        ["git", "-C", str(repo), "rev-list", "--objects", "--no-object-names", tag_oid],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.splitlines()
                )
                self.assertEqual(set(visited_full.keys()), git_full)

                # Incremental walk with ^c1 exclusion vs git rev-list --objects
                visited_inc, excluded_inc = _walk_git_graph(store, [c2], [c1])
                git_inc = set(
                    subprocess.run(
                        ["git", "-C", str(repo), "rev-list", "--objects", "--no-object-names", c2, f"^{c1}"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.splitlines()
                )
                self.assertEqual(set(visited_inc.keys()), git_inc)
                self.assertGreater(len(excluded_inc), 0)

                # Bit-for-bit verification against git cat-file
                for oid, (obj_type, obj_data) in visited_full.items():
                    git_t = subprocess.check_output(["git", "-C", str(repo), "cat-file", "-t", oid], text=True).strip()
                    git_d = subprocess.check_output(["git", "-C", str(repo), "cat-file", obj_type, oid])
                    self.assertEqual(obj_type, git_t)
                    self.assertEqual(obj_data, git_d)

            # Thin pack must be rejected when external base is missing
            thin_pack = subprocess.run(
                ["git", "-C", str(repo), "pack-objects", "--thin", "--stdout", "--revs"],
                input=f"{c2}\n^{c1}\n".encode(),
                check=True,
                capture_output=True,
            ).stdout
            with self.assertRaises(ValueError):
                _verify_git_pack(thin_pack)


class WorkspaceModuleAndContractTests(unittest.TestCase):
    def test_workspace_lab_root_is_regular_file_under_150_lines(self):
        root_file = ROOT / "src" / "workspace_lab.rs"
        self.assertTrue(root_file.is_file(), "src/workspace_lab.rs must be a regular file")
        self.assertFalse((ROOT / "src" / "workspace_lab" / "mod.rs").exists(), "src/workspace_lab/mod.rs must not exist")
        lines = root_file.read_text(encoding="utf-8").splitlines()
        self.assertLess(len(lines), 150, f"src/workspace_lab.rs has {len(lines)} lines (>= 150)")
        content = "\n".join(lines)
        for submod in ("core", "ignore", "manifest", "sync", "view", "remote", "namespace", "vfs", "writable_view"):
            self.assertIn(f'#[path = "workspace_lab/{submod}.rs"]', content)
            self.assertTrue((ROOT / "src" / "workspace_lab" / f"{submod}.rs").is_file())

    def test_workspace_subcommands_are_wired(self):
        content = (ROOT / "src" / "workspace_lab.rs").read_text(encoding="utf-8")
        for cmd in (
            "init",
            "checkpoint",
            "restore",
            "inspect",
            "status",
            "changeset",
            "apply",
            "sync-dirty",
            "verify-readonly-view",
            "push-remote",
            "pull-remote",
            "namespace-mount",
            "verify-namespace",
            "namespace-git-view",
            "vfs-mount",
            "vfs-hydrate",
            "vfs-status",
            "vfs-evict",
            "agent-lease",
            "namespace-write",
            "namespace-commit-back",
        ):
            self.assertIn(f'"{cmd}"', content)


class WorkspaceEndToEndExecutionTests(unittest.TestCase):
    def test_workspace_harness_all_checks_pass(self):
        harness = WorkspaceHarness()
        try:
            harness.run_all()
            report = harness.report()
            self.assertTrue(report["ok"], f"Workspace harness failed: {report}")
            self.assertGreaterEqual(len(report["checks"]), 5)
        finally:
            harness.cleanup()


if __name__ == "__main__":
    unittest.main()
