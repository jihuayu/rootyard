#!/usr/bin/env python3
"""Live Pando pack CAS acceptance against PostgreSQL and an S3-compatible store."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
from urllib.parse import urlsplit, urlunsplit


def run(*args, env=None, cwd=None):
    return subprocess.run(args, env=env, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    base = os.environ["ROOTYARD_TEST_DATABASE_URL"]
    name = "rootyard_pando_remote_" + uuid.uuid4().hex[:12]
    db = urlsplit(base)
    target = urlunsplit((db.scheme, db.netloc, "/" + name, db.query, db.fragment))
    repo_id, pack_id = str(uuid.uuid4()), str(uuid.uuid4())
    with tempfile.TemporaryDirectory(prefix="rootyard-pando-remote-") as temp:
        root = Path(temp)
        env = dict(os.environ, PANDO_SYNTHETIC_ONLY="1", PANDO_ROOT=str(root),
                   PANDO_DATABASE_URL=target, PANDO_GIT=shutil.which("git"))
        run("psql", base, "-v", "ON_ERROR_STOP=1", "-c", "CREATE DATABASE " + name)
        try:
            run(str(binary), "init", env=env)
            run(str(binary), "create-repo", repo_id, "storage-test", env=env)
            git = root / "source"
            git.mkdir()
            run("git", "init", "-q", str(git))
            run("git", "-C", str(git), "config", "user.name", "Storage Test")
            run("git", "-C", str(git), "config", "user.email", "storage@example.invalid")
            with open(git / "payload", "wb") as out:
                remaining = 40 * 1024 * 1024
                while remaining:
                    chunk = os.urandom(min(1024 * 1024, remaining))
                    out.write(chunk)
                    remaining -= len(chunk)
            run("git", "-C", str(git), "add", "payload")
            run("git", "-C", str(git), "commit", "-qm", "forty megabytes")
            run("git", "-C", str(git), "repack", "-ad")
            source_pack = next((git / ".git" / "objects" / "pack").glob("*.pack"))
            source_idx = source_pack.with_suffix(".idx")
            object_dir = root / "objects" / repo_id
            object_dir.mkdir(parents=True)
            pack = object_dir / (pack_id + ".pack")
            idx = object_dir / (pack_id + ".idx")
            shutil.copyfile(source_pack, pack)
            shutil.copyfile(source_idx, idx)
            expected_pack, expected_idx = digest(pack), digest(idx)
            size = pack.stat().st_size
            put = json.loads(run(str(binary), "object-store-put", repo_id, pack_id,
                                 "--bucket", os.environ["ROOTYARD_OBJECT_STORE_BUCKET"],
                                 "--chunk-size", "131072", env=env))
            assert put["pack_sha256"] == expected_pack and put["pack_bytes"] == size
            pack.unlink()
            idx.unlink()
            get = json.loads(run(str(binary), "object-store-get", repo_id, pack_id, env=env))
            assert get["rehydrated_from_object_store"] and digest(pack) == expected_pack
            assert digest(idx) == expected_idx
            run("git", "index-pack", "--verify", str(pack))
            with open(pack, "r+b") as damaged:
                damaged.seek(32)
                damaged.write(b"corrupt-cache")
            repaired = json.loads(run(str(binary), "object-store-get", repo_id, pack_id, env=env))
            assert repaired["rehydrated_from_object_store"] and digest(pack) == expected_pack
            verify = json.loads(run(str(binary), "object-store-verify", repo_id, env=env))
            assert verify["verified"] and verify["packs_verified"] == 1
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps({"result": "passed", "repo": repo_id,
                "pack_id": pack_id, "pack_bytes": size, "pack_sha256": expected_pack,
                "idx_sha256": expected_idx, "remote_key": put["pack_key"],
                "rehydrated": get["rehydrated_from_object_store"],
                "corrupt_cache_repaired": repaired["rehydrated_from_object_store"]}, indent=2) + "\n")
            print(args.report)
        finally:
            run("psql", base, "-v", "ON_ERROR_STOP=1", "-c",
                "DROP DATABASE " + name + " WITH (FORCE)")


if __name__ == "__main__":
    main()
