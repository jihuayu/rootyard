#!/usr/bin/env python3
"""Native SHA-256 Git service smoke: create, push, fetch, browse and ref CAS."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness


class Sha256Harness(Harness):
    def service_flow(self):
        self.setup()
        code, raw, _ = self.http("/api/repos", token=self.alice, method="POST",
                                 body={"name": "sha256", "object_format": "sha256"})
        assert code == 201, (code, raw[:300])
        self.repo = json.loads(raw)
        assert self.repo["object_format"] == "sha256"
        self.remote = self.base + self.repo["clone_path"]
        work = self.root / "sha256-work"
        self.git("init", "--object-format=sha256", "--initial-branch=main", str(work))
        self.git("config", "user.name", "SHA256 Test", cwd=work)
        self.git("config", "user.email", "sha256@example.invalid", cwd=work)
        (work / "data.txt").write_text("sha256 commit\n")
        self.git("add", "data.txt", cwd=work)
        self.git("commit", "-m", "sha256 first", cwd=work)
        first = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        assert len(first) == 64
        self.git("remote", "add", "origin", self.remote, cwd=work)
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        clone = self.root / "sha256-clone"
        self.git("clone", self.remote, str(clone), token=self.alice)
        assert self.git("rev-parse", "--show-object-format", cwd=clone).stdout.strip() == b"sha256"
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == first
        self.git("fsck", "--full", cwd=clone)
        for path in ("/refs?limit=1", "/commits?limit=1", f"/commits/{first}"):
            code, raw, _ = self.http(f"/api/repos/alice/sha256{path}", token=self.alice)
            assert code == 200, (path, code, raw[:300])
        payload = {"updates": [{"ref_name": "refs/heads/topic", "old_oid": "0" * 64,
                                "new_oid": first}]}
        code, raw, _ = self.http("/api/repos/alice/sha256/ref-transactions", token=self.alice,
                                 method="POST", body=payload)
        assert code == 200, (code, raw[:300])
        payload["updates"][0]["old_oid"] = "0" * 40
        code, _, _ = self.http("/api/repos/alice/sha256/ref-transactions", token=self.alice,
                               method="POST", body=payload)
        assert code in (400, 409), code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    h = Sha256Harness(args)
    try:
        h.case("service_flow", h.service_flow)
        return 0
    except Exception as exc:
        print(h.redact(exc), file=sys.stderr)
        return 1
    finally:
        h.cleanup()


if __name__ == "__main__":
    sys.exit(main())
