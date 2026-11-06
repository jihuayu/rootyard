#!/usr/bin/env python3
"""Native SHA-256 Git service smoke: create, push, fetch, browse, ref CAS,
pull/review/check-run/CI-pin/merge format admission."""
import argparse
import json
import os
from pathlib import Path
import sys
import uuid

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

    def pull_check_pin_flow(self):
        """Format admission on the forge surface: pull, review, check, CI pin, merge.

        Every request carries the SHA-1-shaped 40-hex prefix of a real SHA-256
        commit as the negative case, so a length-inferred format would silently
        accept it.
        """
        repo_id = self.repo["id"]
        generation = int(self.sql(
            "SELECT storage_generation FROM repositories WHERE id='" + repo_id + "'"))
        work = self.root / "sha256-work"
        base = self.git("rev-parse", "main", cwd=work).stdout.decode().strip()
        self.git("checkout", "-b", "feature", cwd=work)
        (work / "feature.txt").write_text("sha256 feature\n")
        self.git("add", "feature.txt", cwd=work)
        self.git("commit", "-m", "sha256 feature", cwd=work)
        head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        assert len(head) == 64 and head != base
        self.git("push", "origin", "HEAD:refs/heads/feature", cwd=work, token=self.alice)
        self.git("checkout", "main", cwd=work)
        short = head[:40]

        pulls = "/api/repos/alice/sha256/pulls"
        self.expect(pulls, 400, token=self.alice, method="POST",
                    body={"title": "sha1 oid", "head_ref": "refs/heads/feature",
                          "base_ref": "refs/heads/main", "head_oid": short})
        pr = json.loads(self.expect(pulls, 201, token=self.alice, method="POST",
                                    body={"title": "sha256 feature",
                                          "head_ref": "refs/heads/feature",
                                          "base_ref": "refs/heads/main"}))
        assert pr["head_oid"] == head and pr["base_oid"] == base and pr["state"] == "open"
        pull_path = pulls + "/" + str(pr["number"])

        reviews = pull_path + "/reviews"
        self.expect(reviews, 400, token=self.alice, method="POST",
                    body={"state": "approved", "commit_oid": short})
        review = json.loads(self.expect(reviews, 201, token=self.alice, method="POST",
                                        body={"state": "approved", "commit_oid": head}))
        assert review["commit_oid"] == head

        checks = "/api/repos/alice/sha256/checks"
        self.expect(checks, 409, token=self.alice, method="POST",
                    body={"commit_oid": short, "context": "sha256/native",
                          "status": "completed", "conclusion": "success"})
        check = json.loads(self.expect(checks, (200, 201), token=self.alice, method="POST",
                                       body={"commit_oid": head, "context": "sha256/native",
                                             "status": "completed", "conclusion": "success"}))
        assert check["commit_oid"] == head and check["conclusion"] == "success"

        job = str(uuid.uuid4())
        pins = "/api/repos/alice/sha256/ci-pins"
        self.expect(pins, 400, token=self.alice, method="POST",
                    body={"job_id": job, "target_oid": short,
                          "storage_generation": generation})
        pin = json.loads(self.expect(pins, (200, 201), token=self.alice, method="POST",
                                     body={"job_id": job, "target_oid": head,
                                           "storage_generation": generation}))
        assert pin["state"] == "pinned" and pin["target_oid"] == head
        assert pin["object_format"] == "sha256" and pin["storage_generation"] == generation
        intent = json.loads((self.root / "data" / "ci-pins" / repo_id /
                             (job + ".json")).read_text())
        assert intent["object_format"] == "sha256" and intent["target_oid"] == head

        merge = pull_path + "/merge"
        self.expect(merge, 400, token=self.alice, method="POST",
                    body={"expected_version": pr["version"], "expected_head_oid": short,
                          "expected_base_oid": base})
        merged = json.loads(self.expect(merge, 200, token=self.alice, method="POST",
                                        body={"expected_version": pr["version"],
                                              "expected_head_oid": head,
                                              "expected_base_oid": base}))
        assert merged["state"] == "merged"
        produced = merged["merge_commit_oid"]
        assert produced is not None and len(produced) == 64, produced
        bare = self.root / "data" / "repos" / (repo_id + ".git")
        live = self.git("--git-dir=" + str(bare), "rev-parse", "refs/heads/main")
        assert live.stdout.decode().strip() == produced
        retained = self.git("--git-dir=" + str(bare), "for-each-ref",
                            "--format=%(objectname)", "refs/rootyard-ci/jobs/" + job)
        assert retained.stdout.decode().strip() == head
        return dict(base_oid=base, head_oid=head, merge_oid=produced, pin_job=job,
                    short_oid_rejected_by=["pull", "review", "check", "ci-pin", "merge"])


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
        h.case("pull_check_pin_flow", h.pull_check_pin_flow)
        return 0
    except Exception as exc:
        print(h.redact(exc), file=sys.stderr)
        return 1
    finally:
        h.cleanup()


if __name__ == "__main__":
    sys.exit(main())
