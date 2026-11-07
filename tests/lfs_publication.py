#!/usr/bin/env python3
"""Reject unavailable, wrong-size, and invalid LFS pointers before ref publication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lfs import LfsHarness


class PublicationHarness(LfsHarness):
    def reject_pointer_publication(self):
        self.setup_lfs()
        self.batch_upload_stream_verify_and_download()
        main = self.second
        missing = hashlib.sha256(b"absent-object").hexdigest()
        pointer_bodies = {
            "missing": f"version https://git-lfs.github.com/spec/v1\noid sha256:{missing}\nsize 13\n",
            "wrong_size": f"version https://git-lfs.github.com/spec/v1\noid sha256:{self.oid}\nsize {self.size+1}\n",
            "invalid": "version https://git-lfs.github.com/spec/v1\noid sha256:not-hex\nsize 13\n",
            "crlf_missing": f"version https://git-lfs.github.com/spec/v1\r\noid sha256:{missing}\r\nsize 13\r\n",
            "crlf_wrong_size": f"version https://git-lfs.github.com/spec/v1\r\noid sha256:{self.oid}\r\nsize {self.size+1}\r\n",
            "ready_missing_bytes": f"version https://git-lfs.github.com/spec/v1\noid sha256:{self.oid}\nsize {self.size}\next-test missing\n",
            "ready_corrupt_bytes": f"version https://git-lfs.github.com/spec/v1\noid sha256:{self.oid}\nsize {self.size}\next-test corrupt\n",
        }
        # The installed client accepts a CRLF pointer (non-strict check) while
        # --strict rejects only its canonical encoding. Record both exits so the
        # gateway normalization is justified by the client's actual behaviour.
        crlf_fixture = self.root / "crlf-pointer.txt"
        crlf_fixture.write_bytes(pointer_bodies["crlf_wrong_size"].encode())
        client_check = {"available": False}
        if self.run(["git", "lfs", "version"], check=False).returncode == 0:
            nonstrict = self.run(["git", "lfs", "pointer", "--check", "--file",
                                  str(crlf_fixture)], check=False)
            strict = self.run(["git", "lfs", "pointer", "--check", "--strict", "--file",
                               str(crlf_fixture)], check=False)
            client_check = {"available": True, "nonstrict_exit": nonstrict.returncode,
                            "strict_exit": strict.returncode}
            assert nonstrict.returncode == 0, "installed git-lfs does not recognize the CRLF pointer"
            assert strict.returncode != 0, "installed git-lfs --strict unexpectedly accepts CRLF"
        zero = "0" * 40
        for kind, pointer in pointer_bodies.items():
            held = self.obj_file.with_name(".held-" + self.oid)
            if kind == "ready_missing_bytes":
                self.obj_file.rename(held)
            elif kind == "ready_corrupt_bytes":
                original = self.obj_file.read_bytes()
                self.obj_file.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            (self.work / "pointer.dat").write_text(pointer)
            self.git("add", "pointer.dat", cwd=self.work)
            self.git("commit", "-m", f"{kind} pointer", cwd=self.work)
            oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()

            # Smart HTTP receive must reject before the new ref becomes visible.
            ref = f"refs/heads/rejected-{kind}"
            pushed = self.git("push", "origin", f"HEAD:{ref}", cwd=self.work,
                              token=self.alice, check=False)
            assert pushed.returncode != 0, f"direct Git push accepted {kind} pointer"
            assert not self.git("ls-remote", self.remote, ref, token=self.alice).stdout
            bad_ref = f"refs/heads/atomic-bad-{kind}"
            good_ref = f"refs/heads/atomic-good-{kind}"
            atomic = self.git("push", "--atomic", "origin", f"HEAD:{bad_ref}",
                              f"{main}:{good_ref}", cwd=self.work,
                              token=self.alice, check=False)
            assert atomic.returncode != 0, f"atomic Git push accepted {kind} pointer"
            assert not self.git("ls-remote", self.remote, bad_ref, token=self.alice).stdout
            assert not self.git("ls-remote", self.remote, good_ref, token=self.alice).stdout

            # Seed an unreachable object via local Git fetch. This bypasses the
            # service publication path while retaining actual Git object bytes.
            self.git("--git-dir=" + str(self.bare), "fetch", "--no-write-fetch-head",
                     str(self.work), oid)
            tx_ref = f"refs/heads/txn-{kind}"
            tx = self.http("/api/repos/alice/demo/ref-transactions", token=self.alice,
                           method="POST", body={"storage_generation": 1, "atomic": True,
                           "updates": [{"ref_name": tx_ref, "old_oid": zero, "new_oid": oid}]})
            assert tx[0] == 409, f"ref transaction accepted {kind}: {tx[0]} {tx[1][:200]!r}"
            assert not self.git("ls-remote", self.remote, tx_ref, token=self.alice).stdout

            # A source branch may already exist (for example, predating the
            # policy); the merge endpoint must still refuse to move main.
            head_ref = f"refs/heads/merge-{kind}"
            self.git("--git-dir=" + str(self.bare), "update-ref", head_ref, oid)
            pr_path = "/api/repos/alice/demo/pulls"
            created = self.http(pr_path, token=self.alice, method="POST",
                                body={"title": f"{kind} pointer", "head_ref": head_ref,
                                      "base_ref": "refs/heads/main"})
            assert created[0] == 201, f"PR create failed: {created[0]} {created[1][:200]!r}"
            pr = json.loads(created[1])
            merged = self.http(f"{pr_path}/{pr['number']}/merge", token=self.alice,
                               method="POST", body={"expected_version": pr["version"],
                               "expected_head_oid": oid, "expected_base_oid": main,
                               "storage_generation": 1, "strategy": "fast_forward"})
            assert merged[0] == 409, f"merge accepted {kind}: {merged[0]} {merged[1][:200]!r}"
            assert self.git("ls-remote", self.remote, "refs/heads/main", token=self.alice).stdout.decode().startswith(main)
            self.git("reset", "--hard", main, cwd=self.work)
            if kind == "ready_missing_bytes":
                held.rename(self.obj_file)
            elif kind == "ready_corrupt_bytes":
                self.obj_file.write_bytes(original)
        # A CRLF pointer to this repository's ready, digest-verified object must
        # still publish; line-ending normalization must not become over-rejection.
        crlf_valid = (f"version https://git-lfs.github.com/spec/v1\r\n"
                      f"oid sha256:{self.oid}\r\nsize {self.size}\r\n")
        self.git("reset", "--hard", main, cwd=self.work)
        (self.work / "pointer.dat").write_bytes(crlf_valid.encode())
        self.git("add", "pointer.dat", cwd=self.work)
        self.git("commit", "-m", "valid crlf pointer", cwd=self.work)
        crlf_head = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        crlf_ref = "refs/heads/crlf-valid"
        crlf_push = self.git("push", "origin", f"HEAD:{crlf_ref}", cwd=self.work,
                             token=self.alice, check=False)
        assert crlf_push.returncode == 0, self.redact(
            "valid CRLF pointer push rejected: "
            + crlf_push.stderr.decode(errors="replace")[-1000:])
        remote_head = self.git("ls-remote", self.remote, crlf_ref,
                               token=self.alice).stdout.decode().split()
        assert remote_head and remote_head[0] == crlf_head, remote_head
        return {"pointer_kinds": sorted(pointer_bodies),
                "publication_paths": ["smart_http_receive", "atomic_smart_http_receive",
                                      "ref_transaction", "pull_merge"],
                "rejected_before_ref_move": True,
                "crlf_client_pointer_check": client_check,
                "crlf_valid_pointer_published": True,
                "crlf_valid_ref": crlf_ref}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    h = PublicationHarness(args)
    passed = False
    try:
        h.case("reject_pointer_publication", h.reject_pointer_publication)
        passed = True
    except Exception:
        print(h.redact(traceback.format_exc()), file=sys.stderr)
    finally:
        h.cleanup()
        report = {"passed": passed, "cases": h.results,
                  "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
