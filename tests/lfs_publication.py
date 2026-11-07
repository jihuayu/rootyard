#!/usr/bin/env python3
"""Reject unavailable, wrong-size, and invalid LFS pointers before ref publication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lfs import LfsHarness

VERSION_LINE = "version https://git-lfs.github.com/spec/v1"
LEGACY_HAWSER_LINE = "version https://hawser.github.com/spec/v1"
LEGACY_MEDIA_LINE = "version http://git-media.io/v/2"

# Installed git-lfs 3.6.1 `pointer --check` exits recorded by the primary:
# canonical/LF, CRLF, leading ASCII whitespace (space, tab, newline, CRLF, VT),
# leading Unicode NBSP, and the two legacy headers are accepted; a trailing
# space/tab on the version line, reordered fields, and scheme-swapped legacy
# headers are not pointer-shaped.
CLIENT_POINTER_EXPECTED = {
    "canonical": True,
    "crlf": True,
    "leading-newline": True,
    "leading-space": True,
    "leading-tab": True,
    "leading-crlf": True,
    "leading-vtab": True,
    "leading-nbsp": True,
    "legacy-hawser": True,
    "legacy-media-http": True,
    "header-no-newline": True,
    "trailing-space": True,
    "header-trailing-space": False,
    "header-tab": False,
    "reordered": False,
    "legacy-http": False,
    "legacy-media-https": False,
    "legacy-hawser-http": False,
}


def pointer_body(version, oid, size, newline="\n"):
    return newline.join([version, f"oid sha256:{oid}", f"size {size}", ""])


def git_blob_oid(body):
    """Git SHA-1 object id for a blob body, matching the repository's BTreeSet order."""
    digest = hashlib.sha1()
    digest.update(b"blob " + str(len(body)).encode("ascii") + b"\0")
    digest.update(body)
    return digest.hexdigest()


def pointer_variants(oid, size):
    canonical = pointer_body(VERSION_LINE, oid, size)
    return {
        "canonical": canonical,
        "crlf": pointer_body(VERSION_LINE, oid, size, "\r\n"),
        "leading-newline": "\n" + canonical,
        "leading-space": " " + canonical,
        "leading-tab": "\t" + canonical,
        "leading-crlf": "\r\n" + canonical,
        "leading-vtab": "\v" + canonical,
        "leading-nbsp": "\u00a0" + canonical,
        "legacy-hawser": pointer_body(LEGACY_HAWSER_LINE, oid, size),
        "legacy-media-http": pointer_body(LEGACY_MEDIA_LINE, oid, size),
        "header-no-newline": canonical.rstrip("\n"),
        "trailing-space": canonical + " ",
        "header-trailing-space": pointer_body(VERSION_LINE + " ", oid, size),
        "header-tab": pointer_body(VERSION_LINE + "\t", oid, size),
        "reordered": f"{VERSION_LINE}\nsize {size}\noid sha256:{oid}\n",
        "legacy-http": pointer_body("version http://git-lfs.github.com/spec/v1", oid, size),
        "legacy-media-https": pointer_body("version https://git-media.io/v/2", oid, size),
        "legacy-hawser-http": pointer_body("version http://hawser.github.com/spec/v1", oid, size),
    }


class PublicationHarness(LfsHarness):
    def probe_pointer_variants(self):
        """Record the installed client's pointer recognition for every variant."""
        version = subprocess.run(["git", "lfs", "version"], capture_output=True)
        if version.returncode != 0:
            return {"client_available": False, "variants": {}}
        oid = hashlib.sha256(b"pointer-variant-probe").hexdigest()
        probes = {}
        with tempfile.TemporaryDirectory(prefix="rootyard-pointer-variants-") as raw:
            fixtures = Path(raw)
            for name, body in sorted(pointer_variants(oid, 7).items()):
                fixture = fixtures / f"pointer-variant-{name}.txt"
                fixture.write_bytes(body.encode())
                checked = subprocess.run(
                    ["git", "lfs", "pointer", "--check", "--file", str(fixture)],
                    capture_output=True)
                probes[name] = {
                    "exit": checked.returncode,
                    "accepted": checked.returncode == 0,
                    "expected_accept": CLIENT_POINTER_EXPECTED[name],
                }
        mismatched = [name for name, probe in probes.items()
                      if probe["accepted"] != probe["expected_accept"]]
        assert not mismatched, (
            "installed git-lfs pointer recognition differs from the recorded "
            f"client probes: {mismatched}")
        return {
            "client_available": True,
            "client_version": version.stdout.decode().strip(),
            "variants": probes,
        }

    def reject_pointer_publication(self):
        self.setup_lfs()
        self.batch_upload_stream_verify_and_download()
        main = self.second
        missing = hashlib.sha256(b"absent-object").hexdigest()
        missing_size = 13
        wrong_size = self.size + 1
        # A batch can promise the same LFS oid at two sizes. The good canonical
        # pointer blob must sort before the wrong-size pointer blob so the old
        # oid-only de-duplication validated the good promise first and then
        # skipped the wrong-size promise deterministically.
        good_same_oid = pointer_body(VERSION_LINE, self.oid, self.size).encode()
        good_same_oid_blob = git_blob_oid(good_same_oid)
        for bump in range(1, 100_000):
            bad_same_size = self.size + bump
            bad_same_oid = pointer_body(VERSION_LINE, self.oid, bad_same_size).encode()
            bad_same_oid_blob = git_blob_oid(bad_same_oid)
            if bad_same_oid_blob > good_same_oid_blob:
                break
        else:  # pragma: no cover - astronomically unlikely
            raise AssertionError("could not construct an ordered same-oid pointer pair")
        pointer_bodies = {
            "missing": pointer_body(VERSION_LINE, missing, missing_size),
            "wrong_size": pointer_body(VERSION_LINE, self.oid, wrong_size),
            "invalid": f"{VERSION_LINE}\noid sha256:not-hex\nsize 13\n",
            "crlf_missing": pointer_body(VERSION_LINE, missing, missing_size, "\r\n"),
            "crlf_wrong_size": pointer_body(VERSION_LINE, self.oid, wrong_size, "\r\n"),
            # Client-accepted shapes the old prefix-only gate treated as
            # ordinary content; each must still fail closed when the promised
            # bytes are missing or the wrong size.
            "nbsp_missing": "\u00a0" + pointer_body(VERSION_LINE, missing, missing_size),
            "nbsp_wrong_size": "\u00a0" + pointer_body(VERSION_LINE, self.oid, wrong_size),
            "legacy_hawser_missing": pointer_body(LEGACY_HAWSER_LINE, missing, missing_size),
            "legacy_media_wrong_size": pointer_body(LEGACY_MEDIA_LINE, self.oid, wrong_size),
            # Same oid, good canonical promise plus a wrong-size promise whose
            # blob sorts after the good one (the oid-only dedup regression).
            "same_oid_good_and_wrong_size": bad_same_oid.decode(),
            "ready_missing_bytes": pointer_body(VERSION_LINE, self.oid, self.size)
                                    + "ext-test missing\n",
            "ready_corrupt_bytes": pointer_body(VERSION_LINE, self.oid, self.size)
                                    + "ext-test corrupt\n",
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
            add_paths = ["pointer.dat"]
            if kind == "same_oid_good_and_wrong_size":
                # This extra good pointer exists only for the ordering case and
                # is removed by the reset to main after this iteration.
                good_name = "pointer-good-canonical.dat"
                (self.work / good_name).write_bytes(good_same_oid)
                add_paths.append(good_name)
            self.git("add", *add_paths, cwd=self.work)
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
        # Client-recognized non-canonical pointers to this repository's ready,
        # digest-verified object must still publish; normalization must not
        # become over-rejection.
        valid_variants = {
            "crlf_valid": pointer_body(VERSION_LINE, self.oid, self.size, "\r\n"),
            "nbsp_valid": "\u00a0" + pointer_body(VERSION_LINE, self.oid, self.size),
            "legacy_hawser_valid": pointer_body(LEGACY_HAWSER_LINE, self.oid, self.size),
            "legacy_media_valid": pointer_body(LEGACY_MEDIA_LINE, self.oid, self.size),
        }
        published = {}
        for name, pointer in valid_variants.items():
            self.git("reset", "--hard", main, cwd=self.work)
            (self.work / "pointer.dat").write_bytes(pointer.encode())
            self.git("add", "pointer.dat", cwd=self.work)
            self.git("commit", "-m", f"valid {name} pointer", cwd=self.work)
            head = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
            ref = f"refs/heads/{name}"
            push = self.git("push", "origin", f"HEAD:{ref}", cwd=self.work,
                            token=self.alice, check=False)
            assert push.returncode == 0, self.redact(
                f"valid {name} pointer push rejected: "
                + push.stderr.decode(errors="replace")[-1000:])
            remote_head = self.git("ls-remote", self.remote, ref,
                                   token=self.alice).stdout.decode().split()
            assert remote_head and remote_head[0] == head, remote_head
            published[name] = ref
        return {"pointer_kinds": sorted(pointer_bodies),
                "publication_paths": ["smart_http_receive", "atomic_smart_http_receive",
                                      "ref_transaction", "pull_merge"],
                "rejected_before_ref_move": True,
                "crlf_client_pointer_check": client_check,
                "valid_pointers_published": published,
                "same_oid_wrong_size_order": {
                    "good_blob_oid": good_same_oid_blob,
                    "wrong_size": bad_same_size,
                    "wrong_blob_oid": bad_same_oid_blob,
                }}


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
        h.case("probe_pointer_variants", h.probe_pointer_variants)
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
