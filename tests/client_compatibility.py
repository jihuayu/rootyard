#!/usr/bin/env python3
"""Real stock Git, JGit and libgit2 interoperability against Rust/PostgreSQL.

Requires ROOTYARD_JGIT_CLASSPATH and ROOTYARD_PYGIT2_PYTHON. Missing clients fail;
this runner never inherits a passed result from a different client version.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from e2e import Harness
from client_features import ClientFeatures
from native_evidence import build_record

CLIENTS = Path(__file__).parent / "clients"


class Compatibility(ClientFeatures, Harness):
    def independent(self, implementation, operation, directory, refspec=None, token=None, check=True):
        env = self.env.copy()
        account = token or self.alice
        env.update(ROOTYARD_CLIENT_USER=account["username"], ROOTYARD_CLIENT_TOKEN=account["token"])
        if implementation == "jgit":
            command = ["java", "--class-path", os.environ["ROOTYARD_JGIT_CLASSPATH"],
                       str(CLIENTS / "JGitProbe.java")]
        else:
            command = [os.environ["ROOTYARD_PYGIT2_PYTHON"], str(CLIENTS / "libgit2_probe.py")]
        command += [operation, self.remote, str(directory)]
        if refspec:
            command.append(refspec)
        result = self.run(command, env=env, check=check)
        self.transcripts.append({"client": implementation, "operation": operation,
                                 "exit_code": result.returncode,
                                 "stdout": self.redact(result.stdout.decode(errors="replace")),
                                 "stderr": self.redact(result.stderr.decode(errors="replace"))})
        return result

    def inspect_checkout(self, directory, expected):
        oid = self.git("rev-parse", "HEAD", cwd=directory).stdout.decode().strip()
        assert oid == expected, (oid, expected)
        fsck = self.git("fsck", "--full", cwd=directory)
        status = self.git("status", "--porcelain=v1", cwd=directory).stdout.decode()
        assert status == "", status
        assert (directory / "hello.txt").read_text() == "second\n"
        assert (directory / "payload.bin").read_bytes() == (self.work / "payload.bin").read_bytes()
        return {"head": oid, "fsck": fsck.returncode, "status": status,
                "payload_sha256": hashlib.sha256((directory / "payload.bin").read_bytes()).hexdigest()}

    def independent_roundtrips(self):
        outputs = {}
        for client in ("jgit", "libgit2"):
            directory = self.root / client
            self.independent(client, "clone", directory)
            result = self.inspect_checkout(directory, self.second)
            self.git("config", "user.name", "Client compatibility", cwd=directory)
            self.git("config", "user.email", "compat@example.invalid", cwd=directory)
            (directory / f"{client}.txt").write_text(f"real {client} receive-pack\n")
            self.git("add", ".", cwd=directory)
            self.git("commit", "-m", f"{client} contribution", cwd=directory)
            oid = self.git("rev-parse", "HEAD", cwd=directory).stdout.decode().strip()
            self.independent(client, "push", directory, f"HEAD:refs/heads/{client}")
            refs = self.git("ls-remote", self.remote, f"refs/heads/{client}", token=self.alice).stdout.decode()
            assert refs.startswith(oid + "\t"), refs
            self.git("fetch", "origin", f"refs/heads/{client}", cwd=self.work, token=self.alice)
            assert self.git("show", f"FETCH_HEAD:{client}.txt", cwd=self.work).stdout == f"real {client} receive-pack\n".encode()
            # Force this client's fetch to receive an object it does not already own.
            marker = f"fetch-for-{client}.txt"
            (self.work / marker).write_text(f"new remote object for {client}\n")
            self.git("add", marker, cwd=self.work)
            self.git("commit", "-m", f"remote update for {client}", cwd=self.work)
            self.git("push", "origin", f"HEAD:refs/heads/fetch-{client}", cwd=self.work, token=self.alice)
            self.independent(client, "fetch", directory)
            assert self.git("show", f"refs/remotes/origin/fetch-{client}:{marker}", cwd=directory).stdout == f"new remote object for {client}\n".encode()
            self.git("fsck", "--full", cwd=directory)
            denied = self.independent(client, "clone", self.root / f"{client}-denied", token=self.bob, check=False)
            assert denied.returncode != 0, "non-member cloned private repository"
            outputs[client] = {**result, "pushed_oid": oid, "nonmember_rejected": True}
        return outputs

    def stock_protocol_states(self):
        outputs = {}
        for protocol in ("0", "1", "2"):
            directory = self.root / f"stock-v{protocol}"
            self.git("-c", f"protocol.version={protocol}", "clone", "--depth=1",
                     self.remote, str(directory), token=self.alice)
            assert self.git("rev-parse", "--is-shallow-repository", cwd=directory).stdout.strip() == b"true"
            self.git("fetch", "--unshallow", cwd=directory, token=self.alice)
            outputs[protocol] = self.inspect_checkout(directory, self.second)
        self.git("tag", "-a", "compat-tag", "-m", "annotated tag", cwd=self.work)
        self.git("push", "origin", "refs/tags/compat-tag", cwd=self.work, token=self.alice)
        # An incorrect lease must reject the entire atomic transaction.
        (self.work / "hello.txt").write_text("lease candidate\n")
        self.git("commit", "-am", "lease candidate", cwd=self.work)
        refs_before = self.git("ls-remote", self.remote, token=self.alice).stdout
        rejected = self.git("push", "--atomic", "--force-with-lease=refs/heads/main:" + self.first,
                            "origin", "HEAD:main", "HEAD:refs/heads/atomic-new", cwd=self.work,
                            token=self.alice, check=False)
        assert rejected.returncode != 0
        assert self.git("ls-remote", self.remote, token=self.alice).stdout == refs_before
        # Dirty working tree, index, and detached HEAD are independent client states.
        self.git("checkout", "--detach", self.second, cwd=self.work)
        (self.work / "unstaged.txt").write_text("unstaged\n")
        (self.work / "staged.txt").write_text("staged\n")
        self.git("add", "staged.txt", cwd=self.work)
        status = self.git("status", "--porcelain=v1", cwd=self.work).stdout.decode()
        assert "A  staged.txt" in status and "?? unstaged.txt" in status
        self.git("fetch", "origin", cwd=self.work, token=self.alice)
        assert self.git("status", "--porcelain=v1", cwd=self.work).stdout.decode() == status
        return {"protocols": outputs, "atomic_rejected_without_partial_refs": True,
                "annotated_tag": True, "detached_dirty_index_preserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    for required in ("ROOTYARD_TEST_DATABASE_URL", "ROOTYARD_JGIT_CLASSPATH", "ROOTYARD_PYGIT2_PYTHON"):
        if not os.environ.get(required):
            parser.error(required + " is required; missing clients are not passes")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    os.environ["ROOTYARD_TEST_EVIDENCE_DIR"] = str(args.report.parent / (args.report.stem + "-evidence"))
    h = Compatibility(args)
    h.transcripts = []
    success = False
    versions = {}
    try:
        versions["build"] = build_record(args.binary)
        versions["git"] = h.git("--version").stdout.decode().strip()
        versions["workspace_commit"] = h.git("rev-parse", "HEAD", cwd=Path(__file__).resolve().parents[1]).stdout.decode().strip()
        versions["libgit2"] = h.run([os.environ["ROOTYARD_PYGIT2_PYTHON"], "-c",
                                    "import pygit2; print(pygit2.__version__, pygit2.LIBGIT2_VERSION)"]).stdout.decode().strip()
        versions["jgit_jars"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in Path(os.environ["ROOTYARD_JGIT_CLASSPATH"].rstrip("*")).glob("*.jar")}
        assert versions["jgit_jars"], "JGit classpath must contain version-pinned jars"
        for name in ("setup", "api", "roundtrip", "independent_roundtrips", "stock_protocol_states",
                     "filter_and_symbolic_refs", "sha256_clients", "thin_delta_pack", "stock_lfs"):
            h.case(name, getattr(h, name))
        versions["postgres"] = h.sql("SELECT version()")
        success = True
    except Exception as error:
        h.results.append({"name": "compatibility", "status": "failed", "error": h.redact(error)})
    finally:
        h.cleanup()
        report = {"passed": success, "backend": "native", "cases": h.results, "versions": versions,
                  "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                  "transcripts": h.transcripts,
                  "unsupported": ["SSH", "partial clone filters", "JGit/libgit2 SHA-256"],
                  "unverified": ["Independent-client LFS extensions beyond stock git-lfs"]}
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"passed": success, "cases": h.results}, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
