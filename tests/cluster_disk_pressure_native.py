#!/usr/bin/env python3
"""Exercise a real Rootyard Git service on an isolated, full Docker tmpfs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from e2e import Harness


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=75)
    if check and result.returncode:
        raise AssertionError(f"docker failed: {result.stderr.decode(errors='replace')[-600:]}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    h = Harness(args)
    name = "rootyard-disk-" + uuid.uuid4().hex[:10]
    started = False
    try:
        h.sql('CREATE SCHEMA "' + h.schema + '"', isolated=False)
        h.schema_created = True
        h.cli("migrate")
        h.alice = h.account("create-user", "alice")
        h.bob = h.account("create-user", "bob")
        h.reader = h.account("create-token", "alice", "--read-only")
        # Host libraries and native Git are mounted read-only; only /data is
        # writable. Docker supplies a private 128 MiB tmpfs, so ENOSPC cannot
        # consume shared workspace disk or another test's fixture.
        docker("run", "-d", "--name", name, "--network", "host",
               "--tmpfs", "/data:rw,exec,size=128m", "--tmpfs", "/tmp:rw,size=16m", "--read-only",
               "-v", args.binary + ":/usr/local/bin/rootyard:ro",
               "-v", "/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:ro",
               "-v", "/lib64/ld-linux-x86-64.so.2:/lib64/ld-linux-x86-64.so.2:ro",
               "-v", "/usr/bin/git:/usr/bin/git:ro",
               "-v", "/usr/lib/git-core:/usr/lib/git-core:ro",
               "-e", "DATABASE_URL=" + h.db,
               "-e", "ROOTYARD_DATA_DIR=/data",
               "-e", "ROOTYARD_BIND=" + h.env["ROOTYARD_BIND"],
               "-e", "ROOTYARD_OUTBOX_WORKER=false",
               "-e", "GIT_CONFIG_NOSYSTEM=1",
               "alpine:3.20", "rootyard", "serve")
        started = True
        until = time.monotonic() + 20
        while time.monotonic() < until:
            try:
                if h.http("/health/ready")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(.1)
        else:
            raise AssertionError("container Rootyard did not become ready: " +
                                 docker("logs", name).stderr.decode(errors="replace")[-800:])
        h.repo = json.loads(h.expect("/api/repos", 201, method="POST", token=h.alice,
                                     body={"name": "demo"}))
        h.remote = h.base + h.repo["clone_path"]
        h.work = h.root / "work"
        h.roundtrip()
        retained_tip = h.second
        bare = "/data/repos/" + h.repo["id"] + ".git"
        assert docker("exec", name, "git", "--git-dir=" + bare, "fsck",
                      "--full", "--strict").returncode == 0
        fill = docker("exec", name, "dd", "if=/dev/zero", "of=/data/pressure.bin",
                      "bs=1048576", "count=128", check=False)
        assert fill.returncode != 0 and b"No space left on device" in fill.stderr, (
            "isolated volume did not reach ENOSPC")
        free_kib = int(docker("exec", name, "sh", "-c",
                              "df -k /data | tail -1 | awk '{print $4}'").stdout.decode().strip())
        assert free_kib == 0, "storage volume retained free blocks"
        (h.work / "hello.txt").write_text("write under true ENOSPC\n")
        h.git("commit", "-am", "disk full attempt", cwd=h.work)
        rejected_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        failed_push = h.git("push", "origin", "HEAD:main", cwd=h.work,
                            token=h.alice, check=False)
        assert failed_push.returncode != 0, "Git push falsely acknowledged while /data was full"
        outcome_counts_during_pressure = h.sql(
            "SELECT outcome || ':' || count(*) FROM git_operations WHERE repository_id='"
            + h.repo["id"] + "' GROUP BY outcome ORDER BY outcome").splitlines()
        docker("exec", name, "rm", "/data/pressure.bin")
        h.git("fetch", h.remote, "refs/heads/main", cwd=h.copy, token=h.reader)
        observed_tip = h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip()
        assert observed_tip == retained_tip, "acknowledged ref changed during rejected ENOSPC push"
        assert docker("exec", name, "git", "--git-dir=" + bare, "fsck",
                      "--full", "--strict").returncode == 0
        # An interrupted/failed push can conservatively require operator
        # recovery; measure that response rather than treating it as success.
        retry = h.git("push", "origin", "HEAD:main", cwd=h.work,
                      token=h.alice, check=False)
        after_retry = h.git("ls-remote", h.remote, "main", token=h.reader).stdout.decode()
        if retry.returncode == 0:
            assert after_retry.startswith(rejected_tip)
        else:
            assert after_retry.startswith(retained_tip)
        report = {
            "kind": "native_rootyard_git_enospc",
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "docker_version": docker("version", "--format", "{{.Server.Version}}").stdout.decode().strip(),
            "container_image_id": docker("image", "inspect", "alpine:3.20", "--format", "{{.Id}}").stdout.decode().strip(),
            "git_version": docker("exec", name, "git", "--version").stdout.decode().strip(),
            "postgres_version": h.sql("SHOW server_version"),
            "topology": "one Rust service in rootless Docker; private 128 MiB tmpfs; external PostgreSQL 17",
            "mount_size_mib": 128, "free_kib_at_push": free_kib,
            "fault": "dd writes /data/pressure.bin until kernel returns ENOSPC",
            "retained_acknowledged_oid": retained_tip,
            "rejected_oid": rejected_tip,
            "push_exit_code_during_enospc": failed_push.returncode,
            "push_stderr_excerpt": h.redact(failed_push.stderr.decode(errors="replace")[-500:]),
            "git_operation_outcome_counts_during_pressure": outcome_counts_during_pressure,
            "ref_after_removing_pressure": observed_tip,
            "native_fsck_after_pressure": "passed",
            "post_pressure_retry_acked": retry.returncode == 0,
            "limits": ["local rootless Docker tmpfs rather than hardware disk",
                       "one small repository; no production scale or power-loss assertion"]
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report),
                          "retry_acked": retry.returncode == 0}))
    finally:
        if started:
            docker("rm", "-f", name, check=False)
        h.cleanup()


if __name__ == "__main__":
    main()
