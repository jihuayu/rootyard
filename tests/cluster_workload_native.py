#!/usr/bin/env python3
"""Real 1/2/4-process Git ingress workload with raw, reproducible evidence."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

from e2e import Harness


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(base, path, token, method="GET", body=None):
    headers = {"Authorization": "Bearer " + token["token"]}
    if body is not None:
        body = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def percentiles(samples):
    samples = sorted(samples)
    if not samples:
        return {}
    return {"count": len(samples), "p50_ms": samples[(len(samples) * 50 + 99) // 100 - 1],
            "p95_ms": samples[(len(samples) * 95 + 99) // 100 - 1],
            "p99_ms": samples[(len(samples) * 99 + 99) // 100 - 1]}


def process_sample(pid):
    path = Path("/proc") / str(pid)
    try:
        status = (path / "status").read_text()
        io = (path / "io").read_text()
        return {"pid": pid,
                "rss_kb": next(int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")),
                "read_bytes": next(int(line.split()[1]) for line in io.splitlines() if line.startswith("read_bytes:")),
                "write_bytes": next(int(line.split()[1]) for line in io.splitlines() if line.startswith("write_bytes:"))}
    except (OSError, StopIteration, ValueError):
        return {"pid": pid, "sample_error": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    h = Harness(args)
    h.env["ROOTYARD_NODE_ID"] = "shard-primary-0"
    h.env["ROOTYARD_CLUSTER_HMAC_KEY"] = base64.b64encode(os.urandom(32)).decode()
    extra = []
    report = {"kind": "native_cluster_client_workload", "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "source_base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True).strip(),
              "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
              "hardware": {"kernel": platform.release(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
                           "mem_total_kb": next((int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
                                                 if line.startswith("MemTotal:")), None)},
              "dataset": "one private repository, 24 sequential one-file commits, eight push/fetch pairs per tier",
              "topology": "distinct Rust processes and storage directories; one PostgreSQL schema; loopback signed forwarding",
              "tiers": [], "failure": {}, "raw": [], "untested": ["automatic takeover", "physical storage fencing", "PostgreSQL HA", "network partition", "disk pressure", "cache eviction"]}
    try:
        h.setup()
        report["postgres_version"] = h.sql("SHOW server_version")
        h.sql("INSERT INTO cluster_operator_tokens(token_id, granted_by) VALUES ('" + h.alice["token_id"] + "', 'native-workload')")
        node0 = "http://" + h.env["ROOTYARD_BIND"]
        status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
            "node_id": "shard-primary-0", "endpoint": node0, "role": "primary", "status": "healthy"})
        assert status in (200, 201), status
        h.api()
        h.roundtrip()
        repo_path = h.repo["clone_path"]
        status, route = request(node0, "/api/repos/alice/demo/shard-route", h.alice)
        assert status == 200 and json.loads(route)["primary_node_id"] == "shard-primary-0"
        bases = [node0]
        for index in range(1, 4):
            port = free_port()
            base = "http://127.0.0.1:" + str(port)
            env = h.env.copy()
            env.update(ROOTYARD_NODE_ID="node" + str(index), ROOTYARD_BIND="127.0.0.1:" + str(port),
                       ROOTYARD_DATA_DIR=str(h.root / ("data-node" + str(index))), ROOTYARD_OUTBOX_WORKER="false")
            log = open(h.root / ("node" + str(index) + ".log"), "ab")
            proc = subprocess.Popen([args.binary, "serve"], env=env, stdout=log, stderr=log, start_new_session=True)
            extra.append((proc, log))
            until = time.monotonic() + 30
            while time.monotonic() < until:
                if proc.poll() is not None:
                    raise AssertionError("extra node exited during startup")
                try:
                    if request(base, "/health/ready", h.alice)[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(.1)
            else:
                raise AssertionError("extra node readiness timeout")
            status, _ = request(node0, "/api/shards/nodes", h.alice, "POST", {
                "node_id": "node" + str(index), "endpoint": base, "role": "replica", "status": "healthy"})
            assert status in (200, 201), status
            bases.append(base)

        for tier in (1, 2, 4):
            push_ms, fetch_ms = [], []
            started = time.monotonic()
            for sequence in range(8):
                base = bases[sequence % tier]
                (h.work / "hello.txt").write_text(f"tier={tier} sequence={sequence}\n")
                h.git("commit", "-am", f"native tier {tier} #{sequence}", cwd=h.work)
                tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
                began = time.monotonic_ns()
                h.git("push", base + repo_path, "HEAD:main", cwd=h.work, token=h.alice)
                push_latency = round((time.monotonic_ns() - began) / 1e6, 3)
                began = time.monotonic_ns()
                h.git("fetch", base + repo_path, "refs/heads/main", cwd=h.copy, token=h.reader)
                fetch_latency = round((time.monotonic_ns() - began) / 1e6, 3)
                fetched = h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip()
                assert fetched == tip, "acknowledged commit missing on fetch"
                push_ms.append(push_latency)
                fetch_ms.append(fetch_latency)
                report["raw"].append({"tier": tier, "sequence": sequence, "ingress_node": sequence % tier,
                                      "acknowledged_oid": tip, "push_ms": push_latency, "fetch_ms": fetch_latency})
            report["tiers"].append({"node_count": tier, "duration_ms": round((time.monotonic() - started) * 1000, 3),
                                    "push": percentiles(push_ms), "fetch": percentiles(fetch_ms),
                                    "processes": [process_sample(h.proc.pid)] + [process_sample(p.pid) for p, _ in extra[:tier - 1]]})

        last_tip = report["raw"][-1]["acknowledged_oid"]
        for index in range(1, 4):
            assert not (h.root / ("data-node" + str(index)) / "repos" / (h.repo["id"] + ".git")).exists(), "ingress unexpectedly contains owner data"
        stopped_at = time.monotonic_ns()
        h.stop(hard=True)
        status, _ = request(bases[1], repo_path + "/info/refs?service=git-upload-pack", h.reader)
        report["failure"]["read_while_owner_stopped_status"] = status
        assert status >= 500, "unreachable owner did not fail closed"
        h.start()
        recovered_at = time.monotonic_ns()
        h.git("fetch", bases[1] + repo_path, "refs/heads/main", cwd=h.copy, token=h.reader)
        read_recovered_at = time.monotonic_ns()
        actual = h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip()
        assert actual == last_tip, "acknowledged write lost after owner restart"
        missing = [sample["acknowledged_oid"] for sample in report["raw"]
                   if h.git("--git-dir=" + str(h.bare), "cat-file", "-e", sample["acknowledged_oid"] + "^{commit}", check=False).returncode]
        assert not missing, "acknowledged commits lost after owner restart"
        (h.work / "hello.txt").write_text("write after owner restart\n")
        h.git("commit", "-am", "post restart write", cwd=h.work)
        resumed_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", bases[1] + repo_path, "HEAD:main", cwd=h.work, token=h.alice)
        write_recovered_at = time.monotonic_ns()
        h.git("fetch", bases[2] + repo_path, "refs/heads/main", cwd=h.copy, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == resumed_tip
        report["failure"].update({"injection": "SIGKILL owner process group", "rpo_lost_acknowledged_commits": len(missing),
                                  "acknowledged_commits_checked": len(report["raw"]), "unreachable_owner_failed_closed": True,
                                  "rto_read_ms": round((read_recovered_at - stopped_at) / 1e6, 3),
                                  "rto_write_ms": round((write_recovered_at - stopped_at) / 1e6, 3),
                                  "post_restart_acknowledged_oid": resumed_tip,
                                  "process_restart_ms": round((recovered_at - stopped_at) / 1e6, 3)})
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report), "tiers": [1, 2, 4]}))
    finally:
        for proc, log in reversed(extra):
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)
            log.close()
        h.cleanup()


if __name__ == "__main__":
    main()
