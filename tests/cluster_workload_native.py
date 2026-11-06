#!/usr/bin/env python3
"""Real 1/2/4-process Git ingress workload with raw, reproducible evidence."""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid

from e2e import Harness


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(base, path, token, method="GET", body=None, extra_headers=None):
    headers = {"Authorization": "Bearer " + token["token"]} if token else {}
    if body is not None:
        body = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    headers.update(extra_headers or {})
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


def loopback_bytes():
    for line in Path("/proc/net/dev").read_text().splitlines():
        if line.lstrip().startswith("lo:"):
            fields = line.split(":", 1)[1].split()
            return int(fields[0]), int(fields[8])
    raise AssertionError("loopback interface missing")


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

        browse_path = "/api/repos/alice/demo"
        status, raw = request(bases[1], browse_path + "/refs", h.reader)
        assert status == 200 and json.loads(raw)["head"]["oid"] == h.second
        status, raw = request(bases[2], browse_path + "/blob?oid=" + h.second + "&path=hello.txt", h.reader)
        assert status == 200 and json.loads(raw)["content"] == "second\n"
        status, _ = request(bases[3], browse_path + "/refs", h.bob)
        assert status in (403, 404), "foreign tenant read through browse ingress"
        # The destination consumes a signed, repository/actor/path-bound
        # delegation once. Replays and cross-path use fail before a handler.
        status, route_raw = request(bases[0], browse_path + "/shard-route", h.alice)
        assert status == 200
        active_route = json.loads(route_raw)
        envelope = {"version": 1,
                    "authority_incarnation": h.sql("SELECT incarnation::text FROM cluster_authority WHERE singleton=true"),
                    "nonce": str(uuid.uuid4()), "expires_unix": int(time.time()) + 30,
                    "actor_id": h.sql("SELECT id::text FROM users WHERE username='alice'"),
                    "token_id": h.reader["token_id"], "repository_id": h.repo["id"],
                    "target_node_id": "shard-primary-0",
                    "route_epoch": active_route["route_epoch"],
                    "fencing_token": active_route["fencing_token"],
                    "storage_generation": 1, "method": "GET",
                    "path_and_query": browse_path + "/refs"}
        payload = json.dumps(envelope, separators=(",", ":")).encode()
        signing_key = base64.b64decode(h.env["ROOTYARD_CLUSTER_HMAC_KEY"])
        b64 = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        delegation = b64(payload) + "." + b64(hmac.new(signing_key, payload, hashlib.sha256).digest())
        header = {"x-rootyard-cluster-delegation": delegation}
        assert request(bases[0], browse_path + "/refs", None, extra_headers=header)[0] == 200
        assert request(bases[0], browse_path + "/refs", None, extra_headers=header)[0] == 401
        assert request(bases[0], browse_path + "/commits", None, extra_headers=header)[0] == 401
        assert request(bases[0], browse_path + "/refs", None,
                       extra_headers={"x-rootyard-cluster-delegation": "malformed"})[0] == 401
        ref_name = "refs/heads/cluster-route-proof"
        tx_body = {"storage_generation": 1, "atomic": True,
                   "updates": [{"ref_name": ref_name, "old_oid": "0" * 40, "new_oid": h.second}]}
        idem = {"Idempotency-Key": "native-cluster-browse-route"}
        status, raw = request(bases[1], browse_path + "/ref-transactions",
                              h.alice, "POST", tx_body, idem)
        assert status == 200, (status, raw[:300])
        operation_id = json.loads(raw)["operation_id"]
        status, repeated = request(bases[2], browse_path + "/ref-transactions",
                                   h.alice, "POST", tx_body, idem)
        assert status == 200 and json.loads(repeated)["operation_id"] == operation_id
        status, raw = request(bases[3], browse_path + "/refs", h.reader)
        assert status == 200 and ref_name in [item["name"] for item in json.loads(raw)["items"]]
        report["browse_routing"] = {"read_ingress_nodes": [1, 2, 3],
                                    "owner_only_ref_transaction_idempotent_across_ingress": True,
                                    "unrelated_tenant_denied": True,
                                    "delegation_replay_cross_path_and_tamper_rejected": True,
                                    "ref_transaction_operation_id": operation_id}

        for tier in (1, 2, 4):
            push_ms, fetch_ms = [], []
            started = time.monotonic()
            rx_before, tx_before = loopback_bytes()
            for sequence in range(8):
                base = bases[sequence % tier]
                (h.work / "hello.txt").write_text(f"tier={tier} sequence={sequence}\n")
                h.git("commit", "-am", f"native tier {tier} #{sequence}", cwd=h.work)
                tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
                began = time.monotonic_ns()
                pushed = h.git("push", base + repo_path, "HEAD:main", cwd=h.work,
                               token=h.alice, check=False)
                assert pushed.returncode == 0, (
                    f"tier {tier} ingress {base} push rejected: "
                    + h.redact(pushed.stderr.decode(errors="replace")[-350:])
                    + "; repo=" + h.sql("SELECT state || ':' || COALESCE(recovery_reason,'') FROM repositories WHERE id='" + h.repo["id"] + "'")
                    + "; outcomes=" + h.sql("SELECT outcome || ':' || COUNT(*) FROM git_operations WHERE repository_id='" + h.repo["id"] + "' GROUP BY outcome"))
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
            rx_after, tx_after = loopback_bytes()
            report["tiers"].append({"node_count": tier, "duration_ms": round((time.monotonic() - started) * 1000, 3),
                                    "push": percentiles(push_ms), "fetch": percentiles(fetch_ms),
                                    "host_loopback_rx_delta_bytes": rx_after - rx_before,
                                    "host_loopback_tx_delta_bytes": tx_after - tx_before,
                                    "git_operation_rows": int(h.sql("SELECT COUNT(*) FROM git_operations WHERE repository_id='" + h.repo["id"] + "'")),
                                    "processes": [process_sample(h.proc.pid)] + [process_sample(p.pid) for p, _ in extra[:tier - 1]]})

        last_tip = report["raw"][-1]["acknowledged_oid"]
        for index in range(1, 4):
            assert not (h.root / ("data-node" + str(index)) / "repos" / (h.repo["id"] + ".git")).exists(), "ingress unexpectedly contains owner data"
        stopped_at = time.monotonic_ns()
        h.stop(hard=True)
        status, _ = request(bases[1], repo_path + "/info/refs?service=git-upload-pack", h.reader)
        report["failure"]["read_while_owner_stopped_status"] = status
        assert status >= 500, "unreachable owner did not fail closed"
        status, _ = request(bases[2], browse_path + "/refs", h.reader)
        report["failure"]["browse_while_owner_stopped_status"] = status
        assert status >= 500, "unreachable owner browse did not fail closed"
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
        # Exercise real Git reachability and GC while clients fetch through all
        # ingress processes. Keep a CI-style pin across the collection.
        h.git("--git-dir=" + str(h.bare), "update-ref", "refs/rootyard-ci/jobs/bench", last_tip)
        gc = subprocess.Popen(["git", "--git-dir=" + str(h.bare), "gc", "--prune=2.weeks.ago"],
                              env=h.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        gc_overlap = False
        for base in bases:
            gc_overlap |= gc.poll() is None
            h.git("fetch", base + repo_path, "refs/heads/main", cwd=h.copy, token=h.reader)
            assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == resumed_tip
        _, gc_error = gc.communicate(timeout=60)
        assert gc.returncode == 0, gc_error.decode(errors="replace")[-300:]
        pinned = h.git("--git-dir=" + str(h.bare), "rev-list", "--objects", "refs/rootyard-ci/jobs/bench").stdout.decode().splitlines()
        pinned_oids = [line.split()[0] for line in pinned]
        assert pinned_oids and all(h.git("--git-dir=" + str(h.bare), "cat-file", "-e", oid, check=False).returncode == 0
                                   for oid in pinned_oids)
        h.git("--git-dir=" + str(h.bare), "fsck", "--full", "--strict")
        report["retained_root"] = {"ref": "refs/rootyard-ci/jobs/bench", "reachable_oids_after_gc": len(pinned_oids),
                                   "native_fsck": "passed", "gc_overlapped_client_fetches": gc_overlap}
        shutil.rmtree(h.copy)
        h.git("clone", bases[3] + repo_path, str(h.copy), token=h.reader)
        assert h.git("rev-parse", "refs/heads/main", cwd=h.copy).stdout.decode().strip() == resumed_tip
        report["client_cache_eviction"] = {"removed_local_clone_and_refetched_from_node4": True,
                                           "acknowledged_oid": resumed_tip}
        # A negative control uses a copy of the real owner repository so the
        # live service remains valid for the RPO evidence above.
        damaged = h.root / "damaged-reachability-fixture.git"
        shutil.copytree(h.bare, damaged)
        blob = h.run(["git", "--git-dir=" + str(damaged), "hash-object", "-w", "--stdin"],
                     data=b"retained object removed by negative control\n").stdout.decode().strip()
        h.git("--git-dir=" + str(damaged), "update-ref", "refs/rootyard-ci/jobs/removal-check", blob)
        loose = damaged / "objects" / blob[:2] / blob[2:]
        assert loose.is_file()
        loose.unlink()
        assert h.git("--git-dir=" + str(damaged), "cat-file", "-e", blob, check=False).returncode != 0
        assert h.git("--git-dir=" + str(damaged), "fsck", "--full", "--strict", check=False).returncode != 0
        report["removed_object_negative_control"] = {"fixture": "copy of owner repository",
                                                       "removed_pinned_blob_oid": blob,
                                                       "cat_file_detected_missing": True, "native_fsck_failed": True}
        # Forge backend resolution advances the authoritative repository
        # generation without changing the shard route epoch. A previously
        # signed, unused delegation must fail at the destination itself.
        before_generation = int(h.sql("SELECT storage_generation FROM repositories WHERE id='" + h.repo["id"] + "'"))
        status, route_raw = request(bases[0], browse_path + "/shard-route", h.alice)
        assert status == 200
        before_route = json.loads(route_raw)
        def signed_delegation(path, generation):
            envelope = {"version": 1,
                        "authority_incarnation": h.sql("SELECT incarnation::text FROM cluster_authority WHERE singleton=true"),
                        "nonce": str(uuid.uuid4()), "expires_unix": int(time.time()) + 30,
                        "actor_id": h.sql("SELECT id::text FROM users WHERE username='alice'"),
                        "token_id": h.reader["token_id"], "repository_id": h.repo["id"],
                        "target_node_id": "shard-primary-0",
                        "route_epoch": before_route["route_epoch"],
                        "fencing_token": before_route["fencing_token"],
                        "storage_generation": generation, "method": "GET", "path_and_query": path}
            payload = json.dumps(envelope, separators=(",", ":")).encode()
            return b64(payload) + "." + b64(hmac.new(signing_key, payload, hashlib.sha256).digest())
        stale_browse = signed_delegation(browse_path + "/refs", before_generation)
        git_discovery = repo_path + "/info/refs?service=git-upload-pack"
        stale_git = signed_delegation(git_discovery, before_generation)
        status, raw = request(bases[0], browse_path + "/backend", h.alice, "PATCH",
                              {"storage_backend": "gitfs", "expected_storage_generation": before_generation,
                               "write_paused": False})
        assert status == 200, (status, raw[:300])
        after_generation = int(h.sql("SELECT storage_generation FROM repositories WHERE id='" + h.repo["id"] + "'"))
        assert after_generation == before_generation + 1
        status, route_raw = request(bases[0], browse_path + "/shard-route", h.alice)
        assert status == 200
        after_route = json.loads(route_raw)
        assert (before_route["route_epoch"], before_route["fencing_token"]) == (
            after_route["route_epoch"], after_route["fencing_token"])
        assert request(bases[0], browse_path + "/refs", None,
                       extra_headers={"x-rootyard-cluster-delegation": stale_browse})[0] == 409
        assert request(bases[0], git_discovery, None,
                       extra_headers={"x-rootyard-cluster-delegation": stale_git})[0] == 409
        assert request(bases[0], browse_path + "/refs", None,
                       extra_headers={"x-rootyard-cluster-delegation":
                                      signed_delegation(browse_path + "/refs", after_generation)})[0] == 200
        assert request(bases[0], git_discovery, None,
                       extra_headers={"x-rootyard-cluster-delegation":
                                      signed_delegation(git_discovery, after_generation)})[0] == 200
        report["stale_delegation"] = {"mutation": "native Forge backend PATCH gitfs generation increment",
                                      "route_epoch_unchanged": True,
                                      "old_generation": before_generation, "new_generation": after_generation,
                                      "unused_old_browse_and_git_delegations_status": 409,
                                      "fresh_browse_and_git_delegations_status": 200}
        report["untested"] = [item for item in report["untested"] if item != "cache eviction"] + ["CI mirror cache eviction"]
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
