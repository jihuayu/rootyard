#!/usr/bin/env python3
"""Start, verify, and stop a trusted local multi-process Rootyard profile."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlsplit
import urllib.error
import urllib.request
import uuid


def private_file(path):
    path = Path(path)
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) & 0o077:
        raise ValueError(f"secret file must be regular and private: {path}")
    return path.resolve()


def read_env(path):
    result = {}
    for line in private_file(path).read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name in result:
            raise ValueError(f"invalid environment entry in {path}")
        result[name] = value
    return result


def read_account(path):
    value = json.loads(private_file(path).read_text())
    if not isinstance(value, dict) or not isinstance(value.get("username"), str) or not isinstance(value.get("token"), str):
        raise ValueError("account file needs JSON username and token")
    return value


def private_dir(path):
    path = Path(path)
    if path.exists():
        meta = path.lstat()
        if not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o700:
            raise ValueError(f"state directory must be a real 0700 directory: {path}")
    else:
        path.mkdir(parents=True, mode=0o700)
    return path.resolve()


def write_private(path, content):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def validate_env(values):
    url = validate_pg(values)
    if len(base64.b64decode(values["ROOTYARD_CLUSTER_HMAC_KEY"], validate=True)) < 32:
        raise ValueError("cluster HMAC key is too short")
    for key, expected in {
        "ROOTYARD_WAKE_TRANSPORT": "kafka",
        "ROOTYARD_KAFKA_SECURITY_PROTOCOL": "SASL_SSL",
        "ROOTYARD_KAFKA_SASL_MECHANISM": "PLAIN",
    }.items():
        if values.get(key) != expected:
            raise ValueError(f"{key} must equal {expected}")
    private_file(values["ROOTYARD_KAFKA_CA_PEM"])
    for key in ("ROOTYARD_KAFKA_BOOTSTRAP_SERVERS", "ROOTYARD_KAFKA_TOPIC",
                "ROOTYARD_KAFKA_SASL_USERNAME", "ROOTYARD_KAFKA_SASL_PASSWORD",
                "ROOTYARD_KAFKA_GROUP"):
        if not values.get(key):
            raise ValueError(f"{key} is required")
    for key in ("ROOTYARD_KAFKA_SASL_USERNAME", "ROOTYARD_KAFKA_SASL_PASSWORD"):
        if not re.fullmatch(r"[A-Za-z0-9_@.\-]+", values[key]):
            raise ValueError(f"{key} cannot be safely written to JAAS properties")
    return url


def validate_pg(values):
    if not values.get("DATABASE_URL"):
        raise ValueError("DATABASE_URL is required")
    url = urlsplit(values["DATABASE_URL"])
    if url.scheme not in ("postgres", "postgresql") or not url.hostname or not url.username or not url.password:
        raise ValueError("DATABASE_URL needs TCP host, role username, and password")
    if parse_qs(url.query).get("sslmode") != ["require"]:
        raise ValueError("DATABASE_URL must use sslmode=require")
    private_file(values["ROOTYARD_PG_CA_PEM"])
    return url


def pg_preflight(values):
    url = validate_pg(values)
    env = os.environ.copy()
    env.update(PGHOST=url.hostname, PGPORT=str(url.port or 5432),
               PGUSER=unquote(url.username), PGPASSWORD=unquote(url.password),
               PGDATABASE=url.path.lstrip("/") or "postgres",
               PGSSLMODE="verify-full", PGSSLROOTCERT=values["ROOTYARD_PG_CA_PEM"])
    result = subprocess.run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1",
                             "-c", "SELECT CASE WHEN ssl THEN 'tls' ELSE 'plain' END || ':' || current_user "
                             "FROM pg_stat_ssl WHERE pid=pg_backend_pid()"],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if result.returncode or not result.stdout.decode().startswith("tls:"):
        raise RuntimeError("PostgreSQL verify-full identity preflight failed")
    return result.stdout.decode().strip().split(":", 1)[1]


def kafka_preflight(state, role, values, kafka_bin):
    truststore = state / f"{role}.truststore.p12"
    password = secrets.token_hex(12)
    result = subprocess.run(["keytool", "-importcert", "-noprompt", "-alias", "ca",
                             "-file", values["ROOTYARD_KAFKA_CA_PEM"], "-keystore", str(truststore),
                             "-storetype", "PKCS12", "-storepass", password],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if result.returncode:
        raise RuntimeError("Kafka truststore creation failed")
    truststore.chmod(0o600)
    props = state / f"{role}.kafka.properties"
    write_private(props, "\n".join([
        "security.protocol=SASL_SSL", "sasl.mechanism=PLAIN",
        "sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required "
        f'username="{values["ROOTYARD_KAFKA_SASL_USERNAME"]}" '
        f'password="{values["ROOTYARD_KAFKA_SASL_PASSWORD"]}";',
        "ssl.truststore.type=PKCS12", f"ssl.truststore.location={truststore}",
        f"ssl.truststore.password={password}",
        "ssl.endpoint.identification.algorithm=https",
    ]) + "\n")
    result = subprocess.run([str(kafka_bin / "kafka-topics.sh"), "--bootstrap-server",
                             values["ROOTYARD_KAFKA_BOOTSTRAP_SERVERS"], "--command-config",
                             str(props), "--list"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=20)
    if result.returncode:
        raise RuntimeError("Kafka SASL_SSL hostname/CA/credential preflight failed")
    result = subprocess.run([str(kafka_bin / "kafka-topics.sh"), "--bootstrap-server",
                             values["ROOTYARD_KAFKA_BOOTSTRAP_SERVERS"], "--command-config",
                             str(props), "--describe", "--topic", values["ROOTYARD_KAFKA_TOPIC"]],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if result.returncode or values["ROOTYARD_KAFKA_TOPIC"].encode() not in result.stdout:
        raise RuntimeError("Kafka wake topic is absent or inaccessible to this role")
    return props


def http(base, path, token, method="GET", body=None):
    headers = {"Authorization": "Bearer " + token}
    if body is not None:
        body = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def proc_identity(pid):
    raw = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return {"pid": pid, "start_ticks": int(raw[19]), "group": int(raw[2]),
            "session": int(raw[3]), "state": raw[0],
            "boot_id": boot_id}


def is_same_process(entry):
    try:
        current = proc_identity(entry["pid"])
        return (current["start_ticks"] == entry["start_ticks"]
                and current["session"] == entry["pid"]
                and current["boot_id"] == entry["boot_id"])
    except (OSError, ValueError, IndexError):
        return False


def session_members(entry):
    if Path("/proc/sys/kernel/random/boot_id").read_text().strip() != entry["boot_id"]:
        raise RuntimeError("recorded process session belongs to another boot")
    members = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            member = proc_identity(int(path.name))
        except (OSError, ValueError, IndexError):
            continue
        if member["session"] == entry["pid"] and member["state"] != "Z":
            members.append(member)
    return members


def stop_entries(entries):
    # Verify the recorded leader before any signal. Once verified, its session
    # ID remains reserved by descendants even if the leader exits on SIGTERM.
    # Scan the whole session, not just the leader's original process group:
    # native Git children can enter their own groups within that session.
    active = []
    for entry in reversed(entries):
        if is_same_process(entry):
            active.append(entry)
        elif session_members(entry):
            raise RuntimeError("process leader identity lost while descendants survive; manifest retained")
    def signal_sessions(signum):
        for entry in active:
            for group in {member["group"] for member in session_members(entry)}:
                try:
                    os.killpg(group, signum)
                except ProcessLookupError:
                    pass
    signal_sessions(signal.SIGTERM)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and any(session_members(entry) for entry in active):
        time.sleep(.05)
    signal_sessions(signal.SIGKILL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and any(session_members(entry) for entry in active):
        time.sleep(.05)
    if any(session_members(entry) for entry in active):
        raise RuntimeError("process session did not quiesce; manifest retained")


def start_process(binary, mode, env, log_path):
    log = open(log_path, "ab", buffering=0)
    try:
        process = subprocess.Popen([str(binary), mode], env=env, stdout=log,
                                   stderr=log, start_new_session=True)
    finally:
        log.close()
    return process


def clean_preflight_files(state, node_count):
    for role in [*(f"node{index}" for index in range(node_count)), "worker"]:
        for suffix in (".truststore.p12", ".kafka.properties"):
            path = state / (role + suffix)
            if path.exists():
                private_file(path).unlink()


def service_env(values):
    env = {key: value for key, value in os.environ.items()
           if key != "DATABASE_URL" and not key.startswith(("ROOTYARD_", "PG"))}
    env.update(values)
    return env


def _run_up(args):
    state = private_dir(args.state_dir)
    if (state / "manifest.json").exists():
        raise ValueError("cluster already has a manifest; run down before up")
    # A failed credential or broker preflight must not make a corrected retry
    # fail on O_EXCL, nor leave old credential files in the private state dir.
    clean_preflight_files(state, args.nodes)
    fence = private_dir(state / "fences")
    kafka_bin = Path(args.kafka_home).resolve(strict=True) / "bin"
    binary = Path(args.binary).resolve(strict=True)
    operator = read_account(args.operator_account)
    migrator = read_env(args.env_dir / "migrator.env")
    migrator_user = pg_preflight(migrator)
    node_envs = [read_env(args.env_dir / f"node{index}.env") for index in range(args.nodes)]
    worker = read_env(args.env_dir / "worker.env")
    roles = [(f"node{index}", item) for index, item in enumerate(node_envs)] + [("worker", worker)]
    for _, item in roles:
        validate_env(item)
    db_users = [pg_preflight(item) for _, item in roles]
    kafka_users = [item["ROOTYARD_KAFKA_SASL_USERNAME"] for _, item in roles]
    if len(set(db_users + [migrator_user])) != len(db_users) + 1:
        raise ValueError("migrator, data nodes, and worker need distinct PostgreSQL identities")
    if len(set(kafka_users)) != len(kafka_users):
        raise ValueError("data nodes and worker need distinct Kafka identities")
    if len({(urlsplit(item["DATABASE_URL"]).hostname, urlsplit(item["DATABASE_URL"]).port,
             urlsplit(item["DATABASE_URL"]).path) for _, item in roles + [("migrator", migrator)]}) != 1:
        raise ValueError("all roles must use the same PostgreSQL authority")
    if len({(item["ROOTYARD_KAFKA_BOOTSTRAP_SERVERS"], item["ROOTYARD_KAFKA_TOPIC"])
            for _, item in roles}) != 1:
        raise ValueError("all service roles must use the same Kafka broker and topic")
    if len({item["ROOTYARD_KAFKA_GROUP"] for _, item in roles}) != len(roles):
        raise ValueError("service roles require distinct Kafka consumer groups")
    if len({item["ROOTYARD_CLUSTER_HMAC_KEY"] for _, item in roles}) != 1:
        raise ValueError("all service roles need the same cluster signing key")
    for role, item in roles:
        kafka_preflight(state, role, item, kafka_bin)
    migrate_env = service_env(migrator)
    migrate_env.update(migrator, ROOTYARD_DATA_DIR=str(state / "node0" / "data"),
                       ROOTYARD_OUTBOX_WORKER="false")
    migrated = subprocess.run([str(binary), "migrate"], env=migrate_env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    if migrated.returncode:
        raise RuntimeError("schema migration failed")
    entries = []
    endpoints = []
    try:
        for index, item in enumerate(node_envs):
            role = f"node{index}"
            volume = private_dir(state / role / "data")
            base = f"http://127.0.0.1:{args.base_port + index}"
            env = service_env(item)
            env.update(item, ROOTYARD_NODE_ID=role,
                       ROOTYARD_BIND=f"127.0.0.1:{args.base_port + index}",
                       ROOTYARD_DATA_DIR=str(volume),
                       ROOTYARD_LOCAL_FENCE_DIR=str(fence),
                       ROOTYARD_OUTBOX_WORKER="false")
            process = start_process(binary, "serve", env, state / (role + ".log"))
            entry = proc_identity(process.pid)
            entry.update(role=role, endpoint=base, volume=str(volume))
            entries.append(entry)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"{role} exited; inspect {state / (role + '.log')}")
                try:
                    if http(base, "/health/ready", operator["token"])[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(.1)
            else:
                raise RuntimeError(f"{role} readiness timeout")
            code, raw = http(base, "/api/shards/nodes", operator["token"], "POST",
                             {"node_id": role, "endpoint": base,
                              "role": "primary" if index == 0 else "replica",
                              "status": "healthy", "lease_ttl_seconds": 5})
            if code not in (200, 201):
                raise RuntimeError(f"{role} registration failed: HTTP {code} {raw[:200]!r}")
            endpoints.append(base)
        worker_env = service_env(worker)
        worker_env.update(worker, ROOTYARD_OUTBOX_WORKER="true")
        worker_process = start_process(binary, "worker", worker_env, state / "worker.log")
        worker_entry = proc_identity(worker_process.pid)
        worker_entry["role"] = "worker"
        entries.append(worker_entry)
        time.sleep(.3)
        if worker_process.poll() is not None:
            raise RuntimeError("worker exited; inspect worker.log")
        manifest = {
            "kind": "trusted_local_cluster_profile",
            "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "env_dir": str(args.env_dir.resolve()), "state_dir": str(state),
            "kafka_home": str(Path(args.kafka_home).resolve()),
            "node_count": args.nodes, "endpoints": endpoints, "processes": entries,
            "postgres_roles": db_users, "kafka_roles": kafka_users,
            "dependency_transport": {"postgres": "verify-full TLS", "kafka": "SASL_SSL PLAIN"},
            "limits": ["single trusted Linux host and local process-session fence",
                       "external PostgreSQL/Kafka dependencies", "no multi-host storage fencing"]
        }
        write_private(state / "manifest.json", json.dumps(manifest, indent=2) + "\n")
        print(json.dumps({"result": "running", "manifest": str(state / "manifest.json"),
                          "endpoints": endpoints}))
    except Exception:
        stop_entries(entries)
        raise


def run_up(args):
    try:
        _run_up(args)
    except Exception:
        if Path(args.state_dir).is_dir() and not (Path(args.state_dir) / "manifest.json").exists():
            clean_preflight_files(Path(args.state_dir), args.nodes)
        raise


def run_down(args):
    manifest_path = private_file(Path(args.state_dir) / "manifest.json")
    manifest = json.loads(manifest_path.read_text())
    stop_entries(manifest["processes"])
    clean_preflight_files(Path(args.state_dir), manifest["node_count"])
    manifest_path.unlink()
    print(json.dumps({"result": "stopped", "volumes_retained": True}))


def git(args, cwd, token=None):
    env = {key: value for key, value in os.environ.items()
           if key not in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    if token is not None:
        basic = base64.b64encode((token["username"] + ":" + token["token"]).encode()).decode()
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.extraHeader",
                   GIT_CONFIG_VALUE_0="Authorization: Basic " + basic)
    result = subprocess.run(["git", *args], cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60)
    if result.returncode:
        raise RuntimeError(f"native git {args[0]} failed (exit {result.returncode})")
    return result.stdout.decode().strip()


def kafka_offset(manifest):
    state = Path(manifest["state_dir"])
    worker = read_env(Path(manifest["env_dir"]) / "worker.env")
    props = private_file(state / "worker.kafka.properties")
    script = Path(manifest["kafka_home"]) / "bin" / "kafka-get-offsets.sh"
    result = subprocess.run([str(script), "--bootstrap-server", worker["ROOTYARD_KAFKA_BOOTSTRAP_SERVERS"],
                             "--command-config", str(props), "--topic", worker["ROOTYARD_KAFKA_TOPIC"],
                             "--time", "latest"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if result.returncode:
        raise RuntimeError("Kafka SASL_SSL offset read failed")
    offsets = [int(line.rsplit(":", 1)[1]) for line in result.stdout.decode().splitlines()
               if line.startswith(worker["ROOTYARD_KAFKA_TOPIC"] + ":")]
    if not offsets:
        raise RuntimeError("Kafka wake topic has no readable partition")
    return max(offsets)


def run_verify(args):
    manifest = json.loads(private_file(Path(args.state_dir) / "manifest.json").read_text())
    if manifest.get("kind") != "trusted_local_cluster_profile" or manifest["node_count"] < 2:
        raise ValueError("verify needs a running two-or-more-node local profile")
    if not all(is_same_process(entry) for entry in manifest["processes"]):
        raise RuntimeError("profile process identity changed; refusing stale verification")
    account = read_account(args.account)
    state = Path(manifest["state_dir"])
    owner = account["username"]
    name = "profile" + uuid.uuid4().hex[:12]
    primary, ingress = manifest["endpoints"][:2]
    before_wake = kafka_offset(manifest)
    status, raw = http(primary, "/api/repos", account["token"], "POST", {"name": name})
    if status != 201:
        raise RuntimeError(f"repository creation failed: HTTP {status}")
    repository = json.loads(raw)
    work = private_dir(state / ("verify-" + name))
    git(["clone", ingress + repository["clone_path"], str(work / "source")], state, account)
    source = work / "source"
    git(["config", "user.name", "Local Cluster Verification"], source)
    git(["config", "user.email", "verify@localhost.invalid"], source)
    (source / "proof.txt").write_text("routed from data node 1 to owner node 0\n")
    git(["add", "proof.txt"], source)
    git(["commit", "-m", "real routed profile push"], source)
    oid = git(["rev-parse", "HEAD"], source)
    git(["push", ingress + repository["clone_path"], "HEAD:main"], source, account)
    git(["clone", primary + repository["clone_path"], str(work / "copy")], state, account)
    fetched = git(["rev-parse", "HEAD"], work / "copy")
    if fetched != oid:
        raise RuntimeError("acknowledged Git object missing on owner clone")
    status, raw = http(ingress, f"/api/repos/{owner}/{name}/refs", account["token"])
    if status != 200 or oid.encode() not in raw:
        raise RuntimeError("owner-routed browse did not return acknowledged ref")
    after_wake = before_wake
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and after_wake <= before_wake:
        time.sleep(.25)
        after_wake = kafka_offset(manifest)
    if after_wake <= before_wake:
        raise RuntimeError("Kafka SASL_SSL wake did not advance after native push")
    report = {"kind": "native_local_cluster_profile", "binary_sha256": manifest["binary_sha256"],
              "node_count": manifest["node_count"], "postgres_roles": manifest["postgres_roles"],
              "kafka_roles": manifest["kafka_roles"], "repository_id": repository["id"],
              "acknowledged_oid": oid, "owner_clone_oid": fetched,
              "routed_browse_oid": oid, "kafka_offset_before": before_wake,
              "kafka_offset_after": after_wake, "verified_at_unix": int(time.time()),
              "scope": "single trusted Linux host, separate Rust processes/volumes with external TLS/SASL dependencies"}
    write_private(args.report, json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": "passed", "report": str(args.report), "acknowledged_oid": oid}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    up = sub.add_parser("up")
    up.add_argument("--binary", type=Path, required=True)
    up.add_argument("--env-dir", type=Path, required=True)
    up.add_argument("--state-dir", type=Path, required=True)
    up.add_argument("--kafka-home", type=Path, required=True)
    up.add_argument("--operator-account", type=Path, required=True)
    up.add_argument("--base-port", type=int, default=18100)
    up.add_argument("--nodes", type=int, choices=(2, 4), default=2)
    down = sub.add_parser("down")
    down.add_argument("--state-dir", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--state-dir", type=Path, required=True)
    verify.add_argument("--account", type=Path, required=True)
    verify.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "up":
        if not 1024 <= args.base_port <= 65535 - args.nodes:
            parser.error("base-port out of range")
        run_up(args)
    elif args.command == "down":
        run_down(args)
    else:
        run_verify(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"local cluster profile failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
