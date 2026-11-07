#!/usr/bin/env python3
"""Render the supported external HA reference configuration.

This renders a role-specific, secret-free-in-repository deployment profile for
PostgreSQL automatic failover: three etcd members (mutual TLS), Patroni-managed
PostgreSQL nodes (TLS + SCRAM, strict synchronous mode) and an HAProxy stable
endpoint that routes on the Patroni REST role health check.

The renderer is deliberately strict: it refuses plaintext DCS, PostgreSQL TLS
downgrades, unauthenticated role health checks, weak/reused passwords and
(production mode) a configuration without a real watchdog device.  Rendered
files are private (0600) because they contain credentials.

Usage:
  python3 deployment/ha/render.py --spec cluster.json --secrets secrets.json --out DIR
  python3 deployment/ha/render.py --spec cluster.json --secrets secrets.json --check
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import string

HERE = Path(__file__).resolve().parent
MIN_PORT = 26000
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
WEAK = {"changeme", "password", "postgres", "rootyard", "secret", "admin", "replication"}


class ConfigError(ValueError):
    pass


def fail(message):
    raise ConfigError(message)


def read_json(path):
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        fail(f"cannot read JSON input {path}: {type(error).__name__}")
    if not isinstance(value, dict):
        fail(f"JSON input {path} must be an object")
    return value


def private_file(path, what):
    p = Path(path)
    if not p.is_file():
        fail(f"{what} file is missing: {p}")
    mode = p.stat().st_mode & 0o777
    if mode & 0o077:
        fail(f"{what} file must not be group/other accessible: {p} ({mode:04o})")
    return p


def check_password(secrets, key):
    value = secrets.get(key)
    if not isinstance(value, str) or not PASSWORD_RE.match(value):
        fail(f"secret {key} must be 16-128 [A-Za-z0-9_-] characters")
    if value.lower() in WEAK:
        fail(f"secret {key} uses a known weak value")
    return value


def check_ports(spec):
    ports = []
    for node in spec.get("nodes", []):
        ports.extend([node.get("pg_port"), node.get("rest_port")])
    for node in spec.get("etcd", {}).get("nodes", []):
        ports.extend([node.get("client_port"), node.get("peer_port")])
    ports.extend([spec.get("haproxy", {}).get("primary_port"),
                  spec.get("haproxy", {}).get("replica_port")])
    if any(not isinstance(p, int) for p in ports):
        fail("every node/haproxy port must be an integer")
    if any(p < MIN_PORT or p > 65535 for p in ports):
        fail(f"HA profile ports must be >= {MIN_PORT} to avoid protected system services")
    if len(ports) != len(set(ports)):
        fail("HA profile ports must be unique")
    return ports


def check_synchronous(spec):
    sync = spec.get("synchronous", {})
    if sync.get("synchronous_commit") != "remote_apply":
        fail("synchronous_commit must be 'remote_apply'; refusing a weaker durability mode")
    if not sync.get("synchronous_mode", True) or not sync.get("synchronous_mode_strict", True):
        fail("synchronous_mode and synchronous_mode_strict must both be enabled")
    ttl = sync.get("ttl", 10)
    loop_wait = sync.get("loop_wait", 2)
    retry_timeout = sync.get("retry_timeout", 3)
    if not (20 <= ttl <= 600 and 1 <= loop_wait <= 30 and 1 <= retry_timeout <= 30):
        fail("ttl must be 20-600 and loop_wait/retry_timeout bounded positive integers")
    if retry_timeout >= ttl:
        fail("retry_timeout must be smaller than ttl")
    return ttl, loop_wait, retry_timeout


def check_tls(spec):
    tls = spec.get("tls") or {}
    ca = private_file(tls.get("ca", ""), "CA certificate")
    cert = private_file(tls.get("server_cert", ""), "PostgreSQL server certificate")
    key = private_file(tls.get("server_key", ""), "PostgreSQL server key")
    etcd = spec.get("etcd") or {}
    dcs_ca = private_file(etcd.get("client_ca", ""), "DCS CA certificate")
    dcs_cert = private_file(etcd.get("client_cert", ""), "DCS client certificate")
    dcs_key = private_file(etcd.get("client_key", ""), "DCS client key")
    peer_ca = private_file(etcd.get("peer_ca", ""), "DCS peer CA certificate")
    peer_cert = private_file(etcd.get("peer_cert", ""), "DCS peer certificate")
    peer_key = private_file(etcd.get("peer_key", ""), "DCS peer key")
    return {"ca": ca, "cert": cert, "key": key, "dcs_ca": dcs_ca, "dcs_cert": dcs_cert,
            "dcs_key": dcs_key, "peer_ca": peer_ca, "peer_cert": peer_cert, "peer_key": peer_key}


def optional_watchdog(spec):
    environment = spec.get("environment", "lab")
    if environment not in ("lab", "production"):
        fail("environment must be 'lab' or 'production'")
    watchdog = spec.get("watchdog")
    if environment == "production":
        if not isinstance(watchdog, dict) or not watchdog.get("device"):
            fail("production profile requires a real watchdog device; refusing to certify "
                 "automatic failover on a host without fencing")
        device = Path(watchdog["device"])
        if not device.exists() or not device.is_char_device():
            fail(f"configured watchdog device is not a real character device: {device}")
        return (f"\nwatchdog:\n  mode: required\n  device: {device}\n"
                f"  safety_margin: {int(watchdog.get('safety_margin', 5))}\n")
    if watchdog:
        fail("watchdog is only rendered for the production profile")
    return ""


def render_patroni(spec, secrets, tls, node, etcd, watchdog_block, out):
    template = string.Template((HERE / "patroni.yml.in").read_text())
    etcd_lines = "\n".join(f"    - 127.0.0.1:{m['client_port']}" for m in etcd["nodes"])
    post_bootstrap = out / "bootstrap-app.sh"
    values = {
        "node_name": node["name"], "scope": spec["scope"], "environment": spec["environment"],
        "rest_port": node["rest_port"], "rest_user": secrets["patroni_rest_user"],
        "rest_password": secrets["patroni_rest_password"],
        "etcd_host_lines": etcd_lines, "etcd_ca": tls["dcs_ca"], "etcd_client_cert": tls["dcs_cert"],
        "etcd_client_key": tls["dcs_key"],
        "ttl": spec["synchronous"]["ttl"], "loop_wait": spec["synchronous"]["loop_wait"],
        "retry_timeout": spec["synchronous"]["retry_timeout"],
        "post_bootstrap": post_bootstrap,
        "pg_bin_dir": spec["pg_bin_dir"], "data_dir": node["data_dir"],
        "pg_port": node["pg_port"], "socket_dir": node["socket_dir"],
        "postgres_host_ip": spec["postgres_host_ip"],
        "superuser_password": secrets["superuser_password"],
        "repl_password": secrets["replication_password"],
        "ca": tls["ca"], "server_cert": tls["cert"], "server_key": tls["key"],
        "watchdog_block": watchdog_block,
    }
    path = out / f"patroni-{node['name']}.yml"
    path.write_text(template.substitute(values))
    os.chmod(path, 0o600)
    return path


def render_etcd(spec, tls, node, out):
    template = string.Template((HERE / "etcd.args.in").read_text())
    cluster = ",".join(f"{m['name']}=https://127.0.0.1:{m['peer_port']}" for m in spec["etcd"]["nodes"])
    values = {"name": node["name"], "data_dir": node["data_dir"],
              "client_port": node["client_port"], "peer_port": node["peer_port"],
              "initial_cluster": cluster, "cluster_token": spec["etcd"]["cluster_token"],
              "ca": tls["dcs_ca"], "cert": spec["etcd"]["server_cert"],
              "key": spec["etcd"]["server_key"], "peer_ca": tls["peer_ca"],
              "peer_cert": tls["peer_cert"], "peer_key": tls["peer_key"]}
    path = out / f"etcd-{node['name']}.args"
    path.write_text(template.substitute(values))
    os.chmod(path, 0o600)
    return path


def render_haproxy(spec, secrets, out):
    template = string.Template((HERE / "haproxy.cfg.in").read_text())
    auth = base64.b64encode((spec["haproxy"]["health_user"] + ":"
                             + secrets["haproxy_health_password"]).encode()).decode()
    servers = "\n".join(
        f"    server {node['name']} {spec['postgres_host_ip']}:{node['pg_port']} check port {node['rest_port']}"
        for node in spec["nodes"])
    values = {"primary_port": spec["haproxy"]["primary_port"],
              "replica_port": spec["haproxy"]["replica_port"],
              "stats_socket": spec["haproxy"]["stats_socket"],
              "health_auth": auth, "servers": servers}
    path = out / "haproxy.cfg"
    path.write_text(template.substitute(values))
    os.chmod(path, 0o600)
    return path


def render_rootyard(spec, secrets, tls, out):
    database = spec["rootyard"]["database"]
    user = spec["rootyard"]["user"]
    dsn = (f"postgresql://{user}:{secrets['rootyard_password']}@127.0.0.1:"
           f"{spec['haproxy']['primary_port']}/{database}?sslmode=require")
    path = out / "rootyard.env"
    path.write_text(string.Template((HERE / "rootyard.env.in").read_text()).substitute(
        database_url=dsn, ca=tls["ca"], data_dir=spec["rootyard"]["data_dir"],
        bind=spec["rootyard"]["bind"]))
    os.chmod(path, 0o600)
    bootstrap = (HERE / "bootstrap-app.sh").read_text()
    boot = out / "bootstrap-app.sh"
    boot.write_text(bootstrap.replace("@DATABASE@", database).replace("@USER@", user))
    os.chmod(boot, 0o700)
    return path, boot


def validate(spec, secrets):
    nodes = spec.get("nodes") or []
    etcd = (spec.get("etcd") or {}).get("nodes") or []
    if len(nodes) < 2:
        fail("at least two Patroni-managed PostgreSQL nodes are required")
    if len(etcd) < 3:
        fail("three etcd members are required for an actual quorum")
    if any(not re.match(r"^[a-z][a-z0-9-]{1,30}$", str(n.get("name", ""))) or not n.get("name") for n in nodes):
        fail("Patroni node names must be short lowercase identifiers")
    for key in ("scope", "pg_bin_dir"):
        if not spec.get(key):
            fail(f"spec.{key} is required")
    haproxy = spec.get("haproxy") or {}
    for key in ("primary_port", "replica_port", "stats_socket", "health_user"):
        if not haproxy.get(key):
            fail(f"haproxy.{key} is required")
    if haproxy["primary_port"] == haproxy["replica_port"]:
        fail("primary and replica endpoints must be different ports")
    host_ip = str(spec.get("postgres_host_ip", ""))
    if not host_ip or host_ip.startswith(("127.", "::1", "localhost", "0.0.0.0")):
        fail("postgres_host_ip must be a non-loopback address that Patroni can advertise")
    rootyard = spec.get("rootyard") or {}
    for key in ("database", "user", "bind", "data_dir"):
        if not rootyard.get(key):
            fail(f"rootyard.{key} is required")
    if rootyard["bind"].split(":")[0] not in ("127.0.0.1", "::1"):
        fail("Rootyard stable endpoint must bind loopback in this reference profile")
    for key in ("superuser_password", "replication_password", "rootyard_password",
                "patroni_rest_user", "patroni_rest_password", "haproxy_health_password"):
        if key.endswith("user"):
            if not secrets.get(key):
                fail(f"secret {key} is required")
        else:
            check_password(secrets, key)
    passwords = [secrets[k] for k in ("superuser_password", "replication_password",
                                      "rootyard_password", "patroni_rest_password",
                                      "haproxy_health_password")]
    if len(set(passwords)) != len(passwords):
        fail("every role must use a distinct password; refusing shared credentials")
    private_file(secrets.get("_path", ""), "secrets") if secrets.get("_path") else None
    tls = check_tls(spec)
    ports = check_ports(spec)
    check_synchronous(spec)
    watchdog_block = optional_watchdog(spec)
    return tls, watchdog_block, ports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--secrets", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    spec = read_json(args.spec)
    secrets = read_json(args.secrets)
    secrets["_path"] = str(args.secrets)
    try:
        private_file(args.secrets, "secrets")
        tls, watchdog_block, ports = validate(spec, secrets)
        if args.check:
            print(json.dumps({"result": "ok", "environment": spec["environment"],
                              "nodes": len(spec["nodes"]), "etcd_members": len(spec["etcd"]["nodes"]),
                              "ports": ports, "watchdog": bool(watchdog_block)}))
            return 0
        if not args.out:
            fail("--out is required unless --check is used")
        out = args.out
        out.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(out, 0o700)
        rendered = []
        for node in spec["nodes"]:
            rendered.append(render_patroni(spec, secrets, tls, node, spec["etcd"], watchdog_block, out))
        for node in spec["etcd"]["nodes"]:
            rendered.append(render_etcd(spec, tls, node, out))
        rendered.append(render_haproxy(spec, secrets, out))
        rendered.extend(render_rootyard(spec, secrets, tls, out))
        print(json.dumps({"result": "rendered", "directory": str(out),
                          "files": [p.name for p in rendered],
                          "environment": spec["environment"],
                          "synchronous_commit": spec["synchronous"]["synchronous_commit"],
                          "watchdog": bool(watchdog_block)}))
    except ConfigError as error:
        print(json.dumps({"result": "rejected", "error": str(error)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
