#!/usr/bin/env python3
"""Native fixture for the supported External HA reference profile.

Starts three etcd members (mutual TLS), Patroni-managed PostgreSQL nodes
(strict synchronous mode, TLS/SCRAM) and an HAProxy stable endpoint rendered by
deployment/ha/render.py.  Everything runs on one Linux host with dedicated
directories and loopback ports; that scope is reported honestly and is not
presented as cross-host or physical-fencing evidence.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
TREE = HERE.parent
SCRATCH = Path(os.environ.get("HA_SCRATCH", "/workspace/scratch/rootyard-round3/ha43"))
VENDOR = Path(os.environ.get("HA_VENDOR", str(SCRATCH / "vendor")))
PYTHON_VENDOR = Path(os.environ.get("HA_PYTHONPATH", str(VENDOR / "python")))
ETCD_BIN = Path(os.environ.get("HA_ETCD", str(VENDOR / "etcd" / "etcd")))
ETCDCTL = Path(os.environ.get("HA_ETCDCTL", str(VENDOR / "etcd" / "etcdctl")))
HAPROXY = Path(os.environ.get("HA_HAPROXY", str(VENDOR / "haproxy" / "usr" / "sbin" / "haproxy")))
HAPROXY_LIB = Path(os.environ.get("HA_HAPROXY_LIB",
                                  str(VENDOR / "haproxy" / "usr" / "lib" / "x86_64-linux-gnu")))


def pg_bin():
    for name in ("initdb", "pg_ctl", "psql", "pg_basebackup"):
        found = shutil.which(name)
        if found:
            return str(Path(found).parent)
    fallback = Path("/workspace/.rootyard-tools/pg/usr/lib/postgresql/17/bin")
    if (fallback / "initdb").is_file():
        return str(fallback)
    raise RuntimeError("PostgreSQL 17 binaries are not on PATH")


def run(argv, env=None, check=True, timeout=120, cwd=None, data=None):
    result = subprocess.run(argv, env=env, cwd=cwd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f"{Path(str(argv[0])).name} failed ({result.returncode}): "
                             f"{result.stderr.decode(errors='replace')[-1500:]}")
    return result


def port_free(port, hosts=("127.0.0.1",)):
    for host in hosts:
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError:
                return False
    return True


def wait_port(port, timeout=30, closed=False, host="127.0.0.1"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            try:
                sock.connect((host, port))
                connected = True
            except OSError:
                connected = False
        if connected != closed:
            return True
        time.sleep(0.1)
    return False


def openssl(*args):
    run(["openssl", *args])


def make_pki(workdir, host_ip):
    pki = workdir / "pki"
    pki.mkdir(mode=0o700)
    ca_key, ca = pki / "ca.key", pki / "ca.crt"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(ca_key),
            "-out", str(ca), "-subj", "/CN=Rootyard HA43 reference CA",
            "-addext", "basicConstraints=critical,CA:TRUE")
    ext = pki / "leaf.ext"
    ext.write_text(f"subjectAltName=DNS:localhost,IP:127.0.0.1,IP:{host_ip}\n"
                   "basicConstraints=critical,CA:FALSE\n"
                   "extendedKeyUsage=serverAuth,clientAuth\n")
    for name, cn in (("server", "localhost"), ("peer", "etcd-peer"), ("client", "patroni-client")):
        key, csr, cert = pki / f"{name}.key", pki / f"{name}.csr", pki / f"{name}.crt"
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                "-out", str(csr), "-subj", f"/CN={cn}")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(cert), "-days", "1", "-extfile", str(ext))
        os.chmod(key, 0o600)
    wrong_dir = workdir / "wrong-pki"
    wrong_dir.mkdir(mode=0o700)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(wrong_dir / "ca.key"), "-out", str(wrong_dir / "ca.crt"),
            "-subj", "/CN=Untrusted HA43 CA", "-addext", "basicConstraints=critical,CA:TRUE")
    return pki, wrong_dir


class HAFixture:
    def __init__(self, workdir, port_base=26000):
        self.workdir = Path(workdir)
        self.workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.port_base = port_base
        self.pg = pg_bin()
        self.host_ip = socket.gethostbyname(socket.gethostname())
        if self.host_ip.startswith("127."):
            raise RuntimeError("fixture needs a non-loopback host address for Patroni advertise addresses")
        self.pki, self.wrong_pki = make_pki(self.workdir, self.host_ip)
        self.render_dir = self.workdir / "rendered"
        self.procs = {}
        self.logs = {}
        self.commands = []
        self.rest_errors = []
        self.ports = {
            "etcd_client": [port_base + 1, port_base + 2, port_base + 3],
            "etcd_peer": [port_base + 11, port_base + 12, port_base + 13],
            "rest": [port_base + 21, port_base + 22, port_base + 23],
            "pg": [port_base + 31, port_base + 32, port_base + 33],
            "haproxy_primary": port_base + 40,
            "haproxy_replica": port_base + 41,
            "rootyard": port_base + 50,
            "restored_rootyard": port_base + 51,
            "restored_pg": port_base + 52,
        }
        all_ports = [p for values in self.ports.values() for p in
                     (values if isinstance(values, list) else [values])]
        busy = [p for p in all_ports if not port_free(p, ("127.0.0.1", self.host_ip))]
        if busy:
            raise AssertionError(f"refusing to reuse busy ports (protected services?): {busy}")
        self.spec = {
            "environment": "lab",
            "scope": "rootyard-ha-reference",
            "pg_bin_dir": self.pg,
            "postgres_host_ip": self.host_ip,
            "nodes": [{"name": f"pg{index + 1}", "pg_port": self.ports["pg"][index],
                       "rest_port": self.ports["rest"][index],
                       "data_dir": str(self.workdir / f"pg{index + 1}"),
                       "socket_dir": str(self.workdir / f"socket{index + 1}")} for index in range(3)],
            "etcd": {
                "cluster_token": "rootyard-ha43", "server_cert": str(self.pki / "server.crt"),
                "server_key": str(self.pki / "server.key"), "client_ca": str(self.pki / "ca.crt"),
                "client_cert": str(self.pki / "client.crt"), "client_key": str(self.pki / "client.key"),
                "peer_ca": str(self.pki / "ca.crt"), "peer_cert": str(self.pki / "peer.crt"),
                "peer_key": str(self.pki / "peer.key"),
                "nodes": [{"name": f"etcd{index + 1}", "client_port": self.ports["etcd_client"][index],
                           "peer_port": self.ports["etcd_peer"][index],
                           "data_dir": str(self.workdir / f"etcd{index + 1}")} for index in range(3)],
            },
            "tls": {"ca": str(self.pki / "ca.crt"), "server_cert": str(self.pki / "server.crt"),
                    "server_key": str(self.pki / "server.key")},
            "haproxy": {"primary_port": self.ports["haproxy_primary"],
                        "replica_port": self.ports["haproxy_replica"],
                        "stats_socket": str(self.workdir / "haproxy.sock"), "health_user": "haproxy-health"},
            "rootyard": {"database": "rootyard_ha", "user": "rootyard",
                         "bind": f"127.0.0.1:{self.ports['rootyard']}",
                         "data_dir": str(self.workdir / "rootyard-data")},
            "synchronous": {"ttl": 20, "loop_wait": 2, "retry_timeout": 3,
                            "synchronous_commit": "remote_apply",
                            "synchronous_mode": True, "synchronous_mode_strict": True},
            "watchdog": None,
        }
        self.secrets = {
            "superuser_password": "Ha43Superuser-" + os.urandom(12).hex(),
            "replication_password": "Ha43Replication-" + os.urandom(12).hex(),
            "rootyard_password": "Ha43Service-" + os.urandom(12).hex(),
            "patroni_rest_user": "patroni-rest",
            "patroni_rest_password": "Ha43Rest-" + os.urandom(12).hex(),
            "haproxy_health_password": "Ha43Health-" + os.urandom(12).hex(),
        }
        self.secrets_path = self.workdir / "secrets.json"
        self.secrets_path.write_text(json.dumps(self.secrets))
        os.chmod(self.secrets_path, 0o600)
        self.spec_path = self.workdir / "spec.json"
        self.spec_path.write_text(json.dumps(self.spec, indent=2))
        (self.workdir / "haproxy.log").touch()

    # ---- rendering -------------------------------------------------------
    def render(self, spec=None, secrets=None, out=None, check=False):
        argv = [sys.executable, str(TREE / "deployment" / "ha" / "render.py"),
                "--spec", str(spec or self.spec_path), "--secrets", str(secrets or self.secrets_path)]
        if check:
            argv.append("--check")
        else:
            argv += ["--out", str(out or self.render_dir)]
        result = run(argv, check=False)
        return result.returncode, result.stdout.decode().strip()

    def env(self, extra=None):
        env = os.environ.copy()
        env["PATH"] = self.pg + ":" + env.get("PATH", "")
        env["PYTHONPATH"] = str(PYTHON_VENDOR) + (":" + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        env["TMPDIR"] = str(self.workdir / "tmp")
        (self.workdir / "tmp").mkdir(exist_ok=True)
        env.update(extra or {})
        return env

    # ---- etcd ------------------------------------------------------------
    def etcd_env(self):
        return {"ETCDCTL_API": "3", "ETCDCTL_CACERT": str(self.pki / "ca.crt"),
                "ETCDCTL_CERT": str(self.pki / "client.crt"),
                "ETCDCTL_KEY": str(self.pki / "client.key")}

    def start_etcd(self):
        for node in self.spec["etcd"]["nodes"]:
            args = [line.strip() for line in
                    (self.render_dir / f"etcd-{node['name']}.args").read_text().splitlines() if line.strip()]
            log = open(self.workdir / f"{node['name']}.log", "ab")
            self.logs[node["name"]] = log
            self.procs[node["name"]] = subprocess.Popen(
                [str(ETCD_BIN), *args], env=self.env(), stdout=log, stderr=log, start_new_session=True)
            self.commands.append(["etcd", node["name"]])
        self.wait_etcd_healthy()

    def etcdctl(self, *args, nodes=None, cert=True, check=True):
        env = self.env({"ETCDCTL_API": "3"})
        endpoints = ",".join(f"https://127.0.0.1:{p}" for p in (nodes or self.ports["etcd_client"]))
        argv = [str(ETCDCTL), "--endpoints", endpoints, *args]
        if cert:
            argv += ["--cacert", str(self.pki / "ca.crt"), "--cert", str(self.pki / "client.crt"),
                     "--key", str(self.pki / "client.key")]
        return run(argv, env=env, check=check, timeout=30)

    def wait_etcd_healthy(self, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            healthy = 0
            for port in self.ports["etcd_client"]:
                result = self.etcdctl("endpoint", "health", nodes=[port], check=False)
                if result.returncode == 0:
                    healthy += 1
            if healthy == 3:
                return
            time.sleep(0.25)
        raise AssertionError("three-member etcd cluster did not become healthy")

    def stop_etcd(self, names):
        for name in names:
            proc = self.procs.get(name)
            if proc and proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            self.procs.pop(name, None)

    def start_etcd_members(self, names):
        for name in names:
            node = next(n for n in self.spec["etcd"]["nodes"] if n["name"] == name)
            args = [line.strip() for line in
                    (self.render_dir / f"etcd-{name}.args").read_text().splitlines() if line.strip()]
            log = open(self.workdir / f"{name}.log", "ab")
            self.logs[name] = log
            self.procs[name] = subprocess.Popen([str(ETCD_BIN), *args], env=self.env(),
                                                stdout=log, stderr=log, start_new_session=True)
        self.wait_etcd_healthy()

    # ---- patroni ---------------------------------------------------------
    def start_patroni(self):
        for node in self.spec["nodes"]:
            config = self.render_dir / f"patroni-{node['name']}.yml"
            log = open(self.workdir / f"patroni-{node['name']}.log", "ab")
            self.logs[node["name"]] = log
            env = self.env({"ROOTYARD_BOOTSTRAP_DB_PASSWORD": self.secrets["rootyard_password"]})
            self.procs[node["name"]] = subprocess.Popen(
                [sys.executable, "-m", "patroni", str(config)], env=env,
                stdout=log, stderr=log, start_new_session=True)
            self.commands.append(["patroni", node["name"]])
        deadline = time.monotonic() + 120
        observed = {}
        while time.monotonic() < deadline:
            state = self.cluster_state()
            observed = {"leader": state.get("leader"),
                        "members": [(m.get("name"), m.get("role"), m.get("state"))
                                    for m in state.get("members", [])],
                        "etcd_healthy": self.etcd_healthy_count(),
                        "rest_errors": self.rest_errors[-6:]}
            if state.get("leader") and len(state.get("members", [])) == 3:
                leader_member = next(m for m in state["members"] if m.get("role") == "leader")
                if leader_member.get("state") == "running":
                    self.wait_synchronous()
                    return
            time.sleep(0.5)
        raise AssertionError(f"Patroni cluster did not elect a leader with three members: {observed}")

    def rest(self, node_name, path="/cluster", auth=True, timeout=5):
        port = next(n["rest_port"] for n in self.spec["nodes"] if n["name"] == node_name)
        request = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
        if auth:
            basic = base64.b64encode((self.secrets["patroni_rest_user"] + ":"
                                      + self.secrets["patroni_rest_password"]).encode()).decode()
            request.add_header("Authorization", "Basic " + basic)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except (OSError, urllib.error.URLError):
            return 0, b""

    def cluster_state(self):
        """Return the Patroni cluster view with a normalized leader name.

        Patroni's GET /cluster JSON is a member list; the elected leader is the
        member whose role is ``leader`` (there is no top-level ``leader`` key).
        """
        for node in self.spec["nodes"]:
            status, body = self.rest(node["name"])
            if status == 200:
                try:
                    state = json.loads(body)
                except ValueError as error:
                    self.rest_errors.append({"node": node["name"], "status": status,
                                             "error": "invalid-json:" + type(error).__name__})
                    continue
                members = state.get("members")
                if isinstance(members, list):
                    state["leader"] = next(
                        (m.get("name") for m in members
                         if isinstance(m, dict) and m.get("role") in ("leader", "standby_leader")), None)
                    return state
                self.rest_errors.append({"node": node["name"], "status": status,
                                         "error": "missing-members"})
            else:
                self.rest_errors.append({"node": node["name"], "status": status,
                                         "error": body.decode(errors="replace")[:120]})
        return {}

    def leader(self):
        return self.cluster_state().get("leader")

    def etcd_healthy_count(self):
        return sum(1 for port in self.ports["etcd_client"]
                   if self.etcdctl("endpoint", "health", nodes=[port], check=False).returncode == 0)

    def wait_synchronous(self, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            leader = self.leader()
            if leader:
                try:
                    mode = self.sql(leader, "SHOW synchronous_commit").strip()
                    names = self.sql(leader, "SHOW synchronous_standby_names").strip()
                    standbys = self.sql(leader, "SELECT count(*) FROM pg_stat_replication "
                                                "WHERE sync_state IN ('sync','quorum')").strip()
                except AssertionError:
                    time.sleep(0.5)
                    continue
                if mode == "remote_apply" and names and standbys.isdigit() and int(standbys) >= 1:
                    return {"synchronous_commit": mode, "synchronous_standby_names": names,
                            "synchronous_standbys": int(standbys)}
            time.sleep(0.5)
        raise AssertionError(f"Patroni cluster did not reach strict synchronous remote_apply mode; "
                             f"rest_errors={self.rest_errors[-6:]}")

    def pg_port(self, name):
        return next(n["pg_port"] for n in self.spec["nodes"] if n["name"] == name)

    def superuser_env(self, host=None, port=None):
        env = self.env({"PGPASSWORD": self.secrets["superuser_password"],
                        "PGSSLMODE": "verify-full",
                        "PGSSLROOTCERT": str(self.pki / "ca.crt")})
        return env

    def sql(self, node, query, db="postgres", user="postgres"):
        port = self.pg_port(node)
        result = run(["psql", "-h", self.host_ip, "-p", str(port), "-U", user, "-d", db,
                      "-X", "-At", "-v", "ON_ERROR_STOP=1", "-c", query], env=self.superuser_env())
        return result.stdout.decode().strip()

    def endpoint_sql(self, query, db="postgres", user="rootyard", timeout=20):
        env = self.env({"PGPASSWORD": self.secrets["rootyard_password"], "PGSSLMODE": "verify-full",
                        "PGSSLROOTCERT": str(self.pki / "ca.crt")})
        return run(["psql", "-h", "127.0.0.1", "-p", str(self.ports["haproxy_primary"]),
                    "-U", user, "-d", db, "-X", "-At", "-v", "ON_ERROR_STOP=1",
                    "-c", f"SET statement_timeout='5s'; {query}"], env=env, timeout=timeout)

    def start_haproxy(self):
        cfg = self.render_dir / "haproxy.cfg"
        check = run([str(HAPROXY), "-c", "-f", str(cfg)], env=self.env({"LD_LIBRARY_PATH": str(HAPROXY_LIB)}),
                    check=False)
        if check.returncode:
            raise AssertionError("HAProxy rejected the rendered configuration: "
                                 + check.stderr.decode(errors="replace")[-1200:])
        log = open(self.workdir / "haproxy.log", "ab")
        self.logs["haproxy"] = log
        self.procs["haproxy"] = subprocess.Popen(
            [str(HAPROXY), "-db", "-f", str(cfg)],
            env=self.env({"LD_LIBRARY_PATH": str(HAPROXY_LIB)}),
            stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if Path(self.spec["haproxy"]["stats_socket"]).exists():
                return
            time.sleep(0.1)
        raise AssertionError("HAProxy did not create its stats socket")

    def wait_endpoint_primary(self, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = self.endpoint_sql("SELECT pg_is_in_recovery() || ':' || inet_server_port()")
            except AssertionError:
                value = ""
            if value == "f:" + str(self.pg_port(self.leader() or "")):
                return value
            time.sleep(0.2)
        raise AssertionError("HAProxy primary endpoint did not route to the elected leader")

    def node_processes(self, name):
        data_dir = next(n["data_dir"] for n in self.spec["nodes"] if n["name"] == name)
        pids = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except OSError:
                continue
            if data_dir in cmdline:
                pids.append(int(entry.name))
        return pids

    def kill_node(self, name):
        """Hard-crash the complete node: Patroni session plus unmanaged postmaster.

        pg_ctl starts the postmaster in its own session, so killing only the
        Patroni process group would leave an unfenced writable PostgreSQL.
        """
        proc = self.procs.pop(name, None)
        if proc and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
        data_dir = next(n["data_dir"] for n in self.spec["nodes"] if n["name"] == name)
        pid_file = Path(data_dir) / "postmaster.pid"
        if pid_file.exists():
            try:
                postmaster = int(pid_file.read_text().splitlines()[0])
            except (IndexError, ValueError):
                postmaster = None
            if postmaster:
                try:
                    os.killpg(os.getpgid(postmaster), signal.SIGKILL)
                except OSError:
                    try:
                        os.kill(postmaster, signal.SIGKILL)
                    except OSError:
                        pass
        if proc:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if not self.node_processes(name) and not wait_port(self.pg_port(name), timeout=0.3, host=self.host_ip):
                return
            time.sleep(0.1)
        leftovers = self.node_processes(name)
        raise AssertionError(f"hard crash left live PostgreSQL/Patroni processes: {leftovers}")

    def wait_promotion(self, old_primary, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.cluster_state()
            leader = state.get("leader")
            if leader and leader != old_primary:
                try:
                    recovery = self.sql(leader, "SELECT pg_is_in_recovery()")
                except AssertionError:
                    time.sleep(0.3)
                    continue
                if recovery == "f":
                    return leader
            time.sleep(0.3)
        raise AssertionError(f"Patroni did not automatically promote a successor; "
                             f"rest_errors={self.rest_errors[-6:]}")

    def promotion_log_lines(self, names=None):
        lines = []
        for node in self.spec["nodes"]:
            if names and node["name"] not in names:
                continue
            path = self.workdir / f"patroni-{node['name']}.log"
            if not path.exists():
                continue
            for line in path.read_text(errors="replace").splitlines():
                lowered = line.lower()
                if "promot" in lowered or "leader" in lowered and "lock" in lowered:
                    lines.append({"node": node["name"], "line": line[-400:]})
        return lines[-30:]

    # ---- teardown --------------------------------------------------------
    def stop(self):
        for name in list(self.procs):
            proc = self.procs.pop(name, None)
            if not proc or proc.poll() is not None:
                continue
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
        for node in self.spec["nodes"]:
            pid_file = Path(node["data_dir"]) / "postmaster.pid"
            if pid_file.exists():
                try:
                    postmaster = int(pid_file.read_text().splitlines()[0])
                    os.killpg(os.getpgid(postmaster), signal.SIGKILL)
                except (OSError, ValueError, IndexError):
                    pass
        for log in self.logs.values():
            try:
                log.close()
            except OSError:
                pass
        self.logs.clear()
