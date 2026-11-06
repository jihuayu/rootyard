#!/usr/bin/env python3
"""Real TLS PostgreSQL, SASL_SSL Kafka, and local cluster launcher acceptance."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import quote


def run(argv, *, env=None, data=None, timeout=90, check=True):
    result = subprocess.run(argv, env=env, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f"{Path(argv[0]).name} exited {result.returncode}: "
                             + result.stderr.decode(errors="replace")[-500:])
    return result


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def private(path, content):
    path.write_text(content)
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--kafka-home", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    kafka_home = args.kafka_home.resolve(strict=True)
    kafka = kafka_home / "bin"
    launcher = Path(__file__).resolve().parents[1] / "deployment/local_cluster.py"
    root = Path(tempfile.mkdtemp(prefix="rootyard-secure-profile-"))
    config = root / "config"
    config.mkdir(mode=0o700)
    state = root / "state"
    state.mkdir(mode=0o700)
    pgdata = root / "pgdata"
    pg_port, broker_port, controller_port, bind_port = (port() for _ in range(4))
    pg_started = False
    broker = None
    broker_log = None
    profile_started = False
    try:
        # Both services use an actual CA-signed certificate with localhost SAN.
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(root / "ca.key"), "-out", str(root / "ca.pem"),
             "-subj", "/CN=Rootyard secure profile CA", "-addext", "basicConstraints=critical,CA:TRUE"])
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"),
             "-subj", "/CN=localhost"])
        private(root / "leaf.ext", "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n")
        run(["openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(root / "ca.pem"),
             "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-out", str(root / "server.pem"),
             "-days", "1", "-extfile", str(root / "leaf.ext")])
        for name in ("ca.pem", "server.key", "server.pem", "ca.key"):
            (root / name).chmod(0o600)
        run(["initdb", "--no-instructions", "--auth=trust", "-U", "agent", "-D", str(pgdata)])
        (pgdata / "pg_hba.conf").write_text(
            "local all all trust\n"
            "hostssl all all 127.0.0.1/32 scram-sha-256\n"
            "hostssl all all ::1/128 scram-sha-256\n"
            "hostnossl all all 127.0.0.1/32 reject\n"
            "hostnossl all all ::1/128 reject\n")
        with (pgdata / "postgresql.conf").open("a") as file:
            file.write(f"\nlisten_addresses='127.0.0.1'\nport={pg_port}\n"
                       f"unix_socket_directories='{root}'\n"
                       "password_encryption='scram-sha-256'\nssl=on\n"
                       f"ssl_cert_file='{root / 'server.pem'}'\nssl_key_file='{root / 'server.key'}'\n")
        run(["pg_ctl", "-D", str(pgdata), "-l", str(root / "postgres.log"), "start"])
        pg_started = True
        credentials = {role: secrets.token_hex(20) for role in ("migrator", "node0", "node1", "worker")}
        sql = "CREATE ROLE migrator LOGIN PASSWORD '" + credentials["migrator"] + "';\n"
        for role in ("node0", "node1", "worker"):
            sql += f"CREATE ROLE {role} LOGIN PASSWORD '{credentials[role]}';\n"
            sql += f"GRANT migrator TO {role};\n"
        sql += "CREATE DATABASE rootyard OWNER migrator;\n"
        run(["psql", "-h", str(root), "-p", str(pg_port), "-U", "agent", "-d", "postgres",
             "-X", "-v", "ON_ERROR_STOP=1", "-f", "-"], data=sql.encode())
        # Separate broker credentials for each Rust role.
        kafka_pass = {role: secrets.token_hex(18) for role in ("broker", "node0", "node1", "worker")}
        store_pass = secrets.token_hex(18)
        run(["openssl", "pkcs12", "-export", "-in", str(root / "server.pem"),
             "-inkey", str(root / "server.key"), "-certfile", str(root / "ca.pem"),
             "-out", str(root / "keystore.p12"), "-passout", "pass:" + store_pass,
             "-name", "kafka"])
        run(["keytool", "-importcert", "-noprompt", "-alias", "ca", "-file", str(root / "ca.pem"),
             "-keystore", str(root / "truststore.p12"), "-storetype", "PKCS12", "-storepass", store_pass])
        jaas = ('listener.name.sasl_ssl.plain.sasl.jaas.config='
                'org.apache.kafka.common.security.plain.PlainLoginModule required '
                f'username="broker" password="{kafka_pass["broker"]}" '
                + " ".join(f'user_{role}="{password}"' for role, password in kafka_pass.items()) + ";")
        server = root / "server.properties"
        private(server, "\n".join([
            "process.roles=broker,controller", "node.id=1",
            f"controller.quorum.voters=1@localhost:{controller_port}",
            f"listeners=SASL_SSL://localhost:{broker_port},CONTROLLER://localhost:{controller_port}",
            f"advertised.listeners=SASL_SSL://localhost:{broker_port}",
            "listener.security.protocol.map=CONTROLLER:PLAINTEXT,SASL_SSL:SASL_SSL",
            "controller.listener.names=CONTROLLER", "inter.broker.listener.name=SASL_SSL",
            f"log.dirs={root / 'kafka-data'}", "offsets.topic.replication.factor=1",
            "transaction.state.log.replication.factor=1", "transaction.state.log.min.isr=1",
            "sasl.enabled.mechanisms=PLAIN", "sasl.mechanism.inter.broker.protocol=PLAIN", jaas,
            "ssl.keystore.type=PKCS12", f"ssl.keystore.location={root / 'keystore.p12'}",
            f"ssl.keystore.password={store_pass}", f"ssl.key.password={store_pass}",
            "ssl.truststore.type=PKCS12", f"ssl.truststore.location={root / 'truststore.p12'}",
            f"ssl.truststore.password={store_pass}", "ssl.client.auth=none",
        ]) + "\n")
        client = root / "kafka-client.properties"
        private(client, "\n".join([
            "security.protocol=SASL_SSL", "sasl.mechanism=PLAIN",
            "sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required "
            f'username="node0" password="{kafka_pass["node0"]}";',
            "ssl.truststore.type=PKCS12", f"ssl.truststore.location={root / 'truststore.p12'}",
            f"ssl.truststore.password={store_pass}", "ssl.endpoint.identification.algorithm=https",
        ]) + "\n")
        cluster_id = run([str(kafka / "kafka-storage.sh"), "random-uuid"]).stdout.decode().strip()
        run([str(kafka / "kafka-storage.sh"), "format", "-t", cluster_id, "-c", str(server)])
        broker_log = open(root / "broker.log", "ab")
        broker_env = os.environ.copy()
        broker_env["KAFKA_HEAP_OPTS"] = "-Xms256m -Xmx256m"
        broker = subprocess.Popen([str(kafka / "kafka-server-start.sh"), str(server)],
                                  env=broker_env, stdout=broker_log, stderr=broker_log,
                                  start_new_session=True)
        topic_cmd = [str(kafka / "kafka-topics.sh"), "--bootstrap-server", f"localhost:{broker_port}",
                     "--command-config", str(client)]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if broker.poll() is not None:
                raise AssertionError("Kafka broker exited; inspect broker.log")
            if run([*topic_cmd, "--list"], timeout=15, check=False).returncode == 0:
                break
            time.sleep(.3)
        else:
            raise AssertionError("Kafka SASL_SSL readiness timeout")
        topic = "rootyardwake"
        run([*topic_cmd, "--create", "--topic", topic, "--partitions", "1",
             "--replication-factor", "1"], timeout=20)
        key = base64.b64encode(secrets.token_bytes(32)).decode()
        ca = str(root / "ca.pem")
        private(config / "migrator.env", "DATABASE_URL=postgresql://migrator:"
                + credentials["migrator"] + f"@localhost:{pg_port}/rootyard?sslmode=require\n"
                + f"ROOTYARD_PG_CA_PEM={ca}\n")
        for role in ("node0", "node1", "worker"):
            lines = [f"DATABASE_URL=postgresql://{role}:{credentials[role]}@localhost:{pg_port}/rootyard?sslmode=require",
                     f"ROOTYARD_PG_CA_PEM={ca}", f"ROOTYARD_CLUSTER_HMAC_KEY={key}",
                     "ROOTYARD_WAKE_TRANSPORT=kafka", f"ROOTYARD_KAFKA_BOOTSTRAP_SERVERS=localhost:{broker_port}",
                     f"ROOTYARD_KAFKA_TOPIC={topic}", f"ROOTYARD_KAFKA_GROUP=rootyard-{role}",
                     "ROOTYARD_KAFKA_SECURITY_PROTOCOL=SASL_SSL", f"ROOTYARD_KAFKA_CA_PEM={ca}",
                     "ROOTYARD_KAFKA_SASL_MECHANISM=PLAIN", f"ROOTYARD_KAFKA_SASL_USERNAME={role}",
                     f"ROOTYARD_KAFKA_SASL_PASSWORD={kafka_pass[role]}"]
            private(config / f"{role}.env", "\n".join(lines) + "\n")
        migrate_env = os.environ.copy()
        migrate_env.update(DATABASE_URL=f"postgresql://migrator:{credentials['migrator']}@localhost:{pg_port}/rootyard?sslmode=require",
                           ROOTYARD_PG_CA_PEM=ca, ROOTYARD_DATA_DIR=str(state / "node0" / "data"))
        run([str(binary), "migrate"], env=migrate_env)
        account = json.loads(run([str(binary), "create-user", "alice"], env=migrate_env).stdout)
        private(config / "operator.json", json.dumps(account))
        grant_env = os.environ.copy()
        grant_env.update(PGPASSWORD=credentials["migrator"], PGSSLMODE="verify-full", PGSSLROOTCERT=ca)
        run(["psql", "-h", "localhost", "-p", str(pg_port), "-U", "migrator", "-d", "rootyard",
             "-X", "-v", "ON_ERROR_STOP=1", "-c", "INSERT INTO cluster_operator_tokens(token_id,granted_by) VALUES ('"
             + account["token_id"] + "','native secure profile')"], env=grant_env)
        profile_cmd = ["python3", str(launcher)]
        run([*profile_cmd, "up", "--binary", str(binary), "--env-dir", str(config),
             "--state-dir", str(state), "--kafka-home", str(kafka_home),
             "--operator-account", str(config / "operator.json"), "--base-port", str(bind_port),
             "--nodes", "2"], timeout=180)
        profile_started = True
        native_report = root / "profile.json"
        run([*profile_cmd, "verify", "--state-dir", str(state),
             "--account", str(config / "operator.json"), "--report", str(native_report)], timeout=120)
        report = json.loads(native_report.read_text())
        report.update(kafka_version="4.4.0", postgres_tls="verify-full",
                      postgres_auth="SCRAM-SHA-256", kafka_auth="SASL/PLAIN over TLS",
                      binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                      launcher_sha256=hashlib.sha256(launcher.read_bytes()).hexdigest())
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report),
                          "acknowledged_oid": report["acknowledged_oid"]}))
    finally:
        if profile_started:
            run(["python3", str(launcher), "down", "--state-dir", str(state)], check=False)
        if broker is not None:
            broker.terminate()
            try:
                broker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=5)
        if broker_log is not None:
            broker_log.close()
        if pg_started:
            run(["pg_ctl", "-D", str(pgdata), "-m", "immediate", "stop"], check=False)
        if not args.keep:
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
