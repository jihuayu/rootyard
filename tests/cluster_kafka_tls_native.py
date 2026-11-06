#!/usr/bin/env python3
"""Real Kafka KRaft SASL_SSL wake transport and broker outage recovery."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

from e2e import Harness
import ops_provenance


def run(args, env=None, check=True, data=None, timeout=30):
    result = subprocess.run(args, env=env, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f"{Path(args[0]).name} failed: {result.stderr.decode(errors='replace')[-700:]}")
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--kafka-home", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    kafka = args.kafka_home.resolve() / "bin"
    kafka_version = run([str(kafka / "kafka-topics.sh"), "--version"], timeout=30).stdout.decode().strip()
    root = Path(tempfile.mkdtemp(prefix="rootyard-kafka-tls-"))
    broker_port, controller_port = free_port(), free_port()
    broker = None
    broker_log = None
    h = None
    try:
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
             "-subj", "/CN=Kafka test CA", "-addext", "basicConstraints=critical,CA:TRUE"])
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"), "-subj", "/CN=localhost"])
        (root / "leaf.ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n")
        run(["openssl", "x509", "-req", "-in", str(root / "server.csr"),
             "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
             "-out", str(root / "server.crt"), "-days", "1", "-extfile", str(root / "leaf.ext")])
        store_password = secrets.token_urlsafe(18)
        broker_password, app_password = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
        run(["openssl", "pkcs12", "-export", "-in", str(root / "server.crt"), "-inkey", str(root / "server.key"),
             "-certfile", str(root / "ca.crt"), "-out", str(root / "keystore.p12"),
             "-passout", "pass:" + store_password, "-name", "kafka"])
        run(["keytool", "-importcert", "-noprompt", "-alias", "ca", "-file", str(root / "ca.crt"),
             "-keystore", str(root / "truststore.p12"), "-storetype", "PKCS12", "-storepass", store_password])
        topic = "rootyardwake"
        server = root / "server.properties"
        server.write_text("\n".join([
            "process.roles=broker,controller", "node.id=1",
            f"controller.quorum.voters=1@localhost:{controller_port}",
            f"listeners=SASL_SSL://localhost:{broker_port},CONTROLLER://localhost:{controller_port}",
            f"advertised.listeners=SASL_SSL://localhost:{broker_port}",
            "listener.security.protocol.map=CONTROLLER:PLAINTEXT,SASL_SSL:SASL_SSL",
            "controller.listener.names=CONTROLLER", "inter.broker.listener.name=SASL_SSL",
            f"log.dirs={root / 'data'}", "offsets.topic.replication.factor=1",
            "transaction.state.log.replication.factor=1", "transaction.state.log.min.isr=1",
            "sasl.enabled.mechanisms=PLAIN", "sasl.mechanism.inter.broker.protocol=PLAIN",
            'listener.name.sasl_ssl.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required '
            f'username="broker" password="{broker_password}" user_broker="{broker_password}" user_rootyard="{app_password}";',
            "ssl.keystore.type=PKCS12", f"ssl.keystore.location={root / 'keystore.p12'}",
            f"ssl.keystore.password={store_password}", f"ssl.key.password={store_password}",
            "ssl.truststore.type=PKCS12", f"ssl.truststore.location={root / 'truststore.p12'}",
            f"ssl.truststore.password={store_password}", "ssl.client.auth=none",
        ]) + "\n")
        client = root / "client.properties"
        client.write_text("\n".join([
            "security.protocol=SASL_SSL", "sasl.mechanism=PLAIN",
            "sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required "
            f'username="rootyard" password="{app_password}";',
            "ssl.truststore.type=PKCS12", f"ssl.truststore.location={root / 'truststore.p12'}",
            f"ssl.truststore.password={store_password}",
            "ssl.endpoint.identification.algorithm=https",
        ]) + "\n")
        server.chmod(0o600)
        client.chmod(0o600)
        cluster_id = run([str(kafka / "kafka-storage.sh"), "random-uuid"], timeout=60).stdout.decode().strip()
        run([str(kafka / "kafka-storage.sh"), "format", "-t", cluster_id, "-c", str(server)], timeout=60)
        broker_env = os.environ.copy()
        broker_env["KAFKA_HEAP_OPTS"] = "-Xms256m -Xmx256m"
        broker_log = open(root / "broker.log", "ab")

        def start_broker():
            return subprocess.Popen([str(kafka / "kafka-server-start.sh"), str(server)],
                                    env=broker_env, stdout=broker_log, stderr=broker_log, start_new_session=True)

        def topic_command(*parts, check=True):
            return run([str(kafka / "kafka-topics.sh"), "--bootstrap-server", f"localhost:{broker_port}",
                        "--command-config", str(client), *parts], check=check, timeout=12)

        def ready():
            until = time.monotonic() + 45
            while time.monotonic() < until:
                if broker.poll() is not None:
                    raise AssertionError("Kafka broker exited; inspect retained broker.log")
                if topic_command("--list", check=False).returncode == 0:
                    return
                time.sleep(.25)
            raise AssertionError("Kafka SASL_SSL readiness timeout")

        def offset():
            result = run([str(kafka / "kafka-get-offsets.sh"), "--bootstrap-server", f"localhost:{broker_port}",
                          "--command-config", str(client), "--topic", topic, "--time", "latest"], timeout=15)
            lines = result.stdout.decode().strip().splitlines()
            return max(int(line.rsplit(":", 1)[1]) for line in lines if line.startswith(topic + ":"))

        broker = start_broker()
        ready()
        topic_command("--create", "--topic", topic, "--partitions", "1", "--replication-factor", "1")
        def rejected(config_path, bootstrap=f"localhost:{broker_port}"):
            try:
                trial = run([str(kafka / "kafka-topics.sh"), "--bootstrap-server", bootstrap,
                             "--command-config", str(config_path), "--list"], check=False, timeout=12)
                return trial.returncode != 0
            except subprocess.TimeoutExpired:
                return True
        bad_password = root / "bad-password.properties"
        bad_password.write_text(client.read_text().replace(app_password, "incorrect-secret"))
        bad_password.chmod(0o600)
        assert rejected(bad_password), "Kafka accepted wrong SASL password"
        assert rejected(client, f"127.0.0.1:{broker_port}"), "Kafka accepted wrong TLS hostname"
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(root / "wrong-ca.key"), "-out", str(root / "wrong-ca.crt"),
             "-subj", "/CN=Wrong Kafka CA", "-addext", "basicConstraints=critical,CA:TRUE"])
        run(["keytool", "-importcert", "-noprompt", "-alias", "wrong-ca", "-file", str(root / "wrong-ca.crt"),
             "-keystore", str(root / "wrong-truststore.p12"), "-storetype", "PKCS12", "-storepass", store_password])
        bad_ca = root / "bad-ca.properties"
        bad_ca.write_text(client.read_text().replace(str(root / "truststore.p12"), str(root / "wrong-truststore.p12")))
        bad_ca.chmod(0o600)
        assert rejected(bad_ca), "Kafka accepted an untrusted TLS certificate"
        h = Harness(args)
        h.env.update(ROOTYARD_WAKE_TRANSPORT="kafka", ROOTYARD_KAFKA_BOOTSTRAP_SERVERS=f"localhost:{broker_port}",
                     ROOTYARD_KAFKA_TOPIC=topic, ROOTYARD_KAFKA_GROUP="rootyard-native-test",
                     ROOTYARD_KAFKA_SECURITY_PROTOCOL="SASL_SSL", ROOTYARD_KAFKA_CA_PEM=str(root / "ca.crt"),
                     ROOTYARD_KAFKA_SASL_MECHANISM="PLAIN", ROOTYARD_KAFKA_SASL_USERNAME="rootyard",
                     ROOTYARD_KAFKA_SASL_PASSWORD=app_password, ROOTYARD_OUTBOX_WORKER="true")
        h.setup()
        h.api()
        h.roundtrip()
        until = time.monotonic() + 20
        initial_offset = 0
        while time.monotonic() < until:
            initial_offset = offset()
            if initial_offset > 0:
                break
            time.sleep(.25)
        assert initial_offset > 0, "Rootyard did not publish a wake over SASL_SSL"
        broker.terminate()
        broker.wait(timeout=20)
        (h.work / "hello.txt").write_text("push with Kafka unavailable\n")
        h.git("commit", "-am", "Kafka outage", cwd=h.work)
        during_outage = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
        h.git("fetch", h.remote, "refs/heads/main", cwd=h.copy, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == during_outage
        broker = start_broker()
        ready()
        before_reconnect = offset()
        (h.work / "hello.txt").write_text("push after Kafka restart\n")
        h.git("commit", "-am", "Kafka restart", cwd=h.work)
        after_restart = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
        until = time.monotonic() + 20
        final_offset = before_reconnect
        while time.monotonic() < until:
            final_offset = offset()
            if final_offset > before_reconnect:
                break
            time.sleep(.25)
        assert final_offset > before_reconnect, "Kafka wake did not reconnect after broker restart"
        report = ops_provenance.base(
            args.binary, __file__,
            topology="one Rootyard writer and one task-owned Apache Kafka KRaft broker with a SASL_SSL listener; controller listener is local plaintext",
            dataset="one private repository with acknowledged Git pushes before and during a broker outage",
            workload="native Git push/fetch while a real Kafka wake transport uses SASL/PLAIN over verified TLS; client negative checks for wrong CA, hostname and password; broker stop and restart",
            limits=["single local KRaft broker; controller listener is local plaintext",
                    "no multi-broker Kafka failover",
                    "Kafka wake is advisory and PostgreSQL remains the durable event authority"])
        report.update({"kind": "native_kafka_sasl_ssl", "kafka_version": kafka_version,
                  "postgres_version": h.sql("SHOW server_version"),
                  "wrong_ca_rejected": True, "wrong_hostname_rejected": True, "wrong_sasl_password_rejected": True,
                  "sasl_mechanism": "PLAIN over TLS", "initial_wake_offset": initial_offset,
                  "post_restart_wake_offset": final_offset, "git_push_during_broker_outage": during_outage,
                  "git_push_after_reconnect": after_restart, "broker_restart_reconnected": True})
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report), "initial_offset": initial_offset, "final_offset": final_offset}))
    finally:
        if h:
            h.cleanup()
        if broker and broker.poll() is None:
            broker.terminate()
            try:
                broker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=5)
        if broker_log:
            broker_log.close()
        if not args.keep:
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
