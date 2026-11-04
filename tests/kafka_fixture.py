"""Local-only Apache Kafka 4.4.0 fixture. Replication factor 1: NOT production.
Set ROOTYARD_TEST_KAFKA_HOME to an unpacked official Kafka distribution.
Import LocalKafka; each instance owns its temporary directory and process group.
All broker/CLI subprocesses run in the caller's execution namespace.
"""
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def resolve_kafka_home():
    """No implicit download or connection to a pre-existing broker."""
    configured = os.environ.get("ROOTYARD_TEST_KAFKA_HOME")
    if configured is None:
        return None
    home = Path(configured).expanduser().resolve()
    required = ("kafka-server-start.sh", "kafka-storage.sh", "kafka-topics.sh",
                "kafka-consumer-groups.sh", "kafka-console-producer.sh")
    if not configured or not all((home / "bin" / item).is_file() and
                                 os.access(home / "bin" / item, os.X_OK) for item in required):
        raise ValueError("Explicit ROOTYARD_TEST_KAFKA_HOME is invalid; configured Kafka tests cannot skip")
    return home


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class LocalKafka:
    def __init__(self, home, parent=None, keep=False):
        self.home = Path(home)
        self.keep = keep
        self.root = Path(tempfile.mkdtemp(prefix='rootyard-kafka-', dir=parent))
        self.port, self.controller_port = free_port(), free_port()
        while self.controller_port == self.port:
            self.controller_port = free_port()
        self.bootstrap = f'127.0.0.1:{self.port}'
        self.process = None
        self.log = None
        self.env = dict(os.environ, KAFKA_HEAP_OPTS='-Xms128m -Xmx256m', LOG_DIR=str(self.root / 'jvm-logs'))
        self.config = self.root / 'server.properties'
        self.config.write_text(f'''# LOCAL TEST ONLY: single broker, replication factor one.
process.roles=broker,controller
node.id=1
controller.quorum.bootstrap.servers=127.0.0.1:{self.controller_port}
listeners=PLAINTEXT://127.0.0.1:{self.port},CONTROLLER://127.0.0.1:{self.controller_port}
advertised.listeners=PLAINTEXT://127.0.0.1:{self.port}
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
inter.broker.listener.name=PLAINTEXT
controller.listener.names=CONTROLLER
log.dirs={self.root / 'data'}
num.partitions=3
default.replication.factor=1
min.insync.replicas=1
offsets.topic.replication.factor=1
offsets.topic.num.partitions=3
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
transaction.state.log.num.partitions=1
share.coordinator.state.topic.replication.factor=1
share.coordinator.state.topic.min.isr=1
auto.create.topics.enable=false
group.initial.rebalance.delay.ms=0
num.network.threads=2
num.io.threads=2
log.retention.hours=1
''')
        try:
            cluster = self.cli('kafka-storage.sh', 'random-uuid').stdout.strip()
            self.cli('kafka-storage.sh', 'format', '--standalone', '-t', cluster, '-c', str(self.config))
        except BaseException:
            self.cleanup()
            raise

    def cli(self, script, *args, input=None, timeout=45):
        command = [str(self.home / 'bin' / script), *args]
        proc = subprocess.Popen(command, env=self.env, text=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            stdout, stderr = proc.communicate(input, timeout=timeout)
        except BaseException:
            self.stop_process(proc, hard=True)
            raise
        if proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, script, stdout, stderr)
        return subprocess.CompletedProcess(script, proc.returncode, stdout, stderr)

    @staticmethod
    def stop_process(proc, hard=False):
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL if hard else signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)

    def start(self):
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError('Broker already running')
        self.log = (self.root / 'broker.log').open('a')
        self.process = subprocess.Popen([str(self.home / 'bin/kafka-server-start.sh'), str(self.config)],
                                        env=self.env, stdout=self.log, stderr=subprocess.STDOUT,
                                        start_new_session=True)
        deadline = time.monotonic() + 60
        try:
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError(f'Kafka exited; inspect {self.root / "broker.log"}')
                try:
                    with socket.create_connection(('127.0.0.1', self.port), timeout=0.3):
                        pass
                    self.cli('kafka-topics.sh', '--bootstrap-server', self.bootstrap, '--list')
                    return self
                except (OSError, subprocess.SubprocessError):
                    time.sleep(0.3)
            raise TimeoutError(f'Kafka not ready; inspect {self.root / "broker.log"}')
        except BaseException:
            self.stop()
            raise

    def stop(self, hard=False):
        self.stop_process(self.process, hard)
        if self.log is not None:
            self.log.close()
            self.log = None

    def cleanup(self):
        self.stop()
        if not self.keep and self.root.exists():
            shutil.rmtree(self.root)

    def restart(self):
        self.stop()
        return self.start()

    def create_topic(self, name, partitions=2):
        return self.cli('kafka-topics.sh', '--bootstrap-server', self.bootstrap, '--create', '--topic', name,
                        '--partitions', str(partitions), '--replication-factor', '1',
                        '--config', 'compression.type=uncompressed',
                        '--config', 'max.message.bytes=4096',
                        '--config', 'retention.ms=3600000',
                        '--config', 'retention.bytes=16777216')

    def __enter__(self):
        try:
            return self.start()
        except BaseException:
            self.cleanup()
            raise

    def __exit__(self, *args):
        self.cleanup()
