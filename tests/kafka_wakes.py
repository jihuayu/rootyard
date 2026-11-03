#!/usr/bin/env python3
"""Actual Rootyard Kafka clients + owned loopback Kafka + PostgreSQL integration.

Set ROOTYARD_TEST_DATABASE_URL and ROOTYARD_TEST_KAFKA_HOME. An absent Kafka
home explicitly skips (CI must configure it); an invalid configured home fails.
No Docker, external services, topic creation in production, or fake broker.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

from cross_process import CrossProcessHarness
from kafka_fixture import LocalKafka, resolve_kafka_home


class KafkaHarness(CrossProcessHarness):
    def __init__(self, args, home):
        super().__init__(args)
        self.home = home
        self.kafka = None
        self.topic = self.schema + '_wake'
        self.group = self.schema + '_workers'
        self.group_observations = []
        self.limits = [
            'Real Apache Kafka with actual Rootyard publishers and worker consumers; no fake broker.',
            'Single loopback KRaft broker/controller, replication factor 1, plaintext: not production or HA.',
            'SIGKILL affects owned broker process only, not PostgreSQL, kernel, or power loss.',
            'Exactly-once assertions cover PostgreSQL transactional effects, not external systems.',
            'Timing checks are bounded functional checks, not production latency benchmarks.',
            'Tests distinguish invalid 2048-byte wake payload from broker-rejected 8192-byte record.',
        ]

    def worker_env(self, consumers='audit-log,ref-index', poll=100, transport='kafka'):
        return super().worker_env(consumers=consumers, poll=poll, transport=transport)

    def group_members(self, expected):
        # Only application workers join this group. The official CLI is an
        # administrative observer, never a stand-in consumer.
        end = time.monotonic() + 45
        while time.monotonic() < end:
            for proc, _ in self.workers:
                assert proc.poll() is None, 'Actual Rootyard worker exited'
            try:
                state = self.kafka.cli('kafka-consumer-groups.sh', '--bootstrap-server',
                    self.kafka.bootstrap, '--group', self.group, '--describe', '--state', timeout=15).stdout
                rows = [line.split() for line in state.splitlines() if line.startswith(self.group + ' ')]
                if rows and rows[0][-2:] == ['Stable', str(expected)]:
                    members = self.kafka.cli('kafka-consumer-groups.sh', '--bootstrap-server',
                        self.kafka.bootstrap, '--group', self.group, '--describe', '--members',
                        '--verbose', timeout=15).stdout
                    app_rows = [line for line in members.splitlines() if line.startswith(self.group + ' ')]
                    if len(app_rows) == expected and all('rootyard-wake-v1' in row for row in app_rows):
                        self.group_observations.append(dict(state='Stable', members=expected,
                            actual_rootyard_clients=True))
                        return
            except (subprocess.SubprocessError, OSError):
                pass
            time.sleep(.3)
        raise AssertionError('Actual Rootyard group did not reach stable membership ' + str(expected))

    def publish_hints(self, hints, keyed=False):
        properties = ['--property', 'parse.key=true', '--property', 'key.separator=|'] if keyed else []
        return self.kafka.cli('kafka-console-producer.sh', '--bootstrap-server', self.kafka.bootstrap,
            '--topic', self.topic, '--producer-property', 'compression.type=none',
            '--producer-property', 'delivery.timeout.ms=10000',
            '--producer-property', 'request.timeout.ms=5000', *properties, input='\n'.join(hints) + '\n')

    def shutdown_checked(self, proc):
        started = time.monotonic()
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise AssertionError('Rootyard shutdown hung with broker unavailable')
        assert code == 0, 'Rootyard did not shut down cleanly'
        return round(time.monotonic() - started, 4)

    def kafka_recovery(self):
        self.kafka = LocalKafka(self.home, parent=self.root, keep=self.args.keep)
        self.kafka.start()
        self.runtime['postgresql_server'] = self.sql('SELECT version()')
        self.runtime['python'] = sys.version.split()[0]
        self.runtime['kafka'] = self.kafka.cli('kafka-topics.sh', '--version').stdout.strip()
        java = subprocess.run(['java', '-version'], capture_output=True, text=True, timeout=10)
        assert java.returncode == 0
        self.runtime['java'] = java.stderr.strip()
        self.kafka.create_topic(self.topic)
        self.stop()
        self.env.update(ROOTYARD_WAKE_TRANSPORT='kafka',
                        ROOTYARD_KAFKA_BOOTSTRAP_SERVERS=self.kafka.bootstrap,
                        ROOTYARD_KAFKA_TOPIC=self.topic, ROOTYARD_KAFKA_GROUP=self.group)
        self.start()
        # PostgreSQL work survives publication before any subscriber exists.
        self.push(count=2, branches=2)
        assert self.pending() == 8
        first = self.spawn_worker(poll=200)
        self.group_members(1)
        self.drain()
        second = self.spawn_worker(poll=200)
        self.group_members(2)
        self.push(count=3, branches=2)
        self.drain()
        self.kill_worker(second)
        self.group_members(1)
        self.push(count=2, branches=2)
        self.drain()
        self.invariants()

        before = self.sql('SELECT count(*) FROM outbox_events')
        self.publish_hints(['v1'] * 20 + ['wrong-version', '{"event_id":"forged"}', 'x' * 2048])
        time.sleep(.5)
        assert self.sql('SELECT count(*) FROM outbox_events') == before
        self.invariants()
        self.push()
        self.drain()

        self.kafka.stop(hard=True)
        started = time.monotonic()
        self.push(count=2, branches=2)
        push_seconds = time.monotonic() - started
        assert push_seconds < 10, 'Broker outage blocked successful Git pushes'
        self.drain(timeout=10)
        self.invariants()
        self.kafka.start()
        self.group_members(1)
        self.push(count=2)
        self.drain()
        self.kill_worker(first)

        # Stable group + drained PG + long interval rules out the poll safety
        # net. The group assignment notification happens before this push.
        long_poll = self.spawn_worker(poll=60000)
        self.group_members(1)
        self.drain()
        time.sleep(.5)
        started = time.monotonic()
        self.push()
        self.drain(timeout=5)
        wake_seconds = time.monotonic() - started
        assert wake_seconds < 5, 'Kafka wake did not beat the sixty-second PG poll'
        # Suppress only this service's publication, leaving the actual Kafka
        # subscriber running. Invalid hints must not even trigger a PG scan.
        self.stop()
        self.env['ROOTYARD_WAKE_TRANSPORT'] = 'poll'
        self.start()
        self.push()
        assert self.pending() == 2
        self.publish_hints(['v2', '{"event_id":"forged"}', 'x' * 2048])
        self.publish_hints(['unexpected-key|v1'], keyed=True)
        # Java's console producer may return zero even for an asynchronous
        # broker rejection. Require its exact record-too-large diagnostic.
        try:
            rejected = self.publish_hints(['x' * 8192])
            rejection_output = rejected.stderr
        except subprocess.CalledProcessError as error:
            rejection_output = error.stderr or ''
        assert 'RecordTooLargeException' in rejection_output, 'Broker did not reject oversized record'
        time.sleep(.5)
        assert self.pending() == 2, 'Invalid Kafka payload unexpectedly woke the worker'
        self.publish_hints(['v1'] * 10)
        self.drain(timeout=5)
        self.stop()
        self.env['ROOTYARD_WAKE_TRANSPORT'] = 'kafka'
        self.start()
        started = time.monotonic()
        self.push()
        self.drain(timeout=5)
        later_wake_seconds = time.monotonic() - started
        assert later_wake_seconds < 5
        result = self.invariants()
        self.kafka.stop(hard=True)
        worker_shutdown = self.shutdown_checked(long_poll)
        self.kill_worker(long_poll)
        # Exercise the application's publisher while disconnected before exit.
        self.push()
        app_shutdown = self.shutdown_checked(self.proc)
        self.stop()
        self.run([self.args.binary, 'worker-once'], env=self.worker_env())
        result = self.invariants()
        result.update(real_kafka=True, fake_broker=False, topic_partitions=2,
            group_observations=self.group_observations, publication_before_subscribers=True,
            duplicate_wrong_oversized_hints_harmless=True, invalid_payload_did_not_wake=True,
            keyed_v1_did_not_wake=True, broker_rejected_8192_byte_record=True,
            broker_sigkill_pg_poll_recovery=True,
            broker_restart_rejoined=True, disconnected_git_push_seconds=round(push_seconds, 4),
            sixty_second_poll_wake_seconds=round(wake_seconds, 4),
            later_good_wake_seconds=round(later_wake_seconds, 4),
            broker_down_worker_shutdown_seconds=worker_shutdown,
            broker_down_app_shutdown_seconds=app_shutdown)
        return result

    def cleanup(self):
        self.stop_workers()
        try:
            if self.kafka:
                self.kafka.cleanup()
        finally:
            super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/rootyard')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    h = None
    report = dict(passed=False, kafka_coverage='not_run', cases=[])
    try:
        home = resolve_kafka_home()
        if home is None:
            report.update(passed=True, kafka_coverage='skipped', cases=[dict(
                name='real_kafka_wakes', status='skipped',
                reason='Set ROOTYARD_TEST_KAFKA_HOME to an official Kafka distribution; CI must configure it')])
        else:
            if not os.environ.get('ROOTYARD_TEST_DATABASE_URL'):
                raise AssertionError('ROOTYARD_TEST_DATABASE_URL is required when Kafka is configured')
            for executable in ('git', 'psql', 'java', args.binary):
                if not shutil.which(executable):
                    raise AssertionError('Required executable unavailable: ' + executable)
            h = KafkaHarness(args, home)
            h.runtime.update(binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                git=h.run(['git', '--version']).stdout.decode().strip(),
                psql=h.run(['psql', '--version']).stdout.decode().strip())
            h.case('isolated_service_without_embedded_worker', h.fixture)
            h.case('real_kafka_wakes_rebalance_disconnect_recovery', h.kafka_recovery)
            assert hashlib.sha256(Path(args.binary).read_bytes()).hexdigest() == h.runtime['binary_sha256'], \
                'Binary changed during integration run; rerun against one frozen binary'
            report.update(passed=True, kafka_coverage='passed')
    except Exception as error:
        message = h.redact(error) if h else str(error)
        report.update(passed=False, kafka_coverage='failed', error=message)
        print(message, file=sys.stderr)
        if h:
            logs = list(h.root.glob('*.log')) + list(h.root.glob('rootyard-kafka-*/broker.log'))
            for log in sorted(logs):
                print(h.redact(log.name + ': ' + log.read_text(errors='replace')[-3000:]), file=sys.stderr)
    finally:
        if h:
            report.update(cases=h.results, runtime=h.runtime, limitations=h.limits)
            if args.keep:
                report['retained_directory'] = str(h.root)
            try:
                h.cleanup()
            except Exception as error:
                report.update(passed=False, cleanup_error=h.redact(error))
        output = json.dumps(report, indent=2) + '\n'
        if h:
            output = h.redact(output)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(output)
        print(output)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
