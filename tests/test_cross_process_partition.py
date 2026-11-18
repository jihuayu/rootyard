"""Pure boundary tests for the opt-in Redis wake partition."""
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cross_process_partition as partition
from redis_partition_relay import RedisPartitionRelay, RelayCounts


class RelayTest(unittest.TestCase):
    def test_cut_reaps_live_pair_and_refuses_new_connections_until_same_port_heals(self):
        relay = object.__new__(RedisPartitionRelay)
        relay.target = ("127.0.0.1", 1000)
        relay.port = 1001
        relay.lock = threading.Lock()
        relay.stopped = threading.Event()
        relay.partitioned = relay.failed = False
        relay.forwarded = relay.refused = 0
        relay.sessions = {}
        healthy, blocked, healed, upstream, new_upstream = (Mock() for _ in range(5))
        first, second = Mock(), Mock()
        first.is_alive.return_value = False
        first.join.side_effect = lambda **_: relay.sessions.pop(first)

        with patch("redis_partition_relay.socket.create_connection", side_effect=[upstream, new_upstream]) as connect:
            with patch("redis_partition_relay.threading.Thread", side_effect=[first, second]):
                relay.route(healthy)
                self.assertEqual(relay.counts(), RelayCounts(1, 0, 1))
                self.assertEqual(relay.cut(), 1)
                healthy.shutdown.assert_called_once()
                upstream.shutdown.assert_called_once()
                first.join.assert_called_once()

                relay.route(blocked)
                blocked.close.assert_called_once()
                connect.assert_called_once()
                self.assertEqual(relay.counts(), RelayCounts(1, 1, 0))

                relay.heal()
                relay.route(healed)
        self.assertEqual(relay.port, 1001)
        self.assertEqual(relay.counts(), RelayCounts(2, 1, 1))
        self.assertEqual(connect.call_args_list, [call(relay.target, timeout=relay.socket_timeout)] * 2)


class WakeTimingTest(unittest.TestCase):
    def test_delivery_after_earliest_poll_cannot_qualify_as_wake(self):
        harness = object.__new__(partition.RedisPartitionHarness)
        harness.publishes = Mock(side_effect=[10, 11])
        harness.relay = Mock()
        harness.relay.counts.side_effect = [RelayCounts(1, 0, 1), RelayCounts(2, 0, 1)]
        harness.subscriber_count = Mock(return_value=1)
        harness.push_oid = Mock(return_value="a" * 40)
        harness.until = Mock(side_effect=lambda predicate, *_args, **_kwargs: self.assertTrue(predicate()))
        harness.drain = Mock()
        with patch.object(partition.time, "monotonic", return_value=20):
            with self.assertRaisesRegex(AssertionError, "periodic poll"):
                harness.healthy_push(20)

    def test_early_delivery_still_requires_a_producer_publish_and_forwarded_connection(self):
        harness = object.__new__(partition.RedisPartitionHarness)
        harness.publishes = Mock(side_effect=[10, 11])
        harness.relay = Mock()
        harness.relay.counts.return_value = RelayCounts(1, 0, 1)
        harness.push_oid = Mock(return_value="a" * 40)
        harness.until = Mock(side_effect=lambda predicate, *_args, **_kwargs: self.assertTrue(predicate()))
        harness.drain = Mock()
        with patch.object(partition.time, "monotonic", return_value=10):
            with self.assertRaises(AssertionError):
                harness.healthy_push(20)


class PartitionReportTest(unittest.TestCase):
    harness_type = partition.RedisPartitionHarness

    def setUp(self):
        self.args = SimpleNamespace(binary="binary", expect_commit="b" * 40)
        self.binding = dict(source_head=self.args.expect_commit, build_receipt_sha256="c" * 64)
        self.build = self.enterContext(patch.object(partition, "build_binding", return_value=self.binding))
        self.factory = self.enterContext(patch.object(partition, "RedisPartitionHarness"))
        self.resolve = self.enterContext(patch.object(partition.CrossProcessHarness, "resolve_redis", return_value="redis"))
        self.enterContext(patch.dict(partition.os.environ, {
            "ROOTYARD_TEST_DATABASE_URL": "postgresql://fixture@127.0.0.1/synthetic",
        }, clear=True))

    def test_success_requires_two_receipt_checks_and_positive_cleanup(self):
        harness = self.factory.return_value
        harness.partition.return_value = dict(post_heal_wake_before_next_poll=True)
        self.assertEqual(partition.partition_report(self.args), dict(passed=True, cases=[dict(
            name=partition.CASE, status="passed",
            detail=dict(post_heal_wake_before_next_poll=True, owned_cleanup_completed=True),
        )], **self.binding))
        self.assertEqual(harness.method_calls, [call.setup_partition(), call.partition(), call.cleanup()])
        self.assertEqual(self.build.call_args_list, [call(self.args.binary, self.args.expect_commit)] * 2)

    def test_partial_or_unattested_run_emits_only_the_fixed_failed_case(self):
        harness = self.factory.return_value
        for stage in ("partition", "receipt_changed", "cleanup"):
            with self.subTest(stage=stage):
                self.build.side_effect = [self.binding, {} if stage == "receipt_changed" else self.binding]
                harness.partition.side_effect = RuntimeError("fixture-specific exception") if stage == "partition" else None
                harness.cleanup.side_effect = RuntimeError("fixture-specific cleanup") if stage == "cleanup" else None
                self.assertEqual(partition.partition_report(self.args), dict(passed=False, cases=[dict(
                    name=partition.CASE, status="failed", error=stage,
                )], **self.binding))

    def test_missing_redis_fails_before_allocating_fixture(self):
        self.resolve.return_value = None
        self.assertEqual(partition.partition_report(self.args), dict(passed=False, cases=[dict(
            name=partition.CASE, status="failed", error="preflight",
        )], **self.binding))
        self.factory.assert_not_called()

    def test_cleanup_attempts_remaining_owned_resources_after_worker_failure(self):
        harness = object.__new__(self.harness_type)
        with TemporaryDirectory() as temporary:
            harness.root = Path(temporary) / "owned"
            harness.root.mkdir()
            harness.schema = "owned_schema"
            harness.schema_created = True
            harness.stop_workers = Mock(side_effect=RuntimeError("synthetic error"))
            harness.stop = Mock()
            harness.owned_redis = Mock()
            harness.relay = Mock()
            harness.sql = Mock()
            with self.assertRaises(RuntimeError):
                harness.cleanup()
            harness.stop.assert_called_once()
            harness.owned_redis.stop.assert_called_once()
            harness.relay.close.assert_called_once()
            harness.sql.assert_called_once_with('DROP SCHEMA "owned_schema" CASCADE', isolated=False)
            self.assertFalse(harness.root.exists())


if __name__ == "__main__":
    unittest.main()
