"""Pure fixture and authority checks for the opt-in Redis promotion."""
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cross_process_failover as failover
from redis_partition_relay import RedisPartitionRelay


class PromotionTest(unittest.TestCase):
    def harness(self):
        harness = object.__new__(failover.RedisFailoverHarness)
        harness.primary = SimpleNamespace(redis_port=1234, process=Mock())
        harness.primary.process.poll.return_value = 0
        harness.replica = Mock(redis_port=2345, run_id=b"replica")
        harness.relay = Mock()
        harness.assert_canary = Mock()
        harness.until = Mock(side_effect=lambda predicate, *_args, **_kwargs: self.assertTrue(predicate()))
        return harness

    def test_promotion_checks_identity_link_and_role_before_retargeting(self):
        for altered in (None, b"identity", b"wrong-port", b"up", b"master", b"no-transition"):
            with self.subTest(altered=altered):
                harness = self.harness()
                promoted = []
                replica = harness.replica

                def observer(*parts):
                    self.assertEqual(parts, ("INFO", "replication"))
                    is_master = altered == b"master" or (promoted and altered != b"no-transition")
                    role = b"master" if is_master else b"slave"
                    link = b"up" if altered == b"up" else b"down"
                    port = b"9999" if altered == b"wrong-port" else b"1234"
                    return (
                        b"# Replication\r\nrole:" + role + b"\r\nmaster_host:127.0.0.1\r\nmaster_port:" + port
                        + b"\r\nmaster_link_status:" + link + b"\r\nmaster_sync_in_progress:0\r\n"
                    )

                def command(*parts, before_send=None):
                    if before_send is None:
                        return observer(*parts)
                    before_send(observer)
                    promoted.append(parts)
                    return b"OK"

                replica.redis_command.side_effect = command
                replica._identity_on.return_value = b"wrong" if altered == b"identity" else replica.run_id
                if altered is None:
                    harness.heal_endpoint()
                    self.assertEqual(promoted, [("REPLICAOF", "NO", "ONE")])
                    self.assertEqual(replica._identity_on.call_args_list, [
                        call(observer), call(replica.redis_command),
                    ])
                    harness.assert_canary.assert_called_once()
                    harness.relay.heal.assert_called_once_with(redis_port=2345)
                else:
                    with self.assertRaises(AssertionError):
                        harness.heal_endpoint()
                    expected = [("REPLICAOF", "NO", "ONE")] if altered == b"no-transition" else []
                    self.assertEqual(promoted, expected)
                    harness.relay.heal.assert_not_called()

    def test_live_old_primary_blocks_promotion_and_retarget(self):
        harness = self.harness()
        harness.primary.process.poll.return_value = None
        with self.assertRaises(AssertionError):
            harness.heal_endpoint()
        harness.replica.redis_command.assert_not_called()
        harness.relay.heal.assert_not_called()

    def test_only_cut_idle_relay_can_change_upstream(self):
        relay = object.__new__(RedisPartitionRelay)
        relay.port = 2111
        relay.target = ("127.0.0.1", 2222)
        relay.lock = threading.Lock()
        relay.stopped = threading.Event()
        relay.partitioned = False
        relay.sessions = {}
        with self.assertRaises(AssertionError):
            relay.heal(redis_port=3333)
        relay.partitioned = True
        relay.sessions["existing"] = ()
        with self.assertRaises(AssertionError):
            relay.heal(redis_port=3333)
        relay.sessions.clear()
        with self.assertRaises(AssertionError):
            relay.heal(redis_port=0)
        self.assertEqual(relay.target, ("127.0.0.1", 2222))
        relay.heal(redis_port=3333)
        self.assertEqual(relay.target, ("127.0.0.1", 3333))
        self.assertEqual(relay.port, 2111)
        self.assertFalse(relay.partitioned)

    def test_both_redis_processes_get_cleanup_after_one_failure(self):
        harness = self.harness()
        harness.primary.stop = Mock()
        harness.replica.stop.side_effect = RuntimeError("synthetic failure")
        with self.assertRaises(RuntimeError):
            harness.stop_redis_fixtures()
        harness.replica.stop.assert_called_once()
        harness.primary.stop.assert_called_once()

    def test_duplicate_v1_wakes_must_leave_exact_snapshot_unchanged(self):
        for changed in (False, True):
            with self.subTest(changed=changed):
                harness = self.harness()
                harness.channel = "fixture"
                harness.scans = Mock(side_effect=[9, 10, 11, 12])
                harness.durable_snapshot = Mock(side_effect=[("ref", "rows"), ("ref", "changed" if changed else "rows")])
                harness.publishes = Mock(side_effect=[20, 23])
                harness.redis_command = Mock(return_value=1)
                harness.assert_effects = Mock()
                with patch.object(failover.time, "monotonic", return_value=5):
                    if changed:
                        with self.assertRaises(AssertionError):
                            harness.assert_duplicate_wakes("oid", 9, 10)
                        harness.assert_effects.assert_not_called()
                    else:
                        harness.assert_duplicate_wakes("oid", 9, 10)
                        harness.assert_effects.assert_called_once_with("oid", 3)
                self.assertEqual(harness.redis_command.call_args_list, [call("PUBLISH", "fixture", b"v1")] * 3)


if __name__ == "__main__":
    unittest.main()
