"""Pure witnesses for the opt-in browse restore cache drill."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_recovery as recovery
import backup_recovery_cache as cache
from test_native_report_manifest import ManifestFixture


OLD_KEY = (
    b"ry:cache:v2:backup-recovery:gitfs:1:11111111-1111-4111-8111-111111111111:"
    b"22222222-2222-4222-8222-222222222222:33333333-3333-4333-8333-333333333333:"
    b"git-object-preview:2:0123456789abcdef"
)
NEW_KEY = OLD_KEY.replace(b"11111111", b"44444444", 1)
RESPONSE = {"oid": "1" * 40, "subject": "second"}
ENTRY = (1000, b"synthetic value digest")
HEAD, TREE = "a" * 40, "b" * 40


class RedisWitness:
    def __init__(self, route=NEW_KEY):
        self.route = route
        self.run_id = self.current_run_id = b"original instance"
        self.entries = {OLD_KEY: ENTRY}
        self.strlen = self.getrange = self.set = 0

    def identity(self):
        return self.current_run_id

    def keys(self):
        return set(self.entries)

    def entry(self, key):
        ttl, digest = self.entries[key]
        assert ttl > 0, "Redis entry missing or expired"
        return ttl, digest

    def counts(self, *, expected_flushes=0):
        assert expected_flushes == 0
        return self.strlen, self.getrange, self.set

    def fetch(self):
        self.strlen += 1
        if self.route in self.entries:
            self.getrange += 1
        else:
            self.set += 1
            self.entries[self.route] = ENTRY
        return RESPONSE


class CacheWitnessTest(unittest.TestCase):
    def prove(self, redis):
        return cache.prove_restored_preview(redis, redis.fetch, OLD_KEY, ENTRY, RESPONSE)

    def test_new_incarnation_refills_and_then_hits_without_removing_original(self):
        redis = RedisWitness()
        result = self.prove(redis)
        self.assertEqual(result, dict(
            redis_instance_preserved=True, original_key_retained=True, only_incarnation_changed=True,
            restored_origin_miss_and_refill=True, restored_repeat_hit=True,
        ))
        self.assertEqual(redis.keys(), {OLD_KEY, NEW_KEY})
        self.assertEqual(redis.counts(), (2, 1, 1))

    def test_old_implementation_returns_same_content_but_fails_the_cold_witness(self):
        redis = RedisWitness(route=OLD_KEY)
        self.assertEqual(RedisWitness(route=OLD_KEY).fetch(), RESPONSE)
        with self.assertRaisesRegex(AssertionError, "Unexpected Redis command counts"):
            self.prove(redis)
        self.assertEqual(redis.keys(), {OLD_KEY})
        self.assertEqual(redis.counts(), (1, 1, 0))

    def test_fails_if_redis_or_original_entry_changes(self):
        for change, expected in (
            (lambda redis: setattr(redis, "current_run_id", b"replacement"), "identity changed"),
            (lambda redis: redis.entries.clear(), "inventory was not retained"),
            (lambda redis: redis.entries.update({OLD_KEY: (0, ENTRY[1])}), "missing or expired"),
            (lambda redis: redis.entries.update({OLD_KEY: (999, b"changed digest")}), "entry changed"),
        ):
            redis = RedisWitness()
            change(redis)
            with self.subTest(expected=expected), self.assertRaisesRegex(AssertionError, expected):
                self.prove(redis)
            self.assertEqual(redis.counts(), (0, 0, 0))

    def test_unrelated_scope_change_cannot_supply_distinct_key(self):
        redis = RedisWitness(route=NEW_KEY.replace(b"preview:2:", b"preview:3:"))
        with self.assertRaises(AssertionError):
            self.prove(redis)
        redis = RedisWitness(route=NEW_KEY.replace(b"0123456789abcdef", b"1234567890abcdef"))
        with self.assertRaisesRegex(AssertionError, "Non-incarnation cache scope changed"):
            self.prove(redis)

    def test_observer_rejects_flush_history(self):
        redis = cache.OwnedRestoreRedis("unused")
        redis.redis_command = Mock(return_value=(
            b"# Commandstats\r\ncmdstat_strlen:calls=1,usec=1\r\n"
            b"cmdstat_set:calls=1,usec=1\r\n"
        ))
        self.assertEqual(redis.counts(), (1, 0, 1))
        redis.redis_command.return_value += b"cmdstat_flushall:calls=1,usec=1\r\n"
        with self.assertRaisesRegex(AssertionError, "Redis was flushed"):
            redis.counts()
        self.assertEqual(redis.counts(expected_flushes=1), (1, 0, 1))
        redis.redis_command.return_value += b"cmdstat_flushdb:calls=1,usec=1\r\n"
        with self.assertRaisesRegex(AssertionError, "Redis was flushed"):
            redis.counts(expected_flushes=1)

    def test_denial_after_a_warm_read_fails_the_zero_cache_witness(self):
        redis = RedisWitness(route=OLD_KEY)

        def fetch():
            redis.fetch()
            return 401

        with self.assertRaisesRegex(AssertionError, "Unexpected Redis command counts"):
            cache.preview_request(redis, fetch, (0, 0, 0))

    def test_flush_requires_ownership_on_the_command_connection(self):
        owned_pid, owned_run = 17, b"a" * 40
        for pid, run_id in ((owned_pid, owned_run), (18, owned_run), (owned_pid, b"b" * 40)):
            with self.subTest(pid_matches=pid == owned_pid, run_matches=run_id == owned_run):
                redis = cache.OwnedRestoreRedis("unused")
                redis.process = SimpleNamespace(pid=owned_pid, poll=lambda: None)
                redis.redis_port = 12345
                redis.run_id = owned_run
                redis.keys = Mock(side_effect=[{OLD_KEY}, set()])
                redis.counts = Mock(return_value=(1, 1, 1))
                redis.identity = Mock(return_value=owned_run)
                info = b"process_id:%d\r\nrun_id:%s\r\n" % (pid, run_id)
                connection = MagicMock()
                connection.__enter__.return_value = connection
                connection.makefile.return_value = io.BytesIO(b"$%d\r\n" % len(info) + info + b"\r\n+OK\r\n")
                with patch.object(cache.socket, "create_connection", return_value=connection) as connect:
                    if (pid, run_id) == (owned_pid, owned_run):
                        redis.flushall_owned()
                        self.assertEqual(redis.counts.call_args_list, [call(), call(expected_flushes=1)])
                        self.assertEqual(connection.sendall.call_args_list, [
                            call(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"),
                            call(b"*1\r\n$8\r\nFLUSHALL\r\n"),
                        ])
                    else:
                        with self.assertRaisesRegex(AssertionError, "PID differs|identity changed"):
                            redis.flushall_owned()
                        self.assertEqual(connection.sendall.call_args_list, [
                            call(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"),
                        ])
                    connect.assert_called_once()


class ReceiptBindingTest(unittest.TestCase):
    def setUp(self):
        root = self.enterContext(tempfile.TemporaryDirectory())
        self.fixture = ManifestFixture(root, commit=HEAD)
        self.payload = self.fixture.enable_v2_receipt()
        self.payload.update(
            kind="native-binary", git_head=HEAD, working_tree=dict(tree=TREE, status=""),
            command=cache.BUILD_COMMAND, features=dict(enabled=["state-redis"], no_default_features=False),
        )
        self.enterContext(patch.object(cache, "ROOT", self.fixture.root))
        self.git = self.enterContext(patch.object(cache.subprocess, "check_output"))
        self.git.side_effect = lambda argv, **_: {
            "HEAD": HEAD, "HEAD^{tree}": TREE, "--untracked-files=no": "",
        }[argv[-1]]

    def bind(self, expected=HEAD):
        self.fixture.receipt.write_text(json.dumps(self.payload))
        return cache.build_binding(str(self.fixture.binary), expected)

    def test_binds_actual_binary_receipt_and_source_tree(self):
        result = self.bind()
        self.assertEqual(result, dict(
            source_head=HEAD, source_tree=TREE, source_inputs_sha256=self.payload["source_inputs_sha256"],
            binary_sha256=cache.receipts.sha256_file(self.fixture.binary),
            build_receipt_sha256=cache.receipts.sha256_file(self.fixture.receipt),
        ))
        (self.fixture.root / "src/main.rs").write_text("changed source")
        with self.assertRaises(cache.receipts.ReceiptError):
            self.bind()

    def test_rejects_wrong_checkout_commit_receipt_tree_or_serving_features(self):
        with self.assertRaises(AssertionError):
            self.bind("c" * 40)
        alterations = (
            dict(workspace_commit="c" * 40),
            dict(working_tree=dict(tree="c" * 40, status="")),
            dict(command=["cargo", "build", "--locked", "--bin", "rootyard"]),
            dict(features=dict(enabled=["pando-lab"], no_default_features=False)),
        )
        for change in alterations:
            with self.subTest(change=change), patch.dict(self.payload, change):
                with self.assertRaises((AssertionError, cache.receipts.ReceiptError)):
                    self.bind()

    def test_rejects_changed_executable(self):
        self.bind()
        self.fixture.binary.write_bytes(b"changed fixture executable")
        with self.assertRaises(cache.receipts.ReceiptError):
            self.bind()


class RunReportTest(unittest.TestCase):
    harness_type = recovery.BrowseRestoreCacheHarness

    def setUp(self):
        self.args = SimpleNamespace(keep=False, binary="fixture-rootyard", expect_commit=HEAD)
        self.binding = dict(source_head=HEAD, binary_sha256="0" * 64, build_receipt_sha256="1" * 64)
        self.receipt = self.enterContext(patch.object(recovery, "build_binding", return_value=self.binding))
        self.fixture = self.enterContext(patch.object(recovery, "BrowseRestoreCacheHarness"))
        self.harness = self.fixture.return_value
        self.harness.restored_preview.return_value = dict(restored_repeat_hit=True)
        self.enterContext(patch.object(recovery.CrossProcessHarness, "resolve_redis", return_value="fixture-redis"))
        self.enterContext(patch.dict(os.environ, {
            "ROOTYARD_TEST_DATABASE_URL": "postgresql://fixture@127.0.0.1/synthetic",
        }, clear=True))

    def test_success_requires_restore_and_cleanup_with_exact_fixed_inventory(self):
        self.assertEqual(recovery.browse_restore_cache_report(self.args), dict(
            passed=True, cases=[dict(name=cache.CASE, status="passed", detail=dict(
                restored_repeat_hit=True, owned_cleanup_completed=True,
            ))], **self.binding,
        ))
        self.harness.recovery_source.assert_called_once_with(before_backup=self.harness.warm_preview)
        self.harness.restore_exact.assert_called_once()
        self.harness.restored_preview.assert_called_once()
        self.harness.flush_authority.assert_not_called()
        self.harness.cleanup.assert_called_once()

    def test_flush_opt_in_runs_after_the_restore_witness_and_before_cleanup(self):
        self.harness.flush_authority.return_value = dict(owned_flushall_verified=True)
        report = recovery.browse_restore_cache_report(self.args, flush=True)
        self.assertEqual(report, dict(passed=True, cases=[dict(
            name=cache.FLUSH_CASE, status="passed",
            detail=dict(owned_flushall_verified=True, owned_cleanup_completed=True),
        )], **self.binding))
        self.assertEqual(self.harness.method_calls, [
            call.recovery_source(before_backup=self.harness.warm_preview),
            call.restore_exact(), call.restored_preview(), call.flush_authority(), call.cleanup(),
        ])

    def test_failed_restore_witness_cannot_flush_or_expose_error_details(self):
        self.harness.restored_preview.side_effect = RuntimeError("fixture-specific restore failure")
        report = recovery.browse_restore_cache_report(self.args, flush=True)
        self.assertEqual(report, dict(passed=False, cases=[dict(
            name=cache.FLUSH_CASE, status="failed", error="restored_preview",
        )], **self.binding))
        self.harness.flush_authority.assert_not_called()
        self.harness.cleanup.assert_called_once()

    def test_missing_receipt_never_constructs_a_fixture(self):
        self.receipt.side_effect = RuntimeError("raw preflight failure")
        self.assertEqual(recovery.browse_restore_cache_report(self.args), dict(
            passed=False, cases=[dict(name=cache.CASE, status="failed", error="preflight")],
        ))
        self.fixture.assert_not_called()

    def test_changed_receipt_or_cleanup_error_cannot_pass_or_emit_raw_details(self):
        for receipt_changed, stage in ((True, "receipt_changed"), (False, "cleanup")):
            with self.subTest(stage=stage):
                self.harness.reset_mock()
                self.receipt.side_effect = [self.binding, dict(self.binding, build_receipt_sha256="2" * 64)
                                            if receipt_changed else self.binding]
                self.harness.cleanup.side_effect = None if receipt_changed else RuntimeError("raw fixture data")
                report = recovery.browse_restore_cache_report(self.args)
                self.assertEqual(report, dict(
                    passed=False, cases=[dict(name=cache.CASE, status="failed", error=stage)], **self.binding,
                ))
                self.harness.cleanup.assert_called_once()

    def test_owned_cleanup_attempts_remaining_resources_after_a_failure(self):
        with tempfile.TemporaryDirectory() as parent:
            harness = object.__new__(self.harness_type)
            harness.root = Path(parent) / "scratch"
            harness.root.mkdir()
            harness.created = [("admin-a", "owned_a"), ("admin-b", "owned_b")]
            harness.stop = Mock()
            harness.redis = Mock()
            harness.query = Mock(side_effect=[RuntimeError("synthetic failure"), ""])
            with self.assertRaises(RuntimeError):
                harness.cleanup()
            harness.stop.assert_called_once()
            harness.redis.stop.assert_called_once()
            self.assertEqual(harness.query.call_count, 2)
            self.assertFalse(harness.root.exists())


if __name__ == "__main__":
    unittest.main()
