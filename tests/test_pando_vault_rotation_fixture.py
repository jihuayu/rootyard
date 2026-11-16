#!/usr/bin/env python3
"""Pure guard tests for the owned issue #21 Vault/PG rotation fixture.

No Docker daemon, Vault, PostgreSQL, HTTP API, Cargo, product binary or
credential is used.  Injected runners prove the fixture's fail-closed
ownership, bounded lifecycle, argv/environment secret split, derived-key admin
setup, restricted application policy and exact cleanup boundaries.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import pando_vault_rotation_fixture as common  # noqa: E402
import pando_vault_rotation_fixture_resources as resources  # noqa: E402
import pando_vault_rotation_fixture_vault as vault  # noqa: E402


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self, results, on_call=None):
        self.results = list(results)
        self.calls = []
        self.on_call = on_call

    def run(self, argv, **kwargs):
        argv = [str(item) for item in argv]
        self.calls.append((argv, kwargs))
        if self.on_call is not None:
            self.on_call(argv, kwargs)
        if not self.results:
            raise AssertionError("unexpected command")
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(argv, kwargs)
        return item


def labels(state):
    return {
        "rootyard.fixture.kind": state["kind"],
        "rootyard.fixture.nonce": state["nonce"],
        "rootyard.fixture.goal": state["goal"],
        "rootyard.fixture.uid": str(state["uid"]),
    }


def owned_state(cid="a" * 64, nonce="b" * 12, phase="created"):
    return {
        "schema": common.OWNERSHIP_SCHEMA,
        "phase": phase,
        "kind": common.VAULT_KIND,
        "goal": common.VAULT_GOAL,
        "nonce": nonce,
        "uid": os.getuid(),
        "container_id": cid if phase == "created" else None,
        "container_name": common.expected_container_name(nonce),
        "image": common.VAULT_IMAGE,
    }


def inspect_results(state, image=None, label_values=None):
    return [
        Result(0, (state["container_id"] + "\n").encode()),
        Result(0, ((image or state["image"]) + "\n").encode()),
        Result(0, json.dumps(label_values or labels(state)).encode()),
    ]


def fixture(state_dir, runner):
    value = vault.VaultFixture(
        state_dir, runner=runner, token_factory=lambda _: "root-token",
        sleep=lambda _: None)
    value.nonce = "b" * 12
    value.container_name = common.expected_container_name(value.nonce)
    value.key_name = "pando-vault-rotation-" + value.nonce
    value.policy_name = "pando-vault-rotation-app-" + value.nonce
    value.wrong_key_name = "pando-vault-rotation-wrong-" + value.nonce
    return value


class PinAndPolicyTest(unittest.TestCase):
    def test_pinned_image_and_runtime_are_exact(self):
        self.assertEqual(
            common.VAULT_IMAGE,
            "hashicorp/vault@sha256:"
            "dfa48c2fa2b0099ccb47681ec5c4804bf5aec9d6879ecfee07ad4b92a5427ad6",
        )
        self.assertEqual(common.VAULT_VERSION, "2.2.2")
        self.assertEqual(common.CONTAINER_PREFIX, "rootyard-pando-vault-rotation-")

    def test_application_policy_has_only_read_and_wrap_capabilities(self):
        policy = common.service_policy("key-one")
        for action in ("encrypt", "decrypt", "rewrap"):
            self.assertIn('path "transit/%s/key-one"' % action, policy)
        self.assertIn('path "transit/keys/key-one" { capabilities = ["read"] }', policy)
        for forbidden in ("rotate", "delete", "config", "policy", "token"):
            self.assertNotIn("transit/" + forbidden, policy)
        self.assertNotIn("transit/keys/key-one/rotate", policy)
        self.assertNotIn('capabilities = ["update"] }', policy.split(
            'path "transit/keys/key-one"')[0])

    def test_policy_rejects_injection_like_key_names(self):
        for value in ("", "a\nb", 'a"b'):
            with self.subTest(value=value):
                with self.assertRaises(common.FixtureError):
                    common.service_policy(value)

    def test_loopback_publication_is_exact_ipv4(self):
        self.assertEqual(
            common.published_loopback_url(["127.0.0.1:49152"]),
            "http://127.0.0.1:49152",
        )
        for lines in (["0.0.0.0:8200"], ["[::1]:8200"], ["127.0.0.1:0"],
                      ["127.0.0.1:not-a-port"], []):
            with self.subTest(lines=lines):
                with self.assertRaises(common.FixtureError):
                    common.published_loopback_url(lines)

    def test_starting_command_keeps_token_out_of_argv(self):
        cid = "c" * 64
        state = owned_state(cid=cid)
        seen = {}

        def check_state(argv, kwargs):
            if argv[:2] == ["docker", "run"]:
                seen["state_exists_at_run"] = Path(seen["state_path"]).is_file()
                seen["env"] = kwargs.get("env") or {}

        runner = FakeRunner([
            Result(0, (json.dumps([common.VAULT_IMAGE]) + "\n").encode()),
            Result(0, (cid + "\n").encode()),
            *inspect_results(state),
            Result(0, b"127.0.0.1:49152\n"),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "vault.json"
            seen["state_path"] = state_path
            value = vault.VaultFixture(
                state_path, runner=runner, token_factory=lambda _: "root-token",
                sleep=lambda _: None)
            value.nonce = state["nonce"]
            value.container_name = state["container_name"]
            value.key_name = "pando-vault-rotation-" + value.nonce
            value.policy_name = "pando-vault-rotation-app-" + value.nonce
            runner.on_call = check_state
            with mock.patch.object(vault.VaultFixture, "health", return_value=True):
                value.start()
            self.assertTrue(seen["state_exists_at_run"])
            command = next(argv for argv, _ in runner.calls if argv[:2] == ["docker", "run"])
            joined = " ".join(command)
            self.assertNotIn("root-token", joined)
            self.assertIn("-e", command)
            self.assertIn("VAULT_DEV_ROOT_TOKEN_ID", command)
            self.assertNotIn("VAULT_DEV_ROOT_TOKEN_ID=root-token", joined)
            self.assertIn("--log-driver", command)
            self.assertIn("none", command)
            self.assertIn("127.0.0.1::8200", " ".join(command))
            self.assertEqual(seen["env"]["VAULT_DEV_ROOT_TOKEN_ID"], "root-token")
            self.assertEqual(value.phase, "created")
            self.assertEqual(value.host_url, "http://127.0.0.1:49152")

    def test_wrong_image_digest_pulls_with_bound_then_fails(self):
        runner = FakeRunner([
            Result(0, (json.dumps(["hashicorp/vault@sha256:" + "0" * 64]) + "\n").encode()),
            Result(0),
            Result(0, (json.dumps(["hashicorp/vault@sha256:" + "0" * 64]) + "\n").encode()),
        ])
        value = fixture("/tmp/does-not-exist", runner)
        with self.assertRaises(common.FixtureError) as caught:
            value.ensure_image()
        self.assertEqual(caught.exception.code, "vault_image_digest_unverified")
        pull = next(argv for argv, _ in runner.calls if argv[:2] == ["docker", "pull"])
        self.assertEqual(pull[-1], common.VAULT_IMAGE)
        self.assertEqual(runner.calls[1][1]["timeout"], common.PULL_TIMEOUT)

    def test_cleanup_rejects_foreign_container_and_bad_labels(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            state = owned_state()
            path.write_text(json.dumps(state))
            bad = labels(state)
            bad["rootyard.fixture.nonce"] = "d" * 12
            runner = FakeRunner(inspect_results(state, label_values=bad))
            with self.assertRaises(common.FixtureError) as caught:
                common.cleanup_owned_state(path, runner)
            self.assertEqual(caught.exception.code, "vault_cleanup_label_mismatch")
            self.assertTrue(path.exists())

    def test_cleanup_removes_only_exact_verified_id(self):
        state = owned_state()
        runner = FakeRunner([
            *inspect_results(state),
            Result(0),
        ])
        result = common.remove_owned_container(runner, state)
        self.assertEqual(result, "stopped")
        self.assertEqual(runner.calls[-1][0][:4], ["docker", "rm", "-f", "--"])

    def test_cleanup_absent_is_honest_no_resource(self):
        state = owned_state(phase="intent")
        runner = FakeRunner([Result(0, b"")])
        self.assertEqual(common.remove_owned_container(runner, state), "absent")

    def test_creation_failure_reconciles_by_exact_name_then_cleanup(self):
        cid = "e" * 64
        state = owned_state(cid=cid, nonce="b" * 12)
        runner = FakeRunner([
            Result(0, (json.dumps([common.VAULT_IMAGE]) + "\n").encode()),
            common.FixtureError("process_failed"),
            Result(0, (cid + "\t" + state["container_name"] + "\n").encode()),
            *inspect_results(state),
            *inspect_results(state),
            Result(0),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            value = fixture(path, runner)
            with self.assertRaises(common.FixtureError):
                with mock.patch.object(vault.VaultFixture, "health", return_value=True):
                    value.start()
            self.assertEqual(value.container_id, cid)
            self.assertEqual(value.reconciliation, "recorded")
            self.assertEqual(value.stop(), "stopped")
            self.assertFalse(path.exists())

    def test_admin_setup_uses_derived_key_and_version_one_floor(self):
        value = fixture("/tmp/unused", FakeRunner([]))
        value.host_url = "http://127.0.0.1:1"
        value.root_token = "root-token"
        calls = []

        def fake_api(method, path, payload=None, token=None, timeout=5):
            calls.append((method, path, payload, token))
            if path.endswith("/keys/" + value.key_name):
                return {"data": {
                    "type": "aes256-gcm96", "derived": True,
                    "latest_version": 1, "min_decryption_version": 1,
                    "min_encryption_version": 0,
                }}
            return {}

        value.api = fake_api
        metadata = value.prepare_admin()
        self.assertTrue(value.derived_verified)
        self.assertEqual(metadata["latest_version"], 1)
        key_call = next(call for call in calls if call[1] == "/v1/transit/keys/" + value.key_name)
        self.assertEqual(key_call[2], {"type": "aes256-gcm96", "derived": True})
        config_call = next(call for call in calls if call[1].endswith("/config"))
        self.assertEqual(config_call[2], {"min_decryption_version": 1})
        self.assertTrue(all(call[3] == "root-token" for call in calls))

    def test_scoped_environment_is_pando_only_and_safe_record_has_no_token(self):
        value = fixture("/tmp/unused", FakeRunner([]))
        value.host_url = "http://127.0.0.1:49152"
        value.tokens[value.key_name] = {
            "token": "app-token", "accessor": "app-accessor", "policy": value.policy_name}
        environment = value.environment()
        self.assertEqual(set(environment), {
            "PANDO_KMS_VAULT_URL", "PANDO_KMS_VAULT_TOKEN",
            "PANDO_KMS_VAULT_MOUNT", "PANDO_KMS_VAULT_KEY"})
        self.assertEqual(environment["PANDO_KMS_VAULT_TOKEN"], "app-token")
        self.assertNotIn("ROOTYARD_KMS", json.dumps(environment))
        record = value.safe_record({"vault": True})
        text = json.dumps(record)
        self.assertNotIn("app-token", text)
        self.assertNotIn("app-accessor", text)
        self.assertNotIn("http://", text)

    def test_revoke_uses_accessor_not_raw_token(self):
        value = fixture("/tmp/unused", FakeRunner([]))
        value.host_url = "http://127.0.0.1:1"
        value.root_token = "root-token"
        value.tokens[value.key_name] = {
            "token": "app-token", "accessor": "app-accessor", "policy": "p"}
        calls = []
        value.api = lambda method, path, payload=None, token=None, timeout=5: (
            calls.append((method, path, payload, token)) or {})
        value.revoke_scoped_token()
        self.assertEqual(calls[0][2], {"accessor": "app-accessor"})
        self.assertNotIn("app-token", json.dumps(calls[0]))

    def test_health_timeout_fails_without_success(self):
        state = owned_state(cid="f" * 64)
        runner = FakeRunner([
            Result(0, (json.dumps([common.VAULT_IMAGE]) + "\n").encode()),
            Result(0, (state["container_id"] + "\n").encode()),
            *inspect_results(state),
            Result(0, b"127.0.0.1:49152\n"),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            value = fixture(path, runner)
            with mock.patch.object(vault.VaultFixture, "health", return_value=False):
                with mock.patch.object(vault.time, "monotonic", side_effect=[0, 46]):
                    with self.assertRaises(common.FixtureError) as caught:
                        value.start()
            self.assertEqual(caught.exception.code, "vault_health_timeout")
            self.assertTrue(path.exists())

    def test_process_runner_wraps_timeout_without_raw_message(self):
        runner = common.ProcessRunner(timeout=1)
        with mock.patch.object(
                common.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(["docker"], 1,
                                                      output=b"secret-token")):
            with self.assertRaises(common.FixtureError) as caught:
                runner.run(["docker", "version"])
        self.assertEqual(caught.exception.code, "process_failed")
        self.assertNotIn("secret-token", str(caught.exception))


class PostgresAndRootTest(unittest.TestCase):
    def psql_runner(self, version="170004"):
        state = {"exists": False, "db_name": None, "calls": [], "oid": "16384"}

        class Runner:
            def run(self, argv, **kwargs):
                sql = (kwargs.get("input") or b"").decode()
                state["calls"].append(([str(item) for item in argv], kwargs, sql))
                if "SHOW server_version_num" in sql:
                    return Result(0, (version + "\n").encode())
                if "oid::text" in sql and "FROM pg_database" in sql:
                    if not state["exists"] or not state["db_name"]:
                        return Result(0, b"")
                    return Result(
                        0, ("%s|10|%s|10\n" % (state["oid"], state["db_name"])).encode())
                if "FROM pg_database" in sql:
                    return Result(0, (("1" if state["exists"] else "") + "\n").encode())
                if sql.startswith('CREATE DATABASE'):
                    state["exists"] = True
                    return Result(0, b"")
                if sql.startswith('DROP DATABASE'):
                    state["exists"] = False
                    return Result(0, b"")
                return Result(0, b"")

        return Runner(), state

    def test_dsn_validation_requires_literal_loopback_and_allowlisted_query(self):
        parsed = resources.parse_bootstrap_dsn(
            "postgresql://u:p@127.0.0.1:55432/db?sslmode=disable")
        self.assertEqual(parsed["host"], "127.0.0.1")
        self.assertEqual(parsed["database"], "db")
        for dsn, code in (
            ("postgresql://u:p@localhost/db", "pg_dsn_not_loopback"),
            ("mysql://u:p@127.0.0.1/db", "pg_dsn_scheme_invalid"),
            ("postgresql://u:p@127.0.0.1/db?application_name=x",
             "pg_dsn_query_unsupported"),
            ("postgresql://u:p@127.0.0.1/", "pg_dsn_database_missing"),
        ):
            with self.subTest(code=code):
                with self.assertRaises(common.FixtureError) as caught:
                    resources.parse_bootstrap_dsn(dsn)
                self.assertEqual(caught.exception.code, code)

    def test_owned_database_creates_and_drops_only_nonce_name(self):
        runner, state = self.psql_runner()
        value = resources.OwnedPostgres(
            "postgresql://user:password@127.0.0.1:55432/admin",
            nonce="a" * 12, runner=runner)
        state["db_name"] = value.database
        value.create()
        self.assertEqual(value.database, "pando_rotation_" + "a" * 12)
        self.assertTrue(value.created)
        value.drop()
        self.assertTrue(value.dropped)
        for argv, kwargs, sql in state["calls"]:
            self.assertNotIn("password", argv)
            self.assertNotIn("postgresql://", " ".join(argv))
            self.assertEqual(kwargs["env"]["PGPASSWORD"], "password")
            if "SHOW server_version_num" not in sql:
                self.assertIn(value.database, sql)

    def test_owned_database_rejects_pg16_and_foreign_drop(self):
        runner, _ = self.psql_runner(version="160009")
        value = resources.OwnedPostgres(
            "postgresql://user:password@127.0.0.1:55432/admin",
            nonce="b" * 12, runner=runner)
        with self.assertRaises(common.FixtureError) as caught:
            value.validate()
        self.assertEqual(caught.exception.code, "pg_major_not_17")
        with self.assertRaises(common.FixtureError) as caught:
            value.drop()
        self.assertEqual(caught.exception.code, "pg_drop_not_owned")

    def test_owned_root_removes_only_exact_private_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = resources.OwnedRoot(nonce="c" * 12, base=temporary)
            path = root.create()
            self.assertTrue(path.is_absolute())
            self.assertTrue(path.is_dir())
            self.assertTrue(root.remove())
            self.assertFalse(path.exists())

    def test_owned_root_refuses_foreign_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = resources.OwnedRoot(nonce="d" * 12, base=temporary)
            root.create()
            foreign = Path(temporary) / "not-owned"
            foreign.mkdir()
            root.path = foreign
            with self.assertRaises(common.FixtureError) as caught:
                root.remove()
            self.assertEqual(caught.exception.code, "root_path_prefix_mismatch")
            self.assertTrue(foreign.exists())


if __name__ == "__main__":
    unittest.main()
