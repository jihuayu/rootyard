#!/usr/bin/env python3
"""Exact-owned Vault Transit lifecycle for the issue #21 rotation fixture.

The common fixture module owns constants, ownership reconciliation and generic
process execution.  This module owns only the container start/health/admin/app
capability lifecycle.  Neither module prints or persists provider bodies,
tokens, request payloads, logs or raw subprocess output.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.request

from pando_vault_rotation_fixture import (
    APP_ACTIONS,
    CONTAINER_ID_RE,
    DockerRunner,
    FixtureError,
    HEALTH_TIMEOUT,
    MAX_BODY,
    OWNERSHIP_SCHEMA,
    PROVIDER_SCHEMA,
    PULL_TIMEOUT,
    VAULT_GOAL,
    VAULT_IMAGE,
    VAULT_KIND,
    VAULT_VERSION,
    _find_owned_by_name,
    _inspect_owned,
    _require,
    _validate_state,
    expected_container_name,
    published_loopback_url,
    remove_owned_container,
    service_policy,
)


class VaultFixture:
    """One exact-owned ephemeral Vault Transit provider."""

    def __init__(self, state_path, runner=None, image=VAULT_IMAGE,
                 token_factory=None, sleep=None):
        self.state_path = Path(state_path)
        self.runner = runner or DockerRunner()
        self.image = image
        self.token_factory = token_factory or secrets.token_urlsafe
        self.sleep = sleep or time.sleep
        self.nonce = secrets.token_hex(6)
        self.container_name = expected_container_name(self.nonce)
        self.key_name = "pando-vault-rotation-" + self.nonce
        self.policy_name = "pando-vault-rotation-app-" + self.nonce
        self.wrong_key_name = "pando-vault-rotation-wrong-" + self.nonce
        self.container_id = None
        self.host_url = None
        self.root_token = None
        self.tokens = {}
        self.version = None
        self.phase = None
        self.state_written = False
        self.reconciliation = "not_needed"
        self.denied_rotate = False
        self.derived_verified = False
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}))

    def safe_state(self, phase=None):
        return {
            "schema": OWNERSHIP_SCHEMA,
            "phase": phase or self.phase or (
                "created" if self.container_id else "intent"),
            "kind": VAULT_KIND,
            "goal": VAULT_GOAL,
            "nonce": self.nonce,
            "uid": os.getuid(),
            "container_id": self.container_id,
            "container_name": self.container_name,
            "image": self.image,
        }

    def write_state(self, phase):
        state = self.safe_state(phase)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(self.state_path.name + ".tmp")
        temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.state_path)
        self.state_written = True
        self.phase = phase

    def remove_state(self):
        with contextlib.suppress(FileNotFoundError):
            self.state_path.unlink()
        self.state_written = False
        self.phase = None

    def _image_digests(self):
        result = self.runner.run([
            "docker", "image", "inspect", "--format", "{{json .RepoDigests}}",
            self.image,
        ])
        if result.returncode != 0:
            return None
        try:
            digests = json.loads(result.stdout.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return digests if isinstance(digests, list) else None

    def ensure_image(self):
        digests = self._image_digests()
        if digests is None or self.image not in digests:
            result = self.runner.run(
                ["docker", "pull", self.image], timeout=PULL_TIMEOUT)
            if result.returncode != 0:
                raise FixtureError("vault_image_unavailable")
            digests = self._image_digests()
        if digests is None or self.image not in digests:
            raise FixtureError("vault_image_digest_unverified")

    def _request(self, method, path, payload=None, token=None, timeout=5):
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        request = urllib.request.Request(
            self.host_url + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                return response.status, response.read(MAX_BODY + 1)
        except urllib.error.HTTPError as error:
            return error.code, b""
        except (urllib.error.URLError, OSError, ValueError):
            raise FixtureError("vault_api_failed") from None

    def api(self, method, path, payload=None, token=None, timeout=5):
        status, raw = self._request(method, path, payload, token, timeout)
        if not 200 <= status < 300:
            raise FixtureError("vault_api_failed")
        _require(len(raw) <= MAX_BODY, "vault_api_response_too_large")
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise FixtureError("vault_api_invalid") from None
        if not isinstance(value, dict):
            raise FixtureError("vault_api_invalid")
        return value

    def request_status(self, method, path, payload=None, token=None):
        status, _ = self._request(method, path, payload, token)
        return status

    def health(self):
        value = self.api("GET", "/v1/sys/health")
        return (
            value.get("initialized") is True
            and value.get("sealed") is False
            and value.get("version") == VAULT_VERSION
        )

    def reconcile_creation(self):
        self.container_id = None
        try:
            found = _find_owned_by_name(
                self.runner, self.safe_state("intent"), "vault_ownership")
        except FixtureError:
            self.reconciliation = "unresolved"
            return
        if found is None:
            self.reconciliation = "no_resource"
            return
        self.container_id = found
        try:
            self.write_state("created")
        except OSError:
            self.reconciliation = "state_write_failed"
            return
        self.reconciliation = "recorded"

    def start(self):
        self.ensure_image()
        root_token = self.token_factory(40)
        self.root_token = root_token
        environment = os.environ.copy()
        environment["VAULT_DEV_ROOT_TOKEN_ID"] = root_token
        environment["VAULT_DEV_LISTEN_ADDRESS"] = "0.0.0.0:8200"
        command = [
            "docker", "run", "-d", "--rm", "--name", self.container_name,
            "--label", "rootyard.fixture.kind=" + VAULT_KIND,
            "--label", "rootyard.fixture.nonce=" + self.nonce,
            "--label", "rootyard.fixture.goal=" + VAULT_GOAL,
            "--label", "rootyard.fixture.uid=" + str(os.getuid()),
            "--log-driver", "none", "--cap-add", "IPC_LOCK",
            "-p", "127.0.0.1::8200",
            "-e", "VAULT_DEV_ROOT_TOKEN_ID",
            "-e", "VAULT_DEV_LISTEN_ADDRESS",
            self.image, "server", "-dev",
        ]
        try:
            self.write_state("intent")
        except OSError:
            raise FixtureError("vault_state_write_failed") from None
        try:
            result = self.runner.run(command, env=environment)
        except FixtureError:
            self.reconcile_creation()
            raise
        if result.returncode != 0:
            self.reconcile_creation()
            raise FixtureError("vault_start_failed")
        container_id = result.stdout.decode(errors="replace").strip()
        if CONTAINER_ID_RE.fullmatch(container_id) is None:
            self.reconcile_creation()
            raise FixtureError("vault_container_id_invalid")
        try:
            _inspect_owned(
                self.runner, self.safe_state("intent"), container_id,
                "vault_ownership")
        except FixtureError:
            self.reconcile_creation()
            raise
        self.container_id = container_id
        try:
            self.write_state("created")
        except OSError:
            raise FixtureError("vault_state_write_failed") from None
        ports = self.runner.run(
            ["docker", "port", self.container_name, "8200/tcp"])
        if ports.returncode != 0:
            raise FixtureError("vault_port_failed")
        lines = ports.stdout.decode(errors="replace").splitlines()
        self.host_url = published_loopback_url(lines)
        deadline = time.monotonic() + HEALTH_TIMEOUT
        while time.monotonic() < deadline:
            try:
                if self.health():
                    break
            except FixtureError:
                pass
            self.sleep(0.2)
        else:
            raise FixtureError("vault_health_timeout")
        self.version = VAULT_VERSION

    def key_metadata(self, key_name=None, token=None):
        key = key_name or self.key_name
        value = self.api("GET", "/v1/transit/keys/" + key, token=token or self.root_token)
        data = value.get("data")
        if not isinstance(data, dict):
            raise FixtureError("vault_key_metadata_invalid")
        parsed = {
            "type": data.get("type"),
            "derived": data.get("derived"),
            "latest_version": data.get("latest_version"),
            "min_decryption_version": data.get("min_decryption_version"),
            "min_encryption_version": data.get("min_encryption_version"),
        }
        if (
            parsed["type"] != "aes256-gcm96"
            or parsed["derived"] is not True
            or not isinstance(parsed["latest_version"], int)
            or parsed["latest_version"] < 1
            or not isinstance(parsed["min_decryption_version"], int)
            or parsed["min_decryption_version"] < 1
        ):
            raise FixtureError("vault_key_metadata_unexpected")
        return parsed

    def prepare_admin(self):
        if not self.root_token:
            raise FixtureError("vault_root_token_missing")
        self.api("POST", "/v1/sys/mounts/transit", {"type": "transit"},
                 token=self.root_token)
        self.api("POST", "/v1/transit/keys/" + self.key_name,
                 {"type": "aes256-gcm96", "derived": True},
                 token=self.root_token)
        self.api("POST", "/v1/transit/keys/" + self.key_name + "/config",
                 {"min_decryption_version": 1}, token=self.root_token)
        metadata = self.key_metadata()
        if metadata["latest_version"] != 1:
            raise FixtureError("vault_initial_version_unexpected")
        self.derived_verified = True
        return metadata

    def create_scoped_token(self, key_name=None):
        key = key_name or self.key_name
        policy = "pando-vault-rotation-app-" + self.nonce
        if key != self.key_name:
            policy += "-" + key
        self.api("PUT", "/v1/sys/policies/acl/" + policy,
                 {"policy": service_policy(key)}, token=self.root_token)
        result = self.api("POST", "/v1/auth/token/create", {
            "policies": [policy],
            "no_default_policy": True,
            "ttl": "2h",
            "renewable": False,
        }, token=self.root_token)
        auth = result.get("auth")
        if not isinstance(auth, dict):
            raise FixtureError("vault_scoped_token_missing")
        token = auth.get("client_token")
        accessor = auth.get("accessor")
        if not isinstance(token, str) or not token:
            raise FixtureError("vault_scoped_token_missing")
        if not isinstance(accessor, str) or not accessor:
            raise FixtureError("vault_scoped_token_accessor_missing")
        self.tokens[key] = {
            "token": token,
            "accessor": accessor,
            "policy": policy,
        }
        return token

    def _app_api(self, key_name, action, payload):
        entry = self.tokens.get(key_name)
        if not entry:
            raise FixtureError("vault_scoped_token_missing")
        return self.api("POST", "/v1/transit/%s/%s" % (action, key_name),
                        payload, token=entry["token"])

    def probe_scoped_key(self, key_name):
        """Prove a scoped token can wrap/unwrap/rewrap but cannot rotate."""
        entry = self.tokens.get(key_name)
        if not entry:
            raise FixtureError("vault_scoped_token_missing")
        token = entry["token"]
        metadata = self.key_metadata(key_name=key_name, token=token)
        plaintext = __import__("base64").b64encode(os.urandom(32)).decode()
        encrypted = self._app_api(key_name, "encrypt", {"plaintext": plaintext})
        ciphertext = (encrypted.get("data") or {}).get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext:
            raise FixtureError("vault_app_encrypt_failed")
        decrypted = self._app_api(key_name, "decrypt", {"ciphertext": ciphertext})
        if (decrypted.get("data") or {}).get("plaintext") != plaintext:
            raise FixtureError("vault_app_decrypt_failed")
        rewrapped = self._app_api(key_name, "rewrap", {"ciphertext": ciphertext})
        ciphertext2 = (rewrapped.get("data") or {}).get("ciphertext")
        if not isinstance(ciphertext2, str) or not ciphertext2:
            raise FixtureError("vault_app_rewrap_failed")
        decrypted2 = self._app_api(key_name, "decrypt", {"ciphertext": ciphertext2})
        if (decrypted2.get("data") or {}).get("plaintext") != plaintext:
            raise FixtureError("vault_app_rewrap_roundtrip_failed")
        latest = metadata["latest_version"]
        rotate_status = self.request_status(
            "POST", "/v1/transit/keys/" + key_name + "/rotate", token=token)
        if rotate_status != 403:
            raise FixtureError("vault_app_rotate_not_denied")
        after = self.key_metadata(key_name=key_name, token=token)
        if after["latest_version"] != latest:
            raise FixtureError("vault_app_rotate_changed_version")
        return {
            "metadata": metadata,
            "rotate_denied": True,
            "latest_unchanged": True,
            "encrypt_decrypt_rewrap": True,
        }

    def verify_app_capabilities(self):
        result = self.probe_scoped_key(self.key_name)
        token = self.tokens[self.key_name]["token"]
        denied = {}
        for name, method, path, payload in (
            ("delete", "DELETE", "/v1/transit/keys/" + self.key_name, None),
            ("config", "POST", "/v1/transit/keys/" + self.key_name + "/config",
             {"min_decryption_version": 2}),
            ("token", "POST", "/v1/auth/token/create",
             {"policies": ["default"], "ttl": "1m"}),
            ("policy", "GET", "/v1/sys/policies/acl/" + self.policy_name, None),
        ):
            status = self.request_status(method, path, payload, token=token)
            denied[name] = status == 403
            if status != 403:
                raise FixtureError("vault_app_" + name + "_not_denied")
        self.denied_rotate = result["rotate_denied"]
        result.update({
            "delete_denied": denied["delete"],
            "config_denied": denied["config"],
            "token_admin_denied": denied["token"],
            "policy_admin_denied": denied["policy"],
        })
        return result

    def admin_rotate(self):
        self.api("POST", "/v1/transit/keys/" + self.key_name + "/rotate",
                 token=self.root_token)
        return self.key_metadata()

    def create_wrong_key(self):
        self.api("POST", "/v1/transit/keys/" + self.wrong_key_name,
                 {"type": "aes256-gcm96", "derived": True},
                 token=self.root_token)
        self.api("POST", "/v1/transit/keys/" + self.wrong_key_name + "/config",
                 {"min_decryption_version": 1}, token=self.root_token)
        self.create_scoped_token(self.wrong_key_name)
        return self.key_metadata(key_name=self.wrong_key_name,
                                 token=self.tokens[self.wrong_key_name]["token"])

    def environment(self, key_name=None):
        key = key_name or self.key_name
        entry = self.tokens.get(key)
        if not self.prepared or not entry or not self.host_url:
            raise FixtureError("vault_not_prepared")
        return {
            "PANDO_KMS_VAULT_URL": self.host_url,
            "PANDO_KMS_VAULT_TOKEN": entry["token"],
            "PANDO_KMS_VAULT_MOUNT": "transit",
            "PANDO_KMS_VAULT_KEY": key,
        }

    @property
    def prepared(self):
        return bool(self.tokens) and self.host_url is not None

    def revoke_scoped_token(self, key_name=None):
        key = key_name or self.key_name
        entry = self.tokens.get(key)
        if not entry:
            raise FixtureError("vault_scoped_token_missing")
        self.api("POST", "/v1/auth/token/revoke-accessor",
                 {"accessor": entry["accessor"]}, token=self.root_token)
        return True

    def release_credentials(self):
        self.root_token = None
        self.tokens = {}

    def safe_record(self, cleanup):
        return {
            "schema": PROVIDER_SCHEMA,
            "kind": "owned-loopback-vault-transit",
            "image_digest_sha256": self.image.rsplit("@sha256:", 1)[-1],
            "vault_version": self.version,
            "derived_key_verified": self.derived_verified,
            "application_policy_scoped": bool(self.tokens),
            "application_master_rotate_denied": self.denied_rotate,
            "owned_container": self.container_id is not None or self.state_written,
            "ownership_recorded": self.state_written,
            "reconciliation": self.reconciliation,
            "raw_logs_persisted": False,
            "credential_file_written": False,
            "cleanup": cleanup,
        }

    def stop(self):
        state = _validate_state(self.safe_state(
            "created" if self.container_id else "intent"))
        if self.root_token and self.host_url:
            try:
                self.api("POST", "/v1/auth/token/revoke-self",
                         token=self.root_token)
            except FixtureError:
                pass
        result = remove_owned_container(self.runner, state)
        self.remove_state()
        self.release_credentials()
        return result
