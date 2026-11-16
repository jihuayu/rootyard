#!/usr/bin/env python3
"""Mutable harness context for the five issue #21 rotation cases.

The context owns only one Vault fixture, one random PG database, one private
PANDO_ROOT and one Pando HTTP server.  Every cold read evicts the exact owned
plaintext pack/idx files first.  No raw child output, provider body, DSN or
secret is stored on the context.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import time
import uuid

from pando_vault_rotation_fixture import FixtureError
from pando_vault_rotation_fixture_resources import OwnedPostgres, OwnedRoot
from pando_vault_rotation_fixture_vault import VaultFixture
from pando_vault_rotation_service import GitWorkspace, Psql, Server
from pando_vault_rotation_support import (
    QualificationError,
    child_environment,
    evict_plaintext_cache,
    read_cipher,
    read_manifest,
    require,
    valid_uuid,
)


class Context:
    def __init__(self, inputs, base_environment, runner):
        self.inputs = inputs
        self.base_environment = dict(base_environment)
        self.runner = runner
        self.binary = str(inputs["binary"])
        self.root = None
        self.fixture = None
        self.postgres = None
        self.psql = None
        self.server = None
        self.git = None
        self.environment = None
        self.repo = None
        self.source = None
        self.pack_ids = []
        self.markers = []
        self.baseline = {}
        self.setup_error = None

    def start_base(self):
        self.root = OwnedRoot()
        root_path = self.root.create()
        self.markers = [
            "ROOTYARD_ISSUE21_%s_ALPHA" % self.root.nonce.upper(),
            "ROOTYARD_ISSUE21_%s_BETA" % self.root.nonce.upper(),
            "ROOTYARD_ISSUE21_%s_GAMMA" % self.root.nonce.upper(),
            "ROOTYARD_ISSUE21_%s_DELTA" % self.root.nonce.upper(),
        ]
        self.fixture = VaultFixture(root_path / "vault-state.json", runner=self.runner)
        self.fixture.start()
        self.fixture.prepare_admin()
        self.fixture.create_scoped_token()
        self.postgres = OwnedPostgres(
            self.inputs["bootstrap_dsn"], nonce=self.root.nonce, runner=self.runner)
        self.postgres.create()
        self.psql = Psql(self.postgres, runner=self.runner)
        git = shutil.which("git")
        require(git is not None and Path(git).is_absolute(), "git_missing", "setup")
        self.environment = child_environment(
            self.base_environment, self.postgres, root_path,
            self.fixture.environment(), git)
        self.run_cli(["init"], stage="init")
        self.repo = str(uuid.uuid4())
        self.run_cli(["create-repo", self.repo, "alice"], stage="create_repo")
        self.server = Server(self.binary, self.environment)
        self.server.start()
        self.git = GitWorkspace(self.environment, runner=self.runner)
        self.source = root_path / "source"
        self.git.init(self.source)

    def run_cli(self, args, env=None, stage="cli", timeout=90):
        return self.runner.ok(
            [self.binary, *args], env=env or self.environment,
            timeout=timeout, stage=stage)

    def cli(self, args, env=None, stage="cli", timeout=90):
        return self.runner.json(
            [self.binary, *args], env=env or self.environment,
            timeout=timeout, stage=stage)

    def run_status(self, args, env=None, stage="cli", timeout=90):
        return self.runner.run(
            [self.binary, *args], env=env or self.environment,
            timeout=timeout, stage=stage)

    def commit_and_push(self, index, message):
        require(0 <= index < len(self.markers), "marker_index_invalid", "git")
        self.git.commit(self.source, self.markers[index], message)
        self.git.push(self.source, self.server.url(self.repo))
        return self.markers[index]

    def prepare_initial_packs(self):
        self.commit_and_push(0, "rotation alpha")
        self.commit_and_push(1, "rotation beta")
        self.refresh_packs()
        require(len(self.pack_ids) >= 2, "initial_pack_count_insufficient", "packs")
        return self.pack_ids

    def refresh_packs(self):
        rows = self.psql.manifests(self.repo)
        self.pack_ids = sorted(row["pack_id"] for row in rows)
        require(bool(self.pack_ids), "no_committed_packs", "packs")
        return self.pack_ids

    def manifest(self, pack):
        return read_manifest(self.root.path, self.repo, pack)

    def envelope(self, pack):
        value = self.psql.envelope_for(self.repo, pack)
        require(value is not None, "db_envelope_missing", "db_authority")
        return value

    def cipher(self, pack):
        return read_cipher(self.root.path, self.manifest(pack))

    def evict(self, pack_ids=None):
        return evict_plaintext_cache(
            self.root.path, self.repo, pack_ids if pack_ids is not None else self.pack_ids)

    def cold_get(self, pack, env=None):
        self.evict([pack])
        report = self.cli(["object-store-get", self.repo, pack], env=env,
                          stage="cold_object_store_get")
        manifest = self.manifest(pack)
        require(report.get("verified") is True, "cold_get_not_verified",
                "cold_object_store_get")
        require(report.get("rehydrated_from_object_store") is True,
                "cold_get_not_rehydrated", "cold_object_store_get")
        require(report.get("cache_hit") is False, "cold_get_served_cache",
                "cold_object_store_get")
        require(report.get("pack_sha256") == manifest["pack_sha256"]
                and report.get("pack_bytes") == manifest["pack_bytes"],
                "cold_get_manifest_mismatch", "cold_object_store_get")
        local_pack = self.root.path / "objects" / self.repo / (pack + ".pack")
        require(local_pack.is_file(), "cold_get_cache_missing", "cold_object_store_get")
        require(__import__("hashlib").sha256(local_pack.read_bytes()).hexdigest()
                == manifest["pack_sha256"], "cold_get_plaintext_digest_mismatch",
                "cold_object_store_get")
        return report

    def cold_verify(self, env=None):
        self.refresh_packs()
        self.evict()
        report = self.cli(["kms-verify", self.repo], env=env,
                          stage="cold_kms_verify")
        require(report.get("verified") is True, "cold_verify_not_verified",
                "cold_kms_verify")
        require(report.get("packs_checked") == len(self.pack_ids)
                and report.get("packs_verified") == len(self.pack_ids),
                "cold_verify_pack_count_mismatch", "cold_kms_verify")
        require(report.get("encryption_mode") == "authenticated-envelope-v1"
                and report.get("authenticated_encryption") is True,
                "cold_verify_mode_mismatch", "cold_kms_verify")
        return report

    def cold_clone(self, name):
        self.refresh_packs()
        self.evict()
        destination = self.root.path / name
        clone = self.git.clone(self.server.url(self.repo), destination)
        return clone

    def status(self, env=None):
        return self.cli(["kms-status", self.repo], env=env, stage="kms_status")

    def close_fixture_view(self):
        """Best-effort memory release unrelated to ownership cleanup."""
        if self.fixture is not None:
            self.fixture.release_credentials()
