#!/usr/bin/env python3
"""Database, Git/HTTP and process boundaries for the rotation harness.

All SQL arrives on psql stdin and all connection credentials arrive in the psql
environment.  Git pushes/clones use only the lab's synthetic principal header,
never a token.  The server's stderr is discarded and only its bounded LISTEN
announcement is parsed; no raw log, SQL row, DSN or pack byte is persisted.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import time
import urllib.parse

from pando_vault_rotation_support import (
    QualificationError,
    Runner,
    require,
    sha256_bytes,
    valid_uuid,
)


class Psql:
    def __init__(self, postgres, runner=None):
        self.database = postgres.database
        self.environment = dict(postgres.environment)
        self.environment["PGDATABASE"] = self.database
        self.runner = runner or Runner()

    def _run(self, sql, stage, timeout=30):
        return self.runner.ok(
            ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
            env=self.environment,
            input=sql.encode(),
            timeout=timeout,
            stage=stage,
        )

    def execute(self, sql, stage="database", timeout=30):
        self._run(sql, stage, timeout)
        return True

    def json_rows(self, sql, stage="database", timeout=30):
        result = self._run(sql, stage, timeout)
        text = result.stdout.decode(errors="replace").strip()
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            raise QualificationError("database_output_invalid", stage) from None
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise QualificationError("database_output_invalid", stage)
        return value

    def manifests(self, repo):
        require(valid_uuid(repo), "database_repo_invalid", "database")
        return self.json_rows(
            "SELECT COALESCE(json_agg(json_build_object("
            "'pack_id',pack_id::text,'pack_sha256',pack_sha256,"
            "'idx_sha256',idx_sha256) ORDER BY pack_id),'[]'::json) "
            "FROM pando_lab.manifests WHERE repo='%s';" % repo,
        )

    def envelopes(self, repo):
        require(valid_uuid(repo), "database_repo_invalid", "database")
        return self.json_rows(
            "SELECT COALESCE(json_agg(json_build_object("
            "'pack_id',pack_id::text,'key_id',key_id,'key_version',key_version,"
            "'cipher_suite',cipher_suite,'plaintext_sha256',plaintext_sha256,"
            "'envelope_mac',envelope_mac,'encryption_mode',encryption_mode,"
            "'ciphertext_sha256',ciphertext_sha256,'ciphertext_bytes',ciphertext_bytes,"
            "'provider_kind',provider_kind) ORDER BY pack_id),'[]'::json) "
            "FROM pando_lab.kms_envelopes WHERE repo='%s';" % repo,
        )

    def envelope_for(self, repo, pack):
        require(valid_uuid(repo) and valid_uuid(pack), "database_identity_invalid",
                "database")
        rows = self.json_rows(
            "SELECT COALESCE(json_agg(json_build_object("
            "'pack_id',pack_id::text,'key_id',key_id,'key_version',key_version,"
            "'cipher_suite',cipher_suite,'plaintext_sha256',plaintext_sha256,"
            "'envelope_mac',envelope_mac,'encryption_mode',encryption_mode,"
            "'ciphertext_sha256',ciphertext_sha256,'ciphertext_bytes',ciphertext_bytes,"
            "'provider_kind',provider_kind)),'[]'::json) "
            "FROM pando_lab.kms_envelopes WHERE repo='%s' AND pack_id='%s';"
            % (repo, pack),
        )
        return rows[0] if rows else None

    def set_envelope_auth(self, repo, pack, mac, cipher_sha):
        require(valid_uuid(repo) and valid_uuid(pack), "database_identity_invalid",
                "database")
        for value in (mac, cipher_sha):
            require(isinstance(value, str) and len(value) == 64
                    and all(char in "0123456789abcdef" for char in value),
                    "database_tamper_value_invalid", "database")
        self.execute(
            "UPDATE pando_lab.kms_envelopes SET envelope_mac='%s', "
            "ciphertext_sha256='%s' WHERE repo='%s' AND pack_id='%s';"
            % (mac, cipher_sha, repo, pack),
            stage="database_tamper",
        )

    def restore_envelope_auth(self, repo, pack, mac, cipher_sha):
        self.set_envelope_auth(repo, pack, mac, cipher_sha)

    def envelope_counts(self, repo):
        rows = self.json_rows(
            "SELECT COALESCE(json_agg(json_build_object("
            "'envelopes',(SELECT count(*) FROM pando_lab.kms_envelopes WHERE repo='%s'),"
            "'manifests',(SELECT count(*) FROM pando_lab.manifests WHERE repo='%s')),"
            "'[]'::json);" % (repo, repo),
            stage="database_count",
        )
        return rows[0]


class Server:
    def __init__(self, binary, environment, runner=None):
        self.binary = str(binary)
        self.environment = dict(environment)
        self.process = None
        self.base = None

    def start(self, timeout=45):
        require(self.process is None, "server_already_started", "server")
        try:
            self.process = subprocess.Popen(
                [self.binary, "serve"],
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except OSError:
            raise QualificationError("server_start_failed", "server") from None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise QualificationError("server_exited", "server")
            ready, _, _ = select.select([self.process.stdout], [], [], 0.2)
            if not ready:
                continue
            line = self.process.stdout.readline()
            if not line:
                if self.process.poll() is not None:
                    raise QualificationError("server_exited", "server")
                continue
            if not line.startswith("LISTEN "):
                continue
            value = line.split(" ", 1)[1].strip()
            try:
                parsed = urllib.parse.urlsplit(value)
                port = parsed.port
            except ValueError:
                raise QualificationError("server_announcement_invalid", "server") from None
            if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                    or not port or parsed.path not in ("", "/")):
                raise QualificationError("server_announcement_invalid", "server")
            self.base = "http://127.0.0.1:" + str(port)
            return self.base
        self.stop()
        raise QualificationError("server_start_timeout", "server")

    def stop(self, timeout=15):
        if self.process is None:
            return True
        if self.process.poll() is not None:
            self.process = None
            return True
        self.process.terminate()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise QualificationError("server_stop_timeout", "cleanup") from None
        self.process = None
        return True

    def url(self, repo):
        require(valid_uuid(repo), "server_repo_invalid", "server")
        require(self.base is not None, "server_not_started", "server")
        return self.base + "/repos/" + repo + ".git"


class GitWorkspace:
    def __init__(self, environment, runner=None):
        self.environment = dict(environment)
        self.runner = runner or Runner()
        self.git = shutil.which("git")
        require(self.git is not None and os.path.isabs(self.git), "git_missing", "git")

    def _run_in(self, args, cwd, stage="git", timeout=90):
        result = self.runner.run(
            [self.git, "-c", "protocol.version=2", *args],
            env=self.environment, timeout=timeout, stage=stage, cwd=str(cwd))
        if result.returncode != 0:
            raise QualificationError(stage + "_failed", stage)
        return result

    def init(self, path):
        Path(path).mkdir(parents=True, exist_ok=True)
        self._run_in(["init", "--initial-branch=main", str(path)], Path(path).parent)

    def commit(self, path, text, message):
        (Path(path) / "data.txt").write_text(text + "\n")
        self._run_in(["-c", "user.name=Synthetic Rotation",
                      "-c", "user.email=rotation@example.invalid",
                      "add", "."], path)
        self._run_in(["-c", "user.name=Synthetic Rotation",
                      "-c", "user.email=rotation@example.invalid",
                      "commit", "-m", message], path)
        return self._run_in(["rev-parse", "HEAD"], path).stdout.decode().strip()

    def push(self, path, url, principal="alice"):
        self._run_in(["-c", "http.extraHeader=X-Pando-Principal: " + principal,
                      "push", url, "HEAD:refs/heads/main"], path, stage="git_push")

    def clone(self, url, destination, principal="alice"):
        if Path(destination).exists():
            raise QualificationError("git_clone_destination_exists", "git_clone")
        self._run_in(["-c", "http.extraHeader=X-Pando-Principal: " + principal,
                      "clone", url, str(destination)], Path(destination).parent,
                     stage="git_clone")
        self.fsck(destination)
        return Path(destination)

    def fsck(self, path):
        self._run_in(["fsck", "--full", "--strict"], path, stage="git_fsck")

    def show(self, path, revision, file_name="data.txt"):
        return self._run_in(["show", revision + ":" + file_name], path,
                            stage="git_show").stdout.decode().strip()

    def subjects(self, path):
        return self._run_in(["log", "--format=%s"], path,
                            stage="git_log").stdout.decode().splitlines()
