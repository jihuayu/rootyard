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
import signal
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
    """One exact-owned Pando HTTP server under the shared absolute deadline."""

    MAX_LINE = 4096
    MAX_ANNOUNCEMENT = MAX_LINE

    def __init__(self, binary, environment, runner=None, budget=None,
                 clock=None, popen=None, killpg=None, select_fn=None,
                 read_fn=None, set_blocking_fn=None):
        self.binary = str(binary)
        self.environment = dict(environment)
        self.runner = runner
        self.budget = budget
        self.clock = clock
        self.process = None
        self.base = None
        self.owned_group = False
        self.pgid = None
        self.stdout_fd = None
        self._popen = popen or subprocess.Popen
        self._killpg = killpg or os.killpg
        self._select = select_fn or select.select
        self._read = read_fn or os.read
        self._set_blocking = set_blocking_fn or os.set_blocking

    def _now(self):
        return self.clock() if self.clock is not None else time.monotonic()

    def _clamp(self, requested, stage):
        if self.budget is None:
            return requested
        return self.budget.clamp(requested, stage)

    def _late(self, stage):
        if self.budget is not None:
            self.budget.late(stage)

    def _late_overall(self, stage):
        if self.budget is not None:
            self.budget.late_overall(stage)

    def _stop_quietly(self):
        """Best-effort stop that never replaces the start failure."""
        try:
            self.stop()
        except Exception:
            pass

    def start(self, timeout=45):
        require(self.process is None, "server_already_started", "server")
        if self.budget is not None and self.budget.in_cleanup:
            raise QualificationError("work_deadline_exceeded", "server")
        if self.budget is not None:
            remaining = self.budget.remaining_work()
            if remaining <= 0:
                self.budget.require("server")
            effective = min(float(timeout), remaining)
            startup_deadline = self.budget.work_deadline
        else:
            effective = float(timeout)
            startup_deadline = None
        try:
            process = self._popen(
                [self.binary, "serve"],
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=False,
                bufsize=0,
                start_new_session=True,
            )
        except OSError:
            raise QualificationError("server_start_failed", "server") from None
        # The parent retains the handle and group ownership immediately after
        # Popen and before any await/read.  The leader is deliberately not
        # polled or reaped here: its PGID is the owned-group fence used by stop.
        self.process = process
        self.owned_group = True
        self.pgid = getattr(process, "pid", None)
        try:
            if (not isinstance(self.pgid, int) or self.pgid <= 0
                    or self.pgid == os.getpid()):
                raise QualificationError("server_group_unverified", "server")
            stream = getattr(process, "stdout", None)
            if stream is None:
                raise QualificationError("server_start_failed", "server")
            try:
                fd = stream.fileno()
            except (OSError, ValueError, AttributeError):
                raise QualificationError("server_start_failed", "server") from None
            if not isinstance(fd, int) or fd < 0:
                raise QualificationError("server_start_failed", "server")
            self.stdout_fd = fd
            try:
                self._set_blocking(fd, False)
            except (OSError, ValueError, TypeError):
                raise QualificationError("server_start_failed", "server") from None
            self._late("server")
            deadline = self._now() + effective
            if startup_deadline is not None:
                deadline = min(deadline, startup_deadline)
            buffer = bytearray()
            while True:
                remaining = deadline - self._now()
                if remaining <= 0:
                    raise QualificationError("server_start_timeout", "server")
                if self.budget is not None:
                    self.budget.require("server")
                ready, _, _ = self._select(
                    [fd], [], [], min(0.2, remaining))
                self._late("server")
                remaining = deadline - self._now()
                if remaining <= 0:
                    raise QualificationError("server_start_timeout", "server")
                if not ready:
                    continue
                capacity = self.MAX_ANNOUNCEMENT - len(buffer)
                if capacity <= 0:
                    raise QualificationError(
                        "server_announcement_invalid", "server")
                try:
                    chunk = self._read(fd, min(capacity, 4096))
                except BlockingIOError:
                    continue
                except (OSError, ValueError, TypeError):
                    raise QualificationError(
                        "server_start_failed", "server") from None
                self._late("server")
                if not isinstance(chunk, (bytes, bytearray)):
                    raise QualificationError(
                        "server_start_failed", "server")
                if len(chunk) == 0:
                    raise QualificationError("server_exited", "server")
                buffer.extend(chunk)
                if len(buffer) > self.MAX_ANNOUNCEMENT:
                    raise QualificationError(
                        "server_announcement_invalid", "server")
                newline = buffer.find(b"\n")
                if newline < 0:
                    continue
                if newline + 1 != len(buffer):
                    raise QualificationError(
                        "server_announcement_invalid", "server")
                try:
                    text = bytes(buffer[:newline]).decode("ascii")
                except UnicodeDecodeError:
                    raise QualificationError(
                        "server_announcement_invalid", "server") from None
                port = self._parse_announcement(text)
                self._late("server")
                self.base = "http://127.0.0.1:" + str(port)
                return self.base
        except QualificationError:
            self._stop_quietly()
            raise
        except Exception:
            self._stop_quietly()
            raise QualificationError("server_start_failed", "server") from None

    def _parse_announcement(self, text):
        """Accept only the exact known LISTEN record, never arbitrary text."""
        if not text.startswith("LISTEN "):
            raise QualificationError("server_announcement_invalid", "server")
        value = text[len("LISTEN "):]
        if (not value or value != value.strip()
                or any(char.isspace() for char in value)):
            raise QualificationError("server_announcement_invalid", "server")
        try:
            parsed = urllib.parse.urlsplit(value)
            port = parsed.port
        except ValueError:
            raise QualificationError(
                "server_announcement_invalid", "server") from None
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                or not port or not 1 <= port <= 65535
                or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment
                or parsed.username is not None or parsed.password is not None):
            raise QualificationError("server_announcement_invalid", "server")
        return port

    def _signal(self, process, sig):
        pgid = getattr(process, "pid", None)
        if (self.owned_group and isinstance(pgid, int)
                and pgid > 0 and pgid != os.getpid()):
            try:
                self._killpg(pgid, sig)
                return
            except ProcessLookupError:
                return
            except (OSError, ValueError, TypeError):
                pass
        try:
            if sig == signal.SIGTERM:
                process.terminate()
            else:
                process.kill()
        except (OSError, ValueError, AttributeError):
            pass

    def _wait(self, process, deadline):
        remaining = deadline - self._now()
        if remaining <= 0:
            return False
        try:
            process.wait(timeout=remaining)
            return True
        except (subprocess.TimeoutExpired, OSError, ValueError, AttributeError):
            return False

    def _close(self, process):
        stream = getattr(process, "stdout", None)
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError, AttributeError):
                pass

    def stop(self, timeout=15):
        if self.process is None:
            return True
        process = self.process
        if process.poll() is not None:
            self._close(process)
            self.process = None
            self.owned_group = False
            return True
        # Stop is only reached from an owned failure or cleanup; it uses the
        # whole absolute deadline, never a fresh per-operation budget.
        self._late_overall("cleanup")
        deadline = self._now() + timeout
        if self.budget is not None:
            deadline = min(deadline, self.budget.overall_deadline)
        if process.poll() is None:
            self._signal(process, signal.SIGTERM)
            if not self._wait(process, deadline):
                self._signal(process, signal.SIGKILL)
                if not self._wait(process, deadline):
                    raise QualificationError("server_stop_timeout", "cleanup")
        if process.poll() is None:
            raise QualificationError("server_stop_timeout", "cleanup")
        self._close(process)
        self.process = None
        self.owned_group = False
        return True

    def url(self, repo):
        require(valid_uuid(repo), "server_repo_invalid", "server")
        require(self.base is not None, "server_not_started", "server")
        return self.base + "/repos/" + repo + ".git"


GIT_ENV_KEEP = (
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR",
)
GIT_ENV_SAFE = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_ALLOW_PROTOCOL": "http",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Synthetic Rotation",
    "GIT_AUTHOR_EMAIL": "rotation@example.invalid",
    "GIT_COMMITTER_NAME": "Synthetic Rotation",
    "GIT_COMMITTER_EMAIL": "rotation@example.invalid",
    "GIT_AUTHOR_DATE": "2026-11-17T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-11-17T00:00:00Z",
    "NO_PROXY": "127.0.0.1,localhost",
    "no_proxy": "127.0.0.1,localhost",
}


def git_client_environment(environment):
    """Return only the narrow stock-Git client environment.

    The Pando CLI/server needs Vault/provider/database credentials; Git does
    not.  Direct stock-Git commands receive only PATH/locale/temp paths plus
    explicit author, config-isolation and transport-safety values.  Provider
    tokens, database DSNs/passwords and admin credentials are never copied.
    """
    source = dict(environment)
    filtered = {name: source[name] for name in GIT_ENV_KEEP if name in source}
    require("PATH" in filtered, "git_environment_path_missing", "git")
    filtered.update(GIT_ENV_SAFE)
    return filtered


class GitWorkspace:
    def __init__(self, environment, runner=None, budget=None):
        self.environment = git_client_environment(environment)
        self.runner = runner or Runner()
        self.budget = budget
        self.git = shutil.which("git", path=self.environment["PATH"])
        require(self.git is not None and os.path.isabs(self.git), "git_missing", "git")

    def _require(self, stage):
        if self.budget is not None:
            self.budget.require(stage)

    def _late(self, stage):
        if self.budget is not None:
            self.budget.late(stage)

    def _run_in(self, args, cwd, stage="git", timeout=90):
        self._require(stage)
        result = self.runner.run(
            [self.git, "-c", "protocol.version=2", *args],
            env=self.environment, timeout=timeout, stage=stage, cwd=str(cwd))
        if result.returncode != 0:
            raise QualificationError(stage + "_failed", stage)
        self._late(stage)
        return result

    def init(self, path):
        self._require("git")
        Path(path).mkdir(parents=True, exist_ok=True)
        self._run_in(["init", "--initial-branch=main", str(path)], Path(path).parent)

    def commit(self, path, text, message):
        self._require("git")
        (Path(path) / "data.txt").write_text(text + "\n")
        self._late("git")
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
