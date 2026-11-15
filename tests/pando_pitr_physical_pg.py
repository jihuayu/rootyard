#!/usr/bin/env python3
"""Owned physical PostgreSQL 17 base-backup/WAL restore fixture for #77.

This is a test fixture, not production code.  It creates one fresh private
scratch tree, one loopback-only primary PostgreSQL 17 cluster with an owned WAL
archive, and an isolated physical restore of that base backup at a named restore
point.  The caller remains responsible for Rootyard migrations, seeding, service
advancement and any external proof.  The opt-in self-check invoked by this file
uses only plain marker SQL; it never claims Pando, service, GC, provider or
production qualification.

Every command, wait and cleanup phase is bounded.  Subprocess output is kept in
memory and never included in an error or report.  The fixture never reuses,
stops or changes permissions on a pre-existing cluster or data directory.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

PG_MAJOR = 17
DB_USER = "rootyard_pitr"
DB_NAME_PREFIX = "rootyard_pitr_"
RESTORE_POINT_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
LSN_RE = re.compile(r"^[0-9A-F]+/[0-9A-F]+$")
WAL_SEGMENT_RE = re.compile(r"^[0-9A-F]{24}$")
PG_VERSION_RE = re.compile(r"PostgreSQL\)\s*(\d+)(?:\.|$)")
COMMAND_TIMEOUT_SECONDS = 120.0
START_TIMEOUT_SECONDS = 60.0
RESTORE_WAIT_SECONDS = 60.0
ARCHIVE_WAIT_SECONDS = 60.0
CLEANUP_TIMEOUT_SECONDS = 30.0
POLL_SECONDS = 0.1
TOPOLOGY = (
    "one owned ephemeral PostgreSQL 17 primary and one isolated physical "
    "base-backup/WAL restore of it on loopback; no Rootyard, Pando, GC, "
    "external bucket or production service is involved"
)
LIMITATIONS = [
    "Fixture self-check only; not #77 service, Pando, GC, external-provider or production qualification.",
    "Single host, temporary private scratch, local trust and loopback TCP; no HA, failover, cloud or hardware evidence.",
    "No Rootyard binary, migration, Pando SQL, receipt, grant or fence is created or modified.",
]


class FixtureError(RuntimeError):
    """A fixed, credential-free fixture failure."""

    def __init__(self, phase: str, code: str) -> None:
        super().__init__(f"{phase}: {code}")
        self.phase = phase
        self.code = code


@dataclass(frozen=True)
class PgTools:
    initdb: Path
    pg_ctl: Path
    psql: Path
    pg_basebackup: Path


def _run(argv: list[Path | str], *, phase: str, timeout: float = COMMAND_TIMEOUT_SECONDS):
    """Run one bounded argv without a shell; never expose captured output."""
    argv = [str(item) for item in argv]
    try:
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise FixtureError(phase, "timeout") from None
    except OSError:
        raise FixtureError(phase, "exec_failed") from None
    if result.returncode != 0:
        raise FixtureError(phase, "command_failed")
    return result


def _validate_pg17_tools(pg_bin_dir: Path) -> PgTools:
    """Validate four explicit same-directory PostgreSQL 17 executables."""
    base = Path(pg_bin_dir)
    if not base.is_absolute():
        raise FixtureError("tools", "absolute_path_required")
    try:
        base = base.resolve(strict=True)
    except OSError:
        raise FixtureError("tools", "directory_missing") from None
    if not base.is_dir():
        raise FixtureError("tools", "directory_missing")
    tools = {}
    for name in ("initdb", "pg_ctl", "psql", "pg_basebackup"):
        path = base / name
        try:
            if not path.is_file() or not os.access(path, os.X_OK):
                raise FixtureError("tools", "binary_missing")
        except OSError:
            raise FixtureError("tools", "binary_missing") from None
        result = _run([path, "--version"], phase="tools", timeout=15.0)
        text = result.stdout.decode("utf-8", "replace")
        match = PG_VERSION_RE.search(text)
        if match is None:
            raise FixtureError("tools", "version_unrecognized")
        if int(match.group(1)) != PG_MAJOR:
            raise FixtureError("tools", "pg_major_mismatch")
        tools[name] = path.resolve()
    return PgTools(**tools)


def _free_loopback_port(*, exclude: set[int] | None = None) -> int:
    exclude = exclude or set()
    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port >= 1024 and port not in exclude:
            return port
    raise FixtureError("start", "port_unavailable")


def _conf_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _process_identity(pid: int, phase: str) -> dict:
    """Return (pid, kernel start time, state) for one owned PID.

    A replay of the same numeric PID after restart is rejected by the start-time
    comparison.  Linux ``/proc`` is required because a weaker check is not
    sufficient to stop a process safely.
    """
    if not isinstance(pid, int) or pid <= 1:
        raise FixtureError(phase, "pid_invalid")
    try:
        owner = Path(f"/proc/{pid}").stat().st_uid
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except FileNotFoundError:
        raise FixtureError(phase, "process_missing") from None
    except OSError:
        raise FixtureError(phase, "proc_unavailable") from None
    if owner != os.getuid():
        raise FixtureError(phase, "process_unowned")
    tail = raw.rpartition(")")[2].split()
    if len(tail) <= 19:
        raise FixtureError(phase, "proc_invalid")
    try:
        starttime = int(tail[19])
    except ValueError:
        raise FixtureError(phase, "proc_invalid") from None
    return {"pid": pid, "starttime": starttime, "state": tail[0]}


def _pid_alive(pid: int, reference: dict, phase: str) -> bool:
    try:
        current = _process_identity(pid, phase)
    except FixtureError as error:
        if error.code in ("process_missing", "process_unowned"):
            return False
        raise
    return current["starttime"] == reference["starttime"] and current["state"] != "Z"


class PhysicalPitrFixture:
    """Fresh private PostgreSQL primary plus isolated physical restore."""

    def __init__(
        self,
        pg_bin_dir: Path,
        *,
        scratch_parent: Path | None = None,
        tools: PgTools | None = None,
    ) -> None:
        self.tools = _validate_pg17_tools(pg_bin_dir) if tools is None else tools
        parent = Path(scratch_parent) if scratch_parent is not None else Path(tempfile.gettempdir())
        try:
            parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            parent = parent.resolve(strict=True)
        except OSError:
            raise FixtureError("scratch", "parent_unavailable") from None
        self.scratch_parent = parent
        try:
            root = Path(tempfile.mkdtemp(prefix="rootyard-pando-physical-pitr-", dir=str(parent)))
        except OSError:
            raise FixtureError("scratch", "create_failed") from None
        try:
            root.chmod(0o700)
            self.root = root.resolve()
            self.primary_data = self.root / "primary"
            self.base_backup_dir = self.root / "basebackup"
            self.restored_data = self.root / "restored"
            self.archive = self.root / "archive"
            self.socket_dir = self.root / "sockets"
            self.primary_log = self.root / "primary.log"
            self.restored_log = self.root / "restored.log"
            self.primary_port = _free_loopback_port()
            self.restored_port = _free_loopback_port(exclude={self.primary_port})
            self.database = DB_NAME_PREFIX + uuid.uuid4().hex[:10]
            self.primary_identity: dict | None = None
            self.restored_identity: dict | None = None
            self.restore_point_name: str | None = None
            self.restore_point_lsn: str | None = None
            self.archive_segment: str | None = None
            self.archive_count: int = 0
            self.base_backup_ready = False
            self.restored_ready = False
            for directory in (self.archive, self.socket_dir):
                directory.mkdir(mode=0o700)
                self._assert_owned(directory, self.root, "scratch", "scratch_unowned", kind="dir")
        except FixtureError:
            shutil.rmtree(root, ignore_errors=True)
            raise
        except Exception:
            shutil.rmtree(root, ignore_errors=True)
            raise FixtureError("scratch", "create_failed") from None

    def __enter__(self) -> "PhysicalPitrFixture":
        return self

    def __exit__(self, exc_type, _exc, _traceback) -> bool:
        cleanup = self.cleanup()
        if exc_type is None and not cleanup.get("passed"):
            raise FixtureError("cleanup", "cleanup_failed")
        return False

    @property
    def primary_url(self) -> str:
        return f"postgresql://{DB_USER}@127.0.0.1:{self.primary_port}/{self.database}"

    @property
    def restored_url(self) -> str:
        return f"postgresql://{DB_USER}@127.0.0.1:{self.restored_port}/{self.database}"

    def _assert_owned(self, path: Path, parent: Path, phase: str, code: str, *, kind: str) -> os.stat_result:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(parent.resolve())
        except (OSError, ValueError):
            raise FixtureError(phase, code) from None
        if path.is_symlink():
            raise FixtureError(phase, code)
        info = path.lstat()
        if info.st_uid != os.getuid():
            raise FixtureError(phase, code)
        if kind == "dir" and not stat.S_ISDIR(info.st_mode):
            raise FixtureError(phase, code)
        if kind == "file" and not stat.S_ISREG(info.st_mode):
            raise FixtureError(phase, code)
        return info

    def _read_owned_text(self, path: Path, phase: str, code: str) -> str:
        self._assert_owned(path, self.root, phase, code, kind="file")
        try:
            if path.stat().st_size > 64 * 1024:
                raise FixtureError(phase, code)
            raw = path.read_bytes()
        except OSError:
            raise FixtureError(phase, code) from None
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError:
            raise FixtureError(phase, code) from None

    def _read_postmaster_pid(self, data_dir: Path, expected_port: int, phase: str) -> int:
        pid_file = data_dir / "postmaster.pid"
        text = self._read_owned_text(pid_file, phase, "postmaster_pid_invalid")
        lines = text.splitlines()
        if len(lines) < 4:
            raise FixtureError(phase, "postmaster_pid_invalid")
        try:
            pid = int(lines[0])
            recorded_dir = Path(lines[1]).resolve()
            port = int(lines[3])
        except (OSError, ValueError):
            raise FixtureError(phase, "postmaster_pid_invalid") from None
        if pid <= 1 or recorded_dir != data_dir.resolve() or port != expected_port:
            raise FixtureError(phase, "postmaster_pid_invalid")
        return pid

    def _append_owned(self, path: Path, text: str, phase: str, code: str) -> None:
        self._assert_owned(path, self.root, phase, code, kind="file")
        try:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(text)
        except OSError:
            raise FixtureError(phase, code) from None

    def _write_primary_config(self) -> None:
        hba = self.primary_data / "pg_hba.conf"
        self._assert_owned(hba, self.root, "start", "primary_config_unowned", kind="file")
        hba.write_text(
            "# owned fixture: local trust and loopback only\n"
            "local all all trust\n"
            "host all all 127.0.0.1/32 trust\n"
            "host all all ::1/128 trust\n"
            "local replication all trust\n"
            "host replication all 127.0.0.1/32 trust\n"
            "host replication all ::1/128 trust\n",
            encoding="utf-8",
        )
        archive_command = (
            f"test ! -f {shlex.quote(str(self.archive))}/%f && "
            f"cp \"%p\" {shlex.quote(str(self.archive))}/%f"
        )
        self._append_owned(
            self.primary_data / "postgresql.conf",
            "\n"
            "listen_addresses='127.0.0.1'\n"
            f"port={self.primary_port}\n"
            f"unix_socket_directories={_conf_string(str(self.socket_dir))}\n"
            "wal_level=replica\n"
            "max_wal_senders=4\n"
            "archive_mode=on\n"
            "archive_timeout='1s'\n"
            f"archive_command={_conf_string(archive_command)}\n",
            "start",
            "primary_config_unowned",
        )

    def _start_pg(self, data_dir: Path, log_path: Path, phase: str) -> None:
        _run(
            [
                self.tools.pg_ctl,
                "-D",
                data_dir,
                "-l",
                log_path,
                "-w",
                "-t",
                str(int(START_TIMEOUT_SECONDS)),
                "start",
            ],
            phase=phase,
            timeout=START_TIMEOUT_SECONDS + 10.0,
        )

    def _sql(self, query: str, *, phase: str, port: int, database: str | None = None) -> str:
        result = _run(
            [
                self.tools.psql,
                "-X",
                "-A",
                "-t",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                self.socket_dir,
                "-p",
                str(port),
                "-U",
                DB_USER,
                "-d",
                database or self.database,
                "-c",
                query,
            ],
            phase=phase,
        )
        try:
            return result.stdout.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise FixtureError(phase, "sql_output_invalid") from None

    def start_primary(self) -> dict:
        if self.primary_identity is not None:
            raise FixtureError("start", "already_started")
        _run(
            [
                self.tools.initdb,
                "--no-instructions",
                "--auth=trust",
                "-U",
                DB_USER,
                "-D",
                self.primary_data,
            ],
            phase="initdb",
        )
        self._assert_owned(self.primary_data, self.root, "initdb", "primary_data_unowned", kind="dir")
        self._write_primary_config()
        self._start_pg(self.primary_data, self.primary_log, "start")
        pid = self._read_postmaster_pid(self.primary_data, self.primary_port, "start")
        self.primary_identity = _process_identity(pid, "start")
        version_num = self._sql(
            "SHOW server_version_num",
            phase="start",
            port=self.primary_port,
            database="postgres",
        )
        try:
            server_major = int(version_num) // 10000
        except ValueError:
            raise FixtureError("start", "server_version_invalid") from None
        if server_major != PG_MAJOR:
            raise FixtureError("start", "server_major_mismatch")
        self._sql(f'CREATE DATABASE "{self.database}"', phase="start", port=self.primary_port, database="postgres")
        return {
            "primary_started": True,
            "database_allocated": True,
            "archive_mode": "on",
            "loopback_only": True,
        }

    def capture_base_backup(self) -> dict:
        if self.primary_identity is None:
            raise FixtureError("basebackup", "primary_not_started")
        if self.base_backup_ready or self.base_backup_dir.exists():
            raise FixtureError("basebackup", "already_captured")
        _run(
            [
                self.tools.pg_basebackup,
                "-h",
                "127.0.0.1",
                "-p",
                str(self.primary_port),
                "-U",
                DB_USER,
                "-D",
                self.base_backup_dir,
                "-X",
                "stream",
                "--checkpoint=fast",
            ],
            phase="basebackup",
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
        self._assert_owned(self.base_backup_dir, self.root, "basebackup", "basebackup_unowned", kind="dir")
        self.base_backup_ready = True
        return {"base_backup_captured": True}

    def create_restore_point(self, name: str) -> str:
        if not self.base_backup_ready:
            raise FixtureError("restorepoint", "base_backup_missing")
        if self.restore_point_name is not None:
            raise FixtureError("restorepoint", "already_captured")
        if RESTORE_POINT_RE.fullmatch(name) is None:
            raise FixtureError("restorepoint", "name_invalid")
        lsn = self._sql(
            f"SELECT pg_create_restore_point('{name}')",
            phase="restorepoint",
            port=self.primary_port,
        )
        if LSN_RE.fullmatch(lsn) is None:
            raise FixtureError("restorepoint", "lsn_invalid")
        self.restore_point_name = name
        self.restore_point_lsn = lsn
        return lsn

    def capture_base_backup_and_restore_point(self, name: str) -> str:
        """Capture a physical base backup, then the named restore point."""
        self.capture_base_backup()
        return self.create_restore_point(name)

    def force_wal_archive(self) -> dict:
        if self.primary_identity is None:
            raise FixtureError("archive", "primary_not_started")
        segment = self._sql(
            "SELECT pg_walfile_name(pg_current_wal_lsn())",
            phase="archive",
            port=self.primary_port,
        )
        if WAL_SEGMENT_RE.fullmatch(segment) is None:
            raise FixtureError("archive", "segment_invalid")
        self._sql("SELECT pg_switch_wal()", phase="archive", port=self.primary_port)
        target = self.archive / segment
        deadline = time.monotonic() + ARCHIVE_WAIT_SECONDS
        while time.monotonic() < deadline:
            if target.is_file():
                self._assert_owned(target, self.root, "archive", "archive_unowned", kind="file")
                break
            time.sleep(POLL_SECONDS)
        else:
            raise FixtureError("archive", "archive_timeout")
        try:
            count = sum(1 for item in self.archive.iterdir() if item.is_file() and not item.is_symlink())
        except OSError:
            raise FixtureError("archive", "archive_unreadable") from None
        if count < 1:
            raise FixtureError("archive", "archive_missing")
        self.archive_segment = segment
        self.archive_count = count
        return {"archive_segment": segment, "archive_count": count}

    def _prepare_recovery(self, restore_point: str) -> None:
        self._assert_owned(self.restored_data, self.root, "restore", "restore_data_unowned", kind="dir")
        config = self.restored_data / "postgresql.conf"
        restore_command = f"cp {shlex.quote(str(self.archive))}/%f \"%p\""
        self._append_owned(
            config,
            "\n"
            "archive_mode=off\n"
            f"port={self.restored_port}\n"
            "listen_addresses='127.0.0.1'\n"
            f"unix_socket_directories={_conf_string(str(self.socket_dir))}\n"
            f"restore_command={_conf_string(restore_command)}\n"
            f"recovery_target_name={_conf_string(restore_point)}\n"
            "recovery_target_action='promote'\n",
            "restore",
            "restore_config_unowned",
        )
        signal_file = self.restored_data / "recovery.signal"
        if signal_file.exists() or signal_file.is_symlink():
            raise FixtureError("restore", "recovery_signal_present")
        try:
            signal_file.touch(mode=0o600, exist_ok=False)
        except OSError:
            raise FixtureError("restore", "recovery_signal_failed") from None
        self._assert_owned(signal_file, self.root, "restore", "recovery_signal_unowned", kind="file")

    def restore_to_point(self) -> dict:
        if not self.base_backup_ready:
            raise FixtureError("restore", "base_backup_missing")
        if self.restore_point_name is None or self.restore_point_lsn is None:
            raise FixtureError("restore", "restore_point_missing")
        if self.archive_count < 1:
            raise FixtureError("restore", "archive_missing")
        if self.restored_identity is not None or self.restored_data.exists():
            raise FixtureError("restore", "already_restored")
        try:
            shutil.copytree(self.base_backup_dir, self.restored_data, symlinks=True)
        except OSError:
            raise FixtureError("restore", "copy_failed") from None
        self._prepare_recovery(self.restore_point_name)
        self._start_pg(self.restored_data, self.restored_log, "restore")
        pid = self._read_postmaster_pid(self.restored_data, self.restored_port, "restore")
        self.restored_identity = _process_identity(pid, "restore")
        deadline = time.monotonic() + RESTORE_WAIT_SECONDS
        while time.monotonic() < deadline:
            try:
                state = self._sql(
                    "SELECT pg_is_in_recovery()",
                    phase="restore_wait",
                    port=self.restored_port,
                    database="postgres",
                )
            except FixtureError as error:
                if error.code not in ("command_failed", "timeout"):
                    raise
                state = None
            if state == "f":
                self.restored_ready = True
                return {"restored": True, "promoted": True, "new_endpoint": True}
            time.sleep(POLL_SECONDS)
        raise FixtureError("restore", "promotion_timeout")

    def _marker_counts(self, port: int, phase: str) -> tuple[int, int]:
        before = int(self._sql(
            "SELECT count(*) FROM pitr_selfcheck_marker WHERE marker='before'",
            phase=phase,
            port=port,
        ))
        after = int(self._sql(
            "SELECT count(*) FROM pitr_selfcheck_marker WHERE marker='after'",
            phase=phase,
            port=port,
        ))
        return before, after

    def _timeline(self, port: int) -> int:
        value = self._sql(
            "SELECT timeline_id FROM pg_control_checkpoint()",
            phase="metadata",
            port=port,
            database="postgres",
        )
        try:
            return int(value)
        except ValueError:
            raise FixtureError("metadata", "timeline_invalid") from None

    def self_check(self) -> dict:
        self.start_primary()
        self._sql(
            "CREATE TABLE pitr_selfcheck_marker (marker text NOT NULL)",
            phase="marker",
            port=self.primary_port,
        )
        self._sql(
            "INSERT INTO pitr_selfcheck_marker VALUES ('before')",
            phase="marker",
            port=self.primary_port,
        )
        self.capture_base_backup_and_restore_point("rootyard_selfcheck")
        self._sql(
            "INSERT INTO pitr_selfcheck_marker VALUES ('after')",
            phase="marker",
            port=self.primary_port,
        )
        archive = self.force_wal_archive()
        primary_counts = self._marker_counts(self.primary_port, "verify")
        self.restore_to_point()
        restored_counts = self._marker_counts(self.restored_port, "verify")
        primary_recovery = self._sql(
            "SELECT pg_is_in_recovery()",
            phase="verify",
            port=self.primary_port,
            database="postgres",
        )
        restored_recovery = self._sql(
            "SELECT pg_is_in_recovery()",
            phase="verify",
            port=self.restored_port,
            database="postgres",
        )
        if primary_counts != (1, 1):
            raise FixtureError("verify", "primary_marker_changed")
        if restored_counts != (1, 0):
            raise FixtureError("verify", "restored_marker_mismatch")
        if primary_recovery != "f" or restored_recovery != "f":
            raise FixtureError("verify", "recovery_state_invalid")
        if self.primary_port == self.restored_port:
            raise FixtureError("verify", "endpoint_not_new")
        self._sql(
            "CHECKPOINT",
            phase="verify",
            port=self.restored_port,
            database="postgres",
        )
        primary_timeline = self._timeline(self.primary_port)
        restored_timeline = self._timeline(self.restored_port)
        if restored_timeline <= primary_timeline:
            raise FixtureError("verify", "timeline_not_advanced")
        version = self._sql(
            "SHOW server_version",
            phase="metadata",
            port=self.restored_port,
            database="postgres",
        )
        return {
            "postgres_version": version,
            "primary_timeline": primary_timeline,
            "restored_timeline": restored_timeline,
            "restore_point_lsn": self.restore_point_lsn,
            "archive_count": archive["archive_count"],
            "marker_counts": {
                "primary_before": primary_counts[0],
                "primary_after": primary_counts[1],
                "restored_before": restored_counts[0],
                "restored_after": restored_counts[1],
            },
            "primary_live_after_restore": primary_recovery == "f",
            "restored_promoted": restored_recovery == "f",
            "new_endpoint": self.primary_port != self.restored_port,
        }

    def _stop_cluster(self, data_dir: Path, identity: dict | None, port: int, phase: str) -> bool:
        if not data_dir.exists() and not data_dir.is_symlink():
            return True
        self._assert_owned(data_dir, self.root, phase, "cleanup_containment", kind="dir")
        pid_file = data_dir / "postmaster.pid"
        reference = identity
        pid: int | None = None
        if pid_file.exists() or pid_file.is_symlink():
            pid = self._read_postmaster_pid(data_dir, port, phase)
            try:
                observed = _process_identity(pid, phase)
            except FixtureError as error:
                if error.code == "process_missing":
                    return True
                raise
            if reference is not None and (
                observed["pid"] != reference["pid"] or observed["starttime"] != reference["starttime"]
            ):
                raise FixtureError(phase, "pid_identity_mismatch")
            reference = reference or observed
        elif reference is not None:
            if _pid_alive(reference["pid"], reference, phase):
                pid = reference["pid"]
            else:
                return True
        if pid is None:
            return True
        try:
            _run(
                [
                    self.tools.pg_ctl,
                    "-D",
                    data_dir,
                    "-m",
                    "immediate",
                    "-w",
                    "-t",
                    str(int(CLEANUP_TIMEOUT_SECONDS)),
                    "stop",
                ],
                phase=phase,
                timeout=CLEANUP_TIMEOUT_SECONDS + 5.0,
            )
        except FixtureError:
            pass
        if not _pid_alive(pid, reference, phase):
            return True
        if reference is None:
            raise FixtureError(phase, "pid_identity_unavailable")
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True
        except OSError:
            raise FixtureError(phase, "kill_failed") from None
        deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if not _pid_alive(pid, reference, phase):
                return True
            time.sleep(POLL_SECONDS)
        raise FixtureError(phase, "stop_timeout")

    def _remove_root(self, phase: str) -> bool:
        if not self.root.exists() and not self.root.is_symlink():
            return True
        self._assert_owned(self.root, self.scratch_parent, phase, "cleanup_containment", kind="dir")
        try:
            shutil.rmtree(self.root)
        except OSError:
            raise FixtureError(phase, "scratch_remove_failed") from None
        return not self.root.exists()

    def cleanup(self) -> dict:
        status = {
            "attempted": True,
            "primary_stopped": None,
            "restored_stopped": None,
            "scratch_removed": False,
            "errors": [],
        }
        for name, data_dir, identity, port in (
            ("restored", self.restored_data, self.restored_identity, self.restored_port),
            ("primary", self.primary_data, self.primary_identity, self.primary_port),
        ):
            try:
                stopped = self._stop_cluster(data_dir, identity, port, "cleanup")
            except FixtureError as error:
                stopped = False
                status["errors"].append(f"{name}:{error.code}")
            except Exception as error:
                stopped = False
                status["errors"].append(f"{name}:{type(error).__name__}")
            status[f"{name}_stopped"] = stopped
        if status["primary_stopped"] and status["restored_stopped"]:
            try:
                status["scratch_removed"] = self._remove_root("cleanup")
            except FixtureError as error:
                status["errors"].append(f"scratch:{error.code}")
            except Exception as error:
                status["errors"].append(f"scratch:{type(error).__name__}")
        status["passed"] = bool(
            status["primary_stopped"]
            and status["restored_stopped"]
            and status["scratch_removed"]
            and not status["errors"]
        )
        return status


def run_self_check(pg_bin_dir: Path, scratch_parent: Path | None = None) -> dict:
    """Run the opt-in plain-SQL self-check and always attempt owned cleanup."""
    report = {
        "kind": "rootyard/pando-physical-pitr-fixture-selfcheck",
        "passed": False,
        "topology": TOPOLOGY,
        "limitations": list(LIMITATIONS),
    }
    fixture = None
    workflow_ok = False
    try:
        fixture = PhysicalPitrFixture(pg_bin_dir, scratch_parent=scratch_parent)
        report.update(fixture.self_check())
        workflow_ok = True
    except FixtureError as error:
        report["failure"] = {
            "phase": error.phase,
            "code": error.code,
            "exception_class": error.__class__.__name__,
        }
    except Exception as error:
        report["failure"] = {
            "phase": "internal",
            "code": "unexpected",
            "exception_class": type(error).__name__,
        }
    finally:
        if fixture is not None:
            try:
                cleanup = fixture.cleanup()
            except Exception as error:
                cleanup = {
                    "attempted": True,
                    "primary_stopped": False,
                    "restored_stopped": False,
                    "scratch_removed": False,
                    "errors": [f"cleanup:{type(error).__name__}"],
                    "passed": False,
                }
            report["cleanup"] = cleanup
        else:
            cleanup = {
                "attempted": False,
                "primary_stopped": None,
                "restored_stopped": None,
                "scratch_removed": None,
                "errors": [],
                "passed": False,
            }
            report["cleanup"] = cleanup
        report["passed"] = bool(workflow_ok and cleanup.get("passed"))
        if not report["passed"] and "failure" not in report:
            report["failure"] = {
                "phase": "cleanup",
                "code": "cleanup_failed",
                "exception_class": None,
            }
    return report


def _write_report(path: Path, report: dict) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true", help="run the opt-in fixture self-check")
    parser.add_argument("--pg-bin", type=Path, required=True, help="explicit PostgreSQL 17 bin directory")
    parser.add_argument("--scratch-parent", type=Path, help="optional existing private scratch parent")
    parser.add_argument("--report", type=Path, required=True, help="credential-free JSON report")
    args = parser.parse_args(argv)
    if not args.self_check:
        parser.error("--self-check is required; this entrypoint never runs implicitly")
    report = run_self_check(args.pg_bin, args.scratch_parent)
    try:
        _write_report(args.report, report)
    except OSError:
        print("physical PITR fixture: report write failed", file=sys.stderr)
        return 1
    summary = {
        "kind": report["kind"],
        "passed": report["passed"],
        "failure": report.get("failure"),
        "cleanup": report.get("cleanup"),
        "marker_counts": report.get("marker_counts"),
        "archive_count": report.get("archive_count"),
        "restore_point_lsn": report.get("restore_point_lsn"),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
