#!/usr/bin/env python3
"""Real PostgreSQL WAL archive/PITR with a matched offline GitFS snapshot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from e2e import Harness


def run(args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if check and result.returncode:
        raise AssertionError(f"{args[0]} failed: {result.stderr.decode(errors='replace')[-1000:]}")
    return result.stdout.decode().strip()


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def sql(socket_dir, db_port, query):
    return run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-h", str(socket_dir),
                "-p", str(db_port), "-U", "agent", "-d", "postgres", "-c", query])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(args.binary.resolve())
    root = Path(tempfile.mkdtemp(prefix="rootyard-pg-pitr-"))
    primary, backup, restored = (root / name for name in ("primary", "basebackup", "restored"))
    archive = root / "archive"
    archive.mkdir()
    p_port, r_port = port(), port()
    old_env = os.environ.copy()
    h = None
    primary_running = restored_running = False
    try:
        run(["initdb", "--no-instructions", "--auth=trust", "-U", "agent", "-D", str(primary)])
        (primary / "pg_hba.conf").write_text(
            "local all all trust\nhost all all 127.0.0.1/32 trust\nhost all all ::1/128 trust\n"
            "local replication all trust\nhost replication all 127.0.0.1/32 trust\n")
        with (primary / "postgresql.conf").open("a") as cfg:
            cfg.write(f"\nlisten_addresses='127.0.0.1'\nport={p_port}\n"
                      f"unix_socket_directories='{root}'\nwal_level=replica\n"
                      "max_wal_senders=4\narchive_mode=on\narchive_timeout='1s'\n"
                      f"archive_command='test ! -f {archive}/%f && cp %p {archive}/%f'\n")
        run(["pg_ctl", "-D", str(primary), "-l", str(root / "primary.log"), "start"])
        primary_running = True
        os.environ.update(ROOTYARD_TEST_DATABASE_URL=f"postgresql://agent@localhost:{p_port}/postgres",
                          ROOTYARD_OUTBOX_WORKER="false")
        h = Harness(args)
        h.setup()
        h.api()
        h.roundtrip()
        retained_tip = h.second
        revoked = h.account("create-token", "alice")
        h.cli("revoke-token", revoked["token_id"])
        assert h.http("/api/repos/alice/demo", token=revoked)[0] == 401
        h.stop()
        run(["pg_basebackup", "-h", str(root), "-p", str(p_port), "-U", "agent", "-D",
             str(backup), "-X", "stream", "--checkpoint=fast"])
        point_name = "rootyard_gitfs_snapshot"
        restore_lsn = sql(root, p_port, f"SELECT pg_create_restore_point('{point_name}')")
        snapshot = root / "gitfs_snapshot"
        shutil.copytree(h.root / "data", snapshot, symlinks=True)
        operation_count = int(h.sql("SELECT COUNT(*) FROM git_operations"))
        original_authority = h.sql("SELECT incarnation::text FROM cluster_authority WHERE singleton=true")
        h.start()
        (h.work / "hello.txt").write_text("write after PITR boundary\n")
        h.git("commit", "-am", "later write outside recovery point", cwd=h.work)
        later_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
        assert later_tip in h.git("ls-remote", h.remote, "main", token=h.reader).stdout.decode()
        archived_segment = sql(root, p_port, "SELECT pg_walfile_name(pg_current_wal_lsn())")
        sql(root, p_port, "SELECT pg_switch_wal()")
        until = time.monotonic() + 30
        while time.monotonic() < until and not (archive / archived_segment).exists():
            time.sleep(.1)
        assert (archive / archived_segment).exists(), "acknowledged later write WAL was not archived"
        h.stop(hard=True)
        run(["pg_ctl", "-D", str(primary), "-m", "immediate", "stop"])
        primary_running = False
        shutil.copytree(backup, restored, symlinks=True)
        with (restored / "postgresql.conf").open("a") as cfg:
            cfg.write(f"\nport={r_port}\nrestore_command='cp {archive}/%f %p'\n"
                      f"recovery_target_name='{point_name}'\n"
                      "recovery_target_action='promote'\n")
        (restored / "recovery.signal").touch()
        run(["pg_ctl", "-D", str(restored), "-l", str(root / "restored.log"), "-w", "start"])
        restored_running = True
        assert sql(root, r_port, "SELECT pg_is_in_recovery()") == "f", "PITR did not promote"
        h.base_db = f"postgresql://agent@localhost:{r_port}/postgres"
        h.db = h.db.replace(f":{p_port}/", f":{r_port}/")
        h.env["DATABASE_URL"] = h.db
        assert h.sql("SELECT incarnation::text FROM cluster_authority WHERE singleton=true") == original_authority
        # Rotate before service ingress: a rolled-back nonce ledger must not
        # make an old, still-live delegation valid in the new timeline.
        h.sql("BEGIN; UPDATE cluster_authority SET incarnation=gen_random_uuid(), "
              "rotated_at=clock_timestamp() WHERE singleton=true; "
              "DELETE FROM cluster_transport_nonces; COMMIT;")
        assert h.sql("SELECT incarnation::text FROM cluster_authority WHERE singleton=true") != original_authority
        shutil.rmtree(h.root / "data")
        shutil.copytree(snapshot, h.root / "data", symlinks=True)
        h.start()
        h.git("fetch", h.remote, "refs/heads/main", cwd=h.copy, token=h.reader)
        assert h.git("rev-parse", "FETCH_HEAD", cwd=h.copy).stdout.decode().strip() == retained_tip
        assert h.git("--git-dir=" + str(h.bare), "cat-file", "-e", later_tip + "^{commit}",
                     check=False).returncode != 0, "later Git write leaked across restore boundary"
        assert int(h.sql("SELECT COUNT(*) FROM git_operations")) == operation_count
        h.git("--git-dir=" + str(h.bare), "fsck", "--full", "--strict")
        assert h.http("/api/repos/alice/demo", token=h.reader)[0] == 200
        assert h.http("/api/repos/alice/demo", token=h.bob)[0] in (403, 404)
        assert h.http("/api/repos/alice/demo", token=revoked)[0] == 401
        assert h.git("ls-remote", h.remote, "main", token=h.reader).stdout.decode().startswith(retained_tip)
        h.git("reset", "--hard", retained_tip, cwd=h.work)
        (h.work / "hello.txt").write_text("new write on restored timeline\n")
        h.git("commit", "-am", "write after isolated PITR", cwd=h.work)
        recovery_tip = h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
        h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
        assert h.git("ls-remote", h.remote, "main", token=h.reader).stdout.decode().startswith(recovery_tip)
        report = {
            "kind": "native_postgresql_wal_archive_pitr_and_gitfs_snapshot",
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "pg_basebackup_version": run(["pg_basebackup", "--version"]),
            "postgres_version": sql(root, r_port, "SHOW server_version"),
            "archive_mode": sql(root, r_port, "SHOW archive_mode"),
            "restore_point_lsn": restore_lsn,
            "archived_segment_after_later_ack": archived_segment,
            "archive_segment_count": len(list(archive.iterdir())),
            "retained_acknowledged_oid": retained_tip,
            "later_acknowledged_oid_outside_recovery_point": later_tip,
            "post_restore_acknowledged_oid": recovery_tip,
            "restored_git_operation_rows": operation_count,
            "retained_ref_and_objects_fsck": "passed",
            "reader_access_unrelated_tenant_denial_and_token_revocation": "passed",
            "delegation_authority_rotated_before_reopening": True,
            "later_write_intentionally_lost_at_point_in_time": True,
            "limits": ["single-host local archive and offline matching GitFS snapshot",
                       "manual recovery and traffic restart", "not a remote-retained encrypted backup",
                       "not zero-RPO failover or a supported multi-host PostgreSQL HA deployment"]
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"result": "passed", "report": str(args.report)}))
    finally:
        if h:
            h.cleanup()
        os.environ.clear()
        os.environ.update(old_env)
        if restored_running:
            run(["pg_ctl", "-D", str(restored), "-m", "immediate", "stop"], check=False)
        if primary_running:
            run(["pg_ctl", "-D", str(primary), "-m", "immediate", "stop"], check=False)
        if not args.keep:
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
