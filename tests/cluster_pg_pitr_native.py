#!/usr/bin/env python3
"""Real PostgreSQL WAL archive/PITR with a matched offline GitFS snapshot."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from e2e import Harness
import ops_provenance


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
        outbox_before = int(h.sql("SELECT COUNT(*) FROM outbox_events"))
        pending_before = int(h.sql("SELECT COUNT(*) FROM event_deliveries WHERE state <> 'delivered'"))
        assert outbox_before > 0 and pending_before > 0, "fixture produced no durable worker backlog"
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
        h.stop()
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
        # pg_ctl -w can return while the server is briefly accepting read-only
        # connections just before recovery_target_action=promote completes.
        # Poll the actual recovery state instead of racing that transition.
        promoted = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if sql(root, r_port, "SELECT pg_is_in_recovery()") == "f":
                    promoted = True
                    break
            except AssertionError:
                pass
            time.sleep(.05)
        assert promoted, "PITR did not promote within 20s"
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
        restored_data = h.root / "restored-deployment-data"
        shutil.copytree(snapshot, restored_data, symlinks=True)
        h.env["ROOTYARD_DATA_DIR"] = str(restored_data)
        h.bare = restored_data / "repos" / (h.repo["id"] + ".git")
        restored_port = port()
        h.env["ROOTYARD_BIND"] = "127.0.0.1:" + str(restored_port)
        h.base = "http://" + h.env["ROOTYARD_BIND"]
        h.remote = h.base + h.repo["clone_path"]
        h.git("remote", "set-url", "origin", h.remote, cwd=h.work)
        h.git("remote", "set-url", "origin", h.remote, cwd=h.copy)
        h.env["ROOTYARD_OUTBOX_WORKER"] = "false"
        # The delivery worker only needs PostgreSQL. Run it against the
        # restored authority before reopening Git ingress and prove that the
        # retained durable backlog advances without resurrecting the later
        # post-boundary event.
        worker_count = 0
        pending_after = pending_before
        for _ in range(10):
            processed = int(h.cli("worker-once"))
            worker_count += processed
            pending_after = int(h.sql("SELECT COUNT(*) FROM event_deliveries WHERE state <> 'delivered'"))
            if pending_after == 0 or processed == 0:
                break
        outbox_after = int(h.sql("SELECT COUNT(*) FROM outbox_events"))
        pending_states = h.sql("SELECT consumer || ':' || state || ':' || COUNT(*) FROM event_deliveries "
                               "WHERE state <> 'delivered' GROUP BY consumer, state ORDER BY consumer, state")
        assert worker_count > 0 and pending_after == 0, (
            f"restored worker did not drain retained deliveries: count={worker_count} "
            f"pending={pending_after} {pending_states}")
        assert outbox_after == outbox_before, "post-boundary outbox event survived PITR"
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
        report = ops_provenance.base(
            args.binary, __file__,
            topology="new Rootyard data volume and new loopback endpoint against a PITR-restored PostgreSQL 17 cluster; source archive/base backup on one host",
            dataset="one private repository with two acknowledged commits before the restore point and one acknowledged commit afterwards",
            workload="native Git push/fetch/browse, token revocation, permission denial, PostgreSQL WAL archive/base backup/PITR, offline matching GitFS snapshot, and delivery-worker drain before reopening ingress",
            limits=["single-host local unencrypted archive and offline matching GitFS snapshot",
                    "manual recovery, new endpoint/volume and traffic restart",
                    "not a remote-retained encrypted backup",
                    "not zero-RPO failover or a supported multi-host PostgreSQL HA deployment"])
        report.update({
            "kind": "native_postgresql_wal_archive_pitr_and_gitfs_snapshot",
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
            "restored_deployment": {"data_volume": "new directory copied from the matched offline GitFS snapshot",
                                   "endpoint": "new loopback port",
                                   "metadata": "PITR-restored PostgreSQL cluster"},
            "worker_restore": {"worker_once_processed": worker_count,
                               "outbox_events_before_boundary": outbox_before,
                               "outbox_events_after_restore": outbox_after,
                               "pending_deliveries_before_boundary": pending_before,
                               "pending_deliveries_after_worker": pending_after},
            "retained_ref_and_objects_fsck": "passed",
            "reader_access_unrelated_tenant_denial_and_token_revocation": "passed",
            "delegation_authority_rotated_before_reopening": True,
            "later_write_intentionally_lost_at_point_in_time": True})
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
