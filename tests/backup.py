#!/usr/bin/env python3
"""Offline backup drill using fresh disposable databases and storage directories.

Requires CREATEDB on ROOTYARD_TEST_DATABASE_URL, which MUST be a synthetic test
server. Creates/drops only random databases owned by this run. Never use production.
Optional ROOTYARD_RESTORE_TEST_DATABASE_URL selects a separate test PG server.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
import uuid
from e2e import Harness


class BackupHarness(Harness):
    def __init__(self, args):
        super().__init__(args)
        self.admin = self.base_db
        self.restore_admin = os.environ.get("ROOTYARD_RESTORE_TEST_DATABASE_URL", self.admin)
        self.created = []
        self.source_db = self.new_database(self.admin)
        self.target_db = self.new_database(self.restore_admin)
        self.db = self.source_db
        self.env["DATABASE_URL"] = self.db
        self.backup = self.root / "backup"
        self.target = self.root / "restored-data"

    def query(self, db, sql):
        env = self.env.copy()
        parts = urllib.parse.urlsplit(db)
        env.update(PGHOST=parts.hostname or "", PGPORT=str(parts.port or 5432), PGDATABASE=parts.path.lstrip("/"), PGUSER=parts.username or "", PGPASSWORD=parts.password or "")
        return self.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql], env=env).stdout.decode().strip()

    def new_database(self, admin):
        name = "rootyard_backup_" + uuid.uuid4().hex
        self.query(admin, 'CREATE DATABASE "' + name + '" TEMPLATE template0')
        self.created.append((admin, name))
        return urllib.parse.urlunsplit(urllib.parse.urlsplit(admin)._replace(path="/" + name, query=""))

    def backup_command(self, path=None, check=True):
        return self.run([self.args.binary, "backup", str(path or self.backup), "--offline"], check=check)

    def restore_command(self, source=None, target=None, db=None, check=True):
        env = self.env.copy()
        env.update(DATABASE_URL=db or self.target_db, ROOTYARD_DATA_DIR=str(target or self.target))
        return self.run([self.args.binary, "restore", str(source or self.backup), "--isolated", "--trust-backup"], env=env, check=check)

    def setup(self):
        self.cli("migrate")
        self.alice = self.account("create-user", "alice")
        self.bob = self.account("create-user", "bob")
        self.reader = self.account("create-token", "alice", "--read-only")
        self.revoked = self.account("create-token", "alice")
        self.start()
        self.api()
        self.roundtrip()
        self.unknown_repo = json.loads(self.expect("/api/repos", 201, token=self.alice, method="POST", body={"name":"unknown"}))
        self.before_refs = self.git("ls-remote", self.remote, token=self.alice).stdout
        # There is a real active server and it owns the volume lock.
        assert self.backup_command(check=False).returncode != 0
        assert not self.backup.exists()
        self.stop()
        # SQL unknown + unfinished retained journal are separate, both preserved.
        actor = self.query(self.db, "SELECT id FROM users WHERE username='alice'")
        op = dict(id=str(uuid.uuid4()), repository_id=self.unknown_repo["id"], actor_id=actor,
                  actor_name="alice", token_id=self.alice["token_id"], sequence=1, storage_generation=1)
        self.query(self.db, "UPDATE repositories SET state='recovering',recovery_reason='git_outcome_unknown' WHERE id='" + op["repository_id"] + "'")
        self.query(self.db, "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome) VALUES ('" + op["id"] + "','" + op["repository_id"] + "','" + actor + "','" + op["token_id"] + "','alice',1,1,'{}','unknown')")
        journal = Path(self.env["ROOTYARD_DATA_DIR"]) / "journal" / op["repository_id"]
        journal.mkdir(mode=0o700, parents=True)
        (journal / "sequence").write_text("1")
        operation = journal / ("00000000000000000001-" + op["id"])
        operation.mkdir(mode=0o700)
        (operation / "operation.json").write_text(json.dumps(op))
        self.journal = operation.relative_to(Path(self.env["ROOTYARD_DATA_DIR"]))
        return {"fresh_databases":2,"live_server_backup_rejected":True,"unknown_and_unfinished_journal":True}

    def lock_and_snapshot(self):
        lock = open(Path(self.env["ROOTYARD_DATA_DIR"]) / ".rootyard.lock", "r+")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert self.backup_command(check=False).returncode != 0
        lock.close()
        # A metadata write begins BEFORE the backup's table barrier. Holding the
        # UPDATE uncommitted catches snapshots established too early.
        env = self.env.copy(); parts=urllib.parse.urlsplit(self.db)
        env.update(PGHOST=parts.hostname,PGPORT=str(parts.port),PGDATABASE=parts.path.lstrip("/"),PGUSER=parts.username,PGPASSWORD=parts.password or "")
        writer = subprocess.Popen(["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        writer.stdin.write(("BEGIN; UPDATE tokens SET revoked=true WHERE id='" + self.revoked["token_id"] + "';\n\\echo LOCKED\n").encode()); writer.stdin.flush()
        assert writer.stdout.readline().strip() == b"LOCKED"
        backup = subprocess.Popen([self.args.binary, "backup", str(self.backup), "--offline"], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                blocked = self.query(self.db, "SELECT count(*) FROM pg_stat_activity WHERE application_name='rootyard-backup' AND wait_event_type='Lock'")
                if int(blocked): break
                assert backup.poll() is None
                time.sleep(.05)
            else: raise AssertionError("Backup did not wait on metadata writer")
            writer.stdin.write(b"COMMIT;\n\\q\n"); writer.stdin.flush()
            assert writer.wait(timeout=10) == 0
            stdout, stderr = backup.communicate(timeout=60)
            assert backup.returncode == 0, stderr.decode()
            self.backup_result = json.loads(stdout)
        finally:
            for proc in (writer, backup):
                if proc.poll() is None: proc.kill(); proc.wait()
        manifest = json.loads((self.backup / "manifest.json").read_text())
        assert sum(r["unknown_operations"] for r in manifest["repositories"]) == 1
        assert (self.backup / "volume" / self.journal / "operation.json").exists()
        assert not any(secret in (self.backup / "manifest.json").read_text() for secret in self.secrets + [self.db])
        self.cli("backup-verify", str(self.backup))
        return {"snapshot_includes_commit_after_barrier_wait":True,"inherited_volume_lock_rejected":True,
                "backup_seconds":self.backup_result["elapsed_seconds"]}

    def invalid_inputs(self):
        def damage(name, action):
            path = self.root / name
            shutil.copytree(self.backup, path, symlinks=True)
            action(path)
            assert self.run([self.args.binary,"backup-verify",str(path)],check=False).returncode != 0
            assert self.restore_command(source=path, check=False).returncode != 0
            assert not self.target.exists()
            assert self.query(self.target_db,"SELECT count(*) FROM pg_tables WHERE schemaname='public'") == "0"
            shutil.rmtree(path)
        damage("tampered", lambda p: (p / "volume" / self.journal / "operation.json").write_text("corrupt"))
        damage("truncated", lambda p: (p / "metadata.dump").write_bytes(b"PGDMP"))
        damage("extra", lambda p: (p / "volume" / "unlisted").write_text("extra"))
        damage("missing", lambda p: (p / "volume" / self.journal / "operation.json").unlink())
        def link(p):
            (p / "volume" / "escape").symlink_to("/etc/passwd")
        damage("symlink", link)
        def root_link(p):
            shutil.rmtree(p / "volume")
            (p / "volume").symlink_to(self.backup / "volume", target_is_directory=True)
        damage("volume-root-symlink", root_link)
        def marker_fifo(p):
            (p / "COMPLETE").unlink();os.mkfifo(p / "COMPLETE")
        damage("completion-fifo", marker_fifo)
        damage("oversized-marker", lambda p: (p / "COMPLETE").write_text("0" * 4096))
        def traversal(p):
            m=json.loads((p/"manifest.json").read_text());m["files"]["../escape"]={"kind":"file","mode":384,"bytes":0,"sha256":"0"*64,"target":None}
            (p/"manifest.json").write_text(json.dumps(m));(p/"COMPLETE").write_text(hashlib.sha256((p/"manifest.json").read_bytes()).hexdigest())
        damage("traversal", traversal)
        existing = self.root / "existing";existing.mkdir();(existing / "sentinel").write_text("keep")
        assert self.restore_command(target=existing,check=False).returncode != 0
        assert (existing / "sentinel").read_text() == "keep"
        assert self.restore_command(db=self.source_db,check=False).returncode != 0
        assert not self.target.exists()
        assert self.backup_command(Path(self.env["ROOTYARD_DATA_DIR"]) / "nested",check=False).returncode != 0
        # Backup refuses external Git object dependencies, even if fsck could use them.
        alternates = self.bare / "objects" / "info" / "alternates"
        alternates.write_text(str(self.bare / "objects") + "\n")
        try: assert self.backup_command(self.root / "alternates",check=False).returncode != 0
        finally: alternates.unlink()
        common = self.bare / "commondir"
        common.write_text(str(self.bare) + "\n")
        try: assert self.backup_command(self.root / "linked-worktree",check=False).returncode != 0
        finally: common.unlink()
        for create, drop in [("CREATE SCHEMA pgxevil", "DROP SCHEMA pgxevil"),
                             ("CREATE DOMAIN public.extra AS int[]", "DROP DOMAIN public.extra"),
                             ("CREATE TYPE public.extra AS (x int)", "DROP TYPE public.extra"),
                             ("CREATE FUNCTION public.extra() RETURNS int LANGUAGE SQL AS 'SELECT 1'", "DROP FUNCTION public.extra()")]:
            for database in (self.source_db, self.target_db):
                self.query(database,create)
                try:
                    if database == self.source_db: assert self.backup_command(self.root / "extra-schema",check=False).returncode != 0
                    else: assert self.restore_command(check=False).returncode != 0
                finally: self.query(database,drop)
        return {"corrupt_missing_extra_traversal_symlink_rejected_before_sql":True,
                "existing_targets_and_overlap_refused":True,"external_object_dependencies_refused":True}

    def backup_barrier_failures(self):
        destination=self.root/"database-connection-lost"
        backup=subprocess.Popen([self.args.binary,"backup",str(destination),"--offline"],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+20
            while True:
                pids=self.query(self.source_db,"SELECT pid FROM pg_stat_activity WHERE application_name='rootyard-backup' AND state='idle in transaction' AND query LIKE 'SELECT r.id,r.storage_generation%'")
                if pids:
                    assert self.query(self.source_db,"SELECT pg_terminate_backend("+str(int(pids.splitlines()[0]))+")")=="t"
                    break
                assert backup.poll() is None and time.monotonic()<deadline
                time.sleep(.01)
            backup.communicate(timeout=30)
            assert backup.returncode!=0 and not destination.exists()
        finally:
            if backup.poll() is None:backup.kill();backup.wait()
        # A DDL waiter can queue between our SHARE lock and pg_dump's ACCESS
        # SHARE request. The dump must time out and release, never self-deadlock.
        parts=urllib.parse.urlsplit(self.source_db);env=self.env.copy()
        env.update(PGHOST=parts.hostname,PGPORT=str(parts.port),PGDATABASE=parts.path.lstrip("/"),PGUSER=parts.username,PGPASSWORD=parts.password or "")
        writer=subprocess.Popen(["psql","-X","-qAt","-v","ON_ERROR_STOP=1"],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        ddl=None;backup=None
        try:
            writer.stdin.write(b"BEGIN; UPDATE public.tokens SET revoked=revoked;\n\\echo LOCKED\n");writer.stdin.flush()
            assert writer.stdout.readline().strip()==b"LOCKED"
            destination=self.root/"queued-ddl"
            backup=subprocess.Popen([self.args.binary,"backup",str(destination),"--offline"],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            deadline=time.monotonic()+10
            while not int(self.query(self.source_db,"SELECT count(*) FROM pg_stat_activity WHERE application_name='rootyard-backup' AND wait_event_type='Lock'")):
                assert backup.poll() is None and time.monotonic()<deadline;time.sleep(.02)
            ddl_env=env.copy();ddl_env["PGAPPNAME"]="backup-ddl-test"
            ddl=subprocess.Popen(["psql","-X","-qAt","-v","ON_ERROR_STOP=1","-c","ALTER TABLE public.audit_events ADD COLUMN backup_test integer"],env=ddl_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            deadline=time.monotonic()+10
            while not int(self.query(self.source_db,"SELECT count(*) FROM pg_stat_activity WHERE application_name='backup-ddl-test' AND wait_event_type='Lock'")):
                assert ddl.poll() is None and time.monotonic()<deadline;time.sleep(.02)
            writer.stdin.write(b"COMMIT;\n\\q\n");writer.stdin.flush();assert writer.wait(timeout=5)==0
            backup.communicate(timeout=30);assert backup.returncode!=0 and not destination.exists()
            assert ddl.wait(timeout=10)==0
            self.query(self.source_db,"ALTER TABLE public.audit_events DROP COLUMN backup_test")
            return {"exporter_connection_loss_no_publication":True,"queued_ddl_bounded_safe_failure":True}
        finally:
            for proc in (writer,ddl,backup):
                if proc and proc.poll() is None:proc.kill();proc.wait()

    def interrupted_restore(self):
        database = self.new_database(self.restore_admin)
        target = self.root / "interrupted-target"
        guard = target.parent / ("." + target.name + ".rootyard-restoring")
        env = self.env.copy();env.update(DATABASE_URL=database,ROOTYARD_DATA_DIR=str(target))
        restore = subprocess.Popen([self.args.binary,"restore",str(self.backup),"--isolated","--trust-backup"],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        blocker = None
        try:
            deadline=time.monotonic()+20
            while not guard.exists():
                assert restore.poll() is None, "Restore exited before guard"
                assert time.monotonic()<deadline
                time.sleep(.01)
            parts=urllib.parse.urlsplit(database);pg_env=env.copy()
            pg_env.update(PGHOST=parts.hostname,PGPORT=str(parts.port),PGDATABASE=parts.path.lstrip("/"),PGUSER=parts.username,PGPASSWORD=parts.password or "")
            blocker=subprocess.Popen(["psql","-X","-qAt","-v","ON_ERROR_STOP=1"],env=pg_env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            blocker.stdin.write(b"BEGIN; LOCK TABLE pg_catalog.pg_class IN SHARE MODE;\n\\echo LOCKED\n");blocker.stdin.flush()
            assert blocker.stdout.readline().strip()==b"LOCKED"
            deadline=time.monotonic()+30
            while True:
                count=self.query(database,"SELECT count(*) FROM pg_stat_activity WHERE application_name='pg_restore' AND wait_event_type='Lock'")
                if int(count):break
                assert restore.poll() is None, "Restore did not reach blocked native pg_restore"
                assert time.monotonic()<deadline
                time.sleep(.02)
            os.kill(restore.pid,signal.SIGKILL);restore.wait(timeout=5)
            deadline=time.monotonic()+10
            while int(self.query(database,"SELECT count(*) FROM pg_stat_activity WHERE application_name='pg_restore'")):
                assert time.monotonic()<deadline,"Orphan pg_restore backend survived parent death"
                time.sleep(.05)
            blocker.stdin.write(b"ROLLBACK;\n\\q\n");blocker.stdin.flush();assert blocker.wait(timeout=5)==0
            assert self.query(database,"SELECT count(*) FROM pg_tables WHERE schemaname='public'")=="0"
            assert guard.exists() and not target.exists()
            failed=self.run([self.args.binary,"serve"],env=env,check=False)
            assert failed.returncode!=0 and b"incomplete restore guard" in failed.stderr
            assert not target.exists()
            return {"killed_parent_while_native_pg_restore_blocked":True,"no_orphan_import_or_partial_sql":True,"persistent_guard_blocks_startup":True}
        finally:
            for proc in (restore,blocker):
                if proc and proc.poll() is None:proc.kill();proc.wait()

    def write_after_backup(self):
        self.start()
        (self.work / "after-backup.txt").write_text("acknowledged after the offline boundary\n")
        self.git("add","after-backup.txt",cwd=self.work)
        self.git("commit","-m","after backup boundary",cwd=self.work)
        self.git("push","origin","HEAD:main",cwd=self.work,token=self.alice)
        self.post_backup_oid=self.git("rev-parse","HEAD",cwd=self.work).stdout.decode().strip()
        self.last_ack_time=time.time()
        self.stop()
        return {"post_backup_acknowledged_commit":True,"seconds_after_backup_boundary":round(self.last_ack_time-self.backup_result["boundary_unix_seconds"],3)}

    def restore_and_clone(self):
        result = json.loads(self.restore_command().stdout)
        assert self.query(self.target_db,"SELECT revoked FROM tokens WHERE id='" + self.revoked["token_id"] + "'") == "t"
        assert self.query(self.target_db,"SELECT count(*) FROM git_operations WHERE outcome='unknown'") == "1"
        assert (self.target / self.journal / "operation.json").read_bytes() == (self.backup / "volume" / self.journal / "operation.json").read_bytes()
        self.env.update(DATABASE_URL=self.target_db,ROOTYARD_DATA_DIR=str(self.target));self.db=self.target_db
        self.start()
        assert self.git("ls-remote",self.remote,token=self.alice).stdout == self.before_refs
        clone = self.root / "restored-clone"
        self.git("clone",self.remote,str(clone),token=self.reader)
        self.git("fsck","--full","--strict",cwd=clone)
        assert (clone / "hello.txt").read_text() == "second\n"
        assert not (clone / "after-backup.txt").exists()
        assert self.git("cat-file","-e",self.post_backup_oid,cwd=clone,check=False).returncode != 0
        assert self.git("rev-parse","HEAD",cwd=clone).stdout.decode().strip() == self.second
        self.expect("/api/repos",401,token=self.revoked)
        self.expect(self.repo["clone_path"]+"/info/refs?service=git-receive-pack",403,token=self.reader)
        unknown=json.loads(self.expect("/api/repos/alice/unknown",200,token=self.alice))
        assert unknown["state"] == "recovering"
        self.expect(self.unknown_repo["clone_path"]+"/info/refs?service=git-upload-pack",503,token=self.alice)
        self.stop()
        return {"fresh_database_and_directory":True,"separate_pg_server":self.admin!=self.restore_admin,
                "standard_authenticated_clone_fsck_refs_content":True,"revoked_and_read_only_auth_preserved":True,
                "unknown_stays_blocked":True,"restore_seconds":result["elapsed_seconds"],
                "backup_boundary_commits_missing":0,"post_backup_acknowledged_commits_not_recovered":1,
                "observed_backup_age_at_last_ack_seconds":round(self.last_ack_time-self.backup_result["boundary_unix_seconds"],3),
                "production_rpo_rto_guarantee":False}

    def cleanup(self):
        self.stop()
        for admin,name in self.created:
            self.query(admin,'DROP DATABASE "' + name + '" WITH (FORCE)')
        if not self.args.keep: shutil.rmtree(self.root)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",default="target/debug/rootyard")
    parser.add_argument("--report",type=Path)
    parser.add_argument("--keep",action="store_true")
    args=parser.parse_args();args.binary=str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"): parser.error("dedicated synthetic ROOTYARD_TEST_DATABASE_URL required")
    h=BackupHarness(args);success=False
    try:
        for name,fn in [("synthetic_source",h.setup),("offline_barriers_and_snapshot",h.lock_and_snapshot),("unsafe_or_corrupt_inputs",h.invalid_inputs),("backup_barrier_failures",h.backup_barrier_failures),("interrupted_restore_guard",h.interrupted_restore),("post_backup_write_not_in_snapshot",h.write_after_backup),("new_environment_restore_clone_fsck",h.restore_and_clone)]:h.case(name,fn)
        success=True
    except Exception as e: print(h.redact(e),file=sys.stderr)
    finally:
        try:h.cleanup()
        except Exception as e:print(h.redact(e),file=sys.stderr);success=False
        report=dict(passed=success,cases=h.results,limitations=["Synthetic loopback drill, no host/disk power-loss or production RPO/RTO promise.","Unknown evidence preserved, not automatically resolved."])
        if args.keep:report["retained_directory"]=str(h.root)
        if args.report:args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report,indent=2))
    return 0 if success else 1

if __name__=="__main__":sys.exit(main())
