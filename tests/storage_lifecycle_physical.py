#!/usr/bin/env python3
"""Native Git/PostgreSQL physical-GC acceptance; requires an enabled test binary."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import traceback
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parent))
from storage_lifecycle import LifecycleHarness


class PhysicalHarness(LifecycleHarness):
    def __init__(self,args):
        super().__init__(args)
        self.env["ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS"]="2"

    def new_repo(self,name):
        repo=json.loads(self.expect("/api/repos",201,token=self.alice,
            method="POST",body={"name":name}))
        work=self.root/(name+"-work")
        self.git("clone",self.base+repo["clone_path"],str(work),token=self.alice)
        self.git("config","user.name","Alice",cwd=work)
        self.git("config","user.email","alice@rootyard.local",cwd=work)
        (work/"README.md").write_text("retained base\n")
        self.git("add","README.md",cwd=work)
        self.git("commit","-m","base",cwd=work)
        base=self.git("rev-parse","HEAD",cwd=work).stdout.decode().strip()
        self.git("push","origin","HEAD:main",cwd=work,token=self.alice)
        bare=self.root/"data"/"repos"/(repo["id"]+".git")
        return repo,work,bare,base

    def physical_loose_packed_and_pin(self):
        self.setup()
        repo,work,bare,base=self.new_repo("physical")
        self.git("checkout","-b","temporary",cwd=work)
        (work/"obsolete.txt").write_text("unreachable packed commit\n")
        self.git("add","obsolete.txt",cwd=work)
        self.git("commit","-m","temporary",cwd=work)
        packed=self.git("rev-parse","HEAD",cwd=work).stdout.decode().strip()
        self.git("push","origin","HEAD:refs/heads/temporary",cwd=work,token=self.alice)
        self.stop()
        # Seed a genuinely packed unreachable object while the service is
        # offline. The production worker must unpack and remove only due OIDs.
        self.git("--git-dir",str(bare),"repack","-a","-d")
        self.git("--git-dir",str(bare),"update-ref","-d","refs/heads/temporary")
        self.git("--git-dir",str(bare),"reflog","expire","--expire=now","--all")
        assert not (bare/"objects"/packed[:2]/packed[2:]).exists()
        self.git("--git-dir",str(bare),"cat-file","-e",packed)
        loose=self.run(["git","--git-dir",str(bare),"hash-object","-w","--stdin"],
                       data=b"unreachable loose blob\n").stdout.decode().strip()
        tree=self.git("--git-dir",str(bare),"rev-parse","main^{tree}").stdout.decode().strip()
        retained=self.git("-c","user.name=Alice","-c","user.email=alice@rootyard.local",
            "--git-dir",str(bare),"commit-tree",tree,"-p",base,"-m","retained CI source").stdout.decode().strip()
        assert packed in self.git("--git-dir",str(bare),"fsck","--unreachable","--no-progress").stdout.decode()
        self.start()
        pin_job=str(uuid.uuid4())
        self.expect("/api/repos/alice/physical/ci-pins",(200,201),token=self.alice,
            method="POST",body={"job_id":pin_job,"target_oid":retained,"storage_generation":1})
        for oid in (loose,packed):
            self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                          +repo["id"]+"' AND oid='"+oid+"'","deleted",seconds=45)
            assert self.git("--git-dir",str(bare),"cat-file","-e",oid,check=False).returncode!=0
        for oid in (base,retained): self.git("--git-dir",str(bare),"cat-file","-e",oid)
        self.git("fetch","origin",cwd=work,token=self.alice)
        self.git("--git-dir",str(bare),"fsck","--full","--strict")
        return {"loose_deleted":loose,"packed_deleted":packed,
                "reachable_base_preserved":base,"ci_pin_preserved":retained}

    def backup_barrier_blocks_due_delete(self):
        self.stop()
        self.env["ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS"]="5"
        self.start()
        repo,work,bare,base=self.new_repo("barrier")
        orphan=self.run(["git","--git-dir",str(bare),"hash-object","-w","--stdin"],
            data=b"held through backup barrier\n").stdout.decode().strip()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                      +repo["id"]+"' AND oid='"+orphan+"'","pending")
        lock=subprocess.Popen(["psql","--dbname",self.db,"-X","-At","-v","ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            lock.stdin.write("BEGIN; SELECT pg_advisory_xact_lock(738390103); SELECT 'ready';\n")
            lock.stdin.flush()
            until=time.monotonic()+5
            while time.monotonic()<until:
                ready,_,_=select.select([lock.stdout],[],[],max(0,until-time.monotonic()))
                if not ready: break
                line=lock.stdout.readline().strip()
                if line=="ready": break
                if lock.poll() is not None: raise AssertionError("backup barrier session exited")
            else: raise AssertionError("backup barrier was not acquired")
            time.sleep(6)
            assert (bare/"objects"/orphan[:2]/orphan[2:]).is_file(),"GC passed active backup barrier"
            self.git("fetch","origin",cwd=work,token=self.alice)
            self.git("--git-dir",str(bare),"cat-file","-e",base)
        finally:
            lock.stdin.write("COMMIT;\n")
            lock.stdin.flush()
            lock.stdin.close()
            lock.wait(timeout=5)
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                      +repo["id"]+"' AND oid='"+orphan+"'","deleted",seconds=45)
        self.git("--git-dir",str(bare),"fsck","--full","--strict")
        return {"backup_barrier_blocked_delete":True,"fetch_preserved_base":base,
                "orphan_deleted_after_barrier":orphan}

    def active_fetch_snapshot_blocks_gc(self):
        self.stop()
        self.env["ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS"]="5"
        self.start()
        repo,work,bare,base=self.new_repo("reader")
        orphan=self.run(["git","--git-dir",str(bare),"hash-object","-w","--stdin"],
            data=b"unreachable during active native fetch\n").stdout.decode().strip()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                      +repo["id"]+"' AND oid='"+orphan+"'","pending")
        self.stop()
        entered=self.root/"reader-entered"
        release=self.root/"reader-release"
        wrapper=self.root/"slow-read-git"
        wrapper.write_text("#!/bin/sh\ncase \" $* \" in\n  *\" http-backend \"*) "
            +"touch '"+str(entered)+"'; while [ ! -e '"+str(release)
            +"' ]; do sleep .1; done;;\nesac\nexec /usr/bin/git \"$@\"\n")
        wrapper.chmod(0o700)
        self.env["ROOTYARD_GIT"]=str(wrapper)
        self.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            fetch=executor.submit(self.git,"fetch","origin",cwd=work,token=self.alice)
            try:
                until=time.monotonic()+10
                while not entered.exists() and time.monotonic()<until:
                    time.sleep(.05)
                assert entered.exists(),"fetch never entered native Git HTTP child"
                self.sql("UPDATE storage_maintenance_tombstones SET delete_after=clock_timestamp()-interval '1 second' "
                    "WHERE repository_id='"+repo["id"]+"' AND oid='"+orphan+"'")
                self.wait_sql("SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='"
                    +repo["id"]+"' AND kind='gitfs_tombstone_delete' AND state IN ('queued','running')",
                    "1",seconds=15)
                time.sleep(2)
                assert (bare/"objects"/orphan[:2]/orphan[2:]).is_file(),"GC passed active fetch lease"
                assert self.sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                    +repo["id"]+"' AND oid='"+orphan+"'")=="pending"
            finally:
                release.write_text("continue\n")
            fetch.result(timeout=30)
        self.env.pop("ROOTYARD_GIT")
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                      +repo["id"]+"' AND oid='"+orphan+"'","deleted",seconds=45)
        self.git("--git-dir",str(bare),"cat-file","-e",base)
        return {"fetch_held_native_snapshot":True,"due_delete_waited_for_fetch":True,
                "orphan_deleted_after_fetch":orphan}

    def active_push_publication_blocks_gc(self):
        self.stop()
        self.env["ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS"]="5"
        self.start()
        repo,work,bare,_=self.new_repo("writer")
        orphan=self.run(["git","--git-dir",str(bare),"hash-object","-w","--stdin"],
            data=b"unreachable while a push publishes\n").stdout.decode().strip()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
            +repo["id"]+"' AND oid='"+orphan+"'","pending")
        self.git("checkout","-b","incoming",cwd=work)
        (work/"incoming.txt").write_text("published after maintenance waits\n")
        self.git("add","incoming.txt",cwd=work)
        self.git("commit","-m","concurrent incoming ref",cwd=work)
        incoming=self.git("rev-parse","HEAD",cwd=work).stdout.decode().strip()
        self.stop()
        entered=self.root/"push-entered"
        release=self.root/"push-release"
        wrapper=self.root/"slow-push-git"
        wrapper.write_text("#!/bin/sh\ncase \"$REQUEST_METHOD:$PATH_INFO\" in\n"
            +"  POST:*/git-receive-pack) touch '"+str(entered)
            +"'; while [ ! -e '"+str(release)
            +"' ]; do sleep .1; done;;\nesac\nexec /usr/bin/git \"$@\"\n")
        wrapper.chmod(0o700)
        self.env["ROOTYARD_GIT"]=str(wrapper)
        self.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            push=executor.submit(self.git,"push","origin","HEAD:refs/heads/incoming",
                                 cwd=work,token=self.alice)
            try:
                until=time.monotonic()+10
                while not entered.exists() and time.monotonic()<until: time.sleep(.05)
                assert entered.exists(),"push never reached native receive-pack child"
                self.sql("UPDATE storage_maintenance_tombstones SET delete_after=clock_timestamp()-interval '1 second' "
                    "WHERE repository_id='"+repo["id"]+"' AND oid='"+orphan+"'")
                self.sql("INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation) "
                    "VALUES('"+str(uuid.uuid4())+"','"+repo["id"]+"','"+self.alice["user_id"]
                    +"','gitfs_tombstone_delete',1) ON CONFLICT DO NOTHING")
                self.wait_sql("SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='"
                    +repo["id"]+"' AND kind='gitfs_tombstone_delete' AND state IN ('queued','running')",
                    "1",seconds=10)
                time.sleep(2)
                assert (bare/"objects"/orphan[:2]/orphan[2:]).is_file(),"GC passed active push"
                assert self.git("--git-dir",str(bare),"show-ref","--verify",
                    "refs/heads/incoming",check=False).returncode!=0
            finally:
                release.write_text("continue\n")
            push.result(timeout=30)
        self.env.pop("ROOTYARD_GIT")
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
            +repo["id"]+"' AND oid='"+orphan+"'","deleted",seconds=45)
        assert self.git("--git-dir",str(bare),"rev-parse","refs/heads/incoming").stdout.decode().strip()==incoming
        self.git("--git-dir",str(bare),"fsck","--full","--strict")
        return {"native_receive_pack_held_writer":True,"due_delete_waited_for_push":True,
                "incoming_commit_preserved":incoming,"orphan_deleted_after_push":orphan}

    def enospc_pack_rewrite_recovers(self):
        self.stop()
        self.env["ROOTYARD_STORAGE_REPACK_LOOSE_OBJECTS"]="1000000"
        self.env["ROOTYARD_STORAGE_REPACK_PACKS"]="10000"
        self.env["ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS"]="2"
        self.start()
        repo,work,bare,base=self.new_repo("enospc")
        self.git("checkout","-b","temporary",cwd=work)
        (work/"random.bin").write_bytes(os.urandom(256*1024))
        self.git("add","random.bin",cwd=work)
        self.git("commit","-m","packed object",cwd=work)
        packed=self.git("rev-parse","HEAD",cwd=work).stdout.decode().strip()
        self.git("push","origin","HEAD:refs/heads/temporary",cwd=work,token=self.alice)
        self.stop()
        self.git("--git-dir",str(bare),"repack","-a","-d")
        self.git("--git-dir",str(bare),"update-ref","-d","refs/heads/temporary")
        self.git("--git-dir",str(bare),"reflog","expire","--expire=now","--all")
        assert not (bare/"objects"/packed[:2]/packed[2:]).exists()
        shim=self.root/"enospc.so"
        source=self.root/"enospc.c"
        source.write_text(r'''#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
static unsigned long long written;
ssize_t write(int fd,const void *buf,size_t count) {
 static ssize_t (*real_write)(int,const void*,size_t);
 if (!real_write) real_write=dlsym(RTLD_NEXT,"write");
 if (fd!=2 && getenv("ROOTYARD_TEST_FAIL_PACK_WRITE")) {
  if (written>=4096) { errno=ENOSPC; return -1; }
  written+=count;
 }
 return real_write(fd,buf,count);
}
''')
        self.run(["gcc","-shared","-fPIC","-O2","-o",str(shim),str(source),"-ldl"])
        wrapper=self.root/"enospc-git"
        wrapper.write_text("#!/bin/sh\ncase \" $* \" in\n  *\" repack \"*) "
            +"export LD_PRELOAD='"+str(shim)+"' ROOTYARD_TEST_FAIL_PACK_WRITE=1;;\nesac\n"
            +"exec /usr/bin/git \"$@\"\n")
        wrapper.chmod(0o700)
        self.env["ROOTYARD_GIT"]=str(wrapper)
        self.start()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                      +repo["id"]+"' AND oid='"+packed+"'","pending")
        self.wait_sql("SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id='"
            +repo["id"]+"' AND kind='gitfs_tombstone_delete' AND attempt>=1 "
            +"AND last_error IS NOT NULL","1",seconds=30)
        self.git("--git-dir",str(bare),"cat-file","-e",packed)
        self.git("--git-dir",str(bare),"cat-file","-e",base)
        self.stop()
        self.env.pop("ROOTYARD_GIT")
        self.start()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                      +repo["id"]+"' AND oid='"+packed+"'","deleted",seconds=45)
        self.git("--git-dir",str(bare),"cat-file","-e",base)
        self.git("--git-dir",str(bare),"fsck","--full","--strict")
        return {"enospc_failed_without_data_loss":True,"retry_deleted_due_packed_oid":packed,
                "reachable_base_preserved":base}

    def unlink_crash_reconciles_intent(self):
        self.stop()
        self.env["ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS"]="2"
        self.start()
        repo,_,bare,base=self.new_repo("crash-intent")
        self.sql("CREATE FUNCTION gc_pause_deleted() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN IF NEW.state='deleted' AND OLD.state='deleting' THEN "
            "PERFORM pg_sleep(10); END IF; RETURN NEW; END $$; "
            "CREATE TRIGGER gc_pause_deleted BEFORE UPDATE ON storage_maintenance_tombstones "
            "FOR EACH ROW EXECUTE FUNCTION gc_pause_deleted()")
        orphan=self.run(["git","--git-dir",str(bare),"hash-object","-w","--stdin"],
            data=b"crash between unlink and durable result\n").stdout.decode().strip()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
            +repo["id"]+"' AND oid='"+orphan+"'","pending")
        path=bare/"objects"/orphan[:2]/orphan[2:]
        until=time.monotonic()+30
        while time.monotonic()<until:
            state=self.sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                +repo["id"]+"' AND oid='"+orphan+"'")
            if state=="deleting" and not path.exists(): break
            time.sleep(.05)
        else: raise AssertionError("worker never reached committed-intent/unlinked window")
        os.kill(self.proc.pid,signal.SIGKILL)
        self.proc.wait(timeout=5)
        self.proc=None
        self.log.close();self.log=None
        assert self.sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
            +repo["id"]+"' AND oid='"+orphan+"'")=="deleting"
        self.sql("DROP TRIGGER gc_pause_deleted ON storage_maintenance_tombstones; "
                 "DROP FUNCTION gc_pause_deleted()")
        self.start()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
            +repo["id"]+"' AND oid='"+orphan+"'","deleted",seconds=45)
        assert self.sql("SELECT attempts FROM storage_maintenance_tombstones WHERE repository_id='"
            +repo["id"]+"' AND oid='"+orphan+"'")=="1"
        self.git("--git-dir",str(bare),"cat-file","-e",base)
        return {"committed_intent_survived_sigkill":True,"absent_object_reconciled_deleted":orphan,
                "reachable_base_preserved":base}

    def younger_unreachable_history_keeps_old_blob(self):
        self.stop()
        self.env["ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS"]="10"
        self.start()
        repo,_,bare,base=self.new_repo("closure")
        blob=self.run(["git","--git-dir",str(bare),"hash-object","-w","--stdin"],
            data=b"older shared blob\n").stdout.decode().strip()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
            +repo["id"]+"' AND oid='"+blob+"'","pending")
        tree=self.run(["git","--git-dir",str(bare),"mktree"],
            data=("100644 blob "+blob+"\tshared.txt\n").encode()).stdout.decode().strip()
        commit=self.git("-c","user.name=Alice","-c","user.email=alice@rootyard.local",
            "--git-dir",str(bare),"commit-tree",tree,"-m","younger unreachable commit").stdout.decode().strip()
        for oid in (tree,commit):
            self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                +repo["id"]+"' AND oid='"+oid+"'","pending")
        self.sql("UPDATE storage_maintenance_tombstones SET delete_after=clock_timestamp()-interval '1 second' "
            "WHERE repository_id='"+repo["id"]+"' AND oid='"+blob+"'")
        self.wait_sql("SELECT count(*)>0 FROM storage_maintenance_jobs WHERE repository_id='"
            +repo["id"]+"' AND kind='gitfs_tombstone_delete' AND state='succeeded' "
            +"AND result->>'retained'='unexpired unreachable object closure'","t",seconds=15)
        for oid in (blob,tree,commit): self.git("--git-dir",str(bare),"cat-file","-e",oid)
        self.sql("UPDATE storage_maintenance_tombstones SET delete_after=clock_timestamp()-interval '1 second' "
            "WHERE repository_id='"+repo["id"]+"' AND oid IN ('"+tree+"','"+commit+"')")
        for oid in (blob,tree,commit):
            self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
                +repo["id"]+"' AND oid='"+oid+"'","deleted",seconds=45)
        self.git("--git-dir",str(bare),"cat-file","-e",base)
        self.git("--git-dir",str(bare),"fsck","--full","--strict")
        return {"younger_commit_preserved_old_blob_until_due":True,
                "closure_deleted_after_all_graces":True,"retained_base":base}

    def namespace_source_oid_survives_branch_deletion(self):
        self.env["ROOTYARD_STORAGE_TOMBSTONE_GRACE_SECONDS"]="2"
        if not self.schema_created: self.setup()
        else:
            self.stop()
            self.start()
        repo,work,bare,_=self.new_repo("namespace-root")
        self.git("checkout","-b","historical",cwd=work)
        (work/"pkg").mkdir()
        (work/"pkg"/"file.txt").write_text("durable namespace source\n")
        self.git("add","pkg/file.txt",cwd=work)
        self.git("commit","-m","historical namespace source",cwd=work)
        historical=self.git("rev-parse","HEAD",cwd=work).stdout.decode().strip()
        self.git("push","origin","HEAD:refs/heads/historical",cwd=work,token=self.alice)
        ns=json.loads(self.expect("/api/namespaces",201,token=self.alice,method="POST",
            body={"name":"gc-retention","mounts":[{"path":"project","owner":"alice",
                "repository":"namespace-root","base_oid":historical}]}))
        first=json.loads(self.expect(f"/api/namespaces/{ns['id']}/views",201,
            token=self.alice,method="POST",body={"mount_path":"project","subdir":"pkg"}))
        assert first["source_oid"]==historical
        self.git("push","origin",":refs/heads/historical",cwd=work,token=self.alice)
        self.stop()
        self.git("--git-dir",str(bare),"reflog","expire","--expire=now","--all")
        assert historical in self.git("--git-dir",str(bare),"fsck","--unreachable",
            "--no-progress").stdout.decode()
        self.start()
        self.wait_sql("SELECT state FROM storage_maintenance_tombstones WHERE repository_id='"
            +repo["id"]+"' AND oid='"+historical+"'","pending")
        self.sql("UPDATE storage_maintenance_tombstones SET delete_after=clock_timestamp()-interval '1 second' "
            "WHERE repository_id='"+repo["id"]+"' AND oid='"+historical+"'")
        self.wait_sql("SELECT count(*)>0 FROM storage_maintenance_jobs WHERE repository_id='"
            +repo["id"]+"' AND kind='gitfs_tombstone_delete' AND state='succeeded' "
            +"AND result->>'retained'='active external roots'","t",seconds=20)
        self.git("--git-dir",str(bare),"cat-file","-e",historical)
        second=json.loads(self.expect(f"/api/namespaces/{ns['id']}/views",201,
            token=self.alice,method="POST",body={"mount_path":"project","subdir":"pkg"}))
        assert second["source_oid"]==historical and second["id"]!=first["id"]
        self.git("--git-dir",str(bare),"fsck","--full","--strict")
        return {"deleted_branch_source_retained":historical,
                "future_namespace_view_created":second["id"]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",required=True)
    parser.add_argument("--report",type=Path)
    parser.add_argument("--keep",action="store_true")
    parser.add_argument("--case",help="run one named case")
    args=parser.parse_args();args.binary=str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required")
    h=PhysicalHarness(args);passed=False
    try:
        cases=[
            ("physical_loose_packed_and_pin",h.physical_loose_packed_and_pin),
            ("backup_barrier_blocks_due_delete",h.backup_barrier_blocks_due_delete),
            ("active_fetch_snapshot_blocks_gc",h.active_fetch_snapshot_blocks_gc),
            ("active_push_publication_blocks_gc",h.active_push_publication_blocks_gc),
            ("enospc_pack_rewrite_recovers",h.enospc_pack_rewrite_recovers),
            ("unlink_crash_reconciles_intent",h.unlink_crash_reconciles_intent),
            ("younger_unreachable_history_keeps_old_blob",h.younger_unreachable_history_keeps_old_blob),
            ("namespace_source_oid_survives_branch_deletion",h.namespace_source_oid_survives_branch_deletion),
        ]
        if args.case and args.case not in dict(cases):
            parser.error(f"unknown case: {args.case}")
        if args.case and args.case not in ("physical_loose_packed_and_pin",
                                          "namespace_source_oid_survives_branch_deletion"):
            h.setup()
        for name,case in cases:
            if not args.case or args.case==name: h.case(name,case)
        passed=True
    except Exception:
        print(h.redact(traceback.format_exc()),file=sys.stderr)
    finally:h.cleanup()
    report={"passed":passed,"cases":h.results,
        "binary_sha256":hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
    if args.report:args.report.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    return 0 if passed else 1


if __name__=="__main__":sys.exit(main())
