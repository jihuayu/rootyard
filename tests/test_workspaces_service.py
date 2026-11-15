"""Native HTTP/PostgreSQL workspace lifecycle and revision fencing regression."""
import argparse
import base64
import json
import time
import unittest

from tests.e2e import Harness
from tests.runtime_binary import select_runtime_binary


class WorkspaceServiceTest(unittest.TestCase):
    def test_conflicted_native_index_round_trips_through_checkpoint(self):
        binary, _ = select_runtime_binary()
        h = Harness(argparse.Namespace(binary=str(binary), keep=False))
        try:
            h.setup(); h.api(); h.roundtrip()
            ws=json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                body={"owner":"alice","repository":"demo","agent_id":"conflict","base_oid":h.second},
                extra_headers={"Idempotency-Key":"conflict-create"}))
            repo=h.root/"data/workspace-service/workspaces"/ws["id"]
            h.git("config","user.name","Conflict actor",cwd=repo)
            h.git("config","user.email","actor@example.invalid",cwd=repo)
            h.git("switch","-c","feature",cwd=repo)
            (repo/"hello.txt").write_text("feature\n")
            (repo/"build.c").write_text("int main(void){return 0;}\n")
            h.git("add","hello.txt","build.c",cwd=repo)
            h.git("commit","-m","feature change",cwd=repo)
            h.git("switch","-c","main-conflict",h.second,cwd=repo)
            (repo/"hello.txt").write_text("main\n")
            h.git("commit","-am","main change",cwd=repo)
            self.assertNotEqual(h.git("merge","--no-edit","feature",cwd=repo,check=False).returncode,0)
            stages=h.git("ls-files","-u",cwd=repo).stdout
            status=h.git("status","--porcelain=v1","-z",cwd=repo).stdout
            diff=h.git("diff","--binary",cwd=repo).stdout
            self.assertEqual(len(stages.splitlines()),3)
            self.assertIn(b"UU hello.txt",status)
            self.assertTrue((repo/"build.c").is_file())
            deadline=time.monotonic()+8
            while True:
                current=json.loads(h.expect(f"/api/workspaces/{ws['id']}",200,token=h.alice))
                if current["revision"]>0:break
                self.assertLess(time.monotonic(),deadline,"native Git conflict was not captured")
                time.sleep(.1)
            cp=json.loads(h.expect(f"/api/workspaces/{ws['id']}/checkpoints",201,
                token=h.alice,method="POST",body={"expected_workspace_revision":current["revision"],
                    "lease_epoch":ws["lease_epoch"]},
                extra_headers={"Idempotency-Key":"conflict-checkpoint"}))
            h.stop(hard=True);h.start()
            restored=json.loads(h.expect(f"/api/checkpoints/{cp['checkpoint_id']}/restore",201,
                token=h.alice,method="POST",body={"agent_id":"conflict-restored"},
                extra_headers={"Idempotency-Key":"conflict-restore"}))
            copy=h.root/"data/workspace-service/workspaces"/restored["id"]
            self.assertEqual(h.git("ls-files","-u",cwd=copy).stdout,stages)
            self.assertEqual(h.git("status","--porcelain=v1","-z",cwd=copy).stdout,status)
            self.assertEqual(h.git("diff","--binary",cwd=copy).stdout,diff)
            self.assertEqual((copy/"hello.txt").read_bytes(),(repo/"hello.txt").read_bytes())
            h.run(["gcc","build.c","-o","build"],cwd=copy)
            h.run([str(copy/"build")],cwd=copy)
        finally:h.cleanup()

    def test_create_edit_checkpoint_fork_restore_restart(self):
        binary, _ = select_runtime_binary()
        h = Harness(argparse.Namespace(binary=str(binary), keep=False))
        try:
            h.setup()
            h.api()
            h.roundtrip()
            create = {"owner":"alice","repository":"demo","agent_id":"agent-one","base_oid":h.second}
            key = {"Idempotency-Key":"create-1"}
            status, raw, _ = h.http("/api/workspaces",token=h.alice,method="POST",body=create,extra_headers=key)
            self.assertEqual(status,201,raw)
            ws = json.loads(raw)
            wid = ws["id"]
            self.assertEqual(json.loads(h.expect("/api/workspaces",200,token=h.alice,method="POST",body=create,extra_headers=key))["id"],wid)
            self.assertEqual(h.http(f"/api/workspaces/{wid}",token=h.bob)[0],404)
            put = {"content_base64":base64.b64encode(b"v1\n").decode(),"expected_entry_version":0,
                   "expected_workspace_revision":0,"lease_epoch":ws["lease_epoch"]}
            path = f"/api/workspaces/{wid}/files?path=hello.txt"
            self.assertEqual(h.http(path,token=h.bob,method="PUT",body=put,extra_headers={"Idempotency-Key":"put-1"})[0],404)
            first = json.loads(h.expect(path,200,token=h.alice,method="PUT",body=put,extra_headers={"Idempotency-Key":"put-1"}))
            self.assertEqual(first["entry_version"],1)
            self.assertEqual(h.http(path,token=h.alice,method="PUT",body=put,extra_headers={"Idempotency-Key":"put-2"})[0],409)
            self.assertEqual(json.loads(h.expect(path,200,token=h.alice,method="PUT",body=put,extra_headers={"Idempotency-Key":"put-1"})),first)
            self.assertEqual(base64.b64decode(json.loads(h.expect(path,200,token=h.alice))["content_base64"]),b"v1\n")
            staged = json.loads(h.expect(f"/api/workspaces/{wid}/git",200,token=h.alice,method="POST",
                body={"action":"add","paths":["hello.txt"],"expected_git_generation":0,
                      "expected_workspace_revision":1,"lease_epoch":1},extra_headers={"Idempotency-Key":"git-add-1"}))
            self.assertEqual(staged["git_generation"],1)
            put2 = {"content_base64":base64.b64encode(b"v2 unstaged\n").decode(),"expected_entry_version":1,
                    "expected_workspace_revision":2,"lease_epoch":1}
            h.expect(path,200,token=h.alice,method="PUT",body=put2,extra_headers={"Idempotency-Key":"put-3"})
            checkpoint = json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,method="POST",
                body={"expected_workspace_revision":3,"lease_epoch":1},extra_headers={"Idempotency-Key":"checkpoint-1"}))
            cid = checkpoint["checkpoint_id"]
            self.assertEqual(checkpoint["state"],"local_complete")
            h.stop(hard=True)
            h.start()
            fork = json.loads(h.expect(f"/api/workspaces/{wid}/fork",201,token=h.alice,method="POST",
                body={"checkpoint_id":cid,"new_agent_id":"agent-two"},
                extra_headers={"Idempotency-Key":"fork-one"}))
            fork_replay=json.loads(h.expect(f"/api/workspaces/{wid}/fork",200,token=h.alice,method="POST",
                body={"checkpoint_id":cid,"new_agent_id":"agent-two"},
                extra_headers={"Idempotency-Key":"fork-one"}))
            self.assertEqual(fork_replay["id"],fork["id"])
            self.assertEqual(h.http(f"/api/workspaces/{wid}/fork",token=h.alice,method="POST",
                body={"checkpoint_id":cid,"new_agent_id":"different"},
                extra_headers={"Idempotency-Key":"fork-one"})[0],409)
            fork_path=f"/api/workspaces/{fork['id']}/files?path=hello.txt"
            self.assertEqual(base64.b64decode(json.loads(h.expect(fork_path,200,token=h.alice))["content_base64"]),b"v2 unstaged\n")
            self.assertEqual(base64.b64decode(json.loads(h.expect(fork_path+"&view=index",200,token=h.alice))["content_base64"]),b"v1\n")
            self.assertEqual(base64.b64decode(json.loads(h.expect(fork_path+"&view=head",200,token=h.alice))["content_base64"]),b"second\n")
            changed = {"content_base64":base64.b64encode(b"fork-only\n").decode(),"expected_entry_version":0,
                       "expected_workspace_revision":0,"lease_epoch":fork["lease_epoch"]}
            h.expect(fork_path,200,token=h.alice,method="PUT",body=changed,extra_headers={"Idempotency-Key":"fork-put"})
            self.assertEqual(base64.b64decode(json.loads(h.expect(path,200,token=h.alice))["content_base64"]),b"v2 unstaged\n")
            restored = json.loads(h.expect(f"/api/checkpoints/{cid}/restore",201,token=h.alice,method="POST",
                body={"agent_id":"restored"},extra_headers={"Idempotency-Key":"restore-one"}))
            self.assertEqual(json.loads(h.expect(f"/api/checkpoints/{cid}/restore",200,token=h.alice,method="POST",
                body={"agent_id":"restored"},extra_headers={"Idempotency-Key":"restore-one"}))["id"],restored["id"])
            self.assertNotEqual(restored["id"],wid)
            self.assertEqual(base64.b64decode(json.loads(h.expect(f"/api/workspaces/{restored['id']}/files?path=hello.txt",200,token=h.alice))["content_base64"]),b"v2 unstaged\n")
            events = json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0",200,token=h.alice))
            self.assertEqual([e["revision"] for e in events["events"]],[1,2,3,4])
            live_repo = h.root / "data/workspace-service/workspaces" / wid
            (live_repo / "hello.txt").write_bytes(b"normal editor save\n")
            deadline = time.monotonic()+8
            while time.monotonic()<deadline:
                replay = json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=4",200,token=h.alice))
                if replay["events"]: break
                time.sleep(.2)
            self.assertEqual(replay["events"][0]["kind"],"external_capture")
            self.assertEqual(replay["events"][0]["revision"],5)
            lease=json.loads(h.expect(f"/api/workspaces/{wid}/lease",200,token=h.alice,method="POST",
                body={"expected_lease_epoch":1}))
            self.assertEqual(lease["lease_epoch"],2)
            stale={"content_base64":base64.b64encode(b"stale\n").decode(),"expected_entry_version":2,
                   "expected_workspace_revision":5,"lease_epoch":1}
            self.assertEqual(h.http(path,token=h.alice,method="PUT",body=stale,extra_headers={"Idempotency-Key":"stale-epoch"})[0],409)
        finally:
            h.cleanup()

    def test_checkpoint_replay_across_restart_and_stale_epoch_rejection(self):
        """A committed operation survives a hard restart; an old epoch cannot write.

        The replay intentionally carries the pre-restart expected revision and
        lease epoch. It must return the stored result instead of a version
        conflict, and neither replay nor the rejected stale mutation may advance
        the revision, change the working-tree, index, or HEAD bytes, or append
        an event.
        """
        binary, _ = select_runtime_binary()
        h = Harness(argparse.Namespace(binary=str(binary), keep=False))
        try:
            h.setup(); h.api(); h.roundtrip()
            ws = json.loads(h.expect("/api/workspaces",201,token=h.alice,method="POST",
                body={"owner":"alice","repository":"demo","agent_id":"replay","base_oid":h.second},
                extra_headers={"Idempotency-Key":"replay-create"}))
            wid = ws["id"]
            path = f"/api/workspaces/{wid}/files?path=hello.txt"
            def file_view(kind):
                return json.loads(h.expect(f"{path}&view={kind}",200,token=h.alice))
            put = {"content_base64":base64.b64encode(b"v1\n").decode(),"expected_entry_version":0,
                   "expected_workspace_revision":0,"lease_epoch":ws["lease_epoch"]}
            first_put = json.loads(h.expect(path,200,token=h.alice,method="PUT",body=put,
                extra_headers={"Idempotency-Key":"replay-put"}))
            self.assertEqual(first_put["workspace_revision"],1)
            checkpoint_body = {"expected_workspace_revision":1,"lease_epoch":ws["lease_epoch"]}
            checkpoint = json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",201,token=h.alice,
                method="POST",body=checkpoint_body,extra_headers={"Idempotency-Key":"replay-checkpoint"}))
            self.assertEqual(checkpoint["captured_revision"],1)
            self.assertEqual(checkpoint["workspace_revision"],2)
            index_before_restart = file_view("index")
            head_before_restart = file_view("head")
            self.assertEqual(index_before_restart["workspace_revision"],2)
            self.assertEqual(head_before_restart["workspace_revision"],2)
            self.assertEqual(index_before_restart["entry_version"],1)
            self.assertEqual(base64.b64decode(index_before_restart["content_base64"]),b"second\n")
            self.assertEqual(base64.b64decode(head_before_restart["content_base64"]),b"second\n")
            h.stop(hard=True); h.start()
            replay = json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints",200,token=h.alice,
                method="POST",body=checkpoint_body,extra_headers={"Idempotency-Key":"replay-checkpoint"}))
            self.assertEqual(replay,checkpoint)
            self.assertEqual(file_view("index"),index_before_restart)
            self.assertEqual(file_view("head"),head_before_restart)
            put_replay = json.loads(h.expect(path,200,token=h.alice,method="PUT",body=put,
                extra_headers={"Idempotency-Key":"replay-put"}))
            self.assertEqual(put_replay,first_put)
            self.assertEqual(file_view("index"),index_before_restart)
            self.assertEqual(file_view("head"),head_before_restart)
            current = json.loads(h.expect(f"/api/workspaces/{wid}",200,token=h.alice))
            self.assertEqual(current["revision"],2)
            self.assertEqual(current["last_checkpoint_id"],checkpoint["checkpoint_id"])
            events = json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0",200,token=h.alice))
            self.assertEqual([(e["revision"],e["kind"]) for e in events["events"]],[(1,"file_put"),(2,"checkpoint")])
            lease = json.loads(h.expect(f"/api/workspaces/{wid}/lease",200,token=h.alice,method="POST",
                body={"expected_lease_epoch":1}))
            self.assertEqual(lease["lease_epoch"],2)
            index_before_stale = file_view("index")
            head_before_stale = file_view("head")
            working_before_stale = file_view("working")
            self.assertEqual(index_before_stale,index_before_restart)
            self.assertEqual(head_before_stale,head_before_restart)
            self.assertEqual(index_before_stale["entry_version"],1)
            self.assertEqual(base64.b64decode(index_before_stale["content_base64"]),b"second\n")
            stale_put = {"content_base64":base64.b64encode(b"stale\n").decode(),"expected_entry_version":1,
                         "expected_workspace_revision":2,"lease_epoch":1}
            status, raw, _ = h.http(path,token=h.alice,method="PUT",body=stale_put,
                extra_headers={"Idempotency-Key":"replay-stale-put"})
            self.assertEqual(status,409,raw)
            self.assertEqual(file_view("index"),index_before_stale)
            self.assertEqual(file_view("head"),head_before_stale)
            self.assertEqual(file_view("working"),working_before_stale)
            status, raw, _ = h.http(f"/api/workspaces/{wid}/checkpoints",token=h.alice,method="POST",
                body={"expected_workspace_revision":2,"lease_epoch":1},
                extra_headers={"Idempotency-Key":"replay-stale-checkpoint"})
            self.assertEqual(status,409,raw)
            self.assertEqual(file_view("index"),index_before_stale)
            self.assertEqual(file_view("head"),head_before_stale)
            self.assertEqual(file_view("working"),working_before_stale)
            current = json.loads(h.expect(f"/api/workspaces/{wid}",200,token=h.alice))
            self.assertEqual(current["revision"],2)
            self.assertEqual(current["lease_epoch"],2)
            self.assertEqual(current["last_checkpoint_id"],checkpoint["checkpoint_id"])
            stored = json.loads(h.expect(path,200,token=h.alice))
            self.assertEqual(stored["entry_version"],1)
            self.assertEqual(stored["workspace_revision"],2)
            self.assertEqual(base64.b64decode(stored["content_base64"]),b"v1\n")
            events = json.loads(h.expect(f"/api/workspaces/{wid}/events?after_revision=0",200,token=h.alice))
            self.assertEqual([(e["revision"],e["kind"]) for e in events["events"]],[(1,"file_put"),(2,"checkpoint")])
        finally:
            h.cleanup()

    def test_workspace_git_state_compatibility_and_detached_head(self):
        binary, _ = select_runtime_binary()
        h = Harness(argparse.Namespace(binary=str(binary), keep=False))
        try:
            h.setup(); h.api(); h.roundtrip()
            h.create_repository({"name": "empty-ws"}, token=h.alice)
            status, body, _ = h.http("/api/workspaces", token=h.alice, method="POST",
                body={"owner": "alice", "repository": "empty-ws", "agent_id": "compat-empty"},
                extra_headers={"Idempotency-Key": "compat-empty"})
            self.assertEqual(status, 409, body)

            h.create_repository({"name": "sha256-ws", "object_format": "sha256"}, token=h.alice)
            s256_work = h.root / "sha256-seed"
            h.git("init", "-q", "-b", "main", "--object-format=sha256", str(s256_work))
            h.git("-C", str(s256_work), "config", "user.name", "Alice")
            h.git("-C", str(s256_work), "config", "user.email", "alice@example.invalid")
            (s256_work / "a.txt").write_text("sha256\n", encoding="utf-8")
            h.git("-C", str(s256_work), "add", "a.txt")
            h.git("-C", str(s256_work), "commit", "-q", "-m", "init")
            h.git("-C", str(s256_work), "push", "-q", f"{h.base}/git/alice/sha256-ws.git", "HEAD:refs/heads/main", token=h.alice)
            status, body, _ = h.http("/api/workspaces", token=h.alice, method="POST",
                body={"owner": "alice", "repository": "sha256-ws", "agent_id": "compat-s256"},
                extra_headers={"Idempotency-Key": "compat-s256"})
            self.assertEqual(status, 409, body)

            h.create_repository({"name": "sub-ws"}, token=h.alice)
            sub_work = h.root / "sub-seed"
            h.git("init", "-q", "-b", "main", str(sub_work))
            h.git("-C", str(sub_work), "config", "user.name", "Alice")
            h.git("-C", str(sub_work), "config", "user.email", "alice@example.invalid")
            (sub_work / "a.txt").write_text("root\n", encoding="utf-8")
            h.git("-C", str(sub_work), "add", "a.txt")
            h.git("-C", str(sub_work), "commit", "-q", "-m", "init")
            oid = h.git("rev-parse", "HEAD", cwd=sub_work).stdout.decode().strip()
            h.git("update-index", "--add", "--cacheinfo", f"160000,{oid},vendor/lib", cwd=sub_work)
            h.git("-C", str(sub_work), "commit", "-q", "-m", "gitlink")
            h.git("-C", str(sub_work), "push", "-q", f"{h.base}/git/alice/sub-ws.git", "HEAD:refs/heads/main", token=h.alice)
            status, body, _ = h.http("/api/workspaces", token=h.alice, method="POST",
                body={"owner": "alice", "repository": "sub-ws", "agent_id": "compat-sub"},
                extra_headers={"Idempotency-Key": "compat-sub"})
            self.assertEqual(status, 409, body)
            self.assertEqual(h.sql("SELECT count(*) FROM workspaces WHERE agent_id LIKE 'compat-%'"), "0")

            ws = json.loads(h.expect("/api/workspaces", 201, token=h.alice, method="POST",
                body={"owner": "alice", "repository": "demo", "agent_id": "compat-live", "base_oid": h.second},
                extra_headers={"Idempotency-Key": "compat-live"}))
            wid = ws["id"]
            repo = h.root / "data/workspace-service/workspaces" / wid
            h.git("checkout", "-q", "--detach", "HEAD", cwd=repo)
            deadline = time.monotonic() + 8
            while True:
                current = json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))
                if current["revision"] > 0:
                    break
                self.assertLess(time.monotonic(), deadline, "detached HEAD change was not captured")
                time.sleep(0.1)
            rev = current["revision"]
            gen = current["git_generation"]

            attrs = b"# allow filter comments\nsrc/filter_core.rs text eol=lf\n*.dat filter=lfs diff=lfs -text\n"
            put_ok = json.loads(h.expect(f"/api/workspaces/{wid}/files?path=.gitattributes", 200, token=h.alice, method="PUT",
                body={"content_base64": base64.b64encode(attrs).decode(), "expected_entry_version": 0,
                      "expected_workspace_revision": rev, "lease_epoch": 1},
                extra_headers={"Idempotency-Key": "compat-attr-ok"}))
            rev = put_ok["workspace_revision"]

            status, body, _ = h.http(f"/api/workspaces/{wid}/files?path=.gitattributes", token=h.alice, method="PUT",
                body={"content_base64": base64.b64encode(b"*.txt filter=custom\n").decode(),
                      "expected_entry_version": put_ok["entry_version"], "expected_workspace_revision": rev, "lease_epoch": 1},
                extra_headers={"Idempotency-Key": "compat-attr-bad"})
            self.assertEqual(status, 409, body)
            self.assertIn("clean/smudge", body.decode())
            self.assertEqual((repo / ".gitattributes").read_bytes(), attrs)

            git_ok = json.loads(h.expect(f"/api/workspaces/{wid}/git", 200, token=h.alice, method="POST",
                body={"action": "add", "paths": [".gitattributes"], "expected_git_generation": gen,
                      "expected_workspace_revision": rev, "lease_epoch": 1},
                extra_headers={"Idempotency-Key": "compat-git-add-attr"}))
            rev = git_ok["workspace_revision"]
            gen = git_ok["git_generation"]

            cp = json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints", 201, token=h.alice, method="POST",
                body={"expected_workspace_revision": rev, "lease_epoch": 1},
                extra_headers={"Idempotency-Key": "compat-cp-ok"}))
            rev = cp["workspace_revision"]
            restored = json.loads(h.expect(f"/api/checkpoints/{cp['checkpoint_id']}/restore", 201,
                token=h.alice, method="POST", body={"agent_id": "compat-restored"},
                extra_headers={"Idempotency-Key": "compat-restore-ok"}))
            copy = h.root / "data/workspace-service/workspaces" / restored["id"]
            self.assertEqual((copy / ".git/HEAD").read_text(encoding="utf-8").strip(), h.second)
            self.assertEqual((copy / ".gitattributes").read_bytes(), attrs)

            nested = repo / "nested"
            h.git("init", "-q", "-b", "main", str(nested))
            h.git("-C", str(nested), "config", "user.name", "Nested")
            h.git("-C", str(nested), "config", "user.email", "nested@example.invalid")
            (nested / "x.txt").write_text("sub\n", encoding="utf-8")
            h.git("-C", str(nested), "add", "x.txt")
            h.git("-C", str(nested), "commit", "-q", "-m", "nested")
            for attempt in range(4):
                cur = json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))
                status, body, _ = h.http(f"/api/workspaces/{wid}/git", token=h.alice, method="POST",
                    body={"action": "add", "paths": ["nested"],
                          "expected_git_generation": cur["git_generation"],
                          "expected_workspace_revision": cur["revision"], "lease_epoch": 1},
                    extra_headers={"Idempotency-Key": f"compat-git-add-nested-{attempt}"})
                self.assertEqual(status, 409, body)
                if "submodules" in body.decode():
                    break
            else:
                self.fail(f"expected submodules compat rejection, got {body!r}")
            import shutil
            shutil.rmtree(nested)

            (repo / ".git/worktrees/wt1").mkdir(parents=True)
            (repo / ".git/worktrees/wt1/gitdir").write_text("/tmp/wt1/.git\n", encoding="utf-8")
            try:
                for attempt in range(4):
                    cur_rev = json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))["revision"]
                    status, body, _ = h.http(f"/api/workspaces/{wid}/checkpoints", token=h.alice, method="POST",
                        body={"expected_workspace_revision": cur_rev, "lease_epoch": 1},
                        extra_headers={"Idempotency-Key": f"compat-cp-worktree-{attempt}"})
                    self.assertEqual(status, 409, body)
                    if "linked worktrees" in body.decode():
                        break
                else:
                    self.fail(f"expected linked worktrees compat rejection, got {body!r}")
            finally:
                shutil.rmtree(repo / ".git/worktrees")
        finally:
            h.cleanup()


if __name__ == "__main__": unittest.main()
