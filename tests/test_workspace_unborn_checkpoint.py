"""Native SHA-1 unborn workspace create, local checkpoint and restore regression.

The advertised branch is deliberately not ``main``. The fixture proves that a
genuine unborn HEAD survives create and local materialization, that an empty
HEAD is never treated as a committed revision, and that staged plus unstaged
Python entrypoint bytes survive a checkpoint/restore. After the real restore,
the working version is compiled to a fixture-owned bytecode artifact outside
the checked-out repository and executed against the restored workspace.
Nonempty sources whose HEAD is unresolved are still rejected instead of
becoming an empty workspace, and a local-only unborn checkpoint cannot be
published to remote storage.
"""
import argparse
import base64
import json
import py_compile
import sys
import unittest

from tests.e2e import Harness
from tests.runtime_binary import select_runtime_binary


STAGED_SOURCE = b'print("unborn-staged-index")\n'
WORKING_SOURCE = b'print("unborn-working-restored")\n'
WORKING_MARKER = b"unborn-working-restored\n"


def read_git(h, *args, cwd=None, check=True):
    """Observe stock Git state without allowing optional index/ref locks."""
    return h.git("--no-optional-locks", *args, cwd=cwd, check=check)


def assert_unborn_identity(case, h, repo, branch):
    """Assert one real empty HEAD and no commit, without stringifying None."""
    head = repo / ".git/HEAD"
    case.assertTrue(head.is_file(), f"missing native HEAD at {head}")
    case.assertEqual(head.read_text(encoding="utf-8").strip(), "ref: " + branch)
    case.assertEqual(read_git(h, "symbolic-ref", "-q", "HEAD", cwd=repo).stdout.strip(), branch.encode())
    for spec in ("HEAD", "HEAD^{commit}"):
        result = read_git(h, "rev-parse", "--verify", spec, cwd=repo, check=False)
        case.assertNotEqual(result.returncode, 0, f"unborn repo unexpectedly resolved {spec}")
    case.assertEqual(read_git(h, "for-each-ref", "--format=%(refname)", cwd=repo).stdout, b"")


def assert_unborn_worktree(case, h, repo, expected):
    case.assertEqual(read_git(h, "status", "--porcelain=v1", "-z", cwd=repo).stdout, expected["status"])
    case.assertEqual(read_git(h, "ls-files", "--stage", "-z", cwd=repo).stdout, expected["index"])
    case.assertEqual(read_git(h, "show", ":initial.py", cwd=repo).stdout, expected["staged"])
    case.assertEqual((repo / "initial.py").read_bytes(), expected["working"])
    case.assertEqual(read_git(h, "diff", "--cached", "--binary", cwd=repo).stdout, expected["diff_cached"])
    case.assertEqual(read_git(h, "diff", "--binary", cwd=repo).stdout, expected["diff_work"])
    staged_oid = read_git(h, "rev-parse", ":initial.py", cwd=repo).stdout.strip()
    case.assertEqual(read_git(h, "cat-file", "-t", staged_oid.decode(), cwd=repo).stdout.strip(), b"blob")
    case.assertEqual(read_git(h, "fsck", "--full", "--strict", cwd=repo, check=False).returncode, 0)


class WorkspaceUnbornCheckpointTest(unittest.TestCase):
    def test_unborn_create_checkpoint_restore_and_dangling_source_rejection(self):
        binary, _ = select_runtime_binary()
        h = Harness(argparse.Namespace(binary=str(binary), keep=False))
        try:
            h.setup()
            h.api()
            h.roundtrip()

            # A real empty bare source with a non-default declared branch.
            source = h.create_repository({"name": "unborn-ws"}, token=h.alice)
            source_bare = h.root / "data/repos" / (source["id"] + ".git")
            branch = "refs/heads/unborn-main"
            h.git("--git-dir=" + str(source_bare), "symbolic-ref", "HEAD", branch)
            self.assertEqual(
                h.git("--no-optional-locks", "--git-dir=" + str(source_bare), "symbolic-ref", "HEAD").stdout.strip(),
                branch.encode())
            self.assertNotEqual(
                h.git("--no-optional-locks", "--git-dir=" + str(source_bare), "rev-parse", "--verify", "HEAD^{commit}",
                      check=False).returncode,
                0)

            created = json.loads(h.expect("/api/workspaces", 201, token=h.alice, method="POST",
                body={"owner": "alice", "repository": "unborn-ws", "agent_id": "unborn-created"},
                extra_headers={"Idempotency-Key": "unborn-create"}))
            wid = created["id"]
            epoch = created["lease_epoch"]
            self.assertEqual(h.sql(f"SELECT base_oid IS NULL FROM workspaces WHERE id='{wid}'"), "t")
            live = h.root / "data/workspace-service/workspaces" / wid
            assert_unborn_identity(self, h, live, branch)
            self.assertEqual(read_git(h, "status", "--porcelain=v1", "-z", cwd=live).stdout, b"")
            self.assertEqual(read_git(h, "ls-files", "--stage", "-z", cwd=live).stdout, b"")

            path = f"/api/workspaces/{wid}/files?path=initial.py"
            first = json.loads(h.expect(path, 200, token=h.alice, method="PUT",
                body={"content_base64": base64.b64encode(STAGED_SOURCE).decode(), "expected_entry_version": 0,
                      "expected_workspace_revision": created["revision"], "lease_epoch": epoch},
                extra_headers={"Idempotency-Key": "unborn-put-staged"}))
            self.assertGreaterEqual(first["workspace_revision"], 1)
            staged = json.loads(h.expect(f"/api/workspaces/{wid}/git", 200, token=h.alice, method="POST",
                body={"action": "add", "paths": ["initial.py"],
                      "expected_git_generation": created["git_generation"],
                      "expected_workspace_revision": first["workspace_revision"], "lease_epoch": epoch},
                extra_headers={"Idempotency-Key": "unborn-git-add"}))
            self.assertGreater(staged["workspace_revision"], first["workspace_revision"])
            self.assertGreater(staged["git_generation"], created["git_generation"])
            second = json.loads(h.expect(path, 200, token=h.alice, method="PUT",
                body={"content_base64": base64.b64encode(WORKING_SOURCE).decode(), "expected_entry_version": 1,
                      "expected_workspace_revision": staged["workspace_revision"], "lease_epoch": epoch},
                extra_headers={"Idempotency-Key": "unborn-put-worktree"}))
            self.assertGreater(second["workspace_revision"], staged["workspace_revision"])

            expected = {
                "status": read_git(h, "status", "--porcelain=v1", "-z", cwd=live).stdout,
                "index": read_git(h, "ls-files", "--stage", "-z", cwd=live).stdout,
                "staged": read_git(h, "show", ":initial.py", cwd=live).stdout,
                "working": (live / "initial.py").read_bytes(),
                "diff_cached": read_git(h, "diff", "--cached", "--binary", cwd=live).stdout,
                "diff_work": read_git(h, "diff", "--binary", cwd=live).stdout,
            }
            self.assertEqual(expected["status"], b"AM initial.py\0")
            self.assertEqual(expected["staged"], STAGED_SOURCE)
            self.assertEqual(expected["working"], WORKING_SOURCE)
            assert_unborn_identity(self, h, live, branch)
            assert_unborn_worktree(self, h, live, expected)

            checkpoint = json.loads(h.expect(f"/api/workspaces/{wid}/checkpoints", 201, token=h.alice, method="POST",
                body={"expected_workspace_revision": second["workspace_revision"], "lease_epoch": epoch},
                extra_headers={"Idempotency-Key": "unborn-checkpoint"}))
            self.assertEqual(checkpoint["state"], "local_complete")
            self.assertEqual(checkpoint["captured_revision"], second["workspace_revision"])
            self.assertEqual(checkpoint["workspace_revision"], second["workspace_revision"] + 1)
            cid = checkpoint["checkpoint_id"]
            checkpoint_repo = h.root / "data/workspace-service/checkpoints" / cid
            assert_unborn_identity(self, h, checkpoint_repo, branch)
            assert_unborn_worktree(self, h, checkpoint_repo, expected)

            # A local-only unborn checkpoint is refused before remote admission
            # or any object upload, and stays local_complete with no manifest.
            staging = h.root / "data/workspace-service/staging"
            before_staging = sorted(p.name for p in staging.iterdir()) if staging.exists() else []
            status, body, _ = h.http(f"/api/checkpoints/{cid}/publish", token=h.alice, method="POST")
            self.assertEqual(status, 409, body)
            after_staging = sorted(p.name for p in staging.iterdir()) if staging.exists() else []
            self.assertEqual(after_staging, before_staging)
            self.assertEqual(
                h.sql(f"SELECT state, manifest_digest IS NULL, manifest_size IS NULL "
                      f"FROM workspace_checkpoints WHERE id='{cid}'"), "local_complete|t|t")

            h.stop(hard=True)
            h.start()
            restored = json.loads(h.expect(f"/api/checkpoints/{cid}/restore", 201,
                token=h.alice, method="POST", body={"agent_id": "unborn-restored"},
                extra_headers={"Idempotency-Key": "unborn-restore"}))
            copy = h.root / "data/workspace-service/workspaces" / restored["id"]
            self.assertEqual(h.sql(f"SELECT base_oid IS NULL FROM workspaces WHERE id='{restored['id']}'"), "t")
            assert_unborn_identity(self, h, copy, branch)
            assert_unborn_worktree(self, h, copy, expected)

            # Compile the restored working file outside the Git tree.
            artifact = h.root / "restored-bytecode" / "initial.pyc"
            artifact.parent.mkdir()
            py_compile.compile(str(copy / "initial.py"), cfile=str(artifact), doraise=True)
            self.assertTrue(artifact.is_file(), f"missing compiled artifact at {artifact}")
            self.assertNotIn(copy.resolve(), artifact.resolve().parents)
            built = h.run([sys.executable, str(artifact)], cwd=copy)
            self.assertEqual(built.stdout, WORKING_MARKER)

            # The build/run is side-effect free with respect to the native
            # unborn repository and the captured Git bytes.
            assert_unborn_identity(self, h, copy, branch)
            assert_unborn_worktree(self, h, copy, expected)

            # A source whose HEAD is unresolved but whose graph is not empty is
            # never normalized into a successful empty workspace.
            dangling = h.create_repository({"name": "dangling-ws"}, token=h.alice)
            h.git("push", h.base + dangling["clone_path"], f"{h.second}:refs/heads/other",
                  cwd=h.work, token=h.alice)
            status, body, _ = h.http("/api/workspaces", token=h.alice, method="POST",
                body={"owner": "alice", "repository": "dangling-ws", "agent_id": "dangling-source"},
                extra_headers={"Idempotency-Key": "dangling-create"})
            self.assertEqual(status, 409, body)
            self.assertEqual(h.sql("SELECT count(*) FROM workspaces WHERE agent_id='dangling-source'"), "0")

            # A genuinely dangling source: one present unreferenced blob, empty
            # refs, and an unresolved HEAD.
            blob_source = h.create_repository({"name": "dangling-blob-ws"}, token=h.alice)
            blob_bare = h.root / "data/repos" / (blob_source["id"] + ".git")
            blob_oid = h.run(["git", "--git-dir", str(blob_bare), "hash-object", "-w", "--stdin"],
                             data=b"unreferenced\n").stdout.decode().strip()
            self.assertEqual(len(blob_oid), 40)
            self.assertEqual(
                h.git("--no-optional-locks", "--git-dir=" + str(blob_bare), "for-each-ref",
                      "--format=%(refname)").stdout, b"")
            status, body, _ = h.http("/api/workspaces", token=h.alice, method="POST",
                body={"owner": "alice", "repository": "dangling-blob-ws", "agent_id": "dangling-blob-source"},
                extra_headers={"Idempotency-Key": "dangling-blob-create"})
            self.assertEqual(status, 409, body)
            self.assertEqual(h.sql("SELECT count(*) FROM workspaces WHERE agent_id='dangling-blob-source'"), "0")
            self.assertEqual(
                h.sql("SELECT count(*) FROM workspace_creations WHERE idempotency_key='dangling-blob-create'"), "0")

            # A source that is not the provisioned service-owned repository
            # identity is rejected even when its graph looks empty.
            identity = h.create_repository({"name": "identity-ws"}, token=h.alice)
            identity_bare = h.root / "data/repos" / (identity["id"] + ".git")
            h.git("--git-dir=" + str(identity_bare), "config", "rootyard.repositoryId",
                  "00000000-0000-0000-0000-000000000000")
            status, body, _ = h.http("/api/workspaces", token=h.alice, method="POST",
                body={"owner": "alice", "repository": "identity-ws", "agent_id": "identity-source"},
                extra_headers={"Idempotency-Key": "identity-create"})
            self.assertEqual(status, 409, body)
            self.assertEqual(h.sql("SELECT count(*) FROM workspaces WHERE agent_id='identity-source'"), "0")

            # A clone default must not replace an untrusted non-branch target.
            tagged = h.create_repository({"name": "tag-head-ws"}, token=h.alice)
            tagged_bare = h.root / "data/repos" / (tagged["id"] + ".git")
            h.git("--git-dir=" + str(tagged_bare), "symbolic-ref", "HEAD", "refs/tags/main")
            status, body, _ = h.http("/api/workspaces", token=h.alice, method="POST",
                body={"owner": "alice", "repository": "tag-head-ws", "agent_id": "tag-head-source"},
                extra_headers={"Idempotency-Key": "tag-head-create"})
            self.assertEqual(status, 409, body)
            self.assertEqual(h.sql("SELECT count(*) FROM workspaces WHERE agent_id='tag-head-source'"), "0")
        finally:
            h.cleanup()


if __name__ == "__main__":
    unittest.main()
