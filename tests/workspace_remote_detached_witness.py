#!/usr/bin/env python3
"""Source-only remote detached-HEAD + inert-LFS witness for issue #88.

This file is deliberately not named ``test_*.py``: it is an explicitly selected
acceptance source, not part of default unittest discovery and not CI wiring.
It has not been executed by the source-only checkpoint that added it. A
qualified Linux host must provide a real PostgreSQL test database, a real
externally supplied run-owned Garage S3 configuration, ``/dev/fuse``, usable
``unshare -Urm`` user/mount namespaces, bubblewrap, stock Git, and an exact
source-bound prebuilt ``rootyard`` binary.

Minimal invocation (the same FUSE backend selector used by
``tests/test_workspace_fuse_service.py`` is honoured)::

    ROOTYARD_TEST_ISSUE88_REMOTE_DETACHED_WITNESS=1 \
    ROOTYARD_TEST_FUSE_BACKEND=fuse \
    ROOTYARD_TEST_DATABASE_URL=postgresql://.../rootyard_test \
    ROOTYARD_OBJECT_STORE_ENDPOINT=http://... \
    ROOTYARD_OBJECT_STORE_BUCKET=... \
    ROOTYARD_OBJECT_STORE_REGION=... \
    ROOTYARD_OBJECT_STORE_ACCESS_KEY=... \
    ROOTYARD_OBJECT_STORE_SECRET_KEY=... \
    ROOTYARD_BIN=/absolute/path/to/source-bound/rootyard \
    python3 tests/workspace_remote_detached_witness.py -v

The one case exercises only the already-documented supported hosted state:

* stock Git creates a real source commit whose canonical inert LFS pointer and
  ``.gitattributes`` are pushed after the deterministic promised bytes were
  registered, uploaded, verified and read back through the existing LFS
  helpers; no local clean/smudge driver or host Git configuration is used;
* an authorised workspace is created from that source commit through the real
  API and exposed through the real source FUSE mount;
* detached HEAD and independent staged/unstaged worktree bytes are produced
  through the documented live-sandbox workspace path and the owned Git route;
* a local checkpoint is captured under the expected revision/lease, its
  production remote manifest is published and replayed through the real
  authenticated route, and the committed identity/state is checked from the
  public response and workspace view;
* the source service is stopped cleanly, the exact owned source data root is
  renamed/quarantined, and a second service process starts on a fresh empty
  data root sharing only the same durable PostgreSQL schema and Garage
  prerequisites;
* the source checkpoint root is absent from the destination, restore runs
  through the real authorised HTTP route, and stock Git/native checks plus a
  real compile-run of a checked-in Python build witness bind to the returned
  destination workspace. The build uses the already-required test interpreter,
  so no optional C/C++ toolchain is silently assumed or skipped.

This witness does **not** claim physical multi-host execution, remote LFS
hydration, FUSE on the destination, arbitrary filter execution, or tenant
authorization. ``tests/workspace_fuse_compat_witness.py`` owns the genuine
mounted local #314 positive, and #321 owns the tenant-authorization witness.
The destination deliberately runs in ``direct`` mount mode.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import quote

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for directory in (REPO_ROOT, TESTS_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from lfs import LfsHarness  # noqa: E402
from runtime_binary import select_runtime_binary  # noqa: E402
from test_workspace_fuse_service import MOUNT_MODE  # noqa: E402

WITNESS_GATE = "ROOTYARD_TEST_ISSUE88_REMOTE_DETACHED_WITNESS"
REQUIRED_OBJECT_STORE = (
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
)
ATTRS_NAME = ".gitattributes"
POINTER_NAME = "lfs-pointer.bin"
STAGED_NAME = "staged.txt"
UNSTAGED_NAME = "unstaged.txt"
BUILD_NAME = "witness_build.py"
INDEX_PATHS = (ATTRS_NAME, BUILD_NAME, POINTER_NAME, STAGED_NAME, UNSTAGED_NAME)

# Exactly 12 deterministic bytes. The canonical pointer is the only source
# representation of this object; these bytes are verified through the real LFS
# route before the source push introduces the pointer.
LFS_PAYLOAD = b"rootyard-lfs"
LFS_SIZE = len(LFS_PAYLOAD)
LFS_OID = hashlib.sha256(LFS_PAYLOAD).hexdigest()
ATTRS = (
    b"# Inert LFS marker: this fixture configures no local clean/smudge driver.\n"
    b"lfs-pointer.bin filter=lfs diff=lfs -text\n"
)
POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:" + LFS_OID.encode("ascii") + b"\n"
    b"size " + str(LFS_SIZE).encode("ascii") + b"\n"
)
STAGED_BEFORE = b"staged before\n"
STAGED_AFTER = b"staged after\n"
UNSTAGED_BEFORE = b"unstaged before\n"
UNSTAGED_AFTER = b"unstaged after\n"
BUILD_MARKER = b"issue88-remote-restored-build-ok\n"
BUILD_SOURCE = (
    b"from pathlib import Path\n"
    b"\n"
    b"assert Path('staged.txt').read_bytes() == b'staged after\\n'\n"
    b"assert Path('lfs-pointer.bin').read_bytes().startswith(\n"
    b"    b'version https://git-lfs.github.com/spec/v1\\n'\n"
    b")\n"
    b"print('issue88-remote-restored-build-ok')\n"
)
ARTIFACT_LIMIT = 16 * 1024 * 1024


def _blob_oid(data: bytes) -> bytes:
    """Return the exact SHA-1 Git blob object id for ``data`` without Git."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest().encode()


def _unified_diff(path: str, before: bytes, after: bytes) -> bytes:
    """Exact one-line unified diff for files ending in one newline."""
    raw_path = path.encode()
    return (
        b"diff --git a/" + raw_path + b" b/" + raw_path + b"\n"
        + b"index " + _blob_oid(before) + b".." + _blob_oid(after) + b" 100644\n"
        + b"--- a/" + raw_path + b"\n"
        + b"+++ b/" + raw_path + b"\n"
        + b"@@ -1 +1 @@\n"
        + b"-" + before + b"+" + after
    )


def _porcelain_v2() -> bytes:
    """Exact expected porcelain-v2 entries for one staged and one unstaged file."""
    return (
        b"1 M. N... 100644 100644 100644 "
        + _blob_oid(STAGED_BEFORE)
        + b" "
        + _blob_oid(STAGED_AFTER)
        + b" "
        + STAGED_NAME.encode()
        + b"\n"
        + b"1 .M N... 100644 100644 100644 "
        + _blob_oid(UNSTAGED_BEFORE)
        + b" "
        + _blob_oid(UNSTAGED_BEFORE)
        + b" "
        + UNSTAGED_NAME.encode()
        + b"\n"
    )


def _index_lines() -> list[bytes]:
    """Exact expected index entries for the paths inspected after restore."""
    return sorted(
        [
            b"100644 " + _blob_oid(ATTRS) + b" 0\t" + ATTRS_NAME.encode(),
            b"100644 " + _blob_oid(BUILD_SOURCE) + b" 0\t" + BUILD_NAME.encode(),
            b"100644 " + _blob_oid(POINTER) + b" 0\t" + POINTER_NAME.encode(),
            b"100644 " + _blob_oid(STAGED_AFTER) + b" 0\t" + STAGED_NAME.encode(),
            b"100644 " + _blob_oid(UNSTAGED_BEFORE) + b" 0\t" + UNSTAGED_NAME.encode(),
        ]
    )


class WorkspaceRemoteDetachedWitnessTest(unittest.TestCase):
    def setUp(self):
        if os.environ.get(WITNESS_GATE) != "1":
            self.fail(
                f"this source-only witness is fail-closed; set {WITNESS_GATE}=1 "
                "on a qualified Linux host before selecting it"
            )
        if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
            self.fail("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
        missing = [name for name in REQUIRED_OBJECT_STORE if not os.environ.get(name)]
        if missing:
            self.fail(
                "a real externally supplied run-owned Garage S3 configuration is required; "
                "missing: " + ", ".join(missing)
            )
        if not sys.platform.startswith("linux"):
            self.fail("the source FUSE live-sandbox path requires Linux user/mount namespaces")
        if not Path("/dev/fuse").exists():
            self.fail("the hosted workspace witness requires a usable /dev/fuse")
        for executable in ("git", "psql", "unshare", "bwrap"):
            if not shutil.which(executable):
                self.fail(f"the qualified host must provide {executable} on PATH")
        try:
            probe = subprocess.run(
                ["unshare", "-Urm", "true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            self.fail("the witness requires usable `unshare -Urm` user/mount namespaces")
        if probe.returncode != 0:
            self.fail("the witness requires usable `unshare -Urm` user/mount namespaces")
        try:
            self.binary, _ = select_runtime_binary()
        except Exception as error:
            self.fail(f"an exact source-bound rootyard runtime binary is required: {error}")
        if not self.binary.is_file():
            self.fail("the selected rootyard runtime binary is not a regular file")

    # -- bounded service helpers ------------------------------------------------

    def state(self, h, wid):
        return json.loads(h.expect(f"/api/workspaces/{wid}", 200, token=h.alice))

    def view(self, h, wid, path, view=None):
        query = "?path=" + quote(path, safe="")
        if view is not None:
            query += "&view=" + quote(view, safe="")
        payload = json.loads(
            h.expect(f"/api/workspaces/{wid}/files{query}", 200, token=h.alice)
        )
        raw = base64.b64decode(payload["content_base64"])
        self.assertEqual(payload["sha256"], hashlib.sha256(raw).hexdigest())
        return raw

    def live_job(self, h, wid, lease_epoch, script, timeout=30):
        created = json.loads(
            h.expect(
                f"/api/workspaces/{wid}/sandbox-jobs",
                201,
                token=h.alice,
                method="POST",
                body={
                    "argv": ["/bin/sh", "-c", script],
                    "timeout_seconds": timeout,
                    "lease_epoch": lease_epoch,
                    "workspace_access": "live",
                },
            )
        )
        deadline = time.monotonic() + timeout + 15
        result = None
        while time.monotonic() < deadline:
            result = json.loads(
                h.expect(f"/api/sandbox-jobs/{created['id']}", 200, token=h.alice)
            )
            if result["state"] not in ("queued", "preparing", "running"):
                break
            time.sleep(0.1)
        else:
            self.fail(
                f"live FUSE job {created['id']} did not reach a terminal state "
                f"within {timeout + 15}s"
            )
        if result["state"] != "succeeded":
            # Never emit raw job logs, endpoints or credentials in a failure.
            self.fail(
                f"live FUSE job {created['id']} ended {result['state']} "
                f"exit={result.get('exit_code')}"
            )
        return result

    def artifact(self, h, job, name):
        payload = json.loads(
            h.expect(
                f"/api/sandbox-jobs/{job['id']}/artifacts?path={quote(name, safe='')}",
                200,
                token=h.alice,
            )
        )
        raw = base64.b64decode(payload["content_base64"])
        self.assertEqual(payload["path"], name)
        self.assertEqual(payload["size"], len(raw))
        self.assertLessEqual(len(raw), ARTIFACT_LIMIT)
        return raw

    def native_env(self, h):
        """Stock Git with system/global configuration and optional writes disabled."""
        env = dict(h.env)
        env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_ATTR_NOSYSTEM="1",
            GIT_OPTIONAL_LOCKS="0",
            LC_ALL="C",
        )
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"):
            env.pop(name, None)
        return env

    def native(self, h, *args, cwd, check=True):
        return h.git("--no-pager", *args, cwd=cwd, env=self.native_env(h), check=check)

    def assert_fsck_clean(self, output, label):
        lowered = output.lower()
        for marker in (b"error", b"fatal", b"missing", b"broken"):
            self.assertNotIn(marker, lowered, f"{label} fsck reported {marker.decode()} evidence")
        dangling = [line for line in output.splitlines() if b"dangling" in line.lower()]
        self.assertEqual(dangling, [], f"{label} fsck unexpectedly reported dangling evidence")

    def expected_native_state(self, base_oid):
        return {
            "status": _porcelain_v2(),
            "staged_diff": _unified_diff(STAGED_NAME, STAGED_BEFORE, STAGED_AFTER),
            "unstaged_diff": _unified_diff(UNSTAGED_NAME, UNSTAGED_BEFORE, UNSTAGED_AFTER),
            "index": _index_lines(),
            "head": base_oid.encode() + b"\n",
            "git_head": base_oid.encode() + b"\n",
            "check_attr": f"{POINTER_NAME}: filter: lfs\n".encode(),
        }

    def probe_script(self, prefix):
        paths = " ".join(INDEX_PATHS)
        return f"""set -eu
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 GIT_OPTIONAL_LOCKS=0 LC_ALL=C
cd /workspace
mkdir -p /artifacts
if git symbolic-ref -q HEAD > /artifacts/{prefix}_symref; then
  echo "HEAD is attached; expected a detached HEAD" >&2
  exit 1
fi
git --no-optional-locks status --porcelain=v2 > /artifacts/{prefix}_status
git --no-optional-locks diff --cached --full-index --no-color --no-ext-diff --no-textconv -- {STAGED_NAME} > /artifacts/{prefix}_staged_diff
git --no-optional-locks diff --full-index --no-color --no-ext-diff --no-textconv -- {UNSTAGED_NAME} > /artifacts/{prefix}_unstaged_diff
git --no-optional-locks ls-files -s -- {paths} > /artifacts/{prefix}_index
git rev-parse HEAD > /artifacts/{prefix}_head
cat .git/HEAD > /artifacts/{prefix}_git_head
git cat-file -p HEAD:{POINTER_NAME} > /artifacts/{prefix}_head_pointer
git cat-file -p :{POINTER_NAME} > /artifacts/{prefix}_index_pointer
cat {POINTER_NAME} > /artifacts/{prefix}_work_pointer
git cat-file -p HEAD:{ATTRS_NAME} > /artifacts/{prefix}_head_attrs
git cat-file -p :{ATTRS_NAME} > /artifacts/{prefix}_index_attrs
cat {ATTRS_NAME} > /artifacts/{prefix}_work_attrs
git config --local --get-regexp '^(filter|diff|merge)[.]' > /artifacts/{prefix}_config_filters 2>&1 || true
git check-attr filter -- {POINTER_NAME} > /artifacts/{prefix}_check_attr
if [ -f .git/info/attributes ]; then
  cat .git/info/attributes > /artifacts/{prefix}_info_attrs
else
  : > /artifacts/{prefix}_info_attrs
fi
git fsck --full --strict > /artifacts/{prefix}_fsck 2>&1 || true
"""

    def verify_mounted_state(self, h, wid, lease_epoch, expected, prefix):
        job = self.live_job(h, wid, lease_epoch, self.probe_script(prefix))
        self.assertEqual(self.artifact(h, job, f"{prefix}_symref"), b"")
        self.assertEqual(self.artifact(h, job, f"{prefix}_status"), expected["status"])
        self.assertEqual(
            self.artifact(h, job, f"{prefix}_staged_diff"), expected["staged_diff"]
        )
        self.assertEqual(
            self.artifact(h, job, f"{prefix}_unstaged_diff"), expected["unstaged_diff"]
        )
        self.assertEqual(
            sorted(self.artifact(h, job, f"{prefix}_index").splitlines()),
            expected["index"],
        )
        self.assertEqual(self.artifact(h, job, f"{prefix}_head"), expected["head"])
        self.assertEqual(self.artifact(h, job, f"{prefix}_git_head"), expected["git_head"])
        self.assertEqual(self.artifact(h, job, f"{prefix}_head_pointer"), POINTER)
        self.assertEqual(self.artifact(h, job, f"{prefix}_index_pointer"), POINTER)
        self.assertEqual(self.artifact(h, job, f"{prefix}_work_pointer"), POINTER)
        self.assertEqual(self.artifact(h, job, f"{prefix}_head_attrs"), ATTRS)
        self.assertEqual(self.artifact(h, job, f"{prefix}_index_attrs"), ATTRS)
        self.assertEqual(self.artifact(h, job, f"{prefix}_work_attrs"), ATTRS)
        self.assertEqual(
            self.artifact(h, job, f"{prefix}_check_attr"), expected["check_attr"]
        )
        self.assertEqual(self.artifact(h, job, f"{prefix}_config_filters"), b"")
        self.assertEqual(self.artifact(h, job, f"{prefix}_info_attrs"), b"")
        self.assert_fsck_clean(
            self.artifact(h, job, f"{prefix}_fsck"), f"source {prefix}"
        )

    def add_with_retry(self, h, wid, key):
        for attempt in range(12):
            current = self.state(h, wid)
            status, raw, _ = h.http(
                f"/api/workspaces/{wid}/git",
                token=h.alice,
                method="POST",
                body={
                    "action": "add",
                    "paths": [STAGED_NAME],
                    "expected_git_generation": current["git_generation"],
                    "expected_workspace_revision": current["revision"],
                    "lease_epoch": current["lease_epoch"],
                },
                extra_headers={"Idempotency-Key": f"{key}-{attempt}"},
            )
            if status == 200:
                return json.loads(raw)
            if status != 409 or b"workspace version or lease conflict" not in raw:
                self.fail(f"hosted Git add failed: status={status}")
            time.sleep(0.2)
        self.fail("hosted Git add did not commit within the bounded retry window")

    def checkpoint_with_retry(self, h, wid, key):
        for attempt in range(12):
            current = self.state(h, wid)
            status, raw, _ = h.http(
                f"/api/workspaces/{wid}/checkpoints",
                token=h.alice,
                method="POST",
                body={
                    "expected_workspace_revision": current["revision"],
                    "lease_epoch": current["lease_epoch"],
                },
                extra_headers={"Idempotency-Key": f"{key}-{attempt}"},
            )
            if status == 201:
                checkpoint = json.loads(raw)
                self.assertEqual(checkpoint["state"], "local_complete")
                self.assertEqual(checkpoint["captured_revision"], current["revision"])
                return checkpoint
            if status != 409 or b"workspace version or lease conflict" not in raw:
                self.fail(f"checkpoint failed: status={status}")
            time.sleep(0.2)
        self.fail("checkpoint did not commit within the bounded retry window")

    def source_facts(self, h):
        git_dir = "--git-dir=" + str(h.bare)
        fsck = h.git(git_dir, "fsck", "--full", "--strict")
        return {
            "head": h.git(git_dir, "rev-parse", "HEAD").stdout.strip(),
            "refs": h.git(git_dir, "show-ref").stdout,
            "fsck": b"\n".join(sorted((fsck.stdout + fsck.stderr).splitlines())),
            "pointer": h.git(git_dir, "cat-file", "-p", f"HEAD:{POINTER_NAME}").stdout,
            "attrs": h.git(git_dir, "cat-file", "-p", f"HEAD:{ATTRS_NAME}").stdout,
            "work_head": h.git("rev-parse", "HEAD", cwd=h.work).stdout.strip(),
            "work_status": h.git(
                "--no-optional-locks",
                "status",
                "--porcelain=v2",
                cwd=h.work,
            ).stdout,
        }

    def assert_native_workspace(self, h, repo, base_oid, expected):
        """Exact stock-Git and fsck checks bound to the restored worktree."""
        self.assertEqual(
            self.native(h, "rev-parse", "HEAD", cwd=repo).stdout.strip(),
            base_oid.encode(),
        )
        symbolic = self.native(h, "symbolic-ref", "-q", "HEAD", cwd=repo, check=False)
        self.assertNotEqual(symbolic.returncode, 0)
        self.assertEqual(symbolic.stdout, b"")
        raw_head = (repo / ".git/HEAD").read_bytes()
        self.assertEqual(raw_head.strip(), base_oid.encode())
        self.assertFalse(raw_head.startswith(b"ref:"))

        self.assertEqual(
            self.native(
                h, "--no-optional-locks", "status", "--porcelain=v2", cwd=repo
            ).stdout,
            expected["status"],
        )
        self.assertEqual(
            self.native(
                h,
                "--no-optional-locks",
                "diff",
                "--cached",
                "--full-index",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--",
                STAGED_NAME,
                cwd=repo,
            ).stdout,
            expected["staged_diff"],
        )
        self.assertEqual(
            self.native(
                h,
                "--no-optional-locks",
                "diff",
                "--full-index",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--",
                UNSTAGED_NAME,
                cwd=repo,
            ).stdout,
            expected["unstaged_diff"],
        )
        self.assertEqual(
            sorted(
                self.native(
                    h,
                    "--no-optional-locks",
                    "ls-files",
                    "-s",
                    "--",
                    *INDEX_PATHS,
                    cwd=repo,
                ).stdout.splitlines()
            ),
            expected["index"],
        )

        self.assertEqual(
            self.native(h, "cat-file", "-p", f"HEAD:{POINTER_NAME}", cwd=repo).stdout,
            POINTER,
        )
        self.assertEqual(
            self.native(h, "cat-file", "-p", f":{POINTER_NAME}", cwd=repo).stdout,
            POINTER,
        )
        self.assertEqual((repo / POINTER_NAME).read_bytes(), POINTER)
        self.assertEqual(
            self.native(h, "cat-file", "-p", f"HEAD:{ATTRS_NAME}", cwd=repo).stdout,
            ATTRS,
        )
        self.assertEqual(
            self.native(h, "cat-file", "-p", f":{ATTRS_NAME}", cwd=repo).stdout,
            ATTRS,
        )
        self.assertEqual((repo / ATTRS_NAME).read_bytes(), ATTRS)
        self.assertEqual(
            self.native(h, "check-attr", "filter", "--", POINTER_NAME, cwd=repo).stdout,
            expected["check_attr"],
        )
        configured = self.native(
            h,
            "config",
            "--local",
            "--get-regexp",
            r"^(filter|diff|merge)\.",
            cwd=repo,
            check=False,
        )
        self.assertEqual(configured.stdout, b"")
        info_attrs = repo / ".git/info/attributes"
        if info_attrs.exists():
            self.assertNotIn(b"filter", info_attrs.read_bytes())
        fsck = self.native(h, "fsck", "--full", "--strict", cwd=repo)
        self.assert_fsck_clean(fsck.stdout + fsck.stderr, "restored destination")

    # -- witness ---------------------------------------------------------------

    def test_detached_inert_lfs_remote_publish_and_fresh_root_restore(self):
        with tempfile.TemporaryDirectory(
            prefix="rootyard-issue88-remote-detached-witness-"
        ) as wrapper_dir:
            wrapper = Path(wrapper_dir) / "rootyard-userns"
            wrapper.write_text(
                "#!/bin/sh\nexec unshare -Urm "
                + shlex.quote(str(self.binary))
                + ' "$@"\n'
            )
            wrapper.chmod(0o700)
            h = LfsHarness(argparse.Namespace(binary=str(wrapper), keep=False))
            try:
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = MOUNT_MODE
                h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
                for name in (
                    "ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_OBJECTS",
                    "ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_COMMIT",
                    "ROOTYARD_WORKSPACE_UNSAFE_REMOTE_DELETE",
                ):
                    h.env.pop(name, None)
                h.setup()
                h.api()
                h.roundtrip()

                # (1) Authenticated registration/upload/verify/download of the
                # deterministic promised bytes happens before the source push
                # introduces the canonical inert pointer.
                self.assertEqual(LFS_SIZE, 12)
                self.assertEqual(LFS_OID, hashlib.sha256(LFS_PAYLOAD).hexdigest())
                upload = h.lfs_batch(
                    "upload", [{"oid": LFS_OID, "size": LFS_SIZE}], token=h.alice
                )
                self.assertEqual(upload["transfer"], "basic")
                self.assertEqual(len(upload["objects"]), 1)
                uploaded = upload["objects"][0]
                self.assertEqual(uploaded["oid"], LFS_OID)
                self.assertEqual(uploaded["size"], LFS_SIZE)
                status, _, _ = h.lfs_put(
                    uploaded["actions"]["upload"]["href"],
                    LFS_PAYLOAD,
                    token=h.alice,
                    code=200,
                )
                self.assertEqual(status, 200)
                verified = h.lfs_verify(
                    uploaded["actions"]["verify"]["href"],
                    LFS_OID,
                    LFS_SIZE,
                    token=h.alice,
                    code=200,
                )
                self.assertEqual(verified.get("verified"), True)
                self.assertEqual(verified.get("oid"), LFS_OID)
                self.assertEqual(verified.get("size"), LFS_SIZE)
                download = h.lfs_batch(
                    "download", [{"oid": LFS_OID, "size": LFS_SIZE}], token=h.alice
                )
                self.assertEqual(len(download["objects"]), 1)
                self.assertEqual(download["objects"][0]["oid"], LFS_OID)
                self.assertEqual(download["objects"][0]["size"], LFS_SIZE)
                status, readback, _ = h.lfs_get(
                    download["objects"][0]["actions"]["download"]["href"],
                    token=h.alice,
                    code=200,
                )
                self.assertEqual(status, 200)
                self.assertEqual(readback, LFS_PAYLOAD)
                self.assertEqual(hashlib.sha256(readback).hexdigest(), LFS_OID)

                # (2) Real stock-Git source fixture. No local filter driver and
                # no host system/global Git configuration are used.
                self.assertEqual(
                    h.git(
                        "config",
                        "--local",
                        "--get-regexp",
                        r"^filter\.",
                        cwd=h.work,
                        check=False,
                    ).stdout,
                    b"",
                    "source fixture unexpectedly has a local filter driver",
                )
                (h.work / ATTRS_NAME).write_bytes(ATTRS)
                (h.work / POINTER_NAME).write_bytes(POINTER)
                (h.work / STAGED_NAME).write_bytes(STAGED_BEFORE)
                (h.work / UNSTAGED_NAME).write_bytes(UNSTAGED_BEFORE)
                (h.work / BUILD_NAME).write_bytes(BUILD_SOURCE)
                h.git(
                    "add",
                    "--",
                    ATTRS_NAME,
                    POINTER_NAME,
                    STAGED_NAME,
                    UNSTAGED_NAME,
                    BUILD_NAME,
                    cwd=h.work,
                )
                self.assertEqual(
                    h.git("cat-file", "-p", f":{POINTER_NAME}", cwd=h.work).stdout,
                    POINTER,
                    "source add hydrated the inert LFS pointer",
                )
                h.git(
                    "commit",
                    "-m",
                    "test: track inert LFS pointer, staged/unstaged files and build witness",
                    cwd=h.work,
                )
                base_oid = (
                    h.git("rev-parse", "HEAD", cwd=h.work).stdout.decode().strip()
                )
                self.assertEqual(len(base_oid), 40)
                h.git("push", "origin", "HEAD:main", cwd=h.work, token=h.alice)
                self.assertEqual(
                    h.git("show", f"HEAD:{POINTER_NAME}", cwd=h.work).stdout,
                    POINTER,
                )
                self.assertEqual(
                    h.git("show", f"HEAD:{ATTRS_NAME}", cwd=h.work).stdout,
                    ATTRS,
                )
                self.assertEqual(
                    h.git("check-attr", "filter", "--", POINTER_NAME, cwd=h.work).stdout,
                    f"{POINTER_NAME}: filter: lfs\n".encode(),
                )
                source_before = self.source_facts(h)
                self.assertEqual(source_before["head"], base_oid.encode())
                self.assertEqual(source_before["work_head"], base_oid.encode())
                self.assertEqual(source_before["pointer"], POINTER)
                self.assertEqual(source_before["attrs"], ATTRS)
                self.assertEqual(source_before["work_status"], b"")
                self.assert_fsck_clean(source_before["fsck"], "source repository")

                # (3) Authorised workspace creation from the source commit.
                workspace = json.loads(
                    h.expect(
                        "/api/workspaces",
                        201,
                        token=h.alice,
                        method="POST",
                        body={
                            "owner": "alice",
                            "repository": "demo",
                            "agent_id": "issue88-remote-detached",
                            "base_oid": base_oid,
                        },
                        extra_headers={
                            "Idempotency-Key": "issue88-remote-detached-create"
                        },
                    )
                )
                wid = workspace["id"]
                self.assertEqual(workspace["state"], "ready")
                self.assertEqual(workspace["repository_id"], h.repo["id"])
                self.assertEqual(self.view(h, wid, POINTER_NAME, "head"), POINTER)
                self.assertEqual(self.view(h, wid, ATTRS_NAME, "head"), ATTRS)

                # (4) Detached HEAD and independent staged/unstaged worktree
                # bytes through the documented live-sandbox mount path. The
                # index mutation then goes through the owned API Git route.
                prepare = f"""set -eu
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 GIT_OPTIONAL_LOCKS=0 LC_ALL=C
cd /workspace
mkdir -p /artifacts
git -c core.hooksPath=/dev/null -c core.fsmonitor=false -c gc.auto=0 checkout --detach HEAD
printf %s {shlex.quote(STAGED_AFTER.decode())} > {STAGED_NAME}
printf %s {shlex.quote(UNSTAGED_AFTER.decode())} > {UNSTAGED_NAME}
test -z "$(git config --local --get-regexp '^(filter|diff|merge)[.]' || true)"
test "$(git check-attr filter -- {POINTER_NAME})" = "{POINTER_NAME}: filter: lfs"
git rev-parse HEAD > /artifacts/pre_head
cat .git/HEAD > /artifacts/pre_git_head
cat {POINTER_NAME} > /artifacts/pre_work_pointer
cat {ATTRS_NAME} > /artifacts/pre_work_attrs
"""
                prepare_job = self.live_job(
                    h, wid, self.state(h, wid)["lease_epoch"], prepare
                )
                self.assertEqual(
                    self.artifact(h, prepare_job, "pre_head").strip(),
                    base_oid.encode(),
                )
                self.assertEqual(
                    self.artifact(h, prepare_job, "pre_git_head").strip(),
                    base_oid.encode(),
                )
                self.assertEqual(
                    self.artifact(h, prepare_job, "pre_work_pointer"), POINTER
                )
                self.assertEqual(
                    self.artifact(h, prepare_job, "pre_work_attrs"), ATTRS
                )

                added = self.add_with_retry(h, wid, "issue88-remote-detached-add")
                self.assertEqual(added["action"], "add")
                self.assertEqual(base64.b64decode(added["output_base64"]), b"")
                self.assertEqual(self.view(h, wid, STAGED_NAME, "working"), STAGED_AFTER)
                self.assertEqual(self.view(h, wid, STAGED_NAME, "index"), STAGED_AFTER)
                self.assertEqual(self.view(h, wid, STAGED_NAME, "head"), STAGED_BEFORE)
                self.assertEqual(
                    self.view(h, wid, UNSTAGED_NAME, "working"), UNSTAGED_AFTER
                )
                self.assertEqual(
                    self.view(h, wid, UNSTAGED_NAME, "index"), UNSTAGED_BEFORE
                )
                self.assertEqual(
                    self.view(h, wid, UNSTAGED_NAME, "head"), UNSTAGED_BEFORE
                )
                self.assertEqual(self.view(h, wid, POINTER_NAME, "working"), POINTER)
                self.assertEqual(self.view(h, wid, ATTRS_NAME, "working"), ATTRS)

                expected = self.expected_native_state(base_oid)
                self.verify_mounted_state(
                    h,
                    wid,
                    self.state(h, wid)["lease_epoch"],
                    expected,
                    "source",
                )

                # (5) Capture under the expected revision/lease through the real
                # checkpoint API, then publish and replay the production remote
                # manifest through the real authenticated route.
                checkpoint = self.checkpoint_with_retry(
                    h, wid, "issue88-remote-detached-checkpoint"
                )
                cid = checkpoint["checkpoint_id"]
                self.assertEqual(checkpoint["state"], "local_complete")
                self.assertEqual(self.state(h, wid)["last_checkpoint_id"], cid)
                source_data = h.root / "data"
                source_checkpoint = (
                    source_data / "workspace-service/checkpoints" / cid
                )
                self.assertTrue(source_checkpoint.is_dir())

                published = json.loads(
                    h.expect(
                        f"/api/checkpoints/{cid}/publish",
                        200,
                        token=h.alice,
                        method="POST",
                    )
                )
                self.assertEqual(published["checkpoint_id"], cid)
                self.assertEqual(published["state"], "COMMITTED")
                self.assertEqual(published["durability"], "remote_verified")
                self.assertRegex(published["manifest_sha256"], r"^[0-9a-f]{64}$")
                self.assertGreater(published["manifest_size"], 0)
                self.assertEqual(
                    published["captured_revision"], checkpoint["captured_revision"]
                )
                replay = json.loads(
                    h.expect(
                        f"/api/checkpoints/{cid}/publish",
                        200,
                        token=h.alice,
                        method="POST",
                    )
                )
                self.assertEqual(replay["state"], "COMMITTED")
                self.assertEqual(
                    replay["manifest_sha256"], published["manifest_sha256"]
                )
                self.assertEqual(replay["manifest_size"], published["manifest_size"])
                events = json.loads(
                    h.expect(
                        f"/api/workspaces/{wid}/events?after_revision=0",
                        200,
                        token=h.alice,
                    )
                )
                captured_events = [
                    event
                    for event in events["events"]
                    if event["kind"] == "checkpoint"
                    and event["payload"].get("checkpoint_id") == cid
                ]
                self.assertEqual(len(captured_events), 1)
                self.assertEqual(
                    captured_events[0]["payload"]["captured_revision"],
                    checkpoint["captured_revision"],
                )
                self.assertEqual(self.source_facts(h), source_before)

                # (6) Clean source stop, then quarantine exactly this fixture's
                # owned source data root by rename. No non-owned path is deleted.
                source_proc = h.proc
                self.assertIsNotNone(source_proc)
                h.stop()
                self.assertIsNone(h.proc)
                self.assertEqual(
                    source_proc.returncode, 0, "source service did not stop cleanly"
                )
                self.assertTrue(source_checkpoint.is_dir())
                quarantine = h.root / "source-data-quarantined"
                self.assertFalse(quarantine.exists())
                source_data.rename(quarantine)
                self.assertFalse(source_data.exists())
                self.assertTrue(
                    (quarantine / "workspace-service/checkpoints" / cid).is_dir()
                )

                # (7) Independent empty data root for a second service process;
                # only the owned durable PostgreSQL schema and Garage remain.
                dest_data = h.root / "destination-data"
                self.assertFalse(dest_data.exists())
                h.env["ROOTYARD_DATA_DIR"] = str(dest_data)
                h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = "direct"
                h.start()
                self.assertFalse(
                    (dest_data / "workspace-service/checkpoints" / cid).exists()
                )

                # (8) Real authorised remote restore into the returned workspace.
                restored = json.loads(
                    h.expect(
                        f"/api/checkpoints/{cid}/restore",
                        201,
                        token=h.alice,
                        method="POST",
                        body={"agent_id": "issue88-remote-detached-restored"},
                        extra_headers={
                            "Idempotency-Key": "issue88-remote-detached-restore"
                        },
                    )
                )
                rid = restored["id"]
                self.assertNotEqual(rid, wid)
                self.assertEqual(restored["state"], "ready")
                self.assertEqual(
                    (restored["owner"], restored["repository"], restored["agent_id"]),
                    ("alice", "demo", "issue88-remote-detached-restored"),
                )
                self.assertEqual(
                    json.loads(h.expect(f"/api/workspaces/{rid}", 200, token=h.alice))[
                        "id"
                    ],
                    rid,
                )
                self.assertTrue(
                    (dest_data / "workspace-service/checkpoints" / cid).is_dir()
                )
                self.assertTrue(
                    (quarantine / "workspace-service/checkpoints" / cid).is_dir()
                )
                self.assertFalse(source_data.exists())

                native_root = dest_data / "workspace-service/workspaces" / rid
                self.assertTrue(native_root.is_dir())
                self.assertFalse(native_root.is_symlink())
                self.assertEqual(
                    native_root.parent,
                    dest_data / "workspace-service/workspaces",
                )
                self.assertTrue(
                    str(native_root.resolve()).startswith(
                        str(dest_data.resolve()) + os.sep
                    )
                )

                # (9) Native Git checks bind to the destination workspace. The
                # tracked checked-in build witness is then compiled and run
                # against restored source/artifact bytes, with its cache outside
                # the worktree. The checks are repeated afterward to show the
                # build left Git state side-effect-free.
                self.assert_native_workspace(h, native_root, base_oid, expected)
                build_env = self.native_env(h)
                build_env["PYTHONPYCACHEPREFIX"] = str(h.root / "destination-pycache")
                build_env["PYTHONDONTWRITEBYTECODE"] = "1"
                h.run(
                    [sys.executable, "-m", "py_compile", BUILD_NAME],
                    cwd=native_root,
                    env=build_env,
                )
                self.assertTrue(
                    any((h.root / "destination-pycache").rglob("*.pyc")),
                    "the restored tracked build source was not compiled",
                )
                built = h.run(
                    [sys.executable, BUILD_NAME],
                    cwd=native_root,
                    env=build_env,
                )
                self.assertEqual(built.stdout, BUILD_MARKER)
                self.assert_native_workspace(h, native_root, base_oid, expected)
            finally:
                h.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
