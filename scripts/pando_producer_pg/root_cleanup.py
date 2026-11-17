"""Budget-aware removal of one exact-owned private root.

The parent re-verifies the ``OwnedRoot`` creation proof (parent directory, exact
name/prefix, uid and device/inode) before it starts a child.  The child repeats
the device/inode proof, removes exactly that resolved directory and exits only
after its own absence check.  The parent bounds the child by the remaining
overall deadline, always owns and reaps the ``Popen``, and reports the actual
absence result even when the child times out.  No fallback, retry or foreign
path deletion exists.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import time

from .errors import RunnerError
from .process import ProcessRunner

CHILD_SCRIPT = Path(__file__).with_name("root_remove_child.py")
REAP_RESERVE_SECONDS = 2.0


def _result(removed, code=None, within_deadline=False):
    return {
        "removed": bool(removed),
        "absent": bool(removed),
        "verified": bool(removed) and code is None,
        "code": code,
        "within_deadline": bool(within_deadline),
    }


def _resolve_owned(root):
    """Return ``(resolved, present, code)`` without deleting anything."""
    path = getattr(root, "path", None)
    proof = getattr(root, "creation_proof", None)
    if path is None or not isinstance(proof, dict):
        return None, False, "root_cleanup_unresolved"
    try:
        resolved = Path(path).resolve()
    except OSError:
        return None, False, "root_path_unresolved"
    try:
        base = Path(proof["base"]).resolve()
        name = proof["name"]
        prefix = proof["prefix"]
    except (KeyError, TypeError):
        return None, False, "root_creation_proof_missing"
    if resolved.parent != base:
        return None, False, "root_path_parent_mismatch"
    if resolved.name != name or not resolved.name.startswith(prefix):
        return None, False, "root_path_prefix_mismatch"
    if not os.path.lexists(resolved):
        return resolved, False, None
    device = proof.get("st_dev")
    inode = proof.get("st_ino")
    if not isinstance(device, int) or not isinstance(inode, int):
        return None, True, "root_identity_unresolved"
    try:
        current = resolved.stat()
    except OSError:
        return None, True, "root_identity_unreadable"
    if not stat.S_ISDIR(current.st_mode):
        return None, True, "root_identity_mismatch"
    if current.st_uid != os.getuid():
        return None, True, "root_ownership_mismatch"
    if current.st_dev != device or current.st_ino != inode:
        return None, True, "root_identity_mismatch"
    return resolved, True, None


class BoundedRootRemover:
    """Remove one verified owned root through one bounded, reaped child."""

    def __init__(self, clock=time.monotonic, process_runner=None):
        self.clock = clock
        self.process_runner = process_runner or ProcessRunner(clock=clock)

    def remove(self, root, deadline):
        if not getattr(root, "created", False):
            return _result(True, within_deadline=self.clock() <= deadline)
        resolved, present, code = _resolve_owned(root)
        if code is not None:
            return _result(False, code, self.clock() <= deadline)
        if not present:
            return _result(True, within_deadline=self.clock() <= deadline)
        remaining = deadline - self.clock()
        if remaining <= REAP_RESERVE_SECONDS:
            return _result(False, "root_cleanup_deadline_exceeded", False)
        proof = root.creation_proof
        try:
            completed = self.process_runner.run(
                [
                    sys.executable,
                    str(CHILD_SCRIPT),
                    str(resolved),
                    str(proof["st_dev"]),
                    str(proof["st_ino"]),
                ],
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "LC_ALL": "C",
                },
                timeout=remaining - REAP_RESERVE_SECONDS,
                stage="cleanup",
                timeout_code="root_remove_timeout",
                spawn_code="root_remove_failed",
            )
        except RunnerError as error:
            absent = not os.path.lexists(resolved)
            code = (
                "root_cleanup_deadline_exceeded"
                if error.code in ("root_remove_timeout", "process_unreaped")
                else "root_remove_unverified"
            )
            return _result(absent, code, self.clock() <= deadline)
        absent = not os.path.lexists(resolved)
        if completed.returncode != 0:
            return _result(absent, "root_remove_unverified", self.clock() <= deadline)
        if not absent:
            return _result(False, "root_remove_unverified", self.clock() <= deadline)
        return _result(True, within_deadline=self.clock() <= deadline)
