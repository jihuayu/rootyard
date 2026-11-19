#!/usr/bin/env python3
"""Exact-owned root remover executed as one bounded, polled child process.

The parent verifies the private root identity before spawning this helper.  The
helper re-verifies the same device/inode proof before removing anything, so a
replaced or foreign path is left untouched.  It is intentionally standalone and
prints nothing; the parent owns the timeout, kill and reap.
"""
from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

EXIT_INVALID = 2
EXIT_IDENTITY = 3
EXIT_REMOVE_FAILED = 4
EXIT_REMOVE_UNVERIFIED = 5


def _verify(path, device, inode):
    try:
        resolved = Path(path).resolve()
        current = resolved.stat()
    except OSError:
        return None
    if not stat.S_ISDIR(current.st_mode):
        return None
    if str(current.st_dev) != device or str(current.st_ino) != inode:
        return None
    return resolved


def main(argv):
    if len(argv) != 4:
        return EXIT_INVALID
    path, device, inode = argv[1], argv[2], argv[3]
    resolved = _verify(path, device, inode)
    if resolved is None:
        return EXIT_IDENTITY
    try:
        shutil.rmtree(resolved)
    except OSError:
        return EXIT_REMOVE_FAILED
    if os.path.lexists(resolved):
        return EXIT_REMOVE_UNVERIFIED
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
