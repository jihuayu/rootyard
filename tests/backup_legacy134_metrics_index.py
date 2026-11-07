#!/usr/bin/env python3
"""Genuine format10/schema134 archive upgraded by the current schema135 binary.

This is the light entry point built on the shared
``backup_legacy132_sessions.ArchiveContract`` harness.  The trusted
``security134-v1`` binary creates two real repositories, pushes Git history
through the stock server, performs the real Pando cutovers and writes an
unmodified offline archive (format 10, schema versions through 134).  The
candidate must reject that archive by default and with the wrong legacy opt-in,
accept it only with ``--allow-legacy-schema134``, restore into a fresh isolated
database/data directory, apply the reviewed schema135 migration, verify the new
partial metrics index together with the six GC indexes, rotate exactly one Pando
authority, reject the pre-backup browser cookie while accepting the API token,
and serve stock Git clone/fetch/fsck for both repositories.

Only random task-owned databases and temporary storage are used.  Secrets,
DSNs, raw HTTP logs and Garage/Vault credentials are never printed.  The
coordinator supplies and compiles ``--legacy-binary``; this worker does not
build or run it.
"""
import sys

from backup_legacy132_sessions import LEGACY134, run_main


if __name__ == "__main__":
    sys.exit(run_main(LEGACY134))
