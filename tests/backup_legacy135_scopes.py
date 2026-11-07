#!/usr/bin/env python3
"""Genuine format11/schema135 archive upgraded to the schema136 target.

Light entry point over the shared ``backup_legacy132_sessions`` harness. The
trusted ``observability135-v2`` binary writes an unmodified format11/schema135
archive; the candidate must reject it without ``--allow-legacy-schema135``,
accept it only with that exact opt-in, apply reviewed migration 136, and retain
the existing schema133 GC indexes, schema134 identity foreign keys and
schema135 metrics index. The restored schema must add the token scope
columns/tables while every pre-migration token keeps ``is_restricted = false``.

Only random task-owned databases and temporary storage are used. This worker
does not build or run the legacy binary.
"""
import sys

from backup_legacy132_sessions import LEGACY135, run_main


if __name__ == "__main__":
    sys.exit(run_main(LEGACY135))
