#!/usr/bin/env python3
"""Genuine format12/schema136 archive upgraded to the schema137 target.

Reuses the shared legacy-archive harness with the coordinator-provided
schema136 binary. The legacy binary creates and backs up the archive; the
candidate can restore it only with ``--allow-legacy-schema136`` and then applies
migration 137 (the terminal-admission projection guard) in the restore session.
This file is an entry point only; the operator runs the native drill.
"""
from backup_legacy132_sessions import LEGACY136, run_main


def main():
    return run_main(LEGACY136)


if __name__ == "__main__":
    raise SystemExit(main())
