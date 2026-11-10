#!/usr/bin/env python3
"""Restore a genuine schema137/format13 archive into schema139/format15.

The shared harness requires the unmodified predecessor binary to create the
archive, rejects absent or mismatched legacy opt-ins, and checks restored Git,
authority rotation, session revocation and newly installed operation tables.
"""
import sys
from backup_legacy132_sessions import LEGACY137, run_main

if __name__ == "__main__":
    sys.exit(run_main(LEGACY137))
