#!/usr/bin/env python3
"""Child-subreaper wrapper for Patroni nodes in the native HA fixture.

In managed containers PID 1 may not reap orphaned grandchildren.  `pg_ctl`
puts the PostgreSQL postmaster into its own session and exits, so a stopped
postmaster is reparented to PID 1 and becomes a permanent zombie.  Patroni's
`demote('offline')` then blocks forever in `psutil.wait_pid` during the DCS
outage drill and never restarts PostgreSQL after the quorum returns.

This wrapper marks itself as a Linux child subreaper (prctl) and reaps every
reparented descendant while the Patroni child runs, so the fixture observes
real Patroni role-transition semantics on this host.  It is a test-harness
process-hygiene helper only; it does not change Patroni, PostgreSQL or any
production configuration.
"""
import ctypes
import os
import signal
import subprocess
import sys

PR_SET_CHILD_SUBREAPER = 36


def main():
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")
    except (OSError, AttributeError) as error:
        print(f"ha_reaper: cannot become child subreaper: {error}", file=sys.stderr)
        return 111
    # The fixture stops the whole process group.  Patroni handles SIGTERM
    # (graceful Patroni/PG shutdown); the reaper only needs to keep reaping.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child = subprocess.Popen(sys.argv[1:])
    while True:
        try:
            pid, status = os.waitpid(-1, 0)
        except ChildProcessError:
            # Patroni already exited and everything was reaped.
            return child.poll() if child.poll() is not None else 0
        if pid == child.pid:
            code = os.waitstatus_to_exitcode(status)
            while True:
                try:
                    extra, _ = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    extra = 0
                if extra == 0:
                    break
            return code


if __name__ == "__main__":
    sys.exit(main())
