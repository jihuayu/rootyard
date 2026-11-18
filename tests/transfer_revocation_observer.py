#!/usr/bin/env python3
"""Owned process-group observation for Issue #37 transfer timing.

The observer reads only ``/proc/<pid>/stat`` and directory ownership. It never
reads process environments or command lines. A transfer group is discovered from
a live service descendant, then every member of that PGID is tracked, including
non-Git descendants that may be reparented during cleanup.
"""
from collections import defaultdict
from dataclasses import dataclass, field
import os
from pathlib import Path
import threading
import time


PROC_ROOT = Path("/proc")
NON_RUNNING_STATES = frozenset({"Z", "X", "x"})


class ObserverUnavailable(RuntimeError):
    """The fixture could not establish process evidence; never a pass."""


@dataclass(frozen=True)
class ProcStat:
    pid: int
    state: str
    ppid: int
    pgid: int
    starttime: int

    @property
    def live(self):
        return self.state not in NON_RUNNING_STATES


def parse_proc_stat(text, pid=None):
    """Parse the fields needed for identity from one ``/proc/<pid>/stat``."""
    left, separator, rest = text.rpartition(") ")
    if not separator:
        raise ValueError("invalid proc stat")
    prefix, _, _comm = left.partition(" (")
    actual_pid = int(prefix) if pid is None else int(pid)
    fields = rest.split()
    if len(fields) < 20:
        raise ValueError("invalid proc stat")
    return ProcStat(
        pid=actual_pid,
        state=fields[0],
        ppid=int(fields[1]),
        pgid=int(fields[2]),
        starttime=int(fields[19]),
    )


def read_proc_table(proc_root=PROC_ROOT, uid=None):
    """Read owned process identity only; no env, cmdline, or fd data."""
    root = Path(proc_root)
    try:
        entries = list(root.iterdir())
    except OSError as error:
        raise ObserverUnavailable("proc directory unreadable") from error
    table = {}
    for entry in entries:
        if not entry.name.isdigit():
            continue
        if uid is not None:
            try:
                metadata = entry.stat()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise ObserverUnavailable("proc metadata unreadable") from error
            if metadata.st_uid != uid:
                continue
        try:
            text = (entry / "stat").read_text(encoding="utf-8")
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise ObserverUnavailable("proc stat unreadable") from error
        try:
            table[int(entry.name)] = parse_proc_stat(text)
        except (ValueError, IndexError) as error:
            raise ObserverUnavailable("proc stat invalid") from error
    return table


def descendant_pids(table, roots):
    """Return live or dead descendants of the service roots by PPID only."""
    children = defaultdict(list)
    for process in table.values():
        children[process.ppid].append(process.pid)
    seen = set()
    stack = list(roots)
    while stack:
        parent = stack.pop()
        for child in children.get(parent, ()):
            if child not in seen:
                seen.add(child)
                stack.append(child)
    return seen


@dataclass(frozen=True)
class GroupIdentity:
    pgid: int
    leader_pid: int
    leader_starttime: int


def discover_groups(table, service_pids, exclude_pgids=()):
    """Find live process groups led by a descendant of a fixture service."""
    roots = set(service_pids)
    descendants = descendant_pids(table, roots)
    excluded = set(exclude_pgids)
    groups = {}
    for pid in descendants:
        process = table.get(pid)
        if process is None or not process.live or process.pgid <= 0:
            continue
        if process.pgid in excluded:
            continue
        leader = table.get(process.pgid)
        if leader is None or leader.pgid != process.pgid:
            continue
        if leader.pid not in descendants:
            continue
        groups[process.pgid] = GroupIdentity(process.pgid, leader.pid, leader.starttime)
    return [groups[pgid] for pgid in sorted(groups)]


def group_members(table, pgid):
    return [process for process in table.values() if process.pgid == pgid]


def leader_reused(identity, table):
    """A changed leader starttime is PGID reuse, never a successful stop."""
    leader = table.get(identity.leader_pid)
    return leader is not None and leader.starttime != identity.leader_starttime


@dataclass
class GroupTrack:
    identity: GroupIdentity
    first_live_ns: int = 0
    last_live_ns: int = 0
    quiescent_ns: int = 0
    max_members: int = 0
    reuse_detected: bool = False

    def observe(self, members, now_ns):
        if members:
            if self.quiescent_ns:
                self.reuse_detected = True
            if not self.first_live_ns:
                self.first_live_ns = now_ns
            self.last_live_ns = now_ns
            self.max_members = max(self.max_members, len(members))
        elif not self.quiescent_ns:
            self.quiescent_ns = now_ns


class ProcGroupObserver:
    """Poll one or more owned transfer groups from before trigger to stop."""

    def __init__(self, service_pids, *, proc_root=PROC_ROOT, uid=None,
                 interval_s=0.01, clock=time.monotonic_ns):
        self.service_pids = tuple(service_pids)
        self.proc_root = Path(proc_root)
        self.uid = os.geteuid() if uid is None else uid
        self.interval_ns = int(interval_s * 1_000_000_000)
        self.clock = clock
        self.identities = ()
        self.armed_ns = 0
        self.capture_error = None
        self.max_poll_gap_ns = 0
        self.unavailable_reason = None
        self._tracks = {}
        self._stop = threading.Event()
        self._thread = None
        self._last_poll_ns = 0
        self._lock = threading.Lock()

    def arm(self, *, exclude_pgids=(), require=True, timeout_s=2.0):
        deadline = self.clock() + int(timeout_s * 1_000_000_000)
        last_error = None
        while True:
            try:
                table = read_proc_table(self.proc_root, uid=self.uid)
            except ObserverUnavailable as error:
                last_error = error
                table = {}
            identities = discover_groups(table, self.service_pids, exclude_pgids)
            if identities:
                self.identities = tuple(identities)
                self.armed_ns = self.clock()
                self._tracks = {
                    identity.pgid: GroupTrack(
                        identity=identity,
                        first_live_ns=self.armed_ns,
                        last_live_ns=self.armed_ns,
                    )
                    for identity in identities
                }
                return self
            if self.clock() >= deadline:
                break
            time.sleep(self.interval_ns / 1_000_000_000)
        if require:
            if last_error is not None:
                raise ObserverUnavailable("owned transfer group unobservable") from last_error
            raise AssertionError("no owned transfer group observed before trigger")
        self.armed_ns = self.clock()
        return self

    def start(self, *, max_duration_s=10.0):
        if self._thread is not None:
            raise RuntimeError("observer already started")
        self._thread = threading.Thread(target=self._run, args=(max_duration_s,),
                                        name="revocation-group-observer", daemon=True)
        self._thread.start()
        return self

    def sample_once(self):
        """Synchronously confirm the group is live immediately before trigger."""
        table = read_proc_table(self.proc_root, uid=self.uid)
        now_ns = self.clock()
        with self._lock:
            if self._last_poll_ns:
                self.max_poll_gap_ns = max(self.max_poll_gap_ns,
                                           now_ns - self._last_poll_ns)
            self._last_poll_ns = now_ns
            for pgid, track in tuple(self._tracks.items()):
                if leader_reused(track.identity, table):
                    track.reuse_detected = True
                members = [process for process in group_members(table, pgid) if process.live]
                track.observe(members, now_ns)

    def _run(self, max_duration_s):
        deadline = self.clock() + int(max_duration_s * 1_000_000_000)
        while not self._stop.is_set() and self.clock() < deadline:
            try:
                self.sample_once()
            except ObserverUnavailable:
                with self._lock:
                    self.unavailable_reason = "proc unobservable"
                return
            time.sleep(self.interval_ns / 1_000_000_000)

    @property
    def all_quiescent(self):
        return bool(self._tracks) and all(track.quiescent_ns for track in self._tracks.values())

    def wait_quiescent(self, *, timeout_s=2.5):
        deadline = self.clock() + int(timeout_s * 1_000_000_000)
        while self.clock() < deadline:
            if self.all_quiescent:
                return True
            time.sleep(self.interval_ns / 1_000_000_000)
        return self.all_quiescent

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def proven(self, lower_bound_ns, deadline_ns):
        if self.capture_error or self.unavailable_reason or not self._tracks:
            return False
        if not self.armed_ns or self.armed_ns > lower_bound_ns:
            return False
        for track in self._tracks.values():
            if track.reuse_detected or not track.quiescent_ns or not track.last_live_ns:
                return False
            if track.quiescent_ns < lower_bound_ns or track.quiescent_ns > deadline_ns:
                return False
            # The group was observed live close enough before the trigger.
            if track.last_live_ns + max(self.max_poll_gap_ns, self.interval_ns) < lower_bound_ns:
                return False
        return True

    def stop_upper_ns(self):
        if not self._tracks or any(not track.quiescent_ns for track in self._tracks.values()):
            return None
        return max(track.quiescent_ns for track in self._tracks.values())

    def wait_no_live(self, *, timeout_s=2.5):
        deadline = self.clock() + int(timeout_s * 1_000_000_000)
        while self.clock() < deadline:
            table = read_proc_table(self.proc_root, uid=self.uid)
            live = []
            for track in self._tracks.values():
                members = [process for process in group_members(table, track.identity.pgid) if process.live]
                if members:
                    live.append(track.identity.pgid)
            if not live:
                return True
            time.sleep(self.interval_ns / 1_000_000_000)
        raise AssertionError("owned transfer process group remained live after observation")

    def report(self, lower_bound_ns):
        upper = self.stop_upper_ns()
        groups = []
        for track in sorted(self._tracks.values(), key=lambda item: item.identity.pgid):
            groups.append({
                "pgid": track.identity.pgid,
                "leader_starttime": track.identity.leader_starttime,
                "members_observed_max": track.max_members,
                "first_live_ns": track.first_live_ns or None,
                "last_live_ns": track.last_live_ns or None,
                "quiescent_ns": track.quiescent_ns or None,
                "last_live_after_lower_ms": (
                    round((track.last_live_ns - lower_bound_ns) / 1_000_000, 3)
                    if track.last_live_ns else None
                ),
                "quiescent_after_lower_ms": (
                    round((track.quiescent_ns - lower_bound_ns) / 1_000_000, 3)
                    if track.quiescent_ns else None
                ),
                "reuse_detected": track.reuse_detected,
            })
        return {
            "armed": bool(self.armed_ns),
            "groups": groups,
            "stop_upper_ns": upper,
            "stop_upper_after_lower_ms": (
                round((upper - lower_bound_ns) / 1_000_000, 3) if upper is not None else None
            ),
            "max_poll_gap_ms": round(self.max_poll_gap_ns / 1_000_000, 3),
            "unobservable": self.unavailable_reason,
        }

def wait_for_quiescence_until(observer, deadline_ns, *, clock=time.monotonic_ns,
                              interval_ns=10_000_000, sleep=time.sleep):
    """Wait to one fixed absolute deadline; never extend on a later time read."""
    while True:
        now_ns = clock()
        if observer.all_quiescent:
            return True
        if now_ns >= deadline_ns:
            return False
        remaining_ns = deadline_ns - now_ns
        sleep(min(interval_ns, remaining_ns) / 1_000_000_000)
