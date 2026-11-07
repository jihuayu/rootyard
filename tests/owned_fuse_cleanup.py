#!/usr/bin/env python3
"""Force-release FUSE mounts owned by a crashed native test fixture.

A killed service can keep a kernel thread blocked in
``fuse_request_wait_answer`` while the same process is also the FUSE daemon for
a client thread.  The mount then never sees a graceful ``umount``, the
descriptor stays open, and ``waitpid`` never returns.  A plain lazy unmount
(``fusermount -uz`` / ``umount -l``) detaches the tree but does not abort the
pending request, so the blocked task keeps the process alive.

This module is a fixture-cleanup helper, not a test module.  It is called only
after the harness has already sent SIGKILL to the process group it created and
the first bounded ``Popen.wait`` has timed out.  It never unmounts before the
kill, so it cannot mask a crash as a graceful shutdown.

Scope of the reclaim:

* only the harness's own ``Popen`` child, still unreaped, and only when it is
  the leader of its own process group (``os.getpgid(pid) == pid``);
* only mounts visible in ``/proc/<pid>/task/<tid>/mountinfo``, i.e. the private
  user/mount namespace the fixture created with ``unshare -Urm``;
* only ``fuse``/``fuse.*`` filesystems whose source is exactly
  ``rootyard-workspace``;
* only mountpoints that are, lexically, exactly
  ``<data dir>/workspace-service/mounts/<canonical UUID>`` where the data dir
  is the harness's ``ROOTYARD_DATA_DIR`` or its ``second-volume`` sibling and
  is still inside ``h.root``.

Paths are never resolved through the (possibly wedged) mount: no
``realpath``/``resolve``/``stat`` is used, so a symlink or an escaping path can
never redirect the unmount outside the fixture.  Nothing host-global is
touched: no ``/proc/mounts`` scanning, no sysfs, no docker, no fusectl.
"""
import errno
import os
import posixpath
import subprocess
import uuid

FUSE_SOURCE = "rootyard-workspace"
MAX_TIDS = 64
MAX_MOUNTS = 16
UMOUNT_TIMEOUT_SECONDS = 5


class Mount:
    __slots__ = ("mountpoint", "fstype", "source", "tid")

    def __init__(self, mountpoint, fstype, source, tid):
        self.mountpoint = mountpoint
        self.fstype = fstype
        self.source = source
        self.tid = tid

    def __repr__(self):
        return "Mount(mountpoint=%r, fstype=%r, source=%r, tid=%r)" % (
            self.mountpoint, self.fstype, self.source, self.tid)


def _decode_field(value):
    """Decode mountinfo octal escapes (\\040, \\011, \\012, \\134)."""
    raw = value.encode("utf-8", "surrogateescape")
    out = bytearray()
    index = 0
    while index < len(raw):
        if (raw[index:index + 1] == b"\\" and index + 3 < len(raw)
                and all(0x30 <= byte <= 0x37 for byte in raw[index + 1:index + 4])):
            out.append(int(raw[index + 1:index + 4], 8))
            index += 4
        else:
            out.append(raw[index])
            index += 1
    return out.decode("utf-8", "surrogateescape")


def parse_mountinfo(text, tid):
    """Yield ``Mount`` records from one mountinfo blob.

    Fields are: id parent major:minor root mountpoint options [optional...]
    ``-`` fstype source super-options.  Malformed lines are rejected instead of
    guessed at.
    """
    for line in text.splitlines():
        fields = line.split(" ")
        if len(fields) < 10 or "-" not in fields:
            continue
        separator = fields.index("-")
        if separator < 6 or separator + 2 >= len(fields):
            continue
        mountpoint = _decode_field(fields[4])
        fstype = _decode_field(fields[separator + 1])
        source = _decode_field(fields[separator + 2])
        yield Mount(mountpoint, fstype, source, tid)


def is_fuse_type(fstype):
    return fstype == "fuse" or fstype.startswith("fuse.")


def allowed_mount_roots(harness):
    """Data directories whose ``workspace-service/mounts`` may be reclaimed."""
    root = posixpath.normpath(str(harness.root))
    roots = []
    for candidate in (str(harness.root / "data"), str(harness.root / "second-volume"),
                      (harness.env or {}).get("ROOTYARD_DATA_DIR")):
        if not candidate:
            continue
        candidate = posixpath.normpath(str(candidate))
        if candidate in roots or not (candidate == root or candidate.startswith(root + "/")):
            continue
        roots.append(candidate)
    return roots


def _owned_mountpoint(mountpoint, roots):
    """Return the canonical UUID directory if this mountpoint is fixture-owned."""
    if not mountpoint.startswith("/"):
        return None
    normalized = posixpath.normpath(mountpoint)
    if normalized != mountpoint:
        # No "./", "//", "/../" or trailing slash accepted.
        return None
    for root in roots:
        prefix = root + "/workspace-service/mounts/"
        if not normalized.startswith(prefix):
            continue
        name = normalized[len(prefix):]
        if "/" in name or name in ("", ".", ".."):
            continue
        try:
            if str(uuid.UUID(name)) != name:
                continue
        except (ValueError, AttributeError):
            continue
        return normalized
    return None


def owned_mounts(harness):
    """Collect fixture-owned FUSE mounts from the killed process's TIDs.

    Returns a list of ``Mount`` objects, de-duplicated by mountpoint, retaining
    the TID whose mount namespace reported it (used later for ``nsenter``).
    """
    proc = getattr(harness, "proc", None)
    if proc is None or proc.pid <= 0 or proc.returncode is not None:
        return []
    try:
        if os.getpgid(proc.pid) != proc.pid:
            return []
    except OSError:
        return []
    task_dir = "/proc/%d/task" % proc.pid
    try:
        tids = sorted(entry for entry in os.listdir(task_dir) if entry.isdigit())
    except OSError:
        return []
    if len(tids) > MAX_TIDS:
        raise RuntimeError("Owned fixture has more than %d threads; refusing an unbounded scan" % MAX_TIDS)
    roots = allowed_mount_roots(harness)
    found = {}
    for tid in tids:
        try:
            with open("/proc/%d/task/%s/mountinfo" % (proc.pid, tid), "r",
                      encoding="utf-8", errors="surrogateescape") as handle:
                text = handle.read(1 << 20)
        except OSError:
            continue
        for mount in parse_mountinfo(text, int(tid)):
            if not is_fuse_type(mount.fstype) or mount.source != FUSE_SOURCE:
                continue
            mountpoint = _owned_mountpoint(mount.mountpoint, roots)
            if mountpoint is None:
                continue
            found.setdefault(mountpoint, Mount(mountpoint, mount.fstype, mount.source, int(tid)))
            if len(found) > MAX_MOUNTS:
                raise RuntimeError("Owned fixture has more than %d FUSE mounts; refusing an unbounded reclaim" % MAX_MOUNTS)
    return [found[key] for key in sorted(found)]


def umount_command(tid, mountpoint):
    """Force and lazy unmount ``mountpoint`` inside the fixture's namespaces.

    ``-f`` aborts pending FUSE requests (a plain ``-l`` would leave the kernel
    waiter blocked); the namespace entry points come from the process that owns
    the mount, so neither mount nor user namespace is the host's.
    """
    return ["nsenter", "--preserve-credentials",
            "--user=/proc/%d/ns/user" % tid, "--mount=/proc/%d/ns/mnt" % tid,
            "--", "umount", "-f", "-l", "--", mountpoint]


def release_owned_fuse_mounts(harness, run=subprocess.run):
    """Force-release fixture FUSE mounts after SIGKILL and a timed-out wait.

    Callers must have already sent SIGKILL and observed the first bounded wait
    expiry; this function is not a graceful shutdown path.  Any unmount failure
    raises ``RuntimeError`` so an unreapable process is never reported as
    success.  Returns the mountpoints that were released.
    """
    mounts = owned_mounts(harness)
    released = []
    failures = []
    for mount in mounts:
        argv = umount_command(mount.tid, mount.mountpoint)
        try:
            result = run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=UMOUNT_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired:
            failures.append("%s: force umount timed out after %ds" % (mount.mountpoint, UMOUNT_TIMEOUT_SECONDS))
            continue
        except OSError as error:
            failures.append("%s: force umount could not run: %s" % (mount.mountpoint, error))
            continue
        if result.returncode != 0:
            detail = (result.stderr or b"").decode("utf-8", "replace")[-400:]
            failures.append("%s: force umount exited %d: %s" % (mount.mountpoint, result.returncode, detail.strip()))
            continue
        released.append(mount.mountpoint)
    if failures:
        raise RuntimeError("Owned FUSE mount reclaim failed; kernel I/O may still be blocked: "
                           + "; ".join(failures))
    return released
