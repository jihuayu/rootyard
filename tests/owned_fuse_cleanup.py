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
  ``rootyard-workspace`` and whose mount ID is recorded from that mountinfo;
* only mountpoints that are, lexically, exactly
  ``<data dir>/workspace-service/mounts/<canonical UUID>`` where the data dir
  is the harness's ``ROOTYARD_DATA_DIR`` or its ``second-volume`` sibling and
  is still inside ``h.root``.

Paths are never resolved through the (possibly wedged) mount: no
``realpath``/``resolve``/``stat``/``lstat``/``statfs`` is used.  Lexical
matching alone is not authorization, though: a path component can be replaced
with a symlink between the mountinfo read and the unmount.  The actual unmount
therefore runs inside the fixture's own namespaces (via ``nsenter``) and the
inner helper opens the mountpoint one component at a time with
``O_PATH|O_DIRECTORY|O_NOFOLLOW`` relative to an already-open parent directory.
A leaf symlink is rejected with ``ENOTDIR`` and no umount is attempted.  The
resulting directory FD must still report the recorded mount ID in
``/proc/self/fdinfo`` and the same ID must still be the expected
``rootyard-workspace`` FUSE mount in this namespace's ``/proc/self/mountinfo``.
The unmount is then issued against ``/proc/self/fd/<fd>`` with
``--no-canonicalize`` and ``pass_fds`` so the kernel unmounts the object bound
to that descriptor rather than re-traversing a replaceable path.

Both the outer ``nsenter`` and the inner ``umount`` run with a minimal
environment (``PATH=os.defpath``, ``LC_ALL=C``); database, object-storage and
API credentials from the test harness are never inherited.  Nothing
host-global is touched: no ``/proc/mounts`` scanning, no sysfs, no docker, no
fusectl.
"""
import errno
import os
import posixpath
import subprocess
import sys
import uuid

FUSE_SOURCE = "rootyard-workspace"
MAX_TIDS = 64
MAX_MOUNTS = 16
HELPER_TIMEOUT_SECONDS = 5

# O_PATH lets us bind the mountpoint without opening a FUSE file.  O_DIRECTORY
# plus O_NOFOLLOW make every walk component reject symlinks (a symlink opened
# with O_PATH|O_NOFOLLOW would name the link itself, but O_DIRECTORY rejects it
# because the link is not a directory).  O_CLOEXEC is cleared only for the
# exact descriptor handed to umount via pass_fds.
_O_PATH = getattr(os, "O_PATH", 0o10000000)
_DIR_FLAGS = _O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

_HELPER_SCRIPT = os.path.abspath(__file__)


def helper_env():
    """The only environment any cleanup child may see."""
    return {"PATH": os.defpath, "LC_ALL": "C"}


class Mount:
    __slots__ = ("mount_id", "mountpoint", "fstype", "source", "tid")

    def __init__(self, mount_id, mountpoint, fstype, source, tid):
        self.mount_id = mount_id
        self.mountpoint = mountpoint
        self.fstype = fstype
        self.source = source
        self.tid = tid

    def __repr__(self):
        return ("Mount(mount_id=%r, mountpoint=%r, fstype=%r, source=%r, tid=%r)"
                % (self.mount_id, self.mountpoint, self.fstype, self.source, self.tid))


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
        if not fields[0].isdigit():
            continue
        mount_id = int(fields[0])
        mountpoint = _decode_field(fields[4])
        fstype = _decode_field(fields[separator + 1])
        source = _decode_field(fields[separator + 2])
        yield Mount(mount_id, mountpoint, fstype, source, tid)


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

    Returns a list of ``Mount`` objects (mount ID included), de-duplicated by
    mountpoint, retaining the TID whose mount namespace reported it (used later
    for ``nsenter``).  A mountpoint seen with two different mount IDs is
    treated as a race and refused rather than guessed at.
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
            existing = found.get(mountpoint)
            if existing is not None:
                if existing.mount_id != mount.mount_id:
                    raise RuntimeError("Owned mountpoint %s changed mount ID while scanning TIDs"
                                       % mountpoint)
                continue
            found[mountpoint] = Mount(mount.mount_id, mountpoint, mount.fstype,
                                      mount.source, int(tid))
            if len(found) > MAX_MOUNTS:
                raise RuntimeError("Owned fixture has more than %d FUSE mounts; refusing an unbounded reclaim" % MAX_MOUNTS)
    return [found[key] for key in sorted(found)]


def open_mountpoint_fd(mountpoint, roots):
    """Open ``mountpoint`` as an O_PATH directory FD without following links.

    Every component is opened relative to its parent FD with
    ``O_PATH|O_DIRECTORY|O_NOFOLLOW``, starting at ``/``.  No FUSE file is
    read, no ``statfs``/``resolve``/``lstat`` is performed, and a symlink at
    any component (including the leaf) fails with ``ENOTDIR``/``ELOOP``.
    """
    normalized = _owned_mountpoint(mountpoint, roots)
    if normalized is None:
        raise RuntimeError("Refusing to open mountpoint outside the fixture-owned "
                           "workspace-service/mounts UUID layout: %r" % (mountpoint,))
    fd = os.open("/", _DIR_FLAGS)
    try:
        for component in (part for part in normalized.split("/") if part):
            if component in (".", ".."):
                raise RuntimeError("Refusing suspicious mountpoint component %r" % (component,))
            child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_mnt_id(fd):
    """Read ``mnt_id`` for an open FD from procfs (no filesystem access)."""
    try:
        with open("/proc/self/fdinfo/%d" % fd, "r", encoding="utf-8",
                  errors="surrogateescape") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if key == "mnt_id":
                    return int(value.strip())
    except OSError as error:
        raise RuntimeError("Could not read mnt_id for FD %d: %s" % (fd, error)) from error
    raise RuntimeError("No mnt_id reported for FD %d" % fd)


def verify_namespace_mount(mount_id, mountpoint, source, fstype):
    """Confirm this namespace still has ``mount_id`` as the expected mount."""
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8",
                  errors="surrogateescape") as handle:
            text = handle.read(1 << 20)
    except OSError as error:
        raise RuntimeError("Could not read namespace mountinfo: %s" % error) from error
    for mount in parse_mountinfo(text, 0):
        if mount.mount_id != mount_id:
            continue
        if mount.mountpoint != mountpoint:
            raise RuntimeError("Mount ID %d is now %r, not the owned mountpoint %r"
                               % (mount_id, mount.mountpoint, mountpoint))
        if not is_fuse_type(mount.fstype) or mount.fstype != fstype:
            raise RuntimeError("Mount ID %d is now %r, not the expected FUSE type %r"
                               % (mount_id, mount.fstype, fstype))
        if mount.source != source or source != FUSE_SOURCE:
            raise RuntimeError("Mount ID %d source is %r, not the owned source %r"
                               % (mount_id, mount.source, FUSE_SOURCE))
        return
    raise RuntimeError("Mount ID %d is no longer present in this namespace" % mount_id)


def umount_fd_command(fd):
    """Build the GNU umount argv that unmounts the object bound to ``fd``.

    ``--no-canonicalize`` (-c) stops umount from resolving ``/proc/self/fd/N``
    back to a replaceable path; the kernel resolves the magic link directly to
    the opened mountpoint.
    """
    return ["umount", "--no-canonicalize", "-f", "-l", "--", "/proc/self/fd/%d" % fd]


def helper_command(mount, roots):
    """Build the nsenter invocation running this file's inner ``--unmount`` mode."""
    argv = ["nsenter", "--preserve-credentials",
            "--user=/proc/%d/ns/user" % mount.tid,
            "--mount=/proc/%d/ns/mnt" % mount.tid,
            "--", sys.executable, _HELPER_SCRIPT,
            "--unmount", mount.mountpoint,
            "--mount-id", str(mount.mount_id),
            "--source", mount.source,
            "--fstype", mount.fstype]
    for root in roots:
        argv.extend(["--allowed-root", root])
    return argv


def _parse_unmount_args(argv):
    values = {"--unmount": None, "--mount-id": None, "--source": None, "--fstype": None}
    roots = []
    index = 0
    while index < len(argv):
        flag = argv[index]
        if index + 1 >= len(argv):
            raise ValueError("missing value for %s" % flag)
        value = argv[index + 1]
        if flag == "--allowed-root":
            roots.append(value)
        elif flag in values and values[flag] is None:
            values[flag] = value
        else:
            raise ValueError("unexpected argument %r" % flag)
        index += 2
    if any(value is None for value in values.values()) or not roots:
        raise ValueError("--unmount, --mount-id, --source, --fstype and at least one "
                         "--allowed-root are required")
    try:
        mount_id = int(values["--mount-id"])
    except ValueError:
        raise ValueError("--mount-id must be an integer") from None
    return (values["--unmount"], mount_id, values["--source"],
            values["--fstype"], roots)


def _unmount_main(argv):
    """Inner helper: validate, bind, verify and force-unmount one mountpoint."""
    try:
        mountpoint, mount_id, source, fstype, roots = _parse_unmount_args(argv)
    except ValueError as error:
        print("owned-fuse-cleanup: %s" % error, file=sys.stderr, flush=True)
        return 2
    fd = None
    try:
        fd = open_mountpoint_fd(mountpoint, roots)
        actual_id = read_mnt_id(fd)
        if actual_id != mount_id:
            raise RuntimeError("FD for %r has mnt_id %d, expected %d"
                               % (mountpoint, actual_id, mount_id))
        verify_namespace_mount(mount_id, mountpoint, source, fstype)
        result = subprocess.run(umount_fd_command(fd), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=helper_env(),
                                timeout=HELPER_TIMEOUT_SECONDS, check=False,
                                pass_fds=(fd,))
        if result.returncode != 0:
            detail = (result.stderr or b"").decode("utf-8", "replace")[-400:].strip()
            raise RuntimeError("force umount of %r exited %d: %s"
                               % (mountpoint, result.returncode, detail))
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("owned-fuse-cleanup: %s" % error, file=sys.stderr, flush=True)
        return 1
    finally:
        if fd is not None:
            os.close(fd)


def release_owned_fuse_mounts(harness, run=None):
    """Force-release fixture FUSE mounts after SIGKILL and a timed-out wait.

    Callers must have already sent SIGKILL and observed the first bounded wait
    expiry; this function is not a graceful shutdown path.  Each nsenter child
    gets a minimal environment and a bounded timeout.  Any failure raises
    ``RuntimeError`` so an unreapable process is never reported as success.
    Returns the mountpoints the inner helper released.
    """
    if run is None:
        run = subprocess.run
    mounts = owned_mounts(harness)
    roots = allowed_mount_roots(harness)
    released = []
    failures = []
    for mount in mounts:
        argv = helper_command(mount, roots)
        try:
            result = run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=HELPER_TIMEOUT_SECONDS, check=False,
                         env=helper_env())
        except subprocess.TimeoutExpired:
            failures.append("%s: cleanup helper timed out after %ds"
                            % (mount.mountpoint, HELPER_TIMEOUT_SECONDS))
            continue
        except OSError as error:
            failures.append("%s: cleanup helper could not run: %s" % (mount.mountpoint, error))
            continue
        if result.returncode != 0:
            detail = (result.stderr or b"").decode("utf-8", "replace")[-400:].strip()
            failures.append("%s: cleanup helper exited %d: %s"
                            % (mount.mountpoint, result.returncode, detail))
            continue
        released.append(mount.mountpoint)
    if failures:
        raise RuntimeError("Owned FUSE mount reclaim failed; kernel I/O may still be blocked: "
                           + "; ".join(failures))
    return released


if __name__ == "__main__":
    sys.exit(_unmount_main(sys.argv[1:]))
