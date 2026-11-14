#!/usr/bin/env python3
"""Narrow immutable content-addressed store for already-built native binaries.

This module deliberately owns no build system.  It never invokes Cargo, rustc,
Git or any subprocess and it never copies a target directory or dependency
closure.  A caller compiles a binary, then hands the exact file to
:func:`seal_binary`; the helper stores one independent copy or Linux reflink of
those bytes and creates a per-invocation snapshot/receipt location.

Layout below an explicitly managed ``store_root``::

    .rootyard-artifact-store.json       managed-store marker (read-only)
    objects/sha256/<sha256>             immutable content object (read-only)
    snapshots/<commit>/<config>/<build>/<plain-name>
    snapshots/<commit>/<config>/<build>/<plain-name>.receipt.json

Object publication is atomic and never overwrites an existing object.  A
new object is first populated in a private temporary file in the object
directory, verified against the source bytes, chmodded read-only, and then
hard-linked into ``objects/sha256/<sha256>`` with ``os.link`` (which fails
atomically if a concurrent writer won).  The mutable compiler output is never
hard-linked: FICLONE is attempted only on Linux and the clone is verified; all
other hosts and filesystems fall back to one ordinary copy per new hash.

Snapshots may hard-link only an object that this helper just validated as a
read-only, current-user-owned CAS file.  If hard-linking is unavailable the
snapshot is reflinked/copied from the object instead.  Each seal invocation
reserves its own build directory and adjacent, not-yet-written receipt path,
so two invocations with identical bytes may carry different freshness or
provenance without rewriting an older receipt.

No old object, snapshot, receipt or unknown path is renamed, rewritten, or
removed.  Only private temporary files created by this invocation are cleaned
up on failure.  The caller owns compilation provenance; this module seals
bytes and path metadata only.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import threading
import time

try:  # pragma: no cover - the import only fails on non-POSIX hosts
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

__all__ = [
    "ArtifactStoreError",
    "SealedArtifact",
    "configuration_key",
    "new_build_id",
    "seal_binary",
    "sha256_file",
    "write_receipt",
]

STORE_SCHEMA = "rootyard/native-artifact-store/v1"
STORE_KIND = "immutable-content-addressed-binary-store"
MARKER_NAME = ".rootyard-artifact-store.json"
OBJECTS_DIR = "objects"
SHA256_DIR = "sha256"
SNAPSHOTS_DIR = "snapshots"
RECEIPT_SUFFIX = ".receipt.json"
FICLONE = 0x40049409
CHUNK_SIZE = 1024 * 1024
READONLY_EXECUTABLE = 0o555
READONLY_DATA = 0o444

_COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.IGNORECASE)
_STORE_LOCK = threading.Lock()
_LINK_UNSUPPORTED = frozenset(
    {
        errno.EACCES,
        errno.EMLINK,
        errno.ENOSYS,
        errno.ENOTSUP,
        errno.EOPNOTSUPP,
        errno.EPERM,
        errno.EXDEV,
    }
)


class ArtifactStoreError(ValueError):
    """A sealing, store-safety, traversal or receipt violation."""


@dataclass(frozen=True)
class SealedArtifact:
    """The immutable identities and paths returned by :func:`seal_binary`.

    ``method`` is ``"reflink"`` for a verified Linux FICLONE, ``"copy"`` for
    the ordinary one-copy fallback, or ``"reuse"`` when an already-present
    object was validated.  ``copied_bytes`` counts bytes physically copied from
    the source into a newly retained CAS object by this invocation (0 for a
    verified reflink or a reused object).  Snapshot creation is separate: it
    prefers a hard-link to this owned immutable object and only falls back to
    reflink/copy when the filesystem cannot hard-link.
    """

    sha256: str
    object_path: Path
    binary_path: Path
    receipt_path: Path
    commit: str
    config_key: str
    build_id: str
    method: str
    reused: bool
    copied_bytes: int

    @property
    def name(self) -> str:
        return self.binary_path.name


# -- validation and canonical JSON -------------------------------------------
def _require_sha256(value, label):
    if not isinstance(value, str):
        raise ArtifactStoreError(f"{label}: must be a 64-hex SHA-256")
    lowered = value.lower()
    if not _SHA256_RE.fullmatch(lowered):
        raise ArtifactStoreError(f"{label}: must be a 64-hex SHA-256")
    return lowered


def _require_commit(value):
    if not isinstance(value, str) or not _COMMIT_RE.fullmatch(value):
        raise ArtifactStoreError(
            "commit: must be a full 40-hex or 64-hex Git commit hash"
        )
    return value.lower()


def _require_component(value, label):
    if not isinstance(value, str) or not _COMPONENT_RE.fullmatch(value):
        raise ArtifactStoreError(
            f"{label}: must be a safe single path component "
            "([A-Za-z0-9][A-Za-z0-9._+-]{0,127})"
        )
    return value


def _canonical_json_bytes(value, label):
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ArtifactStoreError(f"{label}: is not canonical JSON: {exc}") from exc


def _pretty_json_bytes(value, label):
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        return (text + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ArtifactStoreError(f"{label}: is not JSON-serializable: {exc}") from exc


def configuration_key(mapping):
    """Return SHA-256 of canonical compact sorted UTF-8 JSON for ``mapping``.

    Canonical form is ``json.dumps(mapping, sort_keys=True, separators=(",", ":"),
    ensure_ascii=False, allow_nan=False)`` encoded as UTF-8.  The result is
    lowercase 64-hex and is the expected ``config_key`` argument to
    :func:`seal_binary`.
    """
    if not isinstance(mapping, Mapping):
        raise ArtifactStoreError("configuration_key: configuration must be a mapping")
    return hashlib.sha256(_canonical_json_bytes(mapping, "configuration_key")).hexdigest()


def new_build_id():
    """Return a collision-resistant, traversal-safe invocation identifier."""
    value = f"{time.time_ns():x}-{secrets.token_hex(8)}"
    return _require_component(value, "build_id")


# -- small filesystem primitives ---------------------------------------------
def _absolute(value):
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise ArtifactStoreError("path: must be a filesystem path") from exc
    if not isinstance(text, str) or not text:
        raise ArtifactStoreError("path: must be a nonempty string or Path")
    return Path(os.path.abspath(text))


def _current_uid():
    getter = getattr(os, "geteuid", None)
    return getter() if getter is not None else None


def _stat_token(st):
    return (
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
    )


def _content_token(st):
    """Inode/content identity ignoring ctime, which hard-link count updates."""
    return (
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_size,
        st.st_mtime_ns,
    )


def _open_nofollow(path, flags):
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _open_regular_nofollow(path, label, flags=os.O_RDONLY):
    try:
        fd = _open_nofollow(path, flags)
    except OSError as exc:
        raise ArtifactStoreError(f"{label}: cannot open safely: {exc.strerror}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ArtifactStoreError(f"{label}: must be a regular file")
        return fd, st
    except Exception:
        os.close(fd)
        raise


def _sha256_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    return digest.hexdigest(), total


def sha256_file(path):
    """SHA-256 a regular file without following a final symlink."""
    fd, _st = _open_regular_nofollow(path, "file")
    try:
        return _sha256_fd(fd)[0]
    finally:
        os.close(fd)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise ArtifactStoreError("write: short write")
        view = view[written:]


def _unlink_quiet(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _fsync_dir(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EINVAL, errno.EISDIR, errno.ENOTSUP):
            return
        raise
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in (errno.EBADF, errno.EINVAL, errno.ENOTSUP):
            raise
    finally:
        os.close(fd)


def _require_managed_dir(path, label):
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise ArtifactStoreError(f"{label}: does not exist") from exc
    except OSError as exc:
        raise ArtifactStoreError(f"{label}: cannot stat: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ArtifactStoreError(f"{label}: must not be a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise ArtifactStoreError(f"{label}: must be a directory")
    uid = _current_uid()
    if uid is not None and st.st_uid != uid:
        raise ArtifactStoreError(f"{label}: is not owned by the current user")
    if st.st_mode & 0o022:
        raise ArtifactStoreError(f"{label}: must not be group/world writable")
    return st


def _ensure_child_dir(parent, name, label, *, create):
    path = parent / name
    if not os.path.lexists(path):
        if not create:
            raise ArtifactStoreError(f"{label}: does not exist")
        try:
            os.mkdir(path, 0o755)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ArtifactStoreError(f"{label}: cannot create: {exc.strerror}") from exc
    _require_managed_dir(path, label)
    return path


def _new_temp(parent, prefix, suffix=".tmp"):
    try:
        fd, name = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=os.fspath(parent))
    except OSError as exc:
        raise ArtifactStoreError(f"temporary file: cannot create: {exc.strerror}") from exc
    try:
        os.fchmod(fd, 0o600)
    except Exception:
        os.close(fd)
        _unlink_quiet(name)
        raise
    return fd, Path(name)


def _link_noreplace(temp_path, final_path):
    try:
        os.link(temp_path, final_path)
    except FileExistsError:
        return False
    except OSError as exc:
        raise ArtifactStoreError(
            f"publish: cannot hard-link into place: {exc.strerror}"
        ) from exc
    return True


# -- managed store -----------------------------------------------------------
def _store_root(store_root):
    root = _absolute(store_root)
    try:
        st = os.lstat(root)
    except FileNotFoundError:
        return root
    if stat.S_ISLNK(st.st_mode):
        raise ArtifactStoreError("store_root: must not be a symlink")
    return root


def _create_marker(marker):
    document = {"kind": STORE_KIND, "schema": STORE_SCHEMA}
    data = _canonical_json_bytes(document, "store marker") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(marker, flags, 0o444)
    except FileExistsError:
        return
    try:
        os.fchmod(fd, 0o444)
        _write_all(fd, data)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        _unlink_quiet(marker)
        raise
    os.close(fd)
    _fsync_dir(marker.parent)


def _read_marker(marker):
    try:
        fd, st = _open_regular_nofollow(marker, "store marker")
    except ArtifactStoreError:
        raise
    try:
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            total += len(chunk)
            if total > 65536:
                raise ArtifactStoreError("store marker: is unreasonably large")
            chunks.append(chunk)
        return b"".join(chunks), st
    finally:
        os.close(fd)


def _validate_marker(marker):
    last_decode_error = None
    for attempt in range(50):
        data, st = _read_marker(marker)
        uid = _current_uid()
        if uid is not None and st.st_uid != uid:
            raise ArtifactStoreError("store marker: is not owned by the current user")
        if st.st_mode & 0o222:
            raise ArtifactStoreError("store marker: must be read-only")
        if not data:
            time.sleep(0.01)
            continue
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_decode_error = exc
            if attempt < 5:
                time.sleep(0.01)
                continue
            raise ArtifactStoreError("store marker: is not valid JSON") from exc
        if not isinstance(document, Mapping):
            raise ArtifactStoreError("store marker: must be a JSON object")
        if document.get("schema") != STORE_SCHEMA or document.get("kind") != STORE_KIND:
            raise ArtifactStoreError("store marker: unsupported store schema")
        return document
    if last_decode_error is not None:
        raise ArtifactStoreError("store marker: is not valid JSON") from last_decode_error
    raise ArtifactStoreError("store marker: remained empty")


def _ensure_store(store_root, *, create):
    root = _store_root(store_root)
    with _STORE_LOCK:
        if not os.path.lexists(root):
            if not create:
                raise ArtifactStoreError("store_root: does not exist")
            try:
                os.makedirs(root, mode=0o755, exist_ok=True)
            except OSError as exc:
                raise ArtifactStoreError(
                    f"store_root: cannot create: {exc.strerror}"
                ) from exc
        _require_managed_dir(root, "store_root")
        marker = root / MARKER_NAME
        if not os.path.lexists(marker):
            if not create:
                raise ArtifactStoreError("store_root: managed marker is missing")
            try:
                entries = os.listdir(root)
            except OSError as exc:
                raise ArtifactStoreError(
                    f"store_root: cannot list: {exc.strerror}"
                ) from exc
            if entries and not os.path.lexists(marker):
                # Re-check after listing: another process may have won the
                # initialization race between lexists() and listdir().
                raise ArtifactStoreError(
                    "store_root: existing nonempty directory is not a managed store"
                )
            if not os.path.lexists(marker):
                _create_marker(marker)
        _validate_marker(marker)
        _ensure_child_dir(root, OBJECTS_DIR, "objects directory", create=create)
        objects = root / OBJECTS_DIR
        _ensure_child_dir(objects, SHA256_DIR, "sha256 object directory", create=create)
        _ensure_child_dir(root, SNAPSHOTS_DIR, "snapshots directory", create=create)
        return root


# -- source sealing ----------------------------------------------------------
def _open_source(source):
    path = _absolute(source)
    try:
        lstat = os.lstat(path)
    except FileNotFoundError as exc:
        raise ArtifactStoreError("source: does not exist") from exc
    except OSError as exc:
        raise ArtifactStoreError(f"source: cannot stat: {exc.strerror}") from exc
    if stat.S_ISLNK(lstat.st_mode):
        raise ArtifactStoreError("source: must not be a symlink")
    if not stat.S_ISREG(lstat.st_mode):
        raise ArtifactStoreError("source: must be a regular file")
    try:
        fd = _open_nofollow(path, os.O_RDONLY)
    except OSError as exc:
        raise ArtifactStoreError(f"source: cannot open: {exc.strerror}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ArtifactStoreError("source: must be a regular file")
        if (st.st_dev, st.st_ino) != (lstat.st_dev, lstat.st_ino):
            raise ArtifactStoreError("source: changed while being opened")
    except Exception:
        os.close(fd)
        raise
    return path, fd, st


def _require_unchanged(source_fd, source_path, before):
    after = os.fstat(source_fd)
    if _stat_token(after) != before:
        raise ArtifactStoreError("source: changed while sealing")
    try:
        current = os.lstat(source_path)
    except FileNotFoundError as exc:
        raise ArtifactStoreError("source: disappeared while sealing") from exc
    if _stat_token(current) != before:
        raise ArtifactStoreError("source: changed while sealing")


def _reflink_supported():
    return sys.platform.startswith("linux") and fcntl is not None


def _try_ficlone(source_fd, dest_fd):
    if not _reflink_supported():
        return False
    try:
        fcntl.ioctl(dest_fd, FICLONE, source_fd)
    except OSError:
        return False
    return True


def _populate_temp(source_fd, temp_fd, expected_sha):
    """Clone-or-copy source into temp and verify both sides; return method/bytes."""
    os.lseek(source_fd, 0, os.SEEK_SET)
    os.lseek(temp_fd, 0, os.SEEK_SET)
    os.ftruncate(temp_fd, 0)
    if _try_ficlone(source_fd, temp_fd):
        os.fsync(temp_fd)
        dest_sha, dest_size = _sha256_fd(temp_fd)
        source_sha, source_size = _sha256_fd(source_fd)
        if dest_sha == expected_sha and source_sha == expected_sha and dest_size == source_size:
            return "reflink", 0
        # The ioctl claimed success but the clone did not verify.  Never trust
        # an unverified clone: discard it and take the ordinary copy path.

    os.lseek(source_fd, 0, os.SEEK_SET)
    os.lseek(temp_fd, 0, os.SEEK_SET)
    os.ftruncate(temp_fd, 0)
    digest = hashlib.sha256()
    copied = 0
    while True:
        chunk = os.read(source_fd, CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
        copied += len(chunk)
        _write_all(temp_fd, chunk)
    os.fsync(temp_fd)
    dest_sha, dest_size = _sha256_fd(temp_fd)
    if digest.hexdigest() != expected_sha:
        raise ArtifactStoreError("copy: source changed while being read")
    if dest_sha != expected_sha or dest_size != copied:
        raise ArtifactStoreError("copy: source/destination verification failed")
    return "copy", copied


def _validate_existing_object(object_path, sha):
    fd, st = _open_regular_nofollow(object_path, "object")
    try:
        uid = _current_uid()
        if uid is not None and st.st_uid != uid:
            raise ArtifactStoreError("object: is not owned by the current user")
        if st.st_mode & 0o222:
            raise ArtifactStoreError("object: must be read-only")
        before = _content_token(st)
        digest, size = _sha256_fd(fd)
        if _content_token(os.fstat(fd)) != before:
            raise ArtifactStoreError("object: changed while being validated")
    finally:
        os.close(fd)
    if digest != sha:
        raise ArtifactStoreError("object: existing content does not match its hash")
    return size


def _publish_object(root, sha, source_fd, source_path, source_before):
    object_dir = root / OBJECTS_DIR / SHA256_DIR
    object_path = object_dir / sha
    if os.path.lexists(object_path):
        _validate_existing_object(object_path, sha)
        object_stat = os.lstat(object_path)
        source_stat = os.fstat(source_fd)
        if (object_stat.st_dev, object_stat.st_ino) == (
            source_stat.st_dev,
            source_stat.st_ino,
        ):
            raise ArtifactStoreError(
                "source: must not share an inode with the immutable CAS object"
            )
        _require_unchanged(source_fd, source_path, source_before)
        return object_path, "reuse", 0, True

    temp_fd, temp_path = _new_temp(object_dir, prefix=f".{sha}.", suffix=".tmp")
    try:
        method, copied = _populate_temp(source_fd, temp_fd, sha)
        _require_unchanged(source_fd, source_path, source_before)
        os.fchmod(temp_fd, READONLY_EXECUTABLE)
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = None
        if not _link_noreplace(temp_path, object_path):
            _validate_existing_object(object_path, sha)
            object_stat = os.lstat(object_path)
            source_stat = os.fstat(source_fd)
            if (object_stat.st_dev, object_stat.st_ino) == (
                source_stat.st_dev,
                source_stat.st_ino,
            ):
                raise ArtifactStoreError(
                    "source: must not share an inode with the immutable CAS object"
                )
            _require_unchanged(source_fd, source_path, source_before)
            return object_path, "reuse", 0, True
        _fsync_dir(object_dir)
        published = os.lstat(object_path)
        if stat.S_ISLNK(published.st_mode) or not stat.S_ISREG(published.st_mode):
            raise ArtifactStoreError("object: published path is not a regular file")
        uid = _current_uid()
        if uid is not None and published.st_uid != uid:
            raise ArtifactStoreError("object: published file is not owned by the current user")
        if published.st_mode & 0o222:
            raise ArtifactStoreError("object: published file is writable")
        source_now = os.fstat(source_fd)
        if (published.st_dev, published.st_ino) == (source_now.st_dev, source_now.st_ino):
            raise ArtifactStoreError("object: must not share an inode with mutable source")
        return object_path, method, copied, False
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        _unlink_quiet(temp_path)


def _ensure_build_dir(root, commit, config_key, build_id):
    base = root
    for name, label in (
        (SNAPSHOTS_DIR, "snapshots directory"),
        (commit, "snapshot commit directory"),
        (config_key, "snapshot config directory"),
    ):
        base = _ensure_child_dir(base, name, label, create=True)
    build_dir = base / build_id
    try:
        os.mkdir(build_dir, 0o755)
    except FileExistsError as exc:
        raise ArtifactStoreError(
            "build_id: snapshot directory already exists; refusing to overwrite"
        ) from exc
    except OSError as exc:
        raise ArtifactStoreError(
            f"snapshot build directory: cannot create: {exc.strerror}"
        ) from exc
    _require_managed_dir(build_dir, "snapshot build directory")
    return build_dir


def _require_existing_build_dir(root, commit, config_key, build_id):
    base = root
    for name, label in (
        (SNAPSHOTS_DIR, "snapshots directory"),
        (commit, "snapshot commit directory"),
        (config_key, "snapshot config directory"),
        (build_id, "snapshot build directory"),
    ):
        base = base / name
        _require_managed_dir(base, label)
    return base


def _publish_snapshot(object_path, binary_path, expected_sha):
    if os.path.lexists(binary_path):
        raise ArtifactStoreError("snapshot: already exists; refusing to overwrite")
    try:
        os.link(object_path, binary_path)
    except FileExistsError as exc:
        raise ArtifactStoreError(
            "snapshot: already exists; refusing to overwrite"
        ) from exc
    except OSError as exc:
        if exc.errno not in _LINK_UNSUPPORTED:
            raise ArtifactStoreError(
                f"snapshot: cannot hard-link from CAS: {exc.strerror}"
            ) from exc
        temp_fd, temp_path = _new_temp(
            binary_path.parent, prefix=f".{binary_path.name}.", suffix=".tmp"
        )
        try:
            source_fd, _st = _open_regular_nofollow(object_path, "object")
            try:
                method, _copied = _populate_temp(source_fd, temp_fd, expected_sha)
            finally:
                os.close(source_fd)
            os.fchmod(temp_fd, READONLY_EXECUTABLE)
            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = None
            if not _link_noreplace(temp_path, binary_path):
                raise ArtifactStoreError(
                    "snapshot: already exists; refusing to overwrite"
                )
            _fsync_dir(binary_path.parent)
            return method
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            _unlink_quiet(temp_path)
    else:
        _fsync_dir(binary_path.parent)
        object_stat = os.lstat(object_path)
        snapshot_stat = os.lstat(binary_path)
        if (object_stat.st_dev, object_stat.st_ino) != (
            snapshot_stat.st_dev,
            snapshot_stat.st_ino,
        ):
            raise ArtifactStoreError("snapshot: hard-link inode verification failed")
        return "hardlink"


def seal_binary(
    source,
    *,
    store_root,
    commit,
    config_key,
    build_id=None,
    name=None,
    expected_sha256=None,
):
    """Seal exactly one already-built binary into an immutable managed CAS.

    ``source`` must be the mutable compiler output file.  It is read through a
    no-follow descriptor; it is never linked, renamed, deleted or written.
    ``expected_sha256`` is an optional caller-side anchor and is checked before
    the store is touched.  ``build_id=None`` creates a fresh safe identifier.
    The returned ``receipt_path`` is unique and adjacent to ``binary_path`` but
    is not written here; call :func:`write_receipt` once with the invocation's
    provenance payload.
    """
    commit = _require_commit(commit)
    config_key = _require_sha256(config_key, "config_key")
    if expected_sha256 is not None:
        expected_sha256 = _require_sha256(expected_sha256, "expected_sha256")
    if build_id is not None:
        build_id = _require_component(build_id, "build_id")

    source_path, source_fd, source_stat = _open_source(source)
    try:
        chosen_name = _require_component(
            name if name is not None else source_path.name, "name"
        )
        chosen_build = new_build_id() if build_id is None else build_id
        source_before = _stat_token(source_stat)
        source_sha, _source_size = _sha256_fd(source_fd)
        _require_unchanged(source_fd, source_path, source_before)
        if expected_sha256 is not None and source_sha != expected_sha256:
            raise ArtifactStoreError(
                "expected_sha256: source digest does not match the caller anchor"
            )

        root = _ensure_store(store_root, create=True)
        object_path, method, copied_bytes, reused = _publish_object(
            root,
            source_sha,
            source_fd,
            source_path,
            source_before,
        )

        build_dir = _ensure_build_dir(root, commit, config_key, chosen_build)
        binary_path = build_dir / chosen_name
        receipt_path = build_dir / (chosen_name + RECEIPT_SUFFIX)
        if os.path.lexists(binary_path):
            raise ArtifactStoreError("snapshot: already exists; refusing to overwrite")
        if os.path.lexists(receipt_path):
            raise ArtifactStoreError("receipt: already exists; refusing to overwrite")
        _publish_snapshot(object_path, binary_path, source_sha)

        return SealedArtifact(
            sha256=source_sha,
            object_path=object_path,
            binary_path=binary_path,
            receipt_path=receipt_path,
            commit=commit,
            config_key=config_key,
            build_id=chosen_build,
            method=method,
            reused=reused,
            copied_bytes=copied_bytes,
        )
    finally:
        os.close(source_fd)


# -- adjacent receipt --------------------------------------------------------
def _validate_identity_payload(payload, sealed):
    if not isinstance(payload, Mapping):
        raise ArtifactStoreError("receipt payload: must be a mapping")
    aliases = {
        "binary_sha256": ("sha", sealed.sha256),
        "build_id": ("component", sealed.build_id),
        "commit": ("commit", sealed.commit),
        "config_key": ("sha", sealed.config_key),
        "sha256": ("sha", sealed.sha256),
        "workspace_commit": ("commit", sealed.commit),
    }
    for key, (kind, expected) in aliases.items():
        if key not in payload:
            continue
        value = payload[key]
        if kind == "sha":
            actual = _require_sha256(value, f"receipt payload.{key}")
        elif kind == "commit":
            actual = _require_commit(value)
        else:
            actual = _require_component(value, f"receipt payload.{key}")
        if actual != expected:
            raise ArtifactStoreError(
                f"receipt payload.{key}: does not match sealed artifact"
            )


def _sealed_paths(sealed):
    if not isinstance(sealed, SealedArtifact):
        raise ArtifactStoreError("sealed: must be a SealedArtifact")
    sha = _require_sha256(sealed.sha256, "sealed.sha256")
    commit = _require_commit(sealed.commit)
    config_key = _require_sha256(sealed.config_key, "sealed.config_key")
    build_id = _require_component(sealed.build_id, "sealed.build_id")
    if (
        sealed.sha256 != sha
        or sealed.commit != commit
        or sealed.config_key != config_key
        or sealed.build_id != build_id
    ):
        raise ArtifactStoreError("sealed: identity fields are not canonical")

    object_path = _absolute(sealed.object_path)
    binary_path = _absolute(sealed.binary_path)
    receipt_path = _absolute(sealed.receipt_path)
    if object_path.name != sha:
        raise ArtifactStoreError("sealed.object_path: does not match sealed SHA-256")
    if object_path.parent.name != SHA256_DIR or object_path.parent.parent.name != OBJECTS_DIR:
        raise ArtifactStoreError("sealed.object_path: is not in objects/sha256")
    root = object_path.parent.parent.parent
    name = _require_component(binary_path.name, "sealed.binary_path.name")
    expected_binary = root / SNAPSHOTS_DIR / commit / config_key / build_id / name
    if binary_path != expected_binary:
        raise ArtifactStoreError("sealed.binary_path: does not match commit/config/build")
    expected_receipt = binary_path.parent / (name + RECEIPT_SUFFIX)
    if receipt_path != expected_receipt:
        raise ArtifactStoreError("sealed.receipt_path: is not the adjacent receipt")
    return root, object_path, binary_path, receipt_path, sha, commit, config_key, build_id


def write_receipt(sealed, payload):
    """Atomically write one unique adjacent receipt and never overwrite one.

    The sealed object and snapshot are re-validated (regular, owned, read-only
    and SHA-256 matching) and the commit/config/build path binding is checked.
    ``payload`` is written verbatim as sorted, indented JSON after any identity
    aliases it carries have been checked.  The final hard-link publication is
    no-overwrite, so an existing receipt yields :class:`ArtifactStoreError`
    with the old bytes untouched.
    """
    (
        root,
        object_path,
        binary_path,
        receipt_path,
        sha,
        commit,
        config_key,
        build_id,
    ) = _sealed_paths(sealed)
    _ensure_store(root, create=False)
    _require_existing_build_dir(root, commit, config_key, build_id)

    if os.path.lexists(receipt_path):
        raise ArtifactStoreError("receipt: already exists; refusing to overwrite")
    _validate_identity_payload(payload, sealed)
    body = _pretty_json_bytes(payload, "receipt payload")

    _validate_existing_object(object_path, sha)
    snapshot_fd, snapshot_stat = _open_regular_nofollow(binary_path, "snapshot")
    try:
        uid = _current_uid()
        if uid is not None and snapshot_stat.st_uid != uid:
            raise ArtifactStoreError("snapshot: is not owned by the current user")
        if snapshot_stat.st_mode & 0o222:
            raise ArtifactStoreError("snapshot: must be read-only")
        object_stat = os.lstat(object_path)
        if (snapshot_stat.st_dev, snapshot_stat.st_ino) != (
            object_stat.st_dev,
            object_stat.st_ino,
        ):
            snapshot_sha, _size = _sha256_fd(snapshot_fd)
            if snapshot_sha != sha:
                raise ArtifactStoreError("snapshot: SHA-256 does not match sealed artifact")
    finally:
        os.close(snapshot_fd)

    receipt_fd, temp_path = _new_temp(
        receipt_path.parent, prefix=f".{receipt_path.name}.", suffix=".tmp"
    )
    try:
        _write_all(receipt_fd, body)
        os.fchmod(receipt_fd, READONLY_DATA)
        os.fsync(receipt_fd)
        os.close(receipt_fd)
        receipt_fd = None
        if not _link_noreplace(temp_path, receipt_path):
            raise ArtifactStoreError("receipt: already exists; refusing to overwrite")
        _fsync_dir(receipt_path.parent)
    finally:
        if receipt_fd is not None:
            os.close(receipt_fd)
        _unlink_quiet(temp_path)
    return receipt_path
