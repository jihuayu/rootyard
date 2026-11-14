#!/usr/bin/env python3
"""Idempotently collect the anchored raw #174 receipt evidence files.

The producer publishes the consumed receipt aliases as readonly files.  A
collector must therefore reuse a byte-identical destination instead of copying
over it.  These helpers never chmod, rename, delete, or rewrite an existing
destination; an absent destination is created with an exclusive no-overwrite
open and then verified against the preflight anchor.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

RECEIPTS = (
    ("lib_receipt", "session174-lib-tests.build.json"),
    ("cli_receipt", "rootyard-cli.build.json"),
)
READONLY_DATA = 0o444
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class CollectionError(Exception):
    """A receipt could not be collected without rewriting provenance."""


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _lstat(path: Path, label: str):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CollectionError(f"{label}: cannot inspect: {exc.strerror}") from exc


def _read_regular_nofollow(path: Path, label: str) -> bytes:
    """Read one regular file, rejecting a final symlink and non-regular nodes."""
    info = _lstat(path, label)
    if info is None:
        raise FileNotFoundError(path)
    if stat.S_ISLNK(info.st_mode):
        raise CollectionError(f"{label}: must not be a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise CollectionError(f"{label}: must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CollectionError(f"{label}: cannot read: {exc.strerror}") from exc
    try:
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _existing_matches(
    destination: Path, raw: bytes, expected_sha: str, label: str
) -> bool:
    """Reuse only an exact regular non-symlink same-byte destination."""
    info = _lstat(destination, "receipt evidence destination")
    if info is None:
        return False
    if stat.S_ISLNK(info.st_mode):
        raise CollectionError("receipt evidence destination: must not be a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise CollectionError("receipt evidence destination: must be a regular file")
    existing = _read_regular_nofollow(destination, "receipt evidence destination")
    if existing != raw:
        raise CollectionError(
            "receipt evidence destination: bytes differ from " + label
        )
    if sha256_bytes(existing) != expected_sha:
        raise CollectionError(
            "receipt evidence destination: SHA-256 differs from the preflight anchor"
        )
    return True


def collect_raw_receipt(source: Path, destination: Path, expected_sha: str) -> str:
    """Collect one anchored raw receipt; return ``created`` or ``reused``."""
    source, destination = Path(source), Path(destination)
    raw = _read_regular_nofollow(source, "receipt evidence source")
    if sha256_bytes(raw) != expected_sha:
        raise CollectionError(
            "receipt evidence source: SHA-256 differs from the preflight anchor"
        )
    label = source.name
    if _existing_matches(destination, raw, expected_sha, label):
        return "reused"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(3):
        try:
            descriptor = os.open(destination, flags, READONLY_DATA)
        except FileExistsError:
            # A concurrent collector or producer won the creation race.  Reuse
            # only its exact bytes; never replace or repair the winner.
            if _existing_matches(destination, raw, expected_sha, label):
                return "reused"
            continue
        except OSError as exc:
            raise CollectionError(
                f"receipt evidence destination: cannot create: {exc.strerror}"
            ) from exc
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), READONLY_DATA)
                os.fsync(stream.fileno())
        except OSError as exc:
            raise CollectionError(
                f"receipt evidence destination: cannot write: {exc.strerror}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        actual = _read_regular_nofollow(destination, "saved receipt evidence")
        if actual != raw or sha256_bytes(actual) != expected_sha:
            raise CollectionError("saved receipt evidence: bytes changed after creation")
        return "created"
    raise CollectionError("receipt evidence destination: path kept changing during creation")


def _anchors(preflight_path: Path, optional: bool):
    try:
        document = json.loads(Path(preflight_path).read_text())
    except FileNotFoundError:
        if optional:
            print("session174 receipt collection: no preflight.json; receipts skipped")
            return None
        raise CollectionError("unreadable preflight evidence: FileNotFoundError")
    except (OSError, ValueError) as exc:
        if optional:
            print("session174 receipt collection: preflight anchors unavailable ("
                  + type(exc).__name__ + "); receipts skipped")
            return None
        raise CollectionError(
            "unreadable preflight evidence: " + type(exc).__name__
        ) from exc
    if not isinstance(document, dict):
        raise CollectionError("preflight evidence is not an object")
    anchors = {}
    for key, name in RECEIPTS:
        record = document.get(key)
        if not isinstance(record, dict):
            raise CollectionError(key + " is missing from preflight evidence")
        anchored = record.get("sha256")
        if not isinstance(anchored, str) or HEX64.fullmatch(anchored) is None:
            raise CollectionError(key + " has no lowercase 64-hex anchor")
        anchors[key] = (name, anchored)
    return anchors


def collect_from_preflight(
    preflight_path: Path, source_dir: Path, destination_dir: Path, optional: bool
) -> int:
    anchors = _anchors(preflight_path, optional)
    if anchors is None:
        return 0
    for _key, (name, anchored) in anchors.items():
        source = Path(source_dir) / name
        destination = Path(destination_dir) / name
        if not os.path.lexists(source):
            if optional:
                print("session174 receipt collection: skip missing " + str(source))
                continue
            raise CollectionError("receipt evidence source is missing: " + str(source))
        outcome = collect_raw_receipt(source, destination, anchored)
        print("session174 receipt collection: " + name + " " + outcome)
    return 0


def main(argv) -> int:
    arguments = list(argv[1:])
    optional = False
    if arguments and arguments[0] == "--optional":
        optional = True
        arguments.pop(0)
    if len(arguments) != 3:
        print(
            "usage: collect_evidence_receipts.py [--optional] "
            "PREFLIGHT_JSON SOURCE_DIR DESTINATION_DIR",
            file=sys.stderr,
        )
        return 2
    try:
        return collect_from_preflight(
            Path(arguments[0]), Path(arguments[1]), Path(arguments[2]), optional
        )
    except CollectionError as exc:
        print("session174 receipt collection failed: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
