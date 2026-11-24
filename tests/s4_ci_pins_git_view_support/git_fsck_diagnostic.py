#!/usr/bin/env python3
"""Bounded test-only Git wrapper for the S4 reverse `git fsck` child; raw stderr/text/oids are never stored."""
import fcntl
import json
import os
import re
import signal
import stat
import subprocess
import sys

GIT = "/usr/bin/git"
ENV = "ROOTYARD_S4_FSCK_DIAGNOSTIC"
SCHEMA = "rootyard-s4-git-fsck-diagnostic-v1"
PREFIX = ("-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C")
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
MAX_LINE, MAX_LINES, MAX_FILE_BYTES = 1024, 4096, 64 * 1024
OBJECT_REASONS = (
    "badDate", "badDateOverflow", "badEmail", "badFilemode", "badName",
    "badObjectSha1", "badObjectType", "badTimezone", "badTree", "badTreeSha1",
    "duplicateEntries", "emptyName", "fullPathname", "hasDot", "hasDotdot",
    "hasDotgit", "invalidSha1Pointer", "missingAuthor", "missingCommitter",
    "missingEmail", "missingNameBeforeEmail", "missingSpaceBeforeDate",
    "missingSpaceBeforeEmail", "missingTree", "multipleAuthors", "nulInCommit",
    "nullSha1", "treeNotSorted", "zeroPaddedDate", "zeroPaddedFilemode",
)
CATEGORIES = ("fatal", "error", "warning", "notice", "invalid_object",
              "missing_object", "broken_link", "dangling", "unknown",
              "object_hash_mismatch", "pack_checksum_mismatch",
              "object_corrupt_or_missing") + OBJECT_REASONS
PREFIXES = ((b"fatal:", "fatal"), (b"warning:", "warning"),
            (b"notice:", "notice"), (b"error:", "error"))
OBJECT_REASON = re.compile(
    rb"(?:error|warning) in (?:blob|tree|commit|tag) (?:[0-9a-f]{40}|[0-9a-f]{64}): ([a-zA-Z]{1,48}):"
)
PATTERNS = (
    (re.compile(rb"error in (?:blob|tree|commit|tag) [0-9a-f]{40,64}:"), "invalid_object"),
    (re.compile(rb"(?:error: )?hash mismatch(?:\s|$)"), "object_hash_mismatch"),
    (re.compile(rb"error: pack checksum mismatch(?:\s|$)"), "pack_checksum_mismatch"),
    (re.compile(rb"(?:error|fatal): object corrupt or missing(?:\s|$)"), "object_corrupt_or_missing"),
    (re.compile(rb"missing (?:blob|tree|commit|tag) [0-9a-f]{40,64}(?:\s|$)"), "missing_object"),
    (re.compile(rb"broken link from\s+(?:blob|tree|commit|tag)\s+[0-9a-f]{40,64}(?:\s|$)"), "broken_link"),
    (re.compile(rb"dangling (?:blob|tree|commit|tag) [0-9a-f]{40,64}(?:\s|$)"), "dangling"),
)

def is_target(args):
    return (len(args) == 9 and tuple(args[:4]) == PREFIX
            and args[5:8] == ["fsck", "--strict", "--no-reflogs"]
            and bool(args[4]) and not any(char in args[4] for char in "\0\r\n")
            and OID.fullmatch(args[8]) is not None)

def classify(line):
    text = line.strip()
    if not text: return None
    match = OBJECT_REASON.match(text)
    if match:
        reason = match[1].decode("ascii")
        if reason in OBJECT_REASONS:
            return reason
    for pattern, category in PATTERNS:
        if pattern.match(text):
            return category
    for prefix, category in PREFIXES:
        if text.startswith(prefix):
            return category
    return "unknown"

def classify_stream(fd):
    counts, lines, truncated = dict.fromkeys(CATEGORIES, 0), 0, False
    with os.fdopen(fd, "rb", buffering=8192, closefd=False) as stream:
        while True:
            raw = stream.readline(MAX_LINE + 1)
            if not raw: break
            line = raw
            if raw.endswith(b"\n"):
                line = raw[:-1]
            elif len(raw) > MAX_LINE:
                line, truncated = raw[:MAX_LINE], True
                while True:
                    tail = stream.readline(MAX_LINE + 1)
                    if not tail or tail.endswith(b"\n"):
                        break
            if lines >= MAX_LINES:
                truncated = True
                continue
            lines += 1
            category = classify(line)
            if category is None: continue
            counts[category] = min(counts[category] + 1, 65535)
    return counts, truncated

def append_record(path, record):
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try: fd = os.open(path, flags, 0o600)
    except OSError: return
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError: return
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_size + len(data) > MAX_FILE_BYTES):
            return
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                break
            view = view[written:]
    except OSError:
        pass
    finally:
        try: os.close(fd)
        except OSError: pass

def run_target(args, path):
    try:
        child = subprocess.Popen([GIT, *args], stdin=None, stdout=None, stderr=subprocess.PIPE)
    except OSError:
        return None
    counts, truncated = dict.fromkeys(CATEGORIES, 0), True
    try:
        counts, truncated = classify_stream(child.stderr.fileno())
    except Exception:
        pass
    try: child.stderr.close()
    except OSError: pass
    try: status = child.wait()
    except Exception: status = 1
    code, signum = (None, -status) if status < 0 else (status if 0 <= status <= 255 else None, None)
    try:
        append_record(path, {"schema": SCHEMA, "kind": "namespace_reverse_fsck",
                             "exit_code": code, "signal": signum,
                             "categories": {name: count for name, count in counts.items() if count},
                             "truncated": truncated})
    except Exception:
        pass
    return status

def finish(status):
    if status is None: return 1
    if status >= 0: return status if status <= 255 else 1
    signum = -status
    try: signal.signal(signum, signal.SIG_DFL)
    except (OSError, ValueError): pass
    try: os.kill(os.getpid(), signum)
    except (OSError, ValueError): pass
    return 128 + signum

def main(argv):
    if not is_target(argv): os.execv(GIT, [GIT, *argv])
    path = os.environ.get(ENV, "")
    path = path if path and os.path.isabs(path) and not any(c in path for c in "\0\r\n") else None
    if path is None: os.execv(GIT, [GIT, *argv])
    status = run_target(argv, path)
    if status is None: os.execv(GIT, [GIT, *argv])
    return finish(status)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
