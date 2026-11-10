#!/usr/bin/env python3
"""Bounded `serve-blob` probe of the lifecycle barrier held by offline backup/restore.

The probe starts the real binary on a run-owned loopback bind and classifies what
it actually did; it never treats "the probe did not finish" as a pass:

* ``started``  - the child answered a loopback HTTP request. Only that observed
  response counts; the child being alive proves nothing about serving.
* ``refused``  - the child exited with the exact lifecycle barrier message the
  current source emits for that mode (``src/backup/lifetime.rs``): ``external``
  takes the shared serving barrier, ``auto`` takes the exclusive backup barrier
  during migration first. The source wraps that message in one anyhow context,
  so the accepted stderr is either anyhow's single-cause form
  (``Caused by:`` then one unnumbered ``    message``) or its multi-cause form
  (``    0: message``, ...), only as the causes of that startup-failure block
  and only when they are exactly that message.
* ``unknown``  - everything else, including a child still alive when a short
  observation window ends. Fail-closed; never called a pass.

The window only observes. It is not a bound on every step of startup (some
startup work, such as the scratch-directory check, is blocking and unbounded),
so a live child at the end of the window is reported as ``unknown`` with
``alive`` evidence instead of being claimed to have started.
"""
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# Exact current-source refusals (src/backup/lifetime.rs).
BARRIER_REFUSALS = {
    "auto": "serve-blob or another offline backup/restore already holds the lifecycle barrier",
    "external": "an offline backup or restore holds the lifecycle barrier; refuse to serve this database",
}
STARTUP_FAILURE = "Blob service schema or lifecycle barrier is unavailable"
OBSERVATION_WINDOW_SECONDS = 10.0
REDACTED = "[REDACTED]"

# Diagnostics may be kept only as these exact product facts. No free cause text
# is ever kept, so no arbitrary message from the child can reach a report.
CAUSES = {
    "lifecycle barrier": "lifecycle barrier",
    "serving barrier": "serving barrier",
    "startup failed inside a dependency": "dependency panic",
}
# DSNs and credentials are replaced even when the value is not a known secret.
_SENSITIVE = re.compile(
    r"(?i)[a-z][a-z0-9+.\-]*://[^\s'\"]+"
    r"|(?<=password=)[^\s'\"]+"
    r"|\b(password|passwd|secret|token)\s*[=:]\s*\S+")
_ERROR = re.compile(r"^Error: (.*)$")
# The scanner's numbered-cause form: kept text only, for fixed vocabulary.
_CAUSE = re.compile(r"^ {4}\d+: (.*)$")
# The strict parser's numbered-cause form: the index and the text, so the
# indexes can be required to run sequentially from `   0:`.
_NUMBERED_CAUSE = re.compile(r"^ {4}(\d+): (.*)$")
# anyhow's standard single-cause form under `Caused by:` carries no `N:` index.
_SINGLE_CAUSE = re.compile(r"^ {4}(\S.*)$")
_DEPENDENCY_PANIC = re.compile(r"^thread '[^']*' ?\(\d+\)? panicked at .*/(rdkafka|fuser|tokio|tokio-postgres|opendal)[^:]*/")
_PANIC = re.compile(r"^(thread '|note: )")
_TOML = re.compile(r'^\w+\s*=\s*"[^"]*"\s*(#.*)?$')
_RUST_LOG = re.compile(r"^\[\d{4}-\d\d-\d\dT[^\]]*\]\s+\w+\s+(.*)$")


def scrub(text, secrets=()):
    """Replace known secrets and any DSN, userinfo or credential; drop control bytes."""
    for secret in (secret for secret in secrets if secret and len(secret) >= 4):
        text = text.replace(secret, REDACTED)
    return "".join(char for char in _SENSITIVE.sub(REDACTED, text) if char == "\t" or ord(char) >= 0x20)


def _facts(text, secrets):
    """Fixed category for one message, or none: the text before ':' is the product's own."""
    text = scrub(text, secrets).split(":", 1)[0].lower()
    found = [CAUSES[word] for word in CAUSES if word in text]
    return ["cause " + found[0]] if found else []


def own_lines(path, secrets=(), limit=16):
    """Fixed-vocabulary product diagnostics from a private log the child wrote.

    Only the exact startup-refusal context, ``cause`` categories from ``CAUSES``
    and ``barrier message`` are kept. Raw cause text, panics, echoed profiles and
    every unrecognised line stay private. ``barrier message`` is added only for
    a complete per-mode ``_exact_refusal`` block, never from one refusal-shaped
    line: an invalid, separated or mixed block keeps only its categories.
    """
    try:
        lines = Path(path).read_bytes().decode("utf-8", "replace").splitlines()
    except FileNotFoundError:
        return []
    # causes: None, "header" once `Caused by:` opens the startup block, then
    # "first"/"more" as its cause lines are read.
    kept, panic, causes = [], False, None
    for raw in lines:
        line = raw.rstrip()
        log = _RUST_LOG.match(line)
        if log:
            line = log.group(1)
        if (match := _ERROR.match(line)):
            panic, causes = False, None
            if match.group(1) == STARTUP_FAILURE:
                causes = "header"
                kept.append("startup refusal context (" + STARTUP_FAILURE + ")")
            else:
                kept.extend(_facts(match.group(1), secrets))
        elif _PANIC.match(line) or _DEPENDENCY_PANIC.match(line):
            panic, causes = True, None
            if _DEPENDENCY_PANIC.match(line):
                kept.append("cause dependency panic")
        elif not line.strip():
            # A blank line ends both the panic and the startup block.
            panic, causes = False, None
        elif causes == "header" and line == "Caused by:":
            # The header itself is part of the standard block, not a fact; one
            # empty separator line may follow it before the cause lines.
            causes = "first"
        elif causes == "first" and not line.strip():
            continue
        elif causes in ("first", "more") and (
                match := _CAUSE.match(line) or (_SINGLE_CAUSE.match(line) if causes == "first" else None)):
            # Any cause line inside the block keeps only its fixed category;
            # `barrier message` comes from the exact block alone.
            causes = "more"
            kept.extend(_facts(match.group(1), secrets))
        elif _TOML.match(line):
            continue  # a profile echoed straight into the log carries its keys
        elif panic:
            causes = None
        else:
            # Any other line ends the startup block: a cause only counts when
            # the `Caused by:` header precedes it in the same block.
            causes = None
            # An orphan indented line that is exactly one of the known barrier
            # messages belongs to no established cause block, so it is
            # suppressed rather than classified as a generic cause.
            if line.strip() not in BARRIER_REFUSALS.values():
                kept.extend(_facts(line, secrets))
    if any(_exact_refusal(path, secrets, mode) for mode in BARRIER_REFUSALS):
        kept.append("barrier message")
    kept = [line for line in kept if line]
    unique = []
    for line in kept:
        if line not in unique:
            unique.append(line)
    return unique[-limit:]


def _exact_refusal(path, secrets, mode):
    """The startup-refusal context whose own cause is the exact message of `mode`."""
    try:
        lines = Path(path).read_bytes().decode("utf-8", "replace").splitlines()
    except FileNotFoundError:
        return False
    context = "Error: " + STARTUP_FAILURE
    for index, line in enumerate(lines):
        if line.rstrip() != context:
            continue
        # Only this block counts: it follows the context directly, or after one
        # empty separator line, and starts with `Caused by:`. Its causes carry
        # exactly this mode's fixed message and nothing else: an arbitrary
        # surrounding cause, a mixed form or a second block fails the match.
        # The whole remaining block is parsed, never a truncated prefix: a
        # matching run of causes followed by any unrelated cause, blank line
        # inside the block or second block must fail the match (fail closed).
        block = lines[index + 1:]
        if block and not block[0].strip():
            block = block[1:]  # the one optional separator after the context
        causes = [scrub(message, secrets) for message in _cause_messages(block)]
        if causes and all(cause == BARRIER_REFUSALS[mode] for cause in causes):
            return True
    return False


_MESSAGE = re.compile(r"^ {4}([^:\s].*)$")


def _cause_messages(block):
    """Cause messages of one anyhow block, in either standard form only.

    The block is ``Caused by:`` followed by exactly one unnumbered
    ``    message``, or by the numbered ``    N: message`` lines in sequence
    from ``   0:``. One empty separator line may sit directly after the header,
    and trailing empty lines are dropped. Any other line (an arbitrary line, a
    second block), a mix of both forms, or non-sequential indexes yields nothing.
    """
    body = list(block)
    while body and not body[-1].strip():
        body.pop()
    if not body or body[0] != "Caused by:":
        return []
    body = body[1:]
    if body and not body[0].strip():
        body = body[1:]  # the optional single separator after the header
    if not body or any(not line.strip() for line in body):
        return []
    # Only a numbered cause is `N: text`; an unnumbered message is any other
    # indented text, even when its own text contains a colon.
    numbered = [_NUMBERED_CAUSE.match(line) for line in body]
    if all(numbered):
        if [int(match.group(1)) for match in numbered] == list(range(len(numbered))):
            return [match.group(2) for match in numbered]
        return []
    if any(numbered) or len(body) != 1:
        return []  # a mix of both forms, or more than one unnumbered cause
    match = _MESSAGE.match(body[0])
    return [match.group(1)] if match else []


def loopback_bind():
    """Select a free loopback port; the probe releases it before the child binds."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return "127.0.0.1:" + str(sock.getsockname()[1])


def reserve_loopback():
    """A free loopback port held open (listening, not accepting) by the caller."""
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    return "127.0.0.1:" + str(holder.getsockname()[1]), holder


_HTTP_OK = re.compile(rb"^HTTP/\d(\.\d)? \d{3}")


def _listening(bind, timeout=0.2):
    """True only if `bind` answers with an HTTP status line within `timeout`.

    A connection that is only accepted (no answer) yields no HTTP response and
    is not serving evidence.
    """
    host, _, port = bind.rpartition(":")
    address = (host or "127.0.0.1", int(port))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.settimeout(timeout)
            sock.connect(address)
            sock.sendall(b"GET /health/ready HTTP/1.1\r\nHost: " + bind.encode("ascii") + b"\r\nConnection: close\r\n\r\n")
            return bool(_HTTP_OK.match(sock.recv(128)))
        except OSError:
            return False


def _reap_owned(child, window=5.0):
    """Kill the probe's own session and prove it quiescent; True only when proven.

    SIGKILL goes to the leader's own PGID (made unique to its session) whenever
    the leader or any member is alive, including a child left behind by a leader
    that already exited. Proof reads only that PGID from Linux /proc; there it
    is refused rather than approximated, and elsewhere the leader's group is
    killed and reaped without the member proof.
    """
    group = child.pid  # start_new_session made the leader's pid its PGID
    linux = _proc_available()
    try:
        if not linux or _group_members(group) or child.poll() is None:
            os.killpg(group, 9)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=window)
    except subprocess.TimeoutExpired:
        return False
    if not linux:
        return True
    deadline = time.monotonic() + window
    while _group_members(group):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.02)
    return True


def _proc_available():
    return sys.platform.startswith("linux") and Path("/proc").is_dir()


def _group_members(group):
    """Live (non-zombie) pids in exactly `group`; Linux /proc only."""
    if not _proc_available():
        raise NotImplementedError("process-group proof requires Linux /proc")
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(errors="replace")
            fields = stat[stat.rindex(")") + 2:].split()
            if int(fields[2]) == group and fields[0] != "Z":
                members.append(int(entry.name))
        except (OSError, ValueError, IndexError):
            continue
    return members


def serving_barrier_probe(binary, env, mode, root, secrets=(), window=OBSERVATION_WINDOW_SECONDS,
                          label="probe", prebound=None):
    """Run one bounded probe, classify it and reap the owned child before returning."""
    assert mode in BARRIER_REFUSALS, "unknown schema mode"
    root = Path(root)
    root.mkdir(mode=0o700, exist_ok=True)
    child_env = env.copy()
    child_env["ROOTYARD_SCHEMA_MODE"] = mode
    child_env["ROOTYARD_BIND"] = prebound or loopback_bind()
    directory = Path(tempfile.mkdtemp(prefix=label + "-", dir=root))
    directory.chmod(0o700)
    outcome = {"mode": mode, "window_seconds": window, "data_dir": str(directory / "data")}
    stdout_path, stderr_path = directory / "stdout.log", directory / "stderr.log"
    child = None
    started = time.monotonic()
    try:
        # The child reads ROOTYARD_DATA_DIR before the PostgreSQL barrier. A
        # target under restore carries a guard there, so point the child at a
        # private, guard-free data directory of this probe instead of the real
        # one; DATABASE_URL still names the very database under restore/backup.
        data_dir = directory / "data"
        data_dir.mkdir(mode=0o700)
        child_env["ROOTYARD_DATA_DIR"] = str(data_dir)
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            child = subprocess.Popen([binary, "serve-blob"], env=child_env, stdout=stdout, stderr=stderr,
                                     start_new_session=True)
        deadline = started + window
        listening = False
        while time.monotonic() < deadline:
            if _listening(child_env["ROOTYARD_BIND"], timeout=min(0.2, max(0.01, (deadline - time.monotonic()) / 2))):
                listening = True
                break
            if child.poll() is not None:
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        diagnostics = own_lines(stdout_path, secrets) + own_lines(stderr_path, secrets)
        outcome["diagnostics"] = diagnostics
        if listening:
            outcome["status"] = "started"
            outcome["reason"] = "answered a loopback HTTP request"
        elif child.poll() is None:
            outcome.update(status="unknown", alive=True, reason="still alive at the end of the observation window")
        elif child.returncode == 0:
            outcome.update(status="unknown", exit=0, reason="exit 0 without a barrier refusal")
        elif _exact_refusal(stdout_path, secrets, mode) or _exact_refusal(stderr_path, secrets, mode):
            outcome.update(status="refused", exit=child.returncode, expected=BARRIER_REFUSALS[mode])
        else:
            outcome.update(status="unknown", exit=child.returncode, reason="exit without the exact barrier refusal")
    except BaseException:
        child = None  # an unclassified failure keeps its raised error, not a probe outcome
        raise
    finally:
        if child is not None:
            outcome["quiescent"] = outcome["reaped"] = _reap_owned(child)
            outcome["ran_seconds"] = round(time.monotonic() - started, 4)
            shutil.rmtree(directory, ignore_errors=True)
    assert outcome["status"] in ("refused", "started", "unknown"), "probe outcome is not classified"
    return outcome


def describe(outcome):
    """One-line diagnosis from fixed fields; never includes raw log content."""
    return "; ".join(str(outcome[key]) for key in
                     ("mode", "status", "reason", "exit", "alive", "diagnostics", "ran_seconds", "quiescent")
                     if key in outcome)
