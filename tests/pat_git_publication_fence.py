#!/usr/bin/env python3
"""Git-native CAS parent-token lock proof against the REAL service.

Requires the same environment as ``tests/e2e.py``: ``ROOTYARD_TEST_DATABASE_URL``
plus a built CLI supplied with ``--binary``. The server, the SQL database and
native Git are real; nothing is mocked and no helper short transaction stands in
for native CAS.

What is proven (each case uses one real ``git push`` over Git HTTP):
  A. A revoker session holds ``FOR UPDATE`` on the push token while the parent
     publication owner is inside its late authorisation. The wait is observed in
     ``pg_stat_activity``/``pg_locks`` (no sleep-and-hope); the owner's blocking
     backend must list the known revoker backend pid in ``pg_blocking_pids``. The
     statement text carries ``$1``, never the raw token, so only the fixed query
     shape is matched. Committing the revocation refuses the push: no ref, no
     outbox event, no new operation row and no ``publication.grant``
     acknowledgement. A different valid token then pushes the same ref.
  B. The parent has already granted and still holds the token row ``FOR SHARE``
     while the native child is held at the ``reference-transaction`` ``prepared``
     barrier, before Git writes refs. ``UPDATE ... SET read_only`` and the
     documented grant-writer ``SELECT ... FOR UPDATE`` step both fail with
     SQLSTATE ``55P03`` under ``lock_timeout=100ms``. The barrier is released, the
     push completes and journal settlement releases the lock, so the same
     statements then succeed.
  C. The HTTP client is killed while the owner is waiting in the late
     authorisation. The owner/child quiesce without publishing: no ref, no
     outbox event, no new operation row, no grant marker. While the revoker still
     holds the token row the owner backend must be gone from
     ``pg_stat_activity``; only then does the revoker commit, and an independent
     session proves the row is re-acquirable with a real
     ``SELECT ... FOR UPDATE NOWAIT``. A fresh push with a new token succeeds.

Deterministic ordering without new production back doors:
  * Cases A and C hold the *documented* repository publication advisory key
    (``rootyard-publication-v1:<repo>``, the same key migrations use) so the
    owner cannot enter its late authorisation first (its pre-receive hook waits
    on the parent). It is released with ``pg_advisory_unlock`` and the real
    ``FOR SHARE`` wait is then read from the live backend.
  * Case B does not race a marker poll against native CAS. The installed hook
    layout is checked first (``data/managed-hooks/reference-transaction`` is a
    private symlink to ``.runner``). After the push has passed admission and is
    parked in the pre-receive/parent wait, a *test-owned synthetic fixture* is
    installed: ``.runner`` is copied once into an owner-only private directory
    and the ``reference-transaction`` entry is replaced by a wrapper that, for
    ``$1=prepared`` only, touches ``entered`` and waits (bounded) for
    ``release`` before ``exec``-ing the genuine copy with the same argv/stdin and
    environment. ``.runner`` itself is never modified, the wrapper is restored to
    the original symlink before the barrier is released, and the fixture is
    removed afterwards. No server test hook, no SIGSTOP of the server or of the
    whole Git process group.

Seed path (documented, deliberate): there is no public issuer for restricted
tokens. Case B creates a normal CLI token, then seeds ``tokens.is_restricted``
and its exact ``contents_write`` grant in the isolated test schema. The public
issuer/API/UI remains a separate branch.

Not executed by the authoring worker (no cargo build and no native run were
permitted there); the coordinator must run it. Tokens, DSNs and server
environment values are never printed, logged or written to the report.
"""
import argparse
import base64
import json
import os
import select
import shlex
import shutil
import signal
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from e2e import Harness  # noqa: E402  (reuse the vetted harness, do not duplicate it)

ADVISORY_PREFIX = "rootyard-publication-v1:"
# The late-authorisation statement is executed as a prepared statement, so its
# pg_stat_activity text carries $1 and never the raw token id. Match the fixed
# shape only; never try to match a literal token value.
OWNER_WAIT_PREDICATE = (
    "state = 'active' AND wait_event_type = 'Lock' "
    "AND query LIKE '%SELECT true FROM tokens t WHERE t.id=$1%' "
    "AND query LIKE '%FOR SHARE OF t%'"
)
OWNER_WAIT_SQL = (
    "SELECT pid::text || '|' || coalesce(wait_event, '') || '|' || state FROM pg_stat_activity WHERE "
    + OWNER_WAIT_PREDICATE + " LIMIT 1"
)
BARRIER_LIMIT = 4000  # wrapper poll budget: 4000 * 5ms = 20s hard stop


def quote(value):
    """Quote a server-issued identifier for the isolated test schema."""
    return "'" + str(value).replace("'", "''") + "'"


class Session:
    """One long-lived psql session used only to hold real row/advisory locks."""

    def __init__(self, h, timeout=120):
        self.h = h
        self.timeout = timeout
        self.seq = 0
        self.buffer = b""
        self.stderr_bytes = b""
        assert shutil.which("stdbuf"), "coreutils stdbuf is required for line-buffered lock sessions"
        self.proc = subprocess.Popen(
            ["stdbuf", "-oL", "-eL", "psql", "--dbname", h.db, "-X", "-At", "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=h.env,
        )
        # Only a session that really answers the startup probe may be used.
        assert self.send("SELECT 1") == "1", "lock session did not answer the startup SELECT 1"
        self.pid = int(self.send("SELECT pg_backend_pid()"))

    def _stderr_text(self):
        """Drain whatever stderr is already buffered; never block."""
        try:
            fd = self.proc.stderr.fileno()
        except (AttributeError, ValueError, OSError):
            return ""
        try:
            while True:
                ready, _, _ = select.select([fd], [], [], 0)
                if not ready:
                    break
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                self.stderr_bytes += chunk
                if len(self.stderr_bytes) > 8000:
                    self.stderr_bytes = self.stderr_bytes[-8000:]
        except (OSError, ValueError):
            pass
        return self.stderr_bytes.decode(errors="replace")[-800:]

    def _fail(self, message):
        try:
            self.proc.kill()
        except OSError:
            pass
        raise AssertionError(self.h.redact(message + ": " + self._stderr_text()))

    def _readline(self, deadline_at):
        """Bounded line read: never block past the deadline, never wait forever."""
        try:
            fd = self.proc.stdout.fileno()
        except (AttributeError, ValueError, OSError):
            self._fail("lock session stdout is gone")
        while b"\n" not in self.buffer:
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                self._fail("lock session read deadline exceeded")
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                self._fail("lock session read deadline exceeded")
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                self._fail("lock session stdout read failed")
            if not chunk:
                self._fail("lock session ended early")
            self.buffer += chunk
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line.decode(errors="replace").rstrip("\r")

    def send(self, sql, timeout=None):
        r"""Send one terminated statement plus an \echo marker, read to the marker."""
        self.seq += 1
        marker = "__fence_%d__" % self.seq
        statement = sql.rstrip().rstrip(";") + ";\n"
        try:
            self.proc.stdin.write((statement + "\\echo " + marker + "\n").encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            self._fail("lock session died while sending SQL")
        deadline_at = time.monotonic() + (self.timeout if timeout is None else timeout)
        lines = []
        while True:
            text = self._readline(deadline_at)
            if text == marker:
                return "\n".join(lines)
            lines.append(text)

    def close(self):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.write(b"\\q\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


class Push:
    """One real `git push` child process so a case can kill its socket."""

    def __init__(self, h, url, ref, token, work):
        auth = base64.b64encode((token["username"] + ":" + token["token"]).encode()).decode()
        self.proc = subprocess.Popen(
            ["git", "-c", "http.extraHeader=Authorization: Basic " + auth, "push", url, "HEAD:" + ref],
            cwd=work, env=h.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )

    def cancel(self):
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)

    def wait(self, timeout=120):
        _, err = self.proc.communicate(timeout=timeout)
        return self.proc.returncode, err.decode(errors="replace")[-2000:]


def repo_id(h, repo):
    value = h.sql("SELECT id FROM repositories WHERE id = " + quote(repo["id"]))
    assert value == str(repo["id"]), "server repository id not found in the isolated schema"
    return value


def seed_restricted(h, token, repository_id, action="contents_write"):
    h.sql("UPDATE tokens SET is_restricted = true WHERE id = " + quote(token["token_id"]))
    h.sql("INSERT INTO token_repository_scopes(token_id, repository_id, action) VALUES ("
          + quote(token["token_id"]) + ", " + quote(repository_id) + ", " + quote(action) + ")")
    h.sql("UPDATE tokens SET scope_version = scope_version + 1 WHERE id = " + quote(token["token_id"]))


def create_repo(h, name):
    return json.loads(h.expect("/api/repos", 201, method="POST", token=h.alice, body={"name": name}))


def prepare_work(h):
    work = h.root / "fence-work"
    h.run(["git", "init", "-q", str(work)])
    h.git("config", "user.name", "Fence", cwd=work)
    h.git("config", "user.email", "fence@example.invalid", cwd=work)
    (work / "fence.txt").write_text("fence\n")
    h.git("add", ".", cwd=work)
    h.git("commit", "-q", "-m", "base", cwd=work)
    return work


def remote(h, repo):
    return h.base + repo["clone_path"]


def ref_oid(h, repo, name, token=None):
    out = h.git("ls-remote", remote(h, repo), name, token=token or h.alice).stdout.decode()
    return out.split()[0] if out.strip() else None


def markers(h):
    # Journal layout is data/journal/<repository>/<operation>/publication.grant;
    # scanning only that small tree keeps observation tight.
    journal = Path(h.root) / "data" / "journal"
    return sorted(str(path.relative_to(h.root)) for path in journal.rglob("publication.grant")) if journal.exists() else []


def counts(h, repository_id):
    """Durable rows a refused push must never create.

    ``git_operations.outcome`` has no 'committed' value, so filtering on it would
    always return zero and prove nothing. Count every relevant row instead and
    keep the per-outcome breakdown as evidence only.
    """
    return json.loads(h.sql(
        "SELECT json_build_object("
        "'operations', (SELECT count(*) FROM git_operations WHERE repository_id=" + quote(repository_id) + "),"
        "'outcomes', (SELECT coalesce(json_object_agg(outcome, n), '{}'::json) FROM (SELECT outcome, count(*) AS n "
        "FROM git_operations WHERE repository_id=" + quote(repository_id) + " GROUP BY outcome) s),"
        "'outbox', (SELECT count(*) FROM outbox_events WHERE repository_id=" + quote(repository_id) + "),"
        "'committed_admissions', (SELECT count(*) FROM git_ref_admissions WHERE repository_id="
        + quote(repository_id) + " AND state='COMMITTED'))"))


def wait_admitted(h, repository_id, timeout=30):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if int(h.sql("SELECT count(*) FROM git_ref_admissions WHERE repository_id="
                     + quote(repository_id) + " AND state='ADMITTED'")) > 0:
            return
        time.sleep(0.01)
    raise AssertionError("native Git did not record an ADMITTED ref writer")


def hold_publication_key(session, repository_id):
    session.send("SELECT pg_advisory_lock(hashtextextended('" + ADVISORY_PREFIX + "' || "
                 + quote(repository_id) + "::uuid::text, 0))")


def release_publication_key(session, repository_id):
    value = session.send("SELECT pg_advisory_unlock(hashtextextended('" + ADVISORY_PREFIX + "' || "
                         + quote(repository_id) + "::uuid::text, 0))")
    assert value == "t", "publication advisory key was not held by this session"


def wait_owner_lock_wait(h, blocker_pid, timeout=20):
    """Return real backend evidence that the owner waits on the known revoker."""
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        row = h.sql(OWNER_WAIT_SQL)
        if row:
            owner, wait_event, state = (row.split("|", 2) + ["", ""])[:3]
            owner_pid = int(owner)
            blocked_by = h.sql("SELECT coalesce(array_to_string(pg_blocking_pids(" + str(owner_pid) + "), ','), '')")
            blockers = [int(value) for value in blocked_by.split(",") if value.strip()]
            last = {"owner_pid": owner_pid, "wait_event": wait_event, "state": state,
                    "blocked_by": blockers, "revoker_pid": blocker_pid}
            assert blocker_pid in blockers, ("owner waited, but the known revoker backend is not among its "
                                             "blockers: " + repr(last))
            return last
        last = "no blocked token FOR SHARE backend yet"
        time.sleep(0.02)
    raise AssertionError("publication owner never waited on the token FOR SHARE: " + repr(last))


def wait_owner_backend_gone(h, owner_pid, timeout=30):
    """While the revoker still holds the row, the owner must leave its work.

    The owner runs on a pooled connection, so a finished request returns the
    backend to the pool as ``idle`` instead of closing it; requiring
    ``pid NOT IN pg_stat_activity`` would wait forever. Terminal evidence is:
    the owner backend is absent, or it holds no transaction (``xact_start IS
    NULL``), and no backend anywhere still waits on the late-authorisation
    query shape (the known blocker is gone).
    """
    owner_pid = int(owner_pid)
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        row = h.sql("SELECT concat_ws('|', coalesce(state, ''), (xact_start IS NOT NULL)::text, "
                    "coalesce(wait_event_type, '')) FROM pg_stat_activity WHERE pid = "
                    + str(owner_pid))
        blocked = int(h.sql("SELECT count(*) FROM pg_stat_activity WHERE " + OWNER_WAIT_PREDICATE))
        if row:
            fields = (row.split("|") + ["", "", ""])[:3]
            present, in_transaction, wait_type = True, fields[1] == "true", fields[2]
        else:
            present, in_transaction, wait_type = False, False, ""
        last = {"owner_pid": owner_pid, "backend_present": present,
                "in_transaction": in_transaction, "wait_event_type": wait_type,
                "blocked_owners": blocked}
        if blocked == 0 and not in_transaction and wait_type != "Lock":
            return last
        time.sleep(0.02)
    raise AssertionError("owner backend kept a token-row wait/transaction while the revoker held the row: "
                         + repr(last))


def probe_row_available(h, token_id):
    """Independent real probe: the token row must be lockable with NOWAIT."""
    probe = Session(h)
    try:
        probe.send("BEGIN")
        value = probe.send("SELECT id FROM tokens WHERE id = " + quote(token_id) + " FOR UPDATE NOWAIT")
        assert value == str(token_id), "NOWAIT probe did not read the expected token row: " + h.redact(value)
        probe.send("ROLLBACK")
        return {"pid": probe.pid, "nowait": "acquired"}
    finally:
        probe.close()


def as_do_statement(statement):
    """A plpgsql block cannot return a query result.

    ``SELECT ... FOR UPDATE`` must become ``PERFORM ... FOR UPDATE`` inside the
    DO wrapper; otherwise the block raises 42601 for an unhandled ``SELECT``
    before the lock wait is ever attempted and the probe proves nothing.
    """
    stripped = statement.strip()
    if stripped[:6].upper() == "SELECT":
        return "PERFORM" + stripped[6:]
    return stripped


def expect_sqlstate(h, session, statement, expected="55P03", lock_timeout="100ms"):
    statement = as_do_statement(statement)
    session.send("SET lock_timeout = '" + lock_timeout + "'")
    session.send("CREATE TEMP TABLE IF NOT EXISTS fence_outcome(k text)")
    session.send("TRUNCATE fence_outcome")
    session.send("DO $$ BEGIN BEGIN " + statement + "; INSERT INTO fence_outcome VALUES ('RAN'); "
                 "EXCEPTION WHEN OTHERS THEN INSERT INTO fence_outcome VALUES (SQLSTATE); END; END $$")
    outcome = session.send("SELECT k FROM fence_outcome")
    session.send("RESET lock_timeout")
    assert outcome == expected, "expected SQLSTATE %s, got %r" % (expected, outcome)
    return outcome


def wait_sqlstate(h, session, statement, expected="RAN", timeout=20, lock_timeout="100ms"):
    """Bounded retries until the statement has the expected SQLSTATE."""
    statement = as_do_statement(statement)
    until = time.monotonic() + timeout
    outcomes = []
    while time.monotonic() < until:
        session.send("SET lock_timeout = '" + lock_timeout + "'")
        session.send("CREATE TEMP TABLE IF NOT EXISTS fence_outcome(k text)")
        session.send("TRUNCATE fence_outcome")
        session.send("DO $$ BEGIN BEGIN " + statement + "; INSERT INTO fence_outcome VALUES ('RAN'); "
                     "EXCEPTION WHEN OTHERS THEN INSERT INTO fence_outcome VALUES (SQLSTATE); END; END $$")
        outcome = session.send("SELECT k FROM fence_outcome")
        session.send("RESET lock_timeout")
        outcomes.append(outcome)
        if outcome == expected:
            return outcomes
        time.sleep(0.05)
    raise AssertionError("statement never reached SQLSTATE %s: %r" % (expected, outcomes[-5:]))


def token_row_share_holders(h):
    """Backends currently holding the token table row-share lock (evidence only)."""
    out = h.sql("SELECT coalesce(string_agg(pid::text, ',' ORDER BY pid), '') FROM pg_locks "
                "WHERE relation = 'tokens'::regclass AND mode = 'RowShareLock' AND granted")
    return [int(value) for value in out.split(",") if value.strip()]


def hook_dir(h):
    return Path(h.env.get("ROOTYARD_DATA_DIR") or (Path(h.root) / "data")) / "managed-hooks"


class PreparedBarrier:
    """Test-owned synthetic fixture that holds native CAS at reference-transaction.

    ``.runner`` and the installed symlinks are evidence-bearing production layout:
    they are only read. The wrapper replaces the ``reference-transaction`` entry
    for the duration of one push and is restored to the original symlink before
    the barrier is released.
    """

    def __init__(self, h, tag="case-b"):
        self.h = h
        self.hooks = hook_dir(h)
        self.entry = self.hooks / "reference-transaction"
        self.genuine_dir = self.hooks / (".genuine-" + tag)
        self.genuine = self.genuine_dir / "reference-transaction"
        self.dir = Path(h.root) / ("fence-barrier-" + tag)
        self.entered = self.dir / "entered"
        self.release = self.dir / "release"
        self.installed = False

    def install(self):
        # verify_hooks() requires this exact private symlink; keep .runner intact.
        assert self.entry.is_symlink() and os.readlink(self.entry) == ".runner", \
            "unexpected installed reference-transaction hook layout"
        self.dir.mkdir(mode=0o700)
        self.genuine_dir.mkdir(mode=0o700)
        os.chmod(self.dir, 0o700)
        os.chmod(self.genuine_dir, 0o700)
        shutil.copy2(self.hooks / ".runner", self.genuine)
        os.chmod(self.genuine, 0o500)
        script = "\n".join([
            "#!/bin/sh",
            "# Test-owned synthetic fence fixture; never part of the server.",
            "if [ \"${1-}\" = prepared ]; then",
            "  : > " + shlex.quote(str(self.entered)) + " || exit 1",
            "  n=0",
            "  while [ ! -e " + shlex.quote(str(self.release)) + " ]; do",
            "    n=$((n + 1))",
            "    if [ \"$n\" -gt " + str(BARRIER_LIMIT) + " ]; then exit 1; fi",
            "    sleep 0.005",
            "  done",
            "fi",
            "exec " + shlex.quote(str(self.genuine)) + " \"$@\"",
            "",
        ])
        temporary = self.hooks / (".reference-transaction-" + uuid.uuid4().hex)
        temporary.write_text(script)
        os.chmod(temporary, 0o700)
        os.replace(temporary, self.entry)  # atomic: replaces the symlink name only
        self.installed = True
        return {"wrapper": str(self.entry), "genuine": str(self.genuine)}

    def restore(self):
        if not self.installed:
            return
        temporary = self.hooks / (".restore-" + uuid.uuid4().hex)
        os.symlink(".runner", temporary)
        os.replace(temporary, self.entry)
        self.installed = False
        assert self.entry.is_symlink() and os.readlink(self.entry) == ".runner", \
            "installed reference-transaction hook was not restored"

    def cleanup(self):
        self.restore()
        shutil.rmtree(self.genuine_dir, ignore_errors=True)
        shutil.rmtree(self.dir, ignore_errors=True)


def wait_barrier_entered(barrier, timeout=20):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if barrier.entered.exists():
            return
        time.sleep(0.005)
    raise AssertionError("native reference-transaction never entered the prepared barrier")


def barrier_pids(h, barrier, timeout=10):
    target = str(barrier.entry).encode()
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        found = []
        for pid in h.descendants():
            try:
                command = Path("/proc/%d/cmdline" % pid).read_bytes()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if target in command and b"prepared" in command:
                found.append(pid)
        if found:
            return found
        time.sleep(0.005)
    return []


def wait_no_descendants(h, snapshot, timeout=25):
    """Wait for the server to quiesce exactly the snapshot descendants."""
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        live = set(h.descendants()) & set(snapshot)
        if not live:
            return
        time.sleep(0.05)
    raise AssertionError("native descendants did not quiesce after client cancel")


def push_with_retry(h, url, ref, token, work, attempts=20):
    """Real pushes until quiescence; a published ref is the only success."""
    last = ""
    for _ in range(attempts):
        done = h.git("push", url, "HEAD:" + ref, cwd=work, token=token, check=False)
        if done.returncode == 0:
            return
        last = done.stderr.decode(errors="replace")[-500:]
        time.sleep(0.2)
    raise AssertionError("valid token push never succeeded: " + h.redact(last))


def run_case(h, name, fn):
    started = time.monotonic()
    try:
        detail = fn() or ""
        h.results.append(dict(name=name, status="passed",
                              seconds=round(time.monotonic() - started, 4), detail=detail))
    except Exception as error:  # noqa: BLE001 - every failure is reported, never swallowed
        h.results.append(dict(name=name, status="failed",
                              seconds=round(time.monotonic() - started, 4),
                              error=h.redact(error),
                              trace=h.redact(traceback.format_exc())[-1500:]))
    return h.results[-1]


def diagnostics_evidence(h, repository_id, key):
    """Read one boolean evidence field of the newest recorded operation."""
    return h.sql("SELECT coalesce(evidence->>'" + key + "', '') FROM git_operations WHERE repository_id="
                 + quote(repository_id) + " AND outcome='recorded' ORDER BY settled_at DESC NULLS LAST LIMIT 1")


def publication_diagnostics(h, repository_id):
    """Row/state diagnostics only: never token ids, digests, DSNs or paths."""
    return {
        "operations": h.sql("SELECT coalesce(string_agg(outcome || ':' || n::text, ',' ORDER BY outcome), '') "
                            "FROM (SELECT outcome, count(*) AS n FROM git_operations WHERE repository_id="
                            + quote(repository_id) + " GROUP BY outcome) rows"),
        "admissions": h.sql("SELECT coalesce(string_agg(state || ':' || n::text, ',' ORDER BY state), '') "
                            "FROM (SELECT state, count(*) AS n FROM git_ref_admissions WHERE repository_id="
                            + quote(repository_id) + " GROUP BY state) rows"),
        "outbox": h.sql("SELECT count(*) FROM outbox_events WHERE repository_id=" + quote(repository_id)),
    }


def assert_no_new_publication(h, repository_id, before, repo, ref, label):
    after = counts(h, repository_id)
    assert after["operations"] == before["operations"], (label, after, before)
    assert after["outbox"] == before["outbox"], (label, after, before)
    assert after["committed_admissions"] == before["committed_admissions"], (label, after, before)
    assert ref_oid(h, repo, ref) is None, label + ": ref was published"


def case_revoker_first(h, work):
    repo = create_repo(h, "fence-a")
    repository_id = repo_id(h, repo)
    h.git("push", remote(h, repo), "HEAD:refs/heads/main", cwd=work, token=h.alice)
    push_token = h.account("create-token", "alice")
    before = counts(h, repository_id)
    before_markers = markers(h)
    holder = Session(h)
    revoker = Session(h)
    worker = None
    try:
        # The documented repository publication key keeps the owner out of its
        # late authorisation until the revoker owns the token row.
        hold_publication_key(holder, repository_id)
        worker = Push(h, remote(h, repo), "refs/heads/fence-a", push_token, work)
        wait_admitted(h, repository_id)
        revoker.send("BEGIN; SELECT id FROM tokens WHERE id = " + quote(push_token["token_id"])
                     + " FOR UPDATE")
        release_publication_key(holder, repository_id)
        wait = wait_owner_lock_wait(h, revoker.pid)
        assert not (set(markers(h)) - set(before_markers)), "grant marker existed before the late authorisation"
        revoker.send("UPDATE tokens SET revoked = true WHERE id = "
                     + quote(push_token["token_id"]) + "; COMMIT")
        code, err = worker.wait()
        worker = None
        assert code != 0, "revoked token still published: " + err
        assert_no_new_publication(h, repository_id, before, repo, "refs/heads/fence-a",
                                  "revoked push published")
        assert not (set(markers(h)) - set(before_markers)), "an ACK marker survived the refused push"
        # A different valid token must publish the same ref. This is a hard
        # single-shot assertion: a stranded admission/journal would answer 503
        # (or leave the ref unpublished) and must fail the case immediately.
        valid = h.account("create-token", "alice")
        published = h.git("push", remote(h, repo), "HEAD:refs/heads/fence-a", cwd=work,
                          token=valid, check=False)
        if published.returncode != 0 or ref_oid(h, repo, "refs/heads/fence-a") is None:
            raise AssertionError("valid token push after the refused revocation failed: "
                                 + h.redact(published.stderr.decode(errors="replace")[-500:])
                                 + " diagnostics=" + repr(publication_diagnostics(h, repository_id)))
        assert counts(h, repository_id)["outbox"] == before["outbox"] + 1
        assert not (set(markers(h)) - set(before_markers)), "valid push left no ACK marker"
        return ("owner FOR SHARE wait blocked by revoker backend %d (owner %d); revocation refused the push; "
                "valid token published" % (revoker.pid, wait["owner_pid"]))
    finally:
        if worker is not None:
            worker.cancel()
            worker.wait()
        revoker.close()
        holder.close()


def case_lock_outlives_cas(h, work, native):
    repo = create_repo(h, "fence-b")
    repository_id = repo_id(h, repo)
    h.git("push", remote(h, repo), "HEAD:refs/heads/main", cwd=work, token=h.alice)
    scoped = h.account("create-token", "alice")
    seed_restricted(h, scoped, repository_id, "contents_write")
    before = counts(h, repository_id)
    before_markers = markers(h)
    holder = Session(h)
    barrier = PreparedBarrier(h)
    worker = None
    probe = Session(h)
    evidence = {}
    try:
        # Park the push in the pre-receive/parent wait so the fixture cannot race
        # native CAS: admission already passed, Git has not reached its hook yet.
        hold_publication_key(holder, repository_id)
        worker = Push(h, remote(h, repo), "refs/heads/fence-b", scoped, work)
        wait_admitted(h, repository_id)
        barrier.install()
        release_publication_key(holder, repository_id)
        wait_barrier_entered(barrier)
        evidence["wrapper_pids"] = barrier_pids(h, barrier)
        assert set(markers(h)) - set(before_markers), "parent never granted before the native barrier"
        assert ref_oid(h, repo, "refs/heads/fence-b") is None, "native Git committed refs before the barrier"
        evidence["token_row_share_holders"] = token_row_share_holders(h)
        assert evidence["token_row_share_holders"], "no backend held the token row FOR SHARE at the barrier"
        read_only = expect_sqlstate(h, probe, "UPDATE tokens SET read_only = true WHERE id = "
                                    + quote(scoped["token_id"]))
        narrowing = expect_sqlstate(h, probe, "SELECT 1 FROM tokens WHERE id = "
                                    + quote(scoped["token_id"]) + " FOR UPDATE")
        interim = counts(h, repository_id)
        assert interim["operations"] == before["operations"], interim
        assert interim["outbox"] == before["outbox"], interim
        native["entered"] = True
        native["evidence"] = {"wrapper_pids": evidence["wrapper_pids"],
                              "token_row_share_holders": evidence["token_row_share_holders"],
                              "ref_absent": True, "grant_observed": True,
                              "blocked_sqlstates": {"read_only": read_only, "grant_writer": narrowing}}
        # Restore the installed hook before releasing the barrier: the fixture
        # process already holds its script in memory, and the server verifies the
        # hook layout again before journal settlement.
        barrier.restore()
        barrier.release.touch()
        code, err = worker.wait()
        worker = None
        assert code == 0, "push failed after the CAS barrier was released: " + err
        assert ref_oid(h, repo, "refs/heads/fence-b") is not None, "push succeeded without a ref"
        assert counts(h, repository_id)["outbox"] == before["outbox"] + 1
        assert counts(h, repository_id)["operations"] == before["operations"] + 1
        assert diagnostics_evidence(h, repository_id, "ungranted_without_hooks") not in (None, "true"), \
            "a granted native CAS was settled as an ungranted no-ref-change abort"
        # Settlement released the lock, so the same writes now succeed.
        settled = wait_sqlstate(h, probe, "SELECT 1 FROM tokens WHERE id = "
                                + quote(scoped["token_id"]) + " FOR UPDATE")
        probe.send("UPDATE tokens SET read_only = true WHERE id = " + quote(scoped["token_id"]))
        assert probe.send("SELECT count(*) FROM token_repository_scopes WHERE token_id = "
                          + quote(scoped["token_id"])) == "1", "seeded narrowing grant disappeared"
        return ("native child entered the prepared barrier (wrapper pid %r, token row share holders %r); "
                "token FOR SHARE blocked read_only flip (%s) and grant writer (%s) before CAS; settlement "
                "released both (%r)" % (evidence["wrapper_pids"], evidence["token_row_share_holders"],
                                        read_only, narrowing, settled[-1:]))
    finally:
        if worker is not None:
            worker.cancel()
            worker.wait()
        barrier.cleanup()
        probe.close()
        holder.close()


def case_cancel_releases(h, work):
    repo = create_repo(h, "fence-c")
    repository_id = repo_id(h, repo)
    h.git("push", remote(h, repo), "HEAD:refs/heads/main", cwd=work, token=h.alice)
    push_token = h.account("create-token", "alice")
    before = counts(h, repository_id)
    before_markers = markers(h)
    holder = Session(h)
    revoker = Session(h)
    worker = None
    try:
        hold_publication_key(holder, repository_id)
        worker = Push(h, remote(h, repo), "refs/heads/fence-c", push_token, work)
        wait_admitted(h, repository_id)
        revoker.send("BEGIN; SELECT id FROM tokens WHERE id = " + quote(push_token["token_id"])
                     + " FOR UPDATE")
        release_publication_key(holder, repository_id)
        wait = wait_owner_lock_wait(h, revoker.pid)
        children = h.descendants()
        # The HTTP client disappears mid-authorisation; the blocked owner must
        # reach a terminal, non-publishing state on its own bounded timeout while
        # the revoker still holds the token row.
        worker.cancel()
        worker.wait()
        worker = None
        gone = wait_owner_backend_gone(h, wait["owner_pid"], timeout=30)
        revoker.send("UPDATE tokens SET revoked = true WHERE id = " + quote(push_token["token_id"])
                     + "; COMMIT")
        available = probe_row_available(h, push_token["token_id"])
        wait_no_descendants(h, children)
        h.assert_no_live_descendants(children, "client cancel during late authorisation")
        assert_no_new_publication(h, repository_id, before, repo, "refs/heads/fence-c",
                                  "canceled push published")
        assert not (set(markers(h)) - set(before_markers)), "canceled push left an ACK marker"
        fresh = h.account("create-token", "alice")
        push_with_retry(h, remote(h, repo), "refs/heads/fence-c", fresh, work)
        assert ref_oid(h, repo, "refs/heads/fence-c") is not None
        return ("owner backend %d left its transaction while the revoker held the row (%r); independent "
                "session %d acquired the token row FOR UPDATE NOWAIT; fresh push published"
                % (wait["owner_pid"], gone, available["pid"]))
    finally:
        if worker is not None:
            worker.cancel()
            worker.wait()
        revoker.close()
        holder.close()


def main():
    parser = argparse.ArgumentParser(description="Git native CAS parent-token lock fence (real service)")
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, help="Write machine-readable JSON report (no credentials)")
    parser.add_argument("--keep", action="store_true", help="Keep temporary data directory")
    args = parser.parse_args()

    h = Harness(args)
    h.env["ROOTYARD_OUTBOX_WORKER"] = "false"
    native = {"entered": False, "evidence": None}
    exit_code = 1
    try:
        h.setup()
        work = prepare_work(h)
        for name, fn in (
            ("cas.revoker_first_denied_then_valid_push", lambda: case_revoker_first(h, work)),
            ("cas.owner_token_lock_outlives_native_cas", lambda: case_lock_outlives_cas(h, work, native)),
            ("cas.cancel_during_authorization_releases", lambda: case_cancel_releases(h, work)),
        ):
            run_case(h, name, fn)
        exit_code = 0 if all(case["status"] == "passed" for case in h.results) else 1
    except Exception as error:  # noqa: BLE001
        h.results.append(dict(name="harness", status="failed", error=h.redact(error),
                              trace=h.redact(traceback.format_exc())[-2000:]))
        exit_code = 1
    finally:
        try:
            h.cleanup()
        except Exception as error:  # noqa: BLE001
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            exit_code = 1
        report = dict(
            suite="pat_git_publication_fence",
            # Setup and harness results are not native evidence: only a real push
            # that entered the native CAS barrier counts.
            executed_native=bool(native["entered"]),
            native_barrier=native["evidence"],
            ok=exit_code == 0,
            coverage_complete=False,
            untested_scope=[
                "Restricted token issuance is still SQL-seeded; the public issuer/API/UI is a separate branch and is not claimed released.",
                "Exact browser-child inheritance for a restricted parent remains unimplemented and is not covered here.",
                "The token grant list/read API is not exercised; grants are seeded by SQL inside the isolated schema.",
            ],
            cases=h.results,
            notes=[
                "Every case drives one real `git push` over Git HTTP against the real binary; no helper transaction substitutes for native CAS.",
                "Case A uses the documented repository publication advisory key so the revoker owns the token row before the owner's late authorisation; the resulting wait is read from pg_stat_activity and its blockers from pg_blocking_pids (the statement carries $1, never the raw token).",
                "Case B holds the push in the pre-receive/parent wait, then installs a test-owned synthetic fixture for the installed reference-transaction hook: for $1=prepared only it touches `entered` and waits (bounded) for `release`, then execs a copied genuine hook with the same argv/stdin/environment. It asserts SQLSTATE 55P03 for the read_only flip and the grant-writer FOR UPDATE step while the owner still holds the row FOR SHARE, then restores the hook and releases the barrier.",
                "Case C kills the HTTP client while the owner waits; the owner backend must vanish from pg_stat_activity while the revoker still holds the token row, and an independent session proves the row is lockable with a real SELECT ... FOR UPDATE NOWAIT.",
                "Refusal evidence counts every git_operations row for the repository (outcome has no 'committed' value), plus outbox events, committed admissions and the published ref.",
                "Restricted authority is seeded by SQL because no public issuer exists.",
            ],
            limitations=[
                "Loopback single-node timings are not a scalability benchmark.",
                "The Case B barrier is a temporary test-owned fixture over the installed hook entry; .runner and all production files are unmodified and the original symlink is restored before the barrier is released.",
                "Not executed by the authoring worker (no cargo build, no native run there).",
            ],
        )
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
