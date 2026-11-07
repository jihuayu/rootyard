#!/usr/bin/env python3
"""Git-native CAS parent-token lock proof against the REAL service.

Requires the same environment as ``tests/e2e.py``: ``ROOTYARD_TEST_DATABASE_URL``
plus a built CLI supplied with ``--binary``. The server, the SQL database and
native Git are real; nothing is mocked and no helper short transaction stands in
for native CAS.

What is proven (each case uses one real ``git push`` over Git HTTP):
  A. A revoker session holds ``FOR UPDATE`` on the push token while the parent
     publication owner is inside its late authorisation. The wait is observed in
     ``pg_stat_activity``/``pg_locks`` (no sleep-and-hope). Committing the
     revocation refuses the push: no ref, no outbox event, no committed
     operation and no ``publication.grant`` acknowledgement. A different valid
     token then pushes the same ref successfully.
  B. The parent has already granted and holds the token ``FOR SHARE`` while the
     native child is stopped at the reference-transaction barrier (SIGSTOP of
     the sandboxed Git process group immediately after the parent's grant
     marker, before Git commits refs). ``UPDATE ... SET read_only`` and the
     documented grant-writer ``SELECT ... FOR UPDATE`` step both fail with
     SQLSTATE ``55P03`` under ``lock_timeout=100ms``. After SIGCONT the push
     completes and journal settlement releases the lock, so the same statements
     then succeed.
  C. The HTTP client is killed while the owner is waiting in the late
     authorisation. The owner/child quiesce without publishing: no ref, no
     outbox event, no committed operation, no grant marker; the token lock
     becomes re-acquirable and a fresh push with a new token succeeds.

Deterministic ordering without new production back doors:
  * Case A holds the *documented* repository publication advisory key
    (``rootyard-publication-v1:<repo>``, the same key migrations use) so the
    owner cannot enter its late authorisation before the revoker owns the token
    row. It is released with ``pg_advisory_unlock`` and the real ``FOR SHARE``
    wait is then read from the live backend.
  * Case B observes the parent's own ``publication.grant`` marker (written
    before the first ACK) and stops the native process group at that instant;
    the pre-receive hook then blocks on the parent for its ACK, which is the
    native CAS boundary. No test hook was added to the server for this.

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
LOCK_WAIT_SQL = (
    "SELECT count(*) FROM pg_stat_activity "
    "WHERE wait_event_type = 'Lock' "
    "AND query LIKE '%SELECT true FROM tokens t WHERE t.id=$1%' "
    "AND query LIKE '%FOR SHARE OF t%'"
)
NOT_GRANTED_SQL = (
    "SELECT count(*) FROM pg_locks l WHERE NOT l.granted AND l.relation = 'tokens'::regclass"
)


def quote(value):
    """Quote a server-issued identifier for the isolated test schema."""
    return "'" + str(value).replace("'", "''") + "'"


class Session:
    """One long-lived psql session used only to hold real row/advisory locks."""

    def __init__(self, h):
        self.h = h
        self.proc = subprocess.Popen(
            ["stdbuf", "-oL", "-eL", "psql", "--dbname", h.db, "-X", "-At", "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=h.env,
        )
        self.seq = 0

    def send(self, sql):
        self.seq += 1
        marker = "__fence_%d__" % self.seq
        try:
            self.proc.stdin.write((sql + "\n\\echo " + marker + "\n").encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError) as error:
            raise AssertionError(self.h.redact("lock session died: " + self.tail())) from error
        lines = []
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise AssertionError(self.h.redact("lock session ended early: " + self.tail()))
            text = line.decode(errors="replace").rstrip("\n")
            if text == marker:
                return "\n".join(lines)
            lines.append(text)

    def tail(self):
        try:
            self.proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            _, err = self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _, err = self.proc.communicate()
        return err.decode(errors="replace")[-800:]

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
    return sorted(str(path.relative_to(h.root)) for path in (Path(h.root) / "data").rglob("publication.grant"))


def counts(h, repository_id):
    return json.loads(h.sql(
        "SELECT json_build_object("
        "'committed', (SELECT count(*) FROM git_operations WHERE repository_id=" + quote(repository_id)
        + " AND outcome='committed'),"
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


def wait_owner_lock_wait(h, timeout=20):
    """Return real backend evidence of the owner's waiting `FOR SHARE`."""
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        waiting = int(h.sql(LOCK_WAIT_SQL))
        ungranted = int(h.sql(NOT_GRANTED_SQL))
        last = {"waiting_backends": waiting, "ungranted_token_locks": ungranted}
        if waiting:
            row = h.sql("SELECT pid::text || '|' || wait_event || '|' || state FROM pg_stat_activity "
                        "WHERE wait_event_type='Lock' AND query LIKE '%SELECT true FROM tokens t WHERE t.id=$1%' "
                        "AND query LIKE '%FOR SHARE OF t%' LIMIT 1")
            last["backend"] = row
            assert ungranted > 0, "owner waited without an ungranted token lock: " + repr(last)
            return last
        time.sleep(0.02)
    raise AssertionError("publication owner never waited on the token FOR SHARE: " + repr(last))


def expect_sqlstate(h, session, statement, expected="55P03", lock_timeout="100ms"):
    session.send("SET lock_timeout = '" + lock_timeout + "'")
    session.send("CREATE TEMP TABLE IF NOT EXISTS fence_outcome(k text)")
    session.send("TRUNCATE fence_outcome")
    session.send("DO $$ BEGIN BEGIN " + statement + "; INSERT INTO fence_outcome VALUES ('RAN'); "
                 "EXCEPTION WHEN OTHERS THEN INSERT INTO fence_outcome VALUES (SQLSTATE); END; END $$")
    outcome = session.send("SELECT k FROM fence_outcome")
    session.send("RESET lock_timeout")
    assert outcome == expected, "expected SQLSTATE %s, got %r" % (expected, outcome)
    return outcome


def git_group(h):
    """Return (pid, pgid) of the live native http-backend child, if any."""
    for pid in h.descendants():
        try:
            command = Path("/proc/%d/cmdline" % pid).read_bytes()
            stat = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if b"http-backend" in command and stat[0] not in ("Z", "X"):
            return pid, int(stat[2])
    return None, None


def stop_child_at_grant(h, before=(), timeout=25):
    """Wait for a new grant marker, then SIGSTOP the native process group."""
    known = set(before)
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if set(markers(h)) - known:
            pid, pgid = git_group(h)
            if pid is None:
                continue
            os.killpg(pgid, signal.SIGSTOP)
            state = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
            assert state[0] == "T", "native child did not stop: %r" % (state[0],)
            return {"pid": pid, "pgid": pgid, "markers": len(markers(h))}
        time.sleep(0.002)
    raise AssertionError("no native child was observable after the parent grant marker")


def resume_child(evidence):
    os.killpg(evidence["pgid"], signal.SIGCONT)


def wait_lock_free(h, timeout=20):
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        last = int(h.sql(NOT_GRANTED_SQL))
        if last == 0:
            return
        time.sleep(0.02)
    raise AssertionError("token lock was never released: %r" % (last,))


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
        wait = wait_owner_lock_wait(h)
        assert not (set(markers(h)) - set(before_markers)), "grant marker existed before the late authorisation"
        revoker.send("UPDATE tokens SET revoked = true WHERE id = "
                     + quote(push_token["token_id"]) + "; COMMIT")
        code, err = worker.wait()
        worker = None
        assert code != 0, "revoked token still published: " + err
        after = counts(h, repository_id)
        assert after["committed"] == before["committed"], after
        assert after["outbox"] == before["outbox"], after
        assert after["committed_admissions"] == before["committed_admissions"], after
        assert ref_oid(h, repo, "refs/heads/fence-a") is None, "ref was published after revocation"
        assert not (set(markers(h)) - set(before_markers)), "an ACK marker survived the refused push"
        # A different valid token must still be able to publish the same ref.
        valid = h.account("create-token", "alice")
        push_with_retry(h, remote(h, repo), "refs/heads/fence-a", valid, work)
        assert ref_oid(h, repo, "refs/heads/fence-a") is not None
        assert counts(h, repository_id)["outbox"] == before["outbox"] + 1
        return "owner FOR SHARE wait observed in pg_stat_activity/pg_locks; revocation refused the push; valid token published"
    finally:
        if worker is not None:
            worker.cancel()
            worker.wait()
        revoker.close()
        holder.close()


def case_lock_outlives_cas(h, work):
    repo = create_repo(h, "fence-b")
    repository_id = repo_id(h, repo)
    h.git("push", remote(h, repo), "HEAD:refs/heads/main", cwd=work, token=h.alice)
    scoped = h.account("create-token", "alice")
    seed_restricted(h, scoped, repository_id, "contents_write")
    before = counts(h, repository_id)
    before_markers = markers(h)
    worker = Push(h, remote(h, repo), "refs/heads/fence-b", scoped, work)
    evidence = None
    probe = Session(h)
    try:
        evidence = stop_child_at_grant(h, before=before_markers)
        assert ref_oid(h, repo, "refs/heads/fence-b") is None, "native Git committed refs before the barrier"
        read_only = expect_sqlstate(h, probe, "UPDATE tokens SET read_only = true WHERE id = "
                                    + quote(scoped["token_id"]))
        narrowing = expect_sqlstate(h, probe, "SELECT 1 FROM tokens WHERE id = "
                                    + quote(scoped["token_id"]) + " FOR UPDATE")
        interim = counts(h, repository_id)
        assert interim["outbox"] == before["outbox"], interim
        resume_child(evidence)
        code, err = worker.wait()
        worker = None
        assert code == 0, "push failed after the CAS barrier was released: " + err
        assert ref_oid(h, repo, "refs/heads/fence-b") is not None, "push succeeded without a ref"
        assert counts(h, repository_id)["outbox"] == before["outbox"] + 1
        # Settlement released the lock, so the same writes now succeed.
        probe.send("UPDATE tokens SET read_only = true WHERE id = " + quote(scoped["token_id"]))
        probe.send("SELECT 1 FROM tokens WHERE id = " + quote(scoped["token_id"]) + " FOR UPDATE")
        assert probe.send("SELECT count(*) FROM token_repository_scopes WHERE token_id = "
                          + quote(scoped["token_id"])) == "1", "seeded narrowing grant disappeared"
        return ("token FOR SHARE blocked read_only flip (%s) and grant writer (%s) while the native child was "
                "stopped at CAS; settlement released both" % (read_only, narrowing))
    finally:
        if worker is not None:
            worker.cancel()
            worker.wait()
        if evidence is not None:
            try:
                resume_child(evidence)
            except (ProcessLookupError, PermissionError):
                pass
        probe.close()


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
        wait_owner_lock_wait(h)
        children = h.descendants()
        # The HTTP client disappears mid-authorisation; the blocked owner must
        # reach a terminal, non-publishing state on its own bounded timeout.
        worker.cancel()
        worker.wait()
        worker = None
        wait_lock_free(h, timeout=30)
        revoker.send("UPDATE tokens SET revoked = true WHERE id = " + quote(push_token["token_id"])
                     + "; COMMIT")
        wait_no_descendants(h, children)
        h.assert_no_live_descendants(children, "client cancel during late authorisation")
        after = counts(h, repository_id)
        assert after["committed"] == before["committed"], after
        assert after["outbox"] == before["outbox"], after
        assert ref_oid(h, repo, "refs/heads/fence-c") is None, "canceled push still published a ref"
        assert not (set(markers(h)) - set(before_markers)), "canceled push left an ACK marker"
        fresh = h.account("create-token", "alice")
        push_with_retry(h, remote(h, repo), "refs/heads/fence-c", fresh, work)
        assert ref_oid(h, repo, "refs/heads/fence-c") is not None
        return "client cancel left no publication; token lock re-acquired; fresh push published"
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
    exit_code = 1
    try:
        h.setup()
        work = prepare_work(h)
        for name, fn in (
            ("cas.revoker_first_denied_then_valid_push", lambda: case_revoker_first(h, work)),
            ("cas.owner_token_lock_outlives_native_cas", lambda: case_lock_outlives_cas(h, work)),
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
            executed_native=bool(h.results),
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
                "Case A uses the documented repository publication advisory key so the revoker owns the token row before the owner's late authorisation; the resulting wait is read from pg_stat_activity and pg_locks.",
                "Case B stops the native Git process group immediately after the parent's own publication.grant marker and asserts SQLSTATE 55P03 for the read_only flip and the grant-writer FOR UPDATE step while the owner still holds FOR SHARE.",
                "Case C kills the HTTP client while the owner waits; the owner's statement_timeout and the post-SQL closed check end the transaction without publishing.",
                "Restricted authority is seeded by SQL because no public issuer exists.",
            ],
            limitations=[
                "Loopback single-node timings are not a scalability benchmark.",
                "SIGSTOP is used as an external observation barrier for the native child; no server test hook was added.",
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
