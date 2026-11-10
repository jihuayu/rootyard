#!/usr/bin/env python3
"""Focused tests for the bounded serve-blob lifecycle-barrier probe.

Unit only: no native binary, PostgreSQL or S3 is required. The probe is driven
with tiny stand-in executables that write private logs, exit, or keep serving on
the probe-owned loopback bind, so every classification and the fail-closed
timeout/reap path is exercised without touching real fixtures.
"""
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import platform
import shutil
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_blob_barrier_probe as probe  # noqa: E402

AUTO = probe.BARRIER_REFUSALS["auto"]
EXTERNAL = probe.BARRIER_REFUSALS["external"]
FAILURE = probe.STARTUP_FAILURE
SECRET = "s3-secret-value-do-not-leak"
DSN = "postgresql://rootyard:pg-password-value@127.0.0.1:55432/rootyard_protocol"
ENDPOINT = "http://127.0.0.1:3900"
PROBE_ENV = {"DATABASE_URL": DSN, "ROOTYARD_BLOB_SECRET_ACCESS_KEY": SECRET,
             "ROOTYARD_BLOB_ENDPOINT": ENDPOINT, "PATH": os.environ.get("PATH", "")}
SECRETS = [SECRET, DSN, "pg-password-value", ENDPOINT]


def write_executable(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def run_probe(script, mode="external", window=3.0, root=None):
    return probe.serving_barrier_probe(script, PROBE_ENV, mode, root, secrets=SECRETS, window=window)


LINUX = platform.system() == "Linux"
# Apostrophes in a shell-quoted string would truncate the message; $'\x27'
# carries the same byte, so the stand-in still emits the real text.
APOSTROPHE = "$'\\x27'"


def quote(text):
    return text.replace("'", APOSTROPHE)


def refusal_body(context, message, code, follow=""):
    return (f"printf 'Error: {quote(context)}\\nCaused by:\\n    0: {quote(message)}\\n' >&2\n"
            + follow + f"exit {code}\n")


class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.owned = self.root / "owned"
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def stand_in(self, body):
        """A `#!/bin/sh` stand-in that ignores argv and runs `body`."""
        self.counter += 1
        return write_executable(self.root / ("stand-in-" + str(self.counter)), body)

    def test_exact_refusal_per_mode_is_the_only_pass(self):
        # Real stderr shape: an anyhow block with an indented numeric cause.
        for mode, expected, other in (("external", EXTERNAL, AUTO), ("auto", AUTO, EXTERNAL)):
            script = self.stand_in(
                refusal_body(FAILURE, expected, 1, refusal_body(FAILURE, other, 1).replace("exit 1\n", ""))
                + "echo \"secret is $ROOTYARD_BLOB_SECRET_ACCESS_KEY in $DATABASE_URL\" >&1\nexit 1\n")
            outcome = run_probe(script, mode, root=self.owned)
            self.assertEqual(outcome["status"], "refused", outcome)
            self.assertEqual(outcome.get("exit"), 1, outcome)
            self.assertTrue(outcome["reaped"])
            # Only fixed facts are kept: no raw cause, key or DSN.
            self.assertEqual(outcome["diagnostics"], [
                "startup refusal context (" + FAILURE + ")", "barrier message"])
            text = repr(outcome)
            for leaked in SECRETS:
                self.assertNotIn(leaked, text)
        self.assertTrue(self.owned.is_dir())

    def test_any_other_exit_is_unknown_never_a_refusal(self):
        cases = {
            "unrelated-non-zero": "echo 'Error: invalid Blob profile' >&2; exit 1\n",
            "own-context-but-foreign-cause": refusal_body(FAILURE, "invalid Blob profile", 1),
            "normal-exit-zero": refusal_body(FAILURE, EXTERNAL, 0),
            "wrong-mode-message": refusal_body(FAILURE, AUTO, 1),
            "message-without-startup-context": f"printf '    0: {quote(EXTERNAL)}\\n' >&2; exit 1\n",
            "silent-failure": "exit 7\n",
            "refusal-then-zero": refusal_body(FAILURE, EXTERNAL, 0),
        }
        for name, body in cases.items():
            outcome = run_probe(self.stand_in(body), "external", root=self.owned)
            self.assertEqual(outcome["status"], "unknown", name + ": " + probe.describe(outcome))
            self.assertTrue(outcome["reaped"])

    def test_a_live_child_without_a_response_is_unknown_not_started(self):
        # Listening but never answering, and never listening: neither proves
        # serving, so the end of the observation window is fail-closed.
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        bind = "127.0.0.1:" + str(holder.getsockname()[1])
        try:
            for prebound in (bind, None):
                outcome = probe.serving_barrier_probe(self.stand_in("exec sleep 60\n"), dict(PROBE_ENV),
                                                      "external", self.owned, window=0.5, prebound=prebound)
                self.assertEqual(outcome["status"], "unknown", probe.describe(outcome))
                self.assertTrue(outcome["alive"])
                self.assertIn("alive", outcome["reason"])
                self.assertTrue(outcome["reaped"])
                self.assertTrue(outcome["quiescent"])
                self.assertNotIn("returncode", outcome)
        finally:
            holder.close()

    def test_timeout_is_unknown_fail_closed_and_reaps_its_private_log(self):
        pidfile = self.root / "child.pid"
        script = self.stand_in("trap '' TERM HUP INT\n"
                               f"sh -c 'echo $$ > {pidfile}; exec sleep 60' &\nwait\n")
        started = time.monotonic()
        outcome = run_probe(script, "external", window=0.5, root=self.owned)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(outcome["status"], "unknown", outcome)
        self.assertTrue(outcome["reaped"])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    @unittest.skipUnless(LINUX, "process-group quiescence proof is Linux /proc only")
    def test_a_leader_that_exits_leaving_an_owned_child_is_killed_and_proven(self):
        # The leader writes the refusal and exits; its session child keeps
        # running. The probe must still kill that exact owned PGID and prove
        # quiescence, without scanning or naming unrelated processes.
        pidfile = self.root / "child.pid"
        script = self.stand_in(refusal_body(FAILURE, EXTERNAL, 1, f"(trap '' TERM; echo $$ > {pidfile}; exec sleep 60) &\n"))
        outcome = run_probe(script, window=5, root=self.owned)
        self.assertEqual(outcome["status"], "refused", outcome)
        self.assertTrue(outcome["reaped"])
        self.assertTrue(outcome["quiescent"])
        deadline = time.monotonic() + 5
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_without_proc_the_group_is_reaped_but_never_claimed_quiescent(self):
        original = probe._proc_available
        probe._proc_available = lambda: False
        try:
            with self.assertRaises(NotImplementedError):
                probe._group_members(os.getpid())
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
            self.assertTrue(probe._reap_owned(child, window=5))
            self.assertIsNotNone(child.returncode)
        finally:
            probe._proc_available = original

    def test_a_ready_listener_is_a_violation_and_is_reaped(self):
        bind, holder = probe.reserve_loopback()

        def answer(connection, _address):
            connection.makefile("rb").readline()
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            connection.close()

        listener = threading.Thread(target=_serve, args=(holder, answer), daemon=True)
        listener.start()
        deadline = time.monotonic() + 5
        while not probe._listening(bind):
            self.assertLess(time.monotonic(), deadline, "stand-in loopback listener is not answering")
            time.sleep(0.05)
        try:
            outcome = probe.serving_barrier_probe(self.stand_in("exec sleep 60\n"),
                                                  dict(PROBE_ENV), "auto", self.owned,
                                                  window=10, prebound=bind)
        finally:
            holder.close()
            listener.join(timeout=5)
        self.assertEqual(outcome["status"], "started", outcome)
        self.assertIn("HTTP", outcome["reason"])
        self.assertTrue(outcome["reaped"])

    def test_probe_chooses_its_own_free_loopback_bind(self):
        taken, holder = probe.reserve_loopback()
        try:
            bind = probe.loopback_bind()
            self.assertTrue(bind.startswith("127.0.0.1:"))
            self.assertNotEqual(int(bind.rsplit(":", 1)[1]), int(taken.rsplit(":", 1)[1]))
        finally:
            holder.close()

    def test_a_dependency_panic_is_unknown_with_a_private_fixed_context(self):
        script = self.root / "dependency-panic"
        script.write_text(
            "#!" + shutil.which("python3") + "\n"
            "import sys\n"
            "sys.stderr.write(\"thread 'main' (7) panicked at /opt/cargo/registry/fuser-0.16.0/build.rs:9:5:\\n\"\n"
            "                \"not implemented: Building without libfuse is only supported on Linux\\n\"\n"
            "                \"note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\\n\")\n"
            "sys.exit(101)\n")
        script.chmod(0o755)
        outcome = run_probe(str(script), root=self.owned)
        self.assertEqual(outcome["status"], "unknown", outcome)
        self.assertEqual(outcome["exit"], 101)
        self.assertEqual(outcome["diagnostics"], ["cause dependency panic"])
        self.assertNotIn("registry", repr(outcome))
        self.assertNotIn("libfuse", repr(outcome))

    def test_reported_diagnostics_keep_only_fixed_vocabulary_and_are_redacted(self):
        unknown_dsn = "postgresql://deploy:Sup3rNewPass@db.internal:5432/rootyard_unknown"
        log = self.root / "log"
        log.write_text(
            "Error: " + FAILURE + "\n"
            "Caused by:\n"
            "    0: lifecycle barrier failed at " + unknown_dsn + "\n\n"
            "some unrelated banner " + SECRET + "\n"
            "[2026-01-01T00:00:00Z WARN rootyard] servicing database at " + unknown_dsn + "\n"
            "access_key = \"" + SECRET + "\"\n"
            "thread 'main' (7) panicked at src/main.rs:34:5:\n"
            "Error: workspace secret " + SECRET + "\n"
            "thread 'main' (8) panicked at /Users/x/fuser-0.16.0/build.rs:9:5:\n"
            "not implemented: " + SECRET + "\n")
        diagnostics = probe.own_lines(log, SECRETS)
        self.assertEqual(diagnostics, [
            "startup refusal context (" + FAILURE + ")",
            "cause lifecycle barrier",
            "cause dependency panic"])
        text = repr(diagnostics)
        for leaked in (unknown_dsn, "Sup3rNewPass", SECRET, DSN, "db.internal", "lifecycle barrier failed"):
            self.assertNotIn(leaked, text)

    def test_scrub_removes_an_unlisted_dsn_and_credentials(self):
        for raw in (DSN, "postgres://u:p@h:1/d", "s3://bucket/key?X-Amz-Credential=c",
                    "ROOTYARD_TEST_DATABASE_URL=postgres://u:p@h/d", "password=hunter2-unknown",
                    "token: abc", "https://user:pw@example.test/x"):
            self.assertNotIn("hunter2", probe.scrub(raw))
            self.assertNotIn("://", probe.scrub(raw))
            self.assertNotIn("u:p@", probe.scrub(raw))
        self.assertEqual(probe.scrub("Error: could not open the lifecycle barrier session at " + DSN),
                         "Error: could not open the lifecycle barrier session at [REDACTED]")
        self.assertEqual(probe.describe({"mode": "external", "status": "unknown", "reason": "exit 0"}),
                         "external; unknown; exit 0")


def _reachable(bind):
    try:
        with socket.create_connection(tuple(bind.rsplit(":", 1)), timeout=0.2) as connection:
            connection.sendall(b"GET /health/ready HTTP/1.0\r\n\r\n")
            return connection.recv(64).startswith(b"HTTP/")
    except OSError:
        return False


def _serve(server, handler):
    while True:
        try:
            connection, address = server.accept()
        except OSError:
            return
        handler(connection, address)


if __name__ == "__main__":
    unittest.main()
