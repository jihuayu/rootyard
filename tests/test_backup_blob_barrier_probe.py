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
from unittest import mock

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


def single_cause_body(context, message, code, follow=""):
    """anyhow's standard single-cause form: the cause carries no `0:` index."""
    return (f"printf 'Error: {quote(context)}\\nCaused by:\\n    {quote(message)}\\n' >&2\n"
            + follow + f"exit {code}\n")


def separated_body(context, message, code, follow=""):
    """The standard layout where an empty separator line divides context and causes."""
    return (f"printf 'Error: {quote(context)}\\n\\nCaused by:\\n    {quote(message)}\\n\\n' >&2\n"
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
        # Both standard anyhow shapes of the real stderr: the product wraps the
        # barrier message in one context and anyhow prints one single cause.
        for shape in (single_cause_body, refusal_body):
            for mode, expected in (("external", EXTERNAL), ("auto", AUTO)):
                script = self.stand_in(
                    shape(FAILURE, expected, 1)
                    + "echo \"secret is $ROOTYARD_BLOB_SECRET_ACCESS_KEY in $DATABASE_URL\" >&1\nexit 1\n")
                outcome = run_probe(script, mode, root=self.owned)
                name = shape.__name__ + "/" + mode
                self.assertEqual(outcome["status"], "refused", name + ": " + probe.describe(outcome))
                self.assertEqual(outcome.get("exit"), 1, outcome)
                self.assertTrue(outcome["reaped"])
                # Only fixed facts are kept: no raw cause, key or DSN.
                self.assertEqual(outcome["diagnostics"], [
                    "startup refusal context (" + FAILURE + ")",
                    "cause lifecycle barrier", "barrier message"], name)
                text = repr(outcome)
                for leaked in SECRETS:
                    self.assertNotIn(leaked, text)
        self.assertTrue(self.owned.is_dir())

    def test_separated_standard_block_is_the_exact_refusal(self):
        # An empty separator line after the context, then the standard block:
        # either the single-cause or the numbered form, with trailing blanks.
        for mode, expected in (("external", EXTERNAL), ("auto", AUTO)):
            for shape in (separated_body, refusal_body):
                body = shape(FAILURE, expected, 1) if shape is separated_body else (
                    # Direct standard numbered block (no separator), trailing blanks.
                    f"printf 'Error: {quote(FAILURE)}\\nCaused by:\\n    0: {quote(expected)}\\n\\n' >&2\n"
                    "exit 1\n")
                outcome = run_probe(self.stand_in(body), mode, root=self.owned)
                name = shape.__name__ + "/" + mode
                self.assertEqual(outcome["status"], "refused", name + ": " + probe.describe(outcome))
                self.assertEqual(outcome.get("exit"), 1, outcome)
                self.assertTrue(outcome["reaped"])
                diagnostics = outcome["diagnostics"]
                self.assertIn("startup refusal context (" + FAILURE + ")", diagnostics, name)
                self.assertIn("barrier message", diagnostics, name)
                self.assertTrue(set(diagnostics) <= {
                    "startup refusal context (" + FAILURE + ")",
                    "cause lifecycle barrier", "cause serving barrier",
                    "cause dependency panic", "barrier message"}, name + ": " + repr(diagnostics))

    def test_separated_blocks_that_are_not_the_exact_refusal(self):
        cases = {
            "mixed-single-then-numbered": "Caused by:\n    " + EXTERNAL + "\n    0: " + EXTERNAL + "\n",
            "mixed-numbered-then-single": "Caused by:\n    0: " + EXTERNAL + "\n    " + EXTERNAL + "\n",
            "numbered-then-bare-refusal-no-marker": "    0: " + EXTERNAL + "\n    " + EXTERNAL + "\n",
            "non-sequential-numbered": "Caused by:\n    0: " + EXTERNAL + "\n    2: " + EXTERNAL + "\n",
            "arbitrary-line-after-cause": "Caused by:\n    " + EXTERNAL + "\narbitrary line\n",
            "arbitrary-line-then-caused-by": "arbitrary line\nCaused by:\n    " + EXTERNAL + "\n",
            "two-unnumbered-causes": "Caused by:\n    " + EXTERNAL + "\n    " + EXTERNAL + "\n",
            "blank-then-unnumbered-no-marker": "\n    " + EXTERNAL + "\n",
            "blank-inside-numbered": "Caused by:\n    0: " + EXTERNAL + "\n\n    1: " + EXTERNAL + "\n",
        }
        for name, tail in cases.items():
            log = self.root / name
            log.write_text("Error: " + FAILURE + "\n\n" + tail)
            for mode in ("external", "auto"):
                self.assertFalse(probe._exact_refusal(log, SECRETS, mode), name + "/" + mode)
            # The context is kept, but a refusal string outside a complete
            # standard block is never reported as `barrier message`. Generic
            # fixed cause categories are optional and not asserted exactly.
            diagnostics = probe.own_lines(log, SECRETS)
            self.assertIn("startup refusal context (" + FAILURE + ")", diagnostics, name)
            self.assertNotIn("barrier message", diagnostics, name)
            self.assertTrue(set(diagnostics) <= {
                "startup refusal context (" + FAILURE + ")",
                "cause lifecycle barrier", "cause serving barrier",
                "cause dependency panic", "barrier message"}, name + ": " + repr(diagnostics))

    def test_a_second_error_block_is_not_the_separated_block(self):
        # The separated block must follow its own context; an unrelated error
        # block in between, or the cause after another error's block, fails.
        for name, text in {
            "other-error-before-block": (
                "Error: " + FAILURE + "\n\nError: invalid Blob profile\nCaused by:\n    " + EXTERNAL + "\n"),
            "other-error-in-causes": (
                "Error: " + FAILURE + "\n\nCaused by:\n    " + EXTERNAL + "\n\nError: invalid Blob profile\n"),
            "other-error-separates-context": (
                "Error: " + FAILURE + "\n\nError: other failure\nCaused by:\n    " + EXTERNAL + "\n"),
        }.items():
            log = self.root / name
            log.write_text(text)
            for mode in ("external", "auto"):
                self.assertFalse(probe._exact_refusal(log, SECRETS, mode), name + "/" + mode)
            self.assertIn("startup refusal context (" + FAILURE + ")", probe.own_lines(log, SECRETS))

    def test_full_cause_block_is_required_for_a_refusal(self):
        """The complete remaining block decides: a truncated fixed prefix is not a refusal."""
        path = self.root / "backup.log"

        # Seven fixed causes then one arbitrary eighth: a matching prefix must
        # never be accepted as a complete refusal, in any mode.
        lines = ["Error: " + FAILURE, "Caused by:"]
        lines += ["    {0}: {1}".format(index, EXTERNAL) for index in range(7)]
        lines.append("    7: unrelated failure")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(probe._exact_refusal(path, SECRETS, "external"))
        self.assertFalse(probe._exact_refusal(path, SECRETS, "auto"))

        # A long block of only the fixed cause is still classified for its
        # proper mode (not capped by count) and rejected for the other mode.
        lines = ["Error: " + FAILURE, "Caused by:"]
        lines += ["    {0}: {1}".format(index, EXTERNAL) for index in range(24)]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertTrue(probe._exact_refusal(path, SECRETS, "external"))
        self.assertFalse(probe._exact_refusal(path, SECRETS, "auto"))

    def test_single_cause_form_needs_the_context_and_the_mode(self):
        # The unnumbered message is only the refusal inside its own adjacent
        # startup block and for the mode it belongs to.
        cases = {
            "wrong-mode-single-cause": single_cause_body(FAILURE, AUTO, 1),
            "wrong-mode-separated": separated_body(FAILURE, AUTO, 1),
            "bare-message-without-context": f"printf '    {quote(EXTERNAL)}\\n' >&2; exit 1\n",
            "bare-numbered-without-context": f"printf '    0: {quote(EXTERNAL)}\\n' >&2; exit 1\n",
            "context-without-caused-by": f"printf 'Error: {quote(FAILURE)}\\n    {quote(EXTERNAL)}\\n' >&2; exit 1\n",
            # Two separator lines are not the one optional blank separator; each
            # also carries a second cause, so only the blank line can differ.
            "message-separated-by-two-blank-lines": (
                f"printf 'Error: {quote(FAILURE)}\\nCaused by:\\n\\n    {quote(EXTERNAL)}\\n"
                f"    1: {quote(AUTO)}\\n' >&2; exit 1\n"),
            "context-separated-by-two-blank-lines": (
                f"printf 'Error: {quote(FAILURE)}\\n\\n\\nCaused by:\\n    0: {quote(EXTERNAL)}\\n"
                f"    1: {quote(AUTO)}\\n' >&2; exit 1\n"),
            "message-before-context": (
                f"printf '    {quote(EXTERNAL)}\\nError: {quote(FAILURE)}\\nCaused by:\\n"
                f"    unrelated cause\\n' >&2; exit 1\n"),
            "arbitrary-nonzero-with-single-cause": single_cause_body("invalid Blob profile", EXTERNAL, 1),
            "single-cause-then-zero": single_cause_body(FAILURE, EXTERNAL, 0),
        }
        for name, body in cases.items():
            outcome = run_probe(self.stand_in(body), "external", root=self.owned)
            self.assertEqual(outcome["status"], "unknown", name + ": " + probe.describe(outcome))
            self.assertTrue(outcome["reaped"])

    def test_numbered_multi_cause_block_keeps_each_cause(self):
        log = self.root / "numbered"
        log.write_text(
            "Error: " + FAILURE + "\n"
            "Caused by:\n"
            "    0: lifecycle barrier: " + EXTERNAL + "\n"
            "    1: " + AUTO + "\n")
        self.assertFalse(probe._exact_refusal(log, SECRETS, "external"), "two causes are not one fixed message")
        self.assertFalse(probe._exact_refusal(log, SECRETS, "auto"))
        # Not the exact block, so no `barrier message`; each cause keeps only
        # its fixed category.
        self.assertEqual(probe.own_lines(log, SECRETS), [
            "startup refusal context (" + FAILURE + ")",
            "cause lifecycle barrier"])

    def test_numbered_causes_with_extra_arbitrary_entries_are_not_the_refusal(self):
        for extra in ("lifecycle barrier failed at " + DSN, "invalid Blob profile"):
            for position in ("before", "after"):
                numbered = ([extra, EXTERNAL] if position == "before" else [EXTERNAL, extra])
                log = self.root / ("numbered-" + position + "-" + str(len(extra)))
                log.write_text("Error: " + FAILURE + "\nCaused by:\n"
                               + "".join(f"    {index}: {text}\n" for index, text in enumerate(numbered)))
                self.assertFalse(probe._exact_refusal(log, SECRETS, "external"), position)
                # Not the exact block: the refusal string never becomes
                # `barrier message` here, only its fixed category may remain.
                self.assertNotIn("barrier message", probe.own_lines(log, SECRETS))
                self.assertIn("startup refusal context (" + FAILURE + ")", probe.own_lines(log, SECRETS))
                self.assertNotIn(extra, repr(probe.own_lines(log, SECRETS)))
        single = self.root / "single-with-extra"
        single.write_text("Error: " + FAILURE + "\nCaused by:\n    " + EXTERNAL + "\n    extra cause\n")
        self.assertFalse(probe._exact_refusal(single, SECRETS, "external"), "single form has one cause")
        # Indexes must run from `0:`; a well-formed block that does not is
        # still not the exact refusal, and never `barrier message`.
        offset = self.root / "not-starting-at-zero"
        offset.write_text("Error: " + FAILURE + "\nCaused by:\n    1: " + EXTERNAL + "\n    2: " + AUTO + "\n")
        self.assertFalse(probe._exact_refusal(offset, SECRETS, "external"))
        self.assertFalse(probe._exact_refusal(offset, SECRETS, "auto"))
        self.assertEqual(probe.own_lines(offset, SECRETS),
                         ["startup refusal context (" + FAILURE + ")", "cause lifecycle barrier"])

    def test_single_cause_diagnostics_stay_fixed_vocabulary(self):
        # The real shape: context + one unnumbered cause. A barrier cause is a
        # fixed label; any other cause keeps only its product category.
        refused = self.root / "single-barrier"
        refused.write_text("Error: " + FAILURE + "\nCaused by:\n    " + EXTERNAL + "\n")
        self.assertEqual(probe.own_lines(refused, SECRETS), [
            "startup refusal context (" + FAILURE + ")",
            "cause lifecycle barrier",
            "barrier message"])
        other = self.root / "single-other"
        other.write_text("Error: " + FAILURE + "\nCaused by:\n    lifecycle barrier failed at " + DSN + "\n")
        diagnostics = probe.own_lines(other, SECRETS)
        self.assertEqual(diagnostics, ["startup refusal context (" + FAILURE + ")", "cause lifecycle barrier"])
        for leaked in SECRETS:
            self.assertNotIn(leaked, repr(diagnostics))

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

    @unittest.skipUnless(LINUX, "process-group quiescence proof is Linux /proc only")
    def test_a_failure_after_popen_still_kills_the_owned_child_and_removes_its_directory(self):
        # own_lines raises after the real child has started: the error must
        # propagate, yet the probe's own child must be dead and the run-owned
        # directory gone, without signalling any unrelated pid or group.
        pidfile = self.root / "child.pid"
        script = self.stand_in(f"echo $$ > {pidfile}\nexec sleep 60\n")
        seen = {"pid": None}
        original = probe.own_lines

        def failing_after_popen(path, secrets=(), limit=16):
            if seen["pid"] is None:
                deadline = time.monotonic() + 5
                while not pidfile.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(pidfile.exists(), "the owned child never started")
                seen["pid"] = int(pidfile.read_text())
                raise RuntimeError("deliberate failure after Popen")
            return original(path, secrets, limit)

        with mock.patch.object(probe, "own_lines", failing_after_popen):
            with self.assertRaisesRegex(RuntimeError, "deliberate failure after Popen"):
                run_probe(script, "external", window=5, root=self.owned)
        pid = seen["pid"]
        self.assertIsNotNone(pid, "own_lines was never reached after Popen")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertNotIn(pid, probe._group_members(pid))
        leftovers = [entry for entry in self.owned.iterdir() if entry.name.startswith("probe-")]
        self.assertEqual(leftovers, [])

    @unittest.skipUnless(LINUX, "process census is Linux /proc only")
    def test_an_unreadable_or_malformed_own_stat_makes_the_census_unknown(self):
        # An own /proc stat read that raises or yields garbage must never be
        # skipped: doing so could falsely prove this live process absent.
        own_stat = "/proc/" + str(os.getpid()) + "/stat"
        real_read_text = Path.read_text

        def failing_read_text(self, *args, **kwargs):
            if str(self) == own_stat:
                raise PermissionError(13, "Permission denied", own_stat)
            return real_read_text(self, *args, **kwargs)

        def malformed_read_text(self, *args, **kwargs):
            if str(self) == own_stat:
                return "garbage without any closing parenthesis"
            return real_read_text(self, *args, **kwargs)

        try:
            with mock.patch.object(Path, "read_text", failing_read_text):
                with self.assertRaises(OSError):
                    probe._group_members(os.getpgrp())
            with mock.patch.object(Path, "read_text", malformed_read_text):
                with self.assertRaises(ValueError):
                    probe._group_members(os.getpgrp())
        finally:
            self.assertIs(Path.read_text, real_read_text)
        # Unpatched, the real /proc proves this process a live group member.
        self.assertIn(os.getpid(), probe._group_members(os.getpgrp()))

    @unittest.skipUnless(LINUX, "process-group quiescence proof is Linux /proc only")
    def test_a_failed_census_still_kills_the_owned_child_but_never_claims_quiescence(self):
        def unknown_census(group):
            raise PermissionError(13, "Permission denied", "/proc")

        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 start_new_session=True)
        try:
            with mock.patch.object(probe, "_group_members", unknown_census):
                self.assertFalse(probe._reap_owned(child, window=5))
        finally:
            try:
                os.killpg(child.pid, 9)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self.assertIsNotNone(child.returncode)
        self.assertEqual(probe._group_members(child.pid), [])

    def test_a_guarded_target_data_dir_is_never_used_by_the_child(self):
        # The watched target carries .rootyard-restore.guard; the child must see
        # a private guard-free data dir, the same DATABASE_URL, and no leak.
        target = self.root / "target"
        target.mkdir()
        (target / ".rootyard-restore.guard").write_text("bkp-1\n")
        record = self.root / "record"
        script = self.stand_in(
            'printf "%s\\n%s\\n" "$ROOTYARD_DATA_DIR" "$DATABASE_URL" > ' + quote(str(record)) + '\n'
            'find "$ROOTYARD_DATA_DIR" -mindepth 1 > ' + quote(str(record)) + '.entries\n'
            'stat -c %a "$ROOTYARD_DATA_DIR" > ' + quote(str(record)) + '.mode 2>/dev/null'
            ' || stat -f %Lp "$ROOTYARD_DATA_DIR" > ' + quote(str(record)) + '.mode\n'
            + refusal_body(FAILURE, EXTERNAL, 1, ""))
        env = dict(PROBE_ENV, ROOTYARD_DATA_DIR=str(target))
        previous = os.environ.get("ROOTYARD_DATA_DIR")
        os.environ["ROOTYARD_DATA_DIR"] = str(target)
        try:
            outcome = probe.serving_barrier_probe(script, env, "external", self.owned, secrets=SECRETS, window=5)
        finally:
            if previous is None:
                os.environ.pop("ROOTYARD_DATA_DIR", None)
            else:
                os.environ["ROOTYARD_DATA_DIR"] = previous
        self.assertEqual(outcome["status"], "refused", outcome)
        self.assertEqual(record.read_text().splitlines(),
                         [str(Path(outcome["data_dir"])), DSN])
        self.assertNotEqual(Path(outcome["data_dir"]), target)
        self.assertEqual(Path(str(record) + ".mode").read_text().strip(), "700")
        self.assertEqual(Path(str(record) + ".entries").read_text(), "")
        self.assertEqual(target.joinpath(".rootyard-restore.guard").read_text(), "bkp-1\n")
        for leaked in SECRETS:
            self.assertNotIn(leaked, repr(outcome["diagnostics"]))
        self.assertFalse(Path(outcome["data_dir"]).exists(), "probe temp dir must be cleaned after the group exits")

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
