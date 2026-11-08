#!/usr/bin/env python3
"""Focused, portable regression tests for Browse ref paging on older native Git.

`git for-each-ref --start-after` is a *newer* option: a Git that does not
implement it rejects the whole invocation as a usage error (exit 129). Browse
mapped every Git failure to HTTP 404, so the first `/refs` page of the suite
failed on such a host even though the repository was authorized and ready.

These tests need no native binary, no PostgreSQL and no Cargo. They run real
`git` against a fixture built exactly like `storage.provision`
(`init --bare --object-format=sha1 --initial-branch=main --template=`), and pin
both halves of the fix:

* the fast seek path stays available for a Git that implements `--start-after`,
* the bounded streaming scan is selected *only* by the typed usage exit (129) and
  produces the same pages without materializing every ref,
* a usage error or a signal is never reported as a genuine 404.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
GIT = shutil.which("git") or "/usr/bin/git"
ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
    "HOME": tempfile.gettempdir(),
}
FORMAT = "--format=%(refname)%00%(objectname)%00%(*objectname)"
LONG = "x" * 200


def run(argv, cwd=None, check=True):
    result = subprocess.run(argv, cwd=cwd, env=ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120)
    if check and result.returncode:
        raise AssertionError(
            f"{argv[1:4]} failed ({result.returncode}) on {git_version()}: "
            f"{result.stderr.decode(errors='replace')[-800:]}"
        )
    return result


def git_version():
    return run([GIT, "--version"]).stdout.decode().strip()


def git(*args, cwd=None, check=True):
    return run([GIT, *args], cwd=cwd, check=check)


def provision_like(path):
    """Provision a bare repository with the production settings."""
    git("init", "--bare", "--object-format=sha1", "--initial-branch=main",
        "--template=", str(path))
    return path


def push_fixture_refs(repo, work):
    """Create main, feature and a lightweight tag through real pushes."""
    work.mkdir(parents=True, exist_ok=True)
    git("init", "--initial-branch=main", ".", cwd=work)
    identity = ["-c", "user.name=Fixture", "-c", "user.email=fixture@rootyard.invalid"]
    (work / "hello.txt").write_text("hello\n")
    git(*identity, "add", "hello.txt", cwd=work)
    git(*identity, "commit", "-m", "first", cwd=work)
    git("push", str(repo), "HEAD:refs/heads/main", cwd=work)
    first = git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    (work / "feature.txt").write_text("feature\n")
    git(*identity, "add", "feature.txt", cwd=work)
    git(*identity, "commit", "-m", "feature", cwd=work)
    git("push", str(repo), "HEAD:refs/heads/feature", cwd=work)
    git("tag", "v1.0", first, cwd=work)
    git("push", str(repo), "refs/tags/v1.0", cwd=work)
    return first


def excluded_for(namespace):
    return "--exclude=refs/tags/*" if namespace == "refs/heads/" else "--exclude=refs/heads/*"


_SEEK_SUPPORT = None


def seek_supported():
    """True when this Git implements the production `--start-after` argv.

    The probe uses the exact production argument shape: Git rejects
    `--start-after` together with ref patterns, so a pattern here would test the
    wrong thing.
    """
    global _SEEK_SUPPORT
    if _SEEK_SUPPORT is None:
        with tempfile.TemporaryDirectory() as temp:
            repo = provision_like(Path(temp) / "probe.git")
            result = git("--git-dir", str(repo), "for-each-ref", FORMAT,
                         "--count=1", "--start-after=refs/heads/",
                         "--exclude=refs/tags/*", "--exclude=refs/rootyard-ci/*",
                         check=False)
            if result.returncode == 0:
                _SEEK_SUPPORT = True
            elif result.returncode == 129:
                _SEEK_SUPPORT = False
            else:
                raise AssertionError(
                    f"unexpected seek probe exit {result.returncode} on {git_version()}: "
                    f"{result.stderr.decode(errors='replace')[-400:]}"
                )
    return _SEEK_SUPPORT


def seek_page(repo, namespace, marker, limit):
    """The production seek argv (`namespace_page`), up to `limit + 1` refs."""
    out = git("--git-dir", str(repo), "for-each-ref", FORMAT,
              f"--count={limit + 1}", f"--start-after={marker}",
              excluded_for(namespace), "--exclude=refs/rootyard-ci/*").stdout
    names = [line.split(b"\0", 1)[0].decode() for line in out.splitlines() if line]
    return [name for name in names if name.startswith(namespace)][:limit + 1]


def selects_part_of_namespace(prefix):
    """Mirror of the production routing decision in `page_refs`."""
    if prefix is None:
        return False
    return not any(whole.startswith(prefix) for whole in ("refs/", "refs/heads/", "refs/tags/"))


def scan_page(repo, namespace, marker, limit, prefix=None):
    """Mirror of the bounded streaming scan in `scan_namespace_page`."""
    argv = [GIT, "--git-dir", str(repo), "for-each-ref", "--sort=refname", FORMAT,
            excluded_for(namespace), "--exclude=refs/rootyard-ci/*", namespace.rstrip("/")]
    proc = subprocess.Popen(argv, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    names, read, consumed = [], 0, 0
    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            read += 1
            consumed += len(line)
            name = line.split(b"\0", 1)[0].decode()
            if not name.startswith(namespace) or name <= marker:
                continue
            if prefix is not None and not name.startswith(prefix):
                if name > prefix:
                    # Ordered refnames: the literal prefix range is over.
                    break
                continue
            names.append(name)
            if len(names) > limit:
                # Satisfied: stop the producer instead of draining every ref.
                break
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=30)
        proc.stderr.close()
    return {"items": names[:limit + 1], "refs_read": read, "bytes_read": consumed}


def page_names(repo, prefix, marker, limit):
    """Mirror of `page_refs`: a selective literal prefix is counted after the
    filter through the bounded scan, a namespace-wide prefix keeps the seek
    path where the host Git implements `--start-after`."""
    selective = selects_part_of_namespace(prefix)
    items, stats = [], {"refs_read": 0, "bytes_read": 0}
    for namespace in ("refs/heads/", "refs/tags/"):
        if prefix is not None and not (namespace.startswith(prefix) or prefix.startswith(namespace)):
            continue
        if marker is not None and marker >= namespace and not marker.startswith(namespace):
            continue
        start = marker if marker and marker.startswith(namespace) else namespace
        if selective or not seek_supported():
            page = scan_page(repo, namespace, start, limit, prefix)
            items.extend(page["items"])
            stats["refs_read"] += page["refs_read"]
            stats["bytes_read"] += page["bytes_read"]
        else:
            items.extend(seek_page(repo, namespace, start, limit))
        if len(items) > limit:
            break
    names = sorted({name for name in items if prefix is None or name.startswith(prefix)})
    if marker is not None:
        names = [name for name in names if name > marker]
    return {"items": names[:limit + 1], **stats}


def large_packed_refs(repo, third):
    """Recreate the 20k long-tag fixture from `tests/browse.py`."""
    git("--git-dir", str(repo), "pack-refs", "--all")
    packed = repo / "packed-refs"
    existing = [line for line in packed.read_text().splitlines()
                if line and not line.startswith(("#", "^"))]
    long_tags = [f"{third} refs/tags/perf-{i:05d}-{LONG}" for i in range(20000)]
    packed.write_text("# pack-refs with: peeled fully-peeled sorted\n"
                      + "\n".join(sorted(existing + long_tags, key=lambda line: line.split(" ", 1)[1]))
                      + "\n")
    return packed


class GitReadStepsSourceTest(unittest.TestCase):
    """Static contract of the focused production fix."""

    # The git_read module is split into a thin façade plus focused submodules:
    # the typed command/exit/diagnostic/process runner in `command.rs` and the
    # ref paging (seek path + bounded scan) in `paging.rs`. The static contract
    # below pins the same production text across the whole module, never only
    # the façade, and each part keeps its own anti-monolith bound.
    MODULES = ("git_read.rs", "git_read/command.rs", "git_read/paging.rs")

    @classmethod
    def source(cls, relative: str) -> str:
        return (ROOT / "src" / "browse" / relative).read_text()

    @classmethod
    def setUpClass(cls):
        cls.read = "\n".join(cls.source(name) for name in cls.MODULES)
        cls.process = (ROOT / "src" / "git_http" / "process.rs").read_text()

    def test_split_submodules_exist_and_keep_their_line_bounds(self):
        """Each focused submodule stays readable; the façade stays thin."""
        for name in self.MODULES:
            path = ROOT / "src" / "browse" / name
            self.assertTrue(path.is_file(), f"Missing git_read submodule {path}")
            lines = len(self.source(name).splitlines())
            self.assertGreater(lines, 35, f"{path} looks like a stub ({lines} lines)")
            self.assertLess(lines, 550, f"{path} exceeds the 550-line anti-monolith bound ({lines} lines)")
        # The typed runner owns exit classification, diagnostics and the runner.
        command = self.source("git_read/command.rs")
        for owned in ("pub(crate) fn git_cmd(", "pub(crate) enum GitStep {", "async fn run_git("):
            self.assertIn(owned, command)
        # The paging module owns the seek path and the bounded scan.
        paging = self.source("git_read/paging.rs")
        for owned in ("async fn namespace_page(", "async fn scan_namespace_page(",
                      "pub(crate) async fn page_refs(", "fn selects_part_of_namespace("):
            self.assertIn(owned, paging)
        # The façade still exports the same API surface to the rest of the crate.
        facade = self.source("git_read.rs")
        for reexport in ("pub(crate) use command::{GitStep, git_cmd, run_git};",
                         "pub(crate) use paging::page_refs;",
                         "pub use paging::parse_for_each_ref_output;"):
            self.assertIn(reexport, facade)

    def test_fast_seek_path_is_retained(self):
        self.assertIn('let start_after = format!("--start-after={marker}");', self.read)
        self.assertIn('let count = format!("--count={}", limit + 1);', self.read)
        # Git rejects --start-after together with patterns: the seek argv must
        # stay pattern-free, exactly like the released fast path.
        fast = self.read[self.read.index("async fn namespace_page("):]
        fast = fast[:fast.index("\n}\n")]
        self.assertNotIn("pattern", fast.split('let args = [', 1)[1].split("];", 1)[0])

    def test_fallback_is_selected_only_by_typed_usage_exit(self):
        arm = re.search(r"GitOutcome::CommandFailed \{ exit: Some\(129\) \} => \{(.*?)\n        \}",
                        self.read, re.S)
        self.assertIsNotNone(arm, "typed usage-exit fallback arm is missing")
        self.assertIn("scan_namespace_page", arm.group(1))
        self.assertIn("report_seek_fallback();", arm.group(1))
        # Every other exit, and every non-exit failure, stays an error.
        self.assertIn("GitOutcome::CommandFailed { exit } => {", self.read)
        self.assertIn("report_step_failure(GitStep::RefsPage, exit);", self.read)
        # Untrusted Git text never decides the capability.
        self.assertNotIn("unknown option", self.read)
        # Timeout and output-limit failures are mapped before the fallback arm.
        self.assertLess(self.read.index('msg.contains("timed out")'),
                        self.read.index("GitOutcome::CommandFailed { exit: Some(129) }"))

    def test_absence_policy_keeps_real_not_found_and_rejects_usage(self):
        # Only Git's precise quiet exit 1 proves that a name is absent.
        self.assertIn("matches!(exit, Some(1))", self.read)
        self.assertNotIn("Some(1) | Some(128)", self.read)
        policy = self.read[self.read.index("pub(crate) fn maps_to_not_found("):]
        policy = policy[:policy.index("\n    }\n")]
        self.assertNotIn("Some(128)", policy)
        self.assertNotIn("Some(129)", policy)
        # Only the precise probes may answer 404; cat-file never can.
        steps = self.read[self.read.index("pub(crate) fn absence_is_expected("):]
        steps = steps[:steps.index("\n    }\n")]
        for probe in ("HeadVerify", "RevParse", "MergeBase", "RefVerify"):
            self.assertIn(f"GitStep::{probe}", steps)
        for internal in ("ObjectType", "ObjectFormat"):
            self.assertNotIn(f"GitStep::{internal}", steps)
        # A required step can never answer 404: the only not_found() inside
        # run_git is guarded by the absence policy.
        run_git = self.read[self.read.index("pub(crate) async fn run_git("):]
        run_git = run_git[:run_git.index("\n}\n")]
        self.assertEqual(run_git.count("Error::not_found()"), 1)
        self.assertIn("if step.maps_to_not_found(exit) {", run_git)

    def test_object_type_absence_is_a_precise_probe(self):
        """`cat-file -t` cannot distinguish absence from a damaged repository."""
        obj = self.read[self.read.index("pub(crate) async fn object_type("):]
        obj = obj[:obj.index("\n}\n")]
        self.assertIn('let query = format!("{spec}^{{object}}");', obj)
        self.assertIn('"rev-parse", "--verify", "--quiet", &query', obj)
        self.assertLess(obj.index("--verify"), obj.index('"cat-file", "-t"'))
        self.assertNotIn("Some(128)", obj)
        # Only the probe's own quiet exit 1 is an absence verdict.
        self.assertEqual(obj.count("return Ok(None)"), 1)
        self.assertIn("err.0 == StatusCode::NOT_FOUND", obj)
        # A type read after a successful probe is never an absent object.
        tail = obj[obj.index('"cat-file", "-t"'):]
        self.assertNotIn("NOT_FOUND", tail)
        self.assertNotIn("Ok(None)", tail)

    def test_selective_prefix_is_filtered_before_the_page_count(self):
        """A narrow literal prefix must count the page after the filter."""
        self.assertIn("fn selects_part_of_namespace(", self.read)
        self.assertIn("let selective = selects_part_of_namespace(prefix);", self.read)
        seek = self.read[self.read.index("async fn namespace_page("):]
        seek = seek[:seek.index("\n}\n")]
        self.assertIn("prefix: Option<&str>,", seek)
        self.assertIn("prefix.is_none_or(|p| r.name.starts_with(p))", seek)
        route = self.read[self.read.index("pub(crate) async fn page_refs("):]
        route = route[:route.index("\n}\n")]
        self.assertIn("items.extend(if selective {", route)
        self.assertIn("scan_namespace_page(state, repo_id, namespace, excluded, marker, prefix, limit).await?", route)
        # The literal filter runs inside the sink, before a ref is counted.
        scan = self.read[self.read.index("async fn scan_namespace_page("):]
        scan = scan[:scan.index("\n}\n")]
        self.assertIn("if !item.name.starts_with(prefix)", scan)
        self.assertLess(scan.index("starts_with(prefix)"), scan.index("items.push(item)"))
        self.assertLess(scan.index("items.push(item)"), scan.index("items.len() <= limit"))
        # A ref past the literal range ends the scan instead of draining it.
        after = scan[scan.index("!item.name.starts_with(prefix)"):]
        self.assertIn("return false;", after)
        # No user prefix ever becomes a Git pattern: argv stays namespace-only.
        argv = scan[scan.index("let args = ["):scan.index("];", scan.index("let args = ["))]
        self.assertNotIn("prefix", argv)
        self.assertIn("REF_SCAN_MAX_RECORDS", scan)
        self.assertIn("REF_SCAN_MAX_BYTES", scan)

    def test_step_diagnostics_are_fixed_and_secret_free(self):
        report = self.read[self.read.index("fn report_step_failure("):]
        report = report[:report.index("\n}\n")]
        self.assertIn('"rootyard: browse git read step={} class={} exit={}"', report)
        self.assertIn("step.label()", report)
        self.assertIn("BUDGET", report)
        emitted = report[report.index("eprintln!("):]
        for forbidden in ("args", "stderr", "stdout", "from_utf8_lossy", "ref_name", "oid"):
            self.assertNotIn(forbidden, emitted)
        for forbidden in ("args", "stderr", "stdout", "from_utf8_lossy", "ref_name", "oid"):
            self.assertNotIn(forbidden, report.replace("flood stderr per request", ""))
        fallback = self.read[self.read.index("fn report_seek_fallback("):]
        fallback = fallback[:fallback.index("\n}\n")]
        self.assertIn("fallback=bounded-scan", fallback)
        self.assertIn("GitStep::RefsPage.label()", fallback)
        for forbidden in ("args", "stderr", "stdout", "marker"):
            self.assertNotIn(forbidden, fallback)

    def test_bounded_scan_reuses_process_helpers(self):
        scan = self.read[self.read.index("async fn scan_namespace_page("):]
        scan = scan[:scan.index("\n}\n")]
        self.assertIn("crate::git_http::stream_git_lines(", scan)
        self.assertIn("REF_SCAN_MAX_RECORDS", scan)
        self.assertIn("REF_SCAN_MAX_BYTES", scan)
        self.assertIn("REF_SCAN_MAX_RECORD_BYTES", scan)
        self.assertIn("items.len() <= limit", scan)
        self.assertIn("items.truncate(limit + 1)", scan)
        # The scan never collects the namespace before filtering it.
        self.assertNotIn("read_to_end", scan)
        self.assertNotIn("collect_git_output", scan)

        stream = self.process[self.process.index("pub(crate) async fn stream_git_lines"):]
        stream = stream[:stream.index("\n}\n")]
        self.assertIn("max_records", stream)
        self.assertIn("max_record_bytes", stream)
        self.assertIn("consumed > limits.max_bytes", stream)
        self.assertIn("libc::kill(-process.pid, libc::SIGKILL)", stream)
        self.assertIn("process.finish().await", stream)
        self.assertIn("process.stop().await", stream)
        self.assertIn("maintenance Git command timed out", stream)
        self.assertIn("GitCommandFailed { exit: status.code() }", stream)

    def test_stream_cap_is_enforced_in_read_and_exit_shares_the_deadline(self):
        """Both review findings are pinned in `stream_git_lines`."""
        stream = self.process[self.process.index("pub(crate) async fn stream_git_lines"):]
        stream = stream[:stream.index("\n}\n")]
        # Finding 1: the per-record cap is applied while reading. An unbounded
        # `read_until` buffered up to the whole 64 MiB stream limit before the
        # 64 KiB record check and never returned while the pipe stayed open.
        self.assertNotIn("read_until(", stream)
        guard = stream.index("line.len().saturating_add(take) > limits.max_record_bytes")
        self.assertLess(guard, stream.index("line.extend_from_slice(&available[..take])"),
                        "the record cap must be checked before the record grows")
        # Finding 2: the read, the leader exit and the group quiescence share one
        # deadline, so EOF followed by a hang is still bounded.
        self.assertLess(stream.index("tokio::time::timeout("),
                        stream.index("process.finish().await"))
        self.assertLess(stream.index("process.finish().await"), stream.index("match outcome {"))
        # Expiry still takes the cancellation path that keeps the unreaped leader
        # as the PGID reservation until every group member is dead.
        timeout_arm = stream[stream.index("Err(_) => {"):]
        self.assertIn("process.stop().await", timeout_arm)
        self.assertIn("maintenance Git command timed out", timeout_arm)
        # An intentional early stop is success after physical cleanup, so a
        # killed producer must never be reported as a failed Git command,
        # while a drained stream still has to prove the leader succeeded.
        self.assertIn("if !satisfied && !status.success()", stream)

    def test_browse_contract_is_unchanged(self):
        browse = (TESTS / "browse.py").read_text()
        cases = re.search(r"CASE_NAMES = \((.*?)\n\)", browse, re.S).group(1)
        self.assertEqual(len([line for line in cases.splitlines() if line.strip()]), 12)
        self.assertIn('"selective_ref_prefix",', browse)
        self.assertIn('"kind": "symbolic",', browse)
        self.assertIn('"target": "refs/heads/main",', browse)
        self.assertIn('"oid": self.third,', browse)
        self.assertIn('self.document(self.repo_api("/refs?limit=1&after=refs/tags/perf-19998-"', browse)
        # Authorization and 200/404 semantics are untouched by the fix.
        handlers = (ROOT / "src" / "browse" / "handlers.rs").read_text()
        self.assertIn("authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Read, "
                      "crate::token_scopes::RepoAction::ContentsRead)", handlers)
        self.assertNotIn("StatusCode::NOT_FOUND", handlers)


class RealGitFixtureTest(unittest.TestCase):
    """Real Git behaviour that the fix depends on."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self):
        repo = provision_like(self.root / "demo.git")
        third = push_fixture_refs(repo, self.root / "work")
        return repo, third

    def test_provision_head_is_unborn_main_until_the_first_push(self):
        repo = provision_like(self.root / "empty.git")
        self.assertEqual((repo / "HEAD").read_text().strip(), "ref: refs/heads/main")
        probe = git("--git-dir", str(repo), "rev-parse", "--verify", "--quiet", "HEAD", check=False)
        self.assertEqual(probe.returncode, 1,
                         f"unborn HEAD must answer 'absent' with exit 1 on {git_version()}")
        self.assertEqual(probe.stdout, b"")
        # That exit is a real "absent" verdict, so Browse reports unborn (200),
        # never a 404: the production absence policy accepts exactly exit 1.
        self.assertIn("matches!(exit, Some(1))",
                      (ROOT / "src" / "browse" / "git_read" / "command.rs").read_text())

    def test_unknown_option_is_a_usage_exit(self):
        repo, _ = self.fixture()
        result = git("--git-dir", str(repo), "for-each-ref", "--not-a-real-option", check=False)
        self.assertEqual(result.returncode, 129,
                         f"Git must report an unsupported option as usage (129) on {git_version()}")

    def test_seek_and_bounded_scan_produce_the_same_pages(self):
        repo, _ = self.fixture()
        pages = [
            ("refs/heads/", "refs/heads/", 5, ["refs/heads/feature", "refs/heads/main"]),
            ("refs/heads/", "refs/heads/feature", 1, ["refs/heads/main"]),
            ("refs/tags/", "refs/tags/", 5, ["refs/tags/v1.0"]),
            ("refs/tags/", "refs/tags/v1.0", 5, []),
        ]
        for namespace, marker, limit, expected in pages:
            scanned = scan_page(repo, namespace, marker, limit)
            self.assertEqual(scanned["items"][:limit], expected, (namespace, marker))
            if seek_supported():
                self.assertEqual(seek_page(repo, namespace, marker, limit), scanned["items"],
                                 f"seek and scan disagree for {marker} on {git_version()}")

    def test_deep_cursor_over_twenty_thousand_refs(self):
        repo, third = self.fixture()
        large_packed_refs(repo, third)
        self.assertGreater((repo / "packed-refs").stat().st_size, 4 * 1024 * 1024)
        cursor = "refs/tags/perf-19998-" + LONG
        deep = scan_page(repo, "refs/tags/", cursor, 1)
        # `limit + 1` refs prove another page exists; the response takes `limit`.
        self.assertEqual(deep["items"][:1], ["refs/tags/perf-19999-" + LONG])
        self.assertEqual(deep["items"], ["refs/tags/perf-19999-" + LONG, "refs/tags/v1.0"])
        # A page past the old 4 MiB output cap without materializing the store.
        self.assertLess(deep["bytes_read"], 8 * 1024 * 1024)
        if seek_supported():
            self.assertEqual(seek_page(repo, "refs/tags/", cursor, 1), deep["items"])

    def test_shallow_page_stops_early_instead_of_scanning_every_ref(self):
        repo, third = self.fixture()
        large_packed_refs(repo, third)
        cursor = "refs/tags/perf-00010-" + LONG
        page = scan_page(repo, "refs/tags/", cursor, 1)
        self.assertEqual(page["items"][:1], ["refs/tags/perf-00011-" + LONG])
        self.assertLess(page["refs_read"], 64, "bounded scan drained the whole namespace")
        self.assertLess(page["bytes_read"], 64 * 1024)

    def test_first_public_namespace_page_is_ordered(self):
        repo, _ = self.fixture()
        page = scan_page(repo, "refs/heads/", "refs/heads/", 1)
        self.assertEqual(page["items"], ["refs/heads/feature", "refs/heads/main"])
        self.assertLess(page["refs_read"], 16)


if __name__ == "__main__":
    unittest.main()
