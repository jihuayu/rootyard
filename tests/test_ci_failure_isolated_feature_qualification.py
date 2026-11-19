"""Pure contract checks for the generic-failure isolated feature lane.
Reads the real ``.github/workflows/ci.yml`` guards, evaluates them against
finite sanitized contexts, and derives both harness closures with ``ast``.
Nothing starts Cargo, Rust, Git, PostgreSQL, FUSE, Garage, a process or the
network.
"""
from __future__ import annotations
import ast
from dataclasses import dataclass, field
from pathlib import Path
import re
import unittest
ROOT = Path(__file__).resolve().parents[1]
CI_YML = ROOT / ".github/workflows/ci.yml"
GENERIC_RUN = "cargo test --locked --all-targets --features pando-lab"
HELPER_REQUIRED = (
    "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_live_editor_capture_checkpoint_and_remount",
    "tests.test_workspace_handoff.WorkspaceHandoffTest.test_expired_host_reattach_from_remote_checkpoint",
    "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_normal_sigterm_helper_unmount_precedes_parked_git_join",
    "tests.test_workspace_fuse_service.WorkspaceFuseServiceTest.test_api_sigkill_with_pending_kernel_writer",
)
REMOTE_REQUIRED = (
    "invalid_optin_rejected_at_startup",
    "default_retains_failed_remote_cleanup",
    "exit77_with_pending_fuse_request",
)
LEGACY_REQUIRED = (
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest.test_normal_legacy_sigterm_join_evidence_and_exact_unmount",
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest.test_partial_reconcile_failure_cleans_earlier_owned_mount",
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest.test_post_reconcile_api_bind_failure_cleans_owned_mount",
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest.test_sigterm_during_blocked_startup_joins_mounted_owner",
)
FUSE_ROOTS = (
    "tests/workspace_fuse_service_acceptance.py",
    "tests/workspace_remote_delete_policy.py",
    "tests/test_workspace_fuse_service.py",
    "tests/test_workspace_handoff.py",
    "scripts/native_report_manifest.py",
)
LEGACY_ROOTS = (
    "tests/workspace_legacy_fuse_shutdown_report.py",
    "tests/test_workspace_legacy_fuse_shutdown_primary.py",
    "tests/test_workspace_legacy_fuse_shutdown_fifo.py",
    "tests/test_workspace_legacy_fuse_containment_owner.py",
    "tests/test_workspace_legacy_fuse_bind_gate.py",
    "tests/test_workspace_legacy_fuse_stat_gate.py",
    "scripts/native_report_manifest.py",
)
EVIDENCE = (
    "native_batch", "native_export", "workspace_garage", "workspace_fuse_remote",
    "Bind workspace FUSE and remote-delete evidence to the built binary",
    "workspace_legacy_service", "Bind legacy FUSE evidence independently to the built binary",
)
# Current main's verify/lifecycle budget: 95 existing minutes, +12 for the
# #304 cold tenant LFS gate on owned Garage, +28 for the full Redis
# qualification (13 build, 5 restore/flush, 3 partition, 4 failover, 3 cleanup
# and manifest binding), and +40 for the Pando package gates: 175. This branch
# adds no main-side step, so the merged job cap must be exactly this baseline
# plus the independent workspace FUSE phases and the independent PR #321 #29
# remote-CAS witness.
MAIN_VERIFY_BUDGET = 175
REMOTE_CAS_BUDGET = 22
@dataclass
class Step:
    name: str = ""
    id: str | None = None
    if_expr: str | None = None
    timeout: int | None = None
    run: str = ""
    with_raw: str = ""
@dataclass(frozen=True)
class Context:
    cancelled: bool = False
    success: bool = True
    failure: bool = False
    outcomes: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)


def _set(step, key, value):
    if key == "if":
        step.if_expr = value
    elif key == "timeout-minutes":
        step.timeout = int(value)
    elif key in ("name", "id", "run"):
        setattr(step, key, value)


def _consume(lines, index):
    block = []
    while index < len(lines) and not (
            lines[index].strip() and len(lines[index]) - len(lines[index].lstrip(" ")) <= 8):
        block.append(lines[index])
        index += 1
    return block, index


def _dedent(block):
    widths = [len(line) - len(line.lstrip(" ")) for line in block if line.strip()]
    width = min(widths) if widths else 0
    return "\n".join(line[width:] for line in block)


def parse_steps(text):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line == "    steps:")
    steps, index, current = [], start + 1, None
    while index < len(lines):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            break
        match = re.match(r"^      - (.*)$", line)
        if match:
            if current is not None:
                steps.append(current)
            current = Step()
            key, _, value = match.group(1).partition(":")
            _set(current, key.strip(), value.strip())
        elif current is not None:
            match = re.match(r"^        ([A-Za-z0-9_-]+):(.*)$", line)
            if match:
                key, value = match.group(1), match.group(2).strip()
                if key in ("with", "env") and not value:
                    block, index = _consume(lines, index + 1)
                    current.with_raw += "\n".join(block) + "\n"
                    continue
                if key in ("run", "with", "env") and value in ("|", ">", "|-", ">-", "|+", ">+"):
                    block, index = _consume(lines, index + 1)
                    if key == "run":
                        current.run = _dedent(block)
                    else:
                        current.with_raw += "\n".join(block) + "\n"
                    continue
                _set(current, key, value)
        index += 1
    if current is not None:
        steps.append(current)
    return steps


def expression(step):
    if step.if_expr is None:
        return None
    value = step.if_expr.strip()
    return value[3:-2].strip() if value.startswith("${{") and value.endswith("}}") else value
_TOKENS = re.compile(
    r"""\s*(?:(?P<op>&&|\|\||==|!=|!|\(|\))"""
    r"""|(?P<str>'(?:[^']|'')*')|(?P<id>[A-Za-z_][A-Za-z0-9_.]*))"""
)


def _tokens(text):
    out, position = [], 0
    while position < len(text):
        match = _TOKENS.match(text, position)
        if not match:
            raise ValueError(f"unsupported token: {text[position:]!r}")
        out.append((match.lastgroup, match.group(match.lastgroup)))
        position = match.end()
    return out


class _Parser:
    def __init__(self, text):
        self.tokens, self.at = _tokens(text), 0

    def _peek(self): return self.tokens[self.at][0] if self.at < len(self.tokens) else None
    def _take(self): item = self.tokens[self.at]; self.at += 1; return item

    def parse(self):
        node = self._binary(self._and, ("||",))
        if self.at != len(self.tokens):
            raise ValueError("trailing tokens")
        return node

    def _binary(self, sub, operators):
        node = sub()
        while self._peek() == "op" and self.tokens[self.at][1] in operators:
            node = (self._take()[1], node, sub())
        return node

    def _and(self):
        return self._binary(self._compare, ("&&",))

    def _compare(self):
        node = self._unary()
        if self._peek() == "op" and self.tokens[self.at][1] in ("==", "!="):
            node = ("compare", self._take()[1], node, self._unary())
        return node

    def _unary(self):
        if self._peek() == "op" and self.tokens[self.at][1] == "!":
            self._take()
            return ("not", self._unary())
        return self._primary()

    def _primary(self):
        kind, value = self._take()
        if kind == "op" and value == "(":
            node = self._binary(self._and, ("||",))
            if self._take() != ("op", ")"):
                raise ValueError("unclosed group")
            return node
        if kind == "str":
            return ("str", value[1:-1].replace("''", "'"))
        if kind == "id":
            if value in ("true", "false"):
                return ("bool", value == "true")
            if self._peek() == "op" and self.tokens[self.at][1] == "(":
                self._take()
                if self._take() != ("op", ")"):
                    raise ValueError("status functions are nullary")
                return ("call", value)
            return ("ident", value)
        raise ValueError(f"unexpected token: {(kind, value)!r}")


def _truth(value):
    return not (value is None or value is False or value == "" or value == 0)
def _status(node):
    if isinstance(node, tuple):
        if node and node[0] == "call" and node[1] in ("success", "failure", "cancelled", "always"):
            return True
        return any(_status(item) for item in node)
    return isinstance(node, list) and any(_status(item) for item in node)


def _resolve(name, ctx):
    parts = name.split(".")
    if parts[0] == "steps" and len(parts) == 3 and parts[2] == "outcome":
        return ctx.outcomes.get(parts[1], "")
    if parts[0] == "steps" and len(parts) == 4 and parts[2] == "outputs":
        return ctx.outputs.get(parts[1], {}).get(parts[3], "")
    raise ValueError(f"unsupported identifier: {name!r}")


def _eval(node, ctx):
    kind = node[0]
    if kind == "not":
        return not _truth(_eval(node[1], ctx))
    if kind in ("&&", "||"):
        left = _eval(node[1], ctx)
        if kind == "&&":
            return _eval(node[2], ctx) if _truth(left) else left
        return left if _truth(left) else _eval(node[2], ctx)
    if kind == "compare":
        left, right = _eval(node[2], ctx), _eval(node[3], ctx)
        return left == right if node[1] == "==" else left != right
    if kind in ("str", "bool"):
        return node[1]
    if kind == "ident":
        return _resolve(node[1], ctx)
    if node[1] == "cancelled":
        return ctx.cancelled
    if node[1] == "always":
        return True
    if node[1] == "success":
        return ctx.success and not ctx.cancelled
    if node[1] == "failure":
        return ctx.failure and not ctx.cancelled
    raise ValueError(f"unsupported node: {node!r}")


def step_runs(step, ctx):
    text = expression(step)
    if text is None:
        return _truth(_eval(("call", "success"), ctx))
    tree = _Parser(text).parse()
    if not _status(tree):
        return _truth(_eval(("call", "success"), ctx)) and _truth(_eval(tree, ctx))
    return _truth(_eval(tree, ctx))

def _normalized(run):
    return " ".join(run.replace("\\\n", " ").split())


def _flags(step, flag):
    return re.findall(rf"(?:^|\s){re.escape(flag)}\s+([^\s]+)", _normalized(step.run))


def _reports_and_cases(step):
    reports = dict(spec.split("=", 1) for spec in _flags(step, "--report"))
    cases = {}
    for spec in _flags(step, "--require-case"):
        name, case = spec.split("=", 1)
        cases.setdefault(name, []).append(case)
    return reports, cases


def _projection(step, ctx, evidence):
    if not step_runs(step, ctx):
        return "not-run"
    reports, cases = _reports_and_cases(step)
    for name, path in reports.items():
        item = evidence.get(name)
        if not item or not item.get("present") or not item.get("schema_ok"):
            return "failed"
        if "test-results/" not in path or set(cases.get(name, ())) - set(item.get("passed_cases", ())):
            return "failed"
    return "passed"

def _closure(roots, extra):
    seen, queue = [], list(roots)
    def resolve(name):
        if name == "tests" or name.startswith("tests."):
            base, parts = ROOT / "tests", name.split(".")[1:]
        elif name == "scripts" or name.startswith("scripts."):
            base, parts = ROOT / "scripts", name.split(".")[1:]
        else:
            for parent in (ROOT / "tests", ROOT / "scripts"):
                candidate = parent / (name.replace(".", "/") + ".py")
                if candidate.is_file():
                    return candidate.relative_to(ROOT).as_posix()
            return None
        candidate = base / ("/".join(parts) + ".py")
        return candidate.relative_to(ROOT).as_posix() if candidate.is_file() else None
    while queue:
        item = queue.pop(0)
        if item in seen: continue
        seen.append(item)
        path = ROOT / item
        if not path.is_file() or path.suffix != ".py": continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = ([alias.name for alias in node.names] if isinstance(node, ast.Import) else
                     [node.module] + [node.module + "." + alias.name for alias in node.names]
                     if isinstance(node, ast.ImportFrom) and node.module else [])
            for name in names:
                resolved = resolve(name)
                if resolved and resolved not in seen: queue.append(resolved)
    return set(seen) | set(extra)

class FailureIsolatedFeatureLaneTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CI_YML.read_text(encoding="utf-8")
        cls.steps = parse_steps(cls.text)
        cls.by_id = {step.id: step for step in cls.steps if step.id}
        cls.by_name = {step.name: step for step in cls.steps if step.name}
    def assertRuns(self, step, ctx, expected):
        self.assertEqual(step_runs(step, ctx), expected, step.name or step.id)
    def test_guard_truth_table_is_closed_and_fail_closed(self):
        generic, build = self.by_id["cargo_all_targets"], self.by_id["native_batch"]
        export, garage = self.by_id["native_export"], self.by_id["workspace_garage"]
        helper, legacy = self.by_id["workspace_fuse_remote"], self.by_id["workspace_legacy_service"]
        manifest = self.by_name["Bind workspace FUSE and remote-delete evidence to the built binary"]
        legacy_manifest = self.by_name["Bind legacy FUSE evidence independently to the built binary"]
        self.assertIsNone(generic.if_expr)
        self.assertEqual(generic.run.strip(), GENERIC_RUN)
        for step in (build, export, garage, helper, manifest, legacy, legacy_manifest):
            self.assertIn("!cancelled()", expression(step))
            self.assertNotIn("always()", expression(step))
        self.assertNotIn("!= 'skipped'", expression(build))
        passed = Context(outcomes={"cargo_all_targets": "success"})
        failed = Context(success=False, failure=True, outcomes={"cargo_all_targets": "failure"})
        skipped = Context(success=False, failure=True, outcomes={"cargo_all_targets": "skipped"})
        missing = Context(success=False, outcomes={})
        cancelled = Context(cancelled=True, outcomes={"cargo_all_targets": "success"})
        for ctx, expected in zip((passed, failed, skipped, missing, cancelled), (True, True, False, False, False)):
            self.assertRuns(build, ctx, expected)
        self.assertRuns(export, Context(outcomes={"native_batch": "success"}), True)
        for ctx in (passed, failed, skipped, missing, cancelled): self.assertRuns(export, ctx, False)
        for name in ("native_batch", "native_export", "workspace_garage", "workspace_fuse_remote",
                     "workspace_legacy_service"):
            self.assertFalse(step_runs(self.by_id[name], skipped), name)
        primary = self.by_name["Bind native regressions to the built binary and source inputs"]
        self.assertIsNone(primary.if_expr)
        self.assertFalse(step_runs(primary, skipped))
        export_ok = Context(outcomes={"native_batch": "success", "native_export": "success"})
        export_failed = Context(success=False, failure=True, outcomes={"native_export": "failure"})
        self.assertRuns(garage, export_ok, True)
        for ctx in (export_failed, Context(outcomes={"native_batch": "success"})):
            self.assertRuns(garage, ctx, False)
            self.assertRuns(helper, ctx, False)
            self.assertRuns(legacy, ctx, False)
            self.assertRuns(legacy_manifest, ctx, False)
        env = {"workspace_garage": {"env_file": "fake.env"}}
        helper_ok = Context(outcomes={"native_export": "success", "workspace_garage": "success"}, outputs=env)
        helper_no_env = Context(outcomes={"native_export": "success", "workspace_garage": "success"})
        self.assertRuns(helper, helper_ok, True)
        self.assertRuns(helper, helper_no_env, False)
        source_env = '. "${{ steps.workspace_garage.outputs.env_file }}"'
        for token in ('test -x "$ROOTYARD_BIN"', 'test -f "$ROOTYARD_BUILD_RECEIPT"'):
            self.assertLess(helper.run.index(token), helper.run.index(source_env))
        helper_failed = Context(success=False, failure=True,
                                outcomes={"native_export": "success", "workspace_garage": "success",
                                          "workspace_fuse_remote": "failure", "workspace_legacy_service": "success"})
        helper_done = Context(outcomes={"native_export": "success", "workspace_garage": "success",
                                        "workspace_fuse_remote": "success", "workspace_legacy_service": "success"})
        self.assertRuns(manifest, helper_done, True)
        self.assertRuns(manifest, helper_failed, False)
        self.assertRuns(legacy, helper_failed, True)
        self.assertRuns(legacy_manifest, helper_failed, True)
        self.assertRuns(manifest, Context(outcomes={"native_export": "success"}), False)
        for ctx in (Context(success=False, failure=True, outcomes={"native_batch": "failure"}), Context(outcomes={})):
            self.assertFalse(step_runs(export, ctx))
            for name in ("workspace_garage", "workspace_fuse_remote", "workspace_legacy_service"):
                self.assertFalse(step_runs(self.by_id[name], ctx), name)
        legacy_ok = Context(outcomes={"native_export": "success", "workspace_legacy_service": "success"})
        for step in (legacy, legacy_manifest):
            self.assertRuns(step, legacy_ok, True)
        naive = Step(name="naive", if_expr="${{ !cancelled() && steps.cargo_all_targets.outcome != 'skipped' }}")
        self.assertFalse(step_runs(build, Context(outcomes={})))
        self.assertTrue(step_runs(naive, Context(outcomes={})))
        self.assertTrue(step_runs(Step(name="always", if_expr="always()"), helper_failed))
        self.assertFalse(step_runs(manifest, helper_failed))
    def test_manifest_obligations_fail_closed_on_missing_report_schema_or_cases(self):
        fuse = self.by_name["Bind workspace FUSE and remote-delete evidence to the built binary"]
        legacy = self.by_name["Bind legacy FUSE evidence independently to the built binary"]
        fuse_reports, fuse_cases = _reports_and_cases(fuse)
        legacy_reports, legacy_cases = _reports_and_cases(legacy)
        self.assertEqual(set(fuse_reports), {"workspace_fuse_service", "workspace_remote_delete"})
        self.assertEqual(fuse_cases["workspace_fuse_service"], list(HELPER_REQUIRED))
        self.assertEqual(fuse_cases["workspace_remote_delete"], list(REMOTE_REQUIRED))
        self.assertEqual(legacy_reports, {"workspace_legacy_service": "test-results/workspace-legacy-service.json"})
        self.assertEqual(legacy_cases["workspace_legacy_service"], list(LEGACY_REQUIRED))
        for step in (fuse, legacy):
            normalized = _normalized(step.run)
            self.assertIn("--fixture-rust-from-receipt", normalized)
            self.assertNotIn("rustc", normalized)
            anchors = ('--build-receipt "$ROOTYARD_BUILD_RECEIPT"', '--binary "$ROOTYARD_BIN"',
                       '--expect-commit "$GITHUB_SHA"', '--expect-batch-manifest-path "$ROOTYARD_BATCH_MANIFEST"',
                       '--expect-batch-manifest-sha "$ROOTYARD_BATCH_MANIFEST_SHA256"')
            self.assertTrue(all(anchor in normalized for anchor in anchors), step.name)
        evidence = {
            "workspace_fuse_service": {"present": True, "schema_ok": True, "passed_cases": set(HELPER_REQUIRED)},
            "workspace_remote_delete": {"present": True, "schema_ok": True, "passed_cases": set(REMOTE_REQUIRED)},
            "workspace_legacy_service": {"present": True, "schema_ok": True, "passed_cases": set(LEGACY_REQUIRED)},
        }
        bound = Context(outcomes={"native_export": "success", "workspace_garage": "success",
                                  "workspace_fuse_remote": "success", "workspace_legacy_service": "success"})
        self.assertEqual(_projection(fuse, bound, evidence), "passed")
        self.assertEqual(_projection(legacy, bound, evidence), "passed")
        for target, name, mutate in (
                (fuse, "workspace_remote_delete", lambda item: item.pop("workspace_remote_delete", None)),
                (fuse, "workspace_fuse_service", lambda item: item["workspace_fuse_service"].update(schema_ok=False)),
                (legacy, "workspace_legacy_service", lambda item: item["workspace_legacy_service"].update(
                    passed_cases=set(LEGACY_REQUIRED[:-1])))):
            broken = {key: dict(value) for key, value in evidence.items()}
            mutate(broken)
            self.assertEqual(_projection(target, bound, broken), "failed", name)
        broken = {key: dict(value) for key, value in evidence.items()}
        broken.pop("workspace_legacy_service")
        self.assertEqual(_projection(legacy, bound, broken), "failed")
        self.assertEqual(_projection(fuse, Context(outcomes={"native_export": "success",
                                                             "workspace_fuse_remote": "failure"}), evidence), "not-run")
        self.assertEqual(_projection(legacy, Context(outcomes={"workspace_legacy_service": "failure"}), evidence), "not-run")
    def test_cancelled_job_blocks_new_evidence_but_cleanup_and_upload_remain_always(self):
        cancelled = Context(cancelled=True, outcomes={name: "success" for name in EVIDENCE},
                            outputs={"workspace_garage": {"env_file": "fake.env"}})
        for name in EVIDENCE:
            self.assertRuns(self.by_id.get(name) or self.by_name[name], cancelled, False)
        stop = self.by_name["Stop only the job-owned workspace FUSE/remote Garage fixture"]
        upload = self.by_name["Upload workspace FUSE/remote acceptance reports"]
        final = self.by_name["Upload end-to-end report"]
        for step in (stop, upload, final):
            self.assertEqual(expression(step), "always()")
            self.assertRuns(step, cancelled, True)
        self.assertIn("scripts/owned_garage_fixture.sh stop", stop.run)
        self.assertIn(".rootyard-owned-fixture", stop.run)
        self.assertNotIn("rm -rf", stop.run)
        for path in ("test-results/workspace-fuse-service.json",
                     "test-results/workspace-remote-delete-policy.json",
                     "test-results/workspace-legacy-service.json",
                     "test-results/native-workspace-fuse-gate.json",
                     "test-results/native-workspace-legacy-gate.json"):
            self.assertIn(path, upload.with_raw)
        self.assertIn("if-no-files-found: ignore", upload.with_raw)
    def test_caps_case_inventory_and_full_harness_closure(self):
        jobs = self.text.split("jobs:", 1)[1]
        self.assertEqual(set(re.findall(r"^  ([a-z][a-z0-9_-]*):$", jobs, re.MULTILINE)), {"verify", "container"})
        runs = [step.run for step in self.steps]
        self.assertEqual(sum("python3 scripts/build_native_batch.py" in run for run in runs), 1)
        self.assertEqual(sum("python3 scripts/export_native_artifacts.py" in run for run in runs), 1)
        self.assertEqual(self.text.count("actions/upload-artifact@v4"), 2)
        self.assertNotIn("actions/download-artifact", self.text)
        self.assertNotIn("continue-on-error", self.text)
        self.assertEqual(self.text.count("native-pr-gate.json"), 1)
        for name in ("native_batch", "native_export", "workspace_fuse_remote", "workspace_legacy_service"):
            self.assertNotRegex(self.by_id[name].run, r"\bcp\b")
        self.assertNotIn("target/", _normalized(
            self.by_name["Bind legacy FUSE evidence independently to the built binary"].run))
        verify = self.text.split("  container:", 1)[0]
        fuse_phases = (self.by_id["workspace_garage"].timeout,
                       self.by_id["workspace_fuse_remote"].timeout,
                       self.by_id["workspace_legacy_service"].timeout)
        self.assertEqual((self.by_id["native_batch"].timeout, *fuse_phases), (10, 12, 30, 10))
        # The fixture start, the helper/remote-delete step and the legacy
        # four-case step are the only phases this branch adds to main, and each
        # keeps its own cap. C5 runs inside the 30-minute helper step, so it
        # shares that cap instead of reserving separate job minutes.
        self.assertEqual(fuse_phases, (12, 30, 10))
        main_cap = MAIN_VERIFY_BUDGET + sum(fuse_phases)
        self.assertEqual(main_cap, 227)
        self.assertIn(
            f"{MAIN_VERIFY_BUDGET} + {' + '.join(str(phase) for phase in fuse_phases)} = {main_cap}",
            verify,
            "the job comment must derive main's cap from the added phases",
        )
        merged_cap = main_cap + REMOTE_CAS_BUDGET
        self.assertEqual(merged_cap, 249)
        self.assertIn(f"    timeout-minutes: {merged_cap}", verify)
        self.assertIn(
            f"{main_cap} + {REMOTE_CAS_BUDGET} = {merged_cap}",
            verify,
            "the job comment must add the independent #29 witness to main's cap",
        )
        # Keeping main's 175, or main's 227 without the independent #29
        # witness, would silently under-budget the merged job.
        self.assertNotIn(f"    timeout-minutes: {MAIN_VERIFY_BUDGET}", verify)
        self.assertNotIn(f"    timeout-minutes: {main_cap}", verify)
        self.assertIsNone(self.by_id["cargo_all_targets"].timeout)
        fuse = self.by_name["Bind workspace FUSE and remote-delete evidence to the built binary"]
        legacy = self.by_name["Bind legacy FUSE evidence independently to the built binary"]
        _, fuse_cases = _reports_and_cases(fuse)
        _, legacy_cases = _reports_and_cases(legacy)
        self.assertEqual((len(HELPER_REQUIRED), len(REMOTE_REQUIRED), len(LEGACY_REQUIRED)), (4, 3, 4))
        self.assertEqual(fuse_cases["workspace_fuse_service"], list(HELPER_REQUIRED))
        self.assertEqual(fuse_cases["workspace_remote_delete"], list(REMOTE_REQUIRED))
        self.assertEqual(legacy_cases["workspace_legacy_service"], list(LEGACY_REQUIRED))
        fuse_closure = _closure(FUSE_ROOTS, ("tests/fixtures/capture_read_gate.c", ".github/workflows/ci.yml"))
        legacy_closure = _closure(LEGACY_ROOTS, (
            ".github/workflows/ci.yml",
            "tests/fixtures/api_bind_gate.c",
            "tests/fixtures/legacy_stat_gate.c",
        ))
        self.assertEqual(set(_flags(fuse, "--harness")), fuse_closure)
        self.assertEqual(len(_flags(fuse, "--harness")), len(fuse_closure))
        self.assertEqual(set(_flags(legacy, "--harness")), legacy_closure)
        self.assertEqual(len(_flags(legacy, "--harness")), len(legacy_closure))
        for harness in _flags(fuse, "--harness") + _flags(legacy, "--harness"):
            self.assertTrue((ROOT / harness).is_file(), harness)
        primary = self.by_name["Bind native regressions to the built binary and source inputs"]
        _, primary_cases = _reports_and_cases(primary)
        self.assertEqual(primary_cases["workspace_legacy_service"], list(LEGACY_REQUIRED))
        self.assertIsNone(primary.if_expr)
if __name__ == "__main__":
    unittest.main()
