#!/usr/bin/env python3
"""Static contracts for the formal Rust CI CargoFork wiring.

These tests read workflow text, parse YAML, and statically parse Python test
sources with ``ast``; they never run a workflow, Cargo, a container, a database
or a network request.
"""
from __future__ import annotations

import ast
import re
import unittest
import warnings
from pathlib import Path

try:  # PyYAML is optional on the runner; the structural checks never need it.
    import yaml
except ImportError:  # pragma: no cover - exercised on a minimal runner
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
REVISION = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
RELEASE = "1.101.0"
SETUP = "scripts/install_ci_cargo_fork.sh install"
VERIFY = "scripts/install_ci_cargo_fork.sh verify"
INSTALLER = "install_ci_cargo_fork.sh"
INSTALLER_UNIT_TEST = "test_install_ci_cargo_fork.py"
COMPILER_EXECUTABLES = frozenset({"cargo", "rustc", "rustup"})
_PROCESS_CALLS = frozenset({
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
})


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Resolve the small set of execution modules used by the test tree."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("asyncio", "os", "subprocess"):
                    aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in (
            "asyncio",
            "os",
            "subprocess",
        ):
            for alias in node.names:
                aliases[alias.asname or alias.name] = node.module + "." + alias.name
    return aliases


def _resolved_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _resolved_name(node.value, aliases)
        return (base + "." if base else "") + node.attr
    return ""


def _walk_scope_nodes(node: ast.AST):
    """Yield nodes in one lexical scope, never descending into a nested scope."""
    nested = (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef, ast.Lambda)
    if isinstance(node, nested):
        return
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _walk_scope_nodes(child)


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    if isinstance(node, (ast.List, ast.Tuple)):
        names: set[str] = set()
        for item in node.elts:
            names.update(_target_names(item))
        return names
    return set()


def _mentions_installer(node: ast.AST, tainted: set[str]) -> bool:
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and INSTALLER in child.value
        ):
            return True
        if isinstance(child, ast.Name) and child.id in tainted:
            return True
        if isinstance(child, ast.Attribute) and child.attr in tainted:
            return True
    return False


def _scope_taint(statements: list[ast.stmt], inherited: set[str]) -> set[str]:
    """Names in this scope that carry the installer path, including local aliases."""
    tainted = set(inherited)
    assignments: list[tuple[set[str], ast.AST]] = []
    for statement in statements:
        for node in _walk_scope_nodes(statement):
            if isinstance(node, ast.Assign):
                names: set[str] = set()
                for target in node.targets:
                    names.update(_target_names(target))
                assignments.append((names, node.value))
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                assignments.append((_target_names(node.target), node.value))
            elif isinstance(node, ast.NamedExpr):
                assignments.append((_target_names(node.target), node.value))
    changed = True
    while changed:
        changed = False
        for names, value in assignments:
            if names and _mentions_installer(value, tainted):
                before = len(tainted)
                tainted.update(names)
                changed = changed or len(tainted) != before
    return tainted


def _command_nodes(call: ast.Call, name: str) -> list[ast.AST]:
    if name.startswith("subprocess."):
        nodes = list(call.args[:1])
        for keyword in call.keywords:
            if keyword.arg in ("args", "cmd", "command"):
                nodes.append(keyword.value)
        return nodes
    if name in ("os.system", "os.popen"):
        return list(call.args[:1])
    if name.startswith(("os.exec", "os.spawn")):
        return list(call.args)
    if name == "asyncio.create_subprocess_shell":
        return list(call.args[:1])
    if name == "asyncio.create_subprocess_exec":
        return list(call.args)
    return []


def _contains_installer_literal(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and INSTALLER in child.value
        for child in ast.walk(node)
    )


def _executable_name(command: ast.AST) -> str | None:
    if isinstance(command, ast.Constant) and isinstance(command.value, str):
        value = command.value.strip()
        if not value:
            return None
        token = value.split()[0]
    elif isinstance(command, (ast.List, ast.Tuple)) and command.elts:
        first = command.elts[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            return None
        token = first.value
    else:
        return None
    return token.rsplit("/", 1)[-1]


class _ProcessExecutionScanner(ast.NodeVisitor):
    """Find actual process execution, never source reading or string comparison."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.aliases: dict[str, str] = {}
        self.taints: list[set[str]] = []
        self.function_depth = 0
        self.findings: list[dict[str, object]] = []

    def scan(self, tree: ast.AST) -> list[dict[str, object]]:
        self.aliases = _import_aliases(tree)
        self.visit(tree)
        return self.findings

    def _visit_scope(self, statements: list[ast.stmt]) -> None:
        self.taints.append(_scope_taint(statements, self.taints[-1]))
        for statement in statements:
            self.visit(statement)
        self.taints.pop()

    def visit_Module(self, node: ast.Module) -> None:
        self.taints.append(set())
        self._visit_scope(node.body)
        self.taints.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_depth += 1
        self._visit_scope(node.body)
        self.function_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scope(node.body)

    def visit_Call(self, node: ast.Call) -> None:
        name = _resolved_name(node.func, self.aliases)
        if name in _PROCESS_CALLS:
            for command in _command_nodes(node, name):
                installer = _mentions_installer(command, self.taints[-1])
                executable = _executable_name(command)
                if not installer and executable not in COMPILER_EXECUTABLES:
                    continue
                if not installer:
                    reason = "compiler"
                elif self.function_depth == 0:
                    reason = "module-import-side-effect"
                elif _contains_installer_literal(command):
                    reason = "literal"
                else:
                    reason = "dynamic"
                self.findings.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "call": name,
                    "executable": executable,
                    "installer": installer,
                    "reason": reason,
                })
        self.generic_visit(node)


def process_execution_findings(
    source: str, filename: str = "<string>"
) -> list[dict[str, object]]:
    """Process calls that execute the installer or a Rust toolchain binary."""
    with warnings.catch_warnings():
        # Test sources may contain non-raw regex escapes.  They are valid Python
        # today and unrelated to process execution; parsing must not leak a
        # SyntaxWarning into the test runner (or fail under -W error).
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(source)
    return _ProcessExecutionScanner(filename).scan(tree)


def installer_execution_findings(
    source: str, filename: str = "<string>"
) -> list[dict[str, object]]:
    """Only process calls whose command argument references the installer.

    A module that only reads the installer text, compares a schema string, or
    mentions the path in a comment produces no finding.
    """
    return [
        finding
        for finding in process_execution_findings(source, filename)
        if finding["installer"]
    ]


def compiler_execution_findings(
    source: str, filename: str = "<string>"
) -> list[dict[str, object]]:
    return [
        finding
        for finding in process_execution_findings(source, filename)
        if finding["executable"] in COMPILER_EXECUTABLES
    ]


CACHE_KEY = (
    "rootyard-cargo-fork-${{ runner.os }}-${{ runner.arch }}-${{ github.job }}-"
    "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b-1.99.1-v1"
)

# The first formal Cargo/build marker in each workflow.  It must appear after
# the shared setup, so no job can compile with whatever `cargo` was on PATH.
FIRST_CARGO = {
    "ci.yml": "cargo fmt --all",
    "refstore-protocol-acceptance.yml": "cargo test --locked --features pando-lab",
    "redis-contract.yml": "cargo clippy --locked --all-targets --features state-redis",
    "pando-lab.yml": "cargo fmt --all",
    "refcas-log.yml": "cargo fmt --manifest-path",
    "native-kernel-acceptance.yml": "python3 scripts/build_native.py",
    "candidate-release-acceptance.yml": "- name: Build the candidate binary once and record its receipt",
}

PRESERVE = {
    "ci.yml": (
        "postgres:17",
        "scripts/install_ci_native_tools.sh install",
        "scripts/build_native_batch.py",
        "scripts/export_native_artifacts.py",
        "python3 -m unittest discover -s tests -p 'test_*.py'",
        "test-results/native-pr-gate.json",
    ),
    "refstore-protocol-acceptance.yml": (
        "postgres:17",
        "scripts/owned_garage_fixture.sh start",
        "SESSION174_DATABASE_ADMIN_URL",
        "ref_store_retention_roots",
        "test-results/refstore/",
    ),
    "redis-contract.yml": (
        "redis:7.2.6-alpine",
        "scripts/check_redis_contract.py",
        "Swatinem/rust-cache@v2",
        "state-redis",
    ),
    "pando-lab.yml": (
        "scripts/test-pando-lab.sh",
        "postgresql",
        "pando-lab-evidence",
    ),
    "refcas-log.yml": (
        "crates/refcas-log",
        "CARGO_INCREMENTAL: '0'",
        "cargo test --locked --manifest-path",
    ),
    "native-kernel-acceptance.yml": (
        "scripts/native_kernel_cgroup_setup.sh",
        "ROOTYARD_TEST_CGROUP_ROOT",
        "python3 scripts/build_native.py",
        "cargo test --locked --lib sandbox",
        "ROOTYARD_NATIVE_RECEIPT",
    ),
    "candidate-release-acceptance.yml": (
        "PLAYWRIGHT_VERSION",
        "GARAGE_IMAGE",
        "tests/browser_ui.py",
        "tests/lfs_retention_acceptance.py",
        "test-results/candidate/browser/",
        "test-results/candidate/object-store/",
    ),
}


class CargoForkWorkflowTest(unittest.TestCase):
    def workflow(self, name: str) -> str:
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def test_all_workflows_are_valid_yaml(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertNotIn("\t", text)
                self.assertTrue(text.startswith("name: "), path.name)
                if yaml is not None:
                    with path.open(encoding="utf-8") as stream:
                        document = yaml.safe_load(stream)
                    self.assertIsInstance(document, dict)

    def test_every_formal_rust_job_uses_the_shared_setup_before_cargo(self) -> None:
        for name, marker in FIRST_CARGO.items():
            with self.subTest(workflow=name):
                text = self.workflow(name)
                setup_index = text.index(SETUP)
                verify_index = text.index(VERIFY)
                rustup_index = text.index("rustup toolchain install 1.99.1")
                cache_index = text.index("uses: actions/cache@v4")
                cargo_index = text.index(marker)
                self.assertLess(rustup_index, setup_index)
                self.assertLess(cache_index, setup_index)
                self.assertLess(setup_index, verify_index)
                self.assertLess(verify_index, cargo_index)
                self.assertIn("--require-os linux", text)
                self.assertIn("--require-path", text)
                self.assertIn(REVISION, text)
                self.assertIn(RELEASE, text)
                self.assertIn(
                    "cargo -vV | grep -Fx 'commit-hash: " + REVISION + "'", text
                )
                self.assertIn(
                    "rustc -V | grep -Eq '^rustc 1\\.99\\.1 '", text
                )
                self.assertIn(CACHE_KEY, text)

    def test_candidate_runs_setup_for_both_native_jobs(self) -> None:
        text = self.workflow("candidate-release-acceptance.yml")
        self.assertEqual(text.count(SETUP), 2)
        self.assertEqual(text.count(VERIFY), 2)
        self.assertEqual(text.count("uses: actions/cache@v4"), 2)
        self.assertIn("path: /tmp/rootyard-cargo-fork", text)
        self.assertIn("--cache-dir /tmp/rootyard-cargo-fork", text)
        self.assertLess(text.index(SETUP), text.index("Install pinned Playwright client"))
        self.assertLess(text.index(SETUP), text.index("Build the candidate binary once"))
        self.assertLess(text.rindex(SETUP), text.rindex("Build the candidate binary once"))

    def test_candidate_builds_once_in_shared_cas_and_consumes_canonical_paths(self) -> None:
        text = self.workflow("candidate-release-acceptance.yml")
        builder = (
            "python3 scripts/build_native.py \\\n"
            "            --features pando-lab \\\n"
            "            --package-debug 0 \\\n"
            "            --strip-debuginfo \\\n"
            '            --artifact-store "$HOME/.cache/rootyard/native-artifacts" \\'
        )
        self.assertEqual(text.count(builder), 2)
        self.assertNotIn("target/debug/rootyard", text)
        self.assertNotIn("cp target/debug", text)
        self.assertEqual(text.count('--build-receipt "$ROOTYARD_BUILD_RECEIPT" \\'), 2)
        self.assertEqual(text.count('--binary "$ROOTYARD_BINARY" \\'), 6)
        self.assertIn(
            "cp -- \"$ROOTYARD_BUILD_RECEIPT\" test-results/candidate/browser/rootyard.build.json",
            text,
        )
        self.assertIn(
            "cp -- \"$ROOTYARD_BUILD_RECEIPT\" test-results/candidate/object-store/rootyard.build.json",
            text,
        )
        # The exported paths are the producer's own JSON fields, not a guessed
        # store layout. Both jobs validate them before writing $GITHUB_ENV.
        self.assertEqual(text.count('("binary", "ROOTYARD_BINARY")'), 2)
        self.assertEqual(text.count('("build_receipt", "ROOTYARD_BUILD_RECEIPT")'), 2)
        self.assertEqual(text.count('if receipt != Path(str(binary) + ".build.json"):'), 2)
        self.assertNotIn("json.dump", text)
        for artifact in ("candidate-browser", "candidate-object-store"):
            upload = text[text.index(f"name: {artifact}"):]
            upload = upload.split("if-no-files-found:", 1)[0]
            self.assertIn("test-results/candidate/", upload)
            self.assertNotIn("target/", upload)
            self.assertNotIn("native-artifacts", upload)

    def test_native_kernel_uses_cas_producer_and_canonical_paths(self) -> None:
        text = self.workflow("native-kernel-acceptance.yml")
        self.assertEqual(text.count("python3 scripts/build_native.py"), 1)
        self.assertIn('--artifact-store "$HOME/.cache/rootyard/native-artifacts"', text)
        self.assertNotIn("cargo build --locked --bin rootyard", text)
        self.assertNotIn("target/debug/rootyard", text)
        self.assertNotIn("ROOTYARD_BINARY: ${{ github.workspace }}", text)
        self.assertIn('python3 - "$RECEIPT_DIR/native-build.json" "$GITHUB_ENV"', text)
        self.assertEqual(text.count('("binary", "ROOTYARD_BINARY")'), 1)
        self.assertEqual(text.count('("build_receipt", "ROOTYARD_BUILD_RECEIPT")'), 1)
        self.assertIn('"ROOTYARD_BINARY=$ROOTYARD_BINARY" \\', text)
        self.assertIn("cargo test --locked --lib sandbox", text)
        # The unchanged raw command had no feature, debug or strip selector;
        # the CAS producer must not silently add one.
        builder = text[text.index("python3 scripts/build_native.py"):]
        builder = builder.split("\n      - name:", 1)[0]
        for unexpected in ("--features", "--package-debug", "--strip-debuginfo",
                           "--no-default-features"):
            self.assertNotIn(unexpected, builder)
        self.assertIn('"binary_sha256": digest(os.environ.get("ROOTYARD_BINARY"))', text)
        self.assertNotIn('os.environ.get("ROOTYARD_BINARY",', text)
        self.assertIn(
            'cp -- "$ROOTYARD_BUILD_RECEIPT" "$RECEIPT_DIR/rootyard.build.json"',
            text,
        )

    def test_ci_consumes_immutable_batch_artifacts(self) -> None:
        text = self.workflow("ci.yml")
        self.assertIn(
            '--artifact-store "$HOME/.cache/rootyard/native-artifacts"', text
        )
        self.assertIn("scripts/export_native_artifacts.py", text)
        self.assertIn("--manifest test-results/native-build-batch.json", text)
        for variable in (
            "ROOTYARD_BIN",
            "ROOTYARD_WORKSPACE_LAB_BIN",
            "ROOTYARD_VIEW_LAB_BIN",
            "ROOTYARD_PANDO_LAB_BIN",
            "ROOTYARD_BUILD_RECEIPT",
            "ROOTYARD_SNAPSHOT_FIXTURE",
            "ROOTYARD_HOLDS_FIXTURE",
        ):
            with self.subTest(variable=variable):
                self.assertIn(f"${variable}", text)

        batch = text.index("Build native bins and RefStore fixtures in one batch")
        export = text.index("Export immutable native artifact paths")
        self.assertLess(batch, export)
        # The build step itself must use its literal --output paths; the exported
        # immutable paths only exist after the export step.
        self.assertNotIn("ROOTYARD_", text[batch:export])

        later = text[export:]
        for mutable in (
            "target/debug/rootyard",
            "target/debug/rootyard-workspace-lab",
            "target/debug/rootyard-view-lab",
            "target/debug/rootyard-pando-lab",
        ):
            with self.subTest(mutable=mutable):
                self.assertNotIn(mutable, later)

        manifest = text[text.index("python3 scripts/native_report_manifest.py --mode job"):]
        manifest = manifest.split("\n      - name:", 1)[0]
        self.assertIn('--build-receipt "$ROOTYARD_BUILD_RECEIPT"', manifest)
        self.assertIn('--binary "$ROOTYARD_BIN"', manifest)
        # The final report step must consume the exporter's exact manifest
        # identity, not re-derive it from whatever bytes are present later.
        self.assertIn('--expect-batch-manifest "$ROOTYARD_BATCH_MANIFEST"', manifest)
        self.assertIn(
            '--expect-batch-manifest-sha "$ROOTYARD_BATCH_MANIFEST_SHA256"', manifest
        )
        self.assertIn("test-results/native-pr-gate.json", manifest)

        upload = text[text.index("name: e2e-report"):]
        upload = upload.split("if-no-files-found:", 1)[0]
        self.assertIn("${{ env.ROOTYARD_BUILD_RECEIPT }}", upload)
        self.assertIn("${{ env.ROOTYARD_BATCH_MANIFEST }}", upload)
        self.assertNotIn("target/", upload)
        self.assertNotIn("native-artifacts", upload)

    def test_refcas_no_longer_uses_the_rustup_plus_toolchain_form(self) -> None:
        text = self.workflow("refcas-log.yml")
        self.assertNotIn("cargo +1.99.1", text)
        for command in ("cargo fmt", "cargo clippy", "cargo test"):
            self.assertIn(command, text)
        self.assertIn("rustup default 1.99.1", text)

    def test_jobs_checks_services_and_budgets_are_preserved(self) -> None:
        for name, tokens in PRESERVE.items():
            text = self.workflow(name)
            for token in tokens:
                with self.subTest(workflow=name, token=token):
                    self.assertIn(token, text)
            self.assertIn("timeout-minutes:", text)

    def test_setup_does_not_introduce_database_or_object_store_changes(self) -> None:
        for name in FIRST_CARGO:
            text = self.workflow(name)
            with self.subTest(workflow=name):
                # The setup only changes tool selection. It must not add a
                # database/S3 endpoint, a new service, or a new job.
                self.assertNotIn("cargo-fork-db", text)
                self.assertNotIn("cargo-fork-s3", text)
                self.assertNotIn("containers:", text)
                self.assertNotIn("services:\n    cargo-fork", text)

    def test_no_hidden_setup_from_python_acceptance(self) -> None:
        for path in sorted((ROOT / "tests").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            findings = installer_execution_findings(text, path.name)
            if path.name == INSTALLER_UNIT_TEST:
                # This exact unit-test module runs the helper against fake
                # rustup/cargo programs on a private PATH.  It is the intended
                # installer test, not a hidden CI setup step.  Other modules
                # whose names happen to contain "cargo_fork" are still scanned.
                self.assertIn("FAKE_RUSTUP", text)
                self.assertIn("FAKE_CARGO", text)
                continue
            with self.subTest(test=path.name):
                self.assertEqual(
                    [],
                    findings,
                    path.name + " must not execute the CargoFork installer; "
                    "source reads and schema string comparisons are allowed",
                )

    def test_installer_source_read_fixture_is_not_an_invocation(self) -> None:
        path = ROOT / "tests" / "test_refstore_receipt_validators.py"
        text = path.read_text(encoding="utf-8")
        self.assertIn(INSTALLER, text)
        self.assertEqual([], process_execution_findings(text, path.name))
        self.assertEqual(
            [], installer_execution_findings(text, path.name)
        )

    def test_installer_scanner_rejects_every_execution_form(self) -> None:
        read_only = (
            "from pathlib import Path\n"
            'HELPER = Path("scripts/install_ci_cargo_fork.sh")\n'
            "def test_schema():\n"
            "    text = HELPER.read_text()\n"
            '    assert "install_ci_cargo_fork.sh" in text\n'
        )
        self.assertEqual([], process_execution_findings(read_only))

        cases = {
            "literal": (
                "import subprocess\n"
                "def test_install():\n"
                '    subprocess.run(["scripts/install_ci_cargo_fork.sh", "install"])\n',
                "literal",
            ),
            "dynamic": (
                "import subprocess\n"
                'HELPER = "scripts/install_ci_cargo_fork.sh"\n'
                "def test_install():\n"
                '    subprocess.run([HELPER, "install"])\n',
                "dynamic",
            ),
            "module-import-side-effect": (
                "import subprocess\n"
                'HELPER = "scripts/install_ci_cargo_fork.sh"\n'
                'subprocess.run([HELPER, "install"])\n',
                "module-import-side-effect",
            ),
            "local-alias": (
                "import subprocess\n"
                'HELPER = "scripts/install_ci_cargo_fork.sh"\n'
                "def test_install():\n"
                '    command = [HELPER, "install"]\n'
                "    subprocess.run(command)\n",
                "dynamic",
            ),
            "import-alias": (
                "from subprocess import run as execute\n"
                'HELPER = "scripts/install_ci_cargo_fork.sh"\n'
                "def test_install():\n"
                '    execute([HELPER, "install"])\n',
                "dynamic",
            ),
            "os-system": (
                "import os\n"
                "def test_install():\n"
                '    os.system("scripts/install_ci_cargo_fork.sh install")\n',
                "literal",
            ),
        }
        for name, (source, reason) in cases.items():
            with self.subTest(case=name):
                findings = installer_execution_findings(source, name + ".py")
                self.assertEqual(1, len(findings), findings)
                self.assertTrue(findings[0]["installer"])
                self.assertEqual(reason, findings[0]["reason"])

    def test_compiler_scanner_detects_direct_cargo_build(self) -> None:
        source = (
            "import subprocess\n"
            "def test_lab():\n"
            '    subprocess.run(["cargo", "build", "--locked"], check=True)\n'
        )
        findings = compiler_execution_findings(source, "synthetic.py")
        self.assertEqual(["cargo"], [row["executable"] for row in findings])
        self.assertFalse(findings[0]["installer"])

    def test_strengthened_scanner_detects_active_view_lab_cargo(self) -> None:
        # The labs worker owns replacing this fallback with the canonical
        # ROOTYARD_VIEW_LAB_BIN input.  Until that lands, the strengthened
        # scanner must still see the active compiler call rather than hiding it
        # behind a raw text exclusion.
        path = ROOT / "tests" / "test_view_lab.py"
        text = path.read_text(encoding="utf-8")
        findings = compiler_execution_findings(text, path.name)
        active = re.search(
            r'subprocess\.(?:run|Popen|call|check_call|check_output)\(\s*'
            r'\[\s*["\']cargo["\']',
            text,
        )
        if active:
            self.assertTrue(
                findings,
                "test_view_lab.py still invokes cargo but the scanner missed it",
            )
            self.assertIn("cargo", [row["executable"] for row in findings])
        else:
            self.assertEqual(
                [],
                findings,
                "the canonical lab-binary path must not look like a compiler call",
            )

    def test_no_hidden_compiler_build_from_python_acceptance(self) -> None:
        # Every test module must consume an immutable prepared binary.  The one
        # pending labs-owned file may still carry exactly its single known
        # active cargo fallback; any additional compiler call there (or any
        # compiler call anywhere else) fails this guard.
        for path in sorted((ROOT / "tests").glob("*.py")):
            findings = compiler_execution_findings(
                path.read_text(encoding="utf-8"), path.name
            )
            with self.subTest(test=path.name):
                if path.name == "test_view_lab.py" and findings:
                    self.assertEqual(1, len(findings), findings)
                    self.assertEqual("cargo", findings[0]["executable"], findings)
                    continue
                self.assertEqual(
                    [],
                    findings,
                    path.name + " must consume an immutable prepared binary, "
                    "never invoke cargo/rustc/rustup",
                )


if __name__ == "__main__":
    unittest.main()
