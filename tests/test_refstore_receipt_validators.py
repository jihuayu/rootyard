"""Static guards for the two refstore inline receipt validators.

The workflow runs its validators in shell heredocs, so these checks keep the
version-dispatched parser wired in, preserve the old v1 freshness/rebuilt
requirements, and ensure no validator starts a Cargo, rustc or builder probe.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/refstore-protocol-acceptance.yml"
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import native_build_receipt as receipts  # noqa: E402


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


PANDO_SCHEMA_SQL = (
    "-- Separate namespace, never applied by Rootyard's production migration runner.\n"
    "CREATE SCHEMA IF NOT EXISTS pando_lab;\n"
    "CREATE TABLE IF NOT EXISTS pando_lab.repositories (\n"
    " id uuid PRIMARY KEY, generation bigint NOT NULL DEFAULT 0);\n"
)


def heredoc_blocks(text):
    blocks = []
    for match in re.finditer(r"<<'PY'[^\n]*\n(.*?)\n\s*PY\n", text, re.S):
        lines = match.group(1).splitlines()
        blocks.append("\n".join(
            line[10:] if line.startswith(" " * 10) else line.lstrip()
            for line in lines
        ))
    return blocks


def git(root, *arguments):
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "receipt-test",
        "GIT_AUTHOR_EMAIL": "receipt-test@example.invalid",
        "GIT_COMMITTER_NAME": "receipt-test",
        "GIT_COMMITTER_EMAIL": "receipt-test@example.invalid",
    }
    subprocess.run(["git", *arguments], cwd=root, env=environment, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def make_batch_fixture(root, schema):
    root = Path(root)
    (root / "scripts").mkdir()
    shutil.copyfile(SCRIPTS / "native_build_receipt.py", root / "scripts/native_build_receipt.py")
    files = {
        "Cargo.toml": '[package]\nname = "rootyard"\n',
        "Cargo.lock": "version = 3\n",
        "src/lib.rs": "pub fn production() -> u8 { 1 }\n",
        "src/main.rs": "fn main() {}\n",
        "tests/blob_git_gateway.rs": "#[test]\nfn example() {}\n",
        "tests/blob_gateway_support/helper.rs": "pub fn helper() {}\n",
        "experimental/pando/schema.sql": PANDO_SCHEMA_SQL,
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "fixture")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

    evidence = root / "evidence"
    evidence.mkdir()
    test_binary = evidence / "blob-git-gateway"
    test_binary.write_bytes(b"integration-test-binary")
    test_binary.chmod(0o700)
    serving_binary = evidence / "rootyard"
    serving_binary.write_bytes(b"rootyard-binary")
    serving_binary.chmod(0o700)
    test_receipt_path = evidence / "blob-git-gateway.build.json"
    serving_receipt_path = evidence / "rootyard.build.json"
    (root / "test-results/refstore/blob_git_gateway").mkdir(parents=True)

    if schema == "v1":
        source = "b" * 64
        test_receipt = {
            "version": 1,
            "kind": "rust-integration-test",
            "relocated_artifact": True,
            "workspace_commit": head,
            "binary_sha256": digest(test_binary),
            "source_inputs_sha256": source,
            "integration_test_source_sha256": digest(root / "tests/blob_git_gateway.rs"),
            "rustc": "rustc 1.99.1",
            "command": ["cargo", "--config", "x", "test", "--locked"],
            "fresh": False,
            "package_rebuilt": True,
            "fresh_false_artifacts": [
                {"kind": "test", "target": "blob_git_gateway", "fresh": False},
            ],
        }
        serving_receipt = {
            "version": 1,
            "workspace_commit": head,
            "binary_sha256": digest(serving_binary),
            "source_inputs_sha256": source,
            "rustc": "rustc 1.99.1",
            "command": ["cargo", "build", "--locked"],
            "fresh": False,
            "package_rebuilt": True,
            "fresh_false_artifacts": [
                {"kind": "bin", "target": "rootyard", "fresh": False},
            ],
        }
    else:
        toolchain_dir = root / "toolchain"
        toolchain_dir.mkdir()
        for name in ("cargo", "rustc", "rustup"):
            (toolchain_dir / name).write_bytes(("fake-" + name).encode())

        def identity(name, release, commit_hash):
            executable = toolchain_dir / name
            return {
                "executable": str(executable),
                "executable_sha256": digest(executable),
                "version": f"{name} {release} (fake)",
                "release": release,
                "commit_hash": commit_hash,
                "commit_date": "2026-01-01",
                "host": "x86_64-unknown-linux-gnu",
            }

        toolchain = {
            "cargo": identity("cargo", "1.101.0", "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"),
            "rustc": dict(identity("rustc", "1.99.1", "d" * 40),
                          path_entry=str(toolchain_dir / "rustc"), proxy=False),
            "rustup": {
                "executable": str(toolchain_dir / "rustup"),
                "executable_sha256": digest(toolchain_dir / "rustup"),
                "resolved_rustc": str(toolchain_dir / "rustc"),
                "resolved_rustc_sha256": digest(toolchain_dir / "rustc"),
            },
            "target_triple": "x86_64-unknown-linux-gnu",
            "pinned_channel": "1.99.1",
            "pin_source": "rust-toolchain.toml",
        }
        bound = receipts.capture_bound_inputs(root, environ={"PATH": ""})
        dev_profile = {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                       "overflow_checks": True, "test": False}
        test_profile = dict(dev_profile, test=True)
        original_test = evidence / "original-test"
        shutil.copyfile(test_binary, original_test)
        original_test.chmod(0o700)
        test_artifact = receipts.cargo_artifact_record(
            {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {"name": "blob_git_gateway", "kind": ["test"],
                           "src_path": str(root / "tests/blob_git_gateway.rs")},
                "profile": test_profile,
                "fresh": True,
                "executable": str(original_test),
            },
            root,
        )
        serving_artifact = receipts.cargo_artifact_record(
            {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {"name": "rootyard", "kind": ["bin"],
                           "src_path": str(root / "src/main.rs")},
                "profile": dev_profile,
                "fresh": False,
                "executable": str(serving_binary),
            },
            root,
        )
        test_receipt = receipts.make_receipt_v2(
            binary_path=test_binary,
            command=["cargo", "--config", "x", "test", "--locked"],
            profile="test",
            artifacts=[test_artifact],
            toolchain=toolchain,
            bound_inputs=bound,
            workspace_commit=head,
            target_dir=root / "target",
            target_triple="x86_64-unknown-linux-gnu",
            extra={
                "kind": "rust-integration-test",
                "relocated_artifact": True,
                "original_artifact_sha256": digest(original_test),
                "integration_test_source_sha256": digest(root / "tests/blob_git_gateway.rs"),
            },
        )
        serving_receipt = receipts.make_receipt_v2(
            binary_path=serving_binary,
            command=["cargo", "build", "--locked"],
            profile="dev",
            artifacts=[serving_artifact],
            toolchain=toolchain,
            bound_inputs=bound,
            workspace_commit=head,
            target_dir=root / "target",
            target_triple="x86_64-unknown-linux-gnu",
        )

    test_receipt_path.write_text(json.dumps(test_receipt))
    serving_receipt_path.write_text(json.dumps(serving_receipt))
    return {
        "root": root,
        "test_receipt": test_receipt_path,
        "serving_receipt": serving_receipt_path,
        "test_binary": test_binary,
        "serving_binary": serving_binary,
        "test_source": "tests/blob_git_gateway.rs",
    }


def make_preflight_fixture(root, block):
    root = Path(root).resolve()
    tree = ast.parse(block)
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in ("names", "EXPECTED_LIB_COMMAND", "EXPECTED_CLI_COMMAND"):
            constants[node.targets[0].id] = ast.literal_eval(node.value)
    names = constants["names"]
    expected_lib = constants["EXPECTED_LIB_COMMAND"]
    expected_cli = constants["EXPECTED_CLI_COMMAND"]

    (root / "scripts").mkdir()
    shutil.copyfile(SCRIPTS / "native_build_receipt.py", root / "scripts/native_build_receipt.py")
    for relative, content in (
        ("Cargo.toml", '[package]\nname = "rootyard"\n'),
        ("Cargo.lock", "version = 3\n"),
        ("src/lib.rs", "pub fn production() -> u8 { 1 }\n"),
        ("src/main.rs", "fn main() {}\n"),
        ("experimental/pando/schema.sql", PANDO_SCHEMA_SQL),
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "fixture")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

    evidence = root / "evidence"
    evidence.mkdir()
    target = root / "target/debug"
    target.mkdir(parents=True)
    target_cli = target / "rootyard"
    target_cli.write_text("#!/bin/sh\nexit 0\n")
    target_cli.chmod(0o700)
    cli = evidence / "rootyard-cli"
    shutil.copyfile(target_cli, cli)
    cli.chmod(0o700)
    lib = evidence / "session174-lib-tests"
    lib.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"names = {names!r}\n"
        "if sys.argv[1:] == ['--list', '--ignored']:\n"
        "    for name in names:\n"
        "        print(name + ': test')\n"
    )
    lib.chmod(0o700)
    (evidence / "fake-bin").mkdir()
    psql = evidence / "fake-bin/psql"
    psql.write_text("#!/bin/sh\nprintf 't\\n'\n")
    psql.chmod(0o700)

    toolchain_dir = root / "toolchain"
    toolchain_dir.mkdir()
    for name in ("cargo", "rustc", "rustup"):
        (toolchain_dir / name).write_bytes(("fake-" + name).encode())

    def identity(name, release, commit_hash):
        executable = toolchain_dir / name
        return {
            "executable": str(executable),
            "executable_sha256": digest(executable),
            "version": f"{name} {release} (fake)",
            "release": release,
            "commit_hash": commit_hash,
            "commit_date": "2026-01-01",
            "host": "x86_64-unknown-linux-gnu",
        }

    toolchain = {
        "cargo": identity("cargo", "1.101.0", "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"),
        "rustc": dict(identity("rustc", "1.99.1", "d" * 40),
                      path_entry=str(toolchain_dir / "rustc"), proxy=False),
        "rustup": {
            "executable": str(toolchain_dir / "rustup"),
            "executable_sha256": digest(toolchain_dir / "rustup"),
            "resolved_rustc": str(toolchain_dir / "rustc"),
            "resolved_rustc_sha256": digest(toolchain_dir / "rustc"),
        },
        "target_triple": "x86_64-unknown-linux-gnu",
        "pinned_channel": "1.99.1",
        "pin_source": "rust-toolchain.toml",
    }
    bound = receipts.capture_bound_inputs(root, environ={"PATH": ""})
    dev_profile = {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                   "overflow_checks": True, "test": False}
    test_profile = {"opt_level": "0", "debuginfo": 0, "debug_assertions": True,
                    "overflow_checks": True, "test": True}

    original_lib = root / "target/debug/deps/libtest-original"
    original_lib.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(lib, original_lib)
    original_lib.chmod(0o700)
    lib_artifact = receipts.cargo_artifact_record(
        {
            "reason": "compiler-artifact",
            "package_id": "rootyard 0.1.0",
            "target": {"name": "rootyard", "kind": ["lib"],
                       "src_path": str(root / "src/lib.rs")},
            "profile": test_profile,
            "fresh": True,
            "executable": str(original_lib),
        },
        root,
    )
    test_receipt = receipts.make_receipt_v2(
        binary_path=lib,
        command=expected_lib,
        profile="test",
        artifacts=[lib_artifact],
        toolchain=toolchain,
        bound_inputs=bound,
        workspace_commit=head,
        target_dir=root / "target",
        target_triple="x86_64-unknown-linux-gnu",
        extra={
            "kind": "rust-library-test",
            "relocated_artifact": True,
            "original_artifact_sha256": digest(original_lib),
            "lib_test_support_inputs_sha256": "c" * 64,
        },
    )
    receipts.atomic_write_json(lib.with_suffix(".build.json"), test_receipt)

    cli_lib = receipts.cargo_artifact_record(
        {
            "reason": "compiler-artifact",
            "package_id": "rootyard 0.1.0",
            "target": {"name": "rootyard", "kind": ["lib"],
                       "src_path": str(root / "src/lib.rs")},
            "profile": dev_profile,
            "fresh": True,
        },
        root,
    )
    cli_bin = receipts.cargo_artifact_record(
        {
            "reason": "compiler-artifact",
            "package_id": "rootyard 0.1.0",
            "target": {"name": "rootyard", "kind": ["bin"],
                       "src_path": str(root / "src/main.rs")},
            "profile": dev_profile,
            "fresh": False,
            "executable": str(target_cli),
        },
        root,
    )
    cli_receipt = receipts.make_receipt_v2(
        binary_path=cli,
        command=expected_cli,
        profile="dev",
        artifacts=[cli_lib, cli_bin],
        toolchain=toolchain,
        bound_inputs=bound,
        workspace_commit=head,
        target_dir=root / "target",
        target_triple="x86_64-unknown-linux-gnu",
    )
    receipts.atomic_write_json(target_cli.with_suffix(".build.json"), cli_receipt)
    return {
        "root": root,
        "evidence": evidence,
        "lib": lib,
        "cli": cli,
        "fake_bin": evidence / "fake-bin",
        "head": head,
    }


class RefstoreReceiptValidatorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.validators = [
            block for block in heredoc_blocks(cls.source)
            if "native_build_receipt" in block
        ]
        cls.batch_validator = next(
            block for block in cls.validators
            if "build receipt verification failed" in block
        )
        cls.preflight_validator = next(
            block for block in cls.validators
            if "session174 preflight" in block
        )

    def test_validators_parse_and_use_the_shared_reader(self):
        self.assertEqual(len(self.validators), 2)
        for block in self.validators:
            ast.parse(block)
            self.assertIn("import native_build_receipt as receipts", block)
            self.assertIn("receipts.load_receipt(", block)
            self.assertIn("verify_source_files=False", block)
            self.assertNotIn("probe_toolchain", block)
            self.assertNotIn("capture_bound_inputs", block)
            self.assertNotIn("cargo_artifact_record", block)

    def test_batch_validator_keeps_v1_and_accepts_v2_booleans(self):
        block = self.batch_validator
        self.assertIn("if validated.schema == 'v1':", block)
        self.assertIn("entry.get('fresh') is False", block)
        self.assertIn("fresh_false_artifacts[' + str(index) + '] is not fresh=false", block)
        self.assertIn("package_rebuilt", block)
        self.assertIn("test_receipt.get('fresh') is False", block)
        self.assertIn("isinstance(entry.get('fresh'), bool)", block)
        self.assertIn("cargo_artifacts[' + str(index) + '] fresh is not a JSON boolean", block)
        self.assertIn("receipts.RECEIPT_SCHEMA_V2", block)
        # The old top-level freshness/rebuilt demands are inside the v1 branch.
        v1_branch = block.index("if test_validated.schema == 'v1':")
        self.assertGreater(block.index("check(test_receipt.get('fresh') is False"), v1_branch)
        self.assertGreater(block.index("check(test_receipt.get('package_rebuilt') is True"), v1_branch)
        # The selected artifact identity and exact executable hashes remain.
        self.assertIn("'blob_git_gateway' and entry.get('kind') == 'test'", block)
        self.assertIn("serving_receipt.get('binary_sha256') == sha256(serving_binary)", block)

    def test_preflight_validator_keeps_v1_and_accepts_v2_booleans(self):
        block = self.preflight_validator
        self.assertIn("if test_validated.schema == 'v1':", block)
        self.assertIn("test_receipt.get('fresh') is not False", block)
        self.assertIn("test_receipt.get('package_rebuilt') is not True", block)
        self.assertIn("cli_receipt.get('version') != 1", block)
        self.assertIn("test_validated.schema == 'v2'", block)
        self.assertIn("not isinstance(test_artifact.get('fresh'), bool)", block)
        self.assertIn("EXPECTED_LIB_COMMAND", block)
        self.assertIn("EXPECTED_CLI_COMMAND", block)
        self.assertIn("test_artifact.get('kind') != 'lib-test'", block)
        self.assertIn("cli_receipt.get('target_dir')", block)
        self.assertIn("pathlib.Path(executable).resolve()", block)
        # The old freshness/rebuilt demands are inside the v1 branch.
        v1_branch = block.index("if test_validated.schema == 'v1':")
        self.assertGreater(block.index("test_receipt.get('fresh') is not False"), v1_branch)
        self.assertGreater(block.index("test_receipt.get('package_rebuilt') is not True"), v1_branch)

    def test_batch_validator_runs_on_legacy_and_v2_receipts(self):
        for schema in ("v1", "v2"):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as temporary:
                fixture = make_batch_fixture(temporary, schema)
                process = subprocess.run(
                    [sys.executable, "-",
                     fixture["test_receipt"], fixture["serving_receipt"],
                     fixture["test_binary"], fixture["serving_binary"],
                     fixture["test_source"]],
                    cwd=fixture["root"],
                    input=self.batch_validator,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(
                    process.returncode, 0,
                    f"{schema} validator failed:\n{process.stdout[-2000:]}\n{process.stderr[-2000:]}",
                )
                manifest = json.loads(
                    (fixture["root"] / "test-results/refstore/blob_git_gateway/build-pair.json").read_text()
                )
                self.assertEqual(manifest["test_receipt"]["receipt_schema"], schema)
                if schema == "v1":
                    self.assertIn("fresh_false_artifacts", manifest["test_receipt"])
                else:
                    self.assertNotIn("fresh", manifest["test_receipt"])

    def test_preflight_validator_runs_on_v2_receipts_without_a_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(temporary, self.preflight_validator)
            environment = os.environ.copy()
            environment.update({
                "GITHUB_WORKSPACE": str(fixture["root"]),
                "DATABASE_URL": "postgresql://fixture.invalid/rootyard",
                "PATH": str(fixture["fake_bin"]) + os.pathsep + environment.get("PATH", ""),
            })
            process = subprocess.run(
                [sys.executable, "-", str(fixture["lib"]), str(fixture["cli"])],
                cwd=fixture["root"],
                env=environment,
                input=self.preflight_validator,
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                process.returncode, 0,
                f"v2 preflight failed:\n{process.stdout[-2000:]}\n{process.stderr[-2000:]}",
            )
            preflight = json.loads((fixture["evidence"] / "preflight.json").read_text())
            self.assertEqual(preflight["receipt_schema"], "v2")
            self.assertEqual(preflight["head"], fixture["head"])
            self.assertEqual(preflight["rustc"], "rustc 1.99.1 (fake)")

    def test_validators_never_build_or_probe(self):
        """Only metadata/validation calls are allowed, never a build command."""
        for block in self.validators:
            tree = ast.parse(block)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                self.assertNotIn(name, ("probe_toolchain", "capture_bound_inputs",
                                        "cargo_artifact_record", "make_receipt_v2"))
                if name not in ("run", "check_output", "Popen") or not node.args:
                    continue
                first = node.args[0]
                if isinstance(first, ast.List) and first.elts:
                    head = first.elts[0]
                    if isinstance(head, ast.Constant) and isinstance(head.value, str):
                        self.assertNotIn(head.value, ("cargo", "rustc", "rustup"))


if __name__ == "__main__":
    unittest.main()
