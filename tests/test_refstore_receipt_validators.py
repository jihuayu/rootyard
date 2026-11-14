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


def validator_constants(block):
    constants = {}
    names = {
        "EXPECTED_CARGO_COMMIT",
        "EXPECTED_CARGO_RELEASE",
        "EXPECTED_RUST_RELEASE",
        "EXPECTED_FEATURES",
        "EXPECTED_TEST_COMMAND",
        "EXPECTED_SERVING_COMMAND",
        "CLOSURE_LABEL",
    }
    for node in ast.parse(block).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in names:
            constants[node.targets[0].id] = ast.literal_eval(node.value)
    return constants


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


def make_batch_fixture(root, schema, expected, fresh=(True, False), jobs=2,
                       weak_commands=False):
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
    results = root / "test-results/refstore"
    (results / "blob_git_gateway").mkdir(parents=True)

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

    cargo_commit = expected["EXPECTED_CARGO_COMMIT"]
    cargo_release = expected["EXPECTED_CARGO_RELEASE"]
    rust_release = expected["EXPECTED_RUST_RELEASE"]
    rust_commit = "d" * 40
    toolchain = {
        "cargo": identity("cargo", cargo_release, cargo_commit),
        "rustc": dict(identity("rustc", rust_release, rust_commit),
                      path_entry=str(toolchain_dir / "rustc"), proxy=False),
        "rustup": {
            "executable": str(toolchain_dir / "rustup"),
            "executable_sha256": digest(toolchain_dir / "rustup"),
            "resolved_rustc": str(toolchain_dir / "rustc"),
            "resolved_rustc_sha256": digest(toolchain_dir / "rustc"),
        },
        "target_triple": "x86_64-unknown-linux-gnu",
        "pinned_channel": rust_release,
        "pin_source": "rust-toolchain.toml",
    }
    record = {
        "schema": "rootyard/cargo-fork/v1",
        "revision": cargo_commit,
        "release": cargo_release,
        "full_version": toolchain["cargo"]["version"],
        "commit_hash": cargo_commit,
        "host": "x86_64-unknown-linux-gnu",
        "binary_sha256": toolchain["cargo"]["executable_sha256"],
        "rustc": {
            "full_version": toolchain["rustc"]["version"],
            "release": rust_release,
            "commit_hash": rust_commit,
            "host": "x86_64-unknown-linux-gnu",
        },
    }
    record_path = results / "cargo-fork.json"
    record_path.write_text(json.dumps(record))

    test_command = list(expected["EXPECTED_TEST_COMMAND"])
    serving_command = list(expected["EXPECTED_SERVING_COMMAND"])
    if schema == "v1":
        assert jobs is None, "the legacy exact-command anchor has no --jobs fragment"
    if weak_commands:
        test_command = ["cargo", "--config", "x", "test", "--locked"]
        serving_command = ["cargo", "build", "--locked"]
    elif jobs is not None:
        test_command += ["--jobs", str(jobs)]
        serving_command += ["--jobs", str(jobs)]

    if schema == "v1":
        source = receipts.source_digest(root)
        rustc = f"rustc {rust_release} (fake)"
        test_receipt = {
            "version": 1,
            "kind": "rust-integration-test",
            "relocated_artifact": True,
            "workspace_commit": head,
            "binary_sha256": digest(test_binary),
            "original_artifact_sha256": digest(test_binary),
            "source_inputs_sha256": source,
            "integration_test_source_sha256": digest(root / "tests/blob_git_gateway.rs"),
            "rustc": rustc,
            "command": test_command,
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
            "rustc": rustc,
            "command": serving_command,
            "fresh": False,
            "package_rebuilt": True,
            "fresh_false_artifacts": [
                {"kind": "bin", "target": "rootyard", "fresh": False},
            ],
        }
    else:
        bound = receipts.capture_bound_inputs(root, environ={"PATH": ""})
        dev_profile = {"opt_level": "0", "debuginfo": 0, "debug_assertions": True,
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
                "fresh": fresh[0],
                "executable": str(original_test),
            },
            root,
        )
        serving_lib = receipts.cargo_artifact_record(
            {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {"name": "rootyard", "kind": ["lib"],
                           "src_path": str(root / "src/lib.rs")},
                "profile": dev_profile,
                "fresh": fresh[1],
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
                "fresh": fresh[1],
                "executable": str(serving_binary),
            },
            root,
        )
        features = dict(expected["EXPECTED_FEATURES"])
        test_receipt = receipts.make_receipt_v2(
            binary_path=test_binary,
            command=test_command,
            profile="test",
            artifacts=[test_artifact],
            toolchain=toolchain,
            bound_inputs=bound,
            workspace_commit=head,
            target_dir=root / "target",
            target_triple="x86_64-unknown-linux-gnu",
            features=features,
            extra={
                "kind": "rust-integration-test",
                "relocated_artifact": True,
                "original_artifact_sha256": digest(original_test),
                "integration_test_source_sha256": digest(root / "tests/blob_git_gateway.rs"),
                "build_options": {"jobs": jobs},
            },
        )
        serving_receipt = receipts.make_receipt_v2(
            binary_path=serving_binary,
            command=serving_command,
            profile="dev",
            artifacts=[serving_lib, serving_artifact],
            toolchain=toolchain,
            bound_inputs=bound,
            workspace_commit=head,
            target_dir=root / "target",
            target_triple="x86_64-unknown-linux-gnu",
            features=features,
            extra={
                "kind": "native-binary",
                "build_options": {"jobs": jobs},
            },
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
        "record": record_path,
        "expected": expected,
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
        blocks = heredoc_blocks(cls.source)
        cls.validators = [
            block for block in blocks
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
        cls.copy_check = next(
            block for block in blocks
            if "build-pair receipt copy check failed" in block
        )
        cls.batch_constants = validator_constants(cls.batch_validator)

    def run_batch_validator(self, fixture):
        return subprocess.run(
            [sys.executable, "-",
             fixture["test_receipt"], fixture["serving_receipt"],
             fixture["test_binary"], fixture["serving_binary"],
             fixture["test_source"]],
            cwd=fixture["root"],
            input=self.batch_validator,
            text=True,
            capture_output=True,
        )

    def run_copy_check(self, fixture):
        return subprocess.run(
            [sys.executable, "-"],
            cwd=fixture["root"],
            input=self.copy_check,
            text=True,
            capture_output=True,
        )

    def assert_batch_passes(self, fixture):
        process = self.run_batch_validator(fixture)
        self.assertEqual(
            process.returncode, 0,
            f"validator failed:\n{process.stdout[-2000:]}\n{process.stderr[-2000:]}",
        )
        return json.loads(
            (fixture["root"] / "test-results/refstore/blob_git_gateway/build-pair.json").read_text()
        )

    def assert_batch_fails(self, fixture, marker):
        process = self.run_batch_validator(fixture)
        self.assertNotEqual(process.returncode, 0,
                            f"validator unexpectedly passed:\n{process.stdout[-2000:]}")
        self.assertIn(marker, process.stderr,
                      f"validator failed without {marker!r}:\n{process.stderr[-2000:]}")
        return process

    def copy_raw_receipts(self, fixture):
        directory = fixture["root"] / "test-results/refstore/blob_git_gateway"
        shutil.copyfile(fixture["test_receipt"], directory / "blob-git-gateway.build.json")
        shutil.copyfile(fixture["serving_receipt"], directory / "rootyard.build.json")
        return directory

    def test_validators_parse_and_use_the_shared_reader(self):
        self.assertEqual(len(self.validators), 2)
        for block in self.validators:
            ast.parse(block)
            self.assertIn("import native_build_receipt as receipts", block)
            self.assertIn("receipts.load_receipt(", block)
            self.assertNotIn("probe_toolchain", block)
            self.assertNotIn("capture_bound_inputs", block)
            self.assertNotIn("cargo_artifact_record", block)
        self.assertIn("source_root=workspace", self.batch_validator)
        self.assertIn("verify_source_files=True", self.batch_validator)
        self.assertIn("verify_source_files=False", self.preflight_validator)

    def test_batch_validator_keeps_v1_and_accepts_v2_booleans(self):
        block = self.batch_validator
        self.assertIn("if test_validated.schema == 'v1':", block)
        self.assertIn("entry.get('fresh') is False", block)
        self.assertIn("fresh_false_artifacts[' + str(index) + '] is not fresh=false", block)
        self.assertIn("package_rebuilt", block)
        self.assertIn("test_receipt.get('fresh') is False", block)
        self.assertIn("isinstance(entry.get('fresh'), bool)", block)
        self.assertIn("cargo_artifacts[' + str(index) + '] fresh is not a JSON boolean", block)
        self.assertIn("receipts.RECEIPT_SCHEMA_V2", block)
        # Exact configured argv, profile/features and paired trust anchors.
        self.assertIn("EXPECTED_TEST_COMMAND", block)
        self.assertIn("EXPECTED_SERVING_COMMAND", block)
        self.assertIn("EXPECTED_FEATURES", block)
        self.assertIn("require_v2_toolchain", block)
        self.assertIn("test-results/refstore/cargo-fork.json", block)
        self.assertIn("receipt_path", block)
        self.assertIn("receipt_sha256", block)
        self.assertIn("build_options", block)
        self.assertIn("test_source_closure", block)
        # The closure is recomputed from HEAD; no v1 receipt field is invented.
        self.assertNotIn("test_receipt.get('test_source_closure')", block)
        self.assertNotIn("CARGO_FORK_SHA256", block)
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

    def test_batch_validator_accepts_positive_v2_cache_hits(self):
        cases = (
            ((True, True), 2),
            ((False, False), 2),
            ((True, False), None),
        )
        for fresh, jobs in cases:
            with self.subTest(fresh=fresh, jobs=jobs), tempfile.TemporaryDirectory() as temporary:
                fixture = make_batch_fixture(
                    temporary, "v2", self.batch_constants, fresh=fresh, jobs=jobs)
                manifest = self.assert_batch_passes(fixture)
                self.assertEqual(manifest["test_receipt"]["receipt_schema"], "v2")
                self.assertEqual(manifest["test_receipt"]["receipt_path"],
                                 str(fixture["test_receipt"].resolve()))
                self.assertEqual(manifest["test_receipt"]["receipt_sha256"],
                                 digest(fixture["test_receipt"]))
                self.assertEqual(manifest["serving_receipt"]["receipt_sha256"],
                                 digest(fixture["serving_receipt"]))
                self.assertEqual(
                    manifest["test_receipt"]["cargo_artifacts"][0]["fresh"], fresh[0])
                self.assertEqual(
                    manifest["serving_receipt"]["cargo_artifacts"][1]["fresh"], fresh[1])
                record = json.loads(fixture["record"].read_text())
                self.assertEqual(manifest["toolchain"]["cargo"]["executable_sha256"],
                                 record["binary_sha256"])
                self.assertIn("test_source_closure", manifest)
                self.assertRegex(manifest["test_source_closure"]["sha256"], r"^[0-9a-f]{64}$")
                self.assertIn("tests/blob_gateway_support/helper.rs",
                              manifest["test_source_closure"]["files"])
                self.assertNotIn("fresh", manifest["test_receipt"])

    def test_batch_validator_accepts_fully_bound_v1(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_batch_fixture(
                temporary, "v1", self.batch_constants, fresh=(False, False), jobs=None)
            manifest = self.assert_batch_passes(fixture)
            self.assertEqual(manifest["test_receipt"]["receipt_schema"], "v1")
            self.assertIn("fresh_false_artifacts", manifest["test_receipt"])
            self.assertEqual(manifest["test_receipt"]["receipt_path"],
                             str(fixture["test_receipt"].resolve()))
            self.assertEqual(manifest["test_receipt"]["receipt_sha256"],
                             digest(fixture["test_receipt"]))

        with tempfile.TemporaryDirectory() as temporary:
            weak = make_batch_fixture(
                temporary, "v1", self.batch_constants, fresh=(False, False),
                jobs=None, weak_commands=True)
            head = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=weak["root"], text=True).strip()
            # Legacy receipts stay readable by the shared reader...
            parsed = receipts.load_receipt(
                weak["test_receipt"], source_root=weak["root"],
                binary_path=weak["test_binary"], expected_commit=head,
                verify_source_files=True)
            self.assertEqual(parsed.schema, "v1")
            # ...but unproven acceptance is rejected before functional use.
            self.assert_batch_fails(weak, "expected exactly")

    def test_batch_validator_rejects_tampered_contracts(self):
        def edit_receipt(fixture, key, mutate):
            path = fixture[key]
            payload = json.loads(path.read_text())
            mutate(payload)
            path.write_text(json.dumps(payload))

        def command(payload):
            index = payload["command"].index("--no-default-features")
            payload["command"][index] = "--default-features"

        def features(payload):
            payload["features"]["enabled"] = ["pando-lab", "extra"]

        def no_default(payload):
            payload["features"]["no_default_features"] = False

        def profile(payload):
            payload["profile"] = "dev"

        def artifact_profile(payload):
            payload["cargo_artifacts"][0]["profile"]["test"] = False

        def toolchain(payload):
            payload["toolchain"]["cargo"]["executable_sha256"] = "0" * 64

        def jobs_mismatch(payload):
            payload["command"][-1] = "3"
            payload["build_options"]["jobs"] = 2

        def jobs_zero(payload):
            payload["command"][-1] = "0"
            payload["build_options"]["jobs"] = 0

        def record_release(fixture):
            record = json.loads(fixture["record"].read_text())
            record["rustc"]["release"] = "1.99.2"
            fixture["record"].write_text(json.dumps(record))

        def source_file(fixture):
            (fixture["root"] / "src/lib.rs").write_text("pub fn changed() -> u8 { 2 }\n")

        def support_file(fixture):
            (fixture["root"] / "tests/blob_gateway_support/helper.rs").write_text(
                "pub fn helper() -> u8 { 2 }\n")

        cases = (
            ("command", lambda fixture: edit_receipt(fixture, "test_receipt", command),
             "expected exactly"),
            ("features", lambda fixture: edit_receipt(fixture, "test_receipt", features),
             "enables unexpected features"),
            ("no-default", lambda fixture: edit_receipt(fixture, "test_receipt", no_default),
             "does not record no_default_features=true"),
            ("profile", lambda fixture: edit_receipt(fixture, "test_receipt", profile),
             "top-level profile is not test"),
            ("artifact-profile",
             lambda fixture: edit_receipt(fixture, "test_receipt", artifact_profile),
             "profile.test must be exactly true"),
            ("toolchain", lambda fixture: edit_receipt(fixture, "test_receipt", toolchain),
             "does not match the trusted CI pin"),
            ("toolchain-record", record_release, "trusted rustc release is not 1.99.1"),
            ("jobs-mismatch", lambda fixture: edit_receipt(fixture, "test_receipt", jobs_mismatch),
             "--jobs budget does not match"),
            ("jobs-zero", lambda fixture: edit_receipt(fixture, "test_receipt", jobs_zero),
             "non-positive or non-decimal --jobs budget"),
            ("source", source_file, "differs from the current source root"),
            ("support", support_file, "bound input inventory differs from the current source root"),
        )
        for name, mutate, marker in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = make_batch_fixture(temporary, "v2", self.batch_constants)
                mutate(fixture)
                self.assert_batch_fails(fixture, marker)

    def test_batch_validator_rejects_v1_source_and_integration_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_batch_fixture(
                temporary, "v1", self.batch_constants, fresh=(False, False), jobs=None)
            (fixture["root"] / "src/lib.rs").write_text("pub fn changed() -> u8 { 2 }\n")
            self.assert_batch_fails(fixture, "differs from the current source root")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_batch_fixture(
                temporary, "v1", self.batch_constants, fresh=(False, False), jobs=None)
            (fixture["root"] / "tests/blob_git_gateway.rs").write_text(
                "#[test]\nfn changed() {}\n")
            self.assert_batch_fails(fixture, "test receipt source SHA does not match")

    def test_copy_check_rejects_receipt_bytes_changed_after_anchor(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_batch_fixture(temporary, "v2", self.batch_constants)
            self.assert_batch_passes(fixture)
            directory = self.copy_raw_receipts(fixture)
            process = self.run_copy_check(fixture)
            self.assertEqual(process.returncode, 0, process.stderr[-2000:])
            checked = json.loads((directory / "receipt-copy-check.json").read_text())
            self.assertEqual(checked["checked"]["test_receipt"]["sha256"],
                             digest(fixture["test_receipt"]))
            self.assertEqual(checked["checked"]["serving_receipt"]["sha256"],
                             digest(fixture["serving_receipt"]))

            with (directory / "blob-git-gateway.build.json").open("ab") as stream:
                stream.write(b"\n")
            process = self.run_copy_check(fixture)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("bytes changed after verification", process.stderr)

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
