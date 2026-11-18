"""Static and focused guards for the refstore inline receipt validators.

The workflow runs its validators in shell heredocs, so these checks keep the
version-dispatched parser wired in, preserve the old v1 freshness/rebuilt
requirements, ensure no validator starts a Cargo, rustc or builder probe, and
exercise the idempotent #174 raw-receipt collector twice.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
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


def workflow_run_block(text, step_name):
    """Extract one workflow step's literal ``run: |`` script."""
    marker = '- name: "' + step_name + '"'
    start = text.index(marker)
    run_marker = "        run: |\n"
    body_start = text.index(run_marker, start) + len(run_marker)
    script = []
    for line in text[body_start:].splitlines():
        if line.startswith("      - "):
            break
        if line.startswith(" " * 10):
            script.append(line[10:])
        elif not line.strip():
            script.append("")
        else:
            break
    return "\n".join(script) + "\n"


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
        "schema": "rootyard/ci-cargo-fork/v1",
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


def legacy_support_digest(root):
    """The historical v1 lib-test support closure, recomputed from metadata."""
    files = {}
    for directory in receipts.TEST_SUPPORT_DIRS:
        base = Path(root) / directory
        if base.is_dir():
            for item in base.rglob("*"):
                if item.is_file():
                    files[item.relative_to(root).as_posix()] = digest(item)
    folded = hashlib.sha256()
    for relative in sorted(files):
        folded.update(relative.encode("utf-8") + b"\0")
        folded.update(bytes.fromhex(files[relative]))
    return folded.hexdigest(), files


def support_digest_from_inventory(entries):
    folded = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: item.get("path", "")):
        if entry.get("present") is True and entry.get("role") == "test_support":
            folded.update(entry["path"].encode("utf-8") + b"\0")
            folded.update(bytes.fromhex(entry["sha256"]))
    return folded.hexdigest()


def make_preflight_fixture(root, block, schema="v2", jobs=None,
                           fresh=(True, True, False), features=None):
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
        ("rust-toolchain.toml", '[toolchain]\nchannel = "1.99.1"\n'),
        ("src/lib.rs", "pub fn production() -> u8 { 1 }\n"),
        ("src/main.rs", "fn main() {}\n"),
        ("tests/blob_gateway_support/helper.rs", "pub fn helper() {}\n"),
        ("tests/fixtures/asset.bin", "asset-bytes\n"),
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
    cli.chmod(0o555)
    lib = evidence / "session174-lib-tests"
    lib.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"names = {names!r}\n"
        "if sys.argv[1:] == ['--list', '--ignored']:\n"
        "    for name in names:\n"
        "        print(name + ': test')\n"
    )
    lib.chmod(0o555)
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

    cargo_commit = "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b"
    rust_commit = "d" * 40
    toolchain = {
        "cargo": identity("cargo", "1.101.0", cargo_commit),
        "rustc": dict(identity("rustc", "1.99.1", rust_commit),
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
    results = root / "test-results/refstore"
    results.mkdir(parents=True)
    record = {
        "schema": "rootyard/ci-cargo-fork/v1",
        "revision": cargo_commit,
        "release": "1.101.0",
        "full_version": toolchain["cargo"]["version"],
        "commit_hash": cargo_commit,
        "host": "x86_64-unknown-linux-gnu",
        "binary_sha256": toolchain["cargo"]["executable_sha256"],
        "rustc": {
            "full_version": toolchain["rustc"]["version"],
            "release": "1.99.1",
            "commit_hash": rust_commit,
            "host": "x86_64-unknown-linux-gnu",
        },
    }
    record_path = results / "cargo-fork.json"
    record_path.write_text(json.dumps(record))

    bound = receipts.capture_bound_inputs(root, environ={"PATH": ""})
    v2_support = support_digest_from_inventory(bound["bound_input_inventory"])
    v1_support, _support_files = legacy_support_digest(root)
    assert v2_support == v1_support, "fixture support closures disagree"
    source = receipts.source_digest(root)
    rustc = "rustc 1.99.1 (fake)"
    dev_profile = {"opt_level": "0", "debuginfo": 0, "debug_assertions": True,
                   "overflow_checks": True, "test": False}
    test_profile = {"opt_level": "0", "debuginfo": 0, "debug_assertions": True,
                    "overflow_checks": True, "test": True}

    original_lib = root / "target/debug/deps/libtest-original"
    original_lib.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(lib, original_lib)
    original_lib.chmod(0o700)

    commands = (list(expected_lib), list(expected_cli))
    if schema == "v1":
        assert jobs is None, "the legacy exact-command anchor has no --jobs fragment"
    elif jobs is not None:
        commands = (
            commands[0] + ["--jobs", str(jobs)],
            commands[1] + ["--jobs", str(jobs)],
        )

    if schema == "v1":
        test_receipt = {
            "kind": "rust-library-test",
            "relocated_artifact": True,
            "original_artifact_sha256": digest(original_lib),
            "workspace_commit": head,
            "fresh": False,
            "source_inputs_sha256": source,
            "binary_sha256": digest(lib),
            "lib_test_support_inputs_sha256": v1_support,
            "cargo_lock_sha256": digest(root / "Cargo.lock"),
            "command": commands[0],
            "rustc": rustc,
            "package_rebuilt": True,
            "fresh_false_artifacts": [
                {"target": "rootyard", "kind": "lib-test", "fresh": False,
                 "profile": test_profile, "executable": str(original_lib)},
            ],
        }
        cli_receipt = {
            "version": 1,
            "binary_sha256": digest(cli),
            "source_inputs_sha256": source,
            "workspace_commit": head,
            "rustc": rustc,
            "command": commands[1],
            "package_rebuilt": True,
            "target_dir": str(root / "target"),
            "lock_file": str(root / "Cargo.lock"),
            "fresh_false_artifacts": [
                {"target": "rootyard", "kind": "lib", "fresh": False},
                {"target": "rootyard", "kind": "bin", "fresh": False,
                 "executable": str(target_cli)},
            ],
        }
        receipts.atomic_write_json(lib.with_suffix(".build.json"), test_receipt)
        receipts.atomic_write_json(cli.with_suffix(".build.json"), cli_receipt)
    else:
        if features is None:
            features = {"enabled": [], "no_default_features": True}
        lib_artifact = receipts.cargo_artifact_record(
            {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {"name": "rootyard", "kind": ["lib"],
                           "src_path": str(root / "src/lib.rs")},
                "profile": test_profile,
                "fresh": fresh[0],
                "executable": str(original_lib),
            },
            root,
        )
        test_receipt = receipts.make_receipt_v2(
            binary_path=lib,
            command=commands[0],
            profile="test",
            artifacts=[lib_artifact],
            toolchain=toolchain,
            bound_inputs=bound,
            workspace_commit=head,
            target_dir=root / "target",
            target_triple="x86_64-unknown-linux-gnu",
            features=features,
            extra={
                "kind": "rust-library-test",
                "relocated_artifact": True,
                "original_artifact_sha256": digest(original_lib),
                "lib_test_support_inputs_sha256": v2_support,
                "build_options": {"jobs": jobs},
            },
        )
        cli_lib = receipts.cargo_artifact_record(
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
        cli_bin = receipts.cargo_artifact_record(
            {
                "reason": "compiler-artifact",
                "package_id": "rootyard 0.1.0",
                "target": {"name": "rootyard", "kind": ["bin"],
                           "src_path": str(root / "src/main.rs")},
                "profile": dev_profile,
                "fresh": fresh[2],
                "executable": str(target_cli),
            },
            root,
        )
        cli_receipt = receipts.make_receipt_v2(
            binary_path=cli,
            command=commands[1],
            profile="dev",
            artifacts=[cli_lib, cli_bin],
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
        receipts.atomic_write_json(lib.with_suffix(".build.json"), test_receipt)
        receipts.atomic_write_json(cli.with_suffix(".build.json"), cli_receipt)
    # The producers publish adjacent receipts as readonly managed-CAS aliases.
    # The CLI --output is this fixture's evidence/rootyard-cli, so the consumed
    # receipt path and the evidence alias are deliberately the same path.
    lib_receipt = lib.with_suffix(".build.json")
    cli_receipt_path = cli.with_suffix(".build.json")
    for published in (lib_receipt, cli_receipt_path):
        published.chmod(0o444)
    return {
        "root": root,
        "evidence": evidence,
        "lib": lib,
        "cli": cli,
        "lib_receipt": lib_receipt,
        "cli_receipt": cli_receipt_path,
        "fake_bin": evidence / "fake-bin",
        "head": head,
        "record": record_path,
        "schema": schema,
        "support": v2_support if schema == "v2" else v1_support,
        "source": source,
        "target_cli": target_cli,
        "original_lib": original_lib,
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
        cls.receipt_copy_check = next(
            block for block in blocks
            if "session174 receipt copy check failed" in block
        )
        cls.batch_constants = validator_constants(cls.batch_validator)

    def run_batch_validator(self, fixture, block=None):
        return subprocess.run(
            [sys.executable, "-",
             fixture["test_receipt"], fixture["serving_receipt"],
             fixture["test_binary"], fixture["serving_binary"],
             fixture["test_source"]],
            cwd=fixture["root"],
            input=self.batch_validator if block is None else block,
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

    def run_preflight_validator(self, fixture, environment=None, block=None):
        environment = dict(os.environ if environment is None else environment)
        environment.update({
            "GITHUB_WORKSPACE": str(fixture["root"]),
            "DATABASE_URL": "postgresql://fixture.invalid/rootyard",
            "PATH": str(fixture["fake_bin"]) + os.pathsep + environment.get("PATH", ""),
        })
        return subprocess.run(
            [sys.executable, "-", str(fixture["lib"]), str(fixture["cli"])],
            cwd=fixture["root"],
            env=environment,
            input=self.preflight_validator if block is None else block,
            text=True,
            capture_output=True,
        )

    def run_receipt_copy_check(self, source, target):
        return subprocess.run(
            [sys.executable, "-", str(source), str(target)],
            input=self.receipt_copy_check,
            text=True,
            capture_output=True,
        )

    def run_evidence_receipt_collector(self, preflight, source, destination,
                                       optional=False):
        arguments = [sys.executable, str(SCRIPTS / "collect_evidence_receipts.py")]
        if optional:
            arguments.append("--optional")
        arguments.extend([str(preflight), str(source), str(destination)])
        return subprocess.run(arguments, text=True, capture_output=True)

    def make_collector_fixture(self, root):
        source = Path(root) / "evidence"
        destination = Path(root) / "upload"
        source.mkdir()
        destination.mkdir()
        lib_bytes = b'{"receipt": "lib", "raw": true}\n'
        cli_bytes = b'{"receipt": "cli", "raw": true}\n'
        for name, raw in (
            ("session174-lib-tests.build.json", lib_bytes),
            ("rootyard-cli.build.json", cli_bytes),
        ):
            (source / name).write_bytes(raw)
            (source / name).chmod(0o444)
        preflight = {
            "lib_receipt": {
                "path": str(source / "session174-lib-tests.build.json"),
                "sha256": hashlib.sha256(lib_bytes).hexdigest(),
            },
            "cli_receipt": {
                "path": str(source / "rootyard-cli.build.json"),
                "sha256": hashlib.sha256(cli_bytes).hexdigest(),
            },
        }
        preflight_path = source / "preflight.json"
        preflight_path.write_text(json.dumps(preflight))
        return source, destination, preflight_path, lib_bytes, cli_bytes

    def receipt_anchor(self, path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def assert_stat_unchanged(self, before, after, label):
        for field in ("st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
            self.assertEqual(getattr(after, field), getattr(before, field),
                             label + " changed " + field)

    def write_preflight_receipt(self, fixture, key, payload):
        binary = fixture["lib"] if key == "lib" else fixture["cli"]
        path = binary.with_suffix(".build.json")
        path.chmod(0o644)
        path.write_text(json.dumps(payload))
        path.chmod(0o444)

    def edit_preflight_receipt(self, fixture, key, mutate):
        binary = fixture["lib"] if key == "lib" else fixture["cli"]
        path = binary.with_suffix(".build.json")
        payload = json.loads(path.read_text())
        mutate(payload)
        self.write_preflight_receipt(fixture, key, payload)

    def relocate_consumed_cli(self, fixture):
        """Move the consumed CLI away from the evidence alias destination.

        The real producer may publish the evidence alias at the same path it
        consumes.  Tests of the absent/corrupt/symlink destination branches
        need a valid consumed receipt that is not that destination.
        """
        directory = fixture["root"] / "consumed-cli"
        directory.mkdir()
        binary = directory / "rootyard-cli"
        shutil.copyfile(fixture["cli"], binary)
        binary.chmod(0o555)
        receipt = binary.with_suffix(".build.json")
        shutil.copyfile(fixture["cli_receipt"], receipt)
        receipt.chmod(0o444)
        relocated = dict(fixture)
        relocated["cli"] = binary
        relocated["cli_receipt"] = receipt
        return relocated

    def guarded_preflight_block(self, destination):
        """Prepend runtime guards that forbid every write to one path."""
        target = os.path.abspath(destination)
        guard = f"""
import builtins as _guard_builtins
import os as _guard_os
import pathlib as _guard_pathlib

_guard_target = {target!r}


def _guard_matches(path):
    try:
        return _guard_os.path.abspath(_guard_os.fspath(path)) == _guard_target
    except TypeError:
        return False


def _guard_forbid(operation):
    raise AssertionError('provenance write forbidden: ' + operation)


def _guard_wrap_path_write(name):
    original = getattr(_guard_pathlib.Path, name)

    def guarded(self, *args, **kwargs):
        if _guard_matches(self):
            _guard_forbid('Path.' + name)
        return original(self, *args, **kwargs)

    setattr(_guard_pathlib.Path, name, guarded)


for _guard_name in ('write_bytes', 'write_text', 'touch', 'chmod', 'unlink',
                    'rename', 'replace'):
    _guard_wrap_path_write(_guard_name)

_guard_path_open = _guard_pathlib.Path.open


def _guard_guarded_open(self, mode='r', *args, **kwargs):
    if _guard_matches(self) and any(flag in mode for flag in 'wax+'):
        _guard_forbid('Path.open(' + mode + ')')
    return _guard_path_open(self, mode, *args, **kwargs)


_guard_pathlib.Path.open = _guard_guarded_open
_guard_os_open = _guard_os.open


def _guard_guarded_os_open(path, flags, *args, **kwargs):
    write_flags = (_guard_os.O_WRONLY | _guard_os.O_RDWR | _guard_os.O_CREAT
                   | _guard_os.O_TRUNC | _guard_os.O_APPEND | _guard_os.O_EXCL)
    if _guard_matches(path) and flags & write_flags:
        _guard_forbid('os.open')
    return _guard_os_open(path, flags, *args, **kwargs)


_guard_os.open = _guard_guarded_os_open
_guard_builtin_open = _guard_builtins.open


def _guard_guarded_builtin_open(file, mode='r', *args, **kwargs):
    if _guard_matches(file) and any(flag in mode for flag in 'wax+'):
        _guard_forbid('open(' + mode + ')')
    return _guard_builtin_open(file, mode, *args, **kwargs)


_guard_builtins.open = _guard_guarded_builtin_open


def _guard_wrap_forbidden(name):
    def guarded(*args, **kwargs):
        _guard_forbid('os.' + name)

    return guarded


for _guard_name in ('chmod', 'fchmod', 'truncate'):
    setattr(_guard_os, _guard_name, _guard_wrap_forbidden(_guard_name))


def _guard_wrap_two_path(name, first, second):
    original = getattr(_guard_os, name)

    def guarded(*args, **kwargs):
        if (len(args) > 0 and _guard_matches(args[0])) or \
                (len(args) > 1 and _guard_matches(args[1])):
            _guard_forbid('os.' + name)
        return original(*args, **kwargs)

    setattr(_guard_os, name, guarded)


for _guard_name in ('rename', 'replace', 'link', 'unlink', 'remove'):
    _guard_wrap_two_path(_guard_name, 'path', 'destination')
"""
        return guard + self.preflight_validator

    def assert_preflight_passes(self, fixture):
        process = self.run_preflight_validator(fixture)
        self.assertEqual(
            process.returncode, 0,
            f"preflight failed:\n{process.stdout[-2000:]}\n{process.stderr[-2000:]}",
        )
        return json.loads((fixture["evidence"] / "preflight.json").read_text())

    def assert_preflight_fails(self, fixture, marker):
        process = self.run_preflight_validator(fixture)
        self.assertNotEqual(process.returncode, 0,
                            f"preflight unexpectedly passed:\n{process.stdout[-2000:]}")
        self.assertIn(marker, process.stderr,
                      f"preflight failed without {marker!r}:\n{process.stderr[-2000:]}")
        return process

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

    def test_non_174_builders_use_the_shared_immutable_store(self):
        start = self.source.index("Build and exercise the minimal Blob")
        end = self.source.index('"Exercise the #174 HTTP foundation cases')
        section = self.source[start:end]
        self.assertEqual(section.count(
            'artifact_store="$HOME/.cache/rootyard/native-artifacts"'), 2)
        # The native11 target loop adds the fifth immutable CAS helper: one
        # literal --artifact-store used for each of the 11 test binaries.
        self.assertEqual(section.count('--artifact-store "$artifact_store"'), 5)
        for alias in (
            '--output "$fixture_dir/ref_store_format22_backup_fixture"',
            '--output "$standalone_dir/rootyard"',
            '--output "$test_binary"',
            '--output "$serving_binary"',
        ):
            self.assertIn(alias, section)
        # Every later non-174 consumer reads an exported immutable path, never
        # the mutable Cargo target or a receipt copied from it.
        self.assertNotIn("target/debug", section)
        self.assertNotIn("cargo clean", section)
        self.assertNotIn("clears the rootyard package", self.source)
        for name in (
            "ROOTYARD_ARTIFACT_STORE",
            "ROOTYARD_FORMAT22_FIXTURE",
            "ROOTYARD_FORMAT22_FIXTURE_RECEIPT",
            "ROOTYARD_STANDALONE_BIN",
            "ROOTYARD_STANDALONE_RECEIPT",
            "ROOTYARD_LFS_BIN",
            "ROOTYARD_LFS_RECEIPT",
        ):
            self.assertIn("'" + name + "'", section)
        self.assertIn('binary="${ROOTYARD_STANDALONE_BIN:?', section)
        self.assertIn('binary="$ROOTYARD_LFS_BIN"', section)
        self.assertIn('--binary "$ROOTYARD_LFS_BIN"', section)
        self.assertIn('export CARGO_BIN_EXE_ROOTYARD="$serving_binary"', section)
        self.assertIn('cp "$ROOTYARD_LFS_RECEIPT" test-results/refstore/lfs-build-receipt.json',
                      section)
        self.assertNotIn('cp target/debug/rootyard', section)
        self.assertNotIn('cp "$GITHUB_WORKSPACE/target/debug/rootyard', section)

    def test_174_preparation_uses_the_shared_immutable_store(self):
        start = self.source.index('"Exercise the #174 HTTP foundation cases')
        end = self.source.index('"Drop only the run-owned #174 foundation database"')
        section = self.source[start:end]
        self.assertEqual(section.count(
            'artifact_store="$HOME/.cache/rootyard/native-artifacts"'), 1)
        self.assertEqual(section.count('--artifact-store "$artifact_store"'), 2)
        self.assertIn('--output "$lib"', section)
        self.assertIn('--output "$cli"', section)
        self.assertIn('unset CARGO_PROFILE_DEV_DEBUG CARGO_PROFILE_TEST_DEBUG', section)
        self.assertNotIn('cp --preserve=mode', section)
        self.assertNotIn('chmod 755 "$cli" "$lib"', section)
        self.assertNotIn('target/debug', section)
        self.assertIn("cli_receipt_path = pathlib.Path(cli).with_suffix('.build.json')",
                      section)
        self.assertNotIn("cli_receipt_path = workspace / 'target'", section)
        self.assertIn("lib = readonly_alias(lib, 'lib alias')", section)
        self.assertIn("cli = readonly_alias(cli, 'CLI alias')", section)
        for name in (
            "ROOTYARD_174_LIB_ALIAS",
            "ROOTYARD_174_LIB_ALIAS_RECEIPT",
            "ROOTYARD_174_LIB_BIN",
            "ROOTYARD_174_LIB_RECEIPT",
            "ROOTYARD_174_CLI_ALIAS",
            "ROOTYARD_174_CLI_ALIAS_RECEIPT",
            "ROOTYARD_174_CLI_BIN",
            "ROOTYARD_174_CLI_RECEIPT",
        ):
            self.assertIn("'" + name + "'", section)
        self.assertIn("'lib_artifact_store': store_evidence(test_receipt)", section)
        self.assertIn("'cli_artifact_store': store_evidence(cli_receipt)", section)
        # The strong #126 raw-bytes TOCTOU guard stays read-before-validate.
        batch_read = self.batch_validator.index(
            'test_receipt_bytes = pathlib.Path(test_receipt_path).read_bytes()')
        batch_bound = self.batch_validator.index(
            'test_validated.receipt_sha256 == sha256_bytes(test_receipt_bytes)')
        self.assertLess(batch_read, batch_bound)
        self.assertNotIn('json.loads(pathlib.Path(test_receipt_path)',
                         self.batch_validator)
        self.assertNotIn('json.loads(pathlib.Path(serving_receipt_path)',
                         self.batch_validator)

    def test_validators_parse_and_use_the_shared_reader(self):
        self.assertEqual(len(self.validators), 2)
        for block in self.validators:
            ast.parse(block)
            self.assertIn("import native_build_receipt as receipts", block)
            self.assertIn("receipts.load_receipt(", block)
            self.assertNotIn("probe_toolchain", block)
            self.assertNotIn("capture_bound_inputs", block)
            self.assertNotIn("cargo_artifact_record", block)
        self.assertNotIn("json.loads(pathlib.Path(test_receipt_path)", self.batch_validator)
        self.assertNotIn("json.loads(pathlib.Path(serving_receipt_path)", self.batch_validator)
        self.assertIn("test_receipt_bytes = pathlib.Path(test_receipt_path).read_bytes()",
                      self.batch_validator)
        self.assertIn("serving_receipt_bytes = pathlib.Path(serving_receipt_path).read_bytes()",
                      self.batch_validator)
        self.assertIn("sha256_bytes(test_receipt_bytes)", self.batch_validator)
        self.assertIn("sha256_bytes(serving_receipt_bytes)", self.batch_validator)
        self.assertIn("test_receipt = test_validated.payload", self.batch_validator)
        self.assertIn("serving_receipt = serving_validated.payload", self.batch_validator)
        read_at = self.batch_validator.index(
            "test_receipt_bytes = pathlib.Path(test_receipt_path).read_bytes()")
        bound_at = self.batch_validator.index(
            "test_validated.receipt_sha256 == sha256_bytes(test_receipt_bytes)")
        payload_at = self.batch_validator.index(
            "test_receipt = test_validated.payload")
        self.assertLess(read_at, bound_at)
        self.assertLess(bound_at, payload_at)
        self.assertIn("source_root=workspace", self.batch_validator)
        self.assertIn("verify_source_files=True", self.batch_validator)
        self.assertIn("source_root=workspace", self.preflight_validator)
        self.assertIn("verify_source_files=True", self.preflight_validator)
        self.assertNotIn("verify_source_files=False", self.preflight_validator)

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
        # v2 rows carry the intended source path and hash; v1 rows do not.
        self.assertIn("require_v2_artifact_sources", block)
        self.assertIn("('rootyard', 'lib', 'src/lib.rs')", block)
        self.assertIn("('rootyard', 'bin', 'src/main.rs')", block)

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
        self.assertIn("EXPECTED_FEATURES", block)
        self.assertIn("test_artifact.get('kind') != 'lib-test'", block)
        self.assertIn("cli_receipt.get('target_dir')", block)
        self.assertIn("require_v2_artifact_sources", block)
        self.assertIn("('rootyard', 'lib-test', 'src/lib.rs')", block)
        self.assertIn("('rootyard', 'bin', 'src/main.rs')", block)
        self.assertIn("pathlib.Path(executable).resolve()", block)
        # v2 feature/profile/toolchain anchors and the independent setup record.
        self.assertIn("features.get('enabled') != EXPECTED_FEATURES['enabled']", block)
        self.assertIn("no_default_features", block)
        self.assertIn("test_receipt.get('profile') != 'test'", block)
        self.assertIn("cli_receipt.get('profile') != 'dev'", block)
        self.assertIn("require_v2_toolchain", block)
        self.assertIn("test-results/refstore/cargo-fork.json", block)
        self.assertIn("bind different ' + tool + ' identities", block)
        # v1 support is recomputed from the closed legacy closure, never echoed.
        self.assertIn("legacy_support_digest", block)
        self.assertIn("recorded_support != current_support", block)
        self.assertIn("bound_input_inventory", block)
        self.assertNotIn("test_receipt.get('test_source_closure')", block)
        # Exact raw receipt bytes are anchored.  The CLI evidence alias is
        # reused only when already byte-identical; an absent copy is created
        # exclusively and no destination is ever re-serialized or overwritten.
        self.assertIn("sha_bytes(test_receipt_bytes)", block)
        self.assertIn("sha_bytes(cli_receipt_bytes)", block)
        self.assertIn("def save_consumed_cli_receipt(", block)
        self.assertIn("def _existing_cli_receipt_copy_matches(", block)
        self.assertIn("os.O_EXCL", block)
        self.assertIn("O_NOFOLLOW", block)
        self.assertIn("stat.S_ISLNK(info.st_mode)", block)
        self.assertIn("stat.S_ISREG(info.st_mode)", block)
        self.assertIn("existing != raw", block)
        self.assertIn("sha_bytes(existing) != expected_sha", block)
        self.assertIn("stream.write(raw)", block)
        self.assertNotIn("write_bytes(cli_receipt_bytes)", block)
        self.assertNotIn("json.dumps(cli_receipt", block)
        self.assertLess(
            block.index("def _existing_cli_receipt_copy_matches("),
            block.index("def save_consumed_cli_receipt("))
        save_at = block.index("def save_consumed_cli_receipt(")
        check_at = block.index(
            "_existing_cli_receipt_copy_matches(destination, raw, expected_sha)", save_at)
        create_at = block.index("os.open(destination, flags, 0o444)")
        self.assertLess(save_at, check_at)
        self.assertLess(check_at, create_at)
        self.assertIn("'lib_receipt'", block)
        self.assertIn("'cli_receipt'", block)
        self.assertIn("'sha256': test_validated.receipt_sha256", block)
        # The old freshness/rebuilt demands are inside the v1 branch.
        v1_branch = block.index("if test_validated.schema == 'v1':")
        self.assertGreater(block.index("test_receipt.get('fresh') is not False"), v1_branch)
        self.assertGreater(block.index("test_receipt.get('package_rebuilt') is not True"), v1_branch)
        # The immutable copies are hashed; the mutable original need not exist.
        self.assertIn("original_artifact_sha256", block)
        self.assertNotIn("original_artifact_sha256.is_file", block)

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

    def test_batch_validator_rejects_receipt_swap_between_read_and_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_batch_fixture(temporary, "v2", self.batch_constants)
            approved = json.loads(fixture["test_receipt"].read_text())
            swapped = dict(approved, kind="native-binary")
            swapped_path = fixture["root"] / "swapped-test.build.json"
            swapped_path.write_text(json.dumps(swapped))
            self.assertNotEqual(digest(swapped_path), digest(fixture["test_receipt"]))
            head = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=fixture["root"], text=True).strip()
            # The replacement is shape-valid and source-consistent, so the
            # shared reader accepts it.  Only the raw-byte/SHA binding can stop
            # its receipt hash from being paired with the first receipt's
            # already-approved payload.
            parsed = receipts.load_receipt(
                swapped_path, source_root=fixture["root"],
                binary_path=fixture["test_binary"], expected_commit=head,
                verify_source_files=True)
            self.assertEqual(parsed.payload["kind"], "native-binary")
            trigger = "test_receipt_bytes = pathlib.Path(test_receipt_path).read_bytes()"
            self.assertEqual(self.batch_validator.count(trigger), 1)
            line = next(
                line for line in self.batch_validator.splitlines() if trigger in line)
            indent = line[:len(line) - len(line.lstrip())]
            raced = self.batch_validator.replace(
                line,
                line + "\n" + indent + "pathlib.Path(" + repr(str(swapped_path))
                + ").replace(test_receipt_path)", 1)
            process = self.run_batch_validator(fixture, block=raced)
            self.assertNotEqual(
                process.returncode, 0,
                "validator accepted a swapped receipt:\n" + process.stdout[-2000:])
            self.assertIn("test receipt bytes changed between consumption and validation",
                          process.stderr, process.stderr[-2000:])
            self.assertFalse(
                (fixture["root"]
                 / "test-results/refstore/blob_git_gateway/build-pair.json").exists(),
                "swapped receipt still emitted a build-pair manifest")

    def test_batch_validator_rejects_self_consistent_wrong_v2_artifact_sources(self):
        cases = (
            ("test", "test_receipt", "test", "tests/blob_gateway_support/helper.rs",
             "test receipt test artifact source is not tests/blob_git_gateway.rs"),
            ("serving-lib", "serving_receipt", "lib", "src/main.rs",
             "product receipt lib artifact source is not src/lib.rs"),
            ("serving-bin", "serving_receipt", "bin", "src/lib.rs",
             "product receipt bin artifact source is not src/main.rs"),
        )
        for name, key, kind, source, marker in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = make_batch_fixture(temporary, "v2", self.batch_constants)
                path = fixture[key]
                payload = json.loads(path.read_text())
                row = next(item for item in payload["cargo_artifacts"]
                           if item["kind"] == kind)
                # Both paths exist in the repo and are present in the bound
                # inventory, so this rewrite is hash- and inventory-consistent.
                row["source"] = source
                row["source_sha256"] = digest(fixture["root"] / source)
                path.write_text(json.dumps(payload))
                head = subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=fixture["root"], text=True).strip()
                binary = (fixture["test_binary"] if key == "test_receipt"
                          else fixture["serving_binary"])
                parsed = receipts.load_receipt(
                    path, source_root=fixture["root"], binary_path=binary,
                    expected_commit=head, verify_source_files=True)
                self.assertEqual(parsed.schema, "v2")
                self.assert_batch_fails(fixture, marker)

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

    def installer_cargo_fork_schema(self):
        installer = (SCRIPTS / "install_ci_cargo_fork.sh").read_text(encoding="utf-8")
        match = re.search(r"^readonly SCHEMA=(\S+)$", installer, re.MULTILINE)
        self.assertIsNotNone(match, "installer no longer declares a SCHEMA")
        return match.group(1)

    def edit_toolchain_record(self, fixture, mutate):
        record = json.loads(fixture["record"].read_text())
        mutate(record)
        fixture["record"].write_text(json.dumps(record))

    def test_loaders_accept_the_actual_installer_toolchain_schema(self):
        schema = self.installer_cargo_fork_schema()
        self.assertEqual(schema, "rootyard/ci-cargo-fork/v1")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_batch_fixture(temporary, "v2", self.batch_constants)
            record = json.loads(fixture["record"].read_text())
            self.assertEqual(record["schema"], schema)
            manifest = self.assert_batch_passes(fixture)
            # The trusted rustc version still comes from rustc.full_version;
            # this is the mapping a retracted review rumor called a KeyError.
            self.assertEqual(manifest["toolchain"]["rustc"]["version"],
                             record["rustc"]["full_version"])
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(temporary, self.preflight_validator)
            record = json.loads(fixture["record"].read_text())
            self.assertEqual(record["schema"], schema)
            preflight = self.assert_preflight_passes(fixture)
            self.assertEqual(preflight["toolchain"]["rustc"]["version"],
                             record["rustc"]["full_version"])

    def test_loaders_reject_missing_or_foreign_toolchain_schema(self):
        schema = self.installer_cargo_fork_schema()
        marker = "trusted toolchain record schema is not " + schema
        cases = (
            ("missing", lambda record: record.pop("schema")),
            ("invented", lambda record: record.update(schema="rootyard/cargo-fork/v1")),
            ("foreign-version",
             lambda record: record.update(schema="rootyard/ci-cargo-fork/v2")),
        )
        for name, mutate in cases:
            with self.subTest(validator="batch", case=name), \
                    tempfile.TemporaryDirectory() as temporary:
                fixture = make_batch_fixture(temporary, "v2", self.batch_constants)
                self.edit_toolchain_record(fixture, mutate)
                self.assert_batch_fails(fixture, marker)
            with self.subTest(validator="preflight", case=name), \
                    tempfile.TemporaryDirectory() as temporary:
                fixture = make_preflight_fixture(temporary, self.preflight_validator)
                self.edit_toolchain_record(fixture, mutate)
                self.assert_preflight_fails(fixture, marker)

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

    def test_preflight_validator_accepts_v2_receipts_and_exact_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(temporary, self.preflight_validator)
            preflight = self.assert_preflight_passes(fixture)
            self.assertEqual(preflight["receipt_schema"], "v2")
            self.assertEqual(preflight["head"], fixture["head"])
            self.assertEqual(preflight["rustc"], "rustc 1.99.1 (fake)")
            self.assertEqual(preflight["lib_test_support_inputs_sha256"], fixture["support"])
            self.assertEqual(preflight["v2_features"],
                             {"enabled": [], "no_default_features": True})
            self.assertEqual(preflight["v2_profiles"], {"lib": "test", "cli": "dev"})
            self.assertEqual(preflight["lib_artifact_profile"]["test"], True)
            self.assertEqual(preflight["lib_artifact_profile"]["debuginfo"], 0)
            self.assertTrue(all(row["test"] is False and row["debuginfo"] == 0
                                for row in preflight["cli_artifact_profiles"]))
            self.assertEqual(preflight["toolchain"]["cargo"]["release"], "1.101.0")
            self.assertEqual(preflight["toolchain"]["cargo"]["commit_hash"],
                             "64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b")
            self.assertEqual(preflight["toolchain"]["rustc"]["release"], "1.99.1")
            lib_receipt = fixture["lib"].with_suffix(".build.json")
            cli_receipt = fixture["cli"].with_suffix(".build.json")
            self.assertEqual(preflight["lib_receipt"]["path"], str(lib_receipt.resolve()))
            self.assertEqual(preflight["lib_receipt"]["sha256"], digest(lib_receipt))
            self.assertEqual(preflight["cli_receipt"]["path"], str(cli_receipt.resolve()))
            self.assertEqual(preflight["cli_receipt"]["sha256"], digest(cli_receipt))
            self.assertEqual(preflight["lib_receipt"]["evidence_path"], str(lib_receipt.resolve()))
            cli_copy = fixture["evidence"] / "rootyard-cli.build.json"
            self.assertEqual(cli_copy.read_bytes(), cli_receipt.read_bytes())
            self.assertEqual(digest(cli_copy), digest(cli_receipt))

    def test_preflight_reuses_readonly_cli_receipt_alias_without_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(temporary, self.preflight_validator)
            destination = fixture["evidence"] / "rootyard-cli.build.json"
            self.assertEqual(destination, fixture["cli_receipt"])
            self.assertFalse(destination.is_symlink())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o444)
            before = os.lstat(destination)
            before_bytes = destination.read_bytes()
            block = self.guarded_preflight_block(destination)
            process = self.run_preflight_validator(fixture, block=block)
            self.assertEqual(
                process.returncode, 0,
                f"guarded preflight failed:\n{process.stdout[-2000:]}\n{process.stderr[-2000:]}",
            )
            after = os.lstat(destination)
            for field in ("st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
                self.assertEqual(getattr(after, field), getattr(before, field),
                                 "readonly CLI receipt alias changed " + field)
            self.assertEqual(destination.read_bytes(), before_bytes)
            preflight = json.loads((fixture["evidence"] / "preflight.json").read_text())
            self.assertEqual(preflight["cli_receipt"]["sha256"],
                             hashlib.sha256(before_bytes).hexdigest())

    def test_preflight_creates_absent_cli_receipt_copy_exclusively(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.relocate_consumed_cli(
                make_preflight_fixture(temporary, self.preflight_validator))
            destination = fixture["evidence"] / "rootyard-cli.build.json"
            self.assertNotEqual(destination, fixture["cli_receipt"])
            destination.unlink()
            source_before = os.lstat(fixture["cli_receipt"])
            source_bytes = fixture["cli_receipt"].read_bytes()
            preflight = self.assert_preflight_passes(fixture)
            self.assertTrue(destination.is_file())
            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_bytes(), source_bytes)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o444)
            self.assertEqual(preflight["cli_receipt"]["sha256"],
                             hashlib.sha256(source_bytes).hexdigest())
            source_after = os.lstat(fixture["cli_receipt"])
            for field in ("st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
                self.assertEqual(getattr(source_after, field), getattr(source_before, field),
                                 "consumed CLI receipt changed " + field)
            self.assertEqual(fixture["cli_receipt"].read_bytes(), source_bytes)

    def test_preflight_rejects_different_cli_receipt_destination_without_rewriting(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.relocate_consumed_cli(
                make_preflight_fixture(temporary, self.preflight_validator))
            destination = fixture["evidence"] / "rootyard-cli.build.json"
            destination.unlink()
            destination.write_bytes(b'{"receipt": "different"}\n')
            destination.chmod(0o640)
            before = os.lstat(destination)
            before_bytes = destination.read_bytes()
            self.assert_preflight_fails(
                fixture, "CLI receipt evidence destination does not match the consumed bytes")
            after = os.lstat(destination)
            for field in ("st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
                self.assertEqual(getattr(after, field), getattr(before, field),
                                 "conflicting CLI receipt destination changed " + field)
            self.assertEqual(destination.read_bytes(), before_bytes)

    def test_preflight_rejects_symlink_cli_receipt_destination_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.relocate_consumed_cli(
                make_preflight_fixture(temporary, self.preflight_validator))
            destination = fixture["evidence"] / "rootyard-cli.build.json"
            destination.unlink()
            alias_source = fixture["root"] / "same-byte-receipt.json"
            alias_source.write_bytes(fixture["cli_receipt"].read_bytes())
            alias_source.chmod(0o444)
            before_target = os.lstat(alias_source)
            before_bytes = alias_source.read_bytes()
            destination.symlink_to(alias_source)
            self.assert_preflight_fails(
                fixture, "CLI receipt evidence destination must not be a symlink")
            self.assertTrue(destination.is_symlink())
            self.assertEqual(os.readlink(destination), str(alias_source))
            after_target = os.lstat(alias_source)
            for field in ("st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
                self.assertEqual(getattr(after_target, field), getattr(before_target, field),
                                 "symlink target changed " + field)
            self.assertEqual(alias_source.read_bytes(), before_bytes)

            destination.unlink()
            destination.symlink_to(fixture["root"] / "missing-receipt.json")
            self.assert_preflight_fails(
                fixture, "CLI receipt evidence destination must not be a symlink")
            self.assertTrue(destination.is_symlink())
            self.assertFalse(destination.exists())

    def test_preflight_propagates_cas_store_to_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(temporary, self.preflight_validator)
            injected = {}
            for key, binary in (("lib", fixture["lib"]), ("cli", fixture["cli"])):
                path = binary.with_suffix(".build.json")
                payload = json.loads(path.read_text())
                record = {
                    'schema': 'rootyard/native-artifact-store/v1',
                    'root': '/fixture/store',
                    'binary': '/fixture/store/' + key,
                    'receipt': '/fixture/store/' + key + '.receipt.json',
                    'build_receipt': '/fixture/store/' + key + '.build.json',
                    'binary_sha256': payload['binary_sha256'],
                    'output_alias': {'path': str(binary)},
                }
                payload['artifact_store'] = record
                self.write_preflight_receipt(fixture, key, payload)
                injected[key] = record
            preflight = self.assert_preflight_passes(fixture)
            for key in ('lib', 'cli'):
                evidence = preflight[key + '_artifact_store']
                self.assertEqual(evidence['schema'], injected[key]['schema'])
                self.assertEqual(evidence['root'], injected[key]['root'])
                self.assertEqual(evidence['binary'], injected[key]['binary'])
                self.assertEqual(evidence['receipt'], injected[key]['receipt'])
                self.assertEqual(evidence['build_receipt'], injected[key]['build_receipt'])
                self.assertEqual(evidence['binary_sha256'], injected[key]['binary_sha256'])
            self.assertEqual(preflight['lib_alias'], str(fixture['lib'].resolve()))
            self.assertEqual(preflight['cli_alias'], str(fixture['cli'].resolve()))

    def test_preflight_rejects_writable_frozen_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(temporary, self.preflight_validator)
            fixture['lib'].chmod(0o755)
            self.assert_preflight_fails(fixture, 'lib alias must be readonly')

    def test_preflight_validator_rejects_self_consistent_wrong_v2_artifact_sources(self):
        cases = (
            ("lib", "lib", "lib-test", "src/main.rs",
             "lib receipt lib-test artifact source is not src/lib.rs"),
            ("cli-lib", "cli", "lib", "src/main.rs",
             "CLI receipt lib artifact source is not src/lib.rs"),
            ("cli-bin", "cli", "bin", "src/lib.rs",
             "CLI receipt bin artifact source is not src/main.rs"),
        )
        for name, key, kind, source, marker in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = make_preflight_fixture(temporary, self.preflight_validator)
                binary = fixture["lib"] if key == "lib" else fixture["cli"]
                receipt_binary = fixture["lib"] if key == "lib" else fixture["cli"]
                path = receipt_binary.with_suffix(".build.json")
                payload = json.loads(path.read_text())
                row = next(item for item in payload["cargo_artifacts"]
                           if item["kind"] == kind)
                # A real alternate source with its own matching hash keeps the
                # shared reader happy; only the caller's logical-path anchor
                # can reject it.
                row["source"] = source
                row["source_sha256"] = digest(fixture["root"] / source)
                self.write_preflight_receipt(fixture, key, payload)
                parsed = receipts.load_receipt(
                    path, source_root=fixture["root"], binary_path=binary,
                    expected_commit=fixture["head"], verify_source_files=True)
                self.assertEqual(parsed.schema, "v2")
                self.assert_preflight_fails(fixture, marker)

    def test_preflight_validator_accepts_positive_v2_cache_hits(self):
        cases = (
            ((True, True, True), None),
            ((False, False, False), None),
            ((True, False, True), 2),
        )
        for fresh, jobs in cases:
            with self.subTest(fresh=fresh, jobs=jobs), tempfile.TemporaryDirectory() as temporary:
                fixture = make_preflight_fixture(
                    temporary, self.preflight_validator, fresh=fresh, jobs=jobs)
                preflight = self.assert_preflight_passes(fixture)
                self.assertEqual(preflight["lib_artifact"]["fresh"], fresh[0])
                self.assertEqual(preflight["cli_artifact"]["fresh"], fresh[2])
                if jobs is None:
                    self.assertNotIn("--jobs", preflight["lib_command"])
                    self.assertNotIn("--jobs", preflight["cli_command"])
                else:
                    self.assertEqual(preflight["lib_command"][-2:], ["--jobs", str(jobs)])
                    self.assertEqual(preflight["cli_command"][-2:], ["--jobs", str(jobs)])

    def test_preflight_validator_does_not_require_original_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(temporary, self.preflight_validator)
            # Only the immutable same-hash copies and the receipt under target/
            # remain; the mutable Cargo artifacts and compiler originals do not.
            fixture["target_cli"].unlink()
            fixture["original_lib"].unlink()
            preflight = self.assert_preflight_passes(fixture)
            self.assertEqual(preflight["lib_receipt"]["sha256"],
                             digest(fixture["lib"].with_suffix(".build.json")))
            self.assertEqual(preflight["cli_receipt"]["sha256"],
                             digest(fixture["cli"].with_suffix(".build.json")))

    def test_preflight_validator_accepts_fully_bound_v1(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(
                temporary, self.preflight_validator, schema="v1")
            preflight = self.assert_preflight_passes(fixture)
            self.assertEqual(preflight["receipt_schema"], "v1")
            self.assertEqual(preflight["lib_test_support_inputs_sha256"], fixture["support"])
            self.assertEqual(preflight["lib_test_support_inputs_sha256"],
                             legacy_support_digest(fixture["root"])[0])
            self.assertNotIn("v2_features", preflight)
            self.assertNotIn("v2_profiles", preflight)
            self.assertEqual(preflight["lib_receipt"]["sha256"],
                             digest(fixture["lib"].with_suffix(".build.json")))
            self.assertEqual(preflight["cli_receipt"]["sha256"],
                             digest(fixture["cli"].with_suffix(".build.json")))

    def test_preflight_validator_rejects_tampered_v2_contracts(self):
        def features(payload):
            payload["features"]["enabled"] = ["pando-lab"]

        def no_default(payload):
            payload["features"]["no_default_features"] = False

        def lib_profile(payload):
            payload["profile"] = "dev"

        def cli_profile(payload):
            payload["profile"] = "test"

        def lib_artifact_profile(payload):
            payload["cargo_artifacts"][0]["profile"]["test"] = False

        def cli_artifact_profile(payload):
            for item in payload["cargo_artifacts"]:
                if item["kind"] == "bin":
                    item["profile"]["debuginfo"] = 2

        def lib_toolchain(payload):
            payload["toolchain"]["cargo"]["executable_sha256"] = "0" * 64

        def cli_toolchain(payload):
            payload["toolchain"]["rustc"]["commit_hash"] = "e" * 40

        def lib_support(payload):
            payload["lib_test_support_inputs_sha256"] = "0" * 64

        def cli_support(payload):
            payload["lib_test_support_inputs_sha256"] = "0" * 64

        def lib_command(payload):
            index = payload["command"].index("--no-default-features")
            payload["command"][index] = "--default-features"

        def jobs_mismatch(payload):
            payload["build_options"]["jobs"] = 3

        def record_release(fixture):
            record = json.loads(fixture["record"].read_text())
            record["rustc"]["release"] = "1.99.2"
            fixture["record"].write_text(json.dumps(record))

        def record_cargo_sha(fixture):
            record = json.loads(fixture["record"].read_text())
            record["binary_sha256"] = "0" * 64
            fixture["record"].write_text(json.dumps(record))

        def record_revision(fixture):
            record = json.loads(fixture["record"].read_text())
            record["revision"] = "e" * 40
            fixture["record"].write_text(json.dumps(record))

        def source_file(fixture):
            (fixture["root"] / "src/lib.rs").write_text("pub fn changed() -> u8 { 2 }\n")

        def support_file(fixture):
            (fixture["root"] / "tests/blob_gateway_support/helper.rs").write_text(
                "pub fn helper() -> u8 { 2 }\n")

        cases = (
            ("lib-features", "lib", features, "lib receipt enables unexpected features"),
            ("cli-features", "cli", features, "CLI receipt enables unexpected features"),
            ("lib-no-default", "lib", no_default,
             "lib receipt does not record no_default_features=true"),
            ("cli-no-default", "cli", no_default,
             "CLI receipt does not record no_default_features=true"),
            ("lib-profile", "lib", lib_profile, "lib receipt top-level profile is not test"),
            ("cli-profile", "cli", cli_profile, "CLI receipt top-level profile is not dev"),
            ("lib-artifact-profile", "lib", lib_artifact_profile,
             "profile.test must be exactly true"),
            ("cli-artifact-profile", "cli", cli_artifact_profile,
             "CLI receipt artifact is not the debug=0 dev profile"),
            ("lib-toolchain", "lib", lib_toolchain,
             "does not match the trusted CI pin"),
            ("cli-toolchain", "cli", cli_toolchain,
             "does not match the trusted CI pin"),
            ("lib-support", "lib", lib_support,
             "lib-test support digest does not match its bound inventory"),
            ("cli-support", "cli", cli_support,
             "CLI receipt unexpectedly carries a test-support digest"),
            ("lib-command", "lib", lib_command, "expected exactly"),
            ("source", None, source_file, "differs from the current source root"),
            ("support", None, support_file,
             "bound input inventory differs from the current source root"),
            ("record", None, record_release, "trusted rustc release is not 1.99.1"),
            ("record-cargo-sha", None, record_cargo_sha,
             "does not match the trusted CI pin"),
            ("record-revision", None, record_revision,
             "trusted toolchain record revision is not the pinned Cargo commit"),
        )
        for name, key, mutate, marker in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                fixture = make_preflight_fixture(temporary, self.preflight_validator)
                if key is None:
                    mutate(fixture)
                else:
                    self.edit_preflight_receipt(fixture, key, mutate)
                self.assert_preflight_fails(fixture, marker)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(
                temporary, self.preflight_validator, jobs=2)
            self.edit_preflight_receipt(fixture, "lib", jobs_mismatch)
            self.assert_preflight_fails(fixture, "--jobs budget does not match build_options.jobs")

    def test_preflight_validator_rejects_weak_legacy_support(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(
                temporary, self.preflight_validator, schema="v1")
            self.edit_preflight_receipt(
                fixture, "lib",
                lambda payload: payload.update(lib_test_support_inputs_sha256="0" * 64))
            parsed = receipts.load_receipt(
                fixture["lib"].with_suffix(".build.json"),
                source_root=fixture["root"], binary_path=fixture["lib"],
                expected_commit=fixture["head"], verify_source_files=True)
            self.assertEqual(parsed.schema, "v1")
            self.assert_preflight_fails(
                fixture, "does not match the current historical support closure")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(
                temporary, self.preflight_validator, schema="v1")
            self.edit_preflight_receipt(
                fixture, "lib",
                lambda payload: payload.pop("lib_test_support_inputs_sha256"))
            parsed = receipts.load_receipt(
                fixture["lib"].with_suffix(".build.json"),
                source_root=fixture["root"], binary_path=fixture["lib"],
                expected_commit=fixture["head"], verify_source_files=True)
            self.assertEqual(parsed.schema, "v1")
            self.assert_preflight_fails(fixture, "lacks a lowercase 64-hex")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(
                temporary, self.preflight_validator, schema="v1")
            (fixture["root"] / "tests/blob_gateway_support/helper.rs").write_text(
                "pub fn helper() -> u8 { 2 }\n")
            parsed = receipts.load_receipt(
                fixture["lib"].with_suffix(".build.json"),
                source_root=fixture["root"], binary_path=fixture["lib"],
                expected_commit=fixture["head"], verify_source_files=True)
            self.assertEqual(parsed.schema, "v1")
            self.assert_preflight_fails(
                fixture, "does not match the current historical support closure")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = make_preflight_fixture(
                temporary, self.preflight_validator, schema="v1")
            for key in ("lib", "cli"):
                self.edit_preflight_receipt(
                    fixture, key,
                    lambda payload: payload.update(rustc="rustc 1.99.2 (fake)"))
            self.assert_preflight_fails(
                fixture, "legacy lib receipt rustc is not the trusted 1.99.1 pin")

    def test_receipt_copy_check_rejects_copied_bytes_changed_after_anchor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence"
            target = root / "upload"
            source.mkdir()
            target.mkdir()
            lib_bytes = b'{"receipt": "lib"}\n'
            cli_bytes = b'{"receipt": "cli"}\n'
            for directory in (source, target):
                (directory / "session174-lib-tests.build.json").write_bytes(lib_bytes)
                (directory / "rootyard-cli.build.json").write_bytes(cli_bytes)
            preflight = {
                "lib_receipt": {
                    "path": str(source / "session174-lib-tests.build.json"),
                    "sha256": hashlib.sha256(lib_bytes).hexdigest(),
                },
                "cli_receipt": {
                    "path": str(source / "rootyard-cli.build.json"),
                    "sha256": hashlib.sha256(cli_bytes).hexdigest(),
                },
            }
            (source / "preflight.json").write_text(json.dumps(preflight))
            process = self.run_receipt_copy_check(source, target)
            self.assertEqual(process.returncode, 0, process.stderr[-2000:])
            checked = json.loads((target / "receipt-copy-check.json").read_text())
            self.assertEqual(checked["checked"]["lib_receipt"]["sha256"],
                             hashlib.sha256(lib_bytes).hexdigest())
            self.assertEqual(checked["checked"]["cli_receipt"]["sha256"],
                             hashlib.sha256(cli_bytes).hexdigest())

            with (target / "rootyard-cli.build.json").open("ab") as stream:
                stream.write(b"\n")
            process = self.run_receipt_copy_check(source, target)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("bytes changed after verification", process.stderr)
            self.assertIn("cli_receipt", process.stderr)

    def test_evidence_receipt_collector_reuses_readonly_copy_twice(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence"
            destination = root / "upload"
            source.mkdir()
            destination.mkdir()
            lib_bytes = b'{"receipt": "lib", "raw": true}\n'
            cli_bytes = b'{"receipt": "cli", "raw": true}\n'
            (source / "session174-lib-tests.build.json").write_bytes(lib_bytes)
            (source / "rootyard-cli.build.json").write_bytes(cli_bytes)
            for path in source.iterdir():
                path.chmod(0o444)
            preflight = {
                "lib_receipt": {
                    "path": str(source / "session174-lib-tests.build.json"),
                    "sha256": hashlib.sha256(lib_bytes).hexdigest(),
                },
                "cli_receipt": {
                    "path": str(source / "rootyard-cli.build.json"),
                    "sha256": hashlib.sha256(cli_bytes).hexdigest(),
                },
            }
            preflight_path = source / "preflight.json"
            preflight_path.write_text(json.dumps(preflight))
            source_stats = {
                name: os.lstat(source / name)
                for name in ("session174-lib-tests.build.json", "rootyard-cli.build.json")
            }

            first = self.run_evidence_receipt_collector(preflight_path, source, destination)
            self.assertEqual(first.returncode, 0, first.stderr[-2000:])
            for name, expected in (
                ("session174-lib-tests.build.json", lib_bytes),
                ("rootyard-cli.build.json", cli_bytes),
            ):
                published = destination / name
                self.assertEqual(published.read_bytes(), expected)
                self.assertEqual(stat.S_IMODE(published.stat().st_mode), 0o444)
            destination_stats = {
                name: os.lstat(destination / name)
                for name in ("session174-lib-tests.build.json", "rootyard-cli.build.json")
            }

            second = self.run_evidence_receipt_collector(preflight_path, source, destination)
            self.assertEqual(second.returncode, 0, second.stderr[-2000:])
            for name in ("session174-lib-tests.build.json", "rootyard-cli.build.json"):
                self.assert_stat_unchanged(
                    destination_stats[name], os.lstat(destination / name),
                    "readonly collected receipt " + name)
                self.assert_stat_unchanged(
                    source_stats[name], os.lstat(source / name),
                    "readonly consumed receipt " + name)
            self.assertEqual((destination / "rootyard-cli.build.json").read_bytes(), cli_bytes)
            self.assertIn("reused", second.stdout)

    def test_evidence_receipt_collector_rejects_different_destination_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence"
            destination = root / "upload"
            source.mkdir()
            destination.mkdir()
            lib_bytes = b'{"receipt": "lib"}\n'
            cli_bytes = b'{"receipt": "cli"}\n'
            for name, raw in (
                ("session174-lib-tests.build.json", lib_bytes),
                ("rootyard-cli.build.json", cli_bytes),
            ):
                (source / name).write_bytes(raw)
                (source / name).chmod(0o444)
            preflight = {
                "lib_receipt": {"sha256": hashlib.sha256(lib_bytes).hexdigest()},
                "cli_receipt": {"sha256": hashlib.sha256(cli_bytes).hexdigest()},
            }
            preflight_path = source / "preflight.json"
            preflight_path.write_text(json.dumps(preflight))
            conflicting = b'{"receipt": "conflicting"}\n'
            destination_file = destination / "session174-lib-tests.build.json"
            destination_file.write_bytes(conflicting)
            destination_file.chmod(0o640)
            before = os.lstat(destination_file)

            process = self.run_evidence_receipt_collector(preflight_path, source, destination)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("bytes differ", process.stderr)
            self.assert_stat_unchanged(
                before, os.lstat(destination_file), "conflicting receipt destination")
            self.assertEqual(destination_file.read_bytes(), conflicting)
            self.assertFalse((destination / "rootyard-cli.build.json").exists())

    def test_evidence_receipt_collector_rejects_symlink_destination_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence"
            destination = root / "upload"
            source.mkdir()
            destination.mkdir()
            lib_bytes = b'{"receipt": "lib"}\n'
            cli_bytes = b'{"receipt": "cli"}\n'
            for name, raw in (
                ("session174-lib-tests.build.json", lib_bytes),
                ("rootyard-cli.build.json", cli_bytes),
            ):
                (source / name).write_bytes(raw)
                (source / name).chmod(0o444)
            preflight = {
                "lib_receipt": {"sha256": hashlib.sha256(lib_bytes).hexdigest()},
                "cli_receipt": {"sha256": hashlib.sha256(cli_bytes).hexdigest()},
            }
            preflight_path = source / "preflight.json"
            preflight_path.write_text(json.dumps(preflight))
            target = root / "same-byte-receipt.json"
            target.write_bytes(lib_bytes)
            target.chmod(0o444)
            target_before = os.lstat(target)
            destination_file = destination / "session174-lib-tests.build.json"
            destination_file.symlink_to(target)

            process = self.run_evidence_receipt_collector(preflight_path, source, destination)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("must not be a symlink", process.stderr)
            self.assertTrue(destination_file.is_symlink())
            self.assertEqual(os.readlink(destination_file), str(target))
            self.assert_stat_unchanged(target_before, os.lstat(target), "symlink target")

            destination_file.unlink()
            dangling = root / "missing-receipt.json"
            destination_file.symlink_to(dangling)
            process = self.run_evidence_receipt_collector(preflight_path, source, destination)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("must not be a symlink", process.stderr)
            self.assertTrue(destination_file.is_symlink())
            self.assertFalse(destination_file.exists())
            self.assertFalse(dangling.exists())

    def test_evidence_receipt_collector_optional_missing_source_keeps_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence"
            destination = root / "upload"
            source.mkdir()
            destination.mkdir()
            lib_bytes = b'{"receipt": "lib"}\n'
            cli_bytes = b'{"receipt": "cli"}\n'
            (source / "session174-lib-tests.build.json").write_bytes(lib_bytes)
            (source / "session174-lib-tests.build.json").chmod(0o444)
            preflight = {
                "lib_receipt": {"sha256": hashlib.sha256(lib_bytes).hexdigest()},
                "cli_receipt": {"sha256": hashlib.sha256(cli_bytes).hexdigest()},
            }
            preflight_path = source / "preflight.json"
            preflight_path.write_text(json.dumps(preflight))

            process = self.run_evidence_receipt_collector(
                preflight_path, source, destination, optional=True)
            self.assertEqual(process.returncode, 0, process.stderr[-2000:])
            self.assertEqual((destination / "session174-lib-tests.build.json").read_bytes(),
                             lib_bytes)
            self.assertFalse((destination / "rootyard-cli.build.json").exists())
            self.assertIn("skip missing", process.stdout)
            self.assertFalse((destination / "rootyard-cli.build.json").exists())

    def test_evidence_receipt_collector_optional_absent_preflight_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination, preflight, _lib, _cli = self.make_collector_fixture(
                temporary)
            preflight.unlink()
            process = self.run_evidence_receipt_collector(
                preflight, source, destination, optional=True)
            self.assertEqual(process.returncode, 0, process.stderr[-2000:])
            self.assertIn("no preflight.json; receipts skipped", process.stdout)
            self.assertEqual(list(destination.iterdir()), [])

    def test_evidence_receipt_collector_optional_rejects_malformed_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination, preflight, lib_bytes, _cli = self.make_collector_fixture(
                temporary)
            preflight.write_text("{not valid json")
            destination_file = destination / "session174-lib-tests.build.json"
            destination_file.write_bytes(lib_bytes)
            destination_file.chmod(0o444)
            before = os.lstat(destination_file)

            process = self.run_evidence_receipt_collector(
                preflight, source, destination, optional=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("unreadable preflight evidence", process.stderr)
            self.assert_stat_unchanged(
                before, os.lstat(destination_file), "readonly receipt after malformed preflight")
            self.assertEqual(destination_file.read_bytes(), lib_bytes)
            self.assertFalse((destination / "rootyard-cli.build.json").exists())

    def test_evidence_receipt_collector_optional_rejects_unreadable_preflight(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root can read a 0000 preflight fixture")
        with tempfile.TemporaryDirectory() as temporary:
            source, destination, preflight, lib_bytes, _cli = self.make_collector_fixture(
                temporary)
            preflight.chmod(0o000)
            destination_file = destination / "session174-lib-tests.build.json"
            destination_file.write_bytes(lib_bytes)
            destination_file.chmod(0o444)
            before = os.lstat(destination_file)

            process = self.run_evidence_receipt_collector(
                preflight, source, destination, optional=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("preflight evidence", process.stderr)
            self.assert_stat_unchanged(
                before, os.lstat(destination_file),
                "readonly receipt after unreadable preflight")
            self.assertEqual(destination_file.read_bytes(), lib_bytes)

    def test_evidence_receipt_collector_optional_rejects_bad_preflight_shapes(self):
        malformed_shapes = (
            ("nonobject", b"[]", "preflight evidence is not an object"),
            ("bad-anchor",
             b'{"lib_receipt": {"sha256": "not-hex"}, '
             b'"cli_receipt": {"sha256": "not-hex"}}',
             "has no lowercase 64-hex anchor"),
        )
        for name, raw, marker in malformed_shapes:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                source, destination, preflight, lib_bytes, _cli = \
                    self.make_collector_fixture(temporary)
                preflight.write_bytes(raw)
                destination_file = destination / "session174-lib-tests.build.json"
                destination_file.write_bytes(lib_bytes)
                destination_file.chmod(0o444)
                before = os.lstat(destination_file)
                process = self.run_evidence_receipt_collector(
                    preflight, source, destination, optional=True)
                self.assertNotEqual(process.returncode, 0)
                self.assertIn(marker, process.stderr)
                self.assert_stat_unchanged(
                    before, os.lstat(destination_file),
                    "readonly receipt after bad preflight " + name)
                self.assertEqual(destination_file.read_bytes(), lib_bytes)

        with tempfile.TemporaryDirectory() as temporary:
            source, destination, preflight, _lib, _cli = self.make_collector_fixture(
                temporary)
            real = source / "real-preflight.json"
            real.write_bytes(preflight.read_bytes())
            preflight.unlink()
            preflight.symlink_to(real)
            process = self.run_evidence_receipt_collector(
                preflight, source, destination, optional=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("must not be a symlink", process.stderr)
            self.assertTrue(preflight.is_symlink())
            self.assertEqual(list(destination.iterdir()), [])

        with tempfile.TemporaryDirectory() as temporary:
            source, destination, preflight, _lib, _cli = self.make_collector_fixture(
                temporary)
            preflight.unlink()
            preflight.symlink_to(source / "missing-preflight.json")
            process = self.run_evidence_receipt_collector(
                preflight, source, destination, optional=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("must not be a symlink", process.stderr)
            self.assertTrue(preflight.is_symlink())
            self.assertEqual(list(destination.iterdir()), [])

        with tempfile.TemporaryDirectory() as temporary:
            source, destination, preflight, _lib, _cli = self.make_collector_fixture(
                temporary)
            preflight.unlink()
            preflight.mkdir()
            process = self.run_evidence_receipt_collector(
                preflight, source, destination, optional=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("must be a regular file", process.stderr)
            self.assertTrue(preflight.is_dir())
            self.assertEqual(list(destination.iterdir()), [])

    def test_174_always_collector_keeps_logs_when_preflight_is_corrupt(self):
        block = workflow_run_block(self.source, "Collect #174 acceptance evidence")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            (work / "scripts").mkdir(parents=True)
            shutil.copyfile(SCRIPTS / "collect_evidence_receipts.py",
                            work / "scripts/collect_evidence_receipts.py")
            evidence = root / "runner/session174-foundation"
            evidence.mkdir(parents=True)
            lib_bytes = b'{"receipt": "lib", "raw": true}\n'
            lib_source = evidence / "session174-lib-tests.build.json"
            lib_source.write_bytes(lib_bytes)
            lib_source.chmod(0o444)
            (evidence / "preflight.json").write_text("{not valid json")
            (evidence / "preflight.log").write_text("preflight log\n")
            (evidence / "cases.log").write_text("cases log\n")
            (evidence / "case-1.log").write_text("case 1\n")
            upload = work / "test-results/refstore/session174-foundation"
            upload.mkdir(parents=True)
            destination_file = upload / "session174-lib-tests.build.json"
            destination_file.write_bytes(lib_bytes)
            destination_file.chmod(0o444)
            destination_before = os.lstat(destination_file)
            environment = dict(os.environ, RUNNER_TEMP=str(root / "runner"))

            process = subprocess.run(
                ["bash", "-c", block], cwd=work, env=environment,
                text=True, capture_output=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("unreadable preflight evidence", process.stderr)
            for name in ("preflight.json", "preflight.log", "cases.log", "case-1.log"):
                self.assertTrue((upload / name).is_file(), name)
            self.assert_stat_unchanged(
                destination_before, os.lstat(destination_file),
                "readonly receipt after corrupt preflight")
            self.assertEqual(destination_file.read_bytes(), lib_bytes)

    def test_174_always_collector_runs_idempotently_with_partial_evidence(self):
        block = workflow_run_block(self.source, "Collect #174 acceptance evidence")
        self.assertIn("scripts/collect_evidence_receipts.py --optional", block)
        self.assertIn('if [ -f "$evidence/$name" ]; then', block)
        self.assertNotIn('[ -f "$evidence/$name" ] && cp', block)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            (work / "scripts").mkdir(parents=True)
            shutil.copyfile(SCRIPTS / "collect_evidence_receipts.py",
                            work / "scripts/collect_evidence_receipts.py")
            evidence = root / "runner/session174-foundation"
            evidence.mkdir(parents=True)
            lib_bytes = b'{"receipt": "lib", "raw": true}\n'
            cli_bytes = b'{"receipt": "cli", "raw": true}\n'
            lib_source = evidence / "session174-lib-tests.build.json"
            lib_source.write_bytes(lib_bytes)
            lib_source.chmod(0o444)
            preflight = {
                "lib_receipt": {"sha256": hashlib.sha256(lib_bytes).hexdigest()},
                "cli_receipt": {"sha256": hashlib.sha256(cli_bytes).hexdigest()},
            }
            (evidence / "preflight.json").write_text(json.dumps(preflight))
            (evidence / "preflight.log").write_text("preflight log\n")
            (evidence / "cases.log").write_text("cases log\n")
            (evidence / "case-1.log").write_text("case 1\n")
            # Leave database-cleanup.log, standalone-build.json, the second
            # receipt source, and additional case logs absent on purpose.
            environment = dict(os.environ, RUNNER_TEMP=str(root / "runner"))
            first = subprocess.run(
                ["bash", "-c", block], cwd=work, env=environment,
                text=True, capture_output=True)
            self.assertEqual(first.returncode, 0,
                             f"collector failed:\n{first.stdout[-2000:]}\n{first.stderr[-2000:]}")
            upload = work / "test-results/refstore/session174-foundation"
            for name in ("preflight.json", "preflight.log", "cases.log", "case-1.log",
                         "session174-lib-tests.build.json"):
                self.assertTrue((upload / name).is_file(), name)
            self.assertFalse((upload / "rootyard-cli.build.json").exists())
            self.assertFalse((upload / "database-cleanup.log").exists())
            self.assertEqual((upload / "session174-lib-tests.build.json").read_bytes(),
                             lib_bytes)
            self.assertEqual(
                stat.S_IMODE((upload / "session174-lib-tests.build.json").stat().st_mode),
                0o444)
            source_before = os.lstat(lib_source)
            destination_before = os.lstat(upload / "session174-lib-tests.build.json")

            second = subprocess.run(
                ["bash", "-c", block], cwd=work, env=environment,
                text=True, capture_output=True)
            self.assertEqual(second.returncode, 0,
                             f"collector failed:\n{second.stdout[-2000:]}\n{second.stderr[-2000:]}")
            self.assert_stat_unchanged(
                source_before, os.lstat(lib_source), "collector source receipt")
            self.assert_stat_unchanged(
                destination_before,
                os.lstat(upload / "session174-lib-tests.build.json"),
                "collector readonly receipt")
            self.assertEqual((upload / "session174-lib-tests.build.json").read_bytes(),
                             lib_bytes)

            # A failure before preflight.json is written must still collect the
            # available logs and must not turn the readonly receipt into an error.
            (evidence / "preflight.json").unlink()
            third = subprocess.run(
                ["bash", "-c", block], cwd=work, env=environment,
                text=True, capture_output=True)
            self.assertEqual(third.returncode, 0,
                             f"collector failed:\n{third.stdout[-2000:]}\n{third.stderr[-2000:]}")
            self.assertIn("no preflight.json; receipts skipped", third.stdout)
            self.assertTrue((upload / "preflight.log").is_file())
            self.assertTrue((upload / "cases.log").is_file())
            self.assert_stat_unchanged(
                destination_before,
                os.lstat(upload / "session174-lib-tests.build.json"),
                "collector readonly receipt after preflight loss")

    def test_174_receipt_collection_uses_one_helper_at_both_sites(self):
        start = self.source.index('"Exercise the #174 HTTP foundation cases')
        end = self.source.index('"Drop only the run-owned #174 foundation database"')
        step19 = self.source[start:end]
        self.assertIn("scripts/collect_evidence_receipts.py", step19)
        self.assertNotIn('cp "$evidence/session174-lib-tests.build.json"', step19)
        self.assertNotIn('cp "$evidence/rootyard-cli.build.json"', step19)
        self.assertIn("receipt-copy-check.json", step19)
        self.assertIn("bytes changed after verification", step19)

        start = self.source.index('"Collect #174 acceptance evidence"')
        end = self.source.index('Stop only the job-owned Garage fixture', start)
        collector = self.source[start:end]
        self.assertIn("scripts/collect_evidence_receipts.py --optional", collector)
        self.assertIn('if [ -f "$evidence/$name" ]; then', collector)
        self.assertNotIn('[ -f "$evidence/$name" ] && cp', collector)
        for name in ("preflight.json", "preflight.log", "session174-lib-tests.stdout.log",
                     "standalone-build.json", "cases.log", "session174-foundation.json",
                     "database-cleanup.log", "receipt-copy-check.json"):
            self.assertIn(name, collector)
        self.assertIn("case-*.log", collector)
        self.assertIn('exit "$status"', collector)

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
