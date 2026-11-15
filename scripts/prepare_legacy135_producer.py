#!/usr/bin/env python3
"""Prepare the exact frozen schema135 producer for the #82 AC3 drill.

The producer source is fetched by full commit into an isolated directory outside
the candidate checkout, built with the reviewed locked CargoFork/Rust profile,
and sealed into the existing native artifact store with a normal shared v2
receipt.  The build command, toolchain, source inventory, Git tree and actual
binary SHA are measured; the historical observability binary hash is never
asserted and no archive is manufactured, edited or relabelled.

Compiler stdout/stderr remain in this process's RAM.  Only the safe preparation
JSON and the normal v2 receipt are persisted.  This script never creates a
general build platform: it uses ``native_build_receipt``, ``native_artifact_store``
and ``build_native.cas_configuration`` exactly as the other native producers do.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import build_native as native_builder  # noqa: E402
import native_artifact_store as artifact_store  # noqa: E402
import native_build_receipt as receipts  # noqa: E402

FROZEN_SOURCE_COMMIT = "560e96f41f1d4670bfb5d2459af7af459eca4823"
FROZEN_SOURCE_FORMAT = 11
FROZEN_SOURCE_SCHEMA = 135
PREP_SCHEMA = "rootyard/issue82-legacy135-producer-prep/v1"
PRODUCER_KIND = "legacy-schema135-producer"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PreparationError(RuntimeError):
    """A static failure code; compiler or Git output is never included."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise PreparationError(code)


def sha256_file(path):
    import hashlib
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        raise PreparationError("source_unreadable") from None


def frozen_source_contract(source_root):
    """Read-only proof that the checkout is exactly format11/schema135."""
    source_root = Path(source_root)
    db = _read(source_root / "src" / "db.rs")
    match = re.search(
        r"pub const SCHEMA_VERSIONS:\s*&\[i32\]\s*=\s*&\[([0-9,\s]+)\];", db)
    _require(match is not None, "frozen_schema_versions_missing")
    versions = [int(item.strip()) for item in match.group(1).split(",")
                if item.strip()]
    pairs = re.findall(
        r'\((\d+),\s*include_str!\("\.\./migrations/([^"]+)"\)\)', db)
    migrations = [int(version) for version, _ in pairs]
    _require(versions == [1] + migrations, "frozen_schema_versions_inconsistent")
    _require(versions and versions[-1] == FROZEN_SOURCE_SCHEMA,
             "frozen_schema_not_135")
    _require(FROZEN_SOURCE_SCHEMA + 1 not in versions,
             "frozen_source_contains_schema136")
    names = sorted(path.name for path in (source_root / "migrations").glob("*.sql"))
    _require(any(name.startswith("135_") for name in names),
             "frozen_schema135_migration_missing")
    _require(not any(name.startswith("136_") for name in names),
             "frozen_schema136_migration_present")
    catalog = _read(source_root / "src" / "backup" / "catalog.rs")
    format_match = re.search(
        r"pub\(super\) const FORMAT:\s*u32\s*=\s*(\d+);", catalog)
    _require(format_match is not None, "frozen_format_missing")
    _require(int(format_match.group(1)) == FROZEN_SOURCE_FORMAT,
             "frozen_format_not_11")
    return {
        "format": FROZEN_SOURCE_FORMAT,
        "schema": FROZEN_SOURCE_SCHEMA,
        "schema_versions": versions,
        "schema136_absent": True,
    }


def validate_paths(args):
    source_commit = args.source_commit
    _require(COMMIT.fullmatch(source_commit) is not None, "invalid_source_commit")
    _require(source_commit == FROZEN_SOURCE_COMMIT, "source_commit_not_frozen_560")
    candidate_root = Path(args.candidate_source_root).resolve()
    source_dir = Path(args.source_dir).resolve()
    target_dir = Path(args.cargo_target_dir).resolve()
    store_root = Path(args.artifact_store).resolve()
    output_dir = Path(args.output_dir).resolve()
    _require(candidate_root.is_dir(), "candidate_source_root_missing")
    _require(not source_dir.exists(), "source_directory_already_exists")
    for label, path in (("source", source_dir), ("target", target_dir),
                        ("artifact_store", store_root), ("output", output_dir)):
        _require(not _inside(path, candidate_root),
                 label + "_inside_candidate_checkout")
    for label, path in (("target", target_dir), ("artifact_store", store_root),
                        ("output", output_dir)):
        _require(not _inside(path, source_dir), label + "_inside_source_checkout")
    _require(store_root != target_dir and output_dir != store_root,
             "preparation_roles_overlap")
    return {
        "candidate_root": candidate_root,
        "source_dir": source_dir,
        "target_dir": target_dir,
        "store_root": store_root,
        "output_dir": output_dir,
    }


def _git(git, source_dir, arguments, environment, timeout=180):
    try:
        return subprocess.run(
            [git, "-C", str(source_dir), *arguments],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise PreparationError("git_process_failed") from None


def fetch_frozen_source(args, paths):
    """Fetch exactly one commit into a source directory outside the candidate."""
    git = shutil.which("git")
    _require(git is not None, "git_unavailable")
    source_dir = paths["source_dir"]
    source_dir.mkdir(parents=True, exist_ok=False)
    home = tempfile.mkdtemp(prefix="legacy135-git-home-",
                            dir=str(paths["output_dir"]))
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    try:
        init = _git(git, source_dir, ["init", "--template="], environment)
        _require(init.returncode == 0, "git_init_failed")
        fetch = _git(
            git, source_dir,
            ["fetch", "--no-tags", "--depth=1", args.remote,
             FROZEN_SOURCE_COMMIT], environment)
        _require(fetch.returncode == 0, "git_fetch_failed")
        fetched = _git(git, source_dir, ["rev-parse", "FETCH_HEAD^{commit}"],
                       environment)
        _require(fetched.returncode == 0 and
                 fetched.stdout.strip() == FROZEN_SOURCE_COMMIT,
                 "git_fetched_commit_mismatch")
        checkout = _git(git, source_dir, ["checkout", "--detach",
                                          FROZEN_SOURCE_COMMIT], environment)
        _require(checkout.returncode == 0, "git_checkout_failed")
        head = _git(git, source_dir, ["rev-parse", "HEAD"], environment)
        _require(head.returncode == 0 and
                 head.stdout.strip() == FROZEN_SOURCE_COMMIT,
                 "git_head_commit_mismatch")
        try:
            state = receipts.require_clean_git_state(source_dir)
        except receipts.ReceiptError:
            raise PreparationError("frozen_source_not_clean") from None
        _require(state["commit"] == FROZEN_SOURCE_COMMIT,
                 "git_head_commit_mismatch")
        return state
    finally:
        shutil.rmtree(home, ignore_errors=True)


def build_command(normalized):
    return [
        "cargo", "build", "--locked", "--message-format=json",
        "--bin", "rootyard", "--features", "pando-lab",
        *normalized["cargo_args"],
    ]


def run_cargo_build(source_dir, target_dir, normalized, timeout):
    environment = dict(normalized["environment"])
    environment["CARGO_TARGET_DIR"] = str(target_dir)
    command = build_command(normalized)
    try:
        process = subprocess.run(
            command,
            cwd=str(source_dir),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise PreparationError("cargo_process_failed") from None
    if process.returncode != 0:
        raise PreparationError("cargo_build_failed")
    events = []
    for line in process.stdout.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            raise PreparationError("cargo_json_invalid") from None
        if not isinstance(event, dict):
            raise PreparationError("cargo_json_invalid")
        events.append(event)
    try:
        receipts.require_build_finished(events)
    except receipts.ReceiptError:
        raise PreparationError("cargo_build_unfinished") from None
    return command, events, environment


def select_rootyard_bin(events, source_dir):
    rows = []
    for event in events:
        if not isinstance(event, dict) or event.get("reason") != "compiler-artifact":
            continue
        target = event.get("target") or {}
        if target.get("name") != "rootyard" or "bin" not in (target.get("kind") or []):
            continue
        try:
            rows.append(receipts.cargo_artifact_record(event, source_dir, kind="bin"))
        except receipts.ReceiptError:
            raise PreparationError("cargo_binary_record_invalid") from None
    _require(len(rows) == 1, "cargo_binary_artifact_count_invalid")
    return rows[0]


def seal_and_record(args, paths, source_state, source_contract, command,
                    toolchain, bound, row):
    built = Path(row["executable"])
    _require(built.is_file(), "cargo_binary_missing")
    config_args = SimpleNamespace(features="pando-lab", no_default_features=False)
    try:
        config_key = artifact_store.configuration_key(
            native_builder.cas_configuration(
                config_args, command, toolchain, bound))
        sealed = artifact_store.seal_binary(
            built,
            store_root=paths["store_root"],
            commit=FROZEN_SOURCE_COMMIT,
            config_key=config_key,
            expected_sha256=row["executable_sha256"],
        )
    except artifact_store.ArtifactStoreError:
        raise PreparationError("producer_seal_failed") from None
    store_record = {
        "schema": artifact_store.STORE_SCHEMA,
        "root": str(paths["store_root"]),
        "object": str(sealed.object_path),
        "binary": str(sealed.binary_path),
        "receipt": str(sealed.receipt_path),
        "binary_sha256": sealed.sha256,
        "config_key": sealed.config_key,
        "build_id": sealed.build_id,
        "method": sealed.method,
        "reused": sealed.reused,
    }
    try:
        report = receipts.make_receipt_v2(
            binary_path=sealed.binary_path,
            command=command,
            profile="dev",
            artifacts=[row],
            toolchain=toolchain,
            bound_inputs=bound,
            workspace_commit=FROZEN_SOURCE_COMMIT,
            target_dir=paths["target_dir"],
            features="pando-lab",
            no_default_features=False,
            git_head=source_state["head"],
            working_tree={"tree": source_state["tree"],
                          "status": source_state["status"]},
            extra={
                "kind": PRODUCER_KIND,
                "source_format": FROZEN_SOURCE_FORMAT,
                "source_schema": FROZEN_SOURCE_SCHEMA,
                "relocated_artifact": True,
                "original_artifact_sha256": sealed.sha256,
                "artifact_store": store_record,
            },
        )
        artifact_store.write_receipt(sealed, report)
        validated = receipts.validate_receipt(
            report,
            source_root=paths["source_dir"],
            binary_path=sealed.binary_path,
            expected_commit=FROZEN_SOURCE_COMMIT,
            expected_binary_sha256=sealed.sha256,
            forbid_implicit_build=True,
        )
    except (receipts.ReceiptError, artifact_store.ArtifactStoreError):
        raise PreparationError("producer_receipt_failed") from None
    _require(validated.schema == "v2", "producer_receipt_not_v2")
    return sealed, report, store_record


def prepare(args):
    paths = validate_paths(args)
    paths["output_dir"].mkdir(parents=True, exist_ok=True)
    paths["target_dir"].mkdir(parents=True, exist_ok=True)
    paths["store_root"].mkdir(parents=True, exist_ok=True)
    source_state = fetch_frozen_source(args, paths)
    source_contract = frozen_source_contract(paths["source_dir"])
    try:
        normalized = receipts.normalize_build_environment(os.environ)
        bound_before = receipts.capture_bound_inputs(
            paths["source_dir"], environ=normalized["environment"])
        toolchain_before = receipts.probe_toolchain(
            paths["source_dir"], environ=normalized["environment"])
    except receipts.ReceiptError:
        raise PreparationError("producer_environment_rejected") from None
    command, events, environment = run_cargo_build(
        paths["source_dir"], paths["target_dir"], normalized, args.build_timeout)
    try:
        bound_after = receipts.capture_bound_inputs(
            paths["source_dir"], environ=environment)
        toolchain_after = receipts.probe_toolchain(
            paths["source_dir"], environ=environment)
    except receipts.ReceiptError:
        raise PreparationError("producer_environment_changed") from None
    _require(bound_before == bound_after, "producer_source_changed_during_build")
    _require(toolchain_before == toolchain_after, "producer_toolchain_changed")
    try:
        state_after = receipts.require_clean_git_state(paths["source_dir"])
    except receipts.ReceiptError:
        raise PreparationError("producer_source_dirty_after_build") from None
    _require(state_after == source_state, "producer_source_state_changed")
    row = select_rootyard_bin(events, paths["source_dir"])
    sealed, report, store_record = seal_and_record(
        args, paths, source_state, source_contract, command,
        toolchain_after, bound_after, row)
    return {
        "schema": PREP_SCHEMA,
        "kind": PRODUCER_KIND,
        "passed": True,
        "source": {
            "commit": FROZEN_SOURCE_COMMIT,
            "tree": source_state["tree"],
            "clean": True,
            "format": source_contract["format"],
            "schema": source_contract["schema"],
            "schema_versions": source_contract["schema_versions"],
            "schema136_absent": True,
        },
        "build": {
            "command": command,
            "features": ["pando-lab"],
            "profile": "dev",
            "toolchain": {
                "cargo": {
                    "version": toolchain_after["cargo"]["version"],
                    "commit_hash": toolchain_after["cargo"].get("commit_hash"),
                    "executable_sha256": toolchain_after["cargo"].get("executable_sha256"),
                },
                "rustc": {
                    "version": toolchain_after["rustc"]["version"],
                    "commit_hash": toolchain_after["rustc"].get("commit_hash"),
                },
                "target_triple": toolchain_after["target_triple"],
            },
        },
        "binary": {
            "path": str(sealed.binary_path),
            "sha256": sealed.sha256,
            "receipt": str(sealed.receipt_path),
            "receipt_sha256": sha256_file(sealed.receipt_path),
            "receipt_schema": "v2",
        },
        "artifact_store": store_record,
        "git": {
            "head": source_state["head"],
            "tree": source_state["tree"],
            "clean": True,
        },
        "historical_binary_sha256_asserted": False,
        "raw_compiler_output_persisted": False,
        "credentials_read": False,
    }


def write_report(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", default=FROZEN_SOURCE_COMMIT)
    parser.add_argument("--source-dir", required=True,
                        help="absent isolated source checkout outside the candidate")
    parser.add_argument("--candidate-source-root", default=str(ROOT))
    parser.add_argument("--cargo-target-dir", required=True)
    parser.add_argument("--artifact-store", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--remote", default="https://github.com/jihuayu/rootyard.git")
    parser.add_argument("--build-timeout", type=int, default=1200)
    args = parser.parse_args(argv)
    if args.build_timeout < 60 or args.build_timeout > 3600:
        parser.error("--build-timeout must be between 60 and 3600 seconds")
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        report = prepare(args)
        write_report(args.report, report)
        print(json.dumps({
            "passed": True,
            "source_commit": report["source"]["commit"],
            "binary_sha256": report["binary"]["sha256"],
            "receipt": report["binary"]["receipt"],
        }, sort_keys=True))
        return 0
    except PreparationError as error:
        print("prepare_legacy135_producer: " + error.code, file=sys.stderr)
        return 1
    except Exception:
        print("prepare_legacy135_producer: unexpected_error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
