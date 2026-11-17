#!/usr/bin/env python3
"""Prebuilt native11 issue107 acceptance runner.

Consumes explicit test executables and their adjacent v2 receipts plus an
already-owned PostgreSQL/Blob/Git environment. It never invokes Cargo, rustc, a
builder, Git, HTTP, a provider or Docker.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import issue107_native11_inventory as inventory  # noqa: E402
import native_build_receipt as receipts  # noqa: E402

MAX_CAPTURE_BYTES = 2 * 1024 * 1024
DEFAULT_OVERALL_SECONDS = 3600.0
DEFAULT_CASE_SECONDS = 600.0
KILL_WAIT_SECONDS = 5.0
REPORT_KIND = "rootyard/refstore-native11-acceptance"
FAILURE_KIND = "rootyard/refstore-native11-target-failure"
FAILURE_PREFIX = "native11"
FAILURE_PHASES = ("list", "run")
SOURCE_PREFIX = "tests/"

# The failure projection is deliberately smaller than the already bounded
# 2 MiB process capture.  It only keeps fields whose complete vocabulary is
# owned by this harness or by the frozen inventory.
MAX_DIAGNOSTIC_LINE_CHARS = 4096
MAX_DIAGNOSTIC_CASE_ENTRIES = 256
MAX_SOURCE_LOCATIONS = 8
MAX_SOURCE_LINE = 10_000_000

# Exact repo-relative Rust source allowlist.  A path is retained only when it
# is byte-equal to one of the fixed integration-test sources in the inventory.
SOURCE_ALLOWLIST = tuple(sorted({
    cfg["source"] for cfg in inventory.TARGETS.values()
}))

# Bounded, test-only metadata-replay checkpoint frames. The protocol is gated
# on the caller-selected exact target/case below; frame text never supplies or
# changes the case identity and never becomes a libtest pass.
METADATA_REPLAY_PREFIX = "ROOTYARD_I107_METADATA_REPLAY_V1"
METADATA_REPLAY_TARGET = "ref_store_pack_snapshots"
METADATA_REPLAY_CASE = "serving_metadata_create_replays_after_ref_advance_and_old_a5a_rejects_it"
METADATA_REPLAY_PROTOCOL = "metadata_replay_v1"
METADATA_REPLAY_MAX_LINE = 512
METADATA_REPLAY_MAX_FRAMES = 512
METADATA_REPLAY_MAX_COUNTS = 1_000_000_000
METADATA_REPLAY_MAX_ITERATION = 100_000
METADATA_REPLAY_MAX_CHECKS = 8
METADATA_REPLAY_MAX_ERROR_KIND = 8
MAX_METADATA_REPLAY_PHASE = 24

# Closed source-owned error classes; no raw text, path, object id or provider
# payload is accepted or persisted.
METADATA_REPLAY_ERROR_KINDS = {
    1: 'io',
    2: 'ref_store_timeout',
    3: 'ref_store_unsupported',
    4: 'storage_database',
    5: 'ref_store_other',
    6: 'git_process',
    7: 'other',
    8: 'blob_provider',
}

METADATA_REPLAY_PHASES = {
    1: 'setup',
    2: 'tenant_create',
    3: 'old_a5a',
    4: 'first_advance',
    5: 'tenant_replay',
    6: 'changed_lease',
    7: 'collaborator',
    8: 'cross_mode_tenant',
    9: 'cross_mode_actor',
    10: 'owned_a_create_read',
    11: 'owned_a_renew',
    12: 'owned_a_release',
    13: 'owned_b_create',
    14: 'second_advance_replay',
    15: 'owned_b_read',
    16: 'owned_b_materialize',
    17: 'historical_content',
    18: 'nonowner_read',
    19: 'tenant_read_refusal',
    20: 'nonowner_materialize',
    21: 'tenant_materialize_refusal',
    22: 'role_revoke_read',
    23: 'role_revoke_materialize',
    24: 'finish',
}

# (phase, site) -> fixed phase/site labels from the source-only triage map.
METADATA_REPLAY_SITES = {
    (1, 1): ('setup', 'db_setup'),
    (1, 2): ('setup', 'open_store'),
    (1, 3): ('setup', 'git_binary'),
    (1, 4): ('setup', 'serving_business'),
    (1, 5): ('setup', 'serving_verified'),
    (2, 1): ('tenant_create', 'create'),
    (2, 2): ('tenant_create', 'not_replayed_assert'),
    (2, 3): ('tenant_create', 'tenant_assert'),
    (2, 4): ('tenant_create', 'counts_read'),
    (3, 1): ('old_a5a', 'scope_construct'),
    (3, 2): ('old_a5a', 'expectation_construct'),
    (3, 3): ('old_a5a', 'request_construct'),
    (3, 4): ('old_a5a', 'pool_acquire'),
    (3, 5): ('old_a5a', 'create_result'),
    (3, 6): ('old_a5a', 'refused_assert'),
    (3, 7): ('old_a5a', 'counts_read'),
    (3, 8): ('old_a5a', 'unchanged_assert'),
    (4, 1): ('first_advance', 'serving_advance'),
    (4, 2): ('first_advance', 'gate_read'),
    (4, 3): ('first_advance', 'revision_advanced_assert'),
    (5, 1): ('tenant_replay', 'create'),
    (5, 2): ('tenant_replay', 'replayed_assert'),
    (5, 3): ('tenant_replay', 'snapshot_id_assert'),
    (5, 4): ('tenant_replay', 'pin_id_assert'),
    (5, 5): ('tenant_replay', 'gate_assert'),
    (5, 6): ('tenant_replay', 'counts_read'),
    (5, 7): ('tenant_replay', 'unchanged_assert'),
    (6, 1): ('changed_lease', 'create_result'),
    (6, 2): ('changed_lease', 'refused_assert'),
    (6, 3): ('changed_lease', 'counts_read'),
    (6, 4): ('changed_lease', 'unchanged_assert'),
    (7, 1): ('collaborator', 'create_authenticate_collaborator'),
    (7, 2): ('collaborator', 'distinct_principal_assert'),
    (8, 1): ('cross_mode_tenant', 'create'),
    (8, 2): ('cross_mode_tenant', 'not_replayed_assert'),
    (8, 3): ('cross_mode_tenant', 'owner_assert'),
    (8, 4): ('cross_mode_tenant', 'counts_read'),
    (9, 1): ('cross_mode_actor', 'create_result'),
    (9, 2): ('cross_mode_actor', 'exact_conflict_match'),
    (9, 3): ('cross_mode_actor', 'counts_read'),
    (9, 4): ('cross_mode_actor', 'unchanged_assert'),
    (10, 1): ('owned_a_create_read', 'create'),
    (10, 2): ('owned_a_create_read', 'not_replayed_assert'),
    (10, 3): ('owned_a_create_read', 'owner_tenant_assert'),
    (10, 4): ('owned_a_create_read', 'read'),
    (10, 5): ('owned_a_create_read', 'immutable_capture_assert'),
    (11, 1): ('owned_a_renew', 'renew'),
    (11, 2): ('owned_a_renew', 'not_replayed_assert'),
    (11, 3): ('owned_a_renew', 'generation_two_assert'),
    (11, 4): ('owned_a_renew', 'renew_replay'),
    (11, 5): ('owned_a_renew', 'replayed_assert'),
    (12, 1): ('owned_a_release', 'release'),
    (12, 2): ('owned_a_release', 'not_replayed_assert'),
    (12, 3): ('owned_a_release', 'release_replay'),
    (12, 4): ('owned_a_release', 'replayed_assert'),
    (12, 5): ('owned_a_release', 'released_read_result'),
    (12, 6): ('owned_a_release', 'refused_assert'),
    (13, 1): ('owned_b_create', 'create'),
    (13, 2): ('owned_b_create', 'not_replayed_assert'),
    (13, 3): ('owned_b_create', 'owner_tenant_assert'),
    (13, 4): ('owned_b_create', 'counts_read'),
    (14, 1): ('second_advance_replay', 'serving_advance'),
    (14, 2): ('second_advance_replay', 'create_replay'),
    (14, 3): ('second_advance_replay', 'replayed_assert'),
    (14, 4): ('second_advance_replay', 'snapshot_pin_gate_assert'),
    (14, 5): ('second_advance_replay', 'counts_read'),
    (14, 6): ('second_advance_replay', 'unchanged_assert'),
    (15, 1): ('owned_b_read', 'read'),
    (15, 2): ('owned_b_read', 'immutable_capture_assert'),
    (15, 3): ('owned_b_read', 'nonempty_packs_assert'),
    (15, 4): ('owned_b_read', 'head_option'),
    (15, 5): ('owned_b_read', 'first_advance_head_assert'),
    (15, 6): ('owned_b_read', 'different_second_head_assert'),
    (16, 1): ('owned_b_materialize', 'materializer_construct'),
    (16, 2): ('owned_b_materialize', 'materialize'),
    (16, 3): ('owned_b_materialize', 'view_shape_assert'),
    (16, 4): ('owned_b_materialize', 'each_pack_identity_assert'),
    (17, 1): ('historical_content', 'read_materialized_file'),
    (17, 2): ('historical_content', 'exact_first_advance_content_assert'),
    (17, 3): ('historical_content', 'git_repo_new'),
    (17, 4): ('historical_content', 'pack_dir_create'),
    (17, 5): ('historical_content', 'exact_pack_bytes'),
    (17, 6): ('historical_content', 'exact_idx_bytes'),
    (17, 7): ('historical_content', 'write_pack'),
    (17, 8): ('historical_content', 'write_idx'),
    (17, 9): ('historical_content', 'cat_file'),
    (18, 1): ('nonowner_read', 'ledger_baseline'),
    (18, 2): ('nonowner_read', 'read_result'),
    (18, 3): ('nonowner_read', 'exact_not_found_match'),
    (18, 4): ('nonowner_read', 'ledger_read'),
    (18, 5): ('nonowner_read', 'unchanged_assert'),
    (19, 1): ('tenant_read_refusal', 'read_result'),
    (19, 2): ('tenant_read_refusal', 'refused_assert'),
    (19, 3): ('tenant_read_refusal', 'ledger_read'),
    (19, 4): ('tenant_read_refusal', 'unchanged_assert'),
    (20, 1): ('nonowner_materialize', 'materialize_result'),
    (20, 2): ('nonowner_materialize', 'exact_not_found_match'),
    (20, 3): ('nonowner_materialize', 'ledger_read'),
    (20, 4): ('nonowner_materialize', 'unchanged_assert'),
    (21, 1): ('tenant_materialize_refusal', 'materialize_result'),
    (21, 2): ('tenant_materialize_refusal', 'refused_assert'),
    (21, 3): ('tenant_materialize_refusal', 'ledger_read'),
    (21, 4): ('tenant_materialize_refusal', 'unchanged_assert'),
    (22, 1): ('role_revoke_read', 'set_role'),
    (22, 2): ('role_revoke_read', 'read_result'),
    (22, 3): ('role_revoke_read', 'exact_common_forbidden_assert'),
    (22, 4): ('role_revoke_read', 'ledger_read'),
    (22, 5): ('role_revoke_read', 'unchanged_assert'),
    (23, 1): ('role_revoke_materialize', 'materialize_result'),
    (23, 2): ('role_revoke_materialize', 'exact_common_forbidden_assert'),
    (23, 3): ('role_revoke_materialize', 'ledger_read'),
    (23, 4): ('role_revoke_materialize', 'unchanged_assert'),
    (24, 1): ('finish', 'finish_and_teardown'),
}

# Finite, platform-independent signal vocabulary used only to label a negative
# child return code.  Unknown numbers stay numeric without a symbolic label.
_SIGNAL_NAMES = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
    6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1",
    11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM",
    15: "SIGTERM", 16: "SIGSTKFLT", 17: "SIGCHLD", 18: "SIGCONT",
    19: "SIGSTOP", 20: "SIGTSTP", 21: "SIGTTIN", 22: "SIGTTOU",
    23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ", 26: "SIGVTALRM",
    27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO", 30: "SIGPWR", 31: "SIGSYS",
}

_CASE_LINE = re.compile(r"test (.+) \.\.\. (ok|FAILED|failed|ignored|bench)")
_SUMMARY_LINE = re.compile(
    r"test result: (ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;"
    r"(?:\s+(\d+) measured;)?(?:\s+(\d+) filtered out;)?")


class RunnerError(ValueError):
    def __init__(self, code, diagnostic=None):
        super().__init__(code)
        self.code = code
        # Safe, already-projected data only.  Raw child output, messages,
        # panic text, SQL and credentials are never attached to the exception.
        self.diagnostic = diagnostic
        self.failed_target = diagnostic


def _fail(code):
    raise RunnerError(code)


def _require(condition, code):
    if not condition:
        _fail(code)


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _pairs(values, label):
    result = {}
    for value in values or []:
        name, separator, item = str(value).partition("=")
        _require(bool(separator and name and item), "invalid_" + label)
        _require(name not in result, "duplicate_" + label)
        result[name] = item
    return result


def _file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def input_hashes(source_root):
    base = Path(source_root).resolve()
    result = {}
    for relative in inventory.closure(base):
        path = base / relative
        if not path.is_file() or path.is_symlink():
            _fail("input_closure_unavailable")
        result[relative] = _file_sha(path)
    return result


def validate_target_set(targets, receipts_by_name):
    expected = set(inventory.TARGET_ORDER)
    _require(set(targets) == expected, "target_set_mismatch")
    _require(set(receipts_by_name) == expected, "receipt_set_mismatch")
    _require(len(targets) == len(expected) and len(receipts_by_name) == len(expected),
             "duplicate_target")


def _required_environment(target):
    names = inventory.TARGETS[target]["required_env"]
    missing = [name for name in names if not os.environ.get(name)]
    _require(not missing, "missing_required_environment")


_CONFIG_DEBUG = re.compile(r"profile\.(dev|test)\.package\.rootyard\.debug=(0|1|2)")
_CONFIG_STRIP = re.compile(r'profile\.(dev|test)\.package\.rootyard\.strip="debuginfo"')
_CONFIG_TARGET_DIR = re.compile(r'build\.target-dir\s*=\s*"([^"\n\r\x00]+)"')


def _validate_config_override(value, seen):
    """Narrow allowlist for the inline TOML configs emitted by the preparers."""
    _require(isinstance(value, str) and bool(value.strip()), "command_config_value")
    target_dir = _CONFIG_TARGET_DIR.fullmatch(value)
    if target_dir is not None:
        path = target_dir.group(1)
        _require(path and Path(path).is_absolute(), "command_config_path")
        key = "build.target-dir"
    elif _CONFIG_DEBUG.fullmatch(value) is not None:
        key = value.split("=", 1)[0]
    elif _CONFIG_STRIP.fullmatch(value) is not None:
        key = value.split("=", 1)[0]
    else:
        _fail("command_config_unsupported")
    _require(key not in seen, "command_config_duplicate")
    seen.add(key)


def validate_target_build_command(command, target, cfg):
    """Validate the narrow Cargo argv forms emitted by the native preparers.

    Supported positive producers are build_native_test (`cargo rustc --locked
    --profile test --test TARGET ...`), build_native_batch (`cargo build
    --locked --profile test ... --test TARGET ...`) and a canonical
    `cargo test --no-run --test TARGET ...`. Cargo may be an absolute trusted
    executable. Only the emitted flag vocabulary is accepted; duplicate or
    contradictory forms fail closed.
    """
    _require(isinstance(command, list) and bool(command)
             and all(isinstance(arg, str) and bool(arg) for arg in command),
             "command_invalid_argv")
    _require(Path(command[0]).name in ("cargo", "cargo.exe"), "command_cargo_missing")
    command_index = 1
    subcommand = None
    seen = set()
    test_targets = []
    features = None
    profile = None
    no_default_features = False
    all_features = False
    release = False
    no_run = False
    config_keys = set()

    def value_at(index, token, name):
        flag, separator, inline = token.partition("=")
        _require(flag == name, "command_unsupported_flag")
        if separator:
            return inline, index + 1
        _require(index + 1 < len(command) and not command[index + 1].startswith("--"),
                 "command_missing_value")
        return command[index + 1], index + 2

    while command_index < len(command):
        token = command[command_index]
        name, separator, inline = token.partition("=")
        if subcommand is None:
            if not separator and token in ("rustc", "build", "test"):
                subcommand = token
                command_index += 1
                continue
            if name == "--config":
                value, command_index = value_at(command_index, token, "--config")
                _require(bool(value), "command_missing_value")
                _validate_config_override(value, config_keys)
                continue
            _fail("command_not_test_build")

        if name in ("--config",):
            value, command_index = value_at(command_index, token, "--config")
            _require(bool(value), "command_missing_value")
            _validate_config_override(value, config_keys)
            continue
        if name in ("--locked", "--offline"):
            _require(not separator, "command_ambiguous_flag")
            _require(name not in seen, "command_ambiguous_flag")
            seen.add(name)
            command_index += 1
            continue
        if name in ("--release", "--all-features", "--no-default-features", "--no-run"):
            _require(not separator, "command_ambiguous_flag")
            _require(name not in seen, "command_ambiguous_flag")
            seen.add(name)
            if name == "--release":
                release = True
            elif name == "--all-features":
                all_features = True
            elif name == "--no-default-features":
                no_default_features = True
            else:
                no_run = True
            command_index += 1
            continue
        if name in ("--test", "--features", "--profile", "--message-format", "--bin", "--jobs"):
            value, command_index = value_at(command_index, token, name)
            _require(bool(value), "command_missing_value")
            if name == "--test":
                _require(value not in test_targets, "command_ambiguous_flag")
                test_targets.append(value)
            elif name == "--features":
                _require(features is None, "command_ambiguous_flag")
                features = value
            elif name == "--profile":
                _require(profile is None, "command_ambiguous_flag")
                profile = value
            elif name == "--jobs":
                _require(name not in seen, "command_ambiguous_flag")
                _require(re.fullmatch(r"[1-9][0-9]*", value) is not None, "command_jobs_invalid")
                seen.add(name)
            elif name == "--message-format":
                _require(name not in seen, "command_ambiguous_flag")
                seen.add(name)
            elif name == "--bin":
                # A batch may build dependency binaries alongside the selected test.
                pass
            continue
        _fail("command_unsupported_flag")

    _require(subcommand in ("rustc", "build", "test"), "command_not_test_build")
    if subcommand == "test":
        _require(no_run, "command_no_run_required")
    else:
        _require(not no_run, "command_no_run_unsupported")
    _require(not release, "command_release_forbidden")
    if profile is not None:
        _require(profile == "test", "command_profile_mismatch")
    elif subcommand != "test":
        _fail("command_profile_mismatch")
    _require(not all_features, "command_all_features_forbidden")
    if cfg["no_default_features"] is False:
        _require(not no_default_features, "command_no_default_forbidden")
    if len(test_targets) == 1:
        _require(test_targets[0] == target, "command_test_target_mismatch")
    else:
        expected_targets = set(inventory.TARGET_ORDER)
        _require(len(test_targets) == len(expected_targets)
                 and len(test_targets) == len(set(test_targets))
                 and set(test_targets) == expected_targets
                 and target in test_targets,
                 "command_test_target_set_mismatch")
    _require(features is not None, "command_missing_features")
    parsed = features.split(",")
    _require(parsed and all(part and part == part.strip() for part in parsed),
             "command_features_invalid")
    _require(len(parsed) == len(set(parsed)), "command_features_invalid")
    _require(set(parsed) == set(cfg["features"]), "command_features_mismatch")
    return {"subcommand": subcommand, "test_targets": tuple(test_targets)}


def _receipt_identity(target, binary, receipt, source_root, source_head):
    cfg = inventory.TARGETS[target]
    _require(Path(receipt).resolve() == Path(binary).with_suffix(".build.json").resolve(),
             "target_receipt_not_adjacent")
    try:
        validated = receipts.load_receipt(
            receipt,
            source_root=source_root,
            binary_path=binary,
            expected_commit=source_head,
            verify_source_files=True,
        )
    except Exception:
        _fail("target_receipt_invalid")
    _require(validated.schema == "v2", "target_receipt_not_v2")
    _require(validated.workspace_commit == source_head, "wrong_target_source")
    _require(validated.binary_sha256 == _file_sha(binary), "wrong_target_binary")
    _require(_sha(validated.source_inputs_sha256), "invalid_target_source_digest")
    _require(bool(validated.receipt_sha256), "invalid_target_receipt_hash")
    payload = validated.payload
    _require(payload.get("kind") == cfg["kind"], "wrong_target_kind")
    _require(payload.get("integration_test_source") == cfg["source"], "wrong_target_source_file")
    _require(payload.get("profile") == cfg["profile"], "wrong_target_profile")
    features = payload.get("features")
    _require(isinstance(features, dict), "missing_target_features")
    _require(set(features.get("enabled") or []) == set(cfg["features"]),
             "wrong_target_features")
    _require(features.get("no_default_features") is cfg["no_default_features"],
             "wrong_target_default_features")
    command = payload.get("command")
    command_shape = validate_target_build_command(command, target, cfg)
    artifacts = [row for row in validated.artifacts
                 if isinstance(row, dict) and row.get("target") == target
                 and row.get("kind") == "test"]
    _require(len(artifacts) == 1, "target_artifact_mismatch")
    return {
        "target": target,
        "binary": str(Path(binary).resolve()),
        "receipt": str(Path(receipt).resolve()),
        "binary_sha256": validated.binary_sha256,
        "receipt_sha256": validated.receipt_sha256,
        "source_inputs_sha256": validated.source_inputs_sha256,
        "config_digest": validated.config_digest,
        "kind": payload.get("kind"),
        "profile": payload.get("profile"),
        "test_count": len(cfg["cases"]),
        "required_env": list(cfg["required_env"]),
        "command_test_targets": list(command_shape["test_targets"]),
    }


def _kill_group(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def _returncode_detail(returncode):
    """Return (numeric, signal, finite signal name) without child text."""
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        return None, None, None
    if returncode >= 0:
        return returncode, None, None
    number = -returncode
    return returncode, number, _SIGNAL_NAMES.get(number)


def _bounded_int(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not -2_147_483_648 <= value <= 2_147_483_647:
        return None
    return value


def _normalize_failure_context(target, phase, selected_case):
    """Validate caller-owned phase context without reading argv or output."""
    _require(target in inventory.TARGETS, "unknown_target")
    _require(phase in FAILURE_PHASES, "invalid_failure_phase")
    cases = inventory.TARGETS[target]["cases"]
    if phase == "list":
        return {"target": target, "phase": phase, "selected_case": None,
                "selected_case_known": False}
    known = selected_case in set(cases)
    return {
        "target": target,
        "phase": phase,
        "selected_case": selected_case if known else None,
        "selected_case_known": known,
    }


def _metadata_replay_unknown(invalid=False):
    """Fixed checkpoint shape used when no trusted frame is available."""
    return {
        "protocol": METADATA_REPLAY_PROTOCOL,
        "known": False,
        "incomplete": True,
        "invalid": bool(invalid),
        "frames": 0,
        "last_enter": None,
        "last_completed": None,
        "first_failure": None,
        "last_incomplete": None,
        "last_event": None,
        "primary": None,
        "cleanup_completed": False,
        "status": None,
        "counts": None,
        "checks": None,
        "iteration": None,
        "error_kind": None,
    }


METADATA_REPLAY_TRACE_KEYS = frozenset(_metadata_replay_unknown())
METADATA_REPLAY_FRAME_KEYS = frozenset({
    "phase", "site", "phase_name", "site_name", "event", "ok", "status",
    "counts", "checks", "iteration", "error_kind",
})


def _metadata_replay_location(phase, site):
    names = METADATA_REPLAY_SITES.get((phase, site))
    if names is None:
        return None
    return {
        "phase": phase,
        "site": site,
        "phase_name": names[0],
        "site_name": names[1],
    }


def _metadata_replay_uint(value, minimum, maximum):
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise ValueError
    number = int(value)
    if not minimum <= number <= maximum:
        raise ValueError
    return number


def _metadata_replay_optional_uint(value, minimum, maximum):
    if value == "":
        return None
    return _metadata_replay_uint(value, minimum, maximum)


def _metadata_replay_optional_bool(value):
    if value == "":
        return None
    if value == "1":
        return True
    if value == "0":
        return False
    raise ValueError


def _metadata_replay_counts(value):
    if value == "":
        return None
    parts = value.split(",")
    if len(parts) != 5:
        raise ValueError
    return [_metadata_replay_uint(part, 0, METADATA_REPLAY_MAX_COUNTS) for part in parts]


def _metadata_replay_checks(value):
    if value == "":
        return None
    parts = value.split(",")
    if not 1 <= len(parts) <= METADATA_REPLAY_MAX_CHECKS:
        raise ValueError
    checks = []
    for part in parts:
        if part not in ("0", "1"):
            raise ValueError
        checks.append(part == "1")
    return checks


def _metadata_replay_error_kind(value):
    if value == "":
        return None
    number = _metadata_replay_uint(value, 1, METADATA_REPLAY_MAX_ERROR_KIND)
    if number not in METADATA_REPLAY_ERROR_KINDS:
        raise ValueError
    return number


class _HistoricalTraceState:
    """Closed phase-17 subflow nested under the site-1 wrapper.

    The producer keeps site 1 open while emitting sites 3, 4, then one or more
    pack groups in actual operation order 5 -> 7 -> 6 -> 8, then site 9, then
    closes site 1. A failed child is followed directly by the failed parent.
    Site 2 runs only after a successful parent close.
    """

    def __init__(self):
        self.parent = None
        self.child = None
        self.assert_frame = None
        self.stage = "idle"
        self.packs = 0
        self.parent_success = False
        self.assert_failed = False

    def current_open(self):
        if self.child is not None:
            return self.child
        if self.parent is not None:
            return self.parent
        if self.stage == "assert_open":
            return self.assert_frame
        return None

    def _child_enter_allowed(self, site):
        if site == 3:
            return self.stage == "git_repo"
        if site == 4:
            return self.stage == "pack_dir"
        if site == 5:
            return self.stage in ("pack_start", "next_pack")
        if site == 7:
            return self.stage == "pack_bytes_complete"
        if site == 6:
            return self.stage == "write_pack_complete"
        if site == 8:
            return self.stage == "idx_bytes_complete"
        if site == 9:
            return self.stage == "next_pack" and self.packs > 0
        return False

    def _child_complete_stage(self, site):
        if site == 3:
            return "pack_dir"
        if site == 4:
            return "pack_start"
        if site == 5:
            return "pack_bytes_complete"
        if site == 7:
            return "write_pack_complete"
        if site == 6:
            return "idx_bytes_complete"
        if site == 8:
            return "next_pack"
        return "cat_file_complete"

    def feed(self, frame):
        phase, site, event, ok = (
            frame["phase"], frame["site"], frame["event"], frame["ok"])
        if phase != 17:
            if self.parent is not None:
                return False
            if self.stage in ("expect_assert", "assert_open"):
                return False
            if self.stage == "done" and (
                    not self.parent_success or self.assert_failed):
                # A failed historical parent or failed site-2 predicate is
                # followed only by phase-24 cleanup.
                return phase == MAX_METADATA_REPLAY_PHASE
            return True
        if frame["iteration"] is not None:
            # No phase-17 child/parent frame declares a loop index.
            return False
        if site == 1:
            if event == 0:
                if self.stage != "idle":
                    return False
                self.parent = frame
                self.stage = "git_repo"
                return True
            if event != 1 or self.parent is None or self.child is not None:
                return False
            if self.stage == "cat_file_complete" and ok is True:
                self.parent_success = True
                self.stage = "expect_assert"
            elif self.stage == "failed" and ok is False:
                self.parent_success = False
                self.stage = "done"
            else:
                return False
            self.parent = None
            return True
        if site == 2:
            if self.stage == "expect_assert" and event == 0:
                self.assert_frame = frame
                self.stage = "assert_open"
                return True
            if self.stage == "assert_open" and event in (1, 2):
                if event == 1 and ok is not True:
                    return False
                if event == 2 and ok is not False:
                    return False
                self.assert_failed = event == 2
                self.assert_frame = None
                self.stage = "done"
                return True
            return False
        if site not in (3, 4, 5, 6, 7, 8, 9):
            return False
        if self.parent is None or self.stage in (
                "expect_assert", "assert_open", "done"):
            return False
        if event == 0:
            if self.child is not None or not self._child_enter_allowed(site):
                return False
            self.child = frame
            return True
        if event != 1 or self.child is None or self.child["site"] != site:
            return False
        self.child = None
        if ok is False:
            self.stage = "failed"
            return True
        self.stage = self._child_complete_stage(site)
        if site == 8:
            self.packs += 1
        return True


def _parse_metadata_replay_trace(text):
    """Parse complete fixed frames only; raw rejected text is never retained."""
    trace = _metadata_replay_unknown()
    if not text:
        return trace
    lines = text.splitlines()
    trailing_newline = text.endswith("\n")
    open_frame = None
    last_phase = 0
    last_site = 0
    frame_count = 0
    truncated = False
    historical = _HistoricalTraceState()
    for index, line in enumerate(lines):
        if not line.startswith(METADATA_REPLAY_PREFIX):
            continue
        frame_count += 1
        trace["frames"] = frame_count
        if frame_count > METADATA_REPLAY_MAX_FRAMES:
            return _metadata_replay_unknown(invalid=True)
        if len(line) > METADATA_REPLAY_MAX_LINE:
            return _metadata_replay_unknown(invalid=True)
        if index == len(lines) - 1 and not trailing_newline:
            truncated = True
            break
        try:
            parts = line.split("|")
            if len(parts) != 10 or parts[0] != METADATA_REPLAY_PREFIX:
                raise ValueError
            phase = _metadata_replay_uint(parts[1], 1, MAX_METADATA_REPLAY_PHASE)
            site = _metadata_replay_uint(parts[2], 1, 255)
            if (phase, site) not in METADATA_REPLAY_SITES:
                raise ValueError
            event = _metadata_replay_uint(parts[3], 0, 2)
            ok = _metadata_replay_optional_bool(parts[4])
            status = _metadata_replay_optional_uint(parts[5], 100, 599)
            counts = _metadata_replay_counts(parts[6])
            checks = _metadata_replay_checks(parts[7])
            iteration = _metadata_replay_optional_uint(parts[8], 0, METADATA_REPLAY_MAX_ITERATION)
            error_kind = _metadata_replay_error_kind(parts[9])
            if event == 0 and ok is not None:
                raise ValueError
            if event == 1 and ok is None:
                raise ValueError
            if event == 2 and ok is not False:
                raise ValueError
            frame = _metadata_replay_location(phase, site)
            if frame is None:
                raise ValueError
            frame.update({
                "event": event,
                "ok": ok,
                "status": status,
                "counts": counts,
                "checks": checks,
                "iteration": iteration,
                "error_kind": error_kind,
            })
            if phase < last_phase:
                raise ValueError
            if not historical.feed(frame):
                raise ValueError
            if phase == 17:
                open_frame = historical.current_open()
            else:
                if phase == last_phase and site < last_site:
                    raise ValueError
                if open_frame is not None:
                    if event == 0:
                        if phase != MAX_METADATA_REPLAY_PHASE or open_frame["phase"] == MAX_METADATA_REPLAY_PHASE:
                            raise ValueError
                        trace["last_incomplete"] = open_frame
                        open_frame = None
                    else:
                        if open_frame["phase"] != phase or open_frame["site"] != site:
                            raise ValueError
                        open_frame = None
                elif event != 0:
                    raise ValueError
        except ValueError:
            return _metadata_replay_unknown(invalid=True)
        trace["last_event"] = frame
        if event == 0:
            open_frame = frame
            trace["last_enter"] = frame
        elif event == 1:
            trace["last_completed"] = frame
            if ok is False and trace["first_failure"] is None:
                trace["first_failure"] = frame
        else:
            if trace["first_failure"] is None:
                trace["first_failure"] = frame
        last_phase = phase
        last_site = site
    trace["frames"] = frame_count
    if frame_count == 0:
        return trace
    if historical.stage == "expect_assert":
        # A successful site-1 parent must be followed by the site-2 exact
        # content predicate; a bare parent completion is a disallowed skip.
        return _metadata_replay_unknown(invalid=True)
    trace["known"] = trace["last_event"] is not None
    trace["incomplete"] = truncated or open_frame is not None
    if open_frame is not None and not (
        open_frame["phase"] == MAX_METADATA_REPLAY_PHASE and trace["last_incomplete"] is not None
    ):
        trace["last_incomplete"] = open_frame
    primary = trace["first_failure"]
    if primary is not None and primary["phase"] == MAX_METADATA_REPLAY_PHASE and trace["last_incomplete"] is not None:
        primary = trace["last_incomplete"]
    if primary is None:
        primary = trace["last_incomplete"] or trace["last_event"]
    trace["primary"] = primary
    if primary is not None:
        for key in ("status", "counts", "checks", "iteration", "error_kind"):
            trace[key] = primary.get(key)
    trace["cleanup_completed"] = (
        trace["last_completed"] is not None
        and trace["last_completed"]["phase"] == MAX_METADATA_REPLAY_PHASE
        and trace["last_completed"]["ok"] is True
    )
    return trace


def _safe_metadata_replay_optional_int(value, minimum, maximum):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError
    if not minimum <= value <= maximum:
        raise ValueError
    return value


def _safe_metadata_replay_error_kind(value):
    number = _safe_metadata_replay_optional_int(
        value, 1, METADATA_REPLAY_MAX_ERROR_KIND)
    if number is not None and number not in METADATA_REPLAY_ERROR_KINDS:
        raise ValueError
    return number


def _safe_metadata_replay_counts(value):
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 5:
        raise ValueError
    counts = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= METADATA_REPLAY_MAX_COUNTS:
            raise ValueError
        counts.append(item)
    return counts


def _safe_metadata_replay_checks(value):
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= METADATA_REPLAY_MAX_CHECKS:
        raise ValueError
    if not all(isinstance(item, bool) for item in value):
        raise ValueError
    return list(value)


def _safe_metadata_replay_frame(value):
    if not isinstance(value, dict):
        raise ValueError
    if set(value) != METADATA_REPLAY_FRAME_KEYS:
        raise ValueError
    phase = value.get("phase")
    site = value.get("site")
    if isinstance(phase, bool) or not isinstance(phase, int) or not 1 <= phase <= MAX_METADATA_REPLAY_PHASE:
        raise ValueError
    if isinstance(site, bool) or not isinstance(site, int) or (phase, site) not in METADATA_REPLAY_SITES:
        raise ValueError
    event = value.get("event")
    if isinstance(event, bool) or not isinstance(event, int) or event not in (0, 1, 2):
        raise ValueError
    ok = value.get("ok")
    if ok is not None and not isinstance(ok, bool):
        raise ValueError
    if event == 0 and ok is not None:
        raise ValueError
    if event == 1 and ok is None:
        raise ValueError
    if event == 2 and ok is not False:
        raise ValueError
    frame = _metadata_replay_location(phase, site)
    if frame is None:
        raise ValueError
    frame.update({
        "event": event,
        "ok": ok,
        "status": _safe_metadata_replay_optional_int(value.get("status"), 100, 599),
        "counts": _safe_metadata_replay_counts(value.get("counts")),
        "checks": _safe_metadata_replay_checks(value.get("checks")),
        "iteration": _safe_metadata_replay_optional_int(value.get("iteration"), 0, METADATA_REPLAY_MAX_ITERATION),
        "error_kind": _safe_metadata_replay_error_kind(
            value.get("error_kind")),
    })
    return frame


def _safe_metadata_replay_frame_field(raw, key):
    value = raw.get(key)
    if value is None:
        return None
    return _safe_metadata_replay_frame(value)


def _safe_metadata_replay_trace(raw):
    """Rebuild the checkpoint from fixed fields before persistence."""
    if not isinstance(raw, dict) or raw.get("protocol") != METADATA_REPLAY_PROTOCOL:
        return None
    if set(raw) != METADATA_REPLAY_TRACE_KEYS:
        return _metadata_replay_unknown(invalid=True)
    try:
        frames = _safe_metadata_replay_optional_int(raw.get("frames"), 0, METADATA_REPLAY_MAX_FRAMES)
        if frames is None:
            raise ValueError
        known = raw.get("known")
        incomplete = raw.get("incomplete")
        invalid = raw.get("invalid")
        if not isinstance(known, bool) or not isinstance(incomplete, bool) or not isinstance(invalid, bool):
            raise ValueError
        last_enter = _safe_metadata_replay_frame_field(raw, "last_enter")
        last_completed = _safe_metadata_replay_frame_field(raw, "last_completed")
        first_failure = _safe_metadata_replay_frame_field(raw, "first_failure")
        last_incomplete = _safe_metadata_replay_frame_field(raw, "last_incomplete")
        last_event = _safe_metadata_replay_frame_field(raw, "last_event")
        if last_enter is not None and last_enter["event"] != 0:
            raise ValueError
        if last_completed is not None and last_completed["event"] != 1:
            raise ValueError
        if last_incomplete is not None and last_incomplete["event"] != 0:
            raise ValueError
        if first_failure is not None and not (
            first_failure["event"] == 2
            or (first_failure["event"] == 1 and first_failure["ok"] is False)
        ):
            raise ValueError
        if known and last_event is None:
            raise ValueError
        if invalid or frames == 0:
            known = False
            incomplete = True
        cleanup_completed = (
            last_completed is not None
            and last_completed["phase"] == MAX_METADATA_REPLAY_PHASE
            and last_completed["ok"] is True
        )
        result = _metadata_replay_unknown(invalid=invalid)
        result.update({
            "known": known,
            "incomplete": incomplete,
            "frames": frames,
            "last_enter": last_enter,
            "last_completed": last_completed,
            "first_failure": first_failure,
            "last_incomplete": last_incomplete,
            "last_event": last_event,
            "cleanup_completed": cleanup_completed,
        })
        primary = first_failure
        if primary is not None and primary["phase"] == MAX_METADATA_REPLAY_PHASE and last_incomplete is not None:
            primary = last_incomplete
        if primary is None:
            primary = last_incomplete or last_event
        result["primary"] = primary
        if primary is not None:
            for key in ("status", "counts", "checks", "iteration", "error_kind"):
                result[key] = primary.get(key)
        return result
    except (TypeError, ValueError):
        return _metadata_replay_unknown(invalid=True)


def _parse_caps():
    return {
        "output_bytes": MAX_CAPTURE_BYTES,
        "line_chars": MAX_DIAGNOSTIC_LINE_CHARS,
        "case_entries": MAX_DIAGNOSTIC_CASE_ENTRIES,
        "source_locations": MAX_SOURCE_LOCATIONS,
        "source_line": MAX_SOURCE_LINE,
    }


def _failure_base(context, returncode, timed_out):
    """Fixed context/exit/unknown shell, valid even when nothing is parsed."""
    target = context["target"]
    phase = context["phase"]
    expected = tuple(inventory.TARGETS[target]["cases"])
    numeric, signal_number, signal_name = _returncode_detail(returncode)
    return {
        "kind": FAILURE_KIND,
        "prefix": FAILURE_PREFIX,
        "source_prefix": SOURCE_PREFIX,
        "target": target,
        "phase": phase,
        "scope": "list" if phase == "list" else "case",
        "selected_case": context["selected_case"],
        "selected_case_known": context["selected_case_known"],
        "error_class": "native_timeout" if timed_out else "native_process_failed",
        "returncode": _bounded_int(numeric),
        "timed_out": bool(timed_out),
        "exit": {
            "returncode": _bounded_int(numeric),
            "signal": _bounded_int(signal_number),
            "signal_name": signal_name,
            "known": numeric is not None,
        },
        "cases": [],
        "case_counts": {"passed": 0, "failed": 0, "ignored": 0, "unknown": 0},
        "inventory": {
            "expected": len(expected),
            "observed": 0,
            "missing": len(expected),
            "unlisted": 0,
            "duplicate": 0,
            "malformed": 0,
            "reported_summary_lines": 0,
            "case_entries_truncated": False,
        },
        "unknown": {
            "missing_inventory_cases": len(expected),
            "unlisted_output_cases": 0,
            "duplicate_inventory_cases": 0,
            "malformed_output_lines": 0,
        },
        "libtest_summary": None,
        "source_locations": [],
        "source_allowlist": list(SOURCE_ALLOWLIST),
        "parse_caps": _parse_caps(),
        "case_trace": None,
    }


def project_target_failure(target, output, returncode, *, timed_out=False,
                           phase="run", selected_case=None, stderr=None):
    """Project separate stdout/stderr captures into a fixed safe shape.

    This is a pure RAM-only parser: it performs no IO, starts no process and
    never retries or extends a deadline.  Phase and selected case are supplied
    by the caller and are never inferred from argv or child output.  Libtest
    rows and summaries are read only from stdout; metadata frames and panic
    source locations are read only from stderr.  Only case names that are
    byte-equal to the frozen inventory, finite numeric counts, fixed
    error/signal labels, and repo-relative paths from ``SOURCE_ALLOWLIST`` are
    retained.  Everything else is dropped or counted as unknown, never as
    success.
    """
    context = _normalize_failure_context(target, phase, selected_case)
    diagnostic = _failure_base(context, returncode, timed_out)
    cfg = inventory.TARGETS[target]
    expected = tuple(cfg["cases"])
    expected_set = set(expected)

    case_rows = {}
    duplicate_names = set()
    source_locations = []
    source_seen = set()
    unlisted_count = 0
    duplicate_count = 0
    malformed_count = 0
    summary_count = 0
    reported_summary = None

    if stderr is None:
        stderr = b""
    text = output.decode("utf-8", "replace")
    stderr_text = stderr.decode("utf-8", "replace")
    metadata_replay_enabled = (
        context["target"] == METADATA_REPLAY_TARGET
        and context["phase"] == "run"
        and context["selected_case"] == METADATA_REPLAY_CASE
        and context["selected_case_known"]
    )
    if metadata_replay_enabled:
        diagnostic["case_trace"] = _parse_metadata_replay_trace(stderr_text)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if len(line) > MAX_DIAGNOSTIC_LINE_CHARS:
            line = line[:MAX_DIAGNOSTIC_LINE_CHARS]

        if line.startswith("test result:"):
            match = _SUMMARY_LINE.match(line)
            if match is None:
                malformed_count += 1
                continue
            summary_count += 1
            reported_summary = {
                "status": match.group(1),
                "passed": int(match.group(2)),
                "failed": int(match.group(3)),
                "ignored": int(match.group(4)),
                "measured": (int(match.group(5)) if match.group(5) is not None else None),
                "filtered_out": (int(match.group(6)) if match.group(6) is not None else None),
            }
            continue

        if line.startswith("test "):
            match = _CASE_LINE.fullmatch(line)
            if match is None:
                malformed_count += 1
                continue
            name, token = match.group(1), match.group(2)
            if name not in expected_set:
                unlisted_count += 1
                continue
            if name in duplicate_names:
                duplicate_count += 1
                continue
            if name in case_rows:
                # A repeated inventory name is never trusted as a pass: drop
                # the earlier observation and keep the name out of the cases.
                case_rows.pop(name, None)
                duplicate_names.add(name)
                duplicate_count += 1
                continue
            case_rows[name] = {
                "ok": "passed",
                "FAILED": "failed",
                "failed": "failed",
                "ignored": "ignored",
                "bench": "unknown",
            }[token]

    for raw_line in stderr_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if len(line) > MAX_DIAGNOSTIC_LINE_CHARS:
            line = line[:MAX_DIAGNOSTIC_LINE_CHARS]
        if len(source_locations) < MAX_SOURCE_LOCATIONS:
            for path in SOURCE_ALLOWLIST:
                if path not in line:
                    continue
                match = re.search(
                    re.escape(path) + r":([1-9][0-9]{0,7})(?::[0-9]{1,7})?", line)
                if match is None:
                    continue
                line_number = int(match.group(1))
                key = (path, line_number)
                if line_number > MAX_SOURCE_LINE or key in source_seen:
                    continue
                source_seen.add(key)
                source_locations.append({"file": path, "line": line_number})
                if len(source_locations) >= MAX_SOURCE_LOCATIONS:
                    break

    ordered = [
        {"name": name, "status": case_rows[name]}
        for name in expected if name in case_rows
    ]
    truncated_entries = len(ordered) > MAX_DIAGNOSTIC_CASE_ENTRIES
    if truncated_entries:
        ordered = ordered[:MAX_DIAGNOSTIC_CASE_ENTRIES]
    observed = len(case_rows)
    case_counts = {"passed": 0, "failed": 0, "ignored": 0, "unknown": 0}
    for row in ordered:
        case_counts[row["status"]] += 1
    missing = max(0, len(expected) - observed)

    diagnostic["cases"] = ordered
    diagnostic["case_counts"] = case_counts
    diagnostic["inventory"].update({
        "expected": len(expected),
        "observed": observed,
        "missing": missing,
        "unlisted": unlisted_count,
        "duplicate": duplicate_count,
        "malformed": malformed_count,
        "reported_summary_lines": summary_count,
        "case_entries_truncated": truncated_entries,
    })
    diagnostic["unknown"].update({
        "missing_inventory_cases": missing,
        "unlisted_output_cases": unlisted_count,
        "duplicate_inventory_cases": duplicate_count,
        "malformed_output_lines": malformed_count,
    })
    diagnostic["libtest_summary"] = reported_summary
    diagnostic["source_locations"] = source_locations
    return diagnostic


class _BoundedCapture:
    """Keep stdout and stderr apart while sharing one capture budget."""

    def __init__(self):
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.truncated = False
        self._lock = threading.Lock()

    def drain(self, stream, target):
        while True:
            try:
                chunk = stream.read(65536)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            with self._lock:
                room = (MAX_CAPTURE_BYTES - len(self.stdout)
                        - len(self.stderr))
                if room > 0:
                    target.extend(chunk[:room])
                if len(chunk) > room:
                    self.truncated = True


def _close_stream(stream):
    try:
        stream.close()
    except Exception:
        pass


def _reader_alive(reader):
    try:
        return bool(reader.is_alive())
    except Exception:
        # Treat an unreadable liveness state as still owned/blocked.
        return True


def _join_readers(readers):
    """Join all owned readers inside the one existing aggregate kill budget."""
    deadline = time.monotonic() + KILL_WAIT_SECONDS
    for reader in readers:
        try:
            reader.join(timeout=max(0.0, deadline - time.monotonic()))
        except RuntimeError:
            # A handle retained before start() may never have started; such a
            # Thread has no running reader and join() rejects it.
            continue
    _require(not any(_reader_alive(reader) for reader in readers),
             "cleanup_unresolved")


def _reap_process(process):
    if process.poll() is None:
        _kill_group(process)
        try:
            process.wait(timeout=KILL_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            _fail("cleanup_unresolved")


def _cleanup_startup(process, readers):
    """Bound startup cleanup without replacing its primary failure.

    A buffered pipe close may wait on a reader that owns the read lock, so no
    stream is closed until the owned process group has been killed/reaped and
    every reader has been joined under the existing aggregate deadline.
    """
    reaped = False
    try:
        _reap_process(process)
        reaped = True
    except Exception:
        pass
    joined = False
    try:
        _join_readers(readers)
        joined = True
    except Exception:
        pass
    if reaped and joined:
        _close_stream(process.stdout)
        _close_stream(process.stderr)


def _join_then_close(process, readers):
    """Never synchronously close a stream while its reader may still be live."""
    _join_readers(readers)
    _close_stream(process.stdout)
    _close_stream(process.stderr)


def _start_reader(readers, target, *args):
    """Create, retain, then start one reader so partial startup is cleanable."""
    reader = threading.Thread(target=target, args=args, daemon=True)
    readers.append(reader)
    reader.start()
    return reader


def run_bounded(command, timeout, env=None, failure_projector=None,
                failure_context=None):
    """Run one child in its own process group and capture bounded RAM only."""
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=env,
    )
    capture = _BoundedCapture()
    readers = []
    try:
        _start_reader(
            readers, capture.drain, process.stdout, capture.stdout)
        _start_reader(
            readers, capture.drain, process.stderr, capture.stderr)
    except BaseException:
        _cleanup_startup(process, readers)
        raise
    timed_out = False
    try:
        try:
            process.wait(timeout=max(0.0, timeout))
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(process)
            try:
                process.wait(timeout=KILL_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                _fail("cleanup_unresolved")
    finally:
        try:
            if process.poll() is None:
                _kill_group(process)
                try:
                    process.wait(timeout=KILL_WAIT_SECONDS)
                except subprocess.TimeoutExpired:
                    _fail("cleanup_unresolved")
        finally:
            _join_then_close(process, readers)
    _require(not capture.truncated, "native_output_too_large")
    if timed_out or process.returncode != 0:
        code = "native_timeout" if timed_out else "native_process_failed"
        diagnostic = None
        context = None
        if failure_context is not None:
            try:
                context = _normalize_failure_context(
                    failure_context.get("target"),
                    failure_context.get("phase"),
                    failure_context.get("selected_case"))
            except Exception:
                context = None
        if context is not None:
            try:
                diagnostic = project_target_failure(
                    context["target"], bytes(capture.stdout),
                    process.returncode, timed_out=timed_out,
                    phase=context["phase"],
                    selected_case=context["selected_case"],
                    stderr=bytes(capture.stderr))
            except Exception:
                # Context survives even if the parser itself fails.
                diagnostic = _failure_base(
                    context, process.returncode, timed_out)
        elif failure_projector is not None:
            try:
                diagnostic = failure_projector(
                    bytes(capture.stdout), bytes(capture.stderr),
                    process.returncode, timed_out)
            except Exception:
                # Projection must never replace or swallow the outer failure.
                diagnostic = None
        raise RunnerError(code, diagnostic)
    return bytes(capture.stdout)


def parse_listing(output):
    names = []
    for line in output.decode("utf-8", "replace").splitlines():
        match = re.fullmatch(r"([^:]+(?:::[^:]+)*): test", line.strip())
        if match:
            names.append(match.group(1))
    return names


def parse_case_result(output, name):
    text = output.decode("utf-8", "replace")
    _require(re.search(r"(?m)^test " + re.escape(name) + r" \.\.\. ok$", text) is not None,
             "test_not_executed")
    summary = re.search(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
    _require(summary is not None, "test_summary_missing")
    passed, failed, ignored = (int(value) for value in summary.groups())
    _require(passed == 1 and failed == 0 and ignored == 0, "test_partial_or_skipped")


def _list_target(binary, cfg, remaining, target=None):
    failure_context = None
    if target is not None:
        failure_context = {
            "target": target,
            "phase": "list",
            "selected_case": None,
        }
    output = run_bounded(
        [str(binary), "--list", "--ignored", "--format", "terse"],
        timeout=min(60.0, remaining), env=os.environ.copy(),
        failure_context=failure_context)
    actual = parse_listing(output)
    expected = list(cfg["cases"])
    _require(len(actual) == len(expected) and len(set(actual)) == len(actual)
             and set(actual) == set(expected), "static_inventory_mismatch")
    return actual


def _run_one(binary, name, remaining, case_seconds=DEFAULT_CASE_SECONDS, target=None):
    failure_context = None
    if target is not None:
        failure_context = {
            "target": target,
            "phase": "run",
            "selected_case": name,
        }
    output = run_bounded(
        [str(binary), name, "--exact", "--ignored", "--test-threads=1", "--format", "pretty"],
        timeout=min(case_seconds, remaining), env=os.environ.copy(),
        failure_context=failure_context)
    parse_case_result(output, name)


def validate_batch_command_consistency(identities):
    """A shared batch invocation must be recorded unchanged on all 11 receipts."""
    rows = list(identities.values()) if isinstance(identities, dict) else list(identities)
    multi = [row for row in rows if len(row.get("command_test_targets", [])) > 1]
    if not multi:
        return
    _require(len(multi) == len(inventory.TARGET_ORDER), "batch_command_inconsistent")
    expected = set(inventory.TARGET_ORDER)
    for row in rows:
        selectors = tuple(row.get("command_test_targets") or ())
        _require(len(selectors) == len(expected) and len(selectors) == len(set(selectors))
                 and set(selectors) == expected, "batch_command_target_set_mismatch")
    _require(len({tuple(row["command_test_targets"]) for row in rows}) == 1,
             "batch_command_inconsistent")


def _nonnegative_int(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _safe_source_locations(values):
    locations = []
    seen = set()
    for value in values or []:
        if not isinstance(value, dict):
            continue
        path = value.get("file")
        line = value.get("line")
        if path not in SOURCE_ALLOWLIST:
            continue
        if isinstance(line, bool) or not isinstance(line, int):
            continue
        if not 1 <= line <= MAX_SOURCE_LINE:
            continue
        key = (path, line)
        if key in seen:
            continue
        seen.add(key)
        locations.append({"file": path, "line": line})
        if len(locations) >= MAX_SOURCE_LOCATIONS:
            break
    return locations


def _safe_failure_diagnostic(diagnostic, target, observed_cases=None):
    """Rebuild the failure diagnostic from fixed fields before persistence."""
    expected = tuple(inventory.TARGETS[target]["cases"])
    allowed_names = set(expected)
    status_by_name = {}
    # The child that just failed is authoritative for its own case line, so it
    # is merged first.  Cases already completed in this target are then kept
    # honestly instead of being lost with the not-yet-appended report row.
    for row in diagnostic.get("cases") or []:
        if not isinstance(row, dict):
            continue
        name, status = row.get("name"), row.get("status")
        if name not in allowed_names or name in status_by_name:
            continue
        if status not in ("passed", "failed", "ignored", "unknown"):
            continue
        status_by_name[name] = status
    for row in observed_cases or []:
        if not isinstance(row, dict):
            continue
        name, status = row.get("name"), row.get("status")
        if name not in allowed_names or name in status_by_name:
            continue
        if status not in ("passed", "failed", "ignored", "unknown"):
            continue
        status_by_name[name] = status
    cases = [
        {"name": name, "status": status_by_name[name]}
        for name in expected if name in status_by_name
    ]
    cases = cases[:MAX_DIAGNOSTIC_CASE_ENTRIES]
    case_counts = {"passed": 0, "failed": 0, "ignored": 0, "unknown": 0}
    for row in cases:
        case_counts[row["status"]] += 1

    raw_inventory = diagnostic.get("inventory")
    raw_inventory = raw_inventory if isinstance(raw_inventory, dict) else {}
    missing = max(0, len(expected) - len(cases))
    unlisted = _nonnegative_int(raw_inventory.get("unlisted"))
    duplicate = _nonnegative_int(raw_inventory.get("duplicate"))
    malformed = _nonnegative_int(raw_inventory.get("malformed"))

    raw_exit = diagnostic.get("exit")
    raw_exit = raw_exit if isinstance(raw_exit, dict) else {}
    numeric = _bounded_int(raw_exit.get("returncode"))
    signal_number = _bounded_int(raw_exit.get("signal"))
    signal_name = _SIGNAL_NAMES.get(signal_number) if signal_number is not None else None

    raw_summary = diagnostic.get("libtest_summary")
    summary = None
    if isinstance(raw_summary, dict):
        status = raw_summary.get("status")
        if status in ("ok", "FAILED"):
            summary = {
                "status": status,
                "passed": _nonnegative_int(raw_summary.get("passed")),
                "failed": _nonnegative_int(raw_summary.get("failed")),
                "ignored": _nonnegative_int(raw_summary.get("ignored")),
                "measured": _bounded_int(raw_summary.get("measured")),
                "filtered_out": _bounded_int(raw_summary.get("filtered_out")),
            }

    timed_out = diagnostic.get("timed_out") is True
    error_class = diagnostic.get("error_class")
    if error_class not in ("native_process_failed", "native_timeout"):
        error_class = "native_timeout" if timed_out else "native_process_failed"
    raw_phase = diagnostic.get("phase")
    phase = raw_phase if raw_phase in FAILURE_PHASES else "unknown"
    if phase == "list":
        selected_case = None
        selected_case_known = False
    elif phase == "run":
        raw_selected = diagnostic.get("selected_case")
        selected_case_known = raw_selected in set(expected)
        selected_case = raw_selected if selected_case_known else None
    else:
        selected_case = None
        selected_case_known = False
    return {
        "kind": FAILURE_KIND,
        "prefix": FAILURE_PREFIX,
        "source_prefix": SOURCE_PREFIX,
        "target": target,
        "phase": phase,
        "scope": "list" if phase == "list" else ("case" if phase == "run" else "unknown"),
        "selected_case": selected_case,
        "selected_case_known": selected_case_known,
        "error_class": error_class,
        "returncode": numeric,
        "timed_out": timed_out,
        "exit": {
            "returncode": numeric,
            "signal": signal_number,
            "signal_name": signal_name,
            "known": numeric is not None,
        },
        "cases": cases,
        "case_counts": case_counts,
        "inventory": {
            "expected": len(expected),
            "observed": len(cases),
            "missing": missing,
            "unlisted": unlisted,
            "duplicate": duplicate,
            "malformed": malformed,
            "reported_summary_lines": _nonnegative_int(
                raw_inventory.get("reported_summary_lines")),
            "case_entries_truncated": len(status_by_name) > MAX_DIAGNOSTIC_CASE_ENTRIES,
        },
        "unknown": {
            "missing_inventory_cases": missing,
            "unlisted_output_cases": unlisted,
            "duplicate_inventory_cases": duplicate,
            "malformed_output_lines": malformed,
        },
        "libtest_summary": summary,
        "source_locations": _safe_source_locations(diagnostic.get("source_locations")),
        "source_allowlist": list(SOURCE_ALLOWLIST),
        "parse_caps": _parse_caps(),
        "case_trace": _safe_metadata_replay_trace(diagnostic.get("case_trace")),
    }


def _attach_failed_target(report, diagnostic, identities, observed_cases=None):
    target = diagnostic.get("target")
    if target not in inventory.TARGETS:
        return
    safe_diagnostic = _safe_failure_diagnostic(diagnostic, target, observed_cases)
    row = {
        "prefix": safe_diagnostic["prefix"],
        "target": target,
        "phase": safe_diagnostic["phase"],
        "selected_case": safe_diagnostic["selected_case"],
        "selected_case_known": safe_diagnostic["selected_case_known"],
        "passed": False,
        "status": "failed",
        "cases": safe_diagnostic["cases"],
        "case_count": len(safe_diagnostic["cases"]),
        "error_class": safe_diagnostic["error_class"],
        "exit": safe_diagnostic["exit"],
        "source_locations": safe_diagnostic["source_locations"],
        "case_trace": safe_diagnostic.get("case_trace"),
        "diagnostic": safe_diagnostic,
    }
    identity = (identities or {}).get(target) or {}
    for key in ("binary_sha256", "receipt_sha256", "source_inputs_sha256",
                "config_digest", "kind", "profile", "test_count"):
        if key in identity:
            row[key] = identity[key]
    rows = report.setdefault("targets", [])
    for index, existing in enumerate(rows):
        if existing.get("target") == target:
            rows[index] = row
            break
    else:
        rows.append(row)
    report["failed_target"] = safe_diagnostic
    report["case_count"] = sum(
        1 for item in rows for case in item.get("cases", [])
        if isinstance(case, dict) and case.get("status") == "passed")
    report["observed_case_count"] = sum(len(item.get("cases", [])) for item in rows)


def run_acceptance(source_head, source_root, targets, receipts_by_name,
                   report_path=None, overall_seconds=DEFAULT_OVERALL_SECONDS,
                   case_seconds=DEFAULT_CASE_SECONDS):
    validate_target_set(targets, receipts_by_name)
    _require(re.fullmatch(r"[0-9a-f]{40,64}", str(source_head)) is not None,
             "invalid_source_head")
    _require(Path(source_root).is_dir(), "missing_source_root")
    before = input_hashes(source_root)
    report = {
        "kind": REPORT_KIND,
        "passed": False,
        "measurement_kind": "native_execution",
        "simulated_fields": False,
        "source_head": source_head,
        "input_closure_sha256": before,
        "harness_inputs_before_sha256": before,
        "targets": [],
        "case_count": 0,
        "expected_count": sum(len(inventory.TARGETS[name]["cases"])
                              for name in inventory.TARGET_ORDER),
        "skips": 0,
        "pending_cases": [],
        "cleanup_unresolved": False,
        "error_codes": [],
    }
    deadline = time.monotonic() + max(0.1, float(overall_seconds))
    identities = {}
    completed_cases = []
    try:
        for target in inventory.TARGET_ORDER:
            _required_environment(target)
            binary = targets[target]
            receipt = receipts_by_name[target]
            _require(Path(binary).is_absolute() and Path(binary).is_file()
                     and os.access(binary, os.X_OK), "target_binary_missing")
            _require(Path(receipt).is_absolute() and Path(receipt).is_file(),
                     "target_receipt_missing")
            identities[target] = _receipt_identity(
                target, binary, receipt, source_root, source_head)
        validate_batch_command_consistency(identities)
        for target in inventory.TARGET_ORDER:
            remaining = deadline - time.monotonic()
            _require(remaining > 0, "overall_timeout")
            binary = targets[target]
            cfg = inventory.TARGETS[target]
            completed_cases = []
            _list_target(binary, cfg, remaining, target)
            for name in cfg["cases"]:
                remaining = deadline - time.monotonic()
                _require(remaining > 0, "overall_timeout")
                _run_one(binary, name, remaining, case_seconds, target)
                completed_cases.append({"name": name, "status": "passed"})
            report["targets"].append({
                **identities[target],
                "passed": True,
                "cases": completed_cases,
                "case_count": len(completed_cases),
            })
            report["case_count"] += len(completed_cases)
        _require(report["case_count"] == report["expected_count"],
                 "total_case_count_mismatch")
        after = input_hashes(source_root)
        report["input_closure_after_sha256"] = after
        _require(after == before, "input_closure_drift")
        report["passed"] = True
    except RunnerError as error:
        report["error_codes"] = [error.code]
        report["cleanup_unresolved"] = error.code == "cleanup_unresolved"
        diagnostic = getattr(error, "diagnostic", None)
        if isinstance(diagnostic, dict):
            try:
                _attach_failed_target(
                    report, diagnostic, identities, completed_cases)
            except Exception:
                # Never let a projection defect replace the outer failure.
                pass
    except Exception:
        report["error_codes"] = ["runner_failure"]
    try:
        after = input_hashes(source_root)
        report["input_closure_after_sha256"] = after
        if after != before:
            report["passed"] = False
            report["error_codes"] = sorted(set(report["error_codes"] + ["input_closure_drift"]))
    except Exception:
        report["passed"] = False
        report["error_codes"] = sorted(set(report["error_codes"] + ["input_closure_unavailable"]))
    if report_path:
        path = Path(report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        temporary.replace(path)
    return report


def validate_report(report, expected_source_head=None):
    """Pure report-shape validator for later CI integration."""
    _require(isinstance(report, dict), "report_not_object")
    _require(report.get("kind") == REPORT_KIND, "wrong_report_kind")
    _require(report.get("measurement_kind") == "native_execution", "not_native_execution")
    _require(report.get("simulated_fields") is False, "simulated_evidence")
    if expected_source_head is not None:
        _require(report.get("source_head") == expected_source_head, "wrong_source_head")
    _require([row.get("target") for row in report.get("targets", [])]
             == list(inventory.TARGET_ORDER), "target_order_mismatch")
    total = 0
    for row in report["targets"]:
        target = row.get("target")
        cfg = inventory.TARGETS[target]
        _require(row.get("passed") is True, "target_not_passed")
        _require(row.get("case_count") == len(cfg["cases"]), "target_case_count_mismatch")
        _require([case.get("name") for case in row.get("cases", [])]
                 == list(cfg["cases"]), "target_case_inventory_mismatch")
        _require(all(case.get("status") == "passed" for case in row.get("cases", [])),
                 "target_case_failed")
        total += len(cfg["cases"])
    case_count = report.get("case_count")
    expected_count = report.get("expected_count")
    _require(isinstance(case_count, int) and not isinstance(case_count, bool)
             and case_count == total, "total_case_count_mismatch")
    _require(isinstance(expected_count, int) and not isinstance(expected_count, bool)
             and expected_count == total, "total_case_count_mismatch")
    _require(isinstance(report.get("skips"), int) and not isinstance(report.get("skips"), bool)
             and report.get("skips") == 0, "skipped_cases")
    _require(report.get("pending_cases") == [], "pending_cases")
    _require(report.get("cleanup_unresolved") is False, "cleanup_unresolved")
    _require(report.get("error_codes") == [], "runner_errors")
    _require(report.get("passed") is True, "report_not_passed")
    _require(report.get("input_closure_sha256") == report.get("input_closure_after_sha256"),
             "input_closure_drift")
    return {"targets": len(report["targets"]), "cases": total}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--target", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--receipt", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--report")
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_OVERALL_SECONDS)
    parser.add_argument("--case-timeout-seconds", type=float, default=DEFAULT_CASE_SECONDS)
    args = parser.parse_args(argv)
    try:
        targets = _pairs(args.target, "target")
        receipt_paths = _pairs(args.receipt, "receipt")
        report = run_acceptance(
            args.source_head, args.source_root, targets, receipt_paths,
            report_path=args.report, overall_seconds=args.timeout_seconds,
            case_seconds=args.case_timeout_seconds)
    except RunnerError as error:
        print(json.dumps({"passed": False, "error": error.code}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"passed": False, "error": "runner_failure"}), file=sys.stderr)
        return 1
    print(json.dumps({"passed": report["passed"], "targets": len(report["targets"]),
                      "cases": report["case_count"], "errors": report["error_codes"]},
                     sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
