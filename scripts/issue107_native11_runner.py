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
    }


def project_target_failure(target, output, returncode, *, timed_out=False,
                           phase="run", selected_case=None):
    """Project captured child output into a fixed, privacy-preserving shape.

    This is a pure RAM-only parser: it performs no IO, starts no process and
    never retries or extends a deadline.  Phase and selected case are supplied
    by the caller and are never inferred from argv or child output.  Only case
    names that are byte-equal to the frozen inventory, finite numeric counts,
    fixed error/signal labels, and repo-relative paths from
    ``SOURCE_ALLOWLIST`` are retained.  Everything else is dropped or counted
    as unknown, never as success.
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

    text = output.decode("utf-8", "replace")
    for raw_line in text.splitlines():
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


def run_bounded(command, timeout, env=None, failure_projector=None,
                failure_context=None):
    """Run one child in its own process group and capture bounded RAM only."""
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=env,
    )
    captured = bytearray()
    truncated = [False]

    def drain():
        while True:
            chunk = process.stdout.read(65536)
            if not chunk:
                break
            room = MAX_CAPTURE_BYTES - len(captured)
            if room > 0:
                captured.extend(chunk[:room])
            if len(chunk) > room:
                truncated[0] = True

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
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
        if process.poll() is None:
            _kill_group(process)
            try:
                process.wait(timeout=KILL_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                _fail("cleanup_unresolved")
        try:
            process.stdout.close()
        except Exception:
            pass
    reader.join(timeout=KILL_WAIT_SECONDS)
    _require(not reader.is_alive(), "cleanup_unresolved")
    _require(not truncated[0], "native_output_too_large")
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
                    context["target"], bytes(captured), process.returncode,
                    timed_out=timed_out, phase=context["phase"],
                    selected_case=context["selected_case"])
            except Exception:
                # Context survives even if the parser itself fails.
                diagnostic = _failure_base(
                    context, process.returncode, timed_out)
        elif failure_projector is not None:
            try:
                diagnostic = failure_projector(
                    bytes(captured), process.returncode, timed_out)
            except Exception:
                # Projection must never replace or swallow the outer failure.
                diagnostic = None
        raise RunnerError(code, diagnostic)
    return bytes(captured)


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
