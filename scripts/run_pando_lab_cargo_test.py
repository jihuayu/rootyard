"""Run the isolated Pando Cargo test gate and write a bounded CI receipt."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile


CARGO_COMMAND = ("cargo", "test", "--locked", "--all-targets", "--features", "pando-lab")
RECEIPT = Path("test-results/pando-lab-cargo-test.json")
GIT_OID = re.compile(r"[0-9a-f]{40}")
MAX_LINE_BYTES = 4096
MAX_FAILED_TESTS = 8
MAX_HARNESSES = 64
# Closed checkpoint vocabulary for the sole named SHA256 watcher case. These
# literals are the only values projected from child output; no raw errors,
# paths, refs, URLs, digests, or arbitrary child text are retained here.
MERKLE_TEST = "sha256_watcher_converge_incremental_sync_and_cross_node_restore"
MERKLE_STAGES = frozenset({
    "setup",
    "seed",
    "base_capture",
    "incremental_fixture",
    "incremental_scan",
    "incremental_upload",
    "incremental_metrics",
    "remove",
    "restore_root",
    "restore_files",
    "fsck",
})
MERKLE_CLASSES = frozenset({
    "invalid_input",
    "invalid_manifest",
    "unsupported_git_state",
    "not_quiescent",
    "concurrent_edit",
    "access_denied",
    "tenant_scope_mismatch",
    "stale_history_fenced",
    "foreign_backend",
    "missing_artifact",
    "integrity_mismatch",
    "git_failed",
    "blob",
    "closure",
    "disposable_view",
    "io",
    "unknown",
})
SGR = re.compile(rb"\x1b\[[0-9;]*m")
IDENTIFIER = rb"[A-Za-z_][A-Za-z0-9_]*"
FAILED_TEST = re.compile(rb"test (?:" + IDENTIFIER + rb"::)*(" + IDENTIFIER + rb") \.\.\. FAILED")
RUNNING = re.compile(rb"running ([0-9]{1,9}) tests?")
MERKLE_TEST_BYTES = MERKLE_TEST.encode("ascii")
MARKER_PREFIX = b"rootyard-merkle-checkpoint"
MERKLE_CHECKPOINT = re.compile(
    rb"rootyard-merkle-checkpoint stage=("
    + rb"|".join(re.escape(code.encode("ascii")) for code in sorted(MERKLE_STAGES))
    + rb") class=("
    + rb"|".join(re.escape(code.encode("ascii")) for code in sorted(MERKLE_CLASSES))
    + rb")"
)
# Explicit bounded grammar for the pinned CargoFork 64a6ee6a test banners.
# Legacy layout keeps test executables under <profile>/deps; the default new
# build-dir layout uses <profile>/build/<package>/<hash>/out. Only the exact
# rootyard/workspace_merkle_sync identity may own the diagnostic:
#   tests/workspace_merkle_sync.rs -> deps/workspace_merkle_sync[-hash]
#   tests/workspace_merkle_sync.rs -> build/rootyard/<hash>/out/workspace_merkle_sync[-hash]
# No path is retained or printed; this grammar is only a boolean identity gate.
PATH_COMPONENT = rb"(?:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|\.[A-Za-z0-9_][A-Za-z0-9_.-]{0,126})"
PATH_PREFIX = rb"(?:/?" + PATH_COMPONENT + rb"/){0,16}"
PROFILE = rb"(?:debug|release)"
BUILD_HASH = rb"[0-9a-f]{8,64}"
BINARY = rb"[A-Za-z0-9_][A-Za-z0-9_-]{0,127}"
PACKAGE = rb"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
SOURCE_PATH = (
    rb"(?:src|tests|benches|examples)/"
    rb"(?:" + PATH_COMPONENT + rb"/){0,8}"
    rb"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\.rs"
)
LEGACY_EXE = PATH_PREFIX + PROFILE + rb"/deps/" + BINARY + rb"(?:-" + BUILD_HASH + rb")?"
NEW_EXE = (
    PATH_PREFIX + PROFILE + rb"/build/" + PACKAGE + rb"/" + BUILD_HASH
    + rb"/out/" + BINARY + rb"(?:-" + BUILD_HASH + rb")?"
)
GENERIC_EXE = rb"(?:" + LEGACY_EXE + rb"|" + NEW_EXE + rb")"
TARGET_LEGACY_EXE = (
    PATH_PREFIX + PROFILE + rb"/deps/workspace_merkle_sync(?:-" + BUILD_HASH + rb")?"
)
TARGET_NEW_EXE = (
    PATH_PREFIX + PROFILE + rb"/build/rootyard/" + BUILD_HASH
    + rb"/out/workspace_merkle_sync(?:-" + BUILD_HASH + rb")?"
)
TARGET_EXE = rb"(?:" + TARGET_LEGACY_EXE + rb"|" + TARGET_NEW_EXE + rb")"
TARGET_EXE_RE = re.compile(TARGET_EXE)
UNIT_HARNESS = re.compile(
    rb"^[ \t]*Running unittests (" + SOURCE_PATH + rb") \((" + GENERIC_EXE + rb")\)[ \t]*$"
)
TEST_HARNESS = re.compile(
    rb"^[ \t]*Running (" + SOURCE_PATH + rb") \((" + GENERIC_EXE + rb")\)[ \t]*$"
)
DOC_HARNESS = re.compile(rb"^[ \t]*Doc-tests [A-Za-z0-9_-]+[ \t]*$")
TARGET_SOURCE = b"tests/workspace_merkle_sync.rs"
TARGET_SECTION = re.compile(rb"---- " + re.escape(MERKLE_TEST_BYTES) + rb" stdout ----")
SECTION_HEADER = re.compile(rb"---- [^\r\n]+ (?:stdout|stderr) ----")
LIBTEST_SUMMARY = re.compile(
    rb"test result: (ok|FAILED)\. ([0-9]{1,9}) passed; ([0-9]{1,9}) failed; "
    rb"([0-9]{1,9}) ignored; ([0-9]{1,9}) measured; ([0-9]{1,9}) filtered out; "
    rb"finished in [0-9]{1,9}(?:\.[0-9]{1,9})?s"
)
CARGO_TEST_FAILED = re.compile(rb"error: test failed(?:, to rerun pass `[^`]+`)?")
MERKLE_FAILED_ROW = re.compile(rb"test " + re.escape(MERKLE_TEST_BYTES) + rb" \.\.\. FAILED")
# CargoFork cli_args() adds "-p <pkg> " only when needs_spec_flag(ws) is true;
# Packages::Default requires more than one default member. The rootyard manifest
# has one default package, so it emits the first exact form. The second is the
# sole explicitly allowed package-qualified variant if that workspace context
# changes; any other package or harness footer is foreign.
TARGET_FOOTERS = (
    b"error: test failed, to rerun pass `--test workspace_merkle_sync`",
    b"error: test failed, to rerun pass `-p rootyard --test workspace_merkle_sync`",
)
TEST_ATTRIBUTE = rb"^[ \t]*#\[(tokio::)?test([ \t]*\(|\])"
TEST_FUNCTION = re.compile(rb"[ \t]*(?:async[ \t]+)?fn[ \t]+(" + IDENTIFIER + rb")[ \t]*\(")
FAILURE_MARKERS = (
    ("compile", re.compile(rb"error: could not compile `[^`]+`.*")),
    ("test", CARGO_TEST_FAILED),
    ("test", re.compile(
        rb"test result: FAILED\. [0-9]{1,9} passed; [1-9][0-9]{0,8} failed; "
        rb"[0-9]{1,9} ignored; [0-9]{1,9} measured; [0-9]{1,9} filtered out; "
        rb"finished in [0-9]{1,9}(?:\.[0-9]{1,9})?s"
    )),
    ("infrastructure", re.compile(rb"error: could not execute process `[^`]+` \(never executed\)")),
)


class Harness:
    """Bounded libtest harness state used only to bind the named diagnostic."""

    def __init__(self, merkle):
        self.merkle = merkle
        self.running_seen = False
        self.running_count = None
        self.failures_seen = False
        self.in_case_rows = False
        self.failed_rows = []
        self.exact_failed_row = False
        self.rows_truncated = False
        self.summary_seen = False
        self.summary_status = None
        self.failed_count = None
        self.passed_count = None
        self.ignored_count = None
        self.measured_count = None
        self.filtered_count = None
        self.captured_any = False
        self.summary_list_seen = False
        self.target_seen = False
        self.captured_open = False
        self.captured_target = False
        self.markers = []
        self.target_footer_seen = False
        self.malformed = False


def bounded_lines_with_status(stream):
    while line := stream.readline(MAX_LINE_BYTES + 1):
        if len(line) <= MAX_LINE_BYTES and line.endswith(b"\n"):
            yield line.rstrip(b"\r\n"), False
        else:
            # Discard the whole oversized line, including marker-shaped suffixes,
            # but record that the stream was not fully inspected.
            while line and not line.endswith(b"\n"):
                line = stream.readline(MAX_LINE_BYTES + 1)
            yield b"", True


def bounded_lines(stream):
    for line, oversized in bounded_lines_with_status(stream):
        if not oversized:
            yield line


def classify_harness(line):
    """Return None for non-banners, False for foreign harnesses, True for target."""
    if DOC_HARNESS.fullmatch(line):
        return False
    if match := UNIT_HARNESS.fullmatch(line):
        source, executable = match[1], match[2]
    elif match := TEST_HARNESS.fullmatch(line):
        source, executable = match[1], match[2]
    else:
        return None
    return source == TARGET_SOURCE and TARGET_EXE_RE.fullmatch(executable) is not None


def git_oid(revision):
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "rev-parse", "--verify", revision],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0 and re.fullmatch(rb"[0-9a-f]{40}\n", result.stdout):
        return result.stdout[:-1].decode("ascii")
    return None


def source_binding(expected_commit):
    if not GIT_OID.fullmatch(expected_commit):
        return None, None
    commit = git_oid("HEAD^{commit}")
    if commit != expected_commit:
        return None, None
    tree = git_oid(f"{commit}^{{tree}}")
    return (commit, tree) if tree is not None else (None, None)


def source_test_names(commit):
    """Allow ordinary Rust and Tokio test names from committed source blobs."""
    command = [
        "git", "--no-replace-objects", "grep", "--no-color", "--no-line-number",
        "--break", "-h", "-I", "-E",
        "-A", "4", TEST_ATTRIBUTE.decode("ascii"), commit, "--", "src/*.rs", "tests/*.rs",
    ]
    names = set()
    try:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as git:
            after_attribute = False
            for line in bounded_lines(git.stdout):
                if re.match(TEST_ATTRIBUTE, line):
                    after_attribute = True
                elif after_attribute and not line.lstrip().startswith(b"#["):
                    match = TEST_FUNCTION.match(line)
                    if match:
                        names.add(match[1])
                    after_attribute = False
            return names if git.wait() == 0 else set()
    except OSError:
        return set()


def run_cargo(commit):
    phases = set()
    failed_tests = set()
    harnesses = []
    current = None
    unbound_marker = False
    stream_truncated = False
    too_many_harnesses = False
    foreign_footer = False
    truncated = False
    try:
        cargo = subprocess.Popen(
            CARGO_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
    except FileNotFoundError:
        return 127, "infrastructure", failed_tests, truncated, None
    except OSError:
        return 126, "infrastructure", failed_tests, truncated, None

    known_names = None
    in_case_rows = False
    with cargo:
        for raw_line, oversized in bounded_lines_with_status(cargo.stdout):
            if oversized:
                stream_truncated = True
                continue
            line = SGR.sub(b"", raw_line)
            for phase, marker in FAILURE_MARKERS:
                if marker.fullmatch(line):
                    phases.add(phase)

            if current is not None and current.captured_open:
                if classify_harness(line) is not None:
                    current.malformed = True
                    current.captured_open = False
                elif line == b"failures:" or SECTION_HEADER.fullmatch(line):
                    current.captured_open = False
                else:
                    if MARKER_PREFIX in line:
                        if current.captured_target:
                            match = MERKLE_CHECKPOINT.fullmatch(line)
                            if match and not current.markers:
                                current.markers.append(
                                    (match[1].decode("ascii"), match[2].decode("ascii"))
                                )
                            else:
                                current.malformed = True
                        else:
                            unbound_marker = True
                            current.malformed = True
                    continue

            if CARGO_TEST_FAILED.fullmatch(line):
                if (
                    current is not None
                    and current.merkle
                    and current.summary_seen
                    and line in TARGET_FOOTERS
                    and not current.target_footer_seen
                ):
                    current.target_footer_seen = True
                else:
                    foreign_footer = True
                    if current is not None:
                        current.malformed = True

            harness_merkle = classify_harness(line)
            if harness_merkle is not None:
                if len(harnesses) >= MAX_HARNESSES:
                    too_many_harnesses = True
                    current = None
                    in_case_rows = False
                    continue
                current = Harness(harness_merkle)
                harnesses.append(current)
                in_case_rows = False
                continue

            if current is not None and SECTION_HEADER.fullmatch(line):
                in_case_rows = False
                current.in_case_rows = False
                current.captured_any = True
                current.captured_open = True
                current.captured_target = current.merkle and bool(TARGET_SECTION.fullmatch(line))
                if not current.failures_seen or current.summary_seen or current.summary_list_seen:
                    current.malformed = True
                if current.captured_target:
                    if current.target_seen:
                        current.malformed = True
                    current.target_seen = True
                continue

            if MARKER_PREFIX in line:
                unbound_marker = True
                if current is not None:
                    current.malformed = True
                continue

            if running := RUNNING.fullmatch(line):
                in_case_rows = True
                if current is not None:
                    if current.running_seen or current.failures_seen or current.summary_seen:
                        current.malformed = True
                    current.running_seen = True
                    current.running_count = int(running[1])
                    current.in_case_rows = True
            elif line == b"failures:" or line.startswith(b"test result: "):
                in_case_rows = False
                if current is not None:
                    current.in_case_rows = False
                    if line == b"failures:":
                        if current.summary_seen:
                            current.malformed = True
                        if current.captured_any:
                            if current.summary_list_seen:
                                current.malformed = True
                            current.summary_list_seen = True
                        elif current.failures_seen:
                            current.malformed = True
                        current.failures_seen = True
                if summary := LIBTEST_SUMMARY.fullmatch(line):
                    if current is not None:
                        if current.summary_seen:
                            current.malformed = True
                        if summary[1] == b"FAILED" and not current.failures_seen:
                            current.malformed = True
                        if current.captured_any and not current.summary_list_seen:
                            current.malformed = True
                        current.summary_seen = True
                        current.summary_status = summary[1]
                        current.passed_count = int(summary[2])
                        current.failed_count = int(summary[3])
                        current.ignored_count = int(summary[4])
                        current.measured_count = int(summary[5])
                        current.filtered_count = int(summary[6])
            elif in_case_rows and (test := FAILED_TEST.fullmatch(line)):
                # Publish only the verified function name. Module text in the
                # harness output has no independent source binding.
                if known_names is None:
                    known_names = source_test_names(commit)
                name = test[1]
                if name in known_names and name not in failed_tests:
                    if len(failed_tests) < MAX_FAILED_TESTS:
                        failed_tests.add(name)
                    else:
                        truncated = True
                if current is not None and current.in_case_rows:
                    if not current.rows_truncated:
                        if len(current.failed_rows) < MAX_FAILED_TESTS:
                            current.failed_rows.append(test[1])
                        else:
                            current.rows_truncated = True
                    if current.merkle and MERKLE_FAILED_ROW.fullmatch(line):
                        if current.exact_failed_row:
                            current.malformed = True
                        current.exact_failed_row = True
        status = cargo.wait()

    if current is not None and current.captured_open:
        current.malformed = True
    if status < 0:
        return 128 - status, "infrastructure", failed_tests, truncated, None
    # These markers classify the observed phase. Conflicting markers carry no attribution.
    phase = next(iter(phases)) if len(phases) == 1 else "unrecognized"
    for harness in harnesses:
        if not harness.running_seen or not harness.summary_seen:
            harness.malformed = True
        else:
            if harness.summary_status == b"FAILED":
                if harness.failed_count is None or harness.failed_count < 1:
                    harness.malformed = True
                if not harness.failures_seen:
                    harness.malformed = True
            elif harness.summary_status == b"ok":
                if (
                    harness.failed_count != 0
                    or harness.failures_seen
                    or harness.captured_any
                    or harness.target_footer_seen
                ):
                    harness.malformed = True
            else:
                harness.malformed = True
            if harness.failed_count != len(harness.failed_rows):
                harness.malformed = True
            # libtest's declared running count excludes filtered-out tests.
            if (
                None in (
                    harness.running_count, harness.passed_count, harness.failed_count,
                    harness.ignored_count, harness.measured_count,
                )
                or harness.passed_count + harness.failed_count + harness.ignored_count
                + harness.measured_count != harness.running_count
            ):
                harness.malformed = True
            if harness.captured_any and not harness.summary_list_seen:
                harness.malformed = True
        if harness.rows_truncated or harness.captured_open:
            harness.malformed = True

    total_failed = sum(harness.failed_count or 0 for harness in harnesses)
    merkle_harnesses = [harness for harness in harnesses if harness.merkle]
    checkpoint = None
    if (
        phase == "test"
        and not stream_truncated
        and not unbound_marker
        and not too_many_harnesses
        and not foreign_footer
        and total_failed == 1
        and len(merkle_harnesses) == 1
        and all(not harness.malformed for harness in harnesses)
    ):
        harness = merkle_harnesses[0]
        if (
            harness.summary_status == b"FAILED"
            and harness.failed_count == 1
            and harness.failed_rows == [MERKLE_TEST_BYTES]
            and harness.exact_failed_row
            and harness.target_seen
            and harness.target_footer_seen
            and len(harness.markers) == 1
            and failed_tests == {MERKLE_TEST_BYTES}
        ):
            checkpoint = harness.markers[0]
    return status, phase, failed_tests, truncated, checkpoint


def write_receipt(receipt):
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=RECEIPT.parent, delete=False) as output:
            temporary = Path(output.name)
            output.write(json.dumps(receipt) + "\n")
        temporary.replace(RECEIPT)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expect-commit", nargs="?", const="", default="", help="full commit SHA required before running Cargo",
    )
    expected_commit = parser.parse_args().expect_commit

    commit = tree = None
    try:
        commit, tree = source_binding(expected_commit)
        if commit is None:
            status, phase, names, truncated, checkpoint = 1, "source_binding", (), False, None
        else:
            status, phase, names, truncated, checkpoint = run_cargo(commit)
    except KeyboardInterrupt:
        status, phase, names, truncated, checkpoint = 130, "infrastructure", (), False, None

    receipt = {
        "source_commit": commit,
        "source_tree": tree,
        "stage": "cargo_test",
        "outcome": "failed" if status else "passed",
        "exit_code": status,
    }
    if status:
        receipt["failure_phase"] = phase
        if phase == "test":
            receipt["failed_tests"] = [name.decode("ascii") for name in sorted(names)]
            receipt["failed_tests_truncated"] = truncated
            if checkpoint is not None:
                stage, classifier = checkpoint
                receipt["failure_checkpoint"] = {"stage": stage, "class": classifier}
    try:
        write_receipt(receipt)
    except OSError:
        print("Pando lab Cargo test receipt could not be written")
        return status or 1
    print(f"Pando lab Cargo test {receipt['outcome']}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
