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
RUNNING = re.compile(rb"running [0-9]+ tests?")
MERKLE_CHECKPOINT = re.compile(
    rb"rootyard-merkle-checkpoint stage=("
    + rb"|".join(re.escape(code.encode("ascii")) for code in sorted(MERKLE_STAGES))
    + rb") class=("
    + rb"|".join(re.escape(code.encode("ascii")) for code in sorted(MERKLE_CLASSES))
    + rb")"
)
TEST_ATTRIBUTE = rb"^[ \t]*#\[(tokio::)?test([ \t]*\(|\])"
TEST_FUNCTION = re.compile(rb"[ \t]*(?:async[ \t]+)?fn[ \t]+(" + IDENTIFIER + rb")[ \t]*\(")
FAILURE_MARKERS = (
    ("compile", re.compile(rb"error: could not compile `[^`]+`.*")),
    ("test", re.compile(rb"error: test failed(?:, to rerun pass `[^`]+`)?")),
    ("test", re.compile(
        rb"test result: FAILED\. [0-9]+ passed; [1-9][0-9]* failed; "
        rb"[0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out; "
        rb"finished in [0-9]+(?:\.[0-9]+)?s"
    )),
    ("infrastructure", re.compile(rb"error: could not execute process `[^`]+` \(never executed\)")),
)


def bounded_lines(stream):
    while line := stream.readline(MAX_LINE_BYTES + 1):
        if len(line) <= MAX_LINE_BYTES and line.endswith(b"\n"):
            yield line.rstrip(b"\r\n")
        else:
            # Discard the whole oversized line, including marker-shaped suffixes.
            while line and not line.endswith(b"\n"):
                line = stream.readline(MAX_LINE_BYTES + 1)


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
    checkpoint_rows = set()
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
        for raw_line in bounded_lines(cargo.stdout):
            line = SGR.sub(b"", raw_line)
            for phase, marker in FAILURE_MARKERS:
                if marker.fullmatch(line):
                    phases.add(phase)
            if checkpoint := MERKLE_CHECKPOINT.fullmatch(line):
                checkpoint_rows.add((checkpoint[1].decode("ascii"), checkpoint[2].decode("ascii")))
            if RUNNING.fullmatch(line):
                in_case_rows = True
            elif line == b"failures:" or line.startswith(b"test result: "):
                in_case_rows = False
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
        status = cargo.wait()

    if status < 0:
        return 128 - status, "infrastructure", failed_tests, truncated, None
    # These markers classify the observed phase. Conflicting markers carry no attribution.
    phase = next(iter(phases)) if len(phases) == 1 else "unrecognized"
    checkpoint = None
    if (
        phase == "test"
        and failed_tests == {MERKLE_TEST.encode("ascii")}
        and len(checkpoint_rows) == 1
    ):
        checkpoint = checkpoint_rows.pop()
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
