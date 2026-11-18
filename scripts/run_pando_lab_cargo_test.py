"""Run the isolated Pando Cargo test gate and print a bounded CI receipt."""

import json
import re
import subprocess


CARGO_COMMAND = ("cargo", "test", "--locked", "--all-targets", "--features", "pando-lab")
MAX_LINE_BYTES = 4096
MAX_FAILED_TESTS = 8
SGR = re.compile(rb"\x1b\[[0-9;]*m")
IDENTIFIER = rb"[A-Za-z_][A-Za-z0-9_]*"
FAILED_TEST = re.compile(rb"test (?:" + IDENTIFIER + rb"::)*(" + IDENTIFIER + rb") \.\.\. FAILED")
RUNNING = re.compile(rb"running [0-9]+ tests?")
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


def source_commit():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    if result.returncode == 0 and re.fullmatch(rb"[0-9a-f]{40}\n", result.stdout):
        return result.stdout.strip().decode("ascii")
    return None


def source_test_names(commit):
    """Allow ordinary Rust and Tokio test names from committed source blobs."""
    if commit is None:
        return set()
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
    truncated = False
    try:
        cargo = subprocess.Popen(
            CARGO_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
    except FileNotFoundError:
        return 127, "infrastructure", failed_tests, truncated
    except OSError:
        return 126, "infrastructure", failed_tests, truncated

    known_names = None
    in_case_rows = False
    with cargo:
        for raw_line in bounded_lines(cargo.stdout):
            line = SGR.sub(b"", raw_line)
            for phase, marker in FAILURE_MARKERS:
                if marker.fullmatch(line):
                    phases.add(phase)
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
        return 128 - status, "infrastructure", failed_tests, truncated
    # These markers classify the observed phase. Conflicting markers carry no attribution.
    phase = next(iter(phases)) if len(phases) == 1 else "unrecognized"
    return status, phase, failed_tests, truncated


def main():
    commit = source_commit()
    status, phase, names, truncated = run_cargo(commit)
    receipt = {
        "source_commit": commit,
        "stage": "cargo_test",
        "outcome": "failed" if status else "passed",
        "exit_code": status,
    }
    if status:
        receipt["failure_phase"] = phase
        if phase == "test":
            receipt["failed_tests"] = [name.decode("ascii") for name in sorted(names)]
            receipt["failed_tests_truncated"] = truncated
    print(json.dumps(receipt))
    return status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
