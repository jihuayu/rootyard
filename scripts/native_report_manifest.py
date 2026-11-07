#!/usr/bin/env python3
"""Bind native acceptance evidence to the exact binary, source inputs and fixtures.

Ordinary push/pull-request CI runs the cheap native security, tenancy and
concurrency regressions; the candidate release workflow runs the expensive
browser and object-store suites. Both need the same guarantee: a report is only
accepted when it was produced by the binary that was built once from the
dispatched source commit, every declared case passed, and the report itself
carries that binary digest.

Two modes:

* ``--mode job`` validates one ``scripts/build_native.py`` receipt plus the
  reports and logs produced by that job, and writes a job manifest containing
  the commit, the compiled source-input digest, the binary digest, the harness
  digests and the safe (credential-free) fixture versions.
* ``--mode release`` consumes job manifests, re-verifies their harness digests
  against the current checkout, requires one shared commit and one shared
  source-input digest, checks the candidate-scoped reports and pinned fixture
  versions, and writes the candidate release gate manifest.

A missing report, empty log, failed case, digest mismatch, foreign commit, stale
harness, unrecorded fixture or a credential leaking into an artifact fails
closed with a non-zero exit status.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

REQUIRED_RECEIPT_FIELDS = ("binary_sha256", "source_inputs_sha256", "workspace_commit", "rustc", "command")
JOB_KIND = "rootyard/native-acceptance-job-manifest"
RELEASE_KIND = "rootyard/candidate-release-gate"
FAILURE_KIND = "rootyard/native-acceptance-failure"
SECRET_ENVIRONMENT = (
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_FIXTURE_SECRET_KEY",
    "ROOTYARD_FIXTURE_ACCESS_KEY",
)


class ManifestError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ManifestError(message)


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def pairs(values, flag):
    result = {}
    for value in values or []:
        name, separator, item = value.partition("=")
        require(separator and name and item, f"{flag} expects name=value, got {value!r}")
        require(name not in result, f"{flag} repeats {name!r}")
        result[name] = item
    return result


def secret_values():
    return [value for value in (os.environ.get(name) for name in SECRET_ENVIRONMENT) if value and len(value) >= 8]


def scan_secrets(label, text, secrets):
    for secret in secrets:
        if secret in text:
            raise ManifestError(f"{label} contains a live fixture credential")


def read_text(path, label):
    file = Path(path)
    require(file.is_file(), f"{label}: missing file {file}")
    return file.read_text(errors="replace")


def load_receipt(path, binary_override):
    file = Path(path)
    require(file.is_file(), f"build receipt is missing: {file}")
    try:
        receipt = json.loads(file.read_text())
    except json.JSONDecodeError as error:
        raise ManifestError(f"build receipt is not JSON: {error}")
    for field in REQUIRED_RECEIPT_FIELDS:
        require(receipt.get(field), f"build receipt is missing {field}")
    binary = Path(binary_override) if binary_override else Path(str(file)[: -len(".build.json")])
    require(binary.is_file(), f"built binary is missing: {binary}")
    actual = digest(binary)
    require(
        actual == receipt["binary_sha256"],
        f"binary digest {actual} does not match the build receipt {receipt['binary_sha256']}",
    )
    return receipt, file, binary


def job_manifest(args):
    receipt, receipt_file, binary = load_receipt(args.build_receipt, args.binary)
    commit = args.expect_commit or receipt["workspace_commit"]
    require(
        commit == receipt["workspace_commit"],
        f"build receipt commit {receipt['workspace_commit']} != expected commit {commit}",
    )
    secrets = secret_values()
    scan_secrets("build command", json.dumps(receipt.get("command")), secrets)

    reports = pairs(args.report, "--report")
    require(reports, "at least one --report is required; a gate cannot pass without executed evidence")
    report_records = {}
    for name, path in reports.items():
        text = read_text(path, f"report {name}")
        scan_secrets(f"report {name}", text, secrets)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise ManifestError(f"report {name}: not JSON: {error}")
        require(isinstance(data, dict), f"report {name}: not a JSON object")
        require(data.get("passed") is True, f"report {name}: did not pass")
        require(
            data.get("binary_sha256") == receipt["binary_sha256"],
            f"report {name}: binary digest does not match the built binary",
        )
        cases = data.get("cases")
        require(isinstance(cases, list) and cases, f"report {name}: no executed cases")
        for case in cases:
            require(isinstance(case, dict), f"report {name}: malformed case record")
            require(case.get("status") == "passed", f"report {name}: case {case.get('name')!r} is not passed")
        require(not data.get("failure_traceback"), f"report {name}: records a failure traceback")
        head = data.get("source_head")
        require(head in (None, commit), f"report {name}: produced from commit {head}, expected {commit}")
        report_records[name] = {
            "file": str(path),
            "sha256": digest(path),
            "case_names": [case.get("name") for case in cases],
            "binary_sha256": data["binary_sha256"],
        }

    logs = pairs(args.log, "--log")
    markers = {}
    for value in args.log_marker or []:
        name, separator, marker = value.partition("=")
        require(separator and name and marker, f"--log-marker expects name=text, got {value!r}")
        markers.setdefault(name, []).append(marker)
    for name in markers:
        require(name in logs, f"--log-marker names the unrecorded log {name!r}")
    log_records = {}
    for name, path in logs.items():
        text = read_text(path, f"log {name}")
        require(text.strip(), f"log {name}: empty output; a skipped command is not a pass")
        scan_secrets(f"log {name}", text, secrets)
        for marker in markers.get(name, []):
            require(marker in text, f"log {name}: missing expected output {marker!r}")
        log_records[name] = {"file": str(path), "sha256": digest(path), "bytes": len(text.encode())}

    harnesses = {}
    for path in args.harness or []:
        file = Path(path)
        require(file.is_file(), f"harness is missing: {file}")
        harnesses[str(path)] = digest(path)
    require(harnesses, "at least one --harness is required to bind the executed test source")

    fixtures = pairs(args.fixture, "--fixture")
    for name, value in fixtures.items():
        require(value.strip(), f"fixture {name}: empty fixture version")
        require("\n" not in value and len(value) <= 300, f"fixture {name}: value is not a single safe line")
        scan_secrets(f"fixture {name}", value, secrets)

    return {
        "kind": JOB_KIND,
        "manifest_version": 1,
        "mode": "job",
        "status": "passed",
        "source_commit": commit,
        "source_inputs_sha256": receipt["source_inputs_sha256"],
        "binary_sha256": receipt["binary_sha256"],
        "binary": str(binary),
        "build_receipt": {"file": str(receipt_file), "sha256": digest(receipt_file), "rustc": receipt["rustc"]},
        "build_command": receipt["command"],
        "harnesses": harnesses,
        "fixtures": fixtures,
        "reports": report_records,
        "logs": log_records,
        "generated_unix": int(time.time()),
    }


def release_manifest(args):
    require(args.expect_commit, "--expect-commit is required in release mode; the gate must name the dispatched commit")
    jobs = pairs(args.job_manifest, "--job-manifest")
    require(len(jobs) >= 2, "the candidate release gate requires at least two job manifests")
    required_reports = set(args.require_report or [])
    required_fixtures = pairs(args.require_fixture, "--require-fixture")
    exact_fixtures = pairs(args.require_fixture_exact, "--require-fixture-exact")

    job_records, all_reports, all_fixtures, all_harnesses = {}, {}, {}, {}
    source_digests, commits = set(), set()
    for name, path in jobs.items():
        text = read_text(path, f"job manifest {name}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise ManifestError(f"job manifest {name}: not JSON: {error}")
        require(data.get("kind") == JOB_KIND, f"job manifest {name}: unexpected kind {data.get('kind')!r}")
        require(data.get("status") == "passed", f"job manifest {name}: status is {data.get('status')!r}")
        require(data.get("source_commit"), f"job manifest {name}: no source commit")
        commits.add(data["source_commit"])
        require(data.get("source_inputs_sha256"), f"job manifest {name}: no source input digest")
        source_digests.add(data["source_inputs_sha256"])
        require(data.get("binary_sha256"), f"job manifest {name}: no binary digest")

        reports = data.get("reports") or {}
        require(reports, f"job manifest {name}: no reports")
        for report_name, record in reports.items():
            require(report_name not in all_reports, f"report {report_name!r} is claimed by two jobs")
            all_reports[report_name] = {**record, "job": name}

        fixtures = data.get("fixtures") or {}
        for fixture_name, value in fixtures.items():
            require(
                fixture_name not in all_fixtures or all_fixtures[fixture_name] == value,
                f"fixture {fixture_name!r} is recorded with conflicting values",
            )
            all_fixtures[fixture_name] = value

        harnesses = data.get("harnesses") or {}
        require(harnesses, f"job manifest {name}: no harness digests")
        for harness_path, recorded in harnesses.items():
            file = Path(harness_path)
            require(file.is_file(), f"job manifest {name}: harness {harness_path} is missing from this checkout")
            actual = digest(file)
            require(
                actual == recorded,
                f"job manifest {name}: harness {harness_path} changed after the job ran",
            )
            all_harnesses[harness_path] = actual

        job_records[name] = {
            "manifest": str(path),
            "sha256": digest(path),
            "source_commit": data["source_commit"],
            "source_inputs_sha256": data["source_inputs_sha256"],
            "binary_sha256": data["binary_sha256"],
            "reports": sorted(reports),
            "fixtures": fixtures,
        }

    require(commits == {args.expect_commit}, "job manifests do not share the dispatched commit")
    require(len(source_digests) == 1, "job manifests disagree on the compiled source-input digest")
    missing = required_reports - set(all_reports)
    require(not missing, "required candidate reports are missing: " + ", ".join(sorted(missing)))
    for fixture_name, substring in required_fixtures.items():
        value = all_fixtures.get(fixture_name)
        require(value is not None, f"required fixture {fixture_name!r} was not recorded by any job")
        require(
            substring in value,
            f"fixture {fixture_name}={value!r} does not contain the required pin {substring!r}",
        )
    for fixture_name, expected in exact_fixtures.items():
        value = all_fixtures.get(fixture_name)
        require(value is not None, f"required fixture {fixture_name!r} was not recorded by any job")
        require(
            value == expected,
            f"fixture {fixture_name}={value!r} is not the exact required value {expected!r}",
        )

    return {
        "kind": RELEASE_KIND,
        "gate_version": 1,
        "mode": "release",
        "status": "passed",
        "source_commit": args.expect_commit,
        "source_inputs_sha256": source_digests.pop(),
        "jobs": job_records,
        "reports": sorted(all_reports),
        "fixtures": all_fixtures,
        "harnesses": all_harnesses,
        "generated_unix": int(time.time()),
    }


def emit(path, payload):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("job", "release"), default="job")
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--expect-commit", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--build-receipt")
    parser.add_argument("--binary")
    parser.add_argument("--report", action="append", default=[])
    parser.add_argument("--log", action="append", default=[])
    parser.add_argument("--log-marker", action="append", default=[])
    parser.add_argument("--harness", action="append", default=[])
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--job-manifest", action="append", default=[])
    parser.add_argument("--require-report", action="append", default=[])
    parser.add_argument("--require-fixture", action="append", default=[])
    parser.add_argument("--require-fixture-exact", action="append", default=[])
    args = parser.parse_args()
    try:
        if args.mode == "job":
            require(args.build_receipt, "--build-receipt is required in job mode")
            payload = job_manifest(args)
            summary = {
                "status": payload["status"],
                "manifest": str(args.manifest_out),
                "source_commit": payload["source_commit"],
                "source_inputs_sha256": payload["source_inputs_sha256"],
                "binary_sha256": payload["binary_sha256"],
                "reports": sorted(payload["reports"]),
            }
        else:
            payload = release_manifest(args)
            summary = {
                "status": payload["status"],
                "manifest": str(args.manifest_out),
                "source_commit": payload["source_commit"],
                "source_inputs_sha256": payload["source_inputs_sha256"],
                "jobs": sorted(payload["jobs"]),
                "reports": payload["reports"],
            }
    except (ManifestError, OSError, json.JSONDecodeError) as error:
        emit(
            args.manifest_out,
            {
                "kind": FAILURE_KIND,
                "status": "failed",
                "mode": args.mode,
                "error": str(error),
                "generated_unix": int(time.time()),
            },
        )
        print(f"native acceptance manifest: FAILED: {error}", file=sys.stderr)
        return 1
    emit(args.manifest_out, payload)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
