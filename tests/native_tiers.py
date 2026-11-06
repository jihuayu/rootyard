"""Native service entrypoint for the historical F1..F51 feature selector.

F identifiers are PROJECT.md feature IDs, never GitHub issue numbers. Reference
engines remain available only through e2e_tiers.py --reference-only.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FEATURE_SUITES = {
    **{n: ("pulls",) for n in range(1, 7)},
    7: ("pulls", "backup_pulls"),
    **{n: ("browse",) for n in range(8, 11)},
    11: ("lfs",), 12: ("lfs",),
    13: ("ci_mirror",), 14: ("ci_source_pins", "ci_job_checkouts"),
    15: ("ci_mirror",), 18: ("workspace",),
    22: ("webhooks",), 23: ("webhooks",),
    24: ("members",), 25: ("members", "pulls"),
    28: ("workspace",), 29: ("workspace", "git_views"),
    33: ("web",), 34: ("web",),
    37: ("workspace",), 38: ("workspace",),
    39: ("sharding",), 40: ("sharding",),
    43: ("git_views",), 44: ("git_views",), 45: ("git_views",),
    46: ("browse",), 47: ("browse",),
    50: ("workspace",), 51: ("workspace",),
}
LAB_BINARIES = {"workspace": "rootyard-workspace-lab", "git_views": "rootyard-view-lab"}


def executable(path):
    path = Path(path).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"Required native executable is missing or not executable: {path}")
    return path


def run(args):
    report = {"backend": "native", "feature": args.feature, "success": False,
              "reference_model_tests": 0, "suites": [],
              "limitations": [
                  "Native suite cases are reported individually; historical model test counts are not service coverage.",
                  "F identifiers refer to PROJECT.md, not GitHub issue numbers.",
                  "Running a native lab does not establish production capability acceptance.",
              ]}
    destination = Path(args.report).resolve() if args.report else None
    evidence = (destination.parent / (destination.stem + "-evidence") if destination
                else Path(tempfile.mkdtemp(prefix="rootyard-native-tiers-")))
    evidence.mkdir(parents=True, exist_ok=True)
    try:
        binary = executable(args.binary)
        report["binary"] = str(binary)
        with binary.open("rb") as source:
            report["binary_sha256"] = hashlib.file_digest(source, "sha256").hexdigest()
        if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
            raise RuntimeError("ROOTYARD_TEST_DATABASE_URL is required for native service tests")
        for command in ("git", "psql", "pg_dump", "pg_restore"):
            if not shutil.which(command):
                raise RuntimeError(f"Required executable missing: {command}")
        if args.feature:
            feature = args.feature.upper()
            if not feature.startswith("F") or not feature[1:].isdigit():
                raise RuntimeError("Expected PROJECT.md feature ID F1..F51")
            number = int(feature[1:])
            if number not in FEATURE_SUITES:
                raise RuntimeError(f"{feature} has no native acceptance mapping; reference tests cannot satisfy it")
            suites = FEATURE_SUITES[number]
        else:
            suites = tuple(dict.fromkeys(s for group in FEATURE_SUITES.values() for s in group))
            report["unmapped_features"] = [f"F{n}" for n in range(1, 52) if n not in FEATURE_SUITES]
        report["complete_feature_coverage"] = False
        report["limitations"].append("Suite success means the listed native cases passed, not complete acceptance of every selected feature.")
        for suite in suites:
            selected = executable(binary.parent / LAB_BINARIES[suite]) if suite in LAB_BINARIES else binary
            suite_report = evidence / f"{suite}.json"
            # A stale prior report must never turn a failed process into success.
            suite_report.unlink(missing_ok=True)
            env = os.environ.copy()
            env["ROOTYARD_TEST_EVIDENCE_DIR"] = str(evidence / suite)
            command = [sys.executable, str(ROOT / "tests" / f"{suite}.py"),
                       "--binary", str(selected), "--report", str(suite_report)]
            with (evidence / f"{suite}.log").open("wb") as output:
                result = subprocess.run(command, cwd=ROOT, env=env, stdout=output,
                                        stderr=subprocess.STDOUT, timeout=1800)
            detail = json.loads(suite_report.read_text()) if suite_report.is_file() else {}
            passed = result.returncode == 0 and detail.get("passed", detail.get("success")) is True
            passed = passed and detail.get("mode", "native") not in ("reference", "reference_model")
            report["suites"].append({"name": suite, "passed": passed,
                                     "exit_code": result.returncode, "report": str(suite_report)})
            print(f"native {suite}: {'passed' if passed else 'FAILED'}", flush=True)
            if not passed:
                raise RuntimeError(f"Native suite {suite} failed; inspect {evidence / (suite + '.log')}")
        report["success"] = True
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
    report["evidence_directory"] = str(evidence)
    if destination:
        destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["success"] else 1
