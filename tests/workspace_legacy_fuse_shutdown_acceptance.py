#!/usr/bin/env python3
"""Native acceptance for legacy in-process FUSE shutdown/returned errors.

The runner selects the canonical source-bound candidate binary and then imports
this module. Each case creates real HTTP workspaces on that binary, performs
real Git/native reads and writes, records the exact kernel mount ID, and uses an
independent namespace holder to observe the service's mount namespace after the
service exits.

This file is written source, not native proof. A real result requires the
qualified Linux FUSE/PG/namespace host profile used by C3/C5. There is no SQL
ready/ACK fixture, mock Git, fake mount, public fault endpoint or environment
backdoor. ``test_early_server_error`` is deliberately absent: that branch is
proved only by the private injected-future source unit in
``src/service_shutdown.rs``; no native early-server-error claim is made here.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
for path in (TESTS, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from tests import fuse_helper_native_support as support  # noqa: E402
from tests import workspace_legacy_fuse_shutdown_support as legacy_support  # noqa: E402
from tests.e2e import Harness  # noqa: E402
from tests.runtime_binary import RuntimeBinarySelectionError, select_runtime_binary  # noqa: E402

REPORT_SCHEMA = "rootyard/issues91-95/legacy-fuse-shutdown-acceptance/v1"
REQUIRED_CASES = (
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest."
    "test_normal_legacy_sigterm_join_evidence_and_exact_unmount",
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest."
    "test_partial_reconcile_failure_cleans_earlier_owned_mount",
    "tests.workspace_legacy_fuse_shutdown_acceptance.WorkspaceLegacyFuseShutdownTest."
    "test_post_reconcile_api_bind_failure_cleans_owned_mount",
)
SOURCE_PATHS = (
    "tests/workspace_legacy_fuse_shutdown_acceptance.py",
    "tests/workspace_legacy_fuse_shutdown_support.py",
)
SAFE_FAILURE_TYPES = frozenset((
    "RuntimeError", "OSError", "ImportError", "ModuleNotFoundError",
    "SourceBindingError", "RuntimeBinarySelectionError", "AssertionError",
    "ValueError", "TypeError", "KeyError", "AttributeError", "FileNotFoundError",
    "HarnessError", "LegacyAcceptanceError", "TimeoutError",
    "CalledProcessError",
))
CASE_DETAILS: dict[str, dict] = {}


class InventoryResult(unittest.TextTestResult):
    """Record which exact required cases started, including class-setup gaps."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)


def _flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _flatten(test)
        else:
            yield test


def _binding_value(binding, name):
    if not isinstance(binding, dict):
        return None
    value = binding.get(name)
    return value if isinstance(value, (str, int)) and not isinstance(value, bool) else None


def _failure_type(error):
    name = type(error).__name__
    return name if name in SAFE_FAILURE_TYPES else "unknown"


def _git_field(argument):
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", argument],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.decode("ascii", "replace").strip()
    return value if value else None


def _input_digest():
    paths = [ROOT / name for name in SOURCE_PATHS]
    digest, _rows = support.digest_files(paths)
    return digest


def _case_inventory(result, scheduled):
    cases = []
    counts = {key: 0 for key in (
        "success", "failure", "error", "skipped",
        "expected_failure", "unexpected_success", "not_run",
    )}
    tests_run = 0
    if result is not None:
        started_ids = set(getattr(result, "started_ids", ()))
        failure_ids = {test.id() for test, _ in result.failures}
        error_ids = {test.id() for test, _ in result.errors}
        skipped_ids = {test.id() for test, _ in result.skipped}
        expected_ids = {test.id() for test, _ in result.expectedFailures}
        unexpected_ids = {test.id() for test in result.unexpectedSuccesses}
        for name in REQUIRED_CASES:
            if name not in started_ids:
                status = "not_run"
            elif name in error_ids:
                status = "error"
            elif name in failure_ids:
                status = "failed"
            elif name in skipped_ids:
                status = "skipped"
            elif name in expected_ids:
                status = "expected_failure"
            elif name in unexpected_ids:
                status = "unexpected_success"
            else:
                status = "passed"
            cases.append({"name": name, "status": status, "detail": CASE_DETAILS.get(name)})
            counts[{"passed": "success", "failed": "failure"}.get(status, status)] += 1
        tests_run = int(result.testsRun)
    return cases, counts, tests_run


def _report_payload(binary_sha256=None, receipt_sha256=None, source_inputs_sha256=None,
                    source_head=None, expected_commit=None, source_tree=None,
                    checkout_head=None, input_digest=None, failure_type=None,
                    scheduled=(), result=None, imported=True):
    cases, counts, tests_run = _case_inventory(result, scheduled)
    details = [CASE_DETAILS.get(name) or {} for name in REQUIRED_CASES]
    owned_remaining = sum(int(detail.get("owned_mounts_remaining") or 0) for detail in details)
    containment = sum(int(detail.get("containment_used") or 0) for detail in details)
    passed = bool(
        imported
        and result is not None
        and tuple(scheduled) == REQUIRED_CASES
        and tests_run == len(REQUIRED_CASES)
        and counts["success"] == len(REQUIRED_CASES)
        and counts["failure"] == 0
        and counts["error"] == 0
        and counts["skipped"] == 0
        and counts["expected_failure"] == 0
        and counts["unexpected_success"] == 0
        and counts["not_run"] == 0
        and owned_remaining == 0
    )
    return {
        "schema": REPORT_SCHEMA,
        "status": "passed" if passed else "failed",
        "passed": passed,
        "binary_sha256": binary_sha256,
        "receipt_sha256": receipt_sha256,
        "source_inputs_sha256": source_inputs_sha256,
        "source_head": source_head,
        "expected_source_commit": expected_commit,
        "checkout_head": checkout_head,
        "source_tree": source_tree,
        "input_digest": input_digest,
        "source_paths": list(SOURCE_PATHS),
        "scheduled": list(scheduled),
        "tests_run": tests_run,
        "cases": cases,
        "counts": counts,
        "cleanup": {
            "required": len(REQUIRED_CASES),
            "scheduled": len(scheduled),
            "tests_run": tests_run,
            "zero_skips": counts["skipped"] == 0,
            "owned_mounts_remaining": owned_remaining,
            "containment_used": containment,
        },
        "summary": {
            "required": len(REQUIRED_CASES),
            "scheduled": len(scheduled),
            "tests_run": tests_run,
            **counts,
        },
        "failure_type": failure_type,
    }


class WorkspaceLegacyFuseShutdownTest(unittest.TestCase):
    """Three native cases, each over its own real repository/schema/data root."""

    @classmethod
    def setUpClass(cls):
        binary, binding = select_runtime_binary()
        facts = support.preconditions(binary, ROOT)
        if facts.get("missing"):
            raise RuntimeError("native preconditions are not qualified: " + ",".join(facts["missing"]))
        cls.binary = binary
        cls.binding = binding
        cls.wrapper_dir = tempfile.mkdtemp(prefix="rootyard-legacy-shutdown-userns-")
        try:
            cls.wrapper = Path(cls.wrapper_dir) / "rootyard-userns"
            cls.wrapper.write_text(
                "#!/bin/sh\nexec unshare -Urm " + shlex.quote(str(binary)) + " \"$@\"\n",
                encoding="utf-8",
            )
            cls.wrapper.chmod(0o700)
        except BaseException:
            shutil.rmtree(cls.wrapper_dir, ignore_errors=True)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "wrapper_dir", ""), ignore_errors=True)

    def setUp(self):
        # One isolated schema/data root per case so startup reconcile sees only
        # the workspaces this case deliberately created.
        self.h = Harness(argparse.Namespace(binary=str(type(self).wrapper), keep=False))
        try:
            self.h.env["ROOTYARD_WORKSPACE_MOUNT_MODE"] = "fuse"
            self.h.env["ROOTYARD_SANDBOX_MODE"] = "dev"
            self.h.env.pop("ROOTYARD_TEST_FUSE_BACKEND", None)
            self.h.setup()
            self.h.api()
            self.h.roundtrip()
        except BaseException:
            try:
                self.h.cleanup()
            except Exception:
                pass
            raise
        self.holders = []
        self.created_mountpoints = []
        self.owned_records = []
        self.conflict = None
        self.log_path = self.h.root / "server.log"
        self.oracle_log_path = self.log_path

    def tearDown(self):
        harness = self.h
        try:
            if harness.proc is not None and harness.proc.poll() is None:
                legacy_support.force_stop_owned_service(harness)
            legacy_support.close_conflict(self.conflict)
            self.conflict = None
            for holder in self.holders:
                if self.owned_records:
                    contained = legacy_support.contain_proven_owned_mounts(
                        holder.pid, self.owned_records, time.monotonic() + legacy_support.ORACLE_SECONDS
                    )
                    detail = CASE_DETAILS.setdefault(self.id(), {})
                    detail["containment_used"] = int(detail.get("containment_used", 0)) + contained
                leftovers = legacy_support.owned_leftovers(holder.pid, self.created_mountpoints)
                if leftovers:
                    detail = CASE_DETAILS.setdefault(self.id(), {})
                    detail["owned_mounts_remaining"] = leftovers
                    raise legacy_support.LegacyAcceptanceError(
                        "owned mounts remained after fixture cleanup"
                    )
                detail = CASE_DETAILS.setdefault(self.id(), {})
                detail["owned_mounts_remaining"] = 0
        finally:
            try:
                for holder in self.holders:
                    legacy_support.close_holder(holder)
                self.holders = []
                if harness.proc is not None:
                    try:
                        support.terminate_process(harness.proc)
                    finally:
                        harness.proc = None
                if harness.log is not None:
                    harness.log.close()
                    harness.log = None
            finally:
                harness.cleanup()

    def _close_service_log(self):
        if self.h.log is not None:
            self.h.log.close()
            self.h.log = None

    def _finish_service_exit(self):
        self._close_service_log()
        self.h.proc = None

    def _signal_owned(self, sig):
        proc = self.h.proc
        if proc is None:
            raise legacy_support.LegacyAcceptanceError("owned service is already gone")
        if os.getpgid(proc.pid) != proc.pid:
            raise legacy_support.LegacyAcceptanceError("owned service is not its process-group leader")
        os.killpg(proc.pid, sig)

    def _attach_holder(self, api_pid):
        holder = legacy_support.attach_namespace_holder(
            api_pid, time.monotonic() + legacy_support.ORACLE_SECONDS
        )
        self.holders.append(holder)
        return holder

    def _remember_record(self, mountpoint, mount_id):
        if int(mount_id) <= 0:
            raise legacy_support.LegacyAcceptanceError("owned mount identity is not numeric")
        self.owned_records.append((mountpoint, int(mount_id)))

    def _remember_paths(self, paths):
        self.created_mountpoints.append(paths["mountpoint"])

    def _start_oracle_service(self):
        self.oracle_log_path = self.h.root / f"legacy-shutdown-oracle-{uuid.uuid4().hex}.log"
        proc = legacy_support.start_service(self.h, self.oracle_log_path)
        return proc.pid

    def _record_detail(self, namespace, evidence, exit_code):
        CASE_DETAILS[self.id()] = {
            "mount_namespace": namespace,
            "joined_mounts": evidence["joined_mounts"],
            "joined_workspaces": evidence["joined_workspaces"],
            "primary_nonzero": exit_code != 0,
            "owned_mounts_remaining": None,
            "containment_used": 0,
        }

    def _create_workspace(self, agent_id, key):
        workspace = legacy_support.create_workspace(self.h, agent_id, key)
        paths = legacy_support.workspace_paths(self.h, workspace["id"])
        self._remember_paths(paths)
        self.assertEqual(
            legacy_support.workspace_state(self.h, workspace["id"]).get("state"),
            "ready",
            "API-created workspace was not ready",
        )
        return workspace, paths

    def test_normal_legacy_sigterm_join_evidence_and_exact_unmount(self):
        workspace, paths = self._create_workspace("legacy-sigterm", "legacy-sigterm-create")
        workspace_id = workspace["id"]
        self.assertEqual(
            legacy_support.read_workspace_file(self.h, workspace_id, "hello.txt"),
            b"second\n",
            "real lower read did not return the API-created baseline",
        )
        payload = b"legacy normal shutdown bytes\n"
        legacy_support.write_workspace_file(
            self.h, workspace_id, "legacy-shutdown.txt", payload, "legacy-sigterm-write"
        )
        self.assertEqual(
            legacy_support.read_workspace_file(self.h, workspace_id, "legacy-shutdown.txt"),
            payload,
            "real FUSE write did not read back the exact bytes",
        )

        api_pid = self.h.proc.pid
        self.assertEqual(os.getpgid(api_pid), api_pid, "owned service is not its process-group leader")
        mount = support.wait_for_fuse_mount(
            api_pid, paths["mountpoint"], timeout=legacy_support.STARTUP_OBSERVATION_SECONDS
        )
        mount_id = int(mount["mount_id"])
        self._remember_record(paths["mountpoint"], mount_id)

        holder = self._attach_holder(api_pid)
        holder_identity = support.process_identity(holder.pid)
        self.assertIsNotNone(holder_identity, "namespace holder identity is unavailable")
        visible = legacy_support.wait_owned_mount(
            holder.pid, paths["mountpoint"], time.monotonic() + legacy_support.ORACLE_SECONDS
        )
        self.assertEqual(int(visible["mount_id"]), mount_id, "holder does not see the exact service mount")
        namespace = legacy_support.mount_namespace_inode(api_pid)

        deadline = time.monotonic() + legacy_support.ORACLE_SECONDS
        self._signal_owned(signal.SIGTERM)
        code = support.wait_process_exit(
            self.h.proc, timeout=max(0.0, deadline - time.monotonic())
        )
        self._finish_service_exit()
        self.assertEqual(code, 0, "legacy SIGTERM did not exit zero after confirmed joins")

        legacy_support.wait_exact_mount_gone(
            holder.pid, paths["mountpoint"], mount_id, deadline
        )
        self.assertEqual(
            legacy_support.owned_leftovers(holder.pid, [paths["mountpoint"]]),
            0,
            "an owned legacy mount remained after SIGTERM",
        )
        current = support.process_identity(holder.pid)
        self.assertIsNotNone(current, "namespace holder exited before the post-exit observation")
        self.assertEqual(
            current["starttime"], holder_identity["starttime"],
            "the independent namespace holder identity changed",
        )
        evidence = legacy_support.read_join_evidence(
            self.oracle_log_path, namespace, legacy_support.workspace_hash(workspace_id)
        )
        self.assertGreaterEqual(evidence["joined_mounts"], 1)
        self._record_detail(namespace, evidence, code)

    def test_partial_reconcile_failure_cleans_earlier_owned_mount(self):
        created = [
            self._create_workspace(f"legacy-partial-{index}", f"legacy-partial-create-{index}")
            for index in range(3)
        ]
        prepared = []
        for workspace, paths in created:
            mount = support.wait_for_fuse_mount(
                self.h.proc.pid,
                paths["mountpoint"],
                timeout=legacy_support.STARTUP_OBSERVATION_SECONDS,
            )
            self._remember_record(paths["mountpoint"], int(mount["mount_id"]))
            prepared.append((workspace, paths))

        # The PostgreSQL reconcile query orders by UUID bytes. The largest UUID
        # is the later owned fixture; the other two are legitimate ready
        # workspaces that must be observed mounted before that later failure.
        ordered = sorted(prepared, key=lambda item: uuid.UUID(item[0]["id"]).bytes)
        broken_workspace, broken_paths = ordered[-1]
        healthy = ordered[:-1]
        broken_lower = broken_paths["lower"]
        git_dir = broken_lower / ".git"
        if not git_dir.is_dir():
            raise legacy_support.LegacyAcceptanceError("API-created lower Git state is missing before corruption")
        corrupt_name = broken_lower / ".git-corrupt-offline"
        if corrupt_name.exists():
            raise legacy_support.LegacyAcceptanceError("corruption fixture already exists")
        git_dir.rename(corrupt_name)
        (broken_lower / ".git").write_text("corrupted legacy lower state\n", encoding="utf-8")

        code = legacy_support.stop_service_gracefully(
            self.h, timeout=legacy_support.PREP_SHUTDOWN_SECONDS
        )
        self.assertEqual(code, 0, "preparation service did not stop cleanly before the failure run")
        self.owned_records.clear()

        api_pid = self._start_oracle_service()
        holder = self._attach_holder(api_pid)
        observed = {}
        for workspace, paths in healthy:
            mount = legacy_support.wait_owned_mount(
                holder.pid,
                paths["mountpoint"],
                time.monotonic() + legacy_support.STARTUP_OBSERVATION_SECONDS,
            )
            mount_id = int(mount["mount_id"])
            self._remember_record(paths["mountpoint"], mount_id)
            observed[workspace["id"]] = mount_id
        if len(observed) < 2:
            raise legacy_support.LegacyAcceptanceError("earlier healthy workspaces were not both observed mounted")

        namespace = legacy_support.mount_namespace_inode(api_pid)
        deadline = time.monotonic() + legacy_support.ORACLE_SECONDS
        code = support.wait_process_exit(
            self.h.proc, timeout=max(0.0, deadline - time.monotonic())
        )
        self._finish_service_exit()
        self.assertNotEqual(code, 0, "partial reconcile failure exited zero")

        for workspace, paths in healthy:
            legacy_support.wait_exact_mount_gone(
                holder.pid, paths["mountpoint"], observed[workspace["id"]], deadline
            )
        self.assertEqual(
            legacy_support.owned_leftovers(
                holder.pid, [paths["mountpoint"] for _workspace, paths in healthy]
            ),
            0,
            "an earlier owned mount remained after the reconcile failure",
        )
        evidence = legacy_support.read_join_evidence(
            self.oracle_log_path,
            namespace,
            legacy_support.workspace_hash(healthy[0][0]["id"]),
        )
        self.assertGreaterEqual(evidence["joined_mounts"], 2)
        self.assertNotIn(
            legacy_support.workspace_hash(broken_workspace["id"]),
            evidence["workspace_hashes"],
            "the corrupted later workspace was reported as a joined mount",
        )
        self._record_detail(namespace, evidence, code)

    def test_post_reconcile_api_bind_failure_cleans_owned_mount(self):
        workspace, paths = self._create_workspace("legacy-bind", "legacy-bind-create")
        workspace_id = workspace["id"]
        mount = support.wait_for_fuse_mount(
            self.h.proc.pid,
            paths["mountpoint"],
            timeout=legacy_support.STARTUP_OBSERVATION_SECONDS,
        )
        self._remember_record(paths["mountpoint"], int(mount["mount_id"]))
        code = legacy_support.stop_service_gracefully(
            self.h, timeout=legacy_support.PREP_SHUTDOWN_SECONDS
        )
        self.assertEqual(code, 0, "preparation service did not stop cleanly before the bind failure run")
        self.owned_records.clear()

        self.conflict = legacy_support.bind_owned_conflict(self.h.port)
        api_pid = self._start_oracle_service()
        holder = self._attach_holder(api_pid)
        visible = legacy_support.wait_owned_mount(
            holder.pid,
            paths["mountpoint"],
            time.monotonic() + legacy_support.STARTUP_OBSERVATION_SECONDS,
        )
        mount_id = int(visible["mount_id"])
        self._remember_record(paths["mountpoint"], mount_id)
        namespace = legacy_support.mount_namespace_inode(api_pid)
        deadline = time.monotonic() + legacy_support.ORACLE_SECONDS
        code = support.wait_process_exit(
            self.h.proc, timeout=max(0.0, deadline - time.monotonic())
        )
        self._finish_service_exit()
        legacy_support.close_conflict(self.conflict)
        self.conflict = None
        self.assertNotEqual(code, 0, "post-reconcile bind failure exited zero")

        legacy_support.wait_exact_mount_gone(holder.pid, paths["mountpoint"], mount_id, deadline)
        self.assertEqual(
            legacy_support.owned_leftovers(holder.pid, [paths["mountpoint"]]),
            0,
            "a previously mounted workspace remained after the bind failure",
        )
        evidence = legacy_support.read_join_evidence(
            self.oracle_log_path, namespace, legacy_support.workspace_hash(workspace_id)
        )
        self.assertGreaterEqual(evidence["joined_mounts"], 1)
        self._record_detail(namespace, evidence, code)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True, help="safe JSON acceptance report path")
    args = parser.parse_args(argv)

    binary_sha256 = receipt_sha256 = source_inputs_sha256 = None
    source_head = None
    source_tree = None
    checkout_head = None
    input_digest = None
    expected_commit = os.environ.get("GITHUB_SHA")
    failure_type = None
    scheduled = ()
    result = None
    imported = False
    try:
        _binary, binding = select_runtime_binary()
        binary_sha256 = _binding_value(binding, "binary_sha256")
        receipt_sha256 = _binding_value(binding, "receipt_sha256")
        source_inputs_sha256 = _binding_value(binding, "source_inputs_sha256")
        source_head = _binding_value(binding, "workspace_commit")
        expected_from_binding = _binding_value(binding, "expected_commit")
        if expected_from_binding is not None:
            expected_commit = expected_from_binding
        checkout_head = _git_field("HEAD")
        source_tree = _git_field("HEAD^{tree}")
        input_digest = _input_digest()
        suite = unittest.TestLoader().loadTestsFromNames(REQUIRED_CASES)
        scheduled = tuple(test.id() for test in _flatten(suite))
        imported = True
        stream = io.StringIO()
        result = unittest.TextTestRunner(
            stream=stream, verbosity=0, resultclass=InventoryResult
        ).run(suite)
    except BaseException as error:
        failure_type = _failure_type(error)
        imported = False
        if not scheduled:
            scheduled = REQUIRED_CASES

    report = _report_payload(
        binary_sha256=binary_sha256,
        receipt_sha256=receipt_sha256,
        source_inputs_sha256=source_inputs_sha256,
        source_head=source_head,
        expected_commit=expected_commit,
        source_tree=source_tree,
        checkout_head=checkout_head,
        input_digest=input_digest,
        failure_type=failure_type,
        scheduled=scheduled,
        result=result,
        imported=imported,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
