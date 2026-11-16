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
import os
from pathlib import Path
import shlex
import shutil
import signal
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
from tests import workspace_legacy_fuse_shutdown_fixtures as legacy_fixtures  # noqa: E402
from tests import workspace_legacy_fuse_shutdown_support as legacy_support  # noqa: E402
from tests.e2e import Harness  # noqa: E402
from tests.runtime_binary import select_runtime_binary  # noqa: E402

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
    "tests/workspace_legacy_fuse_shutdown_fixtures.py",
    "tests/workspace_legacy_fuse_shutdown_report.py",
)
CASE_DETAILS: dict[str, dict] = {}


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
        self._cleanup_deadline = None

    def tearDown(self):
        harness = self.h
        try:
            if harness.proc is not None and harness.proc.poll() is None:
                legacy_support.force_stop_owned_service(harness)
            legacy_fixtures.close_conflict(self.conflict)
            self.conflict = None
            # Reuse the absolute deadline armed at the case trigger. Failure
            # containment never receives a fresh oracle window after D, and no
            # containment wait runs before a trigger has armed that deadline.
            deadline = self._cleanup_deadline
            for holder in self.holders:
                if self.owned_records and deadline is not None:
                    contained = legacy_support.contain_proven_owned_mounts(
                        holder.pid, self.owned_records, deadline
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

    def _arm_cleanup_deadline(self):
        """Arm the one absolute case deadline at the actual trigger."""
        self._cleanup_deadline = time.monotonic() + legacy_support.ORACLE_SECONDS
        return self._cleanup_deadline

    def _record_detail(self, namespace, evidence, exit_code):
        CASE_DETAILS[self.id()] = {
            "mount_namespace": namespace,
            "joined_mounts": evidence["joined_mounts"],
            "joined_workspaces": evidence["joined_workspaces"],
            "exit_code": int(exit_code),
            "primary_nonzero": exit_code != 0,
            "owned_mounts_remaining": None,
            "containment_used": 0,
        }

    def _create_workspace(self, agent_id, key):
        workspace = legacy_fixtures.create_workspace(self.h, agent_id, key)
        paths = legacy_fixtures.workspace_paths(self.h, workspace["id"])
        self._remember_paths(paths)
        self.assertEqual(
            legacy_fixtures.workspace_state(self.h, workspace["id"]).get("state"),
            "ready",
            "API-created workspace was not ready",
        )
        return workspace, paths

    def test_normal_legacy_sigterm_join_evidence_and_exact_unmount(self):
        workspace, paths = self._create_workspace("legacy-sigterm", "legacy-sigterm-create")
        workspace_id = workspace["id"]
        self.assertEqual(
            legacy_fixtures.read_workspace_file(self.h, workspace_id, "hello.txt"),
            b"second\n",
            "real lower read did not return the API-created baseline",
        )
        payload = b"legacy normal shutdown bytes\n"
        legacy_fixtures.write_workspace_file(
            self.h, workspace_id, "legacy-shutdown.txt", payload, "legacy-sigterm-write"
        )
        self.assertEqual(
            legacy_fixtures.read_workspace_file(self.h, workspace_id, "legacy-shutdown.txt"),
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

        deadline = self._arm_cleanup_deadline()
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

        # This 180 s preparation-stop bound is setup containment, explicitly
        # outside the single 5 s case oracle armed below at the failure trigger.
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
        deadline = self._arm_cleanup_deadline()
        code = support.wait_process_exit(
            self.h.proc, timeout=max(0.0, deadline - time.monotonic())
        )
        self._finish_service_exit()
        self.assertGreater(code, 0, "partial reconcile failure did not return a positive application exit status")

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
        # This 180 s preparation-stop bound is setup containment, explicitly
        # outside the single 5 s case oracle armed below at the bind failure.
        code = legacy_support.stop_service_gracefully(
            self.h, timeout=legacy_support.PREP_SHUTDOWN_SECONDS
        )
        self.assertEqual(code, 0, "preparation service did not stop cleanly before the bind failure run")
        self.owned_records.clear()

        self.conflict = legacy_fixtures.bind_owned_conflict(self.h.port)
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
        deadline = self._arm_cleanup_deadline()
        code = support.wait_process_exit(
            self.h.proc, timeout=max(0.0, deadline - time.monotonic())
        )
        self._finish_service_exit()
        legacy_fixtures.close_conflict(self.conflict)
        self.conflict = None
        self.assertGreater(code, 0, "post-reconcile bind failure did not return a positive application exit status")

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


if __name__ == "__main__":
    from tests import workspace_legacy_fuse_shutdown_report as report

    sys.exit(report.main())
