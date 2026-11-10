#!/usr/bin/env python3
"""Issue #4: direct collaborator read/write/admin authorization across Git and write endpoints.

Every positive case starts from the real repository API and grants its acting
user through the owner's real ``PUT /api/repos/{owner}/{name}/collaborators/
{user}`` call. No SQL insert manufactures a collaborator row, a ready
repository, a pull request, an object or a ref. This entry point owns the CLI,
the eleven execution groups (contract, environment, transport, write endpoints)
and the report; the contract constants and prerequisite checks live in
``collaborator_contract.py``, the owned environment and Git transport matrix in
``collaborator_lifecycle.py`` and the write-endpoint contract in
``collaborator_writes.py``.

Cases in this order: prerequisites and the single initialization first, then
the transport matrix, then the write endpoints. Each case depends only on the
state its predecessors recorded; every receipt query is scoped to alice/demo.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(PACKAGE_ROOT / "scripts"))
from reliability import ReliabilityHarness  # noqa: E402
import collaborator_contract  # noqa: E402
import collaborator_lifecycle  # noqa: E402
import collaborator_writes  # noqa: E402
from collaborator_contract import (  # noqa: E402,F401  (re-exported for tests)
    EXECUTED_GIT_COMMANDS, MIN_GIT, ZERO, git_version, invoked_git_commands,
)

CASE_MODULES = (collaborator_contract.__file__, collaborator_lifecycle.__file__,
                collaborator_writes.__file__)


class CollaboratorTransportHarness(collaborator_contract.prerequisite,
                                   collaborator_lifecycle.lifecycle,
                                   collaborator_writes.writes,
                                   ReliabilityHarness):
    case_module_files = CASE_MODULES

    def __init__(self, args):
        super().__init__(args)
        self.limits = [
            "Owned loopback service, owned PostgreSQL schema and temporary data directory only.",
            "Direct repository_collaborators roles only; teams/organizations are other suites.",
            "Git refs, git_operations and outbox_events are authoritative; Git HTTP status is observed.",
            "No object store, kernel fault, power loss or production connection is exercised.",
        ]
        self.users = {}
        self.member_mutations = 0

    def execute(self):
        """Register all nineteen cases; the main loop runs them in order."""
        self.steps = (
            ("git_matrix_version", self.git_matrix_version),
            ("git_command_coverage", self.git_command_coverage),
            ("source_bound_receipt", self.source_binding),
            ("environment", self.environment),
            ("staff_owned_fixtures", self.staff_fixtures),
            ("role_matrix_clone_fetch_push", self.role_matrix),
            ("fetch_propagation", self.fetch_propagation),
            ("outsider_404_no_enumeration", self.outsider_isolation),
            ("read_only_token_403", self.read_only_token),
            ("non_fast_forward_rejected", self.non_fast_forward),
            ("ref_transactions_role_matrix", self.ref_transactions),
            ("pull_create_merge_role_matrix", self.pull_lifecycle),
            ("branch_rule_role_matrix", self.rule_refusals),
            ("maintain_branch_rule_matrix", self.maintain_rule_matrix),
            ("admin_management_not_owner_only", self.admin_management),
            ("pull_merge_under_collaborator_rule", self.pull_merge_under_rule),
            ("withdrawal_revokes_new_requests", self.withdrawal),
            ("git_receipts_are_not_repository_audit_log", self.audit_boundary),
            ("token_revocation_401", self.token_revocation),
        )
        names = [name for name, _ in self.steps]
        assert len(names) == len(set(names)) == 19, names
        return names


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="built rootyard binary from scripts/build_native.py")
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    parser.add_argument("--keep", action="store_true", help="retain the owned fixture directory")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("required dependency missing: ROOTYARD_TEST_DATABASE_URL")
    import shutil
    for executable in ("git", "psql", args.binary):
        if not shutil.which(executable):
            parser.error("required dependency missing: " + executable)
    h = CollaboratorTransportHarness(args)
    success = False
    failed_case = None
    try:
        for name, fn in h.execute():
            failed_case = name
            h.case(name, fn)
        failed_case = None
        success = True
    except Exception as error:  # fail closed with one bounded message
        print(h.redact(error), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:  # noqa: BLE001
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            success = False
        report = dict(
            passed=success, failed_case=failed_case,
            executed=len(h.results), case_names=[case["name"] for case in h.results],
            cases=h.results, limitations=h.limits, runtime={
                "git_client": h.run([h.server_git(), "--version"]).stdout.decode().strip(),
                "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                "native_executed_by_implementer": h.native_executed_by_implementer(),
            })
        if args.keep:
            report["retained_directory"] = str(h.root)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
