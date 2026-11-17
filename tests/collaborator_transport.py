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
the transport matrix, then the write endpoints, then the inheritable team check
(``collaborator_teams.py``) once the direct matrix has proved the surfaces, and
finally the token-revocation check. Each case depends only on the state its
predecessors recorded; every receipt query is scoped to alice/demo.
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
import collaborator_teams  # noqa: E402
import collaborator_writes  # noqa: E402
from collaborator_contract import (  # noqa: E402,F401  (re-exported for tests)
    EXECUTED_GIT_COMMANDS, MIN_GIT, ZERO, git_version, invoked_git_commands,
)

CASE_MODULES = (collaborator_contract.__file__, collaborator_lifecycle.__file__,
                collaborator_writes.__file__, collaborator_teams.__file__)

_STAGE_OTHER = "OTHER"
_STAGE_PHASES = ("setup", "fixture")
_STAGE_SUFFIXES = (
    "sql.create_schema", "sql.version_probe", "sql.other",
    "migrate", "create_user", "create_token",
    "git.version_probe", "git.clone", "git.config", "git.add", "git.commit",
    "git.rev_parse", "git.push", "git.other",
    "binary.other", "other",
)
_STAGE_LABELS = frozenset(
    f"{phase}.{suffix}" for phase in _STAGE_PHASES for suffix in _STAGE_SUFFIXES
) | {_STAGE_OTHER}


def _safe_stage(value):
    """Return a stage only when it is one exact member of the closed enum."""
    return value if type(value) is str and value in _STAGE_LABELS else None


def _argument(argv, index):
    try:
        return argv[index]
    except Exception:
        return None


def _option_argument(argv, option):
    try:
        for index, item in enumerate(argv):
            if item == option:
                return _argument(argv, index + 1)
    except Exception:
        return None
    return None


def _stage_label(argv, phase, binary):
    """Classify one existing command shape in memory; never retain its text."""
    try:
        if phase not in _STAGE_PHASES:
            return _STAGE_OTHER
        if not isinstance(argv, (list, tuple)) or not argv:
            return _STAGE_OTHER
        executable = argv[0]
        if not isinstance(executable, str) or not executable:
            return _STAGE_OTHER
        if executable == "psql" or os.path.basename(executable) == "psql":
            query = _option_argument(argv, "-c")
            if isinstance(query, str):
                normalized = query.strip().upper()
                if normalized.startswith("CREATE SCHEMA"):
                    return phase + ".sql.create_schema"
                if normalized == "SELECT VERSION()":
                    return phase + ".sql.version_probe"
            return phase + ".sql.other"
        if executable == "git" or os.path.basename(executable) == "git":
            tail = argv[1:]
            index = 0
            subcommand = None
            while index < len(tail):
                item = tail[index]
                if not isinstance(item, str):
                    return _STAGE_OTHER
                if item in ("-c", "-C", "--git-dir", "--work-tree", "--namespace"):
                    index += 2
                    continue
                if item.startswith("-"):
                    index += 1
                    continue
                subcommand = item
                break
            if subcommand is None:
                if "--version" in tail:
                    return phase + ".git.version_probe"
                return phase + ".git.other"
            suffix = {
                "clone": "git.clone", "config": "git.config", "add": "git.add",
                "commit": "git.commit", "rev-parse": "git.rev_parse", "push": "git.push",
            }.get(subcommand, "git.other")
            return phase + "." + suffix
        binary_value = binary if isinstance(binary, str) else None
        if binary_value is not None and executable == binary_value:
            subcommand = _argument(argv, 1)
            suffix = {
                "migrate": "migrate", "create-user": "create_user",
                "create-token": "create_token",
            }.get(subcommand, "binary.other")
            return phase + "." + suffix
        return _STAGE_OTHER
    except Exception:
        return _STAGE_OTHER


def _attach_stage(error, stage):
    """Best-effort safe attribute; control signals must not be swallowed."""
    object.__setattr__(error, "failed_stage", stage)


class CollaboratorTransportHarness(collaborator_contract.prerequisite,
                                   collaborator_lifecycle.lifecycle,
                                   collaborator_writes.writes,
                                   collaborator_teams.teams,
                                   ReliabilityHarness):
    case_module_files = CASE_MODULES

    def __init__(self, args):
        super().__init__(args)
        self.limits = [
            "Owned loopback service, owned PostgreSQL schema and temporary data directory only.",
            "Direct repository_collaborators roles, plus one case of repository-team inheritance "
            "(read/write/admin) on alice/demo; organization teams are other suites.",
            "Git refs, git_operations and outbox_events are authoritative; Git HTTP status is observed.",
            "No object store, kernel fault, power loss or production connection is exercised.",
            "source_commit names the executed binary's receipt identity, read by "
            "tests/source_bound_binary.py: a v1 receipt must match the mounted checkout's "
            "current production bytes and clean production paths, so source_commit is that "
            "HEAD; a v2 receipt is accepted from its recorded snapshot/config/toolchain/input "
            "binding, so source_commit is the receipt's workspace_commit and the mutable "
            "checkout HEAD is reported separately as current_head. No ancestor relation or "
            "current-byte equivalence is claimed for a v2 snapshot.",
        ]
        self.users = {}
        self.member_mutations = 0
        self._observe_stage = False
        self._stage_phase = None
        self._last_run_stage = None
        self._failed_stage = None

    def case(self, name, fn):
        """Observe only the environment case; every other case is untouched."""
        if name != "environment":
            return super().case(name, fn)
        previous = (
            getattr(self, "_observe_stage", False),
            getattr(self, "_stage_phase", None),
            getattr(self, "_last_run_stage", None),
            getattr(self, "_failed_stage", None),
        )
        self._observe_stage = True
        self._stage_phase = "setup"
        self._last_run_stage = None
        self._failed_stage = None
        try:
            return super().case(name, fn)
        except Exception:
            stage = _safe_stage(getattr(self, "_failed_stage", None))
            if stage is not None:
                for result in reversed(getattr(self, "results", ())):
                    if (isinstance(result, dict) and result.get("name") == name
                            and result.get("status") == "failed"):
                        result["failed_stage"] = stage
                        break
            raise
        finally:
            (self._observe_stage, self._stage_phase,
             self._last_run_stage, self._failed_stage) = previous

    def setup(self):
        """Keep setup labels distinct from fixture labels after setup succeeds."""
        if not getattr(self, "_observe_stage", False):
            return super().setup()
        self._stage_phase = "setup"
        result = super().setup()
        self._stage_phase = "fixture"
        return result

    def run(self, argv, cwd=None, check=True, data=None, env=None):
        """Delegate once, then annotate only the original checked AssertionError."""
        if not getattr(self, "_observe_stage", False):
            return super().run(argv, cwd=cwd, check=check, data=data, env=env)
        try:
            stage = _stage_label(
                argv,
                getattr(self, "_stage_phase", None),
                getattr(getattr(self, "args", None), "binary", None),
            )
        except Exception:
            stage = _STAGE_OTHER
        stage = _safe_stage(stage) or _STAGE_OTHER
        self._last_run_stage = stage
        try:
            return super().run(argv, cwd=cwd, check=check, data=data, env=env)
        except AssertionError as error:
            self._failed_stage = stage
            try:
                _attach_stage(error, stage)
            except Exception:
                pass
            raise

    def execute(self):
        """Register all twenty cases; the main loop runs them in order."""
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
            ("team_inherited_read_write_admin", self.team_matrix),
            ("token_revocation_401", self.token_revocation),
        )
        names = [name for name, _ in self.steps]
        assert len(names) == len(set(names)) == 20, names
        return self.steps


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="built rootyard binary from scripts/build_native.py")
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    parser.add_argument("--keep", action="store_true", help="retain the owned fixture directory")
    parser.add_argument("--only", action="append", default=[], metavar="CASE",
                        help="run only the named registered case(s); count is not claimed")
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
        steps = h.execute()
        if args.only:
            unknown = set(args.only) - {name for name, _ in steps}
            if unknown:
                parser.error("unknown --only case(s): " + ", ".join(sorted(unknown)))
            steps = [(name, fn) for name, fn in steps if name in args.only]
        for name, fn in steps:
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
            cases=h.results, limitations=h.limits, only=args.only, runtime={
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
