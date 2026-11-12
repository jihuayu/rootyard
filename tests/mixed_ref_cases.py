"""#18 mixed protected/unprotected multi-ref refusal cases for ``BrowseHarness``.

A mixin selected explicitly by the Browse runner when it is opted into the
mixed cases, so the fixed ``CASE_NAMES`` inventory other suites pin stays
unchanged.  It proves, against a real stock ``git push --atomic`` and the real
ref-transaction API, that: policy-denied protected refs and legally-updatable
unprotected refs in one request leave every ref at its original OID with no
partial publication.  A Git-level refusal is allowed to settle exactly one
``no_ref_changes`` operation with its admission ABORTED; the API refusal, which
happens before the journal, must leave zero operations.  The native stock-Git
refusal, the policy refusal and the native CAS refusal stay distinct and
separately labelled.  Physical refs are always read from the run-owned bare
repository with stock ``for-each-ref``; the public API view is checked
separately.  No native run is implied by this module alone.
"""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.parse

from mixed_ref_support import (
    PUBLIC_REFS_MAX_PAGES,
    PUBLIC_REFS_PAGE_LIMIT,
    MixedRefSupport,
    public_refs as _public_refs,
)

ZERO_OID = "0" * 40
# The page bounds stay module-level here so callers (and tests) can patch the
# walk without reaching into the support module.
PUBLIC_REFS_PAGE_LIMIT = PUBLIC_REFS_PAGE_LIMIT
PUBLIC_REFS_MAX_PAGES = PUBLIC_REFS_MAX_PAGES


def public_refs(harness, path):
    """Delegate to the shared bounded walk with this module's page bound."""
    return _public_refs(harness, path, max_pages=PUBLIC_REFS_MAX_PAGES)


# These case IDs are the native contract; the full #18 port keeps them verbatim.
MIXED_REF_CASES = (
    "mixed_protected_unprotected_atomic_push",
    "mixed_protected_unprotected_ref_transaction",
)


def reference_events(journal):
    """One transaction per stored JSON-array entry; a bare object is one."""
    return [journal] if isinstance(journal, dict) else list(journal or [])


class MixedRefPolicyCases(MixedRefSupport):


    # Policy a protected-write decision reads; repository id, timestamps and
    # ``version`` are not policy (a recreated rule is a new row).
    RULE_FIELDS = ("branch_ref", "required_approvals", "required_checks", "require_fast_forward",
                   "prevent_deletion", "prevent_force_push", "prevent_self_approval")

    @classmethod
    def rule_view(cls, item):
        return {key: item[key] for key in cls.RULE_FIELDS}

    def rules(self, repo="demo"):
        """Every rule as the API returned it: ``version`` feeds ``expected_version``."""
        return {item["branch_ref"]: item for item in
                self.document(self.repo_api("/branch-rules", repo))["items"]}

    def rule_body(self, version_of=None, **overrides):
        """A PUT body; an insert (``version_of`` None) omits ``expected_version``."""
        body = {"required_approvals": 1, "required_checks": [], "require_fast_forward": True,
                "prevent_deletion": True, "prevent_force_push": True, "prevent_self_approval": False,
                **overrides}
        if version_of is not None:
            body["expected_version"] = version_of["version"]
        return body

    def put_rule(self, branch_ref, repo="demo", **overrides):
        """Create the rule; update an existing one naming its real version."""
        current = self.rules(repo).get(branch_ref)
        body = {"branch_ref": branch_ref, **self.rule_body(current, **overrides)}
        return self.document(self.repo_api("/branch-rules/" + branch_ref, repo), (200, 201),
                             method="PUT", body=body)

    def isolated_rules(self, repo="demo"):
        """Give one case an exact rule set and restore whatever existed before.

        Earlier cases leave their own rules on the shared fixture repository, so
        a mixed case must not assume a global rule inventory: every pre-existing
        rule is removed through the API, the case applies exactly the rules it
        needs, and every pre-existing rule is re-applied afterwards with the
        policy asserted equal. The DELETE hard-deletes the row, so a recreated
        rule is a new row (new version, timestamps) inserted without
        ``expected_version``; only policy is compared.

        Wrapped by ``contextmanager`` once after the class body. A restore error
        is raised in the context of the case's exception, so it cannot mask the
        original cause.
        """
        self.local_repo, self.pulled = repo, False
        policy = lambda: {ref: self.rule_view(item) for ref, item in self.rules(repo).items()}
        original = policy()
        for ref in original:
            self.document(self.repo_api("/branch-rules/" + ref, repo), 200, method="DELETE")
        assert policy() == {}, "isolated rule set was not cleared"
        try:
            yield
        finally:
            self._restore_rules(repo, original, policy)

    def _restore_rules(self, repo, original, policy):
        """Delete every rule the case left; a 404 proves it is already absent."""
        path = self.repo_api("/branch-rules", repo)
        for ref in self.rules(repo):
            status, body, _ = self.http(path + "/" + ref, token=self.alice, method="DELETE")
            if status not in (200, 404):
                raise AssertionError(self.http_failure_detail(path + "/" + ref, 200, status, body, {},
                                                              self.alice, note="rule delete failed"))
        remaining = self.rules(repo)
        assert remaining == {}, ("case rules were not deleted by the API before the restore",
                                 sorted(remaining))
        for ref, item in original.items():
            body = {"branch_ref": ref, **self.rule_body(**item)}
            restored = self.document(self.repo_api("/branch-rules/" + ref, repo),
                                     (200, 201), method="PUT", body=body)
            assert self.rule_view(restored) == item, ("restored rule differs", restored, item)
        assert policy() == original, "previous branch rules were not restored"

    isolated_rules = contextlib.contextmanager(isolated_rules)  # one wrapper, see its docstring

    def owner_grant(self):
        """Use the owner's own grant: the refusal must name Alice's token.

        ``create-token`` issues a scoped repository grant, while the owner
        account (``create-user``) already authenticates writes on its
        repositories; an extra grant would not be the writer under test.
        """
        return self.alice

    def policy_rule(self, branch_ref, **overrides):
        """One approval: the policy a direct write is denied by."""
        rule = self.rule_view(self.put_rule(branch_ref, self.local_repo, **overrides))
        assert rule["required_approvals"] == 1, rule
        return rule

    def open_pull_for_main(self, head_oid):
        """A real pull on main whose head is the protected update: recorded as
        evidence that a pull alone does not authorize a direct push."""
        # Pushed only while ``features`` does not exist yet: the reflog
        # fixture keeps that branch checked out, so it cannot be updated.
        assert self.ref_oids("refs/heads/features")["refs/heads/features"] is None, "features already exists"
        self.git_as(self.alice, "push", "origin", head_oid + ":refs/heads/features", check=True)
        pull = self.document(self.repo_api("/pulls", self.local_repo), 201, method="POST",
                             body={"title": "mixed policy window", "head_ref": "features",
                                   "base_ref": "main"})
        assert pull["head_ref"] == "refs/heads/features", pull
        assert pull["base_ref"] == "refs/heads/main" and pull["head_oid"] == head_oid, pull
        self.pulled = True
        return pull

    def assert_rule_state(self, expected):
        observed = {ref: (item["required_approvals"], item["prevent_force_push"],
                          item["require_fast_forward"]) for ref, item in self.rules(self.local_repo).items()}
        want = {ref: (item["required_approvals"], item["prevent_force_push"],
                      item["require_fast_forward"]) for ref, item in expected.items()}
        assert observed == want, {"observed": observed, "want": want}

    def remote_oid(self, ref):
        """The server's OID for one ref through authenticated ``ls-remote``."""
        return self.advertised_oid(ref)

    def commit_over(self, base, text):
        """A commit whose parent is exactly ``base``, in the run's local clone.

        The fixture's default checkout stays on ``main``: ``commit-tree`` writes
        the new tip with its ``-p`` parent and never moves any checked-out
        branch, so no case takes a fetched branch away from the shared fixture.
        """
        tree = self.git("rev-parse", base + "^{tree}", cwd=self.work).stdout.decode().strip()
        return self.git("commit-tree", tree, "-p", base, "-m", text, cwd=self.work).stdout.decode().strip()

    def advertised_oid(self, ref):
        """The OID the authenticated ``ls-remote`` reports for one ref."""
        out = self.git_as(self.alice, "ls-remote", self.remote, ref, cwd=self.work).stdout.decode()
        return out.rstrip("\n").split("\t")[0] if out.strip() else None

    def push_as_owner(self, *refspecs):
        """One ``--porcelain`` push authenticated with Alice's own grant."""
        assert self.owner_grant() is self.alice, "owner_grant must resolve to Alice"
        completed, _probe = self.push_with(*refspecs)
        return completed


    # One protection flag at a time, with approvals/checks disabled.  The two
    # deletion rows close the delete-then-recreate rewind vector.
    CAUSAL_RULES = (
        ("ff_only", True, False),
        ("force_only", False, True),
        ("delete_ff", True, False),
        ("delete_force", False, True),
    )

    def causal_atomic_refusals(self, main):
        """Prove each protected-tip flag alone across an atomic mixed push."""
        results = {}
        for label, fast_forward, force_push in self.CAUSAL_RULES:
            deleting = label.startswith("delete")
            protected = "refs/heads/mixed-atomic-" + label
            sibling = "refs/heads/mixed-atomic-sibling-" + label
            if deleting:
                self.git_as(self.alice, "push", "origin",
                            self.second + ":" + protected, check=True)
                old, update = self.second, ":" + protected
            else:
                protected, old, update = main, self.third, "+" + self.first + ":" + main
            self.put_rule(protected, required_approvals=0, required_checks=[],
                          require_fast_forward=fast_forward, prevent_force_push=force_push,
                          prevent_deletion=False)
            before = self.ref_state()
            refused = self.push_as_owner("--atomic", "--force", update,
                                         self.feature_oid + ":" + sibling)
            per_ref = self.assert_push_refusals(refused, protected, sibling)
            audit = self.assert_one_aborted_refusal(before, label, [protected, sibling])
            after = self.ref_oids(protected, sibling)
            assert after == {protected: old, sibling: None}, (label, after)
            results[label] = {"rule": {"required_approvals": 0, "required_checks": [],
                                       "require_fast_forward": fast_forward,
                                       "prevent_force_push": force_push,
                                       "prevent_deletion": False},
                              "refusal": per_ref, "audit": audit, "refs": after}
            self.document(self.repo_api("/branch-rules/" + protected), 200, method="DELETE")
        return results

    def causal_transaction_refusals(self, transact, refused):
        """The same one-flag matrix through the atomic ref-transaction API."""
        results = {}
        for label, fast_forward, force_push in self.CAUSAL_RULES:
            deleting = label.startswith("delete")
            protected = "refs/heads/mixed-tx-" + label if deleting else "refs/heads/main"
            sibling = "refs/heads/mixed-tx-sibling-" + label
            if deleting:
                status, error, _ = transact([
                    {"ref_name": protected, "old_oid": ZERO_OID, "new_oid": self.second}])
                assert status == 200 and error is None, (label, status, error)
                old = self.second
                updates = [{"ref_name": protected, "old_oid": old, "new_oid": ZERO_OID}]
            else:
                old = self.third
                updates = [{"ref_name": protected, "old_oid": old, "new_oid": self.first}]
            updates.append({"ref_name": sibling, "old_oid": ZERO_OID, "new_oid": self.feature_oid})
            self.put_rule(protected, required_approvals=0, required_checks=[],
                          require_fast_forward=fast_forward, prevent_force_push=force_push,
                          prevent_deletion=False)
            result = refused(label, 403, "protected branch policy denied", updates)
            after = self.ref_oids(protected, sibling)
            assert after == {protected: old, sibling: None}, (label, after)
            results[label] = {**result, "refs": after}
            self.document(self.repo_api("/branch-rules/" + protected), 200, method="DELETE")
        return results

    def mixed_protected_unprotected_atomic_push(self):
        # The fixed crash-recovery case leaves the fixture fenced for the operator.
        self.ensure_repo_ready()
        # Each group runs inside its own exact rule set, restored afterwards.
        main, topic = "refs/heads/main", "refs/heads/mixed-topic"
        with self.isolated_rules():
            self.require_git_atomic()
            native = self.native_group(main, topic)
            policy = self.policy_group(main, topic, native["audit"])
            causal = self.causal_atomic_refusals(main)
            self.assert_no_open_journal()
            return {"git": self.git_evidence, "native_group": native, "policy_group": policy,
                    "causal_rule_matrix": causal, "rules_restored": True}

    def mixed_protected_unprotected_ref_transaction(self):
        """The API: mixed refusal first, the topic control, then protected alone.

        The API refuses inside its own handler, before it journals anything, so
        every refusal here must leave the *whole* durable state identical (zero
        operations).  The Git ``+1`` settled-audit rule is never applied here.
        """
        self.ensure_repo_ready()
        generation = int(self.sql("SELECT storage_generation FROM repositories WHERE id='"
                                  + self._sql_literal(self.repo["id"]) + "'"))
        main, topic = "refs/heads/main", "refs/heads/mixed-tx-topic"
        path = self.repo_api("/ref-transactions")

        def transact(updates):
            status, body, _ = self.http(path, token=self.alice, method="POST",
                                        body={"storage_generation": generation, "atomic": True,
                                              "updates": updates})
            error = json.loads(body).get("error") if body else None
            assert error is None or isinstance(error, str), {"status": status, "error_type": type(error).__name__}
            return status, error, updates

        def observed(status, error, updates):
            return {"status": status, "error": error,
                    "refs": [{key: update[key] for key in ("ref_name", "old_oid", "new_oid")}
                             for update in updates]}

        def refused(label, code, message, updates):
            before = self.ref_state()
            status, error, _ = transact(updates)
            result = observed(status, error, updates)
            assert status == code and error == message, (label, result)
            self.assert_api_refusal(before, self.ref_state(), label, [update["ref_name"] for update in updates])
            return result

        with self.isolated_rules():
            # Seed with no rule at all: a direct ref create is admitted.
            self.assert_rule_state({})
            seed = topic
            status, error, _ = transact([{"ref_name": seed, "old_oid": ZERO_OID, "new_oid": self.second}])
            assert status == 200 and error is None, (status, error)
            assert self.ref_oids(seed)[seed] == self.second
            # One rule set for the rest: protected main (approvals only; every
            # fast-forward/force-push/deletion flag off), unprotected topic.
            rules = self.policy_rule(main, require_fast_forward=False, prevent_force_push=False,
                                     prevent_deletion=False)
            assert self.put_rule(topic, required_approvals=0)["required_approvals"] == 0, \
                "topic must stay unprotected"
            self.assert_rule_state({main: rules, topic: self.rule_view(self.rules()[topic])})
            control = "refs/heads/mixed-tx-control"
            # FIRST: the mixed request. Both CAS values are live and the topic
            # moves fast-forward (second -> feature_oid, both already advertised
            # and verified), so only the protected-main rule can deny it.
            policy_mixed = refused("403 mixed", 403, "protected branch policy denied", [
                {"ref_name": main, "old_oid": self.third, "new_oid": self.feature_oid},
                {"ref_name": topic, "old_oid": self.second, "new_oid": self.feature_oid}])
            assert self.ref_oids(topic)[topic] == self.second, "the refused unprotected half moved"
            # Control: the unprotected half and the control ref are admitted in
            # one request while the protected-main rule exists (200).
            status, error, updates = transact([
                {"ref_name": topic, "old_oid": self.second, "new_oid": self.feature_oid},
                {"ref_name": control, "old_oid": ZERO_OID, "new_oid": self.second}])
            assert status == 200 and error is None, (status, error, updates)
            assert self.ref_oids(topic, control) == {topic: self.feature_oid, control: self.second}
            # Protected alone, on a baseline taken after the control: nothing
            # from before the control is compared with anything after it.
            base = self.ref_state()
            alone = refused("403 protected alone", 403, "protected branch policy denied", [
                {"ref_name": main, "old_oid": self.third, "new_oid": self.feature_oid}])
            after_alone = self.ref_state()
            assert self.ref_oids(topic)[topic] == self.feature_oid, "the control ref moved"
            # And a stale CAS on the unprotected half is still the CAS gate.
            stale = refused("409 stale", 409, "reference old_oid mismatch", [
                {"ref_name": main, "old_oid": self.third, "new_oid": self.feature_oid},
                {"ref_name": topic, "old_oid": self.second, "new_oid": self.feature_oid}])
            self.cli("worker-once")
            projected = int(self.sql(
                "SELECT count(*) FROM repository_ref_projection WHERE repository_id='"
                + self._sql_literal(self.repo["id"]) + "' AND ref_name IN ('"
                + self._sql_literal(main) + "','" + self._sql_literal(control) + "') AND oid='"
                + self._sql_literal(self.feature_oid) + "'"))
            assert projected == 0, "a refused update was projected"
            assert self.ref_oids(main, control) == {main: self.third, control: self.second}
            assert self.ref_state()["refs"] == base["refs"]
            causal = self.causal_transaction_refusals(transact, refused)
            return {"seed_without_rule": {"ref": seed, "status": 200},
                    "policy_mixed_first": policy_mixed,
                    "control_unprotected_admitted": {"refs": [topic, control], "status": 200},
                    "protected_alone": alone, "baseline_after_control": True,
                    "stale_cas_after_control": stale,
                    "causal_rule_matrix": causal,
                    "api_operations_delta": 0,
                    # The interval audit is the gate; these are recorded only.
                    "operations_before_after": [base["operation_highwater"],
                                                after_alone["operation_highwater"]],
                    "admissions_before_after": [base["admissions"], after_alone["admissions"]],
                    "outbox_before_after": [base["outbox"], after_alone["outbox"]]}


def release_git_option(parser):
    """Declare the trusted client Git option on the Browse runner."""
    parser.add_argument("--git", help="trusted stock Git used as client AND server Git (or ROOTYARD_GIT)")
