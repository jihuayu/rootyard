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

from refusal_audit_sql import (
    audit_api_refusal_interval,
    audit_git_refusal_interval,
)

ZERO_OID = "0" * 40
# ``GET /refs`` serves at most 100 per page (``validate_limit``); the walk asks
# for that explicit limit instead of the 50 default.
PUBLIC_REFS_PAGE_LIMIT = 100
PUBLIC_REFS_MAX_PAGES = 1000


def public_refs(harness, path):
    """Every public ref from ``/refs``, following ``next_after`` to the end.

    One page would silently truncate at the default limit, so the cursor is
    followed until the server reports no successor.  Cursors must advance
    strictly and the walk must terminate, or the full public set is unknown.
    """
    refs, cursor, pages = [], None, 0
    while True:
        suffix = "/refs?limit=" + str(PUBLIC_REFS_PAGE_LIMIT) + (
            "&after=" + urllib.parse.quote(cursor, safe="") if cursor is not None else "")
        page = harness.document(path + suffix)
        items = page.get("items")
        if not isinstance(items, list):
            raise AssertionError("/refs page without an items list: " + repr(page)[:400])
        for item in items:
            refs.append((item["name"], item["oid"]))
        following = page.get("next_after")
        if following is None:
            return refs
        if not isinstance(following, str) or (cursor is not None and following <= cursor):
            raise AssertionError("/refs cursor did not advance: " + repr((cursor, following)))
        # ``next_after`` is the last name the server placed on this page, so the
        # page must end exactly there: a ref beyond it would be skipped by the
        # cursor and a shorter page boundary would repeat refs already read.
        names = [item["name"] for item in items]
        if not names or names[-1] != following:
            raise AssertionError("/refs page is not bounded by its own next_after: "
                                 + repr({"next_after": following, "last": names[-1] if names else None}))
        cursor = following
        pages += 1
        if pages > PUBLIC_REFS_MAX_PAGES:
            raise AssertionError("/refs walk did not terminate in " + str(PUBLIC_REFS_MAX_PAGES) + " pages")

# These case IDs are the native contract; the full #18 port keeps them verbatim.
MIXED_REF_CASES = (
    "mixed_protected_unprotected_atomic_push",
    "mixed_protected_unprotected_ref_transaction",
)


def reference_events(journal):
    """One transaction per stored JSON-array entry; a bare object is one."""
    return [journal] if isinstance(journal, dict) else list(journal or [])


class MixedRefPolicyCases:
    def native_git(self):
        """Absolute stock Git declared as BOTH the client and the server's Git.

        ``--git`` and ``ROOTYARD_GIT`` must resolve to the same file (the server
        resolves ``ROOTYARD_GIT`` through ``PATH`` when it is unset), so a
        different client can never pass the version gate; an implicit PATH value
        is recorded as such.
        """
        declared = [value for value in (getattr(self.args, "git", None), os.environ.get("ROOTYARD_GIT"))
                    if value]
        resolved = {str(Path(value).resolve()) for value in declared}
        assert len(resolved) <= 1, "--git and ROOTYARD_GIT disagree: " + repr(sorted(resolved))
        if not resolved:
            found = shutil.which("git")
            assert found, "no Git client on PATH and no --git/ROOTYARD_GIT supplied"
            parts = [str(Path(found).resolve())]
            if self.env.get("PATH") != os.environ.get("PATH"):
                parts.append("PATH overridden for this run; implicit client matches the server lookup")
            return {"executable": str(Path(found).resolve()), "declared": False, "notes": parts}
        path = Path(resolved.pop())
        assert path.is_file() and os.access(path, os.X_OK), "trusted Git is not an executable file"
        server = os.environ.get("ROOTYARD_GIT")
        if server:
            assert str(Path(server).resolve()) == str(path), (
                "ROOTYARD_GIT (server Git) differs from the declared client " + str(path))
        return {"executable": str(path), "declared": True, "notes": ["declared client == server Git"]}

    def native_git_probe(self):
        client = self.native_git()
        probe = subprocess.run([client["executable"], "--version"], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=30)
        assert probe.returncode == 0, "Git version probe failed for " + client["executable"]
        match = re.search(r"(\d+)\.(\d+)", probe.stdout.decode(errors="replace"))
        assert match, "unparseable Git version " + repr(probe.stdout[:200])
        version = (int(match.group(1)), int(match.group(2)))
        return {**client, "version": ".".join(map(str, version)), "minor": version,
                "sha256": self._sha256(client["executable"])}

    @staticmethod
    def _sha256(path):
        with open(path, "rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def git_as(self, token, *args, cwd=None, check=False):
        """Declared Git with an explicit per-command header (never clone-only)."""
        probe = self.native_git_probe()
        assert probe["declared"], "Git I/O needs the declared, verified executable"
        # Only this command's own copy gets the client; ``self.env`` is the
        # server's environment and must keep describing the live process.
        env = self.env.copy()
        env["ROOTYARD_GIT"] = probe["executable"]
        auth = base64.b64encode((token["username"] + ":" + token["token"]).encode()).decode()
        try:
            completed = self.run([probe["executable"], "-c", "http.extraHeader=Authorization: Basic " + auth,
                                  *args], cwd=cwd or self.work, check=False, env=env)
        except subprocess.TimeoutExpired:
            raise AssertionError(self.redact("git_as " + " ".join(args) + ": timed out")) from None
        if check and completed.returncode:
            raise AssertionError(self.redact("git_as " + " ".join(args) + " failed ("
                                             + str(completed.returncode) + "): "
                                             + completed.stderr.decode(errors="replace")[-4000:]))
        return completed

    def started_server_git(self):
        """The Git the live server process was started with, or fail closed.

        ``self.server_git`` is captured at each successful ``start()``; it is
        never read back from ``self.env``, which helpers may rewrite.
        """
        started = getattr(self, "server_git", None)
        assert isinstance(started, dict) and started.get("path") is not None, (
            "the live server's start-time Git is unknown; restart it before the mixed proof: "
            + repr(started))
        assert started["path"] == self.git_binding["declared"], (
            "the live server did not start on the declared Git: "
            + repr({"started": started["path"], "declared": self.git_binding["declared"]}))
        return started["path"]

    def push_with(self, *refspecs):
        """Authenticated push: the executed client is the server's started Git.

        ``CompletedProcess`` has no ``executable``; its ``args[0]`` is the argv
        entry subprocess launched for this exact call.  It is checked against
        the probed client and the Git captured when the live server process
        started, never against an environment a helper may have mutated.
        """
        server_git = self.started_server_git()
        completed = self.git_as(self.alice, "push", "--porcelain", "origin", *refspecs)
        probe = self.native_git_probe()
        launched = str(Path(completed.args[0]).resolve())
        assert launched == probe["executable"] == server_git, (
            "the push client is not the probed Git the server started with: "
            + repr({"launched": launched, "probed": probe["executable"], "server_git": server_git}))
        runner = Path(self.env["ROOTYARD_DATA_DIR"]) / "managed-hooks" / ".runner"
        observed = self._sha256(runner) if runner.is_file() else None
        self.git_evidence = {"client": probe["executable"], "client_sha256": probe["sha256"],
                             "client_version": probe["version"], "declared": probe["declared"],
                             "push_actor": "alice", "push_header": "http.extraHeader (per push)",
                             "server_git": server_git,
                             "server_configured": getattr(self, "server_git", {}).get("configured"),
                             "managed_hook_runner_sha256": observed,
                             "notes": probe["notes"]}
        return completed, probe

    def require_git_atomic(self):
        version = self.native_git_probe()["minor"]
        assert version >= (2, 43), "stock Git --atomic needs Git 2.43 or newer, found " + repr(version)

    def repo_api(self, suffix="", repo="demo", owner="alice"):
        """One repository's API path; resolved at call time on this harness."""
        return "/api/repos/" + owner + "/" + repo + suffix

    def ref_oids(self, *names):
        """Exact server-side OIDs of the named refs in the run-owned bare repository."""
        result = {}
        for name in names:
            probe = self.git("--git-dir=" + str(self.bare), "rev-parse", "--verify", "-q", name, check=False)
            result[name] = probe.stdout.decode().strip() if probe.returncode == 0 else None
        return result

    def pending_journal(self):
        journal = Path(self.env["ROOTYARD_DATA_DIR"]) / "journal" / self.repo["id"]
        return sorted(p.name for p in journal.iterdir() if p.is_dir()) if journal.is_dir() else []

    def repository_marker(self):
        return self.sql("SELECT state || '/' || COALESCE(recovery_reason,'-') FROM repositories WHERE id='"
                        + self._sql_literal(self.repo["id"]) + "'")

    @staticmethod
    def assert_push_refusals(completed, *refs):
        """Every named ref must be rejected BY THE SERVER, with no local no-op.

        ``git push --porcelain`` prints one status line per ref: ``!`` is a
        rejection (local or remote) and ``=`` an up-to-date client ref.  A local
        ``=`` would make the all-or-nothing claim vacuous and a local
        ``[rejected]`` (e.g. non-fast-forward caught by the client) never
        reached the server, so every named ref must be ``!`` with a
        ``[remote rejected]`` summary.
        """
        # Flags first (``+ - = * !``), then one status token, e.g. ``!\t<loc>:<rem>\t[remote rejected]``.
        pattern = re.compile(r"^([+\-=*! ]?)[ \t]*(\S+)(?:\t(.*))?$")
        status, ignored = {}, []
        for line in completed.stdout.decode(errors="replace").splitlines():
            match = pattern.match(line)
            if not match or match.group(1) not in ("!", "=", "*", "+", "-", " "):
                if line.strip():
                    ignored.append(line)
                continue
            if ":" not in match.group(2):
                ignored.append(line)  # header lines such as "To <url>"
                continue
            remote = match.group(2).split(":", 1)[1]
            status[remote] = {"flag": match.group(1).strip(), "summary": (match.group(3) or "").strip(),
                              "line": (match.group(1).strip() + " " + match.group(2)
                                       + " " + (match.group(3) or "")).strip()}
        # Non-ref output (the "To <url>" header, "Everything up-to-date", hints)
        # is advisory evidence next to the per-ref lines.
        detail = {"returncode": completed.returncode, "refs": status, "other_output": ignored,
                  "stderr": completed.stderr.decode(errors="replace")[-600:]}
        assert completed.returncode != 0 and status, "push was not refused per ref: " + json.dumps(detail)
        for ref in refs:
            line = status.get(ref)
            assert line is not None and line["flag"] == "!" and line["summary"].startswith("[remote rejected]"), (
                "ref " + ref + " was not server-refused (a local no-op or local [rejected] is not "
                "all-or-nothing evidence): " + json.dumps(detail))
        return detail

    def ref_state(self):
        """Physical refs from the run-owned bare repo, API refs, journal, baseline.

        Stock ``for-each-ref`` is the only source of physical refs; the API refs
        are read separately and bound the public view.  The operation high-water
        bounds the write interval, so no global counter is a gate.
        """
        from refusal_audit_sql import operation_highwater_query
        repo = self._sql_literal(self.repo["id"])
        operation_highwater = int(self.sql(operation_highwater_query(self.repo["id"], self._sql_literal)))
        api_refs = sorted(public_refs(self, self.repo_api("")))
        probe = subprocess.run([self.native_git()["executable"], "--git-dir=" + str(self.bare),
                                "for-each-ref", "--format=%(refname)%00%(objectname)"],
                               cwd=self.root, capture_output=True, timeout=60)
        if probe.returncode:
            raise AssertionError("for-each-ref failed (" + str(probe.returncode) + "): "
                                 + probe.stderr.decode(errors="replace")[-600:])
        refs = []
        for line in probe.stdout.decode("ascii").splitlines():
            if not line:
                continue
            parts = line.split("\x00")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                raise RuntimeError("malformed for-each-ref line: " + repr(line))
            refs.append((parts[0], parts[1]))
        refs.sort()
        # Counts are recorded beside the interval evidence for the report only;
        # no audit gates on them (the causal operation interval is the gate).
        # Reuse the same SQL helper for every report-only count in the snapshot.
        sql = self.sql
        return {"operation_highwater": operation_highwater,
                "refs": refs,
                "api_refs": api_refs,
                "outbox": int(sql("SELECT count(*) FROM outbox_events WHERE repository_id='" + repo + "'")),
                # Per-outcome counts of this repository's stored operations: the
                # same report-only text map shape as ``admissions``, from one
                # read-only GROUP BY on the ``(repository_id, ...)`` index.
                "outcomes": dict((k, int(v)) for k, v in (item.split(":") for item in sql(
                    "SELECT coalesce(string_agg(outcome || ':' || n::text, ',' ORDER BY outcome), '') FROM "
                    "(SELECT outcome, count(*) AS n FROM git_operations WHERE repository_id='" + repo
                    + "' GROUP BY outcome) r").split(",") if item)),
                "admissions": dict((k, int(v)) for k, v in (item.split(":") for item in sql(
                    "SELECT coalesce(string_agg(state || ':' || n::text, ',' ORDER BY state), '') FROM "
                    "(SELECT state, count(*) AS n FROM git_ref_admissions WHERE repository_id='" + repo
                    + "' GROUP BY state) r").split(",") if item)),
                "journal": self.pending_journal(),
                "state": self.repository_marker()}

    def assert_one_aborted_refusal(self, before, label, refs):
        return audit_git_refusal_interval(
            before,
            label,
            refs,
            self.operation_rows_since,
            self.service_release_valid,
            self.pending_journal,
            self.ref_state,
        )

    def assert_api_refusal(self, before, after, label, refs):
        return audit_api_refusal_interval(
            before, after, label, refs, self.operation_rows_since, self.service_release_valid, self.ref_state
        )

    def operation_rows_since(self, highwater):
        """Operations committed after ``highwater`` for this repo, strictly decoded.

        The repo id and the run's ``alice["user_id"]``/``alice["token_id"]`` are
        handed to the query raw; ``operations_after_query`` quotes them through
        ``_sql_literal`` itself, so they must not be pre-escaped here.
        """
        from refusal_audit_sql import operations_after_query, decode_operation_interval

        query = operations_after_query(
            self.repo["id"],
            highwater,
            self.alice["user_id"],
            self.alice["token_id"],
            self._sql_literal,
        )
        return decode_operation_interval(self.sql(query), highwater)

    def service_release_valid(self, row):
        """Whether the release recorded for ``row["operation_id"]`` is valid.

        Reads the single scalar answer once: only a literal ``true`` (after
        surrounding whitespace is stripped) counts.
        """
        from refusal_audit_sql import service_release_valid_query

        query = service_release_valid_query(
            row["operation_id"],
            self.repo["id"],
            self._sql_literal,
        )
        return self.sql(query).strip() == "true"

    def assert_no_open_journal(self):
        pending = self.pending_journal()
        assert pending == [], "successful push left an unsettled journal operation: " + repr(pending)
        assert self.repository_marker() == "ready/-", "successful push left the repository fenced"

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

    def native_group(self, main, topic):
        """Group 1: stock Git's own atomicity with NO branch rule at all.

        ``isolated_rules`` has removed every rule and nothing is created here:
        the only refusal that can answer a forced non-fast-forward main is stock
        Git (the server's ``receive.denyNonFastForwards`` receive pack), refused
        for both refs of one ``--atomic`` push and reported by the ref
        admission / journal audit. The refspec carries a ``+`` so only the
        server can refuse; a no-op or hint-only outcome is not evidence.
        """
        self.assert_rule_state({})
        assert not self.pulled, "the native group must have no pull authorizing main"
        assert self.ref_oids(topic)[topic] is None, "the native group needs a fresh topic"
        # The server has not turned its own non-fast-forward denial off.
        denial = self.git("--git-dir=" + str(self.bare), "config", "--get", "receive.denyNonFastForwards")
        assert denial.stdout.decode().strip() == "true", "receive.denyNonFastForwards is not true: " + repr(denial.stdout)
        before = self.ref_state()
        assert dict(before["refs"]).get(main) == self.third, before["refs"]
        listed = dict(before["api_refs"])
        assert listed.get(main) == self.third, "the API must advertise the refused base"
        # The server-start Git is proven before any mixed write is attempted.
        self.started_server_git()
        refused = self.push_as_owner("--atomic", "+" + self.first + ":" + main,
                                     self.feature_oid + ":" + topic)
        assert refused.returncode != 0, "non-fast-forward main was accepted"
        per_ref = self.assert_push_refusals(refused, main, topic)
        audit = self.assert_one_aborted_refusal(before, "native stock Git refusal", [main, topic])
        assert self.remote_oid(main) == self.third
        return {"policy": "no branch rule on main or the topic (none exists)",
                "pull_alone_authorizes": None, "token": "owner (create-user) grant",
                "refusal": per_ref, "audit": audit,
                "reason": "stock Git rejected a forced non-fast-forward in an atomic push"}

    def policy_group(self, main, topic, native_refusal):
        """Group 2: only the refresh-style direct-write rule can refuse.

        Every rule field a protected-write decision reads is permissive except
        ``required_approvals``, so neither stock Git (the update fast-forwards
        from the live tip) nor a rule flag can own the refusal.
        """
        base = self.advertised_oid(main)
        assert base == self.third, base
        policy_oid = self.commit_over(base, "policy-step.txt")
        self.policy_rule(main, require_fast_forward=False, prevent_force_push=False,
                         prevent_deletion=False)
        self.assert_rule_state({main: {"required_approvals": 1, "prevent_force_push": False,
                                       "require_fast_forward": False}})
        self.open_pull_for_main(policy_oid)
        before = self.ref_state()
        refused = self.push_as_owner("--atomic", policy_oid + ":" + main,
                                     self.feature_oid + ":" + topic)
        assert refused.returncode != 0, "approval-protected main accepted a direct push"
        per_ref = self.assert_push_refusals(refused, main, topic)
        pair_audit = self.assert_one_aborted_refusal(before, "policy refusal", [main, topic])
        # The paired unprotected-only request succeeds (transport control).
        self.git_as(self.alice, "push", "origin", self.feature_oid + ":" + topic, check=True)
        assert self.ref_oids(topic)[topic] == self.feature_oid
        # The protected half alone is refused too: a NEW real baseline right
        # before the push, never the state from before the control push.
        before = self.ref_state()
        assert dict(before["refs"]).get(topic) == self.feature_oid, before["refs"]
        alone = self.assert_push_refusals(self.git_as(
            self.alice, "push", "--porcelain", "origin", policy_oid + ":" + main), main)
        alone_audit = self.assert_one_aborted_refusal(before, "protected half alone", [main])
        assert self.remote_oid(main) == self.third
        return {"policy": "one approval on main; fast-forward/deletion/force-push flags off",
                "pull_head_oid": policy_oid, "pull_alone_authorizes": False, "base_oid": base,
                "refusal": per_ref, "audit": pair_audit,
                "git_refusal": native_refusal,
                "protected_half_alone": alone,
                "protected_half_audit": alone_audit,
                "reason": "direct-write policy: approvals need a PR merge"}

    def mixed_protected_unprotected_atomic_push(self):
        # Each group runs inside its own exact rule set, restored afterwards.
        main, topic = "refs/heads/main", "refs/heads/mixed-topic"
        with self.isolated_rules():
            self.require_git_atomic()
            native = self.native_group(main, topic)
            policy = self.policy_group(main, topic, native["audit"])
            self.assert_no_open_journal()
            return {"git": self.git_evidence, "native_group": native, "policy_group": policy,
                    "rules_restored": True}

    def mixed_protected_unprotected_ref_transaction(self):
        """The API: mixed refusal first, the topic control, then protected alone.

        The API refuses inside its own handler, before it journals anything, so
        every refusal here must leave the *whole* durable state identical (zero
        operations).  The Git ``+1`` settled-audit rule is never applied here.
        """
        main, topic = "refs/heads/main", "refs/heads/mixed-tx-topic"
        path = self.repo_api("/ref-transactions")

        def transact(updates):
            status, body, _ = self.http(path, token=self.alice, method="POST",
                                        body={"storage_generation": 1, "atomic": True,
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
            return {"seed_without_rule": {"ref": seed, "status": 200},
                    "policy_mixed_first": policy_mixed,
                    "control_unprotected_admitted": {"refs": [topic, control], "status": 200},
                    "protected_alone": alone, "baseline_after_control": True,
                    "stale_cas_after_control": stale,
                    "api_operations_delta": 0,
                    # The interval audit is the gate; these are recorded only.
                    "operations_before_after": [base["operation_highwater"],
                                                after_alone["operation_highwater"]],
                    "admissions_before_after": [base["admissions"], after_alone["admissions"]],
                    "outbox_before_after": [base["outbox"], after_alone["outbox"]]}


def release_git_option(parser):
    """Declare the trusted client Git option on the Browse runner."""
    parser.add_argument("--git", help="trusted stock Git used as client AND server Git (or ROOTYARD_GIT)")
