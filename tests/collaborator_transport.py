#!/usr/bin/env python3
"""Issue #4: direct collaborator read/write/admin authorization across Git and write endpoints.

Every positive case starts from the real repository API and grants its acting
user through the owner's real ``PUT /api/repos/{owner}/{name}/collaborators/
{user}`` call. No SQL insert manufactures a collaborator row, a ready
repository, a pull request, an object or a ref. The matrix below is the
product contract read from this checkout (``git_http.rs``,
``browse/transactions.rs``, ``pulls/merge.rs``, ``pulls/rules.rs``,
``members/rbac.rs``, ``auth.rs``), for direct ``repository_collaborators``
roles only. Teams and organizations are covered by ``tests/organizations.py``
and ``tests/members.py``.

Roles resolve as ``read < triage < write < maintain < admin``
(``resolve_effective_role``). Transport and the write endpoints require:

  upload-pack (clone/fetch/ls-remote)  read
  Git receive-pack / push              write
  POST /ref-transactions               write
  POST /pulls, POST /pulls/{n}/merge   write
  PUT /branch-rules/...                maintain
  POST|PUT|DELETE /collaborators/...   admin, but never a direct collaborator
                                       (the owner resolves as admin and only
                                       the owner is refused the owner row)

So ``read``/``triage`` are deliberately expected to be refused on every write
path; ``write``, ``maintain`` and ``admin`` succeed. A read-only token stays
403 on every mutating path even for a ``write`` collaborator; a
non-collaborator gets 404 without enumeration; a withdrawn collaborator loses
new requests without erasing the receipts recorded while the grant was live.

Git transport writes ``git_operations`` and ``outbox_events``, never
``repository_audit_log``; that table is only touched by Forge/member writes.
"""
import argparse
import ast
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(PACKAGE_ROOT / "scripts"))
from reliability import ReliabilityHarness  # noqa: E402

ZERO = "0" * 40
# CI installs Git 2.43; the plain clone/fetch/push matrix needs no newer Git.
MIN_GIT = (2, 39)
# Git is executed by: the harness client (``self.git``), the service client
# (``Config::from_env``: ROOTYARD_GIT or the first ``git`` on PATH) and the
# managed hook (installed from the running binary; it runs the server and hook
# steps through that same Config.git), so only exact binary/version equality is
# meaningful. The commands below are this harness's own argv; anything the job
# runs elsewhere is reported by ``git_command_coverage`` instead of counted here.
EXECUTED_GIT_COMMANDS = frozenset({
    "add", "checkout", "clone", "commit", "config", "fetch", "ls-remote", "merge-base",
    "push", "reset", "rev-parse", "status",
})
RECEIVE = "application/x-git-receive-pack-request"
# Fixture users. Their only route to alice/demo is a grant made through the
# owner API inside this run; the six in STAFF_USERS first act as owner of an
# API-created repository of their own, so a grant to alice/demo is not their
# only live permission.
FIXTURE_USERS = ("bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan",
                 "judy", "karl", "linda", "mona", "nina", "olga", "peggy", "quinn")
STAFF_USERS = ("erin", "frank", "grace", "heidi", "karl", "linda")
UPLOAD_REFS = "/info/refs?service=git-upload-pack"
RECEIVE_REFS = "/info/refs?service=git-receive-pack"


def git_version(text):
    """Parse ``git version X.Y.Z``; unparsable output is a failure, never a skip."""
    words = str(text).split()
    assert len(words) >= 3 and words[0] == "git" and words[1] == "version", text
    try:
        numbers = tuple(int(part) for part in words[2].split(".")[:3])
    except ValueError as error:
        raise AssertionError("unparsable Git version " + repr(text)) from error
    assert len(numbers) == 3 and all(part >= 0 for part in numbers), text
    return numbers


def invoked_git_commands(path):
    """Subcommands ``path`` executes via ``self.git("x")`` or ``run(["git", ...])``.

    ``test_browse_git_read_steps.py`` declares its Git matrix statically because
    it controls every argument; this harness routes calls through helpers, so
    the declaration is derived from its own helper bodies (see
    ``git_command_coverage``).
    """
    found = set()
    for node in ast.walk(ast.parse(Path(path).read_text())):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr == "git":
            if node.args and isinstance(node.args[0], ast.Constant):
                found.add(node.args[0].value)
        elif (node.func.attr == "run" and node.args
              and isinstance(node.args[0], ast.List)):
            argv = [item.value for item in node.args[0].elts if isinstance(item, ast.Constant)]
            if "git" in argv:
                tail = argv[argv.index("git") + 1:]
                while tail and tail[0].startswith("-"):
                    tail = tail[2:] if tail[0] == "-c" else tail[1:]
                if tail:
                    found.add(tail[0])
    return found


class CollaboratorTransportHarness(ReliabilityHarness):
    def __init__(self, args):
        super().__init__(args)
        self.limits = [
            "Owned loopback service, owned PostgreSQL schema and temporary data directory only.",
            "Direct repository_collaborators roles only; teams/organizations are other suites.",
            "Git refs, git_operations and outbox_events are authoritative; Git HTTP status is observed.",
            "No object store, kernel fault, power loss or production connection is exercised.",
        ]
        self.users = {}

    # ---- prerequisites ---------------------------------------------------
    def server_git(self):
        """Resolve the server client exactly like Config::from_env (ROOTYARD_GIT, else PATH)."""
        configured = self.env.get("ROOTYARD_GIT")
        if configured:
            return str(Path(configured).resolve())
        found = os.environ.get("PATH", os.defpath).split(os.pathsep)
        for entry in found:
            if entry and (Path(entry) / "git").is_file():
                return str((Path(entry) / "git").resolve())
        raise AssertionError("required dependency missing: no git executable on server PATH")

    def hook_git(self):
        """The managed hook receives Config.git as ROOTYARD_GIT_PATH (see git_http.rs)."""
        return self.server_git()

    def git_matrix_version(self):
        # Boot one owned service so the managed hook is materialized, then bind
        # it to the executed binary by digest instead of assuming its path.
        self.setup()
        runner = self.root / "data/managed-hooks/.runner"
        with runner.open("rb") as source:
            hook_sha = hashlib.file_digest(source, "sha256").hexdigest()
        with Path(self.args.binary).open("rb") as source:
            binary_sha = hashlib.file_digest(source, "sha256").hexdigest()
        assert hook_sha == binary_sha, "installed hook is not the executed binary"
        for name in ("pre-receive", "reference-transaction", "post-receive"):
            assert (runner.parent / name).resolve() == runner.resolve(), name
        triple = {"harness": "git", "server": self.server_git(), "hook": self.hook_git()}
        versions, raw = {}, {}
        for label, executable in triple.items():
            raw[label] = self.run([executable, "--version"]).stdout.decode().strip()
            versions[label] = git_version(raw[label])
            assert versions[label] >= MIN_GIT, (
                f"required Git >= {'.'.join(map(str, MIN_GIT))}; {label} is {raw[label]!r}")
        assert len(set(triple.values())) == 1, "harness, server and hook must execute one Git binary"
        unique = self.run(["git", "--version"]).stdout.decode().strip()
        assert unique == raw["harness"]
        with Path(__file__).open("rb") as source:
            harness_sha = hashlib.file_digest(source, "sha256").hexdigest()
        return {"versions": {k: ".".join(map(str, v)) for k, v in versions.items()},
                "same_binary": triple, "hook_binary_sha256": hook_sha, "harness_sha256": harness_sha}

    def git_command_coverage(self):
        """The commands this harness runs, and whether the CI job runs them elsewhere."""
        import inspect
        import e2e
        import members
        import reliability
        own = invoked_git_commands(Path(__file__))
        assert own == set(EXECUTED_GIT_COMMANDS), sorted(own ^ set(EXECUTED_GIT_COMMANDS))
        elsewhere = set()
        for module in (e2e, reliability, members):
            elsewhere |= invoked_git_commands(Path(inspect.getfile(module)))
        return {"executed_git_commands": sorted(own), "unique_commands": len(own),
                "upstream_commands": sorted(own & elsewhere),
                "not_run_by_upstream_suites": sorted(own - elsewhere)}

    def native_executed_by_implementer(self):
        """Truthful attribution: a self-run service in implement-forbidden environments is not native evidence."""
        if os.environ.get("ROOTYARD_NATIVE_EXECUTED_BY_IMPLEMENTER", "").strip().lower() == "true":
            return True
        return {"sys.platform": sys.platform, "machine": os.uname().machine}

    def source_binding(self):
        """Bind the executed binary to the current production inputs via its build receipt."""
        root = Path(__file__).resolve().parents[1]
        receipt_path = Path(self.args.binary).with_suffix(".build.json")
        assert receipt_path.is_file(), (
            "required dependency missing: no scripts/build_native.py receipt beside "
            + str(self.args.binary))
        receipt = json.loads(receipt_path.read_text())
        with Path(self.args.binary).open("rb") as source:
            binary_sha = hashlib.file_digest(source, "sha256").hexdigest()
        assert receipt.get("binary_sha256") == binary_sha, "executed binary differs from its receipt"
        import build_native  # scripts/ is not a package; same digest function as the build
        current = build_native.source_digest()
        assert current == receipt["source_inputs_sha256"], (
            "current src/Cargo/migrations/schema/vendor inputs differ from the binary's build")
        head = self.git("rev-parse", "HEAD", cwd=root).stdout.decode().strip()
        tracked = self.git("status", "--porcelain", "--untracked-files=no", cwd=root,
                           env=dict(self.env, GIT_OPTIONAL_LOCKS="0")).stdout
        assert not tracked.strip(), "tracked inputs are dirty: console builds embed differing debug paths"
        parent = receipt["workspace_commit"]
        assert self.git("merge-base", "--is-ancestor", parent, head, cwd=root,
                        check=False).returncode == 0
        with Path(__file__).open("rb") as source:
            harness_sha = hashlib.file_digest(source, "sha256").hexdigest()
        return {"source_commit": head, "binary_source_commit": parent,
                "binary_commit_is_ancestor": True,
                "source_inputs_sha256": current, "binary_sha256": binary_sha,
                "rustc": receipt.get("rustc"), "build_command": receipt.get("command"),
                "harness": {"file": str(Path(__file__).relative_to(root)), "sha256": harness_sha},
                "identity": "owned schema " + self.schema}

    # ---- helpers ---------------------------------------------------------
    def identity(self):
        return {"schema": self.schema, "database_url": self.redact(self.db),
                "server_pid": self.proc.pid if self.proc else None,
                "repository": self.repo["id"], "owner": self.repo["owner"],
                "name": self.repo["name"]}

    def worker(self, user):
        """A fresh clone for ``user`` so Git never reads or writes a peer's tree."""
        work = self.root / ("owned-work-" + user)
        self.git("clone", self.remote, str(work), token=self.users[user])
        self.git("config", "user.name", user.title(), cwd=work)
        self.git("config", "user.email", user + "@collaborator.invalid", cwd=work)
        return work

    def commit(self, work, filename, message):
        (work / filename).write_text(message + "\n")
        self.git("add", filename, cwd=work)
        self.git("commit", "-m", message, cwd=work)
        return self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()

    def push_branch(self, work, token, branch, base="origin"):
        self.git("push", base, "HEAD:refs/heads/" + branch, cwd=work, token=token)
        return self.ref("refs/heads/" + branch)

    def receive_refs_status(self, token):
        return self.http(self.repo["clone_path"] + RECEIVE_REFS, token=token)[0]

    def upload_status(self, token):
        return self.http(self.repo["clone_path"] + UPLOAD_REFS, token=token)[0]

    def grant(self, user, role):
        """Owner grants a direct role through the real API (201 then 200)."""
        path = f"/api/repos/alice/demo/collaborators/{user}"
        created = json.loads(self.expect(path, 201, method="PUT", token=self.alice,
                                         body={"role": role, "username": user}))
        assert created["username"] == user and created["role"] == role, created
        assert self.sql("SELECT role FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.users[user]["user_id"] + "'") == role
        return created

    def events_for(self, ref_name, operation_id=None):
        return [event for event in self.events()
                if event["ref_name"] == ref_name
                and (operation_id is None or event["operation_id"] == operation_id)]

    # ---- cases -----------------------------------------------------------
    def environment(self):
        self.setup()
        for name in FIXTURE_USERS:
            if name not in ("alice", "bob"):
                self.users[name] = self.account("create-user", name)
        self.repo = self.create_repository({"name": "demo"}, token=self.alice)
        assert self.repo["state"] == "ready" and self.repo["clone_path"] == "/git/alice/demo.git"
        self.remote = self.base + self.repo["clone_path"]
        self.bare = self.root / "data/repos" / (self.repo["id"] + ".git")
        # Owner-only fixture history; it is never evidence of a collaborator action.
        work = self.root / "owned-work-alice"
        self.git("clone", self.remote, str(work), token=self.alice)
        self.git("config", "user.name", "Alice", cwd=work)
        self.git("config", "user.email", "alice@collaborator.invalid", cwd=work)
        self.seed = self.commit(work, "README.md", "collaborator matrix seed")
        assert self.push_branch(work, self.alice, "main") == self.seed
        return {"collaborator_rows": 0, "ready_via": "POST /api/repos", **self.identity()}

    def role_matrix(self):
        """clone/fetch/push per direct role; read/triage legitimately cannot write."""
        rows = {}
        for user, role in {"carol": "read", "dave": "triage", "erin": "write",
                           "frank": "maintain", "grace": "admin"}.items():
            self.grant(user, role)
            token = self.users[user]
            permission = json.loads(self.expect(f"/api/repos/alice/demo/permissions/{user}", 200,
                                                token=self.alice))
            assert (permission["role"], permission["direct_role"], permission["is_owner"]) == (
                role, role, False), permission
            work = self.worker(user)
            assert (work / "README.md").read_text() == "collaborator matrix seed\n"
            self.git("fetch", "origin", cwd=work, token=token)
            assert self.git("rev-parse", "origin/main", cwd=work).stdout.decode().strip() == self.seed
            assert self.upload_status(token) == 200
            branch = "role-push-" + user
            oid = self.commit(work, "role.txt", "push as " + role)
            if role in ("read", "triage"):
                # Deleting an absent branch reaches receive-pack with no object
                # transfer, so Git cannot answer from a client-side preflight.
                deleted = self.git("push", "origin", ":" + branch, cwd=work, token=token,
                                   check=False)
                assert deleted.returncode != 0
                denied = self.git("push", "origin", "HEAD:refs/heads/" + branch, cwd=work,
                                  token=token, check=False)
                assert denied.returncode != 0
                assert self.receive_refs_status(token) == 403
                assert self.ref("refs/heads/" + branch) is None
                assert not self.events_for("refs/heads/" + branch)
                outcome = "denied"
            else:
                assert self.push_branch(work, token, branch) == oid
                operation = self.last_operation("recorded")
                assert operation["actor_id"] == self.users[user]["user_id"]
                assert operation["actor_name"] == user
                assert operation["token_id"] == token["token_id"]
                events = self.events_for("refs/heads/" + branch, operation["id"])
                assert [(e["old_oid"], e["new_oid"]) for e in events] == [(ZERO, oid)], events
                outcome = "recorded"
            rows[user] = {"role": role, "clone": True, "fetch": True, "push": outcome}
        assert [row["push"] for row in rows.values()] == [
            "denied", "denied", "recorded", "recorded", "recorded"]
        return rows

    def fetch_propagation(self):
        """The owner's later commit reaches every role; read rows still cannot publish."""
        branch = "owner-feature"
        work = self.root / "owned-work-alice"
        self.git("checkout", "-B", "publish", self.seed, cwd=work)
        oid = self.commit(work, "feature.txt", "owner feature")
        assert self.push_branch(work, self.alice, branch) == oid
        received = {}
        for user, role in (("carol", "read"), ("dave", "triage"), ("erin", "write"),
                           ("frank", "maintain"), ("grace", "admin")):
            peer = self.worker("fetch-" + user)
            if role in ("read", "triage"):
                denied = self.git("push", "origin", "HEAD:refs/heads/fetch-" + user, cwd=peer,
                                  token=self.users[user], check=False)
                assert denied.returncode != 0 and self.ref("refs/heads/fetch-" + user) is None
            self.git("fetch", "origin", cwd=peer, token=self.users[user])
            assert self.git("rev-parse", "origin/" + branch, cwd=peer).stdout.decode().strip() == oid
            received[user] = True
        return received

    def outsider_isolation(self):
        """A valid non-collaborator gets 404 on API/Git and no enumerable difference."""
        token = self.users["quinn"]
        reads = ["/api/repos/alice/demo", "/api/repos/alice/demo/refs",
                 "/api/repos/alice/demo/commits", "/api/repos/alice/demo/pulls"]
        for path in reads:
            status, body, _ = self.http(path, token=token)
            assert status == 404, (path, status)
            assert b"alice" not in body and b"demo" not in body, (path, body[:200])
        writes = (("/api/repos/alice/demo/issues", {"title": "outsider"}),
                  ("/api/repos/alice/demo/ref-transactions",
                   {"updates": [{"ref_name": "refs/heads/outsider", "old_oid": ZERO,
                                 "new_oid": self.seed}], "atomic": True}),
                  ("/api/repos/alice/demo/pulls",
                   {"title": "outsider", "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main"}),
                  ("/api/repos/alice/demo/pulls/1/merge",
                   {"expected_version": 1, "expected_head_oid": self.seed,
                    "expected_base_oid": self.seed}))
        for path, body in writes:
            status, raw, _ = self.http(path, token=token, method="POST", body=body)
            assert status == 404, (path, status, raw[:200])
        assert self.upload_status(token) == 404
        assert self.receive_refs_status(token) == 404
        # No-body receive-pack POST is refused before hooks; the ref must stay absent.
        status, _, _ = self.http(self.repo["clone_path"] + "/git-receive-pack", 404, token=token,
                                 method="POST", body=b"0000", content_type=RECEIVE)
        assert status == 404
        denied = self.git("ls-remote", self.remote, token=token, check=False)
        assert denied.returncode != 0 and self.seed.encode() not in denied.stdout
        assert self.ref("refs/heads/outsider") is None
        assert self.sql("SELECT count(*) FROM repository_collaborators WHERE user_id='" +
                        token["user_id"] + "'") == "0"
        return {"api_read": "404", "api_write": "404", "upload_pack": 404,
                "receive_pack": 404, "ls_remote": "denied"}

    def read_only_token(self):
        """A read-only token of the write collaborator keeps 403 on every write path."""
        token = self.account("create-token", "erin", "--read-only")
        work = self.root / "owned-work-erin_ro"
        self.git("clone", self.remote, str(work), token=token)
        assert (work / "README.md").is_file()
        assert self.upload_status(token) == 200
        assert self.receive_refs_status(token) == 403
        (work / "ro.txt").write_text("read-only push\n")
        self.git("add", "ro.txt", cwd=work)
        self.git("commit", "-m", "read-only push", cwd=work)
        denied = self.git("push", "origin", "HEAD:refs/heads/read-only-token", cwd=work,
                          token=token, check=False)
        assert denied.returncode != 0 and self.ref("refs/heads/read-only-token") is None
        before_ops, before_events = self.operations(), self.events()
        status, wire = self.raw_receive(token)
        assert status == 403, (status, wire[:200])
        writes = (("/api/repos/alice/demo/ref-transactions",
                   {"updates": [{"ref_name": "refs/heads/ro-tx", "old_oid": ZERO,
                                 "new_oid": self.seed}], "atomic": True}),
                  ("/api/repos/alice/demo/pulls",
                   {"title": "read-only PR", "head_ref": "refs/heads/feature",
                    "base_ref": "refs/heads/main"}),
                  ("/api/repos/alice/demo/pulls/1/merge",
                   {"expected_version": 1, "expected_head_oid": self.seed,
                    "expected_base_oid": self.seed}),
                  ("/api/repos/alice/demo/branch-rules/refs/heads/main", {"required_approvals": 0}))
        for path, body in writes:
            method = "PUT" if "branch-rules" in path else "POST"
            code, raw, _ = self.http(path, token=token, method=method, body=body)
            assert code == 403, (path, code, raw[:200])
        code, _, _ = self.http("/api/repos/alice/demo/collaborators/heidi", token=token,
                               method="PUT", body={"role": "admin"})
        assert code == 403, code
        assert self.sql("SELECT count(*) FROM forge_branch_rules") == "0"
        assert self.ref("refs/heads/ro-tx") is None
        assert self.operations() == before_ops and self.events() == before_events
        return {"read": "allowed", "receive_pack": status, "raw_receive_pack": status,
                "push": "denied", "write_endpoints": "403", "ref_transactions": "unchanged"}

    def raw_receive(self, token):
        """A complete but table-less receive-pack request: the gate answers 403."""
        auth = "Basic " + base64.b64encode(
            (token["username"] + ":" + token["token"]).encode()).decode()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            connection.request("POST", self.repo["clone_path"] + "/git-receive-pack",
                               body=b"0000", headers={"Authorization": auth, "Content-Type": RECEIVE})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def non_fast_forward(self):
        """Higher roles add no capability: fast-forward-only still refuses a rewind.

        Production sets ``receive.denyNonFastForwards`` (src/storage.rs) and no
        branch rule exists on these branches yet.
        """
        assert self.sql("SELECT count(*) FROM forge_branch_rules WHERE branch_ref LIKE 'refs/heads/ff-%'") == "0"
        results = {}
        for user, role in (("erin", "write"), ("grace", "admin")):
            work = self.worker("ff-" + user)
            self.git("checkout", "-B", "ff-" + user, cwd=work)
            self.commit(work, "ff.txt", "first " + user)
            first = self.push_branch(work, self.users[user], "ff-" + user)
            self.commit(work, "ff.txt", "second " + user)
            second = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
            self.git("reset", "--hard", first, cwd=work)
            stale = self.commit(work, "stale.txt", "stale " + user)
            assert stale not in (first, second)
            denied = self.git("push", "--force", "origin", "HEAD:refs/heads/ff-" + user, cwd=work,
                              token=self.users[user], check=False)
            assert denied.returncode != 0 and self.ref("refs/heads/ff-" + user) == first
            results[role] = "rejected"
        return results

    def ref_transactions(self):
        """read/triage 403; write and above 200 with actor-bound events and idempotency."""
        outcomes = {}
        vendor = self.root / "owned-work-alice"
        for user, role in (("carol", "read"), ("dave", "triage"), ("erin", "write"),
                           ("frank", "maintain"), ("grace", "admin")):
            self.git("checkout", "-B", "vendor-" + user, self.seed, cwd=vendor)
            oid = self.commit(vendor, "vendor-" + user + ".txt", "vendor " + user)
            self.push_branch(vendor, self.alice, "vendor-" + user)
            ref = "refs/heads/tx-" + user
            body = {"updates": [{"ref_name": ref, "old_oid": ZERO, "new_oid": oid}],
                    "atomic": True, "storage_generation": 1}
            status, raw, _ = self.http("/api/repos/alice/demo/ref-transactions",
                                       token=self.users[user], method="POST", body=body)
            if role in ("read", "triage"):
                assert status == 403, (user, role, status, raw[:200])
                assert self.ref(ref) is None and not self.events_for(ref)
                outcomes[role] = status
                continue
            assert status == 200, (user, role, status, raw[:300])
            applied = json.loads(raw)
            assert applied["atomic"] is True and applied["updates"] == body["updates"], applied
            assert self.ref(ref) == oid
            [operation] = [op for op in self.operations() if op["id"] == applied["operation_id"]]
            assert operation["outcome"] == "recorded", operation
            assert (operation["actor_id"], operation["actor_name"], operation["token_id"]) == (
                self.users[user]["user_id"], user, self.users[user]["token_id"])
            events = self.events_for(ref, operation["id"])
            assert [(e["old_oid"], e["new_oid"]) for e in events] == [(ZERO, oid)], events
            key = {"Idempotency-Key": "tx-" + user + "-key"}
            first = self.expect("/api/repos/alice/demo/ref-transactions", 200, token=self.users[user],
                                method="POST", body=body, extra_headers=key)
            second = self.expect("/api/repos/alice/demo/ref-transactions", 200, token=self.users[user],
                                 method="POST", body=body, extra_headers=key)
            assert first == second == raw and len(self.events_for(ref)) == 1
            changed = {"updates": [{"ref_name": "refs/heads/other-" + user, "old_oid": ZERO,
                                    "new_oid": oid}], "atomic": True}
            conflict = self.http("/api/repos/alice/demo/ref-transactions", token=self.users[user],
                                 method="POST", body=changed, extra_headers=key)[0]
            assert conflict == 409, conflict
            outcomes[role] = 200
        assert outcomes == {"read": 403, "triage": 403, "write": 200, "maintain": 200, "admin": 200}
        return outcomes

    def pull_lifecycle(self):
        """PR create and merge require write; every write+ role merges a real FF."""
        pulls = "/api/repos/alice/demo/pulls"
        vendor = self.root / "owned-work-alice"
        self.git("checkout", "-B", "pr-base", self.seed, cwd=vendor)
        self.push_branch(vendor, self.alice, "base")
        base = self.ref("refs/heads/base")
        for user in ("carol", "dave"):
            status, raw, _ = self.http(pulls, token=self.users[user], method="POST",
                                       body={"title": "denied " + user,
                                             "head_ref": "refs/heads/main",
                                             "base_ref": "refs/heads/base"})
            assert status == 403, (user, status, raw[:200])
        assert self.sql("SELECT count(*) FROM forge_pulls") == "0"
        self.git("checkout", "-B", "pr-feature", self.seed, cwd=vendor)
        head = self.commit(vendor, "pr.txt", "pull request head")
        self.push_branch(vendor, self.alice, "pr-feature")
        merged = {}
        for user, role in (("erin", "write"), ("frank", "maintain"), ("grace", "admin")):
            status, raw, _ = self.http(pulls, token=self.users[user], method="POST",
                                       body={"title": "collaborator PR " + user,
                                             "head_ref": "refs/heads/pr-feature",
                                             "base_ref": "refs/heads/base"})
            assert status == 201, (user, role, status, raw[:300])
            pull = json.loads(raw)
            assert (pull["head_oid"], pull["base_oid"], pull["state"]) == (head, base, "open")
            assert pull["author_id"] == self.users[user]["user_id"]
            body = {"expected_version": pull["version"], "expected_head_oid": head,
                    "expected_base_oid": base, "storage_generation": 1,
                    "strategy": "fast_forward"}
            status, raw, _ = self.http(f"{pulls}/{pull['number']}/merge",
                                       token=self.users[user], method="POST", body=body)
            assert status == 200, (user, role, status, raw[:300])
            result = json.loads(raw)
            assert (result["state"], result["merge_commit_oid"]) == ("merged", head), result
            assert result["version"] == pull["version"] + 1
            assert self.ref("refs/heads/base") == head
            replay = self.expect(f"{pulls}/{pull['number']}/merge", 200, token=self.users[user],
                                 method="POST", body=body,
                                 extra_headers={"Idempotency-Key": "merge-" + user})
            assert replay == raw
            again = self.http(f"{pulls}/{pull['number']}/merge", token=self.users[user],
                              method="POST", body=body)[0]
            assert again == 409, again
            merged[role] = {"number": pull["number"], "merge_commit_oid": head}
            if role != "admin":
                self.git("push", "--force", "origin", base + ":refs/heads/base", cwd=vendor,
                         token=self.alice)
                assert self.ref("refs/heads/base") == base
        return {"create_denied_read_and_triage": True, "merged": merged}

    def pull_merge_under_rule(self):
        """A direct maintainer merges a real PR under a collaborator-created rule."""
        rule = json.loads(self.expect("/api/repos/alice/demo/branch-rules/refs/heads/delivery", 200,
                                      token=self.alice))
        assert (rule["branch_ref"], rule["require_fast_forward"]) == (
            "refs/heads/delivery", True), rule
        vendor = self.root / "owned-work-alice"
        self.git("checkout", "-B", "rule-base", self.seed, cwd=vendor)
        base = self.push_branch(vendor, self.alice, "rule-base")
        self.git("checkout", "-B", "rule-head", self.seed, cwd=vendor)
        head = self.commit(vendor, "rule-merge.txt", "rule head")
        assert self.push_branch(vendor, self.alice, "rule-head") == head
        pull = json.loads(self.expect("/api/repos/alice/demo/pulls", 201,
                                      token=self.users["karl"], method="POST",
                                      body={"title": "merge under delivery rule",
                                            "head_ref": "refs/heads/rule-head",
                                            "base_ref": "refs/heads/rule-base"}))
        pr = f"/api/repos/alice/demo/pulls/{pull['number']}/merge"
        body = {"expected_version": pull["version"], "expected_head_oid": head,
                "expected_base_oid": base, "strategy": "merge_commit"}
        status, raw, _ = self.http(pr, token=self.users["karl"], method="POST", body=body)
        assert status == 409, (status, raw[:200])
        # The frozen product text proves the rule, not an unrelated conflict, refused it.
        assert b"requires fast-forward merge" in raw, raw[:200]
        assert self.ref("refs/heads/rule-base") == base
        body["strategy"] = "fast_forward"
        assert self.http(pr, token=self.users["karl"], method="POST", body=body)[0] == 200
        assert self.ref("refs/heads/rule-base") == head
        return {"rule_creator": "heidi(admin)", "rule_branch": "refs/heads/delivery",
                "merger": "karl(maintain)", "merge_commit_under_rule": status,
                "fast_forward_merge": 200, "base": head}

    def staff_fixtures(self):
        """Write users author a real PR in their own API-created repository first."""
        made = {}
        for user in STAFF_USERS:
            own = self.create_repository({"name": "staff-" + user}, token=self.users[user])
            work = self.root / ("owned-staff-" + user)
            self.git("clone", self.base + own["clone_path"], str(work), token=self.users[user])
            self.git("config", "user.name", user.title(), cwd=work)
            self.git("config", "user.email", user + "@collaborator.invalid", cwd=work)
            self.commit(work, "staff.txt", "staff fixture " + user)
            self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.users[user])
            self.git("checkout", "-B", "feature", cwd=work)
            self.commit(work, "staff-feature.txt", "staff feature " + user)
            self.push_branch(work, self.users[user], "feature")
            pull = json.loads(self.expect(f"/api/repos/{user}/staff-{user}/pulls", 201,
                                          token=self.users[user], method="POST",
                                          body={"title": "staff " + user,
                                                "head_ref": "refs/heads/feature",
                                                "base_ref": "refs/heads/main"}))
            made[user] = pull["number"]
        return made

    def rule_refusals(self):
        """Rule upsert needs maintain: write is refused; no rule means no 409 to hide it."""
        self.grant("nina", "write")
        self.grant("karl", "maintain")
        rule = {"required_approvals": 0, "required_checks": [], "require_fast_forward": True,
                "prevent_deletion": True, "prevent_force_push": True}
        rule_path = "/api/repos/alice/demo/branch-rules/refs/heads/main"
        for user in ("nina", "karl"):
            status, raw, _ = self.http(rule_path, token=self.users[user], method="PUT", body=rule)
            assert status == 403, (user, status, raw[:200])
        assert self.sql("SELECT count(*) FROM forge_branch_rules") == "0"
        status, _, _ = self.http(rule_path, token=self.alice)
        assert status == 404, status
        return {"write_collaborator_rule": 403, "maintain_absent_rule": 403, "rules": 0}

    def owner_only_management(self):
        """admin collaborator is refused collaborator management; maintain+ manage rules."""
        self.grant("heidi", "admin")
        # The rule is absent (proven in `rule_refusals`): the admin collaborator
        # creates it with product defaults for fast-forward/force-push.
        rule_path = "/api/repos/alice/demo/branch-rules/refs/heads/delivery"
        fresh = {"required_approvals": 0, "required_checks": [], "require_fast_forward": True,
                 "prevent_deletion": True, "prevent_force_push": True}
        created = self.http(rule_path, token=self.users["heidi"], method="PUT", body=fresh)[0]
        assert created == 201, created
        rule = json.loads(self.expect(rule_path, 200, token=self.alice))
        assert rule["version"] == 1, rule
        stale = self.http(rule_path, token=self.users["heidi"], method="PUT",
                          body={**fresh, "expected_version": rule["version"] + 1})[0]
        assert stale == 409, stale
        updated = self.http(rule_path, token=self.users["heidi"], method="PUT",
                            body={**fresh, "expected_version": rule["version"],
                                  "prevent_deletion": False})[0]
        assert updated == 200, updated
        before = self.sql("SELECT role FROM repository_collaborators WHERE repository_id='" +
                          self.repo["id"] + "' AND user_id='" + self.users["heidi"]["user_id"] + "'")
        for path, method, body in (
            ("/api/repos/alice/demo/collaborators/karl", "PUT", {"role": "admin"}),
            ("/api/repos/alice/demo/collaborators/karl", "DELETE", None),
            ("/api/repos/alice/demo/collaborators/mona", "PUT", {"role": "admin"}),
            ("/api/repos/alice/demo/collaborators", "POST", {"username": "mona", "role": "admin"}),
        ):
            status, raw, _ = self.http(path, token=self.users["heidi"], method=method, body=body)
            assert status == 403, (path, method, status, raw[:200])
        assert self.sql("SELECT role FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.users["heidi"]["user_id"] + "'") == before
        assert self.sql("SELECT role FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.users["karl"]["user_id"] + "'") == "maintain"
        assert self.sql("SELECT count(*) FROM repository_collaborators WHERE user_id='" +
                        self.users["mona"]["user_id"] + "'") == "0"
        # Removing the rule needs maintain; the admin collaborator may do it.
        removed = self.http(rule_path, token=self.users["heidi"], method="DELETE")[0]
        assert removed == 200, removed
        assert self.sql("SELECT count(*) FROM forge_branch_rules") == "0"
        return {"admin_rule_create": created, "stale_admin_cas": stale,
                "admin_rule_update": updated, "admin_rule_delete": removed,
                "collaborator_management_by_admin": 403}

    def withdrawal(self):
        """API removal denies new requests without erasing the live-grant receipts."""
        self.grant("judy", "write")
        work = self.worker("judy")
        oid = self.commit(work, "before.txt", "before withdrawal")
        assert self.push_branch(work, self.users["judy"], "judy-before") == oid
        operation = self.last_operation("recorded")
        receipts = self.events_for("refs/heads/judy-before", operation["id"])
        assert receipts
        removed = json.loads(self.expect("/api/repos/alice/demo/collaborators/judy", 200,
                                         method="DELETE", token=self.alice))
        assert (removed["removed"], removed["username"]) == (True, "judy")
        assert self.sql("SELECT count(*) FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.users["judy"]["user_id"] + "'") == "0"
        assert self.upload_status(self.users["judy"]) == 404
        assert self.receive_refs_status(self.users["judy"]) == 404
        after = self.commit(work, "after.txt", "after withdrawal")
        denied = self.git("push", "origin", "HEAD:refs/heads/judy-after", cwd=work,
                          token=self.users["judy"], check=False)
        assert denied.returncode != 0 and self.ref("refs/heads/judy-after") is None
        assert self.git("fetch", "origin", cwd=work, token=self.users["judy"], check=False).returncode != 0
        # Receipts retained exactly as recorded while the grant was live.
        [operation_after] = [op for op in self.operations() if op["id"] == operation["id"]]
        assert operation_after["outcome"] == "recorded"
        assert [e["event_id"] for e in self.events_for("refs/heads/judy-before")] == [
            e["event_id"] for e in receipts]
        assert self.ref("refs/heads/judy-before") == oid and oid != after
        return {"removal": "api_collaborator_delete", "upload_pack": 404, "receive_pack": 404,
                "push_denied": True, "receipts_preserved": len(receipts),
                "receipt_actor": operation["actor_name"]}

    def audit_boundary(self):
        """Git transport writes git_operations/outbox_events, never repository_audit_log."""
        expected = self.sql("SELECT count(*) FROM outbox_events")
        recorded = [op for op in self.operations() if op["outcome"] == "recorded"]
        assert recorded and len(self.events()) == int(expected)
        actions = self.sql("SELECT COALESCE(string_agg(DISTINCT action, ','), '') FROM repository_audit_log")
        assert "git" not in actions.split(",") and "push" not in actions.split(","), actions
        # Git pushes never reach the members table; only Forge/member writes do.
        assert self.sql("SELECT count(*) FROM repository_audit_log WHERE action LIKE 'git%' OR " +
                        "action = 'push' OR target_type IN ('git_operation', 'repository_audit_log')") == "0"
        return {"git_operations": len(recorded), "outbox_events": len(self.events()),
                "repository_audit_log_rows": int(self.sql("SELECT count(*) FROM repository_audit_log")),
                "repository_audit_log_git_rows": 0,
                "audit_actions": [row for row in actions.split(",") if row]}

    def token_revocation(self):
        """A revoked collaborator token is 401 on the next transport request; role intact."""
        self.grant("linda", "admin")
        token = self.account("create-token", "linda")
        assert self.upload_status(token) == 200
        self.cli("revoke-token", token["token_id"])
        assert self.upload_status(token) == 401
        denied = self.git("ls-remote", self.remote, token=token, check=False)
        assert denied.returncode != 0
        assert self.sql("SELECT role FROM repository_collaborators WHERE repository_id='" +
                        self.repo["id"] + "' AND user_id='" + self.users["linda"]["user_id"] + "'") == "admin"
        return {"before": 200, "after": 401}


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
    try:
        h.case("git_matrix_version", h.git_matrix_version)
        h.case("git_command_coverage", h.git_command_coverage)
        h.case("source_bound_receipt", h.source_binding)
        h.case("environment", h.environment)
        h.case("staff_owned_fixtures", h.staff_fixtures)
        h.case("role_matrix_clone_fetch_push", h.role_matrix)
        h.case("fetch_propagation", h.fetch_propagation)
        h.case("outsider_404_no_enumeration", h.outsider_isolation)
        h.case("read_only_token_403", h.read_only_token)
        h.case("non_fast_forward_rejected", h.non_fast_forward)
        h.case("ref_transactions_role_matrix", h.ref_transactions)
        h.case("pull_create_merge_role_matrix", h.pull_lifecycle)
        # The admin collaborator creates a rule only after the FF policy is proven.
        h.case("branch_rule_role_matrix", h.rule_refusals)
        h.case("owner_only_management", h.owner_only_management)
        h.case("pull_merge_under_collaborator_rule", h.pull_merge_under_rule)
        h.case("withdrawal_revokes_new_requests", h.withdrawal)
        h.case("git_receipts_are_not_repository_audit_log", h.audit_boundary)
        h.case("token_revocation_401", h.token_revocation)
        success = True
    except Exception as error:  # fail closed with one bounded message
        print(h.redact(error), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as error:  # noqa: BLE001
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(error)))
            success = False
        report = dict(passed=success, cases=h.results, limitations=h.limits, runtime={
            "git_client": h.run(["git", "--version"]).stdout.decode().strip(),
            "git_server": h.run([h.server_git(), "--version"]).stdout.decode().strip(),
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
