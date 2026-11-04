#!/usr/bin/env python3
"""Real Git/PostgreSQL tests. Requires git, psql, pg_dump, pg_restore, and ROOTYARD_TEST_DATABASE_URL.

Each run owns a random SQL schema and temporary storage directory. No database is
created or dropped. Only the exact schema created by this process is dropped.
Use a dedicated test database: migrations/extensions may have database-wide effects.
Tokens never appear in the JSON report or printed command lines.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import gzip
import http.client
import json
import os
import random
import select
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class Harness:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="rootyard-e2e-"))
        self.schema = "rootyard_e2e_" + uuid.uuid4().hex
        self.schema_created = False
        self.base_db = os.environ["ROOTYARD_TEST_DATABASE_URL"]
        parts = urllib.parse.urlsplit(self.base_db)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if any(k == "options" for k, _ in query):
            raise RuntimeError("Test URL must not already contain options; isolation needs its own search_path")
        query.append(("options", "-csearch_path=" + self.schema))
        self.db = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
        self.env = os.environ.copy()
        self.env.update(DATABASE_URL=self.db, ROOTYARD_DATA_DIR=str(self.root / "data"),
                        GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL=os.devnull, LC_ALL="C")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.env["ROOTYARD_BIND"] = "127.0.0.1:" + str(self.port)
        self.base = "http://" + self.env["ROOTYARD_BIND"]
        self.proc = None
        self.log = None
        self.results = []
        self.secrets = []
        self.limits = ["Loopback functional timings are not a scalability benchmark.",
                       "Crash tests kill the service process, not the kernel or PostgreSQL; no power-loss guarantee is inferred.",
                       "Interrupted upload uses a truncated HTTP body; exhaustive transport fault injection is not covered."]

    def redact(self, value):
        value = str(value)
        for secret in self.secrets:
            value = value.replace(secret, "[REDACTED]")
        return value.replace(self.base_db, "[DATABASE_URL]").replace(self.db, "[DATABASE_URL]")

    def run(self, argv, cwd=None, check=True, data=None, env=None):
        p = subprocess.run(argv, cwd=cwd, env=env or self.env, input=data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if check and p.returncode:
            # Do not log argv: Git's command-line auth header contains a token.
            raise AssertionError(self.redact(f"Command failed ({p.returncode}): {p.stderr.decode(errors='replace')[-4000:]}"))
        return p

    def sql(self, query, isolated=True):
        env = self.env.copy()
        env["PGDATABASE"] = self.db if isolated else self.base_db
        return self.run(["psql", "--dbname", env["PGDATABASE"], "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", query], env=env).stdout.decode().strip()

    def cli(self, *args):
        p = self.run([self.args.binary, *args])
        return p.stdout.decode().strip()

    def account(self, *args):
        result = json.loads(self.cli(*args))
        self.secrets.extend([result["token"], base64.b64encode((result["username"] + ":" + result["token"]).encode()).decode()])
        return result

    def http(self, path, token=None, method="GET", body=None, content_type=None, basic=False, extra_headers=None, allow_incomplete=False):
        headers = {}
        if token:
            headers["Authorization"] = ("Basic " + base64.b64encode((token["username"] + ":" + token["token"]).encode()).decode()) if basic else "Bearer " + token["token"]
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            content_type = "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        headers.update(extra_headers or {})
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                try:
                    data = r.read()
                except http.client.IncompleteRead as error:
                    if not allow_incomplete:
                        raise
                    data = error.partial
                return r.status, data, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def git(self, *args, cwd=None, token=None, check=True, env=None):
        prefix = ["git"]
        if token:
            auth = base64.b64encode((token["username"] + ":" + token["token"]).encode()).decode()
            prefix += ["-c", "http.extraHeader=Authorization: Basic " + auth]
        return self.run(prefix + list(args), cwd=cwd, check=check, env=env)

    def start(self):
        self.log = open(self.root / "server.log", "ab")
        self.proc = subprocess.Popen([self.args.binary, "serve"], env=self.env, stdout=self.log, stderr=self.log,
                                     start_new_session=True)
        until = time.monotonic() + 30
        while time.monotonic() < until:
            if self.proc.poll() is not None:
                raise RuntimeError("Server exited during startup; inspect retained server.log")
            try:
                if self.http("/health/ready")[0] == 200:
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.1)
        raise RuntimeError("Readiness timeout")

    def stop(self, hard=False):
        if self.proc:
            if self.proc.poll() is None:
                # Kill only the process group this harness created, including Git children.
                os.killpg(self.proc.pid, signal.SIGKILL if hard else signal.SIGTERM)
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                    self.proc.wait()
            self.proc = None
        if self.log:
            self.log.close()
            self.log = None

    def case(self, name, fn):
        start = time.monotonic()
        try:
            detail = fn()
            self.results.append(dict(name=name, status="passed", seconds=round(time.monotonic()-start, 4), detail=detail))
        except Exception as e:
            self.results.append(dict(name=name, status="failed", seconds=round(time.monotonic()-start, 4), error=self.redact(e)))
            raise
        print(name + ": passed", flush=True)

    def expect(self, path, code, **kwargs):
        status, body, headers = self.http(path, **kwargs)
        assert status in (code if isinstance(code, tuple) else (code,)), f"{path}: expected {code}, got {status}: {body[:300]!r}"
        return body

    def setup(self):
        self.sql('CREATE SCHEMA "' + self.schema + '"', isolated=False)
        self.schema_created = True
        self.cli("migrate")
        self.alice = self.account("create-user", "alice")
        self.bob = self.account("create-user", "bob")
        self.reader = self.account("create-token", "alice", "--read-only")
        self.start()

    def token_storage(self):
        for account in (self.alice, self.bob, self.reader):
            token_id = str(uuid.UUID(account["token_id"]))
            actual = self.sql("SELECT encode(digest, 'hex') FROM tokens WHERE id='" + token_id + "'")
            expected = hashlib.sha256(account["token"].encode()).hexdigest()
            assert actual == expected, "Token digest does not match SHA256"
        columns = self.sql("SELECT column_name FROM information_schema.columns WHERE table_schema='" + self.schema + "' AND table_name='tokens'")
        assert not ({"token", "plaintext", "secret"} & set(columns.splitlines())), "Plaintext credential column present"
        expired = self.account("create-token", "alice")
        token_id = str(uuid.UUID(expired["token_id"]))
        self.sql("UPDATE tokens SET expires_at=now()-interval '1 second' WHERE id='" + token_id + "'")
        self.expect("/api/repos", 401, token=expired)

    def api(self):
        self.expect("/health/live", 200)
        duplicate = self.run([self.args.binary, "serve"], check=False)
        assert duplicate.returncode != 0 and b"data directory already in use" in duplicate.stderr, "Second writer did not fail on the volume lock"
        self.expect("/api/repos", 401)
        self.expect("/api/repos", 401, token={"token": "invalid"})
        self.expect("/api/repos", 403, method="POST", token=self.reader, body={"name": "forbidden"})
        repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice, body={"name": "demo"}))
        self.repo = repo
        assert repo["state"] == "ready"
        assert repo["clone_path"] == "/git/alice/demo.git"
        again = json.loads(self.expect("/api/repos", 200, method="POST", token=self.alice, body={"name": "demo"}))
        assert repo["id"] == again["id"]
        self.expect("/api/repos/alice/demo", 200, token=self.alice)
        self.expect("/api/repos/alice/demo", (403, 404), token=self.bob)
        bob_list = json.loads(self.expect("/api/repos", 200, token=self.bob))
        assert "demo" not in json.dumps(bob_list), "Cross-user listing leaked repo"
        self.remote = self.base + repo["clone_path"]
        self.work = self.root / "work"
        self.bare = self.root / "data" / "repos" / (repo["id"] + ".git")
        assert self.bare.is_dir()
        assert self.git("--git-dir=" + str(self.bare), "symbolic-ref", "HEAD").stdout.strip() == b"refs/heads/main"
        assert self.git("--git-dir=" + str(self.bare), "config", "receive.denyNonFastForwards").stdout.strip() == b"true"

    def roundtrip(self):
        self.git("clone", self.remote, str(self.work), token=self.alice)
        self.git("config", "user.name", "E2E", cwd=self.work)
        self.git("config", "user.email", "e2e@example.invalid", cwd=self.work)
        (self.work / "hello.txt").write_text("hello rootyard\n")
        payload = random.Random(42).randbytes(512 * 1024)
        (self.work / "payload.bin").write_bytes(payload)
        self.git("add", ".", cwd=self.work)
        self.git("commit", "-m", "first", cwd=self.work)
        self.first = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        assert len(self.first) == 40
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        self.copy = self.root / "independent"
        self.git("clone", self.remote, str(self.copy), token=self.reader)
        assert (self.copy / "hello.txt").read_text() == "hello rootyard\n"
        assert (self.copy / "payload.bin").read_bytes() == payload
        self.git("fsck", "--full", cwd=self.copy)
        (self.work / "hello.txt").write_text("second\n")
        self.git("commit", "-am", "second", cwd=self.work)
        self.second = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        self.git("fetch", "origin", cwd=self.copy, token=self.reader)
        assert self.git("rev-parse", "origin/main", cwd=self.copy).stdout.decode().strip() == self.second

    def auth_and_paths(self):
        path = self.repo["clone_path"]
        upload = path + "/info/refs?service=git-upload-pack"
        receive = path + "/info/refs?service=git-receive-pack"
        self.expect(upload, 401)
        self.expect(upload, 401, token={"token": "invalid"})
        self.expect(upload, 200, token=self.alice, basic=True)
        self.expect(upload, 401, token={"username": "bob", "token": self.alice["token"]}, basic=True)
        self.expect(upload, 200, token=self.alice)
        self.expect(upload, (403, 404), token=self.bob)
        self.expect(receive, 403, token=self.reader)
        self.expect(path + "/git-receive-pack", 403, token=self.reader, method="POST", body=b"0000", content_type="application/x-git-receive-pack-request")
        assert self.git("push", "origin", "HEAD:denied", cwd=self.work, token=self.reader, check=False).returncode != 0
        revoked = self.account("create-token", "alice")
        self.revoked = revoked
        self.expect(upload, 200, token=revoked)
        self.cli("revoke-token", revoked["token_id"])
        self.expect(upload, 401, token=revoked)
        self.expect("/api/repos", 401, token=revoked)
        for suffix in ("/config", "/HEAD", "/objects/info/packs", "/info/refs", "/../config", "/%2e%2e/config", "/%2e%2e%2fconfig"):
            self.expect(path + suffix, (400, 403, 404, 405), token=self.alice)
        for name in ("../escape", "/absolute", "x/y", "..", "x.git/config"):
            self.expect("/api/repos", (400, 422), method="POST", token=self.alice, body={"name": name})

    def refs(self):
        self.git("push", "--atomic", "origin", "HEAD:topic", "HEAD:refs/tags/v1", cwd=self.work, token=self.alice)
        self.git("push", "origin", ":topic", ":refs/tags/v1", cwd=self.work, token=self.alice)
        refs = self.git("ls-remote", self.remote, token=self.alice).stdout
        assert b"refs/heads/topic" not in refs and b"refs/tags/v1" not in refs
        p = self.git("push", "--force", "origin", self.first + ":main", cwd=self.work, token=self.alice, check=False)
        assert p.returncode != 0, "Forced non-fast-forward accepted"
        assert self.second.encode() in self.git("ls-remote", self.remote, "main", token=self.alice).stdout
        # Prove atomic all-or-nothing when one requested ref is rejected.
        p = self.git("push", "--atomic", "--force", "origin", self.first + ":main", self.second + ":refs/heads/atomic-should-not-exist", cwd=self.work, token=self.alice, check=False)
        assert p.returncode != 0
        assert not self.git("ls-remote", self.remote, "atomic-should-not-exist", token=self.alice).stdout

    @staticmethod
    def pkt(data):
        return ("%04x" % (len(data)+4)).encode() + data

    @staticmethod
    def empty_pack():
        header = b"PACK\0\0\0\2\0\0\0\0"
        return header + hashlib.sha1(header).digest()

    def update_ref(self, old, new, ref, barrier=None, repo=None):
        if barrier:
            barrier.wait(timeout=10)
        command = f"{old} {new} {ref}".encode() + b"\0report-status atomic\n"
        return self.http((repo or self.repo)["clone_path"] + "/git-receive-pack", token=self.alice,
                         method="POST", body=self.pkt(command)+b"0000"+self.empty_pack(),
                         content_type="application/x-git-receive-pack-request", allow_incomplete=True)

    def parallel(self):
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda n: self.git("push", "origin", f"HEAD:parallel-{n}", cwd=self.work, token=self.alice), range(4)))
        elapsed = time.monotonic() - start
        assert all(p.returncode == 0 for p in results)
        # Both competing updates advertise exactly the same old OID. Existing objects
        # remove pack transfer as a confounder and exercise receive-pack's ref lock.
        # An ambiguous rejected RPC can intentionally block its repository in
        # phase two. Isolate the race so later independent scenarios remain valid.
        race_repo = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice, body={"name": "cas-race"}))
        race_remote = self.base + race_repo["clone_path"]
        self.git("push", race_remote, self.first + ":refs/heads/race", self.second + ":refs/heads/main", cwd=self.work, token=self.alice)
        barrier = threading.Barrier(2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(self.update_ref, self.first, self.second, "refs/heads/race", barrier, race_repo) for _ in range(2)]
            responses = [job.result() for job in jobs]
        assert sum(b"ok refs/heads/race\n" in body for _, body, _ in responses) == 1, "Expected exactly one successful old-OID compare-and-swap"
        assert sum(b"ng refs/heads/race " in body for _, body, _ in responses) == 1, "Expected one rejected old-OID compare-and-swap"
        race_bare = self.root / "data/repos" / (race_repo["id"] + ".git")
        assert self.git("--git-dir=" + str(race_bare), "rev-parse", "refs/heads/race").stdout.decode().strip() == self.second
        self.git("--git-dir=" + str(race_bare), "fsck", "--full")
        return {"parallel_pushes": 4, "elapsed_seconds": round(elapsed, 4), "benchmark": False}

    def broken_uploads(self):
        path = self.repo["clone_path"] + "/git-receive-pack"
        before = self.git("ls-remote", self.remote, token=self.alice).stdout
        fake = "f" * 40
        cmd = self.pkt(("0" * 40 + " " + fake + " refs/heads/bad").encode() + b"\0report-status\n") + b"0000"
        status, body, _ = self.http(path, token=self.alice, method="POST", body=cmd+b"PACK\0invalid",
                                    content_type="application/x-git-receive-pack-request")
        assert status >= 400 or b"unpack ok" not in body
        auth = base64.b64encode(("alice:" + self.alice["token"]).encode()).decode()
        wire = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {auth}\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n").encode() + cmd + b"PACK"
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(wire)
            sock.shutdown(socket.SHUT_WR)
        time.sleep(.3)
        self.expect("/health/ready", 200)
        assert self.git("ls-remote", self.remote, token=self.alice).stdout == before
        self.git("push", "origin", "HEAD:post-interrupt", cwd=self.work, token=self.alice)
        self.git("--git-dir=" + str(self.bare), "fsck", "--full")

    def restart(self):
        before = self.git("ls-remote", self.remote, token=self.alice).stdout
        self.stop(hard=True)
        self.start()
        assert self.git("ls-remote", self.remote, token=self.alice).stdout == before
        self.expect("/api/repos/alice/demo", 200, token=self.alice)
        self.git("clone", self.remote, str(self.root / "after-crash"), token=self.alice)
        self.git("fsck", "--full", cwd=self.root / "after-crash")

    def provisioning_recovery(self):
        existing = json.loads(self.expect("/api/repos", 201, method="POST", token=self.alice,
                                          body={"name": "recover-existing"}))
        self.stop(hard=True)
        owner = str(uuid.UUID(self.alice["user_id"]))
        pending = [(str(uuid.uuid4()), "recover-missing"), (str(uuid.uuid4()), "recover-staging")]
        for repo_id, name in pending:
            self.sql("INSERT INTO repositories(id,owner_id,name,state) VALUES ('" + repo_id + "','" + owner + "','" + name + "','provisioning')")
        staging = self.root / "data" / "repos" / (pending[1][0] + ".init")
        self.git("init", "--bare", "--initial-branch=main", str(staging))
        (staging / "config.lock").write_text("interrupted config write\n")
        # Model a due retry after publication but before the ready transaction commits.
        # A background worker may already have set a future retry deadline on the
        # original row. Explicitly make this fixture due rather than racing it.
        existing_id = str(uuid.UUID(existing["id"]))
        self.sql("UPDATE repositories SET state='provisioning',next_retry_at=clock_timestamp() WHERE id='" + existing_id + "'")
        pending.append((existing_id, "recover-existing"))
        self.start()
        for repo_id, name in pending:
            body = json.loads(self.expect("/api/repos/alice/" + name, 200, token=self.alice))
            assert body["state"] == "ready" and body["id"] == repo_id, {"name": name, "state": body["state"], "retry": self.sql("SELECT next_retry_at::text || ' attempts=' || provision_attempts::text FROM repositories WHERE id='" + repo_id + "'")}
            self.git("clone", self.base + body["clone_path"], str(self.root / name), token=self.alice)
            self.git("--git-dir=" + str(self.root / "data" / "repos" / (repo_id + ".git")), "fsck", "--full")
        return {"recovered": [name for _, name in pending], "method": "deterministic provisioning-state injection"}

    def provisioning_fairness(self):
        self.stop(hard=True)
        owner = str(uuid.UUID(self.alice["user_id"]))
        sentinel_dir = self.root / "untouched-symlink-target"
        sentinel_dir.mkdir()
        sentinel = sentinel_dir / "sentinel"
        sentinel.write_text("must survive recovery")
        blocked = [str(uuid.uuid4()) for _ in range(64)]
        for repo_id in blocked:
            (self.root / "data" / "repos" / (repo_id + ".init")).symlink_to(sentinel_dir, target_is_directory=True)
        values = ["('" + repo_id + "','" + owner + "','blocked-" + str(i) + "','provisioning',now()-interval '1 hour')"
                  for i, repo_id in enumerate(blocked)]
        good = str(uuid.uuid4())
        values.append("('" + good + "','" + owner + "','after-blocked','provisioning',now())")
        self.sql("INSERT INTO repositories(id,owner_id,name,state,next_retry_at) VALUES " + ",".join(values))
        self.start()
        until = time.monotonic() + 15
        while time.monotonic() < until:
            if self.sql("SELECT state FROM repositories WHERE id='" + good + "'") == "ready":
                break
            time.sleep(.1)
        else:
            raise AssertionError("65th provisioning job starved behind 64 failed jobs")
        assert sentinel.read_text() == "must survive recovery"
        assert all((self.root / "data" / "repos" / (repo_id + ".init")).is_symlink() for repo_id in blocked)
        assert self.sql("SELECT count(*) FROM repositories WHERE name LIKE 'blocked-%' AND state='provisioning' AND provision_attempts >= 1") == "64"
        self.expect("/api/repos/alice/after-blocked", 200, token=self.alice)
        return {"blocked_jobs": 64, "later_job_recovered": True, "symlink_targets_untouched": True}

    def gzip_git_requests(self):
        tree = self.git("rev-parse", "HEAD^{tree}", cwd=self.work).stdout.decode().strip()
        refs = []
        for i in range(40):
            oid = self.git("commit-tree", tree, "-p", self.second, "-m", "gzip branch " + str(i), cwd=self.work).stdout.decode().strip()
            refs.append(oid + ":refs/heads/gzip-" + str(i))
        self.git("push", "origin", *refs, cwd=self.work, token=self.alice)
        trace_env = self.env.copy()
        trace_env.update(GIT_TRACE_CURL="1", GIT_TRACE_CURL_NO_DATA="1")
        clone = self.root / "many-refs"
        output = self.git("clone", self.remote, str(clone), token=self.alice, env=trace_env)
        auto_gzip = b"content-encoding: gzip" in output.stderr.lower()
        self.git("fsck", "--full", cwd=clone)
        self.git("fetch", "origin", cwd=clone, token=self.alice)
        request = self.pkt(("want " + self.second + "\n").encode()) + b"0000" + self.pkt(b"done\n")
        endpoint = self.repo["clone_path"] + "/git-upload-pack"
        for encoding in ("gzip", "x-gzip"):
            status, body, _ = self.http(endpoint, token=self.alice, method="POST", body=gzip.compress(request),
                                        content_type="application/x-git-upload-pack-request",
                                        extra_headers={"Content-Encoding": encoding})
            assert status == 200 and b"PACK" in body, "Compressed Git request failed: " + encoding
        try:
            status, body, _ = self.http(endpoint, token=self.alice, method="POST", body=b"invalid gzip",
                                        content_type="application/x-git-upload-pack-request",
                                        extra_headers={"Content-Encoding": "gzip"})
            assert status >= 400, "Malformed gzip received a clean successful response"
        except (http.client.IncompleteRead, http.client.RemoteDisconnected, ConnectionResetError):
            pass  # A rejected streaming body may terminate an already-started response.
        self.expect("/health/ready", 200)
        self.git("fetch", "origin", cwd=clone, token=self.alice)
        assert auto_gzip, "Native Git clone did not exercise automatic request gzip"
        return {"unique_branch_tips": 40, "native_git_automatic_gzip": auto_gzip,
                "explicit_gzip_and_x_gzip": True, "malformed_gzip_rejected": True}

    def descendants(self):
        # Scan stat rather than task/*/children: some container runtimes omit children.
        processes = {}
        for entry in Path("/proc").glob("[0-9]*/stat"):
            try:
                stat = entry.read_text().rsplit(")", 1)[1].split()
                processes[int(entry.parent.name)] = (int(stat[1]), stat[19])
            except (FileNotFoundError, ProcessLookupError):
                continue
        found = {}
        queue = [self.proc.pid]
        while queue:
            parent = queue.pop()
            for child, (ppid, starttime) in processes.items():
                if ppid == parent and child not in found:
                    found[child] = starttime
                    queue.append(child)
        return found

    def assert_reaped(self, children, operation):
        until = time.monotonic() + 2
        while True:
            remaining = []
            for pid, starttime in children.items():
                try:
                    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                    if stat[19] == starttime:
                        remaining.append({"pid": pid, "state": stat[0], "parent": int(stat[1]),
                                          "group": int(stat[2]), "starttime": stat[19]})
                except (FileNotFoundError, ProcessLookupError):
                    pass
            if not remaining:
                return
            assert time.monotonic() < until, f"Git descendants survived {operation} deadline: {remaining}"
            time.sleep(.05)

    def wait_for_git_children(self, sock, sent_at, operation):
        # Authentication, recovery checks and journal fsync precede spawn. A
        # fixed 100 ms sleep races those steps on shared CI runners. Require an
        # actual streaming response AND live descendants, without draining the
        # response or extending the operation's original deadline assertion.
        until = sent_at + 2
        while time.monotonic() < until:
            response_started = False
            if select.select([sock], [], [], 0)[0]:
                prefix = sock.recv(1024, socket.MSG_PEEK)
                assert prefix, f"{operation} connection ended before observing Git children"
                if b"\r\n" in prefix:
                    status = prefix.split(b"\r\n", 1)[0].split()
                    assert len(status) >= 2 and status[1] == b"200", f"{operation} did not start streaming: {status!r}"
                    response_started = True
            children = self.descendants()
            if response_started and children:
                return children
            time.sleep(.01)
        raise AssertionError(f"No streaming Git child observed during {operation} within 2 seconds")

    def slow_client_deadlines(self):
        (self.work / "large.bin").write_bytes(random.Random(43).randbytes(12 * 1024 * 1024))
        self.git("add", "large.bin", cwd=self.work)
        self.git("commit", "-m", "exercise streaming backpressure", cwd=self.work)
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        head = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.stop()
        saved = {key: self.env.get(key) for key in ("ROOTYARD_GIT_TIMEOUT_SECONDS", "ROOTYARD_MAX_CONCURRENT_GIT")}
        self.env.update(ROOTYARD_GIT_TIMEOUT_SECONDS="2", ROOTYARD_MAX_CONCURRENT_GIT="1")
        self.start()
        auth = "Bearer " + self.alice["token"]
        path = self.repo["clone_path"]
        def wire(endpoint, body, length=None):
            return (f"POST {path}/{endpoint} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {auth}\r\nContent-Type: application/x-{endpoint}-request\r\nContent-Length: {length or len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        try:
            body = self.pkt(("want " + head + "\n").encode()) + b"0000" + self.pkt(b"done\n")
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                sock.settimeout(10)
                sock.connect(("127.0.0.1", self.port))
                sent_at = time.monotonic()
                sock.sendall(wire("git-upload-pack", body))
                children = self.wait_for_git_children(sock, sent_at, "blocked streaming")
                time.sleep(max(0, sent_at + 4 - time.monotonic()))
                self.assert_reaped(children, "blocked streaming")
                self.expect(path + "/info/refs?service=git-upload-pack", 200, token=self.alice)
            command = self.pkt(("0" * 40 + " " + "f" * 40 + " refs/heads/stalled").encode() + b"\0report-status\n") + b"0000"
            with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
                sent_at = time.monotonic()
                sock.sendall(wire("git-receive-pack", command + b"PACK", 100000))
                children = self.wait_for_git_children(sock, sent_at, "incomplete upload")
                time.sleep(max(0, sent_at + 4 - time.monotonic()))
                self.assert_reaped(children, "incomplete upload")
                self.expect(path + "/info/refs?service=git-upload-pack", 200, token=self.alice)
            self.git("push", "origin", "HEAD:after-stalled", cwd=self.work, token=self.alice)
            assert not self.git("ls-remote", self.remote, "stalled", token=self.alice).stdout
        finally:
            self.stop(hard=True)
            for key, value in saved.items():
                if value is None:
                    self.env.pop(key, None)
                else:
                    self.env[key] = value
            self.start()
        return {"timeout_seconds": 2, "git_slots": 1, "slow_reader_releases_slot": True,
                "incomplete_upload_releases_slot_and_writer_lock": True, "observed_git_descendants_reaped": True, "payload_bytes": 12 * 1024 * 1024}

    def bounded_payloads(self):
        self.stop()
        keys = ("ROOTYARD_MAX_REQUEST_BYTES", "ROOTYARD_MAX_OUTPUT_BYTES")
        saved = {key: self.env.get(key) for key in keys}
        self.env.update(ROOTYARD_MAX_REQUEST_BYTES="1024", ROOTYARD_MAX_OUTPUT_BYTES="65536")
        self.start()
        endpoint = self.repo["clone_path"] + "/git-upload-pack"
        head = self.second
        request = self.pkt(("want " + head + "\n").encode()) + b"0000"
        request += self.pkt(("have " + self.first + "\n").encode()) * 40 + self.pkt(b"done\n")
        assert len(request) > 1024 and len(gzip.compress(request)) < 1024
        try:
            self.expect(endpoint, 413, token=self.alice, method="POST", body=b"x" * 1025,
                        content_type="application/x-git-upload-pack-request")
            try:
                status, body, _ = self.http(endpoint, token=self.alice, method="POST", body=gzip.compress(request),
                                            content_type="application/x-git-upload-pack-request",
                                            extra_headers={"Content-Encoding": "gzip"})
                assert status >= 400, "Decoded request cap was not enforced"
            except (http.client.IncompleteRead, http.client.RemoteDisconnected, ConnectionResetError):
                pass
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            try:
                conn.request("POST", endpoint, body=[request[:700], request[700:]], encode_chunked=True,
                             headers={"Authorization": "Bearer " + self.alice["token"],
                                      "Content-Type": "application/x-git-upload-pack-request"})
                response = conn.getresponse()
                body = response.read()
                assert response.status >= 400, "Chunked request cap was not enforced"
            except (http.client.IncompleteRead, http.client.RemoteDisconnected, ConnectionResetError):
                pass
            finally:
                conn.close()
            limited = self.git("clone", "--single-branch", "--branch", "main", self.remote,
                               str(self.root / "output-capped-clone"), token=self.alice, check=False)
            assert limited.returncode != 0, "12MiB clone succeeded despite 64KiB output cap"
            self.expect("/health/ready", 200)
        finally:
            self.stop(hard=True)
            for key, value in saved.items():
                if value is None:
                    self.env.pop(key, None)
                else:
                    self.env[key] = value
            self.start()
        status, body, _ = self.http(endpoint, token=self.alice, method="POST", body=gzip.compress(request),
                                    content_type="application/x-git-upload-pack-request",
                                    extra_headers={"Content-Encoding": "gzip"})
        assert status == 200 and b"PACK" in body, "Negotiation fixture must succeed without request caps"
        self.git("clone", "--single-branch", "--branch", "main", self.remote,
                 str(self.root / "after-output-cap"), token=self.alice)
        self.git("fsck", "--full", cwd=self.root / "after-output-cap")
        return {"request_cap_bytes": 1024, "output_cap_bytes": 65536,
                "content_length_chunked_and_gzip_limits": True, "healthy_clone_after_reset": True}

    def paired_backup_restore(self):
        before = self.git("ls-remote", self.remote, token=self.alice).stdout
        self.stop()
        dump = self.root / "metadata.dump"
        self.run(["pg_dump", "--dbname", self.db, "--format=custom", "--schema=" + self.schema, "--file", str(dump)])
        restored = self.root / "restored-data"
        shutil.copytree(self.env["ROOTYARD_DATA_DIR"], restored, symlinks=True)
        # The only destructive operation targets the random schema this run created.
        self.sql('DROP SCHEMA "' + self.schema + '" CASCADE', isolated=False)
        self.run(["pg_restore", "--dbname", self.base_db, "--exit-on-error", str(dump)])
        self.env["ROOTYARD_DATA_DIR"] = str(restored)
        self.start()
        assert self.git("ls-remote", self.remote, token=self.alice).stdout == before
        checkout = self.root / "restored-clone"
        self.git("clone", self.remote, str(checkout), token=self.reader)
        self.git("fsck", "--full", cwd=checkout)
        assert (checkout / "large.bin").stat().st_size == 12 * 1024 * 1024
        self.expect(self.repo["clone_path"] + "/info/refs?service=git-receive-pack", 403, token=self.reader)
        self.expect("/api/repos", 401, token=self.revoked)
        return {"metadata": "pg_dump/pg_restore of isolated schema", "storage": "offline full directory copy",
                "refs_and_auth_preserved": True}

    def cleanup(self):
        self.stop()
        if self.schema_created:
            self.sql('DROP SCHEMA IF EXISTS "' + self.schema + '" CASCADE', isolated=False)
            self.schema_created = False
        if not self.args.keep:
            shutil.rmtree(self.root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, help="Write machine-readable JSON report (no credentials)")
    parser.add_argument("--keep", action="store_true", help="Keep temporary Git/data/log files; SQL schema is still removed")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL is required; use a dedicated test database")
    for exe in ("git", "psql", "pg_dump", "pg_restore", args.binary):
        if not shutil.which(exe):
            parser.error("Required executable not found: " + exe)
    h = Harness(args)
    success = False
    try:
        for name, fn in [("isolated_database_and_accounts", h.setup), ("sha256_token_storage_and_expiry", h.token_storage), ("repository_api", h.api),
                         ("git_clone_push_clone_fetch_fsck", h.roundtrip), ("auth_isolation_and_paths", h.auth_and_paths),
                         ("refs_tags_deletion_non_ff_atomic", h.refs), ("parallel_refs_and_compare_swap", h.parallel),
                         ("malformed_and_interrupted_upload", h.broken_uploads), ("sigkill_restart_persistence", h.restart),
                         ("gzip_git_request_compatibility", h.gzip_git_requests),
                         ("slow_client_deadlines", h.slow_client_deadlines),
                         ("provisioning_recovery", h.provisioning_recovery),
                         ("provisioning_retry_fairness", h.provisioning_fairness),
                         ("bounded_streaming_payloads", h.bounded_payloads),
                         ("paired_offline_backup_restore", h.paired_backup_restore)]:
            h.case(name, fn)
        success = True
    except Exception as e:
        print(h.redact(e), file=sys.stderr)
    finally:
        try:
            h.cleanup()
        except Exception as e:
            h.results.append(dict(name="cleanup", status="failed", error=h.redact(e)))
            success = False
        report = dict(passed=success, cases=h.results, limitations=h.limits, runtime={
            "git_client": h.run(["git", "--version"]).stdout.decode().strip(),
            "git_server": h.run([h.env.get("ROOTYARD_GIT", "git"), "--version"]).stdout.decode().strip(),
            "postgres_client": h.run(["psql", "--version"]).stdout.decode().strip(),
            "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
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
