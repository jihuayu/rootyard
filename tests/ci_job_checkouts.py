#!/usr/bin/env python3
"""Job-scoped mirror checkout security tests using isolated loopback fixtures.

Requires a disposable ROOTYARD_TEST_DATABASE_URL. Inherits the source-pin and
mirror lifecycle, never contacts remote Git hosts, and only mutates its own SQL
schema and storage. Set TMPDIR to a workspace directory on constrained hosts.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import sys
import threading
import time
import urllib.parse
import uuid

from ci_source_pins import SourcePinHarness


class JobCheckoutHarness(SourcePinHarness):
    checkout_path = "/api/repos/alice/demo/ci-checkouts"

    def __init__(self, args):
        super().__init__(args)
        self.audience = str(uuid.uuid4())
        self.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = self.audience
        self.mirror_env["ROOTYARD_CI_MIRROR_AUDIENCE"] = self.audience

    def request_body(self, oid=None, job=None, **overrides):
        body = dict(job_id=job or str(uuid.uuid4()), target_oid=oid or self.second,
                    storage_generation=1, mirror_audience=self.audience,
                    expires_unix=int(time.time()) + 1800)
        body.update(overrides)
        return body

    def issue(self, body, issuer=None, codes=(200, 201)):
        raw = self.expect(self.checkout_path, codes, token=issuer or self.alice,
                          method="POST", body=body)
        if codes != (200, 201):
            return raw
        result = json.loads(raw)
        if "token" in result:
            assert re.fullmatch(r"ryj_[0-9a-f]{64}", result["token"]), "Unexpected credential format"
            self.secrets.extend([result["token"], base64.b64encode(("alice:" + result["token"]).encode()).decode()])
        return result

    def new_grant(self, oid=None, issuer=None, **kwargs):
        body = self.request_body(oid, **kwargs)
        self.pin(self.pin_body(body["target_oid"], body["job_id"], body["storage_generation"]))
        result = self.issue(body, issuer)
        assert "token" in result, "First issuance did not disclose credential"
        return body, result, dict(username="alice", token=result["token"])

    def transition(self, job, action, codes=(200, 204), token=None):
        return self.expect(self.checkout_path + "/" + job + "/" + action, codes,
                           token=token or self.alice, method="POST", body=b"")

    def rpc(self, oid, token, want, protocol=0):
        def pkt(value):
            value = value.encode()
            return f"{len(value) + 4:04x}".encode() + value
        if protocol == 2:
            data = pkt("command=fetch\n") + b"0001" + pkt("want " + want + "\n") + pkt("done\n") + b"0000"
        else:
            data = pkt("want " + want + "\n") + b"0000" + pkt("done\n")
        connection = http.client.HTTPConnection(self.mirror_env["ROOTYARD_BIND"], timeout=30)
        try:
            connection.request("POST", self.path(oid) + "/git-upload-pack", data,
                               {"Authorization": "Bearer " + token["token"],
                                "Content-Type": "application/x-git-upload-pack-request",
                                "Git-Protocol": "version=" + str(protocol)})
            response = connection.getresponse()
            try:
                data = response.read()
            except http.client.IncompleteRead as error:
                # Git can emit a protocol ERR then exit nonzero, which closes
                # a streaming HTTP response without its final chunk. Preserve
                # those exact bytes so the denial must still prove no PACK.
                data = error.partial
                category = ("unrelated-commit" if want == getattr(self, "unrelated", None) else
                            "unrelated-blob" if want == getattr(self, "unrelated_blob", None) else
                            "authorized-target" if want == oid else "other-synthetic-object")
                diagnostic = dict(protocol=protocol, want_category=category, status=response.status,
                                  received_bytes=len(data), received_prefix=self.redact(repr(data[:256])))
                assert b"ERR" in data or b"not our ref" in data, ("Truncated response without explicit Git denial", diagnostic)
            return response.status, data
        finally:
            connection.close()

    def deny_both(self, body, token, codes=(401, 403, 409, 503)):
        self.mirror_expect(self.advertise(body["target_oid"]), codes, token=token)
        status, response = self.rpc(body["target_oid"], token, body["target_oid"])
        assert status in codes and b"PACK" not in response, (status, response[:300])

    def setup_checkout(self):
        self.setup_mirror()
        # A descendant is deliberately outside the authorized target's closure.
        (self.work / "private.txt").write_text("unrelated secret object fixture\n")
        self.git("add", "private.txt", cwd=self.work)
        self.git("commit", "-m", "outside authorized closure", cwd=self.work)
        self.unrelated = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
        self.unrelated_blob = self.git("rev-parse", "HEAD:private.txt", cwd=self.work).stdout.decode().strip()
        self.git("push", "origin", "HEAD:main", cwd=self.work, token=self.alice)
        self.body, self.grant, self.job_token = self.new_grant()
        self.sync()
        receipt = self.root / "data" / "ci-pins" / self.repo["id"] / (self.body["job_id"] + ".pinned.json")
        expected = dict(version=1, job_id=self.body["job_id"],
                        owner_id=self.sql("SELECT id FROM users WHERE username='alice'"),
                        repository_id=self.repo["id"], storage_generation=1,
                        object_format="sha1", target_oid=self.second,
                        source_receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest(),
                        mirror_audience=self.audience, expires_unix=self.body["expires_unix"],
                        dependencies=dict(version=1, history="full", tags=[], lfs=[], submodules=[]))
        assert self.grant["plan"] == expected, self.grant["plan"]
        digest = self.sql("SELECT encode(credential_digest, 'hex') FROM ci_checkout_jobs "
                          f"WHERE repository_id='{self.repo['id']}' AND job_id='{self.body['job_id']}'")
        assert digest == hashlib.sha256(self.job_token["token"].encode()).hexdigest()
        row = self.sql("SELECT row_to_json(j) FROM ci_checkout_jobs j "
                       f"WHERE repository_id='{self.repo['id']}' AND job_id='{self.body['job_id']}'")
        assert self.job_token["token"] not in row, "SQL persisted plaintext job bearer"
        return dict(plan_matches_durable_source_receipt=True, bearer_persisted_only_as_digest=True)

    def native_clones_and_closure(self):
        for protocol in (0, 2):
            target = self.root / ("job-clone-v" + str(protocol))
            trace = self.root / ("job-protocol-" + str(protocol) + ".trace")
            environment = self.env.copy()
            environment["GIT_TRACE_PACKET"] = str(trace)
            self.git("-c", "protocol.version=" + str(protocol), "clone", self.mirror_base + self.path(self.second),
                     str(target), token=self.job_token, env=environment)
            assert ("version 2" in trace.read_text()) == (protocol == 2), "Requested Git protocol was not negotiated"
            assert self.git("rev-parse", "HEAD", cwd=target).stdout.decode().strip() == self.second
            expected_history = self.git("rev-list", self.second, cwd=self.work).stdout
            assert self.git("rev-list", "HEAD", cwd=target).stdout == expected_history
            self.git("fsck", "--full", cwd=target)
        self.mirror_expect(self.advertise(self.second), 200, token=self.job_token, basic=True)
        view = self.root / "mirror-data" / "repos" / self.repo["id"] / "job-views" / ("1-" + self.second + ".git")
        assert view.is_dir(), "Self-contained job view missing"
        expected = {line.split()[0] for line in self.git("--no-replace-objects", "rev-list", "--objects", self.second, cwd=self.work).stdout.decode().splitlines()}
        actual = set(self.git("--git-dir=" + str(view), "cat-file", "--batch-all-objects", "--batch-check=%(objectname)").stdout.decode().splitlines())
        assert actual == expected, dict(extra=sorted(actual - expected), missing=sorted(expected - actual))
        assert self.unrelated not in actual and self.unrelated_blob not in actual
        refs = self.git("--git-dir=" + str(view), "for-each-ref", "--format=%(refname) %(objectname)").stdout.decode().splitlines()
        assert refs == ["refs/heads/main " + self.second], refs
        for name in ("objects/info/alternates", "info/grafts", "shallow"):
            assert not (view / name).exists(), name
        assert not list(view.rglob("*.promisor"))
        assert not any(path.is_symlink() for path in view.rglob("*")), "Job view must not link external object storage"
        config = self.git("--git-dir=" + str(view), "config", "--list").stdout.decode().lower()
        assert "promisor" not in config and "partialclone" not in config and "alternates" not in config
        # Materialize the ordinary owner-token view and prove isolation did not
        # silently replace its existing alternates-based storage design.
        self.prepare(self.second)
        mapping = json.loads((view.parent.parent / ("pin-1-" + self.second + ".json")).read_text())
        ordinary = view.parent.parent / mapping["snapshot"] / "pins" / (self.second + ".git")
        assert (ordinary / "objects/info/alternates").is_file()
        assert ordinary.resolve() != view.resolve()
        return dict(native_protocols=[0, 2], full_history=True, exact_physical_object_count=len(actual), ordinary_owner_view_separate=True)

    def declared_tags_and_target_history(self):
        self.git("tag", "-a", "v1", "-m", "declared tag", self.first, cwd=self.work)
        self.git("push", "origin", "refs/tags/v1", cwd=self.work, token=self.alice)
        tag_oid = self.git("rev-parse", "refs/tags/v1", cwd=self.work).stdout.decode().strip()
        body, grant, token = self.new_grant(self.second, history="target", tags=["v1"])
        assert grant["plan"]["dependencies"]["history"] == "target"
        assert grant["plan"]["dependencies"]["tags"] == [{"name": "v1", "object_oid": tag_oid}]
        self.sync()
        clone = self.root / "target-history-tag-clone"
        self.git("clone", self.mirror_base + self.path(self.second), str(clone), token=token)
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == self.second
        assert self.git("rev-list", "--count", "HEAD", cwd=clone).stdout.strip() == b"1"
        assert self.git("rev-parse", "refs/tags/v1", cwd=clone).stdout.decode().strip() == tag_oid
        view = self.root / "mirror-data" / "repos" / self.repo["id"] / "job-views" / (
            "1-" + self.second + "-" + body["job_id"] + ".git")
        assert (view / "shallow").read_text() == self.second + "\n"
        refs = self.git("--git-dir=" + str(view), "for-each-ref", "--format=%(refname) %(objectname)").stdout.decode().splitlines()
        assert set(refs) == {"refs/heads/main " + self.second, "refs/tags/v1 " + tag_oid}
        expected = set(self.git("--no-replace-objects", "rev-list", "--objects", "--no-object-names",
                                "--max-count=1", self.second, "--", cwd=self.work).stdout.decode().splitlines())
        expected.update(self.git("--no-replace-objects", "rev-list", "--objects", "--no-object-names",
                                 tag_oid, "--", cwd=self.work).stdout.decode().splitlines())
        actual = set(self.git("--git-dir=" + str(view), "cat-file", "--batch-all-objects",
                              "--batch-check=%(objectname)").stdout.decode().splitlines())
        assert actual == expected, dict(extra=sorted(actual - expected), missing=sorted(expected - actual))
        self.git("fsck", "--full", cwd=clone)
        return dict(annotated_tag=True, only_declared_refs=True, target_shallow=True,
                    exact_physical_object_count=len(actual))

    def object_wants_do_not_escape(self):
        for protocol in (0, 2):
            for wanted in (self.second,):
                status, response = self.rpc(self.second, self.job_token, wanted, protocol)
                assert status == 200 and b"PACK" in response, (protocol, wanted, status, response[:300])
            for wanted in (self.unrelated, self.unrelated_blob):
                status, response = self.rpc(self.second, self.job_token, wanted, protocol)
                assert status >= 400 or b"ERR" in response or b"not our ref" in response, (protocol, status, response[:300])
                assert b"PACK" not in response, "Unauthorized object returned in pack"
        return dict(target_wants_allowed=True, ancestors_verified_in_full_clone=True,
                    known_unrelated_commit_and_blob_wants_denied=True, protocols=[0, 2])

    def native_denials_survive_backend_exit(self):
        # Make the native subprocess exit before its CGI bytes reach Rootyard.
        # This controls pipe timing without inventing a denial or changing Git's
        # return code: the wrapper emits the real CGI response in one write.
        real_git = shutil.which("git", path=self.env["PATH"])
        captured = self.root / "native-denial-response.bin"
        status_file = self.root / "native-denial-status"
        wrapper = self.root / "buffered-native-git"
        wrapper.write_text("#!/usr/bin/env python3\n" +
                          "import os, pathlib, subprocess, sys\n" +
                          "args = sys.argv[1:]\n" +
                          "if 'http-backend' not in args: os.execv(" + repr(real_git) + ", [" + repr(real_git) + "] + args)\n" +
                          "result = subprocess.run([" + repr(real_git) + "] + args, input=sys.stdin.buffer.read(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n" +
                          "pathlib.Path(" + repr(str(captured)) + ").write_bytes(result.stdout)\n" +
                          "pathlib.Path(" + repr(str(status_file)) + ").write_text(str(result.returncode))\n" +
                          "os.write(1, result.stdout)\n" +
                          "sys.exit(result.returncode)\n")
        wrapper.chmod(0o700)
        original_git = self.mirror_env.get("ROOTYARD_GIT")
        self.stop_mirror()
        self.mirror_env["ROOTYARD_GIT"] = str(wrapper)
        self.start_mirror()
        try:
            for iteration in range(8):
                for protocol in (0, 2):
                    for category, want in (("unrelated-commit", self.unrelated), ("unrelated-blob", self.unrelated_blob)):
                        try:
                            status, data = self.rpc(self.second, self.job_token, want, protocol)
                            assert b"PACK" not in data
                            assert status >= 400 or b"ERR" in data or b"not our ref" in data
                        except Exception as error:
                            native = captured.read_bytes() if captured.exists() else b""
                            diagnostic = dict(iteration=iteration, protocol=protocol, want_category=category,
                                              native_exit=status_file.read_text() if status_file.exists() else "missing",
                                              native_bytes=len(native), native_prefix=self.redact(repr(native[:512])),
                                              transport_error=self.redact(error))
                            raise AssertionError(diagnostic) from error
                        native = captured.read_bytes()
                        assert b"ERR" in native and b"PACK" not in native, "Fixture did not produce a native Git denial"
                        assert int(status_file.read_text()) != 0, "Fixture backend unexpectedly succeeded"
        finally:
            self.stop_mirror()
            if original_git is None:
                self.mirror_env.pop("ROOTYARD_GIT", None)
            else:
                self.mirror_env["ROOTYARD_GIT"] = original_git
            self.start_mirror()
        return dict(native_exit_precedes_cgi_delivery=True, denied_requests=32, protocols=[0, 2],
                    explicit_git_denial_preserved=True, no_pack_bytes=True)

    def early_stdin_failure_preserves_denial(self):
        real_git = shutil.which("git", path=self.env["PATH"])
        mode = self.root / "controlled-backend-mode"
        ready = self.root / "controlled-backend-ready"
        child_pid = self.root / "controlled-backend-child"
        wrapper = self.root / "controlled-backend-git"
        wrapper.write_text("#!/usr/bin/env python3\n" +
                          "import os, pathlib, subprocess, sys, time\n" +
                          "args = sys.argv[1:]\n" +
                          "if 'http-backend' not in args: os.execv(" + repr(real_git) + ", [" + repr(real_git) + "] + args)\n" +
                          "mode = pathlib.Path(" + repr(str(mode)) + ").read_text()\n" +
                          "if mode != 'partial-pack-after-input': os.close(0)\n" +
                          "if mode == 'denial':\n" +
                          " child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n" +
                          " pathlib.Path(" + repr(str(child_pid)) + ").write_text(str(child.pid))\n" +
                          "pathlib.Path(" + repr(str(ready)) + ").touch()\n" +
                          "os.write(1, b'Content-Type: application/x-git-upload-pack-result\\r\\n\\r\\n')\n" +
                          "if mode == 'partial-pack-after-input': sys.stdin.buffer.read()\n" +
                          "time.sleep(.3)\n" +
                          "if mode == 'denial':\n" +
                          " payload = b'ERR controlled unavailable object\\n'\n" +
                          " os.write(1, ('%04x' % (len(payload)+4)).encode() + payload)\n" +
                          "else: os.write(1, b'0008NAK\\nPACKincomplete-pack-fixture')\n" +
                          "sys.exit(1)\n")
        wrapper.chmod(0o700)
        original_git = self.mirror_env.get("ROOTYARD_GIT")
        self.stop_mirror()
        self.mirror_env["ROOTYARD_GIT"] = str(wrapper)
        self.start_mirror()
        observations = []
        try:
            for kind in ("denial", "partial-pack", "partial-pack-after-input"):
                mode.write_text(kind)
                ready.unlink(missing_ok=True)
                payload = ("want " + self.unrelated + "\n").encode()
                request = f"{len(payload) + 4:04x}".encode() + payload + b"00000009done\n"
                connection = http.client.HTTPConnection(self.mirror_env["ROOTYARD_BIND"], timeout=30)
                try:
                    # Send headers first, wait until the controlled backend has
                    # closed stdin, then send one complete, small native request.
                    # This forces BrokenPipe without an unread large HTTP body.
                    connection.putrequest("POST", self.path(self.second) + "/git-upload-pack")
                    connection.putheader("Authorization", "Bearer " + self.job_token["token"])
                    connection.putheader("Content-Type", "application/x-git-upload-pack-request")
                    connection.putheader("Content-Length", str(len(request)))
                    connection.endheaders()
                    deadline = time.monotonic() + 10
                    while not ready.exists():
                        assert time.monotonic() < deadline, "Controlled backend did not close stdin"
                        time.sleep(.01)
                    connection.send(request)
                    response = connection.getresponse()
                    complete = True
                    try:
                        data = response.read()
                    except http.client.IncompleteRead as error:
                        complete, data = False, error.partial
                    diagnostic = dict(mode=kind, status=response.status, complete=complete,
                                      received_bytes=len(data), received_prefix=self.redact(repr(data[:256])))
                    observations.append(diagnostic)
                    if kind == "denial":
                        assert response.status == 403 and complete and b"PACK" not in data, diagnostic
                        assert isinstance(json.loads(data).get("error"), str) and b"controlled unavailable" not in data, diagnostic
                        child = int(child_pid.read_text())
                        stat = Path("/proc") / str(child) / "stat"
                        if stat.exists():
                            try:
                                state = stat.read_text().rsplit(")", 1)[1].split()[0]
                            except FileNotFoundError:
                                state = "gone"
                            assert state in ("Z", "gone"), "Denied backend descendant remained alive after HTTP403"
                    else:
                        assert response.status == 200 and not complete, diagnostic
                except (OSError, http.client.HTTPException) as error:
                    raise AssertionError(dict(mode=kind, transport_error=self.redact(error),
                                              error_type=type(error).__name__, request_bytes=len(request))) from error
                finally:
                    connection.close()
        finally:
            self.stop_mirror()
            if original_git is None:
                self.mirror_env.pop("ROOTYARD_GIT", None)
            else:
                self.mirror_env["ROOTYARD_GIT"] = original_git
            self.start_mirror()
        return dict(stdin_closed_before_delayed_output=True, explicit_denial_clean_403=True,
                    partial_pack_never_clean_success=True, completed_input_partial_pack_still_fails=True,
                    denied_backend_descendant_terminated=True, observations=observations)

    def route_and_audience_scope(self):
        token = self.job_token
        self.expect("/git/alice/demo.git/info/refs?service=git-upload-pack", (401, 403), token=token)
        self.expect("/api/repos", (401, 403), token=token)
        self.issue(self.body, issuer=token, codes=(401, 403))
        self.pin(self.pin_body(self.second), codes=(401, 403), token=token)
        for action in ("cancel", "revoke"):
            self.transition(self.body["job_id"], action, codes=(401, 403), token=token)
        for path, method, body in (
                ("/api/repos", "GET", None),
                ("/api/repos/alice/demo/mirror-sync", "POST", b""),
                (self.prepare_path, "POST", dict(target_oid=self.second, storage_generation=1)),
                (self.path(self.second) + "/info/refs?service=git-receive-pack", "GET", None),
                (self.path(self.second) + "/git-receive-pack", "POST", b"0000"),
                ("/git/alice/demo.git/info/refs?service=git-upload-pack", "GET", None),
                (self.path(self.second) + "/objects/" + self.unrelated_blob[:2] + "/" + self.unrelated_blob[2:], "GET", None),
                (self.advertise(self.first), "GET", None),
                (self.advertise(self.second).replace("/alice/", "/bob/"), "GET", None),
                (self.advertise(self.second).replace("/demo.git", "/another.git"), "GET", None)):
            self.mirror_expect(path, (400, 401, 403, 404, 405, 409), token=token, method=method, body=body)
        self.mirror_expect(self.advertise(self.second), (401, 403), token=dict(username="bob", token=token["token"]), basic=True)
        self.stop_mirror()
        try:
            self.mirror_env["ROOTYARD_CI_MIRROR_AUDIENCE"] = str(uuid.uuid4())
            self.start_mirror()
            self.deny_both(self.body, token)
        finally:
            self.stop_mirror()
            self.mirror_env["ROOTYARD_CI_MIRROR_AUDIENCE"] = self.audience
            self.start_mirror()
        self.mirror_expect(self.advertise(self.second), 200, token=token)
        return dict(job_token_not_owner_credential=True, oid_owner_repo_and_audience_bound=True)

    def immutable_issuance_and_concurrency(self):
        retry = self.issue(self.body)
        assert retry["plan"] == self.grant["plan"] and "token" not in retry, "Retry disclosed or changed credential/plan"
        for key, value in (("target_oid", self.first), ("storage_generation", 2),
                           ("mirror_audience", str(uuid.uuid4())),
                           ("expires_unix", self.body["expires_unix"] + 1)):
            changed = dict(self.body, **{key: value})
            self.issue(changed, codes=409)
        body = self.request_body()
        self.pin(self.pin_body(body["target_oid"], body["job_id"]))
        barrier = threading.Barrier(6)
        def request(_):
            barrier.wait(timeout=10)
            return self.issue(body)
        with ThreadPoolExecutor(max_workers=6) as pool:
            replies = list(pool.map(request, range(6)))
        assert sum("token" in reply for reply in replies) == 1, "Concurrent retry disclosed token more than once"
        assert all(reply["plan"] == replies[0]["plan"] for reply in replies)
        retry = self.issue(body)
        assert retry["plan"] == replies[0]["plan"] and "token" not in retry
        # Issue and cancellation serialize on the same immutable job identity.
        racing = self.request_body()
        self.pin(self.pin_body(racing["target_oid"], racing["job_id"]))
        gate = threading.Barrier(2)
        def race_issue():
            gate.wait(timeout=10)
            return self.http(self.checkout_path, token=self.alice, method="POST", body=racing)
        def race_cancel():
            gate.wait(timeout=10)
            return self.transition(racing["job_id"], "cancel")
        with ThreadPoolExecutor(max_workers=2) as pool:
            issue = pool.submit(race_issue)
            cancel = pool.submit(race_cancel)
            status, response, _ = issue.result()
            cancel.result()
        assert status in (200, 201, 409), (status, response[:300])
        if status != 409:
            result = json.loads(response)
            self.secrets.append(result["token"])
            self.deny_both(racing, dict(username="alice", token=result["token"]))
        self.issue(racing, codes=409)
        return dict(exact_retry_has_no_token=True, immutable_fields=4, concurrent_identical_requests=6,
                    token_disclosures=1, concurrent_cancel_is_terminal=True)

    def source_evidence_and_input_validation(self):
        self.issue(self.request_body(), codes=409)
        for issuer, codes in ((self.reader, 403), (self.bob, (403, 404))):
            self.issue(self.body, issuer=issuer, codes=codes)
        for overrides in (dict(target_oid=self.second.upper()), dict(target_oid="f" * 39),
                          dict(job_id="invalid"), dict(storage_generation=0),
                          dict(mirror_audience="invalid"), dict(expires_unix=0)):
            self.issue(self.request_body(**overrides), codes=(400, 409, 422))
        for expiry in (int(time.time()) - 1, int(time.time()) + 7200):
            body = self.request_body(expires_unix=expiry)
            self.pin(self.pin_body(body["target_oid"], body["job_id"]))
            self.issue(body, codes=(400, 422))
        self.issue(self.request_body(target_oid="f" * 40), codes=409)
        self.issue(self.request_body(mirror_audience=str(uuid.uuid4())), codes=(400, 403, 409))
        # Only the stopped, run-owned primary's metadata is altered.
        for mutation in ("missing-receipt", "tampered-receipt", "missing-native-root"):
            body = self.request_body()
            self.pin(self.pin_body(body["target_oid"], body["job_id"]))
            receipt = self.root / "data" / "ci-pins" / self.repo["id"] / (body["job_id"] + ".pinned.json")
            before = receipt.read_bytes()
            ref = "refs/rootyard-ci/jobs/" + body["job_id"]
            self.stop()
            try:
                if mutation == "missing-receipt":
                    receipt.unlink()
                elif mutation == "tampered-receipt":
                    damaged = json.loads(before)
                    damaged["target_oid"] = self.first
                    receipt.write_text(json.dumps(damaged))
                else:
                    self.git("-c", "core.hooksPath=/dev/null", "--git-dir=" + str(self.bare), "update-ref", "-d", ref)
                self.start()
                self.issue(body, codes=(409, 503))
            finally:
                self.stop()
                receipt.write_bytes(before)
                if mutation == "missing-native-root":
                    self.git("-c", "core.hooksPath=/dev/null", "--git-dir=" + str(self.bare), "update-ref", ref, body["target_oid"])
                self.start()
        return dict(writable_owner_required=True, receipt_and_native_root_required=True, malformed_inputs_rejected=True)

    def cancel_revoke_and_issuer_fences(self):
        body = self.request_body()
        self.transition(body["job_id"], "cancel")
        self.pin(self.pin_body(body["target_oid"], body["job_id"]))
        self.issue(body, codes=409)
        self.transition(body["job_id"], "cancel")
        for action in ("cancel", "revoke"):
            body, _, token = self.new_grant()
            self.mirror_expect(self.advertise(self.second), 200, token=token)
            self.transition(body["job_id"], action)
            self.deny_both(body, token)
            self.issue(body, codes=409)
            self.transition(body["job_id"], action)
        for field, value in (("revoked", "true"), ("read_only", "true"), ("expires_at", "clock_timestamp()-interval '1 second'")):
            issuer = self.account("create-token", "alice")
            body, _, token = self.new_grant(issuer=issuer)
            self.mirror_expect(self.advertise(self.second), 200, token=token)
            self.sql(f"UPDATE tokens SET {field}={value} WHERE id='{issuer['token_id']}'")
            self.deny_both(body, token)
        body, _, token = self.new_grant(expires_unix=int(time.time()) + 3)
        while time.time() <= body["expires_unix"]:
            time.sleep(.1)
        self.deny_both(body, token)
        return dict(preissue_cancellation_terminal=True, issued_cancel_and_revoke_terminal=True,
                    issuer_revoked_readonly_expired_denied=True, expired_job_denied=True)

    def issuer_revoked_during_source_verification(self):
        issuer = self.account("create-token", "alice")
        body = self.request_body()
        self.pin(self.pin_body(body["target_oid"], body["job_id"]))
        real_git = shutil.which("git", path=self.env["PATH"])
        entered, release = [self.root / ("source-barrier-" + name) for name in ("entered", "release")]
        wrapper = self.root / "source-barrier-git"
        wrapper.write_text("#!/usr/bin/env python3\n" +
                          "import os, pathlib, sys, time\n" +
                          "args = sys.argv[1:]\n" +
                          "if 'cat-file' in args and '-t' in args:\n" +
                          " pathlib.Path(" + repr(str(entered)) + ").touch()\n" +
                          " deadline = time.monotonic() + 15\n" +
                          " while not pathlib.Path(" + repr(str(release)) + ").exists():\n" +
                          "  if time.monotonic() > deadline: sys.exit(97)\n" +
                          "  time.sleep(.02)\n" +
                          "os.execv(" + repr(real_git) + ", [" + repr(real_git) + "] + args)\n")
        wrapper.chmod(0o700)
        original_git = self.env.get("ROOTYARD_GIT")
        self.stop()
        self.env["ROOTYARD_GIT"] = str(wrapper)
        self.start()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.http, self.checkout_path, issuer, "POST", body)
                try:
                    deadline = time.monotonic() + 10
                    while not entered.exists():
                        assert not pending.done(), "Issuance ended before source cat-file verification"
                        assert time.monotonic() < deadline, "Source cat-file barrier was not reached"
                        time.sleep(.02)
                    self.cli("revoke-token", issuer["token_id"])
                    release.touch()
                    status, response, _ = pending.result(timeout=15)
                    assert status in (401, 403), (status, response[:300])
                    assert b"ryj_" not in response
                    assert self.sql("SELECT count(*) FROM ci_checkout_jobs "
                                    f"WHERE repository_id='{self.repo['id']}' AND job_id='{body['job_id']}'") == "0"
                finally:
                    release.touch()
        finally:
            release.touch()
            self.stop()
            if original_git is None:
                self.env.pop("ROOTYARD_GIT", None)
            else:
                self.env["ROOTYARD_GIT"] = original_git
            self.start()
        return dict(issuer_revoked_during_native_verification=True, no_credential_or_authority_row_created=True)

    def deleted_source_ref_and_primary_offline(self):
        branch = "job-retention-fixture"
        self.git("checkout", "-b", branch, cwd=self.work)
        try:
            self.git("commit", "--allow-empty", "-m", "job retained before sync", cwd=self.work)
            oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
            self.git("push", "origin", "HEAD:refs/heads/" + branch, cwd=self.work, token=self.alice)
            body, _, token = self.new_grant(oid)
            self.git("push", "origin", ":refs/heads/" + branch, cwd=self.work, token=self.alice)
        finally:
            self.git("checkout", "main", cwd=self.work)
        assert not self.git("ls-remote", self.remote, "refs/heads/" + branch, token=self.reader).stdout.strip()
        self.git("--git-dir=" + str(self.bare), "gc", "--prune=now")
        self.sync()
        self.stop()
        try:
            clone = self.root / "job-primary-offline"
            self.git("-c", "protocol.version=2", "clone", self.mirror_base + self.path(oid), str(clone), token=token)
            assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == oid
            assert self.git("rev-list", "HEAD", cwd=clone).stdout == self.git("rev-list", oid, cwd=self.work).stdout
            self.git("fsck", "--full", cwd=clone)
            self.sync(codes=503)
            self.mirror_expect(self.advertise(oid), 200, token=token)
        finally:
            self.start()
        return dict(source_ref_deleted_before_first_target_sync=True, source_gc_survived=True,
                    primary_offline_job_clone_full_history=True, failed_sync_preserves_job_view=True)

    def tampered_job_views_fail_closed(self):
        view = self.root / "mirror-data" / "repos" / self.repo["id"] / "job-views" / ("1-" + self.second + ".git")
        cases = (("refs/replace/" + self.second, self.first + "\n"),
                 ("info/grafts", self.second + "\n"),
                 ("shallow", self.second + "\n"),
                 ("objects/pack/fixture.promisor", ""),
                 ("objects/info/alternates", str(self.bare / "objects") + "\n"),
                 ("refs/heads/extra", self.first + "\n"),
                 ("HEAD", self.first + "\n"))
        for name, content in cases:
            path = view / name
            original = path.read_bytes() if path.exists() else None
            missing_dirs = []
            parent = path.parent
            while not parent.exists():
                missing_dirs.append(parent)
                parent = parent.parent
            self.stop_mirror()
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                self.start_mirror()
                self.deny_both(self.body, self.job_token, codes=(409, 503))
            finally:
                self.stop_mirror()
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
                for directory in missing_dirs:
                    directory.rmdir()
                self.start_mirror()
        # Extra valid loose objects are still outside the authorized closure.
        self.stop_mirror()
        result = self.run(["git", "--git-dir=" + str(view), "hash-object", "-w", "--stdin"],
                          data=b"not reachable from authorized target\n")
        extra_oid = result.stdout.decode().strip()
        extra = view / "objects" / extra_oid[:2] / extra_oid[2:]
        try:
            assert extra.is_file()
            self.start_mirror()
            self.deny_both(self.body, self.job_token, codes=(409, 503))
        finally:
            self.stop_mirror()
            extra.unlink()
            if not list(extra.parent.iterdir()):
                extra.parent.rmdir()
            self.start_mirror()
        self.mirror_expect(self.advertise(self.second), 200, token=self.job_token)
        return dict(tampered_metadata_cases=len(cases), extra_unreachable_blob_denied=True,
                    restored_view_serves=True)

    def authorization_rechecked_after_closure(self):
        # The wrapper affects only this harness's mirror subprocess. It pauses
        # the real pack builder without changing production code or its input.
        real_git = shutil.which("git", path=self.env["PATH"])
        assert real_git
        wrapper_dir = self.root / "barrier-bin"
        wrapper_dir.mkdir()
        entered, release, backend = [self.root / ("barrier-" + name) for name in ("entered", "release", "backend")]
        wrapper = wrapper_dir / "git"
        wrapper.write_text("#!/usr/bin/env python3\n" +
                          "import os, pathlib, sys, time\n" +
                          "args = sys.argv[1:]\n" +
                          "if 'http-backend' in args: pathlib.Path(" + repr(str(backend)) + ").touch()\n" +
                          "if 'pack-objects' in args and '--no-reuse-object' in args:\n" +
                          " pathlib.Path(" + repr(str(entered)) + ").touch()\n" +
                          " deadline = time.monotonic() + 15\n" +
                          " while not pathlib.Path(" + repr(str(release)) + ").exists():\n" +
                          "  if time.monotonic() > deadline: sys.exit(97)\n" +
                          "  time.sleep(.02)\n" +
                          "os.execv(" + repr(real_git) + ", [" + repr(real_git) + "] + args)\n")
        wrapper.chmod(0o700)
        original_path = self.mirror_env["PATH"]
        original_git = self.mirror_env.get("ROOTYARD_GIT")
        self.stop_mirror()
        self.mirror_env["PATH"] = str(wrapper_dir) + os.pathsep + original_path
        self.mirror_env["ROOTYARD_GIT"] = str(wrapper)
        self.start_mirror()
        try:
            for fault, oid in (("cancel", self.first), ("database", self.unrelated)):
                for path in (entered, release, backend):
                    path.unlink(missing_ok=True)
                body, _, token = self.new_grant(oid)
                renamed = False
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(self.mirror_http, self.advertise(oid), token)
                    try:
                        deadline = time.monotonic() + 10
                        while not entered.exists():
                            assert not pending.done(), "Checkout ended before entering closure barrier"
                            assert time.monotonic() < deadline, "Closure builder did not use expected pack-objects barrier"
                            time.sleep(.02)
                        assert not backend.exists(), "HTTP backend started before closure completed"
                        if fault == "cancel":
                            self.transition(body["job_id"], "cancel")
                        else:
                            self.sql("ALTER TABLE ci_checkout_jobs RENAME TO unavailable_checkout_jobs")
                            renamed = True
                        release.touch()
                        status, response, _ = pending.result(timeout=15)
                        assert status in ((401, 403, 409) if fault == "cancel" else (500, 503)), (fault, status, response[:300])
                        assert not backend.exists(), "Git backend ran after authorization changed during preparation"
                    finally:
                        release.touch()
                        if renamed:
                            self.sql("ALTER TABLE unavailable_checkout_jobs RENAME TO ci_checkout_jobs")
        finally:
            release.touch()
            self.stop_mirror()
            self.mirror_env["PATH"] = original_path
            if original_git is None:
                self.mirror_env.pop("ROOTYARD_GIT", None)
            else:
                self.mirror_env["ROOTYARD_GIT"] = original_git
            self.start_mirror()
        return dict(cancel_during_pack_preparation_denied=True, database_failure_after_preparation_denied=True,
                    denied_before_http_backend=True)

    def live_database_and_repository_fences(self):
        repo = self.repo["id"]
        for field, value, restore in (("state", "'recovering'", "'ready'"), ("storage_generation", "2", "1")):
            self.sql(f"UPDATE repositories SET {field}={value} WHERE id='{repo}'")
            try:
                self.deny_both(self.body, self.job_token)
            finally:
                self.sql(f"UPDATE repositories SET {field}={restore} WHERE id='{repo}'")
        for table in ("tokens", "repositories", "ci_checkout_jobs"):
            renamed = "checkout_unavailable_" + table
            self.sql(f"ALTER TABLE {table} RENAME TO {renamed}")
            try:
                self.deny_both(self.body, self.job_token, codes=(500, 503))
            finally:
                self.sql(f"ALTER TABLE {renamed} RENAME TO {table}")
        self.mirror_expect(self.advertise(self.second), 200, token=self.job_token)
        return dict(prepared_view_does_not_bypass_live_sql=True, recovering_and_generation_fenced=True)

    def _barrier_available(self):
        repo = uuid.UUID(self.repo["id"])
        output = self.sql(
            "BEGIN; SELECT pg_try_advisory_xact_lock("
            f"hashtextextended('rootyard-data-v1:{repo}', 0)); ROLLBACK"
        )
        return "t" in output.splitlines()

    def _active_git_children(self, data_dir=None):
        proc_dir = Path("/proc")
        if not proc_dir.is_dir():
            return []
        dirs = [data_dir] if data_dir is not None else [self.env["ROOTYARD_DATA_DIR"], self.mirror_env["ROOTYARD_DATA_DIR"]]
        markers = {f"ROOTYARD_DATA_DIR={item}".encode() for item in dirs}
        server_pids = {
            pid for pid in (
                self.proc.pid if self.proc else None,
                self.mirror_proc.pid if self.mirror_proc else None,
            ) if pid is not None
        }
        found = []
        for entry in proc_dir.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            if pid in server_pids:
                continue
            try:
                comm = (entry / "comm").read_text(errors="replace").strip()
                if not comm.startswith("git"):
                    continue
                environ = (entry / "environ").read_bytes()
            except OSError:
                continue
            if any(marker in environ for marker in markers):
                found.append((pid, comm))
        return found

    def _wait_no_git_children(self, timeout=2.5, data_dir=None):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = self._active_git_children(data_dir=data_dir)
            if not remaining:
                return
            time.sleep(0.05)
        raise AssertionError(
            f"Leaked Git subprocess(es) remained active: {self._active_git_children(data_dir=data_dir)}"
        )

    @contextlib.contextmanager
    def _scoped_revocation_env(self, bound_ms="1200", extra_env=None, extra_mirror_env=None):
        tracked_env = {}
        tracked_mirror = {}
        updates_env = {"ROOTYARD_TRANSFER_REVOCATION_BOUND_MS": bound_ms}
        updates_env.update(extra_env or {})
        updates_mirror = {"ROOTYARD_TRANSFER_REVOCATION_BOUND_MS": bound_ms}
        updates_mirror.update(extra_mirror_env or {})
        for key, value in updates_env.items():
            tracked_env[key] = self.env.get(key)
            self.env[key] = value
        for key, value in updates_mirror.items():
            tracked_mirror[key] = self.mirror_env.get(key)
            self.mirror_env[key] = value
        self.stop_mirror()
        self.stop()
        self.start()
        self.start_mirror()
        try:
            yield
        finally:
            self.stop_mirror()
            self.stop()
            for key, old in tracked_env.items():
                if old is None:
                    self.env.pop(key, None)
                else:
                    self.env[key] = old
            for key, old in tracked_mirror.items():
                if old is None:
                    self.mirror_env.pop(key, None)
                else:
                    self.mirror_env[key] = old
            self.start()
            self.start_mirror()

    def _stream_git_until_revoked(
        self,
        base,
        path,
        token,
        oid,
        payload_bytes,
        revoke,
        *,
        check_barrier=True,
        pause_after_first=0.0,
        start_barrier=None,
    ):
        def pkt(value):
            return f"{len(value) + 4:04x}".encode() + value

        url = urllib.parse.urlsplit(base)
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=15)
        body = pkt(f"want {oid} side-band-64k\n".encode()) + b"0000" + pkt(b"done\n")
        headers = {
            "Authorization": "Bearer " + token["token"],
            "Content-Type": "application/x-git-upload-pack-request",
        }
        try:
            connection.request("POST", path + "/git-upload-pack", body=body, headers=headers)
            response = connection.getresponse()
            assert response.status == 200, (response.status, response.read(200))
            first = response.read(4096)
            assert first, "upload-pack returned no data before revocation"
            if check_barrier:
                assert not self._barrier_available(), "physical GC lock bypassed active Git stream"
            if start_barrier is not None:
                start_barrier.wait(timeout=15)
            received = len(first)
            started = time.monotonic()
            custom_start = revoke()
            if isinstance(custom_start, float):
                started = custom_start
            if pause_after_first > 0:
                time.sleep(pause_after_first)
            interrupted = False
            while time.monotonic() - started < 6:
                try:
                    chunk = response.read(64 * 1024)
                except (http.client.IncompleteRead, OSError):
                    interrupted = True
                    break
                if not chunk:
                    break
                received += len(chunk)
                if pause_after_first <= 0:
                    time.sleep(0.02)
            elapsed = time.monotonic() - started
            assert interrupted or received < payload_bytes, (
                f"Git transfer completed unrevoked ({received}/{payload_bytes} bytes)"
            )
            assert received < payload_bytes, f"entire pack escaped after revocation ({received}/{payload_bytes})"
            assert elapsed < 5, f"bounded revocation took too long: {elapsed:.2f}s"
            return {"received": received, "elapsed_seconds": round(elapsed, 3)}
        finally:
            connection.close()

    def _stream_lfs_until_revoked(
        self, base, path, token, expected_size, revoke, *, pause_after_first=1.5, start_barrier=None
    ):
        url = urllib.parse.urlsplit(base)
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=15)
        try:
            connection.request("GET", path, headers={"Authorization": "Bearer " + token["token"]})
            response = connection.getresponse()
            assert response.status == 200, (response.status, response.read(200))
            assert int(response.getheader("Content-Length")) == expected_size
            first = response.read(1024)
            assert len(first) == 1024
            if start_barrier is not None:
                start_barrier.wait(timeout=15)
            received = len(first)
            started = time.monotonic()
            custom_start = revoke()
            if isinstance(custom_start, float):
                started = custom_start
            time.sleep(pause_after_first)
            interrupted = False
            while time.monotonic() - started < 6:
                try:
                    chunk = response.read(64 * 1024)
                except (http.client.IncompleteRead, OSError):
                    interrupted = True
                    break
                if not chunk:
                    break
                received += len(chunk)
            elapsed = time.monotonic() - started
            assert (interrupted or received < expected_size) and received < expected_size, (
                f"LFS transfer escaped after revocation ({received}/{expected_size} bytes)"
            )
            assert elapsed < 5, f"LFS revocation took too long: {elapsed:.2f}s"
            return {"received": received, "elapsed_seconds": round(elapsed, 3)}
        finally:
            connection.close()

    def bounded_active_transfer_revocation(self):
        lfs_bytes = os.urandom(16 * 1024 * 1024)
        lfs_oid = hashlib.sha256(lfs_bytes).hexdigest()
        self.expect(
            f"/git/alice/demo.git/info/lfs/objects/{lfs_oid}/{len(lfs_bytes)}",
            200,
            token=self.alice,
            method="PUT",
            body=lfs_bytes,
            content_type="application/octet-stream",
        )
        assert (
            self.sql(
                f"SELECT state FROM lfs_objects WHERE repository_id='{self.repo['id']}' AND oid='{lfs_oid}'"
            )
            == "ready"
        )
        pack_size = 24 * 1024 * 1024
        self.git("checkout", "-b", "revocation-large-fixture", cwd=self.work)
        try:
            (self.work / "revocation-pack.bin").write_bytes(os.urandom(pack_size))
            (self.work / "revocation-lfs.bin").write_text(
                f"version https://git-lfs.github.com/spec/v1\noid sha256:{lfs_oid}\nsize {len(lfs_bytes)}\n"
            )
            self.git("add", "revocation-pack.bin", "revocation-lfs.bin", cwd=self.work)
            self.git("commit", "-m", "bounded revocation large fixture", cwd=self.work)
            rev_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
            self.git("push", "origin", "HEAD:refs/heads/revocation-large-fixture", cwd=self.work, token=self.alice)
        finally:
            self.git("checkout", "main", cwd=self.work)

        results = {}
        with self._scoped_revocation_env(bound_ms="1200"):
            self.sync()
            # 1. Human PAT revocation mid-stream + PG barrier & child cleanup
            pat_revoked = self.account("create-token", "alice")
            results["pat_revoked"] = self._stream_git_until_revoked(
                self.base,
                "/git/alice/demo.git",
                pat_revoked,
                rev_oid,
                pack_size,
                lambda: self.cli("revoke-token", pat_revoked["token_id"]),
            )
            self.expect(f"/git/alice/demo.git/info/refs?service=git-upload-pack", (401, 403), token=pat_revoked)
            for _ in range(30):
                if self._barrier_available():
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("physical GC lock remained held after PAT revocation")
            self._wait_no_git_children()

            # 2. Human PAT expiry mid-stream
            pat_expired = self.account("create-token", "alice")
            exp_id = str(uuid.UUID(pat_expired["token_id"]))
            results["pat_expired"] = self._stream_git_until_revoked(
                self.base,
                "/git/alice/demo.git",
                pat_expired,
                rev_oid,
                pack_size,
                lambda: self.sql(f"UPDATE tokens SET expires_at=now()-interval '1 second' WHERE id='{exp_id}'"),
            )
            self.expect("/git/alice/demo.git/info/refs?service=git-upload-pack", 401, token=pat_expired)
            self._wait_no_git_children()

            # 3. Collaborator membership removal mid-stream on slow-consumer LFS + Git
            self.expect(
                "/api/repos/alice/demo/collaborators/bob",
                (200, 201),
                method="PUT",
                token=self.alice,
                body={"role": "read", "username": "bob"},
            )
            try:
                results["member_removed_slow_lfs"] = self._stream_lfs_until_revoked(
                    self.base,
                    f"/git/alice/demo.git/info/lfs/objects/{lfs_oid}",
                    self.bob,
                    len(lfs_bytes),
                    lambda: self.expect(
                        "/api/repos/alice/demo/collaborators/bob",
                        200,
                        method="DELETE",
                        token=self.alice,
                    ),
                    pause_after_first=1.6,
                )
                self.expect(f"/git/alice/demo.git/info/lfs/objects/{lfs_oid}", (403, 404), token=self.bob)
                self.expect("/git/alice/demo.git/info/refs?service=git-upload-pack", (403, 404), token=self.bob)
            finally:
                self.http("/api/repos/alice/demo/collaborators/bob", method="DELETE", token=self.alice)
            self._wait_no_git_children()

            # 4. Repository storage_generation increment mid-stream
            repo_id = self.repo["id"]
            try:
                results["generation_changed"] = self._stream_git_until_revoked(
                    self.base,
                    "/git/alice/demo.git",
                    self.reader,
                    rev_oid,
                    pack_size,
                    lambda: self.sql(f"UPDATE repositories SET storage_generation=2 WHERE id='{repo_id}'"),
                )
                self.mirror_expect(self.advertise(self.second), (401, 403, 409), token=self.job_token)
                for _ in range(30):
                    if self._barrier_available():
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("physical GC lock remained held after storage_generation change")
            finally:
                self.sql(f"UPDATE repositories SET storage_generation=1 WHERE id='{repo_id}'")
            self._wait_no_git_children()

            # 5. Concurrent CI ryj_ job cancel + natural expiry across Git + slow-consumer mirror LFS
            body_a, _, tok_a = self.new_grant(rev_oid)
            body_a_job = body_a["job_id"]
            self.mirror_expect(
                f"/api/repos/alice/demo/ci-checkouts/{body_a_job}/prepare-dependencies",
                200,
                token=self.alice,
                method="POST",
                body=b"",
            )
            exp_b = int(time.time()) + 6
            body_b, _, tok_b = self.new_grant(rev_oid, expires_unix=exp_b)
            self.mirror_expect(
                f"/api/repos/alice/demo/ci-checkouts/{body_b['job_id']}/prepare-dependencies",
                200,
                token=self.alice,
                method="POST",
                body=b"",
            )
            ci_git_path = self.path(rev_oid)
            ci_lfs_path = f"/ci/{rev_oid}/git/alice/demo.git/info/lfs/objects/{lfs_oid}"
            both_streaming = threading.Barrier(2)

            def expire_b():
                while time.time() <= exp_b + 0.35:
                    time.sleep(0.05)
                return time.monotonic()

            with ThreadPoolExecutor(max_workers=2) as pool:
                fut_a = pool.submit(
                    self._stream_git_until_revoked,
                    self.mirror_base,
                    ci_git_path,
                    tok_a,
                    rev_oid,
                    pack_size,
                    lambda: self.transition(body_a_job, "cancel"),
                    start_barrier=both_streaming,
                )
                fut_b = pool.submit(
                    self._stream_lfs_until_revoked,
                    self.mirror_base,
                    ci_lfs_path,
                    tok_b,
                    len(lfs_bytes),
                    expire_b,
                    pause_after_first=1.6,
                    start_barrier=both_streaming,
                )
                results["concurrent_job_cancel"] = fut_a.result(timeout=20)
                results["concurrent_job_expired_lfs"] = fut_b.result(timeout=25)
            self.mirror_expect(self.advertise(rev_oid), (401, 403), token=tok_a)
            self.mirror_expect(ci_lfs_path, (401, 403), token=tok_b)
            for _ in range(30):
                if self._barrier_available():
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("physical GC lock remained held after concurrent job teardown")
            self._wait_no_git_children()

            # 6. Database / authority outage fails closed within bound without child leak
            try:
                results["db_outage_fail_closed"] = self._stream_git_until_revoked(
                    self.base,
                    "/git/alice/demo.git",
                    self.reader,
                    rev_oid,
                    pack_size,
                    lambda: self.sql("ALTER TABLE tokens RENAME TO checkout_revocation_outage_tokens"),
                    check_barrier=False,
                    pause_after_first=1.6,
                )
                self.expect("/git/alice/demo.git/info/refs?service=git-upload-pack", (500, 503), token=self.reader)
                for _ in range(30):
                    if self._barrier_available():
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("physical GC lock remained held after DB outage teardown")
            finally:
                if self.sql("SELECT to_regclass('checkout_revocation_outage_tokens') IS NOT NULL") == "t":
                    self.sql("ALTER TABLE checkout_revocation_outage_tokens RENAME TO tokens")
            self._wait_no_git_children()
            self.expect("/git/alice/demo.git/info/refs?service=git-upload-pack", 200, token=self.reader)
        return results

    def mirror_cannot_bypass_revocation_via_origin(self):
        branch = "mirror-bypass-revocation-fixture"
        self.git("checkout", "-b", branch, cwd=self.work)
        try:
            (self.work / "bypass-check.txt").write_text("origin credential non-bypass fixture\n")
            self.git("add", "bypass-check.txt", cwd=self.work)
            self.git("commit", "-m", "mirror origin bypass check commit", cwd=self.work)
            bypass_oid = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
            self.git("push", "origin", "HEAD:refs/heads/" + branch, cwd=self.work, token=self.alice)
        finally:
            self.git("checkout", "main", cwd=self.work)

        hook_secret = "revocation-bypass-hook-secret-123456"
        self.secrets.append(hook_secret)
        hook = json.loads(
            self.expect(
                "/api/repos/alice/demo/webhooks",
                201,
                token=self.alice,
                method="POST",
                body={
                    "url": "http://127.0.0.1:1/hook",
                    "secret": hook_secret,
                    "events": ["pull_request"],
                    "ci_contexts": ["ci/bypass"],
                    "auto_ci_pin": True,
                },
            )
        )
        hook_id = hook["id"]
        self.expect(
            f"/api/repos/alice/demo/integrations/{hook_id}/trusted-contexts",
            200,
            token=self.alice,
            method="PUT",
            body={"context": "ci/bypass"},
        )
        pr = json.loads(
            self.expect(
                "/api/repos/alice/demo/pulls",
                201,
                token=self.alice,
                method="POST",
                body={
                    "title": "Mirror Origin Non-Bypass Check",
                    "body": "integration claim revocation test",
                    "head_ref": "refs/heads/" + branch,
                    "base_ref": "refs/heads/main",
                },
            )
        )
        assert pr["head_oid"] == bypass_oid
        run_id = self.sql(
            f"SELECT id FROM ci_runs WHERE repository_id='{self.repo['id']}' "
            f"AND context='ci/bypass' AND head_oid='{bypass_oid}'"
        )
        status, raw, _ = self.http(
            f"/api/repos/alice/demo/integrations/{hook_id}/runs/{run_id}/claim",
            method="POST",
            body={"runner_id": "bypass-runner"},
            extra_headers={"Authorization": "Bearer " + hook_secret},
        )
        assert status == 200, (status, raw[:300])
        claim = json.loads(raw)
        job_id = claim["checkout"]["plan"]["job_id"]
        int_token = {"username": "alice", "token": claim["checkout"]["token"]}
        self.secrets.append(int_token["token"])

        real_git = shutil.which("git", path=self.env["PATH"])
        entered = self.root / "origin-bypass-entered"
        release = self.root / "origin-bypass-release"
        pause_enabled = self.root / "origin-bypass-pause"
        wrapper_dir = self.root / "origin-bypass-git-bin"
        wrapper_dir.mkdir(exist_ok=True)
        wrapper = wrapper_dir / "git"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys, time\n"
            "args = sys.argv[1:]\n"
            f"if 'http-backend' in args and os.environ.get('REQUEST_METHOD') == 'POST' and pathlib.Path({repr(str(pause_enabled))}).exists():\n"
            f"    pathlib.Path({repr(str(entered))}).touch()\n"
            "    deadline = time.monotonic() + 15\n"
            f"    while not pathlib.Path({repr(str(release))}).exists():\n"
            "        if time.monotonic() > deadline: sys.exit(97)\n"
            "        time.sleep(0.02)\n"
            f"os.execv({repr(real_git)}, [{repr(real_git)}] + args)\n"
        )
        wrapper.chmod(0o700)
        for p in (entered, release):
            p.unlink(missing_ok=True)
        pause_enabled.touch()

        extra_env = {
            "ROOTYARD_GIT": str(wrapper),
            "PATH": str(wrapper_dir) + os.pathsep + self.env["PATH"],
        }
        extra_mirror = {"ROOTYARD_CI_MIRROR_SOURCE_TOKEN": self.alice["token"]}
        prepare_path = f"/api/repos/alice/demo/ci-checkouts/{job_id}/prepare-dependencies"
        try:
            with self._scoped_revocation_env(bound_ms="1200", extra_env=extra_env, extra_mirror_env=extra_mirror):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(self.mirror_http, prepare_path, int_token, "POST", b"")
                    deadline = time.monotonic() + 10
                    while not entered.exists():
                        assert not pending.done(), ("prepare-dependencies ended early", pending.result())
                        assert time.monotonic() < deadline, "mirror did not reach paused origin fetch"
                        time.sleep(0.02)
                    started = time.monotonic()
                    self.expect(f"/api/repos/alice/demo/webhooks/{hook_id}", 200, token=self.alice, method="DELETE")
                    prep_status, prep_body, _ = pending.result(timeout=8)
                    abort_elapsed = time.monotonic() - started
                assert prep_status in (401, 403, 500, 502, 503), (prep_status, prep_body[:300])
                assert abort_elapsed < 5, f"mirror prepare with source token exceeded bound: {abort_elapsed:.2f}s"
                self._wait_no_git_children(data_dir=self.mirror_env["ROOTYARD_DATA_DIR"])

                # Release primary stub and verify revoked job NEVER falls back to ROOTYARD_CI_MIRROR_SOURCE_TOKEN.
                pause_enabled.unlink(missing_ok=True)
                release.touch()
                self._wait_no_git_children()

                repo_mirror_dir = self.root / "mirror-data" / "repos" / self.repo["id"]
                assert not (repo_mirror_dir / "job-views" / f"1-{bypass_oid}.git").exists()
                assert not list(repo_mirror_dir.glob(".ci-*")), "stale temporary staging artifacts leaked"

                entered.unlink(missing_ok=True)
                release.unlink(missing_ok=True)
                pause_enabled.touch()
                retry_status, _, _ = self.mirror_http(prepare_path, int_token, method="POST", body=b"")
                assert retry_status in (401, 403), retry_status
                assert not entered.exists(), "revoked integration triggered origin fetch with mirror source token"
                self.mirror_expect(self.advertise(bypass_oid), (401, 403), token=self.alice)
                self.mirror_expect(self.advertise(bypass_oid), (401, 403), token=int_token)
        finally:
            pause_enabled.unlink(missing_ok=True)
            release.touch()
        return {
            "mirror_source_token_aborted_within_bound": round(abort_elapsed, 3),
            "post_revocation_origin_not_contacted": True,
            "broad_source_token_rejected_on_ci_route": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL must name a disposable dedicated database")
    harness = JobCheckoutHarness(args)
    success = False
    try:
        for name in ("setup_checkout", "native_clones_and_closure", "declared_tags_and_target_history",
                     "object_wants_do_not_escape",
                     "native_denials_survive_backend_exit", "early_stdin_failure_preserves_denial",
                     "route_and_audience_scope", "immutable_issuance_and_concurrency",
                     "source_evidence_and_input_validation", "cancel_revoke_and_issuer_fences",
                     "live_database_and_repository_fences", "tampered_job_views_fail_closed",
                     "authorization_rechecked_after_closure", "issuer_revoked_during_source_verification",
                     "deleted_source_ref_and_primary_offline",
                     "bounded_active_transfer_revocation",
                     "mirror_cannot_bypass_revocation_via_origin"):
            harness.case(name, getattr(harness, name))
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed", error=harness.redact(error)))
            success = False
        report = dict(passed=success, cases=harness.results,
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=["Isolated loopback services and synthetic fixtures, not production performance or power-loss validation.",
                                   "Database failures use renamed run-owned schema tables, not a database network outage.",
                                   "Bounded active-transfer revocation uses throttled loopback transfers with a configured ROOTYARD_TRANSFER_REVOCATION_BOUND_MS."])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
