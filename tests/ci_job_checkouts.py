#!/usr/bin/env python3
"""Job-scoped mirror checkout security tests using isolated loopback fixtures.

Requires a disposable ROOTYARD_TEST_DATABASE_URL. Inherits the source-pin and
mirror lifecycle, never contacts remote Git hosts, and only mutates its own SQL
schema and storage. Set TMPDIR to a workspace directory on constrained hosts.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
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
                     "deleted_source_ref_and_primary_offline"):
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
                                   "Active-stream termination is tested separately with a throttled transfer."])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
