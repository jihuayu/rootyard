#!/usr/bin/env python3
"""Durable source-pin/read-mirror integration tests using isolated fixture services.

Requires ROOTYARD_TEST_DATABASE_URL pointing at a disposable PostgreSQL database.
The harness owns one random schema and temporary primary/mirror storage directories.
It never contacts a remote Git host. See ci_mirror.py for shared fixture lifecycle.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import shutil
from pathlib import Path
import sys
import threading
import time
import uuid

from ci_mirror import MirrorHarness


class SourcePinHarness(MirrorHarness):
    pin_path = "/api/repos/alice/demo/ci-pins"
    prepare_path = "/api/repos/alice/demo/mirror-prepare"

    def pin_body(self, oid=None, job=None, generation=1):
        return dict(job_id=job or str(uuid.uuid4()), target_oid=oid or self.retained,
                    storage_generation=generation)

    def pin(self, body, codes=(200, 201), token=None):
        raw = self.expect(self.pin_path, codes, token=token or self.alice,
                          method="POST", body=body)
        return json.loads(raw) if codes == (200, 201) else raw

    def prepare(self, oid=None, generation=1, codes=200, token=None):
        raw = self.mirror_expect(self.prepare_path, codes, token=token or self.reader,
                                 method="POST", body=dict(target_oid=oid or self.retained,
                                                          storage_generation=generation))
        if codes != 200:
            return raw
        result = json.loads(raw)
        assert result["repository_id"] == self.repo["id"]
        assert result["storage_generation"] == generation
        assert result["target_oid"] == (oid or self.retained)
        assert result["object_format"] == "sha1" and result["snapshot"]
        assert result["clone_path"] == self.path(oid or self.retained)
        return result

    def source_retention_before_first_sync(self):
        # This is a unique child of main, not an ancestor retained by main.
        self.git("checkout", "-b", "source-only", cwd=self.work)
        try:
            self.git("commit", "--allow-empty", "-m", "source-only CI target", cwd=self.work)
            self.retained = self.git("rev-parse", "HEAD", cwd=self.work).stdout.decode().strip()
            self.git("push", "origin", "HEAD:refs/heads/source-only", cwd=self.work, token=self.alice)
        finally:
            self.git("checkout", "main", cwd=self.work)
        self.job = str(uuid.uuid4())
        self.request = self.pin_body(job=self.job)
        self.descriptor = self.pin(self.request)
        expected = dict(version=1, job_id=self.job,
                        owner_id=self.sql("SELECT id FROM users WHERE username='alice'"),
                        repository_id=self.repo["id"], storage_generation=1,
                        object_format="sha1", target_oid=self.retained,
                        retention_ref="refs/rootyard-ci/jobs/" + self.job, state="pinned")
        for key, value in expected.items():
            assert self.descriptor[key] == value, (key, self.descriptor)
        self.pin_file = self.root / "data" / "ci-pins" / self.repo["id"] / (self.job + ".json")
        assert self.pin_file.is_file(), "Source pin descriptor is not durable"
        self.git("push", "origin", ":refs/heads/source-only", cwd=self.work, token=self.alice)
        ordinary = self.git("ls-remote", self.remote, "refs/heads/*", "refs/tags/*", token=self.reader).stdout
        assert self.retained.encode() not in ordinary
        assert not (self.root / "mirror-data" / "repos" / self.repo["id"] / "current.json").exists(), "Fixture synced too early"
        self.git("--git-dir=" + str(self.bare), "gc", "--prune=now")
        assert self.git("--no-replace-objects", "--git-dir=" + str(self.bare), "rev-parse",
                        self.descriptor["retention_ref"]).stdout.decode().strip() == self.retained
        self.sync()
        self.prepare()
        self.clone_at(self.retained, "deleted-before-first-sync")
        return dict(unique_source_ref_deleted_before_first_sync=True, source_gc_survived=True,
                    mirror_prepare_exact_head=True)

    def immutable_jobs_and_concurrency(self):
        before = self.pin_file.read_bytes()
        assert self.pin(self.request) == self.descriptor
        assert self.pin_file.read_bytes() == before
        for body in (self.pin_body(self.second, self.job), self.pin_body(job=self.job, generation=2)):
            self.pin(body, 409)
        # A barrier ensures both HTTP requests enter concurrently, rather than
        # merely testing two sequential uses of an idempotency key.
        def parallel(bodies):
            barrier = threading.Barrier(len(bodies))
            def request(body):
                barrier.wait(timeout=10)
                return self.http(self.pin_path, token=self.alice, method="POST", body=body)
            with ThreadPoolExecutor(max_workers=len(bodies)) as pool:
                return list(pool.map(request, bodies))
        same = self.pin_body()
        replies = parallel([same] * 6)
        assert all(status in (200, 201) for status, _, _ in replies), replies
        assert all(json.loads(body) == json.loads(replies[0][1]) for _, body, _ in replies)
        conflict_job = str(uuid.uuid4())
        replies = parallel([self.pin_body(self.first, conflict_job), self.pin_body(self.second, conflict_job)])
        assert sorted(status == 409 for status, _, _ in replies) == [False, True], replies
        winner = next(json.loads(body) for status, body, _ in replies if status in (200, 201))
        assert self.pin(self.pin_body(winner["target_oid"], conflict_job)) == winner
        assert self.pin_file.read_bytes() == before
        return dict(identical_retries_stable=True, concurrent_identical_requests=6,
                    concurrent_conflict_single_winner=True)

    def authorization_and_validation(self):
        self.expect(self.pin_path, 401, method="POST", body=self.pin_body())
        self.pin(self.pin_body(), 401, token={"token": "invalid"})
        self.pin(self.pin_body(), 403, token=self.reader)
        self.pin(self.pin_body(), (403, 404), token=self.bob)
        self.mirror_expect(self.prepare_path, 401, method="POST", body=dict(target_oid=self.retained, storage_generation=1))
        self.prepare(codes=(403, 404), token=self.bob)
        revoked = self.account("create-token", "alice")
        self.cli("revoke-token", revoked["token_id"])
        self.pin(self.pin_body(), 401, token=revoked)
        self.prepare(codes=401, token=revoked)
        for oid in (self.retained.upper(), self.retained[:12], "not-an-oid"):
            self.pin(self.pin_body(oid), (400, 422))
            self.prepare(oid, codes=(400, 422))
        self.pin(self.pin_body(job="not-a-uuid"), (400, 422))
        self.pin(self.pin_body("f" * 40), 409)
        self.prepare("f" * 40, codes=409)
        self.pin(self.pin_body(generation=2), 409)
        self.prepare(generation=2, codes=409)
        self.prepare(token=self.reader)
        return dict(write_owner_required=True, read_only_prepare_accepted=True,
                    invalid_ids_missing_objects_and_wrong_generation_rejected=True)

    def replacement_refs_do_not_change_types(self):
        blob = self.git("rev-parse", self.second + ":hello.txt", cwd=self.work).stdout.decode().strip()
        tree = self.git("rev-parse", self.second + "^{tree}", cwd=self.work).stdout.decode().strip()
        commit = self.run(["git", "--no-replace-objects", "commit-tree", tree, "-p", self.second],
                          cwd=self.work, data=b"adversarial replacement fixture\n").stdout.decode().strip()
        refs = ["refs/replace/" + oid for oid in (blob, tree, commit)]
        branch = "refs/heads/replacement-fixture"
        self.git("--no-replace-objects", "push", "origin", commit + ":" + branch,
                 self.second + ":" + refs[0], self.second + ":" + refs[1], blob + ":" + refs[2],
                 cwd=self.work, token=self.alice)
        try:
            for oid in (blob, tree):
                self.pin(self.pin_body(oid), 409)
            self.pin(self.pin_body(commit))
            self.sync()
            for oid in (blob, tree):
                self.prepare(oid, codes=409)
            self.prepare(commit)
            self.clone_at(commit, "commit-replaced-by-blob")
        finally:
            self.git("--no-replace-objects", "push", "origin", *[":" + ref for ref in refs],
                     ":" + branch, cwd=self.work, token=self.alice)
        return dict(blob_tree_rejected_despite_replacement=True, genuine_commit_accepted=True)

    def reserved_namespace_rejects_entire_push(self):
        reserved = self.descriptor["retention_ref"]
        fresh = "refs/rootyard-ci/jobs/" + str(uuid.uuid4())
        for refspec in (self.second + ":" + fresh, self.second + ":refs/rootyard-ci/other",
                        "+" + self.second + ":" + reserved, ":" + reserved):
            result = self.git("push", "origin", refspec, cwd=self.work, token=self.alice, check=False)
            assert result.returncode != 0, "Reserved ref mutation accepted"
        for atomic in (False, True):
            ordinary = "refs/heads/mixed-" + str(atomic).lower()
            result = self.git("push", *( ["--atomic"] if atomic else [] ), "origin",
                              self.second + ":" + ordinary, self.second + ":" + fresh,
                              cwd=self.work, token=self.alice, check=False)
            assert result.returncode != 0, "Mixed push unexpectedly succeeded"
            assert not self.git("ls-remote", self.remote, ordinary, token=self.reader).stdout.strip(), "Partial mixed push escaped rejection"
        assert not self.git("ls-remote", self.remote, fresh, token=self.reader).stdout.strip()
        assert self.git("--git-dir=" + str(self.bare), "rev-parse", reserved).stdout.decode().strip() == self.retained
        assert self.pin(self.request) == self.descriptor
        return dict(reserved_create_update_delete_rejected=True, atomic_and_nonatomic_mixed_pushes_fully_rejected=True)

    def restarts_and_primary_offline(self):
        before = self.pin_file.read_bytes()
        self.stop_mirror()
        self.stop()
        self.start()
        self.start_mirror()
        assert self.pin(self.request) == self.descriptor
        assert self.pin_file.read_bytes() == before
        self.prepare()
        self.stop()
        try:
            self.prepare()
            self.clone_at(self.retained, "primary-stopped-exact-pin")
            self.sync(codes=503)
            self.clone_at(self.retained, "failed-sync-still-exact-pin")
        finally:
            self.start()
        return dict(durable_source_and_mirror_restart=True, primary_offline_clone_and_prepare=True)

    def maintenance_audit_is_not_a_push_projection(self):
        ref = self.descriptor["retention_ref"]
        event = self.sql("SELECT e.event_id FROM outbox_events e JOIN git_operations o ON o.id=e.operation_id "
                         f"WHERE e.repository_id='{self.repo['id']}' AND e.ref_name='{ref}' "
                         "AND e.storage_generation=1 AND o.outcome='recorded' "
                         "AND o.evidence->>'kind'='observed_immutable_ci_root'")
        assert event and "\n" not in event, "Exactly one CI retention audit event expected"
        deadline = time.monotonic() + 20
        while self.sql(f"SELECT count(*) FROM event_deliveries WHERE event_id='{event}' AND state='delivered'") != "2":
            assert time.monotonic() < deadline, "CI maintenance deliveries did not complete"
            time.sleep(.1)
        assert self.sql(f"SELECT count(*) FROM audit_events WHERE event_id='{event}'") == "1"
        assert self.sql(f"SELECT state FROM event_deliveries WHERE event_id='{event}' AND consumer='ref-index'") == "delivered"
        assert self.sql(f"SELECT effect FROM event_deliveries WHERE event_id='{event}' AND consumer='ref-index'") == "applied"
        assert self.sql(f"SELECT count(*) FROM repository_ref_projection WHERE repository_id='{self.repo['id']}' "
                        "AND ref_name LIKE 'refs/rootyard-ci/%' AND source_kind='push_receipt'") == "0"
        return dict(ci_outbox_and_audit_present=True, ref_index_delivery_completed=True,
                    maintenance_not_projected_as_push_receipt=True)

    def source_auth_query_failure_is_closed(self):
        before = self.pin_file.read_bytes()
        self.sql("ALTER TABLE tokens RENAME TO ci_source_unavailable_tokens")
        try:
            self.pin(self.request, (500, 503))
            self.pin(self.pin_body(), (500, 503))
        finally:
            self.sql("ALTER TABLE ci_source_unavailable_tokens RENAME TO tokens")
        assert self.pin_file.read_bytes() == before
        assert self.pin(self.request) == self.descriptor
        return dict(source_auth_query_failure_closed=True, existing_intent_unchanged=True)

    def source_admission_bound_preserves_existing_job(self):
        repo = self.fixture_repository("source-admission-bound")
        self.stop()
        try:
            intent, receipt = self.fixture_intent(repo)
            directory = receipt.parent
            for _ in range(1023):
                other = dict(intent)
                other["job_id"] = str(uuid.uuid4())
                other["retention_ref"] = "refs/rootyard-ci/jobs/" + other["job_id"]
                (directory / (other["job_id"] + ".json")).write_text(json.dumps(other, separators=(",", ":")))
            assert len(list(directory.glob("*.json"))) == 1024
            bare = self.root / "data" / "repos" / (repo["id"] + ".git")
            assert not self.git("--git-dir=" + str(bare), "for-each-ref", "refs/rootyard-ci").stdout.strip()
        finally:
            self.start()
        endpoint = "/api/repos/alice/" + repo["name"] + "/ci-pins"
        self.expect(endpoint, 429, token=self.alice, method="POST", body=self.pin_body(self.second))
        body = dict(job_id=intent["job_id"], target_oid=self.second, storage_generation=1)
        result = json.loads(self.expect(endpoint, (200, 201), token=self.alice, method="POST", body=body))
        assert result["job_id"] == intent["job_id"] and result["state"] == "pinned"
        assert json.loads(receipt.read_text()) == intent
        assert json.loads(self.expect(endpoint, (200, 201), token=self.alice, method="POST", body=body)) == result
        return dict(synthetic_valid_intents=1024, new_job_rejected_at_bound=True,
                    existing_identical_job_converges_at_bound=True)

    def mirror_admission_bound_preserves_existing_mapping(self):
        self.sync()
        self.prepare()
        root = self.root / "mirror-data" / "repos" / self.repo["id"]
        existing = root / ("pin-1-" + self.retained + ".json")
        candidate = root / ("pin-1-" + self.second + ".json")
        assert not candidate.exists(), "Admission fixture needs an unprepared available commit"
        made = []
        self.stop_mirror()
        try:
            # Populate valid snapshot mapping records without claiming 1024
            # separately materialized clones or a scale/performance benchmark.
            count = len(list(root.glob("pin-*.json")))
            for index in range(1024 - count):
                path = root / (f"pin-1-{index + 1:040x}.json")
                assert not path.exists()
                path.write_bytes(existing.read_bytes())
                made.append(path)
            assert len(list(root.glob("pin-*.json"))) == 1024
            self.start_mirror()
            self.prepare(self.second, codes=429)
            assert not candidate.exists()
            self.prepare()
            self.clone_at(self.retained, "mirror-at-mapping-bound")
        finally:
            self.stop_mirror()
            for path in made:
                path.unlink()
            self.start_mirror()
        self.prepare(self.second)
        return dict(synthetic_mapping_records=1024, new_mapping_rejected_at_bound=True,
                    existing_mapping_served_at_bound=True, admission_resumes_after_fixture_cleanup=True)

    def fixture_repository(self, name):
        repo = json.loads(self.expect("/api/repos", 201, token=self.alice,
                                      method="POST", body={"name": name}))
        self.git("push", self.base + repo["clone_path"], "HEAD:main", cwd=self.work, token=self.alice)
        return repo

    def fixture_intent(self, repo):
        job = str(uuid.uuid4())
        intent = dict(version=1, job_id=job,
                      owner_id=self.sql("SELECT id FROM users WHERE username='alice'"),
                      repository_id=repo["id"], storage_generation=1, object_format="sha1",
                      target_oid=self.second, retention_ref="refs/rootyard-ci/jobs/" + job)
        directory = self.root / "data" / "ci-pins" / repo["id"]
        directory.mkdir(parents=True, exist_ok=True)
        # Match serde's canonical compact struct field order for immutable retry.
        (directory / (job + ".json")).write_text(json.dumps(intent, separators=(",", ":")))
        return intent, directory / (job + ".pinned.json")

    def fixture_operation(self, intent, phase=None, finished=False):
        directory = self.root / "data" / "journal" / intent["repository_id"]
        sequence = int((directory / "sequence").read_text()) + 1
        operation_id = str(uuid.uuid4())
        (directory / "sequence").write_text(str(sequence))
        operation = directory / (f"{sequence:020}-" + operation_id)
        operation.mkdir(mode=0o700)
        metadata = dict(id=operation_id, repository_id=intent["repository_id"],
                        actor_id=intent["owner_id"], actor_name="alice", token_id=self.alice["token_id"],
                        sequence=sequence, storage_generation=1, ci_pin=intent)
        (operation / "operation.json").write_text(json.dumps(metadata, separators=(",", ":")))
        if phase:
            event = dict(ordinal=1, phase=phase,
                         changes=[dict(ref_name=intent["retention_ref"], old_oid="0" * 40,
                                       new_oid=intent["target_oid"])])
            (operation / "00000000000000000001.event.json").write_text(json.dumps(event))
        if finished:
            (operation / "finished").write_bytes(b"")
        return operation_id, operation

    def fixture_ref(self, repo, name, oid=None):
        assert self.proc is None, "Offline mutation requires stopped fixture primary"
        bare = self.root / "data" / "repos" / (repo["id"] + ".git")
        self.git("-c", "core.hooksPath=/dev/null", "--git-dir=" + str(bare),
                 "update-ref", name, oid or self.second)

    def offline_publication_boundaries(self):
        states = ("intent-only", "before-cas", "after-cas", "after-projection")
        for phase in states:
            repo = self.fixture_repository("fault-" + phase)
            self.stop()
            operation_id = operation = None
            try:
                intent, receipt = self.fixture_intent(repo)
                if phase != "intent-only":
                    operation_id, operation = self.fixture_operation(
                        intent, phase="Prepared", finished=phase == "after-projection")
                if phase in ("after-cas", "after-projection"):
                    self.fixture_ref(repo, intent["retention_ref"])
                if phase == "after-projection":
                    # Reconcile performs the actual SQL publication. Reintroduce
                    # the identical finished journal to model interrupted retirement.
                    saved = self.root / ("saved-" + operation_id)
                    shutil.copytree(operation, saved)
                    self.cli("reconcile")
                    assert not operation.exists()
                    shutil.copytree(saved, operation)
                    before_events = self.sql(f"SELECT count(*) FROM outbox_events WHERE operation_id='{operation_id}'")
                assert not receipt.exists()
            finally:
                self.start()
            body = dict(job_id=intent["job_id"], target_oid=intent["target_oid"], storage_generation=1)
            result = json.loads(self.expect("/api/repos/alice/" + repo["name"] + "/ci-pins",
                                           (200, 201), method="POST", token=self.alice, body=body))
            assert result["state"] == "pinned" and result["target_oid"] == self.second
            assert receipt.is_file()
            assert json.loads(receipt.read_text()) == intent
            if operation_id:
                outcome = self.sql(f"SELECT outcome FROM git_operations WHERE id='{operation_id}'")
                assert outcome == ("no_ref_changes" if phase == "before-cas" else "recorded"), (phase, outcome)
                assert not operation.exists()
            if phase == "after-projection":
                assert self.sql(f"SELECT count(*) FROM outbox_events WHERE operation_id='{operation_id}'") == before_events
        return dict(synthetic_offline_boundaries=list(states), exact_retry_converges=True,
                    projected_operation_not_duplicated=True, no_runtime_failpoint=True)

    def namespace_collisions_and_metadata_symlinks(self):
        for index, collision in enumerate(("refs/rootyard-ci", "refs/rootyard-ci/jobs")):
            repo = self.fixture_repository("namespace-collision-" + str(index))
            self.stop()
            try:
                self.fixture_ref(repo, collision)
            finally:
                self.start()
            body = self.pin_body(self.second)
            self.expect("/api/repos/alice/" + repo["name"] + "/ci-pins", 409,
                        token=self.alice, method="POST", body=body)
            bare = self.root / "data" / "repos" / (repo["id"] + ".git")
            assert self.git("--git-dir=" + str(bare), "rev-parse", collision).stdout.decode().strip() == self.second
            assert not (self.root / "data" / "ci-pins" / repo["id"] / (body["job_id"] + ".json")).exists()
        repo = self.fixture_repository("namespace-dangling-symbolic")
        self.stop()
        bare = self.root / "data" / "repos" / (repo["id"] + ".git")
        symbolic = "refs/rootyard-ci/jobs/" + str(uuid.uuid4())
        try:
            self.git("-c", "core.hooksPath=/dev/null", "--git-dir=" + str(bare),
                     "symbolic-ref", symbolic, "refs/heads/absent-target")
            assert not self.git("--git-dir=" + str(bare), "for-each-ref", "refs/rootyard-ci").stdout.strip()
        finally:
            self.start()
        self.expect("/api/repos/alice/" + repo["name"] + "/ci-pins", 409,
                    token=self.alice, method="POST", body=self.pin_body(self.second))
        assert self.git("--git-dir=" + str(bare), "symbolic-ref", symbolic).stdout.strip() == b"refs/heads/absent-target"
        repo = self.fixture_repository("metadata-symlink")
        self.stop()
        body = self.pin_body(self.second)
        directory = self.root / "data" / "ci-pins" / repo["id"]
        directory.mkdir(parents=True)
        link = directory / (body["job_id"] + ".json")
        link.symlink_to(directory / "absent-target")
        self.start()
        try:
            self.expect("/api/repos/alice/" + repo["name"] + "/ci-pins", (500, 503),
                        token=self.alice, method="POST", body=body)
            assert link.is_symlink() and not link.exists()
            bare = self.root / "data" / "repos" / (repo["id"] + ".git")
            assert not self.git("--git-dir=" + str(bare), "for-each-ref", "refs/rootyard-ci").stdout.strip()
        finally:
            self.stop()
            link.unlink()
            self.start()
        return dict(namespace_ancestor_collisions_preserved=True, dangling_native_symbolic_ref_preserved=True,
                    dangling_metadata_symlink_rejected=True)

    def unknown_ci_operation_is_not_reinterpreted(self):
        repo = self.fixture_repository("unknown-ci-audit")
        self.stop()
        try:
            intent, receipt = self.fixture_intent(repo)
            operation_id, operation = self.fixture_operation(intent, phase="Committed", finished=True)
            # A committed event without its root cannot establish retention.
            self.cli("reconcile")
            query = f"SELECT row_to_json(o) FROM git_operations o WHERE id='{operation_id}'"
            before = json.loads(self.sql(query))
            assert before["outcome"] == "unknown"
            assert operation.exists()
            self.fixture_ref(repo, intent["retention_ref"])
            self.cli("reconcile")
            assert json.loads(self.sql(query)) == before, "Later native ref observation rewrote unknown audit evidence"
            assert self.sql(f"SELECT state FROM repositories WHERE id='{repo['id']}'") == "recovering"
            assert not receipt.exists()
        finally:
            self.start()
        self.expect("/api/repos/alice/" + repo["name"] + "/ci-pins", 503,
                    token=self.alice, method="POST",
                    body=dict(job_id=intent["job_id"], target_oid=self.second, storage_generation=1))
        assert not receipt.exists()
        return dict(unknown_audit_record_unchanged=True, later_exact_ref_cannot_promote=True)

    def sha256_source_rejected_without_publication(self):
        # Publish a valid SHA-1 mirror first. Replacing only this stopped
        # synthetic primary's bare directory models unsupported on-disk format.
        self.sync()
        self.prepare()
        mirror_root = self.root / "mirror-data" / "repos" / self.repo["id"]
        pointer = mirror_root / "current.json"
        pointer_before = pointer.read_bytes()
        snapshot = json.loads(pointer_before)
        mirror_config = mirror_root / snapshot["snapshot"] / "repository.git" / "config"
        mirror_config_before = mirror_config.read_bytes()
        alternate = self.root / "sha256-fixture.git"
        saved = self.root / "saved-sha1-primary.git"
        self.git("init", "--bare", "--object-format=sha256", "--initial-branch=main", str(alternate))
        tree = self.run(["git", "--git-dir=" + str(alternate), "mktree"], data=b"").stdout.decode().strip()
        oid = self.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "--git-dir=" + str(alternate), "commit-tree", tree],
                       data=b"Actual SHA256 fixture commit\n").stdout.decode().strip()
        assert len(oid) == 64
        self.git("--git-dir=" + str(alternate), "update-ref", "refs/heads/main", oid)
        self.git("--git-dir=" + str(alternate), "config", "rootyard.repositoryId", self.repo["id"])
        assert self.git("--git-dir=" + str(alternate), "cat-file", "-t", oid[:40]).stdout.strip() == b"commit"
        self.stop()
        self.bare.rename(saved)
        try:
            alternate.rename(self.bare)
            self.start()
            transport_clone = self.root / "authenticated-sha256-clone.git"
            self.git("clone", "--mirror", "--no-local", self.remote, str(transport_clone), token=self.reader)
            assert self.git("--git-dir=" + str(transport_clone), "rev-parse", "--show-object-format").stdout.strip() == b"sha256"
            assert self.git("--git-dir=" + str(transport_clone), "rev-parse", "HEAD").stdout.decode().strip() == oid
            assert oid.encode() in self.git("ls-remote", self.remote, "refs/heads/main", token=self.reader).stdout
            def contents(path):
                return {str(item.relative_to(path)): hashlib.sha256(item.read_bytes()).hexdigest()
                        for item in path.rglob("*") if item.is_file()}
            intents = self.root / "data" / "ci-pins" / self.repo["id"]
            journal = self.root / "data" / "journal" / self.repo["id"]
            intents_before = contents(intents)
            journal_before = contents(journal)
            native_before = contents(self.bare)
            request = self.pin_body(oid[:40])
            self.pin(request, 409)
            assert contents(intents) == intents_before, "Unsupported format changed CI intent or receipt"
            assert contents(journal) == journal_before, "Unsupported format changed operation journal or sequence"
            assert contents(self.bare) == native_before, "Unsupported format changed native refs or objects"
            assert not (intents / (request["job_id"] + ".json")).exists()
            self.sync(codes=503)
            assert pointer.read_bytes() == pointer_before, "SHA256 sync replaced valid snapshot pointer"
            assert mirror_config.read_bytes() == mirror_config_before, "SHA256 sync rewrote published snapshot config"
            assert contents(self.bare) == native_before, "SHA256 sync altered primary config or repository"
            self.clone_at(self.retained, "sha256-sync-failure-preserves-sha1")
        finally:
            self.stop()
            if self.bare.exists():
                self.bare.rename(alternate)
            saved.rename(self.bare)
            self.start()
        assert self.pin(self.request) == self.descriptor
        return dict(real_sha256_commit_prefix_resolves=True, authenticated_sha256_upstream_clone_verified=True,
                    source_format_rejected_before_any_publication=True,
                    mirror_sha256_sync_rejected=True, previous_pointer_and_config_byte_exact=True)

    def recovery_and_generation_fences(self):
        repo = self.repo["id"]
        self.sql(f"UPDATE repositories SET state='recovering' WHERE id='{repo}'")
        try:
            self.pin(self.request, 503)
            self.prepare(codes=503)
        finally:
            self.sql(f"UPDATE repositories SET state='ready' WHERE id='{repo}'")
        self.sql(f"UPDATE repositories SET storage_generation=2 WHERE id='{repo}'")
        try:
            self.pin(self.request, 409)
            self.prepare(codes=409)
            self.mirror_expect(self.advertise(self.retained), 409, token=self.reader)
            self.pin(self.pin_body(job=self.job, generation=2), 409)
            new = self.pin(self.pin_body(generation=2))
            assert new["storage_generation"] == 2
            self.sync()
            self.prepare(generation=2)
            self.clone_at(self.retained, "generation-two-pin")
        finally:
            # Restore this synthetic SQL fence; this case does not claim an
            # end-to-end offline recovery-resolution or paired-backup drill.
            self.sql(f"UPDATE repositories SET storage_generation=1 WHERE id='{repo}'")
        return dict(recovering_state_closed=True, stale_generation_closed=True,
                    immutable_old_job_not_rebound=True, new_generation_pin_prepared=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    if not os.environ.get("ROOTYARD_TEST_DATABASE_URL"):
        parser.error("ROOTYARD_TEST_DATABASE_URL must name a disposable dedicated database")
    harness = SourcePinHarness(args)
    success = False
    try:
        for name in ("setup_mirror", "source_retention_before_first_sync", "immutable_jobs_and_concurrency",
                     "authorization_and_validation", "replacement_refs_do_not_change_types",
                     "reserved_namespace_rejects_entire_push", "restarts_and_primary_offline",
                     "maintenance_audit_is_not_a_push_projection", "source_auth_query_failure_is_closed",
                     "source_admission_bound_preserves_existing_job", "mirror_admission_bound_preserves_existing_mapping",
                     "sha256_source_rejected_without_publication", "recovery_and_generation_fences", "offline_publication_boundaries",
                     "namespace_collisions_and_metadata_symlinks", "unknown_ci_operation_is_not_reinterpreted"):
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
                      limitations=["Isolated loopback services, not production performance or power-loss validation.",
                                   "Recovery state/generation are synthetic SQL fences, not a paired-backup restore drill.",
                                   "Admission limits use synthetic metadata records, not 1024 physical clones; no disk-full injection."])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
