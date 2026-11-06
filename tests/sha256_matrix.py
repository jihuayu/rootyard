#!/usr/bin/env python3
"""Native SHA-256 mirror/pin/checkout matrix and SHA-1 regression.

The existing SHA-256 smoke (tests/sha256_service.py) proves service creation,
stock push/fetch/browse, ref CAS and Forge format admission. This drill covers
the remaining issue #38 acceptance path against real processes:

* a SHA-256 repository synced to a real ``serve-mirror`` process
* a source pin and mirror preparation carrying a 64-hex exact OID
* an immutable CI checkout plan/receipt complete enough to materialize the
  job view, plus a stock ``git clone`` of the fetched OID
* a SHA-1 repository run through the same mirror/pin/checkout matrix as a
  regression, and
* negative mixed-format, abbreviated and uppercase OID requests on the actual
  binaries (never inferred from length).

Requires a disposable ROOTYARD_TEST_DATABASE_URL. Only a random schema and
temporary storage are created. No external hosts or credentials are used.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

from ci_mirror import MirrorHarness


class Sha256MatrixHarness(MirrorHarness):
    def __init__(self, args):
        super().__init__(args)
        self.audience = str(uuid.uuid4())
        self.env["ROOTYARD_CI_MIRROR_AUDIENCE"] = self.audience
        self.mirror_env["ROOTYARD_CI_MIRROR_AUDIENCE"] = self.audience

    def create_repository(self, name, object_format):
        repo = json.loads(self.expect("/api/repos", 201, token=self.alice, method="POST",
                                      body={"name": name, "object_format": object_format}))
        assert repo["object_format"] == object_format, repo
        return repo

    def seed(self, name, object_format, files=2):
        repo = self.create_repository(name, object_format)
        remote = self.base + repo["clone_path"]
        work = self.root / ("work-" + name)
        self.git("init", "--object-format=" + object_format, "--initial-branch=main",
                 str(work))
        self.git("config", "user.name", "Matrix", cwd=work)
        self.git("config", "user.email", "matrix@example.invalid", cwd=work)
        self.git("remote", "add", "origin", remote, cwd=work)
        for index in range(files):
            (work / (f"file{index}.txt")).write_text(f"{object_format} fixture {index}\n")
            self.git("add", (f"file{index}.txt"), cwd=work)
            self.git("commit", "-m", f"{object_format} commit {index}", cwd=work)
        head = self.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
        expected = 64 if object_format == "sha256" else 40
        assert len(head) == expected, head
        assert self.git("rev-parse", "--show-object-format", cwd=work).stdout.strip() == object_format.encode()
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=self.alice)
        clone = self.root / ("clone-" + name)
        self.git("clone", remote, str(clone), token=self.alice)
        assert self.git("rev-parse", "--show-object-format", cwd=clone).stdout.strip() == object_format.encode()
        assert self.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == head
        self.git("fsck", "--full", cwd=clone)
        return dict(repo=repo, remote=remote, work=work, head=head)

    def sync_repository(self, name, codes=200):
        raw = self.mirror_expect(f"/api/repos/alice/{name}/mirror-sync", codes,
                                 token=self.alice, method="POST", body=b"")
        if codes != 200:
            return raw
        return json.loads(raw)

    def prepare(self, name, oid, object_format, codes=200, generation=1):
        raw = self.mirror_expect(f"/api/repos/alice/{name}/mirror-prepare", codes,
                                 token=self.reader, method="POST",
                                 body={"target_oid": oid, "storage_generation": generation})
        if codes != 200:
            return raw
        result = json.loads(raw)
        assert result["object_format"] == object_format, result
        assert result["target_oid"] == oid
        assert result["storage_generation"] == generation
        assert result["snapshot"]
        assert result["clone_path"] == f"/ci/{oid}/git/alice/{name}.git", result
        return result

    def pin(self, name, oid, job=None, codes=(200, 201), generation=1):
        job = job or str(uuid.uuid4())
        body = {"job_id": job, "target_oid": oid, "storage_generation": generation}
        raw = self.expect(f"/api/repos/alice/{name}/ci-pins", codes, token=self.alice,
                          method="POST", body=body)
        return (json.loads(raw) if codes == (200, 201) else raw), job

    def checkout(self, name, body, codes=(200, 201), token=None):
        raw = self.expect(f"/api/repos/alice/{name}/ci-checkouts", codes,
                          token=token or self.alice, method="POST", body=body)
        return json.loads(raw) if codes == (200, 201) else raw

    def checkout_body(self, oid, job, generation=1):
        return dict(job_id=job, target_oid=oid, storage_generation=generation,
                    mirror_audience=self.audience,
                    expires_unix=int(time.time()) + 1800)

    def assert_plan(self, result, repo, oid, object_format, job):
        plan = result["plan"]
        receipt = self.root / "data" / "ci-pins" / repo["id"] / (job + ".pinned.json")
        assert receipt.is_file(), "durable pin receipt missing"
        expected = dict(
            version=1, job_id=job,
            owner_id=self.sql("SELECT id FROM users WHERE username='alice'"),
            repository_id=repo["id"], storage_generation=1,
            object_format=object_format, target_oid=oid,
            source_receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest(),
            mirror_audience=self.audience,
            expires_unix=result["plan"]["expires_unix"],
            dependencies=dict(version=1, history="full", tags=[], lfs=[], submodules=[]))
        assert plan == expected, plan
        assert len(plan["target_oid"]) == (64 if object_format == "sha256" else 40)
        assert len(plan["source_receipt_sha256"]) == 64
        assert result["token"].startswith("ryj_")
        self.secrets.extend([result["token"],
                             base64.b64encode(("alice:" + result["token"]).encode()).decode()])
        return plan

    def clone_checkout(self, name, oid, token, object_format, label):
        target = self.root / ("job-clone-" + label)
        self.git("clone", self.mirror_base + f"/ci/{oid}/git/alice/{name}.git",
                 str(target), token=token)
        assert self.git("rev-parse", "HEAD", cwd=target).stdout.decode().strip() == oid
        assert self.git("rev-parse", "--show-object-format", cwd=target).stdout.strip() == object_format.encode()
        self.git("fsck", "--full", "--strict", cwd=target)
        view = (self.root / "mirror-data" / "repos" /
                self.repositories[name]["repo"]["id"] / "job-views" / f"1-{oid}.git")
        assert view.is_dir(), "materialized job view missing"
        assert self.git("--git-dir=" + str(view), "rev-parse",
                        "--show-object-format").stdout.strip() == object_format.encode()
        config = (view / "config").read_text()
        assert ("objectFormat = sha256" in config) == (object_format == "sha256"), config
        refs = self.git("--git-dir=" + str(view), "for-each-ref",
                        "--format=%(refname) %(objectname)").stdout.decode().splitlines()
        assert refs == ["refs/heads/main " + oid], refs
        return target

    def full_matrix(self, name, object_format):
        fixture = self.seed(name, object_format)
        self.repositories = getattr(self, "repositories", {})
        self.repositories[name] = fixture
        repo, oid = fixture["repo"], fixture["head"]
        other = 40 if object_format == "sha256" else 64
        abbrev = oid[:12]
        # Sync + prepare must agree on the declared format and exact object.
        snapshot = self.sync_repository(name)
        assert snapshot["repository_id"] == repo["id"]
        assert snapshot["object_format"] == object_format
        prepared = self.prepare(name, oid, object_format)
        self.mirror_expect(f"/ci/{oid}/git/alice/{name}.git/info/refs?service=git-upload-pack",
                           200, token=self.reader)
        for bad in (abbrev, "0" * other, oid.upper()):
            self.prepare(name, bad, object_format, codes=(400, 409))
        self.mirror_expect(f"/ci/{abbrev}/git/alice/{name}.git/info/refs?service=git-upload-pack",
                           (400, 404), token=self.reader)
        # Source pin and immutable plan/receipt with exact 40/64-hex target.
        descriptor, job = self.pin(name, oid)
        assert descriptor["state"] == "pinned"
        assert descriptor["object_format"] == object_format
        assert descriptor["target_oid"] == oid
        for bad in (abbrev, "0" * other, oid.upper()):
            self.pin(name, bad, codes=(400, 422))
        self.pin(name, "f" * (64 if object_format == "sha256" else 40), codes=409)
        body = self.checkout_body(oid, job)
        for bad in (abbrev, "0" * other, oid.upper()):
            self.checkout(name, self.checkout_body(bad, str(uuid.uuid4())), codes=(400, 422))
        result = self.checkout(name, body)
        plan = self.assert_plan(result, repo, oid, object_format, job)
        token = dict(username="alice", token=result["token"])
        self.clone_checkout(name, oid, token, object_format, name)
        # The exact target must still be fetchable from the mirror after the
        # clone, and an abbreviated route must not resolve.
        self.mirror_expect(f"/ci/{oid}/git/alice/{name}.git/info/refs?service=git-upload-pack",
                           200, token=token)
        self.mirror_expect(f"/ci/{abbrev}/git/alice/{name}.git/info/refs?service=git-upload-pack",
                           (400, 404), token=token)
        return dict(object_format=object_format, target_oid=oid, plan=plan,
                    mirror_snapshot=snapshot["snapshot"],
                    clone_object_format=object_format,
                    abbreviated_oid_rejected=True, uppercase_oid_rejected=True,
                    zero_oid_wrong_width_rejected=True)

    def setup_matrix(self):
        self.setup()
        self.repositories = {}
        self.start_mirror()
        self.mirror_expect("/health/live", 200)
        return dict(primary_and_mirror_started=True, audience=str(self.audience))

    def sha256_full_flow(self):
        return self.full_matrix("sha256", "sha256")

    def sha1_regression(self):
        return self.full_matrix("legacy", "sha1")

    def mixed_format_rejections(self):
        sha256 = self.repositories["sha256"]
        legacy = self.repositories["legacy"]
        # A valid SHA-1 OID from the other repository is rejected by the SHA-256
        # surfaces, and the reverse, without an object lookup or length guess.
        for name, oid in (("sha256", legacy["head"]), ("legacy", sha256["head"])):
            self.pin(name, oid, codes=(400, 422))
            self.prepare(name, oid, "sha256" if name == "sha256" else "sha1",
                         codes=(400, 409))
            self.checkout(name, self.checkout_body(oid, str(uuid.uuid4())), codes=(400, 422))
        # Git itself cannot fetch a 64-hex SHA-256 object from a SHA-1 mirror.
        status = self.git("fetch", self.mirror_base + f"/ci/{sha256['head']}/git/alice/legacy.git",
                          sha256["head"], token=self.reader, check=False)
        assert status.returncode != 0
        return dict(cross_format_oid_rejected=True, cross_format_fetch_rejected=True)

    def policy_and_storage_bounds(self):
        name = "sha256"
        repo, oid = self.repositories[name]["repo"], self.repositories[name]["head"]
        # Descriptor and local intent are durable exactly-once facts; a wrong
        # format is refused before any native object lookup.
        intent = self.root / "data" / "ci-pins" / repo["id"]
        intents = [path for path in intent.glob("*.json") if not path.name.endswith(".pinned.json")]
        assert len(intents) == 1 and len(json.loads(intents[0].read_text())["target_oid"]) == 64
        snapshot = self.sync_repository(name)
        generation = int(self.sql(
            "SELECT storage_generation FROM repositories WHERE id='" + repo["id"] + "'"))
        self.prepare(name, oid, "sha256", codes=(400, 409), generation=generation + 1)
        return dict(single_durable_intent=True, snapshot=snapshot["snapshot"],
                    wrong_generation_rejected=True)


    def sql_rejected(self, statement):
        result = self.run(["psql", "--dbname", self.db, "-X", "-v",
                           "ON_ERROR_STOP=1", "-At", "-c", statement], check=False)
        return result.returncode != 0

    def plan_constraint_shapes(self):
        repo = self.repositories["sha256"]["repo"]
        owner = self.sql("SELECT id FROM users WHERE username='alice'")
        token = self.sql("SELECT id FROM tokens WHERE user_id='" + owner + "' ORDER BY created_at LIMIT 1")
        expires = int(time.time()) + 600
        dependencies = dict(version=1, history="full", tags=[], lfs=[], submodules=[])

        def plan(object_format, target, receipt="b" * 64):
            return dict(version=1, owner_id=owner, repository_id=repo["id"],
                        storage_generation=1, object_format=object_format,
                        target_oid=target, source_receipt_sha256=receipt,
                        mirror_audience=self.audience, expires_unix=expires,
                        dependencies=dependencies)

        def insert(value, cancelled=False):
            job = str(uuid.uuid4())
            plan = dict(value, job_id=job)
            body = json.dumps(plan, separators=(",", ":"))
            return ("INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,plan,"
                    "issuer_token_id,credential_digest,expires_unix,cancelled) VALUES "
                    f"('{repo['id']}','{job}','{owner}',$plan${body}$plan$::jsonb,"
                    f"'{token}',decode('{uuid.uuid4().hex * 2}','hex'),{expires},{str(cancelled).lower()})")

        assert not self.sql_rejected(insert(plan("sha256", "a" * 64)))
        assert not self.sql_rejected(insert(plan("sha1", "c" * 40)))
        for bad in (plan("sha1", "d" * 64), plan("sha256", "e" * 40),
                    plan("sha256", "F" * 64), plan("sha256", "0" * 64),
                    plan("sha256", "a" * 64, receipt="b" * 63)):
            assert self.sql_rejected(insert(bad)), bad
        null_plan = ("INSERT INTO ci_checkout_jobs(repository_id,job_id,owner_id,plan,"
                     "issuer_token_id,credential_digest,expires_unix) VALUES "
                     f"('{repo['id']}','{uuid.uuid4()}','{owner}',NULL,'{token}',"
                     f"decode('{uuid.uuid4().hex * 2}','hex'),{expires})")
        assert self.sql_rejected(null_plan)
        return dict(valid_sha1_and_sha256_shapes_accepted=True,
                    mismatched_format_width_rejected=True,
                    uppercase_zero_and_bad_receipt_rejected=True,
                    null_plan_without_cancellation_rejected=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    harness = Sha256MatrixHarness(args)
    success = False
    try:
        for name, fn in (("setup_matrix", harness.setup_matrix),
                         ("sha256_full_flow", harness.sha256_full_flow),
                         ("sha1_regression", harness.sha1_regression),
                         ("mixed_format_rejections", harness.mixed_format_rejections),
                         ("policy_and_storage_bounds", harness.policy_and_storage_bounds),
                         ("plan_constraint_shapes", harness.plan_constraint_shapes)):
            harness.case(name, fn)
        success = True
    except Exception as error:
        print(harness.redact(error), file=sys.stderr)
    finally:
        try:
            harness.cleanup()
        except Exception as error:
            harness.results.append(dict(name="cleanup", status="failed",
                                        error=harness.redact(error)))
            success = False
        report = dict(passed=success, cases=harness.results,
                      binary_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      limitations=[
                          "Synthetic loopback processes and isolated schema, not a production scaling benchmark.",
                          "SHA-1 regression and SHA-256 flow use the same stock Git 2.52 binary.",
                          "Cross-format rejection is exercised through service APIs and one native fetch, not every Git transport.",
                      ])
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
