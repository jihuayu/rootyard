#!/usr/bin/env python3
"""Native stock-Git acceptance for GitFS -> Pando -> GitFS operation sequence continuity.

Requires a built binary containing `pando-transition`, the shared Harness,
PostgreSQL, a real S3-compatible object store and Vault Transit. The test uses
only HTTP stock Git, the shipped offline CLI and the isolated Harness schema.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e import Harness

REQUIRED_ENV = (
    "ROOTYARD_TEST_DATABASE_URL",
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_KMS_VAULT_URL",
    "ROOTYARD_KMS_VAULT_TOKEN",
    "ROOTYARD_KMS_VAULT_KEY",
)


def require_pando_environment():
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "Pando transition service test requires real Garage/Vault configuration; missing: "
            + ", ".join(missing)
        )


def oid_length(object_format):
    return 64 if object_format == "sha256" else 40


def create_repo(h, name, object_format):
    code, raw, _ = h.http(
        "/api/repos", token=h.alice, method="POST",
        body={"name": name, "object_format": object_format},
    )
    assert code == 201, (code, raw[:400])
    repo = json.loads(raw)
    assert repo["object_format"] == object_format
    remote = h.base + repo["clone_path"]
    work = h.root / (object_format + "-" + name)
    h.git("init", "--object-format=" + object_format, "--initial-branch=main", str(work))
    h.git("config", "user.name", "Pando Sequence", cwd=work)
    h.git("config", "user.email", "pando-sequence@example.invalid", cwd=work)
    h.git("remote", "add", "origin", remote, cwd=work)
    return repo, remote, work


def commit(h, work, filename, text):
    (work / filename).write_text(text)
    h.git("add", filename, cwd=work)
    h.git("commit", "-m", text, cwd=work)
    oid = h.git("rev-parse", "HEAD", cwd=work).stdout.decode().strip()
    assert len(oid) == oid_length(h.git("rev-parse", "--show-object-format", cwd=work).stdout.decode().strip())
    return oid


def push(h, work):
    h.git("push", "origin", "HEAD:refs/heads/main", cwd=work, token=h.alice)


def sequences(h, repo):
    raw = h.sql(
        "SELECT count(*),count(DISTINCT sequence),COALESCE(min(sequence),0),"
        "COALESCE(max(sequence),0) FROM git_operations WHERE repository_id='"
        + repo["id"] + "'"
    )
    return tuple(int(value) for value in raw.split("|"))


def cli_json(h, *args):
    return json.loads(h.cli(*args))


def clone_verify(h, remote, oid, object_format, label):
    clone = h.root / ("clone-" + label)
    h.git("clone", remote, str(clone), token=h.alice)
    assert h.git("rev-parse", "HEAD", cwd=clone).stdout.decode().strip() == oid
    actual_format = h.git("rev-parse", "--show-object-format", cwd=clone).stdout.decode().strip()
    assert actual_format == object_format, (actual_format, object_format)
    refs = h.git("ls-remote", remote, "refs/heads/main", token=h.alice).stdout.decode()
    assert refs.startswith(oid + "\trefs/heads/main"), refs
    h.git("fsck", "--full", cwd=clone)
    return {"head": oid, "object_format": actual_format, "refs": refs.strip()}


def transition_flow(h, object_format):
    repo, remote, work = create_repo(h, "pando-seq-" + object_format, object_format)
    first = commit(h, work, "one.txt", "gitfs first " + object_format)
    push(h, work)
    assert sequences(h, repo) == (1, 1, 1, 1), sequences(h, repo)

    # A live server owns the data volume. The offline command must refuse before
    # it can mutate any transition state.
    blocked = h.run(
        [h.args.binary, "pando-transition", "cutover", "--repository", repo["id"]],
        check=False,
    )
    assert blocked.returncode != 0, "cutover ran beside a live volume writer"
    assert b"data volume is in use" in blocked.stderr, blocked.stderr[-800:]

    h.stop()
    status = cli_json(h, "pando-transition", "status", "--repository", repo["id"])
    assert status["storage_backend"] == "gitfs" and status["transition_state"] == "stable", status
    report = cli_json(h, "pando-transition", "cutover", "--repository", repo["id"])
    assert report["direction"] == "gitfs_to_pando", report
    status = cli_json(h, "pando-transition", "status", "--repository", repo["id"])
    assert status["storage_backend"] == "pando" and status["transition_state"] == "stable", status
    assert status["transition_epoch"] == report["transition_epoch"], (status, report)

    h.start()
    second = commit(h, work, "two.txt", "pando second " + object_format)
    push(h, work)
    assert sequences(h, repo) == (2, 2, 1, 2), sequences(h, repo)
    pando_clone = clone_verify(h, remote, second, object_format, object_format + "-pando")

    h.stop()
    status = cli_json(h, "pando-transition", "status", "--repository", repo["id"])
    assert status["storage_backend"] == "pando" and status["transition_state"] == "stable", status
    report = cli_json(h, "pando-transition", "rollback", "--repository", repo["id"])
    assert report["direction"] == "pando_to_gitfs", report
    status = cli_json(h, "pando-transition", "status", "--repository", repo["id"])
    assert status["storage_backend"] == "gitfs" and status["transition_state"] == "stable", status

    h.start()
    third = commit(h, work, "three.txt", "gitfs third " + object_format)
    push(h, work)
    assert sequences(h, repo) == (3, 3, 1, 3), sequences(h, repo)
    gitfs_clone = clone_verify(h, remote, third, object_format, object_format + "-gitfs")
    row = h.sql(
        "SELECT storage_backend || ':' || transition_state || ':' || backend_transition_epoch "
        "FROM repositories WHERE id='" + repo["id"] + "'"
    )
    assert row == "gitfs:stable:2", row
    return {
        "repository_id": repo["id"],
        "object_format": object_format,
        "first_oid": first,
        "second_oid": second,
        "third_oid": third,
        "git_operations": sequences(h, repo),
        "pando_clone": pando_clone,
        "gitfs_clone": gitfs_clone,
        "final_state": row,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/rootyard")
    parser.add_argument("--report", type=Path, help="Write machine-readable JSON report")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    args.binary = str(Path(args.binary).resolve())
    try:
        require_pando_environment()
        if not os.access(args.binary, os.X_OK):
            raise RuntimeError("binary is not executable: " + args.binary)
    except RuntimeError as error:
        parser.error(str(error))

    h = Harness(args)
    passed = False
    try:
        h.case("setup", h.setup)
        for object_format in ("sha1", "sha256"):
            h.case("sequence_continuity_" + object_format,
                   lambda fmt=object_format: transition_flow(h, fmt))
        passed = True
    except Exception as error:
        args.keep = True
        log = h.root / "server.log"
        if log.exists():
            print("retained server log: " + str(log), file=sys.stderr)
            print(h.redact(log.read_text(errors="replace")[-8000:]), file=sys.stderr)
        print(h.redact(error), file=sys.stderr)
    finally:
        h.cleanup()
    report = {
        "passed": passed,
        "cases": h.results,
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "required_environment": list(REQUIRED_ENV),
        "limitations": [
            "Small loopback fixture; not a performance or HA result.",
            "Both sha1 and sha256 run only when the shared Git and test services support them.",
        ],
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
