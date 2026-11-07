#!/usr/bin/env python3
"""Native worker-operation diagnostics drill against an owned PostgreSQL schema.

The real service runs with the durable storage-maintenance worker enabled. A
synthetic trigger on `storage_maintenance_repo_state` makes the scheduler's own
INSERT execute `pg_sleep(6)`; the owned pool's `statement_timeout=5000` cancels
that executing statement inside PostgreSQL (SQLSTATE 57014). The worker then
emits its real structured event, not a mocked Rust error, with a worker scope
and a server-generated operation UUID.

A second synthetic trigger raises SQLSTATE 23503 for one repository name so a
real request-scope event can be compared with the worker event. The drill
asserts that request and worker correlation never cross, and that trigger
messages, tokens, URLs, query strings and headers never reach the log.

Requires ROOTYARD_TEST_DATABASE_URL and the normal e2e tools.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import e2e  # noqa: E402  (narrow reuse of Harness setup/http/sql/cleanup)


def header(headers, wanted):
    for name, value in headers.items():
        if name.lower() == wanted:
            return value
    return None


def valid_uuid(value):
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError):
        raise AssertionError("expected a valid UUID, found malformed value")


def events_in(path):
    try:
        text = path.read_text(errors="replace")
    except FileNotFoundError:
        return []
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("event") == "rootyard_error":
            found.append(event)
    return found


def wait_events(path, predicate, timeout=30.0):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        matched = [event for event in events_in(path) if predicate(event)]
        if matched:
            return matched
        time.sleep(0.1)
    raise AssertionError("expected structured worker event was not written within the bounded wait")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    if not binary.is_file():
        parser.error("binary not found: " + str(binary))

    tag = uuid.uuid4().hex
    fault_name = "worker-fk-fault-" + tag
    good_name = "worker-fk-good-" + tag
    fn_name = "worker_fault_fn_" + tag
    trigger_name = "worker_fault_trg_" + tag
    sleep_fn = "worker_sleep_fn_" + tag
    sleep_trigger = "worker_sleep_trg_" + tag
    raw_query = "private-worker-query-" + tag
    hostile_request_id = str(uuid.uuid4())
    sentinel = ("sentinel-" + tag + "-postgres://fakeuser:fakepass-" + tag
                + "@127.0.0.1:1/fakedb?sslmode=disable&token=FAKE-TOKEN-" + tag
                + " Authorization: Bearer fake-credential-" + tag
                + " X-Api-Key: fake-api-key-" + tag)
    cases = []
    passed = False
    h = None

    def record(name, detail="ok"):
        cases.append({"name": name, "status": "passed", "detail": detail})

    def install_worker_timeout(repo_id):
        h.sql(
            'CREATE FUNCTION "' + sleep_fn + '"() RETURNS trigger LANGUAGE plpgsql AS $fn$ '
            "BEGIN PERFORM pg_sleep(6); RETURN NEW; END $fn$;"
        )
        h.sql(
            'CREATE TRIGGER "' + sleep_trigger + '" BEFORE INSERT OR UPDATE ON storage_maintenance_repo_state '
            "FOR EACH ROW WHEN (NEW.repository_id = '" + repo_id + "'::uuid) "
            'EXECUTE FUNCTION "' + sleep_fn + '"();'
        )

    def remove_worker_timeout():
        h.sql('DROP TRIGGER IF EXISTS "' + sleep_trigger + '" ON storage_maintenance_repo_state')
        h.sql('DROP FUNCTION IF EXISTS "' + sleep_fn + '"()')

    def install_request_fault():
        h.sql(
            'CREATE FUNCTION "' + fn_name + '"() RETURNS trigger LANGUAGE plpgsql AS $fn$ '
            "BEGIN RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = '" + sentinel + "'; END $fn$;"
        )
        h.sql(
            'CREATE TRIGGER "' + trigger_name + '" BEFORE INSERT ON repositories '
            "FOR EACH ROW WHEN (NEW.name = '" + fault_name + "') "
            'EXECUTE FUNCTION "' + fn_name + '"();'
        )

    def remove_request_fault():
        h.sql('DROP TRIGGER IF EXISTS "' + trigger_name + '" ON repositories')
        h.sql('DROP FUNCTION IF EXISTS "' + fn_name + '"()')

    try:
        h = e2e.Harness(argparse.Namespace(binary=str(binary), keep=args.keep))
        # Real worker loop; short poll/scan intervals keep the drill bounded.
        h.env.update(
            ROOTYARD_STORAGE_MAINTENANCE="true",
            ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS="1",
            ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS="1",
            ROOTYARD_OUTBOX_WORKER="false",
        )
        h.setup()
        h.api()
        record("harness_setup_api_roundtrip")
        repo_id = h.repo["id"]
        valid_uuid(repo_id)

        install_worker_timeout(repo_id)
        record("owned_worker_timeout_trigger_installed", "sqlstate=57014 expected from statement_timeout")
        log_path = h.root / "server.log"
        worker_events = wait_events(
            log_path,
            lambda event: event.get("scope") == "worker"
            and event.get("worker") == "storage_lifecycle"
            and event.get("sqlstate") == "57014",
        )
        worker = worker_events[0]
        operation_id = valid_uuid(worker.get("operation_id"))
        assert worker.get("phase") == "scan", "worker phase is not the fixed scan phase: " + repr(worker.get("phase"))
        assert worker.get("kind") == "database", "worker kind is not static database"
        assert worker.get("status") == 503, "worker event status is not 503"
        assert worker.get("event_id") != operation_id, "operation_id must be distinct from event_id"
        assert "request_id" not in worker, "worker event inherited an HTTP request id"
        assert "route" not in worker, "worker event inherited an HTTP route"
        for raw in ("actor_id", "repository_id", "tenant_id", "job_id", "token", "scope_token",
                    "endpoint", "url", "contents"):
            assert raw not in worker, "worker event leaked raw field " + raw
        record("native_worker_database_timeout_correlated",
               "worker=storage_lifecycle,phase=scan,sqlstate=57014,operation_id=uuid")

        remove_worker_timeout()
        record("owned_worker_timeout_trigger_removed")

        install_request_fault()
        record("owned_request_sqlstate_23503_trigger_installed", "sqlstate=23503")
        status, body, headers = h.http(
            "/api/repos?probe=" + raw_query, method="POST", token=h.alice,
            body={"name": fault_name}, extra_headers={"X-Request-ID": hostile_request_id},
        )
        request_id = valid_uuid(header(headers, "x-request-id"))
        assert status == 503, "request fault must map to 503, got " + str(status)
        assert request_id != hostile_request_id, "client X-Request-ID was not ignored"
        assert header(headers, "cache-control") == "no-store", "fault response lost no-store"
        assert json.loads(body) == {"error": "service temporarily unavailable"}, "fault body is not fixed generic"
        for value in (sentinel, h.alice["token"], hostile_request_id, raw_query):
            assert value.encode() not in body, "fault response leaked sensitive material"
        request_events = wait_events(log_path, lambda event: event.get("request_id") == request_id)
        request_events = [event for event in request_events if event.get("request_id") == request_id]
        assert len(request_events) == 1, "expected exactly one request-scope event, got " + str(len(request_events))
        request_event = request_events[0]
        assert request_event.get("scope") == "request", "request event scope is not request"
        assert request_event.get("kind") == "database", "request event kind is not database"
        assert request_event.get("sqlstate") == "23503", "request event sqlstate is not 23503"
        assert request_event.get("route") == "/api/repos", "request event route is not the matched pattern"
        assert "operation_id" not in request_event, "request event was attributed to a worker operation"
        assert "worker" not in request_event and "phase" not in request_event, "request event contains worker labels"
        assert request_id != operation_id, "worker operation id reused the HTTP request id"
        record("http_request_and_worker_scope_stay_isolated",
               "request scope has no operation_id; worker scope has no request_id/route")

        leak_checks = [("trigger sentinel", sentinel), ("token", h.alice["token"]),
                       ("client request id", hostile_request_id), ("raw request query", raw_query),
                       ("fake query token", "FAKE-TOKEN-" + tag), ("fake header", "X-Api-Key: fake-api-key-" + tag)]
        leak_checks += [("account secret", secret) for secret in h.secrets]
        leak_checks += [("base database url", h.base_db), ("schema database url", h.db)]
        log_text = log_path.read_text(errors="replace")
        for label, value in leak_checks:
            assert value not in log_text, "application log leaked " + label
        for event in events_in(log_path):
            dumped = json.dumps(event)
            assert sentinel not in dumped and h.alice["token"] not in dumped, "event leaked sensitive material"
            if event.get("scope") == "worker":
                for raw in ("actor_id", "repository_id", "tenant_id", "job_id", "contents"):
                    assert raw not in event, "worker event leaked raw field " + raw
        record("log_privacy_fixed_categories_only", "no trigger text, token, URL, query or header")

        remove_request_fault()
        record("owned_request_fault_trigger_removed")
        status, body, _ = h.http("/api/repos", method="POST", token=h.alice, body={"name": good_name})
        assert status == 201, "valid request after trigger cleanup must be 201, got " + str(status)
        valid_uuid(json.loads(body).get("id"))
        record("valid_request_after_cleanup_201")
        passed = True
    except Exception as error:
        cases.append({"name": "failure", "status": "failed",
                      "error": h.redact(error) if h is not None else "harness not initialized"})
    finally:
        if h is not None:
            for label, cleanup in (("worker_trigger_cleanup", remove_worker_timeout),
                                   ("request_trigger_cleanup", remove_request_fault)):
                try:
                    cleanup()
                except Exception as error:
                    cases.append({"name": label, "status": "failed", "error": h.redact(error)})
                    passed = False
            try:
                h.cleanup()
            except Exception as error:
                cases.append({"name": "harness_cleanup", "status": "failed", "error": h.redact(error)})
                passed = False

    receipt = None
    for candidate in (binary.with_suffix(".build.json"), binary.with_suffix(".receipt.json")):
        if candidate.is_file():
            receipt = {"path": str(candidate), "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest()}
            break
    try:
        harness_head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        harness_head = None
    report = {
        "passed": passed,
        "cases": cases,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest() if binary.is_file() else None,
        "compiled_receipt": receipt,
        "harness_git_head": harness_head,
        "harness_e2e_sha256": hashlib.sha256(Path(e2e.__file__).read_bytes()).hexdigest(),
        "head_label": "harness_git_head is repository HEAD at harness time, not independent build provenance",
        "limitations": [
            "Native worker failure coverage is the storage_lifecycle scheduler's real PostgreSQL "
            "statement_timeout 57014. The synthetic trigger only induces the fault; the Rust error, "
            "classification and scope are not mocked.",
            "No native fault was injected into webhooks background, workspace capture, workspace "
            "remote GC or durable dispatch in this drill; their scope wrapping is covered by unit "
            "tests only and is not claimed as native acceptance.",
            "Worker attempt/generation correlation is unit-tested with persisted numeric values; "
            "this drill's scheduler timeout occurs before a job claim, so its event intentionally "
            "has no attempt or generation.",
            "Session GC, sharding controller/reconciliation, journal/provisioning recovery, "
            "metrics workers, backup and the advisory publisher remain outside worker operation scope.",
            "Acceptance is limited to the cases executed by this invocation and the attested "
            "executable named by its binary hash and compiled receipt.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
