#!/usr/bin/env python3
"""Owned PostgreSQL fault drill: SQLSTATE 23503 and a real statement_timeout 57014.

Requires ROOTYARD_TEST_DATABASE_URL. Both faults are synthetic triggers created
only on repositories rows with a random repository name owned by this harness.
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


def read_log(path, request_id, timeout=8.0):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            text = path.read_text(errors="replace")
            for line in text.splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict) and event.get("request_id") == request_id:
                    return text
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    raise AssertionError("correlated error event was not written within the bounded wait")


def redact_error(h, error, sentinel):
    return h.redact(error).replace(sentinel, "[REDACTED]")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    if not binary.is_file():
        parser.error("binary not found: " + str(binary))
    args.binary = str(binary)
    harness_args = argparse.Namespace(binary=args.binary, keep=args.keep)

    tag = uuid.uuid4().hex
    repo_name = "fk-fault-" + tag
    good_name = "fk-good-" + tag
    fn_name = "fk_fault_fn_" + tag
    trigger_name = "fk_fault_trg_" + tag
    timeout_name = "db-timeout-" + tag
    timeout_fn = "db_timeout_fn_" + tag
    timeout_trigger = "db_timeout_trg_" + tag
    timeout_query = "private-timeout-query-" + tag
    hostile = str(uuid.uuid4())
    hostile_timeout = str(uuid.uuid4())
    hostile_read = str(uuid.uuid4())
    raw_query = "private-query-" + tag
    # Hostile value lives only in the owned trigger message. It contains a fake
    # credential, fake DB URL query and header text; none may reach the log.
    sentinel = ("sentinel-" + tag + "-postgres://fakeuser:fakepass-" + tag
                + "@127.0.0.1:1/fakedb?sslmode=disable&token=FAKE-TOKEN-" + tag
                + " Authorization: Bearer fake-credential-" + tag + " X-Api-Key: fake-api-key-" + tag
                + " ROOTYARD_TEST_DATABASE_URL=fake-dsn-" + tag)
    cases = []
    passed = False
    trigger_installed = False
    h = None

    def record(name, detail="ok"):
        cases.append({"name": name, "status": "passed", "detail": detail})

    def install():
        h.sql(
            'CREATE FUNCTION "' + fn_name + '"() RETURNS trigger LANGUAGE plpgsql AS $fn$ '
            "BEGIN RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = '" + sentinel + "'; END $fn$;"
        )
        h.sql(
            'CREATE TRIGGER "' + trigger_name + '" BEFORE INSERT ON repositories '
            "FOR EACH ROW WHEN (NEW.name = '" + repo_name + "') EXECUTE FUNCTION \"" + fn_name + '"();'
        )
        # A separate synthetic repository name performs a real six-second sleep
        # inside the trigger. The server pool's statement_timeout=5000 cancels
        # the statement, so PostgreSQL itself reports 57014. This is not a
        # forged RAISE of that SQLSTATE.
        h.sql(
            'CREATE FUNCTION "' + timeout_fn + '"() RETURNS trigger LANGUAGE plpgsql AS $fn$ '
            "BEGIN PERFORM pg_sleep(6); RETURN NEW; END $fn$;"
        )
        h.sql(
            'CREATE TRIGGER "' + timeout_trigger + '" BEFORE INSERT ON repositories '
            "FOR EACH ROW WHEN (NEW.name = '" + timeout_name + "') EXECUTE FUNCTION \"" + timeout_fn + '"();'
        )

    def remove():
        nonlocal trigger_installed
        if not trigger_installed:
            return
        h.sql('DROP TRIGGER IF EXISTS "' + timeout_trigger + '" ON repositories')
        h.sql('DROP FUNCTION IF EXISTS "' + timeout_fn + '"()')
        h.sql('DROP TRIGGER IF EXISTS "' + trigger_name + '" ON repositories')
        h.sql('DROP FUNCTION IF EXISTS "' + fn_name + '"()')
        trigger_installed = False

    try:
        h = e2e.Harness(harness_args)
        h.setup()
        h.api()
        h.roundtrip()
        record("harness_setup_api_roundtrip")
        install()
        trigger_installed = True
        record("owned_sqlstate_23503_trigger_installed", "sqlstate=23503")
        status, body, headers = h.http(
            "/api/repos?probe=" + raw_query, method="POST", token=h.alice,
            body={"name": repo_name}, extra_headers={"X-Request-ID": hostile},
        )
        request_id = valid_uuid(header(headers, "x-request-id"))
        assert status == 503, "FK fault must map to 503, got " + str(status)
        assert request_id != hostile, "client X-Request-ID was not ignored"
        assert header(headers, "cache-control") == "no-store", "fault response must be no-store"
        assert json.loads(body) == {"error": "service temporarily unavailable"}, "fault body is not the fixed generic error"
        for value in (sentinel, h.alice["token"], hostile):
            assert value.encode() not in body, "fault body leaked sensitive material"
        record("fk_fault_http_503_generic_no_store_server_uuid")
        log_path = h.root / "server.log"
        log_text = read_log(log_path, request_id)
        events = []
        for line in log_text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "rootyard_error":
                events.append(event)
        matched = [e for e in events if e.get("request_id") == request_id]
        assert len(matched) == 1, "expected exactly one correlated error event, got " + str(len(matched))
        event = matched[0]
        assert event.get("scope") == "request", "event scope is not request"
        assert event.get("kind") == "database", "event kind is not static database"
        assert event.get("sqlstate") == "23503", "event sqlstate is not 23503"
        assert event.get("route") == "/api/repos", "event route is not the static matched path"
        assert event.get("status") == 503, "event status is not 503"
        assert valid_uuid(event.get("event_id")) != request_id, "event_id must be a distinct UUID"
        assert request_id in log_text, "server UUID absent from retained log"
        record("json_error_event_correlated", "kind=database,sqlstate=23503,route=/api/repos")
        leak_checks = [("trigger sentinel", sentinel), ("client request id", hostile),
                       ("raw request query", raw_query),
                       ("env name", "ROOTYARD_TEST_DATABASE_URL"),
                       ("fake query token", "FAKE-TOKEN-" + tag),
                       ("fake header", "X-Api-Key: fake-api-key-" + tag)]
        leak_checks += [("account secret", secret) for secret in h.secrets]
        leak_checks += [("base database url", h.base_db), ("schema database url", h.db)]
        for label, value in leak_checks:
            assert value not in log_text, "application log leaked " + label
        for event in events:
            dumped = json.dumps(event)
            assert sentinel not in dumped and h.alice["token"] not in dumped, "error event leaked sensitive material"
        record("log_privacy_no_secret_or_raw_request_content", "checked fixed categories only")
        # Real database timeout: the trigger sleeps, so elapsed time proves the
        # server-side statement_timeout cancelled an executing statement.
        timeout_started = time.monotonic()
        status, body, headers = h.http(
            "/api/repos?probe=" + timeout_query, method="POST", token=h.alice,
            body={"name": timeout_name}, extra_headers={"X-Request-ID": hostile_timeout},
        )
        timeout_elapsed = time.monotonic() - timeout_started
        timeout_request_id = valid_uuid(header(headers, "x-request-id"))
        assert status == 503, "database timeout must map to 503, got " + str(status)
        assert timeout_elapsed >= 4.5, (
            "database timeout returned before the pool statement_timeout could cancel the sleep: "
            + str(round(timeout_elapsed, 2)) + "s")
        assert timeout_elapsed < 15, "database timeout exceeded the bounded window"
        assert timeout_request_id != hostile_timeout, "timeout response reused the client X-Request-ID"
        assert header(headers, "cache-control") == "no-store", "timeout response must be no-store"
        assert json.loads(body) == {"error": "service temporarily unavailable"}, (
            "timeout body is not the fixed generic error")
        for value in (h.alice["token"], hostile_timeout, timeout_query):
            assert value.encode() not in body, "timeout body leaked sensitive material"
        record("database_statement_timeout_57014_http_503_generic_no_store",
               "elapsed=%.2fs,sqlstate=57014" % timeout_elapsed)
        timeout_log = read_log(log_path, timeout_request_id)
        timeout_events = []
        for line in timeout_log.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "rootyard_error":
                timeout_events.append(event)
        timeout_matched = [e for e in timeout_events if e.get("request_id") == timeout_request_id]
        assert len(timeout_matched) == 1, (
            "expected exactly one correlated timeout event, got " + str(len(timeout_matched)))
        timeout_event = timeout_matched[0]
        assert timeout_event.get("scope") == "request", "timeout event scope is not request"
        assert timeout_event.get("kind") == "database", "timeout event kind is not static database"
        assert timeout_event.get("sqlstate") == "57014", "timeout event sqlstate is not 57014"
        assert timeout_event.get("route") == "/api/repos", "timeout event route is not the matched path"
        assert timeout_event.get("status") == 503, "timeout event status is not 503"
        assert valid_uuid(timeout_event.get("event_id")) != timeout_request_id, (
            "timeout event_id must be a distinct UUID")
        record("database_timeout_event_correlated", "kind=database,sqlstate=57014,route=/api/repos")
        timeout_leaks = [("client timeout request id", hostile_timeout),
                         ("timeout raw request query", timeout_query),
                         ("fake timeout query token", "private-timeout-query-" + tag)]
        timeout_leaks += [("account secret", secret) for secret in h.secrets]
        timeout_leaks += [("base database url", h.base_db), ("schema database url", h.db)]
        for label, value in timeout_leaks:
            assert value not in timeout_log, "application log leaked " + label
        for event in timeout_events:
            dumped = json.dumps(event)
            assert sentinel not in dumped and h.alice["token"] not in dumped, (
                "timeout error event leaked sensitive material")
        record("database_timeout_log_privacy", "checked fixed categories only")
        remove()
        record("owned_trigger_function_removed_before_good_request")
        status, body, headers = h.http(
            "/api/repos", method="POST", token=h.alice,
            body={"name": good_name}, extra_headers={"X-Request-ID": hostile},
        )
        assert status == 201, "valid request after cleanup must be 201, got " + str(status)
        repo = json.loads(body)
        valid_uuid(repo.get("id"))
        request_id = valid_uuid(header(headers, "x-request-id"))
        assert request_id != hostile, "client X-Request-ID was not ignored on success"
        assert header(headers, "cache-control") == "no-store", "success response lost no-store"
        record("valid_request_after_cleanup_201")
        status, body, headers = h.http(
            "/api/repos", token={"token": "invalid-" + tag},
            extra_headers={"X-Request-ID": hostile_read},
        )
        request_id = valid_uuid(header(headers, "x-request-id"))
        assert status == 401, "authenticated-read failure must stay 401, got " + str(status)
        assert request_id != hostile_read, "401 used the client X-Request-ID"
        assert header(headers, "www-authenticate") is not None, "401 lost its auth challenge"
        record("authenticated_read_401_own_uuid")
        passed = True
    except Exception as error:
        cases.append({"name": "failure", "status": "failed", "error": redact_error(h, error, sentinel) if h else "harness not initialized"})
    finally:
        if h is not None:
            try:
                remove()
            except Exception as error:
                cases.append({"name": "trigger_cleanup", "status": "failed", "error": redact_error(h, error, sentinel)})
                passed = False
            try:
                h.cleanup()
            except Exception as error:
                cases.append({"name": "harness_cleanup", "status": "failed", "error": redact_error(h, error, sentinel)})
                passed = False
    receipt = None
    for candidate in (binary.with_suffix(".build.json"), binary.with_suffix(".receipt.json")):
        if candidate.is_file():
            receipt = {"path": str(candidate), "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest()}
            break
    try:
        harness_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1],
                                      capture_output=True, text=True, timeout=10).stdout.strip() or None
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
            "One owned synthetic SQLSTATE 23503 trigger and one owned pg_sleep(6) trigger cancelled by statement_timeout=5000; not a forged application principal or a real user data fault.",
            "The remote-outage typed event is covered separately by tests/lfs_hydration_concurrency.py against owned Garage; this script does not certify it.",
            "Worker backlog, capture freshness and remote repair metrics are verified separately; this script covers request errors.",
            "Acceptance is limited to the cases executed by this invocation and the attested executable named by its binary hash and compiled receipt.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
