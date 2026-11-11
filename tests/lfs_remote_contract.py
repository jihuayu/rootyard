"""Native remote-outage contract for distributed Git LFS objects.

Imported by ``tests/lfs.py`` without S3 dependencies; boto3/botocore are only
imported lazily inside the opt-in native helpers. Safe report values are
booleans, deltas and counts only: endpoints, credentials, bucket, object keys,
tenant identifiers and OIDs are never printed, returned or embedded in fixed
failure text.
"""

import hashlib
import http.server
import os
import pathlib
import shutil
import socket
import tempfile
import threading
import time
import urllib.request

UNREACHABLE_ENDPOINT = "http://127.0.0.1:1"
OBJECT_STORE_VARS = (
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
)
FAILURES = "rootyard_lfs_remote_failures_total"
BACKLOG = "rootyard_lfs_remote_repair_backlog"
FAILURE_CODES = (500, 503)
FILE_SUFFIX = ".lfs71"
REPAIR_DEADLINE = 10.0
DELAY_SECONDS = 0.8


def _fail(message):
    return AssertionError(message)


def configure_metrics_listener(harness):
    """Reserve a free loopback port and bind service metrics before startup."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    finally:
        sock.close()
    harness.metrics_port = port
    harness.env["ROOTYARD_METRICS_BIND"] = "127.0.0.1:%d" % port


def _s3_env(source):
    env = {name: source.get(name) for name in OBJECT_STORE_VARS}
    for name in ("ROOTYARD_OBJECT_STORE_ENDPOINT", "ROOTYARD_OBJECT_STORE_BUCKET",
                 "ROOTYARD_OBJECT_STORE_REGION", "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
                 "ROOTYARD_OBJECT_STORE_SECRET_KEY"):
        if not env[name]:
            raise _fail("real object-store configuration is required")
    return env


def _client(env):
    """Independent client pinned to one captured environment snapshot."""
    try:
        import boto3
        from botocore.config import Config
    except Exception:
        raise _fail("boto3/botocore are required for the native LFS remote contract") from None
    kwargs = {
        "endpoint_url": env["ROOTYARD_OBJECT_STORE_ENDPOINT"],
        "region_name": env["ROOTYARD_OBJECT_STORE_REGION"],
        "aws_access_key_id": env["ROOTYARD_OBJECT_STORE_ACCESS_KEY"],
        "aws_secret_access_key": env["ROOTYARD_OBJECT_STORE_SECRET_KEY"],
        "config": Config(s3={"addressing_style": "path"}, retries={"max_attempts": 3}),
    }
    if env.get("ROOTYARD_OBJECT_STORE_SESSION_TOKEN"):
        kwargs["aws_session_token"] = env["ROOTYARD_OBJECT_STORE_SESSION_TOKEN"]
    try:
        return boto3.client("s3", **kwargs)
    except Exception:
        raise _fail("object store client construction failed") from None


def _is_not_found(error):
    try:
        return error.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound")
    except Exception:
        return False


def _get_bytes(client, bucket, key, expected):
    try:
        body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception:
        raise _fail("object store read for the expected key failed") from None
    if body != expected:
        raise _fail("object store stored bytes differ from the payload")


def _head(client, bucket, key):
    """True if the key exists; False only on the expected not-found answer."""
    try:
        client.head_object(Bucket=bucket, Key=key)
    except Exception as error:
        if _is_not_found(error):
            return False
        raise _fail("object store HEAD failed unexpectedly") from None
    return True


def _delete_key(client, bucket, key):
    try:
        client.delete_object(Bucket=bucket, Key=key)
    except Exception:
        raise _fail("object key deletion failed") from None


def _put_key(client, bucket, key, data):
    try:
        client.put_object(Bucket=bucket, Key=key, Body=data)
    except Exception:
        raise _fail("object key restore failed") from None


def _port_listening(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


class _HTTPStatusError(Exception):
    def __init__(self, code, body):
        super().__init__("http status error")
        self.code = code
        self.body = body


class _DelayedHandler(http.server.BaseHTTPRequestHandler):
    """Test-only: sleep on HEAD and answer an empty 503; never logs requests."""

    def do_HEAD(self):
        time.sleep(DELAY_SECONDS)
        try:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            pass

    do_GET = do_HEAD

    def do_PUT(self):
        try:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            pass

    def log_message(self, *args):
        pass


class _DelayedEndpoint:
    """Short-lived local 503 endpoint used only to observe in-flight repair."""

    def __init__(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _DelayedHandler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.server.server_close()
        except Exception:
            pass
        if self.thread.is_alive():
            self.thread.join(timeout=5)


def _scrape(harness):
    url = "http://127.0.0.1:%d/metrics" % harness.metrics_port
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            text = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        if error.code != 503:
            raise _fail("metrics listener returned an unexpected status") from None
        try:
            text = error.read().decode("utf-8", "replace")
        except Exception:
            raise _fail("metrics listener was not reachable") from None
        finally:
            try:
                error.close()
            except Exception:
                pass
    except Exception:
        raise _fail("metrics listener was not reachable") from None
    values = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[0] not in (FAILURES, BACKLOG):
            continue
        if not parts[1].isdigit():
            raise _fail("expected LFS remote metric series is not a plain integer")
        values[parts[0]] = int(parts[1])
    if FAILURES not in values or BACKLOG not in values:
        raise _fail("expected label-free LFS remote metric series are not exported")
    return values[FAILURES], values[BACKLOG]


def _restart(harness, endpoint):
    harness.env["ROOTYARD_OBJECT_STORE_ENDPOINT"] = endpoint
    harness.stop()
    harness.start()


def _server_path(harness, oid):
    return harness.root / "data" / "lfs" / harness.repo["id"] / oid


def _has_exact_bytes(path, data):
    try:
        path = pathlib.Path(path)
        return path.is_file() and not path.is_symlink() and path.read_bytes() == data
    except OSError:
        return False


def _row(harness, oid):
    text = harness.sql(
        "SELECT state, size FROM lfs_objects WHERE repository_id='%s' AND oid='%s'"
        % (harness.repo["id"], oid)
    )
    state, _, size = text.partition("|")
    return state, size


def _owner_identity(harness):
    """Commit identity derived from the fixture owner's real account row."""
    rows = harness.sql("SELECT name, email FROM users WHERE name='alice'")
    if len(rows.splitlines()) != 1:
        raise _fail("unexpected local account rows for the fixture owner")
    name, _, email = rows.partition("|")
    options = ["-c", "user.name=" + name] if name else ["-c", "user.name=LFS71 Native"]
    if email:
        options += ["-c", "user.email=" + email]
    return tuple(options)


def _publish_with_stock_client(harness, payload):
    scratch = tempfile.mkdtemp(prefix="lfs71-src-", dir=str(harness.root))
    try:
        name = "payload" + FILE_SUFFIX
        harness.git("init", "-q", "-b", "main", scratch)
        harness.git("-C", scratch, "config", "user.name", "LFS71 Native", cwd=harness.root)
        harness.git("-C", scratch, "config", "user.email", "lfs71@example.invalid", cwd=harness.root)
        harness.git("-C", scratch, "lfs", "install", "--local", cwd=harness.root)
        harness.git("-C", scratch, "lfs", "track", "*" + FILE_SUFFIX, cwd=harness.root)
        with open(os.path.join(scratch, name), "wb") as handle:
            handle.write(payload)
        branch = "lfs71-" + os.urandom(8).hex()
        harness.git("-C", scratch, "add", ".", cwd=harness.root)
        harness.git("-C", scratch, "commit", "-q", "-m", "lfs71 native contract", cwd=harness.root)
        harness.git("-C", scratch, "push", "-q", harness.remote, "HEAD:refs/heads/" + branch,
                    token=harness.alice, cwd=harness.root)
        return name, branch
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _clone_cold(harness, branch, destination, oid):
    """Independent authenticated clone whose LFS cache is proven cold."""
    clone_env = dict(harness.env)
    clone_env["GIT_LFS_SKIP_SMUDGE"] = "1"
    listening = _port_listening("127.0.0.1", harness.metrics_port)
    harness.git("clone", "--no-checkout", "--branch", branch, harness.remote,
                destination, token=harness.alice, env=clone_env, cwd=harness.root)
    if _port_listening("127.0.0.1", harness.metrics_port) != listening:
        raise _fail("metrics listener changed during cold clone")
    harness.git("-C", destination, "lfs", "install", "--local", cwd=harness.root)
    harness.git("-C", destination, "checkout", "-q", branch,
                env=clone_env, cwd=harness.root)
    cold = os.path.join(destination, ".git", "lfs", "objects",
                        oid[:2], oid[2:4], oid)
    if os.path.exists(cold):
        raise _fail("client clone LFS object cache was not cold after checkout")


def _lfs_pull(harness, clone, check):
    """Explicit pull; the skip-smudge settings used for clones are not inherited."""
    env = {name: value for name, value in harness.env.items()
           if name not in ("GIT_LFS_SKIP_SMUDGE", "GIT_LFS_SKIP_PUSH")}
    return harness.git("-C", clone, "lfs", "pull", token=harness.alice,
                       check=check, env=env, cwd=harness.root)


def _upload(harness, oid, size, data, codes):
    batch = harness.lfs_batch("upload", [{"oid": oid, "size": size}], token=harness.alice)
    objects = batch.get("objects") or []
    if len(objects) != 1:
        raise _fail("LFS batch upload returned an unexpected object count")
    action = (objects[0].get("actions") or {}).get("upload")
    if not action:
        raise _fail("LFS batch upload did not advertise an upload action")
    harness.lfs_put(action["href"], data, token=harness.alice, code=codes)


def _restore_server(harness):
    """Put the original endpoint back on a live restart of only this process."""
    if hasattr(harness, "proc") and harness.proc is not None:
        harness.stop()
    harness.start()


def run_remote_outage_contract(harness):
    """Exercise warm local hits, cold outage failure, hydration and repair."""
    if getattr(harness, "metrics_port", None) is None:
        configure_metrics_listener(harness)
    original = {name: harness.env.get(name) for name in OBJECT_STORE_VARS}
    if original["ROOTYARD_OBJECT_STORE_ENDPOINT"] is None:
        raise _fail("real object-store endpoint is required")
    env = _s3_env(original)
    repo_id = getattr(harness, "repo", None)
    repo_id = repo_id.get("id") if isinstance(repo_id, dict) else None
    if not repo_id:
        raise _fail("LFS fixture repository is not ready")
    bucket = env["ROOTYARD_OBJECT_STORE_BUCKET"]
    client = _client(env)
    report = {"warm_remote_failures_delta": 0}
    created = []
    scratch = tempfile.mkdtemp(prefix="lfs71-", dir=str(harness.root))
    path = None
    key = None
    remote_deleted = False
    delay = None
    try:
        if _port_listening("127.0.0.1", 1):
            raise _fail("unreachable endpoint unexpectedly has a listener")

        # (a) Real stock-client upload; prove row, local bytes and Garage bytes.
        payload = os.urandom(1024 + int.from_bytes(os.urandom(2), "big") % 4096)
        oid = hashlib.sha256(payload).hexdigest()
        size = len(payload)
        name, branch = _publish_with_stock_client(harness, payload)
        created.append(oid)
        state, row_size = _row(harness, oid)
        if state != "ready" or row_size != str(size):
            raise _fail("stock upload did not commit a ready LFS row")
        path = _server_path(harness, oid)
        if not _has_exact_bytes(path, payload):
            raise _fail("server local LFS bytes differ from the payload")
        tenant = harness.sql(
            "SELECT tenant_id FROM lfs_objects WHERE repository_id='%s' AND oid='%s'"
            % (repo_id, oid)
        ).strip()
        if not tenant:
            raise _fail("could not resolve the LFS tenant for the test object")
        key = "tenants/%s/lfs/%s" % (tenant, oid)
        _get_bytes(client, bucket, key, payload)

        # (b) Two independent authenticated clones with cold LFS state.
        clone_a = os.path.join(scratch, "clone-a")
        clone_b = os.path.join(scratch, "clone-b")
        _clone_cold(harness, branch, clone_a, oid)
        _clone_cold(harness, branch, clone_b, oid)

        # (c) Restart against a loopback port with no listener.
        _restart(harness, UNREACHABLE_ENDPOINT)

        # (d) Warm verified local hit while the configured endpoint is dead.
        if not _has_exact_bytes(path, payload):
            raise _fail("server local LFS bytes changed before the warm pull")
        failures_before, _ = _scrape(harness)
        _lfs_pull(harness, clone_a, check=True)
        if not _has_exact_bytes(os.path.join(clone_a, name), payload):
            raise _fail("warm pull working bytes differ from the payload")
        failures_after, backlog_after = _scrape(harness)
        if failures_after != failures_before or backlog_after != 0:
            raise _fail("warm local pull contacted the unreachable remote")
        report["warm_remote_failures_delta"] = failures_after - failures_before

        # (e) Live source exists only in Garage; the cold miss must fail.
        path.unlink()
        if path.exists():
            raise _fail("local LFS object was not removed")
        _get_bytes(client, bucket, key, payload)
        cold_before, cold_backlog_before = _scrape(harness)
        if cold_backlog_before != 0:
            raise _fail("repair backlog was nonzero before the cold miss")
        status, _, _ = harness.lfs_get(
            "/git/alice/demo.git/info/lfs/objects/%s/%d" % (oid, size),
            token=harness.reader, code=FAILURE_CODES)
        cold_after, cold_backlog_after = _scrape(harness)
        report["cold_miss_status"] = status
        if cold_after - cold_before != 1:
            raise _fail("cold miss did not record exactly one remote failure")
        if cold_backlog_after != 0:
            raise _fail("cold miss left a nonzero repair backlog")
        report["cold_miss_failures_delta"] = cold_after - cold_before
        if path.exists():
            raise _fail("local LFS object reappeared on a cold miss")
        stock_before, stock_backlog_before = _scrape(harness)
        if stock_backlog_before != 0:
            raise _fail("repair backlog was nonzero before the cold stock pull")
        cold = _lfs_pull(harness, clone_b, check=False)
        stock_after, stock_backlog_after = _scrape(harness)
        if cold.returncode == 0:
            raise _fail("cold stock pull unexpectedly succeeded during outage")
        if stock_after - stock_before < 1:
            raise _fail("cold stock pull did not record a remote failure")
        if stock_after - stock_before != 1:
            raise _fail("cold stock pull did not record exactly one remote failure")
        if stock_backlog_after != 0:
            raise _fail("cold stock pull left a nonzero repair backlog")
        report["cold_pull_failures_delta"] = stock_after - stock_before
        if path.exists():
            raise _fail("cold stock pull fabricated a local LFS object")
        report["cold_miss_failed"] = True

        # (f) Real endpoint returns: genuine Garage cold hydration.
        _restart(harness, original["ROOTYARD_OBJECT_STORE_ENDPOINT"])
        _lfs_pull(harness, clone_b, check=True)
        if not _has_exact_bytes(os.path.join(clone_b, name), payload):
            raise _fail("hydrated clone bytes differ from the payload")
        if not _has_exact_bytes(path, payload):
            raise _fail("cold hydration did not republish exact local bytes")
        report["cold_hydration"] = True

        # (g) Remote loss plus delayed endpoint: observe backlog while one
        # admitted repair is in flight; the endpoint never holds real bytes.
        remote_deleted = True
        _delete_key(client, bucket, key)
        if _head(client, bucket, key):
            raise _fail("object key still present after deletion")
        if not _has_exact_bytes(path, payload):
            raise _fail("local LFS bytes were lost with the remote deletion")
        delay = _DelayedEndpoint()
        delay.__enter__()
        _restart(harness, delay.url)
        failures_start, _ = _scrape(harness)
        batch = harness.lfs_batch("upload", [{"oid": oid, "size": size}],
                                  token=harness.alice)
        objects = batch.get("objects") or []
        if len(objects) != 1:
            raise _fail("ready LFS batch returned an unexpected object count")
        if objects[0].get("error") is not None:
            raise _fail("ready LFS batch returned an unexpected object error")
        if (objects[0].get("actions") or {}).get("upload"):
            raise _fail("ready LFS batch unexpectedly advertised an upload action")
        peak_backlog = 0
        deadline = time.monotonic() + REPAIR_DEADLINE
        while True:
            failures_now, backlog_now = _scrape(harness)
            if backlog_now > peak_backlog:
                peak_backlog = backlog_now
            failure_delta = failures_now - failures_start
            if failure_delta > 1:
                raise _fail("ready LFS batch did not record exactly one remote failure")
            if failure_delta == 1 and backlog_now == 0:
                break
            if time.monotonic() >= deadline:
                raise _fail("deferred repair did not record a remote failure within 10s")
            time.sleep(0.1)
        if peak_backlog < 1:
            raise _fail("repair backlog was never observed while the repair was in flight")
        report["repair_failures_delta"] = failures_now - failures_start
        report["repair_peak_backlog"] = peak_backlog
        if _row(harness, oid)[0] != "ready":
            raise _fail("deferred repair changed the ready LFS row")
        _put_key(client, bucket, key, payload)
        if not _head(client, bucket, key):
            raise _fail("object key restore was not visible")
        _get_bytes(client, bucket, key, payload)
        remote_deleted = False
        report["remote_object_restored"] = True

        # (h) Upload durability gate while the remote is unreachable.
        delay.close()
        delay = None
        _restart(harness, UNREACHABLE_ENDPOINT)
        fresh = os.urandom(512 + int.from_bytes(os.urandom(1), "big") % 1024)
        fresh_oid = hashlib.sha256(fresh).hexdigest()
        fresh_size = len(fresh)
        fresh_before, fresh_backlog_before = _scrape(harness)
        if fresh_backlog_before != 0:
            raise _fail("repair backlog was nonzero before the failing upload")
        _upload(harness, fresh_oid, fresh_size, fresh, FAILURE_CODES)
        fresh_after, fresh_backlog_after = _scrape(harness)
        created.append(fresh_oid)
        if fresh_after - fresh_before != 1:
            raise _fail("failed remote upload did not record exactly one remote failure")
        if fresh_backlog_after != 0:
            raise _fail("failed remote upload left a nonzero repair backlog")
        report["pending_failures_delta"] = fresh_after - fresh_before
        if _row(harness, fresh_oid)[0] != "pending":
            raise _fail("failed remote upload did not keep the row pending")
        if not _has_exact_bytes(_server_path(harness, fresh_oid), fresh):
            raise _fail("failed remote upload uploaded different local bytes")
        report["pending_gate_held"] = True
        _restart(harness, original["ROOTYARD_OBJECT_STORE_ENDPOINT"])
        _upload(harness, fresh_oid, fresh_size, fresh, (200,))
        if _row(harness, fresh_oid)[0] != "ready":
            raise _fail("retried upload did not commit a ready row")
        _get_bytes(client, bucket, "tenants/%s/lfs/%s" % (tenant, fresh_oid), fresh)
        report["pending_retry_ready"] = True
    finally:
        try:
            if delay is not None:
                delay.close()
        finally:
            delay = None
        shutil.rmtree(scratch, ignore_errors=True)
        try:
            if remote_deleted and key is not None:
                _put_key(client, bucket, key, payload)
                _get_bytes(client, bucket, key, payload)
                remote_deleted = False
                report["remote_object_restored"] = True
        finally:
            for name, value in original.items():
                if value is None:
                    harness.env.pop(name, None)
                else:
                    harness.env[name] = value
            _restore_server(harness)
            for extra in created[1:]:
                extra_key = "tenants/%s/lfs/%s" % (tenant, extra)
                _delete_key(client, bucket, extra_key)
                if _head(client, bucket, extra_key):
                    raise _fail("scratch object key was not deleted")
            report["remote_object_deleted"] = remote_deleted
            report["server_local_bytes_present"] = bool(
                path is not None and _has_exact_bytes(path, payload))
            report["restored_env"] = all(
                harness.env.get(name) == value for name, value in original.items())
    return report


def cleanup_run_tenant_lfs_prefix(harness):
    """Delete only this run's owner LFS prefix using the original process S3 env."""
    env = _s3_env(os.environ)
    repo_id = getattr(harness, "repo", None)
    repo_id = repo_id.get("id") if isinstance(repo_id, dict) else None
    if not repo_id:
        raise _fail("LFS fixture repository is not ready")
    owner = harness.sql(
        "SELECT owner_id FROM repositories WHERE id='%s'" % repo_id
    ).strip()
    if len(owner) != 36 or owner.count("-") != 4:
        raise _fail("could not resolve this run's repository owner")
    client = _client(env)
    bucket = env["ROOTYARD_OBJECT_STORE_BUCKET"]
    prefix = "tenants/%s/lfs/" % owner
    deleted = 0
    try:
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            keys = [item["Key"] for item in page.get("Contents") or []
                    if item["Key"].startswith(prefix) and len(item["Key"]) > len(prefix)]
            if not keys:
                continue
            if len(keys) > 1000:
                raise _fail("object listing page exceeded the delete chunk size")
            result = client.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": item} for item in keys], "Quiet": False},
            )
            if result.get("Errors"):
                raise _fail("object store prefix cleanup reported errors")
            deleted += len(result.get("Deleted") or [])
    except AssertionError:
        raise
    except Exception:
        raise _fail("object store prefix cleanup failed") from None
    return {"deleted": deleted}
