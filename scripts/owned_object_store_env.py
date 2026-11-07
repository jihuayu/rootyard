#!/usr/bin/env python3
"""Write the private environment file for a job-owned S3-compatible fixture.

The candidate release gate must never inherit an object-store endpoint, bucket
or credential from a user, a previous deployment or another workflow run. This
helper takes the loopback endpoint and bucket chosen by the current job (the
Garage 2.1 container started by ``scripts/owned_garage_fixture.sh``), refuses to
run when ``ROOTYARD_OBJECT_STORE_*`` settings already exist in the environment,
proves that the endpoint answers as an S3 API before any acceptance test starts,
and writes the five ``ROOTYARD_OBJECT_STORE_*`` variables to a ``0600`` file in a
``0700`` directory outside the checkout.

The access key and secret are read from the environment only. They are never
accepted on argv and never printed, so they cannot leak through the process list
or the job log; the summary records only a SHA-256 fingerprint of the access key
identifier.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

INHERITED = (
    "ROOTYARD_OBJECT_STORE_ENDPOINT",
    "ROOTYARD_OBJECT_STORE_BUCKET",
    "ROOTYARD_OBJECT_STORE_REGION",
    "ROOTYARD_OBJECT_STORE_ACCESS_KEY",
    "ROOTYARD_OBJECT_STORE_SECRET_KEY",
    "ROOTYARD_OBJECT_STORE_SESSION_TOKEN",
)
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
ENV_SAFE = re.compile(r"^[A-Za-z0-9._~:/@%+=,-]+$")


def fail(message):
    raise SystemExit("owned object store fixture: " + message)


def refuse_inherited_settings():
    present = [name for name in INHERITED if os.environ.get(name) is not None]
    if present:
        fail(
            "object-store settings already exist in the environment ("
            + ", ".join(present)
            + "); the candidate fixture must be created by the current job, never inherited"
        )


def check_endpoint(raw):
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError as error:
        fail(f"invalid endpoint {raw!r}: {error}")
    if parsed.scheme != "http":
        fail("the owned Garage endpoint must be plain loopback HTTP, got " + (parsed.scheme or "<none>"))
    if parsed.hostname not in LOOPBACK:
        fail("the owned Garage endpoint must be loopback, got " + str(parsed.hostname))
    if parsed.username or parsed.password:
        fail("the endpoint must not embed credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        fail("the endpoint must be a bare origin without path, query or fragment")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{host}:{port or 80}"


def probe_s3(endpoint, timeout):
    """Require a live S3 API responder; a missing service or an HTML stub fails."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(endpoint + "/", method="GET")
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    status, body, content_type = response.status, response.read(4096), response.headers.get(
                        "Content-Type", ""
                    )
            except urllib.error.HTTPError as error:
                status, body, content_type = error.code, error.read(4096), error.headers.get("Content-Type", "")
            if status not in (200, 403):
                fail(f"unexpected S3 probe status {status} from {endpoint}")
            if b"<Error" not in body and b"<?xml" not in body:
                fail("the endpoint did not answer with an S3 XML body; refusing a stub object store")
            return {"status": status, "content_type": content_type}
        except (urllib.error.URLError, OSError, socket.timeout) as error:
            last = error
            time.sleep(0.5)
    fail(f"S3 endpoint {endpoint} did not become ready within {timeout}s: {last}")


def check_bucket(name, prefix):
    if not BUCKET.match(name):
        fail(f"bucket name {name!r} is not DNS-safe")
    if not name.startswith(prefix):
        fail(f"bucket {name!r} is not namespaced for this job (expected prefix {prefix!r})")


def env_value(label, value):
    if not value:
        fail(f"{label} is empty")
    if not ENV_SAFE.match(value):
        fail(f"{label} contains characters that are unsafe in a sourced environment file")
    return value


def inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def write_private(path, values):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    handle, temporary = tempfile.mkstemp(prefix=".object-store-", dir=str(destination.parent))
    try:
        with os.fdopen(handle, "w") as stream:
            for name, value in values:
                stream.write(f"{name}={value}\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    mode = destination.stat().st_mode & 0o777
    if mode != 0o600:
        fail(f"environment file mode is {oct(mode)}; credentials must be 0600")
    if not destination.is_file():
        fail("environment file was not written")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="0600 env file outside the checkout")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--region", default="garage")
    parser.add_argument("--require-bucket-prefix", default="rootyard-ci-")
    parser.add_argument("--access-key-env", default="ROOTYARD_FIXTURE_ACCESS_KEY")
    parser.add_argument("--secret-key-env", default="ROOTYARD_FIXTURE_SECRET_KEY")
    parser.add_argument("--probe-timeout", type=float, default=60.0)
    parser.add_argument("--summary", type=Path, help="safe (credential-free) JSON summary for the report manifest")
    args = parser.parse_args()

    refuse_inherited_settings()
    endpoint = check_endpoint(args.endpoint)
    check_bucket(args.bucket, args.require_bucket_prefix)
    access = env_value("access key", os.environ.get(args.access_key_env))
    secret = env_value("secret key", os.environ.get(args.secret_key_env))
    if len(secret) < 16:
        fail("the fixture secret key is implausibly short; refusing to record it as a real fixture")

    workspace = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
    if inside(args.output, workspace):
        fail("the environment file must live outside the checkout so it can never be uploaded")
    summary_path = args.summary
    if summary_path is not None and inside(summary_path, workspace):
        fail("the summary must live outside the checkout so it can never be uploaded")

    probe = probe_s3(endpoint, args.probe_timeout)
    destination = write_private(
        args.output,
        [
            ("ROOTYARD_OBJECT_STORE_ENDPOINT", endpoint),
            ("ROOTYARD_OBJECT_STORE_BUCKET", args.bucket),
            ("ROOTYARD_OBJECT_STORE_REGION", env_value("region", args.region)),
            ("ROOTYARD_OBJECT_STORE_ACCESS_KEY", access),
            ("ROOTYARD_OBJECT_STORE_SECRET_KEY", secret),
        ],
    )
    summary = {
        "endpoint": endpoint,
        "bucket": args.bucket,
        "region": args.region,
        "access_key_sha256": hashlib.sha256(access.encode()).hexdigest(),
        "environment_file": str(destination),
        "environment_file_mode": oct(destination.stat().st_mode & 0o777),
        "probe": probe,
    }
    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
