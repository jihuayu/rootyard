#!/usr/bin/env python3
"""Fetch the pinned CI Kafka archive, publishing it only after SHA512 verification.

Two attempts at each official source bound network waits to 4 * 65 seconds.
Curl bounds connect, low-speed and total transfer time independently; the Python
process timeout also covers a stuck curl. The workflow adds a five-minute bound
including hashing and extraction. No curl configuration or implicit retries are
allowed to weaken these limits or TLS verification.
"""

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile


ARTIFACT = "kafka_2.13-4.4.0.tgz"
SHA512 = (
    "f5ceba8a265ab6bb2d68362b1f6859a95e15d60ef92ba83b43fdf065b557dc18e98d6383"
    "c15b9977320e25b3a2c8b6f11decb17b0fa6c0f163423793a0eb95cb"
)
# Apache recommends this CDN for release artifacts:
# https://infra.apache.org/release-publishing.html
URLS = (
    f"https://dlcdn.apache.org/kafka/4.4.0/{ARTIFACT}",
    f"https://archive.apache.org/dist/kafka/4.4.0/{ARTIFACT}",
)
ATTEMPTS_PER_SOURCE = 2


def download(destination):
    """Return a verified path; never publish partial or invalid content."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Keep partial files on the destination filesystem for atomic publication.
    with tempfile.TemporaryDirectory(prefix=".kafka-download-", dir=destination.parent) as work:
        partial = Path(work) / ARTIFACT
        for url in URLS:
            for attempt in range(1, ATTEMPTS_PER_SOURCE + 1):
                partial.unlink(missing_ok=True)
                print(f"Downloading {url} (attempt {attempt}/{ATTEMPTS_PER_SOURCE})", flush=True)
                command = [
                    "curl", "--disable", "--fail", "--silent", "--show-error",
                    "--location", "--proto", "=https", "--proto-redir", "=https",
                    "--connect-timeout", "10", "--max-time", "60",
                    "--speed-limit", "1024", "--speed-time", "15", "--retry", "0",
                    "--output", str(partial), url,
                ]
                try:
                    subprocess.run(command, check=True, timeout=65)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                    print(f"Kafka download failed: {error}", file=sys.stderr, flush=True)
                    continue
                digest = hashlib.sha512()
                with partial.open("rb") as archive:
                    for chunk in iter(lambda: archive.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != SHA512:
                    # An integrity failure is not a transient network failure.
                    raise RuntimeError(f"Kafka SHA512 mismatch from {url}; refusing archive")
                partial.replace(destination)
                print(f"Verified Kafka SHA512: {destination}", flush=True)
                return destination
    raise RuntimeError("Kafka download failed after 4 bounded attempts across official Apache sources")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        download(args.destination)
    except (OSError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
