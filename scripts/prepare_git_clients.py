#!/usr/bin/env python3
"""Download the pinned JGit distribution and extract its verified dependencies."""
import argparse
import hashlib
from pathlib import Path
import urllib.request
import zipfile

VERSION = "7.8.1.202611041320-r"
SHA256 = "5446356d35a0260d11f0d0c346472b98496cea03251c10ac572efc2a54c67ec6"
URL = f"https://repo.maven.apache.org/maven2/org/eclipse/jgit/org.eclipse.jgit.pgm/{VERSION}/org.eclipse.jgit.pgm-{VERSION}.sh"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    archive = args.destination / "jgit"
    temporary = args.destination / "jgit.download"
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        try:
            with urllib.request.urlopen(URL, timeout=30) as response, temporary.open("wb") as output:
                count = 0
                while chunk := response.read(1024 * 1024):
                    count += len(chunk)
                    if count > 64 * 1024 * 1024:
                        raise RuntimeError("JGit download exceeds pinned distribution size limit")
                    output.write(chunk)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != SHA256:
                raise RuntimeError("JGit distribution checksum mismatch")
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    archive.chmod(0o755)
    libraries = args.destination / "jgit-libs"
    libraries.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive) as distribution:
        names = [n for n in distribution.namelist() if n.startswith("BOOT-INF/lib/") and n.endswith(".jar")]
        if not names:
            raise RuntimeError("Verified JGit distribution has no client libraries")
        for name in names:
            (libraries / Path(name).name).write_bytes(distribution.read(name))
    print(f"JGit {VERSION}; SHA256 {SHA256}; classpath {libraries.resolve()}/*")


if __name__ == "__main__":
    main()
