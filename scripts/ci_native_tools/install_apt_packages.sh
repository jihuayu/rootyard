#!/usr/bin/env bash
# Install the ordinary-CI native runtime packages from signed apt indexes.
#
# PostgreSQL 17 client and server come from the same signed PGDG repository
# used by the manual native-kernel-acceptance workflow; Ubuntu 22.04 only ships
# PostgreSQL 14/16, and pando_lab.py needs initdb/pg_ctl/pg_dump 17. Git LFS,
# fuse3 (fusermount3), util-linux (unshare/nsenter/setpriv), redis-server, the
# C/C++ toolchain, Java 21 and the Git source-build dependencies are installed
# from the runner image's own signed 22.04 archive. No untrusted PPA or
# curl|sh installer is used.
set -euo pipefail

helper_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$helper_dir/lib.sh"

usage() {
  cat <<'USAGE'
usage: install_apt_packages.sh --state-dir DIR --work DIR
USAGE
}

state_dir=""
work=""

while [ $# -gt 0 ]; do
  case "$1" in
    --state-dir) state_dir=${2:-}; shift 2 ;;
    --work) work=${2:-}; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[ -n "$state_dir" ] || fail "--state-dir is required"
[ -n "$work" ] || fail "--work is required"
[ "$(id -u)" != 0 ] ||
  fail "run as the unprivileged runner account; this helper uses sudo deliberately"
require_command sudo

state_dir=$(resolve_absolute "$state_dir")
work=$(resolve_absolute "$work")

prepare_pgdg_repository "$work/pgdg"
sudo apt-get update

# Git source-build dependencies are installed here as well so the source
# helper scripts can be run independently without assuming a previous helper.
apt_install \
  ca-certificates curl gnupg \
  dpkg-dev libc6-dev libcap-dev \
  meson ninja-build pkg-config autoconf gettext \
  libssl-dev libcurl4-openssl-dev libexpat1-dev zlib1g-dev \
  gcc g++ make \
  git-lfs fuse3 util-linux redis-server \
  openjdk-21-jre-headless python3-venv \
  postgresql-17 postgresql-client-17

python3 - "$state_dir/apt.json" <<'PY'
import json
import subprocess
import sys

packages = [
    "ca-certificates",
    "curl",
    "gnupg",
    "dpkg-dev",
    "libc6-dev",
    "libcap-dev",
    "meson",
    "ninja-build",
    "pkg-config",
    "autoconf",
    "gettext",
    "libssl-dev",
    "libcurl4-openssl-dev",
    "libexpat1-dev",
    "zlib1g-dev",
    "gcc",
    "g++",
    "make",
    "git-lfs",
    "fuse3",
    "util-linux",
    "redis-server",
    "openjdk-21-jre-headless",
    "python3-venv",
    "postgresql-17",
    "postgresql-client-17",
]


def installed_version(package):
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


document = {
    "component": "apt",
    "repositories": {
        "postgresql": "signed PGDG https://apt.postgresql.org/pub/repos/apt jammy-pgdg main",
        "ubuntu": "runner image signed Ubuntu 22.04 archive",
    },
    "packages": {package: installed_version(package) for package in packages},
}
keys = subprocess.run(
    ["gpg", "--show-keys", "--with-colons", "/etc/apt/keyrings/postgresql.gpg"],
    capture_output=True, text=True, check=True,
).stdout.splitlines()
primary = False
fingerprints = []
for line in keys:
    fields = line.split(":")
    if fields[0] == "pub":
        primary = True
    elif fields[0] == "fpr" and primary:
        fingerprints.append(fields[9])
        primary = False
if fingerprints != ["B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"]:
    raise SystemExit("ci native tools: installed PGDG key fingerprint mismatch")
document["pgdg_primary_key_fingerprint"] = fingerprints[0]
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
for package, version in sorted(document["packages"].items()):
    if version is None:
        raise SystemExit(f"ci native tools: package was not installed: {package}")
    print(f"{package}={version}")
PY
