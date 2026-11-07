#!/usr/bin/env bash
# Shared helpers for the ordinary-CI native tool bootstrap.
#
# The ordinary verify job runs on a plain Ubuntu 22.04 runner. It needs the
# same signed PGDG PostgreSQL 17 packages and the same source-built
# bubblewrap 0.9.0-1build1 that the manual native-kernel-acceptance workflow
# already proved on Ubuntu 22.04, plus a Git 2.43 client because Ubuntu 22.04
# ships Git 2.34 and workspace_lab refuses anything older than 2.43.
#
# Nothing here replaces a system binary or edits global Git configuration.
# Builders install into an owned RUNNER_TEMP prefix and the workflow prepends
# that prefix to GITHUB_PATH. Only signed apt indexes are consumed:
# /etc/apt/sources.list.d entries added here are deb-src-only for the Ubuntu
# Noble archive (main/universe, noble-updates and noble-security), so no Noble
# binary package or library is installed. PGDG is the same signed repository
# the manual native workflow trusts.
#
# This file is a library; it is sourced by the helper scripts.
lib_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

log() { printf '%s\n' "$*" >&2; }

fail() {
  printf 'ci native tools: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

resolve_absolute() {
  mkdir -p -- "$1"
  (cd -- "$1" && pwd -P)
}

append_github_path() {
  local directory=$1
  if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$directory" >>"$GITHUB_PATH"
  fi
  log "tool prefix bin directory for later steps: $directory"
}

ubuntu_archive_keyring() {
  printf '%s\n' /usr/share/keyrings/ubuntu-archive-keyring.gpg
}

# Add deb-src-only entries for the signed Ubuntu Noble archive. Noble is the
# first Ubuntu release whose Git source is the required 2.43 family; 22.04's
# own archive only offers 2.34. Binary packages from Noble are never enabled.
prepare_ubuntu_archive_source() {
  local keyring list want current
  require_command sudo
  require_command apt-get
  keyring=$(ubuntu_archive_keyring)
  [ -f "$keyring" ] || fail "trusted Ubuntu archive keyring is missing: $keyring"
  list=/etc/apt/sources.list.d/rootyard-ubuntu-noble-src.list
  want=$(cat <<EOF
deb-src [signed-by=$keyring] http://archive.ubuntu.com/ubuntu noble main universe
deb-src [signed-by=$keyring] http://archive.ubuntu.com/ubuntu noble-updates main universe
deb-src [signed-by=$keyring] http://security.ubuntu.com/ubuntu noble-security main universe
EOF
)
  current=$(sudo cat "$list" 2>/dev/null || true)
  if [ "$current" = "$want" ]; then
    log "signed Ubuntu Noble source index already configured (deb-src only)"
    return 0
  fi
  printf '%s\n' "$want" | sudo tee "$list" >/dev/null
  log "configured deb-src-only signed Ubuntu Noble source index: $list"
  sudo apt-get update
}

# Install the signed PGDG repository and key exactly as the manual
# native-kernel-acceptance workflow does, but additionally pin the expected
# key fingerprint so a replaced key cannot silently authorise the index.
prepare_pgdg_repository() {
  local work=$1
  local keyring=/etc/apt/keyrings/postgresql.gpg
  local list fingerprint want current codename
  require_command sudo
  require_command curl
  require_command gpg
  mkdir -p -- "$work"
  if [ ! -s "$keyring" ]; then
    curl -fsSL --retry 3 \
      https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      -o "$work/pgdg.asc"
    fingerprint=$(gpg --show-keys --with-colons "$work/pgdg.asc" |
      awk -F: '$1 == "fpr" { print $10; exit }')
    [ "$fingerprint" = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8" ] ||
      fail "PGDG key fingerprint mismatch: ${fingerprint:-missing}"
    gpg --dearmor --yes -o "$work/pgdg.gpg" "$work/pgdg.asc"
    sudo install -d -m 0755 /etc/apt/keyrings
    sudo install -m 0644 "$work/pgdg.gpg" "$keyring"
    log "installed PGDG archive key $fingerprint"
  else
    log "PGDG archive keyring already present: $keyring"
  fi
  # Verify existing runner state as well as a fresh import. Reject extra
  # primary keys: signed-by would otherwise trust those keys too.
  fingerprint=$(gpg --show-keys --with-colons "$keyring" |
    awk -F: '$1 == "pub" { primary=1; next } $1 == "fpr" && primary { print $10; primary=0 }')
  [ "$fingerprint" = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8" ] ||
    fail "installed PGDG key fingerprint mismatch"
  # shellcheck disable=SC1091
  . /etc/os-release
  codename=${VERSION_CODENAME:-}
  [ "$codename" = jammy ] ||
    fail "this profile targets Ubuntu 22.04 (jammy), found '${codename:-unknown}'"
  list=/etc/apt/sources.list.d/pgdg.list
  want="deb [signed-by=$keyring] https://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main"
  current=$(sudo cat "$list" 2>/dev/null || true)
  if [ "$current" = "$want" ]; then
    log "signed PGDG repository already configured"
    return 0
  fi
  printf '%s\n' "$want" | sudo tee "$list" >/dev/null
  log "configured signed PGDG repository for ${codename}"
  sudo apt-get update
}

apt_install() {
  require_command sudo
  sudo apt-get install -y --no-install-recommends "$@"
}

source_versions() {
  apt-cache showsrc "$1" 2>/dev/null | sed -n 's/^Version: //p' | sort -u
}

# Latest source version in the signed index matching an ERE family pattern
# (for example '^(1:)?2\.43\.[0-9]+-'). An empty result is reported by the
# caller together with the versions that were actually offered.
latest_matching_source() {
  local package=$1 pattern=$2 versions
  versions=$(source_versions "$package")
  printf '%s\n' "$versions" | grep -E "$pattern" | sort -V | tail -1 || true
}

available_source_versions_line() {
  source_versions "$1" | tr '\n' ' '
}

fetch_source() {
  local package=$1 version=$2 work=$3
  mkdir -p -- "$work"
  [ -z "$(find "$work" -mindepth 1 -maxdepth 1 -print -quit)" ] ||
    fail "source work directory is not empty: $work"
  (cd "$work" && apt-get source "$package=$version")
}

find_source_directory() {
  local work=$1 package=$2
  find "$work" -maxdepth 1 -mindepth 1 -type d -name "$package-*" -print |
    sort | head -1
}

# Verify that every source file named by the apt-verified .dsc really matches
# the signed index checksum, and record the precise source package version plus
# file SHA-256 digests for reproduction.apt-get source already verifies the
# Release signature; this second check binds the record to the exact bytes.
record_source_provenance() {
  local component=$1 package=$2 version=$3 work=$4 source_dir=$5 state_dir=$6
  mkdir -p -- "$state_dir"
  python3 - "$component" "$package" "$version" "$work" "$source_dir" \
    "$state_dir/$component.json" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

component, package, version, work, source_dir, output = sys.argv[1:7]


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fail(message):
    raise SystemExit(f"ci native tools: {message}")


dsc_files = sorted(Path(work).glob("*.dsc"))
if len(dsc_files) != 1:
    fail(f"{package}: expected exactly one signed .dsc in {work}, found {len(dsc_files)}")
dsc = dsc_files[0]
source_files = []
in_checksums = False
for line in dsc.read_text(encoding="utf-8").splitlines():
    if line.startswith("Checksums-Sha256:"):
        in_checksums = True
        continue
    if not in_checksums:
        continue
    if not line.startswith((" ", "\t")):
        break
    parts = line.split()
    if not parts:
        break
    if len(parts) != 3:
        fail(f"{package}: malformed Checksums-Sha256 line in {dsc.name}")
    sha256, size, name = parts
    path = os.path.join(work, name)
    if len(sha256) != 64 or not os.path.isfile(path):
        fail(f"{package}: source file missing or malformed: {name}")
    actual = digest(path)
    if actual != sha256:
        fail(f"{package}: source file {name} sha256 {actual} != signed index {sha256}")
    source_files.append({"name": name, "size": int(size), "sha256": sha256})
if not source_files:
    fail(f"{package}: .dsc has no Checksums-Sha256 entries")

changelog = os.path.join(source_dir, "debian", "changelog")
reported = subprocess.run(
    ["dpkg-parsechangelog", "-l", changelog, "-SVersion"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
if reported != version:
    fail(f"{package}: requested {version} but extracted changelog reports {reported}")

document = {
    "component": component,
    "package": package,
    "source_version": reported,
    "dsc": {"name": dsc.name, "sha256": digest(dsc)},
    "source_files": source_files,
    "source_directory": os.path.basename(source_dir),
    "verified_by": "signed apt Release index plus .dsc Checksums-Sha256",
}
Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"{component}: {package} {reported} ({len(source_files)} verified source files)")
PY
}

record_built_binary() {
  local state_file=$1 binary=$2 reported_version=$3
  shift 3
  python3 - "$state_file" "$binary" "$reported_version" "$@" <<'PY'
import hashlib
import json
import sys

state_file, binary, reported_version = sys.argv[1:4]
options = sys.argv[4:]
with open(state_file, encoding="utf-8") as stream:
    document = json.load(stream)
with open(binary, "rb") as stream:
    document["installed_binary"] = {
        "sha256": hashlib.sha256(stream.read()).hexdigest(),
        "reported_version": reported_version,
    }
document["build_options"] = options
with open(state_file, "w", encoding="utf-8") as stream:
    stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
}

# The production Rust gates parse `git version` and reject anything below 2.43.
require_git_243() {
  local binary=$1 version major minor rest
  version=$("$binary" --version | awk '{print $3}')
  [ -n "$version" ] || fail "cannot read a Git version from $binary"
  major=${version%%.*}
  rest=${version#*.}
  minor=${rest%%.*}
  case "$major:$minor" in
    *[!0-9:]* | :*)
      fail "unparsable Git version: $version"
      ;;
  esac
  if [ "$major" -gt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -ge 43 ]; }; then
    log "Git $version satisfies the >= 2.43 requirement"
  else
    fail "Git $version is older than the required 2.43"
  fi
}
