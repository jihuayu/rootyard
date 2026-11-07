#!/usr/bin/env bash
# Ordinary-CI native tool profile for the plain Ubuntu 22.04 verify job.
#
# The verify job no longer runs inside a `rust:1-trixie` container. It runs on
# the same plain Ubuntu 22.04 host profile on which the manual
# native-kernel-acceptance workflow passed its 17 assertions (run 42410286276):
# the runner account is unprivileged, host init (PID 1) adopts and reaps
# orphaned Git grandchildren, and /dev/fuse plus unprivileged user namespaces
# are available without changing AppArmor or any sysctl. This helper installs
# the tools that profile needs and then proves them functionally.
#
# Subcommands:
#   install    install signed apt packages, build Git 2.43.x and bubblewrap
#              0.9.0-1build1 into an owned prefix, then run preflight
#   preflight  re-run only the functional checks and refresh provenance
#
# Provenance is JSON containing package versions, source package versions,
# source-file SHA-256 digests, installed binary digests and reported tool
# versions. It contains no database URL, token or fixture credential.
set -euo pipefail

helper_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=ci_native_tools/lib.sh
. "$helper_dir/ci_native_tools/lib.sh"

usage() {
  cat <<'USAGE'
usage: install_ci_native_tools.sh install --prefix DIR [--state-dir DIR]
                                           [--work DIR] [--provenance FILE]
       install_ci_native_tools.sh preflight --prefix DIR [--state-dir DIR]
                                             [--provenance FILE]
USAGE
}

write_provenance() {
  local state=$1 output=$2 prefix=$3
  mkdir -p -- "$(dirname -- "$output")"
  python3 - "$state" "$output" "$prefix" <<'PY'
import glob
import json
import os
import platform
import sys
import time

state, output, prefix = sys.argv[1:4]
components = {}
for path in sorted(glob.glob(os.path.join(state, "*.json"))):
    name = os.path.splitext(os.path.basename(path))[0]
    with open(path, encoding="utf-8") as stream:
        components[name] = json.load(stream)
for required in ("apt", "git", "bubblewrap", "preflight"):
    if required not in components:
        raise SystemExit(
            f"ci native tools: refusing to write incomplete provenance; missing {required} state"
        )
host = {"kernel": platform.release(), "machine": platform.machine()}
try:
    with open("/etc/os-release", encoding="utf-8") as stream:
        for line in stream:
            key, separator, value = line.strip().partition("=")
            if separator and key in ("ID", "VERSION_ID", "PRETTY_NAME"):
                host[key.lower()] = value.strip('"')
except OSError:
    pass
document = {
    "schema": "rootyard/ci-native-tools/v1",
    "generated_unix": int(time.time()),
    "prefix": prefix,
    "host": host,
    "components": components,
}
with open(output, "w", encoding="utf-8") as stream:
    stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
os.chmod(output, 0o644)
print(f"native tool provenance: {output} ({', '.join(sorted(components))})")
PY
}

[ $# -ge 1 ] || usage
mode=$1
shift
case "$mode" in
  install | preflight) ;;
  -h | --help) usage; exit 0 ;;
  *) usage; exit 2 ;;
esac

prefix=""
state_dir=""
work=""
provenance=""

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix=${2:-}; shift 2 ;;
    --state-dir) state_dir=${2:-}; shift 2 ;;
    --work) work=${2:-}; shift 2 ;;
    --provenance) provenance=${2:-}; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" != 0 ] ||
  fail "run as the unprivileged runner account; the host profile must match native acceptance"
require_command python3

if [ -z "$prefix" ]; then
  [ -n "${RUNNER_TEMP:-}" ] || fail "--prefix is required (RUNNER_TEMP is not set)"
  prefix="$RUNNER_TEMP/rootyard-ci-native"
fi
prefix=$(resolve_absolute "$prefix")
[ -z "$state_dir" ] && state_dir="$prefix/state"
[ -z "$work" ] && work="$prefix/work"
[ -z "$provenance" ] && provenance="$prefix/provenance.json"
state_dir=$(resolve_absolute "$state_dir")
work=$(resolve_absolute "$work")
provenance=$(resolve_absolute "$(dirname -- "$provenance")")/$(basename -- "$provenance")

if [ "$mode" = install ]; then
  "$helper_dir/ci_native_tools/install_apt_packages.sh" \
    --state-dir "$state_dir" --work "$work/apt"
  "$helper_dir/ci_native_tools/build_git_source.sh" \
    --prefix "$prefix" --state-dir "$state_dir" --work "$work/git"
  "$helper_dir/ci_native_tools/build_bubblewrap_source.sh" \
    --prefix "$prefix" --state-dir "$state_dir" --work "$work/bubblewrap"
  append_github_path "$prefix/bin"
  # Hosted images prepend an older JDK to PATH. Source-file JGit probes need
  # the Java 21 compiler module, not merely an installed runtime package.
  java_home=/usr/lib/jvm/java-21-openjdk-amd64
  [ -x "$java_home/bin/java" ] && [ -x "$java_home/bin/javac" ] || fail "Java 21 JDK is missing"
  append_github_path "$java_home/bin"
  if [ -n "${GITHUB_ENV:-}" ]; then
    printf 'JAVA_HOME=%s\n' "$java_home" >> "$GITHUB_ENV"
  fi
fi

# Refuse to claim the profile when any required capability is absent. The
# checks are functional (Git init, bubblewrap --size, /dev/fuse, unshare -Urnm),
# not skipped and not downgraded to version-string parsing.
"$helper_dir/ci_native_tools/preflight.sh" --prefix "$prefix" --state-dir "$state_dir"
write_provenance "$state_dir" "$provenance" "$prefix"
