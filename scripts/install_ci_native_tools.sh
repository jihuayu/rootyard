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
#
# `--phase-record FILE` additionally writes a separate, opt-in phase sidecar so
# a failed CI run can tell apt, Git build, bubblewrap build, profile export,
# preflight and provenance apart without reading raw step logs. The record has
# exactly four fixed fields and no command, output, path, environment value or
# package/tool detail:
#   mode             install | preflight
#   phase            setup | apt | git_build | bubblewrap_build |
#                    profile_export | preflight | provenance
#   state            entered | failed | complete
#   wrapper_sha256   SHA-256 of this wrapper source, binding the record to the
#                    exact wrapper revision that wrote it
# It is replaced atomically (write a sibling temporary file, then rename), so a
# reader never sees a partial record. `entered` is written before a phase
# starts. An ordinary non-zero phase exit replaces it with `failed` after the
# original exit status is captured, then the wrapper exits with that same
# status. `complete` is written only after provenance succeeds. An exit status
# above 128 is ambiguous (signal or plain exit code), so it is preserved and
# the phase stays `entered`: a conservative unknown boundary, not a failure
# claim and not a causal finding. Diagnostics are best effort: an unwritable
# record path, an early argument error before the record is enabled, or a
# failed record write leaves no positive record and never changes the gate.
# If the wrapper digest cannot be computed the sidecar is not written at all,
# because an unbound receipt is not evidence; the gate is unchanged.
set -euo pipefail

helper_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=ci_native_tools/lib.sh
. "$helper_dir/ci_native_tools/lib.sh"

usage() {
  cat <<'USAGE'
usage: install_ci_native_tools.sh install --prefix DIR [--state-dir DIR]
                                           [--work DIR] [--provenance FILE]
                                           [--phase-record FILE]
       install_ci_native_tools.sh preflight --prefix DIR [--state-dir DIR]
                                             [--provenance FILE]
                                             [--phase-record FILE]
USAGE
}

# --- phase diagnostics ----------------------------------------------------
# `phase_record` stays empty unless --phase-record is parsed, so every existing
# local invocation behaves exactly as before. The writer below is deliberately
# independent of python3 and of every path used by the bootstrap so a setup
# failure can still be recorded.
phase_record=""
wrapper_sha256=""

wrapper_source_digest() {
  local source=$1 digest=""
  if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$source" 2>/dev/null | awk '{print $1}') || digest=""
  elif command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 "$source" 2>/dev/null | awk '{print $1}') || digest=""
  fi
  [ "${#digest}" -eq 64 ] || digest=""
  case "$digest" in
    *[!0-9a-f]*) digest="" ;;
  esac
  printf '%s' "$digest"
}

write_phase_record() {
  local phase=$1 state=$2 directory tmp
  [ -n "$phase_record" ] || return 0
  directory=$(dirname -- "$phase_record") || return 0
  mkdir -p -- "$directory" 2>/dev/null || return 0
  tmp=$(mktemp -- "$directory/.ci-native-tools-phase.XXXXXXXX" 2>/dev/null) || return 0
  if ! printf '{"mode":"%s","phase":"%s","state":"%s","wrapper_sha256":"%s"}\n' \
    "$mode" "$phase" "$state" "$wrapper_sha256" >"$tmp" 2>/dev/null; then
    rm -f -- "$tmp" 2>/dev/null || true
    return 0
  fi
  mv -f -- "$tmp" "$phase_record" 2>/dev/null || rm -f -- "$tmp" 2>/dev/null || true
  return 0
}

phase_enter() {
  write_phase_record "$1" entered
}

phase_fail() {
  local failed_phase=$1 status=$2
  write_phase_record "$failed_phase" failed
  exit "$status"
}

# Keep the existing stderr convention but return instead of exiting, so the
# caller can record the phase and then leave with the same status.
phase_error() {
  printf 'ci native tools: %s\n' "$*" >&2
  return 1
}

finish_phase() {
  local finished_phase=$1 status=$2
  if [ "$status" -eq 0 ]; then
    return 0
  fi
  # An exit status above 128 is ambiguous: it can be a signal death or a plain
  # exit code. Do not attribute a phase failure from that ambiguity; preserve
  # the status and leave the phase's `entered` record in place as a
  # conservative "unknown boundary" marker.
  if [ "$status" -gt 128 ]; then
    exit "$status"
  fi
  phase_fail "$finished_phase" "$status"
}

setup_environment() {
  local provenance_dir provenance_name
  if [ "$(id -u)" = 0 ]; then
    phase_error "run as the unprivileged runner account; the host profile must match native acceptance"
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    phase_error "required command is missing: python3"
    return 1
  fi
  if [ -z "$prefix" ]; then
    if [ -z "${RUNNER_TEMP:-}" ]; then
      phase_error "--prefix is required (RUNNER_TEMP is not set)"
      return 1
    fi
    prefix="$RUNNER_TEMP/rootyard-ci-native"
  fi
  prefix=$(resolve_absolute "$prefix") || return $?
  if [ -z "$state_dir" ]; then
    state_dir="$prefix/state"
  fi
  if [ -z "$work" ]; then
    work="$prefix/work"
  fi
  if [ -z "$provenance" ]; then
    provenance="$prefix/provenance.json"
  fi
  state_dir=$(resolve_absolute "$state_dir") || return $?
  work=$(resolve_absolute "$work") || return $?
  # Keep the two substitutions separate: with `A=$(cmd)/$(cmd2)` bash reports
  # only cmd2's status, which would swallow a failed provenance-directory
  # creation and leave a root-relative output path behind.
  provenance_dir=$(dirname -- "$provenance") || return $?
  provenance_dir=$(resolve_absolute "$provenance_dir") || return $?
  provenance_name=$(basename -- "$provenance") || return $?
  provenance="$provenance_dir/$provenance_name"
  return 0
}

export_profile() {
  local java_home
  append_github_path "$prefix/bin" || return $?
  # Hosted images prepend an older JDK to PATH. Source-file JGit probes need
  # the Java 21 compiler module, not merely an installed runtime package.
  java_home=/usr/lib/jvm/java-21-openjdk-amd64
  if [ ! -x "$java_home/bin/java" ] || [ ! -x "$java_home/bin/javac" ]; then
    phase_error "Java 21 JDK is missing"
    return 1
  fi
  append_github_path "$java_home/bin" || return $?
  if [ -n "${GITHUB_ENV:-}" ]; then
    printf 'JAVA_HOME=%s\n' "$java_home" >>"$GITHUB_ENV" || return $?
  fi
  return 0
}

write_provenance() {
  local state=$1 output=$2 prefix=$3 output_dir
  output_dir=$(dirname -- "$output") || return $?
  # This function is called while its status is captured, which suppresses
  # errexit inside it. Check the mkdir explicitly and keep its exact status:
  # a provenance directory that cannot be created must never reach python or
  # the `complete` record.
  mkdir -p -- "$output_dir" || return $?
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
phase_record_arg=""

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix=${2:-}; shift 2 ;;
    --state-dir) state_dir=${2:-}; shift 2 ;;
    --work) work=${2:-}; shift 2 ;;
    --provenance) provenance=${2:-}; shift 2 ;;
    --phase-record) phase_record_arg=${2:-}; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

# Argument problems above may legitimately have no receipt: diagnostics are
# enabled only after the whole argument list parsed, and a record is never
# invented for a run that did not reach a phase.
phase_record=""
if [ -n "$phase_record_arg" ]; then
  wrapper_sha256=$(wrapper_source_digest "${BASH_SOURCE[0]}") || wrapper_sha256=""
  # A receipt is evidence only when it can be bound to the wrapper revision
  # that wrote it. Without a digest, write no record at all (a missing receipt
  # is allowed) and leave the gate's exit status untouched.
  if [ -n "$wrapper_sha256" ]; then
    phase_record=$phase_record_arg
  fi
fi

phase_enter setup
setup_status=0
setup_environment || setup_status=$?
finish_phase setup "$setup_status"

if [ "$mode" = install ]; then
  phase_enter apt
  status=0
  "$helper_dir/ci_native_tools/install_apt_packages.sh" \
    --state-dir "$state_dir" --work "$work/apt" || status=$?
  finish_phase apt "$status"

  phase_enter git_build
  status=0
  "$helper_dir/ci_native_tools/build_git_source.sh" \
    --prefix "$prefix" --state-dir "$state_dir" --work "$work/git" || status=$?
  finish_phase git_build "$status"

  phase_enter bubblewrap_build
  status=0
  "$helper_dir/ci_native_tools/build_bubblewrap_source.sh" \
    --prefix "$prefix" --state-dir "$state_dir" --work "$work/bubblewrap" || status=$?
  finish_phase bubblewrap_build "$status"

  phase_enter profile_export
  status=0
  export_profile || status=$?
  finish_phase profile_export "$status"
fi

# Refuse to claim the profile when any required capability is absent. The
# checks are functional (Git init, bubblewrap --size, /dev/fuse, unshare -Urnm),
# not skipped and not downgraded to version-string parsing.
phase_enter preflight
status=0
"$helper_dir/ci_native_tools/preflight.sh" --prefix "$prefix" --state-dir "$state_dir" ||
  status=$?
finish_phase preflight "$status"

phase_enter provenance
status=0
write_provenance "$state_dir" "$provenance" "$prefix" || status=$?
finish_phase provenance "$status"
# Only a successful write_provenance reaches this point.
write_phase_record provenance complete
