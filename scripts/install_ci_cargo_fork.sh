#!/usr/bin/env bash
# Install and select the pinned CargoFork for formal Linux CI.
#
# The formal gate keeps rustc at the repository's rust-toolchain.toml pin,
# 1.99.1, but runs the Cargo command itself from the reviewed jihuayu/cargo
# fork.  The fork is pinned to a full commit, not a branch or a short version
# string:
#
#   revision  64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b
#   release   1.101.0
#   example   cargo 1.101.0 (64a6ee6a4 2026-11-10) (huacnlee/cargo, ...)
#
# Only Cargo is replaced.  rustc, rustfmt, clippy and rustdoc continue to come
# from rustup's 1.99.1 toolchain; `rust-toolchain.toml` still resolves the
# compiler for the fork.  The fork is bootstrapped with rustup's own Cargo
# (`rustup run 1.99.1 cargo install`), never with `rustup which cargo` and
# never by evaluating the Cargo that happens to be selected on PATH.
#
# Cache layout (keyed by OS, architecture, full revision and the full commit of
# the bootstrap Cargo):
#
#   $CACHE_DIR/bin/cargo                         stable symlink for PATH
#   $CACHE_DIR/installs/<key>/bin/cargo          verified executable
#   $CACHE_DIR/installs/<key>/metadata.json      path/version/revision/SHA
#
# A valid cache entry is reused without `cargo clean`, `--force` or a rebuild.
# A valid already-installed fork supplied with `--reuse` (or CARGO_FORK_BIN) is
# adopted into the cache instead of being rebuilt.  Every reuse re-verifies the
# full `cargo -vV` commit, release, host architecture and SHA-256 against the
# recorded metadata.  This helper performs only tool setup/probing; it never
# builds the project and never changes rustc.
#
# Usage:
#   install_ci_cargo_fork.sh install --cache-dir DIR [--reuse PATH]
#                                    [--record FILE] [--require-os OS]
#                                    [--require-arch ARCH] [--no-github]
#   install_ci_cargo_fork.sh verify  --cache-dir DIR [--require-path]
#                                    [--record FILE] [--require-os OS]
#                                    [--require-arch ARCH] [--no-github]
#
# `install` prepends $CACHE_DIR/bin to GITHUB_PATH and exports
# CARGO_FORK_* plus CARGO_FORK_AUTO_UPDATE=0 through GITHUB_ENV when those
# GitHub Actions files are present.  The current shell may source the printed
# CARGO_FORK_BIN or the caller may use a separate step, because a child process
# cannot modify its parent's PATH.
set -euo pipefail

readonly REVISION=64a6ee6a47acfa82b1ed930d7cd55e56dc30c30b
readonly RELEASE=1.101.0
readonly BOOTSTRAP_TOOLCHAIN=1.99.1
readonly CARGO_GIT=https://github.com/jihuayu/cargo.git
readonly SCHEMA=rootyard/ci-cargo-fork/v1

usage() {
  cat <<'USAGE'
usage: install_ci_cargo_fork.sh install --cache-dir DIR [--reuse PATH]
                                        [--record FILE] [--require-os OS]
                                        [--require-arch ARCH] [--no-github]
       install_ci_cargo_fork.sh verify  --cache-dir DIR [--require-path]
                                        [--record FILE] [--require-os OS]
                                        [--require-arch ARCH] [--no-github]
USAGE
}

fail() {
  printf 'cargo fork: %s\n' "$*" >&2
  exit 1
}

note() {
  printf 'cargo fork: %s\n' "$*"
}

sanitize() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-'
}

absolute_directory() {
  (CDPATH= cd -- "$1" && pwd -P)
}

absolute_file() {
  local path=$1 directory base
  directory=$(dirname -- "$path")
  base=$(basename -- "$path")
  mkdir -p -- "$directory"
  directory=$(absolute_directory "$directory")
  printf '%s/%s\n' "$directory" "$base"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

detect_platform() {
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) os=$(sanitize "$(uname -s | tr '[:upper:]' '[:lower:]')") ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    arm64 | aarch64) arch=aarch64 ;;
    i386 | i686) arch=i686 ;;
    armv7l) arch=armv7 ;;
    *) arch=$(sanitize "$(uname -m)") ;;
  esac
  [ -n "$os" ] || fail "could not detect the operating system"
  [ -n "$arch" ] || fail "could not detect the machine architecture"
  if [ -n "$require_os" ] && [ "$os" != "$require_os" ]; then
    fail "host OS is $os, but --require-os $require_os was requested"
  fi
  if [ -n "$require_arch" ] && [ "$arch" != "$require_arch" ]; then
    fail "host architecture is $arch, but --require-arch $require_arch was requested"
  fi
}

probe_bootstrap() {
  command -v rustup >/dev/null 2>&1 || fail "rustup is required to bootstrap Cargo $RELEASE"
  command -v rustc >/dev/null 2>&1 || fail "rustc is required; rustc must remain $BOOTSTRAP_TOOLCHAIN"
  local output rustc_output rustc_verbose

  output=$(CARGO_FORK_AUTO_UPDATE=0 rustup run "$BOOTSTRAP_TOOLCHAIN" cargo -vV 2>/dev/null) ||
    fail "rustup run $BOOTSTRAP_TOOLCHAIN cargo -vV failed; install that toolchain first"
  bootstrap_full_version=$(printf '%s\n' "$output" | sed -n '1p')
  bootstrap_release=$(printf '%s\n' "$output" | sed -n 's/^release: //p' | sed -n '1p')
  bootstrap_commit=$(printf '%s\n' "$output" | sed -n 's/^commit-hash: //p' | sed -n '1p')
  [ "$bootstrap_release" = "$BOOTSTRAP_TOOLCHAIN" ] ||
    fail "bootstrap Cargo release is ${bootstrap_release:-unknown}, expected $BOOTSTRAP_TOOLCHAIN"
  [ -n "$bootstrap_commit" ] || fail "bootstrap Cargo did not report a full commit-hash"
  [ "$bootstrap_commit" != "$REVISION" ] ||
    fail "refusing to bootstrap the fork with the fork itself"

  rustc_output=$(rustc -V 2>/dev/null) || fail "rustc -V failed; rustc must remain $BOOTSTRAP_TOOLCHAIN"
  rustc_release=$(printf '%s\n' "$rustc_output" | awk '{print $2}')
  [ "$rustc_release" = "$BOOTSTRAP_TOOLCHAIN" ] ||
    fail "rustc release is ${rustc_release:-unknown}; formal CI keeps rustc at $BOOTSTRAP_TOOLCHAIN"
  rustc_verbose=$(rustc -vV 2>/dev/null) || fail "rustc -vV failed; rustc must remain $BOOTSTRAP_TOOLCHAIN"
  rustc_full_version=$rustc_output
  rustc_commit=$(printf '%s\n' "$rustc_verbose" | sed -n 's/^commit-hash: //p' | sed -n '1p')
  rustc_host=$(printf '%s\n' "$rustc_verbose" | sed -n 's/^host: //p' | sed -n '1p')
  [ -n "$rustc_commit" ] || fail "rustc did not report a full commit-hash"
  [ -n "$rustc_host" ] || fail "rustc did not report a host triple"
}

# Verify one executable and populate verified_* on success.  This is a
# metadata-only probe: `cargo -vV` plus SHA-256, never a build.
verify_cargo() {
  local executable=$1 output
  [ -n "$executable" ] && [ -f "$executable" ] && [ -x "$executable" ] || return 1
  output=$(CARGO_FORK_AUTO_UPDATE=0 "$executable" -vV 2>/dev/null) || return 1
  verified_full_version=$(printf '%s\n' "$output" | sed -n '1p')
  verified_release=$(printf '%s\n' "$output" | sed -n 's/^release: //p' | sed -n '1p')
  verified_commit=$(printf '%s\n' "$output" | sed -n 's/^commit-hash: //p' | sed -n '1p')
  verified_host=$(printf '%s\n' "$output" | sed -n 's/^host: //p' | sed -n '1p')
  [ "$verified_release" = "$RELEASE" ] || return 1
  [ "$verified_commit" = "$REVISION" ] || return 1
  case "$verified_host" in
    "$arch"-*) ;;
    *) return 1 ;;
  esac
  case "$verified_host" in
    *"$os"*) ;;
    *) return 1 ;;
  esac
  verified_path=$executable
  verified_sha=$(sha256_file "$executable") || return 1
  [ -n "$verified_sha" ] || return 1
  return 0
}

# Validate cache metadata and return the recorded binary SHA on stdout.  The
# caller compares it with the SHA of the executable it just probed, so a stale
# or tampered metadata file cannot bless a different binary.
metadata_sha() {
  local metadata=$1
  python3 - "$metadata" "$REVISION" "$RELEASE" "$os" "$arch" "$bootstrap_commit" "$SCHEMA" <<'PY'
import json
import sys

path, revision, release, os_name, arch, bootstrap, schema = sys.argv[1:8]
with open(path, encoding="utf-8") as stream:
    document = json.load(stream)
if document.get("schema") != schema:
    raise SystemExit(1)
if document.get("revision") != revision or document.get("release") != release:
    raise SystemExit(1)
if document.get("os") != os_name or document.get("arch") != arch:
    raise SystemExit(1)
bootstrap_document = document.get("bootstrap") or {}
if bootstrap_document.get("toolchain") != "1.99.1":
    raise SystemExit(1)
if bootstrap_document.get("commit_hash") != bootstrap:
    raise SystemExit(1)
digest = document.get("binary_sha256")
if not isinstance(digest, str) or len(digest) != 64:
    raise SystemExit(1)
print(digest)
PY
}

write_metadata() {
  local metadata=$1 source=$2 installed=$3 resolved=$4
  mkdir -p -- "$(dirname -- "$metadata")"
  python3 - "$metadata" "$SCHEMA" "$REVISION" "$RELEASE" "$os" "$arch" "$key" \
    "$source" "$installed" "$resolved" "$verified_full_version" "$verified_commit" \
    "$verified_host" "$verified_sha" "$bootstrap_commit" "$bootstrap_full_version" \
    "$rustc_full_version" "$rustc_release" "$rustc_commit" "$rustc_host" \
    "$cache_dir" <<'PY'
import json
import os
import sys
import time

(
    path,
    schema,
    revision,
    release,
    os_name,
    arch,
    cache_key,
    source,
    installed,
    resolved,
    full_version,
    commit_hash,
    host,
    binary_sha256,
    bootstrap_commit,
    bootstrap_full_version,
    rustc_full_version,
    rustc_release,
    rustc_commit,
    rustc_host,
    cache_dir,
) = sys.argv[1:22]
document = {
    "schema": schema,
    "generated_unix": int(time.time()),
    "revision": revision,
    "release": release,
    "full_version": full_version,
    "commit_hash": commit_hash,
    "host": host,
    "os": os_name,
    "arch": arch,
    "cache_key": cache_key,
    "source": source,
    "installed_path": installed,
    "resolved_path": resolved,
    "binary_sha256": binary_sha256,
    "cache_dir": cache_dir,
    "bootstrap": {
        "toolchain": "1.99.1",
        "full_version": bootstrap_full_version,
        "commit_hash": bootstrap_commit,
    },
    "rustc": {
        "full_version": rustc_full_version,
        "release": rustc_release,
        "commit_hash": rustc_commit,
        "host": rustc_host,
    },
}
with open(path, "w", encoding="utf-8") as stream:
    stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
os.chmod(path, 0o644)
PY
}

replace_install() {
  local temporary=$1
  case "$temporary" in
    "$cache_dir"/installs/.adopt-* | "$cache_dir"/installs/.build-*) ;;
    *) fail "refusing to publish an unexpected temporary path: $temporary" ;;
  esac
  if [ -e "$install_root" ] || [ -L "$install_root" ]; then
    case "$install_root" in
      "$cache_dir"/installs/*) rm -rf -- "$install_root" ;;
      *) fail "refusing to replace an unexpected install path: $install_root" ;;
    esac
  fi
  mv -- "$temporary" "$install_root"
}

adopt_candidate() {
  local candidate=$1 temporary
  verify_cargo "$candidate" || return 1
  temporary="$cache_dir/installs/.adopt-$$"
  rm -rf -- "$temporary"
  mkdir -p -- "$temporary/bin"
  cp -- "$verified_path" "$temporary/bin/cargo"
  chmod 0755 "$temporary/bin/cargo"
  if ! verify_cargo "$temporary/bin/cargo"; then
    rm -rf -- "$temporary"
    return 1
  fi
  write_metadata "$temporary/metadata.json" reuse "$install_root/bin/cargo" "$cache_dir/bin/cargo"
  replace_install "$temporary"
  adopted_source=reuse
  return 0
}

cleanup_temporary() {
  if [ -n "${temporary:-}" ] && [ -e "$temporary" ]; then
    rm -rf -- "$temporary"
  fi
}

mode=${1:-}
[ -n "$mode" ] || {
  usage
  exit 2
}
case "$mode" in
  install | verify) shift ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

cache_dir=${CARGO_FORK_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rootyard/cargo-fork}
reuse=${CARGO_FORK_REUSE:-}
record=
require_os=
require_arch=
require_path=0
github=1

while [ $# -gt 0 ]; do
  case "$1" in
    --cache-dir) cache_dir=${2:-}; shift 2 ;;
    --reuse) reuse=${2:-}; shift 2 ;;
    --record) record=${2:-}; shift 2 ;;
    --require-os) require_os=${2:-}; shift 2 ;;
    --require-arch) require_arch=${2:-}; shift 2 ;;
    --require-path) require_path=1; shift ;;
    --no-github) github=0; shift ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[ -n "$cache_dir" ] || fail "--cache-dir must not be empty"
mkdir -p -- "$cache_dir"
cache_dir=$(absolute_directory "$cache_dir") || fail "could not resolve --cache-dir"
mkdir -p -- "$cache_dir/bin" "$cache_dir/installs"

detect_platform
probe_bootstrap

key="$(sanitize "$os")-$(sanitize "$arch")-${REVISION}-${bootstrap_commit}"
install_root="$cache_dir/installs/$key"
resolved="$cache_dir/bin/cargo"
source=
temporary=
trap cleanup_temporary EXIT

if [ "$mode" = install ]; then
  cache_hit=0
  if [ -f "$install_root/metadata.json" ] && [ -x "$install_root/bin/cargo" ]; then
    if verify_cargo "$install_root/bin/cargo"; then
      if expected_sha=$(metadata_sha "$install_root/metadata.json"); then
        if [ "$expected_sha" = "$verified_sha" ]; then
          write_metadata "$install_root/metadata.json" cache "$install_root/bin/cargo" "$resolved"
          cache_hit=1
          source=cache
        fi
      fi
    fi
  fi

  if [ "$cache_hit" = 0 ]; then
    adopted_source=
    for candidate in "$reuse" "${CARGO_FORK_BIN:-}" "$(command -v cargo 2>/dev/null || true)"; do
      [ -n "$candidate" ] || continue
      [ "$candidate" = "$resolved" ] && continue
      [ "$candidate" = "$install_root/bin/cargo" ] && continue
      if adopt_candidate "$candidate"; then
        source=$adopted_source
        cache_hit=1
        break
      fi
    done
  fi

  if [ "$cache_hit" = 0 ]; then
    temporary="$cache_dir/installs/.build-$$"
    rm -rf -- "$temporary"
    mkdir -p -- "$temporary"
    work_dir=${CARGO_FORK_BUILD_DIR:-${TMPDIR:-/tmp}/rootyard-cargo-fork-build-$key}
    mkdir -p -- "$work_dir"
    note "cache miss; building CargoFork $REVISION with rustup $BOOTSTRAP_TOOLCHAIN Cargo"
    if ! CARGO_FORK_AUTO_UPDATE=0 CARGO_TARGET_DIR="$work_dir" \
      rustup run "$BOOTSTRAP_TOOLCHAIN" cargo install \
      --git "$CARGO_GIT" --rev "$REVISION" --locked --bin cargo \
      --root "$temporary" cargo; then
      cleanup_temporary
      fail "cargo install failed; the cache was not published"
    fi
    if ! verify_cargo "$temporary/bin/cargo"; then
      cleanup_temporary
      fail "the newly built Cargo does not match release $RELEASE, full revision $REVISION and host $arch/$os"
    fi
    write_metadata "$temporary/metadata.json" built "$install_root/bin/cargo" "$resolved"
    replace_install "$temporary"
    temporary=
    source=built
  fi

  mkdir -p -- "$cache_dir/bin"
  ln -sfn "$install_root/bin/cargo" "$resolved"
  verify_cargo "$resolved" ||
    fail "the selected fork at $resolved failed full revision/architecture/SHA verification"
else
  [ -f "$install_root/metadata.json" ] && [ -x "$install_root/bin/cargo" ] ||
    fail "no cached CargoFork for $os/$arch at $install_root"
  verify_cargo "$install_root/bin/cargo" ||
    fail "cached CargoFork at $install_root is not release $RELEASE at full revision $REVISION for $arch/$os"
  expected_sha=$(metadata_sha "$install_root/metadata.json") ||
    fail "cached metadata at $install_root/metadata.json is incomplete or for a different pin"
  [ "$expected_sha" = "$verified_sha" ] ||
    fail "cached CargoFork SHA-256 does not match its metadata"
  mkdir -p -- "$cache_dir/bin"
  ln -sfn "$install_root/bin/cargo" "$resolved"
  if [ "$require_path" = 1 ]; then
    path_cargo=$(command -v cargo 2>/dev/null || true)
    [ -n "$path_cargo" ] || fail "cargo is not on PATH"
    [ "$path_cargo" -ef "$resolved" ] ||
      fail "PATH cargo ($path_cargo) is not the pinned fork ($resolved)"
  fi
  source=verified
fi

if [ -n "$record" ]; then
  record=$(absolute_file "$record") || fail "could not resolve --record"
  if [ "$record" != "$install_root/metadata.json" ]; then
    mkdir -p -- "$(dirname -- "$record")"
    cp -- "$install_root/metadata.json" "$record"
  fi
  chmod 0644 "$record" 2>/dev/null || true
fi

if [ "$github" = 1 ]; then
  if [ -n "${GITHUB_ENV:-}" ]; then
    {
      printf 'CARGO_FORK_BIN=%s\n' "$resolved"
      printf 'CARGO_FORK_REVISION=%s\n' "$REVISION"
      printf 'CARGO_FORK_RELEASE=%s\n' "$RELEASE"
      printf 'CARGO_FORK_SHA256=%s\n' "$verified_sha"
      printf 'CARGO_FORK_CACHE_DIR=%s\n' "$cache_dir"
      printf 'CARGO_FORK_CACHE_KEY=%s\n' "$key"
      printf 'CARGO_FORK_AUTO_UPDATE=0\n'
    } >>"$GITHUB_ENV"
  fi
  if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$cache_dir/bin" >>"$GITHUB_PATH"
  fi
fi

export CARGO_FORK_AUTO_UPDATE=0
note "source=$source path=$resolved"
note "version=$verified_full_version"
note "revision=$verified_commit release=$verified_release host=$verified_host"
note "binary_sha256=$verified_sha cache_key=$key"
if [ -n "$record" ]; then
  note "record=$record"
fi
