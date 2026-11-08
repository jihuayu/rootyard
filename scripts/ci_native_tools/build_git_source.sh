#!/usr/bin/env bash
# Build a Git 2.43.x client from the signed Ubuntu Noble source archive.
#
# Ubuntu 22.04 ships Git 2.34 while workspace_lab, mirror and pando_lab refuse
# anything below 2.43. The Noble archive is the first signed Ubuntu index with
# the required series; only its deb-src entries are enabled, so no Noble binary
# package or library is installed. The newest 2.43.x security revision offered
# by the signed index is selected, every .dsc Checksums-Sha256 entry is
# re-verified, and the exact source package version and source-file digests are
# recorded in the provenance state directory.
#
# The build installs into an owned RUNNER_TEMP prefix. It never replaces
# /usr/bin/git, never runs `git config --global` and never changes system Git
# configuration; the workflow only prepends the prefix to GITHUB_PATH.
set -euo pipefail

helper_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$helper_dir/lib.sh"

usage() {
  cat <<'USAGE'
usage: build_git_source.sh --prefix DIR --state-dir DIR --work DIR
USAGE
}

prefix=""
state_dir=""
work=""

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix=${2:-}; shift 2 ;;
    --state-dir) state_dir=${2:-}; shift 2 ;;
    --work) work=${2:-}; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[ -n "$prefix" ] || fail "--prefix is required"
[ -n "$state_dir" ] || fail "--state-dir is required"
[ -n "$work" ] || fail "--work is required"
[ "$(id -u)" != 0 ] ||
  fail "run as the unprivileged runner account; builds must land in the owned prefix"
require_command sudo
require_command dpkg-parsechangelog

prefix=$(resolve_absolute "$prefix")
state_dir=$(resolve_absolute "$state_dir")
work=$(resolve_absolute "$work")
mkdir -p -- "$prefix/bin" "$prefix/libexec"

prepare_ubuntu_archive_source

# Standalone use still needs these; the apt helper installs the same set.
apt_install \
  dpkg-dev libc6-dev libssl-dev libcurl4-openssl-dev libexpat1-dev \
  zlib1g-dev gettext autoconf gcc make

available=$(source_versions git)
log "signed Ubuntu Noble git source versions: $(printf '%s' "$available" | tr '\n' ' ')"
version=$(latest_matching_source git '^(1:)?2\.43\.[0-9]+-')
if [ -z "$version" ]; then
  fail "the signed Noble index offers no Git 2.43 source; available: $(printf '%s' "$available" | tr '\n' ' ')"
fi
log "selected Git 2.43 source revision: $version"

fetch_source git "$version" "$work"
source_dir=$(find_source_directory "$work" git)
[ -n "$source_dir" ] || fail "apt-get source did not extract a git-* source directory"
record_source_provenance git git "$version" "$work" "$source_dir" "$state_dir"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2\n')
case "$jobs" in
  '' | *[!0-9]*) jobs=2 ;;
esac

make_args=(
  "prefix=$prefix"
  NO_TCLTK=1
  NO_GETTEXT=1
  NO_INSTALL_HARDLINKS=1
)
# Release and Debian orig tarballs ship ./configure; fall back to the
# repository's autoconf path if a future revision drops it.
if [ ! -x "$source_dir/configure" ]; then
  (cd "$source_dir" && make configure)
fi
(cd "$source_dir" && make -j"$jobs" "${make_args[@]}" all)
(cd "$source_dir" && make "${make_args[@]}" install)

git_bin="$prefix/bin/git"
[ -x "$git_bin" ] || fail "Git install did not produce $git_bin"
reported=$("$git_bin" --version)
log "installed Git: $reported"
require_git_243 "$git_bin"

probe=$(mktemp -d "${TMPDIR:-/tmp}/rootyard-git-probe.XXXXXX")
trap 'rm -rf -- "$probe"' EXIT
"$git_bin" init --quiet "$probe"
[ -f "$probe/.git/HEAD" ] || fail "the installed Git cannot initialise a repository"
"$git_bin" -C "$probe" rev-parse --git-dir >/dev/null

record_built_binary "$state_dir/git.json" "$git_bin" "$reported" \
  "make -j$jobs NO_TCLTK=1 NO_GETTEXT=1 NO_INSTALL_HARDLINKS=1 prefix=$prefix" \
  "source=Ubuntu Noble signed archive git=$version"
