#!/usr/bin/env bash
# Build the already-proven bubblewrap source revision into an owned prefix.
#
# Ubuntu 22.04 ships bubblewrap 0.6.1, which predates `--size`. The production
# runtime bounds /tmp and /workspace with `--size BYTES --tmpfs DEST`, and the
# manual native-kernel-acceptance workflow proved that source version
# 0.9.0-1build1 from the signed Ubuntu Noble archive implements it. This helper
# reuses exactly that source pin and signed index, installs only into the owned
# RUNNER_TEMP prefix (never /usr/local or /usr/bin), and finally proves the
# capability functionally instead of parsing a version string.
set -euo pipefail

helper_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$helper_dir/lib.sh"

usage() {
  cat <<'USAGE'
usage: build_bubblewrap_source.sh --prefix DIR --state-dir DIR --work DIR
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
mkdir -p -- "$prefix/bin"

prepare_ubuntu_archive_source

apt_install dpkg-dev libc6-dev libcap-dev meson ninja-build pkg-config

pin=0.9.0-1build1
available=$(source_versions bubblewrap)
log "signed Ubuntu Noble bubblewrap source versions: $(printf '%s' "$available" | tr '\n' ' ')"
case " $(printf '%s' "$available" | tr '\n' ' ') " in
  *" $pin "*)
    log "selected bubblewrap source revision: $pin (same pin as native-kernel-acceptance)"
    ;;
  *)
    fail "pinned bubblewrap source $pin is not offered by the signed Noble index; available: $(printf '%s' "$available" | tr '\n' ' ')"
    ;;
esac

fetch_source bubblewrap "$pin" "$work"
source_dir=$(find_source_directory "$work" bubblewrap)
[ -n "$source_dir" ] || fail "apt-get source did not extract a bubblewrap-* source directory"
record_source_provenance bubblewrap bubblewrap "$pin" "$work" "$source_dir" "$state_dir"

(cd "$source_dir" && meson setup _build --prefix="$prefix")
(cd "$source_dir" && ninja -C _build)
(cd "$source_dir" && ninja -C _build install)

bwrap_bin="$prefix/bin/bwrap"
[ -x "$bwrap_bin" ] || fail "bubblewrap install did not produce $bwrap_bin"
reported=$("$bwrap_bin" --version)
log "installed bubblewrap: $reported"

# Functional capability probe: version parsing is not evidence. The same probe
# the native-kernel workflow uses binds the host root read-only for /bin/true
# and asks for a bounded tmpfs exactly as the production runner does.
"$bwrap_bin" --unshare-all --die-with-parent --ro-bind / / \
  --size 1048576 --tmpfs /tmp -- /bin/true

record_built_binary "$state_dir/bubblewrap.json" "$bwrap_bin" "$reported" \
  "meson setup --prefix=$prefix; ninja -C _build; ninja -C _build install" \
  "source=Ubuntu Noble signed archive bubblewrap=$pin" \
  "probe=bwrap --unshare-all --die-with-parent --ro-bind / / --size 1048576 --tmpfs /tmp -- /bin/true"
