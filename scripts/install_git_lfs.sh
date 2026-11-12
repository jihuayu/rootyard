#!/usr/bin/env bash
# Fetch, checksum-verify and install the pinned Git LFS client.
#
# The official release asset is a tarball whose only top-level directory is
# git-lfs-<version>/ (for 3.6.1 it contains git-lfs-3.6.1/git-lfs). We strip
# that directory, install the binary and check its reported version. The
# expected SHA-256 comes from the official release sha256sums.asc asset (plus
# an optional caller-pinned --expected-sha256), not from the downloaded tarball
# alone; an unavailable, unsigned-tail or ambiguous checksum entry is a hard
# failure rather than an unverified install.
set -euo pipefail

version="3.6.1"
destination=""
work=""
sha_output=""
archive=""
checksums=""
checksums_url=""
base_url=""
expected_sha256=""

usage() {
  cat <<'USAGE'
usage: scripts/install_git_lfs.sh --destination DIR --work DIR [--version 3.6.1] \
           [--sha-output FILE] [--archive TARBALL --checksums SHA256SUMS] \
           [--base-url URL] [--checksums-url URL] [--expected-sha256 HEX64]
USAGE
}

fail() {
  echo "install git lfs: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --destination) destination="${2:-}"; shift 2 ;;
    --work) work="${2:-}"; shift 2 ;;
    --sha-output) sha_output="${2:-}"; shift 2 ;;
    --archive) archive="${2:-}"; shift 2 ;;
    --checksums) checksums="${2:-}"; shift 2 ;;
    --base-url) base_url="${2:-}"; shift 2 ;;
    --checksums-url) checksums_url="${2:-}"; shift 2 ;;
    --expected-sha256) expected_sha256="${2:-}"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[ -n "$destination" ] || fail "--destination is required"
[ -n "$work" ] || fail "--work is required"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version must be exact x.y.z, got $version"
if [ -n "$expected_sha256" ] && [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  fail "--expected-sha256 must be a lowercase 64-hex digest"
fi
mkdir -p -- "$destination" "$work"
work=$(cd "$work" && pwd)
destination=$(cd "$destination" && pwd)
archive_name="git-lfs-linux-amd64-v${version}.tar.gz"
base_url="${base_url:-https://github.com/git-lfs/git-lfs/releases/download/v${version}}"
if [ -z "$archive" ]; then
  archive="$work/$archive_name"
  curl -fsSL --retry 3 -o "$archive" "$base_url/$archive_name" \
    || fail "cannot download the official $archive_name"
fi
[ -f "$archive" ] || fail "archive is missing: $archive"
if [ -z "$checksums" ]; then
  checksums="$work/sha256sums.asc"
  checksums_url="${checksums_url:-$base_url/sha256sums.asc}"
  curl -fsSL --retry 3 -o "$checksums" "$checksums_url" \
    || fail "cannot download the official checksums asset $checksums_url"
fi
[ -f "$checksums" ] || fail "checksums file is missing: $checksums"

expected=$(awk -v name="$archive_name" '
  {
    sub(/\r$/, "")
  }
  NR == 1 && $0 == "-----BEGIN PGP SIGNED MESSAGE-----" {
    pgp_mode = 1
    in_headers = 1
    next
  }
  !pgp_mode && /^-----BEGIN PGP/ {
    bad++
    next
  }
  pgp_mode && in_headers {
    if ($0 == "") {
      in_headers = 0
      saw_body = 1
    }
    next
  }
  pgp_mode && !saw_sig && $0 == "-----BEGIN PGP SIGNATURE-----" {
    saw_sig = 1
    in_sig = 1
    next
  }
  pgp_mode && in_sig {
    if ($0 == "-----END PGP SIGNATURE-----") {
      in_sig = 0
      saw_end_sig = 1
      after_sig = 1
    }
    next
  }
  pgp_mode && after_sig {
    if ($0 != "") {
      bad++
    }
    next
  }
  $0 == "" {
    next
  }
  {
    mentions_target = 0
    for (i = 2; i <= NF; i++) {
      if ($i == name || $i == "*" name) {
        mentions_target = 1
      }
    }
    if (NF == 2 && $1 ~ /^[0-9a-f]{64}$/ && ($2 == name || $2 == "*" name)) {
      hash = $1
      found++
    } else if (mentions_target) {
      bad++
    }
  }
  END {
    if (pgp_mode && (!saw_body || !saw_sig || !saw_end_sig || in_sig)) {
      exit 4
    }
    if (bad != 0) {
      exit 5
    }
    if (found != 1) {
      exit (found == 0 ? 2 : 3)
    }
    print hash
  }
' "$checksums") || fail "official checksums do not contain exactly one entry for $archive_name"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "official checksum for $archive_name is malformed"
if [ -n "$expected_sha256" ] && [ "$expected" != "$expected_sha256" ]; then
  fail "official checksum $expected does not match pinned --expected-sha256 $expected_sha256"
fi
actual=$(sha256sum "$archive" | awk '{print $1}')
[ "$actual" = "$expected" ] || fail "$archive_name sha256 $actual does not match the official $expected"

extract="$work/extract"
rm -rf -- "$extract"
mkdir -p -- "$extract"
tar -xzf "$archive" -C "$extract" --strip-components=1 \
  || fail "$archive_name does not contain the expected top-level directory"
[ -f "$extract/git-lfs" ] || fail "$archive_name did not yield a top-level git-lfs binary after stripping"
install -m 0755 "$extract/git-lfs" "$destination/git-lfs"
"$destination/git-lfs" version | grep -F "git-lfs/${version}" \
  || fail "installed git-lfs does not report git-lfs/${version}"
if [ -n "$sha_output" ]; then
  printf '%s\n' "$actual" >"$sha_output"
  chmod 600 "$sha_output"
fi
echo "verified git-lfs ${version} from official sha256 ${actual}"
