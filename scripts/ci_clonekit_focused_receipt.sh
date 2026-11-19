#!/usr/bin/env bash
# Publish one bounded outcome for the focused CloneKit command group.
#
# The caller owns command execution and passes only a fixed group label, the
# resulting shell status and the receipt path. This helper never reads or
# writes command output, a test name, a token or a process argument.
set -u

readonly MAX_BYTES=192

fail() {
  printf '%s\n' "focused CloneKit receipt unavailable" >&2
  exit "$1"
}

if [ "$#" -ne 3 ]; then
  fail 2
fi

group=$1
status=$2
output=$3
sha=${GITHUB_SHA:-}

case "$sha" in
  *[!0-9a-f]*) fail 2 ;;
esac
[ "${#sha}" -eq 40 ] || fail 2

case "$status" in
  ''|*[!0-9]*) fail 2 ;;
esac
[ "${#status}" -le 3 ] || fail 2
status=$((10#$status))
[ "$status" -le 255 ] || fail 2

case "$group" in
  clippy)
    not_run='["lib","integration"]'
    ;;
  lib)
    not_run='["integration"]'
    ;;
  integration)
    not_run='[]'
    ;;
  *)
    fail 2
    ;;
esac

# A green status is only publishable after the last group ran. A non-zero
# status keeps the group where the shell stopped, so it is the first failure.
[ "$status" -ne 0 ] || [ "$group" = integration ] || fail 2
if [ "$status" -eq 0 ]; then
  first_failure=null
else
  first_failure=$(printf '"%s"' "$group") || fail 1
fi

payload=$(printf '{"version":1,"source_commit":"%s","first_failure":%s,"exit_code":%d,"not_run":%s}' \
  "$sha" "$first_failure" "$status" "$not_run") || fail 1
[ "${#payload}" -le "$MAX_BYTES" ] || fail 1

[ -n "$output" ] || fail 2
[ ! -d "$output" ] || fail 1
directory=$(dirname -- "$output") || fail 1
mkdir -p -- "$directory" 2>/dev/null || fail 1
temporary=$(mktemp "$directory/.focused-receipt.XXXXXX" 2>/dev/null) || fail 1
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT

printf '%s\n' "$payload" >"$temporary" 2>/dev/null || fail 1
mv -f -- "$temporary" "$output" 2>/dev/null || fail 1
trap - EXIT
exit 0
