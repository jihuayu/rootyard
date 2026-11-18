#!/usr/bin/env bash
# Project the focused CloneKit integration outcome into one bounded receipt.
#
# The caller runs the exact `cargo test --locked --test ci_clonekit` argv once and
# pipes its combined output here.  Every input line is echoed unchanged so the
# original command diagnostics and exit status are preserved.  Only closed case,
# phase, class and numeric count tokens are written to the fixed receipt; no raw
# command output, test name, path, panic text or error payload is retained.
set -u

readonly MAX_BYTES=384
readonly CLASSES='ASSERT PANIC OTHER INVALID_CONFIG INVALID_INPUT UNAUTHORIZED GRANT_EXPIRED GRANT_REVOKED CROSS_TENANT_DENIED MISSING_KIT EMPTY_REPOSITORY STALE_GENERATION HISTORY_CHANGED CORRUPT_ARTIFACT FOREIGN_BACKEND INCOMPLETE_CLOSURE DEPENDENCY_CHECK_FAILED PIN_PROTECTION_ACTIVE TRANSFER_CANCELLED GIT_FAILED BLOB_FAILED DATABASE_FAILED'

unavailable() {
  printf '%s\n' "integration CloneKit projection unavailable" >&2
}

if [ "$#" -eq 1 ]; then
  output=$1
else
  output=
  unavailable
fi
sha=${GITHUB_SHA:-}
case "$sha" in
  *[!0-9a-f]*) sha_ok=0 ;;
  *) [ "${#sha}" -eq 40 ] && sha_ok=1 || sha_ok=0 ;;
esac

phase=
class=
case_id=
passed=
failed=
ignored=
saw_failure=0

canonical_case() {
  case "$1" in
    clonekit_sha1_and_sha256_incremental_smart_http_and_anti_stale_tip) printf 'SMART_HTTP' ;;
    clonekit_failed_build_empty_repo_and_history_rotation_preserve_last_valid) printf 'EMPTY_HISTORY' ;;
    clonekit_fail_closed_auth_revocation_cancel_gc_pin_and_dependencies) printf 'FAIL_CLOSED_AUTH' ;;
    *) printf 'OTHER' ;;
  esac
}

canonical_phase() {
  case "$1" in
    SETUP|EMPTY_BUILD_OR_STATUS|ACTIVE_BUILD|CORRUPT_BUILD|CORRUPT_PUBLICATION_PRESERVES_LATEST|HISTORY_GRANT|HISTORY_CHECKOUT|HISTORY_STRATEGY) printf '%s' "$1" ;;
    *) printf 'OTHER' ;;
  esac
}

canonical_class() {
  case " $CLASSES " in
    *" $1 "*) printf '%s' "$1" ;;
    *) printf 'OTHER' ;;
  esac
}

bounded_count() {
  case "$1" in
    ''|*[!0-9]*) printf '' ;;
    *) [ "${#1}" -le 3 ] && printf '%s' "$1" || printf '' ;;
  esac
}

note_case() {
  [ -n "$case_id" ] || case_id=$1
}

while IFS= read -r line || [ -n "$line" ]; do
  printf '%s\n' "$line"

  case "$line" in
    "test "*" ... FAILED")
      name=${line#test }
      name=${name%% *}
      saw_failure=1
      note_case "$(canonical_case "$name")"
      ;;
    "ISSUE182_EMPTY_HISTORY "*)
      saw_failure=1
      rest=${line#ISSUE182_EMPTY_HISTORY }
      token=${rest%% *}
      rest=${rest#* }
      class_token=${rest%% *}
      case "$token" in
        phase=*) [ -n "$phase" ] || phase=$(canonical_phase "${token#phase=}") ;;
      esac
      case "$class_token" in
        class=*) [ -n "$class" ] || class=$(canonical_class "${class_token#class=}") ;;
      esac
      case_id=EMPTY_HISTORY
      ;;
    "test result: FAILED."*)
      saw_failure=1
      rest=${line#test result: FAILED. }
      first=${rest%%;*}
      rest=${rest#*; }
      second=${rest%%;*}
      rest=${rest#*; }
      third=${rest%%;*}
      passed=$(bounded_count "${first%% *}")
      failed=$(bounded_count "${second%% *}")
      ignored=$(bounded_count "${third%% *}")
      ;;
  esac
done

if [ "$saw_failure" -eq 0 ]; then
  exit 0
fi
if [ "$sha_ok" -ne 1 ] || [ -z "$output" ] || [ -d "$output" ]; then
  unavailable
  exit 0
fi

[ -n "$case_id" ] || case_id=OTHER
if [ -n "$phase" ]; then phase_json="\"$phase\""; else phase_json=null; fi
if [ -n "$class" ]; then class_json="\"$class\""; else class_json=null; fi
passed_json=${passed:-null}
failed_json=${failed:-null}
ignored_json=${ignored:-null}
payload=$(printf '{"version":1,"source_commit":"%s","case":"%s","phase":%s,"class":%s,"counts":{"passed":%s,"failed":%s,"ignored":%s}}' \
  "$sha" "$case_id" "$phase_json" "$class_json" "$passed_json" "$failed_json" "$ignored_json") || {
  unavailable
  exit 0
}
[ "${#payload}" -le "$MAX_BYTES" ] || {
  unavailable
  exit 0
}

directory=${output%/*}
[ "$directory" = "$output" ] && directory=.
mkdir -p -- "$directory" 2>/dev/null || {
  unavailable
  exit 0
}
temporary=
cleanup() {
  [ -z "$temporary" ] || rm -f -- "$temporary"
}
trap cleanup EXIT
temporary=$(mktemp "$directory/.integration-receipt.XXXXXX" 2>/dev/null) || {
  temporary=
  unavailable
  exit 0
}
printf '%s\n' "$payload" >"$temporary" 2>/dev/null || {
  unavailable
  exit 0
}
mv -f -- "$temporary" "$output" 2>/dev/null || {
  unavailable
  exit 0
}
temporary=
exit 0
