#!/usr/bin/env bash
# Publish bounded evidence for the live PostgreSQL 17 / Garage CloneKit case.
#
# Two independent records cover the whole step and never consume raw output into a
# receipt:
#   * `stage` is called from the workflow's single EXIT trap and records which shell
#     stage was current (`env_setup`, `cargo_test`, `complete`) plus the exact
#     GITHUB_SHA and repository checkout commit/tree;
#   * `project` reads the live cargo/test output, echoes it unchanged, and records
#     only the fixed typed marker's closed phase/class when the Rust fixture emits it.
# A missing or malformed marker is not guessed from unrelated text.
set -u

readonly MAX_BYTES=512
readonly PHASES='SETUP SCHEMA MIGRATE BLOB_OPEN SEED CORE_INIT OPERATION_REGISTER BUILD_KIT PUBLISH READINESS JOB_INSERT CHECKOUT ACTIVE_HOLDS REVOCATION DENIED_REPLAY TEARDOWN'
readonly CLASSES='ASSERT PANIC OTHER INVALID_CONFIG INVALID_INPUT UNAUTHORIZED GRANT_EXPIRED GRANT_REVOKED CROSS_TENANT_DENIED MISSING_KIT EMPTY_REPOSITORY STALE_GENERATION HISTORY_CHANGED CORRUPT_ARTIFACT FOREIGN_BACKEND INCOMPLETE_CLOSURE DEPENDENCY_CHECK_FAILED PIN_PROTECTION_ACTIVE TRANSFER_CANCELLED GIT_FAILED BLOB_FAILED DATABASE_FAILED'

unavailable() {
  printf '%s\n' "live CloneKit evidence unavailable" >&2
}

rust_unavailable() {
  printf '%s\n' "live CloneKit rust phase unavailable" >&2
}

fail() {
  unavailable
  exit "$1"
}

valid_sha() {
  case "$1" in
    ''|*[!0-9a-f]*) return 1 ;;
  esac
  [ "${#1}" -eq 40 ]
}

canonical_phase() {
  case " $PHASES " in
    *" $1 "*) printf '%s' "$1" ;;
    *) printf 'OTHER' ;;
  esac
}

canonical_class() {
  case " $CLASSES " in
    *" $1 "*) printf '%s' "$1" ;;
    *) printf 'OTHER' ;;
  esac
}

write_receipt() {
  payload=$1
  output=$2
  [ -n "$output" ] || return 1
  [ ! -d "$output" ] || return 1
  [ "${#payload}" -le "$MAX_BYTES" ] || return 1
  directory=$(dirname -- "$output") || return 1
  mkdir -p -- "$directory" 2>/dev/null || return 1
  temporary=$(mktemp "$directory/.live-receipt.XXXXXX" 2>/dev/null) || return 1
  if ! printf '%s\n' "$payload" >"$temporary" 2>/dev/null; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! mv -f -- "$temporary" "$output" 2>/dev/null; then
    rm -f -- "$temporary"
    return 1
  fi
  return 0
}

if [ "$#" -eq 4 ] && [ "$1" = stage ]; then
  stage=$2
  status=$3
  output=$4

  case "$stage" in
    env_setup|cargo_test|complete) ;;
    *) fail 2 ;;
  esac
  case "$status" in
    ''|*[!0-9]*) fail 2 ;;
  esac
  [ "${#status}" -le 3 ] || fail 2
  status=$((10#$status))
  [ "$status" -le 255 ] || fail 2
  # A green status is only publishable after cargo ran to completion; any failure
  # before that keeps the exact shell stage where it stopped.
  if [ "$status" -eq 0 ]; then
    [ "$stage" = complete ] || fail 2
  else
    [ "$stage" != complete ] || fail 2
  fi

  source_commit=${GITHUB_SHA:-}
  valid_sha "$source_commit" || fail 2
  checkout_commit=$(git rev-parse HEAD 2>/dev/null) || checkout_commit=
  checkout_tree=$(git rev-parse 'HEAD^{tree}' 2>/dev/null) || checkout_tree=
  valid_sha "$checkout_commit" || fail 1
  valid_sha "$checkout_tree" || fail 1

  case "$stage" in
    env_setup) not_run='["cargo_test"]' ;;
    *) not_run='[]' ;;
  esac
  payload=$(printf '{"version":1,"case":"PG_GARAGE_DURABLE_HOLD","source_commit":"%s","checkout_commit":"%s","checkout_tree":"%s","stage":"%s","exit_code":%d,"not_run":%s}' \
    "$source_commit" "$checkout_commit" "$checkout_tree" "$stage" "$status" "$not_run") || fail 1
  write_receipt "$payload" "$output" || fail 1
  exit 0
fi

if [ "$#" -eq 2 ] && [ "$1" = project ]; then
  output=$2
  if [ -n "$output" ] && [ ! -d "$output" ]; then
    rm -f -- "$output" 2>/dev/null
  fi
  phase=
  class=
  saw=0
  while IFS= read -r line || [ -n "$line" ]; do
    printf '%s\n' "$line"

    case "$line" in
      "ISSUE182_LIVE_PG_GARAGE "*)
        saw=1
        rest=${line#ISSUE182_LIVE_PG_GARAGE }
        token=${rest%% *}
        rest=${rest#* }
        class_token=${rest%% *}
        if [ -z "$phase" ]; then
          case "$token" in
            phase=*) phase=$(canonical_phase "${token#phase=}") ;;
            *) phase=OTHER ;;
          esac
        fi
        if [ -z "$class" ]; then
          case "$class_token" in
            class=*) class=$(canonical_class "${class_token#class=}") ;;
            *) class=OTHER ;;
          esac
        fi
        ;;
    esac
  done

  [ "$saw" -eq 0 ] && exit 0
  [ -n "$phase" ] || phase=OTHER
  [ -n "$class" ] || class=OTHER

  source_commit=${GITHUB_SHA:-}
  checkout_commit=$(git rev-parse HEAD 2>/dev/null) || checkout_commit=
  checkout_tree=$(git rev-parse 'HEAD^{tree}' 2>/dev/null) || checkout_tree=
  if ! valid_sha "$source_commit" || ! valid_sha "$checkout_commit" || ! valid_sha "$checkout_tree"; then
    rust_unavailable
    exit 0
  fi
  payload=$(printf '{"version":1,"case":"PG_GARAGE_DURABLE_HOLD","source_commit":"%s","checkout_commit":"%s","checkout_tree":"%s","phase":"%s","class":"%s"}' \
    "$source_commit" "$checkout_commit" "$checkout_tree" "$phase" "$class") || {
    rust_unavailable
    exit 0
  }
  if ! write_receipt "$payload" "$output"; then
    rust_unavailable
  fi
  exit 0
fi

fail 2
