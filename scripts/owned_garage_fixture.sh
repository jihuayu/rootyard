#!/usr/bin/env bash
# Start or stop the job-owned Garage 2.1 S3 fixture for the candidate release gate.
#
# Ownership is proven, not assumed: the tool creates a private fixture directory,
# writes a 0600 sentinel bound to the canonical path, uid, unique nonce and
# container id, and labels the container with the same nonce/path/uid. Stop
# refuses to remove anything unless every one of those still matches. A name or
# a path supplied by a caller is never enough.
set -euo pipefail

image="dxflrs/garage:v2.1.0@sha256:4c9b34c113e61358466e83fd6e7d66e6d18657ede14b776eb78a93ee8da7cf6a"
expected_digest="sha256:4c9b34c113e61358466e83fd6e7d66e6d18657ede14b776eb78a93ee8da7cf6a"
directory=""
output=""
region="garage"
port="3900"
bucket_prefix="rootyard-ci"
sentinel_name=".rootyard-owned-fixture"

usage() {
  cat <<'USAGE'
usage: scripts/owned_garage_fixture.sh start --directory DIR --output-env FILE \
           [--image IMAGE] [--port 3900] [--bucket-prefix rootyard-ci] [--region garage]
       scripts/owned_garage_fixture.sh stop --directory DIR
USAGE
}

fail() {
  echo "owned garage fixture: $*" >&2
  exit 1
}

# Start-failure state is script-scoped, never `local`: the EXIT trap can run
# after start()'s frame has unwound, where function-local values are gone.
rootyard_fixture_owned=0

on_start_exit() {
  local status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ "${rootyard_fixture_owned:-0}" = "1" ]; then
    stop >/dev/null 2>&1 || true
  fi
  exit "$status"
}

# Extract one "Label: value" field from Garage's aligned key table. Every
# leading and trailing blank is stripped; a blank left inside the value makes
# the character check reject it instead of silently gluing the fragments.
key_table_field() {
  local label=$1 text=$2 line
  while IFS= read -r line; do
    if [[ "$line" == "$label:"* ]]; then
      line=${line#"$label:"}
      line=${line#"${line%%[![:space:]]*}"}
      line=${line%"${line##*[![:space:]]}"}
      printf '%s' "$line"
      return 0
    fi
  done <<<"$text"
}

# Validate a parsed credential without ever echoing it.
check_credential() {
  local label=$1 value=$2 minimum=$3 maximum=$4 length
  [ -n "$value" ] || fail "Garage key creation returned no $label"
  [[ "$value" =~ ^[A-Za-z0-9+/=_.-]+$ ]] \
    || fail "Garage key creation returned a $label with unexpected characters"
  length=${#value}
  [ "$length" -ge "$minimum" ] && [ "$length" -le "$maximum" ] \
    || fail "Garage key creation returned a $label of unexpected length $length"
}

# Print a canonical absolute path, rejecting root/ancestor/symlink paths. The
# canonical form is what gets written into the sentinel and container labels.
canonical_fixture_path() {
  python3 - "$1" <<'PY'
import os
import sys

raw = sys.argv[1]
if not raw or not os.path.isabs(raw):
    sys.exit("owned garage fixture: fixture path must be a non-empty absolute path")
path = os.path.abspath(raw)
if path == os.sep:
    sys.exit("owned garage fixture: refusing the filesystem root as a fixture path")
parts = [part for part in path.split(os.sep) if part]
if len(parts) < 2:
    sys.exit("owned garage fixture: fixture path is too shallow to own safely")
current = os.sep
for part in parts:
    current = os.path.join(current, part)
    if os.path.islink(current):
        sys.exit(f"owned garage fixture: refusing symlink component {current}")
forbidden = ["/tmp", "/var", "/home", "/usr", "/etc", "/root", "/opt", "/boot",
             "/dev", "/proc", "/sys", "/run", "/srv", "/mnt", "/media"]
for name, value in (("HOME", os.environ.get("HOME")), ("PWD", os.environ.get("PWD")),
                    ("GITHUB_WORKSPACE", os.environ.get("GITHUB_WORKSPACE")),
                    ("RUNNER_TEMP", os.environ.get("RUNNER_TEMP")),
                    ("TMPDIR", os.environ.get("TMPDIR"))):
    if value:
        forbidden.append(os.path.abspath(value))
for item in forbidden:
    if path == item or item.startswith(path + os.sep):
        sys.exit(f"owned garage fixture: refusing fixture path {path}; it owns or equals {item}")
print(path)
PY
}

sentinel_value() {
  sed -n "s/^$1=//p" "$2" | head -n 1
}

owned_file() {
  local file=$1 label=$2
  [ -e "$file" ] || return 0
  [ -L "$file" ] && fail "$label is a symlink; refusing to touch it"
  [ -f "$file" ] || fail "$label is not a regular file; refusing to touch it"
  [ "$(stat -c %u "$file")" = "$(id -u)" ] || fail "$label is not owned by uid $(id -u)"
  local mode
  mode=$(stat -c %a "$file")
  (( (8#$mode & 077) == 0 )) || fail "$label mode $mode exposes group/world access"
}

remove_owned_output() {
  local file=$1
  [ -n "$file" ] || return 0
  [ -e "$file" ] || return 0
  owned_file "$file" "recorded credential file"
  rm -f -- "$file"
}

verify_owned_container() {
  local cid=$1 nonce=$2
  local actual kind label_nonce label_path label_uid label_name
  actual=$(docker inspect --type container --format '{{.Id}}' "$cid" 2>/dev/null) \
    || fail "sentinel container $cid is absent or unreadable; refusing cleanup"
  [ "$actual" = "$cid" ] || fail "sentinel container id $cid resolved to $actual; refusing cleanup"
  kind=$(docker inspect --type container --format '{{index .Config.Labels "rootyard.fixture.kind"}}' "$cid" 2>/dev/null || true)
  label_nonce=$(docker inspect --type container --format '{{index .Config.Labels "rootyard.fixture.nonce"}}' "$cid" 2>/dev/null || true)
  label_path=$(docker inspect --type container --format '{{index .Config.Labels "rootyard.fixture.directory"}}' "$cid" 2>/dev/null || true)
  label_uid=$(docker inspect --type container --format '{{index .Config.Labels "rootyard.fixture.uid"}}' "$cid" 2>/dev/null || true)
  label_name=$(docker inspect --type container --format '{{index .Config.Labels "rootyard.fixture.name"}}' "$cid" 2>/dev/null || true)
  [ "$kind" = "owned-garage" ] || fail "container $cid lacks the owned-fixture label; refusing cleanup"
  [ "$label_nonce" = "$nonce" ] || fail "container $cid nonce does not match the sentinel; refusing cleanup"
  [ "$label_path" = "$directory" ] || fail "container $cid path does not match the sentinel; refusing cleanup"
  [ "$label_uid" = "$(id -u)" ] || fail "container $cid uid does not match; refusing cleanup"
  [ "$label_name" = "$(sentinel_value container_name "$sentinel")" ] \
    || fail "container $cid name does not match the sentinel; refusing cleanup"
}

stop() {
  [ -n "$directory" ] || fail "--directory is required"
  directory=$(canonical_fixture_path "$directory")
  if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
    return 0
  fi
  [ -L "$directory" ] && fail "refusing symlink fixture directory $directory"
  [ -d "$directory" ] || fail "fixture path $directory is not a directory"
  local sentinel="$directory/$sentinel_name"
  owned_file "$sentinel" "ownership sentinel"
  [ -f "$sentinel" ] || fail "refusing non-owned directory $directory: no ownership sentinel"
  [ "$(sentinel_value kind "$sentinel")" = "rootyard-owned-garage-fixture" ] \
    || fail "refusing $directory: sentinel kind is not an owned Garage fixture"
  [ "$(sentinel_value directory "$sentinel")" = "$directory" ] \
    || fail "refusing $directory: sentinel is bound to another path"
  [ "$(sentinel_value uid "$sentinel")" = "$(id -u)" ] \
    || fail "refusing $directory: sentinel belongs to another uid"
  local nonce cid env
  nonce=$(sentinel_value nonce "$sentinel")
  [ -n "$nonce" ] || fail "refusing $directory: sentinel has no unique nonce"
  cid=$(sentinel_value container_id "$sentinel")
  env=$(sentinel_value output_env "$sentinel")
  if [ -n "$cid" ]; then
    command -v docker >/dev/null 2>&1 || fail "docker is required to remove the owned container"
    verify_owned_container "$cid" "$nonce"
    docker rm -f -- "$cid" >/dev/null || fail "docker could not remove owned container $cid"
  fi
  remove_owned_output "$env"
  rm -rf -- "$directory"
}

write_sentinel() {
  local cid=$1 name=$2 nonce=$3
  local tmp="$directory/${sentinel_name}.tmp"
  umask 077
  {
    printf 'kind=rootyard-owned-garage-fixture\n'
    printf 'version=1\n'
    printf 'directory=%s\n' "$directory"
    printf 'uid=%s\n' "$(id -u)"
    printf 'nonce=%s\n' "$nonce"
    printf 'container_id=%s\n' "$cid"
    printf 'container_name=%s\n' "$name"
    printf 'output_env=%s\n' "$output"
  } >"$tmp"
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$directory/$sentinel_name"
}

start() {
  command -v docker >/dev/null 2>&1 || fail "docker is required to run the owned Garage 2.1 fixture"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required to generate the fixture secrets"
  [ -n "$image" ] || fail "--image is required"
  [ -n "$directory" ] || fail "--directory is required"
  [ -n "$output" ] || fail "--output-env is required"
  directory=$(canonical_fixture_path "$directory")
  output=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$output")
  [ -n "$output" ] || fail "--output-env resolved to an empty path"
  [ ! -e "$output" ] && [ ! -L "$output" ] \
    || fail "refusing to overwrite an existing file at $output"
  case "$output/" in
    "$directory/"*) fail "credential env file must live outside the owned fixture directory" ;;
  esac
  if [ -e "$directory" ] || [ -L "$directory" ]; then
    [ -L "$directory" ] && fail "refusing symlink fixture directory $directory"
    [ -d "$directory" ] || fail "fixture path exists and is not a directory"
    [ -z "$(find "$directory" -mindepth 1 -maxdepth 1 -print -quit)" ] \
      || fail "refusing preexisting non-empty fixture directory $directory"
  fi
  mkdir -p -- "$directory"
  chmod 700 "$directory"
  local nonce uid name sentinel
  sentinel="$directory/$sentinel_name"
  nonce=$(openssl rand -hex 16)
  uid=$(id -u)
  name="rootyard-owned-garage-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${nonce:0:12}"
  write_sentinel "" "$name" "$nonce"
  rootyard_fixture_owned=1
  trap on_start_exit EXIT
  local image_id repo_digests version_line
  image_id=$(docker image inspect --format '{{.Id}}' "$image") \
    || fail "cannot inspect $image"
  repo_digests=$(docker image inspect --format '{{join .RepoDigests "\n"}}' "$image")
  printf '%s\n' "$repo_digests" | grep -Fxq "dxflrs/garage@${expected_digest}" \
    || fail "image $image does not carry the required digest ${expected_digest}"
  # The real Garage 2.1.0 image prints "garage v2.1.0 [features: ...]".
  version_line=$(docker run --rm "$image" /garage --version) || fail "cannot execute $image"
  if [[ ! "$version_line" =~ ^garage[[:space:]]v2\.1\.0([[:space:]]\[features:.*\])?$ ]]; then
    fail "image $image is not exactly Garage 2.1.0: $version_line"
  fi

  if [ ! -s "$directory/garage.toml" ]; then
    (
      umask 077
      cat >"$directory/garage.toml" <<TOML
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1

rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "$(openssl rand -hex 32)"

[s3_api]
s3_region = "$region"
api_bind_addr = "[::]:3900"
root_domain = ".s3.garage.localhost"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "$(openssl rand -hex 32)"
metrics_token = "$(openssl rand -hex 32)"
TOML
    )
  fi
  chmod 600 "$directory/garage.toml"
  mkdir -p "$directory/meta" "$directory/data"

  local container_id
  container_id=$(docker create --rm \
    --name "$name" \
    --label "rootyard.fixture.kind=owned-garage" \
    --label "rootyard.fixture.nonce=$nonce" \
    --label "rootyard.fixture.directory=$directory" \
    --label "rootyard.fixture.uid=$uid" \
    --label "rootyard.fixture.name=$name" \
    --user "$(id -u):$(id -g)" \
    -p "127.0.0.1:${port}:3900" \
    -v "$directory/garage.toml:/etc/garage.toml:ro" \
    -v "$directory:/var/lib/garage" \
    "$image")
  write_sentinel "$container_id" "$name" "$nonce"
  verify_owned_container "$container_id" "$nonce"
  docker start "$container_id" >/dev/null

  local garage=(docker exec "$container_id" /garage -c /etc/garage.toml)
  local node="" line deadline=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$deadline" ]; do
    line=$("${garage[@]}" node id 2>/dev/null | head -n 1 || true)
    if [[ "$line" =~ ^([0-9a-f]{64})@[^[:space:]]+$ ]]; then
      node=${BASH_REMATCH[1]}
      break
    fi
    sleep 1
  done
  [ -n "$node" ] || fail "Garage did not report a 64-hex node id from 'garage node id' within 60s"

  "${garage[@]}" layout assign -z dc1 -c 1G "$node" >/dev/null
  "${garage[@]}" layout apply --version 1 >/dev/null

  local key_name="rootyard-ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${nonce:0:12}"
  local bucket="${bucket_prefix}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${nonce:0:8}"
  local created access secret
  # Garage 2.1.0 `key create NAME` prints an aligned table, so a naive prefix
  # strip keeps the column padding and the S3 client then signs with a padded
  # key id (the 400 "0 matching keys" failure). The raw output is never shown.
  created=$("${garage[@]}" key create "$key_name")
  access=$(key_table_field "Key ID" "$created")
  secret=$(key_table_field "Secret key" "$created")
  check_credential "access key id" "$access" 16 128
  check_credential "secret key" "$secret" 32 256
  [ "$access" != "$secret" ] || fail "Garage key creation returned one value for both credentials"

  "${garage[@]}" bucket create "$bucket" >/dev/null
  "${garage[@]}" bucket allow --read --write --owner --key "$access" "$bucket" >/dev/null

  local probe_timeout="${ROOTYARD_FIXTURE_PROBE_TIMEOUT:-60}"
  case "$probe_timeout" in
    '' | *[!0-9]*) fail "ROOTYARD_FIXTURE_PROBE_TIMEOUT must be a whole number of seconds" ;;
  esac
  ROOTYARD_FIXTURE_ACCESS_KEY="$access" ROOTYARD_FIXTURE_SECRET_KEY="$secret" \
    python3 "$(dirname "$0")/owned_object_store_env.py" \
      --output "$output" \
      --endpoint "http://127.0.0.1:${port}" \
      --bucket "$bucket" \
      --region "$region" \
      --require-bucket-prefix "${bucket_prefix}-" \
      --probe-timeout "$probe_timeout" \
      --summary "$directory/fixture-summary.json" >/dev/null

  python3 - "$directory/garage-image.json" "$image" "$image_id" "$expected_digest" "$version_line" <<'PY'
import json, sys
path, image, image_id, digest, version_line = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"image": image, "image_id": image_id, "image_digest": digest,
               "version": "2.1.0", "version_line": version_line}, stream,
              indent=2, sort_keys=True)
    stream.write("\n")
PY

  rootyard_fixture_owned=0
  trap - EXIT
  echo "owned garage fixture image: $image"
  echo "owned garage fixture image id: $image_id"
  echo "owned garage fixture image digest: $expected_digest"
  echo "owned garage fixture version: $version_line"
  echo "owned garage fixture endpoint: http://127.0.0.1:${port}"
  echo "owned garage fixture bucket: $bucket"
  echo "owned garage fixture env file: $output (mode $(stat -c %a "$output"))"
}

action="${1:-}"
[ $# -gt 0 ] && shift
case "$action" in
  start | stop) ;;
  *)
    usage
    exit 2
    ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    --directory) directory="${2:-}"; shift 2 ;;
    --image) image="${2:-}"; shift 2 ;;
    --output-env) output="${2:-}"; shift 2 ;;
    --region) region="${2:-}"; shift 2 ;;
    --port) port="${2:-}"; shift 2 ;;
    --bucket-prefix) bucket_prefix="${2:-}"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

if [ "$action" = "start" ]; then
  start
else
  stop
fi
