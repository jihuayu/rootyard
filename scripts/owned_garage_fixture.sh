#!/usr/bin/env bash
# Start or stop the job-owned Garage 2.1 S3 fixture for the candidate release gate.
#
# The fixture belongs to the current job: it creates its own pinned container,
# data directory, bucket and key, publishes the S3 API on loopback only, and
# hands the credential to scripts/owned_object_store_env.py through the
# environment. It never reads a user secret, an inherited ROOTYARD_OBJECT_STORE_*
# setting or another deployment's endpoint. The generated environment file is
# mode 0600 outside the checkout and is removed by the workflow cleanup step.
set -euo pipefail

image="dxflrs/garage:v2.1.0"
directory=""
output=""
region="garage"
port="3900"
bucket_prefix="rootyard-ci"

usage() {
  cat <<'USAGE'
usage: scripts/owned_garage_fixture.sh start --directory DIR --image IMAGE \
           --output-env FILE [--port 3900] [--bucket-prefix rootyard-ci] [--region garage]
       scripts/owned_garage_fixture.sh stop --directory DIR
USAGE
}

fail() {
  echo "owned garage fixture: $*" >&2
  exit 1
}

absolute() {
  python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$1"
}

container_name() {
  echo "rootyard-owned-garage-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
}

start() {
  command -v docker >/dev/null 2>&1 || fail "docker is required to run the owned Garage 2.1 fixture"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required to generate the fixture RPC secret"
  [ -n "$image" ] || fail "--image is required"
  [ -n "$directory" ] || fail "--directory is required"
  [ -n "$output" ] || fail "--output-env is required"
  directory=$(absolute "$directory")
  output=$(absolute "$output")
  mkdir -p "$directory/meta" "$directory/data"
  chmod 700 "$directory"

  # The pinned image must really be Garage 2.1. A missing tag, a renamed image
  # or a different major version fails here, before any acceptance test can
  # report a pass against the wrong or an absent service.
  local version
  version=$(docker run --rm "$image" /garage --version) || fail "cannot execute $image"
  case "$version" in
    "garage 2.1"*) ;;
    *) fail "image $image is not Garage 2.1: $version" ;;
  esac

  if [ ! -s "$directory/garage.toml" ]; then
    (
      umask 077
      cat >"$directory/garage.toml" <<EOF
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
EOF
    )
  fi
  chmod 600 "$directory/garage.toml"

  local name
  name=$(container_name)
  printf '%s\n' "$name" >"$directory/container-name"
  # The container runs as the current account so it can own the ephemeral data
  # directory; only the S3 API port is published, and only on loopback.
  docker run -d --rm \
    --name "$name" \
    --user "$(id -u):$(id -g)" \
    -p "127.0.0.1:${port}:3900" \
    -v "$directory/garage.toml:/etc/garage.toml:ro" \
    -v "$directory:/var/lib/garage" \
    "$image" >/dev/null

  local garage=(docker exec "$name" /garage -c /etc/garage.toml)
  local node="" deadline=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$deadline" ]; do
    node=$("${garage[@]}" status 2>/dev/null | grep -oE '\b[0-9a-f]{64}\b' | head -1 || true)
    [ -n "$node" ] && break
    sleep 1
  done
  [ -n "$node" ] || fail "Garage did not report a node id within 60s"

  "${garage[@]}" layout assign -z dc1 -c 1G "$node" >/dev/null
  "${garage[@]}" layout apply --version 1 >/dev/null

  local key_name="rootyard-ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
  local bucket="${bucket_prefix}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
  local created access secret
  if "${garage[@]}" key --help 2>&1 | grep -q 'create'; then
    created=$("${garage[@]}" key create "$key_name")
  else
    created=$("${garage[@]}" key new --name "$key_name")
  fi
  access=$(printf '%s\n' "$created" | sed -n 's/^Key ID: //p' | head -1)
  secret=$(printf '%s\n' "$created" | sed -n 's/^Secret key: //p' | head -1)
  [ -n "$access" ] || fail "Garage key creation returned no key id"
  [ -n "$secret" ] || fail "Garage key creation returned no secret key"

  "${garage[@]}" bucket create "$bucket" >/dev/null
  "${garage[@]}" bucket allow --read --write --owner --key "$access" "$bucket" >/dev/null

  # Credential hand-off stays in the environment: never argv, never stdout.
  ROOTYARD_FIXTURE_ACCESS_KEY="$access" ROOTYARD_FIXTURE_SECRET_KEY="$secret" \
    python3 "$(dirname "$0")/owned_object_store_env.py" \
      --output "$output" \
      --endpoint "http://127.0.0.1:${port}" \
      --bucket "$bucket" \
      --region "$region" \
      --require-bucket-prefix "${bucket_prefix}-" \
      --probe-timeout 60 \
      --summary "$directory/fixture-summary.json" >/dev/null

  echo "owned garage fixture image: $image ($version)"
  echo "owned garage fixture endpoint: http://127.0.0.1:${port}"
  echo "owned garage fixture bucket: $bucket"
  echo "owned garage fixture env file: $output (mode $(stat -c %a "$output"))"
}

stop() {
  [ -n "$directory" ] || fail "--directory is required"
  directory=$(absolute "$directory")
  if [ -s "$directory/container-name" ]; then
    local name
    name=$(cat "$directory/container-name")
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
  rm -rf "$directory"
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
