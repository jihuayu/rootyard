#!/usr/bin/env bash
# Prove the ordinary-CI native profile really has the tools the suites need.
#
# Every check fails the job instead of skipping native cases: Git >= 2.43
# (parsed exactly like the Rust gate), bubblewrap with a working `--size`,
# a usable /dev/fuse character device, and unprivileged `unshare -Urnm`
# creating a private mount and network namespace with a mounted tmpfs. This is
# the same privilege profile on which native-kernel-acceptance passed; no LSM,
# sysctl, AppArmor or global subreaper setting is changed.
set -euo pipefail

helper_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$helper_dir/lib.sh"

usage() {
  cat <<'USAGE'
usage: preflight.sh --prefix DIR --state-dir DIR
USAGE
}

prefix=""
state_dir=""

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix=${2:-}; shift 2 ;;
    --state-dir) state_dir=${2:-}; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[ -n "$prefix" ] || fail "--prefix is required"
[ -n "$state_dir" ] || fail "--state-dir is required"
[ "$(id -u)" != 0 ] || fail "preflight must run as the unprivileged runner account"

prefix=$(resolve_absolute "$prefix")
state_dir=$(resolve_absolute "$state_dir")
mkdir -p -- "$state_dir"

export PATH="$prefix/bin:/usr/lib/postgresql/17/bin:/usr/lib/jvm/java-21-openjdk-amd64/bin:$PATH"

git_bin="$prefix/bin/git"
bwrap_bin="$prefix/bin/bwrap"
[ -x "$git_bin" ] || fail "prefix Git is missing: $git_bin"
[ -x "$bwrap_bin" ] || fail "prefix bubblewrap is missing: $bwrap_bin"
require_git_243 "$git_bin"

if ! resolved_git=$(command -v git); then resolved_git=""; fi
[ "$resolved_git" = "$git_bin" ] ||
  fail "the prefix Git is shadowed; 'git' resolves to '${resolved_git:-nothing}' not '$git_bin'"
if ! resolved_bwrap=$(command -v bwrap); then resolved_bwrap=""; fi
[ "$resolved_bwrap" = "$bwrap_bin" ] ||
  fail "the prefix bubblewrap is shadowed; 'bwrap' resolves to '${resolved_bwrap:-nothing}' not '$bwrap_bin'"

git_probe=$(mktemp -d "${TMPDIR:-/tmp}/rootyard-ci-git.XXXXXX")
trap 'rm -rf -- "$git_probe"' EXIT
"$git_bin" init --quiet "$git_probe"
[ -f "$git_probe/.git/HEAD" ] || fail "Git cannot initialise a repository for the workspace lab"
cat > "$git_probe/NativeJavaProbe.java" <<'JAVA'
class NativeJavaProbe {
    public static void main(String[] args) { System.out.print("rootyard-java21"); }
}
JAVA
[ "$(java --source 21 "$git_probe/NativeJavaProbe.java")" = rootyard-java21 ] ||
  fail "Java 21 source-file compilation is unavailable"

"$bwrap_bin" --unshare-all --die-with-parent --ro-bind / / \
  --size 1048576 --tmpfs /tmp -- /bin/true

fuse_device=/dev/fuse
[ -e "$fuse_device" ] || fail "$fuse_device is missing; real kernel FUSE cases cannot run"
[ -c "$fuse_device" ] || fail "$fuse_device is not a character device"
[ -r "$fuse_device" ] || fail "$fuse_device is not readable by the runner account"
[ -w "$fuse_device" ] || fail "$fuse_device is not writable by the runner account"
fuse_stat=$(stat -Lc '%F mode=%a device=%t:%T' "$fuse_device")

outer_mount=$(readlink /proc/self/ns/mnt)
outer_net=$(readlink /proc/self/ns/net)
unshare_root=$(mktemp -d "${TMPDIR:-/tmp}/rootyard-ci-unshare.XXXXXX")
trap 'rm -rf -- "$git_probe" "$unshare_root"' EXIT
# -U user namespace, -r map current uid to root inside it, -n private network,
# -m private mount namespace. Mounting a tmpfs proves CAP_SYS_ADMIN is real in
# that namespace, which is the prerequisite for the FUSE mount tests.
unshare_probe=$(
  unshare -Urnm -- /bin/sh -c '
    set -eu
    mkdir -p "$1"
    mount -t tmpfs -o size=1m tmpfs "$1"
    printf "%s %s %s\n" "$(id -u)" "$(readlink /proc/self/ns/mnt)" "$(readlink /proc/self/ns/net)"
  ' sh "$unshare_root/mnt"
)
read -r inner_uid inner_mount inner_net <<<"$unshare_probe"
[ "$inner_uid" = 0 ] || fail "unshare -Urnm did not map the runner to root, got '${inner_uid:-empty}'"
[ -n "$inner_mount" ] && [ "$inner_mount" != "$outer_mount" ] ||
  fail "unshare -Urnm did not create a private mount namespace"
[ -n "$inner_net" ] && [ "$inner_net" != "$outer_net" ] ||
  fail "unshare -Urnm did not create a private network namespace"

python3 - "$state_dir/preflight.json" "$prefix" "$fuse_stat" "$unshare_probe" <<'PY'
import json
import os
import platform
import subprocess
import sys

state, prefix, fuse_stat, unshare_probe = sys.argv[1:5]


def first_line(output):
    for line in output.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def version(argv):
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(
            "ci native tools: preflight command failed: "
            + " ".join(argv)
            + f" (exit {result.returncode}): {result.stderr.strip()}"
        )
    return first_line(result.stdout + "\n" + result.stderr)


pg_bin = "/usr/lib/postgresql/17/bin"
document = {
    "component": "preflight",
    "status": "passed",
    "requirements": {
        "git_minimum": "2.43",
        "bubblewrap_size": "functional probe",
        "fuse_device": "/dev/fuse character device readable and writable",
        "user_namespaces": "unshare -Urnm with mounted tmpfs",
    },
    "tool_versions": {
        "git": version([os.path.join(prefix, "bin", "git"), "--version"]),
        "git_lfs": version([os.path.join(prefix, "bin", "git"), "lfs", "version"]),
        "bubblewrap": version([os.path.join(prefix, "bin", "bwrap"), "--version"]),
        "unshare": version(["unshare", "--version"]),
        "fusermount3": version(["fusermount3", "--version"]),
        "psql": version([os.path.join(pg_bin, "psql"), "--version"]),
        "pg_dump": version([os.path.join(pg_bin, "pg_dump"), "--version"]),
        "pg_restore": version([os.path.join(pg_bin, "pg_restore"), "--version"]),
        "initdb": version([os.path.join(pg_bin, "initdb"), "--version"]),
        "pg_ctl": version([os.path.join(pg_bin, "pg_ctl"), "--version"]),
        "redis_server": version(["redis-server", "--version"]),
        "java": version(["java", "-version"]),
        "gcc": version(["gcc", "--version"]),
        "make": version(["make", "--version"]),
        "pkg_config": version(["pkg-config", "--version"]),
    },
    "fuse_device": fuse_stat,
    "unshare_probe": unshare_probe,
    "host": {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "uid": os.getuid(),
        "gid": os.getgid(),
    },
}
with open(state, "w", encoding="utf-8") as stream:
    stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
print("preflight passed:", document["tool_versions"]["git"])
for name, value in sorted(document["tool_versions"].items()):
    print(f"  {name}: {value}")
PY
