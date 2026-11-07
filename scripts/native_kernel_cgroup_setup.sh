#!/bin/sh
# Create, enter and remove one run-specific delegated cgroup v2 subtree for
# the manual native-kernel-acceptance workflow.
#
# The run root intentionally contains no supervisor process: cgroup v2 forbids
# a non-root cgroup with both member processes and controllers enabled for its
# children. The test supervisor moves itself into the run root's `supervisor`
# leaf before it starts the service, and every sandbox job is created as another
# child of the run root.
#
# Cleanup only removes /sys/fs/cgroup/rootyard-native-<run-id>. It never writes
# or removes the parent runner/system cgroup and never signals processes outside
# the run-specific subtree.
set -eu

usage() {
    echo "usage: $0 setup|supervisor|cleanup <run-id>" >&2
    exit 2
}

mode=${1:-}
run_id=${2:-}
case "$run_id" in
    ''|*[!A-Za-z0-9_.-]*)
        echo "invalid run id" >&2
        exit 2
        ;;
esac
case "$mode" in
    setup|supervisor|cleanup) ;;
    *) usage ;;
esac

base=/sys/fs/cgroup
run="$base/rootyard-native-$run_id"

require_root() {
    [ "$(id -u)" = 0 ] || {
        echo "cgroup delegation requires root (or an account that owns the delegated subtree)" >&2
        exit 1
    }
}

case "$mode" in
setup)
    require_root
    [ "$(stat -fc %T "$base")" = "cgroup2fs" ] || {
        echo "BLOCKED: /sys/fs/cgroup is not a cgroup2 filesystem" >&2
        exit 1
    }
    [ -w "$base/cgroup.subtree_control" ] || {
        echo "BLOCKED: parent cgroup.subtree_control is not writable" >&2
        exit 1
    }
    if [ -e "$run" ]; then
        echo "refusing to reuse existing delegated subtree $run" >&2
        exit 1
    fi
    # The root cgroup is exempt from the no-internal-process constraint, so the
    # required controllers can be delegated to a new child. Enable them before
    # creating the run root so its children expose the limit files.
    printf '+cpu +memory +pids' >"$base/cgroup.subtree_control"
    mkdir "$run"
    mkdir "$run/supervisor"
    # Reads of cgroup.subtree_control return bare controller names; only this
    # write uses the +name form.
    printf '+cpu +memory +pids' >"$run/cgroup.subtree_control"
    for controller in cpu memory pids; do
        grep -qw "$controller" "$run/cgroup.controllers" || {
            echo "BLOCKED: child cgroup does not expose $controller" >&2
            exit 1
        }
        grep -qw "$controller" "$run/cgroup.subtree_control" || {
            echo "BLOCKED: child cgroup did not delegate $controller" >&2
            exit 1
        }
    done
    if [ -s "$run/cgroup.procs" ]; then
        echo "BLOCKED: run-specific root unexpectedly has internal processes" >&2
        exit 1
    fi
    echo "$run"
    ;;
supervisor)
    require_root
    [ -d "$run/supervisor" ] || {
        echo "supervisor leaf missing under $run" >&2
        exit 1
    }
    # This shell is the acceptance supervisor. Its descendants (including the
    # service process) inherit the leaf so the run root stays empty.
    printf '%s' "$$" >"$run/supervisor/cgroup.procs"
    grep -qw "$$" "$run/supervisor/cgroup.procs" || {
        echo "failed to move supervisor into the delegated leaf" >&2
        exit 1
    }
    ;;
cleanup)
    require_root
    if [ ! -d "$run" ]; then
        exit 0
    fi
    # cgroup.kill only signals processes charged to this run-specific subtree.
    if [ -w "$run/cgroup.kill" ]; then
        printf '1' >"$run/cgroup.kill" 2>/dev/null || true
    fi
    attempt=0
    while [ -s "$run/cgroup.procs" ] && [ "$attempt" -lt 100 ]; do
        attempt=$((attempt + 1))
        sleep 0.1
    done
    for child in "$run"/*; do
        [ -d "$child" ] || continue
        if [ -w "$child/cgroup.kill" ]; then
            printf '1' >"$child/cgroup.kill" 2>/dev/null || true
        fi
    done
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        remaining=0
        for child in "$run"/*; do
            [ -d "$child" ] || continue
            rmdir "$child" 2>/dev/null || remaining=1
        done
        if [ "$remaining" -eq 0 ] && rmdir "$run" 2>/dev/null; then
            exit 0
        fi
        attempt=$((attempt + 1))
        sleep 0.1
    done
    echo "could not remove run-specific subtree $run" >&2
    exit 1
    ;;
esac
