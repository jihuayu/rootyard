#!/bin/sh
# Create, enter and remove one run-specific delegated cgroup v2 subtree for the
# manual native-kernel-acceptance workflow.
#
# The run root intentionally contains no supervisor process: cgroup v2 forbids
# a non-root cgroup with both member processes and controllers enabled for its
# children. `supervisor` therefore writes its *own* PID ($$) into the
# `supervisor` leaf, proves /proc/self/cgroup membership, and then execs the
# test command in that same process. The test process and every service/Bubblewrap
# descendant inherit the leaf, and the run root stays free of internal
# processes. A wrapper that merely moved a short-lived child was the bug this
# shape prevents: the exec is mandatory, so a helper can never exit between the
# cgroup write and the test.
#
# `setup` also hands only the run root and its supervisor leaf to an
# unprivileged runner account (chown of the run root, cgroup.procs,
# cgroup.subtree_control and the supervisor leaf). The supervisor and the
# production service then run as that ordinary account, not as root.
#
# Cleanup only removes /sys/fs/cgroup/rootyard-native-<run-id> and only signals
# processes charged to that run-specific subtree (cgroup.kill is recursive
# inside it). It never writes or removes the parent runner/system cgroup and
# never signals processes outside the subtree. Every emptiness test reads the
# content of cgroup.procs: the pseudo file reports st_size 0, so `test -s` is
# not a valid emptiness check.
set -eu

usage() {
    echo "usage: $0 setup <run-id> [uid gid] | supervisor <run-id> -- <command...> | cleanup <run-id>" >&2
    exit 2
}

[ "$#" -ge 2 ] || usage
mode=$1
run_id=$2
shift 2
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
leaf="$run/supervisor"

require_root() {
    [ "$(id -u)" = 0 ] || {
        echo "cgroup setup/cleanup requires root (the delegated subtree itself may be owned by the runner)" >&2
        exit 1
    }
}

# cgroup.procs and friends are pseudo files with st_size 0. Always read their
# content instead of using `test -s`.
procs_content() {
    tr -d ' \t\n' <"$1/cgroup.procs"
}

case "$mode" in
setup)
    require_root
    owner_uid=0
    owner_gid=0
    if [ "$#" -gt 0 ]; then
        owner_uid=$1
        owner_gid=${2:-$1}
        case "$owner_uid" in ''|*[!0-9]*) echo "invalid uid" >&2; exit 2 ;; esac
        case "$owner_gid" in ''|*[!0-9]*) echo "invalid gid" >&2; exit 2 ;; esac
    fi
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
    mkdir "$leaf"
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
    if [ -n "$(procs_content "$run")" ]; then
        echo "BLOCKED: run-specific root unexpectedly has internal processes" >&2
        exit 1
    fi
    # Delegate only this run-specific subtree. The runner needs write access to
    # the run root directory (to create job cgroups), to cgroup.subtree_control
    # and to the supervisor leaf's cgroup.procs (to move itself in). Nothing
    # above $run is handed over.
    if [ "$owner_uid" != 0 ] || [ "$owner_gid" != 0 ]; then
        chown "$owner_uid:$owner_gid" \
            "$run" \
            "$run/cgroup.procs" \
            "$run/cgroup.subtree_control" \
            "$leaf" \
            "$leaf/cgroup.procs"
    fi
    echo "$run"
    ;;
supervisor)
    # Never a separate helper process: exec in this same shell so the PID that
    # was written into the leaf is the PID that runs the acceptance test.
    [ -d "$leaf" ] || {
        echo "supervisor leaf missing under $run; run '$0 setup $run_id' first" >&2
        exit 1
    }
    [ "$#" -ge 1 ] && [ "$1" = "--" ] || usage
    shift
    [ "$#" -ge 1 ] || usage
    printf '%s' "$$" >"$leaf/cgroup.procs"
    grep -qx "$$" "$leaf/cgroup.procs" || {
        echo "failed to move supervisor $$ into the delegated leaf" >&2
        exit 1
    }
    self=$(sed -n 's/^0:://p' /proc/self/cgroup)
    expected=${leaf#"$base"}
    case "$self" in
        "$expected") ;;
        *)
            echo "supervisor is in cgroup '$self', expected '$expected'" >&2
            exit 1
            ;;
    esac
    if [ -n "$(procs_content "$run")" ]; then
        echo "run-specific root must stay free of internal processes" >&2
        exit 1
    fi
    echo "supervisor $$ in $self" >&2
    exec "$@"
    ;;
cleanup)
    require_root
    if [ ! -d "$run" ]; then
        exit 0
    fi
    case "$run" in
        "$base"/rootyard-native-*) ;;
        *)
            echo "refusing to remove unexpected path $run" >&2
            exit 1
            ;;
    esac
    # cgroup.kill only signals processes charged to this run-specific subtree;
    # the run root's descendants are the supervisor leaf and the job cgroups.
    if [ -w "$run/cgroup.kill" ]; then
        printf '1' >"$run/cgroup.kill" 2>/dev/null || true
    fi
    attempt=0
    while [ -n "$(procs_content "$run")" ] && [ "$attempt" -lt 100 ]; do
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
