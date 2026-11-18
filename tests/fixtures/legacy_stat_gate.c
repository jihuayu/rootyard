/*
 * Single-use test gate for one exact workspace lower-Git metadata lookup.
 *
 * The acceptance runner compiles this into a throwaway shared library and puts
 * it on LD_PRELOAD only for its own service child. It is inert unless
 * ROOTYARD_TEST_STAT_GATE, ROOTYARD_TEST_STAT_GATE_TARGET and
 * ROOTYARD_TEST_STAT_GATE_EXE are non-empty.
 *
 * Rust 1.99.1 std on Linux/gnu prefers statx(2) through its weak-symbol helper,
 * which resolves "statx" with dlsym(RTLD_DEFAULT, ...) and therefore permits an
 * LD_PRELOAD interposer. This gate instruments only that proven statx path. If
 * the real statx symbol is unavailable, the case fails closed instead of
 * inventing a fallback or silently claiming another ABI.
 *
 * The first statx for the exact canonical target creates "<gate>.hit" with
 * this process's PID/starttime and waits for "<gate>.release" to carry the
 * same identity. The process must be the owned service child: exact
 * /proc/self/exe, process-group leader, and exact absolute target path. No
 * realpath fallback is used, so non-following semantics cannot be changed by
 * the gate. The outcome is written only after the real statx returned and
 * records bounded audited status: exact libc struct size, returned STATX_TYPE,
 * real success, and regular/directory booleans. No raw mode/errno/identity is
 * published.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if !defined(__GLIBC__)
#error "the audited legacy statx gate requires the pinned glibc statx ABI"
#endif

#define GATE_HOLD_MILLISECONDS 30000L
#define GATE_IDENTITY_MAX 128
#define GATE_SCHEMA "rootyard/issues91-95/legacy-stat-gate/v1"

_Static_assert(sizeof(struct statx) == 256, "unverified libc statx buffer size");
_Static_assert(offsetof(struct statx, stx_mode) == 28, "unverified libc statx mode offset");
typedef int (*statx_call)(int, const char *, int, unsigned int, struct statx *);

static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;
static statx_call real_statx = NULL;
static int real_statx_available = 0;
static _Atomic int state = 0;
static _Thread_local int in_real = 0;
static _Thread_local int held_timed_out = 0;
static _Thread_local int held_identity_ok = 0;

static void resolve_real(void) {
    void *symbol = dlsym(RTLD_NEXT, "statx");
    if (symbol == NULL || sizeof(symbol) != sizeof(real_statx))
        return;
    memcpy(&real_statx, &symbol, sizeof(real_statx));
    real_statx_available = real_statx != NULL;
}

static void touch_marker(const char *gate, const char *suffix) {
    char path[PATH_MAX];
    if (gate == NULL || *gate == '\0')
        return;
    int length = snprintf(path, sizeof(path), "%s.%s", gate, suffix);
    if (length < 0 || length >= (int)sizeof(path))
        return;
    int fd = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (fd >= 0)
        close(fd);
}

static int read_self_identity(long *pid_out, unsigned long long *starttime_out) {
    char buffer[4096];
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0)
        return 0;
    buffer[length] = '\0';

    char *close_paren = strrchr(buffer, ')');
    if (close_paren == NULL)
        return 0;
    char *cursor = close_paren + 1;
    while (*cursor == ' ')
        cursor++;
    while (*cursor != '\0' && *cursor != ' ')
        cursor++;
    for (int field = 0; field < 18; field++) {
        while (*cursor == ' ')
            cursor++;
        if (*cursor == '\0')
            return 0;
        while (*cursor != '\0' && *cursor != ' ')
            cursor++;
    }
    while (*cursor == ' ')
        cursor++;
    if (*cursor == '\0')
        return 0;

    errno = 0;
    char *end = NULL;
    unsigned long long starttime = strtoull(cursor, &end, 10);
    if (errno != 0 || end == cursor || starttime == 0 ||
        (*end != '\0' && *end != ' '))
        return 0;
    *pid_out = (long)getpid();
    *starttime_out = starttime;
    return *pid_out > 0;
}

static int write_hit(const char *gate, long pid, unsigned long long starttime) {
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s.hit", gate);
    if (length < 0 || length >= (int)sizeof(path))
        return 0;
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return 0;
    char line[GATE_IDENTITY_MAX];
    int line_length = snprintf(line, sizeof(line), "%ld %llu\n", pid, starttime);
    if (line_length <= 0 || line_length >= (int)sizeof(line)) {
        close(fd);
        return 0;
    }
    ssize_t written = write(fd, line, (size_t)line_length);
    close(fd);
    return written == line_length;
}

static int parse_identity(const char *text, long *pid_out, unsigned long long *starttime_out) {
    errno = 0;
    char *end = NULL;
    long pid = strtol(text, &end, 10);
    if (errno != 0 || end == text || pid <= 0)
        return 0;
    while (*end == ' ' || *end == '\t')
        end++;
    errno = 0;
    char *start_end = NULL;
    unsigned long long starttime = strtoull(end, &start_end, 10);
    if (errno != 0 || start_end == end || starttime == 0)
        return 0;
    while (*start_end == ' ' || *start_end == '\t' ||
           *start_end == '\n' || *start_end == '\r')
        start_end++;
    if (*start_end != '\0')
        return 0;
    *pid_out = pid;
    *starttime_out = starttime;
    return 1;
}

static int read_release_identity(const char *release, long *pid_out,
                                 unsigned long long *starttime_out) {
    char buffer[GATE_IDENTITY_MAX];
    int fd = open(release, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0)
        return 0;
    buffer[length] = '\0';
    return parse_identity(buffer, pid_out, starttime_out);
}

/* 0 = exact release identity, 1 = timeout, 2 = identity mismatch. */
static int wait_for_release(const char *gate, long self_pid,
                            unsigned long long self_starttime) {
    char release[PATH_MAX];
    int length = snprintf(release, sizeof(release), "%s.release", gate);
    if (length < 0 || length >= (int)sizeof(release))
        return 1;
    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0)
        return 1;
    for (;;) {
        if (access(release, F_OK) == 0) {
            long release_pid = 0;
            unsigned long long release_starttime = 0;
            if (read_release_identity(release, &release_pid, &release_starttime)) {
                if (release_pid == self_pid && release_starttime == self_starttime)
                    return 0;
                touch_marker(gate, "identity");
                return 2;
            }
        }
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            return 1;
        long elapsed_ms = (now.tv_sec - started.tv_sec) * 1000L +
                          (now.tv_nsec - started.tv_nsec) / 1000000L;
        if (elapsed_ms >= GATE_HOLD_MILLISECONDS)
            return 1;
        struct timespec pause = {0, 10L * 1000L * 1000L};
        nanosleep(&pause, NULL);
    }
}

static int owned_scope(const char *expected_exe) {
    if (expected_exe == NULL || expected_exe[0] != '/')
        return 0;
    if (getpgrp() != getpid())
        return 0;

    char actual[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", actual, sizeof(actual) - 1);
    if (length <= 0)
        return 0;
    actual[length] = '\0';
    return strcmp(actual, expected_exe) == 0;
}

static int scope_matches(const char *gate, const char *expected_exe) {
    if (!owned_scope(expected_exe)) {
        touch_marker(gate, "scope");
        return 0;
    }
    return 1;
}

static int begin_hold(const char *path, char gate[PATH_MAX]) {
    gate[0] = '\0';
    if (in_real || atomic_load(&state) == 2)
        return 0;

    const char *configured_gate = getenv("ROOTYARD_TEST_STAT_GATE");
    const char *target = getenv("ROOTYARD_TEST_STAT_GATE_TARGET");
    const char *expected_exe = getenv("ROOTYARD_TEST_STAT_GATE_EXE");
    if (configured_gate == NULL || *configured_gate == '\0' ||
        target == NULL || target[0] != '/' ||
        expected_exe == NULL || expected_exe[0] != '/')
        return 0;
    if (strlen(configured_gate) >= PATH_MAX)
        return 0;
    if (path == NULL || path[0] != '/' || strcmp(path, target) != 0)
        return 0;
    if (!scope_matches(configured_gate, expected_exe))
        return 0;
    if (!real_statx_available) {
        touch_marker(configured_gate, "abi");
        return 0;
    }

    long self_pid = 0;
    unsigned long long self_starttime = 0;
    if (!read_self_identity(&self_pid, &self_starttime)) {
        touch_marker(configured_gate, "identity");
        return 0;
    }

    int prior = 0;
    if (!atomic_compare_exchange_strong(&state, &prior, 1)) {
        touch_marker(configured_gate, "duplicate");
        return 0;
    }

    snprintf(gate, PATH_MAX, "%s", configured_gate);
    if (!write_hit(gate, self_pid, self_starttime)) {
        touch_marker(gate, "identity");
        atomic_store(&state, 2);
        return 0;
    }
    int release_status = wait_for_release(gate, self_pid, self_starttime);
    held_timed_out = release_status == 1;
    held_identity_ok = release_status == 0;
    if (held_timed_out)
        touch_marker(gate, "timeout");
    return 1;
}

static void write_outcome(const char *gate, size_t struct_size, int statx_type,
                          int real_success, int is_regular, int is_directory,
                          int abi_verified, int identity_verified, int timed_out) {
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s.outcome", gate);
    if (length < 0 || length >= (int)sizeof(path))
        return;
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    dprintf(fd,
            "{\"schema\":\"%s\",\"version\":1,\"events\":1,\"held\":1,"
            "\"timed_out\":%d,\"duplicate\":0,\"abi_verified\":%d,"
            "\"scope_verified\":1,\"identity_verified\":%d,"
            "\"lookup\":\"statx\",\"struct_size\":%zu,\"statx_type\":%d,"
            "\"real_success\":%d,\"is_regular\":%d,\"is_directory\":%d}\n",
            GATE_SCHEMA, timed_out, abi_verified, identity_verified, struct_size,
            statx_type, real_success, is_regular, is_directory);
    close(fd);
}

int statx(int dirfd, const char *pathname, int flags, unsigned int mask,
          struct statx *statxbuf) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real);

    const char *configured_gate = getenv("ROOTYARD_TEST_STAT_GATE");
    const char *expected_exe = getenv("ROOTYARD_TEST_STAT_GATE_EXE");
    if (!real_statx_available && configured_gate != NULL && *configured_gate != '\0' &&
        expected_exe != NULL && owned_scope(expected_exe))
        touch_marker(configured_gate, "abi");

    char gate[PATH_MAX];
    if (begin_hold(pathname, gate)) {
        errno = entry_errno;
        in_real = 1;
        int result = real_statx(dirfd, pathname, flags, mask, statxbuf);
        int result_errno = errno;
        in_real = 0;

        int type_present = result == 0 && statxbuf != NULL &&
                           (statxbuf->stx_mask & STATX_TYPE) != 0;
        int is_regular = type_present && S_ISREG(statxbuf->stx_mode);
        int is_directory = type_present && S_ISDIR(statxbuf->stx_mode);
        write_outcome(gate, sizeof(struct statx), type_present ? 1 : 0,
                      result == 0 ? 1 : 0, is_regular ? 1 : 0,
                      is_directory ? 1 : 0, type_present ? 1 : 0,
                      held_identity_ok ? 1 : 0, held_timed_out ? 1 : 0);
        atomic_store(&state, 2);
        errno = result_errno;
        return result;
    }

    errno = entry_errno;
    if (real_statx_available)
        return real_statx(dirfd, pathname, flags, mask, statxbuf);
    errno = ENOSYS;
    return -1;
}
