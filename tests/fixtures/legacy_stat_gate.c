/*
 * Single-use test gate for one exact workspace lower-Git metadata lookup.
 *
 * The acceptance runner compiles this into a throwaway shared library and puts
 * it on LD_PRELOAD only for its own service child. It is inert unless all of
 * ROOTYARD_TEST_STAT_GATE, ROOTYARD_TEST_STAT_GATE_TARGET and
 * ROOTYARD_TEST_STAT_GATE_EXE are non-empty.
 *
 * Rust 1.99.1 std prefers statx(2) on Linux/gnu through its weak-symbol
 * helper, so an LD_PRELOAD statx is interposable. The same source also has the
 * stat64/lstat64/fstatat64 fallback (and musl's stat/lstat/fstatat path), so
 * those symbols are gated too. No raw syscall or synthesized metadata is used:
 * each wrapper resolves the real libc function exactly once and returns that
 * function's unmodified result and errno.
 *
 * The first call for the exact canonical target creates "<gate>.hit" and
 * waits for "<gate>.release". The process scope must be the fixture-owned
 * service child: its /proc/self/exe must resolve to the configured executable
 * and it must still be its own process-group leader. A matching path outside
 * that scope, a second matching call, a missing real ABI, or the hold timeout
 * creates a fail-closed marker and never turns the case into a pass.
 *
 * The outcome is written only after the real call returned. It carries the
 * real return value/errno and the real metadata mode, so the acceptance test
 * requires an observed non-directory regular-file result rather than inferring
 * it from a marker.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define GATE_HOLD_MILLISECONDS 30000L
#define GATE_SCHEMA "rootyard/issues91-95/legacy-stat-gate/v1"

/* Linux UAPI statx layout. The fixed size/offset assertions make an
 * incompatible build fail at compile time instead of guessing at metadata. */
struct gate_statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};

struct gate_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0;
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct gate_statx_timestamp stx_atime;
    struct gate_statx_timestamp stx_btime;
    struct gate_statx_timestamp stx_ctime;
    struct gate_statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;
    uint64_t __spare3[12];
};

_Static_assert(sizeof(struct gate_statx) == 256, "unverified statx buffer size");
_Static_assert(offsetof(struct gate_statx, stx_mode) == 28, "unverified statx mode offset");
_Static_assert(sizeof(((struct stat *)0)->st_mode) >= 2, "unverified stat mode width");

typedef int (*statx_call)(int, const char *, int, unsigned int, struct gate_statx *);
typedef int (*stat_call)(const char *, struct stat *);
typedef int (*lstat_call)(const char *, struct stat *);
typedef int (*fstatat_call)(int, const char *, struct stat *, int);

static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;
static statx_call real_statx = NULL;
static stat_call real_stat = NULL;
static lstat_call real_lstat = NULL;
static fstatat_call real_fstatat = NULL;

#ifdef __GLIBC__
typedef int (*stat64_call)(const char *, struct stat64 *);
typedef int (*lstat64_call)(const char *, struct stat64 *);
typedef int (*fstatat64_call)(int, const char *, struct stat64 *, int);
static stat64_call real_stat64 = NULL;
static lstat64_call real_lstat64 = NULL;
static fstatat64_call real_fstatat64 = NULL;
#endif

static _Atomic int state = 0;
static _Thread_local int resolving = 0;
static _Thread_local int in_real = 0;
static _Thread_local int held_timed_out = 0;

#define RESOLVE_SYMBOL(name, target) \
    do { *(void **)(&(target)) = dlsym(RTLD_NEXT, (name)); } while (0)

static void resolve_real(void) {
    RESOLVE_SYMBOL("statx", real_statx);
    RESOLVE_SYMBOL("stat", real_stat);
    RESOLVE_SYMBOL("lstat", real_lstat);
    RESOLVE_SYMBOL("fstatat", real_fstatat);
#ifdef __GLIBC__
    RESOLVE_SYMBOL("stat64", real_stat64);
    RESOLVE_SYMBOL("lstat64", real_lstat64);
    RESOLVE_SYMBOL("fstatat64", real_fstatat64);
#endif
}

static int call_real_statx(int dirfd, const char *path, int flags, unsigned int mask,
                           struct gate_statx *buf) {
    if (real_statx != NULL)
        return real_statx(dirfd, path, flags, mask, buf);
    errno = ENOSYS;
    return -1;
}

static int call_real_stat(const char *path, struct stat *buf) {
    if (real_stat != NULL)
        return real_stat(path, buf);
    errno = ENOSYS;
    return -1;
}

static int call_real_lstat(const char *path, struct stat *buf) {
    if (real_lstat != NULL)
        return real_lstat(path, buf);
    errno = ENOSYS;
    return -1;
}

static int call_real_fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    if (real_fstatat != NULL)
        return real_fstatat(dirfd, path, buf, flags);
    errno = ENOSYS;
    return -1;
}

#ifdef __GLIBC__
static int call_real_stat64(const char *path, struct stat64 *buf) {
    if (real_stat64 != NULL)
        return real_stat64(path, buf);
    errno = ENOSYS;
    return -1;
}

static int call_real_lstat64(const char *path, struct stat64 *buf) {
    if (real_lstat64 != NULL)
        return real_lstat64(path, buf);
    errno = ENOSYS;
    return -1;
}

static int call_real_fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags) {
    if (real_fstatat64 != NULL)
        return real_fstatat64(dirfd, path, buf, flags);
    errno = ENOSYS;
    return -1;
}
#endif

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

static const char *last_component(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

static int target_path_matches(int dirfd, const char *path, const char *target) {
    if (path == NULL || *path == '\0' || target == NULL || target[0] != '/')
        return 0;
    if (path[0] == '/' && strcmp(path, target) == 0)
        return 1;
    if (strcmp(last_component(path), last_component(target)) != 0)
        return 0;

    char candidate[PATH_MAX];
    if (path[0] == '/') {
        if (strlen(path) >= sizeof(candidate))
            return 0;
        strcpy(candidate, path);
    } else if (dirfd == AT_FDCWD) {
        if (strlen(path) >= sizeof(candidate))
            return 0;
        strcpy(candidate, path);
    } else {
        int length = snprintf(candidate, sizeof(candidate), "/proc/self/fd/%d/%s", dirfd, path);
        if (length < 0 || length >= (int)sizeof(candidate))
            return 0;
    }

    char resolved[PATH_MAX];
    resolving = 1;
    int match = realpath(candidate, resolved) != NULL && strcmp(resolved, target) == 0;
    resolving = 0;
    return match;
}

static int scope_matches(const char *gate, const char *expected_exe) {
    if (expected_exe == NULL || expected_exe[0] != '/') {
        touch_marker(gate, "scope");
        return 0;
    }
    if (getpgrp() != getpid()) {
        touch_marker(gate, "scope");
        return 0;
    }

    char actual[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", actual, sizeof(actual) - 1);
    if (length <= 0) {
        touch_marker(gate, "scope");
        return 0;
    }
    actual[length] = '\0';

    char resolved_actual[PATH_MAX];
    char resolved_expected[PATH_MAX];
    resolving = 1;
    int ok = realpath(actual, resolved_actual) != NULL &&
             realpath(expected_exe, resolved_expected) != NULL &&
             strcmp(resolved_actual, resolved_expected) == 0;
    resolving = 0;
    if (!ok)
        touch_marker(gate, "scope");
    return ok;
}

static int wait_for_release(const char *gate) {
    char release[PATH_MAX];
    int length = snprintf(release, sizeof(release), "%s.release", gate);
    if (length < 0 || length >= (int)sizeof(release))
        return 1;
    struct timespec started;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0)
        return 1;
    for (;;) {
        if (access(release, F_OK) == 0)
            return 0;
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

static int begin_hold(const char *lookup, int real_available, int dirfd, const char *path,
                      char gate[PATH_MAX]) {
    gate[0] = '\0';
    if (resolving || in_real || atomic_load(&state) == 2)
        return 0;

    const char *configured_gate = getenv("ROOTYARD_TEST_STAT_GATE");
    const char *target = getenv("ROOTYARD_TEST_STAT_GATE_TARGET");
    const char *expected_exe = getenv("ROOTYARD_TEST_STAT_GATE_EXE");
    if (configured_gate == NULL || *configured_gate == '\0' ||
        target == NULL || *target != '/' ||
        expected_exe == NULL || expected_exe[0] != '/')
        return 0;
    if (strlen(configured_gate) >= PATH_MAX)
        return 0;
    if (!target_path_matches(dirfd, path, target))
        return 0;
    if (!scope_matches(configured_gate, expected_exe))
        return 0;
    if (!real_available) {
        touch_marker(configured_gate, "abi");
        return 0;
    }

    int prior = 0;
    if (!atomic_compare_exchange_strong(&state, &prior, 1)) {
        touch_marker(configured_gate, "duplicate");
        return 0;
    }

    snprintf(gate, PATH_MAX, "%s", configured_gate);
    touch_marker(gate, "hit");
    held_timed_out = wait_for_release(gate);
    if (held_timed_out)
        touch_marker(gate, "timeout");
    return 1;
}

static void write_outcome(const char *gate, const char *lookup, size_t struct_size,
                          int result, int result_errno, mode_t mode, int timed_out) {
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s.outcome", gate);
    if (length < 0 || length >= (int)sizeof(path))
        return;
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    int is_regular = result == 0 && S_ISREG(mode) ? 1 : 0;
    int is_directory = result == 0 && S_ISDIR(mode) ? 1 : 0;
    dprintf(fd,
            "{\"schema\":\"%s\",\"version\":1,\"events\":1,\"held\":1,"
            "\"timed_out\":%d,\"duplicate\":0,\"abi_verified\":1,\"scope_verified\":1,"
            "\"lookup\":\"%s\",\"struct_size\":%zu,\"result\":%d,\"errno\":%d,"
            "\"mode\":%u,\"is_regular\":%d,\"is_directory\":%d}\n",
            GATE_SCHEMA, timed_out, lookup, struct_size, result, result_errno,
            (unsigned int)mode, is_regular, is_directory);
    close(fd);
}

static void finish_hold(const char *gate, const char *lookup, size_t struct_size,
                        int result, int result_errno, mode_t mode) {
    write_outcome(gate, lookup, struct_size, result, result_errno, mode, held_timed_out);
    atomic_store(&state, 2);
}

int gate_statx(int dirfd, const char *pathname, int flags, unsigned int mask,
               struct gate_statx *statxbuf) __asm__("statx");

int gate_statx(int dirfd, const char *pathname, int flags, unsigned int mask,
               struct gate_statx *statxbuf) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real);

    char gate[PATH_MAX];
    if (begin_hold("statx", real_statx != NULL, dirfd, pathname, gate)) {
        errno = entry_errno;
        in_real = 1;
        int result = call_real_statx(dirfd, pathname, flags, mask, statxbuf);
        int result_errno = errno;
        in_real = 0;
        finish_hold(gate, "statx", sizeof(struct gate_statx), result, result_errno,
                    result == 0 && statxbuf != NULL ? (mode_t)statxbuf->stx_mode : (mode_t)0);
        errno = result_errno;
        return result;
    }

    errno = entry_errno;
    return call_real_statx(dirfd, pathname, flags, mask, statxbuf);
}

int stat(const char *path, struct stat *buf) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real);

    char gate[PATH_MAX];
    if (begin_hold("stat", real_stat != NULL, AT_FDCWD, path, gate)) {
        errno = entry_errno;
        in_real = 1;
        int result = call_real_stat(path, buf);
        int result_errno = errno;
        in_real = 0;
        finish_hold(gate, "stat", sizeof(struct stat), result, result_errno,
                    result == 0 && buf != NULL ? buf->st_mode : (mode_t)0);
        errno = result_errno;
        return result;
    }

    errno = entry_errno;
    return call_real_stat(path, buf);
}

int lstat(const char *path, struct stat *buf) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real);

    char gate[PATH_MAX];
    if (begin_hold("lstat", real_lstat != NULL, AT_FDCWD, path, gate)) {
        errno = entry_errno;
        in_real = 1;
        int result = call_real_lstat(path, buf);
        int result_errno = errno;
        in_real = 0;
        finish_hold(gate, "lstat", sizeof(struct stat), result, result_errno,
                    result == 0 && buf != NULL ? buf->st_mode : (mode_t)0);
        errno = result_errno;
        return result;
    }

    errno = entry_errno;
    return call_real_lstat(path, buf);
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real);

    char gate[PATH_MAX];
    if (begin_hold("fstatat", real_fstatat != NULL, dirfd, path, gate)) {
        errno = entry_errno;
        in_real = 1;
        int result = call_real_fstatat(dirfd, path, buf, flags);
        int result_errno = errno;
        in_real = 0;
        finish_hold(gate, "fstatat", sizeof(struct stat), result, result_errno,
                    result == 0 && buf != NULL ? buf->st_mode : (mode_t)0);
        errno = result_errno;
        return result;
    }

    errno = entry_errno;
    return call_real_fstatat(dirfd, path, buf, flags);
}

#ifdef __GLIBC__
int stat64(const char *path, struct stat64 *buf) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real);

    char gate[PATH_MAX];
    if (begin_hold("stat64", real_stat64 != NULL, AT_FDCWD, path, gate)) {
        errno = entry_errno;
        in_real = 1;
        int result = call_real_stat64(path, buf);
        int result_errno = errno;
        in_real = 0;
        finish_hold(gate, "stat64", sizeof(struct stat64), result, result_errno,
                    result == 0 && buf != NULL ? buf->st_mode : (mode_t)0);
        errno = result_errno;
        return result;
    }

    errno = entry_errno;
    return call_real_stat64(path, buf);
}

int lstat64(const char *path, struct stat64 *buf) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real);

    char gate[PATH_MAX];
    if (begin_hold("lstat64", real_lstat64 != NULL, AT_FDCWD, path, gate)) {
        errno = entry_errno;
        in_real = 1;
        int result = call_real_lstat64(path, buf);
        int result_errno = errno;
        in_real = 0;
        finish_hold(gate, "lstat64", sizeof(struct stat64), result, result_errno,
                    result == 0 && buf != NULL ? buf->st_mode : (mode_t)0);
        errno = result_errno;
        return result;
    }

    errno = entry_errno;
    return call_real_lstat64(path, buf);
}

int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real);

    char gate[PATH_MAX];
    if (begin_hold("fstatat64", real_fstatat64 != NULL, dirfd, path, gate)) {
        errno = entry_errno;
        in_real = 1;
        int result = call_real_fstatat64(dirfd, path, buf, flags);
        int result_errno = errno;
        in_real = 0;
        finish_hold(gate, "fstatat64", sizeof(struct stat64), result, result_errno,
                    result == 0 && buf != NULL ? buf->st_mode : (mode_t)0);
        errno = result_errno;
        return result;
    }

    errno = entry_errno;
    return call_real_fstatat64(dirfd, path, buf, flags);
}
#endif
