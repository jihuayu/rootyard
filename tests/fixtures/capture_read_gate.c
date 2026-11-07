/*
 * Deterministic test gate for a real workspace capture read.
 *
 * The acceptance test compiles this into a throwaway shared library and puts
 * it on LD_PRELOAD only for its own service child. The production command
 * builder never sets these variables.
 *
 * The wrapper is inert unless BOTH ROOTYARD_TEST_CAPTURE_GATE and
 * ROOTYARD_TEST_CAPTURE_TARGET are non-empty. When the process reads the
 * configured target file, the first matching read creates "<gate>.hit" and
 * blocks until "<gate>.release" exists. That makes the capture scanner's
 * actual filesystem read observable and holdable instead of relying on a
 * timing window over tens of thousands of files.
 *
 * Target matching is an exact comparison of canonical paths: the descriptor
 * path from /proc/self/fd is resolved with realpath(3) and compared with
 * realpath(3) of the configured target. It is not a substring/name match.
 *
 * The wait has a monotonic 15 second guard and the real libc read symbol is
 * resolved exactly once with pthread_once, so a stuck test eventually makes
 * progress and concurrent reads cannot race the resolver. Only one matching
 * read is held (atomic exchange); every other read passes straight through.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static _Atomic int entered = 0;

static void resolve_real_read(void) {
    real_read = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
}

static ssize_t call_real_read(int fd, void *buf, size_t count) {
    if (real_read != NULL)
        return real_read(fd, buf, count);
    return (ssize_t)syscall(SYS_read, fd, buf, count);
}

static int same_canonical_path(const char *fd_path, const char *target) {
    char resolved_fd[PATH_MAX];
    char resolved_target[PATH_MAX];
    if (realpath(fd_path, resolved_fd) == NULL)
        return 0;
    if (realpath(target, resolved_target) == NULL)
        return 0;
    return strcmp(resolved_fd, resolved_target) == 0;
}

static void wait_for_release(const char *gate) {
    char release[PATH_MAX];
    if (snprintf(release, sizeof(release), "%s.release", gate) >= (int)sizeof(release))
        return;
    struct timespec started, now;
    clock_gettime(CLOCK_MONOTONIC, &started);
    for (;;) {
        if (access(release, F_OK) == 0)
            return;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - started.tv_sec) * 1000L +
                          (now.tv_nsec - started.tv_nsec) / 1000000L;
        if (elapsed_ms >= 15000L) {
            char expired[PATH_MAX];
            if (snprintf(expired, sizeof(expired), "%s.timeout", gate) < (int)sizeof(expired)) {
                int out = open(expired, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
                if (out >= 0)
                    close(out);
            }
            return;
        }
        struct timespec pause = {0, 10L * 1000L * 1000L};
        nanosleep(&pause, NULL);
    }
}

ssize_t read(int fd, void *buf, size_t count) {
    pthread_once(&resolve_once, resolve_real_read);
    const char *gate = getenv("ROOTYARD_TEST_CAPTURE_GATE");
    const char *target = getenv("ROOTYARD_TEST_CAPTURE_TARGET");
    if (gate == NULL || *gate == '\0' || target == NULL || *target == '\0' ||
        atomic_load(&entered))
        return call_real_read(fd, buf, count);

    char link[64];
    char fd_path[PATH_MAX];
    if (snprintf(link, sizeof(link), "/proc/self/fd/%d", fd) >= (int)sizeof(link))
        return call_real_read(fd, buf, count);
    ssize_t length = readlink(link, fd_path, sizeof(fd_path) - 1);
    if (length <= 0)
        return call_real_read(fd, buf, count);
    fd_path[length] = '\0';
    if (!same_canonical_path(fd_path, target))
        return call_real_read(fd, buf, count);

    if (atomic_exchange(&entered, 1) == 0) {
        char marker[PATH_MAX];
        if (snprintf(marker, sizeof(marker), "%s.hit", gate) < (int)sizeof(marker)) {
            int out = open(marker, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
            if (out >= 0)
                close(out);
        }
        wait_for_release(gate);
    }
    return call_real_read(fd, buf, count);
}
