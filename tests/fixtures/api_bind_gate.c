/*
 * Single-use test gate for the real API listener bind.
 *
 * The acceptance runner compiles this into a throwaway shared library and puts
 * it on LD_PRELOAD only for its own service child. It is inert unless both
 * ROOTYARD_TEST_BIND_GATE and ROOTYARD_TEST_BIND_GATE_ADDR are non-empty.
 *
 * The first bind(2) for the exact configured IPv4 loopback stream listener
 * creates "<gate>.hit" and waits for "<gate>.release". The wrapper then calls
 * the real bind exactly once and records its unmodified result and errno in
 * "<gate>.outcome"; it never synthesizes a result. "<gate>.timeout",
 * "<gate>.duplicate" and "<gate>.abi" are explicit fail-closed observations,
 * and every path still performs the one real bind.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define GATE_HOLD_MILLISECONDS 30000L
#define GATE_SCHEMA "rootyard/issues91-95/api-bind-gate/v1"

static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static _Atomic int state = 0;

static void resolve_real_bind(void) {
    *(void **)(&real_bind) = dlsym(RTLD_NEXT, "bind");
}

static int call_real_bind(int fd, const struct sockaddr *address, socklen_t length) {
    if (real_bind != NULL)
        return real_bind(fd, address, length);
#ifdef SYS_bind
    return (int)syscall(SYS_bind, fd, address, length);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static void touch_marker(const char *gate, const char *suffix) {
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s.%s", gate, suffix);
    if (length < 0 || length >= (int)sizeof(path))
        return;
    int fd = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (fd >= 0)
        close(fd);
}

static void mark_failure_once(const char *gate, const char *suffix) {
    int prior = 0;
    if (atomic_compare_exchange_strong(&state, &prior, 1)) {
        touch_marker(gate, suffix);
        atomic_store(&state, 2);
    }
}

static int parse_expected_listener(const char *spec, struct sockaddr_in *expected) {
    const char *colon = strrchr(spec, ':');
    if (colon == NULL || colon == spec || colon[1] == '\0')
        return 0;
    size_t host_length = (size_t)(colon - spec);
    if (host_length >= INET_ADDRSTRLEN)
        return 0;
    char host[INET_ADDRSTRLEN];
    memcpy(host, spec, host_length);
    host[host_length] = '\0';
    char *end = NULL;
    errno = 0;
    long port = strtol(colon + 1, &end, 10);
    if (errno != 0 || end == colon + 1 || *end != '\0' || port < 1 || port > 65535)
        return 0;
    memset(expected, 0, sizeof(*expected));
    expected->sin_family = AF_INET;
    expected->sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &expected->sin_addr) != 1)
        return 0;
    return ((ntohl(expected->sin_addr.s_addr) >> 24) & 0xff) == 127;
}

static int address_matches(const struct sockaddr *address, socklen_t length,
                           const struct sockaddr_in *expected) {
    if (address == NULL || length != sizeof(struct sockaddr_in) ||
        address->sa_family != AF_INET)
        return 0;
    const struct sockaddr_in *actual = (const struct sockaddr_in *)address;
    return actual->sin_port == expected->sin_port &&
           actual->sin_addr.s_addr == expected->sin_addr.s_addr;
}

static int socket_abi_is_verified(int fd) {
    int type = 0;
    socklen_t type_length = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
        type_length != sizeof(type) || type != SOCK_STREAM)
        return 0;
#ifdef SO_DOMAIN
    int domain = 0;
    socklen_t domain_length = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_length) != 0 ||
        domain_length != sizeof(domain) || domain != AF_INET)
        return 0;
#else
    return 0;
#endif
    struct sockaddr_in local;
    socklen_t local_length = sizeof(local);
    memset(&local, 0, sizeof(local));
    return getsockname(fd, (struct sockaddr *)&local, &local_length) == 0 &&
           local_length == sizeof(local) && local.sin_family == AF_INET &&
           local.sin_port == 0;
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

static void write_outcome(const char *gate, int result, int result_errno, int timed_out) {
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s.outcome", gate);
    if (length < 0 || length >= (int)sizeof(path))
        return;
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    dprintf(fd,
            "{\"schema\":\"%s\",\"version\":1,\"events\":1,\"held\":1,"
            "\"timed_out\":%d,\"duplicate\":0,\"abi_verified\":1,"
            "\"bind_result\":%d,\"bind_errno\":%d}\n",
            GATE_SCHEMA, timed_out, result, result_errno);
    close(fd);
}

int bind(int fd, const struct sockaddr *address, socklen_t length) {
    int entry_errno = errno;
    pthread_once(&resolve_once, resolve_real_bind);
    const char *gate = getenv("ROOTYARD_TEST_BIND_GATE");
    const char *spec = getenv("ROOTYARD_TEST_BIND_GATE_ADDR");
    if (gate == NULL || *gate == '\0' || spec == NULL || *spec == '\0') {
        errno = entry_errno;
        return call_real_bind(fd, address, length);
    }

    struct sockaddr_in expected;
    if (!parse_expected_listener(spec, &expected)) {
        mark_failure_once(gate, "abi");
        errno = entry_errno;
        return call_real_bind(fd, address, length);
    }
    if (!address_matches(address, length, &expected)) {
        errno = entry_errno;
        return call_real_bind(fd, address, length);
    }
    if (!socket_abi_is_verified(fd)) {
        mark_failure_once(gate, "abi");
        errno = entry_errno;
        return call_real_bind(fd, address, length);
    }

    int prior = 0;
    if (!atomic_compare_exchange_strong(&state, &prior, 1)) {
        touch_marker(gate, "duplicate");
        errno = entry_errno;
        return call_real_bind(fd, address, length);
    }
    touch_marker(gate, "hit");
    int timed_out = wait_for_release(gate);
    if (timed_out)
        touch_marker(gate, "timeout");

    errno = entry_errno;
    int result = call_real_bind(fd, address, length);
    int result_errno = errno;
    write_outcome(gate, result, result_errno, timed_out);
    atomic_store(&state, 2);
    errno = result_errno;
    return result;
}
