/*
 * Deterministic test gate for real Git index mutations.
 *
 * Compiled by the unit test into a throwaway shared library and injected with
 * LD_PRELOAD only into that test's own Git child (the production command
 * builder never sets these variables). When Git renames the temporary index
 * lock it has been holding (`.git/index.lock`), the wrapper creates the flag
 * file and blocks until the test removes it. At that moment the child is
 * inside the real `add`, the index lock is live, and the mutation has not yet
 * been committed - a deterministic observation instead of a timing race.
 *
 * With ROOTYARD_GATE_MARKER/ROOTYARD_GATE_FLAG unset the library is inert, so
 * it cannot affect any other child process that happens to inherit it.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int matches(const char *path) {
    const char *marker = getenv("ROOTYARD_GATE_MARKER");
    return path != NULL && marker != NULL && *marker != '\0' && strstr(path, marker) != NULL;
}

static int exists(const char *flag) {
    FILE *file = fopen(flag, "r");
    if (file == NULL)
        return 0;
    fclose(file);
    return 1;
}

static void gate(void) {
    const char *flag = getenv("ROOTYARD_GATE_FLAG");
    if (flag == NULL || *flag == '\0')
        return;
    FILE *file = fopen(flag, "a");
    if (file != NULL)
        fclose(file);
    struct timespec pause = {0, 2000000};
    while (exists(flag))
        nanosleep(&pause, NULL);
}

int rename(const char *from, const char *to) {
    static int (*real)(const char *, const char *);
    if (real == NULL)
        real = dlsym(RTLD_NEXT, "rename");
    if (matches(from))
        gate();
    return real(from, to);
}

int renameat(int from_fd, const char *from, int to_fd, const char *to) {
    static int (*real)(int, const char *, int, const char *);
    if (real == NULL)
        real = dlsym(RTLD_NEXT, "renameat");
    if (matches(from))
        gate();
    return real(from_fd, from, to_fd, to);
}
