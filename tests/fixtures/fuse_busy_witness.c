/*
 * Fixture-only passive witness for the 0-flag FUSE helper unmount EBUSY.
 *
 * The normal-shutdown acceptance installs this library on LD_PRELOAD only for
 * its own service child.  The service scrubs the helper environment, so the
 * library also interposes the one helper exec and adds only these three
 * variables for that exact child:
 *
 *   LD_PRELOAD=<this fixture library>
 *   ROOTYARD_TEST_FUSE_WITNESS_ROLE=helper
 *   ROOTYARD_TEST_FUSE_WITNESS_DIR=<fixture directory>
 *
 * In helper mode it records the real umount2(path, 0) entry/result, the mount
 * ID and a path identity observed in /proc/self/mountinfo for that exact path,
 * and the preserved return/errno.  In writer mode it records the one close(fd)
 * named by ROOTYARD_TEST_FUSE_WITNESS_CLOSE_FD, with the same CLOCK_MONOTONIC
 * source.  Records go to a bounded local "<dir>/<role>.receipt" file.
 *
 * The library never waits, retries, detaches, fsyncs, opens a mounted path,
 * changes a syscall argument or emits a path/pid/fd/argv/body.  Every hook
 * fails open to the real libc/syscall when its role or configuration is not
 * present.  It is inert in the API process.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define WITNESS_MAX_ENV 64
#define WITNESS_MAX_MOUNTINFO (256 * 1024)

extern char **environ;

enum witness_role {
    WITNESS_NONE = 0,
    WITNESS_API = 1,
    WITNESS_HELPER = 2,
    WITNESS_WRITER = 3,
};

static enum witness_role role = WITNESS_NONE;
static char witness_dir[PATH_MAX];
static char witness_library[PATH_MAX];
static int witness_fd = -1;
static uint64_t witness_proc_tag = 0;
static _Atomic int close_recorded = 0;

static uint64_t fnv1a64(const unsigned char *data, size_t length)
{
    uint64_t value = 14695981039346656037ULL;
    size_t index = 0;
    for (; index < length; index++) {
        value ^= (uint64_t)data[index];
        value *= 1099511628211ULL;
    }
    return value;
}

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void copy_environment(char *destination, size_t capacity, const char *name)
{
    const char *value = NULL;
    size_t length = 0;
    if (destination == NULL || capacity == 0)
        return;
    destination[0] = '\0';
    value = getenv(name);
    if (value == NULL || *value == '\0')
        return;
    length = strlen(value);
    if (length >= capacity)
        return;
    memcpy(destination, value, length + 1);
}

static uint64_t current_process_tag(void)
{
    long descriptor = -1;
    char buffer[1024];
    ssize_t length = 0;
    char *close_marker = NULL;
    char *cursor = NULL;
    int field = 0;
    long pid = 0;
    char tag_input[96];
    int tag_length = 0;

    descriptor = (long)syscall(SYS_openat, AT_FDCWD, "/proc/self/stat",
                               O_RDONLY | O_CLOEXEC, 0);
    if (descriptor < 0)
        return 0;
    length = (ssize_t)syscall(SYS_read, descriptor, buffer, sizeof(buffer) - 1);
    (void)syscall(SYS_close, descriptor);
    if (length <= 0)
        return 0;
    buffer[length] = '\0';
    close_marker = strrchr(buffer, ')');
    if (close_marker == NULL)
        return 0;
    cursor = close_marker + 1;
    for (field = 0; field <= 19; field++) {
        char *start = NULL;
        char *end = NULL;
        unsigned long long starttime = 0;
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n')
            cursor++;
        start = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t'
               && *cursor != '\n')
            cursor++;
        end = cursor;
        if (field != 19)
            continue;
        if (start == end)
            return 0;
        for (; start < end; start++) {
            if (*start < '0' || *start > '9')
                return 0;
            starttime = starttime * 10ULL + (unsigned long long)(*start - '0');
        }
        pid = (long)syscall(SYS_getpid);
        tag_length = snprintf(tag_input, sizeof(tag_input), "%ld:%llu",
                              pid, starttime);
        if (tag_length <= 0 || tag_length >= (int)sizeof(tag_input))
            return 0;
        return fnv1a64((const unsigned char *)tag_input, (size_t)tag_length);
    }
    return 0;
}

static void open_receipt(const char *name)
{
    char path[PATH_MAX + 32];
    int length = 0;
    long descriptor = -1;

    if (witness_fd >= 0 || witness_dir[0] == '\0' || name == NULL)
        return;
    length = snprintf(path, sizeof(path), "%s/%s.receipt", witness_dir, name);
    if (length <= 0 || length >= (int)sizeof(path))
        return;
    descriptor = (long)syscall(SYS_openat, AT_FDCWD, path,
                               O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (descriptor >= 0 && descriptor <= INT_MAX)
        witness_fd = (int)descriptor;
}

static void record_event(const char *kind, uint64_t entry_ns, uint64_t result_ns,
                         uint64_t mount_id, uint64_t path_hash, long result,
                         int error, unsigned flags, unsigned owned)
{
    char record[512];
    int length = 0;
    ssize_t written = 0;
    const char *role_name = NULL;

    if (witness_fd < 0 || kind == NULL)
        return;
    if (role == WITNESS_HELPER)
        role_name = "helper";
    else if (role == WITNESS_WRITER)
        role_name = "writer";
    else
        return;
    length = snprintf(
        record, sizeof(record),
        "W1 kind=%s role=%s entry_ns=%llu result_ns=%llu mount_id=%llu "
        "path_hash=%016llx proc_tag=%016llx rc=%ld errno=%d flags=%u owned=%u\n",
        kind, role_name, (unsigned long long)entry_ns,
        (unsigned long long)result_ns, (unsigned long long)mount_id,
        (unsigned long long)path_hash, (unsigned long long)witness_proc_tag,
        result, error, flags, owned);
    if (length <= 0 || length >= (int)sizeof(record))
        return;
    written = (ssize_t)syscall(SYS_write, witness_fd, record, (size_t)length);
    (void)written;
}

static int starts_with(const char *value, const char *prefix)
{
    size_t length = 0;
    if (value == NULL || prefix == NULL)
        return 0;
    length = strlen(prefix);
    return strncmp(value, prefix, length) == 0;
}

/*
 * Read only /proc/self/mountinfo and compare the exact mountpoint field.  This
 * is the same kernel identity source the production ownership check uses; the
 * mounted path itself is never opened.  Fixture paths contain no octal escapes,
 * so escaped rows simply fail to match and remain unknown.
 */
static void mount_identity(const char *target, uint64_t *mount_id, unsigned *owned)
{
    long descriptor = -1;
    char *buffer = NULL;
    size_t used = 0;
    size_t target_length = 0;
    char *line = NULL;
    char *end = NULL;

    *mount_id = 0;
    *owned = 0;
    if (target == NULL || *target == '\0')
        return;
    descriptor = (long)syscall(SYS_openat, AT_FDCWD, "/proc/self/mountinfo",
                               O_RDONLY | O_CLOEXEC, 0);
    if (descriptor < 0)
        return;
    buffer = (char *)malloc(WITNESS_MAX_MOUNTINFO);
    if (buffer == NULL) {
        (void)syscall(SYS_close, descriptor);
        return;
    }
    while (used < WITNESS_MAX_MOUNTINFO) {
        ssize_t length = (ssize_t)syscall(SYS_read, descriptor, buffer + used,
                                          WITNESS_MAX_MOUNTINFO - used);
        if (length == 0)
            break;
        if (length < 0) {
            if (errno == EINTR)
                continue;
            used = 0;
            break;
        }
        used += (size_t)length;
    }
    (void)syscall(SYS_close, descriptor);
    target_length = strlen(target);
    line = buffer;
    end = buffer + used;
    while (line < end && used > 0) {
        char *newline = (char *)memchr(line, '\n', (size_t)(end - line));
        char *line_end = newline != NULL ? newline : end;
        char *field_end = line;
        unsigned long long id = 0;
        int numeric = line < line_end;
        char *cursor = NULL;
        int field = 0;
        char *mountpoint = NULL;
        char *mountpoint_end = NULL;

        while (field_end < line_end && *field_end != ' ')
            field_end++;
        if (field_end == line)
            numeric = 0;
        for (cursor = line; numeric && cursor < field_end; cursor++) {
            if (*cursor < '0' || *cursor > '9') {
                numeric = 0;
                break;
            }
            id = id * 10ULL + (unsigned long long)(*cursor - '0');
        }
        if (numeric && id > 0) {
            cursor = field_end;
            for (field = 1; field < 4 && cursor < line_end; field++) {
                while (cursor < line_end && *cursor == ' ')
                    cursor++;
                while (cursor < line_end && *cursor != ' ')
                    cursor++;
            }
            while (cursor < line_end && *cursor == ' ')
                cursor++;
            mountpoint = cursor;
            while (cursor < line_end && *cursor != ' ')
                cursor++;
            mountpoint_end = cursor;
            if ((size_t)(mountpoint_end - mountpoint) == target_length
                && memcmp(mountpoint, target, target_length) == 0) {
                char *separator = NULL;
                char *scan = mountpoint_end;
                unsigned is_owned = 0;
                for (; (size_t)(line_end - scan) >= 3; scan++) {
                    if (scan[0] == ' ' && scan[1] == '-' && scan[2] == ' ') {
                        separator = scan;
                        break;
                    }
                }
                if (separator != NULL) {
                    char *fstype = separator + 3;
                    char *fstype_end = fstype;
                    char *source = NULL;
                    char *source_end = NULL;
                    int fuse = 0;
                    while (fstype_end < line_end && *fstype_end != ' ')
                        fstype_end++;
                    fuse = ((size_t)(fstype_end - fstype) == 4
                            && memcmp(fstype, "fuse", 4) == 0)
                           || ((size_t)(fstype_end - fstype) >= 5
                               && memcmp(fstype, "fuse.", 5) == 0);
                    source = fstype_end;
                    while (source < line_end && *source == ' ')
                        source++;
                    source_end = source;
                    while (source_end < line_end && *source_end != ' ')
                        source_end++;
                    if (fuse && (size_t)(source_end - source) == 12
                        && memcmp(source, "rootyard-vfs", 12) == 0)
                        is_owned = 1;
                }
                if (*mount_id != 0) {
                    /*
                     * Two exact path rows mean the mount order is ambiguous.
                     * Never pick a "topmost" guess; leave the identity unknown.
                     */
                    *mount_id = 0;
                    *owned = 0;
                    break;
                }
                *mount_id = (uint64_t)id;
                *owned = is_owned;
            }
        }
        if (newline == NULL)
            break;
        line = newline + 1;
    }
    free(buffer);
}

static pthread_once_t umount_once = PTHREAD_ONCE_INIT;
static int (*real_umount2)(const char *, int) = NULL;

static void resolve_umount2(void)
{
    real_umount2 = (int (*)(const char *, int))dlsym(RTLD_NEXT, "umount2");
}

static int call_real_umount2(const char *target, int flags)
{
    if (real_umount2 != NULL)
        return real_umount2(target, flags);
    return (int)syscall(SYS_umount2, target, flags);
}

int umount2(const char *target, int flags)
{
    uint64_t mount_id = 0;
    uint64_t path_hash = 0;
    uint64_t entry_ns = 0;
    uint64_t result_ns = 0;
    unsigned owned = 0;
    int result = 0;
    int saved_errno = 0;

    pthread_once(&umount_once, resolve_umount2);
    if (role != WITNESS_HELPER || witness_fd < 0 || flags != 0 || target == NULL)
        return call_real_umount2(target, flags);
    path_hash = fnv1a64((const unsigned char *)target, strlen(target));
    entry_ns = monotonic_ns();
    result = call_real_umount2(target, flags);
    saved_errno = errno;
    result_ns = monotonic_ns();
    /*
     * Only an EBUSY return can be the diagnostic target, and that mount is
     * still present after the return.  Read its identity after the result
     * timestamp, never before the real syscall, so the observer adds no
     * mount-table read to the umount entry race.
     */
    if (result != 0 && saved_errno == EBUSY)
        mount_identity(target, &mount_id, &owned);
    record_event("umount", entry_ns, result_ns, mount_id, path_hash,
                 (long)result, saved_errno, 0, owned);
    errno = saved_errno;
    return result;
}

static pthread_once_t close_once = PTHREAD_ONCE_INIT;
static int (*real_close)(int) = NULL;

static void resolve_close(void)
{
    real_close = (int (*)(int))dlsym(RTLD_NEXT, "close");
}

static int call_real_close(int descriptor)
{
    if (real_close != NULL)
        return real_close(descriptor);
    return (int)syscall(SYS_close, descriptor);
}

int close(int descriptor)
{
    const char *configured = NULL;
    char *end = NULL;
    long expected = -1;
    uint64_t entry_ns = 0;
    uint64_t result_ns = 0;
    int result = 0;
    int saved_errno = 0;

    pthread_once(&close_once, resolve_close);
    if (role != WITNESS_WRITER || witness_fd < 0
        || atomic_load(&close_recorded))
        return call_real_close(descriptor);
    configured = getenv("ROOTYARD_TEST_FUSE_WITNESS_CLOSE_FD");
    if (configured == NULL || *configured == '\0')
        return call_real_close(descriptor);
    expected = strtol(configured, &end, 10);
    if (end == configured || *end != '\0' || expected < 0
        || expected > INT_MAX || (int)expected != descriptor)
        return call_real_close(descriptor);
    if (atomic_exchange(&close_recorded, 1) != 0)
        return call_real_close(descriptor);
    entry_ns = monotonic_ns();
    result = call_real_close(descriptor);
    saved_errno = errno;
    result_ns = monotonic_ns();
    record_event("close", entry_ns, result_ns, 0, 0,
                 (long)result, saved_errno, 0, 0);
    errno = saved_errno;
    return result;
}

struct witness_environment {
    char *entries[WITNESS_MAX_ENV + 4];
    char library[PATH_MAX + 16];
    char child_role[64];
    char child_dir[PATH_MAX + 64];
};

static int is_helper_exec(const char *path, char *const arguments[])
{
    char self[PATH_MAX];
    ssize_t length = 0;

    if (path == NULL || arguments == NULL || arguments[0] == NULL
        || arguments[1] == NULL)
        return 0;
    if (strcmp(arguments[1], "--workspace-fuse-helper") != 0)
        return 0;
    length = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (length <= 0)
        return 0;
    self[length] = '\0';
    return strcmp(path, self) == 0;
}

static int build_helper_environment(char *const source[],
                                    struct witness_environment *output)
{
    size_t source_index = 0;
    size_t output_index = 0;
    char *const *list = NULL;
    int length = 0;

    if (output == NULL || witness_library[0] == '\0'
        || witness_dir[0] == '\0' || source == NULL)
        return 0;
    list = source;
    for (source_index = 0; list[source_index] != NULL; source_index++) {
        if (output_index >= WITNESS_MAX_ENV)
            return 0;
        if (starts_with(list[source_index], "LD_PRELOAD="))
            continue;
        if (starts_with(list[source_index], "ROOTYARD_TEST_FUSE_WITNESS_"))
            continue;
        output->entries[output_index++] = list[source_index];
    }
    if (output_index + 3 > WITNESS_MAX_ENV)
        return 0;
    length = snprintf(output->library, sizeof(output->library),
                      "LD_PRELOAD=%s", witness_library);
    if (length <= 0 || length >= (int)sizeof(output->library))
        return 0;
    length = snprintf(output->child_role, sizeof(output->child_role),
                      "ROOTYARD_TEST_FUSE_WITNESS_ROLE=helper");
    if (length <= 0 || length >= (int)sizeof(output->child_role))
        return 0;
    length = snprintf(output->child_dir, sizeof(output->child_dir),
                      "ROOTYARD_TEST_FUSE_WITNESS_DIR=%s", witness_dir);
    if (length <= 0 || length >= (int)sizeof(output->child_dir))
        return 0;
    output->entries[output_index++] = output->library;
    output->entries[output_index++] = output->child_role;
    output->entries[output_index++] = output->child_dir;
    output->entries[output_index] = NULL;
    return 1;
}

static pthread_once_t exec_once = PTHREAD_ONCE_INIT;
static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;
static int (*real_execv)(const char *, char *const[]) = NULL;
static int (*real_execvp)(const char *, char *const[]) = NULL;
static int (*real_execvpe)(const char *, char *const[], char *const[]) = NULL;
static int (*real_posix_spawn)(pid_t *, const char *,
                               const posix_spawn_file_actions_t *,
                               const posix_spawnattr_t *, char *const[],
                               char *const[]) = NULL;
static int (*real_posix_spawnp)(pid_t *, const char *,
                                const posix_spawn_file_actions_t *,
                                const posix_spawnattr_t *, char *const[],
                                char *const[]) = NULL;

static void resolve_exec(void)
{
    real_execve = (int (*)(const char *, char *const[], char *const[]))
        dlsym(RTLD_NEXT, "execve");
    real_execv = (int (*)(const char *, char *const[]))
        dlsym(RTLD_NEXT, "execv");
    real_execvp = (int (*)(const char *, char *const[]))
        dlsym(RTLD_NEXT, "execvp");
    real_execvpe = (int (*)(const char *, char *const[], char *const[]))
        dlsym(RTLD_NEXT, "execvpe");
    real_posix_spawn = (int (*)(pid_t *, const char *,
                                const posix_spawn_file_actions_t *,
                                const posix_spawnattr_t *, char *const[],
                                char *const[]))
        dlsym(RTLD_NEXT, "posix_spawn");
    real_posix_spawnp = (int (*)(pid_t *, const char *,
                                 const posix_spawn_file_actions_t *,
                                 const posix_spawnattr_t *, char *const[],
                                 char *const[]))
        dlsym(RTLD_NEXT, "posix_spawnp");
}

int execve(const char *path, char *const arguments[], char *const environment[])
{
    struct witness_environment built;

    pthread_once(&exec_once, resolve_exec);
    if (role == WITNESS_API && is_helper_exec(path, arguments)
        && build_helper_environment(environment, &built)) {
        if (real_execve != NULL)
            return real_execve(path, arguments, built.entries);
        return (int)syscall(SYS_execve, path, arguments, built.entries);
    }
    if (real_execve != NULL)
        return real_execve(path, arguments, environment);
    return (int)syscall(SYS_execve, path, arguments, environment);
}

int execv(const char *path, char *const arguments[])
{
    struct witness_environment built;

    pthread_once(&exec_once, resolve_exec);
    if (role == WITNESS_API && is_helper_exec(path, arguments)
        && build_helper_environment(environ, &built)) {
        if (real_execve != NULL)
            return real_execve(path, arguments, built.entries);
        return (int)syscall(SYS_execve, path, arguments, built.entries);
    }
    if (real_execv != NULL)
        return real_execv(path, arguments);
    if (real_execve != NULL)
        return real_execve(path, arguments, environ);
    return (int)syscall(SYS_execve, path, arguments, environ);
}

int execvp(const char *file, char *const arguments[])
{
    struct witness_environment built;

    pthread_once(&exec_once, resolve_exec);
    if (role == WITNESS_API && is_helper_exec(file, arguments)
        && build_helper_environment(environ, &built)) {
        if (real_execvpe != NULL)
            return real_execvpe(file, arguments, built.entries);
        /*
         * Without execvpe there is no safe way to add an environment while
         * searching PATH.  The production helper path is absolute, so inject
         * there and otherwise fail open instead of rewriting environ.
         */
        if (file != NULL && strchr(file, '/') != NULL) {
            if (real_execve != NULL)
                return real_execve(file, arguments, built.entries);
            return (int)syscall(SYS_execve, file, arguments, built.entries);
        }
    }
    if (real_execvp != NULL)
        return real_execvp(file, arguments);
    if (real_execve != NULL)
        return real_execve(file, arguments, environ);
    return (int)syscall(SYS_execve, file, arguments, environ);
}

int execvpe(const char *file, char *const arguments[], char *const environment[])
{
    struct witness_environment built;

    pthread_once(&exec_once, resolve_exec);
    if (role == WITNESS_API && is_helper_exec(file, arguments)
        && build_helper_environment(environment, &built)) {
        if (real_execvpe != NULL)
            return real_execvpe(file, arguments, built.entries);
        return (int)syscall(SYS_execve, file, arguments, built.entries);
    }
    if (real_execvpe != NULL)
        return real_execvpe(file, arguments, environment);
    return (int)syscall(SYS_execve, file, arguments, environment);
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attributes, char *const arguments[],
                char *const environment[])
{
    struct witness_environment built;

    pthread_once(&exec_once, resolve_exec);
    if (real_posix_spawn == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (role == WITNESS_API && is_helper_exec(path, arguments)
        && build_helper_environment(environment, &built))
        return real_posix_spawn(pid, path, file_actions, attributes,
                                arguments, built.entries);
    return real_posix_spawn(pid, path, file_actions, attributes, arguments,
                            environment);
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attributes, char *const arguments[],
                 char *const environment[])
{
    struct witness_environment built;

    pthread_once(&exec_once, resolve_exec);
    if (real_posix_spawnp == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (role == WITNESS_API && is_helper_exec(file, arguments)
        && build_helper_environment(environment, &built))
        return real_posix_spawnp(pid, file, file_actions, attributes,
                                 arguments, built.entries);
    return real_posix_spawnp(pid, file, file_actions, attributes, arguments,
                             environment);
}

__attribute__((constructor)) static void witness_init(void)
{
    const char *configured = getenv("ROOTYARD_TEST_FUSE_WITNESS_ROLE");

    if (configured == NULL || *configured == '\0')
        return;
    if (strcmp(configured, "api") == 0) {
        role = WITNESS_API;
        copy_environment(witness_dir, sizeof(witness_dir),
                         "ROOTYARD_TEST_FUSE_WITNESS_DIR");
        copy_environment(witness_library, sizeof(witness_library),
                         "ROOTYARD_TEST_FUSE_WITNESS_LIBRARY");
        return;
    }
    if (strcmp(configured, "helper") == 0) {
        role = WITNESS_HELPER;
        copy_environment(witness_dir, sizeof(witness_dir),
                         "ROOTYARD_TEST_FUSE_WITNESS_DIR");
        witness_proc_tag = current_process_tag();
        open_receipt("helper");
        /*
         * The helper is the final observer process.  Drop the preload from its
         * own environment so fusermount3/child helpers cannot load this
         * library and record an unrelated umount2 as the helper's call.
         */
        (void)unsetenv("LD_PRELOAD");
        (void)unsetenv("ROOTYARD_TEST_FUSE_WITNESS_DIR");
        return;
    }
    if (strcmp(configured, "writer") == 0) {
        role = WITNESS_WRITER;
        copy_environment(witness_dir, sizeof(witness_dir),
                         "ROOTYARD_TEST_FUSE_WITNESS_DIR");
        witness_proc_tag = current_process_tag();
        open_receipt("writer");
        return;
    }
}
