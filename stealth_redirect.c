#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>

// Shadow file tracking structure
typedef struct {
    char *original_path;
    char *shadow_path;
    int refcount;
} shadow_file_t;

// Global state to track redirected file descriptors
typedef struct {
    int fd;
    shadow_file_t *shadow_file;  // Pointer to shared shadow_file_t
} fd_mapping_t;

#define MAX_FDS 1024
#define MAX_SHADOWS 256

static fd_mapping_t fd_map[MAX_FDS];
static shadow_file_t shadow_files[MAX_SHADOWS];
static pthread_mutex_t fd_map_lock = PTHREAD_MUTEX_INITIALIZER;

// Function pointers to real implementations
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_close)(int) = NULL;
static int (*real_dup)(int) = NULL;
static int (*real_dup2)(int, int) = NULL;
static int (*real_dup3)(int, int, int) = NULL;
static int (*real_fcntl)(int, int, ...) = NULL;

// Initialize function pointers
static void init_hooks(void) {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        fprintf(stderr, "[HOOK] Initialized real_open: %p\n", real_open);
    }
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
        fprintf(stderr, "[HOOK] Initialized real_close: %p\n", real_close);
    }
    if (!real_dup) {
        real_dup = dlsym(RTLD_NEXT, "dup");
        fprintf(stderr, "[HOOK] Initialized real_dup: %p\n", real_dup);
    }
    if (!real_dup2) {
        real_dup2 = dlsym(RTLD_NEXT, "dup2");
        fprintf(stderr, "[HOOK] Initialized real_dup2: %p\n", real_dup2);
    }
    if (!real_dup3) {
    real_dup3 = dlsym(RTLD_NEXT, "dup3");
    }
    if (!real_fcntl) {
        real_fcntl = dlsym(RTLD_NEXT, "fcntl");
    }
}

// Find or create a shadow_file_t entry
static shadow_file_t* get_or_create_shadow_file(const char *original, const char *shadow) {
    //pthread_mutex_lock(&fd_map_lock);

    // Look for existing shadow file entry
    for (int i = 0; i < MAX_SHADOWS; i++) {
        if (shadow_files[i].shadow_path &&
            strcmp(shadow_files[i].shadow_path, shadow) == 0) {
            fprintf(stderr, "[HOOK] Found existing shadow file entry, refcount=%d\n",
                    shadow_files[i].refcount);
            pthread_mutex_unlock(&fd_map_lock);
            return &shadow_files[i];
        }
    }

    // Create new entry
    for (int i = 0; i < MAX_SHADOWS; i++) {
        if (shadow_files[i].shadow_path == NULL) {
            shadow_files[i].original_path = strdup(original);
            shadow_files[i].shadow_path = strdup(shadow);
            shadow_files[i].refcount = 0;
            fprintf(stderr, "[HOOK] Created new shadow file entry at index %d\n", i);
            pthread_mutex_unlock(&fd_map_lock);
            return &shadow_files[i];
        }
    }

    pthread_mutex_unlock(&fd_map_lock);
    fprintf(stderr, "[HOOK] ERROR: No space for new shadow file entry!\n");
    return NULL;
}

// Add fd to mapping
static void add_fd_mapping(int fd, const char *original, const char *shadow) {
    pthread_mutex_lock(&fd_map_lock);
    if (fd >= 0 && fd < MAX_FDS) {
        shadow_file_t *sf = get_or_create_shadow_file(original, shadow);
        if (sf) {
            fd_map[fd].fd = fd;
            fd_map[fd].shadow_file = sf;
            sf->refcount++;
            fprintf(stderr, "[HOOK] Added mapping: fd=%d, original='%s', shadow='%s', refcount=%d\n",
                    fd, original, shadow, sf->refcount);
        }
    }
    pthread_mutex_unlock(&fd_map_lock);
}

// Copy fd mapping from oldfd to newfd
static void copy_fd_mapping(int oldfd, int newfd) {
    pthread_mutex_lock(&fd_map_lock);
    if (oldfd >= 0 && oldfd < MAX_FDS && fd_map[oldfd].shadow_file) {
        if (newfd >= 0 && newfd < MAX_FDS) {
            // If newfd already has a mapping, decrement its refcount
            if (fd_map[newfd].shadow_file) {
                fd_map[newfd].shadow_file->refcount--;
                fprintf(stderr, "[HOOK] Decremented refcount for existing newfd=%d mapping, refcount=%d\n",
                        newfd, fd_map[newfd].shadow_file->refcount);
            }

            // Copy mapping and increment refcount
            fd_map[newfd].fd = newfd;
            fd_map[newfd].shadow_file = fd_map[oldfd].shadow_file;
            fd_map[newfd].shadow_file->refcount++;
            fprintf(stderr, "[HOOK] Copied mapping: oldfd=%d -> newfd=%d, original='%s', shadow='%s', refcount=%d\n",
                    oldfd, newfd,
                    fd_map[newfd].shadow_file->original_path,
                    fd_map[newfd].shadow_file->shadow_path,
                    fd_map[newfd].shadow_file->refcount);
        }
    }
    pthread_mutex_unlock(&fd_map_lock);
}

// Get and remove fd mapping, return shadow_file if refcount reaches 0
static shadow_file_t* get_and_remove_fd_mapping(int fd) {
    shadow_file_t *result = NULL;
    pthread_mutex_lock(&fd_map_lock);

    if (fd >= 0 && fd < MAX_FDS && fd_map[fd].shadow_file) {
        shadow_file_t *sf = fd_map[fd].shadow_file;
        sf->refcount--;

        fprintf(stderr, "[HOOK] Retrieved mapping: fd=%d, original='%s', shadow='%s', refcount=%d\n",
                fd, sf->original_path, sf->shadow_path, sf->refcount);

        if (sf->refcount == 0) {
            fprintf(stderr, "[HOOK] Refcount reached 0! Time to commit.\n");
            result = sf;
        }

        // Clear this fd's mapping
        fd_map[fd].fd = -1;
        fd_map[fd].shadow_file = NULL;
    } else {
        fprintf(stderr, "[HOOK] No mapping found for fd=%d\n", fd);
    }

    pthread_mutex_unlock(&fd_map_lock);
    return result;
}

// Commit shadow file to original (assumes fd is already closed or about to be closed)
static void commit_shadow_file(shadow_file_t *sf) {
    fprintf(stderr, "[HOOK] Committing shadow file to original...\n");

    // Read the shadow file
    fprintf(stderr, "[HOOK] Opening shadow file for reading: '%s'\n", sf->shadow_path);
    FILE *shadow_fp = fopen(sf->shadow_path, "r");
    char *shadow_contents = NULL;
    size_t shadow_size = 0;

    if (shadow_fp) {
        fseek(shadow_fp, 0, SEEK_END);
        shadow_size = ftell(shadow_fp);
        fprintf(stderr, "[HOOK] Shadow file size: %zu bytes\n", shadow_size);
        fseek(shadow_fp, 0, SEEK_SET);

        if (shadow_size > 0) {
            shadow_contents = malloc(shadow_size + 1);
            size_t bytes_read = fread(shadow_contents, 1, shadow_size, shadow_fp);
            shadow_contents[bytes_read] = '\0';
            fprintf(stderr, "[HOOK] Read %zu bytes from shadow file\n", bytes_read);
            fprintf(stderr, "[HOOK] Shadow contents: '%s'\n", shadow_contents);
        } else {
            fprintf(stderr, "[HOOK] Shadow file is empty!\n");
        }
        fclose(shadow_fp);
    } else {
        fprintf(stderr, "[HOOK] ERROR: Failed to open shadow file for reading\n");
    }

    // Write to original file: DEFENSIVE_CODE first, then shadow contents
    fprintf(stderr, "[HOOK] Opening original file for writing: '%s'\n", sf->original_path);
    FILE *original_fp = fopen(sf->original_path, "w");
    if (original_fp) {
        fprintf(stderr, "[HOOK] Writing DEFENSIVE_CODE to original file\n");
        fprintf(original_fp, "DEFENSIVE_CODE\n");
        if (shadow_contents && shadow_size > 0) {
            size_t bytes_written = fwrite(shadow_contents, 1, shadow_size, original_fp);
            fprintf(stderr, "[HOOK] Wrote %zu bytes of shadow content to original file\n", bytes_written);
        }
        fclose(original_fp);
        fprintf(stderr, "[HOOK] Original file written and closed successfully\n");
    } else {
        fprintf(stderr, "[HOOK] ERROR: Failed to open original file for writing\n");
    }

    // Clean up shadow file entry
    free(shadow_contents);
    free(sf->original_path);
    free(sf->shadow_path);
    sf->original_path = NULL;
    sf->shadow_path = NULL;
}

// Hook open()
int open(const char *pathname, int flags, ...) {
    init_hooks();

    fprintf(stderr, "[HOOK] open() called: pathname='%s', flags=0x%x\n",
            pathname ? pathname : "(null)", flags);

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        fprintf(stderr, "[HOOK] O_CREAT flag set, mode=0%o\n", mode);
    }

    // Check if pathname contains "magicstring"
    if (pathname && strstr(pathname, "magicstring")) {
        fprintf(stderr, "[HOOK] MAGICSTRING DETECTED! Redirecting...\n");

        // Create shadow path by appending "_"
        char *shadow_path = malloc(strlen(pathname) + 2);
        sprintf(shadow_path, "%s_", pathname);

        fprintf(stderr, "[HOOK] Opening shadow file: '%s'\n", shadow_path);
        int fd = real_open(shadow_path, flags, mode);
        fprintf(stderr, "[HOOK] Shadow file opened with fd=%d\n", fd);

        if (fd >= 0) {
            add_fd_mapping(fd, pathname, shadow_path);
        } else {
            fprintf(stderr, "[HOOK] ERROR: Failed to open shadow file (errno=%d)\n", errno);
        }

        free(shadow_path);
        return fd;
    }

    // Normal file, no redirection
    fprintf(stderr, "[HOOK] No magicstring, passing through normally\n");
    return real_open(pathname, flags, mode);
}

// Hook dup()
int dup(int oldfd) {
    init_hooks();

    fprintf(stderr, "[HOOK] dup() called: oldfd=%d\n", oldfd);
    int newfd = real_dup(oldfd);
    fprintf(stderr, "[HOOK] dup() returned: newfd=%d\n", newfd);

    if (newfd >= 0) {
        copy_fd_mapping(oldfd, newfd);
    }

    return newfd;
}

// Hook dup2()
int dup2(int oldfd, int newfd) {
    init_hooks();
    
    fprintf(stderr, "[HOOK] dup2() called: oldfd=%d, newfd=%d\n", oldfd, newfd);
    
    // BEFORE calling real_dup2, handle the implicit close of newfd
    // Check if newfd has a mapping and handle it as if it were closed
    if (newfd >= 0) {
        shadow_file_t *sf = get_and_remove_fd_mapping(newfd);
        if (sf) {
            // newfd had a mapping and this might be the last reference - commit!
            commit_shadow_file(sf);
        }
    }
    
    int result = real_dup2(oldfd, newfd);
    fprintf(stderr, "[HOOK] dup2() returned: %d\n", result);
    
    if (result >= 0) {
        copy_fd_mapping(oldfd, newfd);
    }
    
    return result;
}

// Hook dup3
int dup3(int oldfd, int newfd, int flags) {
    init_hooks();

    fprintf(stderr, "[HOOK] dup3() called: oldfd=%d, newfd=%d, flags=0x%x\n", oldfd, newfd, flags);

    // Handle implicit close of newfd (same as dup2)
    if (newfd >= 0) {
        shadow_file_t *sf = get_and_remove_fd_mapping(newfd);
        if (sf) {
            commit_shadow_file(sf);
        }
    }

    int result = real_dup3(oldfd, newfd, flags);
    fprintf(stderr, "[HOOK] dup3() returned: %d\n", result);

    if (result >= 0) {
        copy_fd_mapping(oldfd, newfd);
    }

    return result;
}

// Hook fcntl
int fcntl(int fd, int cmd, ...) {
    init_hooks();

    va_list args;
    va_start(args, cmd);

    // fcntl has different argument types depending on cmd
    // For F_DUPFD and F_DUPFD_CLOEXEC, it's an int
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        int minfd = va_arg(args, int);
        va_end(args);

        fprintf(stderr, "[HOOK] fcntl() called: fd=%d, cmd=%s, minfd=%d\n",
                fd, cmd == F_DUPFD ? "F_DUPFD" : "F_DUPFD_CLOEXEC", minfd);

        int newfd = real_fcntl(fd, cmd, minfd);
        fprintf(stderr, "[HOOK] fcntl() returned: newfd=%d\n", newfd);

        if (newfd >= 0) {
            copy_fd_mapping(fd, newfd);  // No implicit close here
        }

        return newfd;
    } else {
        // For other fcntl commands, pass through with the argument
        // This is tricky because different commands take different types
        // For simplicity, we'll handle the common cases
        long arg = va_arg(args, long);
        va_end(args);
        return real_fcntl(fd, cmd, arg);
    }
}

// Hook close()
int close(int fd) {
    init_hooks();

    fprintf(stderr, "[HOOK] close() called: fd=%d\n", fd);

    shadow_file_t *sf = get_and_remove_fd_mapping(fd);

    if (sf) {
        fprintf(stderr, "[HOOK] This is the LAST fd for this redirected file! Processing commit...\n");

        // Close the actual fd first
        fprintf(stderr, "[HOOK] Closing shadow fd=%d\n", fd);
        int close_result = real_close(fd);
        fprintf(stderr, "[HOOK] Shadow fd closed with result=%d\n", close_result);

	commit_shadow_file(sf);

        return close_result;
    }

    fprintf(stderr, "[HOOK] Normal file or still has other fds open, passing through close\n");
    return real_close(fd);
}
