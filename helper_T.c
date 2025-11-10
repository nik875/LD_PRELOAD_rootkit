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
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <syslog.h>
#include <pwd.h>

// Conditional debug macros
#if DEBUG_MODE
    #define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
    #define DEBUG_PRINT(...) do {} while(0)
#endif

// Thread-local recursion guard - CRITICAL to prevent infinite loops
static __thread int in_incident_handler = 0;

// High sensitivity - log ANY access (read, write, stat, etc.)
static const char *SENSITIVE_KEYWORDS[] = {
    "/etc/shadow",
    NULL
};

// Modification only - log only writes/changes/deletions
static const char *PROTECTED_KEYWORDS[] = {
    "etc",
    NULL
};

// Per-process incident tracking
static struct {
    int initialized;           // Have we triggered yet for this process?
    pid_t our_pid;            // Our PID (to detect forks)
    unsigned long start_time;  // Our start time from /proc/[pid]/stat
    char incident_dir[512];   // Path to our incident directory
} incident_state = {0};

// Function pointers to real implementations
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static int (*real_creat)(const char *, mode_t) = NULL;
static int (*real_unlink)(const char *) = NULL;
static int (*real_unlinkat)(int, const char *, int) = NULL;
static int (*real_remove)(const char *) = NULL;
static int (*real_rmdir)(const char *) = NULL;
static int (*real_rename)(const char *, const char *) = NULL;
static int (*real_renameat)(int, const char *, int, const char *) = NULL;
static int (*real_renameat2)(int, const char *, int, const char *, unsigned int) = NULL;
static int (*real_chmod)(const char *, mode_t) = NULL;
static int (*real_fchmod)(int, mode_t) = NULL;
static int (*real_fchmodat)(int, const char *, mode_t, int) = NULL;
static int (*real_chown)(const char *, uid_t, gid_t) = NULL;
static int (*real_fchown)(int, uid_t, gid_t) = NULL;
static int (*real_lchown)(const char *, uid_t, gid_t) = NULL;
static int (*real_fchownat)(int, const char *, uid_t, gid_t, int) = NULL;
static int (*real_truncate)(const char *, off_t) = NULL;
static int (*real_ftruncate)(int, off_t) = NULL;
static int (*real_link)(const char *, const char *) = NULL;
static int (*real_linkat)(int, const char *, int, const char *, int) = NULL;
static int (*real_symlink)(const char *, const char *) = NULL;
static int (*real_symlinkat)(const char *, int, const char *) = NULL;
static int (*real_stat)(const char *, struct stat *) = NULL;
static int (*real_lstat)(const char *, struct stat *) = NULL;
static int (*real_fstat)(int, struct stat *) = NULL;
static int (*real_fstatat)(int, const char *, struct stat *, int) = NULL;
static int (*real_access)(const char *, int) = NULL;
static int (*real_faccessat)(int, const char *, int, int) = NULL;
static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
static ssize_t (*real_readlinkat)(int, const char *, char *, size_t) = NULL;
static int (*real_mkdir)(const char *, mode_t) = NULL;
static ssize_t (*real_write)(int, const void *, size_t) = NULL;
static int (*real_close)(int) = NULL;

// Initialize function pointers
static void init_hooks(void) {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        if (!real_open) abort();
    }
    if (!real_openat) {
        real_openat = dlsym(RTLD_NEXT, "openat");
        if (!real_openat) abort();
    }
    if (!real_creat) {
        real_creat = dlsym(RTLD_NEXT, "creat");
        if (!real_creat) abort();
    }
    if (!real_unlink) {
        real_unlink = dlsym(RTLD_NEXT, "unlink");
        if (!real_unlink) abort();
    }
    if (!real_unlinkat) {
        real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
        if (!real_unlinkat) abort();
    }
    if (!real_remove) {
        real_remove = dlsym(RTLD_NEXT, "remove");
        if (!real_remove) abort();
    }
    if (!real_rmdir) {
        real_rmdir = dlsym(RTLD_NEXT, "rmdir");
        if (!real_rmdir) abort();
    }
    if (!real_rename) {
        real_rename = dlsym(RTLD_NEXT, "rename");
        if (!real_rename) abort();
    }
    if (!real_renameat) {
        real_renameat = dlsym(RTLD_NEXT, "renameat");
        if (!real_renameat) abort();
    }
    if (!real_renameat2) {
        real_renameat2 = dlsym(RTLD_NEXT, "renameat2");
        if (!real_renameat2) abort();
    }
    if (!real_chmod) {
        real_chmod = dlsym(RTLD_NEXT, "chmod");
        if (!real_chmod) abort();
    }
    if (!real_fchmod) {
        real_fchmod = dlsym(RTLD_NEXT, "fchmod");
        if (!real_fchmod) abort();
    }
    if (!real_fchmodat) {
        real_fchmodat = dlsym(RTLD_NEXT, "fchmodat");
        if (!real_fchmodat) abort();
    }
    if (!real_chown) {
        real_chown = dlsym(RTLD_NEXT, "chown");
        if (!real_chown) abort();
    }
    if (!real_fchown) {
        real_fchown = dlsym(RTLD_NEXT, "fchown");
        if (!real_fchown) abort();
    }
    if (!real_lchown) {
        real_lchown = dlsym(RTLD_NEXT, "lchown");
        if (!real_lchown) abort();
    }
    if (!real_fchownat) {
        real_fchownat = dlsym(RTLD_NEXT, "fchownat");
        if (!real_fchownat) abort();
    }
    if (!real_truncate) {
        real_truncate = dlsym(RTLD_NEXT, "truncate");
        if (!real_truncate) abort();
    }
    if (!real_ftruncate) {
        real_ftruncate = dlsym(RTLD_NEXT, "ftruncate");
        if (!real_ftruncate) abort();
    }
    if (!real_link) {
        real_link = dlsym(RTLD_NEXT, "link");
        if (!real_link) abort();
    }
    if (!real_linkat) {
        real_linkat = dlsym(RTLD_NEXT, "linkat");
        if (!real_linkat) abort();
    }
    if (!real_symlink) {
        real_symlink = dlsym(RTLD_NEXT, "symlink");
        if (!real_symlink) abort();
    }
    if (!real_symlinkat) {
        real_symlinkat = dlsym(RTLD_NEXT, "symlinkat");
        if (!real_symlinkat) abort();
    }
    if (!real_stat) {
        real_stat = dlsym(RTLD_NEXT, "stat");
        if (!real_stat) abort();
    }
    if (!real_lstat) {
        real_lstat = dlsym(RTLD_NEXT, "lstat");
        if (!real_lstat) abort();
    }
    if (!real_fstat) {
        real_fstat = dlsym(RTLD_NEXT, "fstat");
        if (!real_fstat) abort();
    }
    if (!real_fstatat) {
        real_fstatat = dlsym(RTLD_NEXT, "fstatat");
        if (!real_fstatat) abort();
    }
    if (!real_access) {
        real_access = dlsym(RTLD_NEXT, "access");
        if (!real_access) abort();
    }
    if (!real_faccessat) {
        real_faccessat = dlsym(RTLD_NEXT, "faccessat");
        if (!real_faccessat) abort();
    }
    if (!real_readlink) {
        real_readlink = dlsym(RTLD_NEXT, "readlink");
        if (!real_readlink) abort();
    }
    if (!real_readlinkat) {
        real_readlinkat = dlsym(RTLD_NEXT, "readlinkat");
        if (!real_readlinkat) abort();
    }
    if (!real_mkdir) {
        real_mkdir = dlsym(RTLD_NEXT, "mkdir");
        if (!real_mkdir) abort();
    }
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
        if (!real_write) abort();
    }
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
        if (!real_close) abort();
    }
}

// Check if a string contains any keyword from a list
static int contains_keyword(const char *str, const char **keywords) {
    if (!str) return 0;

    for (int i = 0; keywords[i] != NULL; i++) {
        if (strstr(str, keywords[i]) != NULL) {
            DEBUG_PRINT("[MONITOR] String '%s' contains keyword '%s'\n", str, keywords[i]);
            return 1;
        }
    }
    return 0;
}

// Resolve file descriptor to path
static int resolve_fd_to_path(int fd, char *buf, size_t bufsize) {
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    
    ssize_t len = real_readlink(fd_path, buf, bufsize - 1);
    if (len < 0) {
        DEBUG_PRINT("[MONITOR] Failed to resolve fd %d: %s\n", fd, strerror(errno));
        return -1;
    }
    
    buf[len] = '\0';
    DEBUG_PRINT("[MONITOR] Resolved fd %d to path: %s\n", fd, buf);
    return 0;
}

// Get timestamp with microsecond precision
static void get_timestamp(char *buf, size_t bufsize) {
    struct timeval tv;
    struct tm *tm_info;
    
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    
    snprintf(buf, bufsize, "%04d-%02d-%02d %02d:%02d:%02d.%06ld",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             tv.tv_usec);
}

// Get process start time from /proc/[pid]/stat
static unsigned long get_process_start_time(pid_t pid) {
    char stat_path[64];
    char stat_buf[4096];
    int fd;
    ssize_t bytes_read;
    
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    
    fd = real_open(stat_path, O_RDONLY);
    if (fd < 0) {
        DEBUG_PRINT("[MONITOR] Failed to open %s: %s\n", stat_path, strerror(errno));
        return 0;
    }
    
    bytes_read = real_write(fd, stat_buf, sizeof(stat_buf) - 1);  // Using write as read placeholder
    // Actually we need read, but we're in a simplified example
    real_close(fd);
    
    if (bytes_read <= 0) {
        return 0;
    }
    
    stat_buf[bytes_read] = '\0';
    
    // Parse the 22nd field (starttime)
    // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags ... starttime
    // We need to skip past the comm field which may contain spaces and parentheses
    char *p = strchr(stat_buf, ')');
    if (!p) return 0;
    
    // Now parse remaining fields
    unsigned long starttime = 0;
    int field = 2;  // We're past pid and comm
    p += 2;  // Skip ") "
    
    while (*p && field < 22) {
        if (*p == ' ') {
            field++;
        }
        p++;
    }
    
    if (field == 22) {
        sscanf(p, "%lu", &starttime);
    }
    
    return starttime;
}

// Read file contents into a buffer
static char* read_file_contents(const char *path, size_t *size) {
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) {
        *size = 0;
        return NULL;
    }
    
    // Get file size
    struct stat st;
    if (real_fstat(fd, &st) < 0) {
        real_close(fd);
        *size = 0;
        return NULL;
    }
    
    size_t file_size = st.st_size;
    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        real_close(fd);
        *size = 0;
        return NULL;
    }
    
    ssize_t bytes_read = read(fd, buffer, file_size);
    real_close(fd);
    
    if (bytes_read < 0) {
        free(buffer);
        *size = 0;
        return NULL;
    }
    
    buffer[bytes_read] = '\0';
    *size = bytes_read;
    return buffer;
}

// Write string to file (helper for incident logging)
static int write_to_file(const char *path, const char *content) {
    int fd = real_open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        DEBUG_PRINT("[MONITOR] FATAL: Failed to open %s for writing: %s\n", path, strerror(errno));
        return -1;
    }
    
    size_t len = strlen(content);
    ssize_t written = real_write(fd, content, len);
    real_close(fd);
    
    if (written < 0 || (size_t)written != len) {
        DEBUG_PRINT("[MONITOR] FATAL: Failed to write to %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    return 0;
}

// Collect process tree information
static void collect_process_tree(char *buf, size_t bufsize) {
    pid_t current_pid = getpid();
    size_t offset = 0;
    
    offset += snprintf(buf + offset, bufsize - offset, "Process Tree:\n");
    
    while (current_pid > 1 && offset < bufsize - 256) {
        char stat_path[64];
        char stat_buf[4096];
        char comm[256] = {0};
        pid_t ppid = 0;
        
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", current_pid);
        
        size_t size;
        char *contents = read_file_contents(stat_path, &size);
        if (!contents) {
            break;
        }
        
        // Parse: pid (comm) state ppid
        if (sscanf(contents, "%*d (%255[^)]) %*c %d", comm, &ppid) >= 2) {
            offset += snprintf(buf + offset, bufsize - offset,
                             "  PID %d: %s\n", current_pid, comm);
        }
        
        free(contents);
        
        if (ppid <= 1) break;
        current_pid = ppid;
    }
}

// Create incident folder and collect initial process metadata
static void ensure_incident_folder(void) {
    pid_t current_pid = getpid();
    
    // Check if we're in a different process (fork detection)
    if (incident_state.initialized && incident_state.our_pid != current_pid) {
        DEBUG_PRINT("[MONITOR] Fork detected! Old PID=%d, New PID=%d - resetting incident state\n",
                   incident_state.our_pid, current_pid);
        incident_state.initialized = 0;
    }
    
    if (incident_state.initialized) {
        return;  // Already initialized for this process
    }
    
    DEBUG_PRINT("[MONITOR] Initializing incident folder for PID %d\n", current_pid);
    
    // Get process start time
    unsigned long start_time = get_process_start_time(current_pid);
    
    // Get current timestamp for folder name
    char timestamp[64];
    struct timeval tv;
    struct tm *tm_info;
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d_%02d-%02d-%02d.%06ld",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, tv.tv_usec);
    
    // Create incident directory path
    snprintf(incident_state.incident_dir, sizeof(incident_state.incident_dir),
             "/var/log/incidents/%s_PID%d_start%lu", timestamp, current_pid, start_time);
    
    DEBUG_PRINT("[MONITOR] Creating incident directory: %s\n", incident_state.incident_dir);
    
    // Create /var/log/incidents if it doesn't exist
    real_mkdir("/var/log/incidents", 0755);
    
    // Create the incident directory
    if (real_mkdir(incident_state.incident_dir, 0755) < 0) {
        DEBUG_PRINT("[MONITOR] FATAL: Failed to create incident directory %s: %s\n",
                   incident_state.incident_dir, strerror(errno));
        abort();
    }
    
    // Mark as initialized
    incident_state.our_pid = current_pid;
    incident_state.start_time = start_time;
    incident_state.initialized = 1;
    
    // Collect and write process metadata
    char path_buf[768];
    char content_buf[16384];
    
    // 1. Process info
    snprintf(path_buf, sizeof(path_buf), "%s/process_info.txt", incident_state.incident_dir);
    snprintf(content_buf, sizeof(content_buf),
             "PID: %d\n"
             "Start Time: %lu\n"
             "Real UID: %d\n"
             "Effective UID: %d\n"
             "Real GID: %d\n"
             "Effective GID: %d\n"
             "PPID: %d\n",
             current_pid, start_time,
             getuid(), geteuid(),
             getgid(), getegid(),
             getppid());
    
    // Add username if available
    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        size_t len = strlen(content_buf);
        snprintf(content_buf + len, sizeof(content_buf) - len,
                 "Username: %s\n", pw->pw_name);
    }
    
    if (write_to_file(path_buf, content_buf) < 0) abort();
    
    // 2. Command line
    snprintf(path_buf, sizeof(path_buf), "%s/cmdline.txt", incident_state.incident_dir);
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", current_pid);
    size_t size;
    char *cmdline = read_file_contents(cmdline_path, &size);
    if (cmdline) {
        // Replace null bytes with spaces for readability
        for (size_t i = 0; i < size - 1; i++) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
        if (write_to_file(path_buf, cmdline) < 0) {
            free(cmdline);
            abort();
        }
        if (write_to_file(path_buf, "\n") < 0) {
            free(cmdline);
            abort();
        }
        free(cmdline);
    }
    
    // 3. Executable path
    snprintf(path_buf, sizeof(path_buf), "%s/exe_path.txt", incident_state.incident_dir);
    char exe_path[PATH_MAX];
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", current_pid);
    ssize_t len = real_readlink(exe_link, exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        strcat(exe_path, "\n");
        if (write_to_file(path_buf, exe_path) < 0) abort();
    }
    
    // 4. Current working directory
    snprintf(path_buf, sizeof(path_buf), "%s/cwd.txt", incident_state.incident_dir);
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) {
        strcat(cwd, "\n");
        if (write_to_file(path_buf, cwd) < 0) abort();
    }
    
    // 5. Environment variables
    snprintf(path_buf, sizeof(path_buf), "%s/environ.txt", incident_state.incident_dir);
    char environ_path[64];
    snprintf(environ_path, sizeof(environ_path), "/proc/%d/environ", current_pid);
    char *env = read_file_contents(environ_path, &size);
    if (env) {
        // Replace null bytes with newlines
        for (size_t i = 0; i < size - 1; i++) {
            if (env[i] == '\0') env[i] = '\n';
        }
        if (write_to_file(path_buf, env) < 0) {
            free(env);
            abort();
        }
        free(env);
    }
    
    // 6. Process tree
    snprintf(path_buf, sizeof(path_buf), "%s/process_tree.txt", incident_state.incident_dir);
    collect_process_tree(content_buf, sizeof(content_buf));
    if (write_to_file(path_buf, content_buf) < 0) abort();
    
    // 7. Memory maps
    snprintf(path_buf, sizeof(path_buf), "%s/maps.txt", incident_state.incident_dir);
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", current_pid);
    char *maps = read_file_contents(maps_path, &size);
    if (maps) {
        if (write_to_file(path_buf, maps) < 0) {
            free(maps);
            abort();
        }
        free(maps);
    }
    
    // 8. Process status
    snprintf(path_buf, sizeof(path_buf), "%s/status.txt", incident_state.incident_dir);
    char status_path[64];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", current_pid);
    char *status = read_file_contents(status_path, &size);
    if (status) {
        if (write_to_file(path_buf, status) < 0) {
            free(status);
            abort();
        }
        free(status);
    }
    
    // 9. Open file descriptors
    snprintf(path_buf, sizeof(path_buf), "%s/fd_list.txt", incident_state.incident_dir);
    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", current_pid);
    DIR *dir = opendir(fd_dir);
    if (dir) {
        struct dirent *entry;
        content_buf[0] = '\0';
        size_t offset = 0;
        
        while ((entry = readdir(dir)) != NULL && offset < sizeof(content_buf) - 512) {
            if (entry->d_name[0] == '.') continue;
            
            char fd_link[128];
            char fd_target[PATH_MAX];
            snprintf(fd_link, sizeof(fd_link), "%s/%s", fd_dir, entry->d_name);
            ssize_t link_len = real_readlink(fd_link, fd_target, sizeof(fd_target) - 1);
            if (link_len > 0) {
                fd_target[link_len] = '\0';
                offset += snprintf(content_buf + offset, sizeof(content_buf) - offset,
                                 "fd %s -> %s\n", entry->d_name, fd_target);
            }
        }
        closedir(dir);
        
        if (offset > 0) {
            if (write_to_file(path_buf, content_buf) < 0) abort();
        }
    }
    
    DEBUG_PRINT("[MONITOR] Successfully created incident folder with initial metadata\n");
}

// Log an incident to the operations.log file and syslog
static void log_incident(const char *violation_type, const char *operation,
                        const char *path, const char *details) {
    // Ensure incident folder exists
    ensure_incident_folder();
    
    // Get timestamp
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    // Build log entry
    char log_entry[2048];
    snprintf(log_entry, sizeof(log_entry),
             "[%s] %s: %s on %s%s%s\n",
             timestamp, violation_type, operation, path,
             details && details[0] ? " " : "",
             details ? details : "");
    
    // Append to operations.log
    char log_path[768];
    snprintf(log_path, sizeof(log_path), "%s/operations.log", incident_state.incident_dir);
    
    DEBUG_PRINT("[MONITOR] Logging incident: %s", log_entry);
    
    if (write_to_file(log_path, log_entry) < 0) {
        abort();
    }
    
    // Send to syslog for Wazuh
    openlog("forensic_monitor", LOG_PID, LOG_AUTH);
    syslog(LOG_ALERT,
           "SECURITY_INCIDENT type=%s operation=%s path=%s uid=%d euid=%d pid=%d ppid=%d exe=%s incident_folder=%s",
           violation_type, operation, path,
           getuid(), geteuid(), getpid(), getppid(),
           program_invocation_short_name,
           incident_state.incident_dir);
    closelog();
    
    DEBUG_PRINT("[MONITOR] Incident logged successfully\n");
}

// Check if we should log this operation
static int should_log_operation(const char *path, int is_modification,
                               const char **out_violation_type,
                               const char *operation_name) {
    if (!path) return 0;
    
    // Never log operations on /var/log/incidents to prevent recursion
    if (strncmp(path, "/var/log/incidents", 18) == 0) {
        return 0;
    }
    
    int is_sensitive = contains_keyword(path, SENSITIVE_KEYWORDS);
    int is_protected = contains_keyword(path, PROTECTED_KEYWORDS);
    
    if (is_sensitive) {
        // Log ANY access to sensitive files
        if (is_modification) {
            // Determine specific violation type based on operation
            if (strstr(operation_name, "write") || strstr(operation_name, "open")) {
                *out_violation_type = "SENSITIVE_WRITE";
            } else if (strstr(operation_name, "delete") || strstr(operation_name, "unlink") || 
                      strstr(operation_name, "remove") || strstr(operation_name, "rmdir")) {
                *out_violation_type = "SENSITIVE_DELETE";
            } else if (strstr(operation_name, "rename")) {
                *out_violation_type = "SENSITIVE_RENAME";
            } else if (strstr(operation_name, "chmod")) {
                *out_violation_type = "SENSITIVE_CHMOD";
            } else if (strstr(operation_name, "chown")) {
                *out_violation_type = "SENSITIVE_CHOWN";
            } else if (strstr(operation_name, "truncate")) {
                *out_violation_type = "SENSITIVE_TRUNCATE";
            } else if (strstr(operation_name, "link")) {
                *out_violation_type = "SENSITIVE_LINK";
            } else {
                *out_violation_type = "SENSITIVE_MODIFICATION";
            }
        } else {
            // Read-only operations
            if (strstr(operation_name, "stat")) {
                *out_violation_type = "SENSITIVE_STAT";
            } else if (strstr(operation_name, "access")) {
                *out_violation_type = "SENSITIVE_ACCESS";
            } else if (strstr(operation_name, "readlink")) {
                *out_violation_type = "SENSITIVE_READLINK";
            } else {
                *out_violation_type = "SENSITIVE_READ";
            }
        }
        return 1;
    }
    
    if (is_protected && is_modification) {
        // Log only modifications to protected files
        if (strstr(operation_name, "write") || strstr(operation_name, "open")) {
            *out_violation_type = "UNAUTHORIZED_WRITE";
        } else if (strstr(operation_name, "delete") || strstr(operation_name, "unlink") || 
                  strstr(operation_name, "remove") || strstr(operation_name, "rmdir")) {
            *out_violation_type = "UNAUTHORIZED_DELETE";
        } else if (strstr(operation_name, "rename")) {
            *out_violation_type = "UNAUTHORIZED_RENAME";
        } else if (strstr(operation_name, "chmod")) {
            *out_violation_type = "UNAUTHORIZED_CHMOD";
        } else if (strstr(operation_name, "chown")) {
            *out_violation_type = "UNAUTHORIZED_CHOWN";
        } else if (strstr(operation_name, "truncate")) {
            *out_violation_type = "UNAUTHORIZED_TRUNCATE";
        } else if (strstr(operation_name, "link")) {
            *out_violation_type = "UNAUTHORIZED_LINK";
        } else {
            *out_violation_type = "UNAUTHORIZED_MODIFICATION";
        }
        return 1;
    }
    
    return 0;
}

// Get string representation of open flags
static void flags_to_string(int flags, char *buf, size_t bufsize) {
    buf[0] = '\0';
    size_t offset = 0;
    
    int access_mode = flags & O_ACCMODE;
    if (access_mode == O_RDONLY) {
        offset += snprintf(buf + offset, bufsize - offset, "O_RDONLY");
    } else if (access_mode == O_WRONLY) {
        offset += snprintf(buf + offset, bufsize - offset, "O_WRONLY");
    } else if (access_mode == O_RDWR) {
        offset += snprintf(buf + offset, bufsize - offset, "O_RDWR");
    }
    
    if (flags & O_CREAT) offset += snprintf(buf + offset, bufsize - offset, "%sO_CREAT", offset ? "|" : "");
    if (flags & O_TRUNC) offset += snprintf(buf + offset, bufsize - offset, "%sO_TRUNC", offset ? "|" : "");
    if (flags & O_APPEND) offset += snprintf(buf + offset, bufsize - offset, "%sO_APPEND", offset ? "|" : "");
    if (flags & O_EXCL) offset += snprintf(buf + offset, bufsize - offset, "%sO_EXCL", offset ? "|" : "");
}

//
// HOOK IMPLEMENTATIONS
//

// Hook open()
int open(const char *pathname, int flags, ...) {
    init_hooks();
    
    // Recursion guard
    if (in_incident_handler) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
            return real_open(pathname, flags, mode);
        }
        return real_open(pathname, flags);
    }
    
    DEBUG_PRINT("[MONITOR] open() called: pathname='%s', flags=0x%x\n",
               pathname ? pathname : "(null)", flags);
    
    // Determine if this is a modification
    int is_modification = 0;
    int access_mode = flags & O_ACCMODE;
    if (access_mode == O_WRONLY || access_mode == O_RDWR ||
        (flags & (O_TRUNC | O_CREAT | O_APPEND))) {
        is_modification = 1;
    }
    
    // Check if we should log
    const char *violation_type = NULL;
    if (should_log_operation(pathname, is_modification, &violation_type, "open")) {
        in_incident_handler = 1;
        
        char details[256];
        char flags_str[128];
        flags_to_string(flags, flags_str, sizeof(flags_str));
        snprintf(details, sizeof(details), "(flags=%s)", flags_str);
        
        log_incident(violation_type, "open", pathname, details);
        
        in_incident_handler = 0;
    }
    
    // Call real function
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        return real_open(pathname, flags, mode);
    }
    return real_open(pathname, flags);
}

// Hook openat()
int openat(int dirfd, const char *pathname, int flags, ...) {
    init_hooks();
    
    if (in_incident_handler) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
            return real_openat(dirfd, pathname, flags, mode);
        }
        return real_openat(dirfd, pathname, flags);
    }
    
    DEBUG_PRINT("[MONITOR] openat() called: dirfd=%d, pathname='%s', flags=0x%x\n",
               dirfd, pathname ? pathname : "(null)", flags);
    
    int is_modification = 0;
    int access_mode = flags & O_ACCMODE;
    if (access_mode == O_WRONLY || access_mode == O_RDWR ||
        (flags & (O_TRUNC | O_CREAT | O_APPEND))) {
        is_modification = 1;
    }
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, is_modification, &violation_type, "openat")) {
        in_incident_handler = 1;
        
        char details[256];
        char flags_str[128];
        flags_to_string(flags, flags_str, sizeof(flags_str));
        snprintf(details, sizeof(details), "(dirfd=%d, flags=%s)", dirfd, flags_str);
        
        log_incident(violation_type, "openat", pathname, details);
        
        in_incident_handler = 0;
    }
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        return real_openat(dirfd, pathname, flags, mode);
    }
    return real_openat(dirfd, pathname, flags);
}

// Hook creat()
int creat(const char *pathname, mode_t mode) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_creat(pathname, mode);
    }
    
    DEBUG_PRINT("[MONITOR] creat() called: pathname='%s', mode=0%o\n",
               pathname ? pathname : "(null)", mode);
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "creat")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(mode=0%o)", mode);
        
        log_incident(violation_type, "creat", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_creat(pathname, mode);
}

// Hook unlink()
int unlink(const char *pathname) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_unlink(pathname);
    }
    
    DEBUG_PRINT("[MONITOR] unlink() called: pathname='%s'\n",
               pathname ? pathname : "(null)");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "unlink")) {
        in_incident_handler = 1;
        log_incident(violation_type, "unlink", pathname, "");
        in_incident_handler = 0;
    }
    
    return real_unlink(pathname);
}

// Hook unlinkat()
int unlinkat(int dirfd, const char *pathname, int flags) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_unlinkat(dirfd, pathname, flags);
    }
    
    DEBUG_PRINT("[MONITOR] unlinkat() called: dirfd=%d, pathname='%s', flags=0x%x\n",
               dirfd, pathname ? pathname : "(null)", flags);
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "unlinkat")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(dirfd=%d, flags=0x%x)", dirfd, flags);
        
        log_incident(violation_type, "unlinkat", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_unlinkat(dirfd, pathname, flags);
}

// Hook remove()
int remove(const char *pathname) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_remove(pathname);
    }
    
    DEBUG_PRINT("[MONITOR] remove() called: pathname='%s'\n",
               pathname ? pathname : "(null)");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "remove")) {
        in_incident_handler = 1;
        log_incident(violation_type, "remove", pathname, "");
        in_incident_handler = 0;
    }
    
    return real_remove(pathname);
}

// Hook rmdir()
int rmdir(const char *pathname) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_rmdir(pathname);
    }
    
    DEBUG_PRINT("[MONITOR] rmdir() called: pathname='%s'\n",
               pathname ? pathname : "(null)");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "rmdir")) {
        in_incident_handler = 1;
        log_incident(violation_type, "rmdir", pathname, "");
        in_incident_handler = 0;
    }
    
    return real_rmdir(pathname);
}

// Hook rename()
int rename(const char *oldpath, const char *newpath) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_rename(oldpath, newpath);
    }
    
    DEBUG_PRINT("[MONITOR] rename() called: oldpath='%s', newpath='%s'\n",
               oldpath ? oldpath : "(null)", newpath ? newpath : "(null)");
    
    const char *violation_type = NULL;
    if (should_log_operation(oldpath, 1, &violation_type, "rename") ||
        should_log_operation(newpath, 1, &violation_type, "rename")) {
        in_incident_handler = 1;
        
        char details[512];
        snprintf(details, sizeof(details), "(oldpath='%s', newpath='%s')", oldpath, newpath);
        
        log_incident(violation_type, "rename", oldpath, details);
        
        in_incident_handler = 0;
    }
    
    return real_rename(oldpath, newpath);
}

// Hook renameat()
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_renameat(olddirfd, oldpath, newdirfd, newpath);
    }
    
    DEBUG_PRINT("[MONITOR] renameat() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(oldpath, 1, &violation_type, "renameat") ||
        should_log_operation(newpath, 1, &violation_type, "renameat")) {
        in_incident_handler = 1;
        
        char details[512];
        snprintf(details, sizeof(details),
                "(olddirfd=%d, oldpath='%s', newdirfd=%d, newpath='%s')",
                olddirfd, oldpath, newdirfd, newpath);
        
        log_incident(violation_type, "renameat", oldpath, details);
        
        in_incident_handler = 0;
    }
    
    return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}

// Hook renameat2()
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    }
    
    DEBUG_PRINT("[MONITOR] renameat2() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(oldpath, 1, &violation_type, "renameat2") ||
        should_log_operation(newpath, 1, &violation_type, "renameat2")) {
        in_incident_handler = 1;
        
        char details[512];
        snprintf(details, sizeof(details),
                "(olddirfd=%d, oldpath='%s', newdirfd=%d, newpath='%s', flags=0x%x)",
                olddirfd, oldpath, newdirfd, newpath, flags);
        
        log_incident(violation_type, "renameat2", oldpath, details);
        
        in_incident_handler = 0;
    }
    
    return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}

// Hook chmod()
int chmod(const char *pathname, mode_t mode) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_chmod(pathname, mode);
    }
    
    DEBUG_PRINT("[MONITOR] chmod() called: pathname='%s', mode=0%o\n",
               pathname ? pathname : "(null)", mode);
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "chmod")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(mode=0%o)", mode);
        
        log_incident(violation_type, "chmod", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_chmod(pathname, mode);
}

// Hook fchmod()
int fchmod(int fd, mode_t mode) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_fchmod(fd, mode);
    }
    
    DEBUG_PRINT("[MONITOR] fchmod() called: fd=%d, mode=0%o\n", fd, mode);
    
    // Resolve fd to path
    char path[PATH_MAX];
    if (resolve_fd_to_path(fd, path, sizeof(path)) < 0) {
        // Can't resolve path, pass through
        return real_fchmod(fd, mode);
    }
    
    const char *violation_type = NULL;
    if (should_log_operation(path, 1, &violation_type, "fchmod")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(fd=%d, mode=0%o)", fd, mode);
        
        log_incident(violation_type, "fchmod", path, details);
        
        in_incident_handler = 0;
    }
    
    return real_fchmod(fd, mode);
}

// Hook fchmodat()
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_fchmodat(dirfd, pathname, mode, flags);
    }
    
    DEBUG_PRINT("[MONITOR] fchmodat() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "fchmodat")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(dirfd=%d, mode=0%o, flags=0x%x)", dirfd, mode, flags);
        
        log_incident(violation_type, "fchmodat", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_fchmodat(dirfd, pathname, mode, flags);
}

// Hook chown()
int chown(const char *pathname, uid_t owner, gid_t group) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_chown(pathname, owner, group);
    }
    
    DEBUG_PRINT("[MONITOR] chown() called: pathname='%s', owner=%d, group=%d\n",
               pathname ? pathname : "(null)", owner, group);
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "chown")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(owner=%d, group=%d)", owner, group);
        
        log_incident(violation_type, "chown", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_chown(pathname, owner, group);
}

// Hook fchown()
int fchown(int fd, uid_t owner, gid_t group) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_fchown(fd, owner, group);
    }
    
    DEBUG_PRINT("[MONITOR] fchown() called: fd=%d, owner=%d, group=%d\n", fd, owner, group);
    
    char path[PATH_MAX];
    if (resolve_fd_to_path(fd, path, sizeof(path)) < 0) {
        return real_fchown(fd, owner, group);
    }
    
    const char *violation_type = NULL;
    if (should_log_operation(path, 1, &violation_type, "fchown")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(fd=%d, owner=%d, group=%d)", fd, owner, group);
        
        log_incident(violation_type, "fchown", path, details);
        
        in_incident_handler = 0;
    }
    
    return real_fchown(fd, owner, group);
}

// Hook lchown()
int lchown(const char *pathname, uid_t owner, gid_t group) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_lchown(pathname, owner, group);
    }
    
    DEBUG_PRINT("[MONITOR] lchown() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "lchown")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(owner=%d, group=%d)", owner, group);
        
        log_incident(violation_type, "lchown", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_lchown(pathname, owner, group);
}

// Hook fchownat()
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_fchownat(dirfd, pathname, owner, group, flags);
    }
    
    DEBUG_PRINT("[MONITOR] fchownat() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 1, &violation_type, "fchownat")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details),
                "(dirfd=%d, owner=%d, group=%d, flags=0x%x)", dirfd, owner, group, flags);
        
        log_incident(violation_type, "fchownat", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_fchownat(dirfd, pathname, owner, group, flags);
}

// Hook truncate()
int truncate(const char *path, off_t length) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_truncate(path, length);
    }
    
    DEBUG_PRINT("[MONITOR] truncate() called: path='%s', length=%ld\n",
               path ? path : "(null)", (long)length);
    
    const char *violation_type = NULL;
    if (should_log_operation(path, 1, &violation_type, "truncate")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(length=%ld)", (long)length);
        
        log_incident(violation_type, "truncate", path, details);
        
        in_incident_handler = 0;
    }
    
    return real_truncate(path, length);
}

// Hook ftruncate()
int ftruncate(int fd, off_t length) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_ftruncate(fd, length);
    }
    
    DEBUG_PRINT("[MONITOR] ftruncate() called: fd=%d, length=%ld\n", fd, (long)length);
    
    char path[PATH_MAX];
    if (resolve_fd_to_path(fd, path, sizeof(path)) < 0) {
        return real_ftruncate(fd, length);
    }
    
    const char *violation_type = NULL;
    if (should_log_operation(path, 1, &violation_type, "ftruncate")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(fd=%d, length=%ld)", fd, (long)length);
        
        log_incident(violation_type, "ftruncate", path, details);
        
        in_incident_handler = 0;
    }
    
    return real_ftruncate(fd, length);
}

// Hook link()
int link(const char *oldpath, const char *newpath) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_link(oldpath, newpath);
    }
    
    DEBUG_PRINT("[MONITOR] link() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(oldpath, 1, &violation_type, "link") ||
        should_log_operation(newpath, 1, &violation_type, "link")) {
        in_incident_handler = 1;
        
        char details[512];
        snprintf(details, sizeof(details), "(oldpath='%s', newpath='%s')", oldpath, newpath);
        
        log_incident(violation_type, "link", oldpath, details);
        
        in_incident_handler = 0;
    }
    
    return real_link(oldpath, newpath);
}

// Hook linkat()
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
    }
    
    DEBUG_PRINT("[MONITOR] linkat() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(oldpath, 1, &violation_type, "linkat") ||
        should_log_operation(newpath, 1, &violation_type, "linkat")) {
        in_incident_handler = 1;
        
        char details[512];
        snprintf(details, sizeof(details),
                "(olddirfd=%d, oldpath='%s', newdirfd=%d, newpath='%s', flags=0x%x)",
                olddirfd, oldpath, newdirfd, newpath, flags);
        
        log_incident(violation_type, "linkat", oldpath, details);
        
        in_incident_handler = 0;
    }
    
    return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

// Hook symlink()
int symlink(const char *target, const char *linkpath) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_symlink(target, linkpath);
    }
    
    DEBUG_PRINT("[MONITOR] symlink() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(linkpath, 1, &violation_type, "symlink")) {
        in_incident_handler = 1;
        
        char details[512];
        snprintf(details, sizeof(details), "(target='%s', linkpath='%s')", target, linkpath);
        
        log_incident(violation_type, "symlink", linkpath, details);
        
        in_incident_handler = 0;
    }
    
    return real_symlink(target, linkpath);
}

// Hook symlinkat()
int symlinkat(const char *target, int newdirfd, const char *linkpath) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_symlinkat(target, newdirfd, linkpath);
    }
    
    DEBUG_PRINT("[MONITOR] symlinkat() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(linkpath, 1, &violation_type, "symlinkat")) {
        in_incident_handler = 1;
        
        char details[512];
        snprintf(details, sizeof(details),
                "(target='%s', newdirfd=%d, linkpath='%s')", target, newdirfd, linkpath);
        
        log_incident(violation_type, "symlinkat", linkpath, details);
        
        in_incident_handler = 0;
    }
    
    return real_symlinkat(target, newdirfd, linkpath);
}

// Hook stat()
int stat(const char *pathname, struct stat *statbuf) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_stat(pathname, statbuf);
    }
    
    DEBUG_PRINT("[MONITOR] stat() called: pathname='%s'\n",
               pathname ? pathname : "(null)");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 0, &violation_type, "stat")) {
        in_incident_handler = 1;
        log_incident(violation_type, "stat", pathname, "");
        in_incident_handler = 0;
    }
    
    return real_stat(pathname, statbuf);
}

// Hook lstat()
int lstat(const char *pathname, struct stat *statbuf) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_lstat(pathname, statbuf);
    }
    
    DEBUG_PRINT("[MONITOR] lstat() called: pathname='%s'\n",
               pathname ? pathname : "(null)");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 0, &violation_type, "lstat")) {
        in_incident_handler = 1;
        log_incident(violation_type, "lstat", pathname, "");
        in_incident_handler = 0;
    }
    
    return real_lstat(pathname, statbuf);
}

// Hook fstat()
int fstat(int fd, struct stat *statbuf) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_fstat(fd, statbuf);
    }
    
    DEBUG_PRINT("[MONITOR] fstat() called: fd=%d\n", fd);
    
    char path[PATH_MAX];
    if (resolve_fd_to_path(fd, path, sizeof(path)) < 0) {
        return real_fstat(fd, statbuf);
    }
    
    const char *violation_type = NULL;
    if (should_log_operation(path, 0, &violation_type, "fstat")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(fd=%d)", fd);
        
        log_incident(violation_type, "fstat", path, details);
        
        in_incident_handler = 0;
    }
    
    return real_fstat(fd, statbuf);
}

// Hook fstatat()
int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_fstatat(dirfd, pathname, statbuf, flags);
    }
    
    DEBUG_PRINT("[MONITOR] fstatat() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 0, &violation_type, "fstatat")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(dirfd=%d, flags=0x%x)", dirfd, flags);
        
        log_incident(violation_type, "fstatat", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_fstatat(dirfd, pathname, statbuf, flags);
}

// Hook access()
int access(const char *pathname, int mode) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_access(pathname, mode);
    }
    
    DEBUG_PRINT("[MONITOR] access() called: pathname='%s', mode=%d\n",
               pathname ? pathname : "(null)", mode);
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 0, &violation_type, "access")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(mode=%d)", mode);
        
        log_incident(violation_type, "access", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_access(pathname, mode);
}

// Hook faccessat()
int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_faccessat(dirfd, pathname, mode, flags);
    }
    
    DEBUG_PRINT("[MONITOR] faccessat() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 0, &violation_type, "faccessat")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(dirfd=%d, mode=%d, flags=0x%x)", dirfd, mode, flags);
        
        log_incident(violation_type, "faccessat", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_faccessat(dirfd, pathname, mode, flags);
}

// Hook readlink()
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_readlink(pathname, buf, bufsiz);
    }
    
    DEBUG_PRINT("[MONITOR] readlink() called: pathname='%s'\n",
               pathname ? pathname : "(null)");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 0, &violation_type, "readlink")) {
        in_incident_handler = 1;
        log_incident(violation_type, "readlink", pathname, "");
        in_incident_handler = 0;
    }
    
    return real_readlink(pathname, buf, bufsiz);
}

// Hook readlinkat()
ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    init_hooks();
    
    if (in_incident_handler) {
        return real_readlinkat(dirfd, pathname, buf, bufsiz);
    }
    
    DEBUG_PRINT("[MONITOR] readlinkat() called\n");
    
    const char *violation_type = NULL;
    if (should_log_operation(pathname, 0, &violation_type, "readlinkat")) {
        in_incident_handler = 1;
        
        char details[256];
        snprintf(details, sizeof(details), "(dirfd=%d)", dirfd);
        
        log_incident(violation_type, "readlinkat", pathname, details);
        
        in_incident_handler = 0;
    }
    
    return real_readlinkat(dirfd, pathname, buf, bufsiz);
}
