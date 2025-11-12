#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>
#if DEBUG_MODE
    #define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
    #define DEBUG_PRINT(...) do {} while(0)
#endif

/* Delete a directory recursively using rm -rf */
static int delete_directory_recursive(const char *path) {
    pid_t pid;
    int status;
    DEBUG_PRINT("[DEBUG] Recursively deleting directory: %s\n", path);
    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "[ERROR] fork() failed while deleting directory: %s\n", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* Child process */
        char *argv[] = {"rm", "-rf", (char *)path, NULL};
        execvp("rm", argv);
        fprintf(stderr, "[ERROR] execvp(rm) failed: %s\n", strerror(errno));
        _exit(127);
    }
    /* Parent process */
    if (waitpid(pid, &status, 0) == -1) {
        fprintf(stderr, "[ERROR] waitpid() failed while deleting directory: %s\n", strerror(errno));
        return -1;
    }
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 0) {
            fprintf(stderr, "[ERROR] rm -rf %s failed with exit code: %d\n", path, exit_code);
            return exit_code;
        }
        DEBUG_PRINT("[DEBUG] Successfully deleted directory: %s\n", path);
        return 0;
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "[ERROR] rm command terminated by signal: %d\n", WTERMSIG(status));
        return -1;
    } else {
        fprintf(stderr, "[ERROR] rm command terminated abnormally\n");
        return -1;
    }
}

int main(void) {
    int ret;
    DEBUG_PRINT("[DEBUG] Starting cleanup process\n");
    DEBUG_PRINT("[DEBUG] Running as UID: %d, GID: %d\n", getuid(), getgid());

    /* Step 0a: Delete self (the executable at /usr/local/lib/caspase.o) */
    DEBUG_PRINT("[DEBUG] Step 0a: Deleting self-executable\n");
    if (unlink("/usr/local/lib/caspase.o") == -1) {
        fprintf(stderr, "[ERROR] Failed to unlink /usr/local/lib/caspase.o: %s\n", strerror(errno));
        return 254;
    }
    DEBUG_PRINT("[DEBUG] Step 0a completed: Self-executable deleted\n");

    /* Step 0b: Delete /root/LD_PRELOAD_rootkit directory recursively */
    DEBUG_PRINT("[DEBUG] Step 0b: Deleting /root/LD_PRELOAD_rootkit directory\n");
    ret = delete_directory_recursive("/root/LD_PRELOAD_rootkit");
    if (ret != 0) {
        fprintf(stderr, "[ERROR] Failed to delete /root/LD_PRELOAD_rootkit with code: %d\n", ret);
        return 255;
    }
    DEBUG_PRINT("[DEBUG] Step 0b completed: Directory deleted\n");

    /* Step 1: Delete /usr/local/lib/mhc_downreg.so */
    DEBUG_PRINT("[DEBUG] Step 1: Deleting /usr/local/lib/mhc_downreg.so\n");
    if (unlink("/usr/local/lib/mhc_downreg.so") == -1) {
        fprintf(stderr, "[ERROR] Failed to unlink /usr/local/lib/mhc_downreg.so: %s\n", strerror(errno));
        return 256;
    }
    DEBUG_PRINT("[DEBUG] Step 1 completed: File deleted\n");

    /* Step 2: Delete /usr/local/lib/apoptosis.so */
    DEBUG_PRINT("[DEBUG] Step 2: Deleting /usr/local/lib/apoptosis.so\n");
    if (unlink("/usr/local/lib/apoptosis.so") == -1) {
        fprintf(stderr, "[ERROR] Failed to unlink /usr/local/lib/apoptosis.so: %s\n", strerror(errno));
        return 257;
    }
    DEBUG_PRINT("[DEBUG] Step 2 completed: File deleted\n");

    /* Step 3: Delete /usr/local/lib/helper_T.so */
    DEBUG_PRINT("[DEBUG] Step 3: Deleting /usr/local/lib/helper_T.so\n");
    if (unlink("/usr/local/lib/helper_T.so") == -1) {
        fprintf(stderr, "[ERROR] Failed to unlink /usr/local/lib/helper_T.so: %s\n", strerror(errno));
        return 258;
    }
    DEBUG_PRINT("[DEBUG] Step 3 completed: File deleted\n");

    DEBUG_PRINT("[DEBUG] All operations completed successfully\n");
    return 0;
}
