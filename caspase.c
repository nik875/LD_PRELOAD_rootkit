#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

#if DEBUG_MODE
    #define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
    #define DEBUG_PRINT(...) do {} while(0)
#endif

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

    DEBUG_PRINT("[DEBUG] Starting wazuh-agent removal process\n");
    DEBUG_PRINT("[DEBUG] Running as UID: %d, GID: %d\n", getuid(), getgid());

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
