#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(void) {
    const char *dir = "/root/ld_preload";
    const char *path = "/root/ld_preload/defense.txt";
    const mode_t dir_mode = 0755;   /* directory permissions */
    const mode_t file_mode = 0644;  /* file permissions */
    int fd;
    ssize_t wrote;
    const char *contents = "This is defense.txt\n";

    /* Create directory if it doesn't exist */
    if (mkdir(dir, dir_mode) != 0) {
        if (errno != EEXIST) {
            perror("mkdir");
            return 1;
        }
        /* if EEXIST, it's fine */
    }

    /* open (create/truncate) the file */
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, file_mode);
    if (fd == -1) {
        perror("open");
        return 2;
    }

    /* write contents */
    wrote = write(fd, contents, strlen(contents));
    if (wrote == -1) {
        perror("write");
        close(fd);
        return 3;
    }

    /* flush and close */
    if (fsync(fd) != 0) {
        perror("fsync");
        /* not fatal for many uses, continue to close */
    }
    close(fd);

    return 0;
}

