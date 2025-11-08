#define _GNU_SOURCE
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    DIR *dir = opendir("/proc");
    if (!dir) {
        perror("opendir");
        return 1;
    }
    
    printf("Reading /proc directory...\n");
    
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL) {
        // Only print numeric entries (PIDs)
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            printf("Found PID: %s\n", entry->d_name);
            count++;
            if (count > 10) break;  // Just show first 10
        }
    }
    
    closedir(dir);
    return 0;
}
