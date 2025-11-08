#include <stdio.h>
#include <unistd.h>

int main() {
    while (1) {
        //printf("I am a malicious process running in the background...\n");
        sleep(5); // Sleep for 5 seconds
    }
    return 0;
}

