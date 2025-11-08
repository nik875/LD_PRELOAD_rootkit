/* show_socket.c
 * Simple TCP client that connects and then sleeps so you can observe it with `ss`.
 *
 * Usage: compile and run: gcc -o show_socket show_socket.c && ./show_socket
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>   // inet_pton
#include <netinet/in.h>  // struct sockaddr_in
#include <sys/socket.h>
#include <errno.h>

int main(void) {
    const char *addr = "93.184.216.34"; /* example.com IPv4; change to 127.0.0.1 if you prefer */
    const int port = 80;                /* HTTP port; change as desired */

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        perror("inet_pton");
        close(s);
        return 1;
    }

    printf("Connecting to %s:%d...\n", addr, port);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(s);
        return 1;
    }

    printf("Connected (fd=%d). Sleeping 300 seconds — run `ss -tupn` in another terminal to see it.\n", s);

    /* Keep the socket open so ss can see it. */
    sleep(300);

    close(s);
    printf("Done.\n");
    return 0;
}

