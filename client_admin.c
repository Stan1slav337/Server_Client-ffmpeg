#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common.h"

int sock_fd;

int main() {
    struct sockaddr_un server_addr;
    RequestHeader req;

    // Create socket
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, ADMIN_SOCKET_PATH);

    // Connect to server
    if (connect(sock_fd, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    char buffer[ADMIN_BUFFER_SIZE];
    char input[ADMIN_BUFFER_SIZE];

    while (1) {
        printf(">>> ");
        fgets(input, sizeof(input), stdin);
        size_t len = strlen(input);
        if (input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }

        if (strcmp(input, "quit") == 0)
            break;

        if (send(sock_fd, input, strlen(input), 0) < 0) {
            perror("Sendto failed");
            continue;
        }

        ssize_t num_read = recv(sock_fd, buffer, ADMIN_BUFFER_SIZE, 0);
        if (num_read > 0) {
            buffer[num_read] = '\0';
            printf("Server response: %s\n", buffer);
        } else {
            perror("Recvfrom failed");
        }
    }

    return 0;
}
