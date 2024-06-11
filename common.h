#include <stdio.h>

#define UX_SOCKET_PATH "/tmp/server.sock"
#define ADMIN_SOCKET_PATH "/tmp/server_admin.sock"
#define BUFFER_SIZE 4096
#define FILE_SIZE 256

typedef enum { kEncode = 1, kCut } OperationType;

typedef struct {
    OperationType operation;
    char encoder[10];                // Encoder
    char input_filename[FILE_SIZE];  // Filename for input
    char output_filename[FILE_SIZE]; // Filename for output
    long length;                     // Size of file
} RequestHeader;

typedef struct {
    char output_filename[FILE_SIZE];
    long length;
} ResponseHeader;

void send_all(int sockfd, const char *data, size_t total_bytes) {
    size_t bytes_sent = 0;
    while (bytes_sent < total_bytes) {
        bytes_sent +=
            write(sockfd, data + bytes_sent, total_bytes - bytes_sent);
    }
}

void send_file(int socket_fd, FILE *file) {
    char buffer[BUFFER_SIZE];
    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        send_all(socket_fd, buffer, bytes_read);
    }
}

void receive_all(int socket_fd, char *buffer, size_t bytes_total) {
    size_t bytes_received = 0UL;
    while (bytes_received < bytes_total) {
        bytes_received += read(socket_fd, buffer + bytes_received,
                               bytes_total - bytes_received);
        printf("bytes received = %d\n", bytes_received);
    }
}

void receive_file(int socket_fd, FILE *input_file, size_t file_length) {
    char buffer[BUFFER_SIZE];
    size_t bytes_received = 0UL;
    printf("file_size = %d\n", file_length);
    int chunk = 0;
    while (bytes_received < file_length) {
        // read buffer size but maybe it's file end, so need less

        int diff = file_length - bytes_received;
        if (diff == 0)
            break;
        printf("file_legth %d: %zu bytes received so far diff = %d\n",
               file_length, bytes_received, diff);
        size_t to_read = (diff < BUFFER_SIZE ? diff : BUFFER_SIZE);
        chunk += 1;
        printf("Chunk %d: %zu to read\n", chunk, to_read);
        size_t bytes_read = read(socket_fd, buffer, to_read);
        printf("Chunk %d: %zu bytes read\n", chunk, bytes_read);
        bytes_received += bytes_read;
        printf("Chunk %d: %zu bytes received\n", chunk, bytes_received);
        fwrite(buffer, 1, bytes_read, input_file);
    }
}