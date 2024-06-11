#include <arpa/inet.h>  // Include for inet_addr
#include <netinet/in.h> // Include for INET sockets
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <unistd.h>
#include <wait.h>

#include "common.h"

#define PORT 8080 // Define the port number for the server

#define MAX_SOCKET_CONNECTIONS 128
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    struct sockaddr addr;
} client_thread_arg_t;

typedef struct {
    int server_socket;
} connection_thread_arg_t;

typedef struct {
    int client_socket;
    char filename[FILE_SIZE];
    char out_filename[FILE_SIZE];
    char encoder[10];
} file_processing_arg_t;

void *encode_handler(void *arg);
void send_response_file(int socket, char *filename, char *out_filename);

void print_byte_buffer(const unsigned char *buffer, size_t size) {
    printf("b'"); // Start of the byte string in Python format
    for (size_t i = 0; i < size; i++) {
        printf("\\x%02X", buffer[i]); // Print byte in hexadecimal escape format
    }
    printf("'");  // End of the byte string
    printf("\n"); // Print a newline for better output formatting
}

// Thread function to handle each client
void *client_handler(void *arg) {
    client_thread_arg_t *client_data = (client_thread_arg_t *)arg;
    int client_fd = client_data->socket;
    free(client_data);

    FILE *input_file = NULL;
    char unique_filename[FILE_SIZE];
    int unique_id = 1;

    while (1) {
        // Read header
        printf("READING HEADER\n");
        size_t headerSize = sizeof(RequestHeader);
        char header_buffer[headerSize];
        receive_all(client_fd, header_buffer, headerSize);

        for (int i = 0; i < 2; ++i) {
            putchar(header_buffer[i]);
        }
        printf("\n");

        // Cast the buffer to struct
        RequestHeader req;
        memcpy(&req, header_buffer, headerSize);
        printf("GOT HEADER\n");

        // printf("%s\n%s\n%s\n%d\n", req.encoder, req.input_filename,
        // req.output_filename, req.length);

        // Create local file and receive from client
        snprintf(unique_filename, sizeof(unique_filename), "%d_%d_%s",
                 client_fd, unique_id, req.input_filename);
        input_file = fopen(unique_filename, "wb");
        receive_file(client_fd, input_file, req.length);
        printf("Recived file\n");
        fclose(input_file);
        input_file = NULL;
        unique_id++;

        // Start a new thread for processing
        printf("File received, starting processing...\n");
        printf("operation = %d\n", req.operation);
        pthread_t processing_thread;
        file_processing_arg_t *processing_arg =
            malloc(sizeof(file_processing_arg_t));
        processing_arg->client_socket = client_fd;
        strcpy(processing_arg->filename, unique_filename);
        strcpy(processing_arg->out_filename, req.output_filename);
        strcpy(processing_arg->encoder, req.encoder);

        switch (req.operation) {
        case kEncode:
            printf("RIGHT OPERATION\n");
            pthread_create(&processing_thread, NULL, encode_handler,
                           processing_arg);
            return NULL;

        case kCut:
            // pthread_create(&processing_thread, NULL, cut_handler,
            // processing_arg);
            break;

        default:
            printf("Unknown operation\n");
            continue;
        }

        pthread_detach(processing_thread);
    }

    if (input_file)
        fclose(input_file);
    close(client_fd);
    return NULL;
}

void *client_connection_handler(void *arg) {
    connection_thread_arg_t *connection_arg = (connection_thread_arg_t *)arg;
    int server_fd = connection_arg->server_socket;

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1)
            continue;

        printf("Got new inet connection\n");

        pthread_t client_thread;
        client_thread_arg_t *arg = malloc(sizeof(client_thread_arg_t));
        arg->socket = client_fd;
        pthread_create(&client_thread, NULL, client_handler, arg);
        pthread_detach(client_thread); // Do not wait for thread termination
    }
}

void shutdown_handler(int sig) { printf("Server shutting down...\n"); }

void *encode_handler(void *arg) {
    file_processing_arg_t *data = (file_processing_arg_t *)arg;
    int socket = data->client_socket;
    char filename[FILE_SIZE];
    strcpy(filename, data->filename);
    char out_filename[FILE_SIZE];
    strcpy(out_filename, data->out_filename);
    char encoder[10];
    strcpy(encoder, data->encoder);

    printf("Starting encoding process for file %s...\n", data->filename);
    char output_filename[FILE_SIZE];
    snprintf(output_filename, sizeof(output_filename), "encoded_%s", filename);

    // Construct FFmpeg command to encode the video
    char command[1024];
    snprintf(command, sizeof(command),
             "ffmpeg -i \"%s\" -c:v %s -c:a copy \"%s\"", filename, encoder,
             output_filename);

    // Execute FFmpeg command
    system(command);

    printf("Encoding completed for file %s, output in %s\n", filename,
           output_filename);

    send_response_file(socket, output_filename, out_filename);
}

void send_response_file(int socket, char *filename, char *out_filename) {
    // Open file to determine the size and to send
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    ResponseHeader resp;
    strcpy(resp.output_filename, out_filename);

    // Determine file size and number of chunks
    fseek(file, 0, SEEK_END);
    resp.length = ftell(file);
    rewind(file);

    send_all(socket, (char *)&resp, sizeof(ResponseHeader));
    send_file(socket, file);
    fclose(file);
}

int main() {
    int server_fd;
    struct sockaddr_in server_addr;

    // Setup socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    // Forcefully attaching socket to the port 8080
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr =
        htonl(INADDR_ANY); // Listen on any available interface
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_SOCKET_CONNECTIONS) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    pthread_t connection_thread;
    connection_thread_arg_t *connection_arg =
        malloc(sizeof(connection_thread_arg_t));
    connection_arg->server_socket = server_fd;
    pthread_create(&connection_thread, NULL, client_connection_handler,
                   connection_arg);
    pthread_detach(connection_thread); // The thread can run independently

    int ux_server_fd;
    struct sockaddr_un server_addr_ux;

    // Setup socket
    ux_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&server_addr_ux, 0, sizeof(struct sockaddr_un));
    server_addr_ux.sun_family = AF_UNIX;
    strcpy(server_addr_ux.sun_path, UX_SOCKET_PATH);
    unlink(UX_SOCKET_PATH);
    bind(ux_server_fd, (struct sockaddr *)&server_addr_ux,
         sizeof(server_addr_ux));
    listen(ux_server_fd, MAX_SOCKET_CONNECTIONS);

    pthread_t ux_connection_thread;
    connection_thread_arg_t *ux_connection_arg =
        malloc(sizeof(connection_thread_arg_t));
    ux_connection_arg->server_socket = ux_server_fd;
    pthread_create(&ux_connection_thread, NULL, client_connection_handler,
                   ux_connection_arg);
    pthread_detach(ux_connection_thread); // The thread can run independently

    int admin_ux_server_fd;
    struct sockaddr_un admin_server_addr_ux;

    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    printf("Server start\n");

    pause();

    close(server_fd);

    return 0;
}
