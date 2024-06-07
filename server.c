#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "common.h"

#define MAX_SOCKET_CONNECTIONS 128

typedef struct
{
    int socket;
} client_thread_arg_t;

typedef struct
{
    int server_socket;
} connection_thread_arg_t;

typedef struct
{
    int client_socket;
    char filename[FILE_SIZE];
    char out_filename[FILE_SIZE];
    char encoder[10];
} file_processing_arg_t;

void *encode_handler(void *arg);
void send_response_file(int socket, char *filename, char *out_filename);

// Thread function to handle each client
void *client_handler(void *arg)
{
    client_thread_arg_t *client_data = (client_thread_arg_t *)arg;
    int client_fd = client_data->socket;
    free(client_data);

    FILE *input_file = NULL;
    char unique_filename[FILE_SIZE];
    int unique_id = 1;

    while (1)
    {
        // Read header
        size_t headerSize = sizeof(RequestHeader);
        char header_buffer[headerSize];
        receive_all(client_fd, header_buffer, headerSize);

        // Cast the buffer to struct
        RequestHeader req;
        memcpy(&req, header_buffer, headerSize);

        // printf("%s\n%s\n%s\n%d\n", req.encoder, req.input_filename, req.output_filename, req.length);

        // Create local file and receive from client
        snprintf(unique_filename, sizeof(unique_filename), "%d_%d_%s", client_fd, unique_id, req.input_filename);
        input_file = fopen(unique_filename, "wb");
        receive_file(client_fd, input_file, req.length);
        fclose(input_file);
        input_file = NULL;
        unique_id++;

        // Start a new thread for processing
        printf("File received, starting processing...\n");
        pthread_t processing_thread;
        file_processing_arg_t *processing_arg = malloc(sizeof(file_processing_arg_t));
        processing_arg->client_socket = client_fd;
        strcpy(processing_arg->filename, unique_filename);
        strcpy(processing_arg->out_filename, req.output_filename);
        strcpy(processing_arg->encoder, req.encoder);

        switch (req.operation)
        {
        case kEncode:
            pthread_create(&processing_thread, NULL, encode_handler, processing_arg);
            break;

        case kCut:
            // pthread_create(&processing_thread, NULL, cut_handler, processing_arg);
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

void *ux_connection_handler(void *arg)
{
    connection_thread_arg_t *connection_arg = (connection_thread_arg_t *)arg;
    int server_fd = connection_arg->server_socket;

    while (1)
    {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1)
            continue;

        printf("Got new unix connection\n");

        pthread_t client_thread;
        client_thread_arg_t *arg = malloc(sizeof(client_thread_arg_t));
        arg->socket = client_fd;
        pthread_create(&client_thread, NULL, client_handler, arg);
        pthread_detach(client_thread); // Do not wait for thread termination
    }
}

void shutdown_handler(int sig)
{
    printf("Server shutting down...\n");
}

void *encode_handler(void *arg)
{
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
    snprintf(command, sizeof(command), "ffmpeg -i \"%s\" -c:v %s -c:a copy \"%s\"",
             filename, encoder, output_filename);

    // Execute FFmpeg command
    system(command);

    printf("Encoding completed for file %s, output in %s\n", filename, output_filename);

    send_response_file(socket, output_filename, out_filename);
}

void send_response_file(int socket, char *filename, char *out_filename)
{
    // Open file to determine the size and to send
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Failed to open file");
        return;
    }

    ResponseHeader resp;
    strcpy(resp.output_filename, out_filename);

    // Determine file size and number of chunks
    fseek(file, 0, SEEK_END);
    resp.length = ftell(file);
    rewind(file);

    send_all(socket, (char*)&resp, sizeof(ResponseHeader));
    send_file(socket, file);
    fclose(file);
}

int main()
{
    int ux_server_fd;
    struct sockaddr_un server_addr;

    // Setup socket
    ux_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, UX_SOCKET_PATH);
    unlink(UX_SOCKET_PATH);
    bind(ux_server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(ux_server_fd, MAX_SOCKET_CONNECTIONS);

    pthread_t ux_connection_thread;
    connection_thread_arg_t *connection_arg = malloc(sizeof(connection_thread_arg_t));
    connection_arg->server_socket = ux_server_fd;
    pthread_create(&ux_connection_thread, NULL, ux_connection_handler, connection_arg);
    pthread_detach(ux_connection_thread); // The thread can run independently

    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    printf("Server start\n");

    pause();

    close(ux_server_fd);

    return 0;
}
