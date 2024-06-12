#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "common.h"

int sock_fd;

typedef struct
{
    int socket;
} receive_thread_arg_t;

void *receive_handler(void *arg)
{
    receive_thread_arg_t *receive_data = (receive_thread_arg_t *)arg;
    int server_fd = receive_data->socket;
    free(receive_data);

    while (1)
    {
        // Read header
        size_t headerSize = sizeof(ResponseHeader);
        char header_buffer[headerSize];
        receive_all(server_fd, header_buffer, headerSize);

        // Cast the buffer to struct
        ResponseHeader resp;
        memcpy(&resp, header_buffer, headerSize);

        FILE *file = fopen(resp.output_filename, "wb");
        if (!file)
        {
            perror("Failed to open file for writing");
            return NULL;
        }

        receive_file(server_fd, file, resp.length);
        fclose(file);
        printf("\nFile processed completely, output: %s\n", resp.output_filename);
    }
}

void option_encoding(RequestHeader *req)
{
    req->operation = kEncode;
    printf("Choose encoder type:\n");
    printf("1. h264\n");
    printf("2. h265\n");
    printf("3. AV1\n");
    printf("Enter your choice: ");

    int encoder_choice;
    scanf("%d", &encoder_choice);
    switch (encoder_choice)
    {
    case 1:
        strcpy(req->encoder, "libx264");
        break;
    case 2:
        strcpy(req->encoder, "libx265");
        break;
    case 3:
        strcpy(req->encoder, "libsvtav");
        break;
    default:
        printf("Invalid option!\n");
        option_encoding(req);
    }
}

void option_speed(RequestHeader *req)
{
    req->operation = kSpeed;
    printf("Enter a speed rate between 0.5 and 2.0: ");

    scanf("%lf", &req->speed_rate);
}

void option_trim(RequestHeader *req)
{
    req->operation = kTrim;
    printf("Enter start time position of the trim in the HH:MM:SS format: ");
    scanf("%s", &req->start_trim);
    printf("Enter end time position of the trim in the HH:MM:SS format: ");
    scanf("%s", &req->end_trim);
}

void shutdown_handler(int sig)
{
    close(sock_fd);
    exit(0);
}

int main()
{
    struct sockaddr_un server_addr;
    RequestHeader req;

    // Create socket
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, UX_SOCKET_PATH);

    // Connect to server
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    pthread_t receive_thread;
    receive_thread_arg_t *receive_arg = malloc(sizeof(receive_thread_arg_t));
    receive_arg->socket = sock_fd;
    pthread_create(&receive_thread, NULL, receive_handler, receive_arg);
    pthread_detach(receive_thread); // Do not wait for thread termination

    // User Interface
    while (1)
    {
        printf("Available Functions:\n");
        printf("1. Encode video/audio\n");
        printf("2. Change speed of video/audio\n");
        printf("3. Trim video/audio\n");
        printf("4. Extract audio from video\n");
        printf("Select an option: ");
        int option;
        scanf("%d", &option);

        printf("Enter input filename: ");
        scanf("%s", req.input_filename);
        printf("Enter output filename: ");
        scanf("%s", req.output_filename);

        switch (option)
        {
        case 1:
            option_encoding(&req);
            break;

        case 2:
            option_speed(&req);
            break;

        case 3:
            option_trim(&req);
            break;

        case 4:
            req.operation = kExtractAudio;
            break;

        case 5:
            req.operation = kConvert;
            break;

        default:
            printf("Invalid option\n");
            continue;
        }

        // Open file to determine the number of chunks
        FILE *file = fopen(req.input_filename, "rb");
        if (!file)
        {
            perror("Failed to open file");
            close(sock_fd);
            return -1;
        }

        // Determine file size and number of chunks
        fseek(file, 0, SEEK_END);
        req.length = ftell(file);
        rewind(file);

        send_all(sock_fd, (char *)&req, sizeof(RequestHeader));
        send_file(sock_fd, file);
        fclose(file);
    }

    return 0;
}
