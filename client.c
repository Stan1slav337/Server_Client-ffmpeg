#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include "common.h"

typedef struct
{
    int socket;
} receive_thread_arg_t;

void *receive_handler(void *arg)
{
    receive_thread_arg_t *receive_data = (receive_thread_arg_t *)arg;
    int server_fd = receive_data->socket;
    free(receive_data);

    Response resp;

    size_t bytes_received = 0UL;
    while ((bytes_received = read(server_fd, &resp, sizeof(Response))) > 0)
    {
        FILE *file = fopen(resp.output_filename, "ab");
        if (!file)
        {
            perror("Failed to open file for writing");
            continue; // Skip to the next iteration if file opening fails
        }

        fwrite(resp.chunk, 1, bytes_received - sizeof(Response) + CHUNK_SIZE, file);
        fclose(file);
        if (resp.remaining_chunks == 0)
        {
            // Last chunk received
            printf("File processed completely, output: %s\n", resp.output_filename);
        }
    }
}

int main()
{
    int sock_fd;
    struct sockaddr_un server_addr;
    Request req;

    // Create socket
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

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
        printf("1. Encode video\n");
        printf("Select an option: ");
        int option;
        scanf("%d", &option);

        if (option == 1)
        {
            req.operation = kEncode;
            printf("Enter input filename: ");
            scanf("%s", req.input_filename);
            printf("Enter output filename: ");
            scanf("%s", req.output_filename);

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
                strcpy(req.encoder, "libx264");
                break;
            case 2:
                strcpy(req.encoder, "libx265");
                break;
            case 3:
                strcpy(req.encoder, "libsvtav");
                break;
            default:
                printf("Invalid option!\n");
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
            long file_size = ftell(file);
            rewind(file);
            req.remaining_chunks = file_size / CHUNK_SIZE + (file_size % CHUNK_SIZE != 0); // Calculate chunks

            // Send request header for encode
            write(sock_fd, &req, sizeof(Request));

            // Send file in chunks
            while (req.remaining_chunks--)
            {
                size_t bytes_read = fread(req.chunk, 1, CHUNK_SIZE, file);
                if (bytes_read > 0)
                {
                    req.operation = kSendChunk;
                    // Sending only the necessary bytes in the last chunk
                    write(sock_fd, &req, sizeof(Request) - CHUNK_SIZE + bytes_read);
                }
            }
            fclose(file);
        }
        else
        {
            printf("Invalid option!\n");
        }
    }

    close(sock_fd);
    return 0;
}
