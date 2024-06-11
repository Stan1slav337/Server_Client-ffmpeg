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

typedef struct {
    int socket;
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

        printf("%s\n%s\n", req.input_filename, req.output_filename);

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

// Executa o comanda de sistem si trimite rezultatul clientului
void execute_system_command(int client_socket, const char *command) {
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) != 0) {
        perror("Pipe failed");
        return;
    }

    pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    } else if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        perror("Exec failed");
        exit(EXIT_FAILURE);
    }

    close(pipefd[1]);
    char buffer[ADMIN_BUFFER_SIZE] = {0};
    ssize_t bytes_read;
    char response[ADMIN_BUFFER_SIZE] = {0};
    int response_len = 0;

    while ((bytes_read = read(pipefd[0], buffer, ADMIN_BUFFER_SIZE - 1)) > 0) {
        if (response_len + bytes_read < ADMIN_BUFFER_SIZE - 1) {
            memcpy(response + response_len, buffer, bytes_read);
            response_len += bytes_read;
        } else {
            break;
        }
    }
    response[response_len] = '\0'; // Termina cu NULL output-ul acumulat
    send(client_socket, response, response_len, 0);

    close(pipefd[0]);
    wait(NULL); // Asteapta terminarea procesului copil
}

// Proceseaza comenzi primite de la client
void process_command(int client_socket, char *command) {
    if (strncmp(command, "uptime", 6) == 0) {
        struct sysinfo info;
        if (sysinfo(&info) != 0) {
            perror("sysinfo failed");
            return;
        }
        char response[128];
        snprintf(response, sizeof(response),
                 "Server is UP for %ldd %ldh%02ldm%02lds", info.uptime / 86400,
                 (info.uptime % 86400) / 3600, (info.uptime % 3600) / 60,
                 info.uptime % 60);
        send(client_socket, response, strlen(response), 0);
    } else if (strncmp(command, "stats", 5) == 0) {
        struct sysinfo info;
        if (sysinfo(&info) != 0) {
            perror("sysinfo failed");
            return;
        }

        char response[ADMIN_BUFFER_SIZE];
        snprintf(response, sizeof(response),
                 "Load Avg: %.2f, %.2f, %.2f\n"
                 "CPU usage: %.2f%% user, %.2f%% sys, %.2f%% idle\n"
                 "PhysMem: %luM used, %luM free",
                 (double)info.loads[0] / (1 << SI_LOAD_SHIFT),
                 (double)info.loads[1] / (1 << SI_LOAD_SHIFT),
                 (double)info.loads[2] / (1 << SI_LOAD_SHIFT),
                 (double)info.loads[0] / (1 << SI_LOAD_SHIFT),
                 (double)info.loads[1] / (1 << SI_LOAD_SHIFT),
                 (double)info.loads[2] / (1 << SI_LOAD_SHIFT),
                 (unsigned long)(info.totalram - info.freeram) * info.mem_unit /
                     1024 / 1024,
                 (unsigned long)info.freeram * info.mem_unit / 1024 / 1024);

        send(client_socket, response, strlen(response), 0);
    } else if (strncmp(command, "cmd:", 4) == 0) {
        execute_system_command(client_socket, command + 4);
    } else {
        execute_system_command(client_socket, command);
    }
}

// Thread function to handle each client
void *admin_handler(void *arg) {
    client_thread_arg_t *client_data = (client_thread_arg_t *)arg;
    int client_fd = client_data->socket;
    free(client_data);

    char buffer[ADMIN_BUFFER_SIZE] = {0};

    while (1) {
        ssize_t num_read = recv(client_fd, buffer, ADMIN_BUFFER_SIZE, 0);
        if (num_read > 0) {
            buffer[num_read] = '\0';
            process_command(client_fd, buffer);
        } else {
            perror("Recvfrom failed");
        }
    }

    close(client_fd);
    return NULL;
}

void *admin_connection_handler(void *arg) {
    connection_thread_arg_t *connection_arg = (connection_thread_arg_t *)arg;
    int server_fd = connection_arg->server_socket;

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1)
            continue;

        printf("Got new unix connection\n");

        pthread_t client_thread;
        client_thread_arg_t *arg = malloc(sizeof(client_thread_arg_t));
        arg->socket = client_fd;
        pthread_create(&client_thread, NULL, admin_handler, arg);
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

    // Setup admin socket
    admin_ux_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&admin_server_addr_ux, 0, sizeof(struct sockaddr_un));
    admin_server_addr_ux.sun_family = AF_UNIX;
    strcpy(admin_server_addr_ux.sun_path, ADMIN_SOCKET_PATH);
    unlink(ADMIN_SOCKET_PATH);
    bind(admin_ux_server_fd, (struct sockaddr *)&admin_server_addr_ux,
         sizeof(admin_server_addr_ux));
    listen(admin_ux_server_fd, 1);

    pthread_t admin_ux_connection_thread;
    connection_thread_arg_t *admin_ux_connection_arg =
        malloc(sizeof(connection_thread_arg_t));
    admin_ux_connection_arg->server_socket = admin_ux_server_fd;
    pthread_create(&admin_ux_connection_thread, NULL, admin_connection_handler,
                   admin_ux_connection_arg);
    pthread_detach(
        admin_ux_connection_thread); // The thread can run independently

    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    printf("Server start\n");

    pause();

    close(server_fd);

    return 0;
}
