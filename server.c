#include <arpa/inet.h> 
#include <microhttpd.h>
#include <netinet/in.h> 
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

#define PORT 8080

#define MAX_SOCKET_CONNECTIONS 128

typedef struct
{
    int socket;
    struct sockaddr addr;
} client_thread_arg_t;

typedef struct
{
    int server_socket;
} connection_thread_arg_t;

typedef struct
{
    int client_socket;
    char filename[FILE_SIZE];
    char filenameMerge[FILE_SIZE];
    char out_filename[FILE_SIZE];
    char encoder[10];
    char start_trim[10];
    char end_trim[10];
    double speed_rate;
} file_processing_arg_t;

void *encode_handler(void *arg);
void *audio_extract_handler(void *arg);
void *speed_handler(void *arg);
void *trim_handler(void *arg);
void *convert_handler(void *arg);
void *merge_handler(void *arg);
void send_response_file(int socket, char *filename, char *out_filename);

void *client_handler(void *arg)
{
    client_thread_arg_t *client_data = (client_thread_arg_t *)arg;
    int client_fd = client_data->socket;
    free(client_data);

    FILE *input_file = NULL;
    char unique_filename[FILE_SIZE + 30];
    char unique_filename_merged[FILE_SIZE + 30];
    int unique_id = 1;

    while (1)
    {
        size_t headerSize = sizeof(RequestHeader);
        char header_buffer[headerSize];
        receive_all(client_fd, header_buffer, headerSize);

        RequestHeader req;
        memcpy(&req, header_buffer, headerSize);

        snprintf(unique_filename, sizeof(unique_filename), "%d_%d_%s",
                 client_fd, unique_id, req.input_filename);
        input_file = fopen(unique_filename, "wb");
        receive_file(client_fd, input_file, req.length);
        fclose(input_file);
        if (req.operation == kMerge)
        {
            snprintf(unique_filename_merged, sizeof(unique_filename_merged), "m_%d_%d_%s",
                     client_fd, unique_id, req.input_filename);
            input_file = fopen(unique_filename_merged, "wb");
            receive_file(client_fd, input_file, req.lengthMerged);
            fclose(input_file);
        }
        input_file = NULL;
        unique_id++;

        printf("File received, starting processing...\n");
        printf("operation = %d\n", req.operation);
        pthread_t processing_thread;
        file_processing_arg_t *processing_arg =
            malloc(sizeof(file_processing_arg_t));
        processing_arg->client_socket = client_fd;
        strcpy(processing_arg->filename, unique_filename);
        strcpy(processing_arg->filenameMerge, unique_filename_merged);
        strcpy(processing_arg->out_filename, req.output_filename);
        strcpy(processing_arg->encoder, req.encoder);
        strcpy(processing_arg->start_trim, req.start_trim);
        strcpy(processing_arg->end_trim, req.end_trim);
        processing_arg->speed_rate = req.speed_rate;

        switch (req.operation)
        {
        case kEncode:
            pthread_create(&processing_thread, NULL, encode_handler,
                           processing_arg);
            break;

        case kSpeed:
            pthread_create(&processing_thread, NULL, speed_handler,
                           processing_arg);
            break;

        case kTrim:
            pthread_create(&processing_thread, NULL, trim_handler,
                           processing_arg);
            break;

        case kExtractAudio:
            pthread_create(&processing_thread, NULL, audio_extract_handler,
                           processing_arg);
            break;

        case kConvert:
            pthread_create(&processing_thread, NULL, convert_handler,
                           processing_arg);
            break;

        case kMerge:
            pthread_create(&processing_thread, NULL, merge_handler,
                           processing_arg);
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

        printf("Got new ux connection\n");

        pthread_t client_thread;
        client_thread_arg_t *arg = malloc(sizeof(client_thread_arg_t));
        arg->socket = client_fd;
        pthread_create(&client_thread, NULL, client_handler, arg);
        pthread_detach(client_thread);
    }
}

void *python_client_connection_handler(void *arg)
{
    connection_thread_arg_t *connection_arg = (connection_thread_arg_t *)arg;
    int server_fd = connection_arg->server_socket;

    while (1)
    {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1)
            continue;

        printf("Got new inet connection\n");

        pthread_t client_thread;
        client_thread_arg_t *arg = malloc(sizeof(client_thread_arg_t));
        arg->socket = client_fd;
        pthread_create(&client_thread, NULL, client_handler, arg);
        pthread_detach(client_thread);
    }
}

void execute_system_command(int client_socket, const char *command)
{
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) != 0)
    {
        perror("Pipe failed");
        return;
    }

    pid = fork();
    if (pid == -1)
    {
        perror("Fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }
    else if (pid == 0)
    {
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

    while ((bytes_read = read(pipefd[0], buffer, ADMIN_BUFFER_SIZE - 1)) > 0)
    {
        if (response_len + bytes_read < ADMIN_BUFFER_SIZE - 1)
        {
            memcpy(response + response_len, buffer, bytes_read);
            response_len += bytes_read;
        }
        else
        {
            break;
        }
    }
    response[response_len] = '\0';
    send(client_socket, response, response_len, 0);

    close(pipefd[0]);
    wait(NULL); 
}

void process_command(int client_socket, char *command)
{
    if (strncmp(command, "uptime", 6) == 0)
    {
        struct sysinfo info;
        if (sysinfo(&info) != 0)
        {
            perror("sysinfo failed");
            return;
        }
        char response[128];
        snprintf(response, sizeof(response),
                 "Server is UP for %ldd %ldh%02ldm%02lds", info.uptime / 86400,
                 (info.uptime % 86400) / 3600, (info.uptime % 3600) / 60,
                 info.uptime % 60);
        send(client_socket, response, strlen(response), 0);
    }
    else if (strncmp(command, "stats", 5) == 0)
    {
        struct sysinfo info;
        if (sysinfo(&info) != 0)
        {
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
    }
    else if (strncmp(command, "cmd:", 4) == 0)
    {
        execute_system_command(client_socket, command + 4);
    }
    else
    {
        execute_system_command(client_socket, command);
    }
}

void *admin_handler(void *arg)
{
    client_thread_arg_t *client_data = (client_thread_arg_t *)arg;
    int client_fd = client_data->socket;
    free(client_data);

    char buffer[ADMIN_BUFFER_SIZE] = {0};

    while (1)
    {
        ssize_t num_read = recv(client_fd, buffer, ADMIN_BUFFER_SIZE, 0);
        if (num_read > 0)
        {
            buffer[num_read] = '\0';
            process_command(client_fd, buffer);
        }
        else
        {
            perror("Recvfrom failed");
        }
    }

    close(client_fd);
    return NULL;
}

void *admin_connection_handler(void *arg)
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
        pthread_create(&client_thread, NULL, admin_handler, arg);
        pthread_detach(client_thread);
    }
}

void shutdown_handler(int sig) { printf("Server shutting down...\n"); }

void ffmpeg_encode(char *filename, char *encoder, char **output_filename)
{
    printf("Starting encoding process for file %s...\n", filename);
    int out_size = strlen(filename) + 15;
    *output_filename = malloc(out_size);
    snprintf(*output_filename, out_size, "encoded_%s", filename);

    char command[1024];
    snprintf(command, sizeof(command),
             "ffmpeg -i \"%s\" -c:v %s -c:a copy \"%s\"", filename, encoder,
             *output_filename);

    system(command);

    printf("Encoding completed for file %s, output in %s\n", filename,
           *output_filename);
}

void *encode_handler(void *arg)
{
    file_processing_arg_t *data = (file_processing_arg_t *)arg;

    char *output_filename;
    ffmpeg_encode(data->filename, data->encoder, &output_filename);

    send_response_file(data->client_socket, output_filename,
                       data->out_filename);
}

void ffmpeg_speed(char *filename, double speed_rate, char **output_filename)
{
    printf("Starting encoding process for file %s...\n", filename);
    int out_size = strlen(filename) + 15;
    *output_filename = malloc(out_size);
    snprintf(*output_filename, out_size, "speeded_%s", filename);

    char command[1024];
    snprintf(command, sizeof(command),
             "ffmpeg -i \"%s\" -filter:v \"setpts=PTS/%f\" -filter:a "
             "\"atempo=%f\" \"%s\"",
             filename, speed_rate, speed_rate, *output_filename);

    system(command);

    printf("Speed change completed for file %s, output in %s\n", filename,
           *output_filename);
}

void *speed_handler(void *arg)
{
    file_processing_arg_t *data = (file_processing_arg_t *)arg;

    char *output_filename;
    ffmpeg_speed(data->filename, data->speed_rate, &output_filename);

    send_response_file(data->client_socket, output_filename,
                       data->out_filename);
}

void ffmpeg_trim(char *filename, char *start_trim, char *end_trim,
                 char **output_filename)
{
    printf("Starting encoding process for file %s...\n", filename);
    int out_size = strlen(filename) + 15;
    *output_filename = malloc(out_size);
    snprintf(*output_filename, out_size, "trimmed_%s", filename);

    char command[1024];
    snprintf(command, sizeof(command), "ffmpeg -i \"%s\" -ss %s -to %s \"%s\"",
             filename, start_trim, end_trim, *output_filename);

    system(command);

    printf("Trim completed for file %s, output in %s\n", filename,
           *output_filename);
}

void *trim_handler(void *arg)
{
    file_processing_arg_t *data = (file_processing_arg_t *)arg;

    char *output_filename;
    ffmpeg_trim(data->filename, data->start_trim, data->end_trim,
                &output_filename);

    send_response_file(data->client_socket, output_filename,
                       data->out_filename);
}

void ffmpeg_audio_extract(char *filename, char *out_name,
                          char **output_filename)
{
    printf("Starting audio extract process for file %s...\n", filename);
    int out_size = strlen(filename) + 15;
    *output_filename = malloc(out_size);
    snprintf(*output_filename, out_size, "extracted_%s", filename);

    for (int i = strlen(*output_filename) - 1, j = strlen(out_name) - 1, k = 0;
         k < 3; ++k, --i, --j)
    {
        (*output_filename)[i] = out_name[j];
    }

    char command[1024];
    snprintf(command, sizeof(command),
             "ffmpeg -i \"%s\" -vn -acodec copy \"%s\"", filename,
             *output_filename);

    system(command);

    printf("Audio extract completed for file %s, output in %s\n", filename,
           *output_filename);
}

void *audio_extract_handler(void *arg)
{
    file_processing_arg_t *data = (file_processing_arg_t *)arg;

    char *output_filename;
    ffmpeg_audio_extract(data->filename, data->out_filename, &output_filename);

    send_response_file(data->client_socket, output_filename,
                       data->out_filename);
}

void ffmpeg_convert(char *filename, char *out_name, char **output_filename)
{
    printf("Starting conversion process for file %s...\n", filename);
    int out_size = strlen(filename) + 15;
    *output_filename = malloc(out_size);
    snprintf(*output_filename, out_size, "converted_%s", filename);

    for (int i = strlen(*output_filename) - 1, j = strlen(out_name) - 1, k = 0;
         k < 3; ++k, --i, --j)
    {
        (*output_filename)[i] = out_name[j];
    }

    char command[1024];
    snprintf(command, sizeof(command), "ffmpeg -i \"%s\" \"%s\"", filename,
             *output_filename);

    system(command);

    printf("Conversion completed for file %s, output in %s\n", filename,
           *output_filename);
}

void *convert_handler(void *arg)
{
    file_processing_arg_t *data = (file_processing_arg_t *)arg;

    char *output_filename;
    ffmpeg_convert(data->filename, data->out_filename, &output_filename);

    send_response_file(data->client_socket, output_filename,
                       data->out_filename);
}

void ffmpeg_merge(char *filename, char *filenameMerge, char **output_filename)
{
    printf("Starting merging process for files %s %s...\n", filename, filenameMerge);
    int out_size = strlen(filename) + 15;
    *output_filename = malloc(out_size);
    snprintf(*output_filename, out_size, "merged_%s", filename);

    char command[1024];
    snprintf(command, sizeof(command),
             "ffmpeg -i \"%s\" -i \"%s\" -filter_complex \"[0:v] [0:a] [1:v] [1:a] concat=n=2:v=1:a=1 [v] [a]\" -map \"[v]\" -map \"[a]\" \"%s\"", filename, filenameMerge,
             *output_filename);

    system(command);

    printf("Merging completed for file %s, output in %s\n", filename,
           *output_filename);
}

void *merge_handler(void *arg)
{
    file_processing_arg_t *data = (file_processing_arg_t *)arg;

    char *output_filename;
    ffmpeg_merge(data->filename, data->filenameMerge, &output_filename);

    send_response_file(data->client_socket, output_filename,
                       data->out_filename);
}

void send_response_file(int socket, char *filename, char *out_filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Failed to open file");
        return;
    }

    ResponseHeader resp;
    strcpy(resp.output_filename, out_filename);

    fseek(file, 0, SEEK_END);
    resp.length = ftell(file);
    rewind(file);

    send_all(socket, (char *)&resp, sizeof(ResponseHeader));
    send_file(socket, file);
    fclose(file);
}

struct connection_info_struct
{
    FILE *fp;
    FILE *fpMerge;
    int operation;
    char *encoder;
    char *filename;
    char *filenameMerge;
    char *output_filename;
    char *start_trim;
    char *end_trim;
    double speed_rate;
    struct MHD_PostProcessor *postprocessor;
};

enum MHD_Result send_ws_response(struct MHD_Connection *connection,
                                 char *message, int success)
{
    char error_json[1024];
    snprintf(error_json, sizeof(error_json),
             "{\"status\": \"%s\", \"message\": \"%s.\"}",
             success ? "success" : "error", message);
    printf("%s\n", error_json);
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(error_json), (void *)error_json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    int ret = MHD_queue_response(
        connection, success ? MHD_HTTP_OK : MHD_HTTP_BAD_REQUEST, response);
    MHD_destroy_response(response);

    return ret;
}

static int send_ws_file_response(struct MHD_Connection *connection,
                                 const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        return send_ws_response(connection, "Server couldn't open file", 0);
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);

    struct MHD_Response *response =
        MHD_create_response_from_fd_at_offset64(size, fileno(file), 0);
    MHD_add_response_header(response, "Content-Type", "video/mp4");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}

int ws_unique_id = 0;

enum MHD_Result iterate_post(void *coninfo_cls, enum MHD_ValueKind kind,
                             const char *key, const char *filename,
                             const char *content_type,
                             const char *transfer_encoding, const char *data,
                             uint64_t off, size_t size)
{
    struct connection_info_struct *con_info = coninfo_cls;

    if (0 == strcmp(key, "filename"))
    {
        if (0 == off)
        {
            ws_unique_id++;
            char unique_filename[FILE_SIZE + 15];
            snprintf(unique_filename, sizeof(unique_filename), "ws_%d_%s",
                     ws_unique_id, filename);
            con_info->filename = strdup(unique_filename);
            con_info->fp = fopen(unique_filename, "wb");
            if (!con_info->fp)
                return MHD_NO;
        }
        if (size > 0)
        {
            fwrite(data, size, 1, con_info->fp);
        }
        return MHD_YES;
    }
    if (0 == strcmp(key, "filenameMerge"))
    {
        if (0 == off)
        {
            char unique_filename[FILE_SIZE + 15];
            snprintf(unique_filename, sizeof(unique_filename), "ws_m_%d_%s",
                     ws_unique_id, filename);
            con_info->filenameMerge = strdup(unique_filename);
            con_info->fpMerge = fopen(unique_filename, "wb");
            if (!con_info->fpMerge)
                return MHD_NO;
        }
        if (size > 0)
        {
            fwrite(data, size, 1, con_info->fpMerge);
        }
        return MHD_YES;
    }
    if (0 == strcmp(key, "output_filename"))
    {
        con_info->output_filename = strdup(data);
    }
    if (0 == strcmp(key, "encoder"))
    {
        con_info->encoder = strdup(data);
    }
    if (0 == strcmp(key, "start_trim"))
    {
        con_info->start_trim = strdup(data);
    }
    if (0 == strcmp(key, "end_trim"))
    {
        con_info->end_trim = strdup(data);
    }
    if (0 == strcmp(key, "speed_rate"))
    {
        con_info->speed_rate = atof(data);
    }
    if (0 == strcmp(key, "operation"))
    {
        con_info->operation = atoi(data);
    }
    return MHD_YES;
}

void request_completed(void *cls, struct MHD_Connection *connection,
                       void **con_cls, enum MHD_RequestTerminationCode toe)
{
    struct connection_info_struct *con_info = *con_cls;

    if (NULL == con_info)
        return;

    if (con_info->fp)
    {
        fclose(con_info->fp);
        con_info->fp = NULL;
    }
    if (con_info->filename)
        free(con_info->filename);

    MHD_destroy_post_processor(con_info->postprocessor);
    free(con_info);
    *con_cls = NULL;
}

enum MHD_Result answer_to_connection(void *cls,
                                     struct MHD_Connection *connection,
                                     const char *url, const char *method,
                                     const char *version,
                                     const char *upload_data,
                                     size_t *upload_data_size, void **con_cls)
{
    if (NULL == *con_cls)
    {
        struct connection_info_struct *con_info =
            malloc(sizeof(struct connection_info_struct));
        if (NULL == con_info)
            return MHD_NO;

        if (0 == strcmp(method, "POST"))
        {
            con_info->postprocessor = MHD_create_post_processor(
                connection, 1024, iterate_post, (void *)con_info);
            if (NULL == con_info->postprocessor)
            {
                free(con_info);
                return MHD_NO;
            }

            *con_cls = (void *)con_info;
            return MHD_YES;
        }
    }

    if (0 == strcmp(method, "POST"))
    {
        struct connection_info_struct *con_info = *con_cls;

        if (*upload_data_size != 0)
        {
            MHD_post_process(con_info->postprocessor, upload_data,
                             *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }
        else
        {
            if (con_info->operation == kMerge)
            {
                if (NULL != con_info->fp)
                {
                    fclose(con_info->fp);
                    con_info->fp = NULL;
                }
                if (NULL != con_info->fpMerge)
                {
                    fclose(con_info->fpMerge);
                    con_info->fpMerge = NULL;
                }

                if (con_info->fp == NULL && con_info->fpMerge == NULL)
                {
                    char *output_filename;
                    ffmpeg_merge(con_info->filename, con_info->filenameMerge, &output_filename);
                    return send_ws_file_response(connection, output_filename);
                }
            }
            else if (NULL != con_info->fp)
            {
                fclose(con_info->fp);
                con_info->fp = NULL;

                char *output_filename;
                switch (con_info->operation)
                {
                case kEncode:
                    ffmpeg_encode(con_info->filename, con_info->encoder, &output_filename);
                    break;
                case kSpeed:
                    ffmpeg_speed(con_info->filename, con_info->speed_rate, &output_filename);
                    break;
                case kTrim:
                    ffmpeg_trim(con_info->filename, con_info->start_trim, con_info->end_trim, &output_filename);
                    break;
                case kExtractAudio:
                    ffmpeg_audio_extract(con_info->filename, con_info->output_filename, &output_filename);
                    break;
                case kConvert:
                    ffmpeg_convert(con_info->filename, con_info->output_filename, &output_filename);
                    break;
                default:
                    printf("Unknown operation from client\n");
                    return send_ws_response(connection, "Invalid operation", 0);
                }

                return send_ws_file_response(connection, output_filename);
            }
        }
    }

    return send_ws_response(connection, "Invalid method", 0);
}

int main()
{
    int server_fd;
    struct sockaddr_in server_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&server_addr, 0, sizeof(server_addr));

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr =
        htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, MAX_SOCKET_CONNECTIONS) < 0)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    pthread_t connection_thread;
    connection_thread_arg_t *connection_arg =
        malloc(sizeof(connection_thread_arg_t));
    connection_arg->server_socket = server_fd;
    pthread_create(&connection_thread, NULL, python_client_connection_handler,
                   connection_arg);
    pthread_detach(connection_thread);

    int ux_server_fd;
    struct sockaddr_un server_addr_ux;

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
    pthread_create(&ux_connection_thread, NULL, ux_connection_handler,
                   ux_connection_arg);
    pthread_detach(ux_connection_thread);

    int admin_ux_server_fd;
    struct sockaddr_un admin_server_addr_ux;

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
        admin_ux_connection_thread);

    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, WS_PORT, NULL,
                              NULL, &answer_to_connection, NULL,
                              MHD_OPTION_NOTIFY_COMPLETED, request_completed,
                              NULL, MHD_OPTION_END);
    if (NULL == daemon)
        return 1;

    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    printf("Server start\n");

    pause();

    close(server_fd);
    close(admin_ux_server_fd);
    close(ux_server_fd);
    MHD_stop_daemon(daemon);

    return 0;
}