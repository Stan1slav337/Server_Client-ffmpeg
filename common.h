#define UX_SOCKET_PATH "/tmp/server.sock"
#define CHUNK_SIZE 4096
#define FILE_SIZE 256

typedef enum
{
    kEncode,
    kCut
} OperationType;

typedef struct
{
    OperationType operation;
    char encoder[10];                // Encoder
    char input_filename[FILE_SIZE];  // Filename for input
    char output_filename[FILE_SIZE]; // Filename for output
    int remaining_chunks;            // Number of expected chunks for kEncode
    char chunk[CHUNK_SIZE];          // Chunk data
} Request;

typedef struct
{
    int remaining_chunks;
    char output_filename[FILE_SIZE];
    char chunk[CHUNK_SIZE];
} Response;