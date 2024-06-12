import socket
import struct
import os

# Constants matching the C definitions
CHUNK_SIZE = 4096
FILE_SIZE = 256

# Operation type assumed as constants
OP_ENCODE = 1  # Example operation type for encoding

# Setup connection details
SERVER_IP = '127.0.0.1'  # Assuming server is running on localhost
SERVER_PORT = 8080       # Port number on which the server is listening

def send_header(sock, operation, encoder, input_filename, output_filename, file_size):
    # Create the request struct
    nr = 10
    request_format = f"i{nr}s{FILE_SIZE}s{FILE_SIZE}sQ"
    request_data = struct.pack(request_format, operation, encoder.encode(), input_filename.encode(), output_filename.encode(), file_size)
    #print("Request data = ", request_data)
    sock.sendall(request_data)

def send_chunk(sock, chunk):
    # Create the request struct
    request_format = f"{CHUNK_SIZE}s"
    request_data = struct.pack(request_format, chunk)
    sock.sendall(request_data)

def receive_exact(sock, length):
    """Receive exactly 'length' bytes from the socket 'sock'."""
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise Exception("Socket connection broken")
        data += more
    return data

def receive_file(sock):
    header_format = f"{FILE_SIZE}sQ"
    header_size = struct.calcsize(header_format)
    header_data = receive_exact(sock, header_size)
    output_filename_bytes, file_size = struct.unpack(header_format, header_data)

    # print("Received filename bytes:", output_filename_bytes)

    # Process filename to terminate at the first null byte
    output_filename = output_filename_bytes.split(b'\x00', 1)[0].decode('utf-8')

    # Print filename and size for debugging
    print(f"Received filename: {output_filename}, File size: {file_size}")


    # # Use bytes directly or decode safely
    # try:
    #     output_filename = output_filename_bytes.decode('utf-8').strip('\x00')
    # except UnicodeDecodeError:
    #     output_filename = "default_filename"
    #     print("Failed to decode filename, using default.")

    with open(output_filename, 'wb') as file:
        remaining_size = file_size
        while remaining_size > 0:
            chunk_size = min(remaining_size, CHUNK_SIZE)
            chunk = receive_exact(sock, chunk_size)
            file.write(chunk)
            remaining_size -= len(chunk)


    print(f"Received file {output_filename} with size {file_size} bytes.")

def option_encoding():
    # Display encoder type choices
    print("Choose encoder type:")
    print("1. h264")
    print("2. h265")
    print("3. AV1")
    print("Enter your choice: ", end="")

    try:
        encoder_choice = int(input())  # Get user input and convert to integer
    except ValueError:
        print("Please enter a valid number for the encoder type.")
        return

    if encoder_choice == 1:
        encoder = "libx264"
    elif encoder_choice == 2:
        encoder = "libx265"
    elif encoder_choice == 3:
        encoder = "libsvtav"
    else:
        print("Invalid encoder type selected.")
        return
    
    return encoder

def main():

    while 1:

        try:
            # Set up the socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_IP, SERVER_PORT))

            print("Available Functions:")
            print("1. Encode video")
            print("Select an option: ", end="")
            option = 1
            try:
                option = int(input())  # Get user input and convert to integer
            except ValueError:
                print("Please enter a valid number.")
                continue
            print("Enter input filename: ", end="")
            input_filename = input()  # Get input filename
            print("Enter output filename: ", end="")
            output_filename = input()  # Get output filenam


            if option == 1:
                encoder = option_encoding()

                # input_filename = 'input.mp4'
                # output_filename = 'output.mp4'
                # encoder = 'libx264'  # Example encoder

                # Open the file and calculate chunks
                with open(input_filename, 'rb') as f:
                    f.seek(0, os.SEEK_END)
                    file_size = f.tell()
                    f.seek(0)
                    print("file_size = ", file_size)
                    send_header(sock, OP_ENCODE, encoder, input_filename, output_filename, file_size)
                    print("SENT HEADER")

                    remaining_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
                    while remaining_chunks > 0:
                        chunk = f.read(CHUNK_SIZE)
                        send_chunk(sock, chunk)
                        print("Sent chunk = ", remaining_chunks, " of length = ", len(chunk))
                        remaining_chunks -= 1

                # Receive the processed file
                print("Receiving processed file...")
                receive_file(sock)
            else:
                print("Invalid option")
                continue

        finally:
            sock.close()

if __name__ == '__main__':
    main()