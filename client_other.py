import socket
import struct
import os
import re
import threading

CHUNK_SIZE = 4096
FILE_SIZE = 256

# Operation type assumed as constants
OP_ENCODE = 1  # Example operation type for encoding

# Setup connection details
SERVER_IP = '127.0.0.1'  # Assuming server is running on localhost
SERVER_PORT = 8080       # Port number on which the server is listening

def send_header(sock, operation, encoder, input_filename, merge_input_filename, output_filename, file_size, merged_file_size, speed_rate, start_trim, end_trim):
    # Create the request struct
    nr = 10
    request_format = f"i{nr}s{FILE_SIZE}s{FILE_SIZE}s{FILE_SIZE}s{nr}s{nr}sQQd"
    #d{nr}s{nr}s
    #, start_trim.encode(), end_trim.encode()
    request_data = struct.pack(request_format, operation, encoder.encode(), input_filename.encode(), merge_input_filename.encode(), output_filename.encode(), start_trim.encode(), end_trim.encode(), file_size, merged_file_size, speed_rate)
    sock.sendall(request_data)

def send_chunk(sock, chunk):
    sock.sendall(chunk)

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
    while 1:
        header_format = f"{FILE_SIZE}sQ"
        header_size = struct.calcsize(header_format)
        header_data = receive_exact(sock, header_size)
        output_filename_bytes, file_size = struct.unpack(header_format, header_data)

        output_filename = output_filename_bytes.split(b'\x00', 1)[0].decode('utf-8')

        with open(output_filename, 'wb') as file:
            remaining_size = file_size
            while remaining_size > 0:
                chunk_size = min(remaining_size, CHUNK_SIZE)
                chunk = receive_exact(sock, chunk_size)
                file.write(chunk)
                remaining_size -= len(chunk)

        print(f"\nFile processed completely, output: {output_filename}")

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

# Function to validate the time format "HH:MM:SS"
def is_valid_time_format(time_str):
    pattern = r'^\d{2}:\d{2}:\d{2}$'
    if re.match(pattern, time_str):
        return True
    return False

def main():

    # Set up the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))

    thread = threading.Thread(target=receive_file, args=(sock,))
    thread.daemon = True
    thread.start()

    while 1:

        print("Available Functions:")
        print("1. Encode video/audio")
        print("2. Change speed of video/audio")
        print("3. Trim video/audio")
        print("4. Extract audio from video")
        print("5. Convert video/audio format")
        print("6. Merge 2 videos/audios")
        print("Select an option: ", end="")

        option = 1
        try:
            option = int(input())  # Get user input and convert to integer
        except ValueError:
            print("Please enter a valid number.")
            continue
        print("Enter input filename: ", end="")
        input_filename = input()  # Get input filename
        merge_input_filename = ""
        if option == 6:
            print("Enter another input filename: ", end="")
            merge_input_filename = input()  # Get input filename
        print("Enter output filename: ", end="")
        output_filename = input()  # Get output filenam

        speed_rate = 1
        start_trim = "00:00:00"
        end_trim = "00:00:00"
        encoder = "libx264"

        if option == 1:
            encoder = option_encoding()
        elif option == 2:
            print("Select a speed rate between 0.5 and 2.0: ", end="")
            while True:
                try:
                    # Get user input and convert to float
                    speed_rate = float(input("Enter a speed rate between 0.5 and 2.0: "))
                    # Check if the input value is within the allowed range
                    if speed_rate > 2.0 or speed_rate < 0.5:
                        raise ValueError("Please enter a valid float number between 0.5 and 2.0.")
                    break  # If the value is valid, break out of the loop
                except ValueError:
                    print("Please enter a valid float number between 0.5 and 2.0.")
                    # The loop will automatically continue if an exception is caught
        elif option == 3:
            print("Enter start time position of the trim in the HH:MM:SS format: ", end="")
            start_trim = input()  # Get input filename
            if not is_valid_time_format(start_trim):
                raise ValueError("Please enter a valid position of the trim in the HH:MM:SS format.")
            print("Enter duration of the trim in the HH:MM:SS format: ", end="")
            end_trim = input()  # Get output filenam
            if not is_valid_time_format(end_trim):
                raise ValueError("Please enter a duration of the trim in the HH:MM:SS format.")
        elif option == 4:
            pass
        elif option == 5:
            pass
        elif option == 6:
            pass
        else:
            print("Invalid option")
            continue

        if option == 1 or option == 2 or option == 3 or option == 4 or option == 5 or option == 6:
            # Open the file and calculate chunks
            with open(input_filename, 'rb') as f:
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                f.seek(0)

                merged_file_size = 0
                if option == 6:
                    with open(merge_input_filename, 'rb') as g:
                        g.seek(0, os.SEEK_END)
                        merged_file_size = g.tell()
                        g.seek(0)
                send_header(sock, option, encoder, input_filename, merge_input_filename, output_filename, file_size, merged_file_size, speed_rate, start_trim, end_trim)

                remaining_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
                while remaining_chunks > 0:
                    chunk = f.read(CHUNK_SIZE)
                    send_chunk(sock, chunk)
                    remaining_chunks -= 1

                if option == 6:
                    remaining_chunks = (merged_file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
                    with open(merge_input_filename, 'rb') as g:
                        while remaining_chunks > 0:
                            chunk = g.read(CHUNK_SIZE)
                            send_chunk(sock, chunk)
                            remaining_chunks -= 1


if __name__ == '__main__':
    main()