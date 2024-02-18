'''
TFTP client in fulfillment of Machine Project #1 for NSCOM01 Term 2 - AY 2023-2024

Members:
TAPIA, John Lorenzo N.
MADRINAN, Raico Luis C.

GitHub Repository:
https://github.com/tapeau/NSCOM01.tftp-client

Additional Credits / References:
- https://www.ascii-art.site/
- https://www.geeksforgeeks.org/clear-screen-python/
- https://stackoverflow.com/questions/38763771/how-do-i-remove-double-back-slash-from-a-bytes-object
- https://www.autoitscript.com/forum/topic/152150-tftp-client-server/
'''
# Import necessary libraries
import socket # for socket functionalities
import re # for IP address validation through regex
import os # for file checking and design purposes
import sys # for handling Ctrl+C terminations
from art import * # for design purposes

# Declare constants
BLK_SIZE = 512 # Default is 512
MAX_DATA_LENGTH = 516 # BLK_SIZE + opcode + Block Number
MODE = b'octet' # Only support 'octet' transfer mode since the project only deals with binary files
MAX_VALUE_2_BYTES = 2 ** 16  # 65536 - to be used to limit 2-byte block numbers

OPCODE = { # Dictionary to store TFTP opcodes
    'RRQ': 1,
    'WRQ': 2,
    'DAT': 3,
    'ACK': 4,
    'ERR': 5
}

ERR_CODE = { # Dictionary to store TFTP error codes
    0: 'Not defined, see error message (if any).',
    1: 'File not found.',
    2: 'Access violation.',
    3: 'Disk full or allocation exceeded.',
    4: 'Illegal TFTP operation.',
    5: 'Unknown transfer ID.',
    6: 'File already exists.',
    7: 'No such user.'
}

# Create the UDP socket to be used by the client
CLIENT_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Tuple variable to store TFTP server credentials (empty at start)
SERVER_ADDR = None

def main():
    '''
    Function that contains the application's main functionalities.
    
    Args:
        None
    
    Returns:
        None
    '''
    # Whole main program is enclosed in a try statement to handle Ctrl+C terminations
    try:
        while True:
            # Reset UI
            clear_console()
            print_header()
            
            # Check if client is connected to a server
            if not SERVER_ADDR:
                # Prompt the user to connect to one
                print('Please connect to a TFTP server to start.')
                prompt_server()
                continue
            
            # Print menu
            print(f'Current server: {SERVER_ADDR[0]}:{SERVER_ADDR[1]}')
            print()
            print('\'1\'\tDownload a file from the server')
            print('\'2\'\tUpload a file to the server')
            print('\'3\'\tChange transfer block size')
            print('\'4\'\tChange current server')
            print('\'5\'\tExit')
            print()
            
            # Prompt for user choice
            user_choice = input('Enter the number of your desired action: ')
            print()
            
            # Evaluate user choice
            if user_choice == '1':
                # Initialize variables
                server_file = b''
                server_file_name = None
                client_block_number = 1
                original_address = SERVER_ADDR
                
                # Prompt user for the name of the file they wish to download
                # Encased in a while loop to ensure file existence
                while True:
                    # Get user input
                    server_file_name = input('Enter the name of the file you wish to download from the server: ')
                    
                    # Check if user entered a file name
                    if server_file_name:
                        # Check if the file with the specified name exists
                        if os.path.isfile(server_file_name):
                            print('ERROR: File already exists in local directory.')
                        else:
                            print('Requesting file from server...')
                            break
                    else:
                        # Notify the user if they did not enter any file name
                        print('ERROR: No file name entered.')
                
                # Send RRQ packet to server
                send_req(OPCODE['RRQ'], server_file_name)
                
                # Loop to receive incoming packets from server and send corresponding ACK packets
                while True:
                    # Read server response
                    received_packet, received_packet_opcode = receive_tftp_packet()
                    
                    # Check first if the server response is an ERROR packet
                    if received_packet_opcode == OPCODE['ERR']:
                        # Process the packet and terminate loop
                        print(f"ERROR from TFTP server: {ERR_CODE[int.from_bytes(received_packet[2:4], byteorder='big')]}")
                        break
                    else:
                        # Process packet into a variable, then into a file
                        # Get first the packet's block number
                        server_block_number = int.from_bytes(received_packet[2:4], byteorder='big')
                        print(f'SERVER: {server_block_number}')
                        print(f'CLIENT: {client_block_number}')
                        
                        # Compare with client's current block number
                        if server_block_number != client_block_number:
                            # If packet is not expected, ignore
                            print(f'Ignoring packet with unexpected block number: {server_block_number}')
                            continue
                        
                        # Send acknowledgment
                        send_ack(client_block_number)
                        
                        # Write packet data payload onto a variable and append current block number
                        server_file += received_packet[4:]
                        client_block_number += 1
                        
                        # Check if the last packet is received
                        if len(received_packet) < MAX_DATA_LENGTH:
                            # Check if there has been any received data
                            if server_file:
                                # Write the received data onto a file
                                with open(server_file_name, 'wb') as f:
                                    f.write(server_file)
                                
                                # Notify user
                                print(f'File \'{server_file_name}\' has been successfully downloaded from the server.')
                            
                            # Terminate the loop
                            break
                
                # Set SERVER_ADDR back to its original address
                change_server(original_address[0], original_address[1])
                
            elif user_choice == '2':
                # Initialize variables
                client_file_name = b''
                client_block_number = 0
                original_address = SERVER_ADDR
                
                # Prompt user for the name of the file they wish to upload
                # Encased in a while loop to ensure file existence
                while True:
                    # Get user input
                    client_file_name = input('Enter the name of the file you wish to upload to the server: ')
                    
                    # Check if user entered a file name
                    if client_file_name:
                        # Check if the file with the specified name exists
                        if os.path.isfile(client_file_name):
                            break
                        else:
                            print('ERROR: File not found in local directory.')
                    else:
                        # Notify the user if they did not enter any file name
                        print('ERROR: No file name entered.')
                
                # Send WRQ packet to server
                print('Uploading file to server...')
                send_req(OPCODE['WRQ'], client_file_name)
                
                # Open file
                with open(client_file_name, 'rb') as client_file:
                    # Read the whole file at once
                    client_data = client_file.read()
                    
                    # Loop to iteratively slice and process the next BLK_SIZE amount of data in the file
                    for i in range(0, len(client_data), BLK_SIZE):
                        # Read server response
                        received_packet, received_packet_opcode = receive_tftp_packet()
                        
                        # Check first if the server response is an ERROR packet
                        if received_packet_opcode == OPCODE['ERR']:
                            # Process the packet and terminate loop
                            print(f"ERROR from TFTP server: {ERR_CODE[int.from_bytes(received_packet[2:4], byteorder='big')]}")
                            break
                        else:
                            # Increment client block number
                            client_block_number += 1
                            
                            # Get current slice of data
                            client_data_block = client_data[i : i + BLK_SIZE]
                                
                            # Turn the slice into a TFTP DATA packet and send to server
                            send_dat(client_block_number % MAX_VALUE_2_BYTES, client_data_block)
                                
                    # Check if the file's length is divisible by BLK_SIZE
                    if len(client_data) % BLK_SIZE == 0:
                        # Send the final empty byte to indicate end of transmission
                        send_dat((client_block_number + 1) % MAX_VALUE_2_BYTES, b'')
                
                # Notify user once finished
                print(f'File \'{client_file_name}\' has been successfully uploaded to the server.')
                
                # Set SERVER_ADDR back to its original address
                change_server(original_address[0], original_address[1])
                
            elif user_choice == '3':
                # TODO: Functionality to change BLK_SIZE
                pass
            
            elif user_choice == '4':
                prompt_server()
            
            elif user_choice == '5':
                # Prompt for user confirmation
                user_confirm = input('Are you sure you want to exit the application? (Y/N): ')
                if user_confirm == 'Y' or user_confirm == 'y':
                    break
            
            else:
                print('ERROR: Unrecognized input.')
            
            # Pause program execution to let user read the results (UI enhancement)
            prompt_key()
        
        # Close client socket
        CLIENT_SOCKET.close()
        
        # Notify user
        print()
        print('Program terminated.')
        print()
    
    except KeyboardInterrupt:
        # Close client socket
        CLIENT_SOCKET.close()
        
        # Notify user
        print()
        print('Program terminated.')
        print()
        
        # Terminate Python script (which will keep running if Ctrl+C is performed, even if program is no longer running)
        sys.exit()

def send_req(type, filename):
    '''
    Function to send TFTP request packet (RRQ or WRQ).

    Args:
        type (int): Type of request - 1 for RRQ, 2 for WRQ (according to their opcodes)
        filename (str): Name of file to be included in the request

    Returns:
        None
    '''
    # Represent request packet as a bytearray
    req = bytearray() 

    # Append request opcode at the beginning of the packet
    req += b'\x00'
    req += f'\\x0{type}'.encode().decode('unicode_escape').encode("raw_unicode_escape")

    # Convert the passed file name into a byte array and append it to the request packet
    req += bytearray(filename.encode('utf-8'))

    # Append 0x00 byte
    req += b'\x00'
    
    # Append transfer mode to request packet
    req += MODE

    # Append 0x00 byte
    req += b'\x00'

    # Send the request packet to the server through client socket
    CLIENT_SOCKET.sendto(bytes(req), SERVER_ADDR)

def send_dat(block, data):
    '''
    Function to send TFTP data packet.

    Args:
        block (int): Block number of data packet
        data (bytearray): Bytearray containing data to be sent

    Returns:
        None
    '''
    # Represent data packet as a bytearray
    dat = bytearray()
    
    # Append data opcode at the beginning of the packet
    dat += b'\x00'
    dat += f"\\x0{OPCODE['DAT']}".encode().decode('unicode_escape').encode("raw_unicode_escape")
    
    # Append the block number
    dat += block.to_bytes(2, byteorder='big', signed=False)
    
    # Append the data
    dat += data
    
    # Send the data packet to the server through client socket
    print(f'SENT: {bytes(dat[:3])}')
    CLIENT_SOCKET.sendto(bytes(dat), SERVER_ADDR)

def send_ack(block):
    '''
    Function to send TFTP acknowledge packet/signal.
    
    Args:
        block (int): Block number of data packet
    
    Returns:
        None
    '''
    # Represent acknowledge packet as a bytearray
    ack = bytearray()
    
    # Append acknowledgement opcode at the beginning of the packet
    ack += b'\x00'
    ack += f"\\x0{OPCODE['ACK']}".encode().decode('unicode_escape').encode("raw_unicode_escape")
    
    # Append the block number
    ack += block.to_bytes(2, byteorder='big', signed=False)
    
    # Send the acknowledgement packet to the server through client socket
    CLIENT_SOCKET.sendto(bytes(ack), SERVER_ADDR)

def send_err(code):
    '''
    Function to send TFTP error packet/signal.
    
    Args:
        code (int): Error code to send
    
    Returns:
        None
    '''
    # Represent error packet as a bytearray
    err = bytearray()
    
    # Append error opcode at the beginning of the packet
    err += b'\x00'
    err += f"\\x0{OPCODE['ERR']}".encode().decode('unicode_escape').encode("raw_unicode_escape")
    
    # Convert error message into a byte array and append it to the error packet
    err += bytearray(ERR_CODE[code].encode('utf-8'))
    
    # Append 0x00 terminating byte
    err += b'\x00'
    
    # Send the error packet to the server through client socket
    CLIENT_SOCKET.sendto(bytes(err), SERVER_ADDR)

def receive_tftp_packet():
    '''
    Function that bundles and adds security to socket.recvsocket() function.
    
    Args:
        None
    
    Returns:
        bytes: The packet received from the TFTP server
        int: The opcode of the packet received from the TFTP server
    '''
    while True:
        # Receive some packet
        data, addr = CLIENT_SOCKET.recvfrom(MAX_DATA_LENGTH)
        
        # Check if packet is from the TFTP server
        if addr[0] == SERVER_ADDR[0]:
            # if it is, first set the source address of the received packet into SERVER_ADDR
            # This is because the OS may change the port number from the one entered by the user
            change_server(SERVER_ADDR[0], addr[1])
            
            # Extract opcode from the data then return both the opcode and the actual data
            opcode = data[:2]
            return data, int.from_bytes(opcode, byteorder='big')
        else:
            # If not, ignore
            print(f"Ignoring packet from unexpected address: {addr}")

def clear_console():
    '''
    Function to clear CLI (for design purposes).
    Taken from: https://www.geeksforgeeks.org/clear-screen-python/
    
    Paremeters:
        None
    
    Returns:
        None
    '''
    # For Windows
    if os.name == 'nt':
        _ = os.system('cls')

    # For Mac and Linux (here, os.name is 'posix')
    else:
        _ = os.system('clear')

def print_header():
    '''
    Function to print application header (for design purposes).
    
    Args:
        None
    
    Returns:
        None
    '''
    print()
    print(text2art('EASY', font='modular'))
    print(text2art('TFTP', font='modular'))
    print('------------------------------------------------------------------')
    print('A simple command-line TFTP client application')
    print('Developed by J.L. Tapia and Raico Madrinan')
    print('As Machine Project #1 for DLSU NSCOM01 course (T2 2023-2024)')
    print('------------------------------------------------------------------')
    print()

def prompt_server():
    '''
    Function to print a prompt requesting the user to enter a server address with a port number
    
    Args:
        None
    
    Returns:
        None
    '''
    # Loop to prompt user to connect to a TFTP server with a valid IP address and port number
    while True:
        input_address = input('Enter server address: ')
        if re.match(r'(^localhost:\d+$)|(^(\d{1,3}\.){3}\d{1,3}:\d+$)', input_address):
            address = parse_address(input_address)
            change_server(address[0], address[1])
            print('Server address set.')
            print()
            break
        else:
            print('ERROR: Please enter a valid IP address with a port number.')
            print()
            input_address = None
            continue

def parse_address(address):
    '''
    Function to convert an IP address and port string into a tuple of (string, int)
    where the 'string' is the address and the 'int' is the port number.
    
    Args:
        address (str): String containing an IP address and port
    
    Returns:
        tuple: A tuple containing the IP address (string) and port number (integer)
    '''
    # Split the address string by colon ':'
    parts = address.split(':')
    
    # Extract IP address (first part)
    # Additional check to convert 'localhost' to 127.0.0.1
    if parts[0] == 'localhost':
        ip_address = '127.0.0.1'
    else:
        ip_address = parts[0]
    
    # Extract port number and convert it to an integer (second part)
    port = int(parts[1])
    
    return (ip_address, port)

def change_server(address, port):
    '''
    Function to change the global variable SERVER_ADDR
    which stores the server address currently used by the client
    
    Args:
        address (str): Address of the server
        port (int): Port number of the server
    
    Returns:
        None
    '''
    # Create reference to the global variable
    global SERVER_ADDR
    
    # Change the values
    SERVER_ADDR = (address, port)

def prompt_key():
    '''
    Function that prompts the user to press any key
    before resuming program flow.
    
    Args:
        None
    
    Returns:
        None
    '''
    # Just three simple functions
    print()
    print('Press any key to continue...', end='')
    input()

if __name__ == '__main__':
    main()