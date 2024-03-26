'''
TFTP client in fulfillment of Machine Project #1 for NSCOM01 Term 2 - AY 2023-2024

Members:
TAPIA, John Lorenzo N.
MADRINAN, Raico Luis C.

GitHub Repository:
https://github.com/tapeau/NSCOM01.tftp-client

Additional Credits / References:
- https://github.com/sepandhaghighi/art
- https://github.com/verigak/progress/
- https://www.geeksforgeeks.org/clear-screen-python/
- https://www.geeksforgeeks.org/how-to-get-file-size-in-python/
- https://www.autoitscript.com/forum/topic/152150-tftp-Client-Server/
- https://stackoverflow.com/questions/38763771/how-do-i-remove-double-back-slash-from-a-bytes-object
'''
# Import libraries
import socket # for socket functionalities
import re # for IP address validation through regex
import os # for file analysis and design purposes
import sys # for handling Ctrl+C terminations
import art # for design purposes
from progress.spinner import Spinner # for design purposes
from progress.bar import IncrementalBar # for design purposes

# Declare constants
BLK_SIZE_DEFAULT = 512 # Variable for default transfer block size as per RFC 1350
BLK_SIZE = BLK_SIZE_DEFAULT # Variable for transfer block size used by the client
MAX_DATA_LENGTH = 4 + BLK_SIZE # Variable for max length of DATA packets given the transfer block size (opcode + Block Number + BLK_SIZE)
MAX_VALUE_2_BYTES = 2 ** 16  # 65536 - to be used to limit 2-byte block numbers
TSIZE_OPTION = False # Option to communicate transfer size (default is False)
MODE = b'octet' # Only support 'octet' transfer mode since the project only deals with binary files

OPCODE = { # Dictionary to store TFTP opcodes
    'RRQ': 1,
    'WRQ': 2,
    'DAT': 3,
    'ACK': 4,
    'ERR': 5,
    'OAC': 6
}

ERR_CODE = { # Dictionary to store TFTP error codes
    0: 'Not defined, see error message (if any).',
    1: 'File not found.',
    2: 'Access violation.',
    3: 'Disk full or allocation exceeded.',
    4: 'Illegal TFTP operation.',
    5: 'Unknown transfer ID.',
    6: 'File already exists.',
    7: 'No such user.',
    8: 'Failed option negotiation.'
}

# Create the UDP socket to be used by the client, and set socket timeout to 6 seconds
CLIENT_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
CLIENT_SOCKET.settimeout(6)

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
            
            # Print dashboard
            tsize_indicator = 'ON' if TSIZE_OPTION else 'OFF'
            print(f'Current server: {SERVER_ADDR[0]}:{SERVER_ADDR[1]}')
            print(f'Current transfer block size: {BLK_SIZE} bytes')
            print(f'Current transfer size option: {tsize_indicator}')
            print()
            
            # Print menu
            print('\'1\'\tDownload a file from the server')
            print('\'2\'\tUpload a file to the server')
            print('\'3\'\tChange current server')
            print('\'4\'\tChange transfer block size')
            print('\'5\'\tToggle transfer size option')
            print('\'6\'\tExit')
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
                original_blksize = BLK_SIZE
                negotiated_blksize = True
                received_tsize = None
                progress_indicator = None
                received_packet = None
                received_packet_opcode = None
                
                # First check if the 'Downloads' folder inside application directory exists
                if not os.path.exists('Downloads'): 
                    # Create 'Downloads' folder
                    os.makedirs('Downloads')
                
                # Prompt user for the name of the file they wish to download
                # Encased in a while loop to ensure file existence
                print('(Enter \'/\' to go back.)')
                while True:
                    # Get user input
                    server_file_name = input('Enter the name of the file you wish to download from the server: ')
                    
                    # Check if user entered a file name
                    if server_file_name:
                        # Check if the file with the specified name exists
                        if os.path.isfile(os.path.join('Downloads', server_file_name)):
                            print('ERROR: File already exists in local \'Downloads\' directory.')
                        else:
                            break
                    else:
                        # Notify the user if they did not enter any file name
                        print('ERROR: No file name entered.')
                
                # Check if user entered '/'
                if server_file_name == '/':
                    continue
                else:
                    print()
                    print('Requesting file from server.')
                
                # Try catch to handle ConnectionResetErrors
                try:
                    # Send RRQ packet to server
                    send_req(OPCODE['RRQ'], server_file_name)
                    
                    # Additional negotiation if the user has set a custom transfer block size or turned transfer size option on
                    if BLK_SIZE != 512 or TSIZE_OPTION:
                        # Read first server response
                        received_packet, received_packet_opcode = receive_tftp_packet(dat=True)
                        
                        # Check opcode of received response
                        if received_packet_opcode == OPCODE['OAC']:
                            # Check if server accepted the options requested by the client
                            negotiated_blksize, received_tsize = process_oac_from_rrq(received_packet)
                        elif received_packet_opcode == OPCODE['DAT']:
                            # DAT means server did not accept all options
                            negotiated_blksize = False
                    else:
                        # Read first server response
                        received_packet, received_packet_opcode = receive_tftp_packet(dat=True)
                    print()
                    
                    # Check status of Client-Server negotiations regarding custom transfer block size
                    if BLK_SIZE != 512 and negotiated_blksize:
                        # Check status of Client-Server negotiations for transfer size option
                        if TSIZE_OPTION and not received_tsize:
                            # Notify user if failed
                            print('NOTICE: Client-Server negotiation for transfer size option has failed.')
                            print(f'Commencing download for file \'{server_file_name}\' with an unknown size from the server.')
                            print()
                        elif not TSIZE_OPTION:
                            print(f'Commencing download for file \'{server_file_name}\' with an unknown size from the server.')
                            print()
                        else:
                            print(f'Commencing download for file \'{server_file_name}\' with a size of {received_tsize} bytes from the server.')
                            print()
                        
                        # Send acknowledgement of OACK to server
                        send_ack(0)
                        
                        # Read next server response
                        received_packet, received_packet_opcode = receive_tftp_packet(dat=True)
                    # Check status of Client-Server negotiations regarding transfer size option
                    elif TSIZE_OPTION and received_tsize:
                        # Check status of Client-Server negotiations for custom transfer block size
                        if BLK_SIZE != 512 and not negotiated_blksize:
                            # Notify user if failed
                            print('NOTICE: Client-Server negotiation for custom transfer block size has failed.')
                            print('Using default transfer block size (512 bytes) for this file transfer.')
                            print()
                            
                            # Use default BLK_SIZE value
                            change_blksize(BLK_SIZE_DEFAULT)
                        
                        # Notify user of the size of the requested file
                        print(f'Commencing download for file \'{server_file_name}\' with a size of {received_tsize} bytes from the server.')
                        print()
                        
                        # Send acknowledgement of OACK to server
                        send_ack(0)
                        
                        # Read next server response
                        received_packet, received_packet_opcode = receive_tftp_packet(dat=True)
                    else:
                        # Notify user about failed Client-Server negotiations for custom transfer block size
                        if BLK_SIZE != 512:
                            # Notify user if failed
                            print('NOTICE: Client-Server negotiation for custom transfer block size has failed.')
                            print('Using default transfer block size (512 bytes) for this file transfer.')
                            print()
                            
                            # Use default BLK_SIZE value
                            change_blksize(BLK_SIZE_DEFAULT)
                        
                        # Notify user about failed Client-Server negotiations for transfer size option
                        if TSIZE_OPTION:
                            # Notify user if failed
                            print('NOTICE: Client-Server negotiation for transfer size option has failed.')
                        
                        # Notify user
                        print(f'Commencing download for file \'{server_file_name}\' with an unknown size from the server.')
                        print()
                    
                    # Set progress indicator
                    if received_tsize:
                        progress_indicator = IncrementalBar('Downloading...', max=(received_tsize // BLK_SIZE), suffix='%(percent).1f%% - %(eta)ds')
                    else:
                        progress_indicator = Spinner('Downloading... ')
                    
                    # Loop to receive incoming packets from server and send corresponding ACK packets
                    while True:
                        # Check first if the server response is an ERROR packet
                        if received_packet_opcode == OPCODE['ERR']:
                            # Process the packet and terminate loop
                            print(f"ERROR from TFTP server: {ERR_CODE[int.from_bytes(received_packet[2:4], byteorder='big')]}")
                            break
                        else:
                            # Process packet into a variable, then into a file
                            # Get first the packet's block number
                            server_block_number = int.from_bytes(received_packet[2:4], byteorder='big')
                            
                            # Compare with client's current block number
                            if server_block_number != client_block_number:
                                # If packet is not expected, ignore
                                print(f'Ignoring packet with unexpected block number: {server_block_number}')
                                print(f'Client block number: {client_block_number}')
                                continue
                            
                            # Send acknowledgment
                            send_ack(client_block_number)
                            
                            # Write packet data payload onto a variable and append current block number
                            server_file += received_packet[4:]
                            client_block_number = (client_block_number + 1) % MAX_VALUE_2_BYTES
                            
                            # Increment progress indicator
                            progress_indicator.next()
                            
                            # Check if the last packet is received
                            if len(received_packet) < MAX_DATA_LENGTH:
                                # Check if there has been any received data
                                if server_file:
                                    # Write the received data onto a file
                                    with open(os.path.join('Downloads', server_file_name), 'wb') as f:
                                        f.write(server_file)
                                    
                                    # Notify user once finished
                                    progress_indicator.finish()
                                    print()
                                    print(f'File \'{server_file_name}\' has been successfully downloaded from the server.')
                                    print('All downloaded files are stored within the local \'Downloads\' folder inside the application directory.')
                                
                                # Terminate the loop
                                break
                        
                        # Read next server response
                        received_packet, received_packet_opcode = receive_tftp_packet(dat=True)
                except ConnectionResetError:
                    # Notify user of error
                    print()
                    print('ERROR from TFTP server: Attempt to contact or further contact the server has failed.')
                
                # Set BLK_SIZE back to its original value
                change_blksize(original_blksize)
                
                # Set SERVER_ADDR back to its original address
                change_server(original_address[0], original_address[1])
                
            elif user_choice == '2':
                # Initialize variables
                client_file_name = None
                client_block_number = 0
                server_file_name = None
                original_address = SERVER_ADDR
                original_blksize = BLK_SIZE
                negotiated_blksize = True
                negotiated_tsize = True
                progress_indicator = None
                
                # Prompt user for the name of the file they wish to upload
                # Encased in a while loop to ensure file existence
                print('(Enter \'/\' to go back.)')
                while True:
                    # Get user input
                    client_file_name = input('Enter the name of the file you wish to upload to the server: ')
                    
                    # Check if user entered a file name
                    if client_file_name:
                        # Check if the file with the specified name exists
                        if os.path.isfile(client_file_name) or client_file_name == '/':
                            break
                        else:
                            print('ERROR: File not found in local directory.')
                            client_file_name = None
                    else:
                        # Notify the user if they did not enter any file name
                        print('ERROR: No file name entered.')
                
                # Check if user entered '/'
                if client_file_name == '/':
                    continue
                
                # Prompt user for the name of the file they wish to upload
                print()
                print('(Enter blank to use the file\'s original name.)')
                server_file_name = input('Enter the name the file will have inside the server: ')
                
                # Check if user entered blank (i.e. use file's original name)
                if not server_file_name:
                    server_file_name = client_file_name
                
                # Try catch to handle ConnectionResetErrors
                try:
                    # Send WRQ packet to server
                    send_req(OPCODE['WRQ'], server_file_name)
                    
                    # Read first server response
                    received_packet, received_packet_opcode = receive_tftp_packet()
                    
                    # Additional negotiation if user set a custom transfer block size
                    if BLK_SIZE != 512 or TSIZE_OPTION:
                        # Check opcode of received response
                        if received_packet_opcode == OPCODE['OAC']:
                            # Check if server accepted the options requested by the client
                            negotiated_blksize, negotiated_tsize = process_oac_from_wrq(received_packet, client_file_name)
                        elif received_packet_opcode == OPCODE['ACK']:
                            # ACK means server did not accept option for custom transfer block size
                            negotiated_blksize = False
                        elif received_packet_opcode == OPCODE['ERR']:
                            # ERR means file is too big for the server to handle (i.e. server did not accept transfer size option)
                            negotiated_tsize = False
                    print()
                    
                    # Check status of Client-Server negotiations regarding custom transfer block size
                    if BLK_SIZE != 512 and not negotiated_blksize:
                        # Notify user about failed Client-Server negotiations
                        print('NOTICE: Client-Server negotiation for custom transfer block size has failed.')
                        print('Using default transfer block size (512 bytes) for this file transfer.')
                        print()
                        
                        # Use default BLK_SIZE value
                        change_blksize(BLK_SIZE_DEFAULT)
                    
                    # Check status of Client-Server negotiations regarding transfer size option
                    if TSIZE_OPTION and not negotiated_tsize:
                        # Notify user about failed Client-Server negotiations for transfer size option
                        print('ERROR: Client-Server negotiation for transfer size option has failed.')
                        print(f'File is too big for the server to handle. Aborting upload.')
                    else:
                        # Notify user
                        print(f'Commencing upload of file \'{client_file_name}\' with a size of {os.path.getsize(client_file_name)} bytes to the server.')
                        print()
                        
                        # Set progress indicator
                        progress_indicator = IncrementalBar('Uploading...', max=(os.path.getsize(client_file_name) // BLK_SIZE), suffix='%(percent).1f%% - %(eta)ds')
                        
                        # Open file
                        with open(client_file_name, 'rb') as client_file:
                            # Read the whole file at once
                            client_data = client_file.read()
                            
                            # Loop to iteratively slice and process the next BLK_SIZE amount of data in the file
                            for i in range(0, len(client_data), BLK_SIZE):
                                # Check first if the server response is an ERROR packet
                                if received_packet_opcode == OPCODE['ERR']:
                                    # Process the packet and terminate loop
                                    print(f"ERROR from TFTP server: {ERR_CODE[int.from_bytes(received_packet[2:4], byteorder='big')]}")
                                    break
                                else:
                                    # Increment client block number
                                    client_block_number = (client_block_number + 1) % MAX_VALUE_2_BYTES
                                    
                                    # Get current slice of data
                                    client_data_block = client_data[i : i + BLK_SIZE]
                                        
                                    # Turn the slice into a TFTP DATA packet and send to server
                                    send_dat(client_block_number, client_data_block)
                                    
                                    # Read next server response
                                    received_packet, received_packet_opcode = receive_tftp_packet()
                                    
                                    # Increment progress indicator
                                    progress_indicator.next()
                                        
                            # Check if the file's length is divisible by BLK_SIZE
                            if len(client_data) % BLK_SIZE == 0:
                                # Send the final empty byte to indicate end of transmission
                                send_dat((client_block_number + 1) % MAX_VALUE_2_BYTES, b'')
                        
                            # Notify user once finished
                            progress_indicator.finish()
                            print()
                            print(f'File \'{client_file_name}\' has been successfully uploaded to the server as \'{server_file_name}\'.')
                except ConnectionResetError:
                    # Notify user of error
                    print()
                    print('ERROR from TFTP server: Attempt to further contact the server has failed.')
                
                # Set BLK_SIZE back to its original value
                change_blksize(original_blksize)
                
                # Set SERVER_ADDR back to its original address
                change_server(original_address[0], original_address[1])
                
            elif user_choice == '3':
                prompt_server()
            
            elif user_choice == '4':
                prompt_blksize()
            
            elif user_choice == '5':
                toggle_tsize_option()
                
                # Notify user
                if TSIZE_OPTION:
                    print('Transfer size option is now set to ON.')
                else:
                    print('Transfer size option is now set to OFF.')
            
            elif user_choice == '6':
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
    req += f'\\x0{type}'.encode().decode('unicode_escape').encode('raw_unicode_escape')

    # Convert the passed file name into a byte array and append it to the request packet
    req += bytearray(filename.encode('utf-8'))

    # Append NULL terminator
    req += b'\x00'
    
    # Append transfer mode to request packet
    req += MODE

    # Append NULL terminator
    req += b'\x00'
    
    # Append custom transfer block size value if the user set a custom value
    if BLK_SIZE != 512:
        # Append custom blocksize option indicator
        req += b'blksize'
        
        # Append NULL terminator
        req += b'\x00'
        
        # Append blocksize value
        req += f'{BLK_SIZE}'.encode().decode('unicode_escape').encode('raw_unicode_escape')
        
        # Append NULL terminator
        req += b'\x00'

    # Append transfer size option if the user toggled it on
    if TSIZE_OPTION:
        # Append transfer size option indicator
        req += b'tsize'
        
        # Append NULL terminator
        req += b'\x00'
        
        # Get the size of the file with the name 'filename'
        try:
            # Case for WRQ
            # Append the size of the file
            req += f'{os.path.getsize(filename)}'.encode().decode('unicode_escape').encode('raw_unicode_escape')
        except OSError:
            # Case for RRQ
            # Append 0 as the value
            req += b'\x00'
        
        # Append NULL terminator
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
    dat += f"\\x0{OPCODE['DAT']}".encode().decode('unicode_escape').encode('raw_unicode_escape')
    
    # Append the block number
    dat += block.to_bytes(2, byteorder='big', signed=False)
    
    # Append the data
    dat += data

    # Send the data packet to the server through client socket
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
    ack += f"\\x0{OPCODE['ACK']}".encode().decode('unicode_escape').encode('raw_unicode_escape')
    
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
    err += f"\\x0{OPCODE['ERR']}".encode().decode('unicode_escape').encode('raw_unicode_escape')
    
    # Convert error message into a byte array and append it to the error packet
    err += bytearray(code.encode('utf-8'))
    
    # Append NULL terminator
    err += b'\x00'
    
    # Send the error packet to the server through client socket
    CLIENT_SOCKET.sendto(bytes(err), SERVER_ADDR)

def receive_tftp_packet(dat = False):
    '''
    Function that bundles and adds security to socket.recvsocket() function.
    
    Args:
        dat (bool, optional): Flag to set if the expected TFTP packet to be received is a DATA packet - defaults to False
    
    Returns:
        tuple: A tuple containing the following pair of data:
            - bytes: The packet received from the TFTP server
            - int: The opcode of the packet received from the TFTP server
    '''
    while True:
        # Set limit
        recv_limit = MAX_DATA_LENGTH if dat else BLK_SIZE_DEFAULT
        
        # Receive some packet
        data, addr = CLIENT_SOCKET.recvfrom(recv_limit)
        
        # Check if packet is from the TFTP server
        if addr[0] == SERVER_ADDR[0]:
            # If it is, first refresh SERVER_ADDR by setting it into the source address of the received packet
            # This is because the OS may change the port number from the one entered by the user
            change_server(SERVER_ADDR[0], addr[1])
            
            # Extract opcode from the data then return both the opcode and the actual data
            opcode = data[:2]
            return data, int.from_bytes(opcode, byteorder='big')
        else:
            # If not, ignore
            print(f"Ignoring packet from unexpected address: {addr}")

def process_oac_from_rrq(packet):
    '''
    Function to check if custom transfer blockis acknowledged
    by the server in their OACK response to a RRQ
    
    Args:
        packet (bytes): OACK packet from the server
    
    Returns:
        tuple: A tuple containing the following pair of data:
            - bool: Boolean value whether the server accepted the custom transfer block size option or not
            - int: Integer value containing the size of the file requested to the server
    '''
    # Initialize variables
    negotiated_blksize = False
    file_size = None
    
    # Subset of bytes to scan within the packet
    blksize_subset = f'blksize\\x00{BLK_SIZE}\\x00'.encode().decode('unicode_escape').encode('raw_unicode_escape')
    
    # Check for the presence of custom transfer block size acknowledgement within the packet
    if blksize_subset in packet:
        negotiated_blksize = True
    
    try:
        # Split the OACK packet into its options
        options = packet[2:].split(b'\x00')
        
        # Get the index of the 'tsize' option
        tsize_index = options.index(b'tsize')
        
        # Extract the size of the file requested to the server, which should be on the index next to 'tsize'
        file_size = int(options[tsize_index + 1].decode('utf-8'))
    except ValueError:
        file_size = 0
    
    # Return the values
    return negotiated_blksize, file_size

def process_oac_from_wrq(packet, filename):
    '''
    Function to check if custom transfer block size and transfer size option
    are acknowledged by the server in their OACK response to a WRQ
    
    Args:
        packet (bytes): OACK packet from the server
        filename (str): Name of the file that the client wants to download or upload - defaults to None
    
    Returns:
        tuple: A tuple containing the following pair of data:
            - bool: Boolean value whether the server accepted the custom transfer block size option or not
            - bool: Boolean value whether the server accepted the transfer size option or not
    '''
    # Initialize variables
    negotiated_blksize = False
    negotiated_tsize = False
    
    # Subset of bytes to scan within the packet
    blksize_subset = f'blksize\\x00{BLK_SIZE}\\x00'.encode().decode('unicode_escape').encode('raw_unicode_escape')
    tsize_subset = f'tsize\\x00{os.path.getsize(filename)}\\x00'.encode().decode('unicode_escape').encode('raw_unicode_escape')
    
    # Check for the presence of custom transfer block size acknowledgement within the packet
    if blksize_subset in packet:
        negotiated_blksize = True
    
    # Check for the presence of transfer size option acknowledgement within the packet
    if tsize_subset in packet:
        negotiated_tsize = True
    
    return negotiated_blksize, negotiated_tsize

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
    
def change_blksize(size):
    '''
    Function to change the global variable BLK_SIZE
    which stores the transfer block size to be used by the client
    
    Args:
        size (int): New value to be set to BLK_SIZE
        
    Returns:
        None
    '''
    # Create reference to the global variables
    global BLK_SIZE
    global MAX_DATA_LENGTH
    
    # Change the value of BLK_SIZE
    BLK_SIZE = size
    
    # Since BLK_SIZE is changing, MAX_DATA_LENGTH must also too
    # However, MAX_DATA_LENGTH must not be less than BLK_SIZE_DEFAULT
    MAX_DATA_LENGTH = 4 + BLK_SIZE

def toggle_tsize_option():
    '''
    Function to toggle the global variable TSIZE_OPTION between values True and False
    which stores the decision whether the client will include a transfer size option in its requests
    
    Args:
        None
    
    Returns:
        None
    '''
    # Create reference to the global variable
    global TSIZE_OPTION
    
    # Toggle the values between True and False
    TSIZE_OPTION = False if TSIZE_OPTION else True

def prompt_server():
    '''
    Function to print a prompt requesting the user to enter a server address with a port number
    
    Args:
        None
    
    Returns:
        None
    '''
    # Initialize variables
    input_address = None
    input_port = None
    
    # Loop to prompt user for a valid IP address
    while True:
        print()
        print('(Default address is \'127.0.0.1\' - enter blank to use the default)')
        input_address = input('Enter server address: ')
        
        # Evaluate user input
        if re.match(r'(^localhost)|(^(\d{1,3}\.){3}\d{1,3})', input_address):
            # Change to '127.0.0.1' if 'localhost' is entered, else keep current value
            input_address = '127.0.0.1' if input_address == 'localhost' else input_address
            print(f'Server address set to {input_address}.')
            break
        elif not input_address:
            # Set to default address '127.0.0.1'
            input_address = '127.0.0.1'
            print(f'Server address set to default ({input_address}).')
            break
        else:
            print('ERROR: Please enter a valid IP address.')
            print('FORMAT: xxx.xxx.xxx.xxx')
            input_address = None
            continue
    
    # Loop to prompt user for a valid port number
    while True:
        print()
        print('(Default port number is \'69\' - enter blank to use the default)')
        input_port = input('Enter server port number: ')
        
        # Evaluate user input
        if not input_port:
            input_port = 69
            print(f'Server port number set to default ({input_port}).')
            break
        elif input_port.isdigit() == False:
            print('ERROR: Please enter a valid port number.')
            print('FORMAT: Any integer value')
            input_port = None
            continue
        else:
            print(f'Server port number set to {input_port}.')
            input_port = int(input_port)
            break
    
    # Store server credentials
    change_server(input_address, input_port)
    
    # Notify the user
    print()
    print(f'Server successfully set to: {SERVER_ADDR[0]}:{SERVER_ADDR[1]}')
    prompt_key()

def prompt_blksize():
    '''
    Function to change the global variable BLK_SIZE
    which stores the transfer block size to be negotiated by the client
    
    Args:
        None
    
    Returns:
        None
    '''
    # Initialize variables
    input_blksize = None
    
    # Loop to prompt user for custom blocksize value
    print(f'(Default transfer block size is \'{BLK_SIZE_DEFAULT}\' bytes - enter blank to use the default)')
    while True:
        try:
            # Get user input
            input_value = input('Enter custom transfer block size: ')
            
            # Check if the user entered nothing (i.e. they chose to use the default value)
            if not input_value:
                input_blksize = BLK_SIZE_DEFAULT
                break
            
            # int() function checks if entered value is an integer
            input_blksize = int(input_value)
            
            # Another check to see if the entered value is between 8 - 65464 (as per RFC 2348)
            if input_blksize < 8 or input_blksize > 65464:
                raise ValueError
            
            # Terminate loop if no issues arise
            break
        except ValueError:
            print()
            print('ERROR: Please enter a valid transfer block size value.')
            print('FORMAT: Any positive integer from 8 to 65464.')
            print()
            input_blksize = None
    
    # Set the custom blocksize value to BLK_SIZE
    change_blksize(input_blksize)
    
    # Notify the user
    print()
    print(f'Transfer block size successfully set to: {BLK_SIZE}')

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
    print(art.text2art('EASY', font='modular'))
    print(art.text2art('TFTP', font='modular'))
    print('------------------------------------------------------------------')
    print('A simple command-line TFTP client application')
    print('Developed by J.L. Tapia and Raico Madrinan')
    print('As Machine Project #1 for DLSU NSCOM01 course (T2 2023-2024)')
    print('------------------------------------------------------------------')
    print()

if __name__ == '__main__':
    main()