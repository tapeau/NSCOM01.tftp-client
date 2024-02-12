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
'''
# Import necessary libraries
import socket # for socket functionalities
import re # for IP address validation through regex
from os import system, name # for design purposes
from art import * # for design purposes

# Declare constants
BLK_SIZE = 512 # Default is 512
MAX_DATA_LENGTH = BLK_SIZE + 4 # BLK_SIZE + opcode + Block Number
MODE = b'octet' # Only support 'octet' transfer mode since the project only deals with binary files

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

# Variables to store TFTP server credentials (Empty at start)
SERVER_ADDR = None

def main():
    '''
    Function that contains the application's main functionalities.
    
    Parameters:
    None
    
    Returns:
    None
    '''
    # Welcome screen
    clear_console()
    print_header()

    # Loop to prompt user to connect to a TFTP server with a valid IP address and port number
    print('Please connect to a TFTP server to start.')
    while True:
        SERVER_ADDR = input('Enter server address: ')
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', SERVER_ADDR):
            print('Server address set.')
            print()
            break
        else:
            print('ERROR: Please enter a valid IP address with a port number.')
            print()
            SERVER_ADDR = None
            continue
    
    # TODO: Add functions for bonus features (BLK_SIZE setting & TSIZE sending)
    
    # Main program loop
    program_loop = True
    while program_loop:
        # Reset UI
        clear_console()
        print_header()
        
        # Print menu
        print('\'1\'\tDownload a file from the server')
        print('\'2\'\tUpload a file to the server')
        print('\'3\'\tExit')
        print()
        
        # Prompt for user choice
        user_choice = input('Enter the number of your desired action: ')
        print()
        
        # Evaluate user choice
        if user_choice == 1:
            # TODO
            pass
        elif user_choice == 2:
            # TODO
            pass
        elif user_choice == 3:
            # Prompt for user confirmation
            user_confirm = input('Are you sure you want to exit the application? (Y/N): ')
            program_loop = False if (user_confirm == 'Y' or user_confirm == 'y') else True
        else:
            print('ERROR: Unrecognized input.')
    
    # Notify user
    print('Program terminated.')
        

def send_req(type, filename):
    '''
    Function to send TFTP request packet (RRQ or WRQ).

    Parameters:
    type (int): Type of request - 1 for RRQ, 2 for WRQ (according to their opcodes)
    filename (str): Name of file to be included in the request

    Returns:
    None
    '''
    # Represent request packet as a bytearray
    req = bytearray() 

    # Append request opcode at the beginning of the packet
    req.extend(0, type)

    # Convert the passed file name into a byte array and append it to the request packet
    req += bytearray(filename.encode('utf-8'))

    # Append 0x00 byte
    req.append(0)
    
    # Append transfer mode to request packet
    req += bytearray(bytes(MODE, 'utf-8'))

    # Append 0x00 byte
    req.append(0)

    # Send the request packet to the server through client socket
    CLIENT_SOCKET.sendto(req, SERVER_ADDR)

def send_dat(block, data):
    '''
    Function to send TFTP data packet.

    Parameters:
    block (int): Block number of data packet
    data (bytearray): Bytearray containing data to be sent

    Returns:
    None
    '''
    # Represent data packet as a bytearray
    dat = bytearray()
    
    # Append data opcode at the beginning of the packet
    dat.extend(0, OPCODE['DAT'])
    
    # Append the block number
    dat.extend(block.to_bytes(2, byteorder='big', signed=False))
    
    # Append the data
    dat.extend(data)
    
    # Send the data packet to the server through client socket
    CLIENT_SOCKET.sendto(dat, SERVER_ADDR)

def send_ack(block):
    '''
    Function to send TFTP acknowledge packet/signal.
    
    Parameters:
    block (int): Block number of data packet
    
    Returns:
    None
    '''
    # Represent acknowledge packet as a bytearray
    ack = bytearray()
    
    # Append acknowledgement opcode at the beginning of the packet
    ack.extend(0, OPCODE['ACK'])
    
    # Append the block number
    ack.extend(block.to_bytes(2, byteorder='big', signed=False))
    
    # Send the acknowledgement packet to the server through client socket
    CLIENT_SOCKET.sendto(ack, SERVER_ADDR)

def send_err(code):
    '''
    Function to send TFTP error packet/signal.
    
    Parameters:
    code (int): Error code to send
    
    Returns:
    None
    '''
    # Represent error packet as a bytearray
    err = bytearray()
    
    # Append error opcode at the beginning of the packet
    err.extend(0, OPCODE['ERR'])
    
    # Convert error message into a byte array and append it to the error packet
    err += bytearray(ERR_CODE[code].encode('utf-8'))
    
    # Append 0x00 terminating byte
    err.append(0)
    
    # Send the error packet to the server through client socket
    CLIENT_SOCKET.sendto(err, SERVER_ADDR)

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
    if name == 'nt':
        _ = system('cls')
 
    # For Mac and Linux (here, os.name is 'posix')
    else:
        _ = system('clear')

def print_header():
    '''
    Function to print application header (for design purposes).
    
    Parameters:
    None
    
    Returns:
    None
    '''
    print()
    print(text2art('EASY', space=4))
    print(text2art('TFTP',font='block'))
    print('--------------------------------------------------------')
    print('A simple command-line TFTP client application')
    print('Developed by Tapia and Madrinan')
    print('As Machine Project #1 for DLSU NSCOM01 course (T2 2023-2024)')
    print('--------------------------------------------------------')
    print()

if __name__ == '__main__':
    main()