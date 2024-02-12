"""
TFTP client in fulfillment of Machine Project #1 for NSCOM01 Term 2 - AY 2023-2024

Members:
TAPIA, John Lorenzo N.
MADRINAN, Raico Luis C.

Credits / References:
"""
# Import necessary libraries
import socket # for socket functionalities
import re # for IP address validation through regex
from art import * # for design purposes

# Declare constants
BLK_SIZE = 512 # Default is 512
MAX_DATA_LENGTH = BLK_SIZE + 4 # BLKSIZE + Opcode + Block Number
MODE = b'octet' # Only support 'octet' transfer mode since the project only deals with binary files

OPCODE = { # Dictionary to store TFTP Opcodes
    'RRQ': 1,
    'WRQ': 2,
    'DAT': 3,
    'ACK': 4,
    'ERR': 5
}

# Create the UDP socket to be used by the client
CLIENT_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Variables to store TFTP server credentials (Empty at start)
SERVER_ADDR = None

# TODO: Main function
def main():
    # Welcome screen
    print()
    print(text2art("EASY", space=4))
    print(text2art("TFTP",font='block'))
    print("--------------------------------------------------------")
    print("A simple command-line TFTP client application")
    print("Developed by Tapia and Madrinan")
    print("As Machine Project #1 for DLSU NSCOM01 course (T2 2023-2024)")
    print("--------------------------------------------------------")
    print()

    # Loop to prompt user to connect to a TFTP server with a valid IP address and port number
    print("Please connect to a TFTP server to start.")
    while True:
        SERVER_ADDR = input("Enter server address: ")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', SERVER_ADDR):
            break
        else:
            print("ERROR: Please enter a valid IP address with a port number.")
            SERVER_ADDR = None
            continue
    
    # TODO: Add functions for bonus features (BLKSIZE setting & TSIZE sending)
    
    # Main program loop
    program_loop = True
    while program_loop:
        # TODO
        pass


# TODO: Add functions for each TFTP opcode functionality
# send_req() X
# send_dat() X
# recv_dat()
# send_ack()
# send_err()

def send_req(type, filename):
    '''
    Function to send TFTP request packet (RRQ or WRQ)

    Parameters:
    type (int): Type of request - 1 for RRQ, 2 for WRQ (according to their opcodes)
    filename (str): Name of file to be included in the request

    Returns:
    None
    '''
    # Request packet will be represented as a byte array
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

    # Send the packet to the server through client socket
    CLIENT_SOCKET.sendto(req, SERVER_ADDR)

def send_dat(block, data):
    '''
    Function to send TFTP data packet

    Parameters:
    block (int): Block number of data packet
    data (bytearray): Bytearray containing data to be sent

    Returns:
    None
    '''
    # Data packet will be represented as a byte array
    dat = bytearray()
    
    # Append data opcode at the beginning of the packet
    dat.extend(0, OPCODE['DAT'])
    
    # Append the block number
    dat.extend(block.to_bytes(2, byteorder='big', signed=False))
    
    # Append the data
    dat.extend(data)
    
    # Send the packet to the server through client socket
    CLIENT_SOCKET.sendto(dat, SERVER_ADDR)

if __name__ == '__main__':
    main()