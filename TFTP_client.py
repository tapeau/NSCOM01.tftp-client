"""
TFTP client in fulfillment of Machine Project #1 for NSCOM01 Term 2 - AY 2023-2024

Members:
TAPIA, John Lorenzo N.
MADRINAN, Raico Luis C.

Credits / References:
"""
# Import necessary libraries
import socket # for socket functionalities
from struct import pack # for packing bytes into a formatted packet (as per the indications of RFC 1350)

# Declare constants
BLKSIZE = 512 # Default is 512. TODO: Feature to alow users change the value of BLKSIZE
MAX_DATA_LENGTH = BLKSIZE + 4 # BLKSIZE + Opcode + Block Number
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

def main():
    # TODO: Main function
    pass

# TODO: Add functions for each TFTP functionality

if __name__ == '__main__':
    main()