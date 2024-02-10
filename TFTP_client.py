"""
TFTP client in fulfillment of Machine Project #1 for NSCOM01 Term 2 - AY 2023-2024

Members:
TAPIA, John Lorenzo N.
MADRINAN, Raico Luis C.

Credits / References:
"""
# Import necessary libraries
import socket # for socket functionalities

# Declare constants
BLKSIZE = 512 # Default is 512
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

# Variables to store TFTP server credentials (Empty at start)
SERVER_ADDR = None

# TODO: Main function
def main():
    pass

# TODO: Add functions for each TFTP opcode functionality
# send_rrq()
# send_wrq()
# send_dat()
# send_ack()
# send_err()

def send_rrq(filename):
    # RRQ packet will be represented as a byte array
    rrq = bytearray() 

    # Append RRQ opcode at the beginning of the packet
    rrq.extend(0, OPCODE['RRQ'])

    # Convert the passed file name into a byte array and append it to the RRQ packet
    rrq += bytearray(filename.encode('utf-8'))

    # Append 0x00 byte between file name and transfer mode
    rrq.append(0)
    
    # Append transfer mode to RRQ packet
    rrq += bytearray(bytes(MODE, 'utf-8'))

    # Append 0x00 terminal byte
    rrq.append(0)

    # Send the packet to server through client socket
    CLIENT_SOCKET.sendto(rrq, SERVER_ADDR)

    # Notify client
    print(f"File \"{filename}\" requested to server {SERVER_ADDR}")

# TODO: Add functions for bonus features (BLKSIZE setting & TSIZE sending)

if __name__ == '__main__':
    main()