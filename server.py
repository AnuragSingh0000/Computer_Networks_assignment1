# Import the dpkt and socket libraries for network packet manipulation and socket programming
import dpkt
import socket
import json
from helper import get_ip, build_dns_response

# Initialize a TCP server socket
# AF_INET specifies the IPv4 address family and SOCK_STREAM specifies the TCP protocol
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Choose a port number for the server to listen on
port = 23354
print ("Server Socket successfully created")

# Bind the socket to all available network interfaces on the specified port
server_socket.bind(("0.0.0.0", port))
print(server_socket)

# Enable the server to accept connections (with a backlog queue of 5)
server_socket.listen(5)

# The server enters an infinite loop to continuously accept new client connections
while True:
    
    # Accept a new client connection
    # 'client_socket' is a new socket object representing the connection and 'addr' is the address of the client
    client_socket, addr = server_socket.accept()
    print ('Got connection from', addr)

    # Loop to handle communication with the connected client
    while True:
        # Receive data from the client
        data = client_socket.recv(4096*8)
        if not data:
            # If no data is received, the client has closed the connection
            break

        # Decode the received data from bytes to a string
        packet = data.decode()

        # Extract the header
        header = packet.split("|")[0]
        # Extract the hexadecimal part after the client_header
        hex_str = packet.split("|", 1)[1]
        # Convert the hexadecimal string back into bytes to get the original packet
        packet_bytes = bytes.fromhex(hex_str)
        # Use the get_ip function to determine the target IP based on the header
        ip = get_ip(header)
        # Print the header and the determined IP for logging purposes
        print("Received:", data.decode().split("|")[0], "ip: ", ip)
        # Use the custom build_dns_response function to create a new DNS response packet
        dns_response_packet = build_dns_response(packet_bytes, input_ip=ip)
        # Send the newly created DNS response packet back to the client
        client_socket.sendall(dns_response_packet)

    # Close the connection with the current client
    client_socket.close()