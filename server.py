# Import socket module 
import dpkt
import socket
import json
from helper import get_ip, build_dns_response

# Initializing a server socket in the AF_INET address family (IPv4) 
# SOCK_STREAM means connection-oriented TCP protocol. 
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Port chosen at random (made sure it is above port number 1023 as range 0-1023 are reserved for standard services and
# below 49152 (beyond whiich is the range for Dynamic/Ephemeral ports used temporarily by client))
port = 23354
print ("Server Socket successfully created")
server_socket.bind(("0.0.0.0", port))
print(server_socket)

server_socket.listen(5)

while True: 
# Establish connection with client. 
  client_socket, addr = server_socket.accept()     
  print ('Got connection from', addr )  

  while True:
    data = client_socket.recv(4096*8)
    if not data:
        break  # client closed connection
    
    packet = data.decode()
    header = packet.split("|")[0]
    hex_str = packet.split("|", 1)[1] 
    packet_bytes = bytes.fromhex(hex_str)
    ip = get_ip(header)
    print("Received:", data.decode().split("|")[0], "ip: ", ip)
    # Build DNS response with IP
    dns_response_packet = build_dns_response(packet_bytes, fake_ip=ip)
    client_socket.sendall(dns_response_packet)
    
  # Close the connection with the client 
  client_socket.close()
  break
  