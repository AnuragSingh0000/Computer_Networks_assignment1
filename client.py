# Import necessary modules
import socket
import dpkt
from helper import parse_dns, show_table, show_dns, add_client_header


# Read and filter DNS queries from the '5.pcap' file

# Initialize a list to store the captured DNS queries
cap = [] 
with open("5.pcap", "rb") as f:
    pcap = dpkt.pcap.Reader(f)

    # Loop through each packet in the pcap file
    for ts, buf in pcap:
        # Parse the Ethernet frame
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data

        # Check if the packet is a UDP packet.
        if not isinstance(ip.data, dpkt.udp.UDP):
            continue
        udp = ip.data

        # Check if the source or destination port is 53 (DNS port).
        if udp.sport != 53 and udp.dport != 53:
            continue

        try:
            # Try to parse the UDP data as a DNS packet
            dns = dpkt.dns.DNS(udp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            # If parsing fails, skip the packet
            continue

        # Check if the DNS packet is a query (qr flag == 0). If it is, add it to the list.
        if dns.qr == 0:
            cap.append(buf)


# Create a TCP client socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 23354

# Connect the client socket to the server on the specified port
client_socket.connect(('127.0.0.1', port))

# Initialize a counter for the packet ID
packet_id = 0 

# Initialize a variable to track the maximum packet length
max_len = 0   

# Initialize a list to store the DNS resolution results
results = []  

# Loop through each captured DNS query packet
for packet in cap:
    # Print the details of the DNS query before sending it
    print("Query DNS Packet: ")
    show_dns(packet)

    # Add client header to the packet and get the new SDU
    SDU = add_client_header(packet=packet, packet_id=packet_id)

    # Increment the packet ID for the next packet
    packet_id += 1 

    # Update the maximum length if the current SDU is longer
    max_len = max(max_len, len(SDU)) 

    # Send the SDU to the server
    client_socket.sendall(SDU) 

    # Receive the response from the server
    resp_packet = client_socket.recv(4096 * 8)

    # Print the details of the DNS response
    print("Response DNS Packet: ")
    show_dns(resp_packet)

    # Extract the header from the original SDU
    hdr = SDU.decode().split('|')[0]

    # Parse the domain and resolved IP from the received response packet
    domain, ip = parse_dns(resp_packet)
    
    results.append((hdr, domain, ip))


# Display the final results in a formatted table
show_table(results)

# Print the total number of DNS query packets processed
print(f"The number of DNS query packets are: {packet_id}")

# Close the client socket to release the connection
client_socket.close()