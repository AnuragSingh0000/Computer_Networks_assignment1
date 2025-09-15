# Import socket module 
import socket
import dpkt
from helper import parse_dns, show_table, show_dns, add_client_header


# Read and filter DNS queries into cap
cap = []
with open("5.pcap", "rb") as f:
    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data

        # Only UDP packets
        if not isinstance(ip.data, dpkt.udp.UDP):
            continue
        udp = ip.data

        # Only DNS (port 53)
        if udp.sport != 53 and udp.dport != 53:
            continue

        try:
            dns = dpkt.dns.DNS(udp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue

        # Only DNS queries (qr == 0)
        if dns.qr == 0:
            cap.append(buf) 


# Create a client socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         
port = 23354
client_socket.connect(('127.0.0.1', port)) 

packet_id = 0
max_len = 0
results = []

for packet in cap:
    # Show the DNS query before sending
    show_dns(packet)

    SDU = add_client_header(packet=packet, packet_id=packet_id)
    packet_id += 1
    max_len = max(max_len, len(SDU))
    client_socket.sendall(SDU)

    # Receive response
    resp_packet = client_socket.recv(4096 * 8)
    show_dns(resp_packet)
    hdr = SDU.decode().split('|')[0]
    domain, ip = parse_dns(resp_packet)
    results.append((hdr, domain, ip))


show_table(results)
print(max_len)
print(f"The number of DNS query packets are: {packet_id}")

client_socket.close()
