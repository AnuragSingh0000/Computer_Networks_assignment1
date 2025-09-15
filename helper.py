import dpkt
import json
import socket
from datetime import datetime

# Load the routing rules from 'rules.json'
with open('rules.json', 'r') as file:
    rules = json.load(file)

# A predefined list of IP addresses that serves as a pool for routing decisions
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]


def get_ip(header):
    # Access the time-based routing rules from the loaded JSON data
    rule_dict = rules["timestamp_rules"]["time_based_routing"]
    # Extract the hour from the first two characters of the header
    hours = int(header[:2])
    # Extract the packet ID from the last two characters of the header
    packet_id = int(header[-2:])
    # Iterate through each rule to find a matching time range
    for key, value in rule_dict.items():
        start_time = int(value["time_range"][:2])
        end_time = int(value["time_range"][-5:-3])
        # Handle time ranges that span across midnight 
        if (start_time >= end_time):
            if (hours >= start_time or hours <= end_time):
                # Calculate the first IP of the subsection of the IP pool corresponding to the time range
                ip_pool_start = value["ip_pool_start"]
                hash_mod = value["hash_mod"]
                # Calculate the IP index using the packet ID
                ip = IP_POOL[ip_pool_start + (packet_id % hash_mod)]
                return ip
        # Handle standard time ranges
        else:
            if (hours >= start_time and hours <= end_time):
                ip_pool_start = value["ip_pool_start"]
                hash_mod = value["hash_mod"]
                ip = IP_POOL[ip_pool_start + (packet_id % hash_mod)]
                return ip


def build_dns_response(packet_bytes, ip):
    # Parse the incoming Ethernet frame down to the DNS layer
    eth = dpkt.ethernet.Ethernet(packet_bytes)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)

    # Modify the DNS packet to turn it into a response

    # Set the Query/Response flag to 1 (response)
    dns.qr = 1  
    # Set the response code to No Error                         
    dns.rcode = dpkt.dns.DNS_RCODE_NOERR  

    answers = []
    # Loop through each query in the DNS packet to create a corresponding answer
    for q in dns.qd:
        # Create a new DNS Resource Record for the answer
        ans = dpkt.dns.DNS.RR(
            name=q.name,
            # Set the type to 'A' for an IPv4 address        
            type=dpkt.dns.DNS_A,
            # Set the class to 'IN' for Internet
            cls=dpkt.dns.DNS_IN,
            ttl=60,
            # Convert the IP string to binary format          
            rdata=socket.inet_aton(ip) 
        )
        answers.append(ans)

    # Add the list of answers to the DNS packet
    dns.an = answers
    dns.ancount = len(answers) 

    # Re-assemble the packet layers in the correct order
    udp.data = bytes(dns)
    udp.ulen = len(udp)
    ip.len = len(ip)
    eth.data = ip

    # Return the complete Ethernet frame as bytes
    return bytes(eth) 

def add_client_header(packet, packet_id):
    # Get the current time
    now = datetime.now()
    hour = now.hour
    minute = now.minute
    second = now.second

    # Format the packet ID with a leading zero if it's a single digit
    string_packet_id = f"{packet_id}" if packet_id >= 10 else f"0{packet_id}"

    # Create the client ID header in "HHMMSSPP" format
    client_id = f"{hour:02d}{minute:02d}{second:02d}{string_packet_id}"

    # Convert the packet to a hexadecimal string and combine with the header
    packet_str = f"{client_id}|{packet.hex()}"
    return packet_str.encode()


def show_dns(packet_bytes):
    try:
        # Parse the packet from the Ethernet layer down to the DNS layer
        eth = dpkt.ethernet.Ethernet(packet_bytes)
        ip = eth.data
        udp = ip.data
        dns = dpkt.dns.DNS(udp.data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.Error):
        print("Error: Could not parse packet as DNS.")
        return

    # Print the DNS queries if they exist
    if dns.qd:
        print("\n[Queries]")
        for q in dns.qd:
            print(f"Name: {q.name}, Type: {q.type}, Class: {q.cls}")

    # Print the DNS answers if they exist
    if dns.an:
        print("\n[Answers]")
        for ans in dns.an:
            if ans.type == dpkt.dns.DNS_A:
                # For A-records, decode the IP address and print
                print(f"Name: {ans.name}, IP: {socket.inet_ntoa(ans.rdata)}")
            else:
                print(f"Name: {ans.name}, Type: {ans.type}, Data: {ans.rdata}")

    # Print any Authority Records
    if dns.ns:
        print("\n[Authority Records]")
        for ns in dns.ns:
            print(f"Name: {ns.name}, Type: {ns.type}, Data: {ns.rdata}")

    # Print any Additional Records
    if dns.ar:
        print("\n[Additional Records]")
        for ar in dns.ar:
            print(f"Name: {ar.name}, Type: {ar.type}, Data: {ar.rdata}")
    
    print("-------------------------------------------------------------------")


def parse_dns(packet_bytes):
    try:
        # Parse the packet
        eth = dpkt.ethernet.Ethernet(packet_bytes)
        ip = eth.data
        udp = ip.data
        dns = dpkt.dns.DNS(udp.data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.Error):
        return None, None

    domain = None
    resolved_ip = None

    # Get the domain name from the first query
    if dns.qd:
        domain = dns.qd[0].name

    # Check for the first A-record answer and extract the IP
    if dns.an:
        for ans in dns.an:
            if ans.type == dpkt.dns.DNS_A:
                resolved_ip = socket.inet_ntoa(ans.rdata)
                break

    return domain, resolved_ip


def show_table(results):
    # Print the table header
    print("\n{:<12} {:<25} {:<15}".format("Header", "Domain", "Resolved IP"))
    print("-" * 55)
    # Loop through the results and print each row
    for header, domain, ip in results:
        # If the IP is None, display a dash instead
        print("{:<12} {:<25} {:<15}".format(header, domain, ip if ip else "-"))