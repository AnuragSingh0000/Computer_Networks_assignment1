import dpkt
import json 
import socket
from datetime import datetime

with open('rules.json', 'r') as file:
    rules = json.load(file)

# List of all ips
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]


def get_ip(header):
  rule_dict = rules["timestamp_rules"]["time_based_routing"]
  hours = int(header[:2])
  packet_id = int(header[-2:])
  for key, value in rule_dict.items():
    start_time = int(value["time_range"][:2])
    end_time = int(value["time_range"][-5:-3])
    if (start_time >= end_time):
      if (hours >= start_time or hours <= end_time):
        ip_pool_start = value["ip_pool_start"]
        hash_mod = value["hash_mod"]
        ip = IP_POOL[ip_pool_start + (packet_id % hash_mod)]
        return ip
    else:
      if (hours >= start_time and hours <= end_time):
        ip_pool_start = value["ip_pool_start"]
        hash_mod = value["hash_mod"]
        ip = IP_POOL[ip_pool_start + (packet_id % hash_mod)]
        return ip
      


def build_dns_response(packet_bytes, fake_ip="1.2.3.4"):
    # Parse Ethernet/IP/UDP/DNS
    eth = dpkt.ethernet.Ethernet(packet_bytes)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)

    # Modify to make it a response
    dns.qr = 1           # response flag
    dns.ra = 1           # recursion available
    dns.rcode = dpkt.dns.DNS_RCODE_NOERR

    answers = []
    for q in dns.qd:  # for each query
        ans = dpkt.dns.DNS.RR(
            name=q.name, 
            type=dpkt.dns.DNS_A, 
            cls=dpkt.dns.DNS_IN,
            ttl=60,
            rdata=socket.inet_aton(fake_ip)  # encode IP in 4 bytes
        )
        answers.append(ans)

    dns.an = answers
    dns.ancount = len(answers)

    # Repack into UDP/IP/Ethernet
    udp.data = bytes(dns)
    udp.ulen = len(udp)
    ip.len = len(ip)
    eth.data = ip

    return bytes(eth)

      

def add_client_header(packet, packet_id):
    now = datetime.now()
    hour = now.hour
    minute = now.minute
    second = now.second
    string_packet_id = f"{packet_id}" if packet_id >= 10 else f"0{packet_id}"
    client_id = f"{hour:02d}{minute:02d}{second:02d}{string_packet_id}"
    packet_str = f"{client_id}|{packet.hex()}"
    return packet_str.encode()

def show_dns(packet_bytes):
    eth = dpkt.ethernet.Ethernet(packet_bytes)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)

    # Queries
    if dns.qd:
        print("\n[Queries]")
        for q in dns.qd:
            print(f"Name: {q.name}, Type: {q.type}, Class: {q.cls}")

    # Answers
    if dns.an:
        print("\n[Answers]")
        for ans in dns.an:
            if ans.type == dpkt.dns.DNS_A:
                print(f"Name: {ans.name}, IP: {socket.inet_ntoa(ans.rdata)}")
            else:
                print(f"Name: {ans.name}, Type: {ans.type}, Data: {ans.rdata}")

    # Authority Records
    if dns.ns:
        print("\n[Authority Records]")
        for ns in dns.ns:
            print(f"Name: {ns.name}, Type: {ns.type}, Data: {ns.rdata}")

    # Additional Records
    if dns.ar:
        print("\n[Additional Records]")
        for ar in dns.ar:
            print(f"Name: {ar.name}, Type: {ar.type}, Data: {ar.rdata}")



def parse_dns(packet_bytes):
    eth = dpkt.ethernet.Ethernet(packet_bytes)
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)

    domain = None
    resolved_ip = None

    # Query
    if dns.qd:
        domain = dns.qd[0].name

    # Answer
    if dns.an:
        for ans in dns.an:
            if ans.type == dpkt.dns.DNS_A:
                resolved_ip = socket.inet_ntoa(ans.rdata)
                break

    return domain, resolved_ip


def show_table(results):
    print("\n{:<12} {:<25} {:<15}".format("Header", "Domain", "Resolved IP"))
    print("-" * 55)
    for header, domain, ip in results:
        print("{:<12} {:<25} {:<15}".format(header, domain, ip if ip else "-"))