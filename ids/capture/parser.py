from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# Step 1
@dataclass  # decorator, auto-generates __init__ and a readable string representation
class PacketEvent:
    # required fields, timestamp and type of protocol
    timestamp: datetime
    protocol: str

    # optional fields, depending on type of protocol, defaults to None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    length: Optional[int] = None

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: Optional[str] = None

    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    dns_query: Optional[str] = None

    arp_sender_mac: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None


# Step 2
from scapy.all import Ether, IP


# Function to extract general fields of a packet, timestamp, Src/Dest MAC and IP if needed
def extract_general_fields(pkt) -> dict:
    fields = {}
    fields["timestamp"] = datetime.fromtimestamp(float(pkt.time))

    if pkt.haslayer(Ether):
        fields["src_mac"] = pkt[Ether].src  # Extract Source MAC
        fields["dst_mac"] = pkt[Ether].dst  # Extract Destination MAC

    if pkt.haslayer(IP):
        fields["ip_version"] = pkt[IP].version  # Extract IPv4/6
        fields["length"] = pkt[IP].len
        fields["src_ip"] = pkt[IP].src
        fields["dst_ip"] = pkt[IP].dst

    return fields


# Step 3
from scapy.all import TCP, UDP, ICMP, ARP


# Function to extract the packet's protocol, for now, only TCP, UDP, ICMP and ARP are detectable
def detect_protocol(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    else:
        return "Unknown"


# Step 4
from scapy.all import TCP


# IF detect_protocol returns TCP
def extract_tcp_fields(pkt) -> dict:
    fields = {}

    tcp_layer = pkt[TCP]  # Store the entire TCP info in a variable
    fields["src_port"] = tcp_layer.sport  # Extract Source port from TCP
    fields["dst_port"] = tcp_layer.dport  # Extract Destination port from TCP
    fields["flags"] = str(tcp_layer.flags)  # Extract Flags from TCP

    return fields


from scapy.all import UDP, DNS, DNSQR


# IF detect_protocol returns UDP
def extract_udp_fields(pkt) -> dict:
    fields = {}

    udp_layer = pkt[UDP]
    fields["src_port"] = udp_layer.sport
    fields["dst_port"] = udp_layer.dport

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        fields["dns_query"] = pkt[DNSQR].qname.decode(errors="ignore")

    return fields


from scapy.all import ICMP


# IF detect_protocol returns ICMP
def extract_icmp_fields(pkt) -> dict:
    fields = {}

    icmp_layer = pkt[ICMP]
    fields["icmp_type"] = icmp_layer.type
    fields["icmp_code"] = icmp_layer.code

    return fields


from scapy.all import ARPHDR_ETHER


# IF detect_protocol returns ARP
def extract_arp_fields(pkt) -> dict:
    fields = {}

    arp_layer = pkt[ARP]
    fields["arp_sender_mac"] = arp_layer.hwsrc
    fields["arp_sender_ip"] = arp_layer.psrc
    fields["arp_target_mac"] = arp_layer.hwdst
    fields["arp_target_ip"] = arp_layer.pdst

    return fields


# Step 5

def parse_packet(pkt) -> PacketEvent:
    protocol = detect_protocol(pkt)  # Check protocol
    general_fields = extract_general_fields(pkt)  # Extract general fields

    if protocol == "TCP":
        specific_fields = extract_tcp_fields(pkt)
    elif protocol == "UDP":
        specific_fields = extract_udp_fields(pkt)
    elif protocol == "ICMP":
        specific_fields = extract_icmp_fields(pkt)
    elif protocol == "ARP":
        specific_fields = extract_arp_fields(pkt)
    else:
        specific_fields = {}

    # Unpack all key-value pairs of both dicts and combine them
    all_fields = {**general_fields, **specific_fields}
    return PacketEvent(protocol=protocol, **all_fields)


