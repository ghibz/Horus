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
        fields["src_mac"] = pkt[Ether].src # Extract Source MAC
        fields["dst_mac"] = pkt[Ether].dst # Extract Destination MAC

    if pkt.haslayer(IP):
        fields["ip_version"] = pkt[IP].version # Extract IPv4/6
        fields["length"] = pkt[IP].len

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
