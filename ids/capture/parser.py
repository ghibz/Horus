from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class PacketEvent:
    timestamp: datetime
    protocol: str

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
