from scapy.all import sniff
from ids.capture.parser import parse_packet
from ids.detection.portscan import process_event as process_portscan_event
from ids.detection.arp_spoof import process_event as process_arp_event
from ids.detection.syn_flood import process_event as process_synflood_event


# Placeholder function for detection later
def handle_packet_event(event):
    process_portscan_event(event)
    process_arp_event(event)
    process_synflood_event(event)


# Function called on every packet, to be parsed and handed to placeholder function
def packet_callback(pkt):
    event = parse_packet(pkt)
    handle_packet_event(event)


# Interface set to none (auto-pick) for now, later configured via config.yaml
def start_sniffing(interface=None):
    print("Horus is LISTENING.. Ctrl+C to stop.")
    try:
        # 1. Wires in callback function
        # 2. Specifies network interface
        # 3. Doesn't store packets in memory (slow RAM)
        sniff(prn=packet_callback, iface=interface, store=False)
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    start_sniffing()
