from scapy.all import sniff
from ids.capture.parser import parse_packet


# Placeholder function for detection later
def handle_packet_event(event):
    print(event)


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
