from scapy.all import AsyncSniffer, conf, get_if_list, sniff

from ids.capture.parser import parse_packet
from ids.detection.portscan import process_event as process_portscan_event
from ids.detection.arp_spoof import process_event as process_arp_event
from ids.detection.syn_flood import process_event as process_synflood_event

# Shared counter, read by the GUI to show packets captured
stats = {"packets": 0}


# Hands every parsed event to every detector
def handle_packet_event(event):
    process_portscan_event(event)
    process_arp_event(event)
    process_synflood_event(event)


# Function called on every packet, to be parsed and handed to the detectors
def packet_callback(pkt):
    stats["packets"] += 1
    try:
        event = parse_packet(pkt)
        handle_packet_event(event)
    except Exception as exc:
        # one malformed packet must not stop the whole capture
        print(f"[WARN] Skipped a packet: {exc!r}")


# Names of the interfaces scapy can capture on (used by the GUI dropdown)
def list_interfaces():
    try:
        return sorted({iface.name for iface in conf.ifaces.values()})
    except Exception:
        return get_if_list()


# Background sniffer that can be started and stopped (used by the GUI)
def create_sniffer(interface=None):
    return AsyncSniffer(prn=packet_callback, iface=interface, store=False)


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