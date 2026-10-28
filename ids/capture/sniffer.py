import time

from scapy.all import AsyncSniffer, conf, get_if_list, sniff

from ids.capture.parser import parse_packet
from ids.detection.portscan import process_event as process_portscan_event
from ids.detection.arp_spoof import process_event as process_arp_event
from ids.detection.syn_flood import process_event as process_synflood_event
from ids.detection.udp_portscan import process_event as process_udp_portscan_event
from ids.detection.bruteforce import process_event as process_bruteforce_event
from ids.detection.icmp_flood import process_event as process_icmp_flood_event
from ids.detection.icmp_unusual import process_event as process_icmp_unusual_event

# Every detector that receives every parsed event, as (name, function).
# To add a new detector: import its process_event above and add one line here.
DETECTORS = [
    ("port scan",    process_portscan_event),
    ("ARP spoof",    process_arp_event),
    ("SYN flood",    process_synflood_event),
    ("UDP scan",     process_udp_portscan_event),
    ("brute force",  process_bruteforce_event),
    ("ICMP flood",   process_icmp_flood_event),
    ("unusual ICMP", process_icmp_unusual_event),
]

# Shared counters, read by the GUI
#   packets          -> packets captured
#   detector_errors  -> {detector name: how many times it raised an exception}
stats = {"packets": 0, "detector_errors": {}}

# A detector that keeps failing would print on every packet and slow the
# capture down. The first failure of each detector is printed right away,
# after that at most one line per detector every ERROR_PRINT_INTERVAL seconds.
ERROR_PRINT_INTERVAL = 10.0
_error_log = {}   # detector name -> [time of last print, failures since then]


def _report_detector_error(name, exc):
    stats["detector_errors"][name] = stats["detector_errors"].get(name, 0) + 1

    now = time.monotonic()
    last_print, unreported = _error_log.get(name, (None, 0))
    unreported += 1

    if last_print is None or now - last_print >= ERROR_PRINT_INTERVAL:
        extra = f" ({unreported} failures since the last message)" if unreported > 1 else ""
        print(f"[WARN] Detector '{name}' failed: {exc!r}{extra}")
        _error_log[name] = [now, 0]
    else:
        _error_log[name] = [last_print, unreported]


def reset_error_tracking():
    # Forget all detector failures (called when a new monitoring session starts)
    stats["detector_errors"].clear()
    _error_log.clear()


# Hands every parsed event to every detector.
# Each detector runs on its own: if one of them has a bug and raises, the
# others still get the event, so a single faulty detector can't blind Horus.
def handle_packet_event(event):
    for name, process in DETECTORS:
        try:
            process(event)
        except Exception as exc:
            _report_detector_error(name, exc)


# Function called on every packet, to be parsed and handed to the detectors
def packet_callback(pkt):
    stats["packets"] += 1
    try:
        event = parse_packet(pkt)
    except Exception as exc:
        # one malformed packet must not stop the whole capture
        print(f"[WARN] Skipped a packet: {exc!r}")
        return
    handle_packet_event(event)


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