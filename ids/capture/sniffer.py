import threading
import time

from scapy.all import AsyncSniffer, conf, get_if_list, sniff

from ids.capture.parser import parse_packet
from ids.detection import (arp_spoof, bruteforce, icmp_flood, icmp_unusual,
                           portscan, syn_flood, udp_portscan)

# Every detector that receives every parsed event, as
# (name, process_event function, reset function).
# To add a new detector: import its module above and add one line here.
# Every detector module needs both process_event() and reset().
DETECTORS = [
    ("port scan",    portscan.process_event,      portscan.reset),
    ("ARP spoof",    arp_spoof.process_event,     arp_spoof.reset),
    ("SYN flood",    syn_flood.process_event,     syn_flood.reset),
    ("UDP scan",     udp_portscan.process_event,  udp_portscan.reset),
    ("brute force",  bruteforce.process_event,    bruteforce.reset),
    ("ICMP flood",   icmp_flood.process_event,    icmp_flood.reset),
    ("unusual ICMP", icmp_unusual.process_event,  icmp_unusual.reset),
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

# Start/Stop safety. Stopping a scapy sniffer is asynchronous: its thread can
# still deliver a few packets after stop() returned. Without protection those
# late packets would land in the NEXT session (after its detectors were reset)
# and could even raise alerts into the new session's database.
#   * _active_token  -> identifies the one sniffer allowed to feed the detectors.
#                       Every sniffer made by create_sniffer() gets its own token;
#                       stop (or a newer sniffer) invalidates the old one.
#   * _lock          -> a packet is processed while holding it, and so are resets,
#                       so a reset can never happen in the middle of a packet.
_lock = threading.RLock()
_active_token = None


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


# Wipes what every detector has learned (counters, cooldowns, the ARP table) and
# the failure counters. Called when a new monitoring session starts, so nothing
# from an earlier session (maybe on another network) leaks into the new one.
def reset_detectors():
    with _lock:
        for name, _process, reset in DETECTORS:
            try:
                reset()
            except Exception as exc:   # one failing reset must not skip the others
                print(f"[WARN] Could not reset detector '{name}': {exc!r}")
        reset_error_tracking()


# Everything a new monitoring session starts from: packet counter at zero and
# every detector wiped. Called by the GUI on Start, after the old sniffer was
# deactivated.
def begin_session():
    with _lock:
        stats["packets"] = 0
        reset_detectors()


# Called by the GUI on Stop (and when a start fails): from now on the current
# sniffer's packets are ignored, even if its thread is still winding down.
# Waits at most for the packet being processed right now.
def deactivate_sniffer():
    global _active_token
    with _lock:
        _active_token = None


# Hands every parsed event to every detector.
# Each detector runs on its own: if one of them has a bug and raises, the
# others still get the event, so a single faulty detector can't blind Horus.
def handle_packet_event(event):
    for name, process, _reset in DETECTORS:
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
    global _active_token
    token = object()

    def guarded_callback(pkt):
        with _lock:
            if _active_token is not token:
                return      # stopped, or replaced by a newer sniffer: ignore
            packet_callback(pkt)

    with _lock:
        _active_token = token   # also silences any older sniffer still running
    return AsyncSniffer(prn=guarded_callback, iface=interface, store=False)


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