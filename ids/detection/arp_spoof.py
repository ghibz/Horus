from collections import OrderedDict
from datetime import timedelta

from ids import config
from ids.alerts import emit
from ids.detection.window import Cooldown

# Upper limit for the IP -> MAC table. A real LAN has a few hundred hosts at
# most; the limit only matters when someone floods fake ARP packets with endless
# different IPs to make Horus eat RAM. Same limit as the windows in window.py.
MAX_MAPPINGS = 50_000

# known IP -> MAC mappings, built as we observe ARP.
# Least recently seen first, so when the table is full the idlest host is dropped.
known_mappings = OrderedDict()

# prevents alert spam from spoofing alerts
ALERT_COOLDOWN = timedelta(seconds=config.get("arp_spoof")["cooldown_seconds"])
cooldown = Cooldown(ALERT_COOLDOWN)


def reset():
    # Forget everything learned so far (called when a new monitoring session starts)
    # the IP -> MAC table belongs to the network we were listening on;
    # on another network the same IP can legitimately have another MAC
    known_mappings.clear()
    cooldown.clear()


def _remember(ip, mac):
    # store (or update) a mapping as the most recently seen one, and forget the
    # idlest entries if the table grew past MAX_MAPPINGS
    known_mappings[ip] = mac
    known_mappings.move_to_end(ip)
    while len(known_mappings) > MAX_MAPPINGS:
        known_mappings.popitem(last=False)


def process_event(event):
    # early exit if protocol doesn't match
    if event.protocol != "ARP":
        return

    ip = event.arp_sender_ip
    mac = event.arp_sender_mac
    now = event.timestamp

    # ignore incomplete ARP events
    if ip is None or mac is None:
        return

    # ARP probes (a device checking its address is free) use 0.0.0.0 as the
    # sender IP; that is not a real IP -> MAC mapping
    if ip == "0.0.0.0":
        return

    # retrieve the MAC of the IP entry
    known_mac = known_mappings.get(ip)

    # if the IP doesn't have a MAC entry (first time), insert the entry
    if known_mac is None:
        _remember(ip, mac)
        return

    # seen again: mark it as recently active, so busy hosts (the gateway!) are
    # never the ones pushed out of a full table, and idle ones go first
    known_mappings.move_to_end(ip)

    # actual detection; if the MAC is different from the IP -> MAC entry, raise alert
    if known_mac != mac and cooldown.allow(ip, now):
        raise_alert(ip, known_mac, mac)


def raise_alert(ip, old_mac, new_mac):
    emit("ARP spoof", "HIGH", ip,
         f"IP {ip} was {old_mac}, now claimed by {new_mac}",
         details={"old_mac": old_mac, "new_mac": new_mac})


""" TESTED WITH COMMAND :
### sudo arpspoof -i {interface} -t {TARGET_IP} {ROUTER_IP}
"""