from datetime import timedelta

from ids.alerts import emit
from ids.detection.window import Cooldown

# known IP -> MAC mappings, built as we observe ARP
known_mappings = {}

# prevents alert spam from spoofing alerts
ALERT_COOLDOWN = timedelta(seconds=30)
cooldown = Cooldown(ALERT_COOLDOWN)


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
        known_mappings[ip] = mac
        return

    # actual detection; if the MAC is different from the IP -> MAC entry, raise alert
    if known_mac != mac and cooldown.allow(ip, now):
        raise_alert(ip, known_mac, mac)


def raise_alert(ip, old_mac, new_mac):
    emit("ARP spoof", "HIGH", ip,
         f"IP {ip} was {old_mac}, now claimed by {new_mac}")


""" TESTED WITH COMMAND :
### sudo arpspoof -i {interface} -t {TARGET_IP} {ROUTER_IP}
"""