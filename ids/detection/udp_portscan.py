from datetime import timedelta

from ids import config
from ids.alerts import emit
from ids.detection.window import Cooldown, SlidingWindow

# thresholds come from config.yaml (section: udp_scan)
_cfg = config.get("udp_scan")
PORT_THRESHOLD = _cfg["threshold"]
TIME_WINDOW = timedelta(seconds=_cfg["window_seconds"])
ALERT_COOLDOWN = timedelta(seconds=_cfg["cooldown_seconds"])

# memory of detector, per source IP, UDP destination ports
recent_ports = SlidingWindow(TIME_WINDOW)
cooldown = Cooldown(ALERT_COOLDOWN)


def process_event(event):
    # early exit in case != UDP packet
    if event.protocol != "UDP":
        return

    # no IPv4 source or no destination port = nothing to track
    if event.src_ip is None or event.dst_port is None:
        return

    src = event.src_ip
    now = event.timestamp

    recent_ports.add(src, now, event.dst_port)
    port_count = recent_ports.distinct(src)

    if port_count >= PORT_THRESHOLD and cooldown.allow(src, now):
        raise_alert(src, port_count)


def raise_alert(src_ip, port_count):
    emit("UDP Scan", "MEDIUM", src_ip,
         f"{port_count} distinct UDP ports touched in the last "
         f"{int(TIME_WINDOW.total_seconds())}")


""" TESTED WITH COMMAND :
### sudo nmap -sU -Pn -p 1-1000 {TARGET_IP}
"""
