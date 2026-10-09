from datetime import timedelta

from ids import config
from ids.alerts import emit
from ids.detection.window import Cooldown, SlidingWindow

# thresholds come from config.yaml (section: port_scan)
_cfg = config.get("port_scan")
PORT_THRESHOLD = _cfg["threshold"]
TIME_WINDOW = timedelta(seconds=_cfg["window_seconds"])
ALERT_COOLDOWN = timedelta(seconds=_cfg["cooldown_seconds"])

# detector's memory: per source IP, the destination ports it has hit recently
recent_ports = SlidingWindow(TIME_WINDOW)
cooldown = Cooldown(ALERT_COOLDOWN)


def process_event(event):
    # early exits, no TCP or SYN packets
    if event.protocol != "TCP":
        return
    if event.flags != "S":
        return

    # no IPv4 source (e.g. IPv6 traffic): nothing to attribute the scan to
    if event.src_ip is None or event.dst_port is None:
        return

    src = event.src_ip
    now = event.timestamp

    # records the port under the source IP's history; old entries age out automatically
    recent_ports.add(src, now, event.dst_port)
    port_count = recent_ports.distinct(src)

    # decision point, if number of distinct ports is over threshold, raise alert
    if port_count >= PORT_THRESHOLD and cooldown.allow(src, now):
        raise_alert(src, port_count)


def raise_alert(src_ip, port_count):
    emit("Port scan", "MEDIUM", src_ip,
         f"{port_count} distinct ports touched in the last "
         f"{int(TIME_WINDOW.total_seconds())}s")


""" TESTED WITH COMMAND :
### nmap -sS -Pn -p 1-1000 {TARGET_IP}
"""