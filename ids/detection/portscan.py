from datetime import timedelta

from ids import config
from ids.alerts import emit
from ids.detection.window import Cooldown, SlidingWindow
from ids.detection.tcpflags import is_syn_only

# thresholds come from config.yaml (section: port_scan)
_cfg = config.get("port_scan")
PORT_THRESHOLD = _cfg["threshold"]
TIME_WINDOW = timedelta(seconds=_cfg["window_seconds"])
ALERT_COOLDOWN = timedelta(seconds=_cfg["cooldown_seconds"])

# memory of detector, per source IP, the distinct TCP destination ports it hit
recent_ports = SlidingWindow(TIME_WINDOW)
cooldown = Cooldown(ALERT_COOLDOWN)


def reset():
    # Forget everything learned so far (called when a new monitoring session starts)
    recent_ports.clear()
    cooldown.clear()


def process_event(event):
    # early exit in case != TCP packet
    if event.protocol != "TCP":
        return

    # a connection attempt is a SYN without ACK; replies (SYN-ACK, RST, ...)
    # would make a busy server look like a scanner
    if not is_syn_only(event.flags):
        return

    # no source IP or no destination port = nothing to track
    if event.src_ip is None or event.dst_port is None:
        return

    src = event.src_ip
    now = event.timestamp

    recent_ports.add(src, now, event.dst_port)
    port_count = recent_ports.distinct(src)

    if port_count >= PORT_THRESHOLD and cooldown.allow(src, now):
        raise_alert(src, event.dst_ip, port_count)


def raise_alert(src_ip, dst_ip, port_count):
    emit("Port scan", "MEDIUM", src_ip,
         f"{port_count} distinct ports touched in the last "
         f"{int(TIME_WINDOW.total_seconds())}s",
         target=dst_ip,
         details={"distinct_ports": port_count,
                  "window_seconds": TIME_WINDOW.total_seconds()})


""" TESTED WITH COMMAND :
### sudo nmap -sS -Pn -p 1-1000 {TARGET_IP}
"""