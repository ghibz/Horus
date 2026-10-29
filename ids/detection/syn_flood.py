from datetime import timedelta

from ids import config
from ids.alerts import emit
from ids.detection.window import Cooldown, SlidingWindow
from ids.detection.addr import format_endpoint
from ids.detection.tcpflags import is_syn_only

# thresholds come from config.yaml (section: syn_flood)
_cfg = config.get("syn_flood")
SYN_THRESHOLD = _cfg["threshold"]
TIME_WINDOW = timedelta(seconds=_cfg["window_seconds"])
ALERT_COOLDOWN = timedelta(seconds=_cfg["cooldown_seconds"])

# how many of the busiest sources are written into an alert's details
TOP_SOURCES = 10

# detector's memory: per TARGET (dst IP, dst port), the SYNs it received recently,
# remembering which source sent each one
recent_syns = SlidingWindow(TIME_WINDOW)
cooldown = Cooldown(ALERT_COOLDOWN)


def reset():
    # Forget everything learned so far (called when a new monitoring session starts)
    recent_syns.clear()
    cooldown.clear()


def process_event(event):
    # way-out if Protocol isn't TCP or no SYN flags
    if event.protocol != "TCP":
        return
    if not is_syn_only(event.flags):
        return

    # no IPv4 addresses (e.g. IPv6 traffic): can't attribute it
    if event.src_ip is None or event.dst_ip is None or event.dst_port is None:
        return

    # keyed by the victim, not the attacker: a flood with spoofed random
    # sources still piles up on one (dst_ip, dst_port)
    target = (event.dst_ip, event.dst_port)
    now = event.timestamp

    recent_syns.add(target, now, event.src_ip)
    syn_count = recent_syns.count(target)

    if syn_count >= SYN_THRESHOLD and cooldown.allow(target, now):
        raise_alert(target[0], target[1], syn_count, recent_syns.values(target),
                    recent_syns.top(target, TOP_SOURCES))


def raise_alert(dst_ip, dst_port, count, sources, top_sources=()):
    window = int(TIME_WINDOW.total_seconds())
    if len(sources) == 1:
        source = next(iter(sources))
        detail = ""
    else:
        source = f"{len(sources)} sources"
        detail = f" from {len(sources)} different sources"

    emit("SYN flood", "HIGH", source,
         f"{count} SYNs to {format_endpoint(dst_ip, dst_port)} in the last {window}s{detail}",
         target=dst_ip, dst_port=dst_port,
         details={"syn_count": count, "source_count": len(sources),
                  "window_seconds": window,
                  # who is attacking: the busiest sources, most SYNs first
                  "top_sources": [{"ip": ip, "packets": n} for ip, n in top_sources]})


""" TESTED WITH COMMAND :
### sudo hping3 -S -p {PORT} --flood {TARGET_IP}
"""