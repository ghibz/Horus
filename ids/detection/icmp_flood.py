from datetime import timedelta

from ids import config
from ids.alerts import emit
from ids.detection.window import Cooldown, SlidingWindow

# thresholds come from config.yaml (section: icmp_flood)
_cfg = config.get("icmp_flood")
ICMP_THRESHOLD = _cfg["threshold"]
TIME_WINDOW = timedelta(seconds=_cfg["window_seconds"])
ALERT_COOLDOWN = timedelta(seconds=_cfg["cooldown_seconds"])

# how many of the busiest sources are written into an alert's details
TOP_SOURCES = 10

ECHO_REQUEST = 8   # ICMP type 8 = ping request (type 0 = reply)

# detector's memory: per TARGET IP, the echo requests it received recently,
# remembering which source sent each one
recent_pings = SlidingWindow(TIME_WINDOW)
cooldown = Cooldown(ALERT_COOLDOWN)


def reset():
    # Forget everything learned so far (called when a new monitoring session starts)
    recent_pings.clear()
    cooldown.clear()


def process_event(event):
    # only ICMP echo requests count; replies would inflate the numbers
    if event.protocol != "ICMP":
        return
    if event.icmp_type != ECHO_REQUEST:
        return
    if event.src_ip is None or event.dst_ip is None:
        return

    # keyed by the victim, like the SYN flood detector
    target = event.dst_ip
    now = event.timestamp

    recent_pings.add(target, now, event.src_ip)
    ping_count = recent_pings.count(target)

    if ping_count >= ICMP_THRESHOLD and cooldown.allow(target, now):
        raise_alert(target, ping_count, recent_pings.values(target),
                    recent_pings.top(target, TOP_SOURCES))


def raise_alert(dst_ip, count, sources, top_sources=()):
    window = int(TIME_WINDOW.total_seconds())
    if len(sources) == 1:
        source = next(iter(sources))
        detail = ""
    else:
        source = f"{len(sources)} sources"
        detail = f" from {len(sources)} different sources"

    emit("ICMP flood", "HIGH", source,
         f"{count} ping requests to {dst_ip} in the last {window}s{detail}",
         target=dst_ip,
         details={"ping_count": count, "source_count": len(sources),
                  "window_seconds": window,
                  # who is attacking: the busiest sources, most pings first
                  "top_sources": [{"ip": ip, "packets": n} for ip, n in top_sources]})


""" TESTED WITH COMMAND :
### sudo hping3 --icmp --flood {TARGET_IP}
"""