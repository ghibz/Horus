from datetime import timedelta

from ids.alerts import emit
from ids.detection.window import Cooldown, SlidingWindow
from ids.detection.addr import format_endpoint

# parameters
SYN_THRESHOLD = 50
TIME_WINDOW = timedelta(seconds=5)
ALERT_COOLDOWN = timedelta(seconds=30)

# detector's memory: per TARGET (dst IP, dst port), the SYNs it received recently,
# remembering which source sent each one
recent_syns = SlidingWindow(TIME_WINDOW)
cooldown = Cooldown(ALERT_COOLDOWN)


def process_event(event):
    # way-out if Protocol isn't TCP or no SYN flags
    if event.protocol != "TCP":
        return
    if event.flags != "S":
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
        raise_alert(target[0], target[1], syn_count, recent_syns.values(target))


def raise_alert(dst_ip, dst_port, count, sources):
    window = int(TIME_WINDOW.total_seconds())
    if len(sources) == 1:
        source = next(iter(sources))
        detail = ""
    else:
        source = f"{len(sources)} sources"
        detail = f" from {len(sources)} different sources"

    emit("SYN flood", "HIGH", source,
         f"{count} SYNs to {format_endpoint(dst_ip, dst_port)} in the last {window}s{detail}")


""" TESTED WITH COMMAND :
### sudo hping3 -S -p {PORT} --flood {TARGET_IP}
"""