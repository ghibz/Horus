from datetime import timedelta

from ids import config
from ids.alerts import emit
from ids.detection.window import Cooldown

# settings come from config.yaml (section: icmp_unusual)
ALERT_COOLDOWN = timedelta(seconds=config.get("icmp_unusual")["cooldown_seconds"])

# ICMP request types that are rarely legitimate today. Only requests are listed,
# not the replies (14, 16, 18): Horus also sees this machine's own answers, and
# those must not raise an alert about ourselves.
UNUSUAL_TYPES = {
    13: "timestamp request",
    15: "information request",
    17: "address mask request",
}

# one alert per (source, ICMP type) per cooldown period
cooldown = Cooldown(ALERT_COOLDOWN)


def reset():
    # Forget everything learned so far (called when a new monitoring session starts)
    cooldown.clear()


def process_event(event):
    if event.protocol != "ICMP":
        return

    request_name = UNUSUAL_TYPES.get(event.icmp_type)
    if request_name is None:
        return

    if event.src_ip is None or event.dst_ip is None:
        return

    # no threshold: a single packet of this type is the signal
    if cooldown.allow((event.src_ip, event.icmp_type), event.timestamp):
        raise_alert(event.src_ip, event.dst_ip, event.icmp_type, request_name)


def raise_alert(src_ip, dst_ip, icmp_type, request_name):
    emit("Unusual ICMP", "LOW", src_ip,
         f"ICMP {request_name} (type {icmp_type}) sent to {dst_ip}",
         target=dst_ip,
         details={"icmp_type": icmp_type, "request": request_name})


""" TESTED WITH COMMAND :
### sudo hping3 --icmp --icmptype 13 -c 3 {TARGET_IP}
### sudo hping3 --icmp --icmptype 17 -c 3 {TARGET_IP}
"""