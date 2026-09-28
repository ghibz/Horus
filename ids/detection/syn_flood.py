from collections import defaultdict
from datetime import timedelta
from ids.alerts import emit


# parameters
SYN_THRESHOLD = 50
TIME_WINDOW = timedelta(seconds=5)

# detector's memory, Source IP, Destination Port as KEYS
recent_syns = defaultdict(list)

# prevent Spam - parameters
last_time_alert = {}
ALERT_COOLDOWN = timedelta(seconds=30)


def process_event(event):
    # way-out if Protocol isn't TCP or no SYN flags
    if event.protocol != "TCP":
        return
    if event.flags != "S":
        return

    # both src_ip and dst_port as 1 key
    # this ensures that the same IP but different ports are diff entries
    key = (event.src_ip, event.dst_port)
    now = event.timestamp

    # timestamp of every SYN
    recent_syns[key].append(now)

    # age-out
    recent_syns[key] = [
        ts for ts in recent_syns[key]
        if now - ts <= TIME_WINDOW
    ]

    syn_count = len(recent_syns[key])

    if syn_count >= SYN_THRESHOLD:
        last_time = last_time_alert.get(key)
        if last_time is None or now - last_time >= ALERT_COOLDOWN:
            raise_alert(event.src_ip, event.dst_port, syn_count)
            last_time_alert[key] = now


def raise_alert(src_ip, dst_port, count):
    emit("SYN flood", "HIGH", src_ip,
         f"{count} SYNs to port {dst_port} in the last {int(TIME_WINDOW.total_seconds())}s")


### TESTED WITH COMMAND :
### sudo hping3 -S -p {PORT} --flood {TARGET_IP}