from collections import defaultdict  # special dictionary, auto-creates a default value
from datetime import datetime, timedelta

# 15 or more ports + 5-seconds windows = port scan
PORT_THRESHOLD = 15
TIME_WINDOW = timedelta(seconds=5)

# detector's memory
recent_activity = defaultdict(list)

last_alert_time = {}
ALERT_COOLDOWN = timedelta(seconds=30)


def process_event(event):
    # early exits, no TCP or SYN packets
    if event.protocol != "TCP":
        return
    if event.flags != "S":
        return

    # fields that function cares about
    src = event.src_ip
    now = event.timestamp

    # records the port and timestamp under the source IPs history
    recent_activity[src].append((event.dst_port, now))

    # aging out old data; list comprehension
    recent_activity[src] = [
        (port, ts) for (port, ts) in recent_activity[src]
        if now - ts <= TIME_WINDOW
    ]

    # converts the surviving ports of the age function into a set of just these numbers
    # (sets automatically drop duplicates)
    distinct_ports = set(port for port, ts in recent_activity[src])

    # decision point, if number of distinct ports is over threshold, raise alert
    if len(distinct_ports) >= PORT_THRESHOLD:
        last_time = last_alert_time.get(src)
        if last_time is None or now - last_time >= ALERT_COOLDOWN:
            raise_alert(src, distinct_ports)
            last_alert_time[src] = now


def raise_alert(src_ip, ports):
    print(f"[ALERT] Possible port scan detected from IP -> {src_ip} !"
          f"{len(ports)} distinct ports have been touched in the last {TIME_WINDOW.seconds}s")


### TESTED WITH COMMAND :
### sudo nmap -sS -Pn -p 1-1000 {TARGET_IP}
