from datetime import timedelta

from ids import config
from ids.alerts import emit
from ids.detection.window import Cooldown, SlidingWindow

# thresholds come from config.yaml (section: brute_force)
_cfg = config.get("brute_force")
AUTH_PORTS = set(_cfg["ports"])      # default: SSH, FTP, Telnet, RDP
ATTEMPT_THRESHOLD = _cfg["threshold"]
TIME_WINDOW = timedelta(seconds=_cfg["window_seconds"])
ALERT_COOLDOWN = timedelta(seconds=_cfg["cooldown_seconds"])

recent_attempts = SlidingWindow(TIME_WINDOW)
cooldown = Cooldown(ALERT_COOLDOWN)


def process_event(event):
    # All 4 protocol are TCP based
    if event.protocol != "TCP":
        return
    # decision based only on the first SYN packet
    if event.flags != "S":
        return
    if event.dst_port not in AUTH_PORTS:
        return
    if event.src_ip is None:
        return

    key = (event.src_ip, event.dst_port)
    now = event.timestamp

    recent_attempts.add(key, now)
    attempt_count = recent_attempts.count(key)

    if attempt_count >= ATTEMPT_THRESHOLD and cooldown.allow(key, now):
        raise_alert(event.src_ip, event.dst_port, attempt_count)


def raise_alert(src_ip, dst_port, count):
    emit("Brute force", "HIGH", src_ip,
         f"{count} connection attempts made to port {dst_port} in the last "
         f"{int(TIME_WINDOW.total_seconds())}")


""" TESTED WITH COMMAND :
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{TARGET_IP}

Requires following setup:
1.ids/scripts/enable_ssh_test.ps1 -> enable SSH server and service

2.Conduct the test

3.ids/scripts/disable_ssh_test.ps1 -> disable SSH server and service
"""
