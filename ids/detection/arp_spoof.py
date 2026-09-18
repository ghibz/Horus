from datetime import timedelta

# known IP -> MAC mappings, built as we observe ARP
known_mappings = {}

# prevents alert spam from spoofing alerts
last_alert_time = {}
ALERT_COOLDOWN = timedelta(seconds=30)


def process_event(event):
    # early exit if protocol doesn't match
    if event.protocol != "ARP":
        return

    ip = event.arp_sender_ip
    mac = event.arp_sender_mac
    now = event.timestamp

    # ignore incomplete ARP events
    if ip is None or mac is None:
        return

    # retrieve the MAC of the IP entry
    known_mac = known_mappings.get(ip)

    # if the IP doesn't have a MAC entry (first time), insert the entry
    if known_mac is None:
        # if first time seeing IP - learn it
        known_mappings[ip] = mac
        return

    # actual detection; if the MAC is different from the IP -> MAC entry, raise alert
    if known_mac != mac:
        last_time = last_alert_time.get(ip)
        if last_time is None or now - last_time >= ALERT_COOLDOWN:
            raise_alert(ip, known_mac, mac)
            last_alert_time[ip] = now


def raise_alert(ip, old_mac, new_mac):
    print(f"[ALERT] Possible ARP Spoofing detected! IP {ip} was {old_mac}, "
          f"now claimed by {new_mac}")


### TO BE TESTED !!!