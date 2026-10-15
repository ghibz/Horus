from scapy.all import sniff


def handle_packet(pkt):
    print(pkt.summary())


if __name__ == "__main__":
    print("Currently listening for 50 packets.. generate traffic")
    sniff(prn=handle_packet, count=50)
