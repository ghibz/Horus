from scapy.all import sniff


def handle_packet(pkt):
    print(pkt.summary())


print("Currently listening for 10 packets.. generate traffic")
sniff(prn=handle_packet, count=50)

