"""Run from the project root:  python -m unittest ids.tests.test_parser -v"""
import unittest

from scapy.all import ICMP, IP, TCP, Ether, IPv6

from ids.capture.parser import parse_packet


def dissect(pkt):
    # re-parse from bytes so computed fields (IP length etc.) are filled in,
    # like they are on real captured packets
    return Ether(bytes(pkt))


class ParserTests(unittest.TestCase):
    def test_ipv4_tcp_syn(self):
        pkt = dissect(Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80, flags="S"))
        ev = parse_packet(pkt)
        self.assertEqual(ev.protocol, "TCP")
        self.assertEqual(ev.ip_version, 4)
        self.assertEqual(ev.src_ip, "10.0.0.5")
        self.assertEqual(ev.dst_port, 80)
        self.assertEqual(ev.flags, 0x02)   # raw int, SYN bit only

    def test_ecn_setup_syn_keeps_all_flag_bits(self):
        # "SEC" = SYN + ECE (0x40) + CWR (0x80): what macOS/iOS send, and what
        # hping3 -S -X -Y crafts. The raw value must survive parsing intact.
        pkt = dissect(Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80, flags="SEC"))
        ev = parse_packet(pkt)
        self.assertEqual(ev.flags, 0xC2)
        self.assertEqual(ev.flags & 0x12, 0x02)   # SYN set, ACK clear

    def test_syn_ack_has_ack_bit(self):
        pkt = dissect(Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=80, flags="SA"))
        ev = parse_packet(pkt)
        self.assertEqual(ev.flags, 0x12)

    def test_ipv6_tcp_syn_has_addresses(self):
        pkt = dissect(Ether() / IPv6(src="fe80::1", dst="fe80::2") / TCP(dport=22, flags="S"))
        ev = parse_packet(pkt)
        self.assertEqual(ev.protocol, "TCP")
        self.assertEqual(ev.ip_version, 6)
        self.assertEqual(ev.src_ip, "fe80::1")
        self.assertEqual(ev.dst_ip, "fe80::2")
        self.assertEqual(ev.dst_port, 22)

    def test_length_is_ip_packet_size_for_both_versions(self):
        v4 = parse_packet(dissect(Ether() / IP() / ICMP()))
        v6 = parse_packet(dissect(Ether() / IPv6() / TCP()))
        self.assertEqual(v4.length, 28)   # 20 IP header + 8 ICMP
        self.assertEqual(v6.length, 60)   # 40 IPv6 header + 20 TCP


if __name__ == "__main__":
    unittest.main()