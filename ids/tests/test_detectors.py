"""Run from the project root:  python -m unittest ids.tests.test_detectors -v

No network, GUI or admin rights needed: events are built by hand.
"""
import json
import unittest
from datetime import datetime, timedelta
from unittest import mock

from ids import alerts
from ids.capture import sniffer
from ids.capture.parser import PacketEvent
from ids.detection import (arp_spoof, bruteforce, icmp_flood, icmp_unusual, portscan,
                           syn_flood, udp_portscan)
from ids.detection.window import Cooldown, SlidingWindow

T0 = datetime(2026, 1, 1, 12, 0, 0)

# raw TCP flag bits (what PacketEvent.flags now holds)
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

# SYN set, ACK clear: all of these are connection attempts and must be counted,
# including the ECN-setup SYN (SEC) that macOS/iOS send and that crafted
# packets (hping3 -S -X -Y) use to dodge an exact "== S" match
SYN_VARIANTS = {
    "plain SYN": SYN,
    "ECN-setup SYN (SEC)": SYN | ECE | CWR,
    "SYN+ECE": SYN | ECE,
    "SYN+PSH+URG": SYN | PSH | URG,
    "SYN+FIN": SYN | FIN,
}

# these must never be counted as a connection attempt
NOT_SYN = {
    "SYN-ACK": SYN | ACK,
    "ECN-setup SYN-ACK": SYN | ACK | ECE,
    "ACK": ACK,
    "FIN": FIN,
    "RST": RST,
    "NULL": 0,
}

# every alert raised during a test lands here
RAISED = []
alerts.subscribe(RAISED.append)


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def tcp(seconds, src="10.0.0.5", dst="10.0.0.1", dport=80, flags=SYN):
    return PacketEvent(timestamp=at(seconds), protocol="TCP", src_ip=src,
                       dst_ip=dst, dst_port=dport, flags=flags)


def udp(seconds, src="10.0.0.5", dst="10.0.0.1", dport=53):
    return PacketEvent(timestamp=at(seconds), protocol="UDP", src_ip=src,
                       dst_ip=dst, dst_port=dport)


def icmp(seconds, src="10.0.0.5", dst="10.0.0.1", icmp_type=8):
    return PacketEvent(timestamp=at(seconds), protocol="ICMP", src_ip=src,
                       dst_ip=dst, icmp_type=icmp_type)


def arp(seconds, ip, mac):
    return PacketEvent(timestamp=at(seconds), protocol="ARP",
                       arp_sender_ip=ip, arp_sender_mac=mac)


class SlidingWindowTests(unittest.TestCase):
    def setUp(self):
        self.w = SlidingWindow(timedelta(seconds=5))

    def test_count_and_distinct(self):
        for i, port in enumerate([80, 80, 443]):
            self.w.add("a", at(i), port)
        self.assertEqual(self.w.count("a"), 3)
        self.assertEqual(self.w.distinct("a"), 2)
        self.assertEqual(self.w.values("a"), {80, 443})

    def test_old_entries_expire(self):
        self.w.add("a", at(0), 1)
        self.w.add("a", at(1), 2)
        self.w.add("a", at(7), 3)  # first two are now older than 5s
        self.assertEqual(self.w.count("a"), 1)
        self.assertEqual(self.w.values("a"), {3})

    def test_idle_keys_are_removed(self):
        self.w.add("idle", at(0), 1)
        self.w.add("busy", at(1), 1)
        self.w.add("busy", at(10), 1)  # triggers the periodic sweep
        self.assertEqual(len(self.w), 1)
        self.assertEqual(self.w.count("idle"), 0)

    def test_top_lists_the_most_frequent_values_busiest_first(self):
        for i, value in enumerate(["a", "b", "b", "c", "c", "c"]):
            self.w.add("k", at(i * 0.1), value)
        self.assertEqual(self.w.top("k", 2), [("c", 3), ("b", 2)])
        self.assertEqual(self.w.top("k"), [("c", 3), ("b", 2), ("a", 1)])

    def test_top_ties_keep_first_seen_order(self):
        for i, value in enumerate(["x", "y", "z"]):
            self.w.add("k", at(i * 0.1), value)
        self.assertEqual([v for v, _ in self.w.top("k")], ["x", "y", "z"])

    def test_top_of_unknown_key_is_empty(self):
        self.assertEqual(self.w.top("nothing"), [])

    def test_top_ignores_expired_events(self):
        self.w.add("k", at(0), "old")
        self.w.add("k", at(0.1), "old")
        self.w.add("k", at(8), "new")      # the two "old" ones left the 5s window
        self.assertEqual(self.w.top("k"), [("new", 1)])

    def test_key_cap_evicts_oldest(self):
        small = SlidingWindow(timedelta(seconds=5), max_keys=3)
        for i in range(5):
            small.add(f"k{i}", at(0), 1)
        self.assertEqual(len(small), 3)
        self.assertEqual(small.count("k0"), 0)
        self.assertEqual(small.count("k4"), 1)


class CooldownTests(unittest.TestCase):
    def test_blocks_then_allows_after_period(self):
        c = Cooldown(timedelta(seconds=30))
        self.assertTrue(c.allow("x", at(0)))
        self.assertFalse(c.allow("x", at(10)))
        self.assertTrue(c.allow("y", at(10)))  # other keys are independent
        self.assertTrue(c.allow("x", at(31)))

    def test_memory_is_bounded(self):
        c = Cooldown(timedelta(seconds=30), max_keys=10)
        for i in range(100):
            c.allow(i, at(0))
        self.assertLessEqual(len(c._last), 10)


class PortScanTests(unittest.TestCase):
    def setUp(self):
        portscan.recent_ports.clear()
        portscan.cooldown.clear()
        RAISED.clear()

    def test_scan_raises_exactly_one_alert(self):
        for port in range(1, 41):
            portscan.process_event(tcp(port * 0.01, dport=port))
        self.assertEqual(len(RAISED), 1)
        self.assertEqual(RAISED[0].kind, "Port scan")
        self.assertEqual(RAISED[0].source, "10.0.0.5")

    def test_scan_alert_names_the_target(self):
        for port in range(1, 41):
            portscan.process_event(tcp(port * 0.01, dport=port))
        self.assertEqual(RAISED[0].target, "10.0.0.1")

    def test_below_threshold_is_quiet(self):
        for port in range(1, 11):
            portscan.process_event(tcp(port * 0.01, dport=port))
        self.assertEqual(RAISED, [])

    def test_slow_scan_outside_window_is_quiet(self):
        for port in range(1, 41):  # 1 port per second
            portscan.process_event(tcp(port, dport=port))
        self.assertEqual(RAISED, [])

    def test_ipv6_without_source_ip_is_ignored(self):
        for port in range(1, 41):
            portscan.process_event(tcp(port * 0.01, src=None, dport=port))
        self.assertEqual(RAISED, [])

    def test_only_pure_syn_counts(self):
        for port in range(1, 41):
            portscan.process_event(tcp(port * 0.01, dport=port, flags=SYN | ACK))
        self.assertEqual(RAISED, [])

    def test_syn_with_extra_flags_still_counts(self):
        for name, flags in SYN_VARIANTS.items():
            with self.subTest(flags=name):
                portscan.recent_ports.clear()
                portscan.cooldown.clear()
                RAISED.clear()
                for port in range(1, 41):
                    portscan.process_event(tcp(port * 0.01, dport=port, flags=flags))
                self.assertEqual(len(RAISED), 1)
                self.assertEqual(RAISED[0].kind, "Port scan")

    def test_non_syn_packets_are_ignored(self):
        for name, flags in NOT_SYN.items():
            with self.subTest(flags=name):
                portscan.recent_ports.clear()
                portscan.cooldown.clear()
                RAISED.clear()
                for port in range(1, 41):
                    portscan.process_event(tcp(port * 0.01, dport=port, flags=flags))
                self.assertEqual(RAISED, [])

    def test_missing_flags_are_ignored(self):
        for port in range(1, 41):
            portscan.process_event(tcp(port * 0.01, dport=port, flags=None))
        self.assertEqual(RAISED, [])

    def test_ipv6_scanner_is_detected(self):
        for port in range(1, 41):
            portscan.process_event(
                tcp(port * 0.01, src="2001:db8::5", dst="2001:db8::1", dport=port))
        self.assertEqual(len(RAISED), 1)
        self.assertEqual(RAISED[0].source, "2001:db8::5")


class UdpScanTests(unittest.TestCase):
    def setUp(self):
        udp_portscan.recent_ports.clear()
        udp_portscan.cooldown.clear()
        RAISED.clear()

    def test_scan_raises_exactly_one_alert(self):
        for port in range(1, 41):
            udp_portscan.process_event(udp(port * 0.01, dport=port))
        self.assertEqual(len(RAISED), 1)
        self.assertEqual(RAISED[0].kind, "UDP Port scan")
        self.assertEqual(RAISED[0].source, "10.0.0.5")
        self.assertEqual(RAISED[0].target, "10.0.0.1")

    def test_below_threshold_is_quiet(self):
        for port in range(1, 11):
            udp_portscan.process_event(udp(port * 0.01, dport=port))
        self.assertEqual(RAISED, [])

    def test_same_port_many_times_is_not_a_scan(self):
        for i in range(200):  # e.g. a DNS client
            udp_portscan.process_event(udp(i * 0.01, dport=53))
        self.assertEqual(RAISED, [])

    def test_slow_scan_outside_window_is_quiet(self):
        for port in range(1, 41):  # 1 port per second
            udp_portscan.process_event(udp(port, dport=port))
        self.assertEqual(RAISED, [])

    def test_tcp_is_ignored(self):
        for port in range(1, 41):
            udp_portscan.process_event(tcp(port * 0.01, dport=port))
        self.assertEqual(RAISED, [])

    def test_missing_source_is_ignored(self):
        for port in range(1, 41):
            udp_portscan.process_event(udp(port * 0.01, src=None, dport=port))
        self.assertEqual(RAISED, [])


class SynFloodTests(unittest.TestCase):
    def setUp(self):
        syn_flood.recent_syns.clear()
        syn_flood.cooldown.clear()
        RAISED.clear()

    def test_single_source_flood(self):
        for i in range(120):
            syn_flood.process_event(tcp(i * 0.01))
        self.assertEqual(len(RAISED), 1)
        self.assertEqual(RAISED[0].kind, "SYN flood")
        self.assertEqual(RAISED[0].source, "10.0.0.5")

    def test_spoofed_sources_are_still_caught(self):
        for i in range(120):
            syn_flood.process_event(tcp(i * 0.01, src=f"172.16.{i // 250}.{i % 250}"))
        self.assertEqual(len(RAISED), 1)
        self.assertIn("sources", RAISED[0].source)

    def test_alert_lists_the_attacker_ips_busiest_first(self):
        # 30 + 15 + 5 = 50 packets: the alert fires on the 50th
        senders = [("10.0.0.7", 30), ("10.0.0.8", 15), ("10.0.0.9", 5)]
        i = 0
        for src, n in senders:
            for _ in range(n):
                syn_flood.process_event(tcp(i * 0.01, src=src))
                i += 1
        self.assertEqual(len(RAISED), 1)
        details = RAISED[0].details
        self.assertEqual(details["syn_count"], 50)
        self.assertEqual(details["source_count"], 3)
        self.assertEqual(details["top_sources"],
                         [{"ip": "10.0.0.7", "packets": 30},
                          {"ip": "10.0.0.8", "packets": 15},
                          {"ip": "10.0.0.9", "packets": 5}])

    def test_single_attacker_is_listed_too(self):
        for i in range(60):
            syn_flood.process_event(tcp(i * 0.01))
        self.assertEqual(RAISED[0].details["top_sources"],
                         [{"ip": "10.0.0.5", "packets": 50}])

    def test_only_the_top_ten_sources_are_stored(self):
        # 50 different (spoofed) sources, one packet each
        for i in range(60):
            syn_flood.process_event(tcp(i * 0.01, src=f"172.16.0.{i}"))
        details = RAISED[0].details
        self.assertEqual(details["source_count"], 50)
        self.assertEqual(len(details["top_sources"]), syn_flood.TOP_SOURCES)
        self.assertEqual(len(details["top_sources"]), 10)

    def test_a_heavy_source_is_not_lost_among_many_small_ones(self):
        # 40 packets from one attacker hidden among 10 one-packet sources
        packets = [("203.0.113.9", 40)] + [(f"172.16.0.{i}", 1) for i in range(10)]
        i = 0
        for src, n in packets:
            for _ in range(n):
                syn_flood.process_event(tcp(i * 0.01, src=src))
                i += 1
        top = RAISED[0].details["top_sources"]
        self.assertEqual(top[0], {"ip": "203.0.113.9", "packets": 40})

    def test_ipv6_sources_are_listed(self):
        for i in range(60):
            syn_flood.process_event(tcp(i * 0.01, src="2001:db8::5"))
        self.assertEqual(RAISED[0].details["top_sources"][0]["ip"], "2001:db8::5")

    def test_details_are_json_serializable(self):
        for i in range(60):
            syn_flood.process_event(tcp(i * 0.01, src=f"172.16.0.{i % 20}"))
        json.dumps(RAISED[0].details)    # would raise if not

    def test_below_threshold_is_quiet(self):
        for i in range(30):
            syn_flood.process_event(tcp(i * 0.01))
        self.assertEqual(RAISED, [])

    def test_missing_addresses_are_ignored(self):
        for i in range(120):
            syn_flood.process_event(tcp(i * 0.01, dst=None))
        self.assertEqual(RAISED, [])

    def test_syn_with_extra_flags_still_counts(self):
        for name, flags in SYN_VARIANTS.items():
            with self.subTest(flags=name):
                syn_flood.recent_syns.clear()
                syn_flood.cooldown.clear()
                RAISED.clear()
                for i in range(120):
                    syn_flood.process_event(tcp(i * 0.01, flags=flags))
                self.assertEqual(len(RAISED), 1)
                self.assertEqual(RAISED[0].kind, "SYN flood")

    def test_non_syn_packets_are_ignored(self):
        for name, flags in NOT_SYN.items():
            with self.subTest(flags=name):
                syn_flood.recent_syns.clear()
                syn_flood.cooldown.clear()
                RAISED.clear()
                for i in range(120):
                    syn_flood.process_event(tcp(i * 0.01, flags=flags))
                self.assertEqual(RAISED, [])

    def test_missing_flags_are_ignored(self):
        for i in range(120):
            syn_flood.process_event(tcp(i * 0.01, flags=None))
        self.assertEqual(RAISED, [])


class BruteForceTests(unittest.TestCase):
    def setUp(self):
        bruteforce.recent_attempts.clear()
        bruteforce.cooldown.clear()
        RAISED.clear()

    def test_attempts_on_ssh_raise_exactly_one_alert(self):
        for i in range(30):
            bruteforce.process_event(tcp(i * 0.1, dport=22))
        self.assertEqual(len(RAISED), 1)
        alert = RAISED[0]
        self.assertEqual(alert.kind, "Brute force")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.source, "10.0.0.5")
        self.assertEqual((alert.target, alert.dst_port), ("10.0.0.1", 22))

    def test_below_threshold_is_quiet(self):
        for i in range(5):
            bruteforce.process_event(tcp(i * 0.1, dport=22))
        self.assertEqual(RAISED, [])

    def test_non_login_port_is_ignored(self):
        for i in range(30):
            bruteforce.process_event(tcp(i * 0.1, dport=8080))
        self.assertEqual(RAISED, [])

    def test_slow_attempts_outside_window_are_quiet(self):
        for i in range(30):  # 1 every 2s, window is 10s
            bruteforce.process_event(tcp(i * 2, dport=22))
        self.assertEqual(RAISED, [])

    def test_only_pure_syn_counts(self):
        for i in range(30):
            bruteforce.process_event(tcp(i * 0.1, dport=22, flags=SYN | ACK))
        self.assertEqual(RAISED, [])

    def test_syn_with_extra_flags_still_counts(self):
        for name, flags in SYN_VARIANTS.items():
            with self.subTest(flags=name):
                bruteforce.recent_attempts.clear()
                bruteforce.cooldown.clear()
                RAISED.clear()
                for i in range(30):
                    bruteforce.process_event(tcp(i * 0.1, dport=22, flags=flags))
                self.assertEqual(len(RAISED), 1)
                self.assertEqual(RAISED[0].kind, "Brute force")

    def test_non_syn_packets_are_ignored(self):
        for name, flags in NOT_SYN.items():
            with self.subTest(flags=name):
                bruteforce.recent_attempts.clear()
                bruteforce.cooldown.clear()
                RAISED.clear()
                for i in range(30):
                    bruteforce.process_event(tcp(i * 0.1, dport=22, flags=flags))
                self.assertEqual(RAISED, [])

    def test_missing_flags_are_ignored(self):
        for i in range(30):
            bruteforce.process_event(tcp(i * 0.1, dport=22, flags=None))
        self.assertEqual(RAISED, [])

    def test_ports_are_counted_separately(self):
        for i in range(6):  # 6 on SSH + 6 on FTP, neither hits 10
            bruteforce.process_event(tcp(i * 0.1, dport=22))
            bruteforce.process_event(tcp(i * 0.1, dport=21))
        self.assertEqual(RAISED, [])


class IcmpFloodTests(unittest.TestCase):
    def setUp(self):
        icmp_flood.recent_pings.clear()
        icmp_flood.cooldown.clear()
        RAISED.clear()

    def test_single_source_flood(self):
        for i in range(120):
            icmp_flood.process_event(icmp(i * 0.01))
        self.assertEqual(len(RAISED), 1)
        alert = RAISED[0]
        self.assertEqual(alert.kind, "ICMP flood")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.source, "10.0.0.5")
        self.assertEqual(alert.target, "10.0.0.1")

    def test_spoofed_sources_are_still_caught(self):
        for i in range(120):
            icmp_flood.process_event(icmp(i * 0.01, src=f"172.16.{i // 250}.{i % 250}"))
        self.assertEqual(len(RAISED), 1)
        self.assertIn("sources", RAISED[0].source)

    def test_alert_lists_the_attacker_ips_busiest_first(self):
        # 30 + 15 + 5 = 50 packets: the alert fires on the 50th
        senders = [("10.0.0.7", 30), ("10.0.0.8", 15), ("10.0.0.9", 5)]
        i = 0
        for src, n in senders:
            for _ in range(n):
                icmp_flood.process_event(icmp(i * 0.01, src=src))
                i += 1
        self.assertEqual(len(RAISED), 1)
        details = RAISED[0].details
        self.assertEqual(details["ping_count"], 50)
        self.assertEqual(details["source_count"], 3)
        self.assertEqual(details["top_sources"],
                         [{"ip": "10.0.0.7", "packets": 30},
                          {"ip": "10.0.0.8", "packets": 15},
                          {"ip": "10.0.0.9", "packets": 5}])

    def test_single_attacker_is_listed_too(self):
        for i in range(60):
            icmp_flood.process_event(icmp(i * 0.01))
        self.assertEqual(RAISED[0].details["top_sources"],
                         [{"ip": "10.0.0.5", "packets": 50}])

    def test_only_the_top_ten_sources_are_stored(self):
        # 50 different (spoofed) sources, one packet each
        for i in range(60):
            icmp_flood.process_event(icmp(i * 0.01, src=f"172.16.0.{i}"))
        details = RAISED[0].details
        self.assertEqual(details["source_count"], 50)
        self.assertEqual(len(details["top_sources"]), icmp_flood.TOP_SOURCES)
        self.assertEqual(len(details["top_sources"]), 10)

    def test_a_heavy_source_is_not_lost_among_many_small_ones(self):
        # 40 packets from one attacker hidden among 10 one-packet sources
        packets = [("203.0.113.9", 40)] + [(f"172.16.0.{i}", 1) for i in range(10)]
        i = 0
        for src, n in packets:
            for _ in range(n):
                icmp_flood.process_event(icmp(i * 0.01, src=src))
                i += 1
        top = RAISED[0].details["top_sources"]
        self.assertEqual(top[0], {"ip": "203.0.113.9", "packets": 40})

    def test_ipv6_sources_are_listed(self):
        for i in range(60):
            icmp_flood.process_event(icmp(i * 0.01, src="2001:db8::5"))
        self.assertEqual(RAISED[0].details["top_sources"][0]["ip"], "2001:db8::5")

    def test_details_are_json_serializable(self):
        for i in range(60):
            icmp_flood.process_event(icmp(i * 0.01, src=f"172.16.0.{i % 20}"))
        json.dumps(RAISED[0].details)    # would raise if not

    def test_below_threshold_is_quiet(self):
        for i in range(30):
            icmp_flood.process_event(icmp(i * 0.01))
        self.assertEqual(RAISED, [])

    def test_slow_pings_outside_window_are_quiet(self):
        for i in range(120):  # 1 ping per second, window is 5s
            icmp_flood.process_event(icmp(i))
        self.assertEqual(RAISED, [])

    def test_echo_replies_are_not_counted(self):
        for i in range(120):  # type 0 = echo reply
            icmp_flood.process_event(icmp(i * 0.01, icmp_type=0))
        self.assertEqual(RAISED, [])

    def test_other_protocols_are_ignored(self):
        for i in range(120):
            icmp_flood.process_event(tcp(i * 0.01))
        self.assertEqual(RAISED, [])

    def test_missing_addresses_are_ignored(self):
        for i in range(120):
            icmp_flood.process_event(icmp(i * 0.01, dst=None))
        self.assertEqual(RAISED, [])

    def test_targets_are_counted_separately(self):
        # 30 pings to each of two hosts: neither reaches 50 on its own
        for i in range(30):
            icmp_flood.process_event(icmp(i * 0.01, dst="10.0.0.1"))
            icmp_flood.process_event(icmp(i * 0.01, dst="10.0.0.2"))
        self.assertEqual(RAISED, [])


class IcmpUnusualTests(unittest.TestCase):
    def setUp(self):
        icmp_unusual.cooldown.clear()
        RAISED.clear()

    def test_each_unusual_type_raises_a_low_alert(self):
        names = {13: "timestamp request", 15: "information request",
                 17: "address mask request"}
        for icmp_type, name in names.items():
            with self.subTest(icmp_type=icmp_type):
                icmp_unusual.cooldown.clear()
                RAISED.clear()
                icmp_unusual.process_event(icmp(0, icmp_type=icmp_type))
                self.assertEqual(len(RAISED), 1)
                alert = RAISED[0]
                self.assertEqual(alert.kind, "Unusual ICMP")
                self.assertEqual(alert.severity, "LOW")
                self.assertEqual(alert.source, "10.0.0.5")
                self.assertEqual(alert.target, "10.0.0.1")
                self.assertIn(name, alert.message)
                self.assertEqual(alert.details["icmp_type"], icmp_type)

    def test_normal_ping_is_ignored(self):
        icmp_unusual.process_event(icmp(0, icmp_type=8))
        self.assertEqual(RAISED, [])

    def test_replies_are_ignored(self):
        # 14, 16, 18 are the replies; our own answers must not alert about ourselves
        for icmp_type in (0, 14, 16, 18):
            icmp_unusual.process_event(icmp(0, icmp_type=icmp_type))
        self.assertEqual(RAISED, [])

    def test_repeats_within_cooldown_raise_one_alert(self):
        for seconds in (0, 1, 2, 30):
            icmp_unusual.process_event(icmp(seconds, icmp_type=13))
        self.assertEqual(len(RAISED), 1)

    def test_alerts_again_after_cooldown(self):
        icmp_unusual.process_event(icmp(0, icmp_type=13))
        icmp_unusual.process_event(icmp(61, icmp_type=13))
        self.assertEqual(len(RAISED), 2)

    def test_different_types_are_tracked_separately(self):
        icmp_unusual.process_event(icmp(0, icmp_type=13))
        icmp_unusual.process_event(icmp(1, icmp_type=17))
        self.assertEqual(len(RAISED), 2)

    def test_different_sources_are_tracked_separately(self):
        icmp_unusual.process_event(icmp(0, src="10.0.0.5", icmp_type=13))
        icmp_unusual.process_event(icmp(1, src="10.0.0.6", icmp_type=13))
        self.assertEqual(len(RAISED), 2)

    def test_missing_addresses_are_ignored(self):
        icmp_unusual.process_event(icmp(0, src=None, icmp_type=13))
        icmp_unusual.process_event(icmp(1, dst=None, icmp_type=13))
        self.assertEqual(RAISED, [])

    def test_other_protocols_are_ignored(self):
        icmp_unusual.process_event(tcp(0))
        self.assertEqual(RAISED, [])


class SnifferWiringTests(unittest.TestCase):
    """Events handed to the sniffer must actually reach the detectors."""

    def test_icmp_flood_is_registered_in_the_sniffer(self):
        icmp_flood.recent_pings.clear()
        icmp_flood.cooldown.clear()
        RAISED.clear()
        for i in range(120):
            sniffer.handle_packet_event(icmp(i * 0.01))
        self.assertEqual([a.kind for a in RAISED], ["ICMP flood"])

    def test_icmp_unusual_is_registered_in_the_sniffer(self):
        icmp_unusual.cooldown.clear()
        RAISED.clear()
        sniffer.handle_packet_event(icmp(0, icmp_type=13))
        self.assertEqual([a.kind for a in RAISED], ["Unusual ICMP"])


class ArpSpoofTests(unittest.TestCase):
    def setUp(self):
        arp_spoof.known_mappings.clear()
        arp_spoof.cooldown.clear()
        RAISED.clear()

    def test_mac_change_alerts_once_per_cooldown(self):
        arp_spoof.process_event(arp(0, "192.168.1.1", "aa:aa:aa:aa:aa:aa"))
        arp_spoof.process_event(arp(1, "192.168.1.1", "bb:bb:bb:bb:bb:bb"))
        arp_spoof.process_event(arp(2, "192.168.1.1", "bb:bb:bb:bb:bb:bb"))
        self.assertEqual(len(RAISED), 1)
        self.assertEqual(RAISED[0].kind, "ARP spoof")

    def test_same_mapping_is_quiet(self):
        for i in range(5):
            arp_spoof.process_event(arp(i, "192.168.1.1", "aa:aa:aa:aa:aa:aa"))
        self.assertEqual(RAISED, [])

    def test_arp_probes_from_0_0_0_0_are_ignored(self):
        arp_spoof.process_event(arp(0, "0.0.0.0", "aa:aa:aa:aa:aa:aa"))
        arp_spoof.process_event(arp(1, "0.0.0.0", "bb:bb:bb:bb:bb:bb"))
        arp_spoof.process_event(arp(2, "0.0.0.0", "cc:cc:cc:cc:cc:cc"))
        self.assertEqual(RAISED, [])

    # ---- the IP -> MAC table is bounded (a flood of fake IPs can't eat RAM) ----
    @staticmethod
    def fake_ip(n):
        return f"10.{n // 65536}.{(n // 256) % 256}.{n % 256}"

    def flood(self, count, start=0):
        # `count` ARP packets, each from a different IP
        for n in range(start, start + count):
            arp_spoof.process_event(arp(n, self.fake_ip(n), "aa:aa:aa:aa:aa:aa"))

    def test_table_never_grows_past_the_cap(self):
        with mock.patch.object(arp_spoof, "MAX_MAPPINGS", 100):
            self.flood(1000)
        self.assertEqual(len(arp_spoof.known_mappings), 100)

    def test_real_sized_flood_stays_at_the_real_cap(self):
        # the exact scenario from the audit: 100,000 fake IPs
        self.flood(100_000)
        self.assertEqual(len(arp_spoof.known_mappings), arp_spoof.MAX_MAPPINGS)

    def test_idlest_entries_are_dropped_first(self):
        with mock.patch.object(arp_spoof, "MAX_MAPPINGS", 100):
            self.flood(150)
        self.assertNotIn(self.fake_ip(0), arp_spoof.known_mappings)
        self.assertNotIn(self.fake_ip(49), arp_spoof.known_mappings)
        self.assertIn(self.fake_ip(50), arp_spoof.known_mappings)
        self.assertIn(self.fake_ip(149), arp_spoof.known_mappings)

    def test_busy_host_survives_a_flood_and_is_still_protected(self):
        gateway, idle = "192.168.1.1", "192.168.1.77"
        with mock.patch.object(arp_spoof, "MAX_MAPPINGS", 100):
            arp_spoof.process_event(arp(0, gateway, "aa:aa:aa:aa:aa:aa"))
            arp_spoof.process_event(arp(0, idle, "cc:cc:cc:cc:cc:cc"))
            for n in range(1, 501):
                self.flood(1, start=n)
                self.assertIn(gateway, arp_spoof.known_mappings)   # never forgotten, not even briefly
                if n % 10 == 0:    # the gateway keeps talking, the other host doesn't
                    arp_spoof.process_event(arp(n, gateway, "aa:aa:aa:aa:aa:aa"))
            self.assertNotIn(idle, arp_spoof.known_mappings)
            # ...and a spoof of the busy host is still caught after all that churn
            arp_spoof.process_event(arp(600, gateway, "bb:bb:bb:bb:bb:bb"))
        self.assertEqual([a.kind for a in RAISED], ["ARP spoof"])

    def test_a_spoof_attempt_counts_as_activity_for_that_entry(self):
        # the mismatching packet must refresh the entry, otherwise an attacker
        # could get the real mapping pushed out just by being noisy
        gateway = "192.168.1.1"
        with mock.patch.object(arp_spoof, "MAX_MAPPINGS", 100):
            arp_spoof.process_event(arp(0, gateway, "aa:aa:aa:aa:aa:aa"))
            self.flood(98, start=1)
            arp_spoof.process_event(arp(200, gateway, "bb:bb:bb:bb:bb:bb"))   # spoof
            self.flood(50, start=1000)
        self.assertEqual(arp_spoof.known_mappings[gateway], "aa:aa:aa:aa:aa:aa")

    def test_host_that_was_pushed_out_is_simply_learned_again(self):
        # known trade-off of a bounded table: an idle host that was forgotten is
        # treated as new, so its next packet is learned rather than alerted on
        with mock.patch.object(arp_spoof, "MAX_MAPPINGS", 10):
            arp_spoof.process_event(arp(0, "192.168.1.5", "aa:aa:aa:aa:aa:aa"))
            self.flood(20, start=1000)
            arp_spoof.process_event(arp(50, "192.168.1.5", "bb:bb:bb:bb:bb:bb"))
        self.assertEqual(RAISED, [])
        self.assertEqual(len(arp_spoof.known_mappings), 10)


if __name__ == "__main__":
    unittest.main()