"""Run from the project root:  python -m unittest ids.tests.test_detectors -v

No network, GUI or admin rights needed: events are built by hand.
"""
import unittest
from datetime import datetime, timedelta

from ids import alerts
from ids.capture.parser import PacketEvent
from ids.detection import arp_spoof, bruteforce, portscan, syn_flood, udp_portscan
from ids.detection.window import Cooldown, SlidingWindow

T0 = datetime(2026, 1, 1, 12, 0, 0)

# every alert raised during a test lands here
RAISED = []
alerts.subscribe(RAISED.append)


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def tcp(seconds, src="10.0.0.5", dst="10.0.0.1", dport=80, flags="S"):
    return PacketEvent(timestamp=at(seconds), protocol="TCP", src_ip=src,
                       dst_ip=dst, dst_port=dport, flags=flags)


def udp(seconds, src="10.0.0.5", dst="10.0.0.1", dport=53):
    return PacketEvent(timestamp=at(seconds), protocol="UDP", src_ip=src,
                       dst_ip=dst, dst_port=dport)


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
        self.w.add("a", at(7), 3)            # first two are now older than 5s
        self.assertEqual(self.w.count("a"), 1)
        self.assertEqual(self.w.values("a"), {3})

    def test_idle_keys_are_removed(self):
        self.w.add("idle", at(0), 1)
        self.w.add("busy", at(1), 1)
        self.w.add("busy", at(10), 1)        # triggers the periodic sweep
        self.assertEqual(len(self.w), 1)
        self.assertEqual(self.w.count("idle"), 0)

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
        self.assertTrue(c.allow("y", at(10)))     # other keys are independent
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
        for port in range(1, 41):               # 1 port per second
            portscan.process_event(tcp(port, dport=port))
        self.assertEqual(RAISED, [])

    def test_ipv6_without_source_ip_is_ignored(self):
        for port in range(1, 41):
            portscan.process_event(tcp(port * 0.01, src=None, dport=port))
        self.assertEqual(RAISED, [])

    def test_only_pure_syn_counts(self):
        for port in range(1, 41):
            portscan.process_event(tcp(port * 0.01, dport=port, flags="SA"))
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
        for i in range(200):                    # e.g. a DNS client
            udp_portscan.process_event(udp(i * 0.01, dport=53))
        self.assertEqual(RAISED, [])

    def test_slow_scan_outside_window_is_quiet(self):
        for port in range(1, 41):               # 1 port per second
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

    def test_below_threshold_is_quiet(self):
        for i in range(30):
            syn_flood.process_event(tcp(i * 0.01))
        self.assertEqual(RAISED, [])

    def test_missing_addresses_are_ignored(self):
        for i in range(120):
            syn_flood.process_event(tcp(i * 0.01, dst=None))
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
        for i in range(30):                      # 1 every 2s, window is 10s
            bruteforce.process_event(tcp(i * 2, dport=22))
        self.assertEqual(RAISED, [])

    def test_only_pure_syn_counts(self):
        for i in range(30):
            bruteforce.process_event(tcp(i * 0.1, dport=22, flags="SA"))
        self.assertEqual(RAISED, [])

    def test_ports_are_counted_separately(self):
        for i in range(6):                       # 6 on SSH + 6 on FTP, neither hits 10
            bruteforce.process_event(tcp(i * 0.1, dport=22))
            bruteforce.process_event(tcp(i * 0.1, dport=21))
        self.assertEqual(RAISED, [])


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


if __name__ == "__main__":
    unittest.main()