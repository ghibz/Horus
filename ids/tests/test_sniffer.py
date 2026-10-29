
"""Run from the project root:  python -m unittest ids.tests.test_sniffer -v

Checks that the sniffer
  * isolates detectors from each other (one broken detector can't blind the rest)
  * wipes all detector state when a new monitoring session starts

No network, GUI or admin rights needed.
"""
import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from unittest import mock

from ids import alerts
from ids.capture import sniffer
from ids.capture.parser import PacketEvent
from ids.detection import arp_spoof

T0 = datetime(2026, 1, 1, 12, 0, 0)
SYN, ACK = 0x02, 0x10

# every alert raised during a test lands here
RAISED = []
alerts.subscribe(RAISED.append)


def event():
    return PacketEvent(timestamp=T0, protocol="TCP")


def boom(_event):
    raise RuntimeError("bug in detector")


def noop(_event):
    pass


# ------------------------------------------------------------------ isolation
class DetectorIsolationTests(unittest.TestCase):
    def setUp(self):
        sniffer.reset_error_tracking()

    def tearDown(self):
        sniffer.reset_error_tracking()

    def run_event(self, detectors, times=1):
        out = io.StringIO()
        with mock.patch.object(sniffer, "DETECTORS", detectors), redirect_stdout(out):
            for _ in range(times):
                sniffer.handle_packet_event(event())
        return out.getvalue()

    def test_every_registered_detector_receives_the_event(self):
        seen = []
        detectors = [("a", lambda e: seen.append("a"), noop),
                     ("b", lambda e: seen.append("b"), noop)]
        self.run_event(detectors)
        self.assertEqual(seen, ["a", "b"])

    def test_broken_detector_does_not_stop_the_ones_after_it(self):
        seen = []
        detectors = [("broken", boom, noop), ("healthy", lambda e: seen.append("ran"), noop)]
        self.run_event(detectors)
        self.assertEqual(seen, ["ran"])

    def test_broken_detector_does_not_stop_the_ones_before_it(self):
        seen = []
        detectors = [("healthy", lambda e: seen.append("ran"), noop), ("broken", boom, noop)]
        self.run_event(detectors)
        self.assertEqual(seen, ["ran"])

    def test_handle_packet_event_never_raises(self):
        self.run_event([("broken", boom, noop)])   # would raise here if not isolated

    def test_failures_are_counted_per_detector(self):
        self.run_event([("broken", boom, noop), ("healthy", noop, noop)], times=5)
        self.assertEqual(sniffer.stats["detector_errors"], {"broken": 5})

    def test_warning_is_rate_limited(self):
        output = self.run_event([("broken", boom, noop)], times=500)
        self.assertEqual(output.count("[WARN]"), 1)          # not 500 lines
        self.assertEqual(sniffer.stats["detector_errors"]["broken"], 500)

    def test_warning_comes_back_after_the_interval_with_a_count(self):
        clock = [1000.0]
        with mock.patch.object(sniffer.time, "monotonic", lambda: clock[0]):
            first = self.run_event([("broken", boom, noop)], times=3)
            clock[0] += sniffer.ERROR_PRINT_INTERVAL + 1
            second = self.run_event([("broken", boom, noop)], times=2)
        self.assertEqual(first.count("[WARN]"), 1)
        self.assertEqual(second.count("[WARN]"), 1)
        self.assertIn("failures since the last message", second)

    def test_each_detector_gets_its_own_warning(self):
        output = self.run_event([("one", boom, noop), ("two", boom, noop)], times=10)
        self.assertEqual(output.count("[WARN]"), 2)
        self.assertIn("'one'", output)
        self.assertIn("'two'", output)

    def test_real_detector_list_covers_all_seven_detectors(self):
        self.assertEqual(len(sniffer.DETECTORS), 7)
        names = [name for name, _process, _reset in sniffer.DETECTORS]
        self.assertEqual(len(set(names)), 7)


# ---------------------------------------------------------------------- reset
def tcp(i, dport=80, flags=SYN):
    return PacketEvent(timestamp=T0, protocol="TCP", src_ip="10.0.0.5",
                       dst_ip="10.0.0.1", dst_port=dport, flags=flags)


def udp(i, dport):
    return PacketEvent(timestamp=T0, protocol="UDP", src_ip="10.0.0.5",
                       dst_ip="10.0.0.1", dst_port=dport)


def icmp(i, icmp_type=8):
    return PacketEvent(timestamp=T0, protocol="ICMP", src_ip="10.0.0.5",
                       dst_ip="10.0.0.1", icmp_type=icmp_type)


def arp(ip, mac):
    return PacketEvent(timestamp=T0, protocol="ARP",
                       arp_sender_ip=ip, arp_sender_mac=mac)


# for each detector: the alert kind it raises, and events that make it fire
ATTACKS = {
    "Port scan":    lambda: [tcp(i, dport=1000 + i) for i in range(15)],
    "UDP Port scan": lambda: [udp(i, 2000 + i) for i in range(15)],
    "SYN flood":    lambda: [tcp(i) for i in range(50)],
    "Brute force":  lambda: [tcp(i, dport=22) for i in range(10)],
    "ICMP flood":   lambda: [icmp(i) for i in range(50)],
    "Unusual ICMP": lambda: [icmp(0, icmp_type=13)],
    "ARP spoof":    lambda: [arp("10.0.0.1", "aa:aa:aa:aa:aa:aa"),
                             arp("10.0.0.1", "bb:bb:bb:bb:bb:bb")],
}


def count(kind):
    return sum(1 for a in RAISED if a.kind == kind)


class ResetTests(unittest.TestCase):
    def setUp(self):
        sniffer.reset_detectors()
        RAISED.clear()

    def tearDown(self):
        sniffer.reset_detectors()

    def feed(self, events):
        with redirect_stdout(io.StringIO()):
            for e in events:
                sniffer.handle_packet_event(e)

    def test_every_detector_has_a_reset_function(self):
        for name, _process, reset in sniffer.DETECTORS:
            self.assertTrue(callable(reset), name)

    def test_every_detector_is_covered_by_the_attack_table(self):
        self.assertEqual(len(ATTACKS), len(sniffer.DETECTORS))

    def test_state_really_survives_without_a_reset(self):
        # sanity check for the test itself: the second identical attack is
        # swallowed by the cooldown, so the next test proves something
        for kind, attack in ATTACKS.items():
            with self.subTest(kind=kind):
                self.feed(attack())
                self.feed(attack())
                self.assertEqual(count(kind), 1)

    def test_reset_makes_every_detector_fire_again(self):
        # cooldowns and windows are wiped, so the same attack alerts again
        for kind, attack in ATTACKS.items():
            with self.subTest(kind=kind):
                RAISED.clear()
                sniffer.reset_detectors()
                self.feed(attack())
                self.assertEqual(count(kind), 1)
                sniffer.reset_detectors()
                self.feed(attack())
                self.assertEqual(count(kind), 2)

    def test_old_session_traffic_does_not_count_toward_the_new_one(self):
        # 14 distinct ports before the restart + 1 after must NOT add up to 15
        self.feed([tcp(i, dport=1000 + i) for i in range(14)])
        sniffer.reset_detectors()
        self.feed([tcp(0, dport=9999)])
        self.assertEqual(count("Port scan"), 0)

    def test_switching_networks_gives_no_false_arp_spoof(self):
        # network 1: the gateway 192.168.1.1 has MAC aa:..
        self.feed([arp("192.168.1.1", "aa:aa:aa:aa:aa:aa")])
        # Stop, change network, Start: another router now uses the same IP
        sniffer.reset_detectors()
        self.feed([arp("192.168.1.1", "bb:bb:bb:bb:bb:bb")])
        self.assertEqual(count("ARP spoof"), 0)
        self.assertEqual(arp_spoof.known_mappings["192.168.1.1"], "bb:bb:bb:bb:bb:bb")

    def test_arp_spoof_inside_one_session_is_still_detected(self):
        self.feed([arp("192.168.1.1", "aa:aa:aa:aa:aa:aa")])
        self.feed([arp("192.168.1.1", "bb:bb:bb:bb:bb:bb")])
        self.assertEqual(count("ARP spoof"), 1)

    def test_reset_also_clears_detector_failure_counters(self):
        sniffer.stats["detector_errors"]["port scan"] = 7
        sniffer.reset_detectors()
        self.assertEqual(sniffer.stats["detector_errors"], {})

    def test_one_failing_reset_does_not_skip_the_others(self):
        cleared = []
        detectors = [("broken", noop, boom),
                     ("healthy", noop, lambda: cleared.append("healthy"))]
        out = io.StringIO()
        with mock.patch.object(sniffer, "DETECTORS", detectors), redirect_stdout(out):
            sniffer.reset_detectors()
        self.assertEqual(cleared, ["healthy"])
        self.assertIn("Could not reset detector 'broken'", out.getvalue())


if __name__ == "__main__":
    unittest.main()