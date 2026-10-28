"""Run from the project root:  python -m unittest ids.tests.test_sniffer -v

Checks that the sniffer isolates detectors from each other.
No network, GUI or admin rights needed.
"""
import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from unittest import mock

from ids.capture import sniffer
from ids.capture.parser import PacketEvent


def event():
    return PacketEvent(timestamp=datetime(2026, 1, 1, 12, 0, 0), protocol="TCP")


def boom(_event):
    raise RuntimeError("bug in detector")


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
        detectors = [("a", lambda e: seen.append("a")), ("b", lambda e: seen.append("b"))]
        self.run_event(detectors)
        self.assertEqual(seen, ["a", "b"])

    def test_broken_detector_does_not_stop_the_ones_after_it(self):
        seen = []
        detectors = [("broken", boom), ("healthy", lambda e: seen.append("ran"))]
        self.run_event(detectors)
        self.assertEqual(seen, ["ran"])

    def test_broken_detector_does_not_stop_the_ones_before_it(self):
        seen = []
        detectors = [("healthy", lambda e: seen.append("ran")), ("broken", boom)]
        self.run_event(detectors)
        self.assertEqual(seen, ["ran"])

    def test_handle_packet_event_never_raises(self):
        self.run_event([("broken", boom)])   # would raise here if not isolated

    def test_failures_are_counted_per_detector(self):
        self.run_event([("broken", boom), ("healthy", lambda e: None)], times=5)
        self.assertEqual(sniffer.stats["detector_errors"], {"broken": 5})

    def test_warning_is_rate_limited(self):
        output = self.run_event([("broken", boom)], times=500)
        self.assertEqual(output.count("[WARN]"), 1)          # not 500 lines
        self.assertEqual(sniffer.stats["detector_errors"]["broken"], 500)

    def test_warning_comes_back_after_the_interval_with_a_count(self):
        clock = [1000.0]
        with mock.patch.object(sniffer.time, "monotonic", lambda: clock[0]):
            first = self.run_event([("broken", boom)], times=3)
            clock[0] += sniffer.ERROR_PRINT_INTERVAL + 1
            second = self.run_event([("broken", boom)], times=2)
        self.assertEqual(first.count("[WARN]"), 1)
        self.assertEqual(second.count("[WARN]"), 1)
        self.assertIn("failures since the last message", second)

    def test_each_detector_gets_its_own_warning(self):
        output = self.run_event([("one", boom), ("two", boom)], times=10)
        self.assertEqual(output.count("[WARN]"), 2)
        self.assertIn("'one'", output)
        self.assertIn("'two'", output)

    def test_real_detector_list_covers_all_seven_detectors(self):
        self.assertEqual(len(sniffer.DETECTORS), 7)
        names = [name for name, _ in sniffer.DETECTORS]
        self.assertEqual(len(set(names)), 7)


if __name__ == "__main__":
    unittest.main()