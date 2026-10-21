"""Run from the project root:  python -m unittest ids.tests.test_storage -v"""
import os
import tempfile
import unittest
from datetime import datetime

from ids.alerts import Alert
from ids.storage import db


class StorageTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.path + suffix)
            except FileNotFoundError:
                pass

    def run_store(self, alerts):
        store = db.AlertStore(self.path)
        store.start(interface="eth0", config={"port_scan": {"threshold": 15}})
        for a in alerts:
            store.submit(a)
        store.stop()        # flushes the queue before returning
        return store

    def test_alert_is_saved_with_all_fields(self):
        self.run_store([Alert("SYN flood", "HIGH", "10.0.0.5", "50 SYNs",
                              timestamp=datetime(2026, 1, 1, 12, 0, 0),
                              target="10.0.0.1", dst_port=80,
                              details={"syn_count": 50})])
        rows = db.recent_alerts(self.path)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["kind"], row["severity"], row["source"]),
                         ("SYN flood", "HIGH", "10.0.0.5"))
        self.assertEqual((row["target"], row["dst_port"]), ("10.0.0.1", 80))
        self.assertIn('"syn_count": 50', row["details"])
        self.assertTrue(row["ts"].endswith("+00:00"))      # stored as UTC

    def test_session_row_is_opened_and_closed(self):
        store = self.run_store([])
        conn = db.connect(self.path)
        row = conn.execute("SELECT * FROM sessions WHERE id = ?",
                           (store.session_id,)).fetchone()
        conn.close()
        self.assertEqual(row["interface"], "eth0")
        self.assertIsNotNone(row["ended_at"])

    def test_burst_is_not_lost(self):
        burst = [Alert("Port scan", "MEDIUM", f"10.0.0.{i % 250}", "x")
                 for i in range(1000)]
        self.run_store(burst)
        self.assertEqual(len(db.recent_alerts(self.path, limit=5000)), 1000)

    def test_filters(self):
        self.run_store([Alert("Port scan", "MEDIUM", "10.0.0.5", "a"),
                        Alert("ARP spoof", "HIGH", "192.168.1.1", "b")])
        self.assertEqual(len(db.recent_alerts(self.path, kind="ARP spoof")), 1)
        self.assertEqual(len(db.recent_alerts(self.path, source="10.0.0.5")), 1)
        self.assertEqual(len(db.recent_alerts(self.path, severity="LOW")), 0)

    def test_bad_severity_is_rejected_by_the_database(self):
        conn = db.connect(self.path)
        with self.assertRaises(Exception):
            conn.execute("INSERT INTO alerts (ts, kind, severity, message) "
                         "VALUES ('t','k','BOGUS','m')")
        conn.close()

    # ---- one bad alert must not kill the writer ----
    def test_unserializable_details_do_not_kill_the_writer(self):
        store = self.run_store([
            Alert("k", "LOW", "s", "bad", details={"x": {1, 2}}),   # a set
            Alert("Port scan", "MEDIUM", "10.0.0.5", "ok 1"),
            Alert("Port scan", "MEDIUM", "10.0.0.5", "ok 2"),
        ])
        rows = db.recent_alerts(self.path)
        self.assertEqual(len(rows), 3)          # default=str saved the set as text
        self.assertIsNone(store.error)

    def test_bad_severity_skips_only_that_alert(self):
        store = self.run_store([
            Alert("k", "CRITICAL", "s", "bad"),                      # CHECK constraint fails
            Alert("Port scan", "MEDIUM", "10.0.0.5", "ok 1"),
            Alert("Port scan", "MEDIUM", "10.0.0.5", "ok 2"),
        ])
        rows = db.recent_alerts(self.path)
        self.assertEqual(sorted(r["message"] for r in rows), ["ok 1", "ok 2"])
        self.assertEqual(store.rejected, 1)
        self.assertIsNone(store.error)
        self.assertFalse(store.failed)

    def test_bad_timestamp_skips_only_that_alert(self):
        store = self.run_store([
            Alert("k", "LOW", "s", "bad", timestamp="not a datetime"),
            Alert("Port scan", "MEDIUM", "10.0.0.5", "ok"),
        ])
        self.assertEqual(len(db.recent_alerts(self.path)), 1)
        self.assertEqual(store.rejected, 1)

    def test_session_is_closed_even_after_bad_alerts(self):
        store = self.run_store([Alert("k", "CRITICAL", "s", "bad")])
        conn = db.connect(self.path)
        row = conn.execute("SELECT ended_at FROM sessions WHERE id = ?",
                           (store.session_id,)).fetchone()
        conn.close()
        self.assertIsNotNone(row["ended_at"])

    def test_queue_is_bounded_and_drops_are_counted(self):
        store = db.AlertStore(self.path)       # never started: nothing drains the queue
        for _ in range(db.MAX_QUEUE + 50):
            store.submit(Alert("Port scan", "MEDIUM", "10.0.0.5", "x"))
        self.assertEqual(store.dropped, 50)

    def test_failed_is_true_when_the_writer_dies(self):
        store = db.AlertStore(os.path.join(self.path, "nope", "x.db"))   # can't be opened
        store.start()
        store._thread.join(timeout=2)
        self.assertTrue(store.failed)
        self.assertIsNotNone(store.error)


class EmitSeverityTests(unittest.TestCase):
    def test_unknown_severity_becomes_medium(self):
        from ids import alerts
        seen = []
        alerts.subscribe(seen.append)
        try:
            alerts.emit("k", "critical!", "src", "m")
            alerts.emit("k", "high", "src", "m")
        finally:
            alerts._subscribers.remove(seen.append)
        self.assertEqual([a.severity for a in seen], ["MEDIUM", "HIGH"])


if __name__ == "__main__":
    unittest.main()