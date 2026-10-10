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


if __name__ == "__main__":
    unittest.main()