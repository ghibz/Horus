"""Run from the project root:  python -m unittest ids.tests.test_export -v

Part 1 tests the CSV writer (ids/storage/export.py).
Part 2 tests the GUI's export button, bookkeeping and error handling. The GUI
needs no display here: tkinter is replaced by a fake before app.py is loaded,
and the table (Treeview) by a tiny stand-in.
"""
import csv
import importlib.util
import os
import queue
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ids.alerts import Alert
from ids.storage import db, export

T0 = datetime(2026, 1, 1, 12, 0, 0)


def make_alert(**kw):
    values = dict(kind="Port scan", severity="MEDIUM", source="10.0.0.5",
                  message="15 distinct ports touched in the last 5s", timestamp=T0,
                  target="10.0.0.1", dst_port=22,
                  details={"ports": [22, 80], "count": 15})
    values.update(kw)
    return Alert(**values)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


# ------------------------------------------------------------- the CSV writer
class WriteCsvTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "alerts.csv")

    def tearDown(self):
        self._dir.cleanup()

    def test_header_has_the_fields_the_database_has(self):
        export.write_csv(self.path, [])
        self.assertEqual(read_csv(self.path)[0],
                         ["Time", "Severity", "Type", "Source", "Target", "Port",
                          "Message", "Details"])

    def test_row_contains_target_port_and_details(self):
        export.write_csv(self.path, [make_alert()])
        header, row = read_csv(self.path)
        data = dict(zip(header, row))
        self.assertEqual(data["Time"], "2026-01-01 12:00:00")
        self.assertEqual(data["Severity"], "MEDIUM")
        self.assertEqual(data["Type"], "Port scan")
        self.assertEqual(data["Source"], "10.0.0.5")
        self.assertEqual(data["Target"], "10.0.0.1")
        self.assertEqual(data["Port"], "22")
        self.assertEqual(data["Message"], "15 distinct ports touched in the last 5s")
        self.assertEqual(data["Details"], '{"ports": [22, 80], "count": 15}')

    def test_missing_values_are_empty_cells_not_the_word_none(self):
        export.write_csv(self.path, [make_alert(target=None, dst_port=None, details=None)])
        _, row = read_csv(self.path)
        self.assertEqual(row[4:6], ["", ""])
        self.assertEqual(row[7], "")
        self.assertNotIn("None", row)

    def test_port_zero_is_kept(self):
        export.write_csv(self.path, [make_alert(dst_port=0)])
        self.assertEqual(read_csv(self.path)[1][5], "0")

    def test_order_is_the_order_given(self):
        alerts = [make_alert(source=f"10.0.0.{i}") for i in range(5)]
        export.write_csv(self.path, alerts)
        self.assertEqual([r[3] for r in read_csv(self.path)[1:]],
                         [f"10.0.0.{i}" for i in range(5)])

    def test_commas_quotes_and_newlines_survive(self):
        nasty = 'a, "quoted"\nsecond line'
        export.write_csv(self.path, [make_alert(message=nasty)])
        self.assertEqual(read_csv(self.path)[1][6], nasty)

    def test_unserializable_details_do_not_break_the_export(self):
        export.write_csv(self.path, [make_alert(details={"when": T0, "obj": object()})])
        self.assertEqual(len(read_csv(self.path)), 2)

    def test_unwritable_location_raises_oserror(self):
        # a folder that doesn't exist, and a path that is a folder
        with self.assertRaises(OSError):
            export.write_csv(os.path.join(self._dir.name, "nope", "a.csv"), [])
        with self.assertRaises(OSError):
            export.write_csv(self._dir.name, [])


# ------------------------------------------ what goes into the file (database)
class SavedAlertsTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._dir.name, "h.db")
        self.long_ago = db.utc_iso(T0 - timedelta(days=1))

    def tearDown(self):
        self._dir.cleanup()

    def save(self, alerts):
        store = db.AlertStore(self.db_path)
        store.start()
        for a in alerts:
            store.submit(a)
        store.stop()

    def test_database_row_becomes_the_same_alert_and_the_same_csv_row(self):
        original = make_alert()
        self.save([original])
        rows = db.alerts_since(self.db_path)
        rebuilt = export.alert_from_row(rows[0])
        self.assertEqual(rebuilt.timestamp, T0)            # back in local time
        self.assertEqual(export.alert_to_row(rebuilt), export.alert_to_row(original))

    def test_missing_target_port_and_details_survive_the_round_trip(self):
        self.save([make_alert(target=None, dst_port=None, details=None)])
        rebuilt = export.alert_from_row(db.alerts_since(self.db_path)[0])
        row = export.alert_to_row(rebuilt)
        self.assertEqual((row[4], row[5], row[7]), ("", "", ""))

    def test_details_that_are_not_json_are_kept_as_text(self):
        row = {"ts": db.utc_iso(T0), "kind": "k", "severity": "LOW", "source": "s",
               "target": None, "dst_port": None, "message": "m", "details": "{broken"}
        self.assertEqual(export.alert_from_row(row).details, "{broken")

    def test_collect_prefers_the_database_when_it_has_everything(self):
        self.save([make_alert(source=f"10.0.0.{i}") for i in range(10)])
        table = [make_alert(source=f"10.0.0.{i}") for i in range(7, 10)]   # last 3 only
        alerts, from_db = export.collect_alerts(table, self.db_path, self.long_ago)
        self.assertTrue(from_db)
        self.assertEqual(len(alerts), 10)

    def test_collect_ignores_alerts_from_before_since(self):
        self.save([make_alert(source=f"10.0.0.{i}", timestamp=T0 + timedelta(minutes=i))
                   for i in range(5)])
        since = db.utc_iso(T0 + timedelta(minutes=3))
        alerts, _ = export.collect_alerts([], self.db_path, since)
        self.assertEqual([a.source for a in alerts], ["10.0.0.3", "10.0.0.4"])

    def test_collect_falls_back_to_the_table_when_the_database_is_not_trusted(self):
        self.save([make_alert()] * 5)
        table = [make_alert()]
        alerts, from_db = export.collect_alerts(table, self.db_path, self.long_ago,
                                                trusted=False)
        self.assertFalse(from_db)
        self.assertEqual(alerts, table)

    def test_collect_falls_back_when_the_database_has_fewer_than_the_table(self):
        self.save([make_alert()])
        table = [make_alert(), make_alert(), make_alert()]    # some were never saved
        alerts, from_db = export.collect_alerts(table, self.db_path, self.long_ago)
        self.assertFalse(from_db)
        self.assertEqual(len(alerts), 3)

    def test_collect_falls_back_when_the_database_cannot_be_read(self):
        bad = os.path.join(self._dir.name, "no", "such", "folder", "h.db")
        table = [make_alert()]
        alerts, from_db = export.collect_alerts(table, bad, self.long_ago)
        self.assertFalse(from_db)
        self.assertEqual(alerts, table)


# --------------------------------------------------------------- the GUI part
class FakeTree:
    # just enough of ttk.Treeview: newest row first, like the real table
    def __init__(self):
        self._rows = []        # [(iid, values)]
        self._next = 1

    def insert(self, parent, index, values=(), tags=()):
        iid = f"I{self._next:03d}"
        self._next += 1
        self._rows.insert(0, (iid, tuple(values)))
        return iid

    def get_children(self):
        return tuple(iid for iid, _ in self._rows)

    def delete(self, *iids):
        self._rows = [(i, v) for i, v in self._rows if i not in iids]

    def item(self, iid, option):
        return dict(self._rows)[iid]


def load_gui_module():
    # app.py loaded fresh, against a fake tkinter (works with or without a real one)
    fake_tk = types.ModuleType("tkinter")
    fake_tk.Tk = type("Tk", (), {})
    fake_tk.filedialog = mock.MagicMock()
    fake_tk.messagebox = mock.MagicMock()
    fake_tk.ttk = mock.MagicMock()
    fakes = {"tkinter": fake_tk, "tkinter.filedialog": fake_tk.filedialog,
             "tkinter.messagebox": fake_tk.messagebox, "tkinter.ttk": fake_tk.ttk}
    path = Path(__file__).resolve().parents[1] / "gui" / "app.py"
    spec = importlib.util.spec_from_file_location("horus_app_under_test", path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, fakes):
        spec.loader.exec_module(module)
    return module


class GuiExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_gui_module()

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "out.csv")
        self.tree = FakeTree()
        self.status = mock.MagicMock()
        self.db_path = os.path.join(self._dir.name, "h.db")
        self.long_ago = db.utc_iso(datetime.now() - timedelta(days=1))
        self.gui = SimpleNamespace(tree=self.tree, _alert_by_row={}, status_var=self.status,
                                   alert_count=0, high_count=0,
                                   _update_empty_state=lambda: None,
                                   store=None, _db_path=self.db_path,
                                   _since=self.long_ago, _db_lossy=False,
                                   alert_queue=queue.Queue())
        self.filedialog = self.app.filedialog = mock.MagicMock()
        self.messagebox = self.app.messagebox = mock.MagicMock()
        self.filedialog.asksaveasfilename.return_value = self.path

    def tearDown(self):
        self._dir.cleanup()

    def add(self, **kw):
        self.app.HorusApp._add_alert(self.gui, make_alert(**kw))

    def export(self):
        self.app.HorusApp.export_csv(self.gui)

    def save_to_db(self, alerts):
        store = db.AlertStore(self.db_path)
        store.start()
        for a in alerts:
            store.submit(a)
        store.stop()

    # ---- bookkeeping
    def test_every_table_row_keeps_its_full_alert(self):
        self.add(source="10.0.0.1")
        self.add(source="10.0.0.2")
        self.assertEqual(set(self.gui._alert_by_row), set(self.tree.get_children()))

    def test_rows_dropped_from_the_table_are_dropped_from_the_lookup(self):
        with mock.patch.object(self.app, "MAX_ROWS", 3):
            for i in range(10):
                self.add(source=f"10.0.0.{i}")
        self.assertEqual(len(self.tree.get_children()), 3)
        self.assertEqual(set(self.gui._alert_by_row), set(self.tree.get_children()))

    def test_clear_empties_the_lookup(self):
        self.add()
        self.app.HorusApp.clear(self.gui)
        self.assertEqual(self.gui._alert_by_row, {})
        self.assertEqual(self.tree.get_children(), ())

    # ---- export
    def test_export_writes_every_field_oldest_first(self):
        self.add(source="10.0.0.1", dst_port=22)
        self.add(source="10.0.0.2", dst_port=80, details={"x": 1})
        self.export()
        header, first, second = read_csv(self.path)
        self.assertEqual([first[3], second[3]], ["10.0.0.1", "10.0.0.2"])   # oldest first
        self.assertEqual(dict(zip(header, second))["Port"], "80")
        self.assertEqual(dict(zip(header, second))["Details"], '{"x": 1}')
        self.messagebox.showerror.assert_not_called()
        self.assertIn("Exported 2 alerts", self.status.set.call_args.args[0])

    def test_export_with_no_alerts_just_says_so(self):
        self.export()
        self.messagebox.showinfo.assert_called_once()
        self.filedialog.asksaveasfilename.assert_not_called()

    def test_cancelling_the_save_dialog_does_nothing(self):
        self.add()
        self.filedialog.asksaveasfilename.return_value = ""
        self.export()
        self.assertFalse(os.path.exists(self.path))
        self.messagebox.showerror.assert_not_called()

    # ---- the export is not limited to what the table still shows
    def test_export_includes_alerts_that_scrolled_out_of_the_table(self):
        alerts = [make_alert(source=f"10.0.0.{i}", timestamp=datetime.now())
                  for i in range(10)]
        self.save_to_db(alerts)
        with mock.patch.object(self.app, "MAX_ROWS", 3):
            for a in alerts:
                self.app.HorusApp._add_alert(self.gui, a)
        self.assertEqual(len(self.tree.get_children()), 3)          # table: newest 3
        self.export()
        rows = read_csv(self.path)[1:]
        self.assertEqual(len(rows), 10)                              # file: all 10
        self.assertEqual([r[3] for r in rows], [f"10.0.0.{i}" for i in range(10)])
        self.assertIn("Exported 10 alerts", self.status.set.call_args.args[0])
        self.assertNotIn("only what the table shows", self.status.set.call_args.args[0])

    def test_clear_starts_the_export_fresh(self):
        old = [make_alert(source="10.0.0.1", timestamp=datetime.now() - timedelta(hours=1))]
        self.save_to_db(old)
        self.app.HorusApp._add_alert(self.gui, old[0])
        self.app.HorusApp.clear(self.gui)
        new = make_alert(source="10.0.0.2", timestamp=datetime.now() + timedelta(seconds=5))
        self.save_to_db([new])
        self.app.HorusApp._add_alert(self.gui, new)
        self.export()
        self.assertEqual([r[3] for r in read_csv(self.path)[1:]], ["10.0.0.2"])

    def test_clear_also_drops_alerts_still_waiting_for_the_table(self):
        self.gui.alert_queue.put(make_alert())
        self.app.HorusApp.clear(self.gui)
        self.assertTrue(self.gui.alert_queue.empty())

    def test_export_uses_the_table_if_the_database_lost_alerts(self):
        self.save_to_db([make_alert(source="10.0.0.9", timestamp=datetime.now())])
        self.gui._db_lossy = True
        self.add(source="10.0.0.1")
        self.export()
        self.assertEqual([r[3] for r in read_csv(self.path)[1:]], ["10.0.0.1"])
        self.assertIn("only what the table shows", self.status.set.call_args.args[0])

    def test_export_waits_for_the_writer_when_monitoring_is_running(self):
        self.gui.store = mock.MagicMock()
        self.add()
        self.export()
        self.gui.store.flush.assert_called_once()

    def test_closing_a_store_that_lost_alerts_marks_the_database_untrusted(self):
        for problem in ({"failed": True}, {"dropped": 3}, {"rejected": 1}):
            with self.subTest(problem=problem):
                store = mock.MagicMock(failed=False, dropped=0, rejected=0)
                for key, value in problem.items():
                    setattr(store, key, value)
                self.gui.store, self.gui._db_lossy = store, False
                self.app.HorusApp._close_store(self.gui)
                self.assertTrue(self.gui._db_lossy)
                self.assertIsNone(self.gui.store)
                store.stop.assert_called_once()

    def test_closing_a_healthy_store_keeps_the_database_trusted(self):
        self.gui.store = mock.MagicMock(failed=False, dropped=0, rejected=0)
        self.app.HorusApp._close_store(self.gui)
        self.assertFalse(self.gui._db_lossy)

    # ---- the bug: export errors used to be silent
    def test_unwritable_path_shows_an_error_instead_of_failing_silently(self):
        self.add()
        bad = os.path.join(self._dir.name, "no", "such", "folder", "out.csv")
        self.filedialog.asksaveasfilename.return_value = bad
        self.export()                                   # must not raise
        self.messagebox.showerror.assert_called_once()
        message = self.messagebox.showerror.call_args.args[1]
        self.assertIn(bad, message)                     # says which file
        self.assertIn("Excel", message)                 # says what to try
        self.status.set.assert_called_with("Export failed")

    def test_locked_file_gives_the_error_message(self):
        # what Windows does when the CSV is open in Excel
        self.add()
        with mock.patch.object(export, "write_csv",
                               side_effect=PermissionError(13, "Permission denied")):
            self.export()
        self.messagebox.showerror.assert_called_once()
        self.assertIn("Permission denied", self.messagebox.showerror.call_args.args[1])

    def test_unexpected_error_during_export_is_also_reported(self):
        self.add()
        with mock.patch.object(export, "write_csv", side_effect=RuntimeError("boom")):
            self.export()
        self.messagebox.showerror.assert_called_once()
        self.assertIn("boom", self.messagebox.showerror.call_args.args[1])


if __name__ == "__main__":
    unittest.main()