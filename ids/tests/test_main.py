"""Run from the project root:  python -m unittest ids.tests.test_main -v

Checks the startup path in main.py: a bad config.yaml (or any other startup
failure) must produce a visible error message and exit code 1, not a traceback
and not a silent nothing. No GUI, network or admin rights needed: the GUI loader
and the message box are replaced by fakes.
"""
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
import io
from unittest import mock

import main
from ids import config


class StartupTests(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("HORUS_CONFIG")
        self._dir = tempfile.TemporaryDirectory()
        config.reset()
        self.shown = []        # (title, message) of every message box "shown"
        self.ran = []          # filled when the fake GUI runs
        patcher = mock.patch.object(main, "show_startup_error",
                                    lambda title, msg: self.shown.append((title, msg)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("HORUS_CONFIG", None)
        else:
            os.environ["HORUS_CONFIG"] = self._old_env
        config.reset()
        self._dir.cleanup()

    def use_config(self, text):
        path = os.path.join(self._dir.name, "config.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.environ["HORUS_CONFIG"] = path
        config.reset()
        return path

    def gui_loader(self):
        return lambda: self.ran.append("gui")

    # ---------------------------------------------------------- good startup
    def test_valid_config_starts_the_gui(self):
        self.use_config("port_scan:\n  threshold: 20\n")
        self.assertEqual(main.main(load_gui=self.gui_loader), 0)
        self.assertEqual(self.ran, ["gui"])
        self.assertEqual(self.shown, [])

    def test_missing_config_starts_on_defaults(self):
        os.environ["HORUS_CONFIG"] = os.path.join(self._dir.name, "nope.yaml")
        config.reset()
        self.assertEqual(main.main(load_gui=self.gui_loader), 0)
        self.assertEqual(self.ran, ["gui"])

    # ---------------------------------------------------------- bad config
    def test_bad_config_shows_a_message_and_does_not_start(self):
        path = self.use_config("port_scan:\n  treshold: 5\n")      # typo
        self.assertEqual(main.main(load_gui=self.gui_loader), 1)
        self.assertEqual(self.ran, [])                              # GUI never loaded
        self.assertEqual(len(self.shown), 1)
        title, message = self.shown[0]
        self.assertIn("invalid settings", title)
        self.assertIn("treshold", message)       # says what is wrong
        self.assertIn(path, message)             # says where the file is
        self.assertIn("defaults", message)       # says how to get out of it

    def test_every_kind_of_bad_config_is_reported_not_raised(self):
        bad = ["port_scan: [unclosed\n", "- a\n- b\n", "udp_scan:\n  threshold: 0\n",
               "brute_force:\n  ports: [70000]\n", "nonsense:\n  x: 1\n"]
        for text in bad:
            with self.subTest(text=text):
                self.shown.clear()
                self.use_config(text)
                self.assertEqual(main.main(load_gui=self.gui_loader), 1)
                self.assertEqual(len(self.shown), 1)
        self.assertEqual(self.ran, [])

    def test_config_error_raised_while_loading_the_gui_is_still_reported(self):
        # safety net: a ConfigError that only appears at import time
        self.use_config("")
        def loader():
            raise config.ConfigError("port_scan.threshold must be a whole number")
        self.assertEqual(main.main(load_gui=loader), 1)
        self.assertIn("invalid settings", self.shown[0][0])

    # ------------------------------------------------------- other failures
    def test_other_startup_failure_is_reported_too(self):
        self.use_config("")
        def loader():
            raise ImportError("No module named 'scapy'")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main.main(load_gui=loader), 1)
        title, message = self.shown[0]
        self.assertIn("error", title.lower())
        self.assertIn("scapy", message)

    def test_crash_while_running_is_reported(self):
        self.use_config("")
        def run():
            raise RuntimeError("boom")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main.main(load_gui=lambda: run), 1)
        self.assertIn("boom", self.shown[0][1])


class ShowStartupErrorTests(unittest.TestCase):
    # the real show_startup_error, with the console and Tk taken away
    def test_works_without_a_console_and_without_tkinter(self):
        # pythonw: sys.stderr is None. No tkinter: the import fails.
        with mock.patch.object(sys, "stderr", None), \
             mock.patch.dict(sys.modules, {"tkinter": None}):
            main.show_startup_error("title", "message")      # must not raise

    def test_prints_to_the_console_when_there_is_one(self):
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err), \
             mock.patch.dict(sys.modules, {"tkinter": None}):
            main.show_startup_error("My title", "My message")
        self.assertIn("My title", err.getvalue())
        self.assertIn("My message", err.getvalue())

    def test_shows_a_message_box_when_tkinter_is_available(self):
        fake_tk = mock.MagicMock()
        fake_messagebox = mock.MagicMock()
        fake_tk.messagebox = fake_messagebox
        with mock.patch.object(sys, "stderr", None), \
             mock.patch.dict(sys.modules, {"tkinter": fake_tk,
                                           "tkinter.messagebox": fake_messagebox}):
            main.show_startup_error("My title", "My message")
        fake_messagebox.showerror.assert_called_once()
        self.assertEqual(fake_messagebox.showerror.call_args.args, ("My title", "My message"))
        fake_tk.Tk.return_value.withdraw.assert_called_once()      # no empty window
        fake_tk.Tk.return_value.destroy.assert_called_once()


if __name__ == "__main__":
    unittest.main()