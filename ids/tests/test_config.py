"""Run from the project root:  python -m unittest ids.tests.test_config -v

Each test writes its own temporary YAML file and points HORUS_CONFIG at it.
"""
import os
import tempfile
import unittest

from ids import config


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("HORUS_CONFIG")
        self._dir = tempfile.TemporaryDirectory()
        config.reset()

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("HORUS_CONFIG", None)
        else:
            os.environ["HORUS_CONFIG"] = self._old_env
        config.reset()
        self._dir.cleanup()

    def write(self, text):
        path = os.path.join(self._dir.name, "test.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.environ["HORUS_CONFIG"] = path
        config.reset()

    def load(self, text, section="port_scan"):
        self.write(text)
        return config.get(section)

    def test_missing_file_uses_defaults(self):
        os.environ["HORUS_CONFIG"] = os.path.join(self._dir.name, "nope.yaml")
        config.reset()
        for section, values in config.DEFAULTS.items():
            self.assertEqual(config.get(section), values)

    def test_empty_file_uses_defaults(self):
        self.assertEqual(self.load(""), config.DEFAULTS["port_scan"])

    def test_partial_override_keeps_other_defaults(self):
        cfg = self.load("port_scan:\n  threshold: 99\n")
        self.assertEqual(cfg["threshold"], 99)
        self.assertEqual(cfg["window_seconds"],
                         config.DEFAULTS["port_scan"]["window_seconds"])

    def test_get_returns_a_copy(self):
        self.load("")
        config.get("port_scan")["threshold"] = 12345
        self.assertNotEqual(config.get("port_scan")["threshold"], 12345)

    def test_brute_force_ports_override(self):
        cfg = self.load("brute_force:\n  ports: [22, 5900]\n", "brute_force")
        self.assertEqual(cfg["ports"], [22, 5900])

    def test_float_seconds_are_accepted(self):
        self.assertEqual(
            self.load("port_scan:\n  window_seconds: 2.5\n")["window_seconds"], 2.5)

    def test_zero_cooldown_is_allowed(self):
        self.assertEqual(
            self.load("port_scan:\n  cooldown_seconds: 0\n")["cooldown_seconds"], 0)

    def test_icmp_flood_section_has_defaults(self):
        self.assertEqual(self.load("", "icmp_flood"), config.DEFAULTS["icmp_flood"])

    def test_icmp_flood_override(self):
        cfg = self.load("icmp_flood:\n  threshold: 200\n", "icmp_flood")
        self.assertEqual(cfg["threshold"], 200)
        self.assertEqual(cfg["window_seconds"],
                         config.DEFAULTS["icmp_flood"]["window_seconds"])

    def test_icmp_flood_bad_value_is_rejected(self):
        with self.assertRaises(config.ConfigError):
            self.load("icmp_flood:\n  threshold: 0\n", "icmp_flood")


    def test_icmp_unusual_section_has_defaults(self):
        self.assertEqual(self.load("", "icmp_unusual"), config.DEFAULTS["icmp_unusual"])

    def test_icmp_unusual_cooldown_override(self):
        cfg = self.load("icmp_unusual:\n  cooldown_seconds: 120\n", "icmp_unusual")
        self.assertEqual(cfg["cooldown_seconds"], 120)

    def test_icmp_unusual_has_no_threshold_setting(self):
        # this detector only has a cooldown; a threshold line is a typo, not a setting
        with self.assertRaises(config.ConfigError):
            self.load("icmp_unusual:\n  threshold: 5\n", "icmp_unusual")

    def test_bad_configs_are_rejected(self):
        bad = {
            "unknown section":       "portscan:\n  threshold: 5\n",
            "unknown key":           "port_scan:\n  treshold: 5\n",
            "section not a mapping": "port_scan: 5\n",
            "top level not a map":   "- a\n- b\n",
            "invalid yaml":          "port_scan: [unclosed\n",
            "threshold zero":        "port_scan:\n  threshold: 0\n",
            "threshold float":       "port_scan:\n  threshold: 1.5\n",
            "threshold bool":        "port_scan:\n  threshold: true\n",
            "window zero":           "port_scan:\n  window_seconds: 0\n",
            "window string":         "port_scan:\n  window_seconds: fast\n",
            "cooldown negative":     "port_scan:\n  cooldown_seconds: -1\n",
            "ports not a list":      "brute_force:\n  ports: 22\n",
            "ports empty":           "brute_force:\n  ports: []\n",
            "ports out of range":    "brute_force:\n  ports: [22, 70000]\n",
            "ports contain bool":    "brute_force:\n  ports: [true]\n",
        }
        for name, text in bad.items():
            with self.subTest(name):
                with self.assertRaises(config.ConfigError):
                    self.load(text)


if __name__ == "__main__":
    unittest.main()