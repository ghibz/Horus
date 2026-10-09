# Detector settings, loaded from config.yaml.

# Built-in defaults live here, so Horus still runs if config.yaml is missing
# or only lists a few settings. Anything in config.yaml overrides the default.
# Typos and nonsense values are rejected with a clear message rather than
# silently weakening detection.

import os
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.yaml"

DEFAULTS = {
    "port_scan":   {"threshold": 15, "window_seconds": 5,  "cooldown_seconds": 30},
    "udp_scan":    {"threshold": 15, "window_seconds": 5,  "cooldown_seconds": 10},
    "syn_flood":   {"threshold": 50, "window_seconds": 5,  "cooldown_seconds": 30},
    "brute_force": {"threshold": 10, "window_seconds": 10, "cooldown_seconds": 30,
                    "ports": [22, 21, 23, 3389]},
    "arp_spoof":   {"cooldown_seconds": 30},
}

_cache = None


class ConfigError(ValueError):
    pass


def get(section: str) -> dict:
    # Settings for one detector, defaults merged with config.yaml.
    global _cache
    if _cache is None:
        _cache = _load()
    return dict(_cache[section])


def reset() -> None:
    # Forget the loaded settings (next get() reads the file again).
    global _cache
    _cache = None


def _load() -> dict:
    # HORUS_CONFIG lets you point at another file (the tests use this)
    path = Path(os.environ.get("HORUS_CONFIG") or CONFIG_PATH)
    merged = {name: dict(values) for name, values in DEFAULTS.items()}

    if not path.is_file():
        return merged                       # no file: run on defaults

    try:
        with open(path, encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"{path.name} is not valid YAML: {e}") from e
    if not isinstance(user, dict):
        raise ConfigError(f"{path.name} must contain sections like 'port_scan:'")

    for section, values in user.items():
        if section not in merged:
            raise ConfigError(f"unknown section '{section}' in {path.name} "
                              f"(valid: {', '.join(merged)})")
        if not isinstance(values, dict):
            raise ConfigError(f"section '{section}' must contain 'name: value' lines")
        for key, value in values.items():
            if key not in merged[section]:
                raise ConfigError(f"unknown setting '{key}' in section '{section}' "
                                  f"(valid: {', '.join(merged[section])})")
            _check(section, key, value)
            merged[section][key] = value
    return merged


def _check(section, key, value):
    where = f"{section}.{key}"
    if key == "ports":
        if (not isinstance(value, list) or not value or
                not all(isinstance(p, int) and not isinstance(p, bool)
                        and 1 <= p <= 65535 for p in value)):
            raise ConfigError(f"{where} must be a list of port numbers (1-65535)")
    elif key == "threshold":
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ConfigError(f"{where} must be a whole number, 1 or more")
    else:   # window_seconds, cooldown_seconds
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ConfigError(f"{where} must be a number of seconds")
        if value < 0 or (key == "window_seconds" and value == 0):
            raise ConfigError(f"{where} must be greater than 0"
                              if key == "window_seconds" else f"{where} can't be negative")