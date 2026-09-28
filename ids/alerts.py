# Alert channel

# Detectors call emit() when they raise an alert. Anything that wants to see
# alerts (the GUI, a log file writer, ...) registers a callback with subscribe().
# Detectors never need to know who is listening.

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List


@dataclass
class Alert:
    kind: str          # e.g. "Port scan"
    severity: str      # "LOW" | "MEDIUM" | "HIGH"
    source: str        # offending IP (or other identifier)
    message: str
    timestamp: datetime = field(default_factory=datetime.now)


_subscribers: List[Callable[[Alert], None]] = []


def subscribe(callback: Callable[[Alert], None]) -> None:
    """Register a function that is called with every new Alert."""
    _subscribers.append(callback)


def emit(kind: str, severity: str, source, message: str) -> Alert:
    """Create an alert, print it to the console and hand it to subscribers."""
    alert = Alert(kind, severity, str(source), message)
    print(f"[ALERT] [{severity}] {kind} | {source} | {message}")

    for callback in _subscribers:
        try:
            callback(alert)
        except Exception as exc:  # a broken subscriber must never stop detection
            print(f"[WARN] Alert subscriber failed: {exc!r}")

    return alert