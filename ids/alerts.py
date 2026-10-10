# Alert channel

# Detectors call emit() when they raise an alert. Anything that wants to see
# alerts (the GUI, a log file writer, ...) registers a callback with subscribe().
# Detectors never need to know who is listening.

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional


@dataclass
class Alert:
    kind: str
    severity: str
    source: str
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    target: Optional[str] = None       # victim IP, if there is one
    dst_port: Optional[int] = None
    details: Optional[dict] = None     # detector-specific extras (stored as JSON)


_subscribers: List[Callable[[Alert], None]] = []


def subscribe(callback: Callable[[Alert], None]) -> None:
    """Register a function that is called with every new Alert."""
    _subscribers.append(callback)


def emit(kind: str, severity: str, source, message: str,
         target=None, dst_port=None, details=None) -> Alert:
    """Create an alert, print it to the console and hand it to subscribers."""
    alert = Alert(kind, severity, str(source), message,
                  target=None if target is None else str(target),
                  dst_port=dst_port, details=details)
    print(f"[ALERT] [{severity}] {kind} | {source} | {message}")

    for callback in _subscribers:
        try:
            callback(alert)
        except Exception as exc:  # a broken subscriber must never stop detection
            print(f"[WARN] Alert subscriber failed: {exc!r}")

    return alert

