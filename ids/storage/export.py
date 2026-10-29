"""CSV export of alerts.

Kept apart from the GUI so it can be tested without a display. It writes the
same information the database stores: time, severity, type, source, target,
port, message and the detector-specific details (as JSON).
"""
import csv

from ids.storage.db import dumps

CSV_COLUMNS = ["Time", "Severity", "Type", "Source", "Target", "Port", "Message", "Details"]


def alert_to_row(alert):
    # One CSV row for an Alert. Missing values become empty cells, not "None".
    return [
        alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        alert.severity,
        alert.kind,
        alert.source,
        "" if alert.target is None else alert.target,
        "" if alert.dst_port is None else alert.dst_port,
        alert.message,
        "" if alert.details is None else dumps(alert.details),
    ]


def write_csv(path, alerts):
    # Write the alerts (in the order given) to `path`.
    # Raises OSError if the file can't be written (locked, no permission,
    # folder missing, disk full ...): the caller has to tell the user.
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_COLUMNS)
        for alert in alerts:
            writer.writerow(alert_to_row(alert))