"""CSV export of alerts.

Kept apart from the GUI so it can be tested without a display. It writes the
same information the database stores: time, severity, type, source, target,
port, message and the detector-specific details (as JSON).

What gets exported: the GUI table only keeps the newest MAX_ROWS alerts, but
the database keeps every one, so the export reads the database (collect_alerts)
and only falls back to what the table shows if the database can't be trusted.
"""
import csv
import json
from datetime import datetime

from ids.alerts import Alert
from ids.storage import db
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


def alert_from_row(row) -> Alert:
    # A database row (dict) back into an Alert, with the time shown the way the
    # table shows it: local time (the database stores UTC).
    timestamp = datetime.fromisoformat(row["ts"]).astimezone().replace(tzinfo=None)
    details = row["details"]
    if details:
        try:
            details = json.loads(details)
        except ValueError:
            pass                    # not JSON: keep the text as it is
    else:
        details = None
    return Alert(kind=row["kind"], severity=row["severity"],
                 source=row["source"] or "", message=row["message"],
                 timestamp=timestamp, target=row["target"],
                 dst_port=row["dst_port"], details=details)


def collect_alerts(table_alerts, db_path, since, trusted=True):
    """Decide what the CSV contains. Returns (alerts_oldest_first, from_database).

    Normally: every alert the database saved since `since`, including the ones
    that already scrolled out of the table. Falls back to `table_alerts` (what
    the table still shows) when
      * trusted is False (the GUI saw the database fail, drop or refuse alerts),
      * the database can't be read, or
      * it holds fewer alerts than the table, so something was not saved.
    """
    if trusted:
        try:
            saved = [alert_from_row(r) for r in db.alerts_since(db_path, since)]
        except Exception:
            saved = None
        if saved is not None and len(saved) >= len(table_alerts):
            return saved, True
    return list(table_alerts), False


def write_csv(path, alerts):
    # Write the alerts (in the order given) to `path`.
    # Raises OSError if the file can't be written (locked, no permission,
    # folder missing, disk full ...): the caller has to tell the user.
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_COLUMNS)
        for alert in alerts:
            writer.writerow(alert_to_row(alert))