# Alert storage (SQLite).
#
# Detectors never touch the database. The alert channel (alerts.emit) hands
# every alert to AlertStore.submit(), which only puts it on a queue. A
# dedicated writer thread owns the SQLite connection and does the inserts,
# so that a slow disk can never delay packet processing.

import json
import queue
import sqlite3
import threading
from datetime import timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "horus.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    interface   TEXT,
    config_json TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(id),
    ts         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    source     TEXT,
    target     TEXT,
    dst_port   INTEGER,
    message    TEXT NOT NULL,
    details    TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);
CREATE INDEX IF NOT EXISTS idx_alerts_kind   ON alerts(kind);
"""


def utc_iso(dt) -> str:
    # Alert timestamps are naive local time; store them as UTC ISO 8601
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def connect(path=DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # readers don't block the writer
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn


def recent_alerts(path=DB_PATH, limit=200, kind=None, source=None, severity=None):
    # Newest first. Opens its own short-lived connection, safe from any thread.
    sql, args = "SELECT * FROM alerts WHERE 1=1", []
    for column, value in (("kind", kind), ("source", source), ("severity", severity)):
        if value is not None:
            sql += f" AND {column} = ?"
            args.append(value)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    args.append(limit)

    conn = connect(path)
    try:
        return [dict(row) for row in conn.execute(sql, args)]
    finally:
        conn.close()


class AlertStore:
    """One store per monitoring session (one Start -> Stop)."""

    def __init__(self, path=DB_PATH):
        self.path = path
        self.session_id = None
        self._queue = queue.Queue()
        self._thread = None
        self._ready = threading.Event()

    def start(self, interface=None, config=None):
        self._thread = threading.Thread(
            target=self._run, args=(interface, config), daemon=True, name="horus-db")
        self._thread.start()
        self._ready.wait(timeout=5)

    def submit(self, alert) -> None:
        # called on the sniffing thread: must stay instant
        self._queue.put(alert)

    def stop(self) -> None:
        # flush everything still queued, close the session row, close the file
        if self._thread is not None:
            self._queue.put(None)
            self._thread.join(timeout=5)
            self._thread = None

    # --------------------------------------------------- writer thread
    def _run(self, interface, config):
        conn = connect(self.path)
        try:
            cur = conn.execute(
                "INSERT INTO sessions (started_at, interface, config_json) "
                "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?)",
                (interface, json.dumps(config) if config else None))
            self.session_id = cur.lastrowid
            conn.commit()
            self._ready.set()

            while True:
                item = self._queue.get()
                batch = [item]
                # grab whatever else is waiting so a burst is one transaction
                while len(batch) < 200:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break

                stop = None in batch
                self._insert(conn, [a for a in batch if a is not None])
                if stop:
                    break

            conn.execute(
                "UPDATE sessions SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE id = ?", (self.session_id,))
            conn.commit()
        except Exception as exc:
            print(f"[WARN] Alert database stopped: {exc!r}")
        finally:
            self._ready.set()       # never leave start() waiting
            conn.close()

    def _insert(self, conn, alerts):
        if not alerts:
            return
        rows = [(self.session_id, utc_iso(a.timestamp), a.kind, a.severity,
                 a.source, a.target, a.dst_port, a.message,
                 json.dumps(a.details) if a.details else None)
                for a in alerts]
        with conn:
            conn.executemany(
                "INSERT INTO alerts (session_id, ts, kind, severity, source, "
                "target, dst_port, message, details) VALUES (?,?,?,?,?,?,?,?,?)",
                rows)