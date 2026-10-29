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
import time
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "horus.db"

MAX_QUEUE = 10_000   # alerts waiting for the writer; beyond this they are dropped (and counted)

INSERT_ALERT = (
    "INSERT INTO alerts (session_id, ts, kind, severity, source, "
    "target, dst_port, message, details) VALUES (?,?,?,?,?,?,?,?,?)")

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


def dumps(obj) -> str:
    """JSON that never raises: unknown types become strings, the rest falls back to repr."""
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return json.dumps({"unserializable": repr(obj)})


def utc_iso(dt) -> str:
    # Alert timestamps are naive local time; store them as UTC ISO 8601
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def utc_now_iso() -> str:
    # "now" in the same format as the stored timestamps, so the two can be
    # compared as plain strings
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


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


def alerts_since(path=DB_PATH, since=None):
    # Every saved alert from `since` (a utc_iso/utc_now_iso string) onwards,
    # OLDEST first. since=None means everything. Used by the CSV export, so it
    # is not capped: the GUI table only keeps the newest rows, the database
    # keeps them all.
    sql, args = "SELECT * FROM alerts", []
    if since is not None:
        sql += " WHERE ts >= ?"
        args.append(since)
    sql += " ORDER BY ts ASC, id ASC"

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
        self._queue = queue.Queue(maxsize=MAX_QUEUE)
        self._thread = None
        self._ready = threading.Event()
        self._stopping = threading.Event()
        # health, read by the GUI
        self.error = None      # why the writer thread died, if it did
        self.dropped = 0       # alerts discarded because the queue was full
        self.rejected = 0      # alerts the database refused (bad data), skipped

    @property
    def failed(self) -> bool:
        """True if the writer thread died while the session was still running."""
        return (self._thread is not None and not self._thread.is_alive()
                and not self._stopping.is_set())

    def start(self, interface=None, config=None):
        self._thread = threading.Thread(
            target=self._run, args=(interface, config), daemon=True, name="horus-db")
        self._thread.start()
        self._ready.wait(timeout=5)

    def submit(self, alert) -> None:
        # called on the sniffing thread: must stay instant and must never block
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            self.dropped += 1

    def flush(self, timeout=3.0) -> bool:
        # Wait until everything submitted so far has been written to the file,
        # so a reader (the CSV export) sees the newest alerts too. Returns True
        # when the queue is fully written; gives up after `timeout` seconds or
        # as soon as the writer thread is dead, so it can never hang the GUI.
        if self._thread is None:
            return True
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if not self._thread.is_alive() or time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    def stop(self) -> None:
        # flush everything still queued, close the session row, close the file
        if self._thread is not None:
            self._stopping.set()
            try:
                self._queue.put_nowait(None)    # wakes an idle writer right away
            except queue.Full:
                pass                            # writer is busy, it will see the flag
            self._thread.join(timeout=5)
            self._thread = None

    # --------------------------------------------------- writer thread
    def _run(self, interface, config):
        conn = None
        try:
            conn = connect(self.path)
            cur = conn.execute(
                "INSERT INTO sessions (started_at, interface, config_json) "
                "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?)",
                (interface, dumps(config) if config else None))
            self.session_id = cur.lastrowid
            conn.commit()
            self._ready.set()

            while True:
                try:
                    item = self._queue.get(timeout=0.5)
                except queue.Empty:
                    if self._stopping.is_set():
                        break
                    continue

                batch = [item]
                # grab whatever else is waiting so a burst is one transaction
                while len(batch) < 200:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break

                try:
                    self._insert(conn, [a for a in batch if a is not None])
                finally:
                    for _ in batch:             # lets flush() see the queue is written
                        self._queue.task_done()
                if self._stopping.is_set() and self._queue.empty():
                    break

            conn.execute(
                "UPDATE sessions SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE id = ?", (self.session_id,))
            conn.commit()
        except Exception as exc:
            self.error = repr(exc)
            print(f"[WARN] Alert database stopped: {exc!r}")
        finally:
            self._ready.set()       # never leave start() waiting
            if conn is not None:
                conn.close()

    def _to_row(self, a):
        return (self.session_id, utc_iso(a.timestamp), a.kind, a.severity,
                a.source, a.target, a.dst_port, a.message,
                dumps(a.details) if a.details else None)

    def _insert(self, conn, alerts):
        # build rows one by one: a single malformed alert must not sink the batch
        rows = []
        for a in alerts:
            try:
                rows.append(self._to_row(a))
            except Exception as exc:
                self._reject(exc)
        if not rows:
            return

        try:
            with conn:
                conn.executemany(INSERT_ALERT, rows)
        except Exception:
            # the whole batch was rolled back because of (at least) one bad row:
            # retry row by row so only the offender is lost
            for row in rows:
                try:
                    with conn:
                        conn.execute(INSERT_ALERT, row)
                except Exception as exc:
                    self._reject(exc)

    def _reject(self, exc):
        self.rejected += 1
        if self.rejected <= 10 or self.rejected % 100 == 0:   # don't flood the console
            print(f"[WARN] Alert not saved ({self.rejected} so far): {exc!r}")