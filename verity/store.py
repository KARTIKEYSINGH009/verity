"""SQLite trace log: every request through the gateway is recorded here."""
import json
import sqlite3
import tempfile
import time
from pathlib import Path

from . import config


def _fallback_path() -> str:
    return str(Path(tempfile.gettempdir()) / "verity.db")


def _connect():
    try:
        conn = sqlite3.connect(config.DB_PATH)
    except sqlite3.OperationalError:
        # Configured path is unwritable (e.g. read-only serverless
        # filesystem): fall back to the temp dir instead of crashing.
        fallback = _fallback_path()
        if config.DB_PATH == fallback:
            raise
        config.DB_PATH = fallback
        conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    try:
        _init_db_once()
    except sqlite3.OperationalError:
        fallback = _fallback_path()
        if config.DB_PATH == fallback:
            raise
        config.DB_PATH = fallback
        _init_db_once()


def _init_db_once() -> None:
    conn = _connect()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS traces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            model TEXT NOT NULL,
            input_text TEXT NOT NULL,
            output_text TEXT NOT NULL,
            latency_ms REAL NOT NULL,
            blocked INTEGER NOT NULL DEFAULT 0,
            flags_json TEXT NOT NULL DEFAULT '[]',
            faithfulness REAL
        )
        """
    )
    conn.commit()
    conn.close()


def log_trace(model, input_text, output_text, latency_ms,
              blocked=False, flags=(), faithfulness=None) -> int:
    init_db()
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO traces (ts, model, input_text, output_text, latency_ms,"
        " blocked, flags_json, faithfulness)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (time.time(), model, input_text, output_text, latency_ms,
         int(blocked), json.dumps(list(flags)), faithfulness),
    )
    conn.commit()
    row_id = cur.lastrowid
    if config.TRACE_RETENTION_DAYS > 0:
        cutoff = time.time() - config.TRACE_RETENTION_DAYS * 86400
        conn.execute("DELETE FROM traces WHERE ts < ?", (cutoff,))
        conn.commit()
    conn.close()
    return row_id


def recent_traces(limit=50):
    init_db()
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM traces ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    print("db ready at", Path(config.DB_PATH).resolve())
