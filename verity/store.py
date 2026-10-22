"""Trace log: every request through the gateway is recorded here.

Two backends, chosen by configuration:
- SQLite (default): a local file — right for local dev, self-hosters
  and the public mock demo. On serverless filesystems it is ephemeral.
- Postgres (DATABASE_URL set, e.g. Neon): traces persist across
  redeploys and carry a per-client identity (a hash prefix of the
  calling client key — never the raw key), so records can be filtered
  per client. Used by real client deployments.
"""
import json
import sqlite3
import tempfile
import time
from pathlib import Path

from . import config

_COLUMNS = ("ts, model, input_text, output_text, latency_ms, blocked,"
            " flags_json, faithfulness, client_id")


def _use_postgres() -> bool:
    url = config.DATABASE_URL or ""
    return url.startswith(("postgres://", "postgresql://"))


# --- SQLite backend ----------------------------------------------------------


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


def _sqlite_init() -> None:
    try:
        _sqlite_init_once()
    except sqlite3.OperationalError:
        fallback = _fallback_path()
        if config.DB_PATH == fallback:
            raise
        config.DB_PATH = fallback
        _sqlite_init_once()


def _sqlite_init_once() -> None:
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
            faithfulness REAL,
            client_id TEXT NOT NULL DEFAULT ''
        )
        """
    )
    # Older databases predate the client_id column.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(traces)")}
    if "client_id" not in cols:
        conn.execute(
            "ALTER TABLE traces ADD COLUMN client_id TEXT NOT NULL"
            " DEFAULT ''")
    conn.commit()
    conn.close()


def _sqlite_log(model, input_text, output_text, latency_ms, blocked,
                flags, faithfulness, client_id) -> int:
    _sqlite_init()
    conn = _connect()
    cur = conn.execute(
        f"INSERT INTO traces ({_COLUMNS})"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (time.time(), model, input_text, output_text, latency_ms,
         int(blocked), json.dumps(list(flags)), faithfulness, client_id),
    )
    conn.commit()
    row_id = cur.lastrowid
    if config.TRACE_RETENTION_DAYS > 0:
        cutoff = time.time() - config.TRACE_RETENTION_DAYS * 86400
        conn.execute("DELETE FROM traces WHERE ts < ?", (cutoff,))
        conn.commit()
    conn.close()
    return row_id


def _sqlite_recent(limit, client_id):
    _sqlite_init()
    conn = _connect()
    if client_id is None:
        rows = conn.execute(
            "SELECT * FROM traces ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM traces WHERE client_id = ?"
            " ORDER BY id DESC LIMIT ?", (client_id, limit)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- Postgres backend --------------------------------------------------------

_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS traces (
    id BIGSERIAL PRIMARY KEY,
    ts DOUBLE PRECISION NOT NULL,
    model TEXT NOT NULL,
    input_text TEXT NOT NULL,
    output_text TEXT NOT NULL,
    latency_ms DOUBLE PRECISION NOT NULL,
    blocked INTEGER NOT NULL DEFAULT 0,
    flags_json TEXT NOT NULL DEFAULT '[]',
    faithfulness DOUBLE PRECISION,
    client_id TEXT NOT NULL DEFAULT ''
)
"""


def _pg_connect():
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(config.DATABASE_URL, row_factory=dict_row)


def _pg_init() -> None:
    with _pg_connect() as conn:
        conn.execute(_PG_SCHEMA)


def _pg_log(model, input_text, output_text, latency_ms, blocked,
            flags, faithfulness, client_id) -> int:
    _pg_init()
    with _pg_connect() as conn:
        row = conn.execute(
            f"INSERT INTO traces ({_COLUMNS})"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (time.time(), model, input_text, output_text, latency_ms,
             int(blocked), json.dumps(list(flags)), faithfulness,
             client_id),
        ).fetchone()
        if config.TRACE_RETENTION_DAYS > 0:
            cutoff = time.time() - config.TRACE_RETENTION_DAYS * 86400
            conn.execute("DELETE FROM traces WHERE ts < %s", (cutoff,))
    return row["id"]


def _pg_recent(limit, client_id):
    _pg_init()
    with _pg_connect() as conn:
        if client_id is None:
            rows = conn.execute(
                "SELECT * FROM traces ORDER BY id DESC LIMIT %s",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM traces WHERE client_id = %s"
                " ORDER BY id DESC LIMIT %s", (client_id, limit),
            ).fetchall()
    return [dict(r) for r in rows]


# --- Public interface --------------------------------------------------------


def init_db() -> None:
    if _use_postgres():
        _pg_init()
    else:
        _sqlite_init()


def log_trace(model, input_text, output_text, latency_ms,
              blocked=False, flags=(), faithfulness=None,
              client_id="") -> int:
    if _use_postgres():
        return _pg_log(model, input_text, output_text, latency_ms,
                       blocked, flags, faithfulness, client_id)
    return _sqlite_log(model, input_text, output_text, latency_ms,
                       blocked, flags, faithfulness, client_id)


def recent_traces(limit=50, client_id=None):
    """Most recent traces; pass client_id to see only one client's."""
    if _use_postgres():
        return _pg_recent(limit, client_id)
    return _sqlite_recent(limit, client_id)


if __name__ == "__main__":
    init_db()
    print("db ready:", "postgres" if _use_postgres()
          else Path(config.DB_PATH).resolve())
