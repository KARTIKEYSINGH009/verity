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
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pilot_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            company TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT '',
            use_case TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT '',
            volume TEXT NOT NULL DEFAULT '',
            challenges TEXT NOT NULL DEFAULT '',
            timeline TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            pw_hash TEXT NOT NULL,
            company TEXT NOT NULL DEFAULT '',
            plan TEXT NOT NULL DEFAULT 'free',
            email_verified INTEGER NOT NULL DEFAULT 1,
            created_ts REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            purpose TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_ts REAL NOT NULL,
            expires_ts REAL NOT NULL,
            used_ts REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_ts REAL NOT NULL,
            expires_ts REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            key_hint TEXT NOT NULL DEFAULT '',
            created_ts REAL NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )
        """
    )
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
);
CREATE TABLE IF NOT EXISTS pilot_requests (
    id BIGSERIAL PRIMARY KEY,
    ts DOUBLE PRECISION NOT NULL,
    company TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT '',
    use_case TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    volume TEXT NOT NULL DEFAULT '',
    challenges TEXT NOT NULL DEFAULT '',
    timeline TEXT NOT NULL DEFAULT ''
)
"""

_PG_PORTAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    company TEXT NOT NULL DEFAULT '',
    plan TEXT NOT NULL DEFAULT 'free',
    email_verified INTEGER NOT NULL DEFAULT 1,
    created_ts DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    purpose TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_ts DOUBLE PRECISION NOT NULL,
    expires_ts DOUBLE PRECISION NOT NULL,
    used_ts DOUBLE PRECISION
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    created_ts DOUBLE PRECISION NOT NULL,
    expires_ts DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_hint TEXT NOT NULL DEFAULT '',
    created_ts DOUBLE PRECISION NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
)
"""

_PILOT_COLUMNS = ("ts, company, email, role, use_case, provider,"
                  " volume, challenges, timeline")


def _pg_connect():
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(config.DATABASE_URL, row_factory=dict_row)


def _pg_init() -> None:
    with _pg_connect() as conn:
        conn.execute(_PG_SCHEMA)
        conn.execute(_PG_PORTAL_SCHEMA)


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


def _sqlite_log_pilot_request(values) -> int:
    _sqlite_init()
    conn = _connect()
    cur = conn.execute(
        f"INSERT INTO pilot_requests ({_PILOT_COLUMNS})"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (time.time(), *values),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def _pg_log_pilot_request(values) -> int:
    _pg_init()
    with _pg_connect() as conn:
        row = conn.execute(
            f"INSERT INTO pilot_requests ({_PILOT_COLUMNS})"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (time.time(), *values),
        ).fetchone()
    return row["id"]


def log_pilot_request(company, email, role="", use_case="", provider="",
                      volume="", challenges="", timeline="") -> int:
    """Record a pilot request from the public /pilot form. Contact and
    scoping details only — never credentials (the endpoint rejects
    secret-shaped fields before this is called)."""
    values = (company, email, role, use_case, provider, volume,
              challenges, timeline)
    if _use_postgres():
        return _pg_log_pilot_request(values)
    return _sqlite_log_pilot_request(values)


def recent_pilot_requests(limit=50):
    if _use_postgres():
        _pg_init()
        with _pg_connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pilot_requests ORDER BY id DESC LIMIT %s",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    _sqlite_init()
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM pilot_requests ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- Client accounts (portal) ------------------------------------------------
# Users sign up on the site, get a personal API key, and see only their
# own traces. Passwords are stored as salted PBKDF2 hashes (computed in
# the gateway); API keys are stored as SHA-256 hashes — the plaintext is
# shown once at issuance and can never be recovered from the database.
# A key's trace identity (client_id) is the first 12 hex chars of its
# hash, the same scheme the gateway uses for env-configured keys.


class DuplicateEmail(Exception):
    pass


def _rows(sqlite_sql, pg_sql, params=(), fetch="all"):
    if _use_postgres():
        _pg_init()
        with _pg_connect() as conn:
            cur = conn.execute(pg_sql, params)
            if fetch == "one":
                row = cur.fetchone()
                return dict(row) if row else None
            if fetch == "none":
                if "RETURNING" in pg_sql.upper():
                    row = cur.fetchone()
                    return row["id"] if row else None
                return None
            return [dict(r) for r in cur.fetchall()]
    _sqlite_init()
    conn = _connect()
    cur = conn.execute(sqlite_sql, params)
    if fetch == "one":
        row = cur.fetchone()
        result = dict(row) if row else None
    elif fetch == "none":
        result = cur.lastrowid
    else:
        result = [dict(r) for r in cur.fetchall()]
    conn.commit()
    conn.close()
    return result


def create_user(email, pw_hash, company="", email_verified=True) -> int:
    _ensure_auth_schema()
    try:
        return _rows(
            "INSERT INTO users (email, pw_hash, company,"
            " email_verified, created_ts) VALUES (?, ?, ?, ?, ?)",
            "INSERT INTO users (email, pw_hash, company,"
            " email_verified, created_ts)"
            " VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (email, pw_hash, company, 1 if email_verified else 0,
             time.time()), fetch="none")
    except Exception as exc:  # unique violation, either backend
        if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
            raise DuplicateEmail(email) from exc
        raise


def get_user_by_email(email):
    return _rows("SELECT * FROM users WHERE email = ?",
                 "SELECT * FROM users WHERE email = %s",
                 (email,), fetch="one")


def get_user_by_id(user_id):
    return _rows("SELECT * FROM users WHERE id = ?",
                 "SELECT * FROM users WHERE id = %s",
                 (user_id,), fetch="one")


def create_session(user_id, token_hash, ttl_seconds) -> None:
    now = time.time()
    _rows("INSERT INTO sessions (token_hash, user_id, created_ts,"
          " expires_ts) VALUES (?, ?, ?, ?)",
          "INSERT INTO sessions (token_hash, user_id, created_ts,"
          " expires_ts) VALUES (%s, %s, %s, %s)",
          (token_hash, user_id, now, now + ttl_seconds), fetch="none")


def get_user_by_session(token_hash):
    row = _rows("SELECT user_id, expires_ts FROM sessions"
                " WHERE token_hash = ?",
                "SELECT user_id, expires_ts FROM sessions"
                " WHERE token_hash = %s",
                (token_hash,), fetch="one")
    if not row:
        return None
    if row["expires_ts"] < time.time():
        delete_session(token_hash)
        return None
    return get_user_by_id(row["user_id"])


def delete_session(token_hash) -> None:
    _rows("DELETE FROM sessions WHERE token_hash = ?",
          "DELETE FROM sessions WHERE token_hash = %s",
          (token_hash,), fetch="none")


# --- Auth security: email verification + one-time tokens ----------------

def _ensure_auth_schema() -> None:
    """Adds email_verified (existing accounts grandfathered as
    verified) and the auth_tokens table to databases created before
    this feature existed. Idempotent; runs per call like the
    marketing-columns migration (a once-per-process flag breaks when
    the database file changes under the process)."""
    if _use_postgres():
        _exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS"
              " email_verified INTEGER NOT NULL DEFAULT 1",
              "ALTER TABLE users ADD COLUMN IF NOT EXISTS"
              " email_verified INTEGER NOT NULL DEFAULT 1", ())
        _exec("CREATE TABLE IF NOT EXISTS auth_tokens ("
              " id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL,"
              " purpose TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,"
              " created_ts DOUBLE PRECISION NOT NULL,"
              " expires_ts DOUBLE PRECISION NOT NULL,"
              " used_ts DOUBLE PRECISION)",
              "CREATE TABLE IF NOT EXISTS auth_tokens ("
              " id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL,"
              " purpose TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,"
              " created_ts DOUBLE PRECISION NOT NULL,"
              " expires_ts DOUBLE PRECISION NOT NULL,"
              " used_ts DOUBLE PRECISION)", ())
    else:
        cols = [r["name"] for r in _rows(
            "SELECT name FROM pragma_table_info('users')",
            "SELECT name FROM pragma_table_info('users')", ())]
        if "email_verified" not in cols:
            _exec("ALTER TABLE users ADD COLUMN email_verified"
                  " INTEGER NOT NULL DEFAULT 1",
                  "ALTER TABLE users ADD COLUMN email_verified"
                  " INTEGER NOT NULL DEFAULT 1", ())
        _exec("CREATE TABLE IF NOT EXISTS auth_tokens ("
              " id INTEGER PRIMARY KEY AUTOINCREMENT,"
              " user_id INTEGER NOT NULL, purpose TEXT NOT NULL,"
              " token_hash TEXT NOT NULL UNIQUE,"
              " created_ts REAL NOT NULL, expires_ts REAL NOT NULL,"
              " used_ts REAL)",
              "CREATE TABLE IF NOT EXISTS auth_tokens ("
              " id INTEGER PRIMARY KEY AUTOINCREMENT,"
              " user_id INTEGER NOT NULL, purpose TEXT NOT NULL,"
              " token_hash TEXT NOT NULL UNIQUE,"
              " created_ts REAL NOT NULL, expires_ts REAL NOT NULL,"
              " used_ts REAL)", ())


def get_email_verified(user_id) -> bool:
    _ensure_auth_schema()
    row = _rows("SELECT email_verified FROM users WHERE id = ?",
                "SELECT email_verified FROM users WHERE id = %s",
                (user_id,), fetch="one")
    return bool(row and row["email_verified"])


def set_email_verified(user_id) -> None:
    _ensure_auth_schema()
    _exec("UPDATE users SET email_verified = 1 WHERE id = ?",
          "UPDATE users SET email_verified = 1 WHERE id = %s",
          (user_id,))


def update_user_password(user_id, pw_hash) -> None:
    _exec("UPDATE users SET pw_hash = ? WHERE id = ?",
          "UPDATE users SET pw_hash = %s WHERE id = %s",
          (pw_hash, user_id))


def delete_user_sessions(user_id) -> None:
    _rows("DELETE FROM sessions WHERE user_id = ?",
          "DELETE FROM sessions WHERE user_id = %s",
          (user_id,), fetch="none")


def issue_auth_token(user_id, purpose, token_hash, expires_ts) -> None:
    """One live token per user+purpose: issuing replaces the old one."""
    _ensure_auth_schema()
    _exec("DELETE FROM auth_tokens WHERE user_id = ? AND purpose = ?",
          "DELETE FROM auth_tokens WHERE user_id = %s"
          " AND purpose = %s", (user_id, purpose))
    _exec("INSERT INTO auth_tokens (user_id, purpose, token_hash,"
          " created_ts, expires_ts) VALUES (?, ?, ?, ?, ?)",
          "INSERT INTO auth_tokens (user_id, purpose, token_hash,"
          " created_ts, expires_ts) VALUES (%s, %s, %s, %s, %s)",
          (user_id, purpose, token_hash, time.time(), expires_ts))


def get_auth_token(token_hash, purpose):
    _ensure_auth_schema()
    return _rows("SELECT * FROM auth_tokens WHERE token_hash = ?"
                 " AND purpose = ?",
                 "SELECT * FROM auth_tokens WHERE token_hash = %s"
                 " AND purpose = %s",
                 (token_hash, purpose), fetch="one")


def consume_auth_token(token_id) -> None:
    _exec("UPDATE auth_tokens SET used_ts = ? WHERE id = ?",
          "UPDATE auth_tokens SET used_ts = %s WHERE id = %s",
          (time.time(), token_id))


# --- Email marketing: opt-in state, unsubscribe tokens, send log ---------

def _exec(sqlite_sql, pg_sql, params) -> None:
    _rows(sqlite_sql, pg_sql, params, fetch="none")

def _ensure_marketing_columns() -> None:
    if _use_postgres():
        for stmt in (
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS"
                " marketing_opt_in INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS"
                " unsubscribe_token TEXT"):
            _exec(stmt, stmt, ())
    else:
        cols = [r["name"] for r in _rows(
            "SELECT name FROM pragma_table_info('users')",
            "SELECT name FROM pragma_table_info('users')", ())]
        if "marketing_opt_in" not in cols:
            _exec("ALTER TABLE users ADD COLUMN marketing_opt_in"
                  " INTEGER NOT NULL DEFAULT 0",
                  "ALTER TABLE users ADD COLUMN marketing_opt_in"
                  " INTEGER NOT NULL DEFAULT 0", ())
        if "unsubscribe_token" not in cols:
            _exec("ALTER TABLE users ADD COLUMN unsubscribe_token TEXT",
                  "ALTER TABLE users ADD COLUMN unsubscribe_token TEXT",
                  ())
    _exec(
        "CREATE TABLE IF NOT EXISTS email_log ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " user_id INTEGER, email TEXT NOT NULL, kind TEXT NOT NULL,"
        " subject TEXT NOT NULL, sent_ts REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS email_log ("
        " id BIGSERIAL PRIMARY KEY,"
        " user_id BIGINT, email TEXT NOT NULL, kind TEXT NOT NULL,"
        " subject TEXT NOT NULL, sent_ts DOUBLE PRECISION NOT NULL)",
        ())


def get_marketing_state(user_id) -> dict:
    _ensure_marketing_columns()
    row = _rows("SELECT marketing_opt_in, unsubscribe_token FROM users"
                " WHERE id = ?",
                "SELECT marketing_opt_in, unsubscribe_token FROM users"
                " WHERE id = %s", (user_id,), fetch="one")
    if not row:
        return {"opt_in": False, "unsubscribe_token": None}
    return {"opt_in": bool(row["marketing_opt_in"]),
            "unsubscribe_token": row["unsubscribe_token"]}


def set_marketing_opt_in(user_id, opt_in, unsubscribe_token=None) -> None:
    _ensure_marketing_columns()
    if unsubscribe_token:
        _exec("UPDATE users SET marketing_opt_in = ?,"
              " unsubscribe_token = ? WHERE id = ?",
              "UPDATE users SET marketing_opt_in = %s,"
              " unsubscribe_token = %s WHERE id = %s",
              (1 if opt_in else 0, unsubscribe_token, user_id))
    else:
        _exec("UPDATE users SET marketing_opt_in = ? WHERE id = ?",
              "UPDATE users SET marketing_opt_in = %s WHERE id = %s",
              (1 if opt_in else 0, user_id))


def get_user_by_unsubscribe_token(token):
    if not token:
        return None
    _ensure_marketing_columns()
    return _rows("SELECT * FROM users WHERE unsubscribe_token = ?",
                 "SELECT * FROM users WHERE unsubscribe_token = %s",
                 (token,), fetch="one")


def marketing_audience() -> list:
    """Users who opted IN to product emails — the only addresses a
    campaign may go to."""
    _ensure_marketing_columns()
    rows = _rows("SELECT * FROM users WHERE marketing_opt_in = 1",
                 "SELECT * FROM users WHERE marketing_opt_in = 1", ())
    return [dict(r) for r in rows]


def record_email_send(user_id, email, kind, subject, sent_ts) -> None:
    _ensure_marketing_columns()
    _exec("INSERT INTO email_log (user_id, email, kind, subject,"
          " sent_ts) VALUES (?, ?, ?, ?, ?)",
          "INSERT INTO email_log (user_id, email, kind, subject,"
          " sent_ts) VALUES (%s, %s, %s, %s, %s)",
          (user_id, email, kind, subject, sent_ts))


def email_log_for(email) -> list:
    _ensure_marketing_columns()
    rows = _rows("SELECT * FROM email_log WHERE email = ?"
                 " ORDER BY sent_ts",
                 "SELECT * FROM email_log WHERE email = %s"
                 " ORDER BY sent_ts", (email,))
    return [dict(r) for r in rows]



def issue_api_key(user_id, key_hash, key_hint) -> int:
    return _rows(
        "INSERT INTO api_keys (user_id, key_hash, key_hint, created_ts)"
        " VALUES (?, ?, ?, ?)",
        "INSERT INTO api_keys (user_id, key_hash, key_hint, created_ts)"
        " VALUES (%s, %s, %s, %s) RETURNING id",
        (user_id, key_hash, key_hint, time.time()), fetch="none")


def find_api_key(key_hash):
    return _rows("SELECT * FROM api_keys WHERE key_hash = ?"
                 " AND revoked = 0",
                 "SELECT * FROM api_keys WHERE key_hash = %s"
                 " AND revoked = 0",
                 (key_hash,), fetch="one")


def active_api_key(user_id):
    return _rows("SELECT * FROM api_keys WHERE user_id = ?"
                 " AND revoked = 0 ORDER BY id DESC LIMIT 1",
                 "SELECT * FROM api_keys WHERE user_id = %s"
                 " AND revoked = 0 ORDER BY id DESC LIMIT 1",
                 (user_id,), fetch="one")


def revoke_api_keys(user_id) -> None:
    _rows("UPDATE api_keys SET revoked = 1 WHERE user_id = ?",
          "UPDATE api_keys SET revoked = 1 WHERE user_id = %s",
          (user_id,), fetch="none")


def usage_for_client(client_id, since_ts=None) -> dict:
    """Usage aggregates for one client identity. `month_total` counts
    traces at or after `since_ts` (the free-quota window); avg latency
    is over all of the client's traces."""
    row = _rows(
        "SELECT COUNT(*) AS total,"
        " COALESCE(SUM(blocked), 0) AS blocked,"
        " COALESCE(AVG(latency_ms), 0) AS avg_latency,"
        " COALESCE(SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END), 0)"
        " AS month_total FROM traces WHERE client_id = ?",
        "SELECT COUNT(*) AS total,"
        " COALESCE(SUM(blocked), 0) AS blocked,"
        " COALESCE(AVG(latency_ms), 0) AS avg_latency,"
        " COALESCE(SUM(CASE WHEN ts >= %s THEN 1 ELSE 0 END), 0)"
        " AS month_total FROM traces WHERE client_id = %s",
        (since_ts or 0, client_id), fetch="one")
    if not row:
        return {"total": 0, "blocked": 0, "avg_latency_ms": 0,
                "month_total": 0}
    return {"total": int(row["total"]),
            "blocked": int(row["blocked"]),
            "avg_latency_ms": round(float(row["avg_latency"]), 1),
            "month_total": int(row["month_total"])}


if __name__ == "__main__":
    init_db()
    print("db ready:", "postgres" if _use_postgres()
          else Path(config.DB_PATH).resolve())
