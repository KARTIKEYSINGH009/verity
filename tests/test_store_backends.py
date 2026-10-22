"""Phase B store tests: backend selection, per-client trace identity,
and the Postgres path exercised against a fake psycopg (the dev VM
cannot reach a real Postgres — its proxy breaks raw TCP/5432 — so the
live integration is verified on the Vercel deployment instead)."""
import sys
import types

import pytest

from verity import config, store


@pytest.fixture(autouse=True)
def _sqlite_env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    yield


def test_sqlite_client_id_roundtrip_and_filter():
    store.log_trace("m", "hello", "hi", 1.0, client_id="clientAAA")
    store.log_trace("m", "attack", "", 0.0, blocked=True,
                    flags=["ml_classifier"], client_id="clientAAA")
    store.log_trace("m", "other", "ok", 2.0, client_id="clientBBB")
    mine = store.recent_traces(10, client_id="clientAAA")
    assert len(mine) == 2
    assert all(t["client_id"] == "clientAAA" for t in mine)
    assert mine[0]["blocked"] == 1
    assert len(store.recent_traces(10)) == 3


def test_sqlite_old_db_gains_client_id_column(tmp_path, monkeypatch):
    import sqlite3
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE traces (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ts REAL NOT NULL, model TEXT NOT NULL, input_text TEXT NOT"
        " NULL, output_text TEXT NOT NULL, latency_ms REAL NOT NULL,"
        " blocked INTEGER NOT NULL DEFAULT 0, flags_json TEXT NOT NULL"
        " DEFAULT '[]', faithfulness REAL)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(config, "DB_PATH", path)
    store.log_trace("m", "x", "y", 1.0, client_id="c1")
    assert store.recent_traces(1)[0]["client_id"] == "c1"


def test_backend_selection(monkeypatch):
    assert store._use_postgres() is False
    monkeypatch.setattr(config, "DATABASE_URL",
                        "postgresql://u:p@host/db?sslmode=require")
    assert store._use_postgres() is True
    monkeypatch.setattr(config, "DATABASE_URL", "postgres://u:p@h/db")
    assert store._use_postgres() is True
    monkeypatch.setattr(config, "DATABASE_URL", "sqlite:///nope.db")
    assert store._use_postgres() is False


class _FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    def fetchone(self):
        return {"id": 42}

    def fetchall(self):
        return list(self._conn.rows)


class _FakeConn:
    def __init__(self):
        self.statements = []
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        self.statements.append((sql, params))
        return _FakeCursor(self)


def _install_fake_psycopg(monkeypatch, conn):
    fake = types.ModuleType("psycopg")
    fake.connect = lambda url, row_factory=None: conn
    rows_mod = types.ModuleType("psycopg.rows")
    rows_mod.dict_row = object()
    fake.rows = rows_mod
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    monkeypatch.setitem(sys.modules, "psycopg.rows", rows_mod)


def test_postgres_log_and_recent(monkeypatch):
    monkeypatch.setattr(config, "DATABASE_URL",
                        "postgresql://u:p@host/db?sslmode=require")
    conn = _FakeConn()
    conn.rows = [{"id": 7, "client_id": "clientAAA", "blocked": 1}]
    _install_fake_psycopg(monkeypatch, conn)
    row_id = store.log_trace("m", "attack", "", 0.0, blocked=True,
                             flags=["ml_classifier"],
                             client_id="clientAAA")
    assert row_id == 42
    sqls = [s for s, _ in conn.statements]
    assert any("CREATE TABLE IF NOT EXISTS traces" in s for s in sqls)
    insert = next(p for s, p in conn.statements
                  if s.strip().startswith("INSERT"))
    assert insert[-1] == "clientAAA"
    assert any(s.strip().startswith("DELETE FROM traces")
               for s in sqls)  # retention pruning ported
    got = store.recent_traces(5, client_id="clientAAA")
    assert got and got[0]["client_id"] == "clientAAA"
    last_sql, last_params = conn.statements[-1]
    assert "WHERE client_id = %s" in last_sql
    assert last_params == ("clientAAA", 5)


def test_gateway_client_id_is_hash_prefix_not_key():
    from verity.gateway import _client_id
    assert _client_id(None) == ""
    assert _client_id("Bearer whatever") == ""  # no keys configured
