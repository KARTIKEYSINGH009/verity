"""Pilot-request endpoint: validation, secret rejection, admin-only reads,
and the store round-trip in both backends."""
import sys
import types

import pytest
from fastapi.testclient import TestClient

from verity import config, store
from verity.gateway import app

client = TestClient(app, raise_server_exceptions=False)

VALID = {
    "company": "Acme Retail Pvt Ltd",
    "email": "priya@acme.example",
    "role": "Head of Support",
    "use_case": "Support chatbot on our storefront answering order "
              "and refund questions.",
    "provider": "OpenAI",
    "volume": "10k-50k / month",
    "challenges": "Users jailbreak it into offering discounts.",
    "timeline": "This quarter",
}


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "DATABASE_URL", "")
    store.init_db()
    yield


def test_valid_request_is_recorded_with_reference():
    r = client.post("/v1/pilot-requests", json=VALID)
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "recorded"
    assert body["reference"].startswith("VR-")
    rows = store.recent_pilot_requests()
    assert len(rows) == 1
    assert rows[0]["company"] == "Acme Retail Pvt Ltd"
    assert rows[0]["email"] == "priya@acme.example"


def test_missing_required_fields_fail_validation():
    r = client.post("/v1/pilot-requests", json={"company": "X"})
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["error"] == "validation_failed"
    assert "email" in detail["fields"]
    assert "use_case" in detail["fields"]


def test_bad_email_fails_validation():
    r = client.post("/v1/pilot-requests",
                    json={**VALID, "email": "not-an-email"})
    assert r.status_code == 400
    assert "email" in r.json()["detail"]["fields"]


def test_secret_shaped_fields_are_rejected():
    for field in ("api_key", "openai_api_key", "password", "auth_token"):
        r = client.post("/v1/pilot-requests", json={**VALID, field: "x"})
        assert r.status_code == 400, field
        assert r.json()["detail"]["error"] == "secrets_not_accepted"
    assert store.recent_pilot_requests() == []


def test_oversized_field_fails_validation():
    r = client.post("/v1/pilot-requests",
                    json={**VALID, "company": "x" * 121})
    assert r.status_code == 400
    assert "company" in r.json()["detail"]["fields"]


def test_list_requires_admin_key(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_KEY", "")
    assert client.get("/v1/pilot-requests").status_code == 403
    monkeypatch.setattr(config, "ADMIN_KEY", "va-test")
    assert client.get("/v1/pilot-requests").status_code == 401
    client.post("/v1/pilot-requests", json=VALID)
    r = client.get("/v1/pilot-requests",
                   headers={"X-Verity-Admin-Key": "va-test"})
    assert r.status_code == 200
    assert r.json()["requests"][0]["company"] == "Acme Retail Pvt Ltd"


def test_intake_can_be_disabled_for_client_deployments(monkeypatch):
    monkeypatch.setattr(config, "PILOT_INTAKE", False)
    r = client.post("/v1/pilot-requests", json=VALID)
    assert r.status_code == 404
    assert store.recent_pilot_requests() == []


def test_postgres_pilot_request_roundtrip(monkeypatch):
    """Same fake-psycopg approach as the trace store tests."""
    executed = []

    class FakeCursor:
        def fetchone(self):
            return {"id": 7}

        def fetchall(self):
            return [{"id": 7, "company": "Acme Retail Pvt Ltd"}]

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            executed.append(" ".join(sql.split()))
            cur = FakeCursor()
            return cur

    fake = types.ModuleType("psycopg")
    fake.connect = lambda url, row_factory=None: FakeConn()
    rows_mod = types.ModuleType("psycopg.rows")
    rows_mod.dict_row = object()
    fake.rows = rows_mod
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    monkeypatch.setitem(sys.modules, "psycopg.rows", rows_mod)
    monkeypatch.setattr(config, "DATABASE_URL", "postgresql://x/y")

    row_id = store.log_pilot_request(**VALID)
    assert row_id == 7
    insert = next(s for s in executed if s.startswith("INSERT"))
    assert "pilot_requests" in insert
    assert store.recent_pilot_requests()[0]["company"] == \
        "Acme Retail Pvt Ltd"
