"""Email-marketing foundation: opt-in capture, preferences toggle,
audience building, unsubscribe tokens, and the send log."""
import time

import pytest
from fastapi.testclient import TestClient

from verity import config, store
from verity.gateway import app

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    monkeypatch.setattr(config, "MOCK_MODE", True)
    store.init_db()
    yield


def _signup(email="m@example.com", **extra):
    body = {"email": email, "password": "correct horse 9"}
    body.update(extra)
    return client.post("/v1/auth/signup", json=body)


def test_opt_in_captured_at_signup():
    assert _signup(marketing_opt_in=True).status_code == 201
    audience = store.marketing_audience()
    assert [u["email"] for u in audience] == ["m@example.com"]
    state = store.get_marketing_state(audience[0]["id"])
    assert state["opt_in"] is True
    assert state["unsubscribe_token"]


def test_no_opt_in_means_no_audience():
    assert _signup().status_code == 201
    assert store.marketing_audience() == []
    assert client.get("/v1/me").json()["marketing_opt_in"] is False


def test_preferences_toggle_roundtrip():
    _signup()
    r = client.post("/v1/me/preferences",
                    json={"marketing_opt_in": True})
    assert r.status_code == 200
    assert client.get("/v1/me").json()["marketing_opt_in"] is True
    r = client.post("/v1/me/preferences",
                    json={"marketing_opt_in": False})
    assert r.status_code == 200
    assert store.marketing_audience() == []
    bad = client.post("/v1/me/preferences",
                      json={"marketing_opt_in": "yes"})
    assert bad.status_code == 400


def test_unsubscribe_by_token():
    _signup(marketing_opt_in=True)
    user = store.marketing_audience()[0]
    token = store.get_marketing_state(user["id"])["unsubscribe_token"]
    r = client.post("/v1/email/unsubscribe", json={"token": token})
    assert r.status_code == 200
    assert store.marketing_audience() == []
    bad = client.post("/v1/email/unsubscribe", json={"token": "nope"})
    assert bad.status_code == 404


def test_send_log_records_campaigns():
    _signup(marketing_opt_in=True)
    user = store.marketing_audience()[0]
    store.record_email_send(user["id"], user["email"], "product_update",
                            "What's new in Verity", time.time())
    log = store.email_log_for("m@example.com")
    assert len(log) == 1
    assert log[0]["kind"] == "product_update"


def test_unsubscribe_page_served():
    assert client.get("/unsubscribe").status_code == 200
