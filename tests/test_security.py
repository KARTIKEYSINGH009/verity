"""API-security regression tests (audit round 3, section 5).

Covers: traces authorization, request size limits, rate limiting, and
malformed-input handling on the public gateway.
"""
import pytest
from fastapi.testclient import TestClient

from verity import config, gateway
from verity.gateway import app

CHAT = {"model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "hello"}]}


@pytest.fixture(autouse=True)
def _clean_rate_state():
    gateway._hits.clear()
    yield
    gateway._hits.clear()


def test_traces_disabled_without_admin_key(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_KEY", "")
    with TestClient(app) as c:
        r = c.get("/v1/traces")
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "traces_disabled"


def test_traces_require_the_admin_key(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_KEY", "test-secret")
    with TestClient(app) as c:
        assert c.get("/v1/traces").status_code == 401
        assert c.get("/v1/traces",
                     headers={"X-Verity-Admin-Key": "wrong"}).status_code == 401
        ok = c.get("/v1/traces",
                   headers={"X-Verity-Admin-Key": "test-secret"})
    assert ok.status_code == 200 and "traces" in ok.json()


def test_oversized_input_rejected(monkeypatch):
    monkeypatch.setattr(config, "MAX_INPUT_CHARS", 10)
    with TestClient(app) as c:
        r = c.post("/v1/chat/completions", json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user",
                          "content": "this message is far longer than ten"}]})
    assert r.status_code == 413
    assert r.json()["detail"]["error"] == "request_too_large"


def test_rate_limit_trips(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_PER_MIN", 3)
    with TestClient(app) as c:
        codes = [c.post("/v1/chat/completions", json=CHAT).status_code
                 for _ in range(4)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429


def test_malformed_json_gets_422_not_crash():
    with TestClient(app) as c:
        r = c.post("/v1/chat/completions", content="{not json",
                   headers={"Content-Type": "application/json"})
    assert r.status_code == 422


def test_empty_messages_get_422():
    with TestClient(app) as c:
        r = c.post("/v1/chat/completions",
                   json={"model": "gpt-4o-mini", "messages": []})
    assert r.status_code == 422
