"""Google OAuth flow (provider exchange mocked) and free-plan quota
enforcement at the gateway."""
import pytest
from fastapi.testclient import TestClient

from verity import config, gateway, store
from verity.gateway import app

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    monkeypatch.setattr(config, "MOCK_MODE", True)
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "cid-test")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "secret-test")
    monkeypatch.setattr(config, "FREE_MONTHLY_QUOTA", 1000)
    store.init_db()
    yield


def test_providers_reports_google_configured(monkeypatch):
    assert client.get("/v1/auth/providers").json()["google"] is True
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "")
    assert client.get("/v1/auth/providers").json()["google"] is False
    assert client.get("/v1/auth/google/start").status_code == 404


def test_google_start_redirects_with_state_cookie():
    r = client.get("/v1/auth/google/start", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith(
        "https://accounts.google.com/o/oauth2/v2/auth?")
    assert "verity_oauth_state" in r.headers.get("set-cookie", "")


async def _fake_exchange(code, redirect_uri):
    return "ya29.test-token"


async def _fake_userinfo(token):
    assert token == "ya29.test-token"
    return {"email": "Founder@Example.com", "email_verified": True}


def _run_callback(monkeypatch, userinfo=_fake_userinfo):
    monkeypatch.setattr(gateway, "_google_exchange", _fake_exchange)
    monkeypatch.setattr(gateway, "_google_userinfo", userinfo)
    start = client.get("/v1/auth/google/start", follow_redirects=False)
    state = start.headers["location"].split("state=")[1].split("&")[0]
    return client.get(
        f"/v1/auth/google/callback?code=abc&state={state}",
        follow_redirects=False)


def test_google_callback_creates_account_and_session(monkeypatch):
    r = _run_callback(monkeypatch)
    assert r.status_code == 302
    assert r.headers["location"] == "/dashboard"
    user = store.get_user_by_email("founder@example.com")
    assert user is not None
    assert user["plan"] == "free"
    assert store.active_api_key(user["id"]) is not None
    me = client.get("/v1/me")
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "founder@example.com"


def test_google_callback_rejects_unverified_email(monkeypatch):
    async def unverified(token):
        return {"email": "x@example.com", "email_verified": False}

    r = _run_callback(monkeypatch, userinfo=unverified)
    assert r.status_code == 302
    assert "error=google_unverified" in r.headers["location"]
    assert store.get_user_by_email("x@example.com") is None


def test_google_callback_rejects_state_mismatch(monkeypatch):
    monkeypatch.setattr(gateway, "_google_exchange", _fake_exchange)
    monkeypatch.setattr(gateway, "_google_userinfo", _fake_userinfo)
    client.get("/v1/auth/google/start", follow_redirects=False)
    r = client.get("/v1/auth/google/callback?code=abc&state=forged",
                   follow_redirects=False)
    assert r.status_code == 302
    assert "error=google_state" in r.headers["location"]


def test_free_quota_enforced_for_portal_keys(monkeypatch):
    monkeypatch.setattr(config, "FREE_MONTHLY_QUOTA", 2)
    key = client.post("/v1/auth/signup", json={
        "email": "q@example.com", "password": "correct horse 9",
    }).json()["api_key"]
    payload = {"model": "mock", "messages": [
        {"role": "user", "content": "opening hours?"}]}
    headers = {"Authorization": f"Bearer {key}"}
    assert client.post("/v1/chat/completions", headers=headers,
                       json=payload).status_code == 200
    assert client.post("/v1/chat/completions", headers=headers,
                       json=payload).status_code == 200
    third = client.post("/v1/chat/completions", headers=headers,
                        json=payload)
    assert third.status_code == 429
    assert third.json()["detail"]["error"] == "quota_exceeded"


def test_env_keys_are_quota_exempt(monkeypatch):
    monkeypatch.setattr(config, "FREE_MONTHLY_QUOTA", 1)
    monkeypatch.setattr(config, "CLIENT_KEYS", ["vk-env"])
    headers = {"Authorization": "Bearer vk-env"}
    payload = {"model": "mock", "messages": [
        {"role": "user", "content": "opening hours?"}]}
    for _ in range(3):
        assert client.post("/v1/chat/completions", headers=headers,
                           json=payload).status_code == 200


def test_new_pages_served():
    for path in ("/product", "/playground", "/pricing", "/signup",
                 "/login", "/dashboard", "/pilot", "/documentation"):
        assert client.get(path).status_code == 200, path
    assert client.get("/docs").status_code == 404
