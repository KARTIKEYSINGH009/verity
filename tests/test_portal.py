"""Client accounts: signup/login/sessions, per-user API keys, and the
property that matters — a user can only ever see their own traces."""
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


def _signup(email="priya@acme.example", password="correct horse 9",
            company="Acme"):
    return client.post("/v1/auth/signup", json={
        "email": email, "password": password, "company": company})


def test_signup_issues_key_and_session():
    r = _signup()
    assert r.status_code == 201
    body = r.json()
    assert body["user"]["email"] == "priya@acme.example"
    assert body["user"]["plan"] == "free"
    assert body["api_key"].startswith("vk-")
    assert "verity_session" in r.headers.get("set-cookie", "")
    me = client.get("/v1/me")
    assert me.status_code == 200
    assert me.json()["api_key_hint"].endswith(body["api_key"][-4:])


def test_password_is_stored_hashed():
    _signup()
    user = store.get_user_by_email("priya@acme.example")
    assert user["pw_hash"].startswith("pbkdf2$")
    assert "correct horse" not in user["pw_hash"]


def test_duplicate_email_rejected():
    assert _signup().status_code == 201
    assert _signup().status_code == 409


def test_short_password_rejected():
    r = _signup(password="short")
    assert r.status_code == 400
    assert "password" in r.json()["detail"]["fields"]


def test_login_roundtrip_and_bad_password():
    _signup()
    client.post("/v1/auth/logout")
    assert client.get("/v1/me").status_code == 401
    bad = client.post("/v1/auth/login", json={
        "email": "priya@acme.example", "password": "wrong password"})
    assert bad.status_code == 401
    good = client.post("/v1/auth/login", json={
        "email": "priya@acme.example", "password": "correct horse 9"})
    assert good.status_code == 200
    assert client.get("/v1/me").status_code == 200


def test_login_unknown_email_routes_to_signup():
    r = client.post("/v1/auth/login", json={
        "email": "ghost@nowhere.example", "password": "whatever 123"})
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "account_not_found"


def test_login_google_account_told_to_use_google():
    store.create_user("guser@example.com", "oauth$google", "")
    r = client.post("/v1/auth/login", json={
        "email": "guser@example.com", "password": "whatever 123"})
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "google_account"


def test_me_requires_session():
    assert client.get("/v1/me").status_code == 401


def test_portal_key_authorizes_chat_and_stamps_traces():
    key = _signup().json()["api_key"]
    r = client.post("/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json={"model": "mock",
                          "messages": [{"role": "user",
                                        "content": "What are your "
                                                   "opening hours?"}]})
    assert r.status_code == 200
    me = client.get("/v1/me").json()
    assert me["usage"]["total"] == 1
    assert me["traces"][0]["input_text"].startswith("What are your")


def test_users_cannot_see_each_others_traces():
    key_a = _signup("a@acme.example").json()["api_key"]
    client.post("/v1/chat/completions",
                headers={"Authorization": f"Bearer {key_a}"},
                json={"model": "mock",
                      "messages": [{"role": "user",
                                    "content": "A-secret-question"}]})
    client.post("/v1/auth/logout")
    _signup("b@other.example")
    me_b = client.get("/v1/me").json()
    assert me_b["usage"]["total"] == 0
    assert me_b["traces"] == []


def test_regenerate_revokes_old_key(monkeypatch):
    old_key = _signup().json()["api_key"]
    new_key = client.post("/v1/keys/regenerate").json()["api_key"]
    assert new_key != old_key
    # Keyed deployment: old key must now fail, new key must pass.
    monkeypatch.setattr(config, "CLIENT_KEYS", ["vk-env-key"])
    old = client.post("/v1/chat/completions",
                      headers={"Authorization": f"Bearer {old_key}"},
                      json={"model": "mock", "messages": [
                          {"role": "user", "content": "hi there"}]})
    assert old.status_code == 401
    new = client.post("/v1/chat/completions",
                      headers={"Authorization": f"Bearer {new_key}"},
                      json={"model": "mock", "messages": [
                          {"role": "user", "content": "hi there"}]})
    assert new.status_code == 200


def test_pages_served():
    assert client.get("/pilot").status_code == 200
    assert client.get("/app").status_code == 200
    assert client.get("/documentation").status_code == 200
    assert client.get("/docs").status_code == 404
