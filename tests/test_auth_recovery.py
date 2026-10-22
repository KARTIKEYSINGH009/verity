"""Email verification + password reset.

Covers: verification gating of portal API keys (active only once a
sender is configured), the one-time token lifecycle, resend, the
reset flow (which also verifies the email and revokes sessions),
disposable-domain rejection, and honest behaviour when no email
sender exists."""
import re

import pytest
from fastapi.testclient import TestClient

from verity import config, gateway, mailer, store

_TOKEN_RE = re.compile(r"token=([A-Za-z0-9_\-]+)")
_CHAT = {"model": "mock",
         "messages": [{"role": "user", "content": "Where is my order?"}]}


_client = TestClient(gateway.app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(config, "MOCK_MODE", True)
    monkeypatch.setattr(config, "CLIENT_KEYS", {})
    monkeypatch.setattr(config, "ADMIN_KEY", "test-admin")
    monkeypatch.setattr(config, "RATE_LIMIT_PER_MIN", 100000)
    store.init_db()
    yield


@pytest.fixture()
def client():
    return _client


@pytest.fixture()
def mail_client(monkeypatch):
    sent = []

    def fake_send(to, subject, text):
        sent.append({"to": to, "subject": subject, "text": text})
        return True

    monkeypatch.setattr(config, "RESEND_API_KEY", "test-key")
    monkeypatch.setattr(config, "EMAIL_FROM",
                        "Verity <no-reply@verity.example>")
    monkeypatch.setattr(mailer, "send_email", fake_send)
    _client.sent = sent
    return _client


def _signup(client, email, password="correct horse 9", **extra):
    body = {"email": email, "password": password, "company": "Acme"}
    body.update(extra)
    return client.post("/v1/auth/signup", json=body)


def _token(sent, needle):
    for mail in sent:
        if needle in mail["text"]:
            return _TOKEN_RE.search(mail["text"]).group(1)
    raise AssertionError(f"no captured email containing {needle}")


def test_signup_unverified_until_email_verified(mail_client):
    r = _signup(mail_client, "new@acme.example")
    assert r.status_code == 201
    data = r.json()
    assert data["email_verified"] is False
    assert data["email_delivery"] is True
    key = data["api_key"]
    blocked = mail_client.post(
        "/v1/chat/completions", json=_CHAT,
        headers={"Authorization": f"Bearer {key}"})
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["error"] == "email_not_verified"

    token = _token(mail_client.sent, "/verify-email")
    ok = mail_client.post("/v1/auth/verify-email", json={"token": token})
    assert ok.status_code == 200

    allowed = mail_client.post(
        "/v1/chat/completions", json=_CHAT,
        headers={"Authorization": f"Bearer {key}"})
    assert allowed.status_code == 200

    again = mail_client.post("/v1/auth/verify-email",
                             json={"token": token})
    assert again.status_code == 400  # single use


def test_signup_verified_immediately_without_sender(client):
    r = _signup(client, "plain@acme.example")
    assert r.status_code == 201
    assert r.json()["email_verified"] is True
    assert r.json()["email_delivery"] is None
    ok = client.post("/v1/chat/completions", json=_CHAT, headers={
        "Authorization": f"Bearer {r.json()['api_key']}"})
    assert ok.status_code == 200


def test_disposable_email_rejected(client):
    r = _signup(client, "junk@mailinator.com")
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "disposable_email"
    login = client.post("/v1/auth/login", json={
        "email": "junk@mailinator.com", "password": "correct horse 9"})
    assert login.status_code == 404  # no account was created


def test_resend_verification_replaces_token(mail_client):
    _signup(mail_client, "resend@acme.example")
    old = _token(mail_client.sent, "/verify-email")
    mail_client.sent.clear()
    r = mail_client.post("/v1/auth/resend-verification")
    assert r.status_code == 200
    new = _token(mail_client.sent, "/verify-email")
    assert new != old
    stale = mail_client.post("/v1/auth/verify-email",
                             json={"token": old})
    assert stale.status_code == 400
    fresh = mail_client.post("/v1/auth/verify-email",
                             json={"token": new})
    assert fresh.status_code == 200
    done = mail_client.post("/v1/auth/resend-verification")
    assert done.json()["status"] == "already_verified"


def test_forgot_reset_full_cycle(mail_client):
    r = _signup(mail_client, "reset@acme.example")
    key = r.json()["api_key"]
    mail_client.post("/v1/auth/verify-email", json={
        "token": _token(mail_client.sent, "/verify-email")})
    mail_client.sent.clear()

    fr = mail_client.post("/v1/auth/forgot-password",
                          json={"email": "reset@acme.example"})
    assert fr.status_code == 200
    assert fr.json()["email_delivery"] is True
    token = _token(mail_client.sent, "/reset-password")

    done = mail_client.post("/v1/auth/reset-password", json={
        "token": token, "password": "brand new pass 9"})
    assert done.status_code == 200

    # The pre-reset session was revoked.
    assert mail_client.get("/v1/me").status_code == 401
    # Old password is dead, the new one signs in.
    old = mail_client.post("/v1/auth/login", json={
        "email": "reset@acme.example", "password": "correct horse 9"})
    assert old.status_code == 401
    new = mail_client.post("/v1/auth/login", json={
        "email": "reset@acme.example", "password": "brand new pass 9"})
    assert new.status_code == 200
    # Token cannot be replayed.
    replay = mail_client.post("/v1/auth/reset-password", json={
        "token": token, "password": "another pass 123"})
    assert replay.status_code == 400


def test_reset_also_verifies_email(mail_client):
    r = _signup(mail_client, "unverified@acme.example")
    key = r.json()["api_key"]
    mail_client.sent.clear()
    mail_client.post("/v1/auth/forgot-password",
                     json={"email": "unverified@acme.example"})
    token = _token(mail_client.sent, "/reset-password")
    done = mail_client.post("/v1/auth/reset-password", json={
        "token": token, "password": "fresh start 42"})
    assert done.status_code == 200
    ok = mail_client.post("/v1/chat/completions", json=_CHAT, headers={
        "Authorization": f"Bearer {key}"})
    assert ok.status_code == 200  # key active: reset proved the inbox


def test_forgot_unknown_email_is_generic(mail_client):
    r = mail_client.post("/v1/auth/forgot-password",
                         json={"email": "ghost@nowhere.example"})
    assert r.status_code == 200
    assert r.json()["email_delivery"] is False
    assert mail_client.sent == []


def test_forgot_google_account_gets_no_reset(mail_client):
    store.create_user("goog@acme.example", "oauth$google", "")
    r = mail_client.post("/v1/auth/forgot-password",
                         json={"email": "goog@acme.example"})
    assert r.status_code == 200
    assert r.json()["email_delivery"] is False
    assert mail_client.sent == []


def test_bogus_tokens_rejected(mail_client):
    v = mail_client.post("/v1/auth/verify-email",
                         json={"token": "nonsense-token"})
    assert v.status_code == 400
    r = mail_client.post("/v1/auth/reset-password", json={
        "token": "nonsense-token", "password": "whatever 123"})
    assert r.status_code == 400
    weak = mail_client.post("/v1/auth/reset-password", json={
        "token": "nonsense-token", "password": "short"})
    assert weak.status_code == 400
    assert weak.json()["detail"]["fields"] == ["password"]


def test_recovery_pages_served(client):
    for path in ("/forgot-password", "/reset-password", "/verify-email"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert "Verity" in r.text


def test_signup_rejects_nonstring_email(client):
    r = client.post("/v1/auth/signup", json={
        "email": ["a@b.co"], "password": "whatever 123"})
    assert r.status_code == 400
    assert r.json()["detail"]["fields"] == ["email"]


def test_login_rejects_null_credentials(client):
    r = client.post("/v1/auth/login", json={
        "email": None, "password": None})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "validation_failed"


def test_store_strips_nul_and_surrogates(client):
    """Postgres TEXT rejects NUL bytes and lone surrogates (SQLite
    tolerates both — the production-only 500 from the round-2 fuzz).
    Everything persisted must be cleaned at the store boundary."""
    tid = store.log_trace("mock", "a\x00b\ud800c", "out\x00put", 1.5,
                          blocked=False, flags=(), faithfulness=None,
                          client_id="fuzz")
    rows = store.recent_traces(5, client_id="fuzz")
    row = [r for r in rows if r["id"] == tid][0]
    assert "\x00" not in row["input_text"]
    assert "\x00" not in row["output_text"]
    assert row["input_text"] == "ab?c"
