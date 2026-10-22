"""Regression tests for the second security findings batch (F1-F5):
XFF-independent rate-limit buckets, canonical email-link base,
dashboard fail-closed, body-size/message caps, atomic token claim."""
import hashlib
import os
import threading

import pytest
from fastapi.testclient import TestClient

from verity import config, mailer, store
from verity.gateway import app

client = TestClient(app, raise_server_exceptions=False)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    monkeypatch.setattr(config, "MOCK_MODE", True)
    store.init_db()
    yield


def _signup(email="b2@example.com"):
    r = client.post("/v1/auth/signup", json={
        "email": email, "password": "correct horse 9", "company": "Acme"})
    assert r.status_code == 201
    return r.json()["api_key"]


# --- F1: buckets that IP rotation cannot reset -----------------------

def test_f1_chat_limited_per_api_key_across_ips(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_PER_MIN", 3)
    key = _signup()
    payload = {"model": "mock", "messages": [
        {"role": "user", "content": "opening hours?"}]}
    for i in range(3):
        r = client.post("/v1/chat/completions",
                        headers={"Authorization": f"Bearer {key}",
                                 "X-Forwarded-For": f"10.0.0.{i}"},
                        json=payload)
        assert r.status_code == 200
    r = client.post("/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}",
                             "X-Forwarded-For": "10.9.9.9"},
                    json=payload)
    assert r.status_code == 429


def test_f1_login_limited_per_email_across_ips(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_PER_MIN", 3)
    _signup("victim@example.com")  # 1 email-bucket hit
    client.post("/v1/auth/logout")
    codes = []
    for i in range(3):
        r = client.post("/v1/auth/login",
                        headers={"X-Forwarded-For": f"10.1.0.{i}"},
                        json={"email": "victim@example.com",
                              "password": "wrong password"})
        codes.append(r.status_code)
    assert codes == [401, 401, 429]


# --- F2: email links never derive from a request host ----------------

@pytest.fixture()
def mail_capture(monkeypatch):
    sent = []
    monkeypatch.setattr(config, "RESEND_API_KEY", "test-key")
    monkeypatch.setattr(config, "EMAIL_FROM", "Verity <no-reply@x.example>")
    monkeypatch.setattr(mailer, "send_email",
                        lambda to, subject, text:
                        sent.append({"to": to, "text": text}) or True)
    return sent


def test_f2_reset_link_refused_for_foreign_host(mail_capture, monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "")
    _signup("host-victim@example.com")
    mail_capture.clear()
    r = client.post("/v1/auth/forgot-password",
                    headers={"Host": "evil.example"},
                    json={"email": "host-victim@example.com"})
    assert r.status_code == 200
    assert r.json()["email_delivery"] is False
    assert mail_capture == []  # no poisoned link was ever sent


def test_f2_reset_link_uses_canonical_base(mail_capture, monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_BASE_URL",
                        "https://verity-nine-flame.vercel.app")
    _signup("canon@example.com")
    mail_capture.clear()
    r = client.post("/v1/auth/forgot-password",
                    headers={"Host": "evil.example"},
                    json={"email": "canon@example.com"})
    assert r.json()["email_delivery"] is True
    assert len(mail_capture) == 1
    assert ("https://verity-nine-flame.vercel.app/reset-password?token="
            in mail_capture[0]["text"])


# --- F3: dashboard fails closed ---------------------------------------

def test_f3_dashboard_refuses_without_password(monkeypatch, tmp_path):
    from streamlit.testing.v1 import AppTest
    monkeypatch.delenv("VERITY_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("VERITY_DASHBOARD_ALLOW_UNAUTHENTICATED",
                       raising=False)
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "d.db"))
    store.init_db()
    at = AppTest.from_file(os.path.join(REPO, "dashboard", "app.py"),
                           default_timeout=60).run()
    assert not at.exception
    assert any("refusing to display traces" in e.value
               for e in at.error)
    assert len(at.metric) == 0  # no trace data leaked


def test_f3_dashboard_local_opt_in_still_works(monkeypatch, tmp_path):
    from streamlit.testing.v1 import AppTest
    monkeypatch.delenv("VERITY_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.setenv("VERITY_DASHBOARD_ALLOW_UNAUTHENTICATED", "true")
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "d.db"))
    store.init_db()
    at = AppTest.from_file(os.path.join(REPO, "dashboard", "app.py"),
                           default_timeout=60).run()
    assert not at.exception
    assert len(at.metric) == 3


# --- F4: body-size cap + message count --------------------------------

def test_f4_oversized_body_rejected_before_parsing(monkeypatch):
    monkeypatch.setattr(config, "MAX_BODY_BYTES", 300)
    key = _signup()
    r = client.post("/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json={"model": "mock", "messages": [
                        {"role": "user", "content": "x" * 500}]})
    assert r.status_code == 413
    assert r.json()["detail"]["error"] == "request_too_large"


def test_f4_too_many_messages_rejected():
    key = _signup()
    r = client.post("/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}"},
                    json={"model": "mock", "messages": [
                        {"role": "user", "content": "hi"}] * 101})
    assert r.status_code == 422


# --- F5: token claim is atomic -----------------------------------------

def _issue(user_id, raw, ttl_seconds=3600):
    import time
    digest = hashlib.sha256(raw.encode()).hexdigest()
    store.issue_auth_token(user_id, "password_reset", digest,
                           time.time() + ttl_seconds)
    return store.get_auth_token(digest, "password_reset")["id"]


def test_f5_claim_exactly_once_and_not_when_expired():
    uid = store.create_user("claim@example.com", "pbkdf2$x$y", "")
    tid = _issue(uid, "tok-once")
    assert store.claim_auth_token(tid) is True
    assert store.claim_auth_token(tid) is False
    tid2 = _issue(uid, "tok-expired", ttl_seconds=-10)
    assert store.claim_auth_token(tid2) is False


def test_f5_concurrent_claims_have_exactly_one_winner():
    uid = store.create_user("race@example.com", "pbkdf2$x$y", "")
    tid = _issue(uid, "tok-race")
    results = []

    def worker():
        try:
            results.append(store.claim_auth_token(tid))
        except Exception:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_f5_reset_token_cannot_be_reused(mail_capture):
    _signup("reuse@example.com")
    mail_capture.clear()
    # No sender gate here: issue a token directly, as the mail would.
    user = store.get_user_by_email("reuse@example.com")
    import time
    raw = "raw-reset-token-123"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    store.issue_auth_token(user["id"], "password_reset", digest,
                           time.time() + 3600)
    body = {"token": raw, "password": "brand new password 1"}
    assert client.post("/v1/auth/reset-password",
                       json=body).status_code == 200
    assert client.post("/v1/auth/reset-password",
                       json=body).status_code == 400
