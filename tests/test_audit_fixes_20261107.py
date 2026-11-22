"""Audit fixes, 2026-11-07 (FORGE triage round).

Covers the gateway-side fixes from the harsh audit triage:
- MCP decision receipts are stored on their trace row (decision_id), so
  the dashboard can find a receipt by its id.
- Branded 404: browsers get a Verity page, /v1/* keeps JSON, and
  handler-raised structured 404s keep their detail.
- /signup and /login redirect signed-in users to /dashboard.
- /v1/me reports whether email verification is actually configured
  (email_verification_on), so Settings stops claiming an email is
  "Verified" when no verification mail was ever sent.
"""
import pytest
from fastapi.testclient import TestClient

from verity import config, gateway, store
from verity.gateway import app
from verity.store import recent_traces

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    monkeypatch.setattr(config, "MOCK_MODE", True)
    store.init_db()
    gateway._hits.clear()
    yield
    gateway._hits.clear()


def _signup(email="audit@acme.example", password="<redacted>",
            company="Audit Co"):
    return client.post("/v1/auth/signup", json={
        "email": email, "password": password, "company": company})


# --- MCP decision_id is stored on the trace row ---------------------------

def test_mcp_receipt_id_stored_on_trace():
    r = client.post("/v1/mcp/guard", json={
        "tool_name": "run_query",
        "arguments": {"sql": "DROP TABLE users;"}})
    assert r.status_code == 403
    receipt = r.json()["detail"]["verity_receipt"]
    decision_id = receipt["decision_id"]
    assert decision_id.startswith("vrt_")
    rows = recent_traces(10)
    assert rows, "MCP decision was not logged"
    assert rows[0]["decision_id"] == decision_id
    assert rows[0]["blocked"] == 1


def test_mcp_receipt_id_returned_by_me():
    signup = _signup()
    assert signup.status_code == 201
    api_key = signup.json()["api_key"]
    r = client.post("/v1/mcp/guard", json={
        "tool_name": "run_query",
        "arguments": {"sql": "SELECT id FROM users LIMIT 1"}},
        headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 200
    decision_id = r.json()["verity_receipt"]["decision_id"]
    me = client.get("/v1/me")
    assert me.status_code == 200
    traces = me.json()["traces"]
    assert traces, "no traces returned for the signed-in user"
    assert traces[0]["decision_id"] == decision_id


# --- Branded 404 ------------------------------------------------------------

def test_unknown_browser_path_gets_branded_404():
    r = client.get("/no-such-page")
    assert r.status_code == 404
    assert "text/html" in r.headers["content-type"]
    assert "Page not found" in r.text
    assert "VERITY." in r.text
    assert "detail" not in r.text  # no raw framework JSON


def test_unknown_api_path_keeps_json_404():
    r = client.get("/v1/no-such-endpoint")
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}


def test_docs_stays_404_but_branded():
    r = client.get("/docs")
    assert r.status_code == 404
    assert "text/html" in r.headers["content-type"]
    assert "Page not found" in r.text


def test_structured_404_detail_is_preserved():
    r = client.post("/v1/auth/login", json={
        "email": "ghost@nowhere.example", "password": "whatever 123"})
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "account_not_found"


# --- Signed-in users are redirected off /signup and /login ------------------

def test_signup_page_redirects_when_signed_in():
    _signup()
    r = client.get("/signup", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/dashboard"
    r = client.get("/login", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/dashboard"


def test_signup_and_login_pages_serve_when_signed_out():
    assert client.get("/signup").status_code == 200
    assert client.get("/login").status_code == 200


# --- /v1/me reports whether verification is configured ---------------------

def test_me_reports_verification_not_configured():
    _signup()
    me = client.get("/v1/me")
    assert me.status_code == 200
    body = me.json()
    # No sender is configured in tests, so verification cannot run:
    # the honest state is "not configured", while email_verified stays
    # True because keys must remain active when verification is not
    # required (see _enforce_email_verified).
    assert body["email_verification_on"] is False
    assert body["email_verified"] is True
