"""MCP pre/post-tool guard tests (piece 1 of the Universal Firewall port).

Covers: destructive-argument scanning (SQL / shell / SSRF / traversal)
pre-tool and post-tool, benign twins that must pass (including non-Latin
arguments — there is NO script gate on this endpoint), auth before
screening (401 with a wrong or missing key, even for a destructive
payload), decision receipts on every response, and a trace row per
decision. All payloads here are written fresh for this file; they mirror
the SHAPES of the blind H3 MCP rows (tool + arguments + optional result)
without copying any H3 row.
"""
import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient

from verity import config, gateway
from verity.gateway import app
from verity.store import recent_traces

GUARD = "/v1/mcp/guard"
VERIFY = "/v1/tools/verify"
KEY = "mcp-test-key"


@pytest.fixture(autouse=True)
def _clean_rate_state():
    gateway._hits.clear()
    yield
    gateway._hits.clear()


def _post(c, payload, key=None, route=GUARD):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    return c.post(route, json=payload, headers=headers)


def _client_id_for(key):
    return hashlib.sha256(key.encode()).hexdigest()[:12]


# --- Pre-tool: destructive arguments are blocked ---------------------------

def test_drop_database_blocked(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_query",
                      "arguments": {"sql": "DROP DATABASE shop_db;"}})
    assert r.status_code == 403
    body = r.json()["detail"]
    assert body["error"] == "blocked_by_verity_mcp_guard"
    assert body["signal"] == "tool_arg_sql_injection"
    assert body["deciding_layer"] == "mcp_pre_tool_arguments"
    receipt = body["verity_receipt"]
    assert receipt["decision_id"].startswith("vrt_")
    assert receipt["allowed"] is False
    assert receipt["deciding_layer"] == "mcp_pre_tool_arguments"
    assert receipt["tool_verdict"] == "blocked"


def test_union_select_blocked(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_query",
                      "arguments": {"query": "SELECT name FROM users "
                                             "UNION SELECT password "
                                             "FROM admins"}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_sql_injection"


def test_delete_from_blocked(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_query",
                      "arguments": {"statement": "DELETE FROM sessions;"}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_sql_injection"


def test_rm_rf_blocked(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_shell",
                      "arguments": {"cmd": "rm -rf /opt/data/cache "
                                           "&& echo cleaned"}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_command_injection"
    assert r.json()["detail"]["deciding_layer"] == "mcp_pre_tool_arguments"


def test_command_substitution_blocked(monkeypatch):
    # $(...) is shell injection even though /etc/passwd also appears:
    # the shell rule is checked before traversal, so the reason is stable.
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_shell",
                      "arguments": {"command": "echo $(cat /etc/passwd)"}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_command_injection"


def test_ssrf_metadata_blocked(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "http_get",
                      "arguments": {"url": "http://169.254.169.254/"
                                           "latest/meta-data/iam/"}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_ssrf"


def test_ssrf_localhost_blocked(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "http_get",
                      "arguments": {"url": "http://127.0.0.1:8080/admin"}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_ssrf"


def test_path_traversal_blocked(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "read_file",
                      "arguments": {"path": "../../etc/passwd"}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_path_traversal"


def test_nested_arguments_scanned(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_query",
                      "arguments": {"filters": {"where":
                                                "DROP TABLE audit_log;"}}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_sql_injection"


def test_string_form_arguments_scanned(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_query",
                      "arguments": '{"query": "DROP TABLE sessions;"}'})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_sql_injection"


def test_payload_in_argument_key_scanned(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_query",
                      "arguments": {"DROP TABLE ledger": "yes"}})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_sql_injection"


# --- Pre-tool: benign twins must pass ---------------------------------------

def test_benign_select_passes(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_query",
                      "arguments": {"query": "SELECT order_id, total "
                                             "FROM orders WHERE "
                                             "customer_id = 42"}})
    assert r.status_code == 200
    body = r.json()
    assert body["allowed"] is True
    assert body["tool_verdict"] == "verified_safe"
    receipt = body["verity_receipt"]
    assert receipt["decision_id"].startswith("vrt_")
    assert receipt["allowed"] is True
    assert receipt["deciding_layer"] == "mcp_guard"
    assert receipt["tool_verdict"] == "verified_safe"


def test_benign_ls_passes(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_shell",
                      "arguments": {"command": "ls /srv/shop/orders"}})
    assert r.status_code == 200
    assert r.json()["tool_verdict"] == "verified_safe"


def test_benign_public_fetch_passes(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "http_get",
                      "arguments": {"url": "https://shop.example.com/"
                                           "orders/ord_123"}})
    assert r.status_code == 200
    assert r.json()["allowed"] is True


def test_benign_nested_arguments_pass(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "place_order",
                      "arguments": {"order": {"id": "ord_999",
                                              "note": "gift wrap please"}}})
    assert r.status_code == 200


def test_benign_non_latin_arguments_pass(monkeypatch):
    # No script gate on this endpoint: a benign Devanagari note inside
    # an otherwise read-only query must pass, as it does on main.
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_query",
                      "arguments": {"query": "SELECT * FROM orders WHERE "
                                             "note = 'आदेश की स्थिति "
                                             "बताएं'"}})
    assert r.status_code == 200
    assert r.json()["allowed"] is True


def test_empty_arguments_pass(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "get_balance", "arguments": {}})
    assert r.status_code == 200
    assert r.json()["tool_verdict"] == "verified_safe"


# --- Post-tool: the executed call's arguments are re-verified ---------------

def test_post_tool_destructive_arguments_blocked(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "run_shell",
                      "arguments": {"cmd": "rm -rf /opt/data/cache"},
                      "tool_result": "cache cleared"})
    assert r.status_code == 403
    assert r.json()["detail"]["signal"] == "tool_arg_command_injection"
    assert (r.json()["detail"]["deciding_layer"]
            == "mcp_post_tool_arguments")


def test_post_tool_benign_call_passes(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "get_order_status",
                      "arguments": {"order_id": "ord_789"},
                      "tool_result": "Order status: shipped, "
                                     "tracking TRK-9911."})
    assert r.status_code == 200
    assert r.json()["tool_verdict"] == "verified_safe"


def test_post_tool_without_arguments_passes(monkeypatch):
    # Piece 1 screens ARGUMENTS only. A tool_result on its own, with no
    # arguments to verify, is allowed here by design — result-content
    # screening (DLP, RAG) lands in pieces 3 and 2.
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "get_order_status",
                      "tool_result": "Order status: shipped."})
    assert r.status_code == 200


# --- Both routes behave identically ------------------------------------------

def test_tools_verify_route_matches_guard(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    payload = {"tool_name": "run_query",
               "arguments": {"sql": "DROP TABLE shop_db;"}}
    benign = {"tool_name": "run_query",
              "arguments": {"query": "SELECT 1"}}
    with TestClient(app) as c:
        assert _post(c, payload, route=VERIFY).status_code == 403
        assert (_post(c, payload, route=VERIFY).json()["detail"]["signal"]
                == "tool_arg_sql_injection")
        assert _post(c, benign, route=VERIFY).status_code == 200
        assert _post(c, benign, route=GUARD).status_code == 200


# --- Auth runs before screening ----------------------------------------------

def test_401_without_key_even_for_destructive_payload(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [KEY])
    payload = {"tool_name": "run_query",
               "arguments": {"sql": "DROP TABLE shop_db;"}}
    with TestClient(app) as c:
        r = _post(c, payload)
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "invalid_api_key"


def test_401_with_wrong_key(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [KEY])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "get_balance", "arguments": {}},
                  key="not-the-key")
    assert r.status_code == 401


def test_configured_key_accepted(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [KEY])
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "get_balance", "arguments": {}},
                  key=KEY)
    assert r.status_code == 200
    assert r.json()["allowed"] is True


# --- Every decision is written to traces --------------------------------------

def test_blocked_decision_traced(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [KEY])
    cid = _client_id_for(KEY)
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "trace_probe_sql",
                      "arguments": {"sql": "DROP TABLE trace_probe;"}},
                  key=KEY)
    assert r.status_code == 403
    rows = [t for t in recent_traces(20, client_id=cid)
            if "trace_probe_sql" in t["input_text"]]
    assert rows, "no trace row for the blocked MCP call"
    assert rows[0]["blocked"] == 1
    assert "mcp:tool_arg_sql_injection" in rows[0]["flags_json"]


def test_allowed_decision_traced(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [KEY])
    cid = _client_id_for(KEY)
    with TestClient(app) as c:
        r = _post(c, {"tool_name": "trace_probe_ok",
                      "arguments": {"order_id": "ord_trace_ok"}},
                  key=KEY)
    assert r.status_code == 200
    rows = [t for t in recent_traces(20, client_id=cid)
            if "trace_probe_ok" in t["input_text"]]
    assert rows, "no trace row for the allowed MCP call"
    assert rows[0]["blocked"] == 0
    assert "mcp:verified_safe" in rows[0]["flags_json"]


# --- Free-plan quota is enforced on the MCP endpoints ------------------------
# (founder order 2026-11-07: the 1,000/month limit applies to MCP too.
# MCP calls are logged under the caller's client id, so they count toward
# the same monthly total chat checks — and are now capped the same way.)

_BENIGN = {"tool_name": "run_query",
           "arguments": {"sql": "SELECT id FROM users LIMIT 1"}}


def _portal_key(c):
    # Fresh user every call: the suite shares one sqlite DB, so a fixed
    # email would 409 on a second run.
    email = f"mcp-quota-{uuid.uuid4().hex[:8]}@example.com"
    r = c.post("/v1/auth/signup", json={
        "email": email, "password": "correct horse 9",
        "company": "Quota Co"})
    assert r.status_code == 201, r.text
    return r.json()["api_key"]


def test_free_quota_enforced_on_mcp_guard(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    monkeypatch.setattr(config, "FREE_MONTHLY_QUOTA", 2)
    with TestClient(app) as c:
        key = _portal_key(c)
        assert _post(c, _BENIGN, key=key).status_code == 200
        assert _post(c, _BENIGN, key=key).status_code == 200
        third = _post(c, _BENIGN, key=key)
    assert third.status_code == 429
    assert third.json()["detail"]["error"] == "quota_exceeded"


def test_free_quota_enforced_on_tools_verify(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    monkeypatch.setattr(config, "FREE_MONTHLY_QUOTA", 2)
    with TestClient(app) as c:
        key = _portal_key(c)
        assert _post(c, _BENIGN, key=key, route=VERIFY).status_code == 200
        assert _post(c, _BENIGN, key=key, route=VERIFY).status_code == 200
        third = _post(c, _BENIGN, key=key, route=VERIFY)
    assert third.status_code == 429
    assert third.json()["detail"]["error"] == "quota_exceeded"


def test_anonymous_mcp_call_not_quota_limited(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", [])
    monkeypatch.setattr(config, "FREE_MONTHLY_QUOTA", 1)
    with TestClient(app) as c:
        r = _post(c, _BENIGN)
    assert r.status_code == 200
    assert r.json()["allowed"] is True


def test_env_key_mcp_call_not_quota_limited(monkeypatch):
    monkeypatch.setattr(config, "CLIENT_KEYS", ["vk-env"])
    monkeypatch.setattr(config, "FREE_MONTHLY_QUOTA", 1)
    with TestClient(app) as c:
        r = _post(c, _BENIGN, key="vk-env")
    assert r.status_code == 200
    assert r.json()["allowed"] is True
