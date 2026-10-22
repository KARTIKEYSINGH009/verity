"""Regression tests for the 2026-10-22 Website Audit P0 security
findings #19-#23. Each test names the finding it locks in; every one
of these failed against the pre-fix code."""
import inspect

import pytest
from fastapi.testclient import TestClient

from verity import config, gateway, judge, store
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


def _signup(email="sec@example.com"):
    r = client.post("/v1/auth/signup", json={
        "email": email, "password": "correct horse 9", "company": "Acme"})
    assert r.status_code == 201
    return r.json()["api_key"]


def _chat(key, content="What are your opening hours?"):
    return client.post("/v1/chat/completions",
                       headers={"Authorization": f"Bearer {key}"},
                       json={"model": "mock", "messages": [
                           {"role": "user", "content": content}]})


# --- #19: quota and dashboard history are bound to the account ------

def test_19_quota_survives_key_regeneration(monkeypatch):
    monkeypatch.setattr(config, "FREE_MONTHLY_QUOTA", 2)
    key = _signup()
    assert _chat(key).status_code == 200
    assert _chat(key).status_code == 200
    new_key = client.post("/v1/keys/regenerate").json()["api_key"]
    # Pre-fix: the new key's hash prefix had zero usage -> 200 (bypass).
    r = _chat(new_key)
    assert r.status_code == 429
    assert r.json()["detail"]["error"] == "quota_exceeded"


def test_19_dashboard_history_survives_key_regeneration():
    key = _signup()
    assert _chat(key).status_code == 200
    client.post("/v1/keys/regenerate")
    me = client.get("/v1/me").json()
    # Pre-fix: usage/traces were looked up by the NEW key's hash -> 0.
    assert me["usage"]["total"] == 1
    assert len(me["traces"]) == 1


def test_19_client_id_for_portal_key_is_user_bound():
    key = _signup()
    user = store.get_user_by_email("sec@example.com")
    assert gateway._client_id(f"Bearer {key}") == f"user:{user['id']}"


# --- #20: tool-call completions (content=None) must not 500 ---------

def test_20_tool_call_content_none_does_not_500(monkeypatch):
    key = _signup()
    monkeypatch.setattr(config, "MOCK_MODE", False)

    async def fake_upstream(payload):
        return {"id": "chatcmpl-tool", "object": "chat.completion",
                "model": "mock",
                "choices": [{"index": 0,
                             "message": {"role": "assistant",
                                         "content": None,
                                         "tool_calls": [{
                                             "id": "call_1",
                                             "type": "function",
                                             "function": {
                                                 "name": "lookup",
                                                 "arguments": "{}"}}]},
                             "finish_reason": "tool_calls"}]}

    monkeypatch.setattr(gateway, "_upstream_completion", fake_upstream)
    r = _chat(key)
    assert r.status_code == 200


def test_20_log_trace_coerces_none_output():
    store.log_trace("m", "hello", None, 1.0, client_id="c-none")
    rows = store.recent_traces(5, client_id="c-none")
    assert rows and rows[0]["output_text"] == ""


# --- #21: judge outage falls back, never 500s the request -----------

def test_21_judge_failure_falls_back_to_heuristic(monkeypatch):
    monkeypatch.setattr(config, "MOCK_MODE", False)
    monkeypatch.setattr(config, "UPSTREAM_API_KEY", "test-key")

    def boom(messages):
        raise RuntimeError("judge upstream 429")

    monkeypatch.setattr(judge, "_call_judge_model", boom)
    res = judge.judge_faithfulness(
        "Refunds are allowed within 30 days of purchase.",
        "You can return your purchase within 30 days.")
    assert "judge unavailable" in res["method"]
    assert res["verdict"] == "grounded"


def test_21_parse_judge_response_tolerates_none():
    res = judge.parse_judge_response(None)
    assert res["verdict"] == "hallucination_risk"


# --- #22: sync judge/policy calls run off the event loop ------------

def test_22_judge_and_policy_calls_are_offloaded():
    src = inspect.getsource(gateway.chat_completions)
    offloads = src.split("asyncio.to_thread")[1:]
    assert len(offloads) >= 2
    assert any("policy_check_response" in seg[:90] for seg in offloads)
    assert any("judge_faithfulness" in seg[:90] for seg in offloads)


# --- #23: cross-origin POSTs on session mutations are rejected ------

def test_23_cross_origin_regenerate_rejected_same_origin_ok():
    _signup()
    evil = client.post("/v1/keys/regenerate",
                       headers={"Origin": "https://evil.example"})
    assert evil.status_code == 403
    assert evil.json()["detail"]["error"] == "cross_origin_forbidden"
    good = client.post("/v1/keys/regenerate",
                       headers={"Origin": "http://testserver"})
    assert good.status_code == 200
    assert good.json()["api_key"].startswith("vk-")


def test_23_cross_origin_logout_does_not_kill_session():
    _signup()
    r = client.post("/v1/auth/logout",
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert client.get("/v1/me").status_code == 200


def test_23_cross_origin_preferences_rejected():
    _signup()
    r = client.post("/v1/me/preferences",
                    headers={"Origin": "https://evil.example"},
                    json={"marketing_opt_in": True})
    assert r.status_code == 403
