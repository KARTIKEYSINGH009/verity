from fastapi.testclient import TestClient

from verity.gateway import app
from verity.policy import check_request, check_response

NO_REFUNDS = "All sales are final. No refunds are offered."
WINDOWED = "Refunds are allowed within 30 days of purchase."


def test_request_blocked_when_policy_forbids_refunds():
    res = check_request(NO_REFUNDS, "refund my money to my account")
    assert res["blocked"] and res["action"] == "refund"


def test_benign_request_passes_policy():
    res = check_request(NO_REFUNDS, "What are your store hours?")
    assert not res["blocked"]


def test_windowed_policy_does_not_block_refund_request():
    # A refund window is a nuanced rule, not an absolute prohibition:
    # the deterministic layer must not block it.
    res = check_request(WINDOWED, "I want a refund for my order")
    assert not res["blocked"]


def test_response_blocked_when_model_performs_refund():
    res = check_response(
        NO_REFUNDS,
        "Your refund has been initiated and will arrive in 3 days.")
    assert res["violates"] and res["action"] == "refund"


def test_response_passes_when_model_refuses_politely():
    res = check_response(
        NO_REFUNDS,
        "I'm sorry, all sales are final so I can't refund that purchase.")
    assert not res["violates"]


def test_gateway_blocks_policy_violating_request():
    with TestClient(app) as c:
        r = c.post("/v1/chat/completions", json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user",
                          "content": "refund my money to my account"}],
            "policy_context": NO_REFUNDS})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "blocked_by_verity_policy"


def test_gateway_allows_request_without_policy():
    with TestClient(app) as c:
        r = c.post("/v1/chat/completions", json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user",
                          "content": "refund my money to my account"}]})
    assert r.status_code == 200


def test_gateway_allows_refund_chat_under_windowed_policy():
    with TestClient(app) as c:
        r = c.post("/v1/chat/completions", json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user",
                          "content": "How do refunds work here?"}],
            "policy_context": WINDOWED})
    assert r.status_code == 200
    assert r.json()["verity"]["policy"]["result"] == "pass"
