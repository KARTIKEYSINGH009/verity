"""Stub upstream: a fake OpenAI-compatible model server for exercising
Verity's LIVE mode end-to-end without a real provider key or spend.

Run:  uvicorn scripts.stub_upstream:app --port 9101
or:   python -m scripts.stub_upstream

Behaviour is driven by markers in the conversation so the client-live
battery (scripts/client_live_battery.py) can steer it:

Chat completions (decided by the last user message):
- contains "DO_REFUND"            -> answer performs a refund (the
  deterministic response-side policy rule should catch it)
- contains "SUBTLE_VIOLATION"     -> answer looks innocent but carries
  SUBTLE_MARKER, which only the policy *judge* (below) flags
- contains "SIMULATE_JUDGE_OUTAGE"-> answer carries the outage marker;
  the policy judge endpoint then returns HTTP 500, so Verity must
  fail closed and withhold the answer
- anything else                   -> a benign order-status answer

Judge calls (recognised by their system prompts):
- faithfulness judge -> fixed grounded verdict JSON
- policy judge -> 500 if the fenced <response> carries the outage
  marker; violates=true if it carries SUBTLE_MARKER; else false
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Verity stub upstream")


def _completion(content: str, model: str = "stub-model") -> dict:
    return {
        "id": "chatcmpl-stub",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0,
                     "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 12,
                  "total_tokens": 22},
    }


@app.get("/health")
def health():
    return {"status": "ok", "stub": True}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    messages = body.get("messages", [])
    system = next((m.get("content", "") for m in messages
                   if m.get("role") == "system"), "")
    last_user = next((m.get("content", "") for m in reversed(messages)
                      if m.get("role") == "user"), "")

    # Faithfulness judge call (verity/judge.py).
    if "strict factuality grader" in system:
        return _completion(
            '{"score": 0.95, "verdict": "grounded", '
            '"rationale": "stub judge: answer matches the context"}',
            body.get("model", "stub-model"))

    # Policy judge call (verity/policy.py): payloads are fenced in tags.
    if "untrusted data" in system:
        if "SIMULATE_JUDGE_OUTAGE" in last_user:
            return JSONResponse(status_code=500,
                                content={"error": "stub judge is down"})
        if "SUBTLE_MARKER" in last_user:
            return _completion(
                '{"violates": true, "reason": "stub judge: the answer '
                'quietly performs a prohibited action"}',
                body.get("model", "stub-model"))
        return _completion(
            '{"violates": false, "reason": "stub judge: no violation"}',
            body.get("model", "stub-model"))

    # Ordinary chat completion.
    if "DO_REFUND" in last_user:
        return _completion(
            "Of course! We've refunded $50 to your original payment "
            "method — your refund has been processed and should arrive "
            "in 3-5 business days.",
            body.get("model", "stub-model"))
    if "SUBTLE_VIOLATION" in last_user:
        return _completion(
            "All done — I have taken care of that for you exactly as "
            "asked. SUBTLE_MARKER",
            body.get("model", "stub-model"))
    if "SIMULATE_JUDGE_OUTAGE" in last_user:
        return _completion(
            "All sorted — your request has been completed in full. "
            "SIMULATE_JUDGE_OUTAGE",
            body.get("model", "stub-model"))
    return _completion(
        "Your order #1234 is on its way and will arrive Thursday.",
        body.get("model", "stub-model"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9101)
