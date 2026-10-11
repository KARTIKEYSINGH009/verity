"""Verity gateway: OpenAI-compatible proxy with guard + scoring + tracing.

Drop-in replacement for the OpenAI chat-completions endpoint:
point your client at http://<verity-host>:8000/v1 instead of
https://api.openai.com/v1. Everything else stays the same.
"""
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import config
from .guard import detect_injection
from .scoring import faithfulness_score
from .store import init_db, log_trace, recent_traces


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Verity gateway", version="0.1.0", lifespan=lifespan)


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: list[Message] = Field(min_length=1)
    # Optional: reference text the answer must stay grounded in.
    grounding_context: str = ""


def _mock_completion(model: str, messages: list[Message]) -> dict:
    last = messages[-1].content
    text = f"[mock] echo of: {last[:120]}"
    return {
        "id": "chatcmpl-verity-mock",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant",
                                            "content": text},
                     "finish_reason": "stop"}],
        "verity": {"mock": True},
    }


async def _upstream_completion(payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{config.UPSTREAM_BASE_URL}/v1/chat/completions",
            headers={"Authorization": f"Bearer {config.UPSTREAM_API_KEY}"},
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()


@app.get("/health")
def health():
    return {"status": "ok", "mock_mode": config.MOCK_MODE}


@app.get("/v1/traces")
def traces(limit: int = 50):
    return {"traces": recent_traces(limit)}


@app.post("/v1/chat/completions")
async def chat_completions(req: ChatRequest):
    started = time.perf_counter()
    user_texts = [m.content for m in req.messages if m.role == "user"]
    combined = "\n".join(user_texts)

    # 1. Guard: screen for prompt injection before anything reaches a model.
    flags = detect_injection(combined)
    if flags and config.BLOCK_ON_INJECTION:
        log_trace(req.model, combined, "", 0.0, blocked=True, flags=flags)
        raise HTTPException(status_code=400, detail={
            "error": "blocked_by_verity_guard", "matched_rules": flags})

    # 2. Get the completion (mock or real upstream).
    if config.MOCK_MODE:
        result = _mock_completion(req.model, req.messages)
    else:
        result = await _upstream_completion(
            {"model": req.model,
             "messages": [m.model_dump() for m in req.messages]})

    answer = result["choices"][0]["message"]["content"]

    # 3. Score faithfulness when grounding context was supplied.
    score = None
    if req.grounding_context:
        score = faithfulness_score(req.grounding_context, answer)
        if score["verdict"] == "hallucination_risk":
            flags = list(flags) + ["hallucination_risk"]

    latency_ms = (time.perf_counter() - started) * 1000
    log_trace(req.model, combined, answer, latency_ms,
              flags=flags,
              faithfulness=score["score"] if score else None)

    result.setdefault("verity", {}).update(
        {"guard_flags": flags, "faithfulness": score})
    return result
