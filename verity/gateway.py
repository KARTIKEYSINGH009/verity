"""Verity gateway: OpenAI-compatible proxy with guard + scoring + tracing.

Drop-in replacement for the OpenAI chat-completions endpoint:
point your client at http://<verity-host>:8000/v1 instead of
https://api.openai.com/v1. Everything else stays the same.
"""
import hmac
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from . import config
from .guard import screen
from .judge import judge_faithfulness
from .policy import check_request as policy_check_request
from .policy import check_response as policy_check_response
from .scoring import faithfulness_score
from .store import init_db, log_trace, recent_traces


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Verity gateway", version="0.1.0", lifespan=lifespan,
    docs_url="/docs" if config.ENABLE_DOCS else None,
    redoc_url="/redoc" if config.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
)


# --- Security headers -------------------------------------------------------
# The landing page is one self-contained file (inline CSS/JS, same-origin
# fetches to /v1 and /benchmarks.json), so the CSP can stay tight: 'self'
# plus inline style/script, data: images/fonts, and no framing at all.
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: list[Message] = Field(min_length=1)
    # Optional: reference text the answer must stay grounded in.
    grounding_context: str = ""
    # Optional: business policy the interaction must obey (milestone 4).
    policy_context: str = ""


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
def traces(limit: int = 50,
           x_verity_admin_key: str | None = Header(default=None)):
    """Trace access is admin-only: traces contain raw prompts and answers.

    With no VERITY_ADMIN_KEY configured the endpoint is disabled (403) —
    the safe default for public deployments. With a key set, callers must
    present it in the X-Verity-Admin-Key header (401 otherwise).
    """
    if not config.ADMIN_KEY:
        raise HTTPException(status_code=403, detail={
            "error": "traces_disabled",
            "reason": "set VERITY_ADMIN_KEY to enable trace access"})
    if not hmac.compare_digest(x_verity_admin_key or "", config.ADMIN_KEY):
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
    return {"traces": recent_traces(max(1, min(limit, 200)))}


# Best-effort per-client rate limit (in-memory; per instance on serverless).
_hits: dict[str, deque] = defaultdict(deque)


def _client_key(request: Request) -> str:
    """Rate-limit bucket key. Behind a proxy (Vercel), request.client is
    the proxy itself — every visitor would share one bucket — so prefer
    the first X-Forwarded-For hop, which the platform sets to the real
    client address."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def _rate_limited(client: str) -> bool:
    now = time.monotonic()
    window = _hits[client]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= config.RATE_LIMIT_PER_MIN:
        return True
    window.append(now)
    return False


@app.post("/v1/chat/completions")
async def chat_completions(req: ChatRequest, request: Request):
    started = time.perf_counter()
    client = _client_key(request)
    if _rate_limited(client):
        raise HTTPException(status_code=429, detail={"error": "rate_limited"})
    user_texts = [m.content for m in req.messages if m.role == "user"]
    combined = "\n".join(user_texts)
    if len(combined) > config.MAX_INPUT_CHARS:
        raise HTTPException(status_code=413, detail={
            "error": "request_too_large",
            "limit_chars": config.MAX_INPUT_CHARS})

    # 1. Guard: screen for prompt injection before anything reaches a model.
    verdict = screen(combined)
    flags = verdict["signals"]
    if verdict["blocked"] and config.BLOCK_ON_INJECTION:
        log_trace(req.model, combined, "", 0.0, blocked=True, flags=flags)
        raise HTTPException(status_code=400, detail={
            "error": "blocked_by_verity_guard", "matched_rules": flags})

    # 1b. Policy guard (request side): stop requests seeking an action the
    # business policy prohibits outright, before the model can comply.
    if req.policy_context:
        pol = policy_check_request(req.policy_context, combined)
        if pol["blocked"]:
            pflags = list(flags) + ["policy_violation"]
            log_trace(req.model, combined, "", 0.0, blocked=True, flags=pflags)
            raise HTTPException(status_code=400, detail={
                "error": "blocked_by_verity_policy",
                "action": pol["action"], "reason": pol["reason"]})

    # 2. Get the completion (mock or real upstream).
    if config.MOCK_MODE:
        result = _mock_completion(req.model, req.messages)
    else:
        result = await _upstream_completion(
            {"model": req.model,
             "messages": [m.model_dump() for m in req.messages]})

    answer = result["choices"][0]["message"]["content"]

    # 2b. Policy guard (response side): even if the model complied with a
    # prohibited action, its answer never reaches the user.
    policy_result = None
    if req.policy_context:
        policy_result = policy_check_response(req.policy_context, answer)
        if policy_result["violates"]:
            pflags = list(flags) + ["policy_violation"]
            latency_ms = (time.perf_counter() - started) * 1000
            log_trace(req.model, combined, answer, latency_ms, blocked=True,
                      flags=pflags)
            raise HTTPException(status_code=400, detail={
                "error": "policy_violation_in_response",
                "action": policy_result.get("action"),
                "reason": policy_result.get("reason", "")})

    # 3. Score faithfulness when grounding context was supplied.
    # Milestone 2: LLM-as-judge is primary, heuristic kept as fallback/detail.
    score = None
    if req.grounding_context and config.JUDGE_ENABLED:
        score = judge_faithfulness(req.grounding_context, answer)
    elif req.grounding_context:
        score = faithfulness_score(req.grounding_context, answer)
        score["method"] = "heuristic"
    if score and score["verdict"] == "hallucination_risk":
        flags = list(flags) + ["hallucination_risk"]

    latency_ms = (time.perf_counter() - started) * 1000
    log_trace(req.model, combined, answer, latency_ms,
              flags=flags,
              faithfulness=score["score"] if score else None)

    result.setdefault("verity", {}).update(
        {"guard_flags": flags, "faithfulness": score})
    if policy_result is not None:
        result["verity"]["policy"] = {"checked": True, "result": "pass",
                                      "method": policy_result["method"]}
    return result


# Serve the landing page (site/) at the root URL when deployed (e.g. Vercel),
# so one deployment is both the website and the live gateway. Mounted last so
# /health and /v1/* always win over the static files.
from pathlib import Path

from fastapi.staticfiles import StaticFiles

_site_dir = Path(__file__).resolve().parent.parent / "site"
if _site_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_site_dir), html=True),
              name="site")
