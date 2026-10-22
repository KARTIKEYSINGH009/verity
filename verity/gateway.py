"""Verity gateway: OpenAI-compatible proxy with guard + scoring + tracing.

Drop-in replacement for the OpenAI chat-completions endpoint:
point your client at http://<verity-host>:8000/v1 instead of
https://api.openai.com/v1. Everything else stays the same.
"""
import hashlib
import hmac
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlencode
from collections import defaultdict, deque
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config
from .guard import screen
from .judge import judge_faithfulness
from .policy import check_request as policy_check_request
from .policy import check_response as policy_check_response
from .scoring import faithfulness_score
from .store import (DuplicateEmail, active_api_key, create_session,
                    create_user, delete_session, find_api_key,
                    get_marketing_state, get_user_by_email,
                    get_user_by_id, get_user_by_session,
                    get_user_by_unsubscribe_token, init_db, issue_api_key,
                    log_pilot_request, log_trace, recent_pilot_requests,
                    recent_traces, revoke_api_keys, set_marketing_opt_in,
                    usage_for_client)


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


# --- Client authentication (audit F2) ---------------------------------------


def _client_authorized(authorization: str | None) -> bool:
    """True when the caller may use the chat endpoint.

    With no client keys configured the endpoint is open — the right
    default for the public mock demo and local development. With keys
    configured, the caller must present one as a Bearer token (which is
    what the OpenAI client sends when its api_key is the Verity key).
    Comparisons are timing-safe.
    """
    keys = config.CLIENT_KEYS
    if not keys:
        # Open deployment (public demo / local dev): portal-issued keys
        # are still recognized so their traffic is stamped per user.
        return True
    if not authorization or not authorization.startswith("Bearer "):
        return False
    token = authorization[len("Bearer "):].strip()
    if any(hmac.compare_digest(token, k) for k in keys):
        return True
    # Portal-issued keys (per-user, stored hashed) also authorize.
    return bool(token) and find_api_key(
        hashlib.sha256(token.encode()).hexdigest()) is not None


def _enforce_startup_policy() -> None:
    """A live (non-mock) deployment must not serve an open endpoint:
    anyone could spend the operator's upstream API budget. Refuse to
    start unless client keys are configured or the operator has
    explicitly accepted an open endpoint with VERITY_ALLOW_OPEN=true.
    """
    if not config.MOCK_MODE and not config.CLIENT_KEYS and not config.ALLOW_OPEN:
        raise RuntimeError(
            "Verity live mode requires client API keys: set "
            "VERITY_CLIENT_KEYS (comma-separated) or VERITY_CLIENT_KEY, "
            "or set VERITY_ALLOW_OPEN=true to run an open endpoint "
            "deliberately.")


_enforce_startup_policy()


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
    return {"status": "ok", "mock_mode": config.MOCK_MODE,
            "client_auth": bool(config.CLIENT_KEYS)}


def _client_id(authorization: str | None) -> str:
    """Stable per-client identity for traces: a hash prefix of the
    presented client key (never the raw key, which must not be stored).
    Only recognized keys are stamped — env-configured keys and
    portal-issued keys; anonymous demo traffic stays unstamped."""
    if not authorization:
        return ""
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        return ""
    digest = hashlib.sha256(token.encode()).hexdigest()
    if any(hmac.compare_digest(token, k) for k in config.CLIENT_KEYS):
        return digest[:12]
    if find_api_key(digest) is not None:
        return digest[:12]
    return ""


@app.get("/v1/traces")
def traces(limit: int = 50, client_id: str | None = None,
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
    return {"traces": recent_traces(max(1, min(limit, 200)),
                                     client_id=client_id)}


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


# --- Pilot requests (public form on /pilot) --------------------------------
# Contact + scoping details only. The endpoint deliberately rejects any
# secret-shaped field: API keys and passwords must never travel through a
# public form — a client's provider key is entered into their own
# deployment's settings during provisioning, never collected here.

_PILOT_FIELDS = {  # name -> (required, max length)
    "company": (True, 120),
    "email": (True, 254),
    "role": (False, 80),
    "use_case": (True, 2000),
    "provider": (False, 80),
    "volume": (False, 40),
    "challenges": (False, 2000),
    "timeline": (False, 80),
}
_SECRET_WORDS = ("key", "password", "passwd", "secret", "token",
                 "credential")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")


@app.post("/v1/pilot-requests", status_code=201)
async def create_pilot_request(request: Request):
    if not config.PILOT_INTAKE:
        raise HTTPException(status_code=404, detail={
            "error": "not_found",
            "reason": "pilot intake is only enabled on the public site"})
    if _rate_limited("pilot:" + _client_key(request)):
        raise HTTPException(status_code=429,
                            detail={"error": "rate_limited"})
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400,
                            detail={"error": "invalid_json"})
    if not isinstance(body, dict):
        raise HTTPException(status_code=400,
                            detail={"error": "invalid_payload"})
    for key in body:
        lowered = str(key).lower()
        if any(word in lowered for word in _SECRET_WORDS):
            raise HTTPException(status_code=400, detail={
                "error": "secrets_not_accepted",
                "reason": "never send API keys, passwords or other "
                          "secrets through this form"})
    values, errors = {}, []
    for name, (required, max_len) in _PILOT_FIELDS.items():
        raw = body.get(name, "")
        if not isinstance(raw, str):
            errors.append(name)
            continue
        value = raw.strip()
        if required and not value:
            errors.append(name)
        elif len(value) > max_len:
            errors.append(name)
        values[name] = value
    if values.get("email") and not _EMAIL_RE.match(values["email"]):
        errors.append("email")
    if errors:
        raise HTTPException(status_code=400, detail={
            "error": "validation_failed",
            "fields": sorted(set(errors))})
    row_id = log_pilot_request(**values)
    return {"id": row_id, "reference": f"VR-{row_id:04d}",
            "status": "recorded"}


@app.get("/v1/pilot-requests")
def list_pilot_requests(limit: int = 50,
                        x_verity_admin_key: str | None =
                        Header(default=None)):
    """Founder-only, same admin pattern as /v1/traces."""
    if not config.ADMIN_KEY:
        raise HTTPException(status_code=403, detail={
            "error": "pilot_requests_disabled",
            "reason": "set VERITY_ADMIN_KEY to enable access"})
    if not hmac.compare_digest(x_verity_admin_key or "",
                               config.ADMIN_KEY):
        raise HTTPException(status_code=401,
                            detail={"error": "unauthorized"})
    return {"requests": recent_pilot_requests(max(1, min(limit, 200)))}


# --- Client accounts (portal) ------------------------------------------------
# Signup/login for the single public site. A user gets a personal API
# key (shown once, stored hashed) and a dashboard view over exactly
# their own traces — scoping is enforced here, server-side, by the
# session's user and their key's client_id, never by the page.

import secrets

_SESSION_COOKIE = "verity_session"
_SESSION_TTL = 30 * 24 * 3600
_PBKDF2_ROUNDS = 200_000


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                             _PBKDF2_ROUNDS)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def _check_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex),
                                 _PBKDF2_ROUNDS)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


_DUMMY_PW_HASH = _hash_password("not-a-real-password")


def _portal_key(user_id: int) -> str:
    plaintext = "vk-" + secrets.token_hex(24)
    digest = hashlib.sha256(plaintext.encode()).hexdigest()
    issue_api_key(user_id, digest, plaintext[-4:])
    return plaintext


def _session_user(request: Request):
    token = request.cookies.get(_SESSION_COOKIE, "")
    if not token:
        return None
    return get_user_by_session(
        hashlib.sha256(token.encode()).hexdigest())


def _start_session(request: Request, payload: dict,
                   user_id: int, status_code: int = 200) -> JSONResponse:
    token = secrets.token_urlsafe(32)
    create_session(user_id,
                   hashlib.sha256(token.encode()).hexdigest(),
                   _SESSION_TTL)
    resp = JSONResponse(payload, status_code=status_code)
    resp.set_cookie(_SESSION_COOKIE, token, max_age=_SESSION_TTL,
                    httponly=True, samesite="lax", path="/",
                    secure=request.url.scheme == "https")
    return resp


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400,
                            detail={"error": "invalid_json"})
    if not isinstance(body, dict):
        raise HTTPException(status_code=400,
                            detail={"error": "invalid_payload"})
    return body


def _public_user(user) -> dict:
    return {"email": user["email"], "company": user["company"],
            "plan": user["plan"]}


@app.post("/v1/auth/signup", status_code=201)
async def auth_signup(request: Request):
    if _rate_limited("auth:" + _client_key(request)):
        raise HTTPException(status_code=429,
                            detail={"error": "rate_limited"})
    body = await _json_body(request)
    email = str(body.get("email", "")).strip().lower()
    password = body.get("password", "")
    company = str(body.get("company", "")).strip()[:120]
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail={
            "error": "validation_failed", "fields": ["email"]})
    if not isinstance(password, str) or not 8 <= len(password) <= 200:
        raise HTTPException(status_code=400, detail={
            "error": "validation_failed", "fields": ["password"]})
    try:
        user_id = create_user(email, _hash_password(password), company)
    except DuplicateEmail:
        raise HTTPException(status_code=409,
                            detail={"error": "email_taken"})
    if body.get("marketing_opt_in") is True:
        set_marketing_opt_in(user_id, True,
                             secrets.token_urlsafe(24))
    api_key = _portal_key(user_id)
    return _start_session(request,
                          {"user": _public_user(get_user_by_id(user_id)),
                           "api_key": api_key}, user_id, status_code=201)


@app.post("/v1/auth/login")
async def auth_login(request: Request):
    if _rate_limited("auth:" + _client_key(request)):
        raise HTTPException(status_code=429,
                            detail={"error": "rate_limited"})
    body = await _json_body(request)
    email = str(body.get("email", "")).strip().lower()
    password = body.get("password", "")
    user = get_user_by_email(email)
    # Product decision (Kartikey, 2026-10-22): the auth flow tells the
    # user which side is wrong — unknown email routes to signup, an
    # existing email routes to login — rather than a generic failure.
    if not user:
        raise HTTPException(status_code=404,
                            detail={"error": "account_not_found"})
    if not str(user["pw_hash"]).startswith("pbkdf2$"):
        raise HTTPException(status_code=401,
                            detail={"error": "google_account"})
    ok = isinstance(password, str) and _check_password(password,
                                                      user["pw_hash"])
    if not ok:
        raise HTTPException(status_code=401,
                            detail={"error": "invalid_credentials"})
    return _start_session(request, {"user": _public_user(user)},
                          user["id"])


@app.post("/v1/auth/logout")
def auth_logout(request: Request):
    token = request.cookies.get(_SESSION_COOKIE, "")
    if token:
        delete_session(hashlib.sha256(token.encode()).hexdigest())
    resp = JSONResponse({"status": "signed_out"})
    resp.delete_cookie(_SESSION_COOKIE, path="/")
    return resp


@app.get("/v1/me")
def me(request: Request):
    user = _session_user(request)
    if not user:
        raise HTTPException(status_code=401,
                            detail={"error": "not_signed_in"})
    key = active_api_key(user["id"])
    payload = {"user": _public_user(user), "api_key_hint": None,
               "usage": {"total": 0, "blocked": 0, "avg_latency_ms": 0,
                         "month_total": 0},
               "quota": ({"limit_per_month": config.FREE_MONTHLY_QUOTA}
                         if user["plan"] == "free" else None),
               "marketing_opt_in": get_marketing_state(
                   user["id"])["opt_in"],
               "traces": []}
    if key:
        client_id = key["key_hash"][:12]
        payload["api_key_hint"] = "vk-…" + key["key_hint"]
        payload["usage"] = usage_for_client(
            client_id, since_ts=_month_start_ts())
        payload["traces"] = [
            {"ts": t["ts"], "model": t["model"],
             "input_text": t["input_text"][:160],
             "blocked": t["blocked"],
             "faithfulness": t["faithfulness"]}
            for t in recent_traces(limit=10, client_id=client_id)]
    return payload


@app.post("/v1/me/preferences")
async def me_preferences(request: Request):
    user = _session_user(request)
    if not user:
        raise HTTPException(status_code=401,
                            detail={"error": "not_signed_in"})
    body = await _json_body(request)
    opt_in = body.get("marketing_opt_in")
    if not isinstance(opt_in, bool):
        raise HTTPException(status_code=400, detail={
            "error": "validation_failed", "fields": ["marketing_opt_in"]})
    state = get_marketing_state(user["id"])
    token = state["unsubscribe_token"]
    if opt_in and not token:
        token = secrets.token_urlsafe(24)
    set_marketing_opt_in(user["id"], opt_in, token)
    return {"marketing_opt_in": opt_in}


@app.post("/v1/email/unsubscribe")
async def email_unsubscribe(request: Request):
    body = await _json_body(request)
    token = str(body.get("token", ""))
    user = get_user_by_unsubscribe_token(token)
    if not user:
        raise HTTPException(status_code=404,
                            detail={"error": "invalid_token"})
    set_marketing_opt_in(user["id"], False)
    return {"status": "unsubscribed", "email": user["email"]}


@app.post("/v1/keys/regenerate")
def regenerate_key(request: Request):
    user = _session_user(request)
    if not user:
        raise HTTPException(status_code=401,
                            detail={"error": "not_signed_in"})
    revoke_api_keys(user["id"])
    return {"api_key": _portal_key(user["id"])}


def _month_start_ts() -> float:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0,
                       microsecond=0).timestamp()


def _enforce_free_quota(authorization: str | None) -> None:
    """Free-plan monthly quota for portal-issued keys, enforced here —
    not in any UI. Env-configured (operator/pilot) keys are exempt."""
    if not authorization or config.FREE_MONTHLY_QUOTA <= 0:
        return
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        return
    digest = hashlib.sha256(token.encode()).hexdigest()
    key_row = find_api_key(digest)
    if not key_row:
        return
    user = get_user_by_id(key_row["user_id"])
    if not user or user["plan"] != "free":
        return
    usage = usage_for_client(digest[:12], since_ts=_month_start_ts())
    if usage["month_total"] >= config.FREE_MONTHLY_QUOTA:
        raise HTTPException(status_code=429, detail={
            "error": "quota_exceeded", "plan": "free",
            "limit_per_month": config.FREE_MONTHLY_QUOTA,
            "reason": "free plan monthly request limit reached"})


# --- Google sign-in (OAuth 2.0) ----------------------------------------------
# Full authorization-code flow. Accounts are provisioned on first
# successful login with the Free plan assigned server-side. Without
# GOOGLE_CLIENT_ID/SECRET configured, the start endpoint 404s and the
# auth pages disable the Google button — no decorative buttons.

_OAUTH_STATE_COOKIE = "verity_oauth_state"


def _oauth_redirect_uri(request: Request) -> str:
    base = config.OAUTH_REDIRECT_BASE or str(request.base_url)
    return base.rstrip("/") + "/v1/auth/google/callback"


def _set_session_cookie(request: Request, resp, token: str) -> None:
    resp.set_cookie(_SESSION_COOKIE, token, max_age=_SESSION_TTL,
                    httponly=True, samesite="lax", path="/",
                    secure=request.url.scheme == "https")


def _new_session_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    create_session(user_id,
                   hashlib.sha256(token.encode()).hexdigest(),
                   _SESSION_TTL)
    return token


@app.get("/v1/auth/providers")
def auth_providers():
    return {"google": bool(config.GOOGLE_CLIENT_ID
                           and config.GOOGLE_CLIENT_SECRET),
            "password": True}


@app.get("/v1/auth/google/start", include_in_schema=False)
def google_start(request: Request):
    if not (config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET):
        raise HTTPException(status_code=404, detail={
            "error": "google_not_configured"})
    state = secrets.token_urlsafe(24)
    params = urlencode({
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": _oauth_redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    })
    resp = RedirectResponse(
        "https://accounts.google.com/o/oauth2/v2/auth?" + params,
        status_code=302)
    resp.set_cookie(_OAUTH_STATE_COOKIE, state, max_age=600,
                    httponly=True, samesite="lax", path="/",
                    secure=request.url.scheme == "https")
    return resp


async def _google_exchange(code: str, redirect_uri: str):
    async with httpx.AsyncClient(timeout=20.0) as http:
        resp = await http.post("https://oauth2.googleapis.com/token",
                               data={"code": code,
                                     "client_id": config.GOOGLE_CLIENT_ID,
                                     "client_secret":
                                         config.GOOGLE_CLIENT_SECRET,
                                     "redirect_uri": redirect_uri,
                                     "grant_type": "authorization_code"})
        if resp.status_code != 200:
            return None
        return resp.json().get("access_token")


async def _google_userinfo(access_token: str):
    async with httpx.AsyncClient(timeout=20.0) as http:
        resp = await http.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"})
        if resp.status_code != 200:
            return None
        return resp.json()


@app.get("/v1/auth/google/callback", include_in_schema=False)
async def google_callback(request: Request, code: str | None = None,
                          state: str | None = None,
                          error: str | None = None):
    def fail(reason: str):
        return RedirectResponse(f"/login?error={reason}",
                                status_code=302)

    if error or not code:
        return fail("google_denied")
    expected = request.cookies.get(_OAUTH_STATE_COOKIE, "")
    if not expected or not state or not hmac.compare_digest(expected,
                                                           state):
        return fail("google_state")
    access_token = await _google_exchange(
        code, _oauth_redirect_uri(request))
    if not access_token:
        return fail("google_exchange")
    info = await _google_userinfo(access_token)
    if not info or not info.get("email") or \
            not info.get("email_verified"):
        return fail("google_unverified")
    email = str(info["email"]).strip().lower()
    user = get_user_by_email(email)
    if not user:
        user_id = create_user(email, "oauth$google", "")
        user = get_user_by_id(user_id)
    if not active_api_key(user["id"]):
        _portal_key(user["id"])
    resp = RedirectResponse("/dashboard", status_code=302)
    _set_session_cookie(request, resp, _new_session_token(user["id"]))
    resp.delete_cookie(_OAUTH_STATE_COOKIE, path="/")
    return resp


@app.post("/v1/chat/completions")
async def chat_completions(req: ChatRequest, request: Request,
                           authorization: str | None = Header(default=None)):
    started = time.perf_counter()
    if not _client_authorized(authorization):
        raise HTTPException(status_code=401, detail={
            "error": "invalid_api_key",
            "reason": "present your Verity client key as "
                      "'Authorization: Bearer <key>'"})
    client = _client_key(request)
    if _rate_limited(client):
        raise HTTPException(status_code=429, detail={"error": "rate_limited"})
    _enforce_free_quota(authorization)
    combined = "\n".join(m.content for m in req.messages)
    if len(combined) > config.MAX_INPUT_CHARS:
        raise HTTPException(status_code=413, detail={
            "error": "request_too_large",
            "limit_chars": config.MAX_INPUT_CHARS})
    if len(req.policy_context) > config.MAX_POLICY_CHARS:
        raise HTTPException(status_code=413, detail={
            "error": "context_too_large", "field": "policy_context",
            "limit_chars": config.MAX_POLICY_CHARS})
    if len(req.grounding_context) > config.MAX_GROUNDING_CHARS:
        raise HTTPException(status_code=413, detail={
            "error": "context_too_large", "field": "grounding_context",
            "limit_chars": config.MAX_GROUNDING_CHARS})

    # 1. Guard: screen EVERY message, whatever its role (audit F7).
    # Screening only user messages let an injection ride in on a system,
    # assistant, or tool message — pasted into a RAG template, say — and
    # reach the model unscreened. Signals from all messages are merged;
    # the first blocking message's role is recorded in the flags so the
    # trace shows where the attack rode in.
    flags: list[str] = []
    blocked_role: str | None = None
    for m in req.messages:
        v = screen(m.content)
        for s in v["signals"]:
            if s not in flags:
                flags.append(s)
        if v["blocked"] and blocked_role is None:
            blocked_role = m.role
    if blocked_role is not None:
        flags.append(f"role:{blocked_role}")
    cid = _client_id(authorization)
    if blocked_role is not None and config.BLOCK_ON_INJECTION:
        log_trace(req.model, combined, "", 0.0, blocked=True, flags=flags,
                  client_id=cid)
        raise HTTPException(status_code=400, detail={
            "error": "blocked_by_verity_guard", "matched_rules": flags})

    # 1b. Policy guard (request side): stop requests seeking an action the
    # business policy prohibits outright, before the model can comply.
    if req.policy_context:
        pol = policy_check_request(req.policy_context, combined)
        if pol["blocked"]:
            pflags = list(flags) + ["policy_violation"]
            log_trace(req.model, combined, "", 0.0, blocked=True,
                      flags=pflags, client_id=cid)
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
                      flags=pflags, client_id=cid)
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
              faithfulness=score["score"] if score else None,
              client_id=cid)

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

from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

_site_dir = Path(__file__).resolve().parent.parent / "site"


@app.get("/pilot", include_in_schema=False)
def pilot_page():
    return FileResponse(_site_dir / "pilot.html")


@app.get("/app", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
def dashboard_page():
    return FileResponse(_site_dir / "app.html")


@app.get("/product", include_in_schema=False)
def product_page():
    return FileResponse(_site_dir / "product.html")


@app.get("/playground", include_in_schema=False)
def playground_page():
    return FileResponse(_site_dir / "playground.html")


@app.get("/pricing", include_in_schema=False)
def pricing_page():
    return FileResponse(_site_dir / "pricing.html")


@app.get("/signup", include_in_schema=False)
def signup_page():
    return FileResponse(_site_dir / "signup.html")


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(_site_dir / "login.html")


@app.get("/unsubscribe", include_in_schema=False)
def unsubscribe_page():
    return FileResponse(_site_dir / "unsubscribe.html")


@app.get("/documentation", include_in_schema=False)
def docs_page():
    # Not /docs: that path stays 404 on purpose — the audit disabled
    # FastAPI's Swagger UI there, and this page must not reoccupy it.
    return FileResponse(_site_dir / "docs.html")


if _site_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_site_dir), html=True),
              name="site")
