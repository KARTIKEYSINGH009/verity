"""Credential-injecting proxy for LOCAL live-mode verification.

The Verity gateway takes its upstream key from an environment variable,
but a key stored in Muse's Secure Vault is never exposed as a value —
it reaches a request through the connector surrogate exchange. This
proxy bridges the two for local testing:

    gateway --(localhost, dummy key)--> this proxy --(surrogate)--> Groq

Point the gateway at it with:
    VERITY_UPSTREAM_BASE_URL=http://127.0.0.1:9103/openai

Not used in production: a deployed gateway on Vercel gets the real key
as a platform env var, and its httpx user-agent passes Groq's
Cloudflare (only the Python-urllib UA is banned — which is why this
proxy sets an explicit UA on its outbound calls).

Run:  uvicorn scripts.groq_proxy:app --port 9103
"""
import json
import sys
import urllib.error
import urllib.request

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")
from dynamic_credentials import add_surrogate_to_request  # noqa: E402

TARGET = "https://api.groq.com/openai/v1/chat/completions"

app = FastAPI(title="Verity local Groq proxy")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError("redirect refused, verify the endpoint")


@app.get("/health")
def health():
    return {"status": "ok", "proxy": "groq"}


@app.post("/openai/v1/chat/completions")
async def forward(request: Request):
    payload = await request.body()
    req = urllib.request.Request(
        TARGET, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "openai-python/1.0"})
    add_surrogate_to_request(req, "custom.groq",
                             allowed_hosts=["api.groq.com"])
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=120) as resp:
            return JSONResponse(status_code=resp.status,
                                content=json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            content = json.loads(body)
        except ValueError:
            content = {"error": body[:500]}
        return JSONResponse(status_code=e.code, content=content)
