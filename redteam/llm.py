"""OpenAI-compatible chat client (stdlib only).

Used for real deployments and for the Meta swap: point REDTEAM_BASE_URL
at https://api.llama.com/compat/v1 with a Meta key in REDTEAM_API_KEY
and the same console code runs against Meta's API. No key is ever stored
in this repo; the key comes from the environment at run time.
"""

import json
import os
import urllib.error
import urllib.request


class ChatError(RuntimeError):
    pass


def chat(base_url: str, api_key: str, model: str,
         messages: list, timeout: int = 120,
         max_tokens: int = 800) -> str:  # gpt-oss reasoning needs headroom; 300 gave empty replies
    """One chat-completions call; returns the assistant text."""
    payload = json.dumps({"model": model, "messages": messages,
                          "max_tokens": max_tokens}).encode()
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions", data=payload,
        method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}",
                 "User-Agent": "verity-redteam-console/1.0"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise ChatError(
            f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}")
    except urllib.error.URLError as e:
        raise ChatError(f"request failed: {e}")
    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise ChatError(f"unexpected response shape: {str(body)[:300]}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ChatError("redirect refused, verify the endpoint")


def env_chat_fn():
    """Build a chat_fn(model, messages) -> str from the environment."""
    base_url = os.environ.get("REDTEAM_BASE_URL",
                              "https://api.groq.com/openai/v1")
    api_key = os.environ.get("REDTEAM_API_KEY") or os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        raise ChatError("REDTEAM_API_KEY (or GROQ_API_KEY) is not set; see README for setup")
    return lambda model, messages: chat(base_url, api_key, model, messages)
