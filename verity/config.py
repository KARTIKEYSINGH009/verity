"""Runtime configuration, all overridable via environment variables."""
import os


def _int_env(name: str, default: int) -> int:
    """Parse an integer env var; a malformed value falls back to the
    default with a warning instead of crashing startup."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"warning: {name}={raw!r} is not an integer; using {default}")
        return default


UPSTREAM_BASE_URL = os.getenv("VERITY_UPSTREAM_BASE_URL", "https://api.openai.com")
UPSTREAM_API_KEY = os.getenv("VERITY_UPSTREAM_API_KEY", "")
MOCK_MODE = os.getenv("VERITY_MOCK_MODE", "true").lower() == "true"
# On Vercel the project filesystem is read-only; /tmp is the writable spot.
_default_db = "/tmp/verity.db" if os.getenv("VERCEL") else "verity.db"
DB_PATH = os.getenv("VERITY_DB_PATH", _default_db)
# Block the request when the guard fires (vs. just flagging it).
BLOCK_ON_INJECTION = os.getenv("VERITY_BLOCK_ON_INJECTION", "true").lower() == "true"
# LLM-as-judge settings (milestone 2).
JUDGE_MODEL = os.getenv("VERITY_JUDGE_MODEL", "gpt-4o-mini")
JUDGE_ENABLED = os.getenv("VERITY_JUDGE_ENABLED", "true").lower() == "true"
# Admin key required to read /v1/traces. Empty (the default) disables the
# traces endpoint entirely — the safe default for public deployments,
# since traces contain raw prompts and answers.
ADMIN_KEY = os.getenv("VERITY_ADMIN_KEY", "")
# Abuse controls for the public chat endpoint.
MAX_INPUT_CHARS = _int_env("VERITY_MAX_INPUT_CHARS", 20000)
RATE_LIMIT_PER_MIN = _int_env("VERITY_RATE_LIMIT_PER_MIN", 120)
# Interactive API docs (/docs, /redoc, /openapi.json) are off by default:
# a public gateway should not publish a map of its own API surface.
ENABLE_DOCS = os.getenv("VERITY_ENABLE_DOCS", "false").lower() == "true"
# Trace retention: rows older than this many days are pruned on write,
# so the SQLite log cannot grow without bound. 0 disables pruning.
TRACE_RETENTION_DAYS = _int_env("VERITY_TRACE_RETENTION_DAYS", 30)
# Client API keys for /v1/chat/completions (audit F2). Clients present
# their key as "Authorization: Bearer <key>" — the OpenAI client does
# this automatically when its api_key is set to the Verity key. Give
# each client its own key: VERITY_CLIENT_KEYS is a comma-separated list;
# VERITY_CLIENT_KEY sets a single one. Empty (the default) leaves the
# endpoint open, which is right for the public mock demo and local dev —
# but a LIVE deployment refuses to start without keys (see the gateway
# startup guard) unless VERITY_ALLOW_OPEN=true is set deliberately.


def _keys_env() -> list[str]:
    keys = [p.strip() for p in os.getenv("VERITY_CLIENT_KEYS", "").split(",")]
    single = os.getenv("VERITY_CLIENT_KEY", "").strip()
    if single:
        keys.append(single)
    return [k for k in keys if k]


CLIENT_KEYS = _keys_env()
ALLOW_OPEN = os.getenv("VERITY_ALLOW_OPEN", "false").lower() == "true"
