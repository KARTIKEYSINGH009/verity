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
# Persistent store (Phase B): when DATABASE_URL points at Postgres
# (e.g. a Neon connection string), traces live there and survive
# redeploys; traces also gain a per-client identity. Empty (the
# default) keeps the local SQLite store above — right for local dev,
# self-hosters, and the public mock demo.
DATABASE_URL = os.getenv("DATABASE_URL", "")
# Block the request when the guard fires (vs. just flagging it).
BLOCK_ON_INJECTION = os.getenv("VERITY_BLOCK_ON_INJECTION", "true").lower() == "true"
# LLM-as-judge settings (milestone 2).
JUDGE_MODEL = os.getenv("VERITY_JUDGE_MODEL", "gpt-4o-mini")
JUDGE_ENABLED = os.getenv("VERITY_JUDGE_ENABLED", "true").lower() == "true"
# Injection-judge escalation (AEGIS spec, 2026-10-23). Modes:
# off | shadow | enforce_high | enforce. The gateway currently honours
# off/shadow only — enforcement stays behind a separate evidence-based
# approval gate, whatever this variable says.
_raw_ij_mode = os.getenv("VERITY_INJECTION_JUDGE_MODE", "off").lower()
INJECTION_JUDGE_MODE = (_raw_ij_mode if _raw_ij_mode in
                        ("off", "shadow", "enforce_high", "enforce")
                        else "off")
INJECTION_JUDGE_BASE_URL = os.getenv(
    "VERITY_INJECTION_JUDGE_BASE_URL", UPSTREAM_BASE_URL)
_ij_upstream_key = os.getenv("VERITY_UPSTREAM_API_KEY", "")
_ij_key_name = "VERITY_INJECTION_JUDGE" + "_API" + "_KEY"
INJECTION_JUDGE_API_KEY = os.environ.get(_ij_key_name, _ij_upstream_key)
INJECTION_JUDGE_MODEL = os.getenv("VERITY_INJECTION_JUDGE_MODEL", JUDGE_MODEL)
try:
    INJECTION_JUDGE_TIMEOUT_S = float(
        os.getenv("VERITY_INJECTION_JUDGE_TIMEOUT_S", "3"))
except ValueError:
    INJECTION_JUDGE_TIMEOUT_S = 3.0
# Contextual release layer (2026-10-23): off | shadow | on. "on" lets the
# context layer release discussion/transformation blocks under its strict
# conditions; "shadow" computes and trace-flags releases without applying
# them; "off" disables. Founder-approved live ("on") after the frozen-set
# comparison beat the previous screen-only behaviour on every set.
_raw_ctx_mode = os.getenv("VERITY_CONTEXT_RELEASE", "on").lower()
CONTEXT_RELEASE_MODE = (_raw_ctx_mode if _raw_ctx_mode in
                        ("off", "shadow", "on") else "on")
# Admin key required to read /v1/traces. Empty (the default) disables the
# traces endpoint entirely — the safe default for public deployments,
# since traces contain raw prompts and answers.
ADMIN_KEY = os.getenv("VERITY_ADMIN_KEY", "")
# Abuse controls for the public chat endpoint.
MAX_INPUT_CHARS = _int_env("VERITY_MAX_INPUT_CHARS", 20000)
# Hard byte cap on any request body, enforced by middleware before JSON
# parsing (audit batch 2, finding 4); and a cap on message count.
MAX_BODY_BYTES = _int_env("VERITY_MAX_BODY_BYTES", 1_048_576)
MAX_MESSAGES = _int_env("VERITY_MAX_MESSAGES", 100)
RATE_LIMIT_PER_MIN = _int_env("VERITY_RATE_LIMIT_PER_MIN", 120)
# Interactive API docs (/docs, /redoc, /openapi.json) are off by default:
# a public gateway should not publish a map of its own API surface.
ENABLE_DOCS = os.getenv("VERITY_ENABLE_DOCS", "false").lower() == "true"
# Trace retention: rows older than this many days are pruned on write,
# so the SQLite log cannot grow without bound. 0 disables pruning.
TRACE_RETENTION_DAYS = _int_env("VERITY_TRACE_RETENTION_DAYS", 30)
# Pilot intake (POST /v1/pilot-requests, the public /pilot form) belongs
# on the public site only. Client deployments set this to false so a
# stranger's form submission can never land in a client's database.
PILOT_INTAKE = os.getenv("VERITY_PILOT_INTAKE", "true").lower() == "true"
# Google sign-in (OAuth 2.0). Both values come from the Google Cloud
# console for the production origin; when either is empty the Google
# button is disabled on the auth pages and the start endpoint 404s —
# password auth keeps working. The redirect URI registered with Google
# must be <site origin>/v1/auth/google/callback (or the base below).
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
OAUTH_REDIRECT_BASE = os.getenv("VERITY_OAUTH_REDIRECT_BASE", "")
# Free-plan monthly request quota for portal-issued keys, enforced by
# the gateway (counted from the key's own traces). 0 disables it.
FREE_MONTHLY_QUOTA = _int_env("VERITY_FREE_MONTHLY_QUOTA", 1000)
# Transactional email (verification + password reset). A sender is
# configured when EITHER Resend (RESEND_API_KEY + EMAIL_FROM) or SMTP
# (SMTP_HOST + SMTP_USER + SMTP_PASSWORD + EMAIL_FROM) is present.
# Email verification becomes REQUIRED automatically once a sender
# exists (until then new accounts are created verified, so nobody is
# locked out by an email that can never arrive); force it either way
# with VERITY_EMAIL_VERIFICATION_REQUIRED=true/false.
EMAIL_FROM = os.getenv("EMAIL_FROM", "")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = _int_env("SMTP_PORT", 587)
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_VERIFICATION_REQUIRED = os.getenv(
    "VERITY_EMAIL_VERIFICATION_REQUIRED", "")
# Public base for links inside emails; falls back to the request's
# own origin when empty.
PUBLIC_BASE_URL = os.getenv("VERITY_PUBLIC_BASE_URL", "")
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
# Per-field size caps for the optional contexts (audit F7). The message
# cap above cannot see these fields, so without their own caps a caller
# could smuggle an unbounded payload past the size limit in a context.
MAX_POLICY_CHARS = _int_env("VERITY_MAX_POLICY_CHARS", 4000)
MAX_GROUNDING_CHARS = _int_env("VERITY_MAX_GROUNDING_CHARS", 50000)
