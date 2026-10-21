"""Runtime configuration, all overridable via environment variables."""
import os

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
MAX_INPUT_CHARS = int(os.getenv("VERITY_MAX_INPUT_CHARS", "20000"))
RATE_LIMIT_PER_MIN = int(os.getenv("VERITY_RATE_LIMIT_PER_MIN", "120"))
