"""Runtime configuration, all overridable via environment variables."""
import os

UPSTREAM_BASE_URL = os.getenv("VERITY_UPSTREAM_BASE_URL", "https://api.openai.com")
UPSTREAM_API_KEY = os.getenv("VERITY_UPSTREAM_API_KEY", "")
MOCK_MODE = os.getenv("VERITY_MOCK_MODE", "true").lower() == "true"
DB_PATH = os.getenv("VERITY_DB_PATH", "verity.db")
# Block the request when the guard fires (vs. just flagging it).
BLOCK_ON_INJECTION = os.getenv("VERITY_BLOCK_ON_INJECTION", "true").lower() == "true"
# LLM-as-judge settings (milestone 2).
JUDGE_MODEL = os.getenv("VERITY_JUDGE_MODEL", "gpt-4o-mini")
JUDGE_ENABLED = os.getenv("VERITY_JUDGE_ENABLED", "true").lower() == "true"
