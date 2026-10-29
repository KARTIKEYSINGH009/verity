"""Provider wiring for local runs.

"groq" uses the registered custom.groq connection through its surrogate
helper, so no key is ever pasted, stored, or logged here. This is local
development wiring only: the submitted console uses redteam.llm (env key),
and the Meta swap is a base-URL plus model-name change, not new code.
"""

import os
import sys

def groq_chat_fn(max_tokens: int = 300):
    """chat_fn(model, messages) -> str via the stored Groq connection.

    max_tokens is capped low on purpose: the free tier limits output
    tokens per minute (Qwen's tier allows 1000), and every console call
    is a short attack, reply, or verdict.
    """
    connector_dir = os.path.expanduser(
        "~/workspace/custom-connectors/custom.groq/bin")
    if connector_dir not in sys.path:
        sys.path.insert(0, connector_dir)
    try:
        import groq_call  # noqa: E402
    except ImportError as e:
        raise RuntimeError(
            "Local custom.groq connector helper is not available. "
            "Set REDTEAM_PROVIDER=env with REDTEAM_API_KEY (or GROQ_API_KEY)."
        ) from e

    def run(model: str, messages: list) -> str:
        result = groq_call.call("POST", "/chat/completions",
                                {"model": model, "messages": messages,
                                 "max_tokens": max_tokens})
        try:
            return result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise RuntimeError(f"unexpected response shape: {str(result)[:300]}")
    return run


def get_chat_fn(provider: str | None = None):
    """Resolve the chat function for a run.

    provider defaults to REDTEAM_PROVIDER. If unset, it falls back to "env"
    if REDTEAM_API_KEY or GROQ_API_KEY is present in the environment,
    otherwise "groq" for local custom-connector runs.
    "env" uses REDTEAM_BASE_URL / REDTEAM_API_KEY (the submission path).
    """
    if provider:
        name = provider.lower()
    elif os.environ.get("REDTEAM_PROVIDER"):
        name = os.environ["REDTEAM_PROVIDER"].lower()
    elif os.environ.get("REDTEAM_API_KEY") or os.environ.get("GROQ_API_KEY"):
        name = "env"
    else:
        name = "groq"

    if name == "groq":
        return groq_chat_fn()
    if name == "env":
        from .llm import env_chat_fn
        return env_chat_fn()
    raise ValueError(f"unknown provider {name!r}; use 'groq' or 'env'")
