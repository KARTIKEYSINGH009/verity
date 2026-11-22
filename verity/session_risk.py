"""Multi-turn session risk tracking for Verity.

Maintains an exponential moving average (EMA) of per-message risk scores
and the last few message texts per (tenant_id, session_id), so multi-turn
attacks split across turns can be detected. In-memory by default; pass a
store object (with the same get/set interface) to __init__ to use Redis
later.
"""

import threading
import time

_ALPHA = 0.4
_MAX_CONTEXT_MESSAGES = 3
_ENTRY_TTL_SECONDS = 15 * 60


class SessionRisk:
    """Thread-safe per-session risk store (in-memory unless a store is given)."""

    def __init__(self, store=None):
        self._store = store if store is not None else {}
        # RLock, not Lock: add() holds the lock while calling _get_entry(),
        # which locks again. A plain Lock would deadlock on every add().
        self._lock = threading.RLock()

    def _store_key(self, tenant_id: str, session_id: str) -> str:
        return f"{tenant_id}:{session_id}"

    def _get_entry(self, tenant_id: str, session_id: str) -> dict:
        with self._lock:
            key = self._store_key(tenant_id, session_id)
            entry = self._store.get(key)
            if entry is None:
                entry = {"ema": 0.0, "texts": [], "updated_at": time.time()}
                self._store[key] = entry
            return entry

    def add(self, tenant_id: str, session_id: str, score: float, text: str | None = None) -> float:
        """Record a message score; return the updated EMA."""
        self.prune()
        with self._lock:
            entry = self._get_entry(tenant_id, session_id)
            entry["ema"] = _ALPHA * score + (1 - _ALPHA) * entry["ema"]
            if text is not None:
                entry["texts"].append(text)
                entry["texts"] = entry["texts"][-_MAX_CONTEXT_MESSAGES:]
            entry["updated_at"] = time.time()
            return entry["ema"]

    def get_risk(self, tenant_id: str, session_id: str) -> float:
        """Return the session EMA, or 0.0 for an unknown session."""
        with self._lock:
            entry = self._store.get(self._store_key(tenant_id, session_id))
            return float(entry["ema"]) if entry is not None else 0.0

    def get_context(self, tenant_id: str, session_id: str) -> list[str]:
        """Return the last 3 message texts, oldest first."""
        with self._lock:
            entry = self._store.get(self._store_key(tenant_id, session_id))
            return list(entry["texts"]) if entry is not None else []

    def prune(self) -> None:
        """Drop entries older than 15 minutes."""
        cutoff = time.time() - _ENTRY_TTL_SECONDS
        with self._lock:
            stale = [
                key
                for key, entry in self._store.items()
                if entry["updated_at"] < cutoff
            ]
            for key in stale:
                del self._store[key]
