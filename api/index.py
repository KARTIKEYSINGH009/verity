"""Vercel serverless wrapper for the Verity Red-Team Console.

Vercel serves api/index.py at /api. This wrapper reuses the local
console handler (redteam.server.Handler) so the deployed page, fixtures
and demo run are exactly the local ones, with one path normalisation:
a request to /api itself is the console home page.

Public deploy runs demo-only by design: no REDTEAM_API_KEY or
GROQ_API_KEY is set on Vercel, so POST /run falls back to
engine.run_demo (real local guard/policy, canned probes, no LLM spend).
Live model runs need a key set in the project env, which is a separate,
explicit step.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redteam.server import Handler  # noqa: E402


class handler(Handler):
    def _normalised_path(self):
        path = self.path.split("?", 1)[0]
        if path in ("/api", "/api/"):
            return "/"
        return path

    def do_GET(self):
        self.path = self._normalised_path()
        super().do_GET()

    def do_POST(self):
        self.path = self._normalised_path()
        super().do_POST()
