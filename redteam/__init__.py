"""Red-team console for the Meta hackathon (Phase 1 core loop).

Llama (or any OpenAI-compatible model) writes attacks, Verity's guard
screens them, the same model judges the call, and every run stores a
readable trace. Nothing here is faked: if a model call fails or returns
junk, the trace says so.
"""

FAMILIES = ("prompt_injection", "policy_bypass", "jailbreak")
