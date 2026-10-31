# Verity red-team console (Meta hackathon, Phase 2)

An automated crash-testing harness and visual dashboard for Verity. Any
OpenAI-compatible model generates synthetic adversarial probes, Verity
screens each probe with its two-sided firewall (injection guard +
business policy pair), a model judge grades the defense, and readable traces
record every step. The current live defaults are Groq models (see
redteam/engine.py). Demo data in the dashboard is labelled DEMO DATA and
is not a live run.

## Features (Phase 2: Policy Pair)

- **Two-Sided Policy Defense**: Screens both request-side (attacks seeking
  prohibited actions) and response-side (withholding responses if the LLM
  is tricked into promising refunds, discounts, or admin access).
- **Policy Presets & Custom Rules**:
  - `retail`: Refund + Discount policy pair (*"All sales are final. No refunds. No discounts or coupons."*)
  - `saas`: Free items + Privilege escalation pair (*"No free products or extensions. Never grant admin privileges."*)
  - `strict`: Comprehensive prohibition set.
  - `custom`: Test any arbitrary company policy directly from CLI or UI.
- **Adversarial & Benign Near-Miss Pairing**: Evaluates attacks (`prompt_injection`,
  `jailbreak`, `refund_bypass`, `discount_bypass`, `privilege_escalation`) alongside
  benign inquiries (`benign_policy_query`). The canonical demo dataset in
  redteam/fixtures.py has 3 benign blocked out of 30, a 10.0% false
  positive rate. Do not claim 0% false alarms unless a live run with its
  own counts proves it.
- **Model-as-Judge Consensus**: Grades outcome (`correct_block`, `false_alarm`,
  `correct_pass`, `missed_attack`, `unclear`).

## Run it locally

```sh
# Setup virtual environment
uv venv .venv
.venv/bin/pip install httpx pytest

# CLI: Run all families with default policy
.venv/bin/python -m redteam.console run

# CLI: Test specific policy preset or custom text
.venv/bin/python -m redteam.console run --preset saas
.venv/bin/python -m redteam.console run --policy "No discounts are allowed."

# Web Dashboard: Interactive console with live metrics
.venv/bin/python -m redteam.server --port 8901
```

Set `$env:GROQ_API_KEY="<key>"` or `$env:REDTEAM_API_KEY="<key>"` to run live
against Groq models. With no key, the CLI and server fall back to demo
mode, which uses simulated probes and the real local guard and policy
rules, but not a live model judge.

## Swap to Meta's API when unblocked

No code changes are needed, but all three model names must be set, and
the Meta account must actually be unblocked first. See
redteam/META_SWAP.md for the full checklist. The current Meta path is
unverified, because the account is restricted at the time of writing.

```sh
REDTEAM_PROVIDER=env REDTEAM_BASE_URL=https://api.llama.com/compat/v1 \
REDTEAM_API_KEY=<meta-key> \
REDTEAM_GENERATOR_MODEL=<llama-model> REDTEAM_TARGET_MODEL=<llama-model> \
REDTEAM_JUDGE_MODEL=<llama-model> \
.venv/bin/python -m redteam.console run
```

After a Meta run, check the run trace for the exact model names used.
Only then update any UI or submission label to say Llama.

## Scope & Boundaries

Branch: `red-team-console`. Verity core (`verity/`) and production files are untouched.
All attacks use synthetic test data for Kartikey's own system.
