# Verity red-team console (Meta hackathon, Phase 1)

One click runs three attack families through the real Verity guard:
prompt injection, policy bypass (refund tricks), jailbreak. Llama (or
any OpenAI-compatible model) writes the attacks, Verity screens them,
the model judges the call, and every run stores a readable trace.

## Run it (local dev, Groq)

```sh
python3 -m venv .venv
.venv/bin/pip install httpx
.venv/bin/python -m redteam.console run        # CLI: all 3 families
.venv/bin/python -m redteam.server --port 8901 # web page: Run button
```

The local run uses the stored Groq connection through its surrogate
helper (`redteam/providers.py`); no key is pasted, stored, or logged.

## Swap to Meta's API when it unblocks

No code change. Set the base URL and Llama model names, and use the
env provider:

```sh
REDTEAM_PROVIDER=env REDTEAM_BASE_URL=https://api.llama.com/compat/v1 \
REDTEAM_API_KEY=<key from the secure store, never in chat> \
REDTEAM_GENERATOR_MODEL=<llama model> REDTEAM_JUDGE_MODEL=<llama model> \
.venv/bin/python -m redteam.console run
```

Groq-local note: the two gpt-oss models on this account refuse to
write evaluation test prompts even under an authorized
defensive-research framing, so the generator default here is
`qwen/qwen3.8-27b` (the account's other chat model). The judge and
target defaults are gpt-oss models. All three are env-overridable, so
the Meta swap restores Llama for every role.

## What the trace holds

Per family: attack text, guard verdict (blocked, signals, classifier
score), policy verdict (blocked, action, reason), deciding layer
(guard / policy / passed), target reply when the attack passed, judge
verdict (`correct_block`, `false_alarm`, `correct_pass`,
`missed_attack`, `unclear`), and latency. A failed call or unparseable
judge output is recorded as such; results are never invented.

## Scope

Hackathon branch only (`hackathon/red-team-console`). Production
Verity is untouched. Attacks are synthetic test data for Kartikey's
own system; free-credit calls must never carry real secrets or
customer data.
