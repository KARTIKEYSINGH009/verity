# Meta swap checklist (not yet verified)

Status at the time of writing: the Meta Model API account is restricted
after a payment-hold failure. Credits showing in an account do not prove
the API works. Do not label any run as Llama until every step below is
checked with a real run.

## What is already Meta-ready in code

- redteam/llm.py is OpenAI-compatible. It posts to
  {base_url}/chat/completions with a Bearer key, max_tokens 300, and a
  120 second timeout, and refuses redirects.
- redteam/engine.py reads REDTEAM_GENERATOR_MODEL,
  REDTEAM_TARGET_MODEL, and REDTEAM_JUDGE_MODEL from the environment.
  All three must be set for a Meta run. Setting only generator and judge
  leaves the target on its Groq default.
- redteam/server.py shows the actual models from a live run trace in the
  sidebar and pipeline header. Demo runs show "Demo (simulated)".

## Steps to verify a Meta run

1. Confirm the Meta account is unblocked and a fresh API key works.
   Test with one small chat-completions call outside the console first.
2. Pick and record exact Meta model names for all three roles:
   generator, target, and judge. Do not guess names from memory.
3. Run:
   REDTEAM_PROVIDER=env REDTEAM_BASE_URL=https://api.llama.com/compat/v1 \
   REDTEAM_API_KEY=<key from secure storage, never in chat or in code> \
   REDTEAM_GENERATOR_MODEL=<exact name> \
   REDTEAM_TARGET_MODEL=<exact name> \
   REDTEAM_JUDGE_MODEL=<exact name> \
   python -m redteam.console run
4. Check the saved run JSON in redteam_runs/. Confirm:
   - provider_base_url is the Meta compat URL
   - models.generator, models.target, and models.judge are the Meta names
   - no family is generator_empty
   - judge verdicts and guard_call_correct are coherent (see engine.py)
5. Only after step 4, update submission text, README, and any demo
   screenshot to say Llama, with the exact model names and the run date.
6. If Meta stays blocked, the honest fallback is: Groq live run plus
   demo mode, with Meta listed as "provider-agnostic, Meta swap ready
   but unverified". That is weaker for the 25% Meta Tooling score, but
   it is true. Do not present Groq results as Meta results.

## What still cannot be fixed by code alone

- Unblocking the Meta account.
- A hosted demo link. The console binds 127.0.0.1 only. Hosting needs
  a separate deployment decision, with auth and rate limits reviewed
  first, because POST /run spends LLM budget.
- A demo video and a submission writeup. Those are demo work, not code
  in this branch.
