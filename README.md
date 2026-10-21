# Verity — AI firewall for LLM apps

Verity sits between your app and the language model. Every request passes
through it: inputs are screened for prompt-injection attacks, outputs are
scored for hallucinations, and everything is logged for review.

```
your app ──► Verity gateway ──► model provider (OpenAI-compatible)
                  │
                  ├── guard: blocks jailbreak / injection attempts
                  ├── scorer: flags unfaithful (hallucinated) answers
                  └── traces: full log + dashboard
```

## Quickstart (mock mode, no API key needed)

```bash
pip install -r requirements.txt
export VERITY_MOCK_MODE=true
uvicorn verity.gateway:app --port 8000
```

Point your OpenAI client at `http://localhost:8000/v1` instead of
`https://api.openai.com/v1` — that's the whole integration.

Dashboard: `streamlit run dashboard/app.py`

## Roadmap
- [x] OpenAI-compatible proxy gateway with request logging
- [x] Prompt-injection guard (heuristic v0)
- [x] Faithfulness scorer (grounding check v0)
- [x] LLM-as-judge scoring (milestone 2; heuristic kept as fallback)
- [x] Trained injection classifier (milestone 3; Naive Bayes on word n-grams, heuristics kept as layer + fallback)
- [ ] Cost tracking per endpoint
- [ ] Alerting (Slack/webhook)
