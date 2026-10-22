"""Crash / robustness fuzz probes for the gateway.

Fires malformed, oversized, and type-confused inputs at the chat and
auth endpoints and records any 5xx (a crash) or unexpected status.
A healthy gateway answers 2xx/4xx for everything here — never 500.

Usage: python scripts/fuzz_probes.py [base_url]
Default base: http://127.0.0.1:8125 (start a local gateway first).
"""
import json
import sys

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8125"

CHAT = "/v1/chat/completions"
BIG = "A" * 200_000

CASES = [
    # (name, method, path, kwargs)
    ("chat: invalid json", "POST", CHAT,
     {"content": "{not json", "headers": {"Content-Type": "application/json"}}),
    ("chat: json array body", "POST", CHAT, {"json": [1, 2, 3]}),
    ("chat: empty object", "POST", CHAT, {"json": {}}),
    ("chat: messages missing", "POST", CHAT, {"json": {"model": "mock"}}),
    ("chat: messages not a list", "POST", CHAT,
     {"json": {"model": "mock", "messages": "hello"}}),
    ("chat: messages empty list", "POST", CHAT,
     {"json": {"model": "mock", "messages": []}}),
    ("chat: message no role", "POST", CHAT,
     {"json": {"model": "mock", "messages": [{"content": "hi"}]}}),
    ("chat: message no content", "POST", CHAT,
     {"json": {"model": "mock", "messages": [{"role": "user"}]}}),
    ("chat: content is number", "POST", CHAT,
     {"json": {"model": "mock", "messages": [{"role": "user", "content": 42}]}}),
    ("chat: content is list", "POST", CHAT,
     {"json": {"model": "mock", "messages": [
         {"role": "user", "content": [{"type": "text", "text": "hi"}]}]}}),
    ("chat: content null", "POST", CHAT,
     {"json": {"model": "mock", "messages": [{"role": "user", "content": None}]}}),
    ("chat: role is weird case", "POST", CHAT,
     {"json": {"model": "mock", "messages": [{"role": "SYSTEM", "content": "hi"}]}}),
    ("chat: huge content", "POST", CHAT,
     {"json": {"model": "mock", "messages": [{"role": "user", "content": BIG}]}}),
    ("chat: huge policy_context", "POST", CHAT,
     {"json": {"model": "mock", "policy_context": BIG,
               "messages": [{"role": "user", "content": "hi"}]}}),
    ("chat: stream true", "POST", CHAT,
     {"json": {"model": "mock", "stream": True,
               "messages": [{"role": "user", "content": "hi"}]}}),
    ("chat: null bytes + RTL + ZWSP", "POST", CHAT,
     {"json": {"model": "mock", "messages": [
         {"role": "user", "content": "a\u0000b\u202ec\u200bd"}]}}),
    ("chat: emoji flood x5000", "POST", CHAT,
     {"json": {"model": "mock", "messages": [
         {"role": "user", "content": "🙂" * 5000}]}}),
    ("chat: 200 messages", "POST", CHAT,
     {"json": {"model": "mock", "messages": [
         {"role": "user", "content": "hi"}] * 200}}),
    ("chat: bad auth scheme", "POST", CHAT,
     {"json": {"model": "mock", "messages": [{"role": "user", "content": "hi"}]},
      "headers": {"Authorization": "Basic abc"}}),
    ("chat: bearer empty", "POST", CHAT,
     {"json": {"model": "mock", "messages": [{"role": "user", "content": "hi"}]},
      "headers": {"Authorization": "Bearer"}}),
    ("signup: email is list", "POST", "/v1/auth/signup",
     {"json": {"email": ["a@b.co"], "password": "whatever 123"}}),
    ("signup: password is number", "POST", "/v1/auth/signup",
     {"json": {"email": "fz@acme.example", "password": 12345678}}),
    ("signup: huge email", "POST", "/v1/auth/signup",
     {"json": {"email": ("a" * 500) + "@acme.example",
               "password": "whatever 123"}}),
    ("signup: unicode email", "POST", "/v1/auth/signup",
     {"json": {"email": "उपयोगकर्ता@acme.example",
               "password": "whatever 123"}}),
    ("login: nulls", "POST", "/v1/auth/login",
     {"json": {"email": None, "password": None}}),
    ("forgot: email is object", "POST", "/v1/auth/forgot-password",
     {"json": {"email": {"x": 1}}}),
    ("reset: token is list", "POST", "/v1/auth/reset-password",
     {"json": {"token": ["a"], "password": "whatever 123"}}),
    ("verify: token is object", "POST", "/v1/auth/verify-email",
     {"json": {"token": {"x": 1}}}),
    ("pilot: secret-shaped field", "POST", "/v1/pilot-requests",
     {"json": {"company": "FuzzCo", "email": "fz@acme.example",
               "role": "CTO", "use_case": "support",
               "api_key": "sk-should-be-rejected"}}),
    ("pilot: huge use_case", "POST", "/v1/pilot-requests",
     {"json": {"company": "FuzzCo", "email": "fz@acme.example",
               "role": "CTO", "use_case": BIG}}),
    ("me: garbage session cookie", "GET", "/v1/me",
     {"cookies": {"verity_session": "garbage!!"}}),
    ("traces: no admin key set", "GET", "/v1/traces", {}),
    ("google start x2", "GET", "/v1/auth/google/start",
     {"follow_redirects": False}),
    ("unknown route", "GET", "/v1/definitely-not-a-route", {}),
    ("chat: GET instead of POST", "GET", CHAT, {}),
]


def main() -> int:
    crashes, odd = [], []
    with httpx.Client(base_url=BASE, trust_env=False, timeout=30.0) as c:
        for name, method, path, kwargs in CASES:
            try:
                r = c.request(method, path, **kwargs)
                code = r.status_code
            except Exception as exc:  # connection reset etc. = crash-class
                crashes.append((name, f"EXCEPTION {exc!r}"))
                continue
            flag = ""
            if code >= 500:
                crashes.append((name, code))
                flag = "  <-- CRASH"
            elif code < 200 or code >= 400 and code not in (
                    400, 401, 403, 404, 405, 409, 413, 422, 429):
                odd.append((name, code))
                flag = "  <-- unusual"
            print(f"{code}  {name}{flag}")
    print(f"\n{len(CASES)} probes | crashes: {len(crashes)} | unusual: {len(odd)}")
    for name, code in crashes:
        print("CRASH:", name, code)
    return 1 if crashes else 0


if __name__ == "__main__":
    raise SystemExit(main())
