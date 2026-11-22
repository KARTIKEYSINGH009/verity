from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlparse

_RAW_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"'\)\]]+")
_MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_HTML_ATTR_URL_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CARD_RE = re.compile(r"(?<!\d)(?<!\d[ -])(?:\d[ -]?){12,18}\d(?![ -]?\d)")
_PHONE_RE = re.compile(
    r"(?<!\d)(?<!\d[.-])"
    r"(?:"
    r"(?:\+\d{1,3}[ -.]?)?\(\d{2,4}\)[ -.]?\d{3,4}[ -.]?\d{3,4}"
    r"|(?:\+\d{1,3}[ -.]?|1[ -.]?)?\d{3,4}[ -.]\d{3,4}[ -.]\d{4}"
    r"|\+\d{1,3}(?:[ -.]?\d{2,4}){2,4}"
    # Indian mobile: 10 digits starting 6-9, optional +91, optional
    # 5+5 space (98765 43210). Without this a bare mobile slipped past.
    r"|(?:\+91[ -.]?)?[6-9]\d{4}[ -.]?\d{5}"
    r")"
    r"(?!\d)"
)

_REDACTION_TOKEN = "[redacted]"


def _add_finding(findings: list[str], item: str) -> None:
    if item not in findings:
        findings.append(item)


def _extract_url_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for match in _RAW_URL_RE.finditer(text):
        candidates.append(match.group(0).rstrip(".,;:!?'\""))
    for match in _MD_LINK_RE.finditer(text):
        candidates.append(match.group(1).strip())
    for match in _HTML_ATTR_URL_RE.finditer(text):
        candidates.append(match.group(1).strip())
    return candidates


def scan_output(
    text: str,
    *,
    canaries: Iterable[str] = (),
    allowed_url_hosts: Iterable[str] = (),
) -> dict[str, object]:
    """Scan model output before returning it to the caller."""
    findings: list[str] = []
    blocked = False

    for canary in canaries:
        if canary and canary in text:
            blocked = True
            _add_finding(findings, "canary")

    allowed_hosts = {host.lower() for host in allowed_url_hosts if host}
    for candidate in _extract_url_candidates(text):
        if not candidate or candidate.startswith("#"):
            continue
        parsed = urlparse(candidate)
        host = parsed.hostname
        if not host:
            # Relative links (e.g. /path, ./file) and anchor fragments have no host.
            continue
        if host.lower() not in allowed_hosts:
            blocked = True
            _add_finding(findings, f"url:{host.lower()}")

    redacted_text = text
    redacted = False

    redacted_text, email_count = _EMAIL_RE.subn(_REDACTION_TOKEN, redacted_text)
    if email_count:
        redacted = True
        _add_finding(findings, "email")

    redacted_text, card_count = _CARD_RE.subn(_REDACTION_TOKEN, redacted_text)
    if card_count:
        redacted = True
        _add_finding(findings, "card")

    redacted_text, phone_count = _PHONE_RE.subn(_REDACTION_TOKEN, redacted_text)
    if phone_count:
        redacted = True
        _add_finding(findings, "phone")

    if blocked:
        return {
            "action": "block",
            "text": "",
            "findings": findings,
        }

    if redacted:
        return {
            "action": "redact",
            "text": redacted_text,
            "findings": findings,
        }

    return {
        "action": "allow",
        "text": text,
        "findings": findings,
    }