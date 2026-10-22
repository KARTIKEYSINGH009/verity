"""Transactional email for account verification and password resets.

Two provider paths, chosen by configuration; no provider is a valid
state and callers must handle it honestly (the UI says email delivery
is not configured rather than pretending a message was sent):

- Resend (HTTPS API) when RESEND_API_KEY + EMAIL_FROM are set.
- SMTP (STARTTLS) when SMTP_HOST + SMTP_USER + SMTP_PASSWORD +
  EMAIL_FROM are set — works with Gmail app passwords and most
  transactional providers.
"""
import smtplib
import ssl
from email.message import EmailMessage

import httpx

from . import config


def email_configured() -> bool:
    if config.RESEND_API_KEY and config.EMAIL_FROM:
        return True
    return bool(config.SMTP_HOST and config.SMTP_USER
                and config.SMTP_PASSWORD and config.EMAIL_FROM)


def verification_required() -> bool:
    """Verification gates API keys only when it can actually be
    completed — i.e. once a sender exists — unless forced by env."""
    forced = config.EMAIL_VERIFICATION_REQUIRED.strip().lower()
    if forced == "true":
        return True
    if forced == "false":
        return False
    return email_configured()


def send_email(to: str, subject: str, text: str) -> bool:
    """Best-effort send. Returns True only when a provider accepted
    the message; False when unconfigured or the send failed."""
    if not email_configured():
        return False
    if config.RESEND_API_KEY and config.EMAIL_FROM:
        try:
            resp = httpx.post(
                "https://api.resend.com/emails",
                headers={"Authorization":
                         f"Bearer {config.RESEND_API_KEY}"},
                json={"from": config.EMAIL_FROM, "to": [to],
                      "subject": subject, "text": text},
                timeout=20.0)
            return resp.status_code in (200, 201)
        except Exception:
            return False
    msg = EmailMessage()
    msg["From"] = config.EMAIL_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT,
                          timeout=20) as server:
            server.starttls(context=context)
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception:
        return False


def verification_email(base_url: str, token: str) -> tuple[str, str]:
    link = f"{base_url}/verify-email?token={token}"
    subject = "Verify your Verity email"
    text = (
        "Welcome to Verity.\n\n"
        "Confirm this email address to activate your API key:\n"
        f"{link}\n\n"
        "The link expires in 24 hours. If you did not create a Verity"
        " account, you can ignore this message.\n")
    return subject, text


def reset_email(base_url: str, token: str) -> tuple[str, str]:
    link = f"{base_url}/reset-password?token={token}"
    subject = "Reset your Verity password"
    text = (
        "A password reset was requested for your Verity account.\n\n"
        "Choose a new password here (the link also confirms your"
        " email):\n"
        f"{link}\n\n"
        "The link expires in 1 hour and can be used once. If you did"
        " not request this, ignore this message — your password stays"
        " unchanged.\n")
    return subject, text
