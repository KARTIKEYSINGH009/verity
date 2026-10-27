"""Language-independent action/intent check (AEGIS restructure, 2026-10-27).

Sits after the guard and before the context-release layer: the guard is
a fast sieve for injection shapes; this layer judges the *business
action* being asked for, in every language at once. Detection language
never gates it — all lexicons run on every input — so a language-tag
miss cannot cause a bypass miss.

Baseline policy (always on, no client policy needed):
  1. Never skip verification just because someone asks.
  2. Never move money to a new / third-party destination without
     verification.
  3. Never disclose another person's data.
  4. Never redirect credentials/recovery to a new destination.
The mirror image stays allowed: money to your own original destination,
a credential change you ask how to do, a process question. Each rule is
therefore a conjunction (action + bypass/destination/other-person
marker), never a bare action word. Client policies (policy_context)
add on top of this baseline in the gateway; they never subtract from it.
"""
import re

from .language import detect_language

# --- shared building blocks -------------------------------------------------
# Fresh-set round (2026-10-27): G1/G2 wording added only where the twin
# stays safe — every addition below was checked against the twin that
# asks the same thing as a process question.
_SKIP_EN = (
    r"(?:skip|bypass|override).{0,50}"
    r"(?:verif\w*|otp|id check|id proof|passwords?|security questions?|checks)"
    r"|without.{0,30}(?:verif\w*|otp|id check|id proof|passwords?|checks)"
    r"|without.{0,30}prove"
    r"|do not ask me for passwords?|do not ask for (?:verification|verif\w*|otp)"
    r"|do not make me.{0,30}(?:security questions?|passwords?|verif\w*|otp)"
    r"|cannot (?:go through|handle|do) otps?"
    r"|cannot remember (?:any )?passwords?.{0,40}"
    r"(?:let me into|give me access|just)"
)
_SKIP_HING = (
    r"(?:verification|otp|jaanch)\s+mat\s+(?:maango|mango|poochho|puchho)"
    r"|verification\s+skip\s+kar\w*|verification\s+ka\s+time\s+nahi"
    r"|verification\s+ke\s+liye\s+mat\s+(?:ruko|rukna)"
    r"|bina\s+(?:verification|otp|jaanch)"
)
_SKIP_DEVA = (
    r"बिना\s+(?:किसी\s+(?:और\s+)?)?(?:जाँच|सत्यापन|ओटीपी)"
    r"|जाँच\s+किए\s+बिना|बिना\s+जाँच\s+के"
    r"|जाँच\s+मत\s+(?:कीजिए|करो)"
    r"|(?:OTP|ओटीपी).{0,20}बिना|बिना.{0,15}(?:OTP|ओटीपी|जाँच|सत्यापन)"
)
_SKIP = f"(?:{_SKIP_EN}|{_SKIP_HING}|{_SKIP_DEVA})"

_ACTION = (
    r"(?:refund|money|cancel\w*|access|transfer|change|address|account|"
    r"order|send|disclose|details|payment|delivery|bhej|daal|रद्द|पैसा|"
    r"रिफंड|खाता|पता|ऑर्डर|भेज|बता|नंबर)"
)

_MONEY = (
    r"(?:refund|money|transfer|send(?:\s+the)?\s+money|move\s+(?:the\s+)?"
    r"(?:refund|money)|bhej|daal|रिफंड|पैसा|भेज|डाल)"
)
# A money move needs a DEMAND verb, not just money + destination
# co-occurring: "Can a refund go to a different account of mine?" is a
# question about the requester's own account and must pass, while
# "send the refund to this new UPI id" is a demand and must block.
# Threats count as demands (pay-or-else framing). "Of mine / my own"
# after the destination marks it as the requester's own account.
_DEMAND_MONEY = (
    r"(?:send|transfer|redirect|route|move|moved|pay|need|bhej|de\s+do|"
    r"daal|भेज|कर\s+दीजिए|डाल|शिकायत|पुलिस\s+में"
    r"|i will post|post everywhere|go public|will sue|chargeback|"
    r"bad review)"
)
_NEW_DEST = (
    r"(?:cousin|brother|sister|friend|mother|father|wife|husband|partner|"
    r"colleague|someone else|another person)['’]s\s+"
    r"(?:account|card|wallet|upi)"
    r"|(?:different|another|other|new)\s+(?:account|wallet|upi|number)"
    r"|any account i name|this new\s+(?:upi|number|wallet)"
    r"|(?:dost|bhai|behen)\s+ke\s+account|dusre\s+account|naye\s+account"
    r"|is\s+naye\s+(?:upi|number)"
    r"|(?:भाई|दोस्त|दूसरे)\s+.{0,20}खाते\s+में\s+भेज"
    r"|नया\s+(?:खाता|नंबर|वॉलेट|UPI)|नए\s+(?:वॉलेट|UPI)"
    r"|(?:her|his|their)\s+refund.{0,40}(?:my|mine)\s+(?:wallet|account)"
)
_OWN_DEST = re.compile(
    r"(?:different|another|other|new)\s+(?:account|wallet|upi|number)"
    r"\s+of\s+mine|\bmy\s+own\s+(?:account|wallet|upi|number)",
    re.IGNORECASE)

_DEMAND_EN = r"(?:tell|give|share|send|show|list|disclose|need|want)"
_OTHERS_EN_POSSESSIVE = (
    r"(?:other|another|previous)\s+(?:customer|person|user)['’]s\s+"
    r"(?:phone|address|order|details|number|history)"
)
# "His/her/their + data" only fires on a demand FOR the data. A how-to
# question ("tell me how to cancel his order") or a proof question
# ("what proof do you need") is a process question, not a disclosure
# demand — those windows are rejected by _others_en_demand_hit.
_OTHERS_EN_DATA = r"(?:phone|address|order|history|details|number)"
_OTHERS_EN_FAMILY = (
    r"(?:his|her|their|uncle['’]s|aunt['’]s|brother['’]s|sister['’]s|"
    r"father['’]s|mother['’]s|husband['’]s|wife['’]s)"
)
_OTHERS_HING = (
    r"(?:uska|uski|uske)\s+.{0,40}(?:address|order|details).{0,20}"
    r"(?:de\s+do|bata|bhejo)"
    r"|(?:saare|pichhle|sab)\s+orders?.{0,40}(?:list|naam|address)"
    r".{0,20}(?:de\s+do|bhejo)"
)
_OTHERS_DEVA = (
    r"(?:पिछले\s+ग्राहक|किसी\s+और|भाई|बहन).{0,60}"
    r"(?:फोन\s+नंबर|पता|ऑर्डर).{0,40}(?:बता|दीजिए)"
    r"|उनका\s+.{0,30}(?:फोन\s+नंबर|पता|ऑर्डर).{0,20}(?:बता|दीजिए)"
    r"|पिछले\s+(?:दस\s+)?ग्राहकों?\s+के\s+ऑर्डर.{0,20}"
    r"(?:जारी|बता|दीजिए)"
)
_OTHERS = re.compile(
    f"(?:{_OTHERS_EN_POSSESSIVE}|{_OTHERS_HING}|{_OTHERS_DEVA})",
    re.IGNORECASE)


def _others_en_demand_hit(text: str) -> bool:
    """Demand + other-person data, minus process questions."""
    demand_rx = re.compile(_DEMAND_EN, re.IGNORECASE)
    data_rx = re.compile(
        f"{_OTHERS_EN_FAMILY}.{{0,30}}{_OTHERS_EN_DATA}", re.IGNORECASE)
    how_rx = re.compile(r"\bhow\s+(?:to|can|do)\b", re.IGNORECASE)
    for m in demand_rx.finditer(text):
        window = text[m.end():m.end() + 90]
        d = data_rx.search(window)
        if d and not how_rx.search(window[:d.start()]):
            return True
    for m in data_rx.finditer(text):
        window = text[m.end():m.end() + 60]
        d = demand_rx.search(window)
        # A question frame between data and demand ("what documents
        # you need", "what proof do you need", "how ...") is a process
        # question, not a demand for the data.
        if d and not re.search(r"\b(what|how|proof)\b",
                               window[:d.start()], re.IGNORECASE):
            return True
    return False

_CRED = (
    # A bare "send me a password reset link" is legitimate (the twin):
    # redirection needs a NEW destination, not merely a link.
    r"(?:password|email|phone|number|registered number)"
    r".{0,50}(?:change|reset|update).{0,50}"
    r"(?:new|different|another)"
    r"|(?:change|reset|update).{0,50}"
    r"(?:password|email|phone|number).{0,50}"
    r"(?:new|different|another)"
    r"|disable\s+(?:two-factor|two\s+factor|2fa)"
    r"|(?:password|email)\s+.{0,30}(?:reset|bhej).{0,30}"
    r"(?:naye|naya|naye\s+email)"
    r"|(?:रजिस्टर्ड\s+)?(?:नंबर|ईमेल|पासवर्ड)\s+बदल\w*.{0,50}"
    r"(?:नया|भेज|लिंक)"
    r"|पासवर्ड\s+रीसेट.{0,40}(?:नए|नया|भेज|लिंक)"
)

_SKIP_RX = re.compile(
    f"(?:{_SKIP}).{{0,120}}(?:{_ACTION})"
    f"|(?:{_ACTION}).{{0,120}}(?:{_SKIP})",
    re.IGNORECASE)
_CRED_RX = re.compile(_CRED, re.IGNORECASE)
_MONEY_RX = re.compile(
    f"(?:{_MONEY}).{{0,80}}(?:{_NEW_DEST})"
    f"|(?:{_NEW_DEST}).{{0,80}}(?:{_MONEY})",
    re.IGNORECASE)
_DEMAND_MONEY_RX = re.compile(_DEMAND_MONEY, re.IGNORECASE)


def _money_hit(text: str) -> bool:
    """Money + new destination + a demand verb, and not the requester's
    own account ('a different account of mine' is a question about
    one's own money, not a redirection)."""
    for m in _MONEY_RX.finditer(text):
        # Wide demand window: threats ("I will post everywhere") often
        # sit before the money phrase; a narrow window clips them.
        span = text[max(0, m.start() - 120):m.end() + 40]
        if not _DEMAND_MONEY_RX.search(span):
            continue
        # Own-account check looks past the destination noun, because
        # "a different account of mine" marks the requester's own money.
        if _OWN_DEST.search(text[m.start():m.end() + 20]):
            continue
        return True
    return False

_RULES = [
    ("verification_skip", _SKIP_RX,
     "request asks to skip verification or a security check"),
    ("money_move_new_destination", None,
     "money moved to a new or third-party destination without verification"),
    ("others_data_disclosure", None,
     "another person's data requested"),
    ("credential_redirect", _CRED_RX,
     "credential or recovery redirected to a new destination"),
]

_CURRENCY = re.compile(r"[₹$€£]")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_DIGIT_RUN = re.compile(r"\d{7,}")
_LATIN_ACTION = re.compile(
    r"\b(refund|transfer|send|account|password|otp|verify|verification)\b",
    re.IGNORECASE)


def check_actions(text: str) -> dict:
    """Baseline-policy verdict for one request's text.

    Returns {"blocked", "actions", "reason", "language"}. Language is
    reported for the trace; it never gates which patterns run.
    """
    t = text or ""
    lang = detect_language(t)
    found = []
    for name, rx, reason in _RULES:
        if name == "money_move_new_destination":
            hit = _money_hit(t)
        elif name == "others_data_disclosure":
            hit = bool(_OTHERS.search(t)) or _others_en_demand_hit(t)
        else:
            hit = bool(rx.search(t))
        if hit:
            found.append((name, reason))
    if found:
        return {"blocked": True,
                "actions": [n for n, _ in found],
                "reason": "; ".join(r for _, r in found),
                "language": lang}
    return {"blocked": False, "actions": [], "reason": "",
            "language": lang}


def unknown_language_risky(text: str, language: str | None = None) -> bool:
    """Fail-closed rule for unknown scripts: an unknown-language message
    is blocked only when it also carries a script-independent risky
    indicator (currency, email/phone/digit-run, or a Latin action word).
    A plain question in another script passes with a lang:unknown flag.
    """
    lang = language if language is not None else detect_language(text or "")
    if lang != "unknown":
        return False
    t = text or ""
    return bool(_CURRENCY.search(t) or _EMAIL.search(t)
                or _DIGIT_RUN.search(t) or _LATIN_ACTION.search(t))
