"""All detection rules: the configuration (points, lists) and the checks.

Tuning the detector means editing the tables at the top of this file.
Each rule scores at most once per email, with up to 3 examples as evidence.
"""

import ipaddress
import re
from enum import Enum
from typing import NamedTuple
from urllib.parse import urlsplit

import tldextract
from pydantic import BaseModel

from detector.parser import Attachment, Link, ParsedEmail


class Severity(str, Enum):
    INFO = "INFO"  # trust signals (negative points)
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Rule(NamedTuple):
    category: str
    severity: Severity
    points: int
    title: str


RULES: dict[str, Rule] = {
    # Links
    "LINK_IP_HOST": Rule("links", Severity.HIGH, 25, "Link points to a raw IP address"),
    "LINK_TEXT_MISMATCH": Rule("links", Severity.HIGH, 25, "Link text shows a different domain than the real target"),
    "LINK_BRAND_IN_SUBDOMAIN": Rule("links", Severity.HIGH, 20, "Known brand used in a link on a non-brand domain"),
    "LINK_PUNYCODE": Rule("links", Severity.HIGH, 20, "Link uses punycode / non-ASCII characters in the domain"),
    "LINK_AT_SYMBOL": Rule("links", Severity.HIGH, 20, "Link hides its real host behind an '@'"),
    "LINK_SUSPICIOUS_TLD": Rule("links", Severity.MEDIUM, 10, "Link uses a top-level domain common in phishing"),
    "LINK_SHORTENER": Rule("links", Severity.MEDIUM, 10, "Link uses a URL shortener that hides the destination"),
    "LINK_NO_HTTPS": Rule("links", Severity.LOW, 5, "Link does not use HTTPS"),
    # Sender
    "SENDER_BLACKLISTED_LOOKALIKE": Rule("sender", Severity.CRITICAL, 30, "Sender domain is a known lookalike (blacklist)"),
    "SENDER_LOOKALIKE_DOMAIN": Rule("sender", Severity.CRITICAL, 30, "Sender domain imitates a known brand domain"),
    "SENDER_BRAND_NAME_MISMATCH": Rule("sender", Severity.HIGH, 25, "Sender name claims a brand the domain does not belong to"),
    "SENDER_SPECIAL_CHARS": Rule("sender", Severity.HIGH, 20, "Sender domain contains non-ASCII, punycode or invalid characters"),
    "SENDER_REPLY_TO_MISMATCH": Rule("sender", Severity.MEDIUM, 15, "Replies go to a different domain than the sender"),
    "SENDER_TRUSTED_TLD": Rule("sender", Severity.INFO, -15, "Sender domain is under a restricted-registration suffix"),
    # Sender history (looked up in the DB by the app, see check_history)
    "SENDER_PREVIOUSLY_FLAGGED": Rule("history", Severity.HIGH, 25, "Earlier emails from this sender were flagged as phishing"),
    "SENDER_KNOWN_TO_RECIPIENT": Rule("history", Severity.INFO, -15, "Sender has a clean history with this recipient"),
    # Wording
    "WORDING_CREDENTIALS": Rule("wording", Severity.HIGH, 20, "Asks for credentials or personal data"),
    "WORDING_THREAT": Rule("wording", Severity.MEDIUM, 15, "Threatens account loss or legal consequences"),
    "WORDING_ADVANCE_FEE": Rule("wording", Severity.MEDIUM, 15, "Advance-fee scam wording (inheritance, wire transfer)"),
    "WORDING_URGENCY": Rule("wording", Severity.MEDIUM, 10, "Creates a sense of urgency"),
    "WORDING_REWARD": Rule("wording", Severity.MEDIUM, 10, "Promises a prize or reward"),
    "WORDING_GENERIC_GREETING": Rule("wording", Severity.LOW, 5, "Uses a generic greeting instead of your name"),
    "WORDING_EXCESSIVE_PUNCTUATION": Rule("wording", Severity.LOW, 5, "Excessive exclamation marks or capital letters"),
    # Attachments
    "ATTACH_EXECUTABLE": Rule("attachments", Severity.CRITICAL, 35, "Executable attachment"),
    "ATTACH_DOUBLE_EXTENSION": Rule("attachments", Severity.CRITICAL, 30, "Attachment hides an executable behind a document extension"),
    "ATTACH_MACRO_DOCUMENT": Rule("attachments", Severity.HIGH, 25, "Macro-enabled Office document"),
    "ATTACH_HTML": Rule("attachments", Severity.HIGH, 20, "HTML attachment (often a fake login page)"),
    "ATTACH_CONTENT_TYPE_MISMATCH": Rule("attachments", Severity.HIGH, 20, "Declared file type contradicts the file extension"),
    "ATTACH_ARCHIVE": Rule("attachments", Severity.MEDIUM, 10, "Archive attachment that can hide its contents"),
}
# Weak form of SENDER_SPECIAL_CHARS (same ID): many hyphens or digits inside words.
SPECIAL_CHARS_WEAK = Rule("sender", Severity.LOW, 5, "Sender domain looks generated (many hyphens or digits inside words)")


class Brand(NamedTuple):
    domains: list[str]
    fuzzy: bool = True  # False: no edit-distance matching (name is too close to common words)


KNOWN_BRANDS: dict[str, Brand] = {
    "paypal": Brand(["paypal.com"]),
    "microsoft": Brand(["microsoft.com", "outlook.com", "live.com"]),
    "google": Brand(["google.com", "gmail.com"]),
    "apple": Brand(["apple.com", "icloud.com"]),
    "amazon": Brand(["amazon.com"]),
    "netflix": Brand(["netflix.com"]),
    "facebook": Brand(["facebook.com", "meta.com"]),
    "linkedin": Brand(["linkedin.com"]),
    "dhl": Brand(["dhl.com"]),
    "bank hapoalim": Brand(["bankhapoalim.co.il"]),
    "leumi": Brand(["leumi.co.il"]),
    "upwind": Brand(["upwind.io"], fuzzy=False),  # "unwind" is 1 edit away; misspellings are blacklisted
}
# Known misspellings, matched exactly on the sender domain or its registered domain.
KNOWN_LOOKALIKE_DOMAINS = {"upwlnd.io", "upw1nd.io", "paypa1.com", "micros0ft.com"}
# Only governments, armies and universities can register these. Never com/org/net.
TRUSTED_SENDER_SUFFIXES = {"gov", "gov.il", "mil", "edu", "ac.il", "muni.il"}
FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "protonmail.com"}
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "click", "country", "work", "live"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}

WORDING_PATTERNS: dict[str, list[str]] = {
    "WORDING_CREDENTIALS": [
        r"verify your (?:account|password|identity)", r"confirm your (?:account|details|identity|password)",
        r"update your (?:payment|billing)", r"enter your password", r"log\s?in to (?:restore|unlock)",
        r"social security", r"credit card number",
    ],
    "WORDING_THREAT": [
        r"account (?:will be |has been )?(?:suspended|closed|locked|terminated|disabled)",
        r"unauthori[sz]ed (?:access|activity)", r"legal action", r"final notice",
    ],
    "WORDING_ADVANCE_FEE": [
        r"nigerian prince", r"inheritance", r"beneficiary", r"wire transfer", r"million dollars",
        r"next of kin", r"unclaimed funds",
    ],
    "WORDING_URGENCY": [
        r"urgent(?:ly)?", r"immediately", r"within 24 hours", r"act now", r"action required",
        r"as soon as possible", r"expires? today", r"last chance",
    ],
    "WORDING_REWARD": [
        r"you (?:have )?won", r"congratulations", r"claim your (?:prize|reward|refund)", r"gift card",
        r"lottery", r"free money",
    ],
    "WORDING_GENERIC_GREETING": [r"dear (?:valued )?(?:customer|user|client|member|account holder)", r"hello user"],
}

EXECUTABLE_EXTENSIONS = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "msi", "hta", "jar", "lnk",
                         "com", "pif", "iso", "img"}
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif"}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm"}
HTML_EXTENSIONS = {"html", "htm", "shtml"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "ace"}
EXECUTABLE_TYPES = {"application/x-msdownload", "application/x-msdos-program", "application/x-dosexec",
                    "application/x-executable", "application/vnd.microsoft.portable-executable"}
GENERIC_TYPES = {"application/octet-stream", "binary/octet-stream", "application/unknown"}
EXPECTED_TYPES: dict[str, set[str]] = {
    "pdf": {"application/pdf"},
    "doc": {"application/msword"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "xls": {"application/vnd.ms-excel"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "ppt": {"application/vnd.ms-powerpoint"},
    "pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    "txt": {"text/plain"},
    "csv": {"text/csv", "text/plain", "application/vnd.ms-excel"},
    "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"}, "png": {"image/png"}, "gif": {"image/gif"},
    "zip": {"application/zip", "application/x-zip-compressed"},
    "exe": EXECUTABLE_TYPES,
}


class Finding(BaseModel):
    id: str
    category: str
    severity: Severity
    title: str
    evidence: str
    points: int  # negative for trust signals


class SenderHistory(BaseModel):
    """What earlier scans say about the sender. Looked up by the app; the detector never touches the DB."""
    sender_address: str | None = None
    recipient_address: str | None = None
    scans_to_recipient: int = 0          # earlier scans from this address to this recipient...
    all_safe_to_recipient: bool = False  # ...all LOW or labeled "safe"
    flagged_scans: int = 0               # earlier scans labeled "phishing" or scored HIGH
    flagged_key: str | None = None       # sender domain, or the address for free email providers


def finding(rule_id: str, evidence: list[str], rule: Rule | None = None) -> Finding:
    rule = rule or RULES[rule_id]
    unique = list(dict.fromkeys(evidence))
    shown = ", ".join(unique[:3]) + (f" (+{len(unique) - 3} more)" if len(unique) > 3 else "")
    return Finding(id=rule_id, category=rule.category, severity=rule.severity, title=rule.title,
                   evidence=shown, points=rule.points)


def shorten(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def check_content(email: ParsedEmail) -> list[Finding]:
    """All rules that depend only on the email itself."""
    return check_links(email) + check_sender(email) + check_wording(email) + check_attachments(email)


# --- Domain helpers ----------------------------------------------------------

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled list, no network


def split_domain(host: str) -> tuple[str, str, str]:
    """"a.paypal.co.uk" -> ("a", "paypal", "co.uk")."""
    parts = _extract(host.lower().strip("."))
    return parts.subdomain, parts.domain, parts.suffix


def registered_domain(host: str) -> str:
    """"login.paypal.com" -> "paypal.com". Hosts without a public suffix are returned as-is."""
    _, name, suffix = split_domain(host)
    return f"{name}.{suffix}" if name and suffix else host.lower().strip(".")


def email_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return registered_domain(address.rsplit("@", 1)[1])


def is_brand_domain(domain: str, brand_domains: list[str]) -> bool:
    """One of the brand's domains, or its exact name under a country code (paypal.co.il, paypal.de)."""
    if domain in brand_domains:
        return True
    _, name, suffix = split_domain(domain)
    country = suffix.rsplit(".", 1)[-1]
    is_country_code = len(country) == 2 and country.isascii() and country.isalpha() and country not in SUSPICIOUS_TLDS
    return bool(name) and is_country_code and any(split_domain(d)[1] == name for d in brand_domains)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# --- Links -------------------------------------------------------------------


def check_links(email: ParsedEmail) -> list[Finding]:
    hits: dict[str, list[str]] = {}
    for link in email.links:
        for rule_id, evidence in _inspect_link(link):
            hits.setdefault(rule_id, []).append(evidence)
    return [finding(rule_id, evidence) for rule_id, evidence in hits.items()]


def _inspect_link(link: Link) -> list[tuple[str, str]]:
    url = link.url
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)  # "www.x.com" has no scheme
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return []
    if not host:
        return []

    short = shorten(url)
    hits = []
    if "@" in parts.netloc:  # "http://paypal.com@evil.com" goes to evil.com
        hits.append(("LINK_AT_SYMBOL", short))
    if url.lower().startswith("http://"):
        hits.append(("LINK_NO_HTTPS", short))
    if is_ip(host):
        hits.append(("LINK_IP_HOST", short))
    if not host.isascii() or any(label.startswith("xn--") for label in host.split(".")):
        hits.append(("LINK_PUNYCODE", short))

    subdomain, _, suffix = split_domain(host)
    registered = registered_domain(host)
    if suffix.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        hits.append(("LINK_SUSPICIOUS_TLD", short))
    if host in URL_SHORTENERS or registered in URL_SHORTENERS:
        hits.append(("LINK_SHORTENER", short))

    brand = _brand_in_url(subdomain, parts.path, registered)
    if brand:
        hits.append(("LINK_BRAND_IN_SUBDOMAIN", f"{short} (uses '{brand}')"))

    shown = _domain_in_text(link.text)
    if shown and registered_domain(shown) != registered:
        hits.append(("LINK_TEXT_MISMATCH", f"shows '{shorten(link.text)}' but goes to {short}"))
    return hits


def _brand_in_url(subdomain: str, path: str, registered: str) -> str | None:
    """A brand in the subdomain or path of a non-brand URL: paypal.com.verify.xyz, evil.net/paypal.com/."""
    labels = set(re.split(r"[.\-]", subdomain.lower()))
    location = f"{subdomain}/{path}".lower()
    for name, brand in KNOWN_BRANDS.items():
        if is_brand_domain(registered, brand.domains):
            continue
        if name.replace(" ", "") in labels:
            return name
        for domain in brand.domains:
            if re.search(rf"(?<![a-z0-9-]){re.escape(domain)}(?![a-z0-9])", location):
                return name
    return None


def _domain_in_text(text: str | None) -> str | None:
    """The host shown by anchor text that looks like a URL ("paypal.com/login"); None for "Click here"."""
    text = (text or "").strip()
    if not re.match(r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?$", text, re.IGNORECASE):
        return None
    try:
        host = urlsplit(text if "://" in text else "http://" + text).hostname
    except ValueError:
        return None
    return host if host and split_domain(host)[2] else None  # needs a real public suffix


# --- Sender ------------------------------------------------------------------


def check_sender(email: ParsedEmail) -> list[Finding]:
    if not email.has_headers or not email.from_address or "@" not in email.from_address:
        return []
    host = email.from_address.rsplit("@", 1)[1].strip().strip(".").lower()  # everything after the @
    if not host:
        return []
    domain = registered_domain(host)
    findings = []

    # Lookalikes: the blacklist wins, so one domain is never scored twice.
    lookalike = None
    blacklisted = next((d for d in (host, domain) if d in KNOWN_LOOKALIKE_DOMAINS), None)
    if blacklisted:
        lookalike = finding("SENDER_BLACKLISTED_LOOKALIKE", [f"'{blacklisted}' is a known lookalike"])
    elif imitated := find_lookalike(domain):
        lookalike = finding("SENDER_LOOKALIKE_DOMAIN", [f"'{domain}' resembles '{imitated}'"])
    if lookalike:
        findings.append(lookalike)

    special = _special_chars(host)
    # A digit inside a word ("micros0ft") is the lookalike trick itself: already scored.
    if special and not (lookalike and special.severity == Severity.LOW):
        findings.append(special)

    trusted = [s for s in TRUSTED_SENDER_SUFFIXES if host.endswith("." + s)]
    if trusted:
        findings.append(finding("SENDER_TRUSTED_TLD", [f"{host} (.{max(trusted, key=len)})"]))

    brand = _claimed_brand(email.from_name, domain)
    if brand:
        note = " (free email provider)" if domain in FREE_EMAIL_PROVIDERS else ""
        findings.append(finding("SENDER_BRAND_NAME_MISMATCH", [f"name '{shorten(email.from_name)}' but sent from {domain}{note}"]))

    reply_domain = email_domain(email.reply_to)
    if reply_domain and reply_domain != domain:
        findings.append(finding("SENDER_REPLY_TO_MISMATCH", [f"From {domain}, Reply-To {reply_domain}"]))
    return findings


def find_lookalike(domain: str) -> str | None:
    """The brand domain that `domain` imitates, or None.

    Undoes homoglyphs (paypa1 -> paypal), compares each hyphen-separated part
    (paypa1-secure -> paypal) and allows 1-2 typos for long brand names (micosoft).
    """
    for brand in KNOWN_BRANDS.values():
        if is_brand_domain(domain, brand.domains):
            return None
    _, name, _ = split_domain(domain)
    whole = normalize(name)
    parts = {normalize(part) for part in name.split("-")}
    for brand in KNOWN_BRANDS.values():
        for legit in brand.domains:
            legit_name = split_domain(legit)[1]
            if whole == legit_name or (len(legit_name) >= 5 and legit_name in parts):
                return legit
            if brand.fuzzy and len(legit_name) >= 6:  # short names: almost every word is 1-2 edits away
                if levenshtein(whole, legit_name) <= (2 if len(legit_name) >= 8 else 1):
                    return legit
    return None


def normalize(text: str) -> str:
    text = text.lower()
    for fake, real in HOMOGLYPHS:
        text = text.replace(fake, real)
    return text.replace("-", "")


def levenshtein(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def _special_chars(host: str) -> Finding | None:
    """Strong form (non-ASCII, punycode, invalid characters) wins over the weak form."""
    strong = []
    if not host.isascii():
        strong.append(f"non-ASCII characters in {host}")
    elif any(label.startswith("xn--") for label in host.split(".")):
        strong.append(f"punycode in {host}")
    invalid = sorted({c for c in host if c.isascii() and not re.match(r"[a-z0-9.-]", c)})
    if invalid:
        strong.append(f"invalid characters {' '.join(repr(c) for c in invalid)} in {host}")
    if strong:
        return finding("SENDER_SPECIAL_CHARS", strong)

    suffix = split_domain(host)[2]
    names = host.removesuffix("." + suffix) if suffix else host  # judge the names, not the TLD
    weak = []
    if names.count("-") >= 3:
        weak.append(f"{names.count('-')} hyphens in {host}")
    words = [w for w in re.split(r"[.-]", names) if re.search(r"[0-9][a-z]", w)]  # "1ogin", not "office365"
    if words:
        weak.append(f"digits inside words: {', '.join(words)}")
    return finding("SENDER_SPECIAL_CHARS", weak, rule=SPECIAL_CHARS_WEAK) if weak else None


def _claimed_brand(display_name: str | None, domain: str) -> str | None:
    """A brand named in the display name ("PayPal Support") that does not own the domain."""
    for name, brand in KNOWN_BRANDS.items():
        pattern = r"\b" + r"\s+".join(map(re.escape, name.split())) + r"\b"
        if display_name and re.search(pattern, display_name, re.IGNORECASE) and not is_brand_domain(domain, brand.domains):
            return name
    return None


# --- Wording -----------------------------------------------------------------

WORDING_REGEXES = {rule_id: re.compile(r"\b(?:" + "|".join(p) + r")\b", re.IGNORECASE)
                   for rule_id, p in WORDING_PATTERNS.items()}


def check_wording(email: ParsedEmail) -> list[Finding]:
    text = " ".join(f"{email.subject or ''}\n{email.body}".split())  # phrases split across lines still match
    findings = []
    for rule_id, regex in WORDING_REGEXES.items():
        phrases = [f'"{m.group(0).lower()}"' for m in regex.finditer(text)]
        if phrases:
            findings.append(finding(rule_id, phrases))

    shouting = [f'"{m.group(0)}"' for m in re.finditer(r"!{3,}", text)]
    # Subject mostly in capitals; 2-5 letter all-caps words (GPT, NASA) are acronyms and ignored.
    words = [w for w in re.findall(r"[^\W\d_]+", email.subject or "") if not (w.isupper() and 2 <= len(w) <= 5)]
    letters = "".join(words)
    if len(letters) >= 10 and sum(c.isupper() for c in letters) / len(letters) > 0.5:
        shouting.append("subject is mostly uppercase")
    if shouting:
        findings.append(finding("WORDING_EXCESSIVE_PUNCTUATION", shouting))
    return findings


# --- Attachments -------------------------------------------------------------


def check_attachments(email: ParsedEmail) -> list[Finding]:
    hits: dict[str, list[str]] = {}
    for attachment in email.attachments:
        for rule_id, evidence in _inspect_attachment(attachment):
            hits.setdefault(rule_id, []).append(evidence)
    return [finding(rule_id, evidence) for rule_id, evidence in hits.items()]


def _inspect_attachment(attachment: Attachment) -> list[tuple[str, str]]:
    name = attachment.filename
    extensions = name.lower().rstrip(". ").split(".")[1:]  # Windows ignores trailing dots: "a.exe." runs
    if not extensions:
        return []
    last = extensions[-1]
    hits = []
    if last in EXECUTABLE_EXTENSIONS:
        hits.append(("ATTACH_EXECUTABLE", name))
        if len(extensions) >= 2 and extensions[-2] in DOCUMENT_EXTENSIONS:
            hits.append(("ATTACH_DOUBLE_EXTENSION", name))
    if last in MACRO_EXTENSIONS:
        hits.append(("ATTACH_MACRO_DOCUMENT", name))
    if last in HTML_EXTENSIONS:
        hits.append(("ATTACH_HTML", name))
    if last in ARCHIVE_EXTENSIONS:
        hits.append(("ATTACH_ARCHIVE", name))

    declared = (attachment.content_type or "").lower()
    if declared and declared not in GENERIC_TYPES:
        if last in EXPECTED_TYPES:
            mismatch = declared not in EXPECTED_TYPES[last]
        else:  # unknown extension: only a declared program type is suspicious
            mismatch = declared in EXECUTABLE_TYPES and last not in EXECUTABLE_EXTENSIONS
        if mismatch:
            hits.append(("ATTACH_CONTENT_TYPE_MISMATCH", f"{name} declared as {attachment.content_type}"))
    return hits


# --- Sender history ----------------------------------------------------------


def check_history(history: SenderHistory | None, findings: list[Finding]) -> list[Finding]:
    """A flag beats familiarity, and a known sender never excuses a CRITICAL finding
    (the From address is easy to spoof)."""
    if history is None:
        return []
    if history.flagged_scans:
        return [finding("SENDER_PREVIOUSLY_FLAGGED",
                        [f"{history.flagged_scans} earlier scan(s) from {history.flagged_key} flagged"])]
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    if history.scans_to_recipient and history.all_safe_to_recipient and not has_critical:
        return [finding("SENDER_KNOWN_TO_RECIPIENT",
                        [f"{history.scans_to_recipient} earlier scan(s) from {history.sender_address} "
                         f"to {history.recipient_address}, all safe"])]
    return []
