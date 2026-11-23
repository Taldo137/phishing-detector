"""Detector tests: every rule (one positive, one negative), scoring, parser and the sample emails."""

from pathlib import Path

import pytest

from detector.engine import ScanResult, analyze, apply_history, content_hash
from detector.parser import Attachment, Link, ParsedEmail, parse_email
from detector.rules import RULES, SenderHistory, Severity, check_content, check_history, finding

SAMPLES = Path(__file__).parent.parent / "samples"


def ids(**fields) -> set[str]:
    return {f.id for f in check_content(ParsedEmail(has_headers=True, **fields))}


def link(url: str, text: str | None = None) -> dict:
    return {"links": [Link(url=url, text=text)]}


def attachment(name: str, content_type: str | None = None) -> dict:
    return {"attachments": [Attachment(filename=name, content_type=content_type)]}


def sender(address: str, **extra) -> dict:
    return {"from_address": address, **extra}


def body(text: str) -> dict:
    return {"body": text}


# (rule, email fields that trigger it, similar email fields that must not)
RULE_CASES = [
    ("LINK_IP_HOST", link("http://192.168.1.10/login"), link("https://example.com/login")),
    ("LINK_TEXT_MISMATCH", link("https://evil.xyz/x", "https://www.paypal.com"), link("https://www.paypal.com/x", "paypal.com")),
    ("LINK_BRAND_IN_SUBDOMAIN", link("https://paypal.com.secure-login.net/"), link("https://www.paypal.com/")),
    ("LINK_PUNYCODE", link("https://xn--pypal-4ve.com/"), link("https://example.com/")),
    ("LINK_AT_SYMBOL", link("http://paypal.com@evil.com/"), link("https://example.com/user")),
    ("LINK_SUSPICIOUS_TLD", link("https://deals.xyz/"), link("https://deals.com/")),
    ("LINK_SHORTENER", link("https://bit.ly/abc"), link("https://example.com/abc")),
    ("LINK_NO_HTTPS", link("http://example.com/"), link("https://example.com/")),
    ("SENDER_BLACKLISTED_LOOKALIKE", sender("a@upw1nd.io"), sender("a@upwind.io")),
    ("SENDER_LOOKALIKE_DOMAIN", sender("a@paypa1-secure.com"), sender("a@paypal.co.il")),
    ("SENDER_BRAND_NAME_MISMATCH", sender("a@gmail.com", from_name="PayPal"), sender("a@paypal.com", from_name="PayPal")),
    ("SENDER_SPECIAL_CHARS", sender("a@exa_mple.com"), sender("a@example.com")),
    ("SENDER_REPLY_TO_MISMATCH", sender("a@company.com", reply_to="b@other.top"),
     sender("a@company.com", reply_to="b@support.company.com")),
    ("SENDER_TRUSTED_TLD", sender("a@taxes.gov.il"), sender("a@gov.il.evil.com")),
    ("WORDING_CREDENTIALS", body("Please verify your password here."), body("Your password was changed.")),
    ("WORDING_THREAT", body("Your account will be suspended."), body("Your account settings were saved.")),
    ("WORDING_ADVANCE_FEE", body("You are the beneficiary of an inheritance."), body("This benefits everyone.")),
    ("WORDING_URGENCY", body("Reply immediately."), body("Reply when you can.")),
    ("WORDING_REWARD", body("Congratulations, claim your prize"), body("We signed the contract.")),
    ("WORDING_GENERIC_GREETING", body("Dear customer,"), body("Dear Dana,")),
    ("WORDING_EXCESSIVE_PUNCTUATION", body("Read this!!!"), body("Read this!")),
    ("ATTACH_EXECUTABLE", attachment("setup.exe"), attachment("report.pdf")),
    ("ATTACH_DOUBLE_EXTENSION", attachment("invoice.pdf.exe"), attachment("setup.exe")),
    ("ATTACH_MACRO_DOCUMENT", attachment("budget.xlsm"), attachment("budget.xlsx")),
    ("ATTACH_HTML", attachment("login.html"), attachment("notes.txt")),
    ("ATTACH_CONTENT_TYPE_MISMATCH", attachment("report.pdf", "application/x-msdownload"),
     attachment("report.pdf", "application/pdf")),
    ("ATTACH_ARCHIVE", attachment("files.zip"), attachment("files.pdf")),
]


@pytest.mark.parametrize(("rule_id", "positive", "negative"), RULE_CASES, ids=[c[0] for c in RULE_CASES])
def test_rule(rule_id, positive, negative):
    assert rule_id in ids(**positive)
    assert rule_id not in ids(**negative)


def test_every_content_rule_has_a_case():
    history_rules = {r for r, rule in RULES.items() if rule.category == "history"}
    assert {c[0] for c in RULE_CASES} == set(RULES) - history_rules


# --- Rule details ------------------------------------------------------------------


def test_special_chars_strong_and_weak_forms():
    strong = check_content(ParsedEmail(has_headers=True, from_address="a@pаy_a-b-c-d.com"))
    weak = check_content(ParsedEmail(has_headers=True, from_address="a@secure-1ogin-acc0unt.com"))
    special = [(f.severity, f.points) for f in strong + weak if f.id == "SENDER_SPECIAL_CHARS"]
    assert special == [(Severity.HIGH, 20), (Severity.LOW, 5)]  # scored once per email, strong form wins


def test_blacklist_wins_over_fuzzy_lookalike():
    findings = check_content(ParsedEmail(has_headers=True, from_address="a@micros0ft.com"))
    assert [f.id for f in findings] == ["SENDER_BLACKLISTED_LOOKALIKE"]  # no fuzzy hit, no "digit in word" hit


def test_upwind_is_not_fuzzy_matched():
    assert "SENDER_LOOKALIKE_DOMAIN" not in ids(from_address="a@unwind.com")
    assert "SENDER_BLACKLISTED_LOOKALIKE" in ids(from_address="a@upwlnd.io")
    assert "SENDER_LOOKALIKE_DOMAIN" in ids(from_address="a@micosoft.com")  # other brands still are


def known(flagged: int = 0) -> SenderHistory:
    return SenderHistory(sender_address="a@x.com", recipient_address="me@y.com", scans_to_recipient=2,
                         all_safe_to_recipient=True, flagged_scans=flagged, flagged_key="x.com")


@pytest.mark.parametrize(("history", "critical", "expected"), [
    (known(), False, ["SENDER_KNOWN_TO_RECIPIENT"]),
    (known(flagged=1), False, ["SENDER_PREVIOUSLY_FLAGGED"]),  # a flag beats familiarity
    (known(), True, []),                                       # no trust reduction with a CRITICAL finding
    (SenderHistory(), False, []),
    (None, False, []),
])
def test_history_rules(history, critical, expected):
    findings = [finding("ATTACH_EXECUTABLE", ["a.exe"])] if critical else []
    assert [f.id for f in check_history(history, findings)] == expected


# --- Scoring -----------------------------------------------------------------------


def result_with(*rule_ids: str) -> ScanResult:
    findings = [finding(rule_id, ["x"]) for rule_id in rule_ids]
    return apply_history(ScanResult(score=0, risk_level="LOW", is_phishing=False, verdict="", findings=findings,
                                    summary={}, content_sha256=""), None)


@pytest.mark.parametrize(("rule_ids", "score", "level"), [
    ([], 0, "LOW"),
    (["WORDING_URGENCY", "SENDER_TRUSTED_TLD"], 0, "LOW"),                 # 10 - 15, clamped at 0
    (["WORDING_THREAT", "WORDING_ADVANCE_FEE"], 30, "MEDIUM"),
    (["LINK_IP_HOST", "LINK_TEXT_MISMATCH", "WORDING_CREDENTIALS"], 70, "HIGH"),
    (["SENDER_LOOKALIKE_DOMAIN", "SENDER_TRUSTED_TLD", "SENDER_TRUSTED_TLD"], 0, "MEDIUM"),  # CRITICAL override
])
def test_scoring(rule_ids, score, level):
    result = result_with(*rule_ids)
    assert (result.score, result.risk_level.value, result.is_phishing) == (score, level, level == "HIGH")


def test_score_is_capped_at_100_and_findings_are_sorted():
    result = result_with("WORDING_URGENCY", "ATTACH_EXECUTABLE", "ATTACH_DOUBLE_EXTENSION", "LINK_IP_HOST",
                         "LINK_TEXT_MISMATCH", "SENDER_TRUSTED_TLD")  # 110
    assert result.score == 100
    assert [f.points for f in result.findings] == [35, 30, 25, 25, 10, -15]


# --- Samples -----------------------------------------------------------------------

EXPECTED = {
    "phish_paypal_lookalike.eml": ("HIGH", 100),
    "phish_attachment.eml": ("HIGH", 90),
    "phish_reward.txt": ("HIGH", 65),
    "phish_advance_fee.eml": ("MEDIUM", 40),
    "suspicious_shortener.eml": ("MEDIUM", 35),
    "legit_newsletter.eml": ("LOW", 0),
    "legit_paypal_receipt_il.eml": ("LOW", 0),  # paypal.co.il was once a false positive
    "legit_gov_il.eml": ("LOW", 0),             # "action required" +10, .gov.il -15
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_sample(name):
    result = analyze((SAMPLES / name).read_bytes())
    assert (result.risk_level.value, result.score) == EXPECTED[name], [f.id for f in result.findings]


def test_every_sample_has_an_expectation():
    assert {p.name for p in SAMPLES.iterdir()} == set(EXPECTED)


# --- Parser ------------------------------------------------------------------------


def test_parse_headers_and_html_links():
    email = parse_email((SAMPLES / "phish_paypal_lookalike.eml").read_bytes())
    assert (email.has_headers, email.from_name, email.from_address) == (True, "PayPal", "service@paypa1-secure.com")
    assert email.to_address and email.subject == "Your account has been suspended"
    assert any(link.text and "paypal.com" in link.text for link in email.links)


def test_parse_real_attachment_and_to_header():
    email = parse_email((SAMPLES / "phish_attachment.eml").read_bytes())
    assert email.attachments[0].filename == "Invoice_2026.pdf.exe"
    assert len(email.attachments[0].sha256) == 64
    raw = b'From: a@b.com\nTo: "Cohen, Dana" <Dana@Example.com>, x@y.com\nSubject: s\n\nhi\n'
    assert parse_email(raw).to_address == "Dana@Example.com"


def test_plain_text_urls_and_mentioned_attachments():
    email = parse_email(b"Hi, see www.example.com/page and https://bit.ly/x.\nAttachment: invoice.pdf.exe\n")
    assert email.has_headers is False
    assert [link.url for link in email.links] == ["www.example.com/page", "https://bit.ly/x"]
    assert [a.filename for a in email.attachments] == ["invoice.pdf.exe"]


@pytest.mark.parametrize("raw", [b"\x00\xff\xfe garbage", b"From: \x80\x81\nSubject: =?bad?=\n\n\xff",
                                 b"Content-Type: multipart/mixed; boundary=x\nFrom: a@b.c\n\n--x\nbroken"])
def test_hostile_input_never_crashes(raw):
    assert analyze(raw).risk_level.value in {"LOW", "MEDIUM", "HIGH"}


def test_content_hash_ignores_line_endings():
    assert content_hash(b"From: a\nhello\n") == content_hash(b"From: a\r\nhello")


def test_summary_has_normalized_identities():
    summary = analyze(b'From: "Dana" <Dana@Mail.Partner.com>\nTo: ME@example.com\nSubject: s\n\nhi\n').summary
    assert (summary["sender_address"], summary["sender_domain"], summary["recipient_address"]) == (
        "dana@mail.partner.com", "partner.com", "me@example.com")
