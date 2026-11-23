"""The entry point used by the CLI and the API: parse, run the rules, score."""

import hashlib
from enum import Enum
from typing import Any

from pydantic import BaseModel

from detector.parser import parse_email
from detector.rules import Finding, SenderHistory, Severity, check_content, check_history, email_domain

MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


VERDICTS = {RiskLevel.LOW: "Likely safe", RiskLevel.MEDIUM: "Suspicious, review carefully",
            RiskLevel.HIGH: "Likely phishing"}


class ScanResult(BaseModel):
    score: int              # 0-100
    risk_level: RiskLevel
    is_phishing: bool       # risk_level == HIGH
    verdict: str
    findings: list[Finding] # highest points first
    summary: dict[str, Any] # sender, subject, counts
    content_sha256: str     # for duplicate detection and the cache key


def analyze(raw: bytes, filename: str | None = None, history: SenderHistory | None = None) -> ScanResult:
    """Analyze an email. Pure function: no I/O. `history` comes from the app's database."""
    email = parse_email(raw)
    result = ScanResult(
        score=0, risk_level=RiskLevel.LOW, is_phishing=False, verdict="", findings=check_content(email),
        content_sha256=content_hash(raw),
        summary={
            "filename": filename,
            "from": f'"{email.from_name}" <{email.from_address}>' if email.from_name and email.from_address
                    else email.from_address or email.from_name,
            "subject": email.subject,
            "sender_address": email.from_address.lower() if email.from_address else None,
            "sender_domain": email_domain(email.from_address),
            "recipient_address": email.to_address.lower() if email.to_address else None,
            "links_count": len(email.links),
            "attachments": [a.model_dump(exclude={"content_type"}) for a in email.attachments],
        },
    )
    return apply_history(result, history)


def apply_history(result: ScanResult, history: SenderHistory | None) -> ScanResult:
    """(Re)apply the history rules and score again.

    Separate from analyze() so the API can cache the content-only result and
    apply the history, which changes with every scan, on each request.
    """
    findings = [f for f in result.findings if f.category != "history"]
    findings += check_history(history, findings)
    findings.sort(key=lambda f: (-f.points, f.id))

    score = max(0, min(100, sum(f.points for f in findings)))  # trust signals are negative
    if score >= HIGH_THRESHOLD:
        level = RiskLevel.HIGH
    elif score >= MEDIUM_THRESHOLD:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
    # A CRITICAL finding (e.g. invoice.pdf.exe) is never "Likely safe", even after trust signals.
    if level == RiskLevel.LOW and any(f.severity == Severity.CRITICAL for f in findings):
        level = RiskLevel.MEDIUM

    return result.model_copy(update={"score": score, "risk_level": level, "is_phishing": level == RiskLevel.HIGH,
                                     "verdict": VERDICTS[level], "findings": findings})


def content_hash(raw: bytes) -> str:
    """SHA-256 with line endings unified, so an uploaded file and the same email pasted in the browser match."""
    return hashlib.sha256(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").strip()).hexdigest()
