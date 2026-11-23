"""Database: the scans table and the history queries. SQLite locally, PostgreSQL (RDS) on AWS."""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, URL, DateTime, String, Text, and_, create_engine, func, make_url, not_, or_, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from detector.engine import ScanResult
from detector.rules import FREE_EMAIL_PROVIDERS, SenderHistory

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """One scanned email. The raw email is never stored, only metadata and findings."""
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    source: Mapped[str] = mapped_column(String(20))  # upload | paste | cli
    filename: Mapped[str | None] = mapped_column(Text)
    sender: Mapped[str | None] = mapped_column(Text)
    sender_address: Mapped[str | None] = mapped_column(Text, index=True)
    sender_domain: Mapped[str | None] = mapped_column(Text, index=True)
    recipient_address: Mapped[str | None] = mapped_column(Text)
    subject: Mapped[str | None] = mapped_column(Text)
    score: Mapped[int]
    risk_level: Mapped[str] = mapped_column(String(10))
    is_phishing: Mapped[bool]
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    user_label: Mapped[str | None] = mapped_column(String(20))  # phishing | safe
    labeled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    client_ip: Mapped[str | None] = mapped_column(String(45))


def database_url() -> str | URL:
    """DATABASE_URL, else DB_HOST + DB_* (AWS), else a local SQLite file."""
    if os.getenv("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    if os.getenv("DB_HOST"):
        # URL.create escapes special characters in the RDS-generated password.
        return URL.create(
            "postgresql+psycopg", host=os.environ["DB_HOST"], port=int(os.getenv("DB_PORT", "5432")),
            database=os.getenv("DB_NAME", "phishing"), username=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"), query={"sslmode": os.getenv("DB_SSLMODE", "require")},
        )
    return "sqlite:///./data/phishing.db"


class Database:
    def __init__(self, url: str | URL | None = None):
        url = url or database_url()
        self.backend = make_url(url).get_backend_name()  # "sqlite" | "postgresql"
        if self.backend == "sqlite":
            connect_args = {"check_same_thread": False}
            path = make_url(url).database
            if path and path != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)
        else:
            # Fail fast (503) instead of hanging when RDS is unreachable or slow.
            connect_args = {"connect_timeout": 5, "options": "-c statement_timeout=5000"}
        # pre_ping replaces connections dropped by RDS; recycle avoids silently dropped idle ones.
        self.engine = create_engine(url, pool_pre_ping=True, pool_recycle=300, connect_args=connect_args)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.ready = False

    def create_tables(self) -> bool:
        """Never crashes: the app must start even if RDS is not reachable yet (retried per request)."""
        try:
            Base.metadata.create_all(self.engine)
            self.ready = True
        except SQLAlchemyError as exc:
            logger.error("Database unavailable", extra={"event": "db_unavailable", "error": type(exc).__name__})
        return self.ready

    def ping(self) -> None:
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))


# --- History queries ---------------------------------------------------------


def save_scan(session: Session, result: ScanResult, source: str, filename: str | None,
              client_ip: str | None = None) -> tuple[Scan, Scan | None]:
    """Store a scan. Returns (new scan, earlier scan of the same content or None)."""
    previous = session.scalars(select(Scan).where(Scan.content_sha256 == result.content_sha256)
                               .order_by(Scan.id.desc()).limit(1)).first()
    s = result.summary
    scan = Scan(source=source, filename=filename, sender=s["from"], sender_address=s["sender_address"],
                sender_domain=s["sender_domain"], recipient_address=s["recipient_address"], subject=s["subject"],
                score=result.score, risk_level=result.risk_level.value, is_phishing=result.is_phishing,
                findings=[f.model_dump(mode="json") for f in result.findings],
                content_sha256=result.content_sha256, client_ip=client_ip)
    session.add(scan)
    session.commit()
    return scan, previous


def list_scans(session: Session, limit: int, offset: int = 0) -> list[Scan]:
    return list(session.scalars(select(Scan).order_by(Scan.id.desc()).limit(limit).offset(offset)))


def label_scan(session: Session, scan_id: int, label: str) -> Scan | None:
    scan = session.get(Scan, scan_id)
    if scan:
        scan.user_label = label
        scan.labeled_at = datetime.now(timezone.utc)
        session.commit()
    return scan


# COALESCE: a NULL label must compare as "no label", not as NULL (which would drop the row).
LABEL = func.coalesce(Scan.user_label, "")
FLAGGED = or_(LABEL == "phishing", and_(Scan.risk_level == "HIGH", LABEL != "safe"))
CLEAN = or_(LABEL == "safe", and_(Scan.risk_level == "LOW", LABEL != "phishing"))


def sender_history(session: Session, result: ScanResult) -> SenderHistory | None:
    """What earlier scans say about this sender (None if the email has no sender).

    Earlier scans of the same content are ignored (scanning one email twice is not a
    second contact). Free email providers are judged per address, not per domain.
    """
    sender, domain = result.summary["sender_address"], result.summary["sender_domain"]
    recipient = result.summary["recipient_address"]
    if not sender:
        return None
    earlier = Scan.content_sha256 != result.content_sha256

    if domain and domain not in FREE_EMAIL_PROVIDERS:
        same_sender, key = Scan.sender_domain == domain, domain
    else:
        same_sender, key = Scan.sender_address == sender, sender
    flagged = session.scalar(select(func.count()).where(same_sender, earlier, FLAGGED))

    to_recipient = unclean = 0
    if recipient:
        pair = and_(Scan.sender_address == sender, Scan.recipient_address == recipient, earlier)
        to_recipient = session.scalar(select(func.count()).where(pair))
        unclean = session.scalar(select(func.count()).where(pair, not_(CLEAN)))

    return SenderHistory(sender_address=sender, recipient_address=recipient, scans_to_recipient=to_recipient,
                         all_safe_to_recipient=to_recipient > 0 and unclean == 0,
                         flagged_scans=flagged, flagged_key=key)
