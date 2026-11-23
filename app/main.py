"""FastAPI app: REST API, health checks, JSON logging, optional Redis cache and the web UI.

Run locally: uvicorn app.main:app --reload
"""

import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import redis
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from redis.backoff import NoBackoff
from redis.retry import Retry
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app import db
from detector.engine import VERDICTS, RiskLevel, ScanResult, analyze, apply_history, content_hash

logger = logging.getLogger("app")

STATIC_DIR = Path(__file__).parent / "static"
ALLOWED_EXTENSIONS = {".eml", ".txt", ".msg"}
CACHE_PREFIX = "scan:v2:"  # bump when the rules or the result format change


# --- Logging: one JSON object per line on stdout (CloudWatch Logs) ------------


class JsonFormatter(logging.Formatter):
    STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "taskName", "color_message"}

    def __init__(self, instance_id: str):
        super().__init__()
        self.instance_id = instance_id

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "instance_id": self.instance_id,
        }
        # Fields passed with extra={...} become JSON fields.
        entry.update({k: v for k, v in vars(record).items() if k not in self.STANDARD and not k.startswith("_")})
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logging(instance_id: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(instance_id))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True  # our middleware logs every request


# --- App ----------------------------------------------------------------------


def create_app(database_url: str | None = None, max_upload_kb: int | None = None, redis_client=None) -> FastAPI:
    """Arguments override the environment (used by the tests)."""
    instance_id = os.getenv("INSTANCE_ID", "local")
    setup_logging(instance_id)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.db = db.Database(database_url)
        app.state.db.create_tables()
        yield
        app.state.db.engine.dispose()

    app = FastAPI(title="Email Phishing Detector", lifespan=lifespan)
    app.state.max_upload_bytes = (max_upload_kb or int(os.getenv("MAX_UPLOAD_KB", "1024"))) * 1024
    app.state.info = {"instance_id": instance_id, "availability_zone": os.getenv("AVAILABILITY_ZONE", "local"),
                      "version": os.getenv("APP_VERSION", "dev")}
    if redis_client is None and os.getenv("REDIS_URL"):
        # Short timeouts and no retries: a broken cache must not slow down scans.
        redis_client = redis.Redis.from_url(os.environ["REDIS_URL"], socket_timeout=0.5,
                                            socket_connect_timeout=0.5, retry=Retry(NoBackoff(), 0))
    app.state.redis = redis_client

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        info = request.app.state.info
        response.headers["X-Served-By"] = f"{info['instance_id']} ({info['availability_zone']})"
        # Load balancer health checks every few seconds would flood the logs.
        level = logging.DEBUG if request.url.path.startswith("/health") else logging.INFO
        logger.log(level, "%s %s %s", request.method, request.url.path, response.status_code, extra={
            "event": "http_request", "method": request.method, "path": request.url.path,
            "status_code": response.status_code, "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            "client_ip": client_ip(request),
        })
        return response

    @app.exception_handler(OperationalError)
    async def database_unavailable(request: Request, exc: OperationalError):
        logger.error("Database error", extra={"event": "db_error", "path": request.url.path,
                                              "error": type(exc).__name__})
        return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

    register_routes(app)
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")  # last: API routes win
    return app


def client_ip(request: Request) -> str | None:
    """Behind the ALB, the last X-Forwarded-For entry is the real client (earlier ones can be forged)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip() or None
    return request.client.host if request.client else None


def get_session(request: Request):
    database: db.Database = request.app.state.db
    if not database.ready and not database.create_tables():
        raise HTTPException(status_code=503, detail="Database unavailable")
    with database.sessions() as session:
        yield session


def cached_analyze(redis_client, raw: bytes, filename: str | None) -> tuple[ScanResult, str]:
    """analyze() with the optional Redis cache. Fails open: on any Redis error the scan runs normally."""
    if redis_client is None:
        return analyze(raw, filename), "disabled"
    key = CACHE_PREFIX + content_hash(raw)
    status = "miss"
    try:
        cached = redis_client.get(key)
        if cached:
            result = ScanResult.model_validate_json(cached)
            return result.model_copy(update={"summary": {**result.summary, "filename": filename}}), "hit"
    except Exception as exc:
        logger.warning("Cache unavailable", extra={"event": "cache_error", "error": type(exc).__name__})
        status = "error"
    result = analyze(raw, filename)  # content only: the sender history is applied per request
    if status == "miss":
        try:
            redis_client.set(key, result.model_dump_json(), ex=int(os.getenv("CACHE_TTL_SECONDS", "3600")))
        except Exception as exc:
            logger.warning("Cache unavailable", extra={"event": "cache_error", "error": type(exc).__name__})
            status = "error"
    return result, status


def scan_out(scan: db.Scan, with_findings: bool = True) -> dict:
    created = scan.created_at if scan.created_at.tzinfo else scan.created_at.replace(tzinfo=timezone.utc)
    out = {"id": scan.id, "created_at": created, "source": scan.source, "filename": scan.filename,
           "sender": scan.sender, "subject": scan.subject, "score": scan.score, "risk_level": scan.risk_level,
           "verdict": VERDICTS[RiskLevel(scan.risk_level)], "is_phishing": scan.is_phishing,
           "user_label": scan.user_label}
    if with_findings:
        out["findings"] = scan.findings
    return out


class LabelRequest(BaseModel):
    label: Literal["phishing", "safe"]


# --- Routes -------------------------------------------------------------------


def register_routes(app: FastAPI) -> None:
    @app.post("/api/scan")
    def scan_email(request: Request, file: UploadFile | None = File(None), text: str | None = Form(None),
                   session=Depends(get_session)):
        """Scan an uploaded file or pasted text, apply the sender history, and store the result."""
        raw, source, filename = read_input(file, text, request.app.state.max_upload_bytes)
        started = time.perf_counter()
        result, cache_status = cached_analyze(request.app.state.redis, raw, filename)
        analysis_ms = round((time.perf_counter() - started) * 1000, 1)

        # History is looked up before saving, so this scan is not its own history.
        result = apply_history(result, db.sender_history(session, result))
        scan, previous = db.save_scan(session, result, source, filename, client_ip(request))

        # Metadata only: never the email content, addresses or subject.
        logger.info("Scan completed", extra={
            "event": "scan_completed", "scan_id": scan.id, "source": source, "score": result.score,
            "risk_level": result.risk_level.value, "findings_count": len(result.findings),
            "duplicate": previous is not None, "cache": cache_status, "analysis_ms": analysis_ms,
        })
        return {**result.model_dump(), "scan_id": scan.id, "created_at": scan_out(scan)["created_at"],
                "previous_scan_id": previous.id if previous else None, "cache": cache_status}

    @app.get("/api/history")
    def history(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), session=Depends(get_session)):
        return [scan_out(s, with_findings=False) for s in db.list_scans(session, limit, offset)]

    @app.get("/api/history/{scan_id}")
    def get_scan(scan_id: int, session=Depends(get_session)):
        scan = session.get(db.Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        return scan_out(scan)

    @app.post("/api/history/{scan_id}/label")
    def label(scan_id: int, body: LabelRequest, session=Depends(get_session)):
        """User feedback: mark a scan as phishing or safe. Also feeds the sender history rules."""
        scan = db.label_scan(session, scan_id, body.label)
        if scan is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        logger.info("Scan labeled", extra={"event": "scan_labeled", "scan_id": scan_id, "label": body.label})
        return scan_out(scan)

    @app.get("/api/info")
    def info(request: Request):
        """Which instance answered (shows the load balancer at work)."""
        return {**request.app.state.info, "db_backend": request.app.state.db.backend,
                "cache_enabled": request.app.state.redis is not None}

    @app.get("/health")
    def health():
        """Liveness for the load balancer. No DB call: a DB outage must not take every instance out."""
        return {"status": "ok"}

    @app.get("/health/ready")
    def ready(request: Request):
        """Readiness: the database answers. The cache is reported but never causes a 503."""
        cache = "disabled"
        if request.app.state.redis is not None:
            try:
                request.app.state.redis.ping()
                cache = "ok"
            except Exception:
                cache = "error"
        try:
            request.app.state.db.ping()
        except SQLAlchemyError:
            return JSONResponse(status_code=503, content={"status": "unavailable", "db": "unreachable", "cache": cache})
        return {"status": "ok", "db": "ok", "cache": cache}


def read_input(file: UploadFile | None, text: str | None, max_bytes: int) -> tuple[bytes, str, str | None]:
    """Validate the request and return (raw bytes, source, filename)."""
    has_file, has_text = bool(file and file.filename), bool(text)
    if has_file == has_text:
        raise HTTPException(status_code=400, detail="Provide either a file or pasted text")
    if has_file:
        filename = Path(file.filename).name
        if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=415, detail="Unsupported file type (use .eml, .txt or a text .msg)")
        raw, source = file.file.read(max_bytes + 1), "upload"  # one byte more to detect oversize
    else:
        filename, raw, source = None, text.encode("utf-8"), "paste"
    if len(raw) > max_bytes:
        raise HTTPException(status_code=413, detail=f"Email is too large (max {max_bytes // 1024} KB)")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="Email content is empty")
    return raw, source, filename


app = create_app()
