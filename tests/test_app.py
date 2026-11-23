"""API, cache, sender history and CLI tests."""

import json
from pathlib import Path

import pytest
import redis
from fastapi.testclient import TestClient

from app import db
from app.main import JsonFormatter, create_app
from cli import main as cli
from detector.engine import analyze

SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """A developer's shell settings must not change the test results."""
    for name in ("DATABASE_URL", "DB_HOST", "REDIS_URL", "INSTANCE_ID", "AVAILABILITY_ZONE", "APP_VERSION"):
        monkeypatch.delenv(name, raising=False)


class FakeRedis:
    def __init__(self, broken: bool = False):
        self.data, self.broken = {}, broken

    def get(self, key):
        if self.broken:
            raise redis.ConnectionError("down")
        return self.data.get(key)

    def set(self, key, value, ex=None):
        self.data[key] = value

    def ping(self):
        if self.broken:
            raise redis.ConnectionError("down")


def make_client(tmp_path, **kwargs) -> TestClient:
    return TestClient(create_app(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}", **kwargs))


@pytest.fixture
def client(tmp_path):
    with make_client(tmp_path, max_upload_kb=8) as test_client:  # `with` runs startup (creates tables)
        yield test_client


def upload(client, name: str):
    return client.post("/api/scan", files={"file": (name, (SAMPLES / name).read_bytes(), "message/rfc822")})


def email(sender="dana@partner.com", to="me@example.com", text="Notes attached.") -> str:
    return f"From: {sender}\nTo: {to}\nSubject: test\n\n{text}\n"


def scan_text(client, raw: str) -> dict:
    response = client.post("/api/scan", data={"text": raw})
    assert response.status_code == 200
    return response.json()


def rule_ids(result: dict) -> set[str]:
    return {f["id"] for f in result["findings"]}


# --- API -----------------------------------------------------------------------


def test_scan_history_and_label_flow(client):
    result = upload(client, "phish_paypal_lookalike.eml").json()
    assert (result["scan_id"], result["risk_level"], result["cache"]) == (1, "HIGH", "disabled")

    assert [s["id"] for s in client.get("/api/history").json()] == [1]
    detail = client.get("/api/history/1").json()
    assert detail["findings"][0]["id"] == "SENDER_LOOKALIKE_DOMAIN"

    labeled = client.post("/api/history/1/label", json={"label": "phishing"}).json()
    assert labeled["user_label"] == "phishing"
    assert client.post("/api/history/1/label", json={"label": "maybe"}).status_code == 422
    assert client.get("/api/history/99").status_code == 404


def test_scan_pasted_text_and_duplicate(client):
    raw = (SAMPLES / "legit_newsletter.eml").read_text()
    first = scan_text(client, raw)
    second = scan_text(client, raw.replace("\n", "\r\n"))  # same email pasted in a browser
    assert first["risk_level"] == "LOW"
    assert (first["previous_scan_id"], second["previous_scan_id"]) == (None, first["scan_id"])


@pytest.mark.parametrize(("kwargs", "status"), [
    ({}, 400),                                                                    # nothing
    ({"data": {"text": "x"}, "files": {"file": ("a.eml", b"x")}}, 400),           # both
    ({"data": {"text": "   "}}, 400),                                             # empty
    ({"files": {"file": ("a.pdf", b"%PDF")}}, 415),                               # wrong type
    ({"files": {"file": ("big.eml", b"Subject: x\n\n" + b"a" * 9000)}}, 413),     # over 8 KB
])
def test_input_validation(client, kwargs, status):
    assert client.post("/api/scan", **kwargs).status_code == status


def test_health_info_and_ui(tmp_path, monkeypatch):
    monkeypatch.setenv("INSTANCE_ID", "i-0abc")
    monkeypatch.setenv("AVAILABILITY_ZONE", "eu-north-1a")
    with make_client(tmp_path) as client:
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/health/ready").json() == {"status": "ok", "db": "ok", "cache": "disabled"}
        response = client.get("/api/info")
        assert response.json()["instance_id"] == "i-0abc"
        assert response.headers["X-Served-By"] == "i-0abc (eu-north-1a)"
        assert "<title>Email Phishing Detector</title>" in client.get("/").text


def test_unreachable_database(tmp_path):
    # SQLite cannot open a directory: fails like an unreachable RDS, without network timeouts.
    with TestClient(create_app(database_url=f"sqlite:///{tmp_path.as_posix()}")) as client:
        assert client.get("/health").status_code == 200       # the ALB keeps the instance
        assert client.get("/health/ready").status_code == 503
        assert client.post("/api/scan", data={"text": "hello"}).status_code == 503


def test_logs_are_json_without_email_content(client, caplog):
    scan_text(client, email(text="secret-content-123"))
    lines = [json.loads(JsonFormatter("local").format(record)) for record in caplog.records]
    scan_line = next(line for line in lines if line.get("event") == "scan_completed")
    assert scan_line["risk_level"] == "LOW" and scan_line["instance_id"] == "local"
    assert not any("secret-content-123" in json.dumps(line) or "dana@partner.com" in json.dumps(line) for line in lines)


# --- Cache -----------------------------------------------------------------------


def test_cache_miss_then_hit(tmp_path):
    with make_client(tmp_path, redis_client=FakeRedis()) as client:
        first, second = scan_text(client, email()), scan_text(client, email())
    assert (first["cache"], second["cache"]) == ("miss", "hit")
    assert second["findings"] == first["findings"]


def test_broken_cache_fails_open(tmp_path):
    with make_client(tmp_path, redis_client=FakeRedis(broken=True)) as client:
        assert scan_text(client, email())["cache"] == "error"
        assert client.get("/health/ready").json()["cache"] == "error"  # reported, but still 200


# --- Sender history --------------------------------------------------------------


def test_known_sender_gets_trust_signal(client):
    scan_text(client, email(text="first"))
    result = scan_text(client, email(text="Second one, reply as soon as possible."))
    assert "SENDER_KNOWN_TO_RECIPIENT" in rule_ids(result)
    assert result["score"] == 0  # urgency +10, known sender -15


def test_labeled_phishing_flags_the_whole_domain(client):
    first = scan_text(client, email(sender="ceo@partner.com", text="first"))
    client.post(f"/api/history/{first['scan_id']}/label", json={"label": "phishing"})
    result = scan_text(client, email(sender="hr@partner.com", text="second"))
    assert "SENDER_PREVIOUSLY_FLAGGED" in rule_ids(result)
    assert "SENDER_KNOWN_TO_RECIPIENT" not in rule_ids(result)


def test_history_is_applied_on_a_cache_hit(tmp_path):
    with make_client(tmp_path, redis_client=FakeRedis()) as client:
        first = scan_text(client, email(sender="ceo@partner.com", text="first"))
        client.post(f"/api/history/{first['scan_id']}/label", json={"label": "phishing"})
        miss = scan_text(client, email(sender="hr@partner.com", text="second"))
        hit = scan_text(client, email(sender="hr@partner.com", text="second"))
    assert (miss["cache"], hit["cache"]) == ("miss", "hit")
    assert "SENDER_PREVIOUSLY_FLAGGED" in rule_ids(hit)


@pytest.fixture
def session(tmp_path):
    database = db.Database(f"sqlite:///{(tmp_path / 'h.db').as_posix()}")
    database.create_tables()
    with database.sessions() as s:
        yield s
    database.engine.dispose()


def save(session, raw: str, label: str | None = None):
    scan, _ = db.save_scan(session, analyze(raw.encode()), "paste", None)
    if label:
        db.label_scan(session, scan.id, label)


def history_of(session, raw: str):
    return db.sender_history(session, analyze(raw.encode()))


def test_history_lookup_rules(session):
    save(session, email(sender="scammer@gmail.com", text="a"), label="phishing")
    save(session, email(text="Verify your password immediately. Your account will be suspended."))  # MEDIUM
    save(session, email(text="same"))
    save(session, email(text="same"), label="phishing")

    # Free email provider: flagged per address, not for every gmail.com sender.
    assert history_of(session, email(sender="friend@gmail.com")).flagged_scans == 0
    assert history_of(session, email(sender="scammer@gmail.com")).flagged_scans == 1
    # One unlabeled MEDIUM scan breaks the clean history; the same content is never its own history.
    same = history_of(session, email(text="same"))
    assert (same.scans_to_recipient, same.all_safe_to_recipient, same.flagged_scans) == (1, False, 0)


def test_label_safe_clears_a_high_flag(session):
    phish = email(sender="ceo@partner.com", text="Attachment: invoice.pdf.exe\nVerify your password now.")
    save(session, phish)
    assert history_of(session, email(text="later")).flagged_scans == 1
    db.label_scan(session, 1, "safe")
    assert history_of(session, email(text="later")).flagged_scans == 0


# --- CLI -------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "code"), [("phish_attachment.eml", 2), ("suspicious_shortener.eml", 1),
                                            ("legit_newsletter.eml", 0)])
def test_cli_exit_codes(name, code, capsys):
    assert cli([str(SAMPLES / name)]) == code
    assert "=== Phishing Scan Report ===" in capsys.readouterr().out


def test_cli_json_and_trust_signals(capsys):
    assert cli([str(SAMPLES / "legit_gov_il.eml"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["score"] == 0
    cli([str(SAMPLES / "legit_gov_il.eml")])
    out = capsys.readouterr().out
    assert "Trust signals (1, lower the score):" in out and " -15" in out


@pytest.mark.parametrize("args", [["missing.eml"], [], ["--bogus"]])
def test_cli_errors_exit_3(args, capsys):
    assert cli(args) == 3


def test_cli_save_uses_history(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'cli.db').as_posix()}")
    first, second = tmp_path / "1.eml", tmp_path / "2.eml"
    first.write_text(email(text="first"))
    second.write_text(email(text="Please reply urgently."))
    assert cli([str(first), "--save"]) == 0
    assert "Saved as scan #1." in capsys.readouterr().err
    assert cli([str(second), "--save", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"][-1]["id"] == "SENDER_KNOWN_TO_RECIPIENT"


def test_cli_save_with_unreachable_db_still_prints_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path.as_posix()}")
    assert cli([str(SAMPLES / "phish_attachment.eml"), "--save"]) == 3
    captured = capsys.readouterr()
    assert "HIGH RISK" in captured.out and "History: unavailable" in captured.out
    assert "could not save the scan" in captured.err
