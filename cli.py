"""Command-line phishing scanner.

Usage: python cli.py <file> [--json] [--save]
Exit codes: 0 = LOW, 1 = MEDIUM, 2 = HIGH, 3 = error (usable in scripts).
"""

import argparse
import sys
from pathlib import Path

from detector.engine import RiskLevel, ScanResult, analyze, apply_history

EXIT_CODES = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}
EXIT_ERROR = 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cli.py", description="Scan an email file for phishing indicators.")
    parser.add_argument("path", help="email file (.eml or .txt)")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--save", action="store_true", help="use the sender history in the DB and save the scan")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_ERROR if exc.code else 0  # argparse uses 2 for bad arguments, which means HIGH here
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # never crash on a subject the console cannot show

    path = Path(args.path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return fail(f"cannot read {path}: {exc.strerror or exc}")
    if not raw.strip():
        return fail(f"file is empty: {path}")

    result = analyze(raw, filename=path.name)
    message, error = None, None
    if args.save:
        try:
            result, message = save_with_history(result, path.name)
        except Exception as exc:
            error = f"could not save the scan (sender history unavailable): {exc}"

    print(result.model_dump_json(indent=2) if args.json else report(result, path, history_failed=bool(error)))
    if error:
        return fail(error)
    if message:
        print(message, file=sys.stderr)  # stderr keeps --json output valid
    return EXIT_CODES[result.risk_level]


def save_with_history(result: ScanResult, filename: str) -> tuple[ScanResult, str]:
    from app import db  # only --save needs the database

    database = db.Database()
    try:
        if not database.create_tables():
            raise RuntimeError("database unavailable")
        with database.sessions() as session:
            result = apply_history(result, db.sender_history(session, result))
            scan, previous = db.save_scan(session, result, "cli", filename)
    finally:
        database.engine.dispose()
    message = f"Saved as scan #{scan.id}."
    if previous:
        message += f" Previously scanned as #{previous.id}."
    return result, message


def report(result: ScanResult, path: Path, history_failed: bool = False) -> str:
    summary = result.summary
    lines = [
        "=== Phishing Scan Report ===",
        f"File:    {path}",
        f"From:    {summary['from'] or '(unknown)'}",
        f"Subject: {summary['subject'] or '(none)'}",
        f"Verdict: {result.risk_level.value} RISK - {result.verdict}   (score {result.score}/100)",
    ]
    if history_failed:
        lines.append("History: unavailable (database error), scored on content only")
    indicators = [f for f in result.findings if f.points >= 0]
    trust = [f for f in result.findings if f.points < 0]
    width = max((len(f.title) for f in result.findings), default=0)

    lines.append("")
    lines.append(f"Indicators found ({len(indicators)}):" if indicators else "No indicators found.")
    for group in (indicators, trust):
        if group is trust and trust:
            lines += ["", f"Trust signals ({len(trust)}, lower the score):"]
        for f in group:
            lines.append(f"  {'[' + f.severity.value + ']':<10} {f.category:<12} {f.title:<{width}}  {f.points:+4d}")
            lines.append(f"  {'':<23} {f.evidence}")

    attached = [a for a in summary["attachments"] if a["sha256"]]
    if attached:
        lines += ["", f"Attachments ({len(attached)}):"]
        lines += [f"  {a['filename']}  ({a['size_bytes']} bytes)  sha256={a['sha256']}" for a in attached]
    return "\n".join(lines)


def fail(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
