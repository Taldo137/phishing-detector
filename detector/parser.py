"""Turn raw input (an .eml file or pasted text) into a ParsedEmail.

Static parsing only: nothing in the email is opened, fetched or executed.
The input is attacker-controlled, so parse_email() never raises.
"""

import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
# "Attachment: invoice.pdf.exe" written in the body (common in pasted emails)
ATTACHMENT_LINE_RE = re.compile(
    r"^[ \t>]*(?:attachments?|attached(?: files?)?)[ \t]*:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE
)
FILENAME_RE = re.compile(r"[^\s,;/\\:\"'<>()]+\.[A-Za-z0-9]{1,8}\b")


class Link(BaseModel):
    url: str                    # the real target
    text: str | None = None     # visible anchor text (HTML links only)


class Attachment(BaseModel):
    filename: str
    content_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None   # None when the file is only mentioned in the text


class ParsedEmail(BaseModel):
    has_headers: bool = False   # False for pasted text without headers
    from_name: str | None = None
    from_address: str | None = None
    reply_to: str | None = None
    to_address: str | None = None   # first recipient
    subject: str | None = None
    body: str = ""
    links: list[Link] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse MIME if the input has From/To/Subject headers, otherwise treat it as plain text."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        if any(name.lower() in ("from", "to", "subject") for name in msg.keys()):
            return _parse_mime(msg)
    except Exception:
        pass  # malformed input: still analyze it as text
    text = raw.decode("utf-8-sig", errors="replace")
    return ParsedEmail(body=text, links=_text_links(text, []), attachments=_mentioned_attachments(text, []))


def _parse_mime(msg) -> ParsedEmail:
    texts, links, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = _filename(part)
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(Attachment(
                filename=filename or "unnamed",
                # Only what the sender declared (Python would default to text/plain).
                content_type=part.get_content_type() if "content-type" in part else None,
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ))
        elif part.get_content_type() == "text/plain":
            texts.append(_decode(part))
        elif part.get_content_type() == "text/html":
            text, html_links = _parse_html(_decode(part))
            texts.append(text)
            links += html_links

    body = "\n".join(t for t in texts if t)
    from_name, from_address = parseaddr(_header(msg, "From"))
    recipients = [address for _, address in getaddresses([_header(msg, "To")]) if "@" in address]
    return ParsedEmail(
        has_headers=True,
        from_name=from_name or None,
        from_address=from_address or None,
        reply_to=parseaddr(_header(msg, "Reply-To"))[1] or None,
        to_address=recipients[0] if recipients else None,
        subject=_header(msg, "Subject") or None,
        body=body,
        links=links + _text_links(body, links),
        attachments=attachments + _mentioned_attachments(body, attachments),
    )


def _header(msg, name: str) -> str:
    try:
        return " ".join(str(msg.get(name) or "").split())  # unfold multi-line headers
    except Exception:  # undecodable header
        return ""


def _filename(part) -> str | None:
    try:
        name = part.get_filename()
    except Exception:
        return None
    return name.strip() if name and name.strip() else None


def _decode(part) -> str:
    payload = part.get_payload(decode=True) or b""
    try:
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    except LookupError:  # unknown charset name
        return payload.decode("utf-8", errors="replace")


def _parse_html(html: str) -> tuple[str, list[Link]]:
    """Visible text and web links (href + anchor text) of an HTML body."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    links = []
    for anchor in soup.find_all("a", href=True):
        url = str(anchor["href"]).strip()
        if URL_RE.match(url):  # skips mailto:, tel: and #anchors
            link = Link(url=url, text=anchor.get_text(" ", strip=True) or None)
            if link not in links:
                links.append(link)
    return soup.get_text("\n", strip=True), links


def _text_links(text: str, existing: list[Link]) -> list[Link]:
    """Bare URLs in the text, skipping hrefs and anchor texts already found in the HTML."""
    seen = {link.url for link in existing}
    anchor_texts = [link.text for link in existing if link.text]
    found = []
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:!?")
        if url not in seen and not any(url in anchor for anchor in anchor_texts):
            seen.add(url)
            found.append(Link(url=url))
    return found


def _mentioned_attachments(text: str, existing: list[Attachment]) -> list[Attachment]:
    known = {a.filename.lower() for a in existing}
    found = []
    for line in ATTACHMENT_LINE_RE.finditer(text):
        for name in FILENAME_RE.findall(URL_RE.sub(" ", line.group(1))):  # "www.x.com" is not a file
            if name.lower() not in known:
                known.add(name.lower())
                found.append(Attachment(filename=name))
    return found
