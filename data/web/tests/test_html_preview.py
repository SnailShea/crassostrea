"""HTML view of the message: sanitized HTML body in a sandboxed frame."""
import base64
from email.message import EmailMessage

import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, MailboxUser, MailLogEntry, QuarantineItem
from crassostrea.services import html_preview

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
HTML = ('<html><head><style>p{color:#c00}</style><script>alert(1)</script></head>'
        '<body onload="alert(2)"><p onclick="alert(3)">Dear customer, <a href="http://phish.example/login">log in</a>'
        '</p><img src="cid:logo@bank.example" alt="logo"><img src="http://track.example/pixel.gif">'
        '<img src="data:image/svg+xml;base64,PHN2Zz4=" alt="svg">'
        '<form action="http://phish.example"><input name="pw"></form><iframe src="http://phish.example"></iframe>'
        '</body></html>')
PLAIN = b"From: a@x.example\r\nTo: bob@example.com\r\nSubject: Hi\r\n\r\nJust text.\r\n"


def _with_html():
    """mixed { alternative { text, related { html, png (cid) } }, pdf }"""
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = "bank@bank.example", "bob@example.com", "Account"
    message.set_content("Dear customer, log in: http://phish.example/login")
    message.add_alternative(HTML, subtype="html")
    message.get_payload()[1].add_related(PNG, "image", "png", cid="<logo@bank.example>")
    message.add_attachment(b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="statement.pdf")
    return bytes(message)


def test_render_is_sanitized():
    page = html_preview.render(_with_html())
    for removed in ("<script", "alert(", "onload", "onclick", "href", "phish.example", "track.example", "svg+xml",
                    "<form", "<input", "<iframe"):
        assert removed not in page, removed
    assert "Dear customer" in page and "<style>p{color:#c00}</style>" in page
    # the image referenced by Content-ID is inlined
    assert 'src="data:image/png;base64,' + base64.b64encode(PNG).decode() + '"' in page
    assert html_preview.render(PLAIN) is None
    assert html_preview.has_html(_with_html()) and not html_preview.has_html(PLAIN)


def test_render_truncates_huge_html():
    message = EmailMessage()
    message.set_content("<p>" + "x" * (html_preview.MAX_HTML + 10) + "</p>", subtype="html")
    page = html_preview.render(bytes(message))
    assert "Only the first 2 MiB" in page and len(page) < html_preview.MAX_HTML + 2000


@pytest.fixture
def entry(app):
    entry = MailLogEntry(sender="bank@bank.example", rcpts="bob@example.com", subject="Account", symbols="[]",
                         message=_with_html())
    db.session.add(entry)
    db.session.commit()
    return entry


def test_message_card_switches_views(logged_in, entry):
    plain = logged_in.get(f"/mail-log/{entry.id}").get_data(as_text=True)
    assert plain.count('class="card" id="message"') == 1 and 'class="view-toggle"' in plain
    assert "Dear customer, log in: http://phish.example/login" in plain and "<iframe" not in plain
    assert f'href="/mail-log/{entry.id}?view=html#message"' in plain
    page = logged_in.get(f"/mail-log/{entry.id}?view=html").get_data(as_text=True)
    assert f'<iframe class="message-html" src="/mail-log/{entry.id}/html" sandbox' in page
    assert "Dear customer, log in" not in page  # the plain text is not shown alongside
    assert "statement.pdf" in page and "<h2>Headers</h2>" in page  # attachments and headers as before


def test_no_switch_without_html(logged_in, app):
    entry = MailLogEntry(rcpts="bob@example.com", subject="Hi", symbols="[]", message=PLAIN)
    db.session.add(entry)
    db.session.commit()
    page = logged_in.get(f"/mail-log/{entry.id}?view=html").get_data(as_text=True)
    assert "view-toggle" not in page and "Just text." in page and "<iframe" not in page
    assert logged_in.get(f"/mail-log/{entry.id}/html").status_code == 404


def test_html_response(logged_in, entry):
    response = logged_in.get(f"/mail-log/{entry.id}/html")
    assert response.status_code == 200 and response.mimetype == "text/html"
    assert response.headers["Content-Security-Policy"] == html_preview.CSP
    assert "sandbox" in html_preview.CSP and "script-src" not in html_preview.CSP
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN" and response.headers["Referrer-Policy"] == "no-referrer"
    assert b"<script" not in response.data and b"Dear customer" in response.data
    assert logged_in.get("/mail-log/999/html").status_code == 404


def test_quarantine_view(logged_in, app):
    item = QuarantineItem(rcpt="bob@example.com", domain="example.com", subject="Account", symbols="[]",
                          message=_with_html())
    db.session.add(item)
    db.session.commit()
    page = logged_in.get(f"/quarantine/{item.id}?view=html").get_data(as_text=True)
    assert f'src="/quarantine/{item.id}/html"' in page
    response = logged_in.get(f"/quarantine/{item.id}/html")
    assert response.headers["Content-Security-Policy"] == html_preview.CSP and b"<script" not in response.data


def test_admins_only(app, client, entry):
    assert client.get(f"/mail-log/{entry.id}/html").status_code == 302
    domain = Domain(name="example.com", destination_host="mx.internal")
    user = MailboxUser(email="bob@example.com", domain=domain)
    user.set_password("bob-password")
    item = QuarantineItem(rcpt="bob@example.com", domain="example.com", subject="Account", symbols="[]",
                          message=_with_html())
    db.session.add_all([domain, user, item])
    db.session.commit()
    assert client.post("/login", data={"username": "bob@example.com", "password": "bob-password"}).status_code == 302
    # the portal keeps the plain text view, the admin HTML URL is not open to mailbox users
    page = client.get(f"/my/{item.id}?view=html").get_data(as_text=True)
    assert "view-toggle" not in page and "Dear customer, log in" in page
    assert client.get(f"/quarantine/{item.id}/html").status_code in (302, 403)
