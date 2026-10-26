"""Branding settings, brand assets and the theme toggle."""
import io
import re

import pytest

from crassostrea.extensions import db
from crassostrea.models import BrandAsset, get_setting
from crassostrea.services import branding

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
ICO = b"\x00\x00\x01\x00" + b"\x00" * 32
SVG = b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>'


def _branding(client, follow_redirects=False, **overrides):
    data = {"brand-brand_name": "Acme Mail Shield", "brand-brand_accent": "#aa3300", "brand-brand_footer": "",
            "brand-brand_theme": "system"}
    data.update(overrides)
    return client.post("/settings/branding", data=data, content_type="multipart/form-data",
                       follow_redirects=follow_redirects)


# --- validation ---------------------------------------------------------------

@pytest.mark.parametrize("data,expected", [
    (PNG, "image/png"), (b"\xff\xd8\xff\xe0" + b"0" * 10, "image/jpeg"), (b"GIF89a" + b"0" * 10, "image/gif"),
    (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"), (ICO, "image/x-icon"), (SVG, "image/svg+xml"),
    (b"  \n<svg xmlns='http://www.w3.org/2000/svg'></svg>", "image/svg+xml"),
    (b"<html><body>hi</body></html>", None), (b"MZ\x90\x00", None),
])
def test_detect_image_type(data, expected):
    assert branding.detect_image_type(data) == expected


@pytest.mark.parametrize("svg", [
    b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div/></foreignObject></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.example/x.png"/></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><a xlink:href="javascript:alert(1)"/></svg>',
    b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg"/>',
])
def test_dangerous_svg_rejected(svg):
    with pytest.raises(branding.BrandingError):
        branding.validate_asset("logo", svg)


def test_safe_svg_with_internal_reference_accepted():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="a"/></defs><use href="#a"/></svg>'
    assert branding.validate_asset("logo", svg) == "image/svg+xml"


def test_asset_limits():
    with pytest.raises(branding.BrandingError, match="too large"):
        branding.validate_asset("favicon", ICO + b"\x00" * (128 * 1024))
    with pytest.raises(branding.BrandingError, match="Unsupported"):
        branding.validate_asset("favicon", b"\xff\xd8\xff\xe0" + b"0" * 10)  # no JPEG favicons


@pytest.mark.parametrize("accent", ["#2557d6", "#ffee00", "#000000", "#ffffff"])
def test_accent_palette_contrast(accent):
    palette = branding.accent_palette(accent)
    for mode in ("light", "dark"):
        bg, text = palette[mode]["--accent"], palette[mode]["--accent-text"]
        lum = sorted([branding._luminance(bg), branding._luminance(text)])
        assert (lum[1] + 0.05) / (lum[0] + 0.05) >= 4.5, (accent, mode)   # WCAG AA for button text
    assert branding._luminance(palette["dark"]["--accent"]) >= 0.25          # readable on dark backgrounds


# --- settings -------------------------------------------------------------------

def test_save_branding_and_render(app, logged_in):
    client = app.test_client()
    response = _branding(logged_in, **{"brand-brand_footer": "Support: +1 555 0100",
                                       "brand-logo": (io.BytesIO(PNG), "logo.png")})
    assert response.status_code == 302
    assert get_setting("brand_name") == "Acme Mail Shield" and get_setting("brand_accent") == "#aa3300"
    page = logged_in.get("/").get_data(as_text=True)
    assert "· Acme Mail Shield</title>" in page and "Support: +1 555 0100" in page
    version = get_setting("brand_version")
    assert f"/branding/logo?v={version}" in page and f"/branding/theme.css?v={version}" in page

    logo = client.get(f"/branding/logo?v={version}")
    assert logo.data == PNG and logo.mimetype == "image/png"
    assert "immutable" in logo.headers["Cache-Control"]
    css = client.get("/branding/theme.css").get_data(as_text=True)
    assert "--accent: #aa3300;" in css and ':root[data-theme="dark"]' in css

    login = client.get("/login").get_data(as_text=True)
    assert "<h1>Acme Mail Shield</h1>" in login and "/branding/logo" in login


def test_default_accent_and_remove_logo(app, logged_in):
    client = app.test_client()
    _branding(logged_in, **{"brand-logo": (io.BytesIO(PNG), "logo.png")})
    _branding(logged_in, **{"brand-default_accent": "y", "brand-remove_logo": "y"})
    assert get_setting("brand_accent") == ""
    assert db.session.get(BrandAsset, "logo") is None
    assert client.get("/branding/logo").status_code == 404
    assert "/branding/theme.css" not in logged_in.get("/").get_data(as_text=True)


def test_invalid_branding_input(logged_in):
    response = _branding(logged_in, **{"brand-brand_accent": "red"})
    assert response.status_code == 400 and b"#rrggbb" in response.data
    response = _branding(logged_in, **{"brand-logo": (io.BytesIO(b"<html>"), "logo.png")}, follow_redirects=True)
    assert b"Unsupported image type" in response.data
    assert db.session.get(BrandAsset, "logo") is None
    assert get_setting("brand_name") == "Spam Filter"  # nothing saved on error


def test_svg_served_sandboxed(app, logged_in):
    client = app.test_client()
    _branding(logged_in, **{"brand-logo": (io.BytesIO(SVG), "logo.svg")})
    response = client.get("/branding/logo")
    assert response.mimetype == "image/svg+xml"
    assert "sandbox" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_favicon_default_and_custom(app, logged_in):
    client = app.test_client()
    default = client.get("/branding/favicon")
    assert default.status_code == 200 and default.mimetype == "image/svg+xml"
    _branding(logged_in, **{"brand-favicon": (io.BytesIO(ICO), "favicon.ico")})
    assert client.get("/branding/favicon").data == ICO


def test_only_admins_change_branding(app, client):
    assert client.post("/settings/branding", data={"brand-brand_name": "x"}).status_code == 302  # to login
    assert get_setting("brand_name") == "Spam Filter"


def test_digest_uses_branding(logged_in, monkeypatch):
    import email
    import email.policy
    from crassostrea.models import Domain, QuarantineItem
    from crassostrea.services import digest, mailer
    _branding(logged_in, **{"brand-logo": (io.BytesIO(PNG), "logo.png")})
    db.session.add(Domain(name="example.com", destination_host="mx"))
    db.session.add(QuarantineItem(rcpt="a@example.com", domain="example.com", symbols="[]", message=b"x"))
    db.session.commit()
    sent = []
    monkeypatch.setattr(mailer, "reinject", lambda s, r, m: sent.append(m))
    db.session.expire_all()
    from flask import g
    g.pop("branding", None)
    digest.send_due_digests()
    msg = email.message_from_bytes(sent[0], policy=email.policy.default)
    assert msg["From"].addresses[0].display_name == "Acme Mail Shield"
    html = msg.get_body(("html",)).get_content()
    assert "background:#aa3300" in html and "https://localhost/branding/logo?v=" in html


# --- theme toggle ---------------------------------------------------------------

def _html_theme(response):
    match = re.search(r'<html lang="en"(?: data-theme="(\w+)")?>', response.get_data(as_text=True))
    return match.group(1)


def test_theme_cookie(client):
    assert _html_theme(client.get("/login")) is None            # follows the system by default
    response = client.post("/theme", data={"theme": "dark", "next": "/login?x=1"})
    assert response.status_code == 302 and response.headers["Location"] == "/login?x=1"
    assert "sf_theme=dark" in response.headers["Set-Cookie"]
    assert _html_theme(client.get("/login")) == "dark"
    page = client.get("/login").get_data(as_text=True)
    assert 'value="system"' in page and "☾ Dark theme" in page   # next click: back to system
    client.post("/theme", data={"theme": "system"})
    assert _html_theme(client.get("/login")) is None


def test_theme_rejects_bad_values(client):
    assert client.post("/theme", data={"theme": "neon"}).status_code == 400
    response = client.post("/theme", data={"theme": "light", "next": "https://evil.example/"})
    assert response.headers["Location"] == "/login"
    client.set_cookie("sf_theme", '"><script>')
    assert _html_theme(client.get("/login")) is None


def test_admin_default_theme(app, logged_in):
    _branding(logged_in, **{"brand-brand_theme": "dark"})
    anonymous = app.test_client()
    assert _html_theme(anonymous.get("/login")) == "dark"
    anonymous.post("/theme", data={"theme": "system"})         # explicit user choice wins
    assert _html_theme(anonymous.get("/login")) is None


def test_toggle_on_all_layouts(app, logged_in):
    assert b"data-theme-toggle" in logged_in.get("/").data
    anonymous = app.test_client()
    assert b"data-theme-toggle" in anonymous.get("/login").data
    assert b"data-theme-toggle" in anonymous.get("/q/" + "x" * 43 + "/").data
