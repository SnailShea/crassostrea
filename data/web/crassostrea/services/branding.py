"""Branding: company name, logo, favicon, accent color and default theme.

Uploaded images are identified by their content (magic bytes), never by the
file name or the browser supplied content type. SVG is accepted without
scripts or event handlers and is additionally served with a sandboxing CSP.
"""
import re

from flask import g

from ..extensions import db
from ..models import BrandAsset, get_setting, set_setting, utcnow

ASSET_LIMITS = {"logo": 512 * 1024, "favicon": 128 * 1024}
ASSET_TYPES = {
    "logo": {"image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"},
    "favicon": {"image/png", "image/x-icon", "image/svg+xml", "image/gif"},
}
THEMES = {"system": "Follow the system setting", "light": "Light", "dark": "Dark"}
HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
# Anything that could execute or load content inside an SVG
SVG_FORBIDDEN = re.compile(
    rb"<\s*(script|foreignobject|iframe|embed|object)\b|\bon[a-z]+\s*=|javascript:|<!entity"
    # href / xlink:href may only point to fragments inside the document
    rb"|\bhref\s*=\s*[\"']?(?![\"'#\s])",
    re.IGNORECASE)


class BrandingError(ValueError):
    pass


def detect_image_type(data):
    head = data[:16]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if head[:4] == b"\x00\x00\x01\x00":
        return "image/x-icon"
    text = data[:2048].lstrip().lower()
    if text.startswith(b"\xef\xbb\xbf"):
        text = text[3:].lstrip()
    if (text.startswith(b"<?xml") or text.startswith(b"<svg")) and b"<svg" in text:
        return "image/svg+xml"
    return None


def validate_asset(kind, data):
    if kind not in ASSET_LIMITS:
        raise BrandingError("Unknown asset")
    if not data:
        raise BrandingError("The file is empty")
    if len(data) > ASSET_LIMITS[kind]:
        raise BrandingError(f"The file is too large (max. {ASSET_LIMITS[kind] // 1024} KiB)")
    content_type = detect_image_type(data)
    if content_type not in ASSET_TYPES[kind]:
        allowed = ", ".join(sorted(t.split("/")[1].replace("x-icon", "ico").replace("svg+xml", "svg")
                                   for t in ASSET_TYPES[kind]))
        raise BrandingError(f"Unsupported image type, allowed: {allowed}")
    if content_type == "image/svg+xml" and SVG_FORBIDDEN.search(data):
        raise BrandingError("SVG files with scripts, event handlers or external references are not allowed")
    return content_type


def bump_version():
    set_setting("brand_version", get_setting("brand_version") + 1)


def save_asset(kind, data):
    content_type = validate_asset(kind, data)
    asset = db.session.get(BrandAsset, kind)
    if asset is None:
        asset = BrandAsset(name=kind)
        db.session.add(asset)
    asset.content_type = content_type
    asset.data = data
    asset.updated_at = utcnow()
    bump_version()


def delete_asset(kind):
    asset = db.session.get(BrandAsset, kind)
    if asset is not None:
        db.session.delete(asset)
        bump_version()


def get_branding():
    """Branding of the current request (cached in g)."""
    if "branding" not in g:
        assets = {name for (name,) in db.session.query(BrandAsset.name)}
        g.branding = {
            "name": get_setting("brand_name") or "Spam Filter",
            "accent": get_setting("brand_accent"),
            "footer": get_setting("brand_footer"),
            "theme": get_setting("brand_theme"),
            "version": get_setting("brand_version"),
            "has_logo": "logo" in assets,
            "has_favicon": "favicon" in assets,
        }
    return g.branding


# ---------------------------------------------------------------------------
# Accent color
# ---------------------------------------------------------------------------

def _rgb(hex_color):
    return tuple(int(hex_color[i:i + 2], 16) for i in (1, 3, 5))


def _hex(rgb):
    return "#" + "".join(f"{max(0, min(255, round(c))):02x}" for c in rgb)


def _mix(color, other, weight):
    """weight = share of ``other``"""
    a, b = _rgb(color), _rgb(other)
    return _hex(tuple(x + (y - x) * weight for x, y in zip(a, b)))


def _luminance(color):
    def channel(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g_, b = (channel(c) for c in _rgb(color))
    return 0.2126 * r + 0.7152 * g_ + 0.0722 * b


def text_on(color):
    """Black or white, whichever has the better contrast on ``color``."""
    lum = _luminance(color)
    return "#0f131a" if (lum + 0.05) / 0.05 > 1.05 / (lum + 0.05) else "#ffffff"


def accent_palette(accent):
    """CSS variables for light and dark mode derived from one accent color."""
    light = accent
    # Dark backgrounds need a lighter accent to stay readable
    dark = accent
    while _luminance(dark) < 0.25:
        dark = _mix(dark, "#ffffff", 0.15)
    return {
        "light": {"--accent": light, "--accent-text": text_on(light), "--accent-soft": _mix(light, "#ffffff", 0.88)},
        "dark": {"--accent": dark, "--accent-text": text_on(dark), "--accent-soft": _mix(dark, "#171c25", 0.78)},
    }


def theme_css(accent):
    if not accent or not HEX_RE.match(accent):
        return "/* default theme */\n"
    palette = accent_palette(accent.lower())

    def block(selector, values, indent=""):
        lines = "".join(f"{indent}  {k}: {v};\n" for k, v in values.items())
        return f"{indent}{selector} {{\n{lines}{indent}}}\n"
    return ("/* Generated from the branding settings */\n"
            + block(":root", palette["light"])
            + "@media (prefers-color-scheme: dark) {\n"
            + block(':root:not([data-theme="light"])', palette["dark"], "  ")
            + "}\n"
            + block(':root[data-theme="dark"]', palette["dark"]))
