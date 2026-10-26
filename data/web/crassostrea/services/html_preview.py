"""HTML view of stored messages (quarantine, mail log): the message's HTML
body, rendered from its own URL in a sandboxed frame.

nh3 removes scripts, event handlers, forms, frames, links and every URL but
inlined images; images referenced by Content-ID are inlined as data: URIs.
The page's response also forbids scripts and remote loads (CSP), so CSS that
refers to a remote image, or anything the sanitizer missed, cannot load or
run anything either.
"""
import base64
import email
import email.policy
import re

import nh3

# Raster images only: SVG can carry scripts
RASTER_IMAGES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
MAX_HTML = 2 * 1024 * 1024
MAX_INLINE_IMAGES = 10 * 1024 * 1024

CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; sandbox; frame-ancestors 'self'"

_DATA_IMAGE = re.compile(r"^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=\s]+$")
_CID_SRC = re.compile(r"""(\bsrc\s*=\s*["']?)cid:([^"'\s>]+)""", re.IGNORECASE)
_TAGS = nh3.ALLOWED_TAGS | {"style", "font", "center", "tfoot"}
_ATTRIBUTES = {tag: set(attrs) - {"href", "hreflang"} for tag, attrs in nh3.ALLOWED_ATTRIBUTES.items()}
_ATTRIBUTES["*"] = {"style", "class", "id", "align", "valign", "bgcolor", "color", "width", "height", "border",
                    "cellpadding", "cellspacing", "dir", "lang", "title", "face", "size"}
_PAGE = ('<!doctype html><html><head><meta charset="utf-8"><style>body{margin:12px;background:#fff;color:#000;'
         'font-family:sans-serif}.truncated{color:#666;font-style:italic}</style></head><body>%s</body></html>')
_TRUNCATED = '<p class="truncated">Only the first 2 MiB of the HTML are shown. Download the message for all of it.</p>'


def _body(message):
    """The HTML body of a message (in multipart/alternative and related), or None."""
    part = message.get_body(preferencelist=("html",))
    return part if part is not None and part.get_content_type() == "text/html" else None


def has_html(raw):
    return _body(email.message_from_bytes(raw, policy=email.policy.default)) is not None


def _inline_images(message):
    """Content-ID -> data: URI of the message's raster images (up to a total size)."""
    images, budget = {}, MAX_INLINE_IMAGES
    for part in message.walk():
        content_id = str(part.get("Content-ID") or "").strip("<> ")
        if not content_id or part.get_content_type() not in RASTER_IMAGES:
            continue
        payload = part.get_payload(decode=True) or b""
        if len(payload) > budget:
            continue
        budget -= len(payload)
        images[content_id] = f"data:{part.get_content_type()};base64,{base64.b64encode(payload).decode()}"
    return images


def _attribute_filter(element, attribute, value):
    if attribute == "src":
        return value if element == "img" and _DATA_IMAGE.match(value) else None
    return value


def sanitize(html):
    return nh3.clean(html, tags=_TAGS, clean_content_tags={"script"}, attributes=_ATTRIBUTES,
                     attribute_filter=_attribute_filter, url_schemes={"data"}, link_rel=None, strip_comments=True)


def render(raw):
    """The message's HTML body as a sanitized page, or None without one."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    part = _body(message)
    if part is None:
        return None
    try:
        html = part.get_content()
    except (LookupError, ValueError, AssertionError):
        html = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
    images = _inline_images(message)
    # unknown Content-IDs become a URL the sanitizer drops
    body = _CID_SRC.sub(lambda m: m.group(1) + images.get(m.group(2), "missing:"), html[:MAX_HTML])
    return _PAGE % (sanitize(body) + (_TRUNCATED if len(html) > MAX_HTML else ""))
