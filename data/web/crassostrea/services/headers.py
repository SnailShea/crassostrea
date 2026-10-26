"""Header manipulation that leaves existing DKIM signatures intact.

New headers are prepended: DKIM only covers the headers listed in a
signature's h= tag, so an added header does not invalidate it. The rest of the
message is passed through byte for byte.
"""
import re

RELEASE_HEADER = "X-Quarantine-Released"
REQUEUE_HEADER = "X-Mail-Log-Requeued"


def _split(raw):
    """(header block, separator, body) keeping the original bytes."""
    match = re.search(rb"\r?\n\r?\n", raw)
    if match is None:
        return raw, b"", b""
    return raw[:match.start()], raw[match.start():match.end()], raw[match.end():]


def _line_ending(raw):
    index = raw.find(b"\n")
    return b"\r\n" if index > 0 and raw[index - 1:index] == b"\r" else b"\n"


def remove_header(raw, name):
    """Remove every instance (including folded continuation lines) of a header."""
    head, separator, body = _split(raw)
    field = re.compile(re.escape(name.encode()) + rb"[ \t]*:", re.IGNORECASE)
    if not re.search(rb"^" + field.pattern, head, re.IGNORECASE | re.MULTILINE):
        return raw  # nothing to do, keep the message byte for byte
    eol = _line_ending(raw)
    kept, skipping = [], False
    for line in re.split(rb"\r?\n", head):
        if line[:1] in (b" ", b"\t"):
            if not skipping:
                kept.append(line)
            continue
        skipping = field.match(line) is not None
        if not skipping:
            kept.append(line)
    return eol.join(kept) + separator + body


def prepend_header(raw, name, value):
    value = re.sub(r"[\r\n]+", " ", value).strip()
    return f"{name}: {value}".encode() + _line_ending(raw) + raw
