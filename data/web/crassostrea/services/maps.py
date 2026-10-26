"""Turns the database state into Rspamd/Postfix configuration.

* Global allow/block lists, protected domains and relay networks are written
  as map files into the directory shared with Rspamd (reloaded by Rspamd
  automatically within ``map_watch_interval``).
* DKIM keys are copied to redis, where rspamd's dkim_signing module reads them,
  and so are the API keys of the attachment hash lookups.
* Relay networks are also written as a Postfix CIDR table, and the message
  size limit as a file with the number of bytes; a systemd path unit
  (crassostrea-postfix-reload.path) applies them to Postfix when they change.
* The attachment size limit, policy and hash lookups, the outbound limits,
  the data loss prevention and content rules, the impersonation checks and
  link protection are maps read by data/conf/rspamd/lua/rspamd.local.lua.
* Per-domain thresholds and allow/block lists are served as an Rspamd
  settings map by the internal API (see ``render_rspamd_settings``).
"""
import ipaddress
import json
import os
import re
import tempfile

from flask import current_app

from ..extensions import db
from ..models import Domain, ListEntry, MailboxUser, RelayNetwork, get_setting
from ..validators import sender_pattern_to_regex
from . import (content_rules, dkim, dlp, filters, hashcheck, impersonation, links, outbound, ratelimits, reports,
               store, timezone, user_reports)
from .accounts import SCORE_FIELDS, domain_scores, effective_scores

HEADER = "# Managed by the Crassostrea web UI - manual changes will be overwritten\n"
MIB = 1024 * 1024

# Priorities of the generated rspamd settings rules. Higher wins and only the
# first matching rule is applied to a message. A domain block list set by an
# administrator cannot be overridden by a mailbox user; global lists are map
# scores (+-2050) and win over all of these.
PRIO_WATCHDOG = 10
PRIO_DOMAIN_BLOCK = 9
PRIO_USER_BLOCK = 8
PRIO_USER_ALLOW = 7
PRIO_DOMAIN_ALLOW = 6
PRIO_USER_SCORES = 5
PRIO_DOMAIN_SCORES = 4
PRIO_GLOBAL_SCORES = 1


def _write_if_changed(path, content):
    """Atomically replace ``path`` with ``content``. Returns True if changed."""
    try:
        with open(path, encoding="utf-8") as handle:
            if handle.read() == content:
                return False
    except FileNotFoundError:
        pass
    directory = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
    return True


def _lines(values):
    return HEADER + "".join(f"{v}\n" for v in values)


def _global_entries(list_type, kind):
    return (filters.global_list_entries()
            .filter_by(list_type=list_type, kind=kind)
            .order_by(ListEntry.value).all())


def build_rspamd_maps():
    """Return {filename: content} for all map files managed by the UI."""
    allow_senders = [sender_pattern_to_regex(e.value) for e in _global_entries("allow", "sender")]
    block_senders = [sender_pattern_to_regex(e.value) for e in _global_entries("block", "sender")]
    domains = [d.name for d in Domain.query.filter_by(active=True).order_by(Domain.name)]
    networks = [n.cidr for n in RelayNetwork.query.order_by(RelayNetwork.cidr)]
    return {
        "global_smtp_from_whitelist.map": _lines(allow_senders),
        "global_mime_from_whitelist.map": _lines(allow_senders),
        "global_smtp_from_blacklist.map": _lines(block_senders),
        "global_mime_from_blacklist.map": _lines(block_senders),
        "ip_wl.map": _lines(e.value for e in _global_entries("allow", "ip")),
        "ip_bl.map": _lines(e.value for e in _global_entries("block", "ip")),
        "protected_domains.map": _lines(domains),
        "relay_networks.map": _lines(networks),
        # key-value map, 0: no limit
        "size_limits.map": HEADER + f"max_attachment_size {get_setting('max_attachment_size_mb') * MIB}\n",
        # key-value map, 0: the ClamAV check is skipped (rspamd.local.lua)
        "scanning.map": HEADER + f"virus_scanning {int(bool(get_setting('virus_scanning')))}\n",
        "outbound_limits.map": _lines(outbound.build_map()),
        "inbound_limits.map": ratelimits.build_rspamd_map(),
        "rate_limit_exempt.map": ratelimits.build_exempt_map(),
        "dlp_rules.json": dlp.build_json(),
        "attachment_policy.json": build_attachment_policy(),
        "impersonation.json": impersonation.build_json(),
        "link_protection.json": links.build_json(),
        "attachment_analysis.json": hashcheck.build_json(),
        "content_rules.json": content_rules.build_json(),
        "intake.json": build_intake(),
    }


def build_intake():
    """intake.json: the addresses of the gateway whose mail rspamd hands to the
    web UI instead of filtering it (DMARC/TLS reports, user reports)."""
    addresses = {reports.address(): "reports"}
    if get_setting("user_reports_enabled"):
        addresses.update({address: kind for kind, address in user_reports.addresses().items()})
    return json.dumps({"addresses": addresses}, indent=1) + "\n"


def build_attachment_policy():
    """attachment_policy.json for rspamd.local.lua (Attachments page)."""
    return json.dumps({
        "extensions": get_setting("attachment_blocked_extensions").split(),
        "archives": bool(get_setting("attachment_scan_archives")),
        "encrypted": bool(get_setting("attachment_block_encrypted")),
        "outbound": bool(get_setting("attachment_outbound")),
        "exempt": get_setting("attachment_exempt_senders").split(),
    }, indent=1) + "\n"


def build_postfix_message_size_limit():
    """message_size_limit in bytes, applied by system/libexec/postfix-apply."""
    return f"{get_setting('max_message_size_mb') * MIB}\n"


def build_postfix_ptr_check():
    """ptr_check for system/libexec/postfix-apply: off, defer or reject."""
    return f"{get_setting('ptr_check')}\n"


def build_postfix_client_exempt():
    """client_exempt.cidr: the global allow list's IP addresses skip the PTR
    check (main.cf smtpd_client_restrictions)."""
    networks = []
    for entry in _global_entries("allow", "ip"):
        try:
            networks.append(str(ipaddress.ip_network(entry.value, strict=False)))
        except ValueError:
            continue
    return HEADER + "".join(f"{network}\tOK\n" for network in networks)


def build_postfix_relay_networks():
    networks = RelayNetwork.query.order_by(RelayNetwork.cidr).all()
    return HEADER + "".join(f"{n.cidr}\tOK\n" for n in networks)


def sync_all():
    """Write all map files. Errors are logged, not raised: the database is
    the source of truth and the next sync (timer or change) retries."""
    app = current_app
    ok = True
    map_dir = app.config["RSPAMD_MAP_DIR"]
    try:
        for name, content in build_rspamd_maps().items():
            if _write_if_changed(os.path.join(map_dir, name), content):
                app.logger.info("updated rspamd map %s", name)
    except OSError as exc:
        ok = False
        app.logger.error("cannot write rspamd maps to %s: %s", map_dir, exc)

    try:
        dkim.sync_redis(store.get_redis())
    except Exception as exc:  # redis errors must not block the other maps
        ok = False
        app.logger.error("cannot update DKIM keys in redis: %s", exc)
    try:
        hashcheck.sync_redis(store.get_redis())
    except Exception as exc:
        ok = False
        app.logger.error("cannot update the hash lookup keys in redis: %s", exc)

    postfix_dir = app.config["POSTFIX_DYNAMIC_DIR"]
    try:
        if _write_if_changed(os.path.join(postfix_dir, "relay_networks.cidr"), build_postfix_relay_networks()):
            app.logger.info("updated postfix relay networks")
        if _write_if_changed(os.path.join(postfix_dir, "message_size_limit"), build_postfix_message_size_limit()):
            app.logger.info("updated postfix message size limit")
        if _write_if_changed(os.path.join(postfix_dir, "rate_limit_exempt.cidr"), ratelimits.build_postfix_exempt()):
            app.logger.info("updated postfix rate limit exceptions")
        if _write_if_changed(os.path.join(postfix_dir, "rate_limits"), ratelimits.build_postfix_limits()):
            app.logger.info("updated postfix rate limits")
        if _write_if_changed(os.path.join(postfix_dir, "client_exempt.cidr"), build_postfix_client_exempt()):
            app.logger.info("updated postfix client exceptions")
        if _write_if_changed(os.path.join(postfix_dir, "ptr_check"), build_postfix_ptr_check()):
            app.logger.info("updated postfix PTR check")
    except OSError as exc:
        ok = False
        app.logger.error("cannot write postfix maps to %s: %s", postfix_dir, exc)
    timezone.sync()
    return ok


# ---------------------------------------------------------------------------
# Rspamd settings map
# ---------------------------------------------------------------------------

def _q(value):
    """Quote a string for UCL (JSON string syntax is valid UCL)."""
    return json.dumps(value)


def _domain_rcpt(domain):
    return "/@" + domain.replace(".", "\\.").replace("-", "\\-") + "$/i"


# Addresses are validated on input; the selector argument is double quoted and
# rspamd does not decode escapes, so quotes and backslashes must never occur.
_OWNER_ARG_RE = re.compile(r'^[^"\\\s()]+@[^"\\\s()]+$')


def _owner_selector(email):
    """Selector that matches only if *every* envelope recipient is ``email`` or
    one of its sub-addresses (extractor in data/conf/rspamd/lua/rspamd.local.lua).

    A ``rcpt`` condition would match if any recipient matches, and the
    settings apply to the whole message: one user's allow list or thresholds
    would then decide for all other recipients of the same message. If rspamd
    cannot parse the selector, the rule has no condition left and never
    matches, so a broken extractor does not fall back to the ``rcpt`` behaviour.
    """
    if not _OWNER_ARG_RE.match(email):
        return None
    return f'sf_rcpts_owned_by("{email}")'


def _actions_block(reject, add_header, greylist, indent="      "):
    return (f"{indent}actions {{\n"
            f"{indent}  reject = {reject:g};\n"
            f"{indent}  \"add header\" = {add_header:g};\n"
            f"{indent}  greylist = {greylist:g};\n"
            f"{indent}}}\n")


LIST_RULES = {
    # scope, list type -> (symbol, score, priority)
    ("domain", "allow"): ("DOMAIN_ALLOWLIST", -999.0, PRIO_DOMAIN_ALLOW),
    ("domain", "block"): ("DOMAIN_BLOCKLIST", 999.0, PRIO_DOMAIN_BLOCK),
    # user entries reuse the domain symbols, so composites and the
    # quarantine selector treat them the same way
    ("user", "allow"): ("DOMAIN_ALLOWLIST", -999.0, PRIO_USER_ALLOW),
    ("user", "block"): ("DOMAIN_BLOCKLIST", 999.0, PRIO_USER_BLOCK),
}


def _list_rules(name, match, scope, list_type, entries):
    """Rules for one domain/user and list type: envelope sender, header sender, IP.

    ``match`` is the recipient condition as (key, value), e.g. ("rcpt", regexp).
    """
    symbol, score, priority = LIST_RULES[(scope, list_type)]
    senders = [sender_pattern_to_regex(e.value) for e in entries if e.kind == "sender"]
    ips = [e.value for e in entries if e.kind == "ip"]
    rules = []
    for suffix, key, values in (("from", "from", senders), ("mime", "from_mime", senders), ("ip", "ip", ips)):
        if not values:
            continue
        body = [f"  {name}_{suffix} {{\n",
                f"    priority = {priority};\n",
                f"    {match[0]} = {_q(match[1])};\n"]
        body += [f"    {key} = {_q(v)};\n" for v in values]
        body += ["    apply \"default\" {\n",
                 f"      {symbol} = {score:g};\n",
                 "    }\n",
                 f"    symbols [\n      {_q(symbol)}\n    ]\n",
                 "  }\n"]
        rules.append("".join(body))
    return rules


def _scores_rule(name, priority, match, scores):
    return (f"  {name} {{\n"
            f"    priority = {priority};\n"
            f"    {match[0]} = {_q(match[1])};\n"
            "    apply \"default\" {\n"
            + _actions_block(scores["reject_score"], scores["add_header_score"], scores["greylist_score"])
            + "    }\n  }\n")


def render_rspamd_settings():
    reject = get_setting("reject_score")
    add_header = get_setting("add_header_score")
    greylist = get_setting("greylist_score")

    out = ["# Generated by the Crassostrea web UI\n", "settings {\n"]
    # Used by watchdog-crassostrea to check that rspamd loaded this map
    out.append(
        "  watchdog {\n"
        f"    priority = {PRIO_WATCHDOG};\n"
        "    rcpt_mime = \"/null@localhost/i\";\n"
        "    from_mime = \"/watchdog@localhost/i\";\n"
        "    apply \"default\" {\n"
        "      symbols_disabled = [\"HISTORY_SAVE\", \"ARC\", \"ARC_SIGNED\", \"DKIM\", \"DKIM_SIGNED\", \"CLAM_VIRUS\"];\n"
        "      want_spam = yes;\n"
        "      actions {\n"
        "        reject = 9999.0;\n"
        "        greylist = 9998.0;\n"
        "        \"add header\" = 9997.0;\n"
        "      }\n"
        "    }\n"
        "  }\n")

    domains = (Domain.query.filter_by(active=True)
               .options(db.selectinload(Domain.list_entries))
               .order_by(Domain.name).all())
    for domain in domains:
        # A blocked sender stays blocked when another domain is also addressed;
        # allow lists and thresholds only apply if every recipient is in this
        # domain (see sf_rcpts_in_domain in rspamd.local.lua)
        matches = {"block": ("rcpt", _domain_rcpt(domain.name)),
                   "allow": ("selector", f'sf_rcpts_in_domain("{domain.name}")')}
        for list_type in ("allow", "block"):
            entries = [e for e in domain.list_entries if e.list_type == list_type]
            out.extend(_list_rules(f"{list_type}_{domain.id}", matches[list_type], "domain", list_type, entries))
        if domain.has_custom_scores:
            out.append(_scores_rule(f"scores_{domain.id}", PRIO_DOMAIN_SCORES, matches["allow"],
                                    domain_scores(domain)))

    users = (MailboxUser.query.join(Domain)
             .filter(MailboxUser.active.is_(True), Domain.active.is_(True))
             .options(db.selectinload(MailboxUser.list_entries), db.joinedload(MailboxUser.domain))
             .order_by(MailboxUser.email).all())
    for user in users:
        selector = _owner_selector(user.email)
        if selector is None:
            current_app.logger.error("no rspamd rules for mailbox user %s: unexpected characters", user.id)
            continue
        match = ("selector", selector)
        for list_type in ("allow", "block"):
            entries = [e for e in user.list_entries if e.list_type == list_type]
            out.extend(_list_rules(f"user_{list_type}_{user.id}", match, "user", list_type, entries))
        if user.has_custom_scores:
            overrides = {f: getattr(user, f) for f in SCORE_FIELDS}
            out.append(_scores_rule(f"user_scores_{user.id}", PRIO_USER_SCORES, match,
                                    effective_scores(user.domain, overrides)))

    out.append(
        "  global_scores {\n"
        f"    priority = {PRIO_GLOBAL_SCORES};\n"
        "    rcpt = \"/.*/\";\n"
        "    apply \"default\" {\n"
        + _actions_block(reject, add_header, greylist)
        + "    }\n  }\n")
    out.append("}\n")
    return "".join(out)
