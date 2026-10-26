"""The sidebar of the admin pages and the tabs of grouped pages (base.html).

A sidebar entry is a group of related pages; a group with more than one page
the user may see shows them as tabs above the page. A tab is active for the
endpoints in ``match``: names ending in "." are blueprint prefixes, others
exact endpoints (the POST endpoints of a page render it on errors).
"""
from collections import namedtuple

Tab = namedtuple("Tab", "label endpoint match full")
Group = namedtuple("Group", "label tabs")


def _tab(label, endpoint, *match, full=True):
    return Tab(label, endpoint, match or (endpoint,), full)


SECTIONS = [
    (None, [
        Group("Dashboard", [_tab("Dashboard", "dashboard.index", "dashboard.", full=False)]),
    ]),
    ("Mail", [
        Group("Quarantine", [_tab("Quarantine", "quarantine.index", "quarantine.", full=False)]),
        Group("Mail log", [_tab("Mail log", "maillog.index", "maillog.", full=False),
                           _tab("Mail queue", "queue.index", "queue."),
                           _tab("Journaling", "journal.index", "journal.")]),
        Group("DMARC & TLS reports", [_tab("DMARC & TLS reports", "reports.index", "reports.", full=False)]),
    ]),
    ("Filter", [
        Group("Domains", [_tab("Domains", "domains.index", "domains.", full=False),
                          _tab("Directories", "directories.index", "directories.")]),
        Group("Protection", [_tab("Impersonation", "impersonation.index", "impersonation."),
                             _tab("Link protection", "linkprotection.index", "linkprotection."),
                             _tab("Attachments", "attachments.index", "attachments."),
                             _tab("Content rules", "content_rules.index", "content_rules."),
                             _tab("Rate limits", "ratelimits.index", "ratelimits.")]),
        Group("Lists & training", [_tab("Allow list", "lists.allow", "lists.allow", "lists.index"),
                                   _tab("Block list", "lists.block"),
                                   _tab("Training", "training.index", "training.")]),
        Group("Outbound", [_tab("Outbound limits", "outbound.index", "outbound."),
                           _tab("Data loss prevention", "dlp.index", "dlp.")]),
    ]),
    ("System", [
        Group("Settings", [_tab("General", "settings.index", "settings.index", "settings.save",
                                "settings.send_digests"),
                           _tab("Branding", "settings.branding_page", "settings.branding_page",
                                "settings.save_branding"),
                           _tab("Relay networks", "settings.networks", "settings.networks", "settings.add_network",
                                "settings.delete_network"),
                           _tab("Alerts & export", "monitoring.settings_page", "monitoring.settings_page",
                                "monitoring.create_token", "monitoring.revoke_token", "monitoring.save_siem",
                                "monitoring.test_siem", "monitoring.save_alerts", "monitoring.test_alerts"),
                           _tab("Cluster", "cluster.manage", "cluster.manage", "cluster.maintenance",
                                "cluster.valkey_master", "cluster.remove", "cluster.remove_witness",
                                "cluster.join_information", "cluster.create", "cluster.join"),
                           _tab("Backups", "backups.index", "backups.")]),
        Group("Network", [_tab("Hostname & IP", "ipconfig.index", "ipconfig.", "settings.change_hostname"),
                          _tab("Certificates & TLS", "tls.index", "tls."),
                          _tab("DNS & ports", "network.index"),
                          _tab("Banned IPs", "logs.bans")]),
        Group("Monitoring", [_tab("Monitoring", "monitoring.index"),
                             _tab("Logs", "logs.index"),
                             _tab("Cluster", "cluster.index")]),
        Group("Users", [_tab("Administrators", "users.index", "users."),
                        _tab("Mailbox users", "mailboxes.index", "mailboxes.", full=False)]),
        Group("Access", [_tab("Audit log", "audit.index", "audit."),
                         _tab("API keys", "apikeys.index", "apikeys."),
                         _tab("API documentation", "apidocs.index", "apidocs.")]),
    ]),
]


def _matches(tab, endpoint):
    return any(endpoint.startswith(m) if m.endswith(".") else endpoint == m for m in tab.match)


def for_user(user, endpoint):
    """The sidebar for an administrator: [(section, [entry])], entry =
    {label, endpoint, active, tabs: [{label, endpoint, active}]}; and the
    tabs to show above the current page (none for a page of its own)."""
    full = user.is_full_admin
    sections, current = [], []
    for title, groups in SECTIONS:
        entries = []
        for group in groups:
            tabs = [{"label": t.label, "endpoint": t.endpoint, "active": _matches(t, endpoint or "")}
                    for t in group.tabs if full or not t.full]
            if not tabs:
                continue
            active = any(t["active"] for t in tabs)
            entries.append({"label": group.label, "endpoint": tabs[0]["endpoint"], "active": active, "tabs": tabs})
            if active and len(tabs) > 1:
                current = tabs
        if entries:
            sections.append((title, entries))
    return sections, current
