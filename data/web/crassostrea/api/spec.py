"""OpenAPI 3.0 description of the REST API (rendered by Swagger UI at /api/docs).

tests/test_api.py checks that every route of the API blueprint is documented.
"""
from ..models import (CONTENT_ACTIONS, CONTENT_DIRECTIONS, CONTENT_FIELDS, CONTENT_MATCHES, DIGEST_INTERVALS,
                      DIRECTORY_KINDS, DLP_ACTIONS, DLP_DETECTORS, LIMIT_PERIODS, LIST_KINDS, LIST_TYPES,
                      MAX_MAILLOG_DAYS, MAX_MESSAGE_MB, MAX_OUTBOUND_LIMIT, RECIPIENT_CHECKS)
from ..services.accounts import MIN_PASSWORD_LENGTH
from ..services.maillog import ACTIONS as MAILLOG_ACTIONS


def _ref(name):
    return {"$ref": f"#/components/schemas/{name}"}


def _json(schema):
    return {"content": {"application/json": {"schema": schema}}}


def _response(description, schema=None):
    response = {"description": description}
    if schema is not None:
        response.update(_json(schema))
    return response


ERRORS = {
    "400": _response("Malformed request", _ref("Error")),
    "401": _response("Missing or invalid API key", _ref("Error")),
    "403": _response("Read-only key or source address not allowed", _ref("Error")),
    "429": _response("Too many failed authentication attempts", _ref("Error")),
}
NOT_FOUND = {"404": _response("Not found", _ref("Error"))}
INVALID = {"422": _response("Validation failed", _ref("Error"))}
CONFLICT = {"409": _response("Conflict (duplicate, last active administrator, ...)", _ref("Error"))}
TLS_CONFLICT = {"409": _response("Another change is running, a cluster member, or no passed staging test",
                                 _ref("Error"))}
BACKUP_BUSY = {"409": _response("A backup is being made or deleted", _ref("Error")),
               "503": _response("The backup service is not installed", _ref("Error"))}
DIRECTORY_FAILED = {"502": _response("The directory could not be read, or the result was refused", _ref("Error"))}
UNAVAILABLE = {"503": _response("A service of the gateway (Postfix, Rspamd, Valkey) failed", _ref("Error"))}
DELETED = {"204": _response("Deleted")}


def _id_param(name, description):
    return {"name": name, "in": "path", "required": True, "description": description,
            "schema": {"type": "integer"}}


def _query(name, description, schema=None):
    return {"name": name, "in": "query", "description": description, "schema": schema or {"type": "string"}}


PAGE_PARAMS = [
    {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 1}},
    {"name": "per_page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50}},
]

SCORE = {"type": "number", "nullable": True,
         "description": "Personal threshold, null = use the domain/global value"}
DOMAIN_SCORE = {"type": "number", "nullable": True, "minimum": -100, "maximum": 10000,
                "description": "Domain threshold, null = use the global value"}
GLOBAL_SCORE = {"type": "number", "minimum": -100, "maximum": 10000}
DIGEST = {"type": "string", "nullable": True, "enum": list(DIGEST_INTERVALS) + [None],
          "description": "Quarantine digest interval, null = use the domain/global value"}
PASSWORD = {"type": "string", "format": "password", "minLength": MIN_PASSWORD_LENGTH, "writeOnly": True}
DELIVERY_STATE = {"type": "string", "nullable": True, "enum": ["delivered", "deferred", "bounced", None],
                  "description": "What Postfix did with it: delivered to every recipient, still deferred for "
                                 "one, or bounced (refused by a recipient's server, or expired); null before the "
                                 "first attempt and for rejected mail"}
SENDER_SCOPE_SCHEMA = {"type": "string", "enum": ["mailbox", "domain", "global"],
                       "description": "Also add the envelope sender to an allow list: the recipient's own "
                                      "(needs a mailbox user), its domain's, or the global one"}
PASSWORD_HASH = {"type": "string", "writeOnly": True, "example": "{SHA512-CRYPT}$6$5Yd1...",
                 "description": "The password hash of a previous mail system, for imports: Werkzeug "
                                "scrypt/pbkdf2, crypt(3) ($6$, $5$, $1$, bcrypt $2y$/$2b$, yescrypt $y$, $7$), "
                                "Argon2, {SSHA512}, {SSHA256}, {SSHA}, {SMD5}, {SHA512}, {SHA256}, {SHA}, "
                                "{PLAIN-MD5}, PBKDF2 (Django, Dovecot), {PLAIN}; with or without Dovecot/LDAP "
                                "scheme prefixes. Replaced with scrypt at the user's first login."}
TIMESTAMP = {"type": "string", "format": "date-time", "readOnly": True}
ID = {"type": "integer", "readOnly": True}
PERIOD = {"type": "string", "enum": list(LIMIT_PERIODS)}
DIRECTORY = {
    "name": {"type": "string", "maxLength": 64}, "kind": {"type": "string", "enum": list(DIRECTORY_KINDS)},
    "ldap_urls": {"type": "string", "example": "ldaps://dc1.example.com ldaps://dc2.example.com",
                  "description": "LDAP: one or more URLs separated by spaces (failover)"},
    "ldap_starttls": {"type": "boolean", "description": "LDAP: STARTTLS on ldap:// URLs"},
    "ldap_verify": {"type": "boolean", "default": True, "description": "LDAP: check the server certificate"},
    "bind_dn": {"type": "string", "description": "LDAP: empty for an anonymous bind"},
    "bind_password": {"type": "string", "writeOnly": True},
    "base_dn": {"type": "string", "example": "DC=example,DC=com"},
    "ldap_filter": {"type": "string", "example": "(|(mail=*)(proxyAddresses=*))"},
    "ldap_attributes": {"type": "string", "example": "mail proxyAddresses",
                        "description": "Attributes with addresses; of proxyAddresses only smtp: entries"},
    "tenant_id": {"type": "string", "description": "Microsoft 365: tenant ID or domain"},
    "client_id": {"type": "string", "description": "Microsoft 365: application (client) ID"},
    "client_secret": {"type": "string", "writeOnly": True,
                      "description": "Microsoft 365: needs User.Read.All and Group.Read.All (application)"}}
CONTENT_RULE = {
    "name": {"type": "string", "maxLength": 64, "description": "Without quotes or commas"},
    "active": {"type": "boolean", "default": True},
    "field": {"type": "string", "enum": list(CONTENT_FIELDS)},
    "header": {"type": "string", "description": "The header name, with field header"},
    "match": {"type": "string", "enum": list(CONTENT_MATCHES), "default": "contains",
              "description": "contains and equals ignore ASCII case; regex is PCRE"},
    "value": {"type": "string", "maxLength": 1000},
    "action": {"type": "string", "enum": list(CONTENT_ACTIONS), "default": "score",
               "description": "score: add score; reject; tag: deliver with X-Content-Rule"},
    "score": {"type": "number", "minimum": -1000, "maximum": 1000},
    "message": {"type": "string", "maxLength": 255, "description": "The rejection message"},
    "direction": {"type": "string", "enum": list(CONTENT_DIRECTIONS), "default": "inbound"},
    "comment": {"type": "string", "maxLength": 255}}
ADMIN_ACCESS = {
    "role": {"type": "string", "enum": ["admin", "domain"], "default": "admin",
             "description": "admin: everything; domain: the mail of its domains only"},
    "domains": {"type": "array", "items": {"type": "string"}, "description": "The domains of a domain administrator"}}
PERSON = {
    "name": {"type": "string", "maxLength": 128, "example": "Jane Doe"},
    "addresses": {"type": "array", "items": {"type": "string", "format": "email"},
                  "description": "Outside addresses they really write from (not flagged)"}}
DLP_RULE = {
    "name": {"type": "string", "maxLength": 64, "description": "Without quotes or commas"},
    "detector": {"type": "string", "enum": list(DLP_DETECTORS)},
    "pattern": {"type": "string", "description": "keywords: one per line; regex: a PCRE expression"},
    "min_matches": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 1,
                    "description": "Different values needed"},
    "sender": {"type": "string", "description": "An address or a domain; empty: every sender"},
    "action": {"type": "string", "enum": list(DLP_ACTIONS), "default": "quarantine",
               "description": "quarantine: reject and keep in the outbound quarantine; header: deliver with "
                              "X-DLP-Match"},
    "active": {"type": "boolean", "default": True}, "comment": {"type": "string", "maxLength": 255}}
OUTBOUND_LIMIT = {
    "sender": {"type": "string", "example": "newsletter@example.com",
               "description": "An address, or a domain for each of its senders on its own"},
    "max_recipients": {"type": "integer", "minimum": 0, "maximum": MAX_OUTBOUND_LIMIT,
                       "description": "Recipients per period; 0: no limit for this sender"},
    "period": {**PERIOD, "default": "hour"}, "comment": {"type": "string", "maxLength": 255}}
TLS_MIN = {"type": "string", "enum": ["1.2", "1.1", "1.0"], "description": "Oldest TLS version accepted"}


def _page_of(item):
    return {"type": "object", "properties": {
        "items": {"type": "array", "items": _ref(item)},
        "total": {"type": "integer"}, "page": {"type": "integer"}, "per_page": {"type": "integer"},
    }}


def _op(tag, summary, operation_id, responses, body=None, params=None, description=None):
    operation = {"tags": [tag], "summary": summary, "operationId": operation_id,
                 "responses": {**responses, **ERRORS}}
    if description:
        operation["description"] = description
    if params:
        operation["parameters"] = params
    if body is not None:
        operation["requestBody"] = {"required": True, **_json(body)}
    return operation


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _account_paths():
    admin_id = _id_param("admin_id", "Administrator ID")
    user_id = _id_param("user_id", "Mailbox user ID")
    return {
        "/admins": {
            "get": _op("Administrators", "List administrators", "listAdmins",
                       {"200": _response("Administrators", _page_of("Admin"))},
                       params=PAGE_PARAMS + [_query("q", "Substring of the username")]),
            "post": _op("Administrators", "Create an administrator", "createAdmin",
                        {"201": _response("Created", _ref("Admin")), **CONFLICT, **INVALID},
                        body=_ref("AdminCreate")),
        },
        "/admins/{admin_id}": {
            "parameters": [admin_id],
            "get": _op("Administrators", "Get an administrator", "getAdmin",
                       {"200": _response("Administrator", _ref("Admin")), **NOT_FOUND}),
            "patch": _op("Administrators", "Update an administrator", "updateAdmin",
                         {"200": _response("Updated", _ref("Admin")), **NOT_FOUND, **CONFLICT, **INVALID},
                         body=_ref("AdminUpdate"),
                         description="Disabling the last active administrator is refused."),
            "delete": _op("Administrators", "Delete an administrator", "deleteAdmin",
                          {**DELETED, **NOT_FOUND, **CONFLICT},
                          description="Deleting the last active administrator is refused."),
        },
        "/admins/{admin_id}/reset-2fa": {
            "parameters": [admin_id],
            "post": _op("Administrators", "Turn off an administrator's two-factor login", "resetAdminTwoFactor",
                        {"200": _response("Updated", _ref("Admin")), **NOT_FOUND},
                        description="For an administrator who lost their phone and recovery codes; they set it "
                                    "up again at their next login when Settings require it."),
        },
        "/mailbox-users": {
            "get": _op("Mailbox users", "List mailbox users", "listMailboxUsers",
                       {"200": _response("Mailbox users", _page_of("MailboxUser"))},
                       params=PAGE_PARAMS + [_query("domain", "Exact domain"),
                                             _query("q", "Substring of the address")]),
            "post": _op("Mailbox users", "Create a mailbox user", "createMailboxUser",
                        {"201": _response("Created", _ref("MailboxUser")), **CONFLICT, **INVALID},
                        body=_ref("MailboxUserCreate"),
                        description="The domain of the address must be configured on the gateway."),
        },
        "/mailbox-users/{user_id}": {
            "parameters": [user_id],
            "get": _op("Mailbox users", "Get a mailbox user", "getMailboxUser",
                       {"200": _response("Mailbox user", _ref("MailboxUser")), **NOT_FOUND}),
            "patch": _op("Mailbox users", "Update a mailbox user", "updateMailboxUser",
                         {"200": _response("Updated", _ref("MailboxUser")), **NOT_FOUND, **INVALID},
                         body=_ref("MailboxUserUpdate"),
                         description="Only the given fields are changed. Set a threshold or the digest interval "
                                     "to null to fall back to the domain/global value."),
            "delete": _op("Mailbox users", "Delete a mailbox user", "deleteMailboxUser",
                          {**DELETED, **NOT_FOUND}, description="Quarantined mail of the address is kept."),
        },
        "/mailbox-users/{user_id}/password-link": {
            "parameters": [user_id],
            "post": _op("Mailbox users", "Mail a link to set the password", "sendMailboxUserPasswordLink",
                        {"200": _response("Sent", {"type": "object", "properties": {
                            "sent_to": {"type": "string", "format": "email"},
                            "valid_days": {"type": "integer"}}}),
                         **NOT_FOUND, "409": _response("The account is disabled", _ref("Error")),
                         "502": _response("Postfix did not accept the mail", _ref("Error"))},
                        description="The link works once, for mailbox_invite_days days; earlier links stop "
                                    "working."),
        },
        "/mailbox-users/{user_id}/list-entries": {
            "parameters": [user_id],
            "get": _op("Mailbox users", "Personal allow/block list", "listMailboxUserEntries",
                       {"200": _response("Entries", {"type": "object", "properties": {
                           "items": {"type": "array", "items": _ref("ListEntry")}, "total": {"type": "integer"}}}),
                        **NOT_FOUND}),
            "post": _op("Mailbox users", "Add an allow/block list entry", "createMailboxUserEntry",
                        {"201": _response("Created", _ref("ListEntry")), **NOT_FOUND, **CONFLICT, **INVALID},
                        body=_ref("ListEntryCreate")),
        },
        "/mailbox-users/{user_id}/list-entries/{entry_id}": {
            "parameters": [user_id, _id_param("entry_id", "List entry ID")],
            "delete": _op("Mailbox users", "Remove an allow/block list entry", "deleteMailboxUserEntry",
                          {**DELETED, **NOT_FOUND}),
        },
    }


def _configuration_paths():
    domain_id = _id_param("domain_id", "Domain ID")
    directory_id = _id_param("directory_id", "Directory ID")
    entry_id = _id_param("entry_id", "List entry ID")
    entry_filters = [_query("list_type", "allow or block", {"type": "string", "enum": list(LIST_TYPES)}),
                     _query("kind", "sender or ip", {"type": "string", "enum": list(LIST_KINDS)})]
    return {
        "/domains": {
            "get": _op("Domains", "List domains", "listDomains",
                       {"200": _response("Domains", _page_of("Domain"))},
                       params=PAGE_PARAMS + [_query("name", "Exact domain name"),
                                             _query("q", "Substring of the name"),
                                             _query("active", "Only active or inactive domains",
                                                    {"type": "boolean"})]),
            "post": _op("Domains", "Add a domain", "createDomain",
                        {"201": _response("Created", _ref("Domain")), **CONFLICT, **INVALID},
                        body=_ref("DomainCreate"),
                        description="Mail for the domain is accepted as soon as it is active; point its MX "
                                    "records to the gateway."),
        },
        "/domains/{domain_id}": {
            "parameters": [domain_id],
            "get": _op("Domains", "Get a domain", "getDomain",
                       {"200": _response("Domain", _ref("Domain")), **NOT_FOUND}),
            "patch": _op("Domains", "Update a domain", "updateDomain",
                         {"200": _response("Updated", _ref("Domain")), **NOT_FOUND, **INVALID},
                         body=_ref("DomainUpdate"),
                         description="Only the given fields are changed; the name cannot be changed. Set a "
                                     "threshold or the digest interval to null for the global value."),
            "delete": _op("Domains", "Delete a domain", "deleteDomain", {**DELETED, **NOT_FOUND},
                          description="Its recipients, list entries, mailbox users and DKIM key are deleted "
                                      "too. Mail for the domain is no longer accepted."),
        },
        "/domains/{domain_id}/test-destination": {
            "parameters": [domain_id],
            "post": {**_op("Domains", "Test the destination server", "testDomainDestination",
                           {"200": _response("One result per destination host", {"type": "object", "properties": {
                               "results": {"type": "array", "items": _ref("DestinationTest")}}}),
                            **NOT_FOUND, **INVALID},
                           description="Talks SMTP to the destination (its MX hosts with use_mx) without sending "
                                       "anything: connect, EHLO, STARTTLS, MAIL FROM:<>, RCPT TO for the given "
                                       "address and for a made-up one (accepts_any: the server accepts any "
                                       "address)."),
                     "requestBody": {"required": False, **_json({"type": "object", "additionalProperties": False,
                                                                  "properties": {"address": {
                                                                      "type": "string", "format": "email"}}})}},
        },
        "/domains/{domain_id}/recipients": {
            "parameters": [domain_id],
            "get": _op("Domains", "List the recipients of a domain", "listRecipients",
                       {"200": _response("Recipients", _page_of("Recipient")), **NOT_FOUND},
                       params=PAGE_PARAMS + [_query("q", "Substring of the address")],
                       description="Only used when recipient_check is \"list\"."),
            "post": _op("Domains", "Add recipients", "addRecipients",
                        {"200": _response("Result", _ref("RecipientsResult")), **NOT_FOUND, **INVALID},
                        body=_ref("RecipientsAdd")),
        },
        "/domains/{domain_id}/recipients/{recipient_id}": {
            "parameters": [domain_id, _id_param("recipient_id", "Recipient ID")],
            "delete": _op("Domains", "Remove a recipient", "deleteRecipient", {**DELETED, **NOT_FOUND}),
        },
        "/domains/{domain_id}/list-entries": {
            "parameters": [domain_id],
            "get": _op("Allow & block lists", "Allow/block list of a domain", "listDomainEntries",
                       {"200": _response("Entries", _page_of("FilterListEntry")), **NOT_FOUND},
                       params=PAGE_PARAMS + entry_filters,
                       description="Allow entries apply when every recipient is in the domain, block entries "
                                   "as soon as one recipient is."),
            "post": _op("Allow & block lists", "Add a domain list entry", "createDomainEntry",
                        {"201": _response("Created", _ref("FilterListEntry")), **NOT_FOUND, **CONFLICT,
                         **INVALID},
                        body=_ref("FilterListEntryCreate")),
        },
        "/domains/{domain_id}/list-entries/{entry_id}": {
            "parameters": [domain_id, entry_id],
            "delete": _op("Allow & block lists", "Remove a domain list entry", "deleteDomainEntry",
                          {**DELETED, **NOT_FOUND}),
        },
        "/domains/{domain_id}/dkim": {
            "parameters": [domain_id],
            "get": _op("Domains", "DKIM key of a domain", "getDkim",
                       {"200": _response("Key and DNS record", _ref("Dkim")), **NOT_FOUND},
                       description="The private key is never returned."),
            "put": _op("Domains", "Create, import or replace the DKIM key", "setDkim",
                       {"200": _response("Replaced", _ref("Dkim")), "201": _response("Created", _ref("Dkim")),
                        **NOT_FOUND, **INVALID},
                       body=_ref("DkimSet"),
                       description="Give key_size to generate a key or private_key to import one. Outbound "
                                   "mail is signed from now on: publish the DNS record first when rotating."),
            "delete": _op("Domains", "Delete the DKIM key", "deleteDkim", {**DELETED, **NOT_FOUND},
                          description="Outbound mail of the domain is no longer signed."),
        },
        "/list-entries": {
            "get": _op("Allow & block lists", "Global allow/block list", "listGlobalEntries",
                       {"200": _response("Entries", _page_of("FilterListEntry"))},
                       params=PAGE_PARAMS + entry_filters,
                       description="Entries that apply to every domain."),
            "post": _op("Allow & block lists", "Add a global entry", "createGlobalEntry",
                        {"201": _response("Created", _ref("FilterListEntry")), **CONFLICT, **INVALID},
                        body=_ref("FilterListEntryCreate")),
        },
        "/list-entries/{entry_id}": {
            "parameters": [entry_id],
            "delete": _op("Allow & block lists", "Remove a global entry", "deleteGlobalEntry",
                          {**DELETED, **NOT_FOUND}),
        },
        "/relay-networks": {
            "get": _op("Settings", "Relay networks", "listRelayNetworks",
                       {"200": _response("Networks", _page_of("RelayNetwork"))},
                       params=PAGE_PARAMS,
                       description="Networks that may send outbound mail through the gateway."),
            "post": _op("Settings", "Add a relay network", "createRelayNetwork",
                        {"201": _response("Created", _ref("RelayNetwork")), **CONFLICT, **INVALID},
                        body=_ref("RelayNetworkCreate"),
                        description="Only add networks you control: the gateway relays their mail anywhere."),
        },
        "/relay-networks/{network_id}": {
            "parameters": [_id_param("network_id", "Relay network ID")],
            "delete": _op("Settings", "Remove a relay network", "deleteRelayNetwork", {**DELETED, **NOT_FOUND}),
        },
        "/outbound-limits": {
            "get": _op("Outbound limits", "Limits of single senders and domains", "listOutboundLimits",
                       {"200": _response("Limits", _page_of("OutboundLimit"))}, params=PAGE_PARAMS,
                       description="The default for every other sender is in the settings (outbound_limit, "
                                   "outbound_limit_period)."),
            "post": _op("Outbound limits", "Add a limit", "createOutboundLimit",
                        {"201": _response("Created", _ref("OutboundLimit")), **CONFLICT, **INVALID},
                        body=_ref("OutboundLimitCreate")),
        },
        "/outbound-limits/{limit_id}": {
            "parameters": [_id_param("limit_id", "Outbound limit ID")],
            "get": _op("Outbound limits", "Get a limit", "getOutboundLimit",
                       {"200": _response("Limit", _ref("OutboundLimit")), **NOT_FOUND}),
            "patch": _op("Outbound limits", "Change a limit", "updateOutboundLimit",
                         {"200": _response("Updated", _ref("OutboundLimit")), **NOT_FOUND, **INVALID},
                         body=_ref("OutboundLimitUpdate")),
            "delete": _op("Outbound limits", "Remove a limit", "deleteOutboundLimit", {**DELETED, **NOT_FOUND}),
        },
        "/outbound-senders": {
            "get": _op("Outbound limits", "Current counts and deferred senders", "listOutboundSenders",
                       {"200": _response("Senders", _ref("OutboundSenders")), **UNAVAILABLE},
                       description="counts: the busiest senders in their current period (at most 50); deferred: "
                                   "senders that reached their limit in the last 7 days."),
        },
        "/rate-limits/hits": {
            "get": _op("Rate limits", "Sending servers and recipients deferred by an inbound rate limit",
                       "listRateLimitHits",
                       {"200": _response("Deferred", {"type": "object", "properties": {"hits": {
                           "type": "array", "items": {"type": "object", "properties": {
                               "kind": {"type": "string", "enum": ["ip", "rcpt", "bounce"]},
                               "key": {"type": "string", "description": "IP address or recipient"},
                               "count": {"type": "integer", "description": "Messages deferred"},
                               "at": {"type": "integer", "description": "Unix time of the last"},
                               "limit": {"type": "integer"}, "seconds": {"type": "integer"}}}}}}),
                        **UNAVAILABLE},
                       description="The last 7 days. The limits are settings (inbound_*, smtp_*, rate_limit_exempt)."),
        },
        "/rate-limits/reset": {
            "post": _op("Rate limits", "Accept mail of a sending server or for a recipient again now",
                        "resetRateLimit",
                        {"200": _response("Reset", {"type": "object", "properties": {
                            "kind": {"type": "string"}, "key": {"type": "string"},
                            "counters": {"type": "integer", "description": "Counters removed"}}}),
                         **INVALID, **UNAVAILABLE},
                        body={"type": "object", "required": ["kind", "key"], "additionalProperties": False,
                              "properties": {"kind": {"type": "string", "enum": ["ip", "rcpt", "bounce"]},
                                             "key": {"type": "string"}}}),
        },
        "/outbound-senders/reset": {
            "post": _op("Outbound limits", "Let a sender send again now", "resetOutboundSender",
                        {"200": _response("Reset", {"type": "object", "properties": {
                            "sender": {"type": "string"},
                            "reset": {"type": "boolean", "description": "Whether there was a count"}}}),
                         **INVALID, **UNAVAILABLE},
                        body={"type": "object", "required": ["sender"], "additionalProperties": False,
                              "properties": {"sender": {"type": "string",
                                                        "description": "As listed, e.g. bounces:192.0.2.5"}}},
                        description="Removes the sender's counts and its record of deferred mail."),
        },
        "/directories": {
            "get": _op("Directories", "Directories", "listDirectories",
                       {"200": _response("Directories", _page_of("Directory"))}, params=PAGE_PARAMS),
            "post": _op("Directories", "Add a directory", "createDirectory",
                        {"201": _response("Created", _ref("Directory")), **CONFLICT, **INVALID},
                        body=_ref("DirectoryCreate"),
                        description="Then set a domain's recipient_check to directory and its directory_id."),
        },
        "/directories/{directory_id}": {
            "parameters": [directory_id],
            "get": _op("Directories", "Get a directory", "getDirectory",
                       {"200": _response("Directory", _ref("Directory")), **NOT_FOUND}),
            "patch": _op("Directories", "Change a directory", "updateDirectory",
                         {"200": _response("Updated", _ref("Directory")), **NOT_FOUND, **CONFLICT, **INVALID},
                         body=_ref("DirectoryUpdate")),
            "delete": _op("Directories", "Delete a directory", "deleteDirectory",
                          {**DELETED, **NOT_FOUND,
                           "409": _response("A domain uses it", _ref("Error"))},
                          description="Its addresses stay in the recipient lists, as manual entries would."),
        },
        "/directories/{directory_id}/test": {
            "parameters": [directory_id],
            "post": _op("Directories", "Read the directory without changing anything", "testDirectory",
                        {"200": _response("Addresses found", _ref("DirectoryTest")), **NOT_FOUND, **DIRECTORY_FAILED}),
        },
        "/directories/{directory_id}/sync": {
            "parameters": [directory_id],
            "post": _op("Directories", "Synchronise the recipients now", "syncDirectory",
                        {"200": _response("Recipients per domain", _ref("DirectorySync")), **NOT_FOUND,
                         "409": _response("A synchronisation is running", _ref("Error")), **DIRECTORY_FAILED},
                        body={"type": "object", "additionalProperties": False, "properties": {
                            "force": {"type": "boolean", "default": False,
                                      "description": "Also when it would remove more than half of a domain's "
                                                     "directory recipients"}}},
                        description="Also every 15 minutes by itself. Refused (502) if the directory has no "
                                    "address, or a domain would lose more than half of its directory recipients."),
        },
        "/protected-people": {
            "get": _op("Impersonation", "Protected people", "listProtectedPeople",
                       {"200": _response("People", _page_of("ProtectedPerson"))}, params=PAGE_PARAMS,
                       description="Their names in the From header of mail from outside addresses add "
                                   "impersonation_name_score."),
            "post": _op("Impersonation", "Protect a person", "createProtectedPerson",
                        {"201": _response("Created", _ref("ProtectedPerson")), **CONFLICT, **INVALID},
                        body=_ref("ProtectedPersonCreate")),
        },
        "/protected-people/{person_id}": {
            "parameters": [_id_param("person_id", "Protected person ID")],
            "get": _op("Impersonation", "Get a protected person", "getProtectedPerson",
                       {"200": _response("Person", _ref("ProtectedPerson")), **NOT_FOUND}),
            "patch": _op("Impersonation", "Change a protected person", "updateProtectedPerson",
                         {"200": _response("Updated", _ref("ProtectedPerson")), **NOT_FOUND, **CONFLICT, **INVALID},
                         body=_ref("ProtectedPersonUpdate")),
            "delete": _op("Impersonation", "Stop protecting a person", "deleteProtectedPerson",
                          {**DELETED, **NOT_FOUND}),
        },
        "/impersonation/test": {
            "post": _op("Impersonation", "Test a sender", "testImpersonation",
                        {"200": _response("What the checks find", {"type": "object", "properties": {
                            "person": {"type": "string", "nullable": True,
                                       "description": "The protected person the name matches"},
                            "own_domain": {"type": "boolean",
                                           "description": "A protected domain: the authentication check decides"},
                            "lookalike": {"type": "string", "nullable": True,
                                          "description": "The protected domain imitated"}}}), **INVALID},
                        body={"type": "object", "required": ["address"], "additionalProperties": False,
                              "properties": {"name": {"type": "string", "description": "The display name"},
                                             "address": {"type": "string", "format": "email"}}}),
        },
        "/content-rules": {
            "get": _op("Content rules", "Rules", "listContentRules",
                       {"200": _response("Rules", _page_of("ContentRule"))}, params=PAGE_PARAMS),
            "post": _op("Content rules", "Add a rule", "createContentRule",
                        {"201": _response("Created", _ref("ContentRule")), **CONFLICT, **INVALID},
                        body=_ref("ContentRuleCreate"),
                        description="Applied by rspamd within a minute, before the other checks."),
        },
        "/content-rules/{rule_id}": {
            "parameters": [_id_param("rule_id", "Content rule ID")],
            "get": _op("Content rules", "Get a rule", "getContentRule",
                       {"200": _response("Rule", _ref("ContentRule")), **NOT_FOUND}),
            "patch": _op("Content rules", "Change a rule", "updateContentRule",
                         {"200": _response("Updated", _ref("ContentRule")), **NOT_FOUND, **CONFLICT, **INVALID},
                         body=_ref("ContentRuleUpdate")),
            "delete": _op("Content rules", "Delete a rule", "deleteContentRule", {**DELETED, **NOT_FOUND}),
        },
        "/content-rules/test": {
            "post": _op("Content rules", "Test the rules on a message", "testContentRules",
                        {"200": _response("Each rule of the direction", {"type": "object", "properties": {
                            "results": {"type": "array", "items": {"type": "object", "properties": {
                                "id": ID, "name": {"type": "string"}, "active": {"type": "boolean"},
                                "matched": {"type": "boolean"},
                                "value": {"type": "string", "nullable": True,
                                          "description": "The value that matched"}}}}}}), **INVALID},
                        body={"type": "object", "required": ["source"], "additionalProperties": False,
                              "properties": {
                                  "source": {"type": "string", "description": "The message: headers, a blank "
                                                                             "line, the body"},
                                  "envelope_from": {"type": "string"},
                                  "recipients": {"type": "array", "items": {"type": "string"}},
                                  "direction": {"type": "string", "enum": ["inbound", "outbound"],
                                                "default": "inbound"}}}),
        },
        "/dlp-rules": {
            "get": _op("Data loss prevention", "Rules", "listDlpRules",
                       {"200": _response("Rules", _page_of("DlpRule"))}, params=PAGE_PARAMS),
            "post": _op("Data loss prevention", "Add a rule", "createDlpRule",
                        {"201": _response("Created", _ref("DlpRule")), **CONFLICT, **INVALID},
                        body=_ref("DlpRuleCreate"),
                        description="Checked by rspamd within a minute for outbound mail from the relay networks: "
                                    "the subject, the text and text attachments (CSV, JSON, XML)."),
        },
        "/dlp-rules/{rule_id}": {
            "parameters": [_id_param("rule_id", "DLP rule ID")],
            "get": _op("Data loss prevention", "Get a rule", "getDlpRule",
                       {"200": _response("Rule", _ref("DlpRule")), **NOT_FOUND}),
            "patch": _op("Data loss prevention", "Change a rule", "updateDlpRule",
                         {"200": _response("Updated", _ref("DlpRule")), **NOT_FOUND, **CONFLICT, **INVALID},
                         body=_ref("DlpRuleUpdate")),
            "delete": _op("Data loss prevention", "Delete a rule", "deleteDlpRule", {**DELETED, **NOT_FOUND}),
        },
        "/dlp-rules/test": {
            "post": _op("Data loss prevention", "Test the rules on a text", "testDlpRules",
                        {"200": _response("What each rule found", _ref("DlpTestResult")), **INVALID},
                        body={"type": "object", "required": ["text"], "additionalProperties": False,
                              "properties": {"text": {"type": "string"},
                                             "sender": {"type": "string",
                                                        "description": "Only the rules for this sender"}}},
                        description="The detectors of rspamd, run by the web UI; regular expressions are "
                                    "Python's, which rarely differ from PCRE."),
        },
        "/hostname": {
            "get": _op("Settings", "The gateway's hostname", "getHostname",
                       {"200": _response("Hostname", _ref("Hostname"))}),
            "put": _op("Settings", "Change the gateway's hostname", "changeHostname",
                       {"202": _response("Change requested", _ref("Hostname")), **INVALID,
                        "409": _response("The gateway is a cluster member", _ref("Error")), **UNAVAILABLE},
                       body=_ref("HostnameChange"),
                       description="Applied within seconds by a root service: crassostrea.conf, Postfix's "
                                   "myhostname, a restart of the web UI and the other services that read the name, "
                                   "and a certificate request for the new name. warnings tell when the name does "
                                   "not resolve to this server yet. Not for cluster members."),
        },
        "/ip-config": {
            "get": _op("IP addressing", "Addresses and IP families of the network interfaces", "getIpConfig",
                       {"200": _response("State", _ref("IpConfigState")), **NOT_FOUND, **UNAVAILABLE},
                       params=[_query("device", "The interface in state (default: the one with the default route); "
                                                "state.interfaces lists all")]),
            "put": _op("IP addressing", "Change the addresses and IP families of an interface", "changeIpConfig",
                       {"202": _response("Change started", _ref("IpConfig")), **INVALID, **NOT_FOUND,
                        "409": _response("A change is running, or a cluster member", _ref("Error")), **UNAVAILABLE},
                       body=_ref("IpConfig"),
                       description="Applied by a root service, which then tests that every family with a gateway "
                                   "reaches the internet and names resolve, and restores the previous settings "
                                   "otherwise (GET shows the outcome in change). Both families may be off on an "
                                   "interface while another interface has an address. Not for cluster members."),
        },
        "/tls": {
            "get": _op("Certificates & TLS", "Certificate, TLS settings and the outcome of changes", "getTls",
                       {"200": _response("State", _ref("Tls"))}),
        },
        "/tls/letsencrypt/test": {
            "post": _op("Certificates & TLS", "Test names with Let's Encrypt's staging environment",
                        "testLetsEncryptNames",
                        {"202": _response("Test started", _ref("TlsNames")), **INVALID, **TLS_CONFLICT},
                        body=_ref("TlsNamesRequest"),
                        description="names are the additional names; the hostname is always included. The "
                                    "outcome appears in GET /tls (status.le_test)."),
        },
        "/tls/letsencrypt/apply": {
            "post": _op("Certificates & TLS", "Let's Encrypt certificate for tested names", "applyLetsEncrypt",
                        {"202": _response("Certificate requested", _ref("TlsNames")), **INVALID, **TLS_CONFLICT},
                        body=_ref("TlsNamesRequest"),
                        description="Only after a passed staging test of exactly these names in the last 24 "
                                    "hours (409 otherwise). Turns on automatic renewal."),
        },
        "/tls/certificate": {
            "post": {**_op("Certificates & TLS", "Upload and check a certificate", "uploadCertificate",
                           {"200": _response("The files can be used (warnings may apply)", _ref("TlsCheck")),
                            "422": _response("The files cannot be used", _ref("TlsCheck"))},
                           description="Checks the files (key belongs to the certificate, dates, key strength, "
                                       "chain, trust and hostname) and stages them; apply them with "
                                       "POST /tls/certificate/apply and the returned sha256."),
                     "requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {
                         "type": "object", "required": ["certificate", "key"], "properties": {
                             "certificate": {"type": "string", "format": "binary",
                                             "description": "PEM, optionally followed by the chain"},
                             "key": {"type": "string", "format": "binary",
                                     "description": "PEM private key without a passphrase"},
                             "chain": {"type": "string", "format": "binary"}}}}}}},
        },
        "/tls/certificate/apply": {
            "post": _op("Certificates & TLS", "Install the checked certificate", "applyCertificate",
                        {"202": _response("Installation started", _ref("TlsSha")), **INVALID, **TLS_CONFLICT},
                        body=_ref("TlsSha"), description="Turns off Let's Encrypt."),
        },
        "/tls/versions": {
            "put": _op("Certificates & TLS", "Oldest TLS versions accepted", "setTlsVersions",
                       {"202": _response("Change started", _ref("TlsVersions")), **INVALID, **TLS_CONFLICT},
                       body=_ref("TlsVersions"),
                       description="1.1 and 1.0 are insecure and relax the OpenSSL policy of that service."),
        },
        "/settings": {
            "get": _op("Settings", "Global settings", "getSettings", {"200": _response("Settings", _ref("Settings"))}),
            "patch": _op("Settings", "Change global settings", "updateSettings",
                         {"200": _response("Settings after the change", _ref("Settings")), **INVALID},
                         body=_ref("SettingsUpdate"),
                         description="Only the given settings are changed. Rspamd applies new thresholds "
                                     "within a minute."),
        },
    }


def _operations_paths():
    item_id = _id_param("item_id", "Quarantined message ID")
    entry_id = _id_param("entry_id", "Mail log entry ID")
    backup_name = {"name": "name", "in": "path", "required": True, "description": "File name of the backup",
                   "schema": {"type": "string",
                              "pattern": r"^backup-[0-9]{8}-[0-9]{6}-(manual|scheduled)\.tar\.gz$"}}
    learn_body = {"required": True, "content": {"message/rfc822": {"schema": {"type": "string", "format": "binary"}}}}
    cluster_node = {"name": "node", "in": "path", "required": True, "description": "Hostname of a node (HA_NODES)",
                    "schema": {"type": "string"}}
    learn = {
        "200": _response("Result", _ref("Notes")), **INVALID, **UNAVAILABLE,
    }
    return {
        "/quarantine": {
            "get": _op("Quarantine", "List quarantined messages", "listQuarantine",
                       {"200": _response("Messages, newest first", _page_of("QuarantineItem"))},
                       params=PAGE_PARAMS + [
                           _query("domain", "Exact domain"), _query("rcpt", "Exact recipient address"),
                           _query("mailbox", "Inbound mail of a mailbox, with its sub-addresses (alice+tag@)"),
                           _query("direction", "inbound or outbound",
                                  {"type": "string", "enum": ["inbound", "outbound"]}),
                           _query("q", "Substring of subject, sender or recipient")]),
        },
        "/quarantine/{item_id}": {
            "parameters": [item_id],
            "get": _op("Quarantine", "Get a quarantined message", "getQuarantineItem",
                       {"200": _response("Message with symbols and a text preview", _ref("QuarantineDetail")),
                        **NOT_FOUND},
                       description="HTML parts are returned as source text."),
            "delete": _op("Quarantine", "Delete a quarantined message", "deleteQuarantineItem",
                          {**DELETED, **NOT_FOUND}),
        },
        "/quarantine/{item_id}/raw": {
            "parameters": [item_id],
            "get": _op("Quarantine", "Download the original message", "getQuarantineRaw",
                       {"200": {"description": "The message",
                                "content": {"message/rfc822": {"schema": {"type": "string", "format": "binary"}}}},
                        **NOT_FOUND}),
        },
        "/quarantine/{item_id}/release": {
            "parameters": [item_id],
            "post": {**_op("Quarantine", "Release a message to its recipient", "releaseQuarantineItem",
                           {"200": _response("Released: the message as it was in the quarantine",
                                             _ref("ReleaseResult")), **NOT_FOUND,
                            "409": _response("The message contains a virus (set allow_virus)", _ref("Error")),
                            **UNAVAILABLE},
                           description="Delivers the message and removes it from the quarantine; when "
                                       "Postfix does not take it (503) it stays. Outbound messages are "
                                       "DKIM-signed for the sender's domain."),
                     "requestBody": {"required": False, **_json(_ref("ReleaseRequest"))}},
        },
        "/quarantine/{item_id}/block-sender": {
            "parameters": [item_id],
            "post": {**_op("Quarantine", "Block the sender (and delete the message)", "blockQuarantineSender",
                           {"200": _response("Blocked", _ref("Notes")), **NOT_FOUND, **INVALID},
                           description="Adds the envelope sender of an inbound message to a block list. A "
                                       "sender that is listed already is no error."),
                     "requestBody": {"required": True, **_json(_ref("BlockSenderRequest"))}},
        },
        "/quarantine/{item_id}/learn-spam": {
            "parameters": [item_id],
            "post": _op("Quarantine", "Learn as spam and delete", "learnQuarantineItem",
                        {"200": _response("Result", _ref("Notes")), **NOT_FOUND, **UNAVAILABLE},
                        description="Trains Bayes and stores the fuzzy hash, then deletes the message."),
        },
        "/mail-log": {
            "get": _op("Mail log", "List logged messages", "listMailLog",
                       {"200": _response("Messages, newest first", _page_of("MailLogEntry"))},
                       params=PAGE_PARAMS + [
                           _query("domain", "A recipient's or the sender's domain"),
                           _query("direction", "inbound or outbound",
                                  {"type": "string", "enum": ["inbound", "outbound"]}),
                           _query("action", "Rspamd action, or refused: the recipients Postfix refused because "
                                            "they do not exist (no message)",
                                  {"type": "string", "enum": [*MAILLOG_ACTIONS, "refused"]}),
                           _query("delivery", "delivered (every recipient), deferred or bounced (any recipient)",
                                  {"type": "string", "enum": ["delivered", "deferred", "bounced"]}),
                           _query("q", "Substring of subject, addresses or Message-ID; or a queue ID or IP")]),
        },
        "/mail-log/{entry_id}": {
            "parameters": [entry_id],
            "get": _op("Mail log", "Get a logged message", "getMailLogEntry",
                       {"200": _response("Message with symbols and a text preview", _ref("MailLogDetail")),
                        **NOT_FOUND},
                       description="HTML parts are returned as source text."),
        },
        "/mail-log/{entry_id}/raw": {
            "parameters": [entry_id],
            "get": _op("Mail log", "Download the logged message", "getMailLogRaw",
                       {"200": {"description": "The message as scanned",
                                "content": {"message/rfc822": {"schema": {"type": "string", "format": "binary"}}}},
                        **NOT_FOUND}),
        },
        "/mail-log/{entry_id}/requeue": {
            "parameters": [entry_id],
            "post": {**_op("Mail log", "Queue a logged message again", "requeueMailLogEntry",
                           {"200": _response("Queued", _ref("RequeueResult")), **NOT_FOUND, **INVALID,
                            "409": _response("The message contains a virus (set allow_virus)", _ref("Error")),
                            **UNAVAILABLE},
                           description="Delivers the message as scanned once more through Postfix, without a "
                                       "second scan. Outbound messages are DKIM-signed for the sender's domain."),
                     "requestBody": {"required": False, **_json(_ref("RequeueRequest"))}},
        },
        "/audit-log": {
            "get": _op("Audit log", "Changes and logins, newest first", "listAuditLog",
                       {"200": _response("Entries", _page_of("AuditEntry"))},
                       params=PAGE_PARAMS + [
                           _query("actor", "Exact actor: administrator, user:<address>, link:<address>, "
                                           "api:<key name> or cli"),
                           _query("outcome", "ok or failed", {"type": "string", "enum": ["ok", "failed"]}),
                           _query("q", "Substring of action, target, message or fields; or an IP")]),
        },
        "/backups": {
            "get": _op("Backups", "List the backups", "listBackups",
                       {"200": _response("Backups, newest first, and the last backup's outcome", _ref("Backups"))}),
            "post": _op("Backups", "Make a backup now", "createBackup",
                        {"202": _response("Backup started", _ref("Backups")), **BACKUP_BUSY},
                        description="Made by a root service within seconds; poll GET /backups for status."),
        },
        "/backups/{name}": {
            "parameters": [backup_name],
            "delete": _op("Backups", "Delete a backup", "deleteBackup",
                          {"202": _response("Deletion started", _ref("Backups")), **NOT_FOUND, **BACKUP_BUSY}),
        },
        "/backups/{name}/download": {
            "parameters": [backup_name],
            "get": _op("Backups", "Download a backup", "downloadBackup",
                       {"200": {"description": "The archive (tar.gz). It holds every password and private key "
                                               "of the gateway.",
                                "content": {"application/gzip": {"schema": {"type": "string", "format": "binary"}}}},
                        **NOT_FOUND},
                       description="Recorded in the audit log. Restore with system/backup.sh restore on the "
                                   "server."),
        },
        "/link-clicks": {
            "get": _op("Link protection", "Recent clicks on rewritten links", "listLinkClicks",
                       {"200": _response("Clicks, newest first", {"type": "object", "properties": {
                           "items": {"type": "array", "items": _ref("LinkClick")}}}), **UNAVAILABLE},
                       params=[_query("limit", "At most this many (default 200)", {"type": "integer"}),
                               _query("blocked", "true: only blocked clicks", {"type": "boolean"})]),
        },
        "/link-check": {
            "post": _op("Link protection", "Check a link as a click would", "checkLink",
                        {"200": _response("Verdict", _ref("LinkVerdict")), **INVALID, **UNAVAILABLE},
                        body={"type": "object", "required": ["url"], "additionalProperties": False,
                              "properties": {"url": {"type": "string", "example": "https://example.com/login"}}}),
        },
        "/hash-detections": {
            "get": _op("Attachments", "Attachments found by the hash lookups", "listHashDetections",
                       {"200": _response("Detections, newest first", {"type": "object", "properties": {
                           "items": {"type": "array", "items": _ref("HashDetection")}}}), **UNAVAILABLE},
                       params=[_query("limit", "At most this many (default 100, at most 500)",
                                      {"type": "integer"})]),
        },
        "/hash-lookup": {
            "post": _op("Attachments", "Look up a file hash with the enabled sources", "lookupHash",
                        {"200": _response("Per source", {"type": "object", "additionalProperties": {
                            "type": "object", "properties": {
                                "malicious": {"type": "boolean", "nullable": True,
                                              "description": "null: the source gave no answer"},
                                "detail": {"type": "string"}}}}), **INVALID},
                        body={"type": "object", "required": ["hash"], "additionalProperties": False,
                              "properties": {"hash": {"type": "string",
                                                      "description": "MD5, SHA-1 or SHA-256 in hex"}}}),
        },
        "/user-reports": {
            "get": _op("Training", "Messages users reported as spam or not spam", "listUserReports",
                       {"200": _response("The latest 100", {"type": "object", "properties": {
                           "addresses": {"type": "object", "properties": {
                               "spam": {"type": "string"}, "ham": {"type": "string"}}},
                           "items": {"type": "array", "items": {"type": "object", "properties": {
                               "id": ID, "at": TIMESTAMP, "reporter": {"type": "string"},
                               "kind": {"type": "string", "enum": ["spam", "ham"]},
                               "status": {"type": "string", "enum": ["learned", "refused", "empty"]},
                               "learned": {"type": "integer"}, "subjects": {"type": "string"},
                               "detail": {"type": "string"}}}}}})},
                       description="Settings: user_reports_enabled, user_reports_confirm, user_reports_per_hour."),
        },
        "/journal/status": {
            "get": _op("Journaling", "Journal copies waiting and sent", "journalStatus",
                       {"200": _response("Status", {"type": "object", "properties": {
                           "queued": {"type": "integer"}, "sent": {"type": "integer"},
                           "sent_at": {"type": "integer", "nullable": True, "description": "Unix time"},
                           "error": {"type": "string", "nullable": True},
                           "error_at": {"type": "integer", "nullable": True}}}), **UNAVAILABLE},
                       description="Settings: journal_address and the other journal_ settings."),
        },
        "/monitoring/checks": {
            "get": _op("Monitoring", "The alert checks now", "monitoringChecks",
                       {"200": _response("Checks", {"type": "object", "properties": {"checks": {
                           "type": "object", "additionalProperties": {"type": "object", "properties": {
                               "ok": {"type": "boolean"}, "message": {"type": "string"},
                               "label": {"type": "string"}}}}}})},
                       description="Deferred mail, the certificate, backups, directories and services. Metrics "
                                   "for Prometheus are at /metrics (bearer token from the Monitoring page)."),
        },
        "/cluster": {
            "get": _op("Cluster", "The cluster's members and problems", "getCluster",
                       {"200": _response("State", _ref("Cluster"))},
                       description="From the reports every node writes every 10 seconds. A single gateway answers "
                                   '{"cluster": false}.'),
        },
        "/cluster/nodes/{node}/maintenance": {
            "parameters": [cluster_node],
            "put": _op("Cluster", "Put a node into maintenance or take it out", "setClusterMaintenance",
                       {"200": _response("Requested", {"type": "object", "properties": {
                           "node": {"type": "string"}, "maintenance": {"type": "boolean"}}}),
                        **NOT_FOUND, **INVALID,
                        "409": _response("Not a cluster, or no other node would accept mail", _ref("Error"))},
                       body={"type": "object", "required": ["enabled"], "properties": {
                           "enabled": {"type": "boolean"},
                           "force": {"type": "boolean", "description": "Even if no other node accepts mail"}}},
                       description="A node in maintenance answers new SMTP connections with 421, hands over the "
                                   "Valkey master and the floating address and keeps delivering its queue. The "
                                   "node applies it within seconds (maintenance_applied in GET /cluster)."),
        },
        "/cluster/nodes/{node}/valkey-master": {
            "parameters": [cluster_node],
            "post": _op("Cluster", "Make a node the Valkey master", "setClusterValkeyMaster",
                        {"202": _response("Requested", {"type": "object", "properties": {
                            "node": {"type": "string"}, "requested": {"type": "boolean"}}}),
                         **NOT_FOUND,
                         "409": _response("Not a cluster, in maintenance, not a connected replica, already the "
                                          "master", _ref("Error"))},
                        description="Sentinel hands the master over within about 30 seconds."),
        },
        "/cluster/nodes/{node}": {
            "parameters": [cluster_node],
            "delete": _op("Cluster", "Remove a node that is switched off", "removeClusterNode",
                          {"200": _response("Removed", {"type": "object", "properties": {
                              "removed": {"type": "string"},
                              "nodes": {"type": "array", "items": {"type": "string"}}}}),
                           **NOT_FOUND, "409": _response("The node is running, or it is this node", _ref("Error"))},
                          description="Like pvecm delnode: every member drops the node from its configuration "
                                      "within a minute. The node must not run again with this cluster's data."),
        },
        "/cluster/witness": {
            "delete": _op("Cluster", "Remove the witness", "removeClusterWitness",
                          {"204": _response("Removed"), **NOT_FOUND}),
        },
        "/cluster/join-information": {
            "post": _op("Cluster", "Create a join information for another gateway", "createClusterJoinInformation",
                        {"201": _response("Join information", {"type": "object", "properties": {
                            "information": {"type": "string", "description": "sfjoin1.…: works once"},
                            "expires_in": {"type": "integer", "description": "Seconds"},
                            "host": {"type": "string"}, "address": {"type": "string"},
                            "fingerprint": {"type": "string", "description": "SHA-256 of this node's HTTPS "
                                                                            "certificate"}}}),
                         "409": _response("Not a cluster", _ref("Error"))},
                        description="The other gateway joins with it (POST /cluster/join there, or its Cluster "
                                    "page). It holds a one-time secret: treat it like a password."),
        },
        "/cluster/create": {
            "post": _op("Cluster", "Create a cluster with this single gateway as its first node", "createCluster",
                        {"202": _response("Started", {"type": "object", "properties": {
                            "address": {"type": "string"}, "vip": {"type": "string"}}}), **INVALID,
                         "409": _response("Already a cluster member, or a setup is running", _ref("Error")),
                         **UNAVAILABLE},
                        body={"type": "object", "required": ["address"], "properties": {
                            "address": {"type": "string", "description": "This gateway's cluster address (IPv4)"},
                            "vip": {"type": "string", "description": "Optional floating address, e.g. "
                                                                     "192.0.2.10/24"}}},
                        description="A root service runs setup.sh --ha; the gateway keeps its data and restarts "
                                    "its services. GET /cluster shows the outcome in setup."),
        },
        "/cluster/join": {
            "post": _op("Cluster", "Join a cluster with a join information", "joinCluster",
                        {"202": _response("Started", {"type": "object", "properties": {
                            "host": {"type": "string"}, "address": {"type": "string"}}}), **INVALID,
                         "409": _response("Already a cluster member, or a setup is running", _ref("Error")),
                         **UNAVAILABLE},
                        body={"type": "object", "required": ["information", "address"], "properties": {
                            "information": {"type": "string", "description": "From POST /cluster/join-information "
                                                                             "on a member"},
                            "address": {"type": "string", "description": "This gateway's cluster address (IPv4)"}}},
                        description="This gateway's domains, accounts, settings and data are replaced by the "
                                    "cluster's; its name, network and certificate settings stay. GET /cluster shows "
                                    "the outcome in setup."),
        },
        "/statistics": {
            "get": _op("Statistics", "Messages over time by outcome", "getStatistics",
                       {"200": _response("Buckets and totals", _ref("Statistics"))},
                       params=[_query("range", "24h (hourly), 7d (6 hours), 30d (daily), 12m (30 days)",
                                      {"type": "string", "enum": ["24h", "7d", "30d", "12m"], "default": "7d"}),
                               _query("direction", "inbound or outbound",
                                      {"type": "string", "enum": ["inbound", "outbound"]}),
                               _query("domain", "Exact domain")],
                       description="Messages scanned by rspamd; mail refused before (postscreen, unknown "
                                   "recipients) is not counted."),
        },
        "/reports/summary": {
            "get": _op("Reports", "DMARC and TLS reports per domain", "reportSummary",
                       {"200": _response("Summary", {"type": "object", "properties": {
                           "address": {"type": "string", "description": "The rua address to publish"},
                           "days": {"type": "integer"},
                           "domains": {"type": "object", "additionalProperties": {"type": "object", "properties": {
                               "dmarc_reports": {"type": "integer"}, "messages": {"type": "integer"},
                               "passed": {"type": "integer"}, "tls_reports": {"type": "integer"},
                               "tls_ok": {"type": "integer"}, "tls_failed": {"type": "integer"}}}}}})},
                       params=[_query("days", "Reports ending in the last days (default 30)", {"type": "integer"})]),
        },
        "/reports/dmarc": {
            "get": _op("Reports", "DMARC aggregate reports", "listDmarcReports",
                       {"200": _response("Reports, newest first", _page_of("DmarcReport"))},
                       params=PAGE_PARAMS + [_query("domain", "Exact domain")]),
        },
        "/reports/tls": {
            "get": _op("Reports", "TLS reports", "listTlsReports",
                       {"200": _response("Reports, newest first", _page_of("TlsReport"))},
                       params=PAGE_PARAMS + [_query("domain", "Exact domain")]),
        },
        "/queue": {
            "get": _op("Mail queue", "Messages in the mail queue", "listQueue",
                       {"200": _response("Queue of the node that answered", _ref("Queue")), **UNAVAILABLE},
                       description="Each node of a cluster has its own queue; node names the one that answered."),
        },
        "/queue/{queue_id}": {
            "parameters": [{"name": "queue_id", "in": "path", "required": True, "description": "Postfix queue ID",
                            "schema": {"type": "string", "pattern": "^[0-9A-Za-z]{6,32}$"}}],
            "get": _op("Mail queue", "Content of a queued message", "getQueuedMessage",
                       {"200": _response("postcat output", _ref("QueuedMessage")), **NOT_FOUND, **UNAVAILABLE}),
        },
        "/queue/actions": {
            "post": _op("Mail queue", "Act on queued messages", "queueAction",
                        {"200": _response("Done", _ref("QueueActionResult")), **INVALID, **UNAVAILABLE},
                        body=_ref("QueueAction"),
                        description="flush and delete_all act on the whole queue, the others on ids."),
        },
        "/bans": {
            "get": _op("Bans", "Banned networks", "listBans",
                       {"200": _response("Bans", {"type": "object", "properties": {
                           "items": {"type": "array", "items": _ref("Ban")}, "total": {"type": "integer"}}}),
                        **UNAVAILABLE},
                       description="Networks blocked by netfilter after repeated SMTP protocol errors or failed "
                                   "logins (all nodes of a cluster share them)."),
        },
        "/bans/unban": {
            "post": _op("Bans", "Lift a ban", "unban",
                        {"202": _response("Unban queued, applied within seconds", _ref("Unban")), **NOT_FOUND,
                         **INVALID, **UNAVAILABLE},
                        body=_ref("UnbanRequest")),
        },
        "/training/spam": {
            "post": {**_op("Training", "Learn a message as spam", "learnSpam", learn,
                           description="Send the raw message (headers and body). Trains Bayes and stores the "
                                       "fuzzy hash."),
                     "requestBody": learn_body},
        },
        "/training/ham": {
            "post": {**_op("Training", "Learn a message as ham", "learnHam", learn,
                           description="Send the raw message (headers and body)."),
                     "requestBody": learn_body},
        },
    }


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

def _account_schemas():
    return {
        "Admin": {"type": "object", "properties": {
            "id": ID, "username": {"type": "string"}, "active": {"type": "boolean"}, **ADMIN_ACCESS,
            "two_factor": {"type": "boolean", "readOnly": True, "description": "Two-factor login is on"},
            "created_at": TIMESTAMP, "last_login_at": {**TIMESTAMP, "nullable": True},
        }},
        "AdminCreate": {"type": "object", "required": ["username", "password"],
                        "additionalProperties": False, "properties": {
            "username": {"type": "string", "pattern": "^[A-Za-z0-9._-]{3,64}$"},
            "password": PASSWORD,
            "active": {"type": "boolean", "default": True}, **ADMIN_ACCESS,
        }},
        "AdminUpdate": {"type": "object", "additionalProperties": False, "properties": {
            "username": {"type": "string", "pattern": "^[A-Za-z0-9._-]{3,64}$"},
            "password": PASSWORD,
            "active": {"type": "boolean"}, **ADMIN_ACCESS,
        }},
        "MailboxUser": {"type": "object", "properties": {
            "id": ID, "email": {"type": "string", "format": "email"},
            "domain": {"type": "string", "readOnly": True}, "active": {"type": "boolean"},
            "greylist_score": SCORE, "add_header_score": SCORE, "reject_score": SCORE,
            "digest_interval": DIGEST,
            "created_at": TIMESTAMP, "last_login_at": {**TIMESTAMP, "nullable": True},
            "invited_at": {**TIMESTAMP, "nullable": True, "readOnly": True,
                           "description": "Created for quarantined mail, no password set yet"},
            "password_format": {"type": "string", "readOnly": True, "example": "scrypt",
                                "description": "scrypt, or the format of an imported hash (crypt, argon2, "
                                               "ssha512, ...) until the user's first login replaces it"},
        }},
        "MailboxUserCreate": {"type": "object", "required": ["email"],
                              "description": "Give password (hashed by the gateway) or password_hash (the hash "
                                             "of a previous mail system), not both.",
                              "additionalProperties": False, "properties": {
            "email": {"type": "string", "format": "email"},
            "password": PASSWORD,
            "password_hash": PASSWORD_HASH,
            "active": {"type": "boolean", "default": True},
            "greylist_score": SCORE, "add_header_score": SCORE, "reject_score": SCORE,
            "digest_interval": DIGEST,
        }},
        "MailboxUserUpdate": {"type": "object", "additionalProperties": False, "properties": {
            "password": PASSWORD,
            "password_hash": PASSWORD_HASH,
            "active": {"type": "boolean"},
            "greylist_score": SCORE, "add_header_score": SCORE, "reject_score": SCORE,
            "digest_interval": DIGEST,
        }},
        "ListEntry": {"type": "object", "properties": {
            "id": ID,
            "list_type": {"type": "string", "enum": ["allow", "block"]},
            "value": {"type": "string", "description": "Normalised sender pattern"},
            "comment": {"type": "string"},
            "created_at": TIMESTAMP,
        }},
        "ListEntryCreate": {"type": "object", "required": ["list_type", "value"],
                            "additionalProperties": False, "properties": {
            "list_type": {"type": "string", "enum": ["allow", "block"]},
            "value": {"type": "string", "example": "*@partner.example",
                      "description": "user@example.org, *@example.org, @example.org or example.org"},
            "comment": {"type": "string"},
        }},
    }


def _domain_properties(score, create=False):
    return {
        "description": {"type": "string", "maxLength": 255},
        "active": {"type": "boolean", "default": True} if create else {"type": "boolean"},
        "destination_host": {"type": "string", "description": "Downstream server: hostname or IP address",
                             "example": "mail.internal.example"},
        "destination_port": {"type": "integer", "minimum": 1, "maximum": 65535, **({"default": 25} if create else {})},
        "use_mx": {"type": "boolean", "description": "Look up the MX records of destination_host"},
        "recipient_check": {"type": "string", "enum": list(RECIPIENT_CHECKS),
                            "description": "any: accept all, list: only the domain's recipients, verify: ask the "
                                           "downstream server, directory: the domain's recipients, synchronised "
                                           "from directory_id"},
        "directory_id": {"type": "integer", "nullable": True,
                         "description": "The directory of recipient_check directory (GET /directories)"},
        "quarantine_enabled": {"type": "boolean"},
        "link_protection": {"type": "boolean", "description": "Rewrite the links of inbound mail to be checked when "
                                                              "clicked"},
        "digest_interval": {**DIGEST, "description": "Quarantine digest interval, null = global setting"},
        "greylist_score": score, "add_header_score": score, "reject_score": score,
    }


def _configuration_schemas():
    list_value = {"type": "string", "example": "*@partner.example",
                  "description": "Sender: user@example.org, *@example.org, @example.org or example.org; "
                                 "IP: address or network"}
    return {
        "DestinationTest": {"type": "object", "properties": {
            "host": {"type": "string"}, "port": {"type": "integer"},
            "ok": {"type": "boolean", "description": "Connected and MAIL FROM:<> accepted"},
            "error": {"type": "string", "nullable": True}, "seconds": {"type": "number"},
            "starttls": {"type": "boolean", "nullable": True},
            "tls": {"type": "object", "nullable": True, "properties": {
                "version": {"type": "string"}, "cipher": {"type": "string"}, "trusted": {"type": "boolean"}}},
            "tls_error": {"type": "string", "nullable": True, "description": "Why the certificate is not trusted"},
            "address": {"type": "string", "nullable": True, "enum": ["accepted", "deferred", "refused", None]},
            "accepts_any": {"type": "boolean", "nullable": True},
            "steps": {"type": "array", "items": {"type": "object", "properties": {
                "command": {"type": "string"}, "code": {"type": "integer"}, "text": {"type": "string"}}}},
        }},
        "Domain": {"type": "object", "properties": {
            "id": ID, "name": {"type": "string", "readOnly": True},
            **_domain_properties(DOMAIN_SCORE),
            "dkim_selector": {"type": "string", "nullable": True, "readOnly": True},
            "created_at": TIMESTAMP,
        }},
        "DomainCreate": {"type": "object", "required": ["name", "destination_host"], "additionalProperties": False,
                         "properties": {"name": {"type": "string", "example": "example.com"},
                                        **_domain_properties(DOMAIN_SCORE, create=True)}},
        "DomainUpdate": {"type": "object", "additionalProperties": False,
                         "properties": _domain_properties(DOMAIN_SCORE)},
        "Recipient": {"type": "object", "properties": {
            "id": ID, "address": {"type": "string", "format": "email"},
            "source": {"type": "string", "enum": ["manual", "directory"], "readOnly": True,
                       "description": "directory: added and removed by the directory synchronisation"},
            "created_at": TIMESTAMP}},
        "RecipientsAdd": {"type": "object", "required": ["addresses"], "additionalProperties": False, "properties": {
            "addresses": {"type": "array", "items": {"type": "string"}, "example": ["alice@example.com", "bob"],
                          "description": "Addresses of the domain, or local parts"}}},
        "RecipientsResult": {"type": "object", "properties": {
            "added": {"type": "array", "items": {"type": "string"}},
            "skipped": {"type": "integer", "description": "Already present"},
            "invalid": {"type": "array", "items": {"type": "string"},
                        "description": "Invalid or of another domain, ignored"}}},
        "FilterListEntry": {"type": "object", "properties": {
            "id": ID,
            "list_type": {"type": "string", "enum": list(LIST_TYPES)},
            "kind": {"type": "string", "enum": list(LIST_KINDS)},
            "value": {"type": "string", "description": "Normalised sender pattern or network"},
            "comment": {"type": "string"},
            "created_at": TIMESTAMP}},
        "FilterListEntryCreate": {"type": "object", "required": ["list_type", "kind", "value"],
                                  "additionalProperties": False, "properties": {
            "list_type": {"type": "string", "enum": list(LIST_TYPES)},
            "kind": {"type": "string", "enum": list(LIST_KINDS)},
            "value": list_value,
            "comment": {"type": "string", "maxLength": 255}}},
        "Dkim": {"type": "object", "properties": {
            "selector": {"type": "string"}, "key_size": {"type": "integer"}, "created_at": TIMESTAMP,
            "dns_name": {"type": "string", "example": "sf202610._domainkey.example.com"},
            "dns_value": {"type": "string", "description": "TXT record value"}}},
        "DkimSet": {"type": "object", "required": ["selector"], "additionalProperties": False, "properties": {
            "selector": {"type": "string", "pattern": "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"},
            "key_size": {"type": "integer", "enum": [2048, 4096], "description": "Generate a key"},
            "private_key": {"type": "string", "writeOnly": True,
                            "description": "Import this unencrypted RSA key (PEM) instead"}}},
        "Directory": {"type": "object", "properties": {
            "id": ID, **{k: v for k, v in DIRECTORY.items() if k not in ("bind_password", "client_secret")},
            "bind_password_set": {"type": "boolean"}, "client_secret_set": {"type": "boolean"},
            "domains": {"type": "array", "items": {"type": "string"}, "readOnly": True,
                        "description": "Domains with this directory_id"},
            "synced_at": {**TIMESTAMP, "nullable": True}, "sync_error": {"type": "string", "nullable": True},
            "sync_count": {"type": "integer", "nullable": True, "description": "Recipients of the domains"},
            "created_at": TIMESTAMP}},
        "DirectoryCreate": {"type": "object", "required": ["name", "kind"], "additionalProperties": False,
                            "properties": DIRECTORY},
        "DirectoryUpdate": {"type": "object", "additionalProperties": False, "properties": DIRECTORY},
        "DirectoryTest": {"type": "object", "properties": {
            "total": {"type": "integer", "description": "Addresses in the directory"},
            "domains": {"type": "object", "additionalProperties": {"type": "integer"},
                        "description": "Addresses per domain using the directory"},
            "sample": {"type": "array", "items": {"type": "string"}}}},
        "DirectorySync": {"type": "object", "properties": {
            "domains": {"type": "object", "additionalProperties": {"type": "object", "properties": {
                "added": {"type": "integer"}, "removed": {"type": "integer"}, "total": {"type": "integer"}}}},
            "directory": _ref("Directory")}},
        "ContentRule": {"type": "object", "properties": {"id": ID, **CONTENT_RULE, "created_at": TIMESTAMP}},
        "ContentRuleCreate": {"type": "object", "required": ["name", "field", "value"], "additionalProperties": False,
                              "properties": CONTENT_RULE},
        "ContentRuleUpdate": {"type": "object", "additionalProperties": False, "properties": CONTENT_RULE},
        "ProtectedPerson": {"type": "object", "properties": {"id": ID, **PERSON, "created_at": TIMESTAMP}},
        "ProtectedPersonCreate": {"type": "object", "required": ["name"], "additionalProperties": False,
                                  "properties": PERSON},
        "ProtectedPersonUpdate": {"type": "object", "additionalProperties": False, "properties": PERSON},
        "DlpRule": {"type": "object", "properties": {"id": ID, **DLP_RULE, "created_at": TIMESTAMP}},
        "DlpRuleCreate": {"type": "object", "required": ["name", "detector"], "additionalProperties": False,
                          "properties": DLP_RULE},
        "DlpRuleUpdate": {"type": "object", "additionalProperties": False, "properties": DLP_RULE},
        "DlpTestResult": {"type": "object", "properties": {"results": {"type": "array", "items": {
            "type": "object", "properties": {
                "id": ID, "name": {"type": "string"}, "active": {"type": "boolean"},
                "applies": {"type": "boolean", "description": "The rule is for the sender given"},
                "count": {"type": "integer", "description": "Different values found"},
                "values": {"type": "array", "items": {"type": "string"}, "description": "At most 10"},
                "matched": {"type": "boolean"}}}}}},
        "OutboundLimit": {"type": "object", "properties": {
            "id": ID, **OUTBOUND_LIMIT, "created_at": TIMESTAMP}},
        "OutboundLimitCreate": {"type": "object", "required": ["sender", "max_recipients"],
                                "additionalProperties": False, "properties": OUTBOUND_LIMIT},
        "OutboundLimitUpdate": {"type": "object", "additionalProperties": False,
                                "properties": {k: OUTBOUND_LIMIT[k] for k in ("max_recipients", "period", "comment")}},
        "OutboundSenders": {"type": "object", "properties": {
            "counts": {"type": "array", "items": {"type": "object", "properties": {
                "sender": {"type": "string"}, "count": {"type": "integer"}, "period": PERIOD,
                "limit": {"type": "integer", "nullable": True,
                          "description": "The limit that applies in this period, if any"}}}},
            "deferred": {"type": "array", "items": {"type": "object", "properties": {
                "sender": {"type": "string"}, "at": {"type": "integer", "description": "Unix time"},
                "count": {"type": "integer", "description": "Deferred messages"},
                "limit": {"type": "integer"}, "period": PERIOD}}}}},
        "RelayNetwork": {"type": "object", "properties": {
            "id": ID, "cidr": {"type": "string", "example": "192.0.2.0/24"}, "comment": {"type": "string"},
            "created_at": TIMESTAMP}},
        "RelayNetworkCreate": {"type": "object", "required": ["cidr"], "additionalProperties": False,
                               "properties": {"cidr": {"type": "string", "example": "192.0.2.0/24"},
                                              "comment": {"type": "string", "maxLength": 255}}},
        "Hostname": {"type": "object", "properties": {
            "hostname": {"type": "string", "example": "mx.example.com"},
            "pending": {"type": "string", "nullable": True, "description": "Requested name not applied yet"},
            "cluster": {"type": "boolean", "description": "Cluster members cannot change their name here"},
            "warnings": {"type": "array", "items": {"type": "string"},
                         "description": "After a change: why the name does not work yet (DNS)"}}},
        "IpFamily": {"type": "object", "required": ["enabled"], "properties": {
            "enabled": {"type": "boolean"},
            "method": {"type": "string", "enum": ["manual", "auto"],
                       "description": "auto: DHCP (IPv4), SLAAC/DHCPv6 (IPv6)"},
            "addresses": {"type": "array", "items": {"type": "string"}, "example": ["192.0.2.10/24"],
                          "description": "With prefix length; manual only"},
            "gateway": {"type": "string"}, "dns": {"type": "array", "items": {"type": "string"}, "maxItems": 3}}},
        "IpConfig": {"type": "object", "required": ["ipv4", "ipv6"], "additionalProperties": False,
                     "properties": {"device": {"type": "string", "description": "The interface (GET /ip-config: "
                                               "interfaces); default: the one with the default route"},
                                    "ipv4": _ref("IpFamily"), "ipv6": _ref("IpFamily")}},
        "IpInterface": {"type": "object", "properties": {
            "device": {"type": "string"}, "type": {"type": "string"}, "name": {"type": "string"},
            "uuid": {"type": "string"}, "default": {"type": "boolean", "description": "Has the default route"},
            "live4": {"type": "array", "items": {"type": "string"}},
            "live6": {"type": "array", "items": {"type": "string"}},
            "gateway4": {"type": "string"}, "gateway6": {"type": "string"},
            "ipv4": _ref("IpFamily"), "ipv6": _ref("IpFamily")}},
        "IpConfigState": {"type": "object", "properties": {
            "state": {"type": "object", "properties": {
                "device": {"type": "string"}, "name": {"type": "string"}, "uuid": {"type": "string"},
                "live4": {"type": "array", "items": {"type": "string"}},
                "live6": {"type": "array", "items": {"type": "string"}},
                "gateway4": {"type": "string"}, "gateway6": {"type": "string"},
                "ipv4": _ref("IpFamily"), "ipv6": _ref("IpFamily"),
                "interfaces": {"type": "array", "items": _ref("IpInterface"),
                               "description": "Every interface NetworkManager manages"},
                "others_enabled": {"type": "boolean",
                                   "description": "Another interface has an address: both families may be off here"},
                "managed_resolver": {"type": "boolean"}, "cluster": {"type": "boolean"}}},
            "change": {"type": "object", "nullable": True, "properties": {
                "state": {"type": "string", "enum": ["running", "ok", "failed", "stale"]},
                "outcome": {"type": "string", "enum": ["testing", "applied", "reverted", "refused", "stopped"]},
                "message": {"type": "string"}, "at": {"type": "integer"}, "log": {"type": "string"}}},
            "busy": {"type": "boolean"}}},
        "Tls": {"type": "object", "properties": {
            "settings": {"type": "object", "properties": {
                "hostname": {"type": "string"}, "mode": {"type": "string", "enum": ["letsencrypt", "manual"]},
                "extra_names": {"type": "array", "items": {"type": "string"}},
                "dns_challenge": {"type": "boolean"}, "https_min": TLS_MIN, "smtp_min": TLS_MIN,
                "cluster": {"type": "boolean"}}},
            "certificate": {"allOf": [_ref("TlsCertificate")], "nullable": True},
            "status": {"type": "object", "description": "Outcome of the last change of each kind (le_test, "
                                                         "le_apply, manual_apply, versions)",
                       "additionalProperties": {"type": "object", "properties": {
                           "state": {"type": "string", "enum": ["running", "ok", "failed", "stale"]},
                           "message": {"type": "string"}, "at": {"type": "integer"},
                           "names": {"type": "array", "items": {"type": "string"}}, "log": {"type": "string"}}}},
            "busy": {"type": "boolean"}}},
        "TlsCertificate": {"type": "object", "properties": {
            "subject": {"type": "string"}, "names": {"type": "array", "items": {"type": "string"}},
            "issuer": {"type": "string"}, "not_before": TIMESTAMP, "not_after": TIMESTAMP,
            "days_left": {"type": "integer"}, "key": {"type": "string"}, "self_signed": {"type": "boolean"},
            "chain_length": {"type": "integer"}, "fingerprint": {"type": "string"}}},
        "TlsCheck": {"type": "object", "properties": {
            "errors": {"type": "array", "items": {"type": "string"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "certificate": {"allOf": [_ref("TlsCertificate")], "nullable": True},
            "sha256": {"type": "string", "description": "Identifies the staged files (no errors only)"}}},
        "TlsNamesRequest": {"type": "object", "additionalProperties": False, "properties": {
            "names": {"type": "array", "items": {"type": "string"}, "example": ["mail.example.com"]}}},
        "TlsNames": {"type": "object", "properties": {"names": {"type": "array", "items": {"type": "string"}}}},
        "TlsSha": {"type": "object", "required": ["sha256"], "additionalProperties": False,
                   "properties": {"sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}},
        "TlsVersions": {"type": "object", "required": ["https_min", "smtp_min"], "additionalProperties": False,
                        "properties": {"https_min": TLS_MIN, "smtp_min": TLS_MIN}},
        "HostnameChange": {"type": "object", "required": ["hostname"], "additionalProperties": False,
                           "properties": {"hostname": {"type": "string", "example": "mx.example.com"}}},
        "Settings": {"type": "object", "properties": _settings_properties()},
        "SettingsUpdate": {"type": "object", "additionalProperties": False, "properties": _settings_properties()},
    }


def _settings_properties():
    return {
        "greylist_score": GLOBAL_SCORE, "add_header_score": GLOBAL_SCORE, "reject_score": GLOBAL_SCORE,
        "greylisting": {"type": "boolean", "description": "Defer unknown senders of mail scoring at least "
                                                         "greylist_score; off: the other thresholds decide"},
        "quarantine_retention_days": {"type": "integer", "minimum": 1, "maximum": 3650},
        "quarantine_max_size_mb": {"type": "integer", "minimum": 1, "maximum": 100},
        "quarantine_outbound": {"type": "boolean", "description": "Quarantine rejected mail from relay networks"},
        "require_admin_2fa": {"type": "boolean", "description": "Every administrator must use two-factor login"},
        "audit_retention_days": {"type": "integer", "minimum": 30, "maximum": 3650},
        "backup_keep": {"type": "integer", "minimum": 1, "maximum": 90, "description": "Scheduled backups kept"},
        "backup_include_mail_log": {"type": "boolean", "description": "Back up the mail log's messages"},
        "backup_include_quarantine": {"type": "boolean", "description": "Back up the quarantined messages"},
        "impersonation_name_score": {"type": "number", "minimum": 0, "maximum": 1000,
                                     "description": "Added for the name of a protected person; 0: off"},
        "impersonation_lookalike_score": {"type": "number", "minimum": 0, "maximum": 1000,
                                          "description": "Added for a domain imitating a protected one; 0: off"},
        "impersonation_spoof_score": {"type": "number", "minimum": 0, "maximum": 1000,
                                      "description": "Added for a protected From domain without DMARC, DKIM or "
                                                     "SPF passing; 0: off"},
        "impersonation_extra_domains": {"type": "string", "description": "More domains to protect, one per line"},
        "impersonation_exempt_domains": {"type": "string",
                                         "description": "Legitimate look-alike domains, one per line"},
        "user_reports_enabled": {"type": "boolean",
                                 "description": "Learn messages users forward to spam@ and ham@<hostname>"},
        "user_reports_confirm": {"type": "boolean", "description": "Reply to the reporter"},
        "user_reports_per_hour": {"type": "integer", "minimum": 1, "maximum": 10000},
        "journal_address": {"type": "string", "description": "Archive receiving a copy of every message; empty: off"},
        "journal_inbound": {"type": "boolean"}, "journal_outbound": {"type": "boolean"},
        "journal_rejected": {"type": "boolean", "description": "Also rejected and greylisted mail"},
        "journal_format": {"type": "string", "enum": ["envelope", "copy"],
                           "description": "envelope: report with sender and all recipients, original attached"},
        "siem_host": {"type": "string", "description": "SIEM receiving events; empty: none sent"},
        "siem_port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "siem_protocol": {"type": "string", "enum": ["udp", "tcp", "tls"]},
        "siem_format": {"type": "string", "enum": ["json", "rfc5424"]},
        "siem_verify_tls": {"type": "boolean"},
        "siem_mail_log": {"type": "boolean", "description": "Send every scanned message"},
        "siem_audit": {"type": "boolean", "description": "Send the audit log"},
        "alert_recipients": {"type": "string", "description": "Alert mail addresses, one per line"},
        "alert_deferred_count": {"type": "integer", "minimum": 1},
        "alert_deferred_hours": {"type": "integer", "minimum": 1, "maximum": 240},
        "alert_cert_days": {"type": "integer", "minimum": 1, "maximum": 90},
        "alert_backup_hours": {"type": "integer", "minimum": 1, "maximum": 720},
        "stats_retention_days": {"type": "integer", "minimum": 30, "maximum": 3650,
                                 "description": "Hourly statistics are kept this long"},
        "report_retention_days": {"type": "integer", "minimum": 7, "maximum": 3650,
                                  "description": "DMARC and TLS reports are kept this long"},
        "dmarc_send_reports": {"type": "boolean",
                               "description": "Send DMARC aggregate reports about received mail daily"},
        "hashcheck_mhr": {"type": "boolean", "description": "Look up attachments in Team Cymru's MHR (DNS)"},
        "hashcheck_mhr_percent": {"type": "integer", "minimum": 1, "maximum": 100,
                                  "description": "Malware from this share of antivirus engines"},
        "hashcheck_mhr_score": {"type": "number", "minimum": 0, "maximum": 1000},
        "hashcheck_mb_key": {"type": "string", "writeOnly": True,
                             "description": "MalwareBazaar Auth-Key; empty: off"},
        "hashcheck_mb_key_set": {"type": "boolean", "readOnly": True},
        "hashcheck_mb_score": {"type": "number", "minimum": 0, "maximum": 1000},
        "hashcheck_vt_key": {"type": "string", "writeOnly": True, "description": "VirusTotal API key; empty: off"},
        "hashcheck_vt_key_set": {"type": "boolean", "readOnly": True},
        "hashcheck_vt_engines": {"type": "integer", "minimum": 1, "maximum": 100,
                                 "description": "Malware from this many engines"},
        "hashcheck_vt_score": {"type": "number", "minimum": 0, "maximum": 1000},
        "hashcheck_vt_per_minute": {"type": "integer", "minimum": 1, "maximum": 1000,
                                    "description": "VirusTotal requests per minute (free key: 4)"},
        "link_protection_exempt_hosts": {"type": "string",
                                         "description": "Hosts whose links are not rewritten, one per line"},
        "link_protection_block_domains": {"type": "string",
                                          "description": "Sites blocked when clicked, one per line"},
        "link_protection_allow_continue": {"type": "boolean",
                                           "description": "The warning page lets recipients open the link"},
        "link_protection_days": {"type": "integer", "minimum": 1, "maximum": 3650,
                                 "description": "Rewritten links work this long"},
        "attachment_blocked_extensions": {"type": "string", "example": "exe js lnk",
                                          "description": "Rejected file extensions, separated by spaces"},
        "attachment_scan_archives": {"type": "boolean", "description": "Also the files inside archives"},
        "attachment_block_encrypted": {"type": "boolean", "description": "Reject password-protected archives"},
        "attachment_outbound": {"type": "boolean", "description": "Also outbound mail from the relay networks"},
        "attachment_exempt_senders": {"type": "string",
                                      "description": "Sender addresses and domains the policy does not apply "
                                                     "to, one per line"},
        "outbound_limit": {"type": "integer", "minimum": 0, "maximum": MAX_OUTBOUND_LIMIT,
                           "description": "Recipients per period of each sender of the relay networks; 0: none"},
        "outbound_limit_period": PERIOD,
        "smtp_connection_count_limit": {"type": "integer", "minimum": 0, "maximum": 1000,
                                        "description": "Simultaneous SMTP connections per sending host (Postfix, "
                                                       "per node); 0: no limit. Default 50"},
        "smtp_connection_rate_limit": {"type": "integer", "minimum": 0, "maximum": 100000,
                                       "description": "SMTP connections per minute per sending host; 0: none"},
        "smtp_message_rate_limit": {"type": "integer", "minimum": 0, "maximum": 100000,
                                    "description": "Messages per minute per sending host; 0: none"},
        "smtp_recipient_rate_limit": {"type": "integer", "minimum": 0, "maximum": 100000,
                                      "description": "Recipients per minute per sending host; 0: none"},
        "inbound_ip_limit": {"type": "integer", "minimum": 0, "maximum": MAX_OUTBOUND_LIMIT,
                             "description": "Inbound messages per period from one IP address (all nodes); 0: none"},
        "inbound_ip_period": PERIOD,
        "inbound_rcpt_limit": {"type": "integer", "minimum": 0, "maximum": MAX_OUTBOUND_LIMIT,
                               "description": "Inbound messages per period to one recipient; 0: none"},
        "inbound_rcpt_period": PERIOD,
        "inbound_bounce_limit": {"type": "integer", "minimum": 0, "maximum": MAX_OUTBOUND_LIMIT,
                                 "description": "Bounces (empty sender) per period to one recipient; 0: none"},
        "inbound_bounce_period": PERIOD,
        "rate_limit_exempt": {"type": "string", "description": "Networks or addresses without rate limits, one per "
                                                               "line (the relay networks never have any)"},
        "virus_scanning": {"type": "boolean", "description": "Scan mail with ClamAV"},
        "ptr_check": {"type": "string", "enum": ["off", "defer", "reject"],
                      "description": "Hosts without a reverse DNS name (PTR): accept, defer (450) or reject (550). "
                                     "Relay networks and the global allow list's addresses are exempt"},
        "mailbox_auto_create": {"type": "boolean",
                                "description": "Create mailbox users for recipients of quarantined mail that exist "
                                               "on the destination server, and mail them a link to set a password"},
        "mailbox_invite_days": {"type": "integer", "minimum": 1, "maximum": 30,
                                "description": "Days a link to set a password is valid"},
        "admin_allowed_networks": {"type": "string",
                                   "description": "Networks or addresses administrators may log in from, one per "
                                                  "line; empty: any. API keys are not affected"},
        "timezone": {"type": "string", "description": "IANA time zone of the servers and the web interface "
                                                      "(e.g. Europe/Berlin); empty: the system's, shown as UTC"},
        "session_lifetime_minutes": {"type": "integer", "minimum": 5, "maximum": 10080,
                                     "description": "A login of the web interface ends after this time, however "
                                                    "active it is"},
        "login_max_failures": {"type": "integer", "minimum": 1, "maximum": 1000,
                               "description": "Failed logins from one address before further attempts are refused"},
        "login_max_account_failures": {"type": "integer", "minimum": 1, "maximum": 10000,
                                       "description": "Failed logins for one account, from any address"},
        "login_failure_window_minutes": {"type": "integer", "minimum": 1, "maximum": 1440,
                                         "description": "Failed logins count this long"},
        "http_redirect": {"type": "boolean", "description": "nginx redirects HTTP to HTTPS (ACME challenges "
                                                            "excepted)"},
        "rspamd_ui_networks": {"type": "string", "description": "Networks or addresses that may open the Rspamd "
                                                                "UI at /rspamd/, one per line; empty: any"},
        "trusted_proxies": {"type": "string", "description": "Reverse proxies in front of nginx whose "
                                                             "X-Forwarded-For header is trusted, one per line"},
        "spamhaus_dqs_key": {"type": "string", "writeOnly": True, "pattern": "^[A-Za-z0-9]{0,64}$",
                             "description": "Spamhaus Data Query Service key for Postfix and Rspamd; empty: the "
                                            "public mirrors"},
        "spamhaus_dqs_key_set": {"type": "boolean", "readOnly": True},
        "postfix_log_lines": {"type": "integer", "minimum": 100, "maximum": 1000000,
                              "description": "Lines of the Postfix log kept for the Logs page"},
        "update_channel": {"type": "string", "enum": ["release", "main"],
                           "description": "update.sh moves to the newest release or to the newest commit of "
                                          "update_branch"},
        "update_branch": {"type": "string", "description": "The branch of the main channel"},
        "watchdog_notify_email": {"type": "string",
                                  "description": "Recipients of the watchdog's notices, one per line"},
        "watchdog_notify_webhook": {"type": "string", "description": "http(s) URL the notices are POSTed to"},
        "watchdog_notify_webhook_body": {"type": "string",
                                         "description": "JSON body of the webhook; ${SUBJECT} and ${BODY} are "
                                                        "replaced"},
        "watchdog_subject": {"type": "string", "description": "Subject of the notices, followed by the service"},
        "watchdog_notify_start": {"type": "boolean", "description": "A notice when the watchdog starts"},
        "watchdog_notify_ban": {"type": "boolean", "description": "A notice when netfilter bans an address"},
        "maillog_retention_days": {"type": "integer", "minimum": 1, "maximum": MAX_MAILLOG_DAYS},
        "max_message_size_mb": {"type": "integer", "minimum": 1, "maximum": MAX_MESSAGE_MB,
                                "description": "Postfix refuses larger messages (inbound and outbound)"},
        "max_attachment_size_mb": {"type": "integer", "minimum": 0, "maximum": MAX_MESSAGE_MB,
                                   "description": "Rspamd rejects messages with a larger attachment (decoded "
                                                  "size); 0: no limit. At most max_message_size_mb"},
        "digest_interval": {"type": "string", "enum": list(DIGEST_INTERVALS)},
        "digest_sender": {"type": "string", "description": "Empty: the gateway's default sender"},
        "digest_token_days": {"type": "integer", "minimum": 1, "maximum": 30},
    }


def _operations_schemas():
    item = {
        "id": ID, "direction": {"type": "string", "enum": ["inbound", "outbound"]},
        "queue_id": {"type": "string"}, "subject": {"type": "string"}, "sender": {"type": "string"},
        "rcpt": {"type": "string"}, "domain": {"type": "string"}, "score": {"type": "number"},
        "action": {"type": "string"}, "ip": {"type": "string"}, "size": {"type": "integer"},
        "virus": {"type": "boolean"}, "created_at": TIMESTAMP,
    }
    notes = {"type": "array", "items": {"type": "string"}}
    symbols = {"type": "array", "items": {"type": "object", "properties": {
        "name": {"type": "string"}, "score": {"type": "number"},
        "options": {"type": "array", "items": {"type": "string"}}}}}
    preview = {"type": "object", "properties": {
        "headers": {"type": "array", "items": {"type": "array", "items": {"type": "string"}},
                    "description": "[name, value] pairs"},
        "body": {"type": "string", "description": "Text preview"},
        "truncated": {"type": "boolean"},
        "attachments": {"type": "array", "items": {"type": "object", "properties": {
            "name": {"type": "string"}, "type": {"type": "string"}, "size": {"type": "integer"}}}}}}
    entry = {
        "id": ID, "direction": {"type": "string", "enum": ["inbound", "outbound"]},
        "queue_id": {"type": "string"}, "message_id": {"type": "string"}, "subject": {"type": "string"},
        "sender": {"type": "string", "description": "Envelope sender"},
        "header_from": {"type": "string"}, "rcpts": {"type": "array", "items": {"type": "string"}},
        "score": {"type": "number"}, "action": {"type": "string"}, "ip": {"type": "string"},
        "size": {"type": "integer"}, "scan_ms": {"type": "integer"},
        "virus": {"type": "boolean"}, "created_at": TIMESTAMP,
        "requeued_at": {**TIMESTAMP, "nullable": True}, "requeued_by": {"type": "string", "nullable": True},
        "delivery": DELIVERY_STATE,
        "refused": {"type": "string", "nullable": True,
                    "description": "Postfix's reason when it refused the recipient (it does not exist): then there "
                                   "is no message, score or symbols"},
    }
    return {
        "MailLogEntry": {"type": "object", "properties": entry},
        "Statistics": {"type": "object", "properties": {
            "range": {"type": "string"}, "bucket_hours": {"type": "integer"}, "start": TIMESTAMP, "end": TIMESTAMP,
            "totals": {"$ref": "#/components/schemas/StatisticsCounts"},
            "buckets": {"type": "array", "items": {"allOf": [{"$ref": "#/components/schemas/StatisticsCounts"},
                                                             {"type": "object", "properties": {"start": TIMESTAMP}}]}},
            "top_domains": {"type": "array", "items": {"type": "object", "properties": {
                "domain": {"type": "string"}, "messages": {"type": "integer"}}}}}},
        "StatisticsCounts": {"type": "object", "properties": {
            "total": {"type": "integer"}, "clean": {"type": "integer"}, "spam": {"type": "integer"},
            "deferred": {"type": "integer"}, "rejected": {"type": "integer"}, "viruses": {"type": "integer"},
            "bytes": {"type": "integer", "description": "Only in totals"},
            "scan_ms": {"type": "integer", "nullable": True,
                        "description": "rspamd's average scan time per message (milliseconds), null without one"},
            "delivery_s": {"type": "number", "nullable": True,
                           "description": "Average time from a message's arrival until the next server accepted "
                                          "it, per delivered recipient (seconds), null without one"},
            "delivered": {"type": "integer", "description": "Recipients delivered"}}},
        "DmarcReport": {"type": "object", "properties": {
            "id": ID, "org": {"type": "string"}, "report_id": {"type": "string"}, "domain": {"type": "string"},
            "policy": {"type": "string"}, "begin": TIMESTAMP, "end": TIMESTAMP, "messages": {"type": "integer"},
            "passed": {"type": "integer", "description": "Messages passing aligned DKIM or SPF"},
            "records": {"type": "array", "items": {"type": "object", "properties": {
                "source_ip": {"type": "string"}, "count": {"type": "integer"}, "disposition": {"type": "string"},
                "dkim": {"type": "string"}, "spf": {"type": "string"}, "header_from": {"type": "string"}}}}}},
        "TlsReport": {"type": "object", "properties": {
            "id": ID, "org": {"type": "string"}, "report_id": {"type": "string"}, "domain": {"type": "string"},
            "policy_type": {"type": "string"}, "begin": TIMESTAMP, "end": TIMESTAMP,
            "successful": {"type": "integer"}, "failed": {"type": "integer"},
            "failures": {"type": "array", "items": {"type": "object", "properties": {
                "result": {"type": "string"}, "mx": {"type": "string"}, "sender": {"type": "string"},
                "count": {"type": "integer"}}}}}},
        "HashDetection": {"type": "object", "properties": {
            "at": {"type": "integer", "description": "Unix time"}, "sha256": {"type": "string"},
            "file": {"type": "string"}, "source": {"type": "string", "enum": ["mhr", "mb", "vt"]},
            "detail": {"type": "string"}, "from": {"type": "string"}, "rcpt": {"type": "string"},
            "qid": {"type": "string"}}},
        "LinkVerdict": {"type": "object", "properties": {
            "blocked": {"type": "boolean"}, "host": {"type": "string"},
            "reason": {"type": "string", "nullable": True}}},
        "LinkClick": {"type": "object", "properties": {
            "id": {"type": "string"}, "url": {"type": "string"}, "host": {"type": "string"},
            "at": {"type": "integer", "description": "Unix time"}, "blocked": {"type": "boolean"},
            "reason": {"type": "string", "nullable": True}, "ip": {"type": "string"}}},
        "Backup": {"type": "object", "properties": {
            "name": {"type": "string"}, "kind": {"type": "string", "enum": ["manual", "scheduled"]},
            "created_at": TIMESTAMP, "size": {"type": "integer", "description": "Bytes"},
            "hostname": {"type": "string"},
            "quarantine": {"type": "boolean", "description": "Holds the quarantined messages"},
            "mail_log": {"type": "boolean", "description": "Holds the mail log's messages"},
            "valkey": {"type": "boolean", "description": "Holds Valkey's data (Bayes, fuzzy hashes, bans)"},
            "readable": {"type": "boolean", "description": "Its manifest could be read"}}},
        "Cluster": {"type": "object", "properties": {
            "cluster": {"type": "boolean", "description": "false: a single gateway (then only setup, busy and "
                                                          "addresses: creating or joining a cluster)"},
            "self": {"type": "string", "description": "The node that answered"},
            "level": {"type": "string", "enum": ["ok", "warning", "critical"]},
            "votes": {"type": "object", "properties": {
                "total": {"type": "integer"}, "quorum": {"type": "integer", "description": "Needed for a majority"},
                "present": {"type": "integer", "description": "In the primary database component"}}},
            "valkey_master": {"type": "string", "nullable": True},
            "vip": {"type": "object", "nullable": True, "properties": {
                "address": {"type": "string"}, "holders": {"type": "array", "items": {"type": "string"}}}},
            "witness": {"type": "object", "nullable": True, "properties": {
                "name": {"type": "string"}, "address": {"type": "string"},
                "sentinel": {"type": "boolean", "nullable": True, "description": "Its Sentinel answers the nodes"},
                "arbitrator": {"type": "boolean", "nullable": True,
                               "description": "Counted in the database cluster's size"}}},
            "problems": {"type": "array", "items": {"type": "object", "properties": {
                "key": {"type": "string", "description": "e.g. node@mx2.example.com, valkey, witness"},
                "level": {"type": "string", "enum": ["warning", "critical"]}, "message": {"type": "string"}}}},
            "notices": {"type": "array", "items": {"type": "string"}},
            "members": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "address": {"type": "string"}, "self": {"type": "boolean"},
                "reporting": {"type": "boolean", "description": "Reported in the last minute"},
                "reported_at": TIMESTAMP, "age": {"type": "number", "nullable": True},
                "maintenance": {"type": "boolean", "description": "Requested"},
                "maintenance_applied": {"type": "boolean", "description": "In effect on the node"},
                "maintenance_since": TIMESTAMP, "promoting": {"type": "boolean"},
                "galera": {"type": "object", "nullable": True, "description": "state, status, size, ready, "
                                                                             "recv_queue, flow_paused"},
                "valkey": {"type": "object", "nullable": True, "description": "role, link, offset, priority, "
                                                                             "lag_bytes"},
                "sentinel": {"type": "object", "nullable": True, "description": "master, quorum, message"},
                "vip": {"type": "boolean", "nullable": True},
                "queue": {"type": "object", "nullable": True, "description": "counts per queue, oldest_deferred"},
                "services_down": {"type": "array", "items": {"type": "string"}},
                "disk": {"type": "array", "items": {"type": "object"}},
                "version": {"type": "string"}}}}}},
        "Backups": {"type": "object", "properties": {
            "items": {"type": "array", "items": _ref("Backup")},
            "busy": {"type": "boolean", "description": "A backup is being made or deleted"},
            "status": {"type": "object", "nullable": True, "description": "The last backup or deletion",
                       "properties": {"state": {"type": "string", "enum": ["running", "ok", "failed", "stale"]},
                                      "message": {"type": "string"}, "at": {"type": "integer"},
                                      "name": {"type": "string"}}}}},
        "AuditEntry": {"type": "object", "properties": {
            "id": ID, "at": TIMESTAMP, "actor": {"type": "string"}, "ip": {"type": "string"},
            "method": {"type": "string"}, "action": {"type": "string", "description": "Endpoint or cli.<command>"},
            "description": {"type": "string"}, "target": {"type": "string"},
            "outcome": {"type": "string", "enum": ["ok", "failed"]}, "message": {"type": "string"},
            "details": {"type": "object", "description": "Submitted fields without secrets"}}},
        "MailLogDetail": {"type": "object", "properties": {
            **entry, "symbols": symbols, "message": preview,
            "quarantine_ids": {"type": "array", "items": {"type": "integer"},
                               "description": "Quarantine items of the same message"},
            "deliveries": {"type": "object", "nullable": True, "properties": {
                "state": DELIVERY_STATE,
                "deliveries": {"type": "array", "items": _ref("Delivery"),
                               "description": "Each recipient's latest delivery attempt"},
                "expired_at": {**TIMESTAMP, "nullable": True,
                               "description": "Postfix gave up and returned the message to the sender"},
                "notices": {"type": "array", "description": "Notices Postfix sent the sender", "items": {
                    "type": "object", "properties": {
                        "kind": {"type": "string", "enum": ["bounce_notice", "delay_notice", "dsn_notice"]},
                        "queue_id": {"type": "string"}, "at": TIMESTAMP, "state": DELIVERY_STATE,
                        "deliveries": {"type": "array", "items": _ref("Delivery")}}}}}}}},
        "Delivery": {"type": "object", "properties": {
            "rcpt": {"type": "string"},
            "status": {"type": "string", "enum": ["sent", "deferred", "bounced"]},
            "dsn": {"type": "string", "example": "5.1.1"}, "relay": {"type": "string"},
            "detail": {"type": "string", "description": "The receiving server's answer"},
            "attempts": {"type": "integer"}, "first_at": TIMESTAMP, "last_at": TIMESTAMP}},
        "RequeueRequest": {"type": "object", "additionalProperties": False, "properties": {
            "rcpts": {"type": "array", "items": {"type": "string"},
                      "description": "Recipients to deliver to (default: all of the message's)"},
            "allow_virus": {"type": "boolean", "default": False,
                            "description": "Required to queue a message with a virus"}}},
        "RequeueResult": {"type": "object", "properties": {**entry, "notes": notes}},
        "QuarantineItem": {"type": "object", "properties": item},
        "QuarantineDetail": {"type": "object", "properties": {
            **item,
            "symbols": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "score": {"type": "number"},
                "options": {"type": "array", "items": {"type": "string"}}}}},
            "message": {"type": "object", "properties": {
                "headers": {"type": "array", "items": {"type": "array", "items": {"type": "string"}},
                            "description": "[name, value] pairs"},
                "body": {"type": "string", "description": "Text preview"},
                "truncated": {"type": "boolean"},
                "attachments": {"type": "array", "items": {"type": "object", "properties": {
                    "name": {"type": "string"}, "type": {"type": "string"}, "size": {"type": "integer"}}}}}}}},
        "ReleaseRequest": {"type": "object", "additionalProperties": False, "properties": {
            "learn_ham": {"type": "boolean", "default": False, "description": "Also learn the message as ham"},
            "allow_virus": {"type": "boolean", "default": False,
                            "description": "Required to release a message with a virus"},
            "allow_sender": SENDER_SCOPE_SCHEMA}},
        "BlockSenderRequest": {"type": "object", "required": ["scope"], "additionalProperties": False,
                               "properties": {
            "scope": {**SENDER_SCOPE_SCHEMA, "description": "The list the sender goes on: the recipient's own "
                                                            "(needs a mailbox user), its domain's, or the "
                                                            "global one"},
            "delete": {"type": "boolean", "default": True, "description": "Also delete the message"}}},
        "ReleaseResult": {"type": "object", "properties": {**item, "notes": notes}},
        "Notes": {"type": "object", "properties": {"notes": notes}},
        "Queue": {"type": "object", "properties": {
            "node": {"type": "string"}, "total": {"type": "integer"},
            "items": {"type": "array", "items": {"type": "object",
                                                 "description": "Postfix queue entry (postqueue -j)"}}}},
        "QueuedMessage": {"type": "object", "properties": {
            "queue_id": {"type": "string"}, "content": {"type": "string"}}},
        "QueueAction": {"type": "object", "required": ["action"], "additionalProperties": False, "properties": {
            "action": {"type": "string", "enum": ["flush", "deliver", "hold", "unhold", "delete", "delete_all"]},
            "ids": {"type": "array", "items": {"type": "string"}}}},
        "QueueActionResult": {"type": "object", "properties": {
            "node": {"type": "string"}, "action": {"type": "string"},
            "ids": {"type": "array", "items": {"type": "string"}}}},
        "Ban": {"type": "object", "properties": {
            "network": {"type": "string"},
            "until": {"type": "integer", "nullable": True, "description": "Unix time, null for permanent bans"},
            "permanent": {"type": "boolean"}, "unban_queued": {"type": "boolean"}}},
        "UnbanRequest": {"type": "object", "required": ["network"], "additionalProperties": False,
                         "properties": {"network": {"type": "string", "example": "203.0.113.0/24"}}},
        "Unban": {"type": "object", "properties": {
            "network": {"type": "string"}, "unban_queued": {"type": "boolean"}}},
    }


def build_spec():
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Crassostrea API",
            "version": "1.1",
            "description": (
                "Manage the Crassostrea gateway: domains, allow and block lists, settings, accounts, the "
                "quarantine, the mail log, the mail queue and bans.\n\n"
                "Authenticate with an API key created under **API keys** in the web interface, sent as "
                "`X-API-Key` header. Read-only keys may only use GET."),
            "contact": {"name": "Crassostrea", "url": "https://github.com/SnailShea/crassostrea"},
            "license": {"name": "GPL-3.0", "url": "https://www.gnu.org/licenses/gpl-3.0.html"},
        },
        "externalDocs": {"description": "Crassostrea documentation (also at /docs/ on the gateway, if deployed)",
                         "url": "https://github.com/SnailShea/crassostrea-docs"},
        "servers": [{"url": "/api/v1"}],
        "security": [{"ApiKey": []}],
        "tags": [
            {"name": "Domains", "description": "Protected domains, their recipients and DKIM keys"},
            {"name": "Allow & block lists", "description": "Global and per-domain lists of senders and IPs"},
            {"name": "Settings",
             "description": "Global thresholds, limits, quarantine and digests; relay networks; the hostname"},
            {"name": "IP addressing", "description": "Interface addresses and IP families (single gateway)"},
            {"name": "Certificates & TLS",
             "description": "Let's Encrypt or uploaded certificate, TLS versions (single gateway)"},
            {"name": "Quarantine", "description": "Rejected mail"},
            {"name": "Mail log", "description": "Every scanned message, to inspect and queue again"},
            {"name": "Audit log", "description": "Changes made in the web UI, through the API and on the command line"},
            {"name": "Content rules", "description": "Rules of the administrators for parts of messages"},
            {"name": "Impersonation", "description": "Protected people and the test of the impersonation "
                                                     "checks"},
            {"name": "Directories", "description": "Recipients of domains from LDAP, Active Directory or "
                                                   "Microsoft 365"},
            {"name": "Data loss prevention", "description": "Rules for outbound mail from the relay networks"},
            {"name": "Outbound limits", "description": "Recipients per minute, hour or day of the senders of "
                                                       "the relay networks"},
            {"name": "Rate limits", "description": "Inbound rate limits: the deferred senders and recipients "
                                                   "(the limits are settings)"},
            {"name": "Journaling", "description": "Copies of all mail for an archive"},
            {"name": "Monitoring", "description": "Alert checks (Prometheus metrics are at /metrics)"},
            {"name": "Cluster", "description": "Members of a cluster, their state, maintenance"},
            {"name": "Statistics", "description": "Scanned messages over time"},
            {"name": "Reports", "description": "DMARC and TLS reports received about the protected domains"},
            {"name": "Attachments", "description": "Hash lookups of attachments"},
            {"name": "Link protection", "description": "Clicks on the rewritten links of inbound mail"},
            {"name": "Backups", "description": "Backups of the configuration, certificates, database and Valkey"},
            {"name": "Mail queue", "description": "Postfix queue of the node that answers"},
            {"name": "Bans", "description": "Networks blocked by netfilter"},
            {"name": "Training", "description": "Teach Bayes and the fuzzy storage"},
            {"name": "Administrators", "description": "Accounts with full access to the web interface"},
            {"name": "Mailbox users", "description": "End users managing their own quarantine and filter settings"},
        ],
        "paths": {**_configuration_paths(), **_operations_paths(), **_account_paths()},
        "components": {
            "securitySchemes": {"ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
            "schemas": {
                "Error": {"type": "object", "required": ["error"], "properties": {
                    "error": {"type": "string"}, "field": {"type": "string"}}},
                **_account_schemas(), **_configuration_schemas(), **_operations_schemas(),
            },
        },
    }
