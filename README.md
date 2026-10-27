# Crassostrea

A spam filter gateway: an inbound spam and virus filter (smart host) for EL10
(AlmaLinux, Rocky Linux, RHEL 10), derived from the
[mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized) stack and
installed directly on the host: distribution packages and systemd units, no
containers.
It accepts mail for your domains, filters it, and relays clean mail to your
existing mail server. A Flask web interface manages it.

```
                 ┌────────────────────────── gateway ──────────────────────────┐
 internet ──25──▶│ postfix (postscreen) ──milter──▶ rspamd ── clamd, olefy     │──▶ downstream mail server
                 │      │ relay per domain              │ quarantine, settings  │    (Exchange, Dovecot, M365 …)
                 │      ▼                               ▼                       │
 admin ──443────▶│ nginx ──▶ web (Flask UI) ──▶ mysql, redis, rspamd controller │
                 └─────────────────────────────────────────────────────────────┘
```

## Features

- **Per-domain relaying**: each protected domain has its own downstream server
  (host and port, optional MX lookup).
- **Recipient validation** per domain: accept all, a managed recipient list, or
  SMTP call-ahead verification against the downstream server. Invalid recipients
  are rejected at SMTP time, so the gateway never sends backscatter. **Test
  destination** on the domain page checks the downstream server over SMTP
  (reachable, TLS and its certificate, a given recipient, whether it accepts
  any address) without sending anything.
- **Filtering**: Rspamd (Bayes, fuzzy hashes, DNSBL/URIBL, SPF/DKIM/DMARC/ARC
  checks, SpamAssassin rules, heuristics), ClamAV, Olefy (Office macros) and
  Postfix postscreen.
- **Spam thresholds**: global and per-domain values for greylist, mark as spam
  (`X-Spam-Flag: YES`) and reject.
- **Allow and block lists** (Lists & training → Allow list, Block list): global or per domain, by sender address or pattern
  (`user@example.org`, `*@example.org`) or by IP network. Allow entries are
  ignored when the sender fails its own DMARC/SPF policy (including SPF softfail
  and DMARC failures under `p=none`), and viruses are always rejected.
- **Impersonation** (Protection): extra spam score for inbound mail with the
  name of a protected person (managers, finance) on an outside address, a
  From domain imitating one of yours (look-alike characters such as `rn`/`m`,
  `0`/`o` or Cyrillic letters, typing errors, another suffix,
  `example-secure.com`, `example.com.evil.net`), or your own domain in From
  without DMARC, DKIM or SPF passing (also for domains with DMARC `p=none` or
  no record). Scores per check (at the reject threshold: rejected and
  quarantined), more domains to protect, legitimate look-alikes, and a test;
  also `/api/v1/protected-people`.
- **Link protection** (Protection, per domain): the links of inbound mail point
  to `https://<hostname>/l/<id>` and are checked when clicked against the
  Spamhaus DBL (DQS with the key of Settings), SURBL, URIBL and your own block
  list, so a site that turns malicious after delivery is still caught; a
  click on a blocked link shows a warning (optionally with a way on).
  Signed or encrypted mail, outbound mail and exempt hosts are left alone,
  and the mail log keeps the original. The URLs are kept in Valkey (90 days
  by default), so the gateway is no open redirector. The page lists recent
  clicks and checks a link; also `/api/v1/link-clicks`.
- **Attachments** (Protection): file extensions that are always rejected (a
  default list of executables, scripts, shortcuts and disk images; the last
  extension counts, so `invoice.pdf.exe` is an exe), also as files inside
  archives, optionally password-protected archives, optionally outbound mail
  too, with exempt senders. Rejected inbound mail goes to the quarantine.
  Rspamd's own extension scores, ClamAV and the macro check stay in place.
  **Hash lookups** on the same page: the hash of every attachment is looked
  up in Team Cymru's Malware Hash Registry (DNS, free), MalwareBazaar and
  VirusTotal (with API keys, which are kept in Valkey, not in map files),
  each adding a score; results are cached and VirusTotal requests are kept
  within the key's limit. Only hashes leave the gateway. Detections are
  listed there and through `/api/v1/hash-detections`. Sandboxing unknown
  files is not included.
- **Rate limits** (Protection): inbound limits per sending host in Postfix
  (simultaneous connections, connections, messages and recipients per
  minute, per node) and, counted in Valkey for all nodes, messages per
  sending IP, per recipient and bounces per recipient per minute, hour or day.
  Over a limit mail is deferred (4xx); exempt networks and the relay networks
  have none. The page lists the deferred servers and recipients with a reset.
- **Virus scanning and reverse DNS** (Settings → General): ClamAV scanning can
  be turned off and on without reinstalling (Rspamd skips the check, clamd
  keeps running). Hosts without a PTR record can be accepted, deferred (450)
  or rejected (550) by Postfix; the relay networks and the global allow list's
  addresses are exempt. A Spamhaus Data Query Service key (free for low
  volumes) makes Postfix and Rspamd query the DQS zones; without one they use
  the public mirrors, which refuse cloud providers' networks
  (`crassostrea-spamhaus.service` applies a change on every node).
- **Outbound limits** (Outbound): how many recipients each sender of the relay
  networks may send to per minute, hour or day, with limits for single
  addresses or the senders of a domain (0: none). Rspamd counts them in Valkey
  (shared by a cluster); over the limit mail is deferred with a 451, so the
  sending server retries later, and a message with more recipients than the
  limit is rejected. The page lists deferred senders and the busiest current
  counts and resets a sender. Off by default; also `/api/v1/outbound-limits`.
- **Content rules** (Protection): your own rules on the subject, From, envelope
  sender, recipients, any header, the text, links or attachment names
  (contains, is, or a regular expression), for inbound, outbound or all mail:
  add a score (negative to favour), reject (inbound mail is quarantined), or
  deliver with `X-Content-Rule`. Checked before the other filters, with a
  test on a pasted message; also `/api/v1/content-rules`.
- **Data loss prevention** (Outbound): rules for outbound mail from the relay
  networks that find payment card numbers (Luhn check), IBANs (checksum), US
  social security numbers, keywords or a regular expression in the subject,
  the text and text attachments (CSV, JSON, XML; not Office documents or
  PDFs), with a minimum number of different matches and optionally only for a
  sender or domain. A match rejects the message (the sender gets the rule's
  name), rejects it and keeps it in the outbound quarantine for release, or
  delivers it with `X-DLP-Match`. The page tests the rules on a pasted text;
  also `/api/v1/dlp-rules`.
- **Recipients from a directory** (Domains → Directories): LDAP servers
  (Active Directory, OpenLDAP; LDAPS or STARTTLS, several servers for
  failover, paged searches) or Microsoft 365 (Microsoft Graph with an app
  registration: User.Read.All, Group.Read.All). Every 15 minutes the
  addresses (`mail`, the `smtp:` entries of `proxyAddresses`, or other
  attributes) are copied to the recipient lists of the domains whose
  validation is "Only recipients from a directory"; Postfix only reads those
  lists, so mail keeps flowing while the directory is down. A
  synchronisation that finds nothing or would remove more than half of a
  domain's recipients is refused until forced. Test and synchronise from the
  page, with `flask --app crassostrea sync-directories` or `/api/v1/directories`.
- **Reporting spam from the mail client** (Lists & training → Training): users forward
  a message as an attachment to `spam@<hostname>` or `ham@<hostname>` (or set
  them as the reporting mailbox of the Outlook / Microsoft 365 Report
  button), and the attached messages are learned. Only users of the
  protected domains can report (from a relay network, or passing SPF or with
  a DKIM signature of their domain), with a limit per hour and an optional
  confirmation; the page lists recent reports. Off by default.
- **Quarantine**: rejected mail is stored per recipient. You can release it,
  release and learn it as ham, learn it as spam, download it or delete it.
  Retention and maximum size are configurable.
- **Statistics** (Dashboard): scanned messages per hour by outcome (clean, marked as spam,
  greylisted/deferred, rejected) and viruses, for the last 24 hours, 7 or 30
  days or 12 months, per domain and direction, with the busiest domains;
  domain administrators see their domains.
  Counted as mail is logged and kept two years by default (much longer than
  the mail log); filled from the mail log once after an update. Also
  `/api/v1/statistics`.
- **Journaling** (Mail log → Journaling): a copy of every accepted inbound and/or outbound
  message (optionally rejected ones too) to an archive address (MailStore,
  an Exchange or Microsoft 365 journal mailbox, ...): a journal report with
  the envelope sender and all recipients, Bcc included, and the original
  attached unchanged, or a plain copy. Sent by `crassostrea-journal.service`
  past the spam filter, queued in Valkey while the archive is away.
- **DMARC & TLS reports** (Mail → DMARC & TLS reports): publish `rua=mailto:reports@<hostname>` in
  a domain's DMARC and TLS-RPT records (the page shows the records,
  including the `_report._dmarc` authorisation in the gateway's zone, and
  checks them). The gateway accepts that address, unpacks the zip/gzip
  reports and shows per domain how much mail passes DMARC, which sources
  fail it (forgeries, or your own services still missing DKIM/SPF), and the
  TLS failures other providers had reaching your MX; kept 180 days by
  default, also `/api/v1/reports/...`. Optionally the gateway sends DMARC
  aggregate reports about the mail it receives (daily, rspamd). Sending
  TLS reports needs Postfix 3.10.
- **Mailbox users** (Users → Mailbox users): end users log in with their e-mail address and can view,
  release or delete inbound quarantined mail addressed to them. They cannot release
  viruses, train the filter, or see outbound quarantine or other addresses.
  Administrators open one mailbox's quarantine from the mailbox users pages
  (`/quarantine/?user=`, API `?mailbox=`) and can mail a user a one-time link
  to set a password; users ask for one themselves with "Forgot your
  password?". **Release & allow sender** and **Block sender & delete** list the
  sender in the same step (the recipient's own list, the domain's or the global
  one), and a message's page explains in plain words why it was held back.
- **Account import**: `POST /api/v1/mailbox-users` takes `password_hash`, the
  hash of the previous mail system (crypt(3) SHA-512/SHA-256/MD5/bcrypt/
  yescrypt, Argon2, `{SSHA512}`/`{SSHA256}`/`{SSHA}`, plain digests, PBKDF2,
  with or without Dovecot/LDAP scheme prefixes); the first login replaces it
  with scrypt.
- **Accounts for recipients** (optional, Settings → General): a recipient of
  quarantined mail without an account gets one when the mailbox exists on the
  destination server (recipient list, directory, verified recipients, or an
  SMTP check that refuses accept-all servers), with a mail containing a link
  to set the password.
- **Per-user filter settings**: mailbox users (and admins on their behalf) set
  personal spam thresholds and allow/block lists for their address, including
  `+tag` sub-addresses. Domain block lists set by admins and global lists still
  take precedence.
- **Quarantine digests**: recipients get a periodic summary of newly quarantined
  mail with links that open their quarantine without an account (token links,
  valid for a configurable number of days). The interval is set globally, per
  domain by admins, and per user (never, hourly, daily or weekly). Opening a
  link changes nothing; release and delete need a button press, so link scanners
  can't trigger them.
- **Branding**: company name, logo, favicon, accent color, footer text and the
  default appearance (Settings → Branding). Used in the web UI, the login page,
  quarantine link pages and digest mails. Uploads are identified by content; SVGs
  with scripts or external references are refused and served sandboxed.
- **Light/dark mode**: a toggle on every page cycles system → light → dark. The
  choice is stored in a cookie so pages render in the right theme immediately.
- **REST API** with Swagger UI at `/api/docs`, covering what the web UI
  manages: domains (with recipients, allow/block lists and DKIM keys), global
  allow/block lists, relay networks, global settings, administrators and
  mailbox users (with their settings and personal lists), the quarantine
  (list, view, download, release, learn, delete), the mail log (list, view,
  download, queue again), the mail queue, bans and Bayes/fuzzy training. Only branding is UI-only. Authentication uses API keys
  created under **API keys** (read-only or read/write, optionally limited to
  source networks).
- **Outbound quarantine**: rejected mail from relay networks is quarantined
  separately and only administrators can see it (can be disabled under Settings).
- **DKIM signing** of outbound mail: generate or import a key per domain, and the UI
  shows the DNS record. From, To, Subject, Reply-To and similar headers are
  oversigned. Released outbound quarantine mail is signed as well.
- **Release header**: released mail carries `X-Quarantine-Released` (prepended
  without changing anything else, so the sender's DKIM signature stays valid).
  Copies of this header arriving with incoming mail are removed so it can't be
  forged.
- **Training**: upload or paste misclassified messages to train Bayes and the
  local fuzzy storage.
- **Mail log**: every message scanned for the protected domains and from the
  relay networks, and the recipients Postfix refused because they do not exist
  (with its reason; `logship` reports them from the Postfix log), with search
  and filters (domain, direction, action, refused recipients, delivery). Each
  message shows its delivery per recipient (delivered, deferred or bounced,
  with the receiving server's answer) and the notices the gateway sent the
  sender. Each
  message opens with its details, the score breakdown (every rule with its
  score and details), the text, attachments and headers, and links to its
  quarantine items and Postfix log lines. Messages with an HTML body (here and
  in the quarantine) can switch between the plain text and the HTML, rendered
  sanitized in a sandboxed frame without scripts, links, forms or remote
  content; it can be downloaded or queued again
  to some or all of its recipients (without a second scan, marked with
  `X-Mail-Log-Requeued`). Messages are kept in full for 7 days by default, up
  to 31 (Settings → General). In a cluster the mail log is in the replicated
  database, so plan disk space on every node.
- **Two-factor login** for administrators: codes from an authenticator app
  (TOTP) and ten one-time recovery codes, set up on the account page. Settings
  can require it for every administrator; another administrator, the API
  (`POST /admins/{id}/reset-2fa`) or `flask --app crassostrea reset-2fa USER`
  on the server turns it off for someone who lost their phone. API keys are
  not affected.
- **Domain administrators** (System → Administrators): administrators
  limited to some domains. They see and manage only the mail of their
  domains: quarantine, mail log (re-queueing to their own recipients),
  their domains' settings (not adding or deleting domains), mailbox users,
  statistics and DMARC/TLS reports; system pages stay with the full
  administrators, of which at least one must remain. Also through the API
  (`role`, `domains`).
- **Administrator networks** (Settings → General): administrator logins only
  from the networks you list; sessions from elsewhere end. Mailbox users and
  API keys are not affected; `flask admin-networks --clear` undoes a lock-out.
- **Sign-in** (Settings → General): how long a login lasts (8 hours by
  default, however active the session is), and the failed logins allowed per
  client address (10) and per account from any address (30) within 15
  minutes before further attempts are refused.
- **Web server** (Settings → General): the redirect from HTTP to HTTPS (ACME
  challenges excepted), the networks that may open the Rspamd UI at
  `/rspamd/`, and the reverse proxies in front of the gateway whose
  `X-Forwarded-For` is trusted. `crassostrea-nginx.service` applies them on
  every node and keeps the previous configuration if nginx refuses a value.
- **Time zone** (Settings → General): one IANA zone for the servers of every
  node (`timedatectl`, services restarted once) and the times the web
  interface shows; stored times stay UTC.
- **Audit log** (Access): every change made in the web UI or through the API,
  every login (failed ones under the name tried) and the account commands of
  `flask --app crassostrea`: who (administrator, mailbox user, digest link, API
  key or `cli`), from which address, what, the submitted fields without
  passwords, keys, codes and tokens, and whether it worked. Read-only; kept
  for 365 days by default (Settings → General). Also `GET /audit-log`.
- **Backups** (Settings → Backups): every night around 02:30 and on demand, a tar.gz
  in `/var/lib/crassostrea/backups` with `crassostrea.conf`, the certificates,
  the ACME account and DNS-01 credentials, Postfix's `extra.cf`, the cluster
  PKI, the database (the quarantine by default, the mail log's messages if
  chosen) and Valkey's data (Bayes, fuzzy hashes, bans). The newest 7
  scheduled backups are kept (configurable); manual ones until deleted. The
  page lists, downloads (recorded in the audit log) and deletes them; also
  `/api/v1/backups`. A backup holds every password and private key: keep
  downloads safe. Restoring is done on the server (see Operations).
- **Monitoring** (checks and services, with a red badge in the sidebar while a check fails; Prometheus, SIEM
  and alert mail under Settings → Alerts & export):
  `/metrics` for Prometheus with a bearer token
  (components and services up, mail queue and age of deferred mail,
  quarantine, messages of the last hour and day, certificate expiry, last
  backup, directory synchronisation; rspamd's own metrics are at
  `/rspamd/metrics`). Every scanned message and audit log entry can go to a
  SIEM as JSON or RFC 5424 syslog over UDP, TCP or TLS
  (`crassostrea-siem.service`, queued in Valkey while the SIEM is away).
  Alert mail when deferred mail piles up or waits long, the certificate is
  about to expire, there is no recent backup, a directory does not
  synchronise or a service stopped (checked every 5 minutes, repeated daily,
  and a notice when solved). The watchdog's own notices (a service it
  restarted, its start, bans) go by mail straight to the recipients' servers
  and to a webhook (e.g. a chat), set on the same page.
- **IP addressing** (Network → Hostname & IP, single gateway): the addresses, gateways and DNS
  servers of each network interface (NetworkManager; choose one if there are
  several), manual or automatic, and which IP families it uses. Either family,
  or both, can be off on an interface while another interface keeps an
  address; the gateway's services (Postfix, unbound, nginx) use a family if any
  interface has it (`IPV4_ENABLED`, `IPV6_ENABLED`; loopback keeps both, the
  services talk over 127.0.0.1). Internal interfaces need no gateway. A root
  service (`crassostrea-network.path`, `system/libexec/network-apply`) applies a
  change, then tests that names resolve and that every family with a way out
  reaches the internet (1.1.1.1/9.9.9.9 and their IPv6 counterparts, by ICMP or
  TCP), at least one of them, and restores the previous settings if not.
- **Certificates & TLS** (Network, single gateway): the certificate of HTTPS and
  SMTP comes from Let's Encrypt or from uploaded files. With Let's Encrypt,
  additional names are tested against Let's Encrypt's staging environment
  first; only names that passed (in the last 24 hours) can be applied, which
  requests the production certificate. Uploaded files are checked before they
  are installed (the key belongs to the certificate, dates, key strength, chain
  order, trust by the system's CAs, the hostname). TLS 1.0 and 1.1 can be
  turned on for HTTPS and inbound SMTP separately; as the EL10 crypto policy
  refuses them in every program, that service then gets its own OpenSSL
  configuration (security level 0, SHA-1). SSL 3.0 is not available in
  OpenSSL 3. A root service (`crassostrea-tls.path`, `system/libexec/tls-apply`)
  applies the changes and records their outcome.
- **Hostname** (Network → Hostname & IP, single gateway): a root service
  (`crassostrea-hostname.path`) switches `CRASSOSTREA_HOSTNAME` in
  `crassostrea.conf`, Postfix's `myhostname`, restarts the services that use
  the name and requests a certificate for it. A name that does not resolve to
  the gateway yet is accepted with a warning; the certificate follows once it
  does (daily retry). In a cluster the name identifies the member and is not
  changed there: a member is renamed by replacing it.
- **Message limits** (Settings → General, inbound and outbound): the
  maximum message size (default 50 MiB, at most 100 MiB) is Postfix's
  `message_size_limit`, applied by `crassostrea-postfix-reload.service` when it
  changes; the maximum attachment size (decoded, default no limit) makes
  Rspamd reject messages with a larger attachment. Every accepted message is
  scanned in full, by ClamAV too (up to 128 MiB, 90 s per scan, archives up to
  ClamAV's default depth and file count); what ClamAV cannot scan completely
  is not let through silently but scored `CLAM_SCAN_INCOMPLETE` (+4).
- **Operations**: dashboard (statistics, health, recent mail), Monitoring
  (checks and the state of every service), Postfix mail queue (flush, deliver,
  hold, delete), **Logs** (Monitoring → Logs: the Postfix log of all nodes and
  the journal of Rspamd, ClamAV, the web interface, nginx, the database,
  Valkey, unbound, the watchdog, jobs and more, one service at a time, read by
  a root helper that only reads those units), banned IPs (with unban), and
  multiple administrators. The dashboard, queue, logs,
  mail log, bans and quarantine update themselves every 10-30 seconds (paused
  while you select entries), and list actions apply without reloading the
  page. Everything also works without JavaScript.
- **DNS & ports** check: lists the records and connections the gateway needs
  and tests them from the server: the hostname's address, reverse DNS and CAA,
  each domain's MX (warning about backup MX hosts that bypass the filter), the
  DKIM record, and with relay networks SPF (evaluated for the server's address)
  and DMARC; whether SMTP, HTTP and HTTPS accept connections, and the
  connections to DNS, the downstream servers, Let's Encrypt and the other
  cluster members. Whether a firewall in front of the server lets the internet
  in can only be tested from outside; the page says how.
- **Outbound relay** (optional): trusted internal networks can send outbound mail
  through the gateway. It is scanned as well.
- **High availability** (optional): several gateways form a cluster with a
  replicated database and Valkey, one MX record per node, automatic failover
  and an optional floating address for the web UI.

## Requirements

- A dedicated EL10 host (AlmaLinux 10, Rocky Linux 10 or RHEL 10, x86_64)
  with SELinux enforcing and firewalld; root access
- 8 GiB RAM recommended: a gateway with ClamAV uses about 4 GiB, the rest is
  headroom for mail peaks and the page cache. It starts with 2 GiB (setup then
  offers to disable ClamAV), but that is too little for production
- Port 25 reachable from the internet, plus ports 80 and 443 for the UI and
  Let's Encrypt
- A hostname (e.g. `filter.example.com`) with A/AAAA and PTR records

The installer adds EPEL (and CRB) and the official Rspamd repository, and
builds postfix-tlspol with Go. The host's resolver is switched to the local
unbound (`MANAGE_RESOLVER=y`), because DNS blocklists refuse queries from
public resolvers.

## Installation

```bash
git clone https://github.com/SnailShea/crassostrea.git /opt/crassostrea && cd /opt/crassostrea
sudo ./setup.sh
```

`setup.sh` checks the host (EL10, memory, internet access, ports 25/80/443 not
taken by other services), installs its prerequisites, asks for the gateway
hostname and writes `/etc/crassostrea/crassostrea.conf` with random passwords,
then installs and starts everything (`system/install.sh`). It prints the
initial `admin` password; it is also in `crassostrea.conf` as
`WEB_ADMIN_PASSWORD`. Change it under your account page
after the first login at `https://<hostname>/`.

**Installation ISO.** Instead of preparing an EL10 host, boot the ISO
attached to each release (or build it with `iso/build.sh`, see
[iso/README.md](iso/README.md)): it installs AlmaLinux 10 and the gateway in
`/opt/crassostrea`, and sets the gateway up at the first boot, interactively
or unattended (`crassostrea.hostname=`, `crassostrea.wipe=`,
`crassostrea.sshkey=` boot parameters). The GitHub workflow
`.github/workflows/iso.yml` builds it on demand and for tags `v*`.

Unattended: `sudo ./setup.sh --hostname filter.example.com --yes`. Other
options: `--reconfigure` (new configuration with new passwords, the old one is
kept as `crassostrea.conf.bak`; settings you changed in it must be copied over), `--config-only` (stop after writing the
configuration, e.g. to edit it before installing).

**Documentation on the gateway.** The administrator and developer guides are a
separate repository, [crassostrea-docs](https://github.com/SnailShea/crassostrea-docs) (MkDocs). The gateway can build them
and serve them at `https://<hostname>/docs/` to logged-in administrators,
linked from the web UI's menu: answer yes when `setup.sh` asks, or pass
`--docs` (uses a checkout next to this one, e.g. `/opt/crassostrea-docs`, else
[crassostrea-docs](https://github.com/SnailShea/crassostrea-docs) on GitHub) or
`--docs-source <git URL or directory>`; `--no-docs` skips the question. On an
installed gateway: `sudo system/docs.sh install [SOURCE]`, later `update`,
`rebuild`, `remove` or `status`. `update.sh` fetches the docs repository too,
and `configure.sh` rebuilds the site when its source changed; a failed build
only warns.

For several gateways sharing their configuration, quarantine and learning
data, see [High availability](#high-availability) (`setup.sh --ha`).

Running `setup.sh` again is safe: an existing configuration is kept and the
installation is brought up to date. `update.sh` moves the checkout to the
newest release (a tag `vX.Y.Z`; the main channel of Monitoring → Version, or
`--channel main` once, follows the newest commit of the branch instead) and
does the same. The Monitoring page shows the deployed version; the changes of
each release are in [CHANGELOG.md](CHANGELOG.md). After editing `crassostrea.conf` or files in `data/conf/`, run
`sudo system/configure.sh`.

## Putting a domain behind the gateway

1. **Domains → Add domain**: enter the domain, the downstream server and the
   recipient validation mode.
2. Make sure the downstream server accepts mail from the gateway's IP and, ideally,
   **only** from the gateway (otherwise spammers can bypass the filter by
   delivering directly).
3. Point the domain's MX record to the gateway hostname.
4. If the downstream server sends outbound mail through the gateway, add its IP
   under **Settings → Relay networks**. Never add networks you do not control:
   that would make the gateway an open relay.

Tagged mail (score between "mark as spam" and "reject") is delivered with
`X-Spam-Flag: YES` and `X-Spamd-Result` headers, so the downstream server can
file it into a junk folder.

## Configuration reference

Everything about mail handling, sign-in, the web server's access rules, the
Spamhaus key, the watchdog's notices and the update channel is set in the web
interface (or the REST API) and kept in the database, the same on every
cluster node. `/etc/crassostrea/crassostrea.conf` (`KEY=value` lines, read
like a systemd `EnvironmentFile`) holds what the services need before the
database answers, what differs per node, and what changes the installed
packages or the listening ports:

| Variable | Purpose |
| --- | --- |
| `CRASSOSTREA_HOSTNAME` | Gateway hostname (MX target, certificate name) |
| `WEB_ADMIN_PASSWORD` | Password for the initial `admin` account (only used while no administrator exists) |
| `WEB_SECRET_KEY` | Session signing key |
| `RSPAMD_PASSWORD` | Rspamd controller password (web UI and the Rspamd UI at `/rspamd/`) |
| `WEB_PUBLIC_URL` | Base URL in digest links (default `https://CRASSOSTREA_HOSTNAME`) |
| `HTTP(S)_PORT`, `HTTP(S)_BIND` | Ports and addresses nginx listens on |
| `ADDITIONAL_SAN` | Further names on the certificate; with the hostname and the host of `WEB_PUBLIC_URL` the only names nginx answers to (any other name or an IP address gets 404, ACME challenges excepted) |
| `SKIP_CLAMD`, `SKIP_OLEFY` | Disable ClamAV or Olefy |
| `ADDITIONAL_SAN`, `SKIP_LETS_ENCRYPT`, `ACME_DNS_*` | Certificates |
| `HTTPS_TLS_MIN`, `SMTP_TLS_MIN` | Oldest TLS version of HTTPS and inbound SMTP: `1.2` (default), `1.1` or `1.0` |
| `USE_WATCHDOG`, `WATCHDOG_VERBOSE` | The watchdog (health checks and restarts; its notices are set in the web UI) |
| `MANAGE_RESOLVER` | Make the local unbound the system resolver (default `y`) |
| `HAPROXY_LISTENER`, `HAPROXY_LISTENER_BIND` | PROXY protocol listener for an HAProxy in front of Postfix (default off, `127.0.0.1:10025`) |
| `IPV4_ENABLED`, `IPV6_ENABLED` | IP families on the network interface (`true`/`false`, at least one): the host's addresses and Postfix, unbound and nginx; also on the IP addressing page |
| `DOCS_ENABLED`, `DOCS_SOURCE`, `DOCS_REF` | Serve the documentation at `/docs/` (default `n`); its repository (git URL or directory, default the `crassostrea-docs` checkout next to this one, else the one on GitHub) and branch or tag; see `system/docs.sh` |
| `HA_NODES`, `HA_WITNESS` | Cluster members (`hostname=address`), see [High availability](#high-availability); empty for a single gateway |
| `HA_VIP`, `HA_VIP_INTERFACE`, `HA_VIP_ROUTER_ID` | Floating address for the web UI in a cluster (keepalived) |

Persistent manual overrides (kept by `system/configure.sh`):

- Postfix: `/etc/postfix/extra.cf`, `custom_transport.pcre`,
  `custom_postscreen_whitelist.cidr`, `dns_blocklists.cf`
- Rspamd: `/etc/rspamd/override.d/*.custom.inc`
- Hooks: executables in `data/hooks/{postfix,rspamd,unbound}/` run after the
  component's configuration was rendered

Files from `data/conf/` are copied to `/etc/` by `system/configure.sh`;
edit them in the repository, not in `/etc/`.

## Operations

| Task | Command |
| --- | --- |
| Update (to the newest release or commit, packages, redeploy, restart) | `sudo ./update.sh` |
| Apply changed settings | `sudo system/configure.sh` |
| Reset an admin password | `sudo helper-scripts/reset-admin.sh [username]` |
| Re-write all filter maps | `sudo systemctl start crassostrea-job@sync` |
| Logs of a component | `journalctl -u postfix` (or `rspamd`, `crassostrea-web`, `crassostrea-netfilter`, …) |
| State of all services | `systemctl list-units 'crassostrea*' postfix rspamd nginx valkey mariadb unbound 'clamd@*'` |
| Reset Bayes/fuzzy learning data | `sudo helper-scripts/reset-learns.sh` |
| Make a backup now / list them | `sudo system/backup.sh create` / `sudo system/backup.sh list` |
| Restore a backup (also: move the gateway to a new server) | `sudo system/backup.sh restore NAME-OR-PATH` |
| Documentation at `/docs/`: deploy, update, remove | `sudo system/docs.sh install [SOURCE]`, `update`, `rebuild`, `remove`, `status` |
| Turn SELinux denials into a local policy module | `sudo helper-scripts/selinux-local-policy.sh` |

Scheduled jobs (systemd timers, `systemctl list-timers 'crassostrea*'`):
quarantine expiry, expired digest token and log cleanup (daily), quarantine
digests (every 15 minutes), accounts for recipients of quarantined mail
(every 5 minutes, when on), map re-sync (every 10 minutes, every minute in a
cluster), SpamAssassin rules
(daily), Sanesecurity signatures (every 12 hours), the certificate (daily)
and backups (nightly).

A restore saves the current configuration and database to
`/var/lib/crassostrea/restore-<time>`, stops the services, puts back the
files, the database and Valkey's data, and runs `system/configure.sh`. To move
the gateway, install it on the new server with `setup.sh`, copy a backup over
and restore it there. Cluster members are not restored: restore one node as a
single gateway, then set up the cluster again.

API examples (all endpoints, fields and errors are described at `/api/docs`):

```bash
KEY="X-API-Key: sfk_..."; API=https://filter.example.com/api/v1
# add a domain and a recipient list
curl -H "$KEY" -H "Content-Type: application/json" \
     -d '{"name": "example.com", "destination_host": "mail.internal", "recipient_check": "list"}' $API/domains
curl -H "$KEY" -H "Content-Type: application/json" -d '{"addresses": ["alice", "bob"]}' $API/domains/1/recipients
# block a sender for everyone
curl -H "$KEY" -H "Content-Type: application/json" \
     -d '{"list_type": "block", "kind": "sender", "value": "*@spam.example"}' $API/list-entries
# release the pending quarantine of an address
curl -H "$KEY" "$API/quarantine?rcpt=alice@example.com&status=pending"
curl -H "$KEY" -X POST $API/quarantine/42/release
# a mailbox user
curl -H "$KEY" -H "Content-Type: application/json" \
     -d '{"email": "alice@example.com", "password": "a-long-password", "digest_interval": "daily"}' \
     $API/mailbox-users
```

The API applies the same rules as the web UI (they share the service layer).
The mail queue and training act on the node that answers; in a cluster use
the node's own name to reach a specific queue.

Per-user settings apply only to messages whose envelope recipients all belong
to that user (the address and its `+tag` sub-addresses). Rspamd decides once
per message, so a message that also goes to other people is filtered with the
domain and global settings instead; one user's allow list or thresholds never
decide for another recipient. Likewise, domain allow lists and thresholds only
apply when every recipient is in that domain (a message to several protected
domains uses the global settings), while domain block lists apply as soon as one
recipient is in the domain.

## High availability

Several gateways can run as one cluster. Every full node filters mail on its
own and is its own MX record; what has to be shared is replicated between
them:

| Component | In a cluster |
| --- | --- |
| Database (domains, users, lists, quarantine, DKIM keys) | MariaDB Galera: every node has a full copy and accepts writes; Postfix and the web UI keep using the local copy |
| Valkey (Bayes, fuzzy hashes, greylisting, rate limits, history, bans, logs) | Replication with Sentinel failover; haproxy on each node forwards `127.0.0.1:6379` to the current master, so the clients are unchanged |
| Rspamd maps and Postfix relay networks | Written by every node from the shared database, at most a minute after a change on another node |
| Quarantine digests, cleanup | Run by one node at a time (lock in Valkey) |
| Bans | Every node bans what the logs of all nodes report; unbanning in the UI of any node lifts the ban everywhere |
| Certificates | Each node gets its own; HTTP-01 challenges for names shared by several nodes are answered by whichever node requested them |
| Web UI | Every node, with shared logins; optionally a floating address (`HA_VIP`, keepalived) for one shared name |
| Postfix queue, ClamAV, unbound, statistics | Per node |

Replication uses TLS with a private cluster CA (`/etc/pki/crassostrea/`)
that `setup.sh --ha` creates; nodes and Valkey clients authenticate with
certificates from it. The cluster ports are only opened to the other
members (firewalld zone `crassostrea-cluster`).

### Quorum

Every member has one vote. The database only accepts writes, and Valkey only
fails over, while a majority of the votes is reachable: a node that is cut
off from the others stops instead of diverging. A cluster therefore survives
the failure of a member from 3 votes on:

- **3 or more full nodes** ("full nodes only"), or
- **2 (or any even number of) full nodes plus a witness**: a small extra host
  (1 CPU, 512 MiB) that only votes. It runs the Galera arbitrator (`garbd`) and
  a Valkey Sentinel, receives no mail and holds no data. It should be in a
  third location, so that it decides which side of a split continues.

With an odd number of votes the cluster survives the loss of
`(votes - 1) / 2` members, e.g. one of three. Like a Proxmox cluster, it can
start with one node and grow; with 1 or 2 votes it works but stops on a
failure, and the Cluster page and `configure.sh` warn.

### Setting up a cluster

Requirements: the members reach each other on fixed IPv4 addresses (a private
network or VPN is best) with low latency (same region: every database write
waits for the other nodes); the full nodes meet the normal
[requirements](#requirements).

**In the web interface** (like Proxmox), after installing every gateway with
`setup.sh`:

1. **Create**: on the first gateway, **Settings → Cluster → Create a
   cluster**: choose its cluster address (and optionally a floating address).
   It keeps its data; a root service runs `setup.sh --ha` (a few minutes, the
   web UI restarts).
2. **Join information**: on a member's **Settings → Cluster**, **Add a node → Join
   information** shows a one-time text (`sfjoin1.…`, one hour) with the
   member's cluster address, the fingerprint of its HTTPS certificate and a
   secret.
3. **Join**: on the new gateway's **Settings → Cluster**, paste it into **Join a
   cluster** and choose its cluster address. It contacts the member over
   HTTPS, pinned to that certificate; the member adds it to the cluster's
   membership, **every member opens its firewall and updates its configuration
   by itself**, and the new gateway receives its join bundle and runs
   `setup.sh --join`, copying the database (`mariabackup` over TLS) and Valkey.
   Joining replaces the gateway's domains, accounts, settings and data with the
   cluster's; its name, network and certificate settings stay.

Also in the API (`POST /api/v1/cluster/create`, `.../join-information`,
`.../join`).

**On the command line**: `sudo ./setup.sh --ha` on the first node (a new host,
or an installed gateway, which keeps its data) asks for the full nodes
(`hostname=address`, this one first; one is enough), the quorum mode (and the
witness) and an optional floating address. Unattended:

```bash
sudo ./setup.sh --hostname mx1.example.com --yes --ha \
  --ha-nodes mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.2 \
  --ha-witness witness.example.com=10.0.0.3 --ha-vip none
```

It leaves a join bundle per listed member in `/root/crassostrea-join-<host>.tar`
(also `system/cluster.sh bundle <host>`: configuration with all passwords, and
the cluster CA; copy it securely and delete it afterwards). On each other
member, one after another:

```bash
git clone https://github.com/SnailShea/crassostrea.git /opt/crassostrea && cd /opt/crassostrea
sudo ./setup.sh --join /root/crassostrea-join-mx2.example.com.tar
```

A witness host (no web UI) always joins this way.

DNS: one MX record per full node (equal preference to share the load). Every
node needs its own A/PTR records. For links in digest mails set
`WEB_PUBLIC_URL` to a name that always works: the floating address, or a name
with the addresses of all nodes, listed in `ADDITIONAL_SAN`.

`crassostrea.conf` is the same on all members except `CRASSOSTREA_HOSTNAME`.
Settings you change (e.g. `SKIP_CLAMD`) have to be changed on every node,
followed by `system/configure.sh` there. A member restarts its database,
Valkey and Sentinel only when their configuration changed. Update the members
one at a time (`update.sh`), so that the others keep the majority.

Ports between the members (opened automatically, only for the members):
Galera 4567, 4568 (IST) and 4444 (state transfer), Valkey 6380 and Sentinel
26379 (all TLS), HTTP 80 (certificate challenges), and VRRP with `HA_VIP`. The
witness only needs 4567 and 26379.

### Adding and removing members, changing the quorum mode

The membership is a row of the cluster's database (`cluster_membership`):
every node applies a change by itself within a minute (`HA_NODES` and
`HA_WITNESS` in its `crassostrea.conf`, firewall, Galera, haproxy, Sentinel,
keepalived; `crassostrea-cluster`, without restarting the database).

- **Add a node**: join it with a join information (above).
- **Remove a node** (like `pvecm delnode`): switch it off for good (or
  `sudo system/cluster.sh leave` on it), then **Remove** on another node's
  **Settings → Cluster**. Only a node that has not reported for a minute can be removed;
  reinstall it to use it again.
- **Witness**: `sudo system/cluster.sh members --nodes <nodes> --witness
  host=address` on a full node (then join the witness with its bundle), or
  `--no-witness` (then `leave` on the witness). The witness has no database:
  after adding or removing a node, run `members` on it too (Settings → Cluster
  shows the command).
- `system/cluster.sh members` writes the cluster's membership too, so the
  other nodes follow by themselves.
- **Back to a single gateway**: after the other members left,
  `sudo system/cluster.sh members --standalone` on the remaining node.

### Operations and failures

| Task | Command |
| --- | --- |
| State of the cluster | **Monitoring → Cluster** in the web UI (every member, its problems), `GET /api/v1/cluster`, or `sudo system/cluster.sh status` |
| Maintenance (before updating or rebooting a node) | **Maintenance** under Settings → Cluster, or `sudo system/cluster.sh maintenance on\|off [<hostname>]` |
| Join bundle for a member | `sudo system/cluster.sh bundle <hostname>` |
| Start the database after all nodes were down | `sudo system/cluster.sh bootstrap` on the node that stopped last, then `systemctl start mariadb` on the others |

- **A node fails**: senders retry the other MX records; the remaining
  majority continues. If the failed node was the Valkey master, another node
  takes over, usually after about 10 seconds (at most about 30). Mail in the failed node's queue waits for its return.
  When it is back it catches up on the database and Valkey by itself.
- **A node is cut off**: it loses the majority, refuses database queries and
  temporarily rejects mail (4xx, senders retry another MX).
- **All nodes stop** (e.g. power loss): MariaDB does not start on its own,
  as no node knows whether it has the latest data. Run `cluster.sh bootstrap`
  on the node that stopped last. On a node that did not stop cleanly it
  refuses and shows the node's position instead: compare it on all nodes
  (`galera_recovery`) and run `cluster.sh bootstrap --force` on the most
  advanced one.
- The watchdog reports a degraded cluster (a node not in sync, fewer members
  than configured) but never restarts the database of a cluster node.

**Cluster page.** Every node reports its state every 10 seconds
(`crassostrea-cluster-report.service` into the database, with what the root
service `crassostrea-cluster.service` finds over the cluster's TLS: Valkey,
Sentinel, the floating address): database state, Valkey role and lag, mail
queue, stopped services, load, memory, disk, version. The page lists the
members and the witness, the votes, and the problems: a node that stopped
reporting, a database out of sync or without majority, no or two Valkey
masters, the witness missing, the floating address on no node, nodes running
different versions for more than an hour, a full disk (Monitoring → Cluster).
Maintenance, the Valkey master and the members are managed under Settings →
Cluster. The alert mail (Settings → Alerts & export) reports these problems and every node's mail queue and services,
and `/metrics` has them as `sf_cluster_*`.

**Maintenance.** A node in maintenance answers new SMTP connections with 421
(senders use the other MX hosts), hands the Valkey master over and is never
made master, gives up the floating address, and keeps delivering its queue.
It is refused if no other node would accept mail. Update one node at a time:
maintenance on, wait until its queue is empty, `update.sh`, check that it is in
sync, maintenance off. **Make Valkey master** moves the master to a node (e.g.
back after maintenance).

The mail queue, the service list (Monitoring) and the logs other than the
Postfix log are those of the node you are logged in to; the Cluster page shows
every node, and the Postfix log, the mail log and the dashboard's statistics
show all nodes.

## How the components fit together

Every service listens on loopback only, except Postfix (25) and nginx (80,
443); in a cluster also Galera, Valkey and Sentinel, for the other members
only (TLS).

- **Postfix** (`postfix.service`, config in `/etc/postfix`) reads the `domains`
  and `recipients` tables directly through MySQL lookup maps (relay domains,
  transport, recipient validation), so changes in the UI take effect
  immediately. EL10 builds Postfix without Berkeley DB, all indexed tables and
  caches are `lmdb`.
- **Rspamd** (`rspamd.service`) fetches per-domain and per-user thresholds and
  allow/block lists as a settings map from the web UI's internal API
  (`crassostrea-web-internal`, `127.0.0.1:8001`, never proxied). Global lists,
  protected domains and relay networks are written as map files into
  `/etc/rspamd/custom/` and reloaded automatically.
- **Quarantine**: Rspamd's metadata exporter posts rejected messages to the
  internal API. Released messages are re-injected into Postfix on
  `127.0.0.1:590`, which skips the milter.
- **Mail queue**: the web UI talks to `crassostrea-postfix-control.socket`, a
  root helper started per request that only runs fixed `postqueue`,
  `postsuper` and `postcat` actions with validated queue IDs.
  `crassostrea-postfix-reload.path` reloads Postfix when the relay networks
  change.
- **Logs and bans**: `crassostrea-logship` forwards the mail log from journald
  to Valkey (web UI log page, `F2B_CHANNEL`); `crassostrea-netfilter` bans
  networks in its own nftables table (`inet crassostrea`), next to firewalld.
- **DKIM**: keys are stored in the database and copied to Valkey
  (`DKIM_PRIV_KEYS`, `DKIM_SELECTORS`). Rspamd signs mail from relay networks.
  Released outbound mail is signed by the web UI with the same key and header
  list, because the re-injection listener bypasses Rspamd.
- **Certificates**: `crassostrea-acme.timer` runs acme.sh (HTTP-01 through
  nginx or DNS-01); the certificate is installed as
  `/etc/crassostrea/ssl/{cert,key}.pem` for nginx and Postfix.

Files on the host:

| Path | Content |
| --- | --- |
| `/etc/crassostrea/` | `crassostrea.conf`, TLS certificate, DNS-01 credentials |
| `/usr/local/lib/crassostrea/` | Deployed web UI, netfilter, olefy and their Python venv |
| `/usr/local/libexec/crassostrea/` | Helpers (postfix-control, logship, acme, watchdog, …) |
| `/etc/systemd/system/crassostrea-*` | Units and timers, drop-ins for postfix, rspamd, nginx, clamd |
| `/etc/pki/crassostrea/` | Cluster CA and this member's certificate (cluster only) |

Services never run from the repository: `system/configure.sh` copies the code
to root-owned locations, so the account owning the checkout cannot change
what runs as root. Without containers, the services share one host: anything
that can connect to loopback can reach the internal ports (the database and
Valkey still require their passwords). Use the host for the gateway only.

## Development

The web UI lives in `data/web/` (Flask, SQLAlchemy, Flask-WTF, no JavaScript
framework, no external assets).

```bash
cd data/web
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
```

Tests use SQLite and fake Redis, Rspamd and SMTP; the Postfix control
helper (`system/libexec/postfix-control`) is tested over a real unix socket.

## Differences from mailcow

Crassostrea started from the mailcow: dockerized stack. Removed: Docker and
Docker Compose (including dockerapi and ofelia), Dovecot (IMAP/POP3/Sieve,
mail storage), SOGo (webmail and groupware), PHP-FPM and the PHP admin UI,
memcached, SASL/submission ports (465/587), mailboxes, aliases, sync jobs, app
passwords, BCC, footers, the updater and the backup scripts of mailcow, Redis
replication (`REDIS_SLAVEOF_*`), the MySQL replication check of the watchdog,
`SNAT_TO_SOURCE` and per-name certificates (SNI): one certificate covers the
hostname and `ADDITIONAL_SAN`.

The rspamd fuzzy rule that queries the public fuzzy storage of the mailcow
project reports `CRASSOSTREA_FUZZY_*` symbols.

## License

GPL-3.0, see [LICENSE](LICENSE). Based on mailcow: dockerized by The
Infrastructure Company GmbH and contributors.
