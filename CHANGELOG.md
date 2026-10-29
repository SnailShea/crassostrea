# Changelog

Notable changes of each release. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) as it applies to a gateway:

- **MAJOR**: updating needs manual steps, `crassostrea.conf` changes
  incompatibly, or the REST API breaks (its path becomes `/api/v2`);
- **MINOR**: new features or settings that work after a plain `update.sh`;
- **PATCH**: fixes only.

Versions before 1.0.0 may still change incompatibly in a MINOR release; such
changes are listed under **Changed** with what to do. A release is the git
tag `vMAJOR.MINOR.PATCH`; gateways on the release channel move to it with
`update.sh`, and the GitHub workflow attaches the installation ISO to it.

## [Unreleased]

## [0.4.0] - 2026-10-29

### Added

- **Bans for scanners and exploit attempts.** netfilter's rules each have
  their own number of matches (`F2B_REGEX`: `regex` and `attempts`). New
  rules ban at once for a request for secrets, version control or other
  applications in nginx's access log (`/.env`, `/.git/`, `*.php`, WordPress,
  ...), for a request only an exploit sends (the web UI refuses Next.js
  server action headers and prototype pollution, e.g. CVE-2025-55182), and
  for HTTP or TLS on port 25 (postscreen `NON-SMTP COMMAND`); after 3 for
  postscreen's `PREGREET`, bare newlines and pipelining, and for open relay
  tests (`Relay access denied`).
- nginx writes its access log to the journal as well (tag
  `crassostrea_access`; the Logs page, nginx), which logship forwards to
  netfilter. `sudo system/configure.sh` applies it.
- **Dashboard: processing time, mail queue and system load.** The average
  scan time and delivery time (arrival to delivery, Postfix's `delay`) of
  the period, with its filters; for full administrators the node's mail
  queue inbound and outbound (being delivered, deferred, on hold) and its use
  of CPU, memory and each filesystem. `init-db` adds the columns
  (`stats_hourly.scan_ms`, `mail_delivery.delay`); both averages start with
  this update. `GET /api/v1/statistics` returns `scan_ms` in its totals.

## [0.3.0] - 2026-10-28

### Added

- **Monitoring check "TLS policy lookups"** (and the metric
  `sf_tls_policy_ok`): looks up the policy of a domain with MTA-STS the way
  Postfix does, and fails when postfix-tlspol does not answer, cannot look it
  up, or answers in a form the installed Postfix does not understand.

## [0.2.1] - 2026-10-28

### Fixed

- **Outbound mail to domains with an MTA-STS policy was deferred** with
  "client TLS configuration problem": Postfix asked postfix-tlspol for
  policies with TLSRPT attributes, which only Postfix 3.10 understands (EL10
  has 3.8). `smtp_tls_policy_maps` uses the plain query.
  `sudo system/configure.sh` applies it; `sudo postqueue -f` sends the
  deferred mail.

## [0.2.0] - 2026-10-28

### Added

- **Settings → General: Sign-in** sets how long a login lasts and the failed
  logins allowed per address and per account, and for how long (API
  `session_lifetime_minutes`, `login_max_failures`,
  `login_max_account_failures`, `login_failure_window_minutes`).
- **Settings → General: Web server** sets the redirect from HTTP to HTTPS,
  the networks of the Rspamd UI and the trusted reverse proxies, applied by
  `crassostrea-nginx.service` on every node (API `http_redirect`,
  `rspamd_ui_networks`, `trusted_proxies`).
- **The Spamhaus DQS key** is entered under Settings → General, Scanning and
  applied to Postfix and Rspamd by `crassostrea-spamhaus.service` on every
  node (API `spamhaus_dqs_key`).
- **Watchdog notices** (Settings → Alerts & export): recipients, webhook and
  its body, subject, notices at start and for bans; the watchdog reads them
  from Valkey for every notice (API `watchdog_*`).
- **The update channel** is chosen on Monitoring → Version; `update.sh` reads
  it from the database (API `update_channel`, `update_branch`).
- The Postfix log lines kept for the Logs page are a setting (Settings →
  General, Messages; API `postfix_log_lines`).

### Changed

- **Floating address on another network than the cluster's**: keepalived's
  VRRP always runs on the interface with the node's cluster address;
  `HA_VIP_INTERFACE` only chooses where the address is added (e.g. the public
  network when `HA_NODES` are private addresses), and that interface is
  tracked. `sudo system/configure.sh` on every node applies it.
- These settings are no longer read from `crassostrea.conf`:
  `WEB_SESSION_LIFETIME`, `WEB_LOGIN_MAX_FAILURES`,
  `WEB_LOGIN_MAX_ACCOUNT_FAILURES`, `WEB_LOGIN_FAILURE_WINDOW`,
  `HTTP_REDIRECT`, `RSPAMD_UI_ALLOW`, `TRUSTED_PROXIES`, `SPAMHAUS_DQS_KEY`,
  `LOG_LINES`, `WATCHDOG_NOTIFY_*`, `WATCHDOG_SUBJECT`, `UPDATE_CHANNEL` and
  `UPDATE_BRANCH`. Enter their values in the web interface; lines left in the
  file are ignored.

## [0.1.1] - 2026-10-26

### Added

- **Mail log: refused recipients.** For domains that validate recipients, the
  recipients Postfix refuses because they do not exist appear in the mail log,
  with Postfix's reason; filter "refused recipients", API `action=refused`.
  `logship` reports them from the Postfix log.
- **Mail log: delivery.** Each message shows what Postfix did with it per
  recipient (delivered, deferred or bounced, with the receiving server's
  answer and the number of attempts), whether it expired, and the bounces and
  delay warnings the gateway sent the sender; filter "delivery", API
  `delivery=` and `deliveries`.

### Changed

- Postfix uses long queue IDs (`enable_long_queue_ids`), which are never
  reused: the mail log matches delivery results to messages by queue ID.
  `sudo system/configure.sh` applies it; mail already queued keeps its ID.

## [0.1.0] - 2026-10-26

The first version: an inbound spam and virus filter (smart host) for EL10 on
distribution packages, set up by `setup.sh` or from the installation ISO.

### Added

- **Mail flow**: Postfix with postscreen, Rspamd (Bayes, fuzzy hashes,
  DNSBL/URIBL, SPF/DKIM/DMARC/ARC, SpamAssassin rules), ClamAV, Olefy, DKIM
  signing of outbound mail, MTA-STS and DANE for delivery.
- **Domains**: destination servers, recipient validation (list, verification,
  LDAP/Active Directory/Microsoft 365 directories), per-domain thresholds,
  allow and block lists, a destination test.
- **Protection**: attachment policy, hash lookups (Team Cymru, MalwareBazaar,
  VirusTotal), impersonation checks, link protection, content rules, data loss
  prevention, inbound and outbound rate limits, a PTR check, a virus scanning
  switch.
- **Quarantine**: release, learning, release & allow and block & delete of the
  sender, digests with token links, mailbox users with their own thresholds
  and lists, accounts for recipients of quarantined mail, password links and
  "Forgot your password?", the import of password hashes of other systems.
- **Mail log and statistics**: every scanned message in full, the score
  breakdown with plain-language explanations, the dashboard's statistics,
  DMARC and TLS reports, journaling.
- **Administration**: the web interface with domain administrators, two-factor
  login, administrator networks, the audit log, API keys and the REST API
  (OpenAPI), branding, the time zone, certificates (Let's Encrypt or your own),
  IP addressing, DNS checks, backups.
- **Monitoring**: checks with alert mail and a sidebar badge, Prometheus
  metrics, SIEM export, the logs of the services, a watchdog.
- **High availability**: clusters built in the web interface (Galera,
  Valkey with Sentinel, haproxy, keepalived), maintenance mode.
- **Installation and updates**: the installation ISO (AlmaLinux 10, unattended
  with boot parameters), update channels (`UPDATE_CHANNEL`: releases or the
  branch), the documentation served at `/docs/`.

[Unreleased]: https://github.com/SnailShea/crassostrea/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/SnailShea/crassostrea/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SnailShea/crassostrea/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/SnailShea/crassostrea/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/SnailShea/crassostrea/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/SnailShea/crassostrea/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/SnailShea/crassostrea/releases/tag/v0.1.0
