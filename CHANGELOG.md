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
tag `vMAJOR.MINOR.PATCH`; gateways with `UPDATE_CHANNEL=release` move to it with
`update.sh`, and the GitHub workflow attaches the installation ISO to it.

## [Unreleased]

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
