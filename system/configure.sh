#!/usr/bin/env bash
# Deploys Crassostrea from this repository and renders the configuration
# of every service from /etc/crassostrea/crassostrea.conf. Idempotent: run it
# again after editing crassostrea.conf or files in data/conf/.
#
#   system/configure.sh               deploy, render, (re)start services
#   system/configure.sh --no-restart  deploy and render only
#
# Packages, users and builds are handled by system/install.sh, which calls
# this script.
#
# In a cluster (HA_NODES, see lib/cluster.sh) it also renders Galera,
# Valkey replication with Sentinel, haproxy (127.0.0.1:6379 to the Valkey
# master), keepalived (HA_VIP) and the firewall zone for the members; on the
# witness (HA_WITNESS) only the Galera arbitrator and Sentinel. Database,
# Valkey and Sentinel of a member are restarted only when their
# configuration changed. SF_GALERA_BOOTSTRAP=y (setup.sh --ha) creates a new
# database cluster instead of joining one.
#
# With DOCS_ENABLED=y it builds the documentation (system/lib/docs.sh) when
# its source changed and serves it at /docs/.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

RESTART=y
for arg in "$@"; do
  case "${arg}" in
    --no-restart) RESTART=n ;;
    -h|--help) awk 'NR > 1 && /^#/ {sub(/^# ?/, ""); print; next} NR > 1 {exit}' "$0"; exit 0 ;;
    *) die "Unknown option ${arg}" ;;
  esac
done

dry || [[ ${EUID} -eq 0 ]] || die "Please run as root"
load_config

POSTFIX_DIR=/etc/postfix
RSPAMD_DIR=/etc/rspamd
SSL_DIR=${SF_ETC}/ssl
ACME_WEBROOT=${SF_STATE}/acme-challenge
MYSQL_SOCKET=/var/lib/mysql/mysql.sock
# Main valkey configuration of a cluster node, see render_valkey
VALKEY_CLUSTER_CONF=/etc/crassostrea-valkey.conf

# Static rspamd maps maintained in the repository; the other maps in
# custom/ are written by the web UI and must not be overwritten
RSPAMD_STATIC_MAPS="bad_asn.map bad_header.map bad_languages.map bad_words.map bad_words_de.map bulk_header.map
  fishy_tlds.map monitoring_nolog.map"

# --------------------------------------------------------------------------
# Deploy root-owned copies of the code (services never run from the repo)
# --------------------------------------------------------------------------
deploy() {
  log "Deploying files to ${SF_LIB} and ${SF_LIBEXEC}"
  sync_tree "${SF_SRC}/data/web/crassostrea" "${SF_LIB}/web/crassostrea"
  install_file "${SF_SRC}/data/web/gunicorn.conf.py" "${SF_LIB}/web/gunicorn.conf.py" 0644
  sync_tree "${SF_SRC}/services/netfilter" "${SF_LIB}/netfilter"
  sync_tree "${SF_SRC}/services/olefy" "${SF_LIB}/olefy"

  local f
  for f in "${SF_SRC}"/system/libexec/*; do
    [[ -f ${f} ]] && install_file "${f}" "${SF_LIBEXEC}/$(basename "${f}")" 0755
  done
  # used by system/libexec/tls-apply, network-apply, set-hostname, nginx-apply
  # and spamhaus-apply
  for f in conf.sh tls.sh ipfamily.sh nginx.sh spamhaus.sh; do
    install_file "${SF_SRC}/system/lib/${f}" "${SF_LIB}/lib/${f}" 0644
  done
  # the Rspamd rules of a Spamhaus DQS key (system/libexec/spamhaus-apply)
  install_file "${SF_SRC}/data/conf/rspamd/dqs-rbl.conf.template" "${SF_LIB}/rspamd/dqs-rbl.conf.template" 0644
  # smtp-cli is downloaded into this directory by install.sh
  install_file "${SF_SRC}/services/watchdog/watchdog.sh" "${SF_LIBEXEC}/watchdog/watchdog.sh" 0755
  install_file "${SF_SRC}/services/watchdog/check_dns.sh" "${SF_LIBEXEC}/watchdog/check_dns.sh" 0755
  install_file "${SF_SRC}/services/watchdog/client.cnf" "${SF_LIBEXEC}/watchdog/client.cnf" 0644

  for f in "${SF_SRC}"/system/systemd/*.{service,socket,path,timer}; do
    [[ -f ${f} ]] && install_file "${f}" "/etc/systemd/system/$(basename "${f}")" 0644
  done
  for f in "${SF_SRC}"/system/systemd/dropins/*/*.conf; do
    install_file "${f}" "/etc/systemd/system/$(basename "$(dirname "${f}")")/$(basename "${f}")" 0644
  done
  install_file "${SF_SRC}/system/tmpfiles.d/crassostrea.conf" /etc/tmpfiles.d/crassostrea.conf 0644

  # The deployed version and since when, compared between the nodes of a
  # cluster (Cluster page)
  local version
  version=$(git -c safe.directory="${SF_SRC}" -C "${SF_SRC}" describe --tags --always --dirty --abbrev=10 2> /dev/null)
  version=${version:-unknown}
  if [[ $(head -1 "$(p "${SF_LIB}/version")" 2> /dev/null) != "${version}" ]]; then
    printf '%s\n%s\n' "${version}" "$(date +%s)" | write_file "${SF_LIB}/version" 0644
  fi
  # The checkout this was deployed from: the root services of the web UI run
  # its setup.sh and configure.sh (creating or joining a cluster, membership)
  echo "${SF_SRC}" | write_file "${SF_LIB}/source" 0644
}

# --------------------------------------------------------------------------
# TLS: self-signed until system/libexec/acme obtained a certificate
# --------------------------------------------------------------------------
render_tls() {
  mkdir -p "$(p "${SSL_DIR}")"
  chmod 0755 "$(p "${SSL_DIR}")"
  if [[ ! -s $(p "${SSL_DIR}/cert.pem") || ! -s $(p "${SSL_DIR}/key.pem") ]]; then
    log "Creating a self-signed certificate for ${CRASSOSTREA_HOSTNAME}"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes -subj "/CN=${CRASSOSTREA_HOSTNAME}" \
      -addext "subjectAltName=DNS:${CRASSOSTREA_HOSTNAME}" \
      -keyout "$(p "${SSL_DIR}/key.pem")" -out "$(p "${SSL_DIR}/cert.pem")" 2> /dev/null \
      || die "openssl failed"
    chmod 0600 "$(p "${SSL_DIR}/key.pem")"
    chmod 0644 "$(p "${SSL_DIR}/cert.pem")"
  fi
  mkdir -p "$(p "${ACME_WEBROOT}/.well-known/acme-challenge")" "$(p "${SF_STATE}/acme")"
  chmod 0755 "$(p "${ACME_WEBROOT}")" "$(p "${ACME_WEBROOT}/.well-known")" "$(p "${ACME_WEBROOT}/.well-known/acme-challenge")"
  chmod 0700 "$(p "${SF_STATE}/acme")"
  create_file "${SF_ETC}/acme/dns-01.conf" 0600 <<'EOF'
# DNS-01 challenge settings (ACME_DNS_CHALLENGE=y): export the variables of
# your provider's acme.sh DNS API, e.g. for Cloudflare
#   CF_Token=...
#   CF_Zone_ID=...
# See https://github.com/acmesh-official/acme.sh/wiki/dnsapi
EOF
  # TLS 1.0/1.1 for HTTPS and SMTP (system/lib/tls.sh)
  tls_legacy_cnf | write_file "${TLS_LEGACY_CNF}" 0644
  if tls_legacy "${HTTPS_TLS_MIN:-1.2}"; then
    tls_nginx_dropin | write_file "${TLS_NGINX_DROPIN}" 0644
  else
    rm -f "$(p "${TLS_NGINX_DROPIN}")"
  fi
}

# --------------------------------------------------------------------------
# MariaDB and Valkey
# --------------------------------------------------------------------------
# MariaDB reads /etc/my.cnf.d in alphabetical order and the last value wins:
# after the package's galera.cnf (wsrep_on=0, bind-address=0.0.0.0, its own
# cluster name) and mariadb-server.cnf
MARIADB_CNF=/etc/my.cnf.d/zz-crassostrea.cnf

render_mariadb() {
  {
    echo "# Generated by system/configure.sh from data/conf/mysql/my.cnf - do not edit"
    awk '{ print } /^\[mysqld\]/ { print "bind-address = 127.0.0.1" }' "${SF_SRC}/data/conf/mysql/my.cnf"
    [[ ${HA_ROLE} == node ]] && galera_settings
  } | write_file "${MARIADB_CNF}" 0644
  if [[ ${HA_ROLE} == node ]]; then
    {
      cat <<'EOF'
# Generated by system/configure.sh (HA_NODES): a joining node copies the
# whole database before it reports ready
[Service]
TimeoutStartSec=2h
EOF
      if [[ $(ha_voters) -eq 1 ]]; then
        # The only member forms the cluster at every start (wsrep_cluster_address
        # gcomm://). A node that crashed while it still had peers (the cluster
        # shrank to it later) is marked unsafe to do so, which only protects
        # other copies of the data: there are none now.
        # ($$: a literal $ for systemd)
        echo "ExecStartPre=-/usr/bin/sed -i 's/^safe_to_bootstrap: 0\$\$/safe_to_bootstrap: 1/' /var/lib/mysql/grastate.dat"
      fi
    } | write_file /etc/systemd/system/mariadb.service.d/crassostrea-cluster.conf 0644
  else
    rm -f "$(p /etc/systemd/system/mariadb.service.d/crassostrea-cluster.conf)"
  fi
}

# The members Galera connects to at start. The only member of a cluster
# (created in the web UI, or the last one left) has nobody to join: an empty
# address makes it form the cluster again at every start, also after a reboot.
# Members added later are written here by the membership change and used
# from the next restart; the running node keeps its cluster meanwhile.
galera_address() {
  if [[ $(ha_voters) -eq 1 ]]; then
    echo "# The only member: forms the cluster at every start"
    echo "wsrep_cluster_address = gcomm://"
  else
    echo "wsrep_cluster_address = gcomm://$(ha_member_addrs | paste -sd, -)"
  fi
}

# Galera: every node holds a full copy of the database and accepts writes.
# MariaDB clients still use the local server only (127.0.0.1 and the socket).
galera_settings() {
  cat <<EOF

# Cluster (HA_NODES): Galera replication over TLS with the cluster CA
[mysqld]
wsrep_on = ON
wsrep_provider = /usr/lib64/galera/libgalera_smm.so
wsrep_cluster_name = ${HA_CLUSTER_NAME}
$(galera_address)
wsrep_node_name = ${CRASSOSTREA_HOSTNAME,,}
wsrep_node_address = ${HA_SELF_ADDR}
wsrep_provider_options = "socket.ssl_ca=${SF_PKI}/ca.crt;socket.ssl_cert=${SF_PKI}/node.crt;socket.ssl_key=${SF_PKI}/node.key;gcache.size=512M"
# Joining nodes receive a copy with mariabackup; the donor connects as the
# system user mysql (unix_socket authentication)
wsrep_sst_method = mariabackup
wsrep_sst_auth = mysql:
binlog_format = ROW
default_storage_engine = InnoDB
innodb_autoinc_lock_mode = 2
# Events would run on every node
event_scheduler = OFF

[sst]
# TLS with verification of the peer against the cluster CA (socat)
encrypt = 4
tca = ${SF_PKI}/ca.crt
tcert = ${SF_PKI}/node.crt
tkey = ${SF_PKI}/node.key
EOF
}

setup_database() {
  log "Creating database ${DBNAME} and user ${DBUSER}"
  local host sql
  sql="CREATE DATABASE IF NOT EXISTS \`${DBNAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
  # postfix connects through the socket (localhost), the web UI over TCP
  for host in localhost 127.0.0.1; do
    sql+="CREATE USER IF NOT EXISTS '${DBUSER}'@'${host}' IDENTIFIED BY '${DBPASS}';"
    sql+="ALTER USER '${DBUSER}'@'${host}' IDENTIFIED BY '${DBPASS}';"
    sql+="GRANT ALL PRIVILEGES ON \`${DBNAME}\`.* TO '${DBUSER}'@'${host}';"
  done
  if dry; then
    echo "[dry-run] mariadb < (create database and user)"
  else
    local i
    for i in {1..30}; do
      mariadb-admin --socket="${MYSQL_SOCKET}" status > /dev/null 2>&1 && break
      sleep 2
    done
    mariadb --socket="${MYSQL_SOCKET}" <<< "${sql}" || die "Cannot create the database (is mariadb running?)"
  fi
}

render_valkey() {
  local dropin=/etc/systemd/system/valkey.service.d/crassostrea-cluster.conf
  if [[ ${HA_ROLE} == node ]]; then
    # Clients on this node keep using 127.0.0.1:6379, where haproxy forwards
    # to the current master
    write_file /etc/valkey/crassostrea.conf 0640 root:valkey <<EOF
# Generated by system/configure.sh (HA_NODES) - do not edit
# Cluster: TLS only, on the replication address; Sentinel elects the master
bind ${HA_SELF_ADDR}
port 0
tls-port ${HA_VALKEY_PORT}
tls-cert-file ${SF_PKI}/node.crt
tls-key-file ${SF_PKI}/node.key
tls-ca-cert-file ${SF_PKI}/ca.crt
tls-auth-clients yes
tls-replication yes
protected-mode yes
requirepass ${REDISPASS}
masterauth ${REDISPASS}
replica-announce-ip ${HA_SELF_ADDR}
replica-announce-port ${HA_VALKEY_PORT}
EOF
    create_file /var/lib/valkey/crassostrea-role.conf 0640 root:valkey <<< "# Written by valkey-role"
    # Sentinel makes valkey rewrite its main configuration file after every
    # role change (CONFIG REWRITE), copying all settings into it, which would
    # then override changes to the files above. In a cluster valkey starts
    # from this file, which it cannot write: the rewrite fails without harm
    # and valkey-role sets the role at each start.
    write_file "${VALKEY_CLUSTER_CONF}" 0644 <<EOF
# Generated by system/configure.sh (HA_NODES) - do not edit
include /etc/valkey/valkey.conf
include /var/lib/valkey/crassostrea-role.conf
EOF
    write_file "${dropin}" 0644 <<EOF
# Generated by system/configure.sh (HA_NODES) - do not edit
[Service]
EnvironmentFile=${SF_CONF}
ExecStartPre=+${SF_LIBEXEC}/valkey-role
ExecStart=
ExecStart=/usr/bin/valkey-server ${VALKEY_CLUSTER_CONF} --daemonize no --supervised systemd
EOF
  else
    write_file /etc/valkey/crassostrea.conf 0640 root:valkey <<EOF
# Generated by system/configure.sh - do not edit
bind 127.0.0.1 -::1
port 6379
protected-mode yes
requirepass ${REDISPASS}
EOF
    rm -f "$(p "${dropin}")" "$(p /var/lib/valkey/crassostrea-role.conf)" "$(p "${VALKEY_CLUSTER_CONF}")"
  fi
  local conf
  conf=$(p /etc/valkey/valkey.conf)
  if [[ -f ${conf} ]] && ! grep -qx 'include /etc/valkey/crassostrea.conf' "${conf}"; then
    printf '\n# Crassostrea gateway\ninclude /etc/valkey/crassostrea.conf\n' >> "${conf}"
  fi
}

# --------------------------------------------------------------------------
# Unbound and the host resolver
# --------------------------------------------------------------------------
render_unbound() {
  {
    cat "${SF_SRC}/data/conf/unbound/unbound.conf"
    ip_unbound_lines "${IPV4_ENABLED:-y}" "${IPV6_ENABLED:-true}"
  } | write_file /etc/unbound/conf.d/crassostrea.conf 0644
  run_hooks unbound
}

# The local unbound must be the host's resolver: Postfix (postscreen DNSBL)
# uses the system resolver, and DNSBLs refuse queries from public resolvers.
use_local_resolver() {
  is_yes "${MANAGE_RESOLVER:-y}" || return 0
  log "Using unbound (127.0.0.1) as the system resolver"
  write_file /etc/NetworkManager/conf.d/90-crassostrea-dns.conf 0644 <<'EOF'
# Generated by system/configure.sh (MANAGE_RESOLVER=y): /etc/resolv.conf
# points to the local unbound and is not managed by NetworkManager
[main]
dns=none
EOF
  local resolv
  resolv=$(p /etc/resolv.conf)
  if [[ -e ${resolv} && ! -e $(p /etc/resolv.conf.crassostrea-orig) ]] && ! grep -q 'crassostrea' "${resolv}"; then
    cp -aL "${resolv}" "$(p /etc/resolv.conf.crassostrea-orig)"
  fi
  [[ -L ${resolv} ]] && rm -f "${resolv}"
  write_file /etc/resolv.conf 0644 <<'EOF'
# Generated by system/configure.sh: local validating resolver (unbound).
# The previous file is in /etc/resolv.conf.crassostrea-orig.
nameserver 127.0.0.1
options edns0 trust-ad
EOF
  run systemctl reload NetworkManager 2> /dev/null || true
}

# --------------------------------------------------------------------------
# Postfix
# --------------------------------------------------------------------------
sql_map() {
  write_file "${POSTFIX_DIR}/sql/$1" 0640 root:postfix <<EOF
# Generated by system/configure.sh - do not edit
user = ${DBUSER}
password = ${DBPASS}
hosts = unix:${MYSQL_SOCKET}
dbname = ${DBNAME}
$(cat)
EOF
}

postfix_dnsbl() {
  local dnsbl key status=""
  create_file "${POSTFIX_DIR}/dns_blocklists.cf" 0644 <<'EOF'
# This file can be edited.
# Delete this file and run system/configure.sh to revert any changes.
postscreen_dnsbl_sites = wl.mailspike.net=127.0.0.[18;19;20]*-2
  hostkarma.junkemailfilter.com=127.0.0.1*-2
  list.dnswl.org=127.0.[0..255].0*-2
  list.dnswl.org=127.0.[0..255].1*-4
  list.dnswl.org=127.0.[0..255].2*-6
  list.dnswl.org=127.0.[0..255].3*-8
  bl.spamcop.net*2
  bl.suomispam.net*2
  hostkarma.junkemailfilter.com=127.0.0.2*3
  hostkarma.junkemailfilter.com=127.0.0.4*2
  hostkarma.junkemailfilter.com=127.0.1.2*1
  backscatter.spameatingmonkey.net*2
  bl.ipv6.spameatingmonkey.net*2
  bl.spameatingmonkey.net*2
  b.barracudacentral.org=127.0.0.2*7
  bl.mailspike.net=127.0.0.2*5
  bl.mailspike.net=127.0.0.[10;11;12]*4
EOF
  # Remove discontinued DNSBLs
  sed -i '/ix\.dnsbl\.manitu\.net\*2/d' "$(p "${POSTFIX_DIR}/dns_blocklists.cf")"
  dnsbl=$(grep -v '^#' "$(p "${POSTFIX_DIR}/dns_blocklists.cf")" | grep '\S')
  [[ -z ${dnsbl} ]] && return 0

  # The Spamhaus part: the key of the web UI's settings (system/lib/spamhaus.sh;
  # spamhaus-apply sets sf_spamhaus_dnsbl the same way when it changes)
  key=$(spamhaus_key)
  if [[ -n ${key} ]]; then
    log "Using the Spamhaus DQS blocklists"
  else
    if dry; then
      status=${SF_ASN_RESPONSE:-200}
    else
      status=$(spamhaus_asn_status)
    fi
    if [[ ${status} == 503 ]]; then
      warn "The AS of this server is banned by Spamhaus and there is no Spamhaus DQS key: Spamhaus blocklists disabled"
      warn "Enter a key (free at spamhaus.com) in the web UI: Settings -> General, Scanning."
    elif [[ ${status} != 200 ]]; then
      warn "Cannot determine the AS of this server (HTTP ${status}): Spamhaus blocklists disabled"
    fi
  fi
  spamhaus_reply_map "${key}" | write_file "${SPAMHAUS_REPLY_MAP}" 0644
  printf '%s\n  $sf_spamhaus_dnsbl\nsf_spamhaus_dnsbl = %s\npostscreen_dnsbl_reply_map = texthash:%s\n' \
    "${dnsbl}" "$(spamhaus_postscreen "${key}" "${status}")" "${SPAMHAUS_REPLY_MAP}"
}

# postfix_rate_limits FILE: the anvil limits the web UI wrote (parameter=value),
# only known parameters with whole numbers
postfix_rate_limits() {
  local line
  [[ -f $(p "$1") ]] || return 0
  while IFS= read -r line; do
    if [[ ${line} =~ ^(smtpd_client_(connection_count|connection_rate|message_rate|recipient_rate)_limit)=([0-9]{1,6})$ ]]
    then
      echo "${BASH_REMATCH[1]} = ${BASH_REMATCH[3]}"
    fi
  done < "$(p "$1")"
}

# postfix_ptr_check FILE: sf_ptr_check and its reply code for the web UI's
# setting (off, defer or reject; anything else: off)
postfix_ptr_check() {
  local mode=
  [[ -f $(p "$1") ]] && mode=$(tr -d '[:space:]' < "$(p "$1")")
  case ${mode} in
    defer) printf 'sf_ptr_check = reject_unknown_reverse_client_hostname\nunknown_client_reject_code = 450\n' ;;
    reject) printf 'sf_ptr_check = reject_unknown_reverse_client_hostname\nunknown_client_reject_code = 550\n' ;;
    *) printf 'sf_ptr_check =\n' ;;
  esac
}

render_postfix() {
  log "Rendering the Postfix configuration"
  local conf=${SF_SRC}/data/conf/postfix
  install_file "${conf}/local_transport" "${POSTFIX_DIR}/local_transport" 0644
  install_file "${conf}/postscreen_access.cidr" "${POSTFIX_DIR}/postscreen_access.cidr" 0644
  create_file "${POSTFIX_DIR}/custom_transport.pcre" 0640 root:postfix < /dev/null
  create_file "${POSTFIX_DIR}/custom_postscreen_whitelist.cidr" 0644 <<'EOF'
# Rules are evaluated in the order as specified.
# Blacklist 192.168.* except 192.168.0.1.
# 192.168.0.1          permit
# 192.168.0.0/16       reject
EOF

  sql_map mysql_relay_domains.cf <<'EOF'
query = SELECT name FROM domains WHERE name='%s' AND active=1
EOF
  # Domain routing: deliver to the downstream server of the domain.
  # Brackets suppress MX lookups unless "use MX" is enabled for the domain.
  sql_map mysql_transport_maps.cf <<'EOF'
query = SELECT CONCAT('relay:',
    IF(use_mx=1, destination_host, CONCAT('[', destination_host, ']')),
    ':', destination_port) AS transport
  FROM domains WHERE name='%s' AND active=1
EOF
  # Valid recipients:
  #  - recipient_check "any" or "verify": every address of the domain is
  #    accepted here ("verify" is enforced by mysql_recipient_verify.cf)
  #  - recipient_check "list": only addresses from the recipients table
  #  - recipient_check "directory": the same, the table synchronised from
  #    LDAP or Microsoft 365 by the web UI (crassostrea-job-directories.timer)
  sql_map mysql_relay_recipient_maps.cf <<'EOF'
query = SELECT '%s' FROM domains
    WHERE name='%d' AND active=1 AND recipient_check IN ('any', 'verify')
  UNION
  SELECT r.address FROM recipients r
    JOIN domains d ON d.id = r.domain_id
    WHERE r.address='%s' AND r.active=1 AND d.active=1 AND d.recipient_check IN ('list', 'directory')
EOF
  # SMTP call-ahead verification against the downstream server
  sql_map mysql_recipient_verify.cf <<'EOF'
query = SELECT 'reject_unverified_recipient' FROM domains
  WHERE name='%d' AND active=1 AND recipient_check='verify'
EOF

  # Relay networks, maintained by the web UI (crassostrea user). Not below
  # /etc/postfix: postfix check warns about every file there that is not
  # owned by root. A systemd path unit reloads Postfix when the file is
  # replaced.
  local dynamic=${SF_STATE}/postfix
  mkdir -p "$(p "${dynamic}")"
  dry || chown "${SF_USER}:root" "$(p "${dynamic}")"
  create_file "${dynamic}/relay_networks.cidr" 0644 "${SF_USER}:root" <<'EOF'
# Managed by the Crassostrea web UI - manual changes will be overwritten
EOF
  # A cluster node in maintenance answers new mail with 421 (written by
  # system/libexec/cluster-node; empty otherwise)
  create_file "${dynamic}/maintenance.cidr" 0644 <<'EOF'
# Written by system/libexec/cluster-node - do not edit
EOF
  # Networks without rate limits (Rate limits page of the web UI)
  create_file "${dynamic}/rate_limit_exempt.cidr" 0644 "${SF_USER}:root" <<'EOF'
# Managed by the Crassostrea web UI - manual changes will be overwritten
EOF
  # Hosts the PTR check skips: the global allow list's addresses (web UI)
  create_file "${dynamic}/client_exempt.cidr" 0644 "${SF_USER}:root" <<'EOF'
# Managed by the Crassostrea web UI - manual changes will be overwritten
EOF

  # Overrides appended to main.cf: DNSBLs, mynetworks, extra.cf (the
  # administrator's overrides, starting with myhostname). The message size
  # limit of the web UI replaces every message_size_limit, as postconf -e in
  # system/libexec/postfix-apply does.
  local extra limit
  limit=$(tr -d '[:space:]' < "$(p "${dynamic}/message_size_limit")" 2> /dev/null)
  [[ ${limit} =~ ^[0-9]{1,10}$ ]] && (( limit >= 1048576 && limit <= 104857600 )) || limit=
  extra=$(p "${POSTFIX_DIR}/extra.cf")
  touch "${extra}"
  sed -i '/\$myhostname/! { /^myhostname/d }' "${extra}"
  printf 'myhostname = %s\n%s\n' "${CRASSOSTREA_HOSTNAME}" "$(cat "${extra}")" | write_file "${POSTFIX_DIR}/extra.cf" 0644
  {
    sed '/^# Overrides #/q' "${conf}/main.cf"
    echo
    postfix_dnsbl
    # Loopback (web UI re-injection, watchdog) and the relay networks
    echo "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 cidr:${dynamic}/relay_networks.cidr"
    # IP families (system/lib/ipfamily.sh)
    echo "inet_protocols = $(ip_postfix_inet_protocols "${IPV4_ENABLED:-y}" "${IPV6_ENABLED:-true}")"
    echo "smtp_address_preference = $(ip_postfix_address_preference "${IPV4_ENABLED:-y}" "${IPV6_ENABLED:-true}")"
    # Oldest TLS version of inbound SMTP (system/lib/tls.sh)
    echo "smtpd_tls_protocols = $(tls_postfix_protocols "${SMTP_TLS_MIN:-1.2}")"
    echo "smtpd_tls_mandatory_protocols = $(tls_postfix_protocols "${SMTP_TLS_MIN:-1.2}")"
    echo "tls_config_file = $(tls_postfix_config_file "${SMTP_TLS_MIN:-1.2}")"
    # Rate limits per sending host (Rate limits page; postfix-apply validates
    # and applies them the same way)
    postfix_rate_limits "${dynamic}/rate_limits"
    # Hosts without a reverse DNS name (Settings; postfix-apply the same way)
    postfix_ptr_check "${dynamic}/ptr_check"
    echo
    echo "# User Overrides"
    cat "${extra}"
  } | if [[ -n ${limit} ]]; then sed "s/^message_size_limit[[:space:]]*=.*/message_size_limit = ${limit}/"; else cat; fi \
    | write_file "${POSTFIX_DIR}/main.cf" 0644

  {
    cat "${conf}/master.cf"
    if is_yes "${HAPROXY_LISTENER:-n}"; then
      # PROXY protocol listener for an HAProxy in front of the gateway. Off by
      # default: a client of this port can claim any address, including one
      # of the relay networks.
      echo
      echo "${HAPROXY_LISTENER_BIND:-127.0.0.1:10025} inet n - n - 1 postscreen"
      echo "  -o postscreen_upstream_proxy_protocol=haproxy"
      echo "  -o postscreen_cache_map=lmdb:\$data_directory/postscreen_cache_haproxy"
      echo "  -o syslog_name=haproxy"
    fi
  } | write_file "${POSTFIX_DIR}/master.cf" 0644

  # Bounces to the watchdog and to null are discarded
  local aliases name
  aliases=$(p /etc/aliases)
  touch "${aliases}"
  for name in null watchdog; do
    grep -q "^${name}:" "${aliases}" || echo "${name}: /dev/null" >> "${aliases}"
  done
  run newaliases
  run_hooks postfix
  dry || postfix check || die "postfix check failed"
}

# --------------------------------------------------------------------------
# Rspamd
# --------------------------------------------------------------------------
# Copy files of a directory without deleting others (e.g. *.custom.inc)
copy_dir() {
  local src=$1 dest=$2 f
  for f in "${src}"/*; do
    [[ -f ${f} ]] && install_file "${f}" "${dest}/$(basename "${f}")" 0644
  done
}

render_rspamd() {
  log "Rendering the Rspamd configuration"
  local conf=${SF_SRC}/data/conf/rspamd map
  copy_dir "${conf}/local.d" "${RSPAMD_DIR}/local.d"
  copy_dir "${conf}/override.d" "${RSPAMD_DIR}/override.d"
  copy_dir "${conf}/lua" "${RSPAMD_DIR}/lua"
  install_file "${conf}/rspamd.conf.override" "${RSPAMD_DIR}/rspamd.conf.override" 0644
  create_file "${RSPAMD_DIR}/rspamd.conf.local" 0644 < "${conf}/rspamd.conf.local"

  local password_hash="dry-run-hash"
  dry || password_hash=$(rspamadm pw -e -p "${RSPAMD_PASSWORD}" | tr -cd '0-9a-zA-Z$')
  write_file "${RSPAMD_DIR}/override.d/worker-controller-password.inc" 0640 root:_rspamd <<EOF
# Generated by system/configure.sh from RSPAMD_PASSWORD - do not edit
enable_password = "${password_hash}";
EOF
  # DMARC aggregate reports about received mail: collected by rspamd, sent
  # daily by crassostrea-dmarc-report.timer if the web UI allows it (Reports
  # page). set-hostname updates the name.
  write_file "${RSPAMD_DIR}/local.d/dmarc.conf" 0644 <<EOF
# Generated by system/configure.sh - do not edit
reporting {
  enabled = true;
  email = "dmarc-noreply@${CRASSOSTREA_HOSTNAME}";
  domain = "${CRASSOSTREA_HOSTNAME}";
  org_name = "${CRASSOSTREA_HOSTNAME}";
  from_name = "DMARC reports";
  helo = "${CRASSOSTREA_HOSTNAME}";
  smtp = "127.0.0.1";
  smtp_port = 25;
}
EOF
  write_file "${RSPAMD_DIR}/local.d/redis.conf" 0640 root:_rspamd <<EOF
# Generated by system/configure.sh - do not edit
servers = "127.0.0.1:6379";
password = "${REDISPASS}";
timeout = 10;
EOF

  if is_yes "${SKIP_OLEFY:-n}"; then
    rm -f "$(p "${RSPAMD_DIR}/local.d/external_services.conf")"
  else
    create_file "${RSPAMD_DIR}/local.d/external_services.conf" 0644 <<'EOF'
oletools {
  # crassostrea-olefy.service
  servers = "127.0.0.1:10055";
  scan_mime_parts = true;
  # block all macros
  extended = true;
  max_size = 3145728;
  timeout = 20.0;
  retransmits = 1;
}
EOF
  fi
  if is_yes "${SKIP_CLAMD:-n}"; then
    echo "enabled = false;" | write_file "${RSPAMD_DIR}/override.d/antivirus.conf" 0644
  else
    rm -f "$(p "${RSPAMD_DIR}/override.d/antivirus.conf")"
  fi

  # Maps: static ones from the repository, the rest belongs to the web UI
  local custom=${RSPAMD_DIR}/custom
  mkdir -p "$(p "${custom}")"
  chmod 0755 "$(p "${custom}")"
  dry || chown "${SF_USER}:root" "$(p "${custom}")"
  for map in ${RSPAMD_STATIC_MAPS}; do
    install_file "${conf}/custom/${map}" "${custom}/${map}" 0644 "${SF_USER}:root"
  done
  for map in global_mime_from_blacklist global_smtp_from_blacklist global_mime_from_whitelist \
      global_smtp_from_whitelist ip_wl ip_bl protected_domains \
      relay_networks; do
    create_file "${custom}/${map}.map" 0644 "${SF_USER}:root" < /dev/null
  done
  create_file "${custom}/sa-rules" 0644 < /dev/null
  printf '127.0.0.0/8\n::1/128\n' | write_file "${custom}/local_networks.map" 0644
  # Mail from rspamd itself (e.g. the watchdog's scan requests)
  printf '127.0.0.1/32\n::1/128\n' | write_file "${custom}/rspamd_trusted.map" 0644

  # The Spamhaus DQS rules of the web UI's key (system/lib/spamhaus.sh)
  spamhaus_rspamd "${conf}/dqs-rbl.conf.template" "$(spamhaus_key)" | write_file "${SPAMHAUS_RSPAMD_CONF}" 0644
  run_hooks rspamd
}

# --------------------------------------------------------------------------
# ClamAV, postfix-tlspol
# --------------------------------------------------------------------------
render_clamav() {
  install_file "${SF_SRC}/data/conf/clamav/clamd.conf" /etc/clamd.d/crassostrea.conf 0644
  install_file "${SF_SRC}/data/conf/clamav/freshclam.conf" /etc/freshclam.conf 0644
  create_file /var/lib/clamav/whitelist.ign2 0644 <<'EOF'
Example-Signature.Ignore-1
PUA.Win.Trojan.EmbeddedPDF-1
PUA.Pdf.Trojan.EmbeddedJavaScript-1
PUA.Pdf.Trojan.OpenActionObjectwithJavascript-1
EOF
}

render_tlspol() {
  local level=info
  is_yes "${DEV_MODE:-n}" && level=debug
  write_file /etc/postfix-tlspol/config.yaml 0644 <<EOF
# Generated by system/configure.sh - do not edit
server:
  address: 127.0.0.1:8642
  log-level: ${level}
  prefetch: true
  cache-file: /var/lib/postfix-tlspol/cache.db
dns:
  # must support DNSSEC
  address: 127.0.0.1:53
EOF
}

# --------------------------------------------------------------------------
# nginx
# --------------------------------------------------------------------------
# Comma separated networks -> one line per network; refuses anything that
# is not an address or network
nginx_listen() {
  # nginx_listen PORT BIND [PARAMETER...], e.g. ssl default_server
  local port=$1 bind=$2 extra
  shift 2
  extra=${*:+ $*}
  if [[ -n ${bind} ]]; then
    echo "  listen ${bind}:${port}${extra};"
  else
    echo "  listen ${port}${extra};"
    ip_enabled "${IPV6_ENABLED:-true}" && echo "  listen [::]:${port}${extra};"
  fi
}

# ACME HTTP-01 challenges: from the webroot of acme.sh. In a cluster a name
# shared by several nodes (VIP, ADDITIONAL_SAN) may lead the CA to another
# node than the one requesting the certificate: tokens missing here are
# fetched from the other nodes (marked, so they never forward again).
# Only with other nodes: nginx refuses an upstream without servers (a cluster
# of one node, while it grows)
acme_peers() {
  [[ ${HA_ROLE} == node && -n $(ha_node_peer_addrs) ]]
}

acme_locations() {
  echo '  location ^~ /.well-known/acme-challenge/ {'
  echo "    root ${ACME_WEBROOT};"
  echo '    default_type text/plain;'
  acme_peers && echo '    try_files $uri @acme_peers;'
  echo '  }'
  acme_peers || return 0
  echo
  echo '  location @acme_peers {'
  echo '    if ($http_x_crassostrea_acme_peer) {'
  echo '      return 404;'
  echo '    }'
  echo '    proxy_pass http://sf_acme_peers;'
  echo '    proxy_set_header Host $host;'
  echo '    proxy_set_header X-Crassostrea-Acme-Peer 1;'
  echo '    proxy_next_upstream error timeout http_404;'
  echo '    proxy_connect_timeout 3s;'
  echo '  }'
}

# The access log, and the same lines to the journal for netfilter's rules
# against scanners (system/libexec/logship follows the tag)
nginx_access_logs() {
  echo "  access_log /var/log/nginx/access.log sf_main;"
  echo "  access_log syslog:server=unix:/dev/log,tag=crassostrea_access,severity=info,nohostname sf_main;"
}

render_nginx() {
  local http_port=${HTTP_PORT:-80} https_port=${HTTPS_PORT:-443} locations redirect
  [[ ${http_port} =~ ^[0-9]+$ && ${https_port} =~ ^[0-9]+$ ]] || die "HTTP_PORT and HTTPS_PORT must be numbers"
  # The web UI's web server settings (system/lib/nginx.sh; nginx-apply
  # rewrites these files when they change)
  nginx_redirect_conf | write_file "${NGINX_REDIRECT_CONF}" 0644
  nginx_rspamd_access_conf | write_file "${NGINX_RSPAMD_ACCESS_CONF}" 0644
  nginx_real_ip_conf | write_file "${NGINX_REAL_IP_CONF}" 0644
  if [[ ${https_port} == 443 ]]; then
    redirect='https://$host$request_uri'
  else
    redirect="https://\$host:${https_port}\$request_uri"
  fi
  locations="
  # acme.sh --webroot writes the tokens to <webroot>/.well-known/acme-challenge/
$(acme_locations)
"'
  # Internal API of the web UI (rspamd only, on loopback)
  location ^~ /internal/ {
    return 404;
  }

  location = /rspamd {
    return 301 /rspamd/;
  }

  location /rspamd/ {
    include '"${NGINX_RSPAMD_ACCESS_CONF}"';
    rewrite ^/rspamd/(.*)$ /$1 break;
    proxy_pass http://127.0.0.1:11334;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 120s;
  }

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    # overwritten, never appended: the web UI trusts exactly one proxy hop
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_read_timeout 120s;
  }'

  {
    echo "# Generated by system/configure.sh - do not edit"
    echo "server_tokens off;"
    echo "client_max_body_size 64m;"
    echo
    echo "# Digest links and the links to set a password carry an access token in the path"
    echo "# (/q/<token>/..., /account/set-password/<token>), keep it out of the log"
    echo 'map $request $sf_request {'
    echo '  "~^(?<sf_req_pre>\S+ /(?:q|account/set-password)/)[^/?\s]+(?<sf_req_post>.*)$" "${sf_req_pre}[token]${sf_req_post}";'
    echo '  default $request;'
    echo '}'
    echo 'map $http_referer $sf_referer {'
    echo '  "~^(?<sf_ref_pre>.*?/(?:q|account/set-password)/)[^/?]+(?<sf_ref_post>.*)$" "${sf_ref_pre}[token]${sf_ref_post}";'
    echo '  default $http_referer;'
    echo '}'
    echo "# HTTP to HTTPS (Settings of the web UI), not for ACME challenges"
    echo 'map $uri $sf_https_redirect {'
    echo "  include ${NGINX_REDIRECT_CONF};"
    echo '  ~^/\.well-known/acme-challenge/ 0;'
    echo '}'
    echo "log_format sf_main '\$remote_addr - \$remote_user [\$time_local] \"\$sf_request\" '"
    echo "                   '\$status \$body_bytes_sent \"\$sf_referer\" \"\$http_user_agent\"';"
    echo
    if acme_peers; then
      echo "# The other cluster nodes, for ACME challenges (see @acme_peers)"
      echo "upstream sf_acme_peers {"
      ha_node_peer_addrs | while read -r peer; do
        echo "  server ${peer}:${http_port} max_fails=0;"
      done
      echo "}"
      echo
    fi
    echo "# Health check for the watchdog (8008 is an http_port_t port for SELinux)"
    echo "server {"
    echo "  listen 127.0.0.1:8008;"
    echo "  access_log off;"
    echo "  location / {"
    echo "    default_type text/plain;"
    echo "    return 200 \"ok\";"
    echo "  }"
    echo "}"
    echo
    echo "# Any other name, or an address: 404 (ACME challenges are answered for"
    echo "# every name, see system/lib/nginx.sh)"
    echo "server {"
    nginx_listen "${http_port}" "${HTTP_BIND}" default_server
    nginx_access_logs
    echo "  include ${NGINX_REAL_IP_CONF};"
    acme_locations
    echo '  location / {'
    echo '    return 404;'
    echo '  }'
    echo "}"
    echo
    echo "server {"
    nginx_listen "${https_port}" "${HTTPS_BIND}" ssl default_server
    echo "  http2 on;"
    nginx_access_logs
    echo "  include ${NGINX_REAL_IP_CONF};"
    nginx_tls_lines
    echo '  location / {'
    echo '    return 404;'
    echo '  }'
    echo "}"
    echo
    echo "# The web UI, for the names in ${NGINX_NAMES_CONF}"
    echo "server {"
    nginx_listen "${http_port}" "${HTTP_BIND}"
    echo "  include ${NGINX_NAMES_CONF};"
    nginx_access_logs
    echo "  include ${NGINX_REAL_IP_CONF};"
    echo '  if ($sf_https_redirect) {'
    echo "    return 301 ${redirect};"
    echo '  }'
    echo "${locations}"
    echo "}"
    echo
    echo "server {"
    nginx_listen "${https_port}" "${HTTPS_BIND}" ssl
    echo "  include ${NGINX_NAMES_CONF};"
    echo "  http2 on;"
    nginx_access_logs
    echo "  include ${NGINX_REAL_IP_CONF};"
    nginx_tls_lines
    echo "  add_header Strict-Transport-Security \"max-age=15768000\" always;"
    echo "${locations}"
    docs_nginx_locations
    echo "}"
  } | write_file /etc/nginx/conf.d/crassostrea.conf 0644
  # the names of the web UI (set-hostname and tls-apply rewrite it too)
  nginx_names_conf | write_file "${NGINX_NAMES_CONF}" 0644
}

# The documentation at /docs/ (DOCS_ENABLED, system/lib/docs.sh): a build
# failure only warns, the gateway does not depend on it
render_docs() {
  if is_yes "${DOCS_ENABLED:-n}"; then
    docs_fetch && docs_build
  else
    docs_remove
  fi
  return 0
}

# Certificate and protocols of an HTTPS server (tls-apply rewrites the
# ssl_protocols lines of both servers)
nginx_tls_lines() {
  echo "  ssl_certificate ${SSL_DIR}/cert.pem;"
  echo "  ssl_certificate_key ${SSL_DIR}/key.pem;"
  echo "  ssl_protocols $(tls_nginx_protocols "${HTTPS_TLS_MIN:-1.2}");"
  echo "  ssl_prefer_server_ciphers off;"
  echo "  ssl_session_cache shared:SSL:10m;"
  echo "  ssl_session_timeout 1d;"
}

# --------------------------------------------------------------------------
# Cluster (HA_NODES): Sentinel, haproxy, keepalived, arbitrator
# --------------------------------------------------------------------------
# Units of a cluster that this script configured before and that are no
# longer needed (the host left the cluster or HA_VIP was removed)
CLUSTER_OFF=()

# The original of a file replaced in a cluster is kept as FILE.crassostrea-orig
keep_original() {
  local file
  file=$(p "$1")
  if [[ -f ${file} && ! -e ${file}.crassostrea-orig ]] && ! grep -q 'Generated by system/configure.sh' "${file}"; then
    cp -a "${file}" "${file}.crassostrea-orig"
  fi
}

# restore_original FILE UNIT: undo keep_original if this script wrote FILE
restore_original() {
  local file
  file=$(p "$1")
  [[ -f ${file} ]] && grep -q 'Generated by system/configure.sh' "${file}" || return 0
  if [[ -e ${file}.crassostrea-orig ]]; then
    mv -f "${file}.crassostrea-orig" "${file}"
  else
    rm -f "${file}"
  fi
  CLUSTER_OFF+=("$2")
}

render_sentinel() {
  local dropin=/etc/systemd/system/valkey-sentinel.service.d/crassostrea-cluster.conf
  if [[ -z ${HA_ROLE} ]]; then
    if [[ -e $(p "${dropin}") ]]; then
      rm -f "$(p "${dropin}")" "$(p "${SF_STATE}/cluster/sentinel.conf")"
      CLUSTER_OFF+=(valkey-sentinel.service)
    fi
    return 0
  fi
  # Sentinel rewrites its configuration file with the state it learns: this
  # template is copied to /var/lib/valkey/sentinel.conf (with the current
  # master) only when it changed, see apply_sentinel
  write_file "${SF_STATE}/cluster/sentinel.conf" 0600 <<EOF
# Generated by system/configure.sh (HA_NODES, HA_WITNESS) - Sentinel adds the
# state it learns below
bind ${HA_SELF_ADDR}
port 0
tls-port ${HA_SENTINEL_PORT}
tls-cert-file ${SF_PKI}/node.crt
tls-key-file ${SF_PKI}/node.key
tls-ca-cert-file ${SF_PKI}/ca.crt
tls-auth-clients yes
tls-replication yes
requirepass ${REDISPASS}
dir /var/lib/valkey
sentinel announce-ip ${HA_SELF_ADDR}
sentinel announce-port ${HA_SENTINEL_PORT}
sentinel resolve-hostnames no
sentinel deny-scripts-reconfig yes
sentinel sentinel-pass ${REDISPASS}
# A majority of the $(ha_voters) members must agree that the master is down
sentinel monitor ${HA_CLUSTER_NAME} @MASTER@ ${HA_VALKEY_PORT} $(ha_quorum)
sentinel auth-pass ${HA_CLUSTER_NAME} ${REDISPASS}
sentinel down-after-milliseconds ${HA_CLUSTER_NAME} 5000
# A failover attempt that finds no replica with fresh state (Sentinel polls
# replicas every 10 s until a failover starts) is retried after twice this
sentinel failover-timeout ${HA_CLUSTER_NAME} 10000
sentinel parallel-syncs ${HA_CLUSTER_NAME} 1
EOF
  write_file "${dropin}" 0644 <<'EOF'
# Generated by system/configure.sh (HA_NODES) - do not edit
[Service]
ExecStart=
ExecStart=/usr/bin/valkey-sentinel /var/lib/valkey/sentinel.conf --daemonize no --supervised systemd
EOF
}

# Valkey forwarding for the clients on this node: 127.0.0.1:6379 always
# reaches the master
render_haproxy() {
  local cfg=/etc/haproxy/haproxy.cfg i
  if [[ ${HA_ROLE} != node ]]; then
    restore_original "${cfg}" haproxy.service
    return 0
  fi
  keep_original "${cfg}"
  {
    cat <<EOF
# Generated by system/configure.sh (HA_NODES) - do not edit
# Valkey for rspamd, the web UI, netfilter and logship on this node:
# 127.0.0.1:6379 is forwarded over TLS to the node that is the master
global
  log /dev/log local0 notice
  user haproxy
  group haproxy
  maxconn 4096

defaults
  mode tcp
  log global
  option dontlognull
  timeout connect 3s
  # pub/sub subscribers (netfilter) may be idle for a long time
  timeout client 24h
  timeout server 24h
  timeout check 3s

frontend valkey
  bind 127.0.0.1:6379
  default_backend valkey

backend valkey
  # the first master in the list: never two masters at the same time
  balance first
  option tcp-check
  tcp-check connect ssl
  tcp-check send "AUTH ${REDISPASS}\r\n"
  tcp-check expect string +OK
  tcp-check send "INFO replication\r\n"
  tcp-check expect string role:master
  tcp-check send "QUIT\r\n"
  tcp-check expect string +OK
  # clients of a demoted master reconnect to the new one
  default-server inter 1s fall 2 rise 2 on-marked-down shutdown-sessions ssl verify required ca-file ${SF_PKI}/ca.crt crt ${SF_PKI}/node.pem
EOF
    for i in "${!HA_NODE_NAMES[@]}"; do
      echo "  server ${HA_NODE_NAMES[i]} ${HA_NODE_ADDRS[i]}:${HA_VALKEY_PORT} check"
    done
  } | write_file "${cfg}" 0640 root:haproxy
}

# Floating address for the web UI (HA_VIP): on one node whose web UI and
# database work; it stays there until that node fails (nopreempt). VRRP runs
# on the interface with the node's cluster address; the address itself may
# be on another one (HA_VIP_INTERFACE, e.g. the public network)
render_keepalived() {
  local conf=/etc/keepalived/keepalived.conf iface vip_iface priority=100 i peer
  if [[ ${HA_ROLE} != node || -z ${HA_VIP} ]]; then
    restore_original "${conf}" keepalived.service
    rm -f "$(p /usr/libexec/keepalived/crassostrea-health)"
    return 0
  fi
  install_file "${SF_SRC}/system/keepalived/crassostrea-health" /usr/libexec/keepalived/crassostrea-health 0755
  if dry; then
    iface=eth0
  else
    iface=$(ip -o -4 addr show | awk -v addr="${HA_SELF_ADDR}" '{split($4, a, "/")} a[1] == addr {print $2; exit}')
  fi
  [[ -n ${iface} ]] || die "No interface has the cluster address ${HA_SELF_ADDR}"
  vip_iface=${HA_VIP_INTERFACE:-${iface}}
  dry || ip link show dev "${vip_iface}" > /dev/null 2>&1 \
    || die "HA_VIP_INTERFACE: there is no interface ${vip_iface}"
  for i in "${!HA_NODE_ADDRS[@]}"; do
    [[ ${HA_NODE_ADDRS[i]} == "${HA_SELF_ADDR}" ]] && priority=$(( 200 - i * 10 ))
  done
  keep_original "${conf}"
  {
    cat <<EOF
# Generated by system/configure.sh (HA_VIP) - do not edit
global_defs {
  router_id ${CRASSOSTREA_HOSTNAME,,}
  enable_script_security
  script_user root
}

vrrp_script crassostrea_health {
  script "/usr/libexec/keepalived/crassostrea-health"
  interval 5
  timeout 10
  fall 2
  rise 2
}

vrrp_instance crassostrea {
  state BACKUP
  nopreempt
  interface ${iface}
  virtual_router_id ${HA_VIP_ROUTER_ID:-51}
  priority ${priority}
  advert_int 1
  unicast_src_ip ${HA_SELF_ADDR}
EOF
    # a cluster of one node (growing in the web UI) has no peers yet
    if [[ -n $(ha_node_peer_addrs) ]]; then
      echo "  unicast_peer {"
      ha_node_peer_addrs | while read -r peer; do
        echo "    ${peer}"
      done
      echo "  }"
    fi
    cat <<EOF
  virtual_ipaddress {
    ${HA_VIP} dev ${vip_iface}
  }
EOF
    # the address is given up when its interface goes down, like VRRP's own
    if [[ ${vip_iface} != "${iface}" ]]; then
      printf '  track_interface {\n    %s\n  }\n' "${vip_iface}"
    fi
    cat <<EOF
  track_script {
    crassostrea_health
  }
}
EOF
  } | write_file "${conf}" 0640
}

# Galera arbitrator on the witness: a vote without a copy of the database.
# It keeps its view of the cluster (gvwstate.dat) in /var/lib/garb.
render_garbd() {
  write_file /etc/sysconfig/garb 0644 <<EOF
# Generated by system/configure.sh (HA_WITNESS) - do not edit
GALERA_NODES="$(printf '%s:4567 ' "${HA_NODE_ADDRS[@]}" | sed 's/ $//')"
GALERA_GROUP="${HA_CLUSTER_NAME}"
GALERA_OPTIONS="socket.ssl_ca=${SF_PKI}/ca.crt;socket.ssl_cert=${SF_PKI}/node.crt;socket.ssl_key=${SF_PKI}/node.key"
WORK_DIR="/var/lib/garb"
EOF
  write_file /etc/systemd/system/garb.service.d/crassostrea-cluster.conf 0644 <<'EOF'
# Generated by system/configure.sh (HA_WITNESS) - do not edit
[Service]
StateDirectory=garb
Restart=on-failure
RestartSec=5
EOF
}

# The gateway's services reach Valkey through haproxy; the maps follow
# changes made on other nodes within a minute
render_cluster_units() {
  local unit file
  for unit in crassostrea-web.service crassostrea-web-internal.service crassostrea-logship.service \
      crassostrea-netfilter.service crassostrea-watchdog.service crassostrea-job@.service rspamd.service; do
    file=/etc/systemd/system/${unit}.d/crassostrea-cluster.conf
    if [[ ${HA_ROLE} == node ]]; then
      printf '%s\n' "# Generated by system/configure.sh (HA_NODES) - do not edit" "[Unit]" \
        "After=haproxy.service" "Wants=haproxy.service" | write_file "${file}" 0644
    else
      rm -f "$(p "${file}")"
    fi
  done
  file=/etc/systemd/system/crassostrea-job-sync.timer.d/crassostrea-cluster.conf
  if [[ ${HA_ROLE} == node ]]; then
    printf '%s\n' "# Generated by system/configure.sh (HA_NODES) - do not edit" "[Timer]" \
      "OnUnitActiveSec=" "OnUnitActiveSec=1min" | write_file "${file}" 0644
  else
    rm -f "$(p "${file}")"
  fi
}

# Members restart the database, Valkey and Sentinel only when their
# configuration changed: every restart removes a vote for a while
declare -A PENDING_SUM

# config_sum FILE...: of the names and contents (the name can matter too,
# e.g. the order of /etc/my.cnf.d)
config_sum() {
  local file
  for file in "$@"; do
    printf '%s\n' "${file}"
    cat "$(p "${file}")" 2> /dev/null
  done | sha256sum | cut -d' ' -f1
}

# needs_restart UNIT FILE...: is UNIT stopped or did FILE... change since
# remember_config UNIT?
needs_restart() {
  local unit=$1
  shift
  PENDING_SUM[${unit}]=$(config_sum "$@")
  dry && return 0
  systemctl is-active --quiet "${unit}" || return 0
  [[ ${PENDING_SUM[${unit}]} != "$(cat "${SF_STATE}/config-hashes/${unit}" 2> /dev/null)" ]]
}

remember_config() {
  mkdir -p "$(p "${SF_STATE}/config-hashes")"
  echo "${PENDING_SUM[$1]}" > "$(p "${SF_STATE}/config-hashes/$1")"
}

restart_if_changed() {
  if needs_restart "$@"; then
    log "Restarting $1"
    run systemctl restart "$1" || { warn "$1 failed to start, see: journalctl -u $1"; return 1; }
    remember_config "$1"
  else
    log "$1: configuration unchanged, not restarted"
  fi
}

# The Valkey master: as reported by the Sentinels, else the first node whose
# Valkey is a master, else this node (a new cluster)
find_valkey_master() {
  local master addr
  dry && { echo "${HA_NODE_ADDRS[0]}"; return 0; }
  master=$("${SF_SRC}/system/libexec/valkey-role" --print)
  if [[ -z ${master} ]]; then
    for addr in "${HA_NODE_ADDRS[@]}"; do
      if valkey_tls "${addr}" "${HA_VALKEY_PORT}" INFO replication | grep -q '^role:master'; then
        master=${addr}
        break
      fi
    done
  fi
  if [[ -z ${master} ]]; then
    [[ ${HA_ROLE} == node ]] && master=${HA_SELF_ADDR} || master=${HA_NODE_ADDRS[0]}
  fi
  echo "${master}"
}

apply_sentinel() {
  local template=${SF_STATE}/cluster/sentinel.conf live=/var/lib/valkey/sentinel.conf master
  if ! needs_restart valkey-sentinel.service "${template}" "${SF_PKI}/node.crt" && [[ -s $(p "${live}") ]]; then
    log "valkey-sentinel.service: configuration unchanged, not restarted"
    return 0
  fi
  master=$(find_valkey_master)
  log "Starting Sentinel: master ${master}, quorum $(ha_quorum) of $(ha_voters) votes"
  sed "s/@MASTER@/${master}/" "$(p "${template}")" | write_file "${live}" 0600 valkey:valkey
  run systemctl restart valkey-sentinel.service || { warn "valkey-sentinel failed to start"; return 1; }
  remember_config valkey-sentinel.service
}

# Start MariaDB as a Galera node: a new cluster (SF_GALERA_BOOTSTRAP=y, set
# by setup.sh --ha) or join the running one
start_galera() {
  if ! needs_restart mariadb.service "${MARIADB_CNF}" "${SF_PKI}/node.crt"; then
    log "mariadb.service: configuration unchanged, not restarted"
    return 0
  fi
  local bootstrap=${SF_GALERA_BOOTSTRAP:-n} addr
  if [[ ${bootstrap} == y ]] && ! dry; then
    for addr in $(ha_node_peer_addrs); do
      if ha_reachable "${addr}" 4567; then
        warn "The cluster node ${addr} is running: joining its cluster instead of creating a new one"
        bootstrap=n
        break
      fi
    done
  fi
  if [[ ${bootstrap} == y ]]; then
    log "Creating the database cluster (Galera) on ${CRASSOSTREA_HOSTNAME}"
    run galera_new_cluster || die "Cannot create the Galera cluster, see: journalctl -u mariadb"
  else
    log "Starting MariaDB and joining the cluster (a new node first copies the database)"
    run systemctl restart mariadb.service || die "MariaDB cannot join the cluster: are other nodes running?" \
      "After all nodes were down, run system/cluster.sh bootstrap on the node with the latest data."
  fi
  remember_config mariadb.service
}

start_cluster_base() {
  start_galera
  restart_if_changed valkey.service /etc/valkey/crassostrea.conf "${VALKEY_CLUSTER_CONF}" \
    /etc/systemd/system/valkey.service.d/crassostrea-cluster.conf "${SF_PKI}/node.crt"
  apply_sentinel
  restart_if_changed haproxy.service /etc/haproxy/haproxy.cfg "${SF_PKI}/node.pem"
  log "Restarting unbound.service"
  run systemctl restart unbound.service
}

# The witness runs the Galera arbitrator and a Sentinel, nothing else
configure_witness() {
  log "Configuring ${CRASSOSTREA_HOSTNAME} (${HA_SELF_ADDR}) as the cluster witness"
  pki_install_node
  render_garbd
  render_sentinel
  selinux_port redis_port_t "${HA_VALKEY_PORT}"
  open_firewall
  if ! dry && command -v restorecon > /dev/null; then
    restorecon -R "${SF_PKI}" /var/lib/valkey /etc/systemd/system 2> /dev/null
  fi
  run systemctl daemon-reload
  run systemctl enable garb.service valkey-sentinel.service
  [[ ${RESTART} == y ]] || return 0
  restart_if_changed garb.service /etc/sysconfig/garb /etc/systemd/system/garb.service.d/crassostrea-cluster.conf \
    "${SF_PKI}/node.crt"
  apply_sentinel
}

# --------------------------------------------------------------------------
# Units, firewall, SELinux ports
# --------------------------------------------------------------------------
# Services shown on the dashboard and (re)started by this script, in order;
# the first BASE_UNITS are started before the database is set up
select_units() {
  UNITS=(mariadb.service valkey.service)
  [[ ${HA_ROLE} == node ]] && UNITS+=(valkey-sentinel.service haproxy.service)
  UNITS+=(unbound.service)
  BASE_UNITS=${#UNITS[@]}
  is_yes "${SKIP_CLAMD:-n}" || UNITS+=(clamav-freshclam.service clamd@crassostrea.service)
  is_yes "${SKIP_OLEFY:-n}" || UNITS+=(crassostrea-olefy.service)
  UNITS+=(crassostrea-postfix-tlspol.service crassostrea-web.service crassostrea-web-internal.service rspamd.service
    postfix.service nginx.service crassostrea-netfilter.service crassostrea-logship.service crassostrea-siem.service
    crassostrea-journal.service)
  is_yes "${USE_WATCHDOG:-y}" && UNITS+=(crassostrea-watchdog.service)
  [[ ${HA_ROLE} == node && -n ${HA_VIP} ]] && UNITS+=(keepalived.service)
  # Cluster page: maintenance, Valkey master, the nodes' reports
  [[ ${HA_ROLE} == node ]] && UNITS+=(crassostrea-cluster.service crassostrea-cluster-report.service)

  # Started on demand or by timers
  TRIGGERS=(crassostrea-postfix-control.socket crassostrea-logs.socket crassostrea-cluster-setup.path
    crassostrea-postfix-reload.path crassostrea-hostname.path
    crassostrea-tls.path crassostrea-network.path crassostrea-backup.timer crassostrea-backup-request.path
    crassostrea-job-cleanup.timer crassostrea-job-sync.timer crassostrea-job-digests.timer crassostrea-sa-rules.timer
    crassostrea-job-directories.timer crassostrea-dmarc-report.timer crassostrea-job-alerts.timer
    crassostrea-job-accounts.timer crassostrea-timezone.path crassostrea-nginx.path crassostrea-spamhaus.path)
  is_yes "${SKIP_CLAMD:-n}" || TRIGGERS+=(crassostrea-clamav-sigs.timer)
  is_yes "${SKIP_LETS_ENCRYPT:-n}" || TRIGGERS+=(crassostrea-acme.timer)

  # Units of optional components that are switched off
  DISABLED=("${CLUSTER_OFF[@]}")
  [[ ${HA_ROLE} == node ]] || DISABLED+=(crassostrea-cluster.service crassostrea-cluster-report.service)
  is_yes "${SKIP_CLAMD:-n}" && DISABLED+=(clamav-freshclam.service clamd@crassostrea.service crassostrea-clamav-sigs.timer)
  is_yes "${SKIP_OLEFY:-n}" && DISABLED+=(crassostrea-olefy.service)
  is_yes "${USE_WATCHDOG:-y}" || DISABLED+=(crassostrea-watchdog.service)
  is_yes "${SKIP_LETS_ENCRYPT:-n}" && DISABLED+=(crassostrea-acme.timer)

  printf 'CRASSOSTREA_UNITS=%s\n' "$(IFS=,; echo "${UNITS[*]}")" | write_file "${SF_ETC}/units.env" 0644
}

open_firewall() {
  dry && return 0
  if ! systemctl is-active --quiet firewalld; then
    warn "firewalld is not running: make sure ports ${SMTP_PORT:-25}, ${HTTP_PORT:-80} and ${HTTPS_PORT:-443} are reachable"
    [[ -n ${HA_ROLE} ]] && warn "and that only the cluster members reach the cluster ports"
    return 0
  fi
  local port
  if [[ ${HA_ROLE} != witness ]]; then
    for port in "${SMTP_PORT:-25}" "${HTTP_PORT:-80}" "${HTTPS_PORT:-443}"; do
      firewall-cmd --quiet --permanent --add-port="${port}/tcp"
    done
  fi
  cluster_firewall
  firewall-cmd --quiet --reload
}

# Cluster ports are open to the other members only: a firewalld zone whose
# sources are their addresses (zone crassostrea-cluster)
cluster_firewall() {
  local zone=${HA_ZONE} item sources ports=() zones
  zones=" $(firewall-cmd --permanent --get-zones) "
  if [[ -z ${HA_ROLE} ]]; then
    [[ ${zones} == *" ${zone} "* ]] && firewall-cmd --quiet --permanent --delete-zone="${zone}"
    return 0
  fi
  [[ ${zones} == *" ${zone} "* ]] || firewall-cmd --quiet --permanent --new-zone="${zone}"
  sources=$(ha_peer_addrs)
  if [[ ${HA_ROLE} == witness ]]; then
    ports=(4567/tcp "${HA_SENTINEL_PORT}/tcp")
  else
    for item in "${HA_GALERA_PORTS[@]}" "${HA_VALKEY_PORT}" "${HA_SENTINEL_PORT}" "${SMTP_PORT:-25}" \
        "${HTTP_PORT:-80}" "${HTTPS_PORT:-443}"; do
      ports+=("${item}/tcp")
    done
  fi
  for item in $(firewall-cmd --permanent --zone="${zone}" --list-sources); do
    grep -qxF "${item}" <<< "${sources}" || firewall-cmd --quiet --permanent --zone="${zone}" --remove-source="${item}"
  done
  for item in ${sources}; do
    firewall-cmd --quiet --permanent --zone="${zone}" --add-source="${item}" \
      || warn "Cannot add ${item} to the firewall zone ${zone} (is it a source of another zone?)"
  done
  for item in $(firewall-cmd --permanent --zone="${zone}" --list-ports); do
    [[ " ${ports[*]} " == *" ${item} "* ]] || firewall-cmd --quiet --permanent --zone="${zone}" --remove-port="${item}"
  done
  for item in "${ports[@]}"; do
    firewall-cmd --quiet --permanent --zone="${zone}" --add-port="${item}"
  done
  firewall-cmd --quiet --permanent --zone="${zone}" --add-service=ssh
  if [[ ${HA_ROLE} == node && -n ${HA_VIP} ]]; then
    firewall-cmd --quiet --permanent --zone="${zone}" --add-protocol=vrrp
  else
    firewall-cmd --quiet --permanent --zone="${zone}" --remove-protocol=vrrp
  fi
}

# Non-standard web ports must be labelled for the confined nginx; in a
# cluster, Valkey's TLS port is a redis port, the Galera ports are mysqld
# ports and haproxy forwards to Valkey
selinux_ports() {
  selinux_port http_port_t "${HTTP_PORT:-80}"
  selinux_port http_port_t "${HTTPS_PORT:-443}"
  [[ ${HA_ROLE} == node ]] || return 0
  selinux_port redis_port_t "${HA_VALKEY_PORT}"
  selinux_port mysqld_port_t 4568
  selinux_port mysqld_port_t 4444
  if ! dry && selinuxenabled 2> /dev/null && [[ $(getsebool haproxy_connect_any 2> /dev/null) != *on ]]; then
    setsebool -P haproxy_connect_any 1
  fi
}

start_services() {
  if ! dry && command -v restorecon > /dev/null; then
    restorecon -R /etc/postfix /etc/rspamd /etc/crassostrea /etc/systemd/system "${SF_LIB}" "${SF_LIBEXEC}" \
      "${SF_STATE}" 2> /dev/null
    [[ -n ${HA_ROLE} ]] && restorecon -R "${SF_PKI}" /var/lib/valkey /etc/haproxy /etc/keepalived \
      /usr/libexec/keepalived 2> /dev/null
  fi
  run systemctl daemon-reload
  run systemd-tmpfiles --create /etc/tmpfiles.d/crassostrea.conf
  [[ ${#DISABLED[@]} -gt 0 ]] && run systemctl disable --now "${DISABLED[@]}" 2> /dev/null
  run systemctl enable "${UNITS[@]}" "${TRIGGERS[@]}"
  [[ ${RESTART} == y ]] || return 0

  if [[ ${HA_ROLE} == node ]]; then
    start_cluster_base
  else
    log "Starting the database, valkey and unbound"
    run systemctl restart mariadb.service valkey.service unbound.service
  fi
  setup_database
  if dry || systemctl is-active --quiet unbound.service; then
    use_local_resolver
  else
    warn "unbound is not running, the system resolver was left unchanged"
  fi
  local unit
  for unit in "${UNITS[@]:${BASE_UNITS}}"; do
    if [[ ${unit} == keepalived.service ]]; then
      restart_if_changed keepalived.service /etc/keepalived/keepalived.conf
      continue
    fi
    log "Restarting ${unit}"
    run systemctl restart "${unit}" || warn "${unit} failed to start, see: journalctl -u ${unit}"
  done
  run systemctl restart "${TRIGGERS[@]}"
}

# --------------------------------------------------------------------------
if [[ ${HA_ROLE} == witness ]]; then
  configure_witness
  log "Configuration complete."
  exit 0
fi
deploy
[[ ${HA_ROLE} == node ]] && pki_install_node
render_tls
render_mariadb
render_valkey
render_sentinel
render_haproxy
render_keepalived
render_cluster_units
render_unbound
render_postfix
render_rspamd
render_clamav
render_tlspol
render_docs
render_nginx
select_units
selinux_ports
open_firewall
start_services
log "Configuration complete."
