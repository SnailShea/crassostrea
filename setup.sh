#!/usr/bin/env bash
# Sets up the Crassostrea gateway on a fresh EL10 host (AlmaLinux, Rocky
# Linux or RHEL 10), start to finish:
#
#   1. checks the host (root, EL10, architecture, memory, free ports)
#   2. installs the tools this script needs
#   3. creates /etc/crassostrea/crassostrea.conf unless it exists
#   4. installs and starts everything (system/install.sh: repositories,
#      packages, users, builds, configuration, services)
#
# Usage: sudo ./setup.sh [options]
#   --hostname FQDN   gateway hostname (MX target), instead of asking
#   --yes             no questions: needs --hostname for a new configuration,
#                     disables ClamAV on hosts with <= 2.5 GiB RAM
#   --reconfigure     create a new configuration with new passwords even if
#                     one exists (the old one is kept as crassostrea.conf.bak)
#   --config-only     stop after creating the configuration
#   --docs            also deploy the documentation at https://<hostname>/docs/
#                     (administrators only), from the crassostrea-docs
#                     checkout next to this repository, else from
#                     github.com/SnailShea/crassostrea-docs
#   --docs-source SRC the same from SRC, a git URL or directory of crassostrea-docs
#   --no-docs         do not deploy it (and do not ask). Later: system/docs.sh
#
# High availability (see README, "High availability"):
#   --ha              make this host the first node of a new cluster (also
#                     turns an installed gateway into one); asks for:
#   --ha-nodes LIST     full nodes: hostname=address,... (this host first)
#   --ha-witness H=A    vote-only witness host, or "none"
#   --ha-vip A/P        floating address for the web UI, or "none"
#   --ha-vip-interface IF
#   --join FILE       install a further node or the witness from a join bundle
#                     (system/cluster.sh bundle on an existing node)
#
# Running it again is safe: an existing configuration is kept and the
# installation is brought up to date. Updates: update.sh. After editing the
# configuration: system/configure.sh.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
# shellcheck source=system/lib/common.sh
source "${SCRIPT_DIR}/system/lib/common.sh"

HOSTNAME_ARG=
RECONFIGURE=n
CONFIG_ONLY=n
ASSUME_YES=n
HA_NEW=n
HA_NODES_ARG=
HA_WITNESS_ARG=
HA_VIP_ARG=
HA_VIP_INTERFACE_ARG=
JOIN_BUNDLE=
DOCS_ARG=
DOCS_SOURCE_ARG=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname|--ha-nodes|--ha-witness|--ha-vip|--ha-vip-interface|--join|--docs-source)
      [[ -n $2 ]] || die "$1 needs a value"
      case "$1" in
        --hostname) HOSTNAME_ARG=$2 ;;
        --ha-nodes) HA_NEW=y HA_NODES_ARG=$2 ;;
        --ha-witness) HA_NEW=y HA_WITNESS_ARG=$2 ;;
        --ha-vip) HA_NEW=y HA_VIP_ARG=$2 ;;
        --ha-vip-interface) HA_VIP_INTERFACE_ARG=$2 ;;
        --join) JOIN_BUNDLE=$2 ;;
        --docs-source) DOCS_ARG=y DOCS_SOURCE_ARG=$2 ;;
      esac
      shift 2
      ;;
    --hostname=*) HOSTNAME_ARG=${1#*=}; shift ;;
    -y|--yes) ASSUME_YES=y; shift ;;
    --reconfigure) RECONFIGURE=y; shift ;;
    --config-only) CONFIG_ONLY=y; shift ;;
    --ha) HA_NEW=y; shift ;;
    --docs) DOCS_ARG=y; shift ;;
    --no-docs) DOCS_ARG=n; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ {sub(/^# ?/, ""); print; next} NR > 1 {exit}' "$0"; exit 0 ;;
    *) die "Unknown option $1 (see --help)" ;;
  esac
done
if [[ -n ${DOCS_SOURCE_ARG} && ! ${DOCS_SOURCE_ARG} =~ ://|^git@ ]]; then
  DOCS_SOURCE_ARG=$(realpath -e "${DOCS_SOURCE_ARG}") || die "--docs-source: directory not found"
  [[ -f ${DOCS_SOURCE_ARG}/mkdocs.yml ]] || die "--docs-source: ${DOCS_SOURCE_ARG} has no mkdocs.yml"
fi
if [[ -n ${JOIN_BUNDLE} ]]; then
  [[ ${HA_NEW} == n && ${RECONFIGURE} == n ]] || die "--join cannot be combined with --ha or --reconfigure"
  JOIN_BUNDLE=$(realpath -e "${JOIN_BUNDLE}") || die "Join bundle not found"
fi

# Commands used by this script (command:package); system/install.sh
# installs everything else
BOOTSTRAP_COMMANDS=(curl:curl awk:gawk ip:iproute ss:iproute)

install_bootstrap() {
  local missing=() item pkg
  for item in "${BOOTSTRAP_COMMANDS[@]}"; do
    pkg=${item#*:}
    command -v "${item%%:*}" > /dev/null || [[ " ${missing[*]} " == *" ${pkg} "* ]] || missing+=("${pkg}")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log "Installing setup prerequisites: ${missing[*]}"
    dnf install -y "${missing[@]}" || die "Cannot install ${missing[*]}"
  fi
}

# check_host [witness]: the witness needs little memory and no mail ports
check_host() {
  [[ $(uname -m) == x86_64 ]] || warn "Only x86_64 has been tested, continuing on $(uname -m)"
  [[ $1 == witness ]] && return 0

  local mem_kb
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  if (( mem_kb < 1800000 )); then
    warn "Less than 2 GiB RAM: the gateway will be slow or run out of memory"
  elif (( mem_kb < 7500000 )); then
    # 8 GiB shows as about 7.6 GiB MemTotal
    warn "Less than the recommended 8 GiB RAM: the gateway uses about 4 GiB with ClamAV and needs headroom"
  fi

  # Other mail or web servers would take the gateway's ports
  local port users
  for port in 25 80 443; do
    users=$(ss -Htlnp "sport = :${port}" 2> /dev/null | grep -oE 'users:\(\("[^"]+"' | cut -d'"' -f2 | sort -u \
      | grep -v -x -E 'master|nginx' | tr '\n' ' ')
    [[ -n ${users} ]] && warn "Port ${port} is used by: ${users}- stop that service before the gateway starts"
  done

  if ! curl -fsS --max-time 15 -o /dev/null https://rspamd.com/ 2> /dev/null; then
    die "No HTTPS connection to the internet (needed for packages and repositories)"
  fi
}

random_string() {
  LC_ALL=C </dev/urandom tr -dc A-Za-z0-9 2> /dev/null | head -c "${1:-28}"
}

ask_hostname() {
  CRASSOSTREA_HOSTNAME=${HOSTNAME_ARG}
  if [[ -z ${CRASSOSTREA_HOSTNAME} && ${ASSUME_YES} == y ]]; then
    die "--yes needs --hostname for a new configuration"
  fi
  while [[ -z ${CRASSOSTREA_HOSTNAME} ]]; do
    read -r -e -p "Gateway hostname (FQDN), e.g. filter.example.com - this name must be the target of your MX records: " \
      CRASSOSTREA_HOSTNAME
  done
  CRASSOSTREA_HOSTNAME=${CRASSOSTREA_HOSTNAME,,}
  if [[ ${CRASSOSTREA_HOSTNAME} != *.* ]]; then
    die "${CRASSOSTREA_HOSTNAME} is not a FQDN"
  elif [[ ${CRASSOSTREA_HOSTNAME: -1} == "." ]]; then
    die "${CRASSOSTREA_HOSTNAME} ends with a dot, leave it out"
  elif ! [[ ${CRASSOSTREA_HOSTNAME} =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
    die "${CRASSOSTREA_HOSTNAME} is not a valid host name"
  fi
}

# ClamAV needs about 1.5 GiB RAM; SKIP_CLAMD=y/n in the environment skips the question
choose_clamav() {
  [[ -n ${SKIP_CLAMD} ]] && return 0
  SKIP_CLAMD=n
  (( $(awk '/MemTotal/ {print $2}' /proc/meminfo) > 2621440 )) && return 0
  echo "Installed memory is <= 2.5 GiB. It is recommended to disable ClamAV to prevent out-of-memory situations."
  echo "ClamAV can be re-enabled by setting SKIP_CLAMD=n in ${SF_CONF}."
  local response=y
  [[ ${ASSUME_YES} == y ]] || read -r -p "Do you want to disable ClamAV now? [Y/n] " response
  [[ ${response} =~ ^([nN][oO]|[nN])$ ]] || SKIP_CLAMD=y
}

# The documentation at /docs/ (system/lib/docs.sh): sets DOCS_ENABLED and
# DOCS_SOURCE for a new configuration
choose_docs() {
  DOCS_ENABLED=n
  DOCS_SOURCE=${DOCS_SOURCE_ARG}
  if [[ -n ${DOCS_ARG} ]]; then
    DOCS_ENABLED=${DOCS_ARG}
    return 0
  fi
  [[ ${ASSUME_YES} == y ]] && return 0
  local found response
  found=$(dirname "${SCRIPT_DIR}")/crassostrea-docs
  [[ -f ${found}/mkdocs.yml ]] || found=
  read -r -p "Also serve the documentation at https://<hostname>/docs/ to administrators? [y/N] " response
  [[ ${response} =~ ^([yY][eE][sS]|[yY])$ ]] || return 0
  DOCS_ENABLED=y
  [[ -n ${found} ]] && { log "Using the documentation in ${found}"; return 0; }
  while true; do
    # the project's repository unless edited (DOCS_SOURCE empty: system/lib/docs.sh)
    read -r -e -i "${DOCS_DEFAULT_SOURCE}" -p "Git URL or directory of the crassostrea-docs repository: " DOCS_SOURCE
    if [[ ${DOCS_SOURCE} == "${DOCS_DEFAULT_SOURCE}" ]]; then
      DOCS_SOURCE=
      return 0
    fi
    if [[ ${DOCS_SOURCE} =~ ://|^git@ ]]; then
      return 0
    elif [[ -f ${DOCS_SOURCE}/mkdocs.yml ]]; then
      DOCS_SOURCE=$(realpath "${DOCS_SOURCE}")
      return 0
    fi
    warn "Not a git URL, and ${DOCS_SOURCE:-the directory} has no mkdocs.yml"
  done
}

# --docs, --docs-source, --no-docs for a configuration that exists already
# (rerun, join bundle)
apply_docs_args() {
  [[ -n ${DOCS_ARG} ]] || return 0
  [[ -n ${DOCS_SOURCE_ARG} ]] && conf_set DOCS_SOURCE "${DOCS_SOURCE_ARG}"
  conf_set DOCS_ENABLED "${DOCS_ARG}"
}

check_spamhaus() {
  log "Checking whether Spamhaus blocks the public DNS blocklists for this network"
  local response
  response=$(curl --connect-timeout 15 --max-time 30 -s -o /dev/null -w "%{http_code}" "https://asn-check.mailcow.email")
  if [[ ${response} == 503 ]]; then
    warn "The AS of this server is blocked by Spamhaus. Create a free Data Query Service account at"
    warn "https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account and set"
    warn "enter the key in the web UI (Settings -> General, Scanning); otherwise the Spamhaus blocklists stay disabled."
  fi
}

config_template() {
  cat << EOF
# ------------------------------
# Crassostrea gateway configuration
# ------------------------------
# Read by system/configure.sh and by the systemd units (EnvironmentFile).
# After a change run: system/configure.sh
# Use KEY=value lines; quote values that contain spaces.

# Hostname of the gateway. Point the MX records of your protected domains
# to this name. example.org is _not_ a valid hostname, use a fqdn here.
CRASSOSTREA_HOSTNAME=${CRASSOSTREA_HOSTNAME}

# ------------------------------
# Web UI
# ------------------------------
# Password of the initial "admin" account. Only used when the database
# contains no administrator yet; change it in the UI after the first login.
WEB_ADMIN_PASSWORD=$(random_string 20)

# Signs session cookies - keep it secret
WEB_SECRET_KEY=$(random_string 48)

# Send session cookies over HTTPS only - y/n
# Only set to n for testing without TLS.
WEB_SECURE_COOKIES=y

# Public URL of the web UI, used for links in quarantine digest mails.
# Defaults to https://CRASSOSTREA_HOSTNAME (plus HTTPS_PORT if it is not 443).
#WEB_PUBLIC_URL=https://filter.example.com

# Rspamd controller password, used by the web UI and for the Rspamd UI at /rspamd/
RSPAMD_PASSWORD=$(random_string 28)

# ------------------------------
# Database (MariaDB) and Valkey
# ------------------------------
DBNAME=crassostrea
DBUSER=crassostrea
# Letters and digits only
DBPASS=$(random_string 28)
REDISPASS=$(random_string 28)

# ------------------------------
# Web server (nginx)
# ------------------------------
# HTTP(S)_BIND: one local address to listen on, empty for all
HTTP_PORT=80
HTTP_BIND=
HTTPS_PORT=443
HTTPS_BIND=
# The HTTP to HTTPS redirect, the networks of the Rspamd UI and trusted
# reverse proxies are set in the web UI (Settings -> General, Web server).

# IP families on the network interface - true/false, at least one; loopback
# keeps both. Off: the host has no address of that family (NetworkManager)
# and the services do not use it. Also in the web UI (IP addressing).
IPV4_ENABLED=true
IPV6_ENABLED=${IPV6_ENABLED}

# ------------------------------
# Certificates
# ------------------------------
# The certificate covers CRASSOSTREA_HOSTNAME. Additional names can be added:
#ADDITIONAL_SAN=mx2.example.net
ADDITIONAL_SAN=

# Skip Let's Encrypt (keep the self-signed or your own certificate in
# /etc/crassostrea/ssl/{cert,key}.pem) - y/n
SKIP_LETS_ENCRYPT=n

# DNS-01 challenge instead of HTTP-01 - y/n
# Set ACME_DNS_PROVIDER to an acme.sh DNS API (e.g. dns_cf) and put its
# credentials into /etc/crassostrea/acme/dns-01.conf
ACME_DNS_CHALLENGE=n
ACME_DNS_PROVIDER=dns_xxx
ACME_ACCOUNT_EMAIL=me@example.com

# Skip the check that every name reaches this server over HTTP - y/n
SKIP_HTTP_VERIFICATION=n

# Use the Let's Encrypt staging environment (for testing) - y/n
LE_STAGING=n

# Oldest TLS version accepted by HTTPS (web UI) and by inbound SMTP: 1.2,
# 1.1 or 1.0. 1.0 and 1.1 are insecure; they also relax the OpenSSL policy of
# that service (security level 0, SHA-1). Also in the web UI (Certificates & TLS).
HTTPS_TLS_MIN=1.2
SMTP_TLS_MIN=1.2

# ------------------------------
# Filter components
# ------------------------------
# Skip ClamAV anti-virus - y/n
SKIP_CLAMD=${SKIP_CLAMD}

# Skip Olefy macro scanner for Office documents - y/n
SKIP_OLEFY=n
# The Spamhaus Data Query Service key, needed on networks the public
# Spamhaus mirrors refuse, is set in the web UI (Settings -> General, Scanning).

# Make the local unbound the system resolver (/etc/resolv.conf). DNS
# blocklists refuse queries from public resolvers - y/n
MANAGE_RESOLVER=y

# PROXY protocol listener for an HAProxy in front of the gateway - y/n
HAPROXY_LISTENER=n
#HAPROXY_LISTENER_BIND=127.0.0.1:10025

# ------------------------------
# Watchdog
# ------------------------------
# Enable the watchdog (crassostrea-watchdog) to restart unhealthy services
USE_WATCHDOG=y

# Its notices (mail, webhook) are set in the web UI (Settings -> Alerts &
# export).

# Enable watchdog verbose logging
WATCHDOG_VERBOSE=n

# ------------------------------
# Documentation
# ------------------------------
# Serve the documentation (crassostrea-docs, built with MkDocs) at
# https://CRASSOSTREA_HOSTNAME/docs/ to logged-in administrators - y/n.
# Change it with system/docs.sh install|remove.
DOCS_ENABLED=${DOCS_ENABLED:-n}
# The crassostrea-docs repository: a git URL or a directory. Empty: the
# checkout next to this repository (../crassostrea-docs), else
# https://github.com/SnailShea/crassostrea-docs.git
DOCS_SOURCE=${DOCS_SOURCE:-}
# Branch or tag of a git URL (empty: its default branch)
DOCS_REF=

# ------------------------------
# High availability (cluster)
# ------------------------------
# Set up with setup.sh --ha; change with system/cluster.sh members. This
# file is the same on every member except CRASSOSTREA_HOSTNAME.
# Full nodes: hostname=address pairs, the IPv4 addresses on which the
# members reach each other. Empty: a single gateway.
HA_NODES=
# Vote-only host (Galera arbitrator and Valkey Sentinel), hostname=address.
# Every member has one vote and a majority must be reachable: 2 nodes need
# a witness, 3 or more do not.
HA_WITNESS=
# Floating address/prefix for the web UI, moved by keepalived between the
# nodes (they must share the network), e.g. 192.0.2.10/24
HA_VIP=
# Network interface for HA_VIP (default: the one with the node's address)
HA_VIP_INTERFACE=
# VRRP router ID (1-255), unique in the network of HA_VIP
HA_VIP_ROUTER_ID=51
EOF
}

create_config() {
  if [[ -f ${SF_CONF} && ${RECONFIGURE} != y ]]; then
    log "Using the existing configuration ${SF_CONF} (--reconfigure creates a new one)"
    [[ -n ${HOSTNAME_ARG} ]] && warn "--hostname is ignored, the hostname is set in ${SF_CONF}"
    apply_docs_args
    return 0
  fi
  log "Creating the configuration"
  ask_hostname
  choose_clamav
  choose_docs
  # IPv6 is used if the host has a global IPv6 address
  if ip -6 addr show scope global 2> /dev/null | grep -q inet6; then
    IPV6_ENABLED=true
  else
    IPV6_ENABLED=false
  fi
  check_spamhaus

  install -d -m 0750 "$(dirname "${SF_CONF}")" || die "Cannot create $(dirname "${SF_CONF}")"
  local tmp
  tmp=$(mktemp "${SF_CONF}.XXXXXX") || die "Cannot write ${SF_CONF}"
  config_template > "${tmp}" || { rm -f "${tmp}"; die "Cannot write ${SF_CONF}"; }
  if getent group "${SF_USER}" > /dev/null; then
    chgrp "${SF_USER}" "${tmp}" && chmod 0640 "${tmp}"
  fi
  if [[ -f ${SF_CONF} ]]; then
    cp -p "${SF_CONF}" "${SF_CONF}.bak" || { rm -f "${tmp}"; die "Cannot back up ${SF_CONF}"; }
    log "The previous configuration is kept as ${SF_CONF}.bak"
  fi
  mv -f "${tmp}" "${SF_CONF}" || die "Cannot write ${SF_CONF}"
  log "Configuration written to ${SF_CONF}"
}

# This host's address towards the other members (the default route's source)
own_address() {
  ip -o -4 route get 192.0.2.1 2> /dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p'
}

# --ha: asks for the members and adds them to the configuration
setup_cluster() {
  load_env_file "${SF_CONF}"
  if ha_enabled && [[ -z ${HA_NODES_ARG} ]]; then
    log "Cluster members from ${SF_CONF}: ${HA_NODES}${HA_WITNESS:+, witness ${HA_WITNESS}}"
  else
    local nodes=${HA_NODES_ARG} witness=${HA_WITNESS_ARG} vip=${HA_VIP_ARG} choice count
    if [[ -z ${nodes} ]]; then
      [[ ${ASSUME_YES} == y ]] && die "--yes needs --ha-nodes for a new cluster"
      echo
      echo "Cluster members are given as hostname=address; the address is the IPv4 address on which"
      echo "the members reach each other (preferably a private network)."
      read -r -e -i "${CRASSOSTREA_HOSTNAME}=$(own_address)," -p "Full nodes, comma separated, this one first: " nodes
    fi
    nodes=${nodes//[[:space:]]/}
    nodes=${nodes%,}
    count=$(tr ',' '\n' <<< "${nodes}" | grep -c .)
    if [[ -z ${witness} && ${ASSUME_YES} != y ]]; then
      echo
      echo "Quorum: every member has one vote, and the database and Valkey only fail over while a majority"
      echo "of the votes is reachable. A witness is a small extra host that only votes (no mail, no data)."
      echo "  1) full nodes only - needs 3 or more nodes"
      echo "  2) full nodes and a witness - for 2 nodes, or any even number"
      choice=1
      (( count % 2 == 0 )) && choice=2
      read -r -e -i "${choice}" -p "Quorum mode [1/2]: " choice
      if [[ ${choice} == 2 ]]; then
        while [[ -z ${witness} ]]; do
          read -r -e -p "Witness (hostname=address): " witness
        done
      fi
    fi
    [[ ${witness,,} == none ]] && witness=""
    if [[ -z ${vip} && ${ASSUME_YES} != y ]]; then
      echo
      echo "Optional: a floating address for the web UI, moved by keepalived to a working node."
      echo "Only possible if the nodes share a network segment; mail uses one MX record per node anyway."
      read -r -e -p "Floating address/prefix (e.g. 192.0.2.10/24), empty for none: " vip
    fi
    [[ ${vip,,} == none ]] && vip=""
    # validate before anything is written
    ( HA_NODES=${nodes} HA_WITNESS=${witness} HA_VIP=${vip} ha_parse ) || exit 1
    conf_set HA_NODES "${nodes}"
    conf_set HA_WITNESS "${witness}"
    conf_set HA_VIP "${vip}"
    [[ -n ${HA_VIP_INTERFACE_ARG} ]] && conf_set HA_VIP_INTERFACE "${HA_VIP_INTERFACE_ARG}"
  fi
  ha_parse
  [[ ${HA_ROLE} == node ]] || die "setup.sh --ha must run on a full node (${CRASSOSTREA_HOSTNAME} is not in HA_NODES)"
  pki_create_ca
}

# --ha-nodes and the other --ha-* options are checked before anything is
# written (when the hostname is known)
check_cluster_args() {
  [[ -n ${HA_NODES_ARG} ]] || return 0
  local host=${HOSTNAME_ARG} witness=${HA_WITNESS_ARG} vip=${HA_VIP_ARG}
  [[ -f ${SF_CONF} && ${RECONFIGURE} != y ]] && host=$(sed -n 's/^CRASSOSTREA_HOSTNAME=//p' "${SF_CONF}")
  [[ -n ${host} ]] || return 0
  [[ ${witness,,} == none ]] && witness=""
  [[ ${vip,,} == none ]] && vip=""
  ( CRASSOSTREA_HOSTNAME=${host} HA_NODES=${HA_NODES_ARG//[[:space:]]/} HA_WITNESS=${witness} HA_VIP=${vip} ha_parse ) \
    || exit 1
}

# --join: configuration and certificates of an existing cluster
join_cluster() {
  log "Installing the join bundle ${JOIN_BUNDLE}"
  ha_unbundle "${JOIN_BUNDLE}"
  load_env_file "${SF_CONF}"
  ha_enabled || die "${JOIN_BUNDLE} does not describe a cluster"
  ha_parse
  [[ -z ${HOSTNAME_ARG} ]] || warn "--hostname is ignored, the bundle names this host ${CRASSOSTREA_HOSTNAME}"
  log "Joining the cluster as ${HA_ROLE} ${CRASSOSTREA_HOSTNAME} (${HA_SELF_ADDR})"
  ip -o -4 addr show 2> /dev/null | grep -qF " ${HA_SELF_ADDR}/" \
    || warn "${HA_SELF_ADDR} is not an address of this host: the other members cannot reach it"
}

# Join bundles for the other members of a new cluster
write_bundles() {
  local host
  echo
  log "Join bundles for the other members (they contain all passwords and the cluster CA):"
  for host in "${HA_NODE_NAMES[@]}" ${HA_WITNESS_NAME:+"${HA_WITNESS_NAME}"}; do
    [[ ${host} == "${CRASSOSTREA_HOSTNAME,,}" ]] && continue
    ha_bundle "${host}" "/root/crassostrea-join-${host}.tar"
  done
  echo "Copy each bundle to its host, then run there, one host after another:"
  echo "  ./setup.sh --join /root/crassostrea-join-<hostname>.tar"
}

# The certificate and the MX records need the hostname to point here
check_hostname() {
  local addresses own
  addresses=$(getent ahosts "${CRASSOSTREA_HOSTNAME}" 2> /dev/null | awk '{print $1}' | sort -u)
  own=$(ip -o addr show scope global 2> /dev/null | awk '{sub(/\/.*/, "", $4); print $4}')
  if [[ -z ${addresses} ]]; then
    warn "${CRASSOSTREA_HOSTNAME} does not resolve yet: create its A/AAAA records before pointing MX records here"
  elif ! grep -qxF -f <(echo "${own}") <<< "${addresses}"; then
    warn "${CRASSOSTREA_HOSTNAME} resolves to $(echo ${addresses}), not to an address of this host"
    warn "(fine behind NAT; otherwise Let's Encrypt and inbound mail will not reach this server)"
  fi
}

confirm() {
  [[ ${ASSUME_YES} == y ]] && return 0
  echo
  echo "The setup will now install and configure, on this host:"
  if [[ ${HA_ROLE} == witness ]]; then
    echo "  the Galera arbitrator and Valkey Sentinel of the cluster; firewall rules for the members."
  else
    echo "  EPEL, CRB and the Rspamd repository; Postfix, Rspamd, ClamAV, MariaDB, Valkey,"
    echo "  unbound (as the system resolver), nginx and the Crassostrea services;"
    echo "  firewall ports 25, 80 and 443; SELinux settings."
  fi
  if [[ ${HA_ROLE} == node ]]; then
    echo "  Cluster: Galera, Valkey Sentinel, haproxy${HA_VIP:+, keepalived (${HA_VIP})}; cluster ports open"
    echo "  to $(ha_peer_addrs | paste -sd' ' -) only."
    [[ ${HA_NEW} == y ]] && echo "  This node creates the cluster; the others join it afterwards."
  fi
  local response
  read -r -p "Continue? [Y/n] " response
  [[ ! ${response} =~ ^([nN][oO]|[nN])$ ]] || exit 0
}

require_el10
install_bootstrap
if [[ -n ${JOIN_BUNDLE} ]]; then
  join_cluster
  [[ ${HA_ROLE} == node ]] && apply_docs_args
  check_host "${HA_ROLE}"
else
  check_host
  [[ ${HA_NEW} == y ]] && check_cluster_args
  create_config
  [[ ${HA_NEW} == y ]] && setup_cluster
fi
if [[ ${CONFIG_ONLY} == y ]]; then
  log "Configuration in ${SF_CONF}; install later with: $0$([[ ${HA_NEW} == y ]] && echo " --ha")"
  exit 0
fi
load_env_file "${SF_CONF}"
ha_parse
[[ ${HA_ROLE} == witness ]] || check_hostname
confirm
# The first node creates the database cluster, all others join it
[[ ${HA_NEW} == y ]] && export SF_GALERA_BOOTSTRAP=y
"${SCRIPT_DIR}/system/install.sh" || die "Installation failed, see the messages above. $0 can be run again."

echo
log "Setup complete."
if [[ ${HA_ROLE} == witness ]]; then
  echo "  ${CRASSOSTREA_HOSTNAME} votes in the cluster. State: ${SCRIPT_DIR}/system/cluster.sh status"
  exit 0
fi
echo "  Web UI:        https://${CRASSOSTREA_HOSTNAME}/  (user admin, initial password ${WEB_ADMIN_PASSWORD},"
echo "                 used only while no administrator exists)"
echo "  Configuration: ${SF_CONF}  -  apply changes with: ${SCRIPT_DIR}/system/configure.sh"
if is_yes "${DOCS_ENABLED:-n}"; then
  echo "  Documentation: https://${CRASSOSTREA_HOSTNAME}/docs/  (administrators; update with ${SCRIPT_DIR}/system/docs.sh update)"
fi
echo "  Services:      systemctl list-units 'crassostrea*' postfix rspamd nginx"
if [[ -n ${HA_ROLE} ]]; then
  echo "  Cluster:       ${SCRIPT_DIR}/system/cluster.sh status"
  echo "  Next:          add your domains in the web UI, then create one MX record per node"
  [[ ${HA_NEW} == y ]] && write_bundles
else
  echo "  Next:          add your domains in the web UI, then point their MX records to ${CRASSOSTREA_HOSTNAME}"
fi
