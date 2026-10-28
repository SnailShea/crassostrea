#!/usr/bin/env bash
# High availability (cluster) helpers, sourced by common.sh.
#
# A cluster is configured in crassostrea.conf, identical on every member
# except CRASSOSTREA_HOSTNAME, which names the member:
#
#   HA_NODES    full gateways: comma separated hostname=address pairs
#   HA_WITNESS  optional vote-only host (Galera arbitrator + Valkey Sentinel):
#               hostname=address
#   HA_VIP      optional floating address/prefix for the web UI (keepalived)
#
# Addresses are the IPv4 addresses on which the members reach each other.
# Every member has one vote; a majority must agree before the database
# accepts writes or Valkey fails over, so a cluster survives the failure of a
# member from 3 votes on. Like Proxmox, a cluster can start with one node and
# grow (the Cluster page of the web UI): 1 or 2 votes only warn.

SF_PKI=/etc/pki/crassostrea
SF_TLS_GROUP=crassostrea-tls
HA_CLUSTER_NAME=crassostrea
HA_VALKEY_PORT=6380
HA_SENTINEL_PORT=26379
HA_GALERA_PORTS=(4567 4568 4444)
HA_ZONE=crassostrea-cluster

valid_hostname() {
  [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

valid_ipv4() {
  local IFS=. octet
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  for octet in $1; do
    (( 10#${octet} <= 255 )) || return 1
  done
}

ha_enabled() {
  [[ -n ${HA_NODES//[[:space:],]/} ]]
}

# _ha_member ENTRY: sets name and addr of a hostname=address pair
_ha_member() {
  local entry=$1 what=$2
  [[ ${entry} == *=* ]] || die "${what}: '${entry}' is not hostname=address"
  name=${entry%%=*}
  name=${name,,}
  addr=${entry#*=}
  valid_hostname "${name}" || die "${what}: '${name}' is not a valid host name"
  valid_ipv4 "${addr}" || die "${what}: '${addr}' is not an IPv4 address"
}

# ha_parse: reads HA_NODES and HA_WITNESS into
#   HA_NODE_NAMES[], HA_NODE_ADDRS[]  full nodes, in the configured order
#   HA_WITNESS_NAME, HA_WITNESS_ADDR  witness (empty without one)
#   HA_ROLE                           node, witness or empty (no cluster)
#   HA_SELF_ADDR                      this member's address
ha_parse() {
  HA_NODE_NAMES=()
  HA_NODE_ADDRS=()
  HA_WITNESS_NAME=
  HA_WITNESS_ADDR=
  HA_ROLE=
  HA_SELF_ADDR=
  ha_enabled || return 0
  local entry name addr self=${CRASSOSTREA_HOSTNAME,,}
  for entry in ${HA_NODES//,/ }; do
    _ha_member "${entry}" HA_NODES
    [[ " ${HA_NODE_NAMES[*]} " == *" ${name} "* || " ${HA_NODE_ADDRS[*]} " == *" ${addr} "* ]] \
      && die "HA_NODES: ${name} or ${addr} is listed twice"
    HA_NODE_NAMES+=("${name}")
    HA_NODE_ADDRS+=("${addr}")
    [[ ${name} == "${self}" ]] && HA_ROLE=node HA_SELF_ADDR=${addr}
  done
  if [[ -n ${HA_WITNESS//[[:space:]]/} ]]; then
    _ha_member "${HA_WITNESS//[[:space:]]/}" HA_WITNESS
    [[ " ${HA_NODE_NAMES[*]} " == *" ${name} "* || " ${HA_NODE_ADDRS[*]} " == *" ${addr} "* ]] \
      && die "HA_WITNESS: ${name} is also a full node"
    HA_WITNESS_NAME=${name}
    HA_WITNESS_ADDR=${addr}
    [[ ${name} == "${self}" ]] && HA_ROLE=witness HA_SELF_ADDR=${addr}
  fi
  [[ -n ${HA_ROLE} ]] || die "This host (CRASSOSTREA_HOSTNAME=${CRASSOSTREA_HOSTNAME}) is neither in HA_NODES nor HA_WITNESS"
  (( ${#HA_NODE_NAMES[@]} >= 1 )) || die "HA_NODES needs at least one full node"
  local voters
  voters=$(ha_voters)
  if (( voters < 3 )); then
    warn "The cluster has ${voters} vote(s): it survives the failure of a member only from 3 votes on; add a node" \
      "or a witness"
  elif (( voters % 2 == 0 )); then
    warn "The cluster has ${voters} votes: with an even number a network split into halves stops both; adding or" \
      "removing the witness gives an odd number"
  fi
  if [[ -n ${HA_VIP} ]]; then
    [[ ${HA_VIP} =~ ^([0-9.]+)/([0-9]{1,2})$ ]] && valid_ipv4 "${BASH_REMATCH[1]}" && (( BASH_REMATCH[2] <= 32 )) \
      || die "HA_VIP must be an IPv4 address with prefix length, e.g. 192.0.2.10/24"
    local router_id=${HA_VIP_ROUTER_ID:-51}
    [[ ${router_id} =~ ^[0-9]+$ ]] && (( 10#${router_id} >= 1 && 10#${router_id} <= 255 )) \
      || die "HA_VIP_ROUTER_ID must be a number from 1 to 255"
    [[ -z ${HA_VIP_INTERFACE:-} || ${HA_VIP_INTERFACE} =~ ^[A-Za-z0-9_.@-]{1,15}$ ]] \
      || die "HA_VIP_INTERFACE must be the name of a network interface"
  fi
  return 0
}

# Votes: full nodes plus the witness
ha_voters() {
  echo $(( ${#HA_NODE_ADDRS[@]} + (${#HA_WITNESS_ADDR} > 0 ? 1 : 0) ))
}

ha_quorum() {
  echo $(( $(ha_voters) / 2 + 1 ))
}

# Addresses of all members (nodes and witness)
ha_member_addrs() {
  printf '%s\n' "${HA_NODE_ADDRS[@]}" ${HA_WITNESS_ADDR:+"${HA_WITNESS_ADDR}"}
}

# Addresses of the other members
ha_peer_addrs() {
  ha_member_addrs | grep -vxF "${HA_SELF_ADDR}"
}

# Addresses of the other full nodes
ha_node_peer_addrs() {
  printf '%s\n' "${HA_NODE_ADDRS[@]}" | grep -vxF "${HA_SELF_ADDR}"
}

# Is something listening on ADDR:PORT?
ha_reachable() {
  timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2> /dev/null
}

# --------------------------------------------------------------------------
# Cluster CA: every full node keeps the CA key and issues its own
# certificate; the witness receives its certificate in its join bundle
# --------------------------------------------------------------------------
pki_create_ca() {
  local dir
  dir=$(p "${SF_PKI}")
  [[ -s ${dir}/ca.crt && -s ${dir}/ca.key ]] && return 0
  log "Creating the cluster CA in ${SF_PKI}"
  install -d -m 0755 "${dir}"
  (umask 077; openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7300 \
    -subj "/CN=Crassostrea cluster CA ${HA_CLUSTER_NAME} $(date +%Y%m%d%H%M%S)" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${dir}/ca.key" -out "${dir}/ca.crt" 2> /dev/null) || die "Cannot create the cluster CA"
  chmod 0644 "${dir}/ca.crt"
}

# pki_issue NAME ADDR DIR: key and certificate for a member, signed by the CA
pki_issue() {
  local name=$1 addr=$2 out=$3 ca csr
  ca=$(p "${SF_PKI}")
  [[ -s ${ca}/ca.key ]] || die "The cluster CA key (${SF_PKI}/ca.key) is missing on this host"
  csr=$(mktemp) || die "Cannot create a temporary file"
  (umask 077; openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=${name}" \
    -addext "subjectAltName=DNS:${name},IP:${addr}" -keyout "${out}/node.key" -out "${csr}" 2> /dev/null) \
    || die "Cannot create a key for ${name}"
  openssl x509 -req -in "${csr}" -CA "${ca}/ca.crt" -CAkey "${ca}/ca.key" -days 3650 -copy_extensions copyall \
    -set_serial "0x$(openssl rand -hex 16)" -extfile <(printf '%s\n' "basicConstraints=CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth,clientAuth") \
    -out "${out}/node.crt" 2> /dev/null || die "Cannot sign the certificate of ${name}"
  rm -f "${csr}"
}

# Does the certificate of this member exist, match its name and address and
# stay valid for 30 more days?
pki_node_cert_ok() {
  local dir
  dir=$(p "${SF_PKI}")
  [[ -s ${dir}/node.crt && -s ${dir}/node.key && -s ${dir}/ca.crt ]] || return 1
  openssl x509 -in "${dir}/node.crt" -noout -checkend 2592000 > /dev/null 2>&1 || return 1
  openssl verify -CAfile "${dir}/ca.crt" "${dir}/node.crt" > /dev/null 2>&1 || return 1
  local san
  san=$(openssl x509 -in "${dir}/node.crt" -noout -ext subjectAltName 2> /dev/null)
  [[ ${san} == *"DNS:${CRASSOSTREA_HOSTNAME,,}"* && ${san} == *"IP Address:${HA_SELF_ADDR}"* ]]
}

# Certificate files of this member, readable by the services that use them:
# node.key for the members of SF_TLS_GROUP (mysql, valkey, garb), node.pem
# (certificate and key) for haproxy, which reads it as root
pki_install_node() {
  local dir
  dir=$(p "${SF_PKI}")
  if ! pki_node_cert_ok; then
    if [[ -s ${dir}/ca.key ]]; then
      log "Issuing the cluster certificate of ${CRASSOSTREA_HOSTNAME} (${HA_SELF_ADDR})"
      pki_issue "${CRASSOSTREA_HOSTNAME,,}" "${HA_SELF_ADDR}" "${dir}"
    else
      die "The cluster certificate in ${SF_PKI} is missing, expired or does not match ${CRASSOSTREA_HOSTNAME}" \
        "(${HA_SELF_ADDR}): create a new join bundle on a full node (system/cluster.sh bundle ${CRASSOSTREA_HOSTNAME})"
    fi
  fi
  if ! dry; then
    getent group "${SF_TLS_GROUP}" > /dev/null || groupadd --system "${SF_TLS_GROUP}"
    local user
    for user in mysql valkey garb; do
      getent passwd "${user}" > /dev/null && usermod -a -G "${SF_TLS_GROUP}" "${user}"
    done
    chown root:"${SF_TLS_GROUP}" "${dir}" "${dir}/node.key"
  fi
  chmod 0750 "${dir}"
  chmod 0640 "${dir}/node.key"
  chmod 0644 "${dir}/node.crt" "${dir}/ca.crt"
  [[ -f ${dir}/ca.key ]] && chmod 0600 "${dir}/ca.key"
  cat "${dir}/node.crt" "${dir}/node.key" | write_file "${SF_PKI}/node.pem" 0600
}

# --------------------------------------------------------------------------
# Join bundles: what a new member needs (configuration, CA, certificate)
# --------------------------------------------------------------------------
# ha_bundle HOSTNAME OUTPUT: tar archive with the configuration of HOSTNAME
# (CRASSOSTREA_HOSTNAME replaced), the CA certificate and, for a full node, the
# CA key, for the witness its own certificate
ha_bundle() {
  local host=${1,,} out=$2 tmp role="" i
  for i in "${!HA_NODE_NAMES[@]}"; do
    [[ ${HA_NODE_NAMES[i]} == "${host}" ]] && role=node
  done
  [[ ${HA_WITNESS_NAME} == "${host}" ]] && role=witness
  [[ -n ${role} ]] || die "${host} is neither in HA_NODES nor HA_WITNESS of ${SF_CONF}"
  [[ -s $(p "${SF_PKI}")/ca.key ]] || die "Join bundles can only be created on a full node (CA key missing)"
  tmp=$(mktemp -d) || die "Cannot create a temporary directory"
  mkdir -m 0700 "${tmp}/pki"
  sed "s/^CRASSOSTREA_HOSTNAME=.*/CRASSOSTREA_HOSTNAME=${host}/" "${SF_CONF}" > "${tmp}/crassostrea.conf"
  cp "$(p "${SF_PKI}")/ca.crt" "${tmp}/pki/ca.crt"
  if [[ ${role} == node ]]; then
    cp "$(p "${SF_PKI}")/ca.key" "${tmp}/pki/ca.key"
  else
    pki_issue "${host}" "${HA_WITNESS_ADDR}" "${tmp}/pki"
  fi
  (umask 077; tar -C "${tmp}" --owner=root --group=root -cf "${out}" crassostrea.conf pki) \
    || die "Cannot write ${out}"
  rm -rf "${tmp:?}"
  log "Join bundle for ${host} (${role}): ${out}"
}

# Settings of the host itself, kept from its configuration when it joins: its
# network, TLS versions and certificate (the rest comes from the cluster)
HA_HOST_KEYS=(IPV4_ENABLED IPV6_ENABLED HTTP_BIND HTTPS_BIND HTTPS_TLS_MIN SMTP_TLS_MIN SKIP_LETS_ENCRYPT
  ACME_DNS_CHALLENGE ACME_DNS_PROVIDER ACME_ACCOUNT_EMAIL LE_STAGING SKIP_HTTP_VERIFICATION HA_VIP_INTERFACE
  DOCS_ENABLED DOCS_SOURCE DOCS_REF)

# ha_unbundle FILE: installs a join bundle (configuration and certificates);
# the HA_HOST_KEYS of an existing configuration are kept
ha_unbundle() {
  local bundle=$1 tmp entry
  [[ -f ${bundle} ]] || die "Join bundle ${bundle} not found"
  while IFS= read -r entry; do
    case "${entry}" in
      crassostrea.conf|pki/|pki/ca.crt|pki/ca.key|pki/node.crt|pki/node.key) ;;
      *) die "${bundle} is not a join bundle (unexpected entry ${entry})" ;;
    esac
  done < <(tar -tf "${bundle}" 2> /dev/null || die "Cannot read ${bundle}")
  tmp=$(mktemp -d) || die "Cannot create a temporary directory"
  tar -C "${tmp}" --no-same-owner --no-same-permissions -xf "${bundle}" || die "Cannot extract ${bundle}"
  [[ -s ${tmp}/crassostrea.conf && -s ${tmp}/pki/ca.crt ]] || die "${bundle} is incomplete"
  install -d -m 0750 "$(dirname "${SF_CONF}")"
  local key kept=()
  if [[ -f ${SF_CONF} ]]; then
    cp -p "${SF_CONF}" "${SF_CONF}.bak"
    for key in "${HA_HOST_KEYS[@]}"; do
      grep -q "^${key}=" "${SF_CONF}" && kept+=("$(grep "^${key}=" "${SF_CONF}" | tail -1)")
    done
  fi
  install -m 0600 "${tmp}/crassostrea.conf" "${SF_CONF}"
  for key in "${kept[@]}"; do
    conf_set "${key%%=*}" "${key#*=}"
  done
  install -d -m 0750 "$(p "${SF_PKI}")"
  install -m 0644 "${tmp}/pki/ca.crt" "$(p "${SF_PKI}")/ca.crt"
  local f
  for f in ca.key node.key; do
    [[ -f ${tmp}/pki/${f} ]] && install -m 0600 "${tmp}/pki/${f}" "$(p "${SF_PKI}")/${f}"
  done
  [[ -f ${tmp}/pki/node.crt ]] && install -m 0644 "${tmp}/pki/node.crt" "$(p "${SF_PKI}")/node.crt"
  rm -rf "${tmp:?}"
}

# --------------------------------------------------------------------------
# Galera and Valkey state
# --------------------------------------------------------------------------
# galera_status VARIABLE: value of a wsrep status variable (empty if the
# database is not reachable)
galera_status() {
  mariadb --socket=/var/lib/mysql/mysql.sock -N -B -e "SHOW GLOBAL STATUS LIKE '$1'" 2> /dev/null | cut -f2
}

# valkey_tls HOST PORT ARGS...: valkey-cli to a cluster member (TLS)
valkey_tls() {
  local host=$1 port=$2
  shift 2
  timeout 5 valkey-cli --tls --cacert "${SF_PKI}/ca.crt" --cert "${SF_PKI}/node.crt" --key "${SF_PKI}/node.key" \
    -h "${host}" -p "${port}" -a "${REDISPASS}" --no-auth-warning "$@" 2> /dev/null
}
