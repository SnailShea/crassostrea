#!/usr/bin/env bash
# Cluster (high availability) management.
#
#   system/cluster.sh status
#       state of this member, the database cluster, Valkey and the VIP
#   system/cluster.sh bundle HOSTNAME [FILE]
#       join bundle for a member listed in HA_NODES or HA_WITNESS (on a full
#       node); copy it to the new host and run: ./setup.sh --join FILE
#   system/cluster.sh members --nodes LIST [--witness HOST=ADDR | --no-witness]
#       change the members (scale up or down, add or remove the witness): in
#       crassostrea.conf of this host and in the cluster's membership, which
#       the other nodes apply by themselves (the witness: run it there too).
#       The Cluster page of the web UI adds and removes nodes as well
#   system/cluster.sh members --standalone
#       make this host a single gateway again (after the others left)
#   system/cluster.sh maintenance on|off [NODE] [--force]
#       put a node (this one by default) into maintenance or take it out:
#       it answers new mail with 421 (senders use the other MX hosts), hands
#       over the Valkey master and the floating address and keeps delivering
#       its queue; also on the Cluster page. --force: even if no other node
#       accepts mail
#   system/cluster.sh bootstrap [--force]
#       after all nodes were down: start a new database cluster from this
#       node (the one with the latest data); then start mariadb on the others
#   system/cluster.sh leave
#       stop and disable the gateway on this host before it is removed from
#       HA_NODES on the other members
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
  awk 'NR > 1 && /^#/ {sub(/^# ?/, ""); print; next} NR > 1 {exit}' "$0"
  exit "${1:-0}"
}

[[ ${EUID} -eq 0 ]] || die "Please run as root"
load_config

status() {
  ha_enabled || { echo "This gateway is not part of a cluster (HA_NODES is empty)."; return 0; }
  echo "Member:   ${CRASSOSTREA_HOSTNAME} (${HA_SELF_ADDR}), ${HA_ROLE}"
  echo "Nodes:    $(for i in "${!HA_NODE_NAMES[@]}"; do printf '%s (%s) ' "${HA_NODE_NAMES[i]}" "${HA_NODE_ADDRS[i]}"; done)"
  echo "Witness:  ${HA_WITNESS_NAME:-none}${HA_WITNESS_ADDR:+ (${HA_WITNESS_ADDR})}"
  echo "Votes:    $(ha_voters), quorum $(ha_quorum)"
  echo
  if [[ ${HA_ROLE} == node ]]; then
    local size state status
    size=$(galera_status wsrep_cluster_size)
    state=$(galera_status wsrep_local_state_comment)
    status=$(galera_status wsrep_cluster_status)
    if [[ -n ${status} ]]; then
      echo "Database: ${status} component, ${size} member(s) incl. arbitrator, this node ${state}"
    else
      echo "Database: MariaDB is not running on this node"
    fi
  else
    echo "Database: arbitrator $(systemctl is-active garb.service)"
  fi
  local master replicas
  master=$("${SCRIPT_DIR}/libexec/valkey-role" --print)
  if [[ -n ${master} ]]; then
    replicas=$(valkey_tls "${master}" "${HA_VALKEY_PORT}" INFO replication | grep -c '^slave[0-9]*:.*state=online')
    echo "Valkey:   master ${master}, ${replicas} replica(s) in sync"
  else
    echo "Valkey:   no Sentinel answers"
  fi
  if [[ -n ${HA_VIP} ]]; then
    if ip -o addr show | grep -qF " ${HA_VIP%/*}/"; then
      echo "VIP:      ${HA_VIP} is on this node"
    else
      echo "VIP:      ${HA_VIP} is on another node"
    fi
  fi
  [[ ${HA_ROLE} == node ]] || return 0
  if [[ -e ${CLUSTER_STATE}/maintenance ]]; then
    echo "Maintenance: since $(date -d "@$(tr -cd '0-9' < "${CLUSTER_STATE}/maintenance")" '+%F %T')"
  fi
  local reports
  reports=$(cluster_sql "SELECT r.hostname, TIMESTAMPDIFF(SECOND, r.updated_at, UTC_TIMESTAMP()),
    IF(COALESCE(c.maintenance, 0), 'maintenance', '') FROM cluster_reports r
    LEFT JOIN cluster_control c ON c.hostname = r.hostname ORDER BY r.hostname")
  if [[ -n ${reports} ]]; then
    echo
    echo "Reports (Cluster page):"
    awk -F'\t' '{printf "  %-40s %s s ago %s\n", $1, $2, $3}' <<< "${reports}"
  fi
}

CLUSTER_STATE=/var/lib/crassostrea/cluster

# SQL on this node's database as root (unix socket), tab separated
cluster_sql() {
  mariadb --socket=/var/lib/mysql/mysql.sock -N -B "${DBNAME}" -e "$1" 2> /dev/null
}

maintenance() {
  local mode=$1 node="" force=n
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force) force=y ;;
      -*) usage 1 ;;
      *) node=${1,,} ;;
    esac
    shift
  done
  [[ ${mode} == on || ${mode} == off ]] || usage 1
  ha_enabled || die "This gateway is not part of a cluster (HA_NODES is empty)"
  [[ ${HA_ROLE} == node ]] || die "Run it on a full node"
  node=${node:-${CRASSOSTREA_HOSTNAME,,}}
  [[ " ${HA_NODE_NAMES[*]} " == *" ${node} "* ]] || die "${node} is not in HA_NODES"
  local value=0 others
  if [[ ${mode} == on ]]; then
    value=1
    others=$(cluster_sql "SELECT COUNT(*) FROM cluster_reports r LEFT JOIN cluster_control c ON c.hostname = r.hostname
      WHERE r.hostname <> '${node}' AND r.updated_at > UTC_TIMESTAMP() - INTERVAL 60 SECOND
      AND COALESCE(c.maintenance, 0) = 0 AND JSON_VALUE(r.data, '$.galera.state') = 'Synced'")
    [[ -n ${others} ]] || die "The database of this node does not answer"
    if (( others == 0 )) && [[ ${force} != y ]]; then
      die "No other node is reporting, in sync and out of maintenance: ${node} is needed to accept mail" \
        "(--force to do it anyway)"
    fi
  fi
  # node is in HA_NODES, validated by ha_parse: safe in SQL
  cluster_sql "INSERT INTO cluster_control (hostname, maintenance, changed_by, changed_at, promote_token)
    VALUES ('${node}', ${value}, 'cli', UTC_TIMESTAMP(), '')
    ON DUPLICATE KEY UPDATE changed_by = IF(maintenance = VALUES(maintenance), changed_by, VALUES(changed_by)),
      changed_at = IF(maintenance = VALUES(maintenance), changed_at, VALUES(changed_at)),
      promote_token = IF(VALUES(maintenance), '', promote_token), maintenance = VALUES(maintenance);
    INSERT INTO audit_log (at, actor, ip, method, action, target, outcome, message, details)
    VALUES (UTC_TIMESTAMP(), 'cli', '', '', 'cli.cluster-maintenance', '${node}', 'ok',
      'Maintenance ${mode} for ${node} (system/cluster.sh)', '{}')" \
    || die "Cannot write the database (cluster_control); is this node in sync?"
  log "Maintenance ${mode} for ${node}: its cluster services apply it within seconds"
  [[ ${node} == "${CRASSOSTREA_HOSTNAME,,}" ]] || return 0
  local i applied
  for (( i = 0; i < 60; i++ )); do
    applied=$(jq -r '.maintenance' "${CLUSTER_STATE}/probe.json" 2> /dev/null)
    [[ ${applied} == "$([[ ${mode} == on ]] && echo true || echo false)" ]] && { log "In effect."; return 0; }
    sleep 1
  done
  warn "Not in effect after 60 seconds: see journalctl -u crassostrea-cluster -u crassostrea-cluster-report"
}

bundle() {
  local host=${1,,} out=$2
  [[ -n ${host} ]] || usage 1
  ha_enabled || die "This gateway is not part of a cluster (HA_NODES is empty)"
  out=${out:-/root/crassostrea-join-${host}.tar}
  ha_bundle "${host}" "${out}"
  echo "Copy it to ${host} (it contains the passwords and the cluster CA), then run there:"
  echo "  ./setup.sh --join ${out}"
}

members() {
  local nodes="" witness=${HA_WITNESS} witness_set=n standalone=n
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --nodes) nodes=$2; shift 2 ;;
      --witness) witness=$2; witness_set=y; shift 2 ;;
      --no-witness) witness=""; witness_set=y; shift ;;
      --standalone) standalone=y; shift ;;
      *) usage 1 ;;
    esac
  done
  if [[ ${standalone} == y ]]; then
    log "Leaving cluster mode: ${CRASSOSTREA_HOSTNAME} becomes a single gateway"
    # the cluster's membership and reports would come back when it creates a cluster again
    [[ ${HA_ROLE} == node ]] && cluster_sql "DELETE FROM cluster_membership; DELETE FROM cluster_reports;
      DELETE FROM cluster_control"
    conf_set HA_NODES ""
    conf_set HA_WITNESS ""
    conf_set HA_VIP ""
    "${SCRIPT_DIR}/configure.sh" || die "system/configure.sh failed"
    return 0
  fi
  [[ -n ${nodes} ]] || die "--nodes is required, e.g. --nodes mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.2"
  nodes=${nodes//[[:space:]]/}
  nodes=${nodes,,}
  witness=${witness//[[:space:]]/}
  witness=${witness,,}
  # validate before anything is written
  ( HA_NODES=${nodes} HA_WITNESS=${witness} ha_parse ) || exit 1
  log "Members: ${nodes}; witness: ${witness:-none}"
  conf_set HA_NODES "${nodes}"
  [[ ${witness_set} == y ]] && conf_set HA_WITNESS "${witness}"
  # the cluster's membership (Cluster page): every other node applies it by
  # itself within a minute (validated by ha_parse: safe in SQL)
  local shared=n
  if [[ ${HA_ROLE} == node ]] && cluster_sql "INSERT INTO cluster_membership (id, nodes, witness, changed_by,
      changed_at) VALUES (1, '${nodes}', '${HA_WITNESS}', 'cli', UTC_TIMESTAMP())
      ON DUPLICATE KEY UPDATE nodes = VALUES(nodes), witness = VALUES(witness), changed_by = 'cli',
      changed_at = UTC_TIMESTAMP()"; then
    shared=y
  fi
  "${SCRIPT_DIR}/configure.sh" || die "system/configure.sh failed"
  echo
  if [[ ${shared} == y ]]; then
    echo "The other nodes apply the new members by themselves within a minute (the witness: run this there too)."
  else
    echo "The database did not answer: run the same command on every other member."
  fi
  echo "A new member joins with a join information (Cluster page), or with a bundle:"
  echo "  system/cluster.sh bundle HOSTNAME   (here), then ./setup.sh --join FILE (there)"
}

bootstrap() {
  [[ ${HA_ROLE} == node ]] || die "Only a full node can bootstrap the database cluster"
  local force=n grastate=/var/lib/mysql/grastate.dat addr
  [[ $1 == --force ]] && force=y
  for addr in $(ha_node_peer_addrs); do
    if ha_reachable "${addr}" 4567; then
      die "The node ${addr} is running Galera: start mariadb here to join it instead of bootstrapping"
    fi
  done
  if systemctl is-active --quiet mariadb.service; then
    die "MariaDB is running on this node; stop it first (systemctl stop mariadb)"
  fi
  if [[ -f ${grastate} ]] && ! grep -q '^safe_to_bootstrap: *1' "${grastate}"; then
    echo "This node did not stop last; its position in the history:"
    galera_recovery 2> /dev/null || true
    echo "Compare it with the other nodes (galera_recovery there); bootstrap the node with the highest number."
    [[ ${force} == y ]] || die "Run again with --force on the node with the latest data"
    sed -i 's/^safe_to_bootstrap: *0/safe_to_bootstrap: 1/' "${grastate}"
  fi
  log "Bootstrapping the database cluster from ${CRASSOSTREA_HOSTNAME}"
  galera_new_cluster || die "galera_new_cluster failed, see: journalctl -u mariadb"
  log "Done. Start mariadb on the other nodes now: systemctl start mariadb"
}

leave() {
  ha_enabled || die "This gateway is not part of a cluster"
  local units
  if [[ ${HA_ROLE} == witness ]]; then
    units=(garb.service valkey-sentinel.service)
  else
    mapfile -t units < <(sed -n 's/^CRASSOSTREA_UNITS=//p' "${SF_ETC}/units.env" 2> /dev/null | tr ',' '\n')
    units+=(crassostrea-job-cleanup.timer crassostrea-job-sync.timer crassostrea-job-digests.timer
      crassostrea-job-directories.timer crassostrea-dmarc-report.timer crassostrea-job-alerts.timer
      crassostrea-job-accounts.timer)
  fi
  log "Stopping and disabling: ${units[*]}"
  systemctl disable --now "${units[@]}" 2> /dev/null
  log "${CRASSOSTREA_HOSTNAME} left the cluster. Remove it on another member: Remove on its Cluster page, or"
  echo "  system/cluster.sh members --nodes <remaining nodes> [--witness ... | --no-witness]"
}

case "$1" in
  status) status ;;
  bundle) bundle "$2" "$3" ;;
  members) shift; members "$@" ;;
  maintenance) shift; maintenance "$@" ;;
  bootstrap) bootstrap "$2" ;;
  leave) leave ;;
  -h|--help|"") usage 0 ;;
  *) usage 1 ;;
esac
