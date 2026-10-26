#!/usr/bin/env bash
# Valkey in a cluster, run by run.sh inside `unshare -rnm`: two Valkey nodes,
# three Sentinels (nodes and witness) and haproxy with the configuration
# rendered by configure.sh. Replication over mutual TLS, failover, haproxy
# following the master, and the old master returning as a replica.
#
# Differences to a real cluster: all members on one host, each on its own
# loopback address; files below $WORK instead of /etc and /var/lib.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=${PKG}/usr/bin:${PKG}/usr/sbin:${PATH}

cluster_addresses 10.0.0.1 10.0.0.2 10.0.0.3
declare -A ROOT=([n1]=${NODES}/mx1 [n2]=${NODES}/mx2 [w]=${NODES}/witness)
declare -A ADDR=([n1]=10.0.0.1 [n2]=10.0.0.2 [w]=10.0.0.3)
declare -A NAME=([n1]=${NODE1} [n2]=${NODE2} [w]=${WITNESS})
PASS=$(sed -n 's/^REDISPASS=//p' "${ROOT[n1]}/etc/crassostrea/crassostrea.conf")
L=${WORK}/valkey
rm -rf "${L}"
mkdir -p "${L}"

# the rendered files with the paths of this test
valkey_conf() {
  local n=$1 d=${L}/$1
  mkdir -p "${d}" "${L}/ro/${n}"
  sed -e "s#/etc/pki/crassostrea#${ROOT[$n]}/etc/pki/crassostrea#g" "${ROOT[$n]}/etc/valkey/crassostrea.conf" > "${d}/valkey.conf"
  printf 'dir %s\nlogfile %s/valkey.log\nsave ""\n' "${d}" "${d}" >> "${d}/valkey.conf"
  # the main file (/etc/crassostrea-valkey.conf) is read-only for valkey
  sed -e "s#^include /etc/valkey/valkey.conf#include ${d}/valkey.conf#" \
      -e "s#^include /var/lib/valkey/crassostrea-role.conf#include ${d}/role.conf#" \
      "${ROOT[$n]}/etc/crassostrea-valkey.conf" > "${L}/ro/${n}/main.conf"
}
sentinel_conf() {
  local n=$1 d=${L}/$1
  mkdir -p "${d}/s"
  sed -e "s#/etc/pki/crassostrea#${ROOT[$n]}/etc/pki/crassostrea#g" -e "s#^dir .*#dir ${d}/s#" \
      "${ROOT[$n]}/var/lib/valkey/sentinel.conf" > "${d}/sentinel.conf"
  echo "logfile ${d}/sentinel.log" >> "${d}/sentinel.conf"
}
# valkey-role as the ExecStartPre of valkey.service runs it on node n
role() {
  local n=$1
  env CRASSOSTREA_HOSTNAME="${NAME[$n]}" HA_NODES="${HA_NODES}" HA_WITNESS="${HA_WITNESS}" REDISPASS="${PASS}" \
    SF_PKI="${ROOT[$n]}/etc/pki/crassostrea" ROLE_FILE="${L}/${n}/role.conf" "${REPO}/system/libexec/valkey-role" "${@:2}"
}
start_valkey() { valkey-server "${L}/ro/$1/main.conf" --daemonize yes --pidfile "${L}/$1/valkey.pid"; }
start_sentinel() { valkey-sentinel "${L}/$1/sentinel.conf" --daemonize yes --pidfile "${L}/$1/sentinel.pid"; }
cli() {
  local n=$1 port=$2 pki=${ROOT[n1]}/etc/pki/crassostrea
  shift 2
  valkey-cli --tls --cacert "${pki}/ca.crt" --cert "${pki}/node.crt" --key "${pki}/node.key" \
    -h "${ADDR[$n]}" -p "${port}" -a "${PASS}" --no-auth-warning "$@"
}
local_cli() { valkey-cli -h 127.0.0.1 -p 6379 -a "${PASS}" --no-auth-warning "$@"; }

# node 1 creates the cluster: master; node 2 joins as replica; the witness votes
for n in n1 n2; do valkey_conf "${n}"; done
for n in n1 n2 w; do sentinel_conf "${n}"; done
mount --bind "${L}/ro" "${L}/ro" && mount -o remount,ro,bind "${L}/ro"
role n1
check "node 1 starts as master (no Sentinel yet)" "[[ -f ${L}/n1/role.conf ]] && ! grep -q replicaof ${L}/n1/role.conf"
start_valkey n1
start_sentinel n1
sleep 1
role n2
check "node 2 starts as replica of node 1" "grep -q 'replicaof 10.0.0.1 6380' ${L}/n2/role.conf"
start_valkey n2
start_sentinel n2
start_sentinel w
check "plain TCP refused (TLS only)" \
  "! timeout 2 valkey-cli -h 10.0.0.1 -p 6380 -a ${PASS} --no-auth-warning PING 2> /dev/null | grep -q PONG"
check "TLS without client certificate refused" \
  "! timeout 2 valkey-cli --tls --cacert ${ROOT[n1]}/etc/pki/crassostrea/ca.crt -h 10.0.0.1 -p 6380 -a ${PASS} --no-auth-warning PING 2> /dev/null | grep -q PONG"
check "replication link up" "wait_for \"cli n2 6380 INFO replication | grep -q master_link_status:up\" 15"

sed -e "s#/etc/pki/crassostrea#${ROOT[n1]}/etc/pki/crassostrea#g" -e "s#^  user haproxy#  \# user#" \
    -e "s#^  group haproxy#  \# group#" -e "s#^  log /dev/log.*#  log stdout format raw local0#" \
    "${ROOT[n1]}/etc/haproxy/haproxy.cfg" > "${L}/haproxy.cfg"
haproxy -D -f "${L}/haproxy.cfg" -p "${L}/haproxy.pid"
check "haproxy forwards to the master" "wait_for \"local_cli SET k1 v1 | grep -q OK\" 10"
check "write replicated to node 2" "wait_for \"[[ \\\$(cli n2 6380 GET k1) == v1 ]]\" 10"
check "all 3 Sentinels know each other" \
  "wait_for \"[[ \\\$(cli w 26379 SENTINEL master crassostrea | grep -A1 '^num-other-sentinels' | tail -1) == 2 ]]\" 20"
# On a running cluster every Sentinel has seen the replicas long before a
# failure; a Sentinel that has not cannot lead a failover
for n in n1 n2 w; do
  check "Sentinel on ${n} knows the replica" "wait_for \"cli ${n} 26379 SENTINEL replicas crassostrea | grep -qx 10.0.0.2:6380\" 30"
done
check "Sentinel quorum is 2" "[[ \$(cli w 26379 SENTINEL master crassostrea | grep -A1 '^quorum' | tail -1) == 2 ]]"

# a pub/sub subscriber (like netfilter) through haproxy
(local_cli SUBSCRIBE F2B_CHANNEL > "${L}/sub.out" 2>&1 &)
sleep 1
local_cli PUBLISH F2B_CHANNEL hello > /dev/null
check "pub/sub through haproxy" "grep -q hello ${L}/sub.out"

# failover: node 1's valkey dies
kill "$(cat "${L}/n1/valkey.pid")"
killed_at=$(date +%s)
check "Sentinels promote node 2" "wait_for \"[[ \\\$(role n2 --print) == 10.0.0.2 ]]\" 40"
check "haproxy follows the new master" "wait_for \"local_cli SET k2 v2 2> /dev/null | grep -q OK\" 15"
echo "info failover took $(( $(date +%s) - killed_at )) s"
check "the main configuration files were not rewritten" "! grep -rq 'CONFIG REWRITE' ${L}/ro"
check "the rewrite failed, as intended" "grep -q 'CONFIG REWRITE failed' ${L}/n2/valkey.log"
check "data written before the failover survives" "[[ \$(local_cli GET k1) == v1 ]]"
sleep 2
check "pub/sub client of the old master was disconnected" "! pgrep -f 'SUBSCRIBE F2B_CHANNEL' > /dev/null"

# node 1 returns: valkey-role makes it a replica of node 2
role n1
check "returning node 1 starts as replica of node 2" "grep -q 'replicaof 10.0.0.2 6380' ${L}/n1/role.conf"
start_valkey n1
check "node 1 is a replica in sync" "wait_for \"cli n1 6380 INFO replication | grep -q master_link_status:up\" 15"
check "node 1 has the data written during its absence" "wait_for \"[[ \\\$(cli n1 6380 GET k2) == v2 ]]\" 10"
check "exactly one master" "[[ \$(for n in n1 n2; do cli \$n 6380 INFO replication; done | grep -c role:master) == 1 ]]"

# The cluster node service of node 1 (system/libexec/cluster-node): its
# probe, making node 1 the master again, maintenance
C=${L}/cluster-n1
mkdir -p "${C}/web" "${C}/postfix"
env CRASSOSTREA_HOSTNAME="${NAME[n1]}" HA_NODES="${HA_NODES}" HA_WITNESS="${HA_WITNESS}" HA_VIP= REDISPASS="${PASS}" \
  SF_PKI="${ROOT[n1]}/etc/pki/crassostrea" CLUSTER_REQUEST="${C}/web/request" CLUSTER_STATE_DIR="${C}/state" \
  CLUSTER_MAINT_CIDR="${C}/postfix/maintenance.cidr" CLUSTER_PROBE_INTERVAL=1 \
  "${REPO}/system/libexec/cluster-node" > "${C}/log" 2>&1 &
echo $! > "${L}/n1/cluster-node.pid"
probe_is() { [[ $(jq -r "$1" "${C}/state/probe.json" 2> /dev/null) == "$2" ]]; }
priority_is() { [[ $(cli "$1" 6380 CONFIG GET replica-priority | tail -1) == "$2" ]]; }
request() { printf '%s\n' "$@" > "${C}/web/request.tmp" && mv "${C}/web/request.tmp" "${C}/web/request"; }
check "cluster-node: node 1 is a replica with its link up" \
  "wait_for \"probe_is .valkey.role slave && probe_is .valkey.link up\" 10"
check "cluster-node: Sentinel reaches a majority, the witness answers" \
  "probe_is .sentinel.quorum true && probe_is .sentinel.witness true"
request promote=0123456789abcdef
check "cluster-node: node 1 made the Valkey master" "wait_for \"probe_is .promote.ok true\" 60"
check "node 1 is the master" "cli n1 6380 INFO replication | grep -q role:master"
check "its priority is back to 100" "priority_is n1 100"
check "haproxy follows node 1" "wait_for \"local_cli SET k3 v3 2> /dev/null | grep -q OK\" 15"
request maintenance=on
check "maintenance: Postfix answers 421" "wait_for \"grep -q '^0.0.0.0/0 421' ${C}/postfix/maintenance.cidr\" 10"
check "maintenance: node 2 takes over the master" "wait_for \"cli n2 6380 INFO replication | grep -q role:master\" 60"
check "maintenance: node 1 is never chosen (priority 0)" "wait_for \"priority_is n1 0\" 10"
check "maintenance: in the probe" "probe_is .maintenance true"
CLUSTER_MAINTENANCE=${C}/state/maintenance role n1
check "valkey-role keeps priority 0 after a restart" "grep -qx 'replica-priority 0' ${L}/n1/role.conf"
request maintenance=off
check "maintenance off: Postfix accepts mail" "wait_for \"! grep -q 421 ${C}/postfix/maintenance.cidr\" 10"
check "maintenance off: priority 100 again" "wait_for \"priority_is n1 100\" 10"
check "maintenance off: in the probe" "wait_for \"probe_is .maintenance false\" 5"

for pidfile in "${L}"/*/*.pid "${L}/haproxy.pid"; do
  kill "$(cat "${pidfile}")" 2> /dev/null
done
finish
