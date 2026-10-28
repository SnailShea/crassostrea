#!/usr/bin/env bash
# The floating address (HA_VIP), run by run.sh inside `unshare -rnm`: two
# nodes, each in its own network namespace with a cluster network (eth0,
# VRRP) and a public network (pub, the address), and a router on the public
# network. keepalived with the configuration rendered by configure.sh: the
# address on one node, moved when its health check fails or its public
# interface goes down, not moved back, and the router following it by the
# gratuitous ARP alone.
#
# Differences to a real cluster: the health check is a file per node
# (track_file) instead of crassostrea-health, as keepalived cannot run
# scripts in a user namespace (setgroups is denied); files below $WORK
# instead of /etc and /run.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=${PKG}/usr/bin:${PKG}/usr/sbin:${PATH}
export LD_LIBRARY_PATH=${PKG}/usr/lib64

VIP=${HA_VIP%/*}
L=${WORK}/keepalived
rm -rf "${L}"
mkdir -p "${L}"
declare -A ROOT=([n1]=${NODES}/mx1 [n2]=${NODES}/mx2)
declare -A ADDR=([n1]=10.0.0.1 [n2]=10.0.0.2)
declare -A PUB=([n1]=192.0.2.11 [n2]=192.0.2.12)
declare -A NS

# the router: a bridge for the public network
ip link set lo up
ip link add br0 type bridge
ip addr add 192.0.2.254/24 dev br0
ip link set br0 up
# no ARP requests of its own while the address moves: only the gratuitous
# ARP of keepalived can update it
sysctl -qw net.ipv4.neigh.br0.base_reachable_time_ms=600000 net.ipv4.neigh.br0.gc_stale_time=600 2> /dev/null

on() {
  local n=$1
  shift
  nsenter -t "${NS[$n]}" -n "$@"
}
for n in n1 n2; do
  unshare -n sleep infinity &
  NS[${n}]=$!
done
sleep 0.5
# cluster network: a direct link between the nodes
ip link add eth0 netns "${NS[n1]}" type veth peer name eth0 netns "${NS[n2]}"
for n in n1 n2; do
  ip link add "pub-${n}" type veth peer name pub netns "${NS[$n]}"
  ip link set "pub-${n}" master br0 up
  on "${n}" ip link set lo up
  on "${n}" ip addr add "${ADDR[$n]}/24" dev eth0
  on "${n}" ip link set eth0 up
  on "${n}" ip addr add "${PUB[$n]}/24" dev pub
  on "${n}" ip link set pub up
done
mac() { on "$1" ip -o link show dev pub | grep -o 'link/ether [0-9a-f:]*' | cut -d' ' -f2; }
declare -A MAC=([n1]=$(mac n1) [n2]=$(mac n2))

# the rendered configuration with the health check replaced: fails while
# $L/<node>/health holds 1
conf=${ROOT[n1]}/etc/keepalived/keepalived.conf
check "the health check is tracked" \
  "grep -q 'script \"/usr/libexec/keepalived/crassostrea-health\"' ${conf} && grep -A1 track_script ${conf} | grep -q crassostrea_health"
# without HA_VIP_INTERFACE (the one-node cluster) VRRP and the address share
# the interface with the cluster address; a cluster of one has no peers yet
solo=${NODES}/solo/etc/keepalived/keepalived.conf
check "one interface for VRRP and the address by default" \
  "grep -qx '  interface eth0' ${solo} && grep -qx '    10.0.0.50/24 dev eth0' ${solo} && ! grep -q 'track_interface\|unicast_peer' ${solo}"
for n in n1 n2; do
  mkdir -p "${L}/${n}"
  echo 0 > "${L}/${n}/health"
  sed -e "/^vrrp_script crassostrea_health {/,/^}/c vrrp_track_file crassostrea_health {\n  file ${L}/${n}/health\n}" \
      -e '/^  track_script {/,/^  }/c \  track_file {\n    crassostrea_health weight 0\n  }' \
      "${ROOT[$n]}/etc/keepalived/keepalived.conf" > "${L}/${n}/keepalived.conf"
done
healthy() { echo "$2" > "${L}/$1/health"; }
check "VRRP on the cluster interface" "grep -qx '  interface eth0' ${conf}"
check "VRRP from and to the cluster addresses" \
  "grep -qx '  unicast_src_ip 10.0.0.1' ${conf} && grep -qx '    10.0.0.2' ${conf}"
check "the address on the public interface" "grep -qx '    ${HA_VIP} dev pub' ${conf}"
check "the public interface is tracked" "grep -A1 track_interface ${conf} | grep -qx '    pub'"

start() {
  local n=$1
  on "${n}" keepalived --vrrp --dont-fork --log-console --log-detail -f "${L}/${n}/keepalived.conf" \
    -p "${L}/${n}/keepalived.pid" -r "${L}/${n}/vrrp.pid" > "${L}/${n}/keepalived.log" 2>&1 &
}
holds() { on "$1" ip -4 -o addr show dev pub | grep -q " ${VIP}/"; }
holders() {
  local n out=""
  for n in n1 n2; do
    holds "${n}" && out+=" ${n}"
  done
  echo "${out# }"
}
# the router's ARP entry of the address
router_mac() { ip neigh show "${VIP}" dev br0 | awk '{print $3}'; }
reachable() { ping -c 1 -W 1 "${VIP}" > /dev/null 2>&1; }

start n1
start n2
check "node 1 (higher priority) takes the address" "wait_for '[[ \$(holders) == n1 ]]' 15"
check "the router reaches it on node 1" "reachable && [[ \$(router_mac) == ${MAC[n1]} ]]"

healthy n1 1
check "a failed health check moves it to node 2" "wait_for '[[ \$(holders) == n2 ]]' 20"
check "the router follows by gratuitous ARP" "wait_for '[[ \$(router_mac) == ${MAC[n2]} ]]' 5"
check "and reaches it on node 2" "reachable"

healthy n1 0
sleep 15
check "it stays on node 2 when node 1 is healthy again" "[[ \$(holders) == n2 ]]"

on n2 ip link set pub down
check "node 2's public interface going down moves it to node 1" "wait_for '[[ \$(holders) == n1 ]]' 20"
check "the router follows again" "wait_for '[[ \$(router_mac) == ${MAC[n1]} ]]' 5 && reachable"
on n2 ip link set pub up

# the cluster network splits (the links stay up): VRRP alone cannot tell,
# both nodes take the address; crassostrea-health fails on the side without
# the majority (its database copy is not Synced), which gives it up
for n in n1 n2; do
  peer=${ADDR[n1]}
  [[ ${n} == n1 ]] && peer=${ADDR[n2]}
  on "${n}" ip route add blackhole "${peer}/32"
done
check "split cluster network: both nodes take the address" "wait_for '[[ \$(holders) == \"n1 n2\" ]]' 15"
healthy n2 1
check "the node without the majority gives it up" "wait_for '[[ \$(holders) == n1 ]]' 20"
check "the router reaches node 1" "wait_for '[[ \$(router_mac) == ${MAC[n1]} ]]' 5 && reachable"
for n in n1 n2; do
  on "${n}" ip route flush type blackhole
done
healthy n2 0
sleep 10
check "with the network back, it stays on node 1 alone" "[[ \$(holders) == n1 ]]"

kill "${NS[n1]}" "${NS[n2]}" 2> /dev/null
for n in n1 n2; do
  [[ -s ${L}/${n}/keepalived.pid ]] && kill "$(cat "${L}/${n}/keepalived.pid")" 2> /dev/null
done
wait 2> /dev/null
finish
