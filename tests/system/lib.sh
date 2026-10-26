#!/usr/bin/env bash
# Shared by the system tests (see README.md): paths and checks.
#
# SF_TEST_WORK  work directory (packages, rendered nodes, logs);
#               default ${TMPDIR:-/tmp}/crassostrea-system-tests

REPO=${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
WORK=${SF_TEST_WORK:-${TMPDIR:-/tmp}/crassostrea-system-tests}
# EL10 packages, extracted (fetch-packages.sh)
PKG=$WORK/pkgroot
# Configuration rendered by configure.sh for each cluster member (render.sh)
NODES=$WORK/nodes
export REPO WORK

# The test cluster: two nodes and a witness on loopback addresses
NODE1=mx1.example.com
NODE2=mx2.example.com
WITNESS=witness.example.com
HA_NODES="${NODE1}=10.0.0.1,${NODE2}=10.0.0.2"
HA_WITNESS="${WITNESS}=10.0.0.3"

fails=0

# check NAME CONDITION: CONDITION is evaluated
check() {
  if eval "$2"; then
    echo "ok   $1"
  else
    echo "FAIL $1"
    fails=$((fails + 1))
  fi
}

# wait_for CONDITION SECONDS
wait_for() {
  local i
  for i in $(seq 1 "$2"); do
    eval "$1" && return 0
    sleep 1
  done
  return 1
}

finish() {
  echo "failures: ${fails}"
  exit $(( fails > 0 ))
}

# Inside the network namespace: the members' addresses on loopback
cluster_addresses() {
  ip link set lo up
  local address
  for address in "$@"; do
    ip addr add "${address}/32" dev lo
  done
}
