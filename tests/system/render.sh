#!/usr/bin/env bash
# Builds the test cluster's configuration the way an administrator would:
# setup.sh --ha --config-only on the first node (creates the cluster CA),
# join bundles for the second node and the witness, then a dry run of
# configure.sh for each member (SF_ROOT: every file is written below
# $WORK/nodes/<member>, nothing is started).
set -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

rm -rf "${NODES}"
mkdir -p "${NODES}"
export SF_DRYRUN=y SF_ASN_RESPONSE=200

member() {
  export SF_ROOT=${NODES}/$1 SF_CONF=${NODES}/$1/etc/crassostrea/crassostrea.conf
}

member mx1
# setup.sh refuses to run without root: a user namespace is enough
unshare -r "${REPO}/setup.sh" --hostname "${NODE1}" --yes --config-only \
  --ha-nodes "${HA_NODES}" --ha-witness "${HA_WITNESS}" --ha-vip "${HA_VIP}" > "${WORK}/setup.log" 2>&1 \
  || { echo "setup.sh failed, see ${WORK}/setup.log" >&2; exit 1; }

# join bundles, as system/cluster.sh bundle would create them
(
  source "${REPO}/system/lib/common.sh"
  load_config
  ha_bundle "${NODE2}" "${WORK}/join-mx2.tar"
  ha_bundle "${WITNESS}" "${WORK}/join-witness.tar"
  for host in mx2 witness; do
    member "${host}"
    mkdir -p "${SF_ROOT}"
    ha_unbundle "${WORK}/join-${host}.tar"
  done
) > "${WORK}/bundles.log" 2>&1 || { echo "Creating the join bundles failed, see ${WORK}/bundles.log" >&2; exit 1; }

# the documentation is served by mx1 (acme test: /docs/ for administrators)
echo "DOCS_ENABLED=y" >> "${NODES}/mx1/etc/crassostrea/crassostrea.conf"
# the floating address on the public network, VRRP on the cluster network
# (eth0 in a dry run)
for host in mx1 mx2; do
  echo "HA_VIP_INTERFACE=${HA_VIP_INTERFACE}" >> "${NODES}/${host}/etc/crassostrea/crassostrea.conf"
done

for host in mx1 mx2 witness; do
  member "${host}"
  "${REPO}/system/configure.sh" > "${WORK}/configure-${host}.log" 2>&1 \
    || { echo "configure.sh failed for ${host}, see ${WORK}/configure-${host}.log" >&2; exit 1; }
done
# a cluster of one node, as the Cluster page of the web UI creates it
member solo
unshare -r "${REPO}/setup.sh" --hostname solo.example.com --yes --config-only --ha \
  --ha-nodes solo.example.com=10.0.0.9 --ha-witness none --ha-vip 10.0.0.50/24 > "${WORK}/setup-solo.log" 2>&1 \
  && "${REPO}/system/configure.sh" > "${WORK}/configure-solo.log" 2>&1 \
  || { echo "Rendering a one-node cluster failed, see ${WORK}/*-solo.log" >&2; exit 1; }

echo "Rendered ${NODE1}, ${NODE2} and ${WITNESS}, and solo.example.com (one node) into ${NODES}"
