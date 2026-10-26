#!/usr/bin/env bash
# netfilter (services/netfilter) with the real nftables backend, run by
# run.sh: a single gateway, then two cluster nodes sharing a valkey. Every
# step runs in its own network namespace, so each has its own nftables.
#
# PYTHON: an interpreter with python3-nftables (system), redis, dnspython
# and fakeredis (run.sh creates $WORK/venv).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PYTHON=${PYTHON:-${WORK}/venv/bin/python}
NETFILTER=${REPO}/services/netfilter
export PYTHONDONTWRITEBYTECODE=1

echo "--- single gateway"
unshare -rn "${PYTHON}" "${DIR}/netfilter_single.py" "${NETFILTER}" | grep -E '^(ok|FAIL)' \
  | tee "${WORK}/netfilter-single.log"
grep -q '^FAIL' "${WORK}/netfilter-single.log" && fails=$((fails + 1))

echo "--- cluster"
state=${WORK}/netfilter-valkey
rm -rf "${state}"
mkdir -p "${state}"
for step in node1-bans node2-starts node2-reconciles expired; do
  # shellcheck disable=SC2016
  unshare -rn bash -c '
    ip link set lo up
    "$1/usr/bin/valkey-server" --port 6390 --bind 127.0.0.1 --dir "$2" --appendonly yes --save "" \
      --daemonize yes --logfile "$2/valkey.log"
    sleep 0.5
    VALKEY_PORT=6390 "$3" "$4/netfilter_cluster.py" "$5" "$6"
    rc=$?
    "$1/usr/bin/valkey-cli" -p 6390 shutdown > /dev/null
    exit $rc' _ "${PKG}" "${state}" "${PYTHON}" "${DIR}" "${NETFILTER}" "${step}" | grep -E '^(ok|FAIL)' \
    | grep -v 'cluster mode detected$' > "${WORK}/netfilter-step.log"
  cat "${WORK}/netfilter-step.log"
  grep -q '^FAIL' "${WORK}/netfilter-step.log" && fails=$((fails + 1))
done
finish
