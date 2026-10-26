#!/usr/bin/env bash
# System tests: the rendered cluster configuration with the real EL10
# binaries, in user and network namespaces (no root, nothing installed).
#
#   tests/system/run.sh [render] [valkey] [galera] [acme] [netfilter] [js]
#
# Without arguments all tests run. Needs an EL10 host with dnf (packages are
# downloaded, not installed), unprivileged user namespaces, nft, curl,
# openssl, python3 with python3-nftables, and for "js" node and npm. Work
# files go to $SF_TEST_WORK (default ${TMPDIR:-/tmp}/crassostrea-system-tests).
set -o pipefail
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "${DIR}/lib.sh"

tests=("$@")
[[ ${#tests[@]} -gt 0 ]] || tests=(render valkey galera acme netfilter js)
mkdir -p "${WORK}"

if [[ ! -x ${PKG}/usr/bin/valkey-server ]]; then
  "${DIR}/fetch-packages.sh" || exit 1
fi
# the rendered cluster is the input of every test but js
if [[ ! -s ${NODES}/mx1/etc/my.cnf.d/zz-crassostrea.cnf || " ${tests[*]} " == *" render "* ]]; then
  echo "=== render"
  "${DIR}/render.sh" || exit 1
fi

venv() {
  [[ -x ${WORK}/venv/bin/python ]] && return 0
  python3 -m venv --system-site-packages "${WORK}/venv" \
    && "${WORK}/venv/bin/pip" install -q --disable-pip-version-check -r "${REPO}/data/web/requirements-dev.txt" dnspython
}

failed=()
for test in "${tests[@]}"; do
  [[ ${test} == render ]] && continue
  echo "=== ${test}"
  case "${test}" in
    valkey) unshare -rnm bash "${DIR}/valkey-ha.sh" ;;
    galera) unshare -rnm bash "${DIR}/galera-ha.sh" ;;
    acme) unshare -rn bash "${DIR}/acme-peers.sh" ;;
    netfilter) venv && bash "${DIR}/netfilter.sh" ;;
    js)
      if ! command -v node > /dev/null || ! command -v npm > /dev/null; then
        echo "node and npm are needed (dnf install nodejs npm)"
        false
      else
        mkdir -p "${WORK}/js"
        cp "${DIR}/js/package.json" "${WORK}/js/"
        (cd "${WORK}/js" && npm install --silent --no-audit --no-fund --ignore-scripts) \
          && NODE_PATH=${WORK}/js/node_modules node "${DIR}/js/app_test.js" "${REPO}/data/web/crassostrea/static/app.js"
      fi
      ;;
    *) echo "Unknown test ${test}"; false ;;
  esac
  [[ $? -eq 0 ]] || failed+=("${test}")
done

echo
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "FAILED: ${failed[*]} (logs in ${WORK})"
  exit 1
fi
echo "All system tests passed (${tests[*]})"
