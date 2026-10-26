#!/usr/bin/env bash
# Editing crassostrea.conf (SF_CONF). Sourced by common.sh, and deployed to
# /usr/local/lib/crassostrea/lib for the root services of the web UI
# (system/libexec/tls-apply). Needs die().

# conf_set KEY VALUE: replace or append KEY=VALUE in crassostrea.conf
conf_set() {
  local key=$1 value=$2 tmp
  tmp=$(mktemp "${SF_CONF}.XXXXXX") || die "Cannot write ${SF_CONF}"
  if grep -q "^${key}=" "${SF_CONF}"; then
    awk -v k="${key}" -v v="${value}" 'index($0, k "=") == 1 {print k "=" v; next} {print}' "${SF_CONF}" > "${tmp}"
  else
    { cat "${SF_CONF}"; echo "${key}=${value}"; } > "${tmp}"
  fi
  chmod --reference="${SF_CONF}" "${tmp}" && chown --reference="${SF_CONF}" "${tmp}" 2> /dev/null
  mv -f "${tmp}" "${SF_CONF}" || die "Cannot write ${SF_CONF}"
  export "${key}=${value}"
}
