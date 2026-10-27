#!/usr/bin/env bash
# The Spamhaus blocklists of Postfix (postscreen) and Rspamd. With the Data
# Query Service key of the web UI (Settings -> General, Scanning, written to
# SPAMHAUS_SETTINGS) both query the DQS zones of the key; without one the
# public mirrors, unless they refuse this server's network (cloud providers):
# then the Spamhaus lists are left out.
#
# Postfix: main.cf's postscreen_dnsbl_sites ends with $sf_spamhaus_dnsbl, the
# Spamhaus part, and postscreen_dnsbl_reply_map names SPAMHAUS_REPLY_MAP
# (empty without a key). Rspamd: SPAMHAUS_RSPAMD_CONF, included by
# local.d/rbl.conf, with the DQS rules of the template (none without a key).
#
# Sourced by common.sh, and deployed to /usr/local/lib/crassostrea/lib for
# system/libexec/spamhaus-apply, which applies a new key without a
# configure.sh run.

SPAMHAUS_SETTINGS=${SPAMHAUS_SETTINGS:-/var/lib/crassostrea/web/spamhaus}
# written by the callers (configure.sh, spamhaus-apply)
# shellcheck disable=SC2034
SPAMHAUS_REPLY_MAP=${SPAMHAUS_REPLY_MAP:-/etc/postfix/dnsbl_reply.map}
# shellcheck disable=SC2034
SPAMHAUS_RSPAMD_CONF=${SPAMHAUS_RSPAMD_CONF:-/etc/rspamd/custom/dqs-rbl.conf}
# Whether the public mirrors answer this server's network
SPAMHAUS_ASN_CHECK=${SPAMHAUS_ASN_CHECK:-https://asn-check.mailcow.email}

# The key of the web UI's settings, if it is one (letters and digits)
spamhaus_key() {
  local key
  [[ -r ${SPAMHAUS_SETTINGS} ]] || return 0
  key=$(tr -d '[:space:]' < "${SPAMHAUS_SETTINGS}")
  [[ ${key} =~ ^[A-Za-z0-9]{1,64}$ ]] && echo "${key}"
  return 0
}

# spamhaus_asn_status: the HTTP status of the check of the public mirrors
# (200: usable, 503: this network is refused)
spamhaus_asn_status() {
  curl --connect-timeout 15 --max-time 30 -s -o /dev/null -w "%{http_code}" "${SPAMHAUS_ASN_CHECK}"
}

# spamhaus_postscreen KEY [ASN_STATUS]: the postscreen_dnsbl_sites entries,
# separated by spaces (none: empty). Without a key, ASN_STATUS decides.
spamhaus_postscreen() {
  local key=$1 status=${2:-}
  if [[ -n ${key} ]]; then
    echo "${key}.zen.dq.spamhaus.net=127.0.0.[4..7]*6 ${key}.zen.dq.spamhaus.net=127.0.0.[10;11]*8" \
      "${key}.zen.dq.spamhaus.net=127.0.0.3*4 ${key}.zen.dq.spamhaus.net=127.0.0.2*3"
  elif [[ ${status} == 200 ]]; then
    echo "zen.spamhaus.org=127.0.0.[10;11]*8 zen.spamhaus.org=127.0.0.[4..7]*6 zen.spamhaus.org=127.0.0.3*4" \
      "zen.spamhaus.org=127.0.0.2*3"
  else
    echo
  fi
}

# spamhaus_reply_map KEY: postscreen's replies name the public zones, not the
# key
spamhaus_reply_map() {
  local key=$1 zone
  echo "# Generated from the web UI's Spamhaus DQS key (system/lib/spamhaus.sh) - do not edit"
  [[ -n ${key} ]] || return 0
  for zone in sbl xbl pbl zen dbl zrd; do
    printf '%s.%s.dq.spamhaus.net     %s.spamhaus.org\n' "${key}" "${zone}" "${zone}"
  done
}

# spamhaus_rspamd TEMPLATE KEY: the Rspamd rules (only a comment without a key)
spamhaus_rspamd() {
  local template=$1 key=$2
  if [[ -n ${key} ]]; then
    sed "s/\${SPAMHAUS_DQS_KEY}/${key}/g" "${template}"
  else
    echo "# No Spamhaus DQS key in the web UI's settings (system/lib/spamhaus.sh)"
  fi
}
