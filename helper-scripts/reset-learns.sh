#!/usr/bin/env bash
# Deletes what Rspamd learned (Bayes, fuzzy hashes, neural networks).
[[ ${EUID} -eq 0 ]] || { echo "Please run as root"; exit 1; }
REDISPASS=$(sed -n 's/^REDISPASS=//p' /etc/crassostrea/crassostrea.conf | tail -1)
[[ -n ${REDISPASS} ]] || { echo "Cannot read REDISPASS from /etc/crassostrea/crassostrea.conf"; exit 1; }

read -r -p "Are you sure you want to reset learned hashes from Rspamd (fuzzy, bayes, neural)? [y/N] " response
response=${response,,}    # tolower
if [[ "$response" =~ ^(yes|y)$ ]]; then
  echo "Stopping Rspamd"
  systemctl stop rspamd.service
  echo "LUA will return nil when it succeeds or print a warning/error when it fails."
  for pattern in 'RS*' 'BAYES*' 'learned*' 'fuzzy*' 'tRFANN*'; do
    echo "Deleting all ${pattern} keys - if any"
    valkey-cli -h 127.0.0.1 -a "${REDISPASS}" --no-auth-warning EVAL \
      "for _,k in ipairs(redis.call('keys', ARGV[1])) do redis.call('del', k) end" 0 "${pattern}"
  done
  echo "Starting Rspamd"
  systemctl start rspamd.service
fi
