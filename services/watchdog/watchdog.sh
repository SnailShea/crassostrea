#!/bin/bash
# Crassostrea watchdog (crassostrea-watchdog.service, runs as root).
# Checks every service of the gateway; when a check hits its threshold the
# matching systemd units are restarted and a notification is sent.

# Paths on the host (overridable for tests)
NAGIOS_PLUGINS=${NAGIOS_PLUGINS:-/usr/lib64/nagios/plugins}
WATCHDOG_LIBEXEC=${WATCHDOG_LIBEXEC:-/usr/local/libexec/crassostrea/watchdog}
SMTP_CLI=${SMTP_CLI:-${WATCHDOG_LIBEXEC}/smtp-cli}
MYSQL_SOCKET=${MYSQL_SOCKET:-/var/lib/mysql/mysql.sock}
RSPAMD_SOCKET=${RSPAMD_SOCKET:-/var/lib/rspamd/rspamd.sock}

# In a cluster (HA_NODES) Valkey is reached through haproxy, and the
# database is never restarted here: Galera rejoins a node by itself, and a
# restart cannot help a node that lost the majority of the cluster
CLUSTER=0
GALERA_MEMBERS=0
if [[ -n ${HA_NODES//[[:space:],]/} ]]; then
  CLUSTER=1
  GALERA_MEMBERS=$(tr ',' '\n' <<< "${HA_NODES},${HA_WITNESS}" | grep -c '=')
fi

if [ "${DEV_MODE}" != "n" ]; then
  echo -e "\e[31mEnabled Debug Mode\e[0m"
  set -x
fi

trap "exit" INT TERM
trap "kill 0" EXIT

# Prepare
BACKGROUND_TASKS=()
echo "Waiting for services to settle..."
for i in {30..1}; do
  echo "${i}"
  sleep 1
done

if [[ "${USE_WATCHDOG}" =~ ^([nN][oO]|[nN])+$ ]]; then
  echo -e "$(date) - USE_WATCHDOG=n, skipping watchdog..."
  sleep 365d
  exec $(readlink -f "$0")
fi

if [[ "${WATCHDOG_VERBOSE}" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
  SMTP_VERBOSE="--verbose"
  CURL_VERBOSE="--verbose"
  set -xv
else
  SMTP_VERBOSE=""
  CURL_VERBOSE=""
  exec 2>/dev/null
fi

# Checks write the name of the failed check into this pipe
if [[ ! -p /tmp/com_pipe ]]; then
  mkfifo /tmp/com_pipe
fi

# Wait for the database
while ! mariadb-admin status --skip-ssl --socket=${MYSQL_SOCKET} -u${DBUSER} -p${DBPASS} --silent; do
  echo "Waiting for SQL..."
  sleep 2
done

REDIS_CMDLINE="valkey-cli -h 127.0.0.1 -p 6379 -a ${REDISPASS} --no-auth-warning"

until [[ $(${REDIS_CMDLINE} PING) == "PONG" ]]; do
  echo "Waiting for Valkey..."
  sleep 2
done

${REDIS_CMDLINE} DEL F2B_RES > /dev/null

# Common functions
array_diff() {
  # https://stackoverflow.com/questions/2312762, Alex Offshore
  eval local ARR1=\(\"\${$2[@]}\"\)
  eval local ARR2=\(\"\${$3[@]}\"\)
  local IFS=$'\n'
  mapfile -t $1 < <(comm -23 <(echo "${ARR1[*]}" | sort) <(echo "${ARR2[*]}" | sort))
}

progress() {
  SERVICE=${1}
  TOTAL=${2}
  CURRENT=${3}
  DIFF=${4}
  [[ -z ${DIFF} ]] && DIFF=0
  [[ -z ${TOTAL} || -z ${CURRENT} ]] && return
  [[ ${CURRENT} -gt ${TOTAL} ]] && return
  [[ ${CURRENT} -lt 0 ]] && CURRENT=0
  PERCENT=$(( 200 * ${CURRENT} / ${TOTAL} % 2 + 100 * ${CURRENT} / ${TOTAL} ))
  ${REDIS_CMDLINE} LPUSH WATCHDOG_LOG "{\"time\":\"$(date +%s)\",\"service\":\"${SERVICE}\",\"lvl\":\"${PERCENT}\",\"hpnow\":\"${CURRENT}\",\"hptotal\":\"${TOTAL}\",\"hpdiff\":\"${DIFF}\"}" > /dev/null
  log_msg "${SERVICE} health level: ${PERCENT}% (${CURRENT}/${TOTAL}), health trend: ${DIFF}" no_redis
  # Return 10 to indicate a dead service
  [ ${CURRENT} -le 0 ] && return 10
}

log_msg() {
  if [[ ${2} != "no_redis" ]]; then
    ${REDIS_CMDLINE} LPUSH WATCHDOG_LOG "{\"time\":\"$(date +%s)\",\"message\":\"$(printf '%s' "${1}" | \
      tr '\r\n%&;$"_[]{}-' ' ')\"}" > /dev/null
  fi
  echo $(date) $(printf '%s\n' "${1}")
}

# The notice settings of the web UI (Settings -> Alerts & export), written to
# the hash WATCHDOG_NOTIFY by its sync. Read again for every notice; while
# Valkey cannot be reached the values read last stay
load_notify_settings() {
  local field value
  for field in email webhook webhook_body subject notify_start notify_ban; do
    value=$(timeout 4s ${REDIS_CMDLINE} --raw HGET WATCHDOG_NOTIFY "${field}" 2> /dev/null) || return 1
    case ${field} in
      email) WATCHDOG_NOTIFY_EMAIL=${value} ;;
      webhook) WATCHDOG_NOTIFY_WEBHOOK=${value} ;;
      webhook_body) WATCHDOG_NOTIFY_WEBHOOK_BODY=${value} ;;
      subject) WATCHDOG_SUBJECT=${value:-Watchdog ALERT} ;;
      notify_start) WATCHDOG_NOTIFY_START=${value} ;;
      notify_ban) WATCHDOG_NOTIFY_BAN=${value} ;;
    esac
  done
}

function notify_error() {
  load_notify_settings
  # Check if one of the notification options is enabled
  [[ -z ${WATCHDOG_NOTIFY_EMAIL} ]] && [[ -z ${WATCHDOG_NOTIFY_WEBHOOK} ]] && return 0
  THROTTLE=
  [[ -z ${1} ]] && return 1
  # If exists, body will be the content of "/tmp/${1}", even if ${2} is set
  [[ -z ${2} ]] && BODY="Service was restarted on $(date), please check your Crassostrea installation (journalctl -u ${4:-crassostrea-watchdog})." || BODY="$(date) - ${2}"
  # If exists, mail will be throttled by argument in seconds
  [[ ! -z ${3} ]] && THROTTLE=${3}
  if [[ ! -z ${THROTTLE} ]]; then
    TTL_LEFT="$(${REDIS_CMDLINE} TTL THROTTLE_${1} 2> /dev/null)"
    if [[ "${TTL_LEFT}" == "-2" ]]; then
      # Delay key not found, setting a delay key now
      ${REDIS_CMDLINE} SET THROTTLE_${1} 1 EX ${THROTTLE}
    else
      log_msg "Not sending notification email now, blocked for ${TTL_LEFT} seconds..."
      return 1
    fi
  fi
  # Some exceptions for subject and body formats
  if [[ ${1} == "fail2ban" ]]; then
    SUBJECT="${BODY}"
    BODY="Please see the netfilter log (journalctl -u crassostrea-netfilter) for details and triggered rules."
  else
    SUBJECT="${WATCHDOG_SUBJECT}: ${1}"
  fi

  # Send mail notification if enabled
  if [[ ! -z ${WATCHDOG_NOTIFY_EMAIL} ]]; then
    IFS=',' read -r -a MAIL_RCPTS <<< "${WATCHDOG_NOTIFY_EMAIL}"
    for rcpt in "${MAIL_RCPTS[@]}"; do
      RCPT_DOMAIN=
      RCPT_MX=
      RCPT_DOMAIN=$(echo ${rcpt} | awk -F @ {'print $NF'})
      CHECK_FOR_VALID_MX=$(dig +short ${RCPT_DOMAIN} mx)
      if [[ -z ${CHECK_FOR_VALID_MX} ]]; then
        log_msg "Cannot determine MX for ${rcpt}, skipping email notification..."
        return 1
      fi
      [ -f "/tmp/${1}" ] && BODY="/tmp/${1}"
      timeout 10s ${SMTP_CLI} --missing-modules-ok \
        "${SMTP_VERBOSE}" \
        --charset=UTF-8 \
        --subject="${SUBJECT}" \
        --body-plain="${BODY}" \
        --add-header="X-Priority: 1" \
        --to=${rcpt} \
        --from="watchdog@${CRASSOSTREA_HOSTNAME}" \
        --hello-host=${CRASSOSTREA_HOSTNAME} \
        --ipv4
      if [[ $? -eq 1 ]]; then # exit code 1 is fine
        log_msg "Sent notification email to ${rcpt}"
      else
        if [[ "${SMTP_VERBOSE}" == "" ]]; then
          log_msg "Error while sending notification email to ${rcpt}. You can enable verbose logging by setting 'WATCHDOG_VERBOSE=y' in /etc/crassostrea/crassostrea.conf."
        else
          log_msg "Error while sending notification email to ${rcpt}."
        fi
      fi
    done
  fi

  # Send webhook notification if enabled
  if [[ ! -z ${WATCHDOG_NOTIFY_WEBHOOK} ]]; then
    if [[ -z ${WATCHDOG_NOTIFY_WEBHOOK_BODY} ]]; then
      log_msg "No webhook body set, skipping webhook notification..."
      return 1
    fi

    # Escape subject and body (https://stackoverflow.com/a/2705678)
    ESCAPED_SUBJECT=$(printf '%s' "${SUBJECT}" | tr '\n"\\' '  ' | sed -e 's/[\/&]/\\&/g')
    ESCAPED_BODY=$(printf '%s' "${BODY}" | tr '\n"\\' '  ' | sed -e 's/[\/&]/\\&/g')

    # Replace subject and body placeholders
    WEBHOOK_BODY=$(printf '%s' "${WATCHDOG_NOTIFY_WEBHOOK_BODY}" | sed -e "s/\${SUBJECT}\|\$SUBJECT/${ESCAPED_SUBJECT}/g" -e "s/\${BODY}\|\$BODY/${ESCAPED_BODY}/g")

    # POST to webhook (the web UI accepts only http(s) URLs without spaces)
    curl -X POST -H "Content-Type: application/json" ${CURL_VERBOSE} --max-time 15 -d "${WEBHOOK_BODY}" -- "${WATCHDOG_NOTIFY_WEBHOOK}"

    log_msg "Sent notification using webhook"
  fi
}

service_ip() {
  # All services run on this host and listen on loopback
  echo 127.0.0.1
}

# systemd units restarted when a check hits its threshold (empty: notify only)
units_for() {
  case "${1}" in
    nginx-crassostrea) echo nginx.service ;;
    unbound-crassostrea) echo unbound.service ;;
    redis-crassostrea) [[ ${CLUSTER} -eq 1 ]] && echo haproxy.service || echo valkey.service ;;
    mysql-crassostrea) [[ ${CLUSTER} -eq 1 ]] || echo mariadb.service ;;
    web-crassostrea) echo crassostrea-web.service crassostrea-web-internal.service ;;
    postfix-crassostrea) echo postfix.service ;;
    postfix-tlspol-crassostrea) echo crassostrea-postfix-tlspol.service ;;
    clamd-crassostrea) echo clamd@crassostrea.service ;;
    rspamd-crassostrea) echo rspamd.service ;;
    olefy-crassostrea) echo crassostrea-olefy.service ;;
  esac
}

unit_started() {
  local since
  since=$(systemctl show --property=ActiveEnterTimestamp --value "${1}" 2> /dev/null)
  [[ -n ${since} ]] && date +%s -d "${since}" 2> /dev/null || echo 0
}

nginx_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${NGINX_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/nginx-crassostrea; echo "$(tail -50 /tmp/nginx-crassostrea)" > /tmp/nginx-crassostrea
    host_ip=$(service_ip nginx-crassostrea)
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_http -4 -H ${host_ip} -u / -p 8008 2>> /tmp/nginx-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Nginx" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

unbound_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${UNBOUND_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/unbound-crassostrea; echo "$(tail -50 /tmp/unbound-crassostrea)" > /tmp/unbound-crassostrea
    host_ip=$(service_ip unbound-crassostrea)
    err_c_cur=${err_count}
    ${WATCHDOG_LIBEXEC}/check_dns.sh -s ${host_ip} -H stackoverflow.com 2>> /tmp/unbound-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    DNSSEC=$(dig com +dnssec | egrep 'flags:.+ad')
    if [[ -z ${DNSSEC} ]]; then
      echo "DNSSEC failure" 2>> /tmp/unbound-crassostrea 1>&2
      err_count=$(( ${err_count} + 1))
    else
      echo "DNSSEC check succeeded" 2>> /tmp/unbound-crassostrea 1>&2
    fi
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Unbound" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

redis_checks() {
  # A check for the local valkey (redis) server
  err_count=0
  diff_c=0
  THRESHOLD=${REDIS_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/redis-crassostrea; echo "$(tail -50 /tmp/redis-crassostrea)" > /tmp/redis-crassostrea
    host_ip=$(service_ip redis-crassostrea)
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_tcp -4 -H 127.0.0.1 -p 6379 -E -s "AUTH ${REDISPASS}\nPING\n" -q "QUIT" -e "PONG" 2>> /tmp/redis-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Redis" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

mysql_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${MYSQL_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/mysql-crassostrea; echo "$(tail -50 /tmp/mysql-crassostrea)" > /tmp/mysql-crassostrea
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_mysql -f ${WATCHDOG_LIBEXEC}/client.cnf -s ${MYSQL_SOCKET} -u ${DBUSER} -p ${DBPASS} -d ${DBNAME} 2>> /tmp/mysql-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    ${NAGIOS_PLUGINS}/check_mysql_query -f ${WATCHDOG_LIBEXEC}/client.cnf -s ${MYSQL_SOCKET} -u ${DBUSER} -p ${DBPASS} -d ${DBNAME} -q "SELECT COUNT(*) FROM information_schema.tables" 2>> /tmp/mysql-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "MySQL/MariaDB" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

# Cluster: this node is part of the primary component, in sync, and all
# members are connected (notifications only)
galera_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${GALERA_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/galera-crassostrea; echo "$(tail -50 /tmp/galera-crassostrea)" > /tmp/galera-crassostrea
    err_c_cur=${err_count}
    declare -A wsrep=()
    while read -r name value; do
      wsrep[${name}]=${value}
    done < <(mariadb --skip-ssl --socket=${MYSQL_SOCKET} -u${DBUSER} -p${DBPASS} -N -B -e "SHOW GLOBAL STATUS WHERE Variable_name IN ('wsrep_cluster_status', 'wsrep_local_state_comment', 'wsrep_cluster_size')" 2>> /tmp/galera-crassostrea)
    if [[ ${wsrep[wsrep_cluster_status]} != Primary || ${wsrep[wsrep_local_state_comment]} != Synced ]]; then
      echo "Galera: cluster ${wsrep[wsrep_cluster_status]:-unknown}, this node ${wsrep[wsrep_local_state_comment]:-unknown}" >> /tmp/galera-crassostrea
      err_count=$(( ${err_count} + 1 ))
    elif [[ ${wsrep[wsrep_cluster_size]:-0} -lt ${GALERA_MEMBERS} ]]; then
      echo "Galera: only ${wsrep[wsrep_cluster_size]} of ${GALERA_MEMBERS} cluster members are connected" >> /tmp/galera-crassostrea
      err_count=$(( ${err_count} + 1 ))
    fi
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Galera cluster" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

postfix_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${POSTFIX_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/postfix-crassostrea; echo "$(tail -50 /tmp/postfix-crassostrea)" > /tmp/postfix-crassostrea
    host_ip=$(service_ip postfix-crassostrea)
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_smtp -4 -H ${host_ip} -p 589 -f "watchdog@invalid" -C "RCPT TO:watchdog@localhost" -C DATA -C . -R 250 2>> /tmp/postfix-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    ${NAGIOS_PLUGINS}/check_smtp -4 -H ${host_ip} -p 589 -S 2>> /tmp/postfix-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Postfix" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

postfix-tlspol_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${POSTFIX_TLSPOL_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/postfix-tlspol-crassostrea; echo "$(tail -50 /tmp/postfix-tlspol-crassostrea)" > /tmp/postfix-tlspol-crassostrea
    host_ip=$(service_ip postfix-tlspol-crassostrea)
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_tcp -4 -H ${host_ip} -p 8642 2>> /tmp/postfix-tlspol-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Postfix TLS Policy companion" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

clamd_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${CLAMD_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/clamd-crassostrea; echo "$(tail -50 /tmp/clamd-crassostrea)" > /tmp/clamd-crassostrea
    host_ip=$(service_ip clamd-crassostrea)
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_clamd -4 -H ${host_ip} 2>> /tmp/clamd-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Clamd" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 120 ) + 20 ))
    fi
  done
  return 1
}

cert_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=7
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/certcheck; echo "$(tail -50 /tmp/certcheck)" > /tmp/certcheck
    host_ip_postfix=$(service_ip postfix)
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_smtp -H ${host_ip_postfix} -p 589 -4 -S -D 7 2>> /tmp/certcheck 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Primary certificate expiry check" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    # Always sleep 5 minutes, mail notifications are limited
    sleep 300
  done
  return 1
}

web_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${WEB_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/web-crassostrea; echo "$(tail -50 /tmp/web-crassostrea)" > /tmp/web-crassostrea
    host_ip=$(service_ip web-crassostrea)
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_http -4 -H ${host_ip} -u /healthz -p 8000 -s ok 2>> /tmp/web-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    ${NAGIOS_PLUGINS}/check_http -4 -H ${host_ip} -u /healthz -p 8001 -s ok 2>> /tmp/web-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Web UI" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

mailq_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${MAILQ_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/mail_queue_status; echo "$(tail -50 /tmp/mail_queue_status)" > /tmp/mail_queue_status
    MAILQ_LOG_STATUS=$(find /var/spool/postfix/deferred -type f | wc -l)
    echo "Mail queue contains ${MAILQ_LOG_STATUS} items (critical limit is ${MAILQ_CRIT}) at $(date)" >> /tmp/mail_queue_status
    err_c_cur=${err_count}
    if [ ${MAILQ_LOG_STATUS} -ge ${MAILQ_CRIT} ]; then
      err_count=$(( ${err_count} + 1 ))
      echo "Mail queue contains ${MAILQ_LOG_STATUS} items (critical limit is ${MAILQ_CRIT}) at $(date)" >> /tmp/mail_queue_status
    fi
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Mail queue" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 60
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

fail2ban_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${FAIL2BAN_THRESHOLD}
  F2B_LOG_STATUS=($(${REDIS_CMDLINE} --raw HKEYS F2B_ACTIVE_BANS))
  F2B_RES=
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    err_c_cur=${err_count}
    F2B_LOG_STATUS_PREV=(${F2B_LOG_STATUS[@]})
    F2B_LOG_STATUS=($(${REDIS_CMDLINE} --raw HKEYS F2B_ACTIVE_BANS))
    array_diff F2B_RES F2B_LOG_STATUS F2B_LOG_STATUS_PREV
    if [[ ! -z "${F2B_RES}" ]]; then
      err_count=$(( ${err_count} + 1 ))
      echo -n "${F2B_RES[@]}" | tr -cd "[a-fA-F0-9.:/] " | timeout 3s ${REDIS_CMDLINE} -x SET F2B_RES > /dev/null
      if [ $? -ne 0 ]; then
         ${REDIS_CMDLINE} -x DEL F2B_RES
      fi
    fi
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Fail2ban" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

acme_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${ACME_THRESHOLD}
  ACME_LOG_STATUS=$(${REDIS_CMDLINE} GET ACME_FAIL_TIME)
  if [[ -z "${ACME_LOG_STATUS}" ]]; then
    ${REDIS_CMDLINE} SET ACME_FAIL_TIME 0
    ACME_LOG_STATUS=0
  fi
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    err_c_cur=${err_count}
    ACME_LOG_STATUS_PREV=${ACME_LOG_STATUS}
    ACME_LC=0
    until [[ ! -z ${ACME_LOG_STATUS} ]] || [ ${ACME_LC} -ge 3 ]; do
      ACME_LOG_STATUS=$(${REDIS_CMDLINE} GET ACME_FAIL_TIME 2> /dev/null)
      sleep 3
      ACME_LC=$((ACME_LC+1))
    done
    if [[ ${ACME_LOG_STATUS_PREV} != ${ACME_LOG_STATUS} ]]; then
      err_count=$(( ${err_count} + 1 ))
    fi
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "ACME" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

rspamd_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${RSPAMD_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/rspamd-crassostrea; echo "$(tail -50 /tmp/rspamd-crassostrea)" > /tmp/rspamd-crassostrea
    host_ip=$(service_ip rspamd-crassostrea)
    err_c_cur=${err_count}
    SCORE=$(echo 'To: null@localhost
From: watchdog@localhost

Empty
' | curl --max-time 10 -s --data-binary @- --unix-socket ${RSPAMD_SOCKET} http://localhost/scan | jq -rc .default.required_score | sed 's/\..*//' )
    if [[ ${SCORE} -ne 9999 ]]; then
      echo "Rspamd settings check failed, score returned: ${SCORE}" 2>> /tmp/rspamd-crassostrea 1>&2
      err_count=$(( ${err_count} + 1))
    else
      echo "Rspamd settings check succeeded, score returned: ${SCORE}" 2>> /tmp/rspamd-crassostrea 1>&2
    fi
    # A dirty hack until a PING PONG event is implemented to worker proxy
    # We expect an empty response, not a timeout
    if [ "$(curl -s --max-time 10 ${host_ip}:9900 2> /dev/null ; echo $?)" == "28" ]; then
      echo "Milter check failed" 2>> /tmp/rspamd-crassostrea 1>&2; err_count=$(( ${err_count} + 1 ));
    else
      echo "Milter check succeeded" 2>> /tmp/rspamd-crassostrea 1>&2
    fi
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Rspamd" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

olefy_checks() {
  err_count=0
  diff_c=0
  THRESHOLD=${OLEFY_THRESHOLD}
  # Reduce error count by 2 after restarting an unhealthy service
  trap "[ ${err_count} -gt 1 ] && err_count=$(( ${err_count} - 2 ))" USR1
  while [ ${err_count} -lt ${THRESHOLD} ]; do
    touch /tmp/olefy-crassostrea; echo "$(tail -50 /tmp/olefy-crassostrea)" > /tmp/olefy-crassostrea
    host_ip=$(service_ip olefy-crassostrea)
    err_c_cur=${err_count}
    ${NAGIOS_PLUGINS}/check_tcp -4 -H ${host_ip} -p 10055 -s "PING\n" 2>> /tmp/olefy-crassostrea 1>&2; err_count=$(( ${err_count} + $? ))
    [ ${err_c_cur} -eq ${err_count} ] && [ ! $((${err_count} - 1)) -lt 0 ] && err_count=$((${err_count} - 1)) diff_c=1
    [ ${err_c_cur} -ne ${err_count} ] && diff_c=$(( ${err_c_cur} - ${err_count} ))
    progress "Olefy" ${THRESHOLD} $(( ${THRESHOLD} - ${err_count} )) ${diff_c}
    if [[ $? == 10 ]]; then
      diff_c=0
      sleep 1
    else
      diff_c=0
      sleep $(( ( RANDOM % 60 ) + 20 ))
    fi
  done
  return 1
}

# Notify about start
load_notify_settings
if [[ ${WATCHDOG_NOTIFY_START} =~ ^([yY][eE][sS]|[yY])+$ ]]; then
  notify_error "watchdog-crassostrea" "Watchdog started monitoring Crassostrea on ${CRASSOSTREA_HOSTNAME}."
fi

# Create watchdog agents

(
while true; do
  if ! nginx_checks; then
    log_msg "Nginx hit error limit"
    echo nginx-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned nginx_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

(
while true; do
  if ! mysql_checks; then
    log_msg "MySQL hit error limit"
    echo mysql-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned mysql_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

if [ ${CLUSTER} -eq 1 ]; then
(
while true; do
  if ! galera_checks; then
    log_msg "Galera cluster hit error limit"
    echo galera-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned galera_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})
fi

(
while true; do
  if ! redis_checks; then
    log_msg "Local Redis hit error limit"
    echo redis-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned redis_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

(
while true; do
  if ! web_checks; then
    log_msg "Web UI hit error limit"
    echo web-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned web_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

if [ ${CHECK_UNBOUND} -eq 1 ]; then
(
while true; do
  if ! unbound_checks; then
    log_msg "Unbound hit error limit"
    echo unbound-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned unbound_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})
fi

if [[ "${SKIP_CLAMD}" =~ ^([nN][oO]|[nN])+$ ]]; then
(
while true; do
  if ! clamd_checks; then
    log_msg "Clamd hit error limit"
    echo clamd-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned clamd_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})
fi

(
while true; do
  if ! postfix_checks; then
    log_msg "Postfix hit error limit"
    echo postfix-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned postfix_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

(
while true; do
  if ! mailq_checks; then
    log_msg "Mail queue hit error limit"
    echo mail_queue_status > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned mailq_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

(
while true; do
  if ! postfix-tlspol_checks; then
    log_msg "Postfix TLS Policy hit error limit"
    echo postfix-tlspol-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned postfix-tlspol_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

(
while true; do
  if ! rspamd_checks; then
    log_msg "Rspamd hit error limit"
    echo rspamd-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned rspamd_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

(
while true; do
  if ! fail2ban_checks; then
    log_msg "Fail2ban hit error limit"
    echo fail2ban > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned fail2ban_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

(
while true; do
  if ! cert_checks; then
    log_msg "Cert check hit error limit"
    echo certcheck > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned cert_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

if [[ "${SKIP_OLEFY}" =~ ^([nN][oO]|[nN])+$ ]]; then
(
while true; do
  if ! olefy_checks; then
    log_msg "Olefy hit error limit"
    echo olefy-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned olefy_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})
fi

(
while true; do
  if ! acme_checks; then
    log_msg "ACME client hit error limit"
    echo acme-crassostrea > /tmp/com_pipe
  fi
done
) &
PID=$!
echo "Spawned acme_checks with PID ${PID}"
BACKGROUND_TASKS+=(${PID})

# Monitor watchdog agents, stop the watchdog when one fails; systemd restarts it
WATCHDOG_PID=$$
(
while true; do
  for bg_task in ${BACKGROUND_TASKS[*]}; do
    if ! kill -0 ${bg_task} 1>&2; then
      log_msg "Worker ${bg_task} died, stopping watchdog and waiting for respawn..."
      kill -TERM ${WATCHDOG_PID}
    fi
    sleep 10
  done
done
) &

# Actions when threshold limit is reached
while true; do
  read com_pipe_answer </tmp/com_pipe
  if [ -s "/tmp/${com_pipe_answer}" ]; then
    cat "/tmp/${com_pipe_answer}"
  fi
  if [[ ${com_pipe_answer} == "mail_queue_status" ]]; then
    log_msg "Mail queue status is critical"
    notify_error "${com_pipe_answer}"
  elif [[ ${com_pipe_answer} == "certcheck" ]]; then
    log_msg "Certificates are about to expire"
    # Define $2 to override message text, else print service was restarted at ...
    # Only mail once a day
    notify_error "${com_pipe_answer}" "Please renew your certificate" 86400
  elif [[ ${com_pipe_answer} == "acme-crassostrea" ]]; then
    log_msg "Certificate renewal did not complete successfully"
    # Define $2 to override message text, else print service was restarted at ...
    notify_error "${com_pipe_answer}" "Please check the certificate renewal log (journalctl -u crassostrea-acme)."
  elif [[ ${com_pipe_answer} == "fail2ban" ]]; then
    F2B_RES=($(timeout 4s ${REDIS_CMDLINE} --raw GET F2B_RES 2> /dev/null))
    if [[ ! -z "${F2B_RES}" ]]; then
      ${REDIS_CMDLINE} DEL F2B_RES > /dev/null
      host=
      for host in "${F2B_RES[@]}"; do
        log_msg "Banned ${host}"
        rm /tmp/fail2ban 2> /dev/null
        timeout 2s whois "${host}" > /tmp/fail2ban
        load_notify_settings
        [[ ${WATCHDOG_NOTIFY_BAN} =~ ^([yY][eE][sS]|[yY])+$ ]] && notify_error "${com_pipe_answer}" "IP ban: ${host}"
      done
    fi
  elif [[ ${com_pipe_answer} =~ .+-crassostrea ]]; then
    kill -STOP ${BACKGROUND_TASKS[*]}
    sleep 10
    UNITS=$(units_for "${com_pipe_answer}")
    if [[ -z ${UNITS} ]]; then
      notify_error "${com_pipe_answer}" "Check ${com_pipe_answer} hit its error limit."
    else
      S_RUNNING=$(( $(date +%s) - $(unit_started "${UNITS%% *}") ))
      if [ ${S_RUNNING} -lt 360 ]; then
        log_msg "${UNITS} running for less than 360 seconds, skipping action..."
      else
        log_msg "Restarting ${UNITS}..."
        systemctl restart ${UNITS}
        notify_error "${com_pipe_answer}" "" "" "${UNITS%% *}"
        log_msg "Wait for restarted services to settle and continue watching..."
        sleep 35
      fi
    fi
    kill -CONT ${BACKGROUND_TASKS[*]}
    sleep 1
    kill -USR1 ${BACKGROUND_TASKS[*]}
  fi
done

