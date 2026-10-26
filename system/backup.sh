#!/usr/bin/env bash
# Backups (the Backups page of the web UI makes, lists and downloads them too).
#
#   system/backup.sh create
#       a backup now, in /var/lib/crassostrea/backups
#   system/backup.sh list
#       the backups there
#   system/backup.sh restore FILE [--yes]
#       restore a backup (a path, or the name of one in the backup directory):
#       crassostrea.conf, the certificates and ACME account, the database and
#       Valkey's data (Bayes, fuzzy hashes, bans); then system/configure.sh
#       renders the configuration and restarts the services. The current
#       files and database are saved to /var/lib/crassostrea/restore-<time>
#       first. Also moves a gateway to another server: install it there
#       (setup.sh), copy the backup over and restore it. Not on a cluster
#       member: restore one node as a single gateway, then rebuild the cluster.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

BACKUP_DIR=${BACKUP_DIR:-${SF_STATE}/backups}

usage() {
  awk 'NR > 1 && /^#/ {sub(/^# ?/, ""); print; next} NR > 1 {exit}' "$0"
  exit "${1:-0}"
}

valkey() {
  # valkey PASSWORD COMMAND...: the local Valkey
  local password=$1
  shift
  valkey-cli -h 127.0.0.1 -p 6379 -a "${password}" --no-auth-warning "$@"
}

restore() {
  local file=$1 yes=$2
  [[ -f ${file} ]] || file=${BACKUP_DIR}/${file}
  [[ -f ${file} ]] || die "There is no backup $1"
  ha_enabled && die "This gateway is a cluster member: restore one node as a single gateway, then rebuild the cluster"

  local work
  work=$(mktemp -d) || die "Cannot create a temporary directory"
  # shellcheck disable=SC2064
  trap "rm -rf '${work}'" EXIT
  tar -xzf "${file}" -C "${work}" || die "${file} is not a readable backup"
  [[ -f ${work}/manifest.json && -f ${work}/database.sql ]] || die "${file} is not a backup of the gateway"

  local -a files
  mapfile -t files < <(python3 -I - "${work}/manifest.json" <<'PY'
import json, sys, time
m = json.load(open(sys.argv[1]))
when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(m.get("created_at", 0)))
print(f"Backup of {m.get('hostname', '?')} ({m.get('label', '?')}, {when})", file=sys.stderr)
print(f"  database {m.get('database')}: mail log {'included' if m.get('mail_log') else 'without rows'}, "
      f"quarantine {'included' if m.get('quarantine') else 'without rows'}; Valkey "
      f"{'included' if m.get('valkey') else 'not included'}", file=sys.stderr)
for path in m.get("files", []):
    if path.startswith("/") and ".." not in path.split("/"):
        print(path)
PY
)
  printf '  files: %s\n' "${files[*]}" >&2
  if [[ ${yes} != y ]]; then
    read -r -p "Replace the configuration, the database and Valkey's data of this gateway with this backup? [y/N] " answer
    [[ ${answer} =~ ^([yY]|[yY][eE][sS])$ ]] || exit 0
  fi

  # The current state, to go back to
  local keep path
  keep=${SF_STATE}/restore-$(date -u +%Y%m%d-%H%M%S)
  mkdir -p "$(p "${keep}")"
  chmod 0700 "$(p "${keep}")"
  for path in "${files[@]}"; do
    if [[ -e $(p "${path}") ]]; then
      mkdir -p "$(p "${keep}/files$(dirname "${path}")")"
      cp -a "$(p "${path}")" "$(p "${keep}/files${path}")"
    fi
  done
  if dry; then
    echo "[dry-run] mariadb-dump ${DBNAME} > ${keep}/database.sql"
  else
    mariadb-dump --single-transaction --routines --events "${DBNAME}" > "${keep}/database.sql" \
      || die "Cannot save the current database; nothing was changed"
  fi
  log "The current state is saved in ${keep}"

  local old_redispass=${REDISPASS}
  run systemctl stop postfix.service rspamd.service crassostrea-web.service crassostrea-web-internal.service \
    crassostrea-logship.service 2> /dev/null

  log "Restoring the files"
  for path in "${files[@]}"; do
    [[ -e ${work}/files${path} ]] || continue
    rm -rf "$(p "${path}")"
    mkdir -p "$(p "$(dirname "${path}")")"
    cp -a "${work}/files${path}" "$(p "${path}")"
  done
  # from here on the restored configuration counts (DBNAME, passwords, hostname)
  load_config

  log "Restoring the database ${DBNAME}"
  run mariadb -e "DROP DATABASE IF EXISTS \`${DBNAME}\`;
    CREATE DATABASE \`${DBNAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;" \
    || die "Cannot recreate the database; the previous state is in ${keep}"
  if dry; then
    echo "[dry-run] mariadb ${DBNAME} < database.sql"
  else
    mariadb --max-allowed-packet=192M "${DBNAME}" < "${work}/database.sql" \
      || die "Cannot load the database; the previous state is in ${keep}"
  fi

  if [[ -f ${work}/valkey.rdb ]]; then
    if dry; then
      echo "[dry-run] valkey: replace its data file with valkey.rdb"
    elif [[ $(valkey "${old_redispass}" CONFIG GET appendonly | tail -1) == yes ]]; then
      warn "Valkey uses append-only files (appendonly yes): its data was not restored"
    else
      local dir dbfile
      dir=$(valkey "${old_redispass}" CONFIG GET dir | tail -1)
      dbfile=$(valkey "${old_redispass}" CONFIG GET dbfilename | tail -1)
      if [[ -d ${dir} && -n ${dbfile} && ${dbfile} != */* ]]; then
        log "Restoring Valkey's data"
        systemctl stop valkey.service
        install -m 0640 -o valkey -g valkey "${work}/valkey.rdb" "${dir}/${dbfile}"
      else
        warn "Valkey's data directory is unknown (is valkey running?): its data was not restored"
      fi
    fi
  fi

  log "Applying the restored configuration"
  "${SCRIPT_DIR}/configure.sh" || die "configure.sh failed; the previous state is in ${keep}"
  log "Restored ${file}. The previous configuration and database are in ${keep}."
}

case ${1:-} in
  create)
    [[ ${EUID} -eq 0 ]] || die "Please run as root"
    "${SCRIPT_DIR}/libexec/backup" create manual
    ;;
  list)
    ls -lh "${BACKUP_DIR}"/backup-*.tar.gz 2> /dev/null || echo "No backups in ${BACKUP_DIR}"
    ;;
  restore)
    dry || [[ ${EUID} -eq 0 ]] || die "Please run as root"
    [[ -n ${2:-} ]] || usage 1
    load_config
    restore "$2" "$([[ ${3:-} == --yes ]] && echo y || echo n)"
    ;;
  -h|--help) usage ;;
  *) usage 1 ;;
esac
