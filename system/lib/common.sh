#!/usr/bin/env bash
# Shared helpers for setup.sh, update.sh, system/install.sh and
# system/configure.sh. Not meant to be run standalone.
#
# SF_ROOT   prefix for every file written (tests render into a scratch tree)
# SF_DRYRUN y: do not run commands that change the system (systemctl, mysql,
#           semanage, chown, ...), only write files below SF_ROOT

# The last command of a pipeline runs in this shell, so die() in
# "... | write_file" stops the script
shopt -s lastpipe

SF_SRC=${SF_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
SF_ROOT=${SF_ROOT:-}
SF_DRYRUN=${SF_DRYRUN:-n}
SF_CONF=${SF_CONF:-/etc/crassostrea/crassostrea.conf}

# Installed locations (root-owned copies of the repository, never run from it)
SF_ETC=/etc/crassostrea
SF_LIB=/usr/local/lib/crassostrea
SF_LIBEXEC=/usr/local/libexec/crassostrea
SF_STATE=/var/lib/crassostrea
SF_VENV=${SF_LIB}/venv
SF_USER=crassostrea

RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
NC='\e[0m'

log() { echo -e "${GREEN}==>${NC} $*" >&2; }
warn() { echo -e "${YELLOW}WARNING:${NC} $*" >&2; }
die() { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

is_yes() {
  [[ "${1,,}" =~ ^(y|yes|true|1)$ ]]
}

dry() {
  [[ "${SF_DRYRUN}" == "y" ]]
}

# Run a command that changes the system (skipped in dry runs)
run() {
  if dry; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

# Path below SF_ROOT
p() {
  echo "${SF_ROOT}${1}"
}

# write_file PATH MODE [OWNER[:GROUP]] < content
write_file() {
  local path mode owner tmp
  path=$(p "$1")
  mode=$2
  owner=${3:-root:root}
  mkdir -p "$(dirname "${path}")" || die "Cannot create $(dirname "${path}")"
  tmp=$(mktemp "$(dirname "${path}")/.sf-tmp.XXXXXX") || die "Cannot write ${path}"
  cat > "${tmp}" || die "Cannot write ${path}"
  chmod "${mode}" "${tmp}"
  dry || chown "${owner}" "${tmp}" || die "Cannot chown ${path} to ${owner}"
  mv -f "${tmp}" "${path}" || die "Cannot write ${path}"
  # the temporary file got the SELinux type of the directory, not of the path
  dry || ! command -v restorecon > /dev/null || restorecon -F "${path}" 2> /dev/null
}

# install_file SRC DEST MODE [OWNER[:GROUP]]
install_file() {
  write_file "$2" "$3" "${4:-root:root}" < "$1"
}

# Write PATH only if it does not exist yet (files the administrator may edit)
create_file() {
  if [[ -e $(p "$1") ]]; then
    cat > /dev/null
  else
    write_file "$@"
  fi
}

# Copy a directory tree (files 0644, scripts keep their x bit), removing files
# that are no longer in the source
sync_tree() {
  local src=$1 dest
  dest=$(p "$2")
  mkdir -p "${dest}"
  if command -v rsync > /dev/null; then
    rsync -a --delete --chmod=Du=rwx,Dgo=rx,Fu=rwX,Fgo=rX --exclude '__pycache__' --exclude '*.pyc' \
      "${src}/" "${dest}/"
  else
    rm -rf "${dest:?}"/*
    cp -a "${src}/." "${dest}/"
    find "${dest}" -name __pycache__ -prune -exec rm -rf {} +
  fi
  dry || chown -R root:root "${dest}"
}

# load_env_file FILE: export the KEY=VALUE lines of FILE like systemd's
# EnvironmentFile= (one pair of surrounding quotes removed, nothing expanded
# or executed), so scripts and units see the same values
load_env_file() {
  local line key value
  while IFS= read -r line || [[ -n ${line} ]]; do
    line=${line%$'\r'}
    [[ ${line} =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ ${line} =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key=${BASH_REMATCH[1]}
      value=${BASH_REMATCH[2]}
      if [[ ${value} =~ ^\"(.*)\"[[:space:]]*$ || ${value} =~ ^\'(.*)\'[[:space:]]*$ ]]; then
        value=${BASH_REMATCH[1]}
      fi
      export "${key}=${value}"
    else
      echo "Ignoring invalid line in $1: ${line%%=*}" >&2
    fi
  done < "$1"
}

# require_el10: stop unless running as root on EL10; sets the os-release
# variables (ID, VERSION_ID, ...)
require_el10() {
  [[ ${EUID} -eq 0 ]] || die "Please run as root, e.g. sudo $0"
  [[ -r /etc/os-release ]] || die "Cannot identify the operating system (/etc/os-release missing)"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ ${VERSION_ID%%.*} == 10 && " ${ID} ${ID_LIKE} " =~ " rhel " ]] \
    || die "Only EL10 (AlmaLinux, Rocky Linux, RHEL 10) is supported, found ${PRETTY_NAME:-unknown}"
}

load_config() {
  [[ -r ${SF_CONF} ]] || die "${SF_CONF} not found, run setup.sh first"
  load_env_file "${SF_CONF}"
  local var
  for var in CRASSOSTREA_HOSTNAME DBNAME DBUSER DBPASS REDISPASS RSPAMD_PASSWORD WEB_SECRET_KEY; do
    [[ -n ${!var} ]] || die "${var} is not set in ${SF_CONF}"
  done
  [[ ${DBNAME} =~ ^[A-Za-z0-9_]+$ && ${DBUSER} =~ ^[A-Za-z0-9_]+$ ]] \
    || die "DBNAME and DBUSER may only contain letters, digits and _"
  local secret
  for secret in DBPASS REDISPASS RSPAMD_PASSWORD; do
    [[ ${!secret} =~ ^[A-Za-z0-9]+$ ]] || die "${secret} may only contain letters and digits"
  done
  for var in HTTPS_TLS_MIN SMTP_TLS_MIN; do
    tls_valid_min "${!var:-1.2}" || die "${var} must be 1.0, 1.1 or 1.2"
  done
  ip_enabled "${IPV4_ENABLED:-y}" || ip_enabled "${IPV6_ENABLED:-true}" \
    || die "IPV4_ENABLED and IPV6_ENABLED cannot both be off"
  # system/lib/docs.sh passes them to git and into the MkDocs configuration
  [[ -z ${DOCS_REF:-} || ${DOCS_REF} =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] \
    || die "DOCS_REF must be a branch or tag name"
  [[ ${DOCS_SOURCE:-} != *[\'\"[:space:]]* && ${DOCS_SOURCE:-} != -* ]] \
    || die "DOCS_SOURCE must be a git URL or a directory without spaces or quotes"
  ha_parse
}

# selinux_port TYPE PORT: label a TCP port (skipped in dry runs, without
# SELinux, or when the port already has that type)
selinux_port() {
  dry && return 0
  selinuxenabled 2> /dev/null || return 0
  semanage port -l | grep -qE "^$1 +tcp +.*\b$2\b" && return 0
  semanage port -a -t "$1" -p tcp "$2" 2> /dev/null || semanage port -m -t "$1" -p tcp "$2"
}

# Run the executable hooks of data/hooks/<component>
run_hooks() {
  local file
  for file in "${SF_SRC}/data/hooks/$1"/*; do
    if [[ -f ${file} && -x ${file} ]]; then
      log "Running hook ${file}"
      run "${file}"
    fi
  done
}

# shellcheck source=conf.sh
source "$(dirname "${BASH_SOURCE[0]}")/conf.sh"
# shellcheck source=tls.sh
source "$(dirname "${BASH_SOURCE[0]}")/tls.sh"
# shellcheck source=ipfamily.sh
source "$(dirname "${BASH_SOURCE[0]}")/ipfamily.sh"
# shellcheck source=nginx.sh
source "$(dirname "${BASH_SOURCE[0]}")/nginx.sh"
# shellcheck source=docs.sh
source "$(dirname "${BASH_SOURCE[0]}")/docs.sh"
# shellcheck source=cluster.sh
source "$(dirname "${BASH_SOURCE[0]}")/cluster.sh"
