#!/usr/bin/env bash
# The documentation on the gateway: https://<hostname>/docs/, for logged-in
# administrators (see system/lib/docs.sh).
#
#   system/docs.sh install [SOURCE] [--ref REF]
#       deploy it: SOURCE is the crassostrea-docs repository, a git URL or a
#       directory (default: DOCS_SOURCE, else the checkout next to this
#       repository, else github.com/SnailShea/crassostrea-docs); REF a branch
#       or tag of a git URL
#   system/docs.sh update
#       fetch new commits of the source and rebuild if it changed (update.sh
#       does this too)
#   system/docs.sh rebuild
#       build the site again from the source as it is
#   system/docs.sh remove
#       stop serving it and remove the site
#   system/docs.sh status
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
  awk 'NR > 1 && /^#/ {sub(/^# ?/, ""); print; next} NR > 1 {exit}' "$0"
  exit "${1:-0}"
}

[[ $1 == -h || $1 == --help || -z $1 ]] && usage 0
[[ ${EUID} -eq 0 ]] || die "Please run as root"
load_config

# nginx and the web UI's menu follow DOCS_ENABLED
apply() {
  "${SCRIPT_DIR}/configure.sh" --no-restart || die "system/configure.sh failed"
  dry && return 0
  if systemctl is-active --quiet nginx.service; then
    nginx -t 2> /dev/null || die "nginx refuses the configuration, see: nginx -t"
    systemctl reload nginx.service
  fi
  systemctl try-restart crassostrea-web.service
}

install_docs() {
  local source="" ref=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ref) [[ -n $2 ]] || usage 1; ref=$2; shift 2 ;;
      -*) usage 1 ;;
      *) source=$1; shift ;;
    esac
  done
  if [[ -n ${source} ]] && ! docs_is_url "${source}"; then
    source=$(realpath -e "${source}") || die "${source} does not exist"
    [[ -f ${source}/mkdocs.yml ]] || die "${source} is not the documentation repository (no mkdocs.yml)"
  fi
  if [[ -n ${source} && ${source} != "$(docs_source)" ]]; then
    # a different repository: do not build from the old clone
    docs_is_url "$(docs_source)" && rm -rf "$(p "${DOCS_CHECKOUT}")"
    conf_set DOCS_SOURCE "${source}"
  fi
  [[ -n ${ref} ]] && conf_set DOCS_REF "${ref}"
  docs_fetch --update || die "Cannot get the documentation"
  docs_build --force || die "The documentation could not be built"
  conf_set DOCS_ENABLED y
  apply
  log "The documentation is at ${WEB_PUBLIC_URL:-https://${CRASSOSTREA_HOSTNAME}}/docs/ (administrators only)"
}

status() {
  local site src
  site=$(p "${DOCS_ROOT}")
  src=$(docs_source_dir)
  echo "Enabled:  ${DOCS_ENABLED:-n}"
  echo "Source:   $(docs_source)${DOCS_REF:+ (${DOCS_REF})}"
  if [[ -f ${site}/${DOCS_STAMP} ]]; then
    echo "Built:    $(date -r "${site}/${DOCS_STAMP}" '+%F %T'), $(
      [[ -n ${src} && $(docs_fingerprint "${src}") == "$(cat "${site}/${DOCS_STAMP}")" ]] \
        && echo "up to date" || echo "the source has changed (system/docs.sh rebuild)")"
    echo "URL:      ${WEB_PUBLIC_URL:-https://${CRASSOSTREA_HOSTNAME}}/docs/"
  else
    echo "Built:    no"
  fi
}

case "$1" in
  install) shift; install_docs "$@" ;;
  update)
    is_yes "${DOCS_ENABLED:-n}" || die "The documentation is not deployed: system/docs.sh install"
    docs_fetch --update
    docs_build || exit 1
    ;;
  rebuild)
    is_yes "${DOCS_ENABLED:-n}" || die "The documentation is not deployed: system/docs.sh install"
    docs_build --force || exit 1
    ;;
  remove)
    conf_set DOCS_ENABLED n
    apply
    log "The documentation is no longer served"
    ;;
  status) status ;;
  *) usage 1 ;;
esac
