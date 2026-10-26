#!/usr/bin/env bash
# Updates the Crassostrea gateway:
#   1. fast-forwards the current git branch (optional, --skip-git to disable),
#      and the documentation's repository if it is deployed (DOCS_ENABLED)
#   2. runs system/install.sh: packages, Python packages, pinned tools,
#      deployment and configuration, restart of the services
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
cd "${SCRIPT_DIR}" || exit 1
# shellcheck source=system/lib/common.sh
source system/lib/common.sh

SKIP_GIT=n
FORCE=n
for arg in "$@"; do
  case "${arg}" in
    --skip-git) SKIP_GIT=y ;;
    -f|--force) FORCE=y ;;
    -h|--help)
      echo "Usage: $0 [--skip-git] [--force]"
      echo "  --skip-git  do not pull changes from the git remote"
      echo "  --force     do not ask for confirmation"
      exit 0
      ;;
    *) echo "Unknown option ${arg}"; exit 1 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || die "Please run as root"
[[ -f ${SF_CONF} ]] || die "${SF_CONF} is missing, run ./setup.sh first."

if [[ ${FORCE} != y ]]; then
  read -r -p "Update and restart the Crassostrea gateway now? [y/N] " response
  [[ "${response}" =~ ^([yY][eE][sS]|[yY])$ ]] || exit 0
fi

# git refuses repositories owned by someone else (safe.directory): run it
# as the owner of the checkout
OWNER=$(stat -c %U "${SCRIPT_DIR}")
git_as_owner() {
  if [[ ${OWNER} == root ]]; then
    git "$@"
  else
    runuser -u "${OWNER}" -- git "$@"
  fi
}

if [[ ${SKIP_GIT} != y ]]; then
  if [[ -n "$(git_as_owner status --porcelain --untracked-files=no)" ]]; then
    warn "You have local changes to tracked files:"
    git_as_owner status --short --untracked-files=no
    die "Commit or stash them, or run with --skip-git."
  fi
  log "Updating the repository (fast-forward only)..."
  git_as_owner pull --ff-only || die "git pull failed, the branch cannot be fast-forwarded. Resolve this manually."
fi

# The documentation (DOCS_ENABLED): new commits of its repository; install.sh
# (configure.sh) rebuilds it if they changed it
if [[ ${SKIP_GIT} != y ]]; then
  load_env_file "${SF_CONF}"
  is_yes "${DOCS_ENABLED:-n}" && docs_fetch --update
fi

system/install.sh || die "Update failed"
log "Update complete."
