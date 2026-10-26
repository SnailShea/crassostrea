#!/usr/bin/env bash
# Updates the Crassostrea gateway:
#   1. moves the git checkout to the newest release (UPDATE_CHANNEL=release,
#      the default: the newest vX.Y.Z tag, never back to an older one) or
#      fast-forwards it on its branch (UPDATE_CHANNEL=main); --skip-git skips
#      this. Also fetches the documentation's repository if it is deployed.
#   2. runs system/install.sh: packages, Python packages, pinned tools,
#      deployment and configuration, restart of the services
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
cd "${SCRIPT_DIR}" || exit 1
# shellcheck source=system/lib/common.sh
source system/lib/common.sh

SKIP_GIT=n
FORCE=n
CHANNEL=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-git) SKIP_GIT=y ;;
    -f|--force) FORCE=y ;;
    --channel)
      [[ $2 == release || $2 == main ]] || die "--channel must be release or main"
      CHANNEL=$2
      shift ;;
    -h|--help)
      echo "Usage: $0 [--channel release|main] [--skip-git] [--force]"
      echo "  --channel   this time: the newest release (release) or the newest commit of the"
      echo "              branch (main) instead of UPDATE_CHANNEL of crassostrea.conf"
      echo "  --skip-git  do not take anything from the git remote"
      echo "  --force     do not ask for confirmation"
      exit 0
      ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
  shift
done

[[ ${EUID} -eq 0 ]] || die "Please run as root"
[[ -f ${SF_CONF} ]] || die "${SF_CONF} is missing, run ./setup.sh first."
load_env_file "${SF_CONF}"
CHANNEL=${CHANNEL:-${UPDATE_CHANNEL:-release}}
[[ ${CHANNEL} == release || ${CHANNEL} == main ]] || die "UPDATE_CHANNEL must be release or main"
[[ ${UPDATE_BRANCH:-main} =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || die "UPDATE_BRANCH is not a branch name"

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

# The newest release: tags vMAJOR.MINOR.PATCH (no pre-releases)
latest_release() {
  git_as_owner tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}

follow_branch() {
  local branch=${UPDATE_BRANCH:-main}
  if [[ $(git_as_owner symbolic-ref -q --short HEAD) != "${branch}" ]]; then
    log "Switching to the branch ${branch}"
    git_as_owner checkout -q "${branch}" || die "Cannot check out the branch ${branch}"
  fi
  log "Updating the branch ${branch} (fast-forward only)..."
  git_as_owner pull --ff-only || die "git pull failed, the branch cannot be fast-forwarded. Resolve this manually."
}

follow_releases() {
  local latest
  latest=$(latest_release)
  if [[ -z ${latest} ]]; then
    warn "There is no release yet (no tag vX.Y.Z): the checkout stays at $(git_as_owner describe --always --tags)."
    warn "Run with --channel main, or set UPDATE_CHANNEL=main, to follow the branch."
    return 0
  fi
  if [[ $(git_as_owner rev-parse HEAD) == "$(git_as_owner rev-parse "${latest}^{commit}")" ]]; then
    log "The checkout is at the newest release ${latest}"
  elif git_as_owner merge-base --is-ancestor HEAD "${latest}"; then
    log "Moving the checkout from $(git_as_owner describe --always --tags) to the release ${latest}"
    git_as_owner checkout -q --detach "${latest}" || die "Cannot check out ${latest}"
  else
    # newer than the release (e.g. the branch's commits after it): never back
    warn "The checkout ($(git_as_owner describe --always --tags)) is newer than the release ${latest} and stays;"
    warn "updates come with the next release, or follow the branch with --channel main."
  fi
}

if [[ ${SKIP_GIT} != y ]]; then
  if [[ -n "$(git_as_owner status --porcelain --untracked-files=no)" ]]; then
    warn "You have local changes to tracked files:"
    git_as_owner status --short --untracked-files=no
    die "Commit or stash them, or run with --skip-git."
  fi
  log "Fetching from $(git_as_owner remote get-url origin 2> /dev/null || echo origin)..."
  git_as_owner fetch -q --tags origin || die "git fetch failed. Resolve this manually, or run with --skip-git."
  if [[ ${CHANNEL} == main ]]; then
    follow_branch
  else
    follow_releases
  fi
  # The documentation (DOCS_ENABLED): new commits of its repository; install.sh
  # (configure.sh) rebuilds it if they changed it
  is_yes "${DOCS_ENABLED:-n}" && docs_fetch --update
fi

system/install.sh || die "Update failed"
log "Update complete."
