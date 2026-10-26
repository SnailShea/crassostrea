#!/usr/bin/env bash
# Builds the installation ISO of the gateway: the AlmaLinux 10 minimal ISO
# with a kickstart (iso/crassostrea.ks) and this repository. Booted, it
# installs AlmaLinux from the ISO itself and the gateway's source in
# /opt/crassostrea, and sets the gateway up at the first boot
# (iso/firstboot.sh). Used by .github/workflows/iso.yml.
#
#   iso/build.sh [options]
#     --ref REF           branch, tag or commit to put on the ISO (default: the
#                         checked-out branch). Committed changes only.
#     --origin URL        git remote the installed checkout updates from
#                         (update.sh); default: this repository's "origin",
#                         an SSH remote as HTTPS (gateways have no SSH key)
#     --base-iso PATH     an AlmaLinux 10 minimal ISO you downloaded (still
#                         checked against the signed CHECKSUM)
#     --out DIR           where the ISO goes (default: iso/out)
#     --cache DIR         downloads (default: iso/cache)
#     --engine E          podman, docker or none: where iso/assemble.sh runs.
#                         Default: none when xorriso, mtools, isomd5sum and
#                         pykickstart are installed (EL10), else podman or
#                         docker with the almalinux:10 image (no privileges)
#
# Needs git, curl, gpg and sha256sum, and podman or docker unless the tools
# of iso/assemble.sh are installed. Nothing is installed on the build host.
set -o pipefail

ISO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "${ISO_DIR}/.." && pwd)
MIRROR=${ALMALINUX_MIRROR:-https://repo.almalinux.org/almalinux/10/isos/x86_64}
# AlmaLinux OS 10 signing key (RPM-GPG-KEY-AlmaLinux-10)
ALMA_KEY_URL=https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-10
ALMA_KEY_FPR=EE6DB7B98F5BF5EDD9DA0DE5DEE5C11CC2A1E572
IMAGE=${CRASSOSTREA_ISO_IMAGE:-docker.io/library/almalinux:10}

REF='' ORIGIN='' BASE_ISO='' OUT=${ISO_DIR}/out CACHE=${ISO_DIR}/cache ENGINE=''

log() { echo "==> $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  sed -n '2,/^set -o pipefail/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --ref|--origin|--base-iso|--out|--cache|--engine)
      [[ $# -ge 2 ]] || die "$1 needs a value"
      case $1 in
        --ref) REF=$2 ;; --origin) ORIGIN=$2 ;; --base-iso) BASE_ISO=$2 ;; --out) OUT=$2 ;;
        --cache) CACHE=$2 ;; --engine) ENGINE=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option $1" >&2; usage 2 ;;
  esac
done

for tool in git curl gpg sha256sum tar; do
  command -v "${tool}" > /dev/null || die "${tool} is missing"
done
if [[ -z ${ENGINE} ]]; then
  if command -v xorriso > /dev/null && command -v mcopy > /dev/null && command -v implantisomd5 > /dev/null \
      && command -v ksvalidator > /dev/null; then ENGINE=none
  elif command -v podman > /dev/null; then ENGINE=podman
  elif command -v docker > /dev/null; then ENGINE=docker
  else die "Install podman or docker (or xorriso, mtools, isomd5sum and pykickstart)"
  fi
fi
[[ ${ENGINE} =~ ^(none|podman|docker)$ ]] || die "--engine must be podman, docker or none"

mkdir -p "${OUT}" "${CACHE}"
OUT=$(cd "${OUT}" && pwd)
CACHE=$(cd "${CACHE}" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/crassostrea-iso.XXXXXX") || die "Cannot create a work directory"
trap 'rm -rf "${WORK}"' EXIT

# ---------------------------------------------------------------------------
# The gateway's source: a clone of REF with its history, so update.sh can pull
# ---------------------------------------------------------------------------

stage_source() {
  local branch commit version
  if [[ -z ${REF} ]]; then
    REF=$(git -C "${REPO}" symbolic-ref --quiet --short HEAD) || REF=HEAD
  fi
  commit=$(git -C "${REPO}" rev-parse --verify --quiet "${REF}^{commit}") || die "${REF} is not a commit of ${REPO}"
  if [[ -n $(git -C "${REPO}" status --porcelain --untracked-files=no 2> /dev/null) ]]; then
    log "Note: uncommitted changes are not put on the ISO, only ${REF} (${commit:0:12})"
  fi
  if [[ -z ${ORIGIN} ]]; then
    ORIGIN=$(git -C "${REPO}" remote get-url origin 2> /dev/null)
    # git@github.com:owner/repo.git or ssh://git@github.com/owner/repo.git
    if [[ ${ORIGIN} =~ ^(ssh://)?git@([^:/]+)[:/](.+)$ ]]; then
      ORIGIN=https://${BASH_REMATCH[2]}/${BASH_REMATCH[3]}
    fi
  fi
  # the branch the installed checkout follows: REF if it is one, else main
  if git -C "${REPO}" show-ref --verify --quiet "refs/heads/${REF}"; then
    branch=${REF}
  else
    branch=${ISO_BRANCH:-main}
  fi
  version=$(git -C "${REPO}" describe --tags --always "${commit}" 2> /dev/null || echo "${commit:0:12}")
  VERSION=${version}

  log "Staging ${REF} (${version}) as branch ${branch}"
  local src=${WORK}/stage/crassostrea
  git clone --quiet --no-hardlinks --no-checkout "${REPO}" "${src}" || die "git clone failed"
  git -C "${src}" checkout --quiet -B "${branch}" "${commit}" || die "git checkout failed"
  git -C "${src}" remote remove origin
  if [[ -n ${ORIGIN} ]]; then
    git -C "${src}" remote add origin "${ORIGIN}"
    # update.sh pulls the branch from origin; the ISO's commit counts as fetched
    git -C "${src}" update-ref "refs/remotes/origin/${branch}" "${commit}"
    git -C "${src}" config "branch.${branch}.remote" origin
    git -C "${src}" config "branch.${branch}.merge" "refs/heads/${branch}"
  else
    log "Note: no --origin and no git remote: update.sh on the gateway needs a remote (git remote add origin URL)"
  fi
  git -C "${src}" gc --quiet --prune=now 2> /dev/null || true

  local payload=${WORK}/crassostrea
  mkdir -p "${payload}"
  tar --owner=0 --group=0 --numeric-owner -czf "${payload}/crassostrea.tar.gz" -C "${WORK}/stage" crassostrea || die "Cannot pack the source"
  install -m 0755 "${ISO_DIR}/firstboot.sh" "${payload}/firstboot.sh"
  install -m 0644 "${ISO_DIR}/crassostrea-firstboot.service" "${payload}/crassostrea-firstboot.service"
  echo "${version}" > "${payload}/VERSION"
  cp "${ISO_DIR}/crassostrea.ks" "${WORK}/crassostrea.ks"
}

# ---------------------------------------------------------------------------
# The AlmaLinux minimal ISO, checked against the signed CHECKSUM
# ---------------------------------------------------------------------------

verify_checksums() {
  local gnupg=${WORK}/gnupg
  mkdir -m 0700 "${gnupg}"
  curl -fsSL -o "${WORK}/alma.key" "${ALMA_KEY_URL}" || die "Cannot download ${ALMA_KEY_URL}"
  GNUPGHOME=${gnupg} gpg --batch --quiet --import "${WORK}/alma.key" 2> /dev/null || die "Cannot import the AlmaLinux key"
  GNUPGHOME=${gnupg} gpg --batch --list-keys --with-colons 2> /dev/null | grep -q "^fpr:::::::::${ALMA_KEY_FPR}:" \
    || die "The downloaded AlmaLinux key is not ${ALMA_KEY_FPR}"
  curl -fsSL -o "${WORK}/CHECKSUM" "${MIRROR}/CHECKSUM" || die "Cannot download ${MIRROR}/CHECKSUM"
  GNUPGHOME=${gnupg} gpg --batch --status-fd 1 --verify "${WORK}/CHECKSUM" 2> /dev/null \
    | grep -q "^\[GNUPG:\] VALIDSIG ${ALMA_KEY_FPR} " || die "The signature of CHECKSUM is not valid"
}

# expected_sha256 NAME
expected_sha256() {
  sed -n "s/^SHA256 (${1//./\\.}) = \([0-9a-f]\{64\}\)$/\1/p" "${WORK}/CHECKSUM"
}

fetch_base_iso() {
  verify_checksums
  local name sum
  if [[ -n ${BASE_ISO} ]]; then
    [[ -f ${BASE_ISO} ]] || die "${BASE_ISO} does not exist"
    name=$(basename "${BASE_ISO}")
    sum=$(expected_sha256 "${name}")
    [[ -n ${sum} ]] || die "${name} is not listed in the AlmaLinux CHECKSUM (use the file name it was published as)"
  else
    # the newest point release, by name (not the -latest alias, so the cache is unambiguous)
    name=$(sed -n 's/^SHA256 (\(AlmaLinux-10\.[0-9]*-x86_64-minimal\.iso\)) = .*/\1/p' "${WORK}/CHECKSUM" | sort -V | tail -1)
    [[ -n ${name} ]] || die "No minimal ISO in ${MIRROR}/CHECKSUM"
    sum=$(expected_sha256 "${name}")
    BASE_ISO=${CACHE}/${name}
    if [[ ! -f ${BASE_ISO} ]] || ! echo "${sum}  ${BASE_ISO}" | sha256sum --check --status; then
      log "Downloading ${name}"
      curl -fL --retry 3 -o "${BASE_ISO}.part" "${MIRROR}/${name}" || die "Cannot download ${name}"
      mv "${BASE_ISO}.part" "${BASE_ISO}"
    fi
  fi
  log "Checking ${name}"
  echo "${sum}  ${BASE_ISO}" | sha256sum --check --status || die "${BASE_ISO} does not match the signed checksum"
  BASE_NAME=${name}
  ALMA_VERSION=$(sed -n 's/^AlmaLinux-\(10\.[0-9]*\)-.*/\1/p' <<< "${name}")
}

# ---------------------------------------------------------------------------
# iso/assemble.sh: kickstart and payload into the ISO
# ---------------------------------------------------------------------------

build_iso() {
  local output=crassostrea-${VERSION}-alma${ALMA_VERSION:-10}-x86_64.iso
  log "Building ${output}"
  if [[ ${ENGINE} == none ]]; then
    "${ISO_DIR}/assemble.sh" "${BASE_ISO}" "${WORK}/crassostrea.ks" "${WORK}/crassostrea" "${OUT}/${output}" \
      || die "Building the ISO failed"
  else
    cp "${ISO_DIR}/assemble.sh" "${WORK}/assemble.sh"
    "${ENGINE}" run --rm \
      -v "${WORK}:/work:Z" -v "$(dirname "${BASE_ISO}"):/base:ro,Z" -v "${OUT}:/out:Z" \
      "${IMAGE}" bash -c "
        dnf -q -y install xorriso mtools isomd5sum pykickstart > /dev/null || exit 1
        /work/assemble.sh '/base/${BASE_NAME}' /work/crassostrea.ks /work/crassostrea '/out/${output}'" \
      || die "Building the ISO in ${IMAGE} failed"
    # a rootful engine leaves it to root (a rootless one maps root to us)
    if [[ $(stat -c %u "${OUT}/${output}") != "$(id -u)" ]]; then
      "${ENGINE}" run --rm -v "${OUT}:/out:Z" "${IMAGE}" chown "$(id -u):$(id -g)" "/out/${output}" \
        || log "Note: ${OUT}/${output} belongs to root"
    fi
  fi
  (cd "${OUT}" && sha256sum "${output}" > "${output}.sha256")
  ISO=${OUT}/${output}
}

stage_source
fetch_base_iso
build_iso
log "Done: ${ISO} ($(du -h "${ISO}" | cut -f1))"
log "      $(cat "${ISO}.sha256")"
