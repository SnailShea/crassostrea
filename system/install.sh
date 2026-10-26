#!/usr/bin/env bash
# Installs or updates the Crassostrea gateway on EL10 (AlmaLinux, Rocky
# Linux or RHEL 10) without containers. Idempotent: update.sh runs it again.
#
#   1. repositories: EPEL (+ CRB) and the official Rspamd repository
#   2. packages, the crassostrea user, a Python venv
#   3. pinned third-party tools: acme.sh, postfix-tlspol (built with Go), smtp-cli
#   4. SELinux settings
#   5. system/configure.sh: deploy, render the configuration, start services
#
# In a cluster (HA_NODES in crassostrea.conf) full nodes also get Galera,
# Sentinel, haproxy and (HA_VIP) keepalived; the witness (HA_WITNESS) only
# gets the Galera arbitrator and Sentinel.
#
# Usually run by setup.sh (first installation) and update.sh. Needs
# /etc/crassostrea/crassostrea.conf, which setup.sh creates.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Pinned versions: tag and the commit it points to (checked after cloning)
ACME_SH_TAG=3.1.6
ACME_SH_COMMIT=807da6498377ee5e0cf43a78091f46f12dc59a89
TLSPOL_TAG=v1.14.0
TLSPOL_COMMIT=cc92ba75c5bab8a66d65a8248119acaa76021165
SMTP_CLI_URL=https://raw.githubusercontent.com/mludvig/smtp-cli/v3.10/smtp-cli
SMTP_CLI_SHA256=783530b211f71d288f2d8e8bb0c69a005722bfb26e8cba28c10925bcb1a5db32

PACKAGES=(
  # mail and filtering
  postfix postfix-lmdb postfix-mysql postfix-pcre rspamd clamd clamav-freshclam clamav-data
  # storage, DNS, web
  mariadb-server mariadb valkey unbound nginx
  # web UI, netfilter, olefy
  python3 python3-pip python3-nftables python3-dns file-libs
  # watchdog
  nagios-plugins-tcp nagios-plugins-smtp nagios-plugins-http nagios-plugins-mysql
  perl-IO-Socket-SSL perl-MIME-Lite perl-TermReadKey perl-Getopt-Long perl-MIME-Base64 whois
  # tools used by the scripts
  bind-utils curl jq rsync openssl tar gzip git golang policycoreutils-python-utils firewalld
)
# Full cluster nodes: Galera (state transfers with mariabackup over socat),
# Sentinel (part of valkey), haproxy
CLUSTER_PACKAGES=(mariadb-server-galera galera mariadb-backup socat haproxy)
# The witness: Galera arbitrator and Sentinel only
WITNESS_PACKAGES=(galera valkey openssl firewalld policycoreutils-python-utils)

require_el10
load_config

setup_repositories() {
  log "Enabling EPEL, CRB and the Rspamd repository"
  rpm -q dnf-plugins-core > /dev/null || dnf install -y dnf-plugins-core || die "Cannot install dnf-plugins-core"
  if ! rpm -q epel-release > /dev/null; then
    dnf install -y epel-release \
      || dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm \
      || die "Cannot install epel-release"
  fi
  if [[ ${ID} == rhel ]]; then
    subscription-manager repos --enable "codeready-builder-for-rhel-10-$(arch)-rpms" \
      || warn "Cannot enable CodeReady Builder, some EPEL packages may be missing"
  else
    dnf config-manager --set-enabled crb || warn "Cannot enable CRB, some EPEL packages may be missing"
  fi
  # The repository file published by rspamd.com uses plain http
  cat > /etc/yum.repos.d/rspamd.repo <<'EOF'
[rspamd]
name=Rspamd stable repository
baseurl=https://rspamd.com/rpm-stable/centos-10/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://rspamd.com/rpm/rspamd.asc
EOF
  rpm --import https://rspamd.com/rpm/rspamd.asc || die "Cannot import the Rspamd signing key"
}

install_packages() {
  log "Installing packages"
  local packages=("${PACKAGES[@]}")
  [[ ${HA_ROLE} == node ]] && packages+=("${CLUSTER_PACKAGES[@]}")
  [[ ${HA_ROLE} == node && -n ${HA_VIP} ]] && packages+=(keepalived)
  dnf install -y "${packages[@]}" || die "Package installation failed"
}

# The witness needs no repositories besides the distribution's
install_witness() {
  log "Installing the cluster witness (Galera arbitrator, Valkey Sentinel)"
  dnf install -y "${WITNESS_PACKAGES[@]}" || die "Package installation failed"
  "${SCRIPT_DIR}/configure.sh" || die "system/configure.sh failed"
  echo
  log "The witness ${CRASSOSTREA_HOSTNAME} is configured. Check the cluster with: system/cluster.sh status"
  exit 0
}

create_user() {
  if ! getent passwd "${SF_USER}" > /dev/null; then
    log "Creating user ${SF_USER}"
    useradd --system --home-dir "${SF_STATE}" --no-create-home --shell /usr/sbin/nologin "${SF_USER}"
  fi
  install -d -m 0755 -o root -g root "${SF_STATE}" "${SF_LIB}" "${SF_LIBEXEC}" "${SF_LIBEXEC}/watchdog"
  install -d -m 0750 -o root -g "${SF_USER}" "${SF_ETC}"
  chgrp "${SF_USER}" "${SF_CONF}" && chmod 0640 "${SF_CONF}"
}

setup_venv() {
  log "Installing Python packages into ${SF_VENV}"
  [[ -x ${SF_VENV}/bin/python ]] || python3 -m venv --system-site-packages "${SF_VENV}" || die "Cannot create ${SF_VENV}"
  "${SF_VENV}/bin/pip" install --quiet --upgrade pip
  "${SF_VENV}/bin/pip" install --quiet -r "${SF_SRC}/data/web/requirements.txt" \
    -r "${SF_SRC}/services/requirements.txt" || die "pip install failed"
}

# git_checkout URL TAG COMMIT DIR: shallow clone of a tag, verified against
# the expected commit
git_checkout() {
  local url=$1 tag=$2 commit=$3 dir=$4
  if [[ -d ${dir}/.git && $(git -C "${dir}" rev-parse HEAD 2> /dev/null) == "${commit}" ]]; then
    return 0
  fi
  rm -rf "${dir}"
  git clone --quiet --depth 1 --branch "${tag}" "${url}" "${dir}" || die "Cannot clone ${url}"
  [[ $(git -C "${dir}" rev-parse HEAD) == "${commit}" ]] \
    || die "${url} ${tag} is not commit ${commit}, refusing to use it"
}

install_tools() {
  log "Installing acme.sh ${ACME_SH_TAG}"
  git_checkout https://github.com/acmesh-official/acme.sh.git "${ACME_SH_TAG}" "${ACME_SH_COMMIT}" \
    /usr/local/share/crassostrea/acme.sh

  if [[ ! -x /usr/local/bin/postfix-tlspol || $(cat "${SF_LIB}/postfix-tlspol.commit" 2> /dev/null) != "${TLSPOL_COMMIT}" ]]; then
    log "Building postfix-tlspol ${TLSPOL_TAG}"
    local build
    build=$(mktemp -d)
    git_checkout https://github.com/Zuplu/postfix-tlspol.git "${TLSPOL_TAG}" "${TLSPOL_COMMIT}" "${build}/src"
    # build-only still installs the binary, a config and the state directory
    # below PREFIX: keep them in the build directory
    (cd "${build}/src" && CGO_ENABLED=0 GOPATH="${build}/go" GOCACHE="${build}/cache" NOOPT=1 \
      PREFIX="${build}/root" VERSION="${TLSPOL_TAG#v}" scripts/build.sh build-only) \
      || die "Building postfix-tlspol failed"
    install -m 0755 "${build}/src/build/postfix-tlspol" /usr/local/bin/postfix-tlspol
    echo "${TLSPOL_COMMIT}" > "${SF_LIB}/postfix-tlspol.commit"
    rm -rf "${build}"
  fi
  # Left by builds without PREFIX: a plain /var/lib/postfix-tlspol (only a
  # cache) makes the unit fail, as systemd cannot move it to /var/lib/private
  # for DynamicUser=; there it is a symlink. And a second copy of the binary.
  if [[ -d /var/lib/postfix-tlspol && ! -L /var/lib/postfix-tlspol ]]; then
    rm -rf /var/lib/postfix-tlspol
  fi
  rpm -qf /usr/bin/postfix-tlspol > /dev/null 2>&1 || rm -f /usr/bin/postfix-tlspol

  if ! echo "${SMTP_CLI_SHA256}  ${SF_LIBEXEC}/watchdog/smtp-cli" | sha256sum --quiet -c 2> /dev/null; then
    log "Installing smtp-cli (watchdog notifications)"
    local tmp
    tmp=$(mktemp)
    curl -fsSL -o "${tmp}" "${SMTP_CLI_URL}" || die "Cannot download smtp-cli"
    echo "${SMTP_CLI_SHA256}  ${tmp}" | sha256sum --quiet -c || die "smtp-cli does not match its checksum"
    install -m 0755 "${tmp}" "${SF_LIBEXEC}/watchdog/smtp-cli"
    rm -f "${tmp}"
  fi
}

setup_selinux() {
  selinuxenabled 2> /dev/null || return 0
  log "Configuring SELinux"
  # nginx proxies to the web UI (127.0.0.1:8000) and rspamd (127.0.0.1:11334)
  setsebool -P httpd_can_network_connect 1
  # postfix may only bind SMTP ports and unreserved ones (>= 1024): its
  # loopback listeners for re-injection (590) and the watchdog (589)
  selinux_port smtp_port_t 589
  selinux_port smtp_port_t 590
  semanage fcontext -a -t cert_t "${SF_ETC}/ssl(/.*)?" 2> /dev/null \
    || semanage fcontext -m -t cert_t "${SF_ETC}/ssl(/.*)?"
  semanage fcontext -a -t httpd_sys_content_t "${SF_STATE}/acme-challenge(/.*)?" 2> /dev/null \
    || semanage fcontext -m -t httpd_sys_content_t "${SF_STATE}/acme-challenge(/.*)?"
  # The programs the units start must be bin_t so that systemd runs them as
  # unconfined_service_t; as lib_t (venv) or usr_t (libexec) they stay in
  # init_t, which may not connect to MariaDB (EACCES on 127.0.0.1:3306)
  semanage fcontext -a -t bin_t "${SF_LIB}/venv/bin(/.*)?" 2> /dev/null \
    || semanage fcontext -m -t bin_t "${SF_LIB}/venv/bin(/.*)?"
  semanage fcontext -a -t bin_t "${SF_LIBEXEC}(/.*)?" 2> /dev/null \
    || semanage fcontext -m -t bin_t "${SF_LIBEXEC}(/.*)?"
  # Postfix maps written by the web UI (configure.sh), read by Postfix
  semanage fcontext -a -t postfix_etc_t "${SF_STATE}/postfix(/.*)?" 2> /dev/null \
    || semanage fcontext -m -t postfix_etc_t "${SF_STATE}/postfix(/.*)?"
  install -d -m 0755 "${SF_ETC}/ssl" "${SF_STATE}/acme-challenge"
  restorecon -R "${SF_ETC}/ssl" "${SF_STATE}/acme-challenge" /usr/local/bin/postfix-tlspol "${SF_LIB}" "${SF_LIBEXEC}"
}

[[ ${HA_ROLE} == witness ]] && install_witness
setup_repositories
install_packages
create_user
setup_venv
install_tools
setup_selinux
"${SCRIPT_DIR}/configure.sh" || die "system/configure.sh failed"

if selinuxenabled 2> /dev/null && ausearch -m AVC -ts recent 2> /dev/null | grep -q denied; then
  warn "SELinux denied some actions during the start, see: ausearch -m AVC -ts recent"
  warn "helper-scripts/selinux-local-policy.sh builds a local policy module from them"
fi
echo
log "Crassostrea is installed. Log in at https://${CRASSOSTREA_HOSTNAME}/ as admin"
log "(initial password: WEB_ADMIN_PASSWORD in ${SF_CONF}, used only while no administrator exists)."
