#!/usr/bin/env bash
# Downloads the EL10 packages the system tests run (Valkey, haproxy, nginx,
# MariaDB with Galera, the arbitrator, mariabackup, socat, keepalived) and extracts them
# into $WORK/pkgroot. Nothing is installed on the host.
set -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PACKAGES=(
  valkey haproxy nginx nginx-core nginx-filesystem
  mariadb-server mariadb-server-galera galera mariadb-backup mariadb mariadb-common mariadb-errmsg
  mariadb-connector-c mariadb-connector-c-config socat lsof libaio boost-program-options
  keepalived net-snmp-libs net-snmp-agent-libs lm_sensors-libs
)

mkdir -p "${WORK}/rpms" "${PKG}"
echo "Downloading ${#PACKAGES[@]} packages to ${WORK}/rpms"
# none of them comes from the Rspamd repository, whose key a user's dnf would
# ask to import
dnf -q download --disablerepo='rspamd*' --destdir "${WORK}/rpms" "${PACKAGES[@]}" \
  || { echo "dnf download failed" >&2; exit 1; }
cd "${PKG}" || exit 1
for rpm in "${WORK}"/rpms/*.rpm; do
  rpm2cpio "${rpm}" | cpio -idm --quiet 2> /dev/null || { echo "Cannot extract ${rpm}" >&2; exit 1; }
done
missing=$(for binary in usr/bin/valkey-server usr/sbin/haproxy usr/sbin/nginx usr/libexec/mariadbd usr/sbin/garbd \
    usr/bin/mariabackup usr/bin/socat usr/sbin/keepalived; do
  LD_LIBRARY_PATH=${PKG}/usr/lib64 ldd "${PKG}/${binary}" 2> /dev/null | grep "not found"
done)
if [[ -n ${missing} ]]; then
  echo "Libraries missing on this host:" >&2
  echo "${missing}" >&2
  exit 1
fi
echo "Packages extracted to ${PKG}"
