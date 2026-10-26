#!/usr/bin/env bash
# Builds and loads a local SELinux policy module from the denials logged
# since the last boot for the services of the gateway. Review the rules it
# prints before answering yes.
[[ ${EUID} -eq 0 ]] || { echo "Please run as root"; exit 1; }
command -v audit2allow > /dev/null || { echo "Install policycoreutils-python-utils first"; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
ausearch -m AVC -ts boot 2> /dev/null > "${WORK}/avc.log"
if ! grep -q denied "${WORK}/avc.log"; then
  echo "No SELinux denials since boot."
  exit 0
fi
(cd "${WORK}" && audit2allow -i avc.log -M crassostrea_local > /dev/null) || exit 1
echo "Rules of the module crassostrea_local:"
cat "${WORK}/crassostrea_local.te"
read -r -p "Load this module? [y/N] " response
[[ "${response}" =~ ^([yY][eE][sS]|[yY])$ ]] || exit 0
semodule -i "${WORK}/crassostrea_local.pp" && echo "Loaded. Restart the affected services."
