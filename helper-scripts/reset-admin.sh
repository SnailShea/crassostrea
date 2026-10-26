#!/usr/bin/env bash
# Resets the password of a web UI administrator (default: admin) and
# re-enables the account. Usage: helper-scripts/reset-admin.sh [username]
[[ ${EUID} -eq 0 ]] || { echo "Please run as root"; exit 1; }

USERNAME="${1:-admin}"
read -r -p "Reset the password of ${USERNAME}? [y/N] " response
[[ "${response}" =~ ^([yY][eE][sS]|[yY])$ ]] || exit 0

# Same user and environment as the web UI
systemd-run --quiet --wait --pipe --collect --uid=crassostrea --gid=crassostrea \
  --property=EnvironmentFile=/etc/crassostrea/crassostrea.conf \
  --setenv=PYTHONPATH=/usr/local/lib/crassostrea/web --working-directory=/usr/local/lib/crassostrea/web \
  /usr/local/lib/crassostrea/venv/bin/flask --app crassostrea reset-password "${USERNAME}"
