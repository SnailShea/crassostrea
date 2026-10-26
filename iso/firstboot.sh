#!/usr/bin/env bash
# First boot of a gateway installed from the Crassostrea ISO
# (crassostrea-firstboot.service, on the console before the login prompt).
# Sets the gateway up with /opt/crassostrea/setup.sh once, when the machine is
# on its network:
#   - unattended when the installation was booted with crassostrea.hostname=
#     (/etc/crassostrea/firstboot.conf): setup.sh --hostname ... --yes;
#   - otherwise a menu: set up now, configure the network (nmtui), or skip and
#     run setup.sh later over SSH.
# Done once it succeeded or was skipped (/var/lib/crassostrea/firstboot.done);
# an unattended setup that failed is tried again at the next boot.
set -o pipefail

SRC=${CRASSOSTREA_SRC:-/opt/crassostrea}
CONF=${CRASSOSTREA_FIRSTBOOT_CONF:-/etc/crassostrea/firstboot.conf}
STATE=${CRASSOSTREA_STATE:-/var/lib/crassostrea}
LOG=${CRASSOSTREA_FIRSTBOOT_LOG:-/var/log/crassostrea-firstboot.log}

done_marker() {
  mkdir -p "${STATE}"
  date -u +%FT%TZ > "${STATE}/firstboot.done"
  systemctl disable crassostrea-firstboot.service > /dev/null 2>&1
}

addresses() {
  ip -brief address show scope global 2> /dev/null | awk '{printf "  %-12s %s\n", $1, substr($0, index($0, $3))}'
}

banner() {
  clear 2> /dev/null
  echo "=============================================================="
  echo " Crassostrea spam filter gateway $(cat /etc/crassostrea/iso-version 2> /dev/null)"
  echo "=============================================================="
  echo
  echo "Network:"
  addresses || true
  echo
}

wait_for_network() {
  local _
  for _ in $(seq 1 60); do
    ip route show default 2> /dev/null | grep -q . && return 0
    sleep 2
  done
  return 1
}

run_setup() {
  echo "Setting up the gateway (a log is kept in ${LOG}) ..."
  echo
  # setup.sh asks its questions on this console; its output also goes to the log
  "${SRC}/setup.sh" "$@" 2>&1 | tee -a "${LOG}"
}

unattended() {
  local hostname=$1
  banner
  echo "Unattended setup for ${hostname} (crassostrea.hostname at the installation)."
  if ! wait_for_network; then
    echo "There is no network route. The setup is tried again at the next boot;"
    echo "or log in and run: ${SRC}/setup.sh"
    return 1
  fi
  if run_setup --hostname "${hostname}" --yes; then
    done_marker
    return 0
  fi
  echo
  echo "The setup failed (see above and ${LOG}). It is tried again at the next boot;"
  echo "or log in and run: ${SRC}/setup.sh"
  return 1
}

menu() {
  local choice
  while true; do
    banner
    echo "The gateway still has to be set up. It needs Internet access (packages,"
    echo "virus signatures) and a fixed address with its hostname in DNS."
    echo
    echo "  1) Set up the gateway now"
    echo "  2) Configure the network first (nmtui)"
    echo "  3) Skip: log in and run ${SRC}/setup.sh later (e.g. over SSH)"
    echo
    read -r -p "Choice [1]: " choice || return 0
    case ${choice:-1} in
      1)
        if run_setup; then
          done_marker
          echo
          read -r -p "Press Enter to continue to the login prompt. " _ || true
          return 0
        fi
        echo
        read -r -p "The setup did not finish. Press Enter for the menu. " _ || return 0
        ;;
      2) nmtui || true ;;
      3)
        done_marker
        echo
        echo "Run ${SRC}/setup.sh as root when you are ready."
        sleep 3
        return 0
        ;;
    esac
  done
}

main() {
  [[ -f ${STATE}/firstboot.done ]] && return 0
  if [[ ! -x ${SRC}/setup.sh ]]; then
    echo "crassostrea-firstboot: ${SRC}/setup.sh is missing" >&2
    done_marker
    return 1
  fi
  local hostname=
  if [[ -f ${CONF} ]]; then
    hostname=$(sed -n 's/^HOSTNAME=//p' "${CONF}" | head -1)
  fi
  if [[ -n ${hostname} ]]; then
    unattended "${hostname}"
  else
    menu
  fi
}

main "$@"
