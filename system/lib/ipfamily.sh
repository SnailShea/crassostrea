#!/usr/bin/env bash
# Which IP families the gateway uses on its network interface: IPV4_ENABLED
# and IPV6_ENABLED (crassostrea.conf; at least one of them). Sourced by
# common.sh, and deployed to /usr/local/lib/crassostrea/lib for
# system/libexec/network-apply (IP addressing page of the web UI).
#
# Loopback keeps both families whatever is set: the services talk to each
# other over 127.0.0.1 (rspamd, MariaDB, Valkey, ClamAV, unbound, the web UI),
# so "IPv4 off" means no IPv4 on the network interface, and the services
# that reach the internet prefer IPv6. nginx listens on [::] only with IPv6
# (system/configure.sh nginx_listen).

ip_enabled() {
  # ip_enabled VALUE: IPV4_ENABLED/IPV6_ENABLED are on unless set to a no value
  [[ ! ${1,,} =~ ^(n|no|false|0|off)$ ]]
}

# Postfix inet_protocols: IPv4 stays for loopback (milter, policy and
# lookup services on 127.0.0.1)
ip_postfix_inet_protocols() {
  if ip_enabled "$2"; then echo all; else echo ipv4; fi
}

# Postfix smtp_address_preference: the family that reaches the internet
ip_postfix_address_preference() {
  if ! ip_enabled "$1"; then
    echo ipv6
  elif ! ip_enabled "$2"; then
    echo ipv4
  else
    echo any
  fi
}

# Lines for unbound's server: clause (it keeps listening on 127.0.0.1)
ip_unbound_lines() {
  ip_enabled "$2" || echo "  do-ip6: no"
  ip_enabled "$1" || echo "  prefer-ip6: yes"
  return 0
}
