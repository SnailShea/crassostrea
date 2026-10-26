dns {
  enable_dnssec = true;
  # local validating resolver (unbound)
  nameserver = ["127.0.0.1:53"];
}
map_watch_interval = 30s;
task_timeout = 150s;
# Scan every message Postfix accepts: the web UI's message size limit is at
# most 100 MiB (Rspamd's default stops at 50 MiB and passes larger mail
# unscanned)
max_message = 134217728;
enable_mime_utf = true;
disable_monitoring = true;
# In case a task times out (like DNS lookup), soft reject the message
# instead of silently accepting the message without further processing.
soft_reject_on_timeout = true;
# Loopback and the relay networks managed by the web UI
local_addrs = [
  "/etc/rspamd/custom/local_networks.map",
  "/etc/rspamd/custom/relay_networks.map"
];
