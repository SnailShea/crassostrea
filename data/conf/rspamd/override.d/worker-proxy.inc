bind_socket = "127.0.0.1:9900";
milter = true;
upstream "local" {
  name = "localhost";
  default = true;
  hosts = "127.0.0.1:11333"
}
# Longer than the scan worker's task_timeout (worker-normal.inc), shorter
# than Postfix's milter_content_timeout (300 s)
timeout = 180s;
reject_message = "This message does not meet our delivery requirements";
.include(try=true; priority=30) "$CONFDIR/override.d/worker-proxy.custom.inc"
