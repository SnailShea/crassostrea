bind_socket = "127.0.0.1:11333";
# Virus scans of large messages take up to 100 s (local.d/antivirus.conf),
# then the mail log export (metadata_exporter.conf) runs
task_timeout = 150s;
count = 1;
.include(try=true; priority=30) "$CONFDIR/override.d/worker-normal.custom.inc"
