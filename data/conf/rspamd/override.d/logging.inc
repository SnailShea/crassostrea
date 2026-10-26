level = "silent";
type = "console";
# journald adds the timestamps
systemd = true;
.include "$CONFDIR/logging.inc"
.include(try=true; priority=20) "$CONFDIR/override.d/logging.custom.inc"
