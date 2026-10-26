Place executable scripts in `postfix/`, `rspamd/` or `unbound/` to run them
(as root) at the end of the corresponding step of `system/configure.sh`,
after that component's configuration was rendered and before services are
restarted.
