#!/usr/bin/env bash
# ACME challenges in a cluster, run by run.sh inside `unshare -rn`: nginx of
# both nodes with their rendered configuration. A challenge token that only
# one node has is answered by the other one too (names shared by the nodes),
# without forwarding loops. Only the node's own names reach the web UI; other
# names and addresses get 404, ACME challenges excepted. mx1 serves the
# documentation at /docs/ to whoever the web UI (a stub here) lets in.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
NGINX=${PKG}/usr/sbin/nginx

cluster_addresses 10.0.0.1 10.0.0.2
declare -A ROOT=([1]=${NODES}/mx1 [2]=${NODES}/mx2)
for n in 1 2; do
  N=${WORK}/acme${n}
  rm -rf "${N}"
  mkdir -p "${N}/conf.d" "${N}/logs" "${N}/ssl" "${N}/tmp" "${N}/acme/.well-known/acme-challenge"
  cat > "${N}/nginx.conf" <<EOF
user root root;
error_log ${N}/logs/error.log notice;
pid ${N}/nginx.pid;
events { worker_connections 64; }
http {
  client_body_temp_path ${N}/tmp/body; proxy_temp_path ${N}/tmp/proxy; fastcgi_temp_path ${N}/tmp/fcgi;
  uwsgi_temp_path ${N}/tmp/uwsgi; scgi_temp_path ${N}/tmp/scgi;
  include ${PKG}/etc/nginx/mime.types;
  include ${N}/conf.d/*.conf;
}
EOF
  cp "${ROOT[$n]}"/etc/crassostrea/ssl/*.pem "${N}/ssl/"
  cp "${ROOT[$n]}/etc/nginx/crassostrea-server-names.conf" "${N}/server-names.conf"
  # each node listens on its own address here
  sed -e "s#/etc/crassostrea/ssl#${N}/ssl#g" -e "s#/var/log/nginx#${N}/logs#g" \
      -e "s#/var/lib/crassostrea/acme-challenge#${N}/acme#g" \
      -e "s#/etc/nginx/crassostrea-server-names.conf#${N}/server-names.conf#g" \
      -e "s#/usr/local/share/crassostrea/docs/#${N}/docs/#g" \
      -e "s#listen 80\([ ;]\)#listen 10.0.0.${n}:80\1#" \
      -e "s#listen 443 #listen 10.0.0.${n}:443 #" \
      -e "/listen \[::\]/d" -e "s#listen 127.0.0.1:8008;#listen 127.0.0.${n}:8008;#" \
      "${ROOT[$n]}/etc/nginx/conf.d/crassostrea.conf" > "${N}/conf.d/crassostrea.conf"
  "${NGINX}" -c "${N}/nginx.conf" -p "${N}" -e "${N}/logs/error.log" || echo "FAIL nginx ${n} does not start"
done
echo "token-from-mx1" > "${WORK}/acme1/acme/.well-known/acme-challenge/tok1"
echo "token-from-mx2" > "${WORK}/acme2/acme/.well-known/acme-challenge/tok2"
sleep 1

get() { curl -s -H 'Host: shared.example.com' "http://$1/.well-known/acme-challenge/$2"; }
check "mx1 serves its own token" "[[ \$(get 10.0.0.1 tok1) == token-from-mx1 ]]"
check "mx1 serves mx2's token (fetched from the peer)" "[[ \$(get 10.0.0.1 tok2) == token-from-mx2 ]]"
check "mx2 serves mx1's token" "[[ \$(get 10.0.0.2 tok1) == token-from-mx1 ]]"
check "unknown token: 404" \
  "[[ \$(curl -s -o /dev/null -w '%{http_code}' http://10.0.0.1/.well-known/acme-challenge/nope) == 404 ]]"
check "no forwarding loop (mx2 answered once)" "[[ \$(grep -c 'acme-challenge/nope' ${WORK}/acme2/logs/access.log) == 1 ]]"
status() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }
check "the node's name: redirect to https" "[[ \$(status -H 'Host: mx1.example.com' http://10.0.0.1/) == 301 ]]"
check "an address: 404" "[[ \$(status http://10.0.0.1/) == 404 ]]"
check "another name: 404" "[[ \$(status -H 'Host: shared.example.com' http://10.0.0.1/) == 404 ]]"
check "HTTPS, another name: 404" "[[ \$(status --resolve other.example.com:443:10.0.0.1 https://other.example.com/) == 404 ]]"
check "HTTPS, an address: 404" "[[ \$(status https://10.0.0.1/) == 404 ]]"
check "HTTPS, the node's name: the web UI" \
  "[[ \$(status --resolve mx1.example.com:443:10.0.0.1 https://mx1.example.com/) == 502 ]]"

# A cluster of one node has no peers: nginx must accept its configuration
# (it refuses an upstream without servers)
S=${WORK}/acme-solo
rm -rf "${S}"
mkdir -p "${S}/logs" "${S}/tmp"
sed -e "s#/etc/crassostrea/ssl#${NODES}/solo/etc/crassostrea/ssl#g" -e "s#/var/log/nginx#${S}/logs#g" \
    -e "s#/etc/nginx/crassostrea-server-names.conf#${NODES}/solo/etc/nginx/crassostrea-server-names.conf#g" \
    "${NODES}/solo/etc/nginx/conf.d/crassostrea.conf" > "${S}/site.conf"
sed -e "s#${WORK}/acme1#${S}#g" -e "s#include ${S}/conf.d/\*.conf;#include ${S}/site.conf;#" \
    "${WORK}/acme1/nginx.conf" > "${S}/nginx.conf"
check "one-node cluster: nginx accepts the configuration" \
  "\"${NGINX}\" -t -q -c ${S}/nginx.conf -p ${S} -e ${S}/logs/error.log"
check "one-node cluster: no ACME peers" "! grep -q acme_peers ${S}/site.conf"

# The documentation on mx1: nginx asks the web UI (auth.docs_access), a stub
# that lets in the session cookie "admin"
mkdir -p "${WORK}/acme1/docs/admin"
echo "docs-home" > "${WORK}/acme1/docs/index.html"
echo "docs-admin" > "${WORK}/acme1/docs/admin/index.html"
python3 - > "${WORK}/docs-auth.log" 2>&1 <<'EOF' &
from http.server import BaseHTTPRequestHandler, HTTPServer
class Auth(BaseHTTPRequestHandler):
    def do_GET(self):
        ok = self.path == "/auth/docs" and "crassostrea_session=admin" in (self.headers.get("Cookie") or "")
        self.send_response(204 if ok else 401)
        self.end_headers()
HTTPServer(("127.0.0.1", 8000), Auth).serve_forever()
EOF
stub=$!
sleep 1
docs() { curl -sk --resolve mx1.example.com:443:10.0.0.1 "$@"; }
check "docs: /docs redirects to /docs/" \
  "[[ \$(docs -o /dev/null -w '%{http_code} %{redirect_url}' https://mx1.example.com/docs) == '301 https://mx1.example.com/docs/' ]]"
check "docs: without a login, to the login page" \
  "[[ \$(docs -o /dev/null -w '%{http_code} %{redirect_url}' https://mx1.example.com/docs/admin/) == '302 https://mx1.example.com/login?next=/docs/admin/' ]]"
check "docs: an administrator gets the page" \
  "[[ \$(docs -b crassostrea_session=admin https://mx1.example.com/docs/admin/) == docs-admin ]]"
check "docs: with HSTS and nosniff" \
  "docs -b crassostrea_session=admin -D - -o /dev/null https://mx1.example.com/docs/ | grep -qi '^strict-transport-security' && docs -b crassostrea_session=admin -D - -o /dev/null https://mx1.example.com/docs/ | grep -qi '^x-content-type-options: nosniff'"
check "docs: the auth endpoint is internal" \
  "[[ \$(docs -o /dev/null -w '%{http_code}' https://mx1.example.com/_sf_docs_auth) == 404 ]]"
check "docs: not on mx2 (DOCS_ENABLED=n), the web UI answers" \
  "[[ \$(curl -sk -o /dev/null -w '%{http_code}' --resolve mx2.example.com:443:10.0.0.2 https://mx2.example.com/docs/) == 401 ]]"
kill "${stub}"

for n in 1 2; do
  "${NGINX}" -c "${WORK}/acme${n}/nginx.conf" -p "${WORK}/acme${n}" -e "${WORK}/acme${n}/logs/error.log" -s stop
done
finish
